use std::{cmp::max, collections::BTreeMap, sync::Arc};

use ruma::{
	api::client::{
		error::ErrorKind,
		room::{self, aliases, create_room, get_room_event, upgrade_room},
	},
	events::{
		room::{
			canonical_alias::RoomCanonicalAliasEventContent,
			create::RoomCreateEventContent,
			guest_access::{GuestAccess, RoomGuestAccessEventContent},
			history_visibility::{HistoryVisibility, RoomHistoryVisibilityEventContent},
			join_rules::{JoinRule, RoomJoinRulesEventContent},
			member::{MembershipState, RoomMemberEventContent},
			name::RoomNameEventContent,
			power_levels::RoomPowerLevelsEventContent,
			tombstone::RoomTombstoneEventContent,
			topic::RoomTopicEventContent,
		},
		StateEventType, TimelineEventType,
	},
	int,
	serde::JsonObject,
	CanonicalJsonObject, CanonicalJsonValue, OwnedRoomAliasId, OwnedRoomId, RoomAliasId, RoomId, RoomVersionId,
};
use serde_json::{json, value::to_raw_value};
use tracing::{debug, error, info, warn};

use crate::{api::client_server::invite_helper, service::pdu::PduBuilder, services, Error, Result, Ruma};

/// # `POST /_matrix/client/v3/createRoom`
///
/// Creates a new room.
///
/// - Room ID is randomly generated
/// - Create alias if `room_alias_name` is set
/// - Send create event
/// - Join sender user
/// - Send power levels event
/// - Send canonical room alias
/// - Send join rules
/// - Send history visibility
/// - Send guest access
/// - Send events listed in initial state
/// - Send events implied by `name` and `topic`
/// - Send invite events
pub async fn create_room_route(body: Ruma<create_room::v3::Request>) -> Result<create_room::v3::Response> {
	use create_room::v3::RoomPreset;

	let sender_user = body.sender_user.as_ref().expect("user is authenticated");

	if !services().globals.allow_room_creation()
		&& body.appservice_info.is_none()
		&& !services().users.is_admin(sender_user)?
	{
		return Err(Error::BadRequest(ErrorKind::forbidden(), "Room creation has been disabled."));
	}

	let room_id: OwnedRoomId;

	// checks if the user specified an explicit (custom) room_id to be created with
	// in request body. falls back to normal generated room ID if not specified.
	if let Some(CanonicalJsonValue::Object(json_body)) = &body.json_body {
		match json_body.get("room_id") {
			Some(custom_room_id) => {
				let custom_room_id_s = custom_room_id.to_string();

				// do some checks on the custom room ID similar to room aliases
				if custom_room_id_s.contains(':') {
					return Err(Error::BadRequest(
						ErrorKind::InvalidParam,
						"Custom room ID contained `:` which is not allowed. Please note that this expects a \
						 localpart, not the full room ID.",
					));
				} else if custom_room_id_s.contains(char::is_whitespace) {
					return Err(Error::BadRequest(
						ErrorKind::InvalidParam,
						"Custom room ID contained spaces which is not valid.",
					));
				} else if custom_room_id_s.len() > 255 {
					return Err(Error::BadRequest(ErrorKind::InvalidParam, "Custom room ID is too long."));
				}

				// apply forbidden room alias checks to custom room IDs too
				if services()
					.globals
					.forbidden_alias_names()
					.is_match(&custom_room_id_s)
				{
					return Err(Error::BadRequest(ErrorKind::Unknown, "Custom room ID is forbidden."));
				}

				let full_room_id = "!".to_owned()
					+ &custom_room_id_s.replace('"', "")
					+ ":" + services().globals.server_name().as_ref();
				debug!("Full room ID: {}", full_room_id);

				room_id = RoomId::parse(full_room_id).map_err(|e| {
					info!("User attempted to create room with custom room ID but failed parsing: {}", e);
					Error::BadRequest(ErrorKind::InvalidParam, "Custom room ID could not be parsed")
				})?;
			},
			None => room_id = RoomId::new(services().globals.server_name()),
		}
	} else {
		room_id = RoomId::new(services().globals.server_name());
	}

	// check if room ID doesn't already exist instead of erroring on auth check
	if services().rooms.short.get_shortroomid(&room_id)?.is_some() {
		return Err(Error::BadRequest(
			ErrorKind::RoomInUse,
			"Room with that custom room ID already exists",
		));
	}

	services().rooms.short.get_or_create_shortroomid(&room_id)?;

	let mutex_state = Arc::clone(
		services()
			.globals
			.roomid_mutex_state
			.write()
			.await
			.entry(room_id.clone())
			.or_default(),
	);
	let state_lock = mutex_state.lock().await;

	let alias: Option<OwnedRoomAliasId> = body
		.room_alias_name
		.as_ref()
		.map_or(Ok(None), |localpart| {
			// Basic checks on the room alias validity
			if localpart.contains(':') {
				return Err(Error::BadRequest(
					ErrorKind::InvalidParam,
					"Room alias contained `:` which is not allowed. Please note that this expects a localpart, not \
					 the full room alias.",
				));
			} else if localpart.contains(char::is_whitespace) {
				return Err(Error::BadRequest(
					ErrorKind::InvalidParam,
					"Room alias contained spaces which is not a valid room alias.",
				));
			} else if localpart.len() > 255 {
				// there is nothing spec-wise saying to check the limit of this,
				// however absurdly long room aliases are guaranteed to be unreadable or done
				// maliciously. there is no reason a room alias should even exceed 100
				// characters as is. generally in spec, 255 is matrix's fav number
				return Err(Error::BadRequest(
					ErrorKind::InvalidParam,
					"Room alias is excessively long, clients may not be able to handle this. Please shorten it.",
				));
			} else if localpart.contains('"') {
				return Err(Error::BadRequest(
					ErrorKind::InvalidParam,
					"Room alias contained `\"` which is not allowed.",
				));
			}

			// check if room alias is forbidden
			if services()
				.globals
				.forbidden_alias_names()
				.is_match(localpart)
			{
				return Err(Error::BadRequest(ErrorKind::Unknown, "Room alias name is forbidden."));
			}

			let alias =
				RoomAliasId::parse(format!("#{}:{}", localpart, services().globals.server_name())).map_err(|e| {
					warn!("Failed to parse room alias for room ID {}: {e}", room_id);
					Error::BadRequest(ErrorKind::InvalidParam, "Invalid room alias specified.")
				})?;

			if services()
				.rooms
				.alias
				.resolve_local_alias(&alias)?
				.is_some()
			{
				Err(Error::BadRequest(ErrorKind::RoomInUse, "Room alias already exists."))
			} else {
				Ok(Some(alias))
			}
		})?;

	if let Some(ref alias) = alias {
		if let Some(ref info) = body.appservice_info {
			if !info.aliases.is_match(alias.as_str()) {
				return Err(Error::BadRequest(ErrorKind::Exclusive, "Room alias is not in namespace."));
			}
		} else if services().appservice.is_exclusive_alias(alias).await {
			return Err(Error::BadRequest(ErrorKind::Exclusive, "Room alias reserved by appservice."));
		}
	}

	let room_version = match body.room_version.clone() {
		Some(room_version) => {
			if services()
				.globals
				.supported_room_versions()
				.contains(&room_version)
			{
				room_version
			} else {
				return Err(Error::BadRequest(
					ErrorKind::UnsupportedRoomVersion,
					"This server does not support that room version.",
				));
			}
		},
		None => services().globals.default_room_version(),
	};

	let content = match &body.creation_content {
		Some(content) => {
			let mut content = content
				.deserialize_as::<CanonicalJsonObject>()
				.map_err(|e| {
					error!("Failed to deserialise content as canonical JSON: {}", e);
					Error::bad_database("Failed to deserialise content as canonical JSON.")
				})?;
			match room_version {
				RoomVersionId::V1
				| RoomVersionId::V2
				| RoomVersionId::V3
				| RoomVersionId::V4
				| RoomVersionId::V5
				| RoomVersionId::V6
				| RoomVersionId::V7
				| RoomVersionId::V8
				| RoomVersionId::V9
				| RoomVersionId::V10 => {
					content.insert(
						"creator".into(),
						json!(&sender_user).try_into().map_err(|e| {
							info!("Invalid creation content: {e}");
							Error::BadRequest(ErrorKind::BadJson, "Invalid creation content")
						})?,
					);
				},
				RoomVersionId::V11 => {}, // V11 removed the "creator" key
				_ => {
					warn!("Unexpected or unsupported room version {room_version}");
					return Err(Error::BadRequest(
						ErrorKind::BadJson,
						"Unexpected or unsupported room version found",
					));
				},
			}

			content.insert(
				"room_version".into(),
				json!(room_version.as_str())
					.try_into()
					.map_err(|_| Error::BadRequest(ErrorKind::BadJson, "Invalid creation content"))?,
			);
			content
		},
		None => {
			let content = match room_version {
				RoomVersionId::V1
				| RoomVersionId::V2
				| RoomVersionId::V3
				| RoomVersionId::V4
				| RoomVersionId::V5
				| RoomVersionId::V6
				| RoomVersionId::V7
				| RoomVersionId::V8
				| RoomVersionId::V9
				| RoomVersionId::V10 => RoomCreateEventContent::new_v1(sender_user.clone()),
				RoomVersionId::V11 => RoomCreateEventContent::new_v11(),
				_ => {
					warn!("Unexpected or unsupported room version {room_version}");
					return Err(Error::BadRequest(
						ErrorKind::BadJson,
						"Unexpected or unsupported room version found",
					));
				},
			};
			let mut content = serde_json::from_str::<CanonicalJsonObject>(
				to_raw_value(&content)
					.map_err(|_| Error::BadRequest(ErrorKind::BadJson, "Invalid creation content"))?
					.get(),
			)
			.unwrap();
			content.insert(
				"room_version".into(),
				json!(room_version.as_str())
					.try_into()
					.map_err(|_| Error::BadRequest(ErrorKind::BadJson, "Invalid creation content"))?,
			);
			content
		},
	};

	// Validate creation content
	let de_result = serde_json::from_str::<CanonicalJsonObject>(
		to_raw_value(&content)
			.expect("Invalid creation content")
			.get(),
	);

	if de_result.is_err() {
		return Err(Error::BadRequest(ErrorKind::BadJson, "Invalid creation content"));
	}

	// 1. The room create event
	services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomCreate,
				content: to_raw_value(&content).expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(String::new()),
				redacts: None,
			},
			sender_user,
			&room_id,
			&state_lock,
		)
		.await?;

	// 2. Let the room creator join
	services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomMember,
				content: to_raw_value(&RoomMemberEventContent {
					membership: MembershipState::Join,
					displayname: services().users.displayname(sender_user)?,
					avatar_url: services().users.avatar_url(sender_user)?,
					is_direct: Some(body.is_direct),
					third_party_invite: None,
					blurhash: services().users.blurhash(sender_user)?,
					reason: None,
					join_authorized_via_users_server: None,
				})
				.expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(sender_user.to_string()),
				redacts: None,
			},
			sender_user,
			&room_id,
			&state_lock,
		)
		.await?;

	// 3. Power levels

	// Figure out preset. We need it for preset specific events
	let preset = body.preset.clone().unwrap_or(match &body.visibility {
		room::Visibility::Public => RoomPreset::PublicChat,
		_ => RoomPreset::PrivateChat, // Room visibility should not be custom
	});

	let mut users = BTreeMap::new();
	users.insert(sender_user.clone(), int!(100));

	if preset == RoomPreset::TrustedPrivateChat {
		for invite_ in &body.invite {
			users.insert(invite_.clone(), int!(100));
		}
	}

	let mut power_levels_content = serde_json::to_value(RoomPowerLevelsEventContent {
		users,
		..Default::default()
	})
	.expect("event is valid, we just created it");

	// secure proper defaults of sensitive/dangerous permissions that moderators
	// (power level 50) should not have easy access to
	power_levels_content["events"]["m.room.power_levels"] = serde_json::to_value(100).expect("100 is valid Value");
	power_levels_content["events"]["m.room.server_acl"] = serde_json::to_value(100).expect("100 is valid Value");
	power_levels_content["events"]["m.room.tombstone"] = serde_json::to_value(100).expect("100 is valid Value");
	power_levels_content["events"]["m.room.encryption"] = serde_json::to_value(100).expect("100 is valid Value");
	power_levels_content["events"]["m.room.history_visibility"] =
		serde_json::to_value(100).expect("100 is valid Value");

	// synapse does this too. clients do not expose these permissions. it prevents
	// default users from calling public rooms, for obvious reasons.
	if body.visibility == room::Visibility::Public {
		power_levels_content["events"]["m.call.invite"] = serde_json::to_value(50).expect("50 is valid Value");
		power_levels_content["events"]["org.matrix.msc3401.call"] =
			serde_json::to_value(50).expect("50 is valid Value");
		power_levels_content["events"]["org.matrix.msc3401.call.member"] =
			serde_json::to_value(50).expect("50 is valid Value");
	}

	if let Some(power_level_content_override) = &body.power_level_content_override {
		let json: JsonObject = serde_json::from_str(power_level_content_override.json().get())
			.map_err(|_| Error::BadRequest(ErrorKind::BadJson, "Invalid power_level_content_override."))?;

		for (key, value) in json {
			power_levels_content[key] = value;
		}
	}

	services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomPowerLevels,
				content: to_raw_value(&power_levels_content).expect("to_raw_value always works on serde_json::Value"),
				unsigned: None,
				state_key: Some(String::new()),
				redacts: None,
			},
			sender_user,
			&room_id,
			&state_lock,
		)
		.await?;

	// 4. Canonical room alias
	if let Some(room_alias_id) = &alias {
		services()
			.rooms
			.timeline
			.build_and_append_pdu(
				PduBuilder {
					event_type: TimelineEventType::RoomCanonicalAlias,
					content: to_raw_value(&RoomCanonicalAliasEventContent {
						alias: Some(room_alias_id.to_owned()),
						alt_aliases: vec![],
					})
					.expect("We checked that alias earlier, it must be fine"),
					unsigned: None,
					state_key: Some(String::new()),
					redacts: None,
				},
				sender_user,
				&room_id,
				&state_lock,
			)
			.await?;
	}

	// 5. Events set by preset

	// 5.1 Join Rules
	services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomJoinRules,
				content: to_raw_value(&RoomJoinRulesEventContent::new(match preset {
					RoomPreset::PublicChat => JoinRule::Public,
					// according to spec "invite" is the default
					_ => JoinRule::Invite,
				}))
				.expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(String::new()),
				redacts: None,
			},
			sender_user,
			&room_id,
			&state_lock,
		)
		.await?;

	// 5.2 History Visibility
	services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomHistoryVisibility,
				content: to_raw_value(&RoomHistoryVisibilityEventContent::new(HistoryVisibility::Shared))
					.expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(String::new()),
				redacts: None,
			},
			sender_user,
			&room_id,
			&state_lock,
		)
		.await?;

	// 5.3 Guest Access
	services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomGuestAccess,
				content: to_raw_value(&RoomGuestAccessEventContent::new(match preset {
					RoomPreset::PublicChat => GuestAccess::Forbidden,
					_ => GuestAccess::CanJoin,
				}))
				.expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(String::new()),
				redacts: None,
			},
			sender_user,
			&room_id,
			&state_lock,
		)
		.await?;

	// 6. Events listed in initial_state
	for event in &body.initial_state {
		let mut pdu_builder = event.deserialize_as::<PduBuilder>().map_err(|e| {
			warn!("Invalid initial state event: {:?}", e);
			Error::BadRequest(ErrorKind::InvalidParam, "Invalid initial state event.")
		})?;

		// Implicit state key defaults to ""
		pdu_builder.state_key.get_or_insert_with(String::new);

		// Silently skip encryption events if they are not allowed
		if pdu_builder.event_type == TimelineEventType::RoomEncryption && !services().globals.allow_encryption() {
			continue;
		}

		services()
			.rooms
			.timeline
			.build_and_append_pdu(pdu_builder, sender_user, &room_id, &state_lock)
			.await?;
	}

	// 7. Events implied by name and topic
	if let Some(name) = &body.name {
		services()
			.rooms
			.timeline
			.build_and_append_pdu(
				PduBuilder {
					event_type: TimelineEventType::RoomName,
					content: to_raw_value(&RoomNameEventContent::new(name.clone()))
						.expect("event is valid, we just created it"),
					unsigned: None,
					state_key: Some(String::new()),
					redacts: None,
				},
				sender_user,
				&room_id,
				&state_lock,
			)
			.await?;
	}

	if let Some(topic) = &body.topic {
		services()
			.rooms
			.timeline
			.build_and_append_pdu(
				PduBuilder {
					event_type: TimelineEventType::RoomTopic,
					content: to_raw_value(&RoomTopicEventContent {
						topic: topic.clone(),
					})
					.expect("event is valid, we just created it"),
					unsigned: None,
					state_key: Some(String::new()),
					redacts: None,
				},
				sender_user,
				&room_id,
				&state_lock,
			)
			.await?;
	}

	// 8. Events implied by invite (and TODO: invite_3pid)
	drop(state_lock);
	for user_id in &body.invite {
		_ = invite_helper(sender_user, user_id, &room_id, None, body.is_direct).await;
	}

	// Homeserver specific stuff
	if let Some(alias) = alias {
		services().rooms.alias.set_alias(&alias, &room_id)?;
	}

	if body.visibility == room::Visibility::Public {
		services().rooms.directory.set_public(&room_id)?;
	}

	info!("{} created a room", sender_user);

	Ok(create_room::v3::Response::new(room_id))
}

/// # `GET /_matrix/client/r0/rooms/{roomId}/event/{eventId}`
///
/// Gets a single event.
///
/// - You have to currently be joined to the room (TODO: Respect history
///   visibility)
pub async fn get_room_event_route(body: Ruma<get_room_event::v3::Request>) -> Result<get_room_event::v3::Response> {
	let sender_user = body.sender_user.as_ref().expect("user is authenticated");

	let event = services()
		.rooms
		.timeline
		.get_pdu(&body.event_id)?
		.ok_or_else(|| {
			warn!("Event not found, event ID: {:?}", &body.event_id);
			Error::BadRequest(ErrorKind::NotFound, "Event not found.")
		})?;

	if !services()
		.rooms
		.state_accessor
		.user_can_see_event(sender_user, &event.room_id, &body.event_id)?
	{
		return Err(Error::BadRequest(
			ErrorKind::forbidden(),
			"You don't have permission to view this event.",
		));
	}

	let mut event = (*event).clone();
	event.add_age()?;

	Ok(get_room_event::v3::Response {
		event: event.to_room_event(),
	})
}

/// # `GET /_matrix/client/r0/rooms/{roomId}/aliases`
///
/// Lists all aliases of the room.
///
/// - Only users joined to the room are allowed to call this, or if
///   `history_visibility` is world readable in the room
pub async fn get_room_aliases_route(body: Ruma<aliases::v3::Request>) -> Result<aliases::v3::Response> {
	let sender_user = body.sender_user.as_ref().expect("user is authenticated");

	if !services()
		.rooms
		.state_accessor
		.user_can_see_state_events(sender_user, &body.room_id)?
	{
		return Err(Error::BadRequest(
			ErrorKind::forbidden(),
			"You don't have permission to view this room.",
		));
	}

	Ok(aliases::v3::Response {
		aliases: services()
			.rooms
			.alias
			.local_aliases_for_room(&body.room_id)
			.filter_map(Result::ok)
			.collect(),
	})
}

/// # `POST /_matrix/client/r0/rooms/{roomId}/upgrade`
///
/// Upgrades the room.
///
/// - Creates a replacement room
/// - Sends a tombstone event into the current room
/// - Sender user joins the room
/// - Transfers some state events
/// - Moves local aliases
/// - Modifies old room power levels to prevent users from speaking
pub async fn upgrade_room_route(body: Ruma<upgrade_room::v3::Request>) -> Result<upgrade_room::v3::Response> {
	let sender_user = body.sender_user.as_ref().expect("user is authenticated");

	if !services()
		.globals
		.supported_room_versions()
		.contains(&body.new_version)
	{
		return Err(Error::BadRequest(
			ErrorKind::UnsupportedRoomVersion,
			"This server does not support that room version.",
		));
	}

	// Create a replacement room
	let replacement_room = RoomId::new(services().globals.server_name());
	services()
		.rooms
		.short
		.get_or_create_shortroomid(&replacement_room)?;

	let mutex_state = Arc::clone(
		services()
			.globals
			.roomid_mutex_state
			.write()
			.await
			.entry(body.room_id.clone())
			.or_default(),
	);
	let state_lock = mutex_state.lock().await;

	// Send a m.room.tombstone event to the old room to indicate that it is not
	// intended to be used any further Fail if the sender does not have the required
	// permissions
	let tombstone_event_id = services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomTombstone,
				content: to_raw_value(&RoomTombstoneEventContent {
					body: "This room has been replaced".to_owned(),
					replacement_room: replacement_room.clone(),
				})
				.expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(String::new()),
				redacts: None,
			},
			sender_user,
			&body.room_id,
			&state_lock,
		)
		.await?;

	// Change lock to replacement room
	drop(state_lock);
	let mutex_state = Arc::clone(
		services()
			.globals
			.roomid_mutex_state
			.write()
			.await
			.entry(replacement_room.clone())
			.or_default(),
	);
	let state_lock = mutex_state.lock().await;

	// Get the old room creation event
	let mut create_event_content = serde_json::from_str::<CanonicalJsonObject>(
		services()
			.rooms
			.state_accessor
			.room_state_get(&body.room_id, &StateEventType::RoomCreate, "")?
			.ok_or_else(|| Error::bad_database("Found room without m.room.create event."))?
			.content
			.get(),
	)
	.map_err(|_| Error::bad_database("Invalid room event in database."))?;

	// Use the m.room.tombstone event as the predecessor
	let predecessor = Some(ruma::events::room::create::PreviousRoom::new(
		body.room_id.clone(),
		(*tombstone_event_id).to_owned(),
	));

	// Send a m.room.create event containing a predecessor field and the applicable
	// room_version
	match body.new_version {
		RoomVersionId::V1
		| RoomVersionId::V2
		| RoomVersionId::V3
		| RoomVersionId::V4
		| RoomVersionId::V5
		| RoomVersionId::V6
		| RoomVersionId::V7
		| RoomVersionId::V8
		| RoomVersionId::V9
		| RoomVersionId::V10 => {
			create_event_content.insert(
				"creator".into(),
				json!(&sender_user).try_into().map_err(|e| {
					info!("Error forming creation event: {e}");
					Error::BadRequest(ErrorKind::BadJson, "Error forming creation event")
				})?,
			);
		},
		RoomVersionId::V11 => {
			// "creator" key no longer exists in V11 rooms
			create_event_content.remove("creator");
		},
		_ => {
			warn!("Unexpected or unsupported room version {}", body.new_version);
			return Err(Error::BadRequest(
				ErrorKind::BadJson,
				"Unexpected or unsupported room version found",
			));
		},
	}

	create_event_content.insert(
		"room_version".into(),
		json!(&body.new_version)
			.try_into()
			.map_err(|_| Error::BadRequest(ErrorKind::BadJson, "Error forming creation event"))?,
	);
	create_event_content.insert(
		"predecessor".into(),
		json!(predecessor)
			.try_into()
			.map_err(|_| Error::BadRequest(ErrorKind::BadJson, "Error forming creation event"))?,
	);

	// Validate creation event content
	let de_result = serde_json::from_str::<CanonicalJsonObject>(
		to_raw_value(&create_event_content)
			.expect("Error forming creation event")
			.get(),
	);

	if de_result.is_err() {
		return Err(Error::BadRequest(ErrorKind::BadJson, "Error forming creation event"));
	}

	services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomCreate,
				content: to_raw_value(&create_event_content).expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(String::new()),
				redacts: None,
			},
			sender_user,
			&replacement_room,
			&state_lock,
		)
		.await?;

	// Join the new room
	services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomMember,
				content: to_raw_value(&RoomMemberEventContent {
					membership: MembershipState::Join,
					displayname: services().users.displayname(sender_user)?,
					avatar_url: services().users.avatar_url(sender_user)?,
					is_direct: None,
					third_party_invite: None,
					blurhash: services().users.blurhash(sender_user)?,
					reason: None,
					join_authorized_via_users_server: None,
				})
				.expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(sender_user.to_string()),
				redacts: None,
			},
			sender_user,
			&replacement_room,
			&state_lock,
		)
		.await?;

	// Recommended transferable state events list from the specs
	let transferable_state_events = vec![
		StateEventType::RoomServerAcl,
		StateEventType::RoomEncryption,
		StateEventType::RoomName,
		StateEventType::RoomAvatar,
		StateEventType::RoomTopic,
		StateEventType::RoomGuestAccess,
		StateEventType::RoomHistoryVisibility,
		StateEventType::RoomJoinRules,
		StateEventType::RoomPowerLevels,
	];

	// Replicate transferable state events to the new room
	for event_type in transferable_state_events {
		let event_content = match services()
			.rooms
			.state_accessor
			.room_state_get(&body.room_id, &event_type, "")?
		{
			Some(v) => v.content.clone(),
			None => continue, // Skipping missing events.
		};

		services()
			.rooms
			.timeline
			.build_and_append_pdu(
				PduBuilder {
					event_type: event_type.to_string().into(),
					content: event_content,
					unsigned: None,
					state_key: Some(String::new()),
					redacts: None,
				},
				sender_user,
				&replacement_room,
				&state_lock,
			)
			.await?;
	}

	// Moves any local aliases to the new room
	for alias in services()
		.rooms
		.alias
		.local_aliases_for_room(&body.room_id)
		.filter_map(Result::ok)
	{
		services()
			.rooms
			.alias
			.set_alias(&alias, &replacement_room)?;
	}

	// Get the old room power levels
	let mut power_levels_event_content: RoomPowerLevelsEventContent = serde_json::from_str(
		services()
			.rooms
			.state_accessor
			.room_state_get(&body.room_id, &StateEventType::RoomPowerLevels, "")?
			.ok_or_else(|| Error::bad_database("Found room without m.room.create event."))?
			.content
			.get(),
	)
	.map_err(|_| Error::bad_database("Invalid room event in database."))?;

	// Setting events_default and invite to the greater of 50 and users_default + 1
	let new_level = max(int!(50), power_levels_event_content.users_default + int!(1));
	power_levels_event_content.events_default = new_level;
	power_levels_event_content.invite = new_level;

	// Modify the power levels in the old room to prevent sending of events and
	// inviting new users
	_ = services()
		.rooms
		.timeline
		.build_and_append_pdu(
			PduBuilder {
				event_type: TimelineEventType::RoomPowerLevels,
				content: to_raw_value(&power_levels_event_content).expect("event is valid, we just created it"),
				unsigned: None,
				state_key: Some(String::new()),
				redacts: None,
			},
			sender_user,
			&body.room_id,
			&state_lock,
		)
		.await?;

	drop(state_lock);

	// Return the replacement room id
	Ok(upgrade_room::v3::Response {
		replacement_room,
	})
}
