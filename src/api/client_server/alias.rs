use rand::seq::SliceRandom;
use ruma::{
	api::{
		appservice,
		client::{
			alias::{create_alias, delete_alias, get_alias},
			error::ErrorKind,
		},
		federation,
	},
	OwnedRoomAliasId, OwnedServerName,
};

use crate::{services, Error, Result, Ruma};

/// # `PUT /_matrix/client/v3/directory/room/{roomAlias}`
///
/// Creates a new room alias on this server.
pub async fn create_alias_route(body: Ruma<create_alias::v3::Request>) -> Result<create_alias::v3::Response> {
	if body.room_alias.server_name() != services().globals.server_name() {
		return Err(Error::BadRequest(ErrorKind::InvalidParam, "Alias is from another server."));
	}

	if services()
		.globals
		.forbidden_alias_names()
		.is_match(body.room_alias.alias())
	{
		return Err(Error::BadRequest(ErrorKind::Unknown, "Room alias is forbidden."));
	}

	if let Some(ref info) = body.appservice_info {
		if !info.aliases.is_match(body.room_alias.as_str()) {
			return Err(Error::BadRequest(ErrorKind::Exclusive, "Room alias is not in namespace."));
		}
	} else if services()
		.appservice
		.is_exclusive_alias(&body.room_alias)
		.await
	{
		return Err(Error::BadRequest(ErrorKind::Exclusive, "Room alias reserved by appservice."));
	}

	if services()
		.rooms
		.alias
		.resolve_local_alias(&body.room_alias)?
		.is_some()
	{
		return Err(Error::Conflict("Alias already exists."));
	}

	if services()
		.rooms
		.alias
		.set_alias(&body.room_alias, &body.room_id)
		.is_err()
	{
		return Err(Error::BadRequest(
			ErrorKind::InvalidParam,
			"Invalid room alias. Alias must be in the form of '#localpart:server_name'",
		));
	};

	Ok(create_alias::v3::Response::new())
}

/// # `DELETE /_matrix/client/v3/directory/room/{roomAlias}`
///
/// Deletes a room alias from this server.
///
/// - TODO: additional access control checks
/// - TODO: Update canonical alias event
pub async fn delete_alias_route(body: Ruma<delete_alias::v3::Request>) -> Result<delete_alias::v3::Response> {
	if body.room_alias.server_name() != services().globals.server_name() {
		return Err(Error::BadRequest(ErrorKind::InvalidParam, "Alias is from another server."));
	}

	if services()
		.rooms
		.alias
		.resolve_local_alias(&body.room_alias)?
		.is_none()
	{
		return Err(Error::BadRequest(ErrorKind::NotFound, "Alias does not exist."));
	}

	if let Some(ref info) = body.appservice_info {
		if !info.aliases.is_match(body.room_alias.as_str()) {
			return Err(Error::BadRequest(ErrorKind::Exclusive, "Room alias is not in namespace."));
		}
	} else if services()
		.appservice
		.is_exclusive_alias(&body.room_alias)
		.await
	{
		return Err(Error::BadRequest(ErrorKind::Exclusive, "Room alias reserved by appservice."));
	}

	if services()
		.rooms
		.alias
		.remove_alias(&body.room_alias)
		.is_err()
	{
		return Err(Error::BadRequest(
			ErrorKind::InvalidParam,
			"Invalid room alias. Alias must be in the form of '#localpart:server_name'",
		));
	};

	// TODO: update alt_aliases?

	Ok(delete_alias::v3::Response::new())
}

/// # `GET /_matrix/client/v3/directory/room/{roomAlias}`
///
/// Resolve an alias locally or over federation.
pub async fn get_alias_route(body: Ruma<get_alias::v3::Request>) -> Result<get_alias::v3::Response> {
	get_alias_helper(body.body.room_alias).await
}

pub(crate) async fn get_alias_helper(room_alias: OwnedRoomAliasId) -> Result<get_alias::v3::Response> {
	if room_alias.server_name() != services().globals.server_name() {
		let response = services()
			.sending
			.send_federation_request(
				room_alias.server_name(),
				federation::query::get_room_information::v1::Request {
					room_alias: room_alias.clone(),
				},
			)
			.await?;

		let room_id = response.room_id;

		let mut servers = response.servers;

		// since the room alias server_name responded, insert it into the list
		servers.push(room_alias.server_name().into());

		// find active servers in room state cache to suggest
		servers.extend(
			services()
				.rooms
				.state_cache
				.room_servers(&room_id)
				.filter_map(Result::ok),
		);

		servers.sort_unstable();
		servers.dedup();

		// shuffle list of servers randomly after sort and dedupe
		servers.shuffle(&mut rand::thread_rng());

		// prefer the very first server to be ourselves if available, else prefer the
		// room alias server first
		if let Some(server_index) = servers
			.iter()
			.position(|server| server == services().globals.server_name())
		{
			servers.remove(server_index);
			servers.insert(0, services().globals.server_name().to_owned());
		} else if let Some(alias_server_index) = servers
			.iter()
			.position(|server| server == room_alias.server_name())
		{
			servers.remove(alias_server_index);
			servers.insert(0, room_alias.server_name().into());
		}

		return Ok(get_alias::v3::Response::new(room_id, servers));
	}

	let mut room_id = None;
	match services().rooms.alias.resolve_local_alias(&room_alias)? {
		Some(r) => room_id = Some(r),
		None => {
			for appservice in services().appservice.read().await.values() {
				if appservice.aliases.is_match(room_alias.as_str())
					&& matches!(
						services()
							.sending
							.send_appservice_request(
								appservice.registration.clone(),
								appservice::query::query_room_alias::v1::Request {
									room_alias: room_alias.clone(),
								},
							)
							.await,
						Ok(Some(_opt_result))
					) {
					room_id = Some(
						services()
							.rooms
							.alias
							.resolve_local_alias(&room_alias)?
							.ok_or_else(|| Error::bad_config("Room does not exist."))?,
					);
					break;
				}
			}
		},
	};

	let Some(room_id) = room_id else {
		return Err(Error::BadRequest(ErrorKind::NotFound, "Room with alias not found."));
	};

	// find active servers in room state cache to suggest
	let mut servers: Vec<OwnedServerName> = services()
		.rooms
		.state_cache
		.room_servers(&room_id)
		.filter_map(Result::ok)
		.collect();

	servers.sort_unstable();
	servers.dedup();

	// shuffle list of servers randomly after sort and dedupe
	servers.shuffle(&mut rand::thread_rng());

	// insert our server as the very first choice if in list
	if let Some(server_index) = servers
		.iter()
		.position(|server| server == services().globals.server_name())
	{
		servers.remove(server_index);
		servers.insert(0, services().globals.server_name().to_owned());
	}

	Ok(get_alias::v3::Response::new(room_id, servers))
}
