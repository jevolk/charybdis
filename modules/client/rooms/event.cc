// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2019 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include "rooms.h"

using namespace ircd;

static void
remote_fetch_eval(const m::resource::request &request,
                  const m::room::id &room_id,
                  const m::event::id &event_id);

m::resource::response
get__event(client &client,
           const m::resource::request &request,
           const m::room::id &room_id)
{
	if(request.parv.size() < 3)
		throw m::NEED_MORE_PARAMS
		{
			"event_id path parameter required"
		};

	m::event::id::buf event_id
	{
		url::decode(event_id, request.parv[2])
	};

	if(!m::exists(event_id) && m::exists(room_id))
		remote_fetch_eval(request, room_id, event_id);

	const m::room room
	{
		room_id, event_id
	};

	if(!visible(room, request.user_id))
		throw m::ACCESS_DENIED
		{
			"You are not permitted to view the room at this event"
		};

	m::event::fetch::opts fopts;
	fopts.query_json_force = true;
	const m::event::fetch event
	{
		event_id, fopts
	};

	const unique_mutable_buffer buf
	{
		m::event::MAX_SIZE
	};

	json::stack out{buf};
	{
		json::stack::object top{out};
		m::event::append
		{
			top, event,
			{
				.event_idx = event.event_idx,
				.user_id = request.user_id,
				.query_prev_state = false,
				.query_redacted = false,
				.query_visible = false,
			}
		};
	};

	return m::resource::response
	{
		client, json::object
		{
			out.completed()
		}
	};
}

void
remote_fetch_eval(const m::resource::request &request,
                  const m::room::id &room_id,
                  const m::event::id &event_id)
try
{
	auto fetch
	{
		m::fetch::start(
		{
			.op = m::fetch::op::event,
			.room_id = room_id,
			.event_id = event_id,
		})
	};

	const auto response
	{
		fetch.get()
	};

	const json::object body
	{
		response
	};

	const json::array pdus
	{
		body["pdus"]
	};

	m::vm::opts vmopts;
	vmopts.user_id = request.user_id;
	vmopts.phase.set(m::vm::phase::NOTIFY, false);
	vmopts.phase.set(m::vm::phase::FETCH_PREV, false);
	vmopts.phase.set(m::vm::phase::FETCH_STATE, false);
	vmopts.wopts.appendix.set(m::dbs::appendix::ROOM_HEAD, false);
	m::vm::eval
	{
		pdus, vmopts
	};
}
catch(const ctx::interrupted &e)
{
	throw;
}
catch(const std::exception &e)
{
	log::error
	{
		"Failed to fetch %s in %s for %s :%s",
		string_view{event_id},
		string_view{room_id},
		string_view{request.user_id},
		e.what(),
	};
}
