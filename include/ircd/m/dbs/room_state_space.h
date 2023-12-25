// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2019 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_M_DBS_ROOM_STATE_SPACE_H

namespace ircd::m::dbs
{
	using room_state_space_tuple = std::tuple<string_view, string_view, int64_t, event::idx>;

	constexpr size_t ROOM_STATE_SPACE_KEY_MAX_SIZE
	{
		id::MAX_SIZE +
		event::TYPE_MAX_SIZE +
		event::STATE_KEY_MAX_SIZE +
		sizeof(int64_t) +
		sizeof(event::idx)
	};

	string_view room_state_space_key(const mutable_buffer &out, const id::room &, const string_view &type, const string_view &state_key, const int64_t &depth, const event::idx & = 0);
	string_view room_state_space_key(const mutable_buffer &out, const id::room &, const string_view &type, const string_view &state_key);
	string_view room_state_space_key(const mutable_buffer &out, const id::room &, const string_view &type);
	string_view room_state_space_key(const mutable_buffer &out, const id::room &);
	room_state_space_tuple room_state_space_key(const string_view &amalgam);

	void _index_room_state_space(db::txn &,  const event &, const opts &);

	// room_id | type, state_key, depth, event_idx => --
	extern db::domain room_state_space;
}

namespace ircd::m::dbs::desc
{
	extern conf::item<std::string> room_state_space__comp;
	extern conf::item<size_t> room_state_space__block__size;
	extern conf::item<size_t> room_state_space__meta_block__size;
	extern conf::item<size_t> room_state_space__cache__size;
	extern conf::item<size_t> room_state_space__bloom__bits;
	extern const db::prefix_transform room_state_space__pfx;
	extern const db::comparator room_state_space__cmp;
	extern const db::descriptor room_state_space;
}
