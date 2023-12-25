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
#define HAVE_IRCD_M_DBS_EVENT_TYPE_H

namespace ircd::m::dbs
{
	using event_type_tuple = std::tuple<event::idx>;

	constexpr size_t EVENT_TYPE_KEY_MAX_SIZE
	{
		event::TYPE_MAX_SIZE + 1 + 8
	};

	string_view event_type_key(const mutable_buffer &out, const string_view &, const event::idx & = 0);
	event_type_tuple event_type_key(const string_view &amalgam);

	void _index_event_type(db::txn &, const event &, const opts &);

	// type | event_idx => -
	extern db::domain event_type;
}

namespace ircd::m::dbs::desc
{
	// events type
	extern conf::item<std::string> event_type__comp;
	extern conf::item<size_t> event_type__block__size;
	extern conf::item<size_t> event_type__meta_block__size;
	extern conf::item<size_t> event_type__cache__size;
	extern const db::prefix_transform event_type__pfx;
	extern const db::descriptor event_type;
}
