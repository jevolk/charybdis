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
#define HAVE_IRCD_M_DBS_EVENT_REFS_H

namespace ircd::m::dbs
{
	using event_refs_tuple = std::tuple<ref, event::idx>;

	constexpr size_t EVENT_REFS_KEY_MAX_SIZE
	{
		sizeof(event::idx) + sizeof(event::idx)
	};

	constexpr size_t ref_shift
	{
		8 * (sizeof(event::idx) - sizeof(ref))
	};

	constexpr event::idx ref_mask
	{
		0xFFUL << ref_shift
	};

	string_view
	event_refs_key(const mutable_buffer &out,
	               const event::idx &tgt,
	               const ref type,
	               const event::idx &referer);

	event_refs_tuple
	event_refs_key(const string_view &amalgam);

	[[gnu::pure]] string_view reflect(ref);
	size_t _prefetch_event_refs(const event &, const opts &);
	void _index_event_refs(db::txn &, const event &, const opts &);

	// event_idx | ref_type, event_idx
	extern db::domain event_refs;
}

namespace ircd::m::dbs::desc
{
	extern conf::item<std::string> event_refs__comp;
	extern conf::item<size_t> event_refs__block__size;
	extern conf::item<size_t> event_refs__meta_block__size;
	extern conf::item<size_t> event_refs__cache__size;
	extern const db::prefix_transform event_refs__pfx;
	extern const db::comparator event_refs__cmp;
	extern const db::descriptor event_refs;
}

/// Types of references indexed by event_refs. This is a single byte integer,
/// which should be plenty of namespace. Internally event_refs_key() and
/// event_refs store this in a high order byte of an event::idx integer. This
/// is an alternative to having separate columns for each type of reference.
///
/// NOTE: These values are written to the database and cannot be changed to
/// maintain ABI stability.
///
/// NOTE: These values not bit-flags and the entire integer space is in use.
///
enum class ircd::m::dbs::ref
:uint8_t
{
	/// All events which reference this event in their `prev_events`.
	NEXT                = 0x00,

	/// All power events which reference this event in their `auth_events`.
	/// Non-auth/non-power events are not involved in this graph at all.
	NEXT_AUTH           = 0x01,

	/// The next states in the transitions for a (type,state_key) cell.
	NEXT_STATE          = 0x02,

	/// The previous states in the transitions for a (type,state_key) cell.
	PREV_STATE          = 0x04,

	/// All m.receipt's which target this event.
	M_RECEIPT__M_READ   = 0x10,

	/// All m.relates_to's which target this event.
	M_RELATES           = 0x20,

	/// All m.room.redaction's which target this event.
	M_ROOM_REDACTION    = 0x40,
};
