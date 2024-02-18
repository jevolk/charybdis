// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_M_EVENT_H

namespace ircd::m
{
	struct event;

	// General util
	bool my(const id::event &);
	bool my(const event &);
	bool exists(const id::event &);
	bool cached(const id::event &);
	bool bad(const id::event &);

	// parallel util; returns bitset
	uint64_t exists(const vector_view<const id::event> &);
	size_t exists_count(const vector_view<const id::event> &);

	// Equality tests the event_id only! know this.
	bool operator==(const event &a, const event &b);

	// Depth comparison; expect unstable sorting.
	bool operator<(const event &, const event &);
	bool operator>(const event &, const event &);
	bool operator<=(const event &, const event &);
	bool operator>=(const event &, const event &);

	// Topological comparison
	size_t degree(const event &);
	bool before(const event &a, const event &b);

	event essential(event, const mutable_buffer &content, const bool &sigs = false);
	event signatures(const mutable_buffer &, const event &, const string_view &origin, const ed25519::sk &, const string_view &pkid);
	event signatures(const mutable_buffer &, const event &, const string_view &origin);
	event signatures(const mutable_buffer &, const event &);

	json::object hashes(const mutable_buffer &, const event &);
	bool verify_hash(const event &, const sha256::buf &);
	bool verify_hash(const event &);

	bool verify(const event &, const ed25519::pk &, const ed25519::sig &sig);
	bool verify(const event &, const ed25519::pk &, const string_view &origin, const string_view &pkid);
	bool verify(const event &, const string_view &origin, const string_view &pkid); // io/yield
	bool verify(const event &, const string_view &origin); // io/yield
	bool verify(const event &); // io/yield

	sha256::buf hash(const event &);
	ed25519::sig sign(const event &, const ed25519::sk &);
	ed25519::sig sign(const event &, const string_view &origin);
	ed25519::sig sign(const event &);

	id::event make_id(const event &, const string_view &version, id::event::buf &buf, const const_buffer &hash);
	id::event make_id(const event &, const string_view &version, id::event::buf &buf);
	bool check_id(const event &, const string_view &room_version) noexcept;
	bool check_id(const event &) noexcept;
}

///
/// This json::tuple provides at least all of the legal members of the matrix
/// standard event. This is the fundamental building block of the matrix
/// system. Rooms are collections of events. Messages between servers are
/// passed as bundles of events (or directly).
///
/// It is better to have 100 functions operate on one data structure than
/// to have 10 functions operate on 10 data structures.
/// -Alan Perlis
///
struct ircd::m::event
:json::tuple
<
	json::property<name::auth_events, json::array>,
	json::property<name::content, json::object>,
	json::property<name::depth, int64_t>,
	json::property<name::event_id, json::string>,
	json::property<name::hashes, json::object>,
	json::property<name::membership, json::string>,
	json::property<name::origin, json::string>,
	json::property<name::origin_server_ts, time_t>,
	json::property<name::prev_events, json::array>,
	json::property<name::prev_state, json::array>,
	json::property<name::redacts, json::string>,
	json::property<name::room_id, json::string>,
	json::property<name::sender, json::string>,
	json::property<name::signatures, json::object>,
	json::property<name::state_key, json::string>,
	json::property<name::type, json::string>
>
{
	struct auth;
	struct prev;
	struct refs;
	struct horizon;
	struct fetch;
	struct conforms;
	struct append;
	struct purge;

	using keys = json::keys<event>;
	using id = m::id::event;
	using idx = uint64_t;
	using idx_range = std::pair<idx, idx>;
	using closure = std::function<void (const event &)>;
	using closure_bool = std::function<bool (const event &)>;
	using closure_idx = std::function<void (const idx &)>;
	using closure_idx_bool = std::function<bool (const idx &)>;
	using closure_iov_mutable = std::function<void (json::iov &)>;

	static constexpr const size_t MAX_SIZE {64_KiB};
	static constexpr const size_t TYPE_MAX_SIZE {256};
	static constexpr const size_t ORIGIN_MAX_SIZE {256};
	static constexpr const size_t STATE_KEY_MAX_SIZE {512};
	static conf::item<size_t> max_size;
	static thread_local char buf[4][MAX_SIZE]; // general-use scratch

	static bool my(const idx &);
	static json::object preimage(const mutable_buffer &, const json::object &);
	static void essential(json::iov &event, const json::iov &content, const closure_iov_mutable &);
	static bool verify(const json::object &, const ed25519::pk &, const ed25519::sig &sig, const bool &canonical = false);
	static ed25519::sig sign(const string_view &, const ed25519::sk &);
	static ed25519::sig sign(const string_view &);
	static ed25519::sig sign(const json::object &, const ed25519::sk &);
	static ed25519::sig sign(const json::object &);
	static ed25519::sig sign(json::iov &event, const json::iov &content, const ed25519::sk &);
	static ed25519::sig sign(json::iov &event, const json::iov &content);
	static json::object signatures(const mutable_buffer &, json::iov &event, const json::iov &content);
	static sha256::buf hash(json::iov &event, const string_view &content);
	static sha256::buf hash(const json::object &);
	static json::object hashes(const mutable_buffer &, json::iov &event, const string_view &content);

	/// Always set for PDU's, not set for EDU's. The reference to the event_id
	/// for this event. For v1 events, this may point to somewhere inside the
	/// source; otherwise the event source may have been hashed into a buffer
	/// near the construction site, or retrieved from db, etc.
	id event_id;

	/// Convenience morphism
	explicit operator const id &() const;

	event(const json::object &, const id &, const keys &);
	event(const json::object &, const id &);
	event(id::buf &, const json::object &, const string_view &version = {});
	event(const json::object &, const keys &);
	event(const json::object &);
	explicit event(const json::members &);
	explicit event(const json::iov &, const id &);
	explicit event(const json::iov &);
	event() = default;
};

#include "index.h"
#include "auth.h"
#include "prev.h"
#include "refs.h"
#include "horizon.h"
#include "event_id.h"
#include "fetch.h"
#include "cached.h"
#include "prefetch.h"
#include "conforms.h"
#include "append.h"
#include "purge.h"

inline ircd::m::event::operator
const id &()
const
{
	return event_id;
}
