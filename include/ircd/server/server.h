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
#define HAVE_IRCD_SERVER_H

/// The interface for when IRCd plays the role of client to other servers
///
namespace ircd::server
{
	struct init;
	struct link;
	struct peer;
	struct request;
	struct tag;

	IRCD_EXCEPTION(ircd::error, error);
	IRCD_EXCEPTION(error, buffer_overrun);
	IRCD_EXCEPTION(error, unavailable);
	IRCD_EXCEPTION(error, canceled);

	using peers_value_type = std::pair<const string_view, peer *>;
	using peers_allocator_state = allocator::node<peers_value_type>;
	using peers_allocator = typename peers_allocator_state::allocator;
	using peers_map_type = std::map<string_view, peer *, std::less<>, peers_allocator>;
	using peers_node_type = std::pair<typename peers_map_type::node_type, peers_value_type>;

	extern conf::item<bool> enable;
	extern peers_map_type peers;
}

#include "tag.h"
#include "request.h"
#include "link.h"
#include "peer.h"

namespace ircd::server
{
	// const utils
	size_t tag_count();
	size_t link_count();
	size_t peer_count();
	size_t peer_unfinished();

	// iteration of all requests.
	bool for_each(const link &, const request::each_closure &);
	bool for_each(const peer &, const request::each_closure &);
	bool for_each(const request::each_closure &);

	// const utils
	string_view errmsg(const net::hostport &) noexcept;
	bool errant(const net::hostport &) noexcept;
	bool exists(const net::hostport &) noexcept;
	bool linked(const net::hostport &) noexcept;
	bool avail(const net::hostport &) noexcept; // exists() && !errant()
	peer &find(const net::hostport &);

	// mutable utils
	peer &get(const net::hostport &);      // creates the peer if not found.
	bool prelink(const net::hostport &);   // creates and links if not errant.
	bool errclear(const net::hostport &);  // clear cached error.

	// manual control panel
	void interrupt();
	void close();
	void wait();
}

/// Subsystem initialization / destruction from ircd::main
///
struct [[gnu::visibility("hidden")]]
ircd::server::init
{
	init() noexcept;
	~init() noexcept;
};

inline size_t
ircd::server::peer_count()
{
	return peers.size();
}
