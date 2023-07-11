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
#define HAVE_IRCD_NET_H

/// Network IO subsystem.
///
/// Some parts of this system are not automatically included here when they
/// involve types which cannot be forward declared without boost headers.
/// This should not concern most developers as we have wrapped (or you should
/// wrap!) anything we need to expose to the rest of the project, or low-level
/// access may be had by including the asio.h header.
///
namespace ircd::net
{
	struct init;
	struct socket;

	IRCD_EXCEPTION(ircd::error, error)
	IRCD_EXCEPTION(error, disconnected)
	IRCD_EXCEPTION(error, inauthentic)
	IRCD_EXCEPTION(error, not_found)

	extern const std::error_code eof;
	extern conf::item<bool> enable_ipv6;
	extern log::log log;
}

#include "hostport.h"
#include "ipaddr.h"
#include "ipport.h"
#include "bpf.h"
#include "dns.h"
#include "dns_cache.h"
#include "listener.h"
#include "listener_udp.h"
#include "sock_opts.h"
#include "sock_stat.h"
#include "addrs.h"
#include "open.h"
#include "close.h"
#include "wait.h"
#include "check.h"
#include "read.h"
#include "write.h"
#include "scope_timeout.h"

namespace ircd::net
{
	uint64_t id(const socket &) noexcept;
	int native_handle(const socket &) noexcept;

	bool opened(const socket &) noexcept;
	ipport local_ipport(const socket &) noexcept;
	ipport remote_ipport(const socket &) noexcept;

	const_buffer peer_cert_der(const mutable_buffer &, const socket &);
	const_buffer peer_cert_der_sha256(const mutable_buffer &, const socket &);
	string_view peer_cert_der_sha256_b64(const mutable_buffer &, const socket &);
}

// Exports to ircd::
namespace ircd
{
	using net::socket;
}

struct [[gnu::visibility("hidden")]]
ircd::net::init
{
	init();
	~init() noexcept;
};
