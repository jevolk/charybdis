// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2023 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_NET_SOCK_STAT_H

namespace ircd::net
{
	struct sock_stat;

	pair<size_t> bytes(const socket &) noexcept; // <in, out>
	pair<size_t> calls(const socket &) noexcept; // <in, out>
}

struct ircd::net::sock_stat
{
	static stats::item<uint64_t> total_bytes_in;
	static stats::item<uint64_t> total_bytes_out;
	static stats::item<uint64_t> total_calls_in;
	static stats::item<uint64_t> total_calls_out;

	size_t bytes {0};
	size_t calls {0};
	nanoseconds usr {0};
	nanoseconds sys {0};
	nanoseconds ack {0};

	// [in, out]
	static pair<const sock_stat *> get(const socket &) noexcept;
	static pair<sock_stat *> get(socket &) noexcept;
};

inline std::pair<size_t, size_t>
ircd::net::calls(const socket &socket)
noexcept
{
	const auto &[in, out]
	{
		sock_stat::get(socket)
	};

	return { in->calls, out->calls };
}

inline std::pair<size_t, size_t>
ircd::net::bytes(const socket &socket)
noexcept
{
	const auto &[in, out]
	{
		sock_stat::get(socket)
	};

	return { in->bytes, out->bytes };
}
