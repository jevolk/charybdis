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
#define HAVE_IRCD_NET_SOCK_OPTS_H

namespace ircd::net
{
	struct sock_opts;
	IRCD_OVERLOAD(system);

	bool v6only(const socket &);
	bool blocking(const socket &, system_t);
	bool blocking(const socket &);
	bool nopush(const socket &);
	bool nodelay(const socket &, system_t);
	bool nodelay(const socket &);
	bool quickack(const socket &);
	bool keepalive(const socket &);
	int linger(const socket &);
	int read_bufsz(const socket &);
	int write_bufsz(const socket &);
	int read_lowat(const socket &);
	int write_lowat(const socket &);
	int attach(const socket &);
	int iptos(const socket &);
	int priority(const socket &);
	int affinity(const socket &);
	int pmtudisc(const socket &);
	int pmtu(const socket &);
	int tstamp(const socket &);

	// returns true if supported, false if unsupported; failures will throw.
	bool v6only(socket &, const bool);
	bool blocking(socket &, const bool, system_t);
	bool blocking(socket &, const bool);
	bool nopush(socket &, const bool);
	bool nodelay(socket &, const bool, system_t);
	bool nodelay(socket &, const bool);
	bool quickack(socket &, const bool);
	bool keepalive(socket &, const bool);
	bool linger(socket &, const int); // -1 is OFF; >= 0 is ON
	bool read_bufsz(socket &, const int bytes);
	bool write_bufsz(socket &, const int bytes);
	bool read_lowat(socket &, const int bytes);
	bool write_lowat(socket &, const int bytes);
	bool attach(const int sd, const int fd);
	bool attach(socket &, const int fd);
	bool detach(const int sd, const int fd);
	bool detach(socket &, const int fd);
	bool iptos(socket &, const int);
	bool priority(socket &, const int);
	bool affinity(socket &, const int);
	bool pmtudisc(socket &, const int);
	bool tstamp(socket &, const int);

	void set(socket &, const sock_opts &);
}

/// Socket options convenience aggregate. This structure allows observation
/// or manipulation of socket options all together. Pass an active socket to
/// the constructor to observe all options. Use net::set(socket, sock_opts) to
/// set all non-ignored options.
struct ircd::net::sock_opts
{
	/// Magic value to not set this option on a set() pass.
	static constexpr int8_t IGN { std::numeric_limits<int8_t>::min() };

	int8_t v6only { IGN };
	int8_t blocking { IGN };             // Simulates blocking behavior
	int8_t nopush { IGN };
	int8_t nodelay { IGN };
	int8_t quickack { IGN };
	int8_t keepalive { IGN };
	int linger { IGN };                  // -1 is OFF; >= 0 is ON
	int read_bufsz { IGN };
	int write_bufsz { IGN };
	int read_lowat { IGN };
	int write_lowat { IGN };
	int ebpf { IGN };
	int iptos { IGN };
	int priority { IGN };
	int affinity { IGN };
	int pmtudisc { IGN };
	int pmtu { IGN };
	int tstamp { IGN };

	bool enable_tstamp() noexcept;       // platform-specific helper

	sock_opts(const socket &);           // Get options from socket
	sock_opts() = default;
};
