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
#define HAVE_IRCD_NET_LISTENER_H

namespace ircd::net
{
	struct listener;
	struct acceptor;

	extern conf::item<bool> listen;

	std::string cipher_list(const acceptor &);
	json::object config(const acceptor &) noexcept;
	string_view name(const acceptor &) noexcept;
	string_view cname(const acceptor &) noexcept;
	ipport binder(const acceptor &);
	ipport local(const acceptor &);

	size_t handshaking_count(const acceptor &, const ipaddr &) noexcept;
	size_t handshaking_count(const acceptor &) noexcept;
	size_t accepting_count(const acceptor &) noexcept;

	bool allow(acceptor &);
	bool start(acceptor &);
	bool stop(acceptor &);
}

/// This object is a wrapper interface to the internal net::acceptor object
/// which contains boost assets which we cannot forward declare here. It
/// implicitly converts as a reference to the internal acceptor. Users wishing
/// to listen on a network interface for incoming connections create and hold
/// an instance of this object.
///
/// The configuration is provided in JSON. The operations are asynchronous on
/// the main stack and connected sockets are called back in callback. There is
/// also a proffer callback which is made as early as possible (before the SSL
/// handshake, and ideally if the platform supports it before a SYN-ACK) to
/// reject connections by returning false.
struct ircd::net::listener
{
	using callback = std::function<void (acceptor &, const std::shared_ptr<socket> &)>;
	using proffer = std::function<bool (acceptor &, const ipport &)>;

	IRCD_EXCEPTION(net::error, error)

  private:
	std::shared_ptr<net::acceptor> acceptor;

  public:
	operator const net::acceptor &() const;
	operator net::acceptor &();

	explicit operator json::object() const;
	string_view name() const;

	listener(const string_view &name,
	         const json::object &options,
	         callback,
	         proffer = {});

	explicit
	listener(const string_view &name,
	         const std::string &options,
	         callback,
	         proffer = {});

	~listener() noexcept;
};
