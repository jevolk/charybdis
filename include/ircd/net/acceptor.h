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
#define HAVE_IRCD_NET_ACCEPTOR_H

// This file is not included with the IRCd standard include stack because
// it requires symbols we can't forward declare without boost headers. It
// is part of the <ircd/asio.h> stack which can be included in your
// definition file if you need low level access to this acceptor API.

namespace ircd::net
{
	[[gnu::pure]] string_view loghead(const mutable_buffer &, const acceptor &);
	[[gnu::pure]] string_view loghead(const acceptor &);
}

/// Implementation to net::listener. See listener.h for additional interface.
struct [[gnu::visibility("protected")]]
ircd::net::acceptor
:std::enable_shared_from_this<struct ircd::net::acceptor>
{
	using error_code = boost::system::error_code;
	using callback = listener::callback;
	using proffer = listener::proffer;
	using sockets = std::list<std::shared_ptr<socket>>;

	IRCD_EXCEPTION(listener::error, error)
	IRCD_EXCEPTION(error, sni_warning)

	static constexpr bool debug_alpn {false};

	static log::log log;
	static ios::descriptor accept_desc;
	static ios::descriptor handshake_desc;
	static conf::item<size_t> handshaking_max;
	static conf::item<size_t> handshaking_max_per_peer;
	static conf::item<milliseconds> timeout;
	static conf::item<std::string> ssl_curve_list;
	static conf::item<std::string> ssl_cipher_list;
	static conf::item<std::string> ssl_cipher_blacklist;

	std::string name;
	std::string opts;
	std::string cname;
	size_t backlog;
	listener::callback cb;
	listener::proffer pcb;
	bpf::prog filter;
	asio::ssl::context ssl;
	ip::tcp::endpoint ep;
	ip::tcp::acceptor a;
	size_t accepting {0};
	sockets handshaking;
	bool secure {false};
	bool interrupting {false};
	ctx::dock joining;

	// Internal configuration
	void configure_dh(const json::object &);
	bool configure_certs(const json::object &);
	void configure_curves(const json::object &);
	void configure_ciphers(const json::object &);
	void configure_flags(const json::object &);
	void configure_password(const json::object &);
	void configure_sni(const json::object &);
	bool configure(const json::object &opts);

	// Completion stack
	void accepted(const std::shared_ptr<socket> &);

	// Handshake stack
	bool handle_sni(socket &, int &ad);
	string_view handle_alpn(socket &, const vector_view<const string_view> &in);
	void check_handshake_error(const error_code &ec, socket &) const;
	void handshake(const error_code &, const std::shared_ptr<socket>, const decltype(handshaking)::const_iterator) noexcept;

	// Acceptance stack
	static bool proffer_default(acceptor &, const ipport &);
	bool check_handshake_limit(socket &, const ipport &) const;
	bool check_accept_error(const error_code &ec, socket &) const;
	void accept(const error_code &, const std::shared_ptr<socket>) noexcept;

	// Accept next
	bool set_handle();

	// Acceptor shutdown
	bool interrupt() noexcept;
	void join() noexcept;
	void close();
	void open();

	acceptor(net::listener &,
	         const string_view &name,
	         const json::object &opts,
	         listener::callback,
	         listener::proffer);

	~acceptor() noexcept;
};
