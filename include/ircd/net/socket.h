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
#define HAVE_IRCD_NET_SOCKET_H

// This file is not included with the IRCd standard include stack because
// it requires symbols we can't forward declare without boost headers. It
// is part of the <ircd/asio.h> stack which can be included in your
// definition file if you need low level access to this socket API.

namespace ircd::net
{
	extern conf::item<std::string> ssl_curve_list;
	extern conf::item<std::string> ssl_cipher_list;
	extern conf::item<std::string> ssl_cipher_blacklist;
	extern asio::ssl::context sslv23_client;

	[[gnu::pure]] string_view loghead(const mutable_buffer &out, const socket &);
	[[gnu::pure]] string_view loghead(const socket &);
}

/// Internal socket interface
/// Socket cannot be copied or moved; must be constructed as shared ptr.
struct [[gnu::visibility("protected")]]
ircd::net::socket
:std::enable_shared_from_this<ircd::net::socket>
{
	struct io;
	struct stat;
	struct xfer;

	using endpoint = ip::tcp::endpoint;
	using wait_type = ip::tcp::socket::wait_type;
	using message_flags = asio::socket_base::message_flags;
	using ssl_stream = asio::ssl::stream<ip::tcp::socket &>;
	using handshake_type = asio::ssl::stream<ip::tcp::socket>::handshake_type;
	using handler = std::function<void (const error_code &, const size_t)>;
	using ec_handler = std::function<void (const error_code &)>;
	using eptr_handler = std::function<void (std::exception_ptr)>;

	struct stat
	{
		size_t bytes {0};
		size_t calls {0};
	};

	static uint64_t count;                       // monotonic
	static uint64_t instances;                   // current socket count
	static stats::item<uint64_t> total_bytes_in;
	static stats::item<uint64_t> total_bytes_out;
	static stats::item<uint64_t> total_calls_in;
	static stats::item<uint64_t> total_calls_out;
	static ios::descriptor desc_connect;
	static ios::descriptor desc_handshake;
	static ios::descriptor desc_disconnect;
	static ios::descriptor desc_timeout;
	static ios::descriptor desc_wait[4];
	static ios::descriptor desc_write;           // for cb interface only
	static ios::descriptor desc_read;            // for cb interface only
	static thread_local socket *this_sock;       // desc allocator's hint

	uint64_t id {++count};
	ip::tcp::socket sd;
	std::optional<ssl_stream> ssl;
	endpoint local, remote;
	stat in, out;
	deadline_timer timer;
	uint64_t timer_sem[2] {0};                   // handler, sender
	char alpn[12] {0};
	bool timer_set {false};                      // boolean lockout
	bool timedout {false};
	bool fini {false};
	mutable bool _nodelay {false};               // userspace tracking only
	unique_mutable_buffer desc_buf_timeout[2];   // desc_timeout's alloc
	unique_mutable_buffer desc_buf_wait[4];      // desc_wait's alloc
	unique_mutable_buffer desc_buf_write;        // desc_write's alloc
	unique_mutable_buffer desc_buf_read;         // desc_read's alloc

	static void *desc_alloc(ios::handler &, const size_t &, unique_mutable_buffer &);
	static void desc_dealloc(ios::handler &, void *const &, const size_t &) noexcept;
	void call_user(const handler &, const error_code &, size_t) noexcept;
	void call_user(const eptr_handler &, const error_code &) noexcept;
	void call_user(const ec_handler &, const error_code &) noexcept;
	bool handle_verify(bool, asio::ssl::verify_context &, const open_opts &) noexcept;
	void handle_disconnect(std::shared_ptr<socket>, eptr_handler, error_code) noexcept;
	void handle_handshake(std::weak_ptr<socket>, eptr_handler, error_code) noexcept;
	void handle_connect(std::weak_ptr<socket>, const open_opts &, eptr_handler, error_code) noexcept;
	void handle_timeout(std::shared_ptr<socket>, ec_handler, error_code) noexcept;
	void handle_ready(std::weak_ptr<socket>, ready, ec_handler, error_code) noexcept;
	void handle_write(std::weak_ptr<socket>, handler, error_code, size_t) noexcept;

  public:
	operator const ip::tcp::socket &() const     { return sd;                                      }
	operator ip::tcp::socket &()                 { return sd;                                      }
	operator const SSL &() const;
	operator SSL &();

	// Timer for this socket
	void set_timeout(const milliseconds &, ec_handler);
	void set_timeout(const milliseconds &);
	milliseconds cancel_timeout() noexcept;
	bool cancel() noexcept;

	void disconnect(const close_opts &, eptr_handler);
	void handshake(const open_opts &, eptr_handler);
	void connect(const endpoint &, const open_opts &, eptr_handler);

	socket(asio::ssl::context &);
	socket();
	socket(socket &&) = delete;
	socket(const socket &) = delete;
	socket &operator=(socket &&) = delete;
	socket &operator=(const socket &) = delete;
	~socket() noexcept;
};

inline void
ircd::net::socket::set_timeout(const milliseconds &t)
{
	set_timeout(t, nullptr);
}

inline ircd::net::socket::operator
SSL &()
{
	assert(ssl);
	assert(ssl->native_handle());
	return *ssl->native_handle();
}

inline ircd::net::socket::operator
const SSL &()
const
{
	auto &ssl(mutable_cast(this)->ssl);

	assert(ssl);
	assert(ssl->native_handle());
	return *ssl->native_handle();
}
