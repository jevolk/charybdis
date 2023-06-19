// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

namespace ircd::net
{
	ctx::dock dock;
	std::optional<dns::init> _dns_;

	static void init_ipv6();
	static void wait_close_sockets();
}

void
ircd::net::wait_close_sockets()
{
	while(socket::instances)
		if(!dock.wait_for(seconds(2)))
			log::warning
			{
				log, "Waiting for %zu sockets to destruct",
				socket::instances
			};
}

void
ircd::net::init_ipv6()
{
	if(!enable_ipv6)
	{
		log::warning
		{
			log, "IPv6 is disabled by the configuration."
			" Not checking for usable interfaces."
		};
		return;
	}

	if(!addrs::has_usable_ipv6_interface())
	{
		log::dwarning
		{
			log, "No usable IPv6 interfaces detected."
		};

		enable_ipv6.set("false");
		return;
	}

	log::info
	{
		log, "Detected usable IPv6 interfaces."
		" Server will query AAAA records and attempt IPv6 connections. If this"
		" is an error please set ircd.net.enable_ipv6 to false or start with -no6."
	};
}

///////////////////////////////////////////////////////////////////////////////
//
// init
//

/// Network subsystem initialization
ircd::net::init::init()
{
	init_ipv6();
	sslv23_client.set_verify_mode(asio::ssl::verify_peer);
	sslv23_client.set_default_verify_paths();
	_dns_.emplace();
}

/// Network subsystem shutdown
[[gnu::cold]]
ircd::net::init::~init()
noexcept
{
	_dns_.reset();
	wait_close_sockets();
	assert(!socket::this_sock);
}

///////////////////////////////////////////////////////////////////////////////
//
// net/net.h
//

decltype(ircd::net::eof)
ircd::net::eof
{
	make_error_code(boost::system::error_code
	{
		boost::asio::error::eof,
		boost::asio::error::get_misc_category()
	})
};

decltype(ircd::net::enable_ipv6)
ircd::net::enable_ipv6
{
	{ "name",     "ircd.net.enable_ipv6"  },
	{ "default",  true                    },
	{ "persist",  false                   },
};

/// Network subsystem log facility
decltype(ircd::net::log)
ircd::net::log
{
	"net", 'N'
};

ircd::string_view
ircd::net::peer_cert_der_sha256_b64(const mutable_buffer &buf,
                                    const socket &socket)
{
	char shabuf alignas(32) [sha256::digest_size];
	const auto hash
	{
		peer_cert_der_sha256(shabuf, socket)
	};

	return b64::encode_unpadded(buf, hash);
}

ircd::const_buffer
ircd::net::peer_cert_der_sha256(const mutable_buffer &buf,
                                const socket &socket)
{
	thread_local char derbuf[16384];

	sha256
	{
		buf, peer_cert_der(derbuf, socket)
	};

	return
	{
		data(buf), sha256::digest_size
	};
}

ircd::const_buffer
ircd::net::peer_cert_der(const mutable_buffer &buf,
                         const socket &socket)
{
	const SSL &ssl(socket);
	const X509 &cert
	{
		openssl::peer_cert(ssl)
	};

	return openssl::i2d(buf, cert);
}

ircd::string_view
ircd::net::loghead(const socket &socket)
{
	thread_local char buf[512];
	return loghead(buf, socket);
}

ircd::string_view
ircd::net::loghead(const mutable_buffer &out,
                   const socket &socket)
{
	char buf[2][128];
	return fmt::sprintf
	{
		out, "socket:%lu fd:%d local:%s remote:%s",
		id(socket),
		native_handle(socket),
		string(buf[0], local_ipport(socket)),
		string(buf[1], remote_ipport(socket)),
	};
}

ircd::net::ipport
ircd::net::remote_ipport(const socket &socket)
noexcept try
{
	if(!opened(socket))
		return {};

	const auto &ep(socket.remote);
	return make_ipport(ep);
}
catch(...)
{
	return {};
}

ircd::net::ipport
ircd::net::local_ipport(const socket &socket)
noexcept try
{
	if(!opened(socket))
		return {};

	const auto &ep(socket.local);
	return make_ipport(ep);
}
catch(...)
{
	return {};
}

[[gnu::hot]]
int
ircd::net::native_handle(const socket &socket)
noexcept try
{
	ip::tcp::socket &sd(mutable_cast(socket));
	return sd.lowest_layer().native_handle();
}
catch(...)
{
	return -1;
}

[[gnu::hot]]
bool
ircd::net::opened(const socket &socket)
noexcept try
{
	const ip::tcp::socket &sd(socket);
	return sd.is_open();
}
catch(...)
{
	return false;
}

[[gnu::hot]]
uint64_t
ircd::net::id(const socket &socket)
noexcept
{
	return socket.id;
}

///////////////////////////////////////////////////////////////////////////////
//
// net/write.h
//

void
ircd::net::flush(socket &socket)
{
	if(nodelay(socket))
		return;

	nodelay(socket, true);
	nodelay(socket, false);
}

/// Callback after everything is sent.
void
ircd::net::write_all(socket &socket,
                     const vector_view<const const_buffer> &bufs,
                     write_handler &&callback)
try
{
	assert(!socket.fini);
	auto &desc
	{
		socket.desc_write
	};

	auto handle
	{
		std::bind(&socket::handle_write, &socket, weak_from(socket), std::move(callback), ph::_1, ph::_2)
	};

	auto candle
	{
		asio::bind_cancellation_slot(socket.cancel_write.slot(), ios::handle(desc, std::move(handle)))
	};

	assert(!socket::this_sock);
	const scope_restore desc_sock
	{
		socket::this_sock, &socket
	};

	if(socket.ssl)
		asio::async_write(*socket.ssl, bufs, candle);
	else
		asio::async_write(socket.sd, bufs, candle);
}
catch(const boost::system::system_error &e)
{
	assert(false);
	throw_system_error(e);
}

/// Callback after as much as possible is sent.
void
ircd::net::write_few(socket &socket,
                     const vector_view<const const_buffer> &bufs,
                     write_handler &&callback)
try
{
	assert(!socket.fini);
	auto &desc
	{
		socket.desc_write
	};

	auto handle
	{
		std::bind(&socket::handle_write, &socket, weak_from(socket), std::move(callback), ph::_1, ph::_2)
	};

	auto candle
	{
		asio::bind_cancellation_slot(socket.cancel_write.slot(), ios::handle(desc, std::move(handle)))
	};

	assert(!socket::this_sock);
	const scope_restore desc_sock
	{
		socket::this_sock, &socket
	};

	if(socket.ssl)
		socket.ssl->async_write_some(bufs, candle);
	else
		socket.sd.async_write_some(bufs, candle);
}
catch(const boost::system::system_error &e)
{
	assert(false);
	throw_system_error(e);
}

/// Yields ircd::ctx until all buffers are sent.
///
/// This is blocking behavior; use this if the following are true:
///
/// * You put a timer on the socket so if the remote slows us down the data
/// will not occupy the daemon's memory for a long time. Remember, *all* of
/// the data will be sitting in memory even after some of it was ack'ed by
/// the remote.
///
/// * You are willing to dedicate the ircd::ctx to sending all the data to
/// the remote. The ircd::ctx will be yielding until everything is sent.
///
size_t
ircd::net::write_all(socket &socket,
                     const vector_view<const const_buffer> &bufs)
try
{
	static const auto completion
	{
		asio::transfer_all()
	};

	assert(!socket.fini);
	assert(!blocking(socket));
	const auto interruption{[&socket]
	(ctx::ctx *const &) noexcept
	{
		socket.cancel();
	}};

	size_t ret{};
	continuation
	{
		continuation::asio_predicate, interruption, [&socket, &ret, &bufs]
		(auto &yield)
		{
			ret = socket.ssl?
				asio::async_write(*socket.ssl, bufs, completion, yield):
				asio::async_write(socket.sd, bufs, completion, yield);
		}
	};

	++socket.out.calls;
	socket.out.bytes += ret;
	++sock_stat::total_calls_out;
	sock_stat::total_bytes_out += ret;
	return ret;
}
catch(const boost::system::system_error &e)
{
	throw_system_error(e);
}

/// Yields ircd::ctx until at least some buffers are sent.
///
/// This is blocking behavior; use this if the following are true:
///
/// * You put a timer on the socket so if the remote slows us down the data
/// will not occupy the daemon's memory for a long time.
///
/// * You are willing to dedicate the ircd::ctx to sending the data to
/// the remote. The ircd::ctx will be yielding until the kernel has at least
/// some space to consume at least something from the supplied buffers.
///
size_t
ircd::net::write_few(socket &socket,
                     const vector_view<const const_buffer> &bufs)
try
{
	assert(!socket.fini);
	assert(!blocking(socket));
	const auto interruption{[&socket]
	(ctx::ctx *const &) noexcept
	{
		socket.cancel();
	}};

	size_t ret{};
	continuation
	{
		continuation::asio_predicate, interruption, [&socket, &ret, &bufs]
		(auto &yield)
		{
			ret = socket.ssl?
				socket.ssl->async_write_some(bufs, yield):
				socket.sd.async_write_some(bufs, yield);
		}
	};

	++socket.out.calls;
	socket.out.bytes += ret;
	++sock_stat::total_calls_out;
	sock_stat::total_bytes_out += ret;
	return ret;
}
catch(const boost::system::system_error &e)
{
	throw_system_error(e);
}

/// Writes as much as possible until one of the following is true:
///
/// * The kernel buffer for the socket is full.
/// * The user buffer is exhausted.
///
/// This is non-blocking behavior. No yielding will take place; no timer is
/// needed. Multiple syscalls will be composed to fulfill the above points.
///
size_t
ircd::net::write_any(socket &socket,
                     const vector_view<const const_buffer> &bufs)
try
{
	static const auto completion
	{
		asio::transfer_all()
	};

	assert(!socket.fini);
	assert(!blocking(socket));
	const size_t ret
	{
		socket.ssl?
			asio::write(*socket.ssl, bufs, completion):
			asio::write(socket.sd, bufs, completion)
	};

	++socket.out.calls;
	socket.out.bytes += ret;
	++sock_stat::total_calls_out;
	sock_stat::total_bytes_out += ret;
	return ret;
}
catch(const boost::system::system_error &e)
{
	throw_system_error(e);
}

/// Writes one "unit" of data or less; never more. The size of that unit
/// is determined by the system. Less may be written if one of the following
/// is true:
///
/// * The kernel buffer for the socket is full.
/// * The user buffer is exhausted.
///
/// If neither are true, more can be written using additional calls;
/// alternatively, use other variants of write_ for that.
///
/// This is non-blocking behavior. No yielding will take place; no timer is
/// needed. Only one syscall will occur.
///
size_t
ircd::net::write_one(socket &socket,
                     const vector_view<const const_buffer> &bufs)
try
{
	assert(!socket.fini);
	assert(!blocking(socket));
	const size_t ret
	{
		socket.ssl?
			socket.ssl->write_some(bufs):
			socket.sd.write_some(bufs)
	};

	++socket.out.calls;
	socket.out.bytes += ret;
	++sock_stat::total_calls_out;
	sock_stat::total_bytes_out += ret;
	return ret;
}
catch(const boost::system::system_error &e)
{
	throw_system_error(e);
}

/// Bytes remaining for transmission (in the kernel)
size_t
ircd::net::writable(const socket &socket)
{
	const ssize_t write_bufsz
	(
		net::write_bufsz(socket)
	);

	const ssize_t flushing
	(
		net::flushing(socket)
	);

	assert(write_bufsz >= flushing);
	return std::max(write_bufsz - flushing, 0L);
}

/// Bytes buffered for transmission (in the kernel)
size_t
ircd::net::flushing(const socket &socket)
{
	const auto &fd
	{
		native_handle(socket)
	};

	long value(0);
	#ifdef TIOCOUTQ
		syscall(::ioctl, fd, TIOCOUTQ, &value);
	#else
		#warning "TIOCOUTQ is not defined on this platform."
	#endif

	return value;
}

///////////////////////////////////////////////////////////////////////////////
//
// net/read.h
//

namespace ircd::net
{
	static char discard_buffer[4096];
}

/// Yields ircd::ctx until len bytes have been received and discarded from the
/// socket.
///
size_t
ircd::net::discard_all(socket &socket,
                       const size_t &len)
{
	size_t remain{len}; while(remain)
	{
		const mutable_buffer mb
		{
			discard_buffer, std::min(remain, sizeof(discard_buffer))
		};

		remain -= read_all(socket, mb);
	}

	return len;
}

/// Non-blocking discard of up to len bytes. The amount of bytes discarded
/// is returned. Zero is only returned if len==0 because the EAGAIN is
/// thrown. If any bytes have been discarded any EAGAIN encountered in
/// this function's internal loop is not thrown, but used to exit the loop.
///
size_t
ircd::net::discard_any(socket &socket,
                       const size_t &len)
{
	size_t remain{len}; while(remain)
	{
		const mutable_buffer mb
		{
			discard_buffer, std::min(remain, sizeof(discard_buffer))
		};

		size_t read;
		if(!(read = read_one(socket, mb)))
			break;

		remain -= read;
	}

	return len - remain;
}

/// Yields ircd::ctx until buffers are full.
///
/// Use this only if the following are true:
///
/// * You know the remote has made a guarantee to send you a specific amount
/// of data.
///
/// * You put a timer on the socket so that if the remote runs short this
/// call doesn't hang the ircd::ctx forever, otherwise it will until cancel.
///
/// * You are willing to dedicate the ircd::ctx to just this operation for
/// that amount of time.
///
size_t
ircd::net::read_all(socket &socket,
                    const vector_view<const mutable_buffer> &bufs)
try
{
	static const auto completion
	{
		asio::transfer_all()
	};

	assert(!socket.fini);
	const auto interruption{[&socket]
	(ctx::ctx *const &) noexcept
	{
		socket.cancel();
	}};

	size_t ret{};
	continuation
	{
		continuation::asio_predicate, interruption, [&socket, &ret, &bufs]
		(auto &yield)
		{
			ret = socket.ssl?
				asio::async_read(*socket.ssl, bufs, completion, yield):
				asio::async_read(socket.sd, bufs, completion, yield);
		}
	};

	if(!ret)
		throw std::system_error
		{
			eof
		};

	++socket.in.calls;
	socket.in.bytes += ret;
	++sock_stat::total_calls_in;
	sock_stat::total_bytes_in += ret;
	return ret;
}
catch(const boost::system::system_error &e)
{
	throw_system_error(e);
}

/// Yields ircd::ctx until remote has sent at least one frame. The buffers may
/// be filled with any amount of data depending on what has accumulated.
///
/// Use this if the following are true:
///
/// * You know there is data to be read; you can do this asynchronously with
/// other features of the socket. Otherwise this will hang the ircd::ctx.
///
/// * You are willing to dedicate the ircd::ctx to just this operation,
/// which is non-blocking if data is known to be available, but may be
/// blocking if this call is made in the blind.
///
size_t
ircd::net::read_few(socket &socket,
                    const vector_view<const mutable_buffer> &bufs)
try
{
	assert(!socket.fini);
	const auto interruption{[&socket]
	(ctx::ctx *const &) noexcept
	{
		socket.cancel();
	}};

	size_t ret{};
	continuation
	{
		continuation::asio_predicate, interruption, [&socket, &ret, &bufs]
		(auto &yield)
		{
			ret = socket.ssl?
				socket.ssl->async_read_some(bufs, yield):
				socket.sd.async_read_some(bufs, yield);
		}
	};

	if(!ret)
		throw std::system_error
		{
			eof
		};

	++socket.in.calls;
	socket.in.bytes += ret;
	++sock_stat::total_calls_in;
	sock_stat::total_bytes_in += ret;
	return ret;
}
catch(const boost::system::system_error &e)
{
	throw_system_error(e);
}

/// Reads as much as possible. Non-blocking behavior.
///
/// This is intended for lowest-level/custom control and not preferred by
/// default for most users on an ircd::ctx.
///
size_t
ircd::net::read_any(socket &socket,
                    const vector_view<const mutable_buffer> &bufs)
{
	static const auto completion
	{
		asio::transfer_all()
	};

	assert(!socket.fini);
	assert(!blocking(socket));
	boost::system::error_code ec;
	const size_t ret
	{
		socket.ssl?
			asio::read(*socket.ssl, bufs, completion, ec):
			asio::read(socket.sd, bufs, completion, ec)
	};

	++socket.in.calls;
	socket.in.bytes += ret;
	++sock_stat::total_calls_in;
	sock_stat::total_bytes_in += ret;

	if(likely(!ec))
		return ret;

	if(ec == boost::system::errc::resource_unavailable_try_again)
		return ret;

	throw_system_error(ec);
	__builtin_unreachable();
}

/// Reads one message or less in a single syscall. Non-blocking behavior.
///
/// This is intended for lowest-level/custom control and not preferred by
/// default for most users on an ircd::ctx.
///
size_t
ircd::net::read_one(socket &socket,
                    const vector_view<const mutable_buffer> &bufs)
{
	assert(!socket.fini);
	assert(!blocking(socket));
	boost::system::error_code ec;
	const size_t ret
	{
		socket.ssl?
			socket.ssl->read_some(bufs, ec):
			socket.sd.read_some(bufs, ec)
	};

	++socket.in.calls;
	socket.in.bytes += ret;
	++sock_stat::total_calls_in;
	sock_stat::total_bytes_in += ret;

	if(likely(!ec))
		return ret;

	if(ec == boost::system::errc::resource_unavailable_try_again)
		return ret;

	throw_system_error(ec);
	__builtin_unreachable();
}

/// Bytes available for reading (SSL; w/ fallback).
/// @returns 0 for socket errors, unsupported, or nothing available.
size_t
ircd::net::pending(const socket &socket)
noexcept
{
	if(!socket.ssl)
		return available(socket);

	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		return SSL_pending(mutable_cast(socket).ssl->native_handle());
	#else
		return 0;
	#endif
}

/// Bytes available for reading (userspace)
size_t
ircd::net::available(const socket &socket)
noexcept
{
	const ip::tcp::socket &sd(socket);
	boost::system::error_code ec;
	return sd.available(ec);
}

/// Bytes available for reading (kernel)
size_t
ircd::net::readable(const socket &socket)
{
	ip::tcp::socket::bytes_readable command{true};
	ip::tcp::socket &sd(mutable_cast(socket));
	sd.io_control(command);
	return command.get();
}

///////////////////////////////////////////////////////////////////////////////
//
// net/check.h
//

void
ircd::net::check(socket &socket,
                 const ready &type)
{
	const error_code ec
	{
		check(std::nothrow, socket, type)
	};

	if(likely(!ec))
		return;

	throw_system_error(ec);
	__builtin_unreachable();
}

std::error_code
ircd::net::check(std::nothrow_t,
                 socket &socket,
                 const ready &type)
noexcept
{
	static const size_t bufsz{64};
	static auto &buf{net::discard_buffer};
	static_assert(sizeof(buf) >= bufsz);

	if(!socket.sd.is_open())
		return make_error_code(std::errc::bad_file_descriptor);

	if(socket.fini)
		return make_error_code(std::errc::not_connected);

	std::error_code ret;
	if(socket.ssl && SSL_peek(socket.ssl->native_handle(), buf, bufsz) > 0)
		return ret;

	assert(!blocking(socket));
	boost::system::error_code ec;
	const std::array<mutable_buffer, 1> bufs
	{
		mutable_buffer{buf, bufsz}
	};

	if(socket.sd.receive(bufs, socket.sd.message_peek, ec) > 0)
	{
		assert(!ec.value());
		return ret;
	}

	if(ec.value())
		ret = make_error_code(ec);
	else
		ret = eof;

	if(ret == std::errc::resource_unavailable_try_again)
		ret = {};

	return ret;
}

///////////////////////////////////////////////////////////////////////////////
//
// net/wait.h
//

namespace ircd::net
{
	static asio::ip::tcp::socket::wait_type translate(const ready &) noexcept;
}

decltype(ircd::net::wait_opts_default)
ircd::net::wait_opts_default;

/// Wait for socket to become "ready" using a ctx::future.
ircd::ctx::future<void>
ircd::net::wait(use_future_t,
                socket &socket,
                const wait_opts &wait_opts)
{
	ctx::promise<void> p;
	ctx::future<void> f{p};
	wait(socket, wait_opts, [p(std::move(p))]
	(std::exception_ptr eptr)
	mutable
	{
		if(eptr)
			p.set_exception(std::move(eptr));
		else
			p.set_value();
	});

	return f;
}

/// Wait for socket to become "ready"; yields ircd::ctx returning code.
std::error_code
ircd::net::wait(nothrow_t,
                socket &socket,
                const wait_opts &wait_opts)
try
{
	wait(socket, wait_opts);
	return {};
}
catch(const std::system_error &e)
{
	return e.code();
}

/// Wait for socket to become "ready"; yields ircd::ctx; throws errors.
void
ircd::net::wait(socket &socket,
                const wait_opts &wait_opts)
try
{
	assert(!socket.fini);
	const auto interruption{[&socket]
	(ctx::ctx *const &) noexcept
	{
		socket.cancel();
	}};

	const scope_timeout timeout
	{
		socket, wait_opts.timeout
	};

	const auto wait_cond
	{
		translate(wait_opts.type)
	};

	continuation
	{
		continuation::asio_predicate, interruption, [&socket, &wait_cond]
		(auto &yield)
		{
			socket.sd.async_wait(wait_cond, yield);
		}
	};
}
catch(const boost::system::system_error &e)
{
	if(e.code() == boost::system::errc::operation_canceled && socket.timedout)
		throw_system_error(std::errc::timed_out);

	throw_system_error(e);
}

/// Wait for socket to become "ready"; callback with exception_ptr
void
ircd::net::wait(socket &socket,
                const wait_opts &wait_opts,
                wait_callback_eptr callback)
{
	wait(socket, wait_opts, [callback(std::move(callback))]
	(const error_code &ec)
	{
		if(likely(!ec))
			return callback(std::exception_ptr{});

		callback(make_system_eptr(ec));
	});
}

void
ircd::net::wait(socket &socket,
                const wait_opts &wait_opts,
                wait_callback_ec callback)
try
{
	auto &desc
	{
		socket.desc_wait[int(wait_opts.type)]
	};

	auto handle
	{
		std::bind
		(
			&socket::handle_ready,
			&socket,
			weak_from(socket),
			wait_opts.type,
			std::move(callback),
			ph::_1
		)
	};

	assert(!socket.fini);
	socket.set_timeout(wait_opts.timeout);
	const unwind_exceptional unset{[&socket]
	{
		socket.cancel_timeout();
	}};

	assert(!socket::this_sock);
	const scope_restore desc_sock
	{
		socket::this_sock, &socket
	};

	if(wait_opts.type == ready::READ)
	{
		// The problem here is that waiting on the sd doesn't account for bytes
		// read into SSL that we didn't consume yet. If something is stuck in
		// those userspace buffers, the socket won't know about it and perform
		// the wait. ASIO should fix this by adding a ssl::stream.wait() method
		// which will bail out immediately in this case before passing up to the
		// real socket wait.
		static const size_t bufsz{64};
		static auto &buf{net::discard_buffer};
		static_assert(sizeof(buf) >= bufsz);
		if(socket.ssl && SSL_peek(socket.ssl->native_handle(), buf, bufsz) > 0)
		{
			ircd::dispatch
			{
				desc, ios::defer, [handle(std::move(handle))]
				{
					handle(error_code{});
				}
			};

			return;
		}

		const std::array<mutable_buffer, 1> bufs
		{
			mutable_buffer{buf, bufsz}
		};

		// The problem here is that the wait operation gives ec=success on both a
		// socket error and when data is actually available. We then have to check
		// using a non-blocking peek in the handler. By doing it this way here we
		// just get the error in the handler's ec.
		//sd.async_wait(bufs, sd.message_peek, ios::handle(desc_wait[1], [handle(std::move(handle))]
		socket.sd.async_receive(bufs, socket.sd.message_peek, ios::handle
		{
			desc, [handle(std::move(handle))]
			(const auto &ec, const size_t bytes)
			{
				handle
				(
					!ec && bytes?
						error_code{}:
					!ec && !bytes?
						net::eof:
						make_error_code(ec)
				);
			}
		});

		return;
	}

	assert(wait_opts.type != ready::ANY);
	socket.sd.async_wait(translate(wait_opts.type), ios::handle
	{
		desc, std::move(handle)
	});
}
catch(const boost::system::system_error &e)
{
	throw_system_error(e);
}

boost::asio::ip::tcp::socket::wait_type
ircd::net::translate(const ready &ready)
noexcept
{
	using wait_type = asio::ip::tcp::socket::wait_type;

	switch(ready)
	{
		case ready::ANY:
			return wait_type::wait_read | wait_type::wait_write | wait_type::wait_error;

		case ready::READ:
			return wait_type::wait_read;

		case ready::WRITE:
			return wait_type::wait_write;

		case ready::ERROR:
			return wait_type::wait_error;
	}

	assert(0);
	__builtin_unreachable();
}

ircd::string_view
ircd::net::reflect(const ready &type)
{
	switch(type)
	{
		case ready::ANY:     return "ANY"_sv;
		case ready::READ:    return "READ"_sv;
		case ready::WRITE:   return "WRITE"_sv;
		case ready::ERROR:   return "ERROR"_sv;
	}

	return "????"_sv;
}

///////////////////////////////////////////////////////////////////////////////
//
// net/close.h
//

namespace ircd::net
{
	static asio::ip::tcp::socket::shutdown_type translate(const dc &) noexcept;
}

decltype(ircd::net::close_opts::default_timeout)
ircd::net::close_opts::default_timeout
{
	{ "name",     "ircd.net.close.timeout"  },
	{ "default",  7500L                     },
};

/// Static instance of default close options.
decltype(ircd::net::close_opts_default)
ircd::net::close_opts_default;

/// Static helper callback which may be passed to the callback-based overload
/// of close(). This callback does nothing.
ircd::net::close_callback
const ircd::net::close_ignore{[]
(std::exception_ptr eptr) noexcept
{
	return;
}};

ircd::ctx::future<void>
ircd::net::close(socket &s,
                 const dc &type)
{
	return close(s, close_opts
	{
		.type = type,
	});
}

ircd::ctx::future<void>
ircd::net::close(socket &socket,
                 const close_opts &opts)
{
	ctx::promise<void> p;
	ctx::future<void> f(p);
	close(socket, opts, [p(std::move(p))]
	(std::exception_ptr eptr)
	mutable
	{
		if(eptr)
			p.set_exception(std::move(eptr));
		else
			p.set_value();
	});

	return f;
}

void
ircd::net::close(socket &s,
                 const dc &type,
                 close_callback cb)
{
	const close_opts opts
	{
		.type = type,
	};

	return close(s, opts, std::move(cb));
}

void
ircd::net::close(socket &socket,
                 const close_opts &opts,
                 close_callback callback)
{
	socket.disconnect(opts, std::move(callback));
}

boost::asio::ip::tcp::socket::shutdown_type
ircd::net::translate(const dc &val)
noexcept
{
	using type = asio::ip::tcp::socket::shutdown_type;

	switch(val)
	{
		case dc::SSL_NOTIFY:  assert(0); [[fallthrough]];
		case dc::RST:         assert(0); [[fallthrough]];
		case dc::FIN:
			return type::shutdown_both;

		case dc::FIN_SEND:
			return type::shutdown_send;

		case dc::FIN_RECV:
			return type::shutdown_receive;
	}

	assert(0);
	__builtin_unreachable();
}

ircd::string_view
ircd::net::reflect(const dc type)
noexcept
{
	switch(type)
	{
		case dc::RST:         return "RST";
		case dc::FIN:         return "FIN";
		case dc::FIN_SEND:    return "FIN_SEND";
		case dc::FIN_RECV:    return "FIN_RECV";
		case dc::SSL_NOTIFY:  return "SSL_NOTIFY";
	}

	return "????"_sv;
}

///////////////////////////////////////////////////////////////////////////////
//
// net/open.h
//

decltype(ircd::net::open_opts::default_connect_timeout)
ircd::net::open_opts::default_connect_timeout
{
	{ "name",     "ircd.net.open.connect_timeout"  },
	{ "default",  7500L                            },
};

decltype(ircd::net::open_opts::default_handshake_timeout)
ircd::net::open_opts::default_handshake_timeout
{
	{ "name",     "ircd.net.open.handshake_timeout"  },
	{ "default",  7500L                              },
};

decltype(ircd::net::open_opts::default_verify_certificate)
ircd::net::open_opts::default_verify_certificate
{
	{ "name",     "ircd.net.open.verify_certificate"  },
	{ "default",  true                                },
};

decltype(ircd::net::open_opts::default_allow_self_signed)
ircd::net::open_opts::default_allow_self_signed
{
	{ "name",     "ircd.net.open.allow_self_signed"  },
	{ "default",  false                              },
};

decltype(ircd::net::open_opts::default_allow_self_chain)
ircd::net::open_opts::default_allow_self_chain
{
	{ "name",     "ircd.net.open.allow_self_chain"  },
	{ "default",  false                             },
};

decltype(ircd::net::open_opts::default_allow_expired)
ircd::net::open_opts::default_allow_expired
{
	{ "name",     "ircd.net.open.allow_expired"  },
	{ "default",  false                          },
};

/// Open new socket with future-based report.
///
ircd::ctx::future<std::shared_ptr<ircd::net::socket>>
ircd::net::open(const open_opts &opts)
{
	ctx::promise<std::shared_ptr<socket>> p;
	ctx::future<std::shared_ptr<socket>> f(p);
	auto s
	{
		opts.secure?
			std::make_shared<socket>(sslv23_client):
			std::make_shared<socket>()
	};

	open(*s, opts, [s, p(std::move(p))]
	(std::exception_ptr eptr)
	mutable
	{
		if(eptr)
			p.set_exception(std::move(eptr));
		else
			p.set_value(s);
	});

	return f;
}

/// Open existing socket with callback-based report.
///
std::shared_ptr<ircd::net::socket>
ircd::net::open(const open_opts &opts,
                open_callback handler)
{
	auto s
	{
		opts.secure?
			std::make_shared<socket>(sslv23_client):
			std::make_shared<socket>()
	};

	open(*s, opts, std::move(handler));
	return s;
}

/// Open existing socket with callback-based report.
///
void
ircd::net::open(socket &socket,
                const open_opts &opts,
                open_callback handler)
{
	auto complete{[s(shared_from(socket)), handler(std::move(handler))]
	(std::exception_ptr eptr)
	{
		if(eptr && !s->fini)
			close(*s, dc::RST, close_ignore);

		handler(std::move(eptr));
	}};

	const dns::callback_ipport connector{[&socket, opts, complete(std::move(complete))]
	(std::exception_ptr eptr, const hostport &hp, const ipport &ipport)
	{
		if(eptr)
			return complete(std::move(eptr));

		const auto ep{make_endpoint(ipport)};
		socket.connect(ep, opts, std::move(complete));
	}};

	if(!opts.ipport)
		dns::resolve(opts.hostport, dns::opts_default, std::move(connector));
	else
		connector({}, opts.hostport, opts.ipport);
}

///////////////////////////////////////////////////////////////////////////////
//
// net/sopts.h
//

/// Construct sock_opts with the current options from socket argument
ircd::net::sock_opts::sock_opts(const socket &socket)
:v6only{net::v6only(socket)}
,blocking{net::blocking(socket)}
,nopush{net::nopush(socket)}
,nodelay{net::nodelay(socket)}
,quickack{net::quickack(socket)}
,keepalive{net::keepalive(socket)}
,linger{net::linger(socket)}
,read_bufsz{net::read_bufsz(socket)}
,write_bufsz{net::write_bufsz(socket)}
,read_lowat{net::read_lowat(socket)}
,write_lowat{net::write_lowat(socket)}
,ebpf{net::attach(socket)}
,iptos{net::iptos(socket)}
,priority{net::priority(socket)}
,affinity{net::affinity(socket)}
,pmtudisc{net::pmtudisc(socket)}
,pmtu{net::pmtu(socket)}
,tstamp{net::tstamp(socket)}
{
}

[[gnu::weak]]
bool
ircd::net::sock_opts::enable_tstamp()
noexcept
{
	return false;
}

/// Updates the socket with provided options. Defaulted / -1'ed options are
/// ignored for updating.
void
ircd::net::set(socket &socket,
               const sock_opts &opts)
{
	if(opts.v6only != opts.IGN)
		net::v6only(socket, opts.v6only);

	if(opts.blocking != opts.IGN)
		net::blocking(socket, opts.blocking);

	if(opts.nopush != opts.IGN)
		net::nopush(socket, opts.nopush);

	if(opts.nodelay != opts.IGN)
		net::nodelay(socket, opts.nodelay);

	if(opts.quickack != opts.IGN)
		net::quickack(socket, opts.quickack);

	if(opts.keepalive != opts.IGN)
		net::keepalive(socket, opts.keepalive);

	if(opts.linger != opts.IGN)
		net::linger(socket, opts.linger);

	if(opts.read_bufsz != opts.IGN)
		net::read_bufsz(socket, opts.read_bufsz);

	if(opts.write_bufsz != opts.IGN)
		net::write_bufsz(socket, opts.write_bufsz);

	if(opts.read_lowat != opts.IGN)
		net::read_lowat(socket, opts.read_lowat);

	if(opts.write_lowat != opts.IGN)
		net::write_lowat(socket, opts.write_lowat);

	if(opts.ebpf != opts.IGN)
		net::attach(socket, opts.ebpf);

	if(opts.iptos != opts.IGN)
		net::iptos(socket, opts.iptos);

	if(opts.priority != opts.IGN)
		net::priority(socket, opts.priority);

	if(opts.affinity != opts.IGN)
		net::affinity(socket, opts.affinity);

	if(opts.pmtudisc != opts.IGN)
		net::pmtudisc(socket, opts.pmtudisc);

	if(opts.tstamp != opts.IGN)
		net::tstamp(socket, opts.tstamp);
}

bool
ircd::net::tstamp(socket &socket,
                  const int val)
#if defined(SO_TIMESTAMPING) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	sys::call(::setsockopt, fd, SOL_SOCKET, SO_TIMESTAMPING, &val, sizeof(val));
	return true;
}
#else
{
	#warning "SO_TIMESTAMPING is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::pmtudisc(socket &socket,
                    const int val)
#if defined(IP_MTU_DISCOVER) && defined(IPPROTO_IP)
{
	const auto &fd
	{
		native_handle(socket)
	};

	sys::call(::setsockopt, fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
	return true;
}
#else
{
	#warning "IP_MTU_DISCOVER is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::affinity(socket &socket,
                    const int cpu)
#if defined(SO_INCOMING_CPU) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	sys::call(::setsockopt, fd, SOL_SOCKET, SO_INCOMING_CPU, &cpu, sizeof(cpu));
	return true;
}
#else
{
	#warning "SO_INCOMING_CPU is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::priority(socket &socket,
                    const int prio)
#if defined(SO_PRIORITY) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	sys::call(::setsockopt, fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	return true;
}
#else
{
	#warning "SO_PRIORITY is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::iptos(socket &socket,
                 const int tos)
#if defined(IP_TOS) && defined(IPPROTO_IP)
{
	const auto &fd
	{
		native_handle(socket)
	};

	sys::call(::setsockopt, fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
	return true;
}
#else
{
	#warning "IP_TOS is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::detach(socket &socket,
                  const int prog_fd)
{
	const auto &fd
	{
		native_handle(socket)
	};

	detach(fd, prog_fd);
	return true;
}

bool
ircd::net::detach(const int sd,
                  const int prog_fd)
#if defined(SO_DETACH_BPF) && defined(SOL_SOCKET)
{
	const socklen_t len(sizeof(prog_fd));
	sys::call(::setsockopt, sd, SOL_SOCKET, SO_DETACH_BPF, &prog_fd, len);
	return true;
}
#else
{
	#warning "SO_DETACH_BPF is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::attach(socket &socket,
                  const int prog_fd)
{
	const auto &fd
	{
		native_handle(socket)
	};

	attach(fd, prog_fd);
	return true;
}

bool
ircd::net::attach(const int sd,
                  const int prog_fd)
#if defined(SO_ATTACH_BPF) && defined(SOL_SOCKET)
{
	const socklen_t len(sizeof(prog_fd));
	sys::call(::setsockopt, sd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, len);
	return true;
}
#else
{
	#warning "SO_ATTACH_BPF is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::write_lowat(socket &socket,
                       const int bytes)
{
	assert(bytes <= std::numeric_limits<int>::max());
	const ip::tcp::socket::send_low_watermark option
	{
		int(bytes)
	};

	ip::tcp::socket &sd(socket);
	sd.set_option(option);
	return true;
}

bool
ircd::net::read_lowat(socket &socket,
                      const int bytes)
{
	assert(bytes <= std::numeric_limits<int>::max());
	const ip::tcp::socket::receive_low_watermark option
	{
		int(bytes)
	};

	ip::tcp::socket &sd(socket);
	sd.set_option(option);
	return true;
}

bool
ircd::net::write_bufsz(socket &socket,
                       const int bytes)
{
	assert(bytes <= std::numeric_limits<int>::max());
	const ip::tcp::socket::send_buffer_size option
	{
		int(bytes)
	};

	ip::tcp::socket &sd(socket);
	sd.set_option(option);
	return true;
}

bool
ircd::net::read_bufsz(socket &socket,
                      const int bytes)
{
	assert(bytes <= std::numeric_limits<int>::max());
	const ip::tcp::socket::receive_buffer_size option
	{
		int(bytes)
	};

	ip::tcp::socket &sd(socket);
	sd.set_option(option);
	return true;
}

bool
ircd::net::linger(socket &socket,
                  const int t)
{
	const ip::tcp::socket::linger option
	{
		t >= 0,                // ON / OFF boolean
		t >= 0? t : 0          // Uses 0 when OFF
	};

	ip::tcp::socket &sd(socket);
	sd.set_option(option);
	return true;
}

bool
ircd::net::keepalive(socket &socket,
                     const bool b)
{
	const ip::tcp::socket::keep_alive option{b};
	ip::tcp::socket &sd(socket);
	sd.set_option(option);
	return true;
}

bool
ircd::net::quickack(socket &socket,
                    const bool b)
#if defined(TCP_QUICKACK) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	const int val(b);
	const socklen_t len(sizeof(val));
	syscall(::setsockopt, fd, SOL_SOCKET, TCP_QUICKACK, &val, len);
	return true;
}
#else
{
	#warning "TCP_QUICKACK is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::nodelay(socket &socket,
                   const bool b)
{
	if(likely(nodelay(socket) != b))
		nodelay(socket, b, system);

	return true;
}

bool
ircd::net::nodelay(socket &socket,
                   const bool b,
                   system_t)
{
	const ip::tcp::no_delay option{b};
	ip::tcp::socket &sd(socket);
	sd.set_option(option);
	socket._nodelay = b;
	return true;
}

bool
ircd::net::nopush(socket &socket,
                  const bool b)
#if defined(TCP_CORK) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	const int val(b);
	const socklen_t len(sizeof(val));
	syscall(::setsockopt, fd, SOL_SOCKET, TCP_CORK, &val, len);
	return true;
}
#else
{
	#warning "TCP_CORK is not defined on this platform."
	return false;
}
#endif

/// Toggles the behavior of non-async asio calls.
///
/// This option affects very little in practice and only sets a flag in
/// userspace in asio, not an actual ioctl(2) (XXX this is not true anymore,
/// sd.non_blocking() and sd.native_non_blocking() both seem to ioctl(2)).
/// See below the deprecated section.
///
/// ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
/// * All sockets are already set by asio to FIONBIO=1 no matter what, thus
/// nothing really blocks the event loop ever by default unless you try hard.
///
/// * All asio::async_ and sd.async_ and ssl.async_ calls will always do what
/// the synchronous/blocking alternative would have accomplished but using
/// the async methodology. i.e if a buffer is full you will always wait
/// asynchronously: async_write() will wait for everything, async_write_some()
/// will wait for something, etc -- but there will never be true non-blocking
/// _effective behavior_ from these calls.
///
/// * All asio non-async calls conduct blocking by (on linux) poll()'ing the
/// socket to get a real kernel-blocking operation out of it (this is the
/// try-hard part).
///
/// This flag only controls the behavior of the last bullet. In practice,
/// in this project there is never a reason to ever set this to true,
/// however, sockets do get constructed by asio in blocking mode by default
/// so we mostly use this function to set it to non-blocking.
/// ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
///
/// The system_t overload is added to decide between native_non_blocking()
/// (with system_t) or non_blocking() (without system_t). These both set
/// different flags in asio but they both result in the same ioctl(FIONBIO)
/// probably due to third-party libraries flipping FIONBIO outside of asio's
/// knowledge and naive users complaining too much to the maintainer.
///
/// To deal with this we have added a query to the sd.non_blocking() getter
/// which AT LEAST FOR NOW only reads asio's flags without a syscall and
/// won't call the sd.non_blocking() setter if it's superfluous.
bool
ircd::net::blocking(socket &socket,
                    const bool b)
{
	ip::tcp::socket &sd(socket);
	if(likely(sd.non_blocking() == b))
		sd.non_blocking(!b);

	return true;
}

bool
ircd::net::blocking(socket &socket,
                    const bool b,
                    system_t)
{
	ip::tcp::socket &sd(socket);
	sd.native_non_blocking(!b);
	return true;
}

bool
ircd::net::v6only(socket &socket,
                  const bool b)
{
	const ip::v6_only option{b};
	ip::tcp::socket &sd(socket);
	sd.set_option(option);
	return true;
}

int
ircd::net::tstamp(const socket &socket)
#if defined(SO_TIMESTAMPING) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	int ret {-1};
	socklen_t len(sizeof(ret));
	sys::call(::getsockopt, fd, SOL_SOCKET, SO_TIMESTAMPING, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "SO_TIMESTAMPING is not defined on this platform."
	return -1;
}
#endif

int
ircd::net::pmtu(const socket &socket)
#if defined(IP_MTU) && defined(IPPROTO_IP)
{
	// This sockopt only works on connected sockets; throwing an exception
	// when querying at other times is a bit too much burden on our callsites.
	constexpr auto opts
	{
		sys::call::NOTHROW
	};

	const auto &fd
	{
		native_handle(socket)
	};

	int ret {-1};
	socklen_t len(sizeof(ret));
	sys::call<opts>(::getsockopt, fd, IPPROTO_IP, IP_MTU, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "IP_MTU is not defined on this platform."
	return -1;
}
#endif

int
ircd::net::pmtudisc(const socket &socket)
#if defined(IP_MTU_DISCOVER) && defined(IPPROTO_IP)
{
	const auto &fd
	{
		native_handle(socket)
	};

	int ret {-1};
	socklen_t len(sizeof(ret));
	sys::call(::getsockopt, fd, IPPROTO_IP, IP_MTU_DISCOVER, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "IP_MTU_DISCOVER is not defined on this platform."
	return -1;
}
#endif

int
ircd::net::affinity(const socket &socket)
#if defined(SO_INCOMING_CPU) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	int ret {-1};
	socklen_t len(sizeof(ret));
	sys::call(::getsockopt, fd, SOL_SOCKET, SO_INCOMING_CPU, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "SO_INCOMING_CPU is not defined on this platform."
	return -1;
}
#endif

int
ircd::net::priority(const socket &socket)
#if defined(SO_PRIORITY) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	int ret {-1};
	socklen_t len(sizeof(ret));
	sys::call(::getsockopt, fd, SOL_SOCKET, SO_PRIORITY, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "SO_PRIORITY is not defined on this platform."
	return -1;
}
#endif

int
ircd::net::iptos(const socket &socket)
#if defined(IP_TOS) && defined(IPPROTO_IP)
{
	const auto &fd
	{
		native_handle(socket)
	};

	int ret {-1};
	socklen_t len(sizeof(ret));
	sys::call(::getsockopt, fd, IPPROTO_IP, IP_TOS, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "IP_TOS is not defined on this platform."
	return -1;
}
#endif

int
ircd::net::attach(const socket &socket)
#if defined(SO_ATTACH_BPF) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	int ret {-1};
	socklen_t len(sizeof(ret));
	sys::call(::getsockopt, fd, SOL_SOCKET, SO_ATTACH_BPF, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "SO_ATTACH_BPF is not defined on this platform."
	return -1;
}
#endif

int
ircd::net::write_lowat(const socket &socket)
{
	const ip::tcp::socket &sd(socket);
	ip::tcp::socket::send_low_watermark option{};
	sd.get_option(option);
	return option.value();
}

int
ircd::net::read_lowat(const socket &socket)
{
	const ip::tcp::socket &sd(socket);
	ip::tcp::socket::receive_low_watermark option{};
	sd.get_option(option);
	return option.value();
}

int
ircd::net::write_bufsz(const socket &socket)
{
	const ip::tcp::socket &sd(socket);
	ip::tcp::socket::send_buffer_size option{};
	sd.get_option(option);
	return option.value();
}

int
ircd::net::read_bufsz(const socket &socket)
{
	const ip::tcp::socket &sd(socket);
	ip::tcp::socket::receive_buffer_size option{};
	sd.get_option(option);
	return option.value();
}

int
ircd::net::linger(const socket &socket)
{
	const ip::tcp::socket &sd(socket);
	ip::tcp::socket::linger option;
	sd.get_option(option);
	return option.enabled()? option.timeout() : -1;
}

bool
ircd::net::keepalive(const socket &socket)
{
	const ip::tcp::socket &sd(socket);
	ip::tcp::socket::keep_alive option;
	sd.get_option(option);
	return option.value();
}

bool
ircd::net::quickack(const socket &socket)
#if defined(TCP_QUICKACK) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	uint32_t ret;
	socklen_t len(sizeof(ret));
	syscall(::getsockopt, fd, SOL_SOCKET, TCP_QUICKACK, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "TCP_QUICKACK is not defined on this platform."
	return false;
}
#endif

bool
ircd::net::nodelay(const socket &socket,
                   system_t)
{
	const ip::tcp::socket &sd(socket);
	ip::tcp::no_delay option;
	sd.get_option(option);
	mutable_cast(socket)._nodelay = option.value();
	return socket._nodelay;
}

[[gnu::hot]]
bool
ircd::net::nodelay(const socket &socket)
{
	return socket._nodelay;
}

bool
ircd::net::nopush(const socket &socket)
#if defined(TCP_CORK) && defined(SOL_SOCKET)
{
	const auto &fd
	{
		native_handle(socket)
	};

	uint32_t ret;
	socklen_t len(sizeof(ret));
	syscall(::getsockopt, fd, SOL_SOCKET, TCP_CORK, &ret, &len);
	assert(len <= sizeof(ret));
	return ret;
}
#else
{
	#warning "TCP_CORK is not defined on this platform."
	return false;
}
#endif

[[gnu::hot]]
bool
ircd::net::blocking(const socket &socket)
{
	const ip::tcp::socket &sd(socket);
	return !sd.non_blocking();
}

[[gnu::hot]]
bool
ircd::net::blocking(const socket &socket,
                    system_t)
{
	const ip::tcp::socket &sd(socket);
	return !sd.native_non_blocking();
}

bool
ircd::net::v6only(const socket &socket)
{
	const ip::tcp::socket &sd(socket);
	ip::v6_only option;
	sd.get_option(option);
	return option.value();
}

///////////////////////////////////////////////////////////////////////////////
//
// net/sock_stat.h
//

decltype(ircd::net::sock_stat::total_bytes_in)
ircd::net::sock_stat::total_bytes_in
{
	{ "name", "ircd.net.socket.in.total.bytes"                      },
	{ "desc", "The total number of bytes received by all sockets"   },
};

decltype(ircd::net::sock_stat::total_bytes_out)
ircd::net::sock_stat::total_bytes_out
{
	{ "name", "ircd.net.socket.out.total.bytes"                     },
	{ "desc", "The total number of bytes received by all sockets"   },
};

decltype(ircd::net::sock_stat::total_calls_in)
ircd::net::sock_stat::total_calls_in
{
	{ "name", "ircd.net.socket.in.total.calls"                      },
	{ "desc", "The total number of read operations on all sockets"  },
};

decltype(ircd::net::sock_stat::total_calls_out)
ircd::net::sock_stat::total_calls_out
{
	{ "name", "ircd.net.socket.out.total.calls"                      },
	{ "desc", "The total number of write operations on all sockets"  },
};

[[gnu::hot]]
std::pair<ircd::net::sock_stat *, ircd::net::sock_stat *>
ircd::net::sock_stat::get(socket &socket)
noexcept
{
	return
	{
		&socket.in, &socket.out
	};
}

[[gnu::hot]]
std::pair<const ircd::net::sock_stat *, const ircd::net::sock_stat *>
ircd::net::sock_stat::get(const socket &socket)
noexcept
{
	return
	{
		&socket.in, &socket.out
	};
}

///////////////////////////////////////////////////////////////////////////////
//
// net/scope_timeout.h
//

ircd::net::scope_timeout::scope_timeout(socket &socket,
                                        const milliseconds &timeout)
:s
{
	timeout < 0ms? nullptr : &socket
}
{
	if(timeout < 0ms)
		return;

	socket.set_timeout(timeout);
}

ircd::net::scope_timeout::scope_timeout(socket &socket,
                                        const milliseconds &timeout,
                                        handler callback)
:s
{
	timeout < 0ms? nullptr : &socket
}
{
	if(timeout < 0ms)
		return;

	socket.set_timeout(timeout, [callback(std::move(callback))]
	(const error_code &ec)
	{
		const bool &timed_out{!ec}; // success = timeout
		callback(timed_out);
	});
}

ircd::net::scope_timeout::scope_timeout(scope_timeout &&other)
noexcept
:s{std::move(other.s)}
{
	other.s = nullptr;
}

ircd::net::scope_timeout &
ircd::net::scope_timeout::operator=(scope_timeout &&other)
noexcept
{
	this->~scope_timeout();
	s = std::move(other.s);
	other.s = nullptr;
	return *this;
}

ircd::net::scope_timeout::~scope_timeout()
noexcept
{
	cancel();
}

bool
ircd::net::scope_timeout::cancel()
noexcept try
{
	if(!this->s)
		return false;

	auto *const s{this->s};
	this->s = nullptr;
	s->cancel_timeout();
	return true;
}
catch(const std::exception &e)
{
	log::error
	{
		log, "socket(%p) scope_timeout::cancel :%s",
		(const void *)s,
		e.what()
	};

	return false;
}

bool
ircd::net::scope_timeout::release()
{
	const auto s{this->s};
	this->s = nullptr;
	return s != nullptr;
}

///////////////////////////////////////////////////////////////////////////////
//
// net/socket.h
//

[[clang::always_destroy]]
decltype(ircd::net::ssl_curve_list)
ircd::net::ssl_curve_list
{
	{ "name",     "ircd.net.ssl.curve.list" },
	{ "default",  string_view{}             },
};

[[clang::always_destroy]]
decltype(ircd::net::ssl_cipher_list)
ircd::net::ssl_cipher_list
{
	{ "name",     "ircd.net.ssl.cipher.list" },
	{ "default",  string_view{}              },
};

[[clang::always_destroy]]
decltype(ircd::net::ssl_cipher_blacklist)
ircd::net::ssl_cipher_blacklist
{
	{ "name",     "ircd.net.ssl.cipher.blacklist" },
	{ "default",  string_view{}                   },
};

[[clang::always_destroy]]
[[gnu::visibility("hidden")]]
boost::asio::ssl::context
ircd::net::sslv23_client
{
	boost::asio::ssl::context::method::sslv23_client
};

decltype(ircd::net::socket::count)
ircd::net::socket::count;

decltype(ircd::net::socket::instances)
ircd::net::socket::instances;

thread_local
decltype(ircd::net::socket::this_sock)
ircd::net::socket::this_sock;

[[clang::always_destroy]]
decltype(ircd::net::socket::desc_connect)
ircd::net::socket::desc_connect
{
	"ircd.net.socket.connect"
};

[[clang::always_destroy]]
decltype(ircd::net::socket::desc_handshake)
ircd::net::socket::desc_handshake
{
	"ircd.net.socket.handshake"
};

[[clang::always_destroy]]
decltype(ircd::net::socket::desc_disconnect)
ircd::net::socket::desc_disconnect
{
	"ircd.net.socket.disconnect"
};

[[clang::always_destroy]]
decltype(ircd::net::socket::desc_timeout)
ircd::net::socket::desc_timeout
{
	"ircd.net.socket.timeout",
	[](ios::handler &handler, const size_t size) -> void *
	{
		assert(this_sock);
		const size_t bufs
		{
			util::size(this_sock->desc_buf_timeout)
		};

		// Ensure there aren't more timers in flight than we have buffers for.
		assert(this_sock->timer_sem[0] + bufs >= this_sock->timer_sem[1]);
		const size_t i
		{
			this_sock->timer_sem[1] % bufs
		};

		return desc_alloc(handler, size, this_sock->desc_buf_timeout[i]);
	},
	[](ios::handler &handler, void *const ptr, const size_t size)
	{
		desc_dealloc(handler, ptr, size);
	},
};

[[clang::always_destroy]]
decltype(ircd::net::socket::desc_wait)
ircd::net::socket::desc_wait
{
	{
		"ircd.net.socket.wait.ready.ANY",
		[](ios::handler &handler, const size_t size) -> void *
		{
			return desc_alloc(handler, size, this_sock->desc_buf_wait[int(ready::ANY)]);
		},
		[](ios::handler &handler, void *const ptr, const size_t size)
		{
			desc_dealloc(handler, ptr, size);
		},
	},
	{
		"ircd.net.socket.wait.ready.READ",
		[](ios::handler &handler, const size_t size) -> void *
		{
			return desc_alloc(handler, size, this_sock->desc_buf_wait[int(ready::READ)]);
		},
		[](ios::handler &handler, void *const ptr, const size_t size)
		{
			desc_dealloc(handler, ptr, size);
		},
	},
	{
		"ircd.net.socket.wait.ready.WRITE",
		[](ios::handler &handler, const size_t size) -> void *
		{
			return desc_alloc(handler, size, this_sock->desc_buf_wait[int(ready::WRITE)]);
		},
		[](ios::handler &handler, void *const ptr, const size_t size)
		{
			desc_dealloc(handler, ptr, size);
		},
	},
	{
		"ircd.net.socket.wait.ready.ERROR",
		[](ios::handler &handler, const size_t size) -> void *
		{
			return desc_alloc(handler, size, this_sock->desc_buf_wait[int(ready::ERROR)]);
		},
		[](ios::handler &handler, void *const ptr, const size_t size)
		{
			desc_dealloc(handler, ptr, size);
		},
	},
};

[[clang::always_destroy]]
decltype(ircd::net::socket::desc_write)
ircd::net::socket::desc_write
{
	"ircd.net.socket.write",
	[](ios::handler &handler, const size_t size) -> void *
	{
		return desc_alloc(handler, size, this_sock->desc_buf_write);
	},
	[](ios::handler &handler, void *const ptr, const size_t size)
	{
		desc_dealloc(handler, ptr, size);
	},
};

[[clang::always_destroy]]
decltype(ircd::net::socket::desc_read)
ircd::net::socket::desc_read
{
	"ircd.net.socket.read",
	[](ios::handler &handler, const size_t size) -> void *
	{
		return desc_alloc(handler, size, this_sock->desc_buf_read);
	},
	[](ios::handler &handler, void *const ptr, const size_t size)
	{
		desc_dealloc(handler, ptr, size);
	},
};

//
// socket::socket
//

ircd::net::socket::socket()
:sd
{
	ios::get()
}
,timer
{
	ios::get()
}
{
	++instances;
}

ircd::net::socket::socket(asio::ssl::context &ssl)
:sd
{
	ios::get()
}
,ssl
{
	std::in_place, this->sd, ssl
}
,timer
{
	ios::get()
}
{
	++instances;
}

/// The dtor asserts that the socket is not open/connected requiring a
/// an SSL close_notify. There's no more room for async callbacks via
/// shared_ptr after this dtor.
ircd::net::socket::~socket()
noexcept try
{
	assert(instances > 0);
	if(unlikely(--instances == 0))
		net::dock.notify_all();

	if(unlikely(opened(*this) || timer_set))
		throw panic
		{
			"socket:%lu fd:%d must be done before dtor; open:%b fini:%b timer:%b",
			this->id,
			native_handle(*this),
			opened(*this),
			fini,
			timer_set,
		};
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket(%p) close :%s",
		this,
		e.what(),
	};

	return;
}
catch(...)
{
	log::critical
	{
		log, "socket(%p) close :unexpected",
		this,
	};

	ircd::terminate();
}

void
ircd::net::socket::connect(const endpoint &ep,
                           const open_opts &opts,
                           eptr_handler callback)
{
	char epbuf[128];
	log::debug
	{
		log, "socket:%lu attempting connect remote[%s] to:%ld$ms",
		this->id,
		string(epbuf, ep),
		opts.connect_timeout.count()
	};

	auto connect_handler
	{
		std::bind(&socket::handle_connect, this, weak_from(*this), opts, std::move(callback), ph::_1)
	};

	this->remote = ep;
	set_timeout(opts.connect_timeout);

	assert(!this_sock);
	const scope_restore desc_sock
	{
		this_sock, this
	};

	sd.async_connect(ep, ios::handle(desc_connect, std::move(connect_handler)));
}

void
ircd::net::socket::handshake(const open_opts &opts,
                             eptr_handler callback)
{
	assert(!fini);
	assert(sd.is_open());
	assert(ssl);

	log::debug
	{
		log, "%s handshaking to '%s' for '%s' to:%ld$ms",
		loghead(*this),
		opts.send_sni?
			server_name(opts):
			"<no sni>"_sv,
		common_name(opts),
		opts.handshake_timeout.count()
	};

	auto handshake_handler
	{
		std::bind(&socket::handle_handshake, this, weak_from(*this), std::move(callback), ph::_1)
	};

	auto verify_handler
	{
		std::bind(&socket::handle_verify, this, ph::_1, ph::_2, opts)
	};

	assert(!fini);
	set_timeout(opts.handshake_timeout);

	if(opts.send_sni && server_name(opts))
		openssl::server_name(*this, server_name(opts));

	ssl->set_verify_callback(std::move(verify_handler));

	assert(!this_sock);
	const scope_restore desc_sock
	{
		this_sock, this
	};

	ssl->async_handshake(handshake_type::client, ios::handle(desc_handshake, std::move(handshake_handler)));
}

void
ircd::net::socket::disconnect(const close_opts &opts,
                              eptr_handler callback)
try
{
	if(!sd.is_open())
	{
		call_user(callback, {});
		return;
	}

	assert(!fini);
	log::debug
	{
		log, "%s disconnect type:%s shut:%s user[in:%zu out:%zu]",
		loghead(*this),
		reflect(opts.type),
		!ssl? reflect(opts.shutdown): "--"_sv,
		in.bytes,
		out.bytes
	};

	cancel();
	assert(!fini);
	fini = true;

	if(opts.sopts)
		set(*this, *opts.sopts);

	switch(opts.type)
	{
		case dc::RST:
			sd.close();
			break;

		case dc::FIN:
		case dc::FIN_SEND:
		case dc::FIN_RECV:
			sd.shutdown(translate(opts.type));
			break;

		case dc::SSL_NOTIFY:
		{
			if(!ssl)
			{
				// Redirect SSL_NOTIFY to another strategy for non-SSL sockets.
				if(opts.shutdown != dc::RST)
					sd.shutdown(translate(opts.shutdown));

				sd.close();
				break;
			}

			set_timeout(opts.timeout);
			auto disconnect_handler
			{
				std::bind(&socket::handle_disconnect, this, shared_from(*this), std::move(callback), ph::_1)
			};

			assert(!this_sock);
			const scope_restore desc_sock
			{
				this_sock, this
			};

			ssl->async_shutdown(ios::handle(desc_disconnect, std::move(disconnect_handler)));
			return;
		}
	}

	call_user(callback, {});
}
catch(const boost::system::system_error &e)
{
	log::derror
	{
		log, "socket:%lu disconnect type:%d :%s",
		this->id,
		uint(opts.type),
		e.what()
	};

	call_user(callback, make_error_code(e));
}
catch(const std::exception &e)
{
	throw panic
	{
		"socket:%lu disconnect: type: %d :%s",
		this->id,
		uint(opts.type),
		e.what()
	};
}

void
ircd::net::socket::handle_write(const std::weak_ptr<socket> wp,
                                const handler callback,
                                error_code ec,
                                const size_t bytes)
noexcept try
{
	using std::errc;

	const life_guard<socket> s{wp};
	assert(s.get() == this);

	if(unlikely(!ec && !sd.is_open()))
		ec = make_error_code(errc::bad_file_descriptor);

	if(unlikely(!ec && fini))
		ec = make_error_code(errc::not_connected);

	if(!ec && !bytes)
		ec = make_error_code(net::eof);

	if constexpr((false)) // manual debug; large nr syscalls
	{
		char ecbuf[64];
		log::debug
		{
			log, "%s wrote %s bytes:%zu",
			loghead(*this),
			string(ecbuf, ec),
			bytes,
		};
	}

	++out.calls;
	out.bytes += bytes;
	++sock_stat::total_calls_out;
	sock_stat::total_bytes_out += bytes;
	call_user(callback, ec, bytes);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket(%p) handle_write :%s",
		this,
		e.what()
	};

	const ctx::exception_handler eh;
	call_user(callback, ec, bytes);
}

void
ircd::net::socket::handle_ready(const std::weak_ptr<socket> wp,
                                const net::ready type,
                                const ec_handler callback,
                                error_code ec)
noexcept try
{
	using std::errc;

	// After life_guard is constructed it is safe to use *this in this frame.
	const life_guard<socket> s{wp};
	assert(s.get() == this);

	if(!timedout && !is(ec, errc::operation_canceled) && !fini)
		cancel_timeout();

	if(timedout && is(ec, errc::operation_canceled))
		ec = make_error_code(errc::timed_out);

	if(unlikely(!ec && !sd.is_open()))
		ec = make_error_code(errc::bad_file_descriptor);

	if(unlikely(!ec && fini))
		ec = make_error_code(errc::not_connected);

	if constexpr((false)) // manual debug; large nr syscalls
	{
		char ecbuf[64];
		log::debug
		{
			log, "%s ready %s %s avail:%zu:%zu",
			loghead(*this),
			reflect(type),
			string(ecbuf, ec),
			type == ready::READ? bytes : 0UL,
			type == ready::READ? pending(*this): 0UL,
		};
	}

	call_user(callback, ec);
}
catch(const std::bad_weak_ptr &e)
{
	// This handler may still be registered with asio after the socket destructs, so
	// the weak_ptr will indicate that fact. However, this is never intended and is
	// a debug assertion which should be corrected.
	log::warning
	{
		log, "socket(%p) belated callback to handler... (%s)",
		this,
		e.what()
	};

	assert(0);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket(%p) handle :%s",
		this,
		e.what()
	};

	const ctx::exception_handler eh;
	call_user(callback, ec);
}

void
ircd::net::socket::handle_timeout(const std::shared_ptr<socket> sp,
                                  const ec_handler callback,
                                  error_code ec)
noexcept try
{
	assert(sp.get() == this);

	// We increment our end of the timer semaphore. If the count is still
	// behind the other end of the semaphore, this callback was sitting in
	// the ios queue while the timer was given a new task; any effects here
	// will be erroneously bleeding into the next timeout. However the callback
	// is still invoked to satisfy each user's expectation for receiving it.
	assert(timer_sem[0] < timer_sem[1]);
	const bool sem_hit
	{
		++timer_sem[0] == timer_sem[1]
	};

	const bool hit
	{
		sem_hit && std::exchange(timer_set, false)
	};

	if(hit) switch(ec.value())
	{
		// A 'success' for this handler means there was a timeout on the socket
		case 0:
		{
			assert(timedout == false);
			timedout = true;
			sd.cancel();
			break;
		}

		// A cancelation means there was no timeout.
		[[likely]]
		case int(std::errc::operation_canceled):
		{
			assert(ec.category() == std::system_category());
			assert(timedout == false);
			break;
		}

		// All other errors are unexpected, logged and ignored here.
		[[unlikely]]
		default: throw panic
		{
			"socket(%p): unexpected :%s",
			(const void *)this,
			string(ec)
		};
	}
	else ec = make_error_code(std::errc::operation_canceled);

	if(callback)
		call_user(callback, ec);
}
catch(const boost::system::system_error &e)
{
	using std::errc;

	const auto ec_(e.code());
	if(system_category(ec_)) switch(ec_.value())
	{
		case int(errc::bad_file_descriptor):
		{
			if(fini)
				break;

			[[fallthrough]];
		}

		default:
		{
			assert(0);
			log::critical
			{
				log, "socket(%p) handle timeout :%s",
				(const void *)this,
				string(e)
			};

			break;
		}
	}

	if(callback)
	{
		const ctx::exception_handler eh;
		call_user(callback, ec_);
	}
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket(%p) handle timeout :%s",
		(const void *)this,
		e.what()
	};

	if(callback)
	{
		const ctx::exception_handler eh;
		call_user(callback, ec);
	}
}

void
ircd::net::socket::handle_connect(const std::weak_ptr<socket> wp,
                                  const open_opts &opts,
                                  const eptr_handler callback,
                                  error_code ec)
noexcept try
{
	using std::errc;

	const life_guard<socket> s{wp};
	assert(s.get() == this);

	if(likely(sd.is_open()))
		this->local = sd.local_endpoint();

	char ecbuf[64], epbuf[128];
	log::debug
	{
		log, "%s connect to %s :%s",
		loghead(*this),
		string(epbuf, opts.ipport),
		string(ecbuf, ec)
	};

	// The timer was set by socket::connect() and may need to be canceled.
	if(!timedout && !is(ec, errc::operation_canceled) && !fini)
		cancel_timeout();

	if(timedout && is(ec, errc::operation_canceled))
		ec = make_error_code(errc::timed_out);

	if(!ec && opts.handshake && fini)
		ec = make_error_code(errc::operation_canceled);

	// A connect error; abort here by calling the user back with error.
	if(ec)
		return call_user(callback, ec);

	// Try to set the user's socket options now; if something fails we can
	// invoke their callback with the error from the exception handler.
	if(opts.sopts && !fini)
		set(*this, *opts.sopts);

	// The user can opt out of performing the handshake here.
	if(!ssl || !opts.handshake)
	{
		blocking(*this, false);
		return call_user(callback, ec);
	}

	assert(!fini);
	handshake(opts, std::move(callback));
}
catch(const std::bad_weak_ptr &e)
{
	log::warning
	{
		log, "socket(%p) belated callback to handle_connect... (%s)",
		this,
		e.what()
	};

	assert(0);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket(%p) handle_connect :%s",
		this,
		e.what()
	};

	const ctx::exception_handler eh;
	call_user(callback, ec);
}

void
ircd::net::socket::handle_disconnect(const std::shared_ptr<socket> s,
                                     const eptr_handler callback,
                                     error_code ec)
noexcept try
{
	using std::errc;

	assert(s.get() == this);
	assert(fini);

	if(!timedout && ec != errc::operation_canceled)
		cancel_timeout();

	if(timedout && ec == errc::operation_canceled)
		ec = make_error_code(errc::timed_out);

	char ecbuf[64];
	log::debug
	{
		log, "%s disconnect %s",
		loghead(*this),
		string(ecbuf, ec)
	};

	// This ignores EOF and turns it into a success to alleviate user concern.
	if(ec == eof)
		ec = error_code{};

	sd.close();
	call_user(callback, ec);
}
catch(const boost::system::system_error &e)
{
	log::error
	{
		log, "socket(%p) disconnect :%s",
		this,
		e.what()
	};

	const auto code(e.code());
	const ctx::exception_handler eh;
	call_user(callback, code);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket(%p) disconnect :%s",
		this,
		e.what()
	};

	const ctx::exception_handler eh;
	call_user(callback, ec);
}

void
ircd::net::socket::handle_handshake(const std::weak_ptr<socket> wp,
                                    const eptr_handler callback,
                                    error_code ec)
noexcept try
{
	using std::errc;

	const life_guard<socket> s{wp};
	assert(s.get() == this);

	if(!timedout && ec != errc::operation_canceled && !fini)
		cancel_timeout();

	if(timedout && ec == errc::operation_canceled)
		ec = make_error_code(errc::timed_out);

	if constexpr(RB_DEBUG_LEVEL)
	{
		const auto *const current_cipher
		{
			!ec?
				openssl::current_cipher(*this):
				nullptr
		};

		char ecbuf[64];
		log::debug
		{
			log, "%s handshake cipher:%s %s",
			loghead(*this),
			current_cipher?
				openssl::name(*current_cipher):
				"<NO CIPHER>"_sv,
			string(ecbuf, ec)
		};
	}

	// Toggles the behavior of non-async functions; see func comment
	if(!ec)
		blocking(*this, false);

	// This is the end of the asynchronous call chain; the user is called
	// back with or without error here.
	call_user(callback, ec);
}
catch(const boost::system::system_error &e)
{
	log::error
	{
		log, "socket(%p) after handshake :%s",
		this,
		e.what()
	};

	const auto code(e.code());
	const ctx::exception_handler eh;
	call_user(callback, e.code());
}
catch(const std::bad_weak_ptr &e)
{
	log::warning
	{
		log, "socket(%p) belated callback to handle_handshake... (%s)",
		this,
		e.what()
	};

	assert(0);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket(%p) handle_handshake :%s",
		this,
		e.what()
	};

	const ctx::exception_handler eh;
	call_user(callback, ec);
}

bool
ircd::net::socket::handle_verify(const bool valid,
                                 asio::ssl::verify_context &vc,
                                 const open_opts &opts)
noexcept try
{
	// `valid` indicates whether or not there's an anomaly with the
	// certificate; if so, it is usually enumerated by the `switch()`
	// statement below. If `valid` is false, this function can return
	// true to still continue.

	// Socket ordered to shut down. We abort the verification here
	// to allow the open_opts out of scope with the user.
	if(fini || !sd.is_open())
		return false;

	// The user can set this option to bypass verification.
	if(!opts.verify_certificate)
		return true;

	// X509_STORE_CTX &
	assert(vc.native_handle());
	const auto &stctx{*vc.native_handle()};
	const auto &cert{openssl::current_cert(stctx)};
	const auto reject{[&stctx, &opts]
	{
		throw inauthentic
		{
			"%s #%ld: %s",
			common_name(opts),
			openssl::get_error(stctx),
			openssl::get_error_string(stctx)
		};
	}};

	if(!valid)
	{
		thread_local char buf[16_KiB];
		const critical_assertion ca;
		log::warning
		{
			log, "verify[%s] :%s :%s",
			common_name(opts),
			openssl::get_error_string(stctx),
			openssl::print_subject(buf, cert)
		};
	}

	const auto err
	{
		openssl::get_error(stctx)
	};

	if(!valid) switch(err)
	{
		[[unlikely]]
		case X509_V_OK:
			assert(0);
			[[fallthrough]];

		default:
			reject();
			__builtin_unreachable();

		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			assert(openssl::get_error_depth(stctx) == 0);
			if(opts.allow_self_signed)
				return true;

			reject();
			__builtin_unreachable();

		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			if(opts.allow_self_signed || opts.allow_self_chain)
				return true;

			reject();
			__builtin_unreachable();

		case X509_V_ERR_CERT_HAS_EXPIRED:
			if(opts.allow_expired)
				return true;

			reject();
			__builtin_unreachable();
	}

	const bool verify_common_name
	{
		opts.verify_common_name &&
		(opts.verify_self_signed_common_name && err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
	};

	if(verify_common_name)
	{
		if(unlikely(!common_name(opts)))
			throw inauthentic
			{
				"No common name specified in connection options"
			};

		boost::asio::ssl::rfc2818_verification verifier
		{
			common_name(opts)
		};

		if(!verifier(true, vc))
		{
			thread_local char buf[rfc1035::NAME_BUFSIZE];
			const critical_assertion ca;
			throw inauthentic
			{
				"/CN=%s does not match target host %s :%s",
				openssl::subject_common_name(buf, cert),
				common_name(opts),
				openssl::get_error_string(stctx)
			};
		}
	}

	if constexpr(RB_DEBUG_LEVEL)
	{
		thread_local char buf[16_KiB];
		const critical_assertion ca;
		log::debug
		{
			log, "verify[%s] %s",
			common_name(opts),
			openssl::print_subject(buf, cert)
		};
	}

	return true;
}
catch(const inauthentic &e)
{
	log::error
	{
		log, "Certificate rejected :%s", e.what()
	};

	return false;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "Certificate error :%s", e.what()
	};

	return false;
}

void
ircd::net::socket::call_user(const ec_handler &callback,
                             const error_code &ec)
noexcept try
{
	callback(ec);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket(%p) async handler :unhandled exception :%s",
		this,
		e.what()
	};

	close(*this, dc::RST, close_ignore);
}

void
ircd::net::socket::call_user(const eptr_handler &callback,
                             const error_code &ec)
noexcept try
{
	if(likely(!ec))
		return callback(std::exception_ptr{});

	callback(make_system_eptr(ec));
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket:%lu async handler :unhandled exception :%s",
		this->id,
		e.what()
	};
}

void
ircd::net::socket::call_user(const handler &callback,
                             const error_code &ec,
                             const size_t bytes)
noexcept try
{
	callback(ec, bytes);
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "socket:%lu async handler :unhandled exception :%s",
		this->id,
		e.what()
	};

	close(*this, dc::RST, close_ignore);
}

bool
ircd::net::socket::cancel()
noexcept
{
	cancel_timeout();

	boost::system::error_code ec;
	sd.cancel(ec);
	if(unlikely(ec))
	{
		char ecbuf[64];
		log::dwarning
		{
			log, "socket:%lu cancel :%s",
			this->id,
			string(ecbuf, ec)
		};
	}

	return !ec;
}

ircd::milliseconds
ircd::net::socket::cancel_timeout()
noexcept
{
	const bool timedout
	{
		std::exchange(this->timedout, false)
	};

	const bool timer_set
	{
		std::exchange(this->timer_set, false)
	};

	if(!timer_set)
		return 0ms;

	const auto exp
	{
		timer.expires_from_now()
	};

	const milliseconds ret
	{
		exp.total_milliseconds()
	};

	boost::system::error_code ec;
	timer.cancel(ec);
	assert(!ec);
	return ret;
}

void
ircd::net::socket::set_timeout(const milliseconds &t,
                               ec_handler callback)
{
	cancel_timeout();
	if(t < milliseconds(0))
		return;

	auto handler
	{
		std::bind(&socket::handle_timeout, this, shared_from(*this), std::move(callback), ph::_1)
	};

	// The sending-side of the semaphore is incremented here to invalidate any
	// pending/queued callbacks to handle_timeout as to not conflict now. The
	// required companion boolean timer_set is also lit here.
	assert(timer_sem[0] <= timer_sem[1]);
	assert(timer_set == false);
	assert(timedout == false);
	++timer_sem[1];
	timer_set = true;
	const boost::posix_time::milliseconds pt
	{
		t.count()
	};

	timer.expires_from_now(pt);
	assert(!this_sock);
	const scope_restore desc_sock
	{
		this_sock, this
	};

	timer.async_wait(ios::handle(desc_timeout, std::move(handler)));
}

[[gnu::visibility("internal")]]
void *
ircd::net::socket::desc_alloc(ios::handler &h,
                              const size_t &size,
                              unique_mutable_buffer &buf)
{
	assert(this_sock);
	if(buffer::size(buf) < size)
		buf = unique_mutable_buffer{size};

	assert(buffer::size(buf) >= size);
	return data(buf);
}

[[gnu::visibility("internal")]]
void
ircd::net::socket::desc_dealloc(ios::handler &h,
                                void *const &ptr,
                                const size_t &size)
noexcept
{
}

///////////////////////////////////////////////////////////////////////////////
//
// net/ipport.h
//

std::ostream &
ircd::net::operator<<(std::ostream &s, const ipport &t)
{
	char buf[128];
	s << net::string(buf, t);
	return s;
}

ircd::string_view
ircd::net::string(const mutable_buffer &buf,
                  const ipport &ipp)
{
	mutable_buffer out{buf};
	const bool has_port(port(ipp));
	const bool need_bracket
	{
		has_port && is_v6(ipp) && !is_null(ipp)
	};

	if(need_bracket)
		consume(out, copy(out, '['));

	if(ipp)
		consume(out, size(string(out, std::get<ipport::IP>(ipp))));

	if(need_bracket)
		consume(out, copy(out, ']'));

	if(has_port)
	{
		consume(out, copy(out, ':'));
		consume(out, size(lex_cast(port(ipp), out)));
	}

	return
	{
		data(buf), data(out)
	};
}

[[gnu::visibility("protected")]]
ircd::net::ipport
ircd::net::make_ipport(const boost::asio::ip::udp::endpoint &ep)
{
	return ipport
	{
		ep.address(), ep.port()
	};
}

[[gnu::visibility("protected")]]
ircd::net::ipport
ircd::net::make_ipport(const boost::asio::ip::tcp::endpoint &ep)
{
	return ipport
	{
		ep.address(), ep.port()
	};
}

[[gnu::visibility("protected")]]
boost::asio::ip::udp::endpoint
ircd::net::make_endpoint_udp(const ipport &ipport)
{
	return
	{
		make_address(std::get<ipport::IP>(ipport)), port(ipport)
	};
}

[[gnu::visibility("protected")]]
boost::asio::ip::tcp::endpoint
ircd::net::make_endpoint(const ipport &ipport)
{
	return
	{
		make_address(std::get<ipport::IP>(ipport)), port(ipport)
	};
}

//
// cmp
//

bool
ircd::net::ipport::cmp_ip::operator()(const ipport &a, const ipport &b)
const
{
	return ipaddr::cmp()(std::get<ipport::IP>(a), std::get<ipport::IP>(b));
}

bool
ircd::net::ipport::cmp_port::operator()(const ipport &a, const ipport &b)
const
{
	return std::get<ipport::PORT>(a) < std::get<ipport::PORT>(b);
}

///////////////////////////////////////////////////////////////////////////////
//
// net/ipaddr.h
//

[[gnu::visibility("protected")]]
boost::asio::ip::address
ircd::net::make_address(const ipaddr &ipaddr)
{
	return is_v4(ipaddr)?
		ip::address(make_address(ipaddr.v4)):
		ip::address(make_address(ipaddr.v6));
}

[[gnu::visibility("protected")]]
boost::asio::ip::address
ircd::net::make_address(const string_view &ip)
try
{
	return
		ip && ip == "*"?
			boost::asio::ip::address_v6::any():
		ip?
			boost::asio::ip::make_address(ip):
			boost::asio::ip::address{};
}
catch(const boost::system::system_error &e)
{
	throw_system_error(e);
}

[[gnu::visibility("protected")]]
boost::asio::ip::address_v4
ircd::net::make_address(const uint32_t &ip)
{
	return ip::address_v4{ip};
}

[[gnu::visibility("protected")]]
boost::asio::ip::address_v6
ircd::net::make_address(const uint128_t &ip)
#ifdef __cpp_lib_bit_cast
{
	return ip::address_v6
	{
		std::bit_cast<decltype(ipaddr::byte)>(hton(ip))
	};
}
#else
{
	return ip::address_v6
	{
		reinterpret_cast<const decltype(ipaddr::byte) &&>(hton(ip))
	};
}
#endif

std::ostream &
ircd::net::operator<<(std::ostream &s, const ipaddr &ipa)
{
	char buf[128];
	s << net::string(buf, ipa);
	return s;
}

ircd::string_view
ircd::net::string(const mutable_buffer &buf,
                  const ipaddr &ipaddr)
{
	return is_v4(ipaddr)?
		string_ip4(buf, ipaddr.v4):
		string_ip6(buf, ipaddr.v6);
}

ircd::string_view
ircd::net::string_ip4(const mutable_buffer &buf,
                      const uint32_t &ip)
{
	return string(buf, make_address(ip));
}

ircd::string_view
ircd::net::string_ip6(const mutable_buffer &buf,
                      const uint128_t &ip)
{
	return string(buf, make_address(ip));
}

bool
ircd::net::is_loop(const ipaddr &ipaddr)
{
	return is_v4(ipaddr)?
		make_address(ipaddr.v4).is_loopback():
		make_address(ipaddr.v6).is_loopback();
}

//
// ipaddr::ipaddr
//

static_assert
(
	SIZEOF_LONG_LONG >= 8,
	"8 byte integer literals are required."
);

decltype(ircd::net::ipaddr::v4_max)
ircd::net::ipaddr::v4_min
{
	0x0000ffff00000000ULL
};

decltype(ircd::net::ipaddr::v4_max)
ircd::net::ipaddr::v4_max
{
	v4_min +
	0x00000000ffffffffULL
};

ircd::net::ipaddr::ipaddr(const string_view &ip)
:ipaddr
{
	make_address(ip)
}
{
}

ircd::net::ipaddr::ipaddr(const rfc1035::record::A &rr)
:ipaddr
{
	rr.ip4
}
{
}

ircd::net::ipaddr::ipaddr(const rfc1035::record::AAAA &rr)
:ipaddr
{
	rr.ip6
}
{
}

ircd::net::ipaddr::ipaddr(const uint32_t &ip)
:ipaddr
{
	make_address(ip)
}
{
}

ircd::net::ipaddr::ipaddr(const uint128_t &ip)
:ipaddr
{
	make_address(ip)
}
{
}

[[gnu::visibility("protected")]]
ircd::net::ipaddr::ipaddr(const asio::ip::address &address)
{
	const auto address_
	{
		address.is_v6()?
			address.to_v6():
			make_address_v6(ip::v4_mapped, address.to_v4())
	};

	byte = address_.to_bytes();
	std::reverse(byte.begin(), byte.end());
}

//
// ipaddr::ipaddr
//

bool
ircd::net::ipaddr::cmp::operator()(const ipaddr &a, const ipaddr &b)
const
{
	return a.byte < b.byte;
}

///////////////////////////////////////////////////////////////////////////////
//
// net/hostport.h
//

/// Creates a host:service or host:port pair from the single string literally
/// containing the colon deliminated values. If the suffix is a port number
/// then the behavior for the port number constructor applies; if a service
/// string then the service constructor applies.
ircd::net::hostport::hostport(const string_view &amalgam)
:host
{
	rfc3986::host(amalgam)
}
,port
{
	rfc3986::port(amalgam)
}
{
	// When the amalgam has no port || a valid integer port
	if(amalgam == host || port)
		return;

	// When the port is actually a service string
	this->service = rsplit(amalgam, ':').second;
}

ircd::net::hostport::hostport(const string_view &amalgam,
                              verbatim_t)
:host
{
	rfc3986::host(amalgam)
}
,service
{
	amalgam != host && !rfc3986::port(amalgam)?
		rsplit(amalgam, ':').second:
		string_view{}
}
,port
{
	rfc3986::port(amalgam)
}
{}

std::ostream &
ircd::net::operator<<(std::ostream &s, const hostport &t)
{
	thread_local char buf[rfc3986::DOMAIN_BUFSIZE * 2];
	const critical_assertion ca;
	s << string(buf, t);
	return s;
}

std::string
ircd::net::canonize(const hostport &hostport)
{
	const size_t len
	{
		size(host(hostport))            // host
		+ 1 + size(service(hostport))   // ':' + service
		+ 1 + 5 + 1                     // ':' + portnum  (optimistic)
	};

	return ircd::string(len, [&hostport]
	(const mutable_buffer &buf)
	{
		return canonize(buf, hostport);
	});
}

ircd::string_view
ircd::net::canonize(const mutable_buffer &buf,
                    const hostport &hostport)
{
	thread_local char svc[32], tlbuf[2][rfc3986::DOMAIN_BUFSIZE * 2];
	assert(service(hostport) || port(hostport));

	const string_view &service_name
	{
		!service(hostport)?
			net::dns::service_name(std::nothrow, svc, port(hostport), "tcp"):
			service(hostport)
	};

	if(likely(service_name))
		return fmt::sprintf
		{
			buf, "%s:%s",
			tolower(tlbuf[0], host(hostport)),
			tolower(tlbuf[1], service_name),
		};

	if(unlikely(!port(hostport)))
		throw error
		{
			"Missing service suffix in hostname:service string.",
		};

	return fmt::sprintf
	{
		buf, "%s:%u",
		tolower(tlbuf[0], host(hostport)),
		port(hostport),
	};
}

ircd::string_view
ircd::net::string(const mutable_buffer &buf,
                  const hostport &hp)
{
	thread_local char tlbuf[2][rfc3986::DOMAIN_BUFSIZE * 2];

	if(empty(service(hp)) && port(hp) == 0)
		return fmt::sprintf
		{
			buf, "%s",
			tolower(tlbuf[0], host(hp)),
		};

	if(empty(service(hp)) && port(hp) != 0)
		return fmt::sprintf
		{
			buf, "%s:%u",
			tolower(tlbuf[0], host(hp)),
			port(hp)
		};

	if(!empty(service(hp)) && port(hp) == 0)
		return fmt::sprintf
		{
			buf, "%s:%s",
			tolower(tlbuf[0], host(hp)),
			tolower(tlbuf[1], service(hp)),
		};

	return fmt::sprintf
	{
		buf, "%s:%u (%s)",
		tolower(tlbuf[0], host(hp)),
		port(hp),
		tolower(tlbuf[1], service(hp)),
	};
}

///////////////////////////////////////////////////////////////////////////////
//
// net/asio.h
//

[[gnu::visibility("protected")]]
std::string
ircd::net::string(const ip::tcp::endpoint &ep)
{
	return string(make_ipport(ep));
}

[[gnu::visibility("protected")]]
ircd::string_view
ircd::net::string(const mutable_buffer &buf,
                  const ip::tcp::endpoint &ep)
{
	return string(buf, make_ipport(ep));
}

[[gnu::visibility("protected")]]
std::string
ircd::net::host(const ip::tcp::endpoint &ep)
{
	return string(addr(ep));
}

[[gnu::visibility("protected")]]
boost::asio::ip::address
ircd::net::addr(const ip::tcp::endpoint &ep)
{
	return ep.address();
}

[[gnu::visibility("protected")]]
uint16_t
ircd::net::port(const ip::tcp::endpoint &ep)
{
	return ep.port();
}

[[gnu::visibility("protected")]]
std::string
ircd::net::string(const ip::address &addr)
{
	return
		addr.is_v4()?
			string(addr.to_v4()):
			string(addr.to_v6());
}

[[gnu::visibility("protected")]]
std::string
ircd::net::string(const ip::address_v4 &addr)
{
	return util::string(16, [&addr]
	(const mutable_buffer &out)
	{
		return string(out, addr);
	});
}

[[gnu::visibility("protected")]]
std::string
ircd::net::string(const ip::address_v6 &addr)
{
	return addr.to_string();
}

[[gnu::visibility("protected")]]
ircd::string_view
ircd::net::string(const mutable_buffer &out,
                  const ip::address &addr)
{
	return
		addr.is_v4()?
			string(out, addr.to_v4()):
			string(out, addr.to_v6());
}

[[gnu::visibility("protected")]]
ircd::string_view
ircd::net::string(const mutable_buffer &out,
                  const ip::address_v4 &addr)
{
	const uint32_t a(addr.to_ulong());
	return fmt::sprintf
	{
		out, "%u.%u.%u.%u",
		(a & 0xFF000000U) >> 24,
		(a & 0x00FF0000U) >> 16,
		(a & 0x0000FF00U) >> 8,
		(a & 0x000000FFU) >> 0,
	};
}

[[gnu::visibility("protected")]]
ircd::string_view
ircd::net::string(const mutable_buffer &out,
                  const ip::address_v6 &addr)
{
	return
	{
		data(out), string(addr).copy(data(out), size(out))
	};
}

///////////////////////////////////////////////////////////////////////////////
//
// buffer.h - provide definition for the null buffers and asio conversion
//

[[gnu::visibility("protected"), gnu::hot]]
ircd::buffer::mutable_buffer::operator
boost::asio::mutable_buffer()
const noexcept
{
	return boost::asio::mutable_buffer
	{
		data(*this), size(*this)
	};
}

[[gnu::visibility("protected"), gnu::hot]]
ircd::buffer::const_buffer::operator
boost::asio::const_buffer()
const noexcept
{
	return boost::asio::const_buffer
	{
		data(*this), size(*this)
	};
}
