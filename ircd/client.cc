// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

//
// client::settings conf::item's
//

ircd::conf::item<size_t>
ircd::client::settings::max_client
{
	{ "name",     "ircd.client.max_client"  },
	{ "default",  16384L                    },
};

ircd::conf::item<size_t>
ircd::client::settings::max_client_per_peer
{
	{ "name",     "ircd.client.max_client_per_peer"  },
	{ "default",  24L                                },
};

ircd::conf::item<size_t>
ircd::client::settings::stack_size
{
	{ "name",     "ircd.client.stack_size"  },
	{ "default",  ssize_t(1_MiB)            },
};

ircd::conf::item<size_t>
ircd::client::settings::pool_size
{
	{
		{ "name",     "ircd.client.pool_size"  },
		{ "default",  96L                      },
	},
	[](conf::item<void> &)
	{
		if(run::level == run::level::RUN)
			client::pool.set(client::settings::pool_size);
	}
};

ircd::conf::item<size_t>
ircd::client::settings::pool_disp
{
	{ "name",     "ircd.client.pool_disp"      },
	{ "default",  long(ctx::dock::opts::LIFO)  },
};

/// Linkage for the default settings
decltype(ircd::client::settings)
ircd::client::settings;

//
// client::conf conf::item's
//

ircd::conf::item<ircd::seconds>
ircd::client::conf::async_timeout_default
{
	{ "name",     "ircd.client.conf.async_timeout" },
	{ "default",  305L                             },
};

ircd::conf::item<ircd::seconds>
ircd::client::conf::request_timeout_default
{
	{ "name",     "ircd.client.conf.request_timeout" },
	{ "default",  33L                                },
};

ircd::conf::item<size_t>
ircd::client::conf::header_max_size_default
{
	{ "name",     "ircd.client.conf.header_max_size" },
	{ "default",  ssize_t(8_KiB)                     },
};

/// Linkage for the default conf
decltype(ircd::client::default_conf)
ircd::client::default_conf;

decltype(ircd::client::log)
ircd::client::log
{
	"client", 'C'
};

decltype(ircd::client::pool_opts)
ircd::client::pool_opts
{
	.stack_size = size_t(settings.stack_size),
	.initial = size_t(settings.pool_size),
	.dispatch = ctx::dock::opts(size_t(settings.pool_disp)),
};

/// The pool of request contexts. When a client makes a request it does so by acquiring
/// a stack from this pool. The request handling and response logic can then be written
/// in a synchronous manner as if each connection had its own thread.
[[clang::always_destroy]]
decltype(ircd::client::pool)
ircd::client::pool
{
	"client", pool_opts
};

/// A general semaphore for the client system; used for coarse operations
/// like waiting for all clients to disconnect / system shutdown et al.
decltype(ircd::client::dock)
ircd::client::dock;

decltype(ircd::client::ctr)
ircd::client::ctr;

// Allocator for the container of all active clients for iteration purposes.
template<>
decltype(ircd::client::allocator)
ircd::util::instance_multimap<ircd::net::ipport, ircd::client, ircd::net::ipport::cmp_ip>::allocator
{};

// Linkage for the container of all active clients for iteration purposes.
template<>
decltype(ircd::client::map)
ircd::util::instance_multimap<ircd::net::ipport, ircd::client, ircd::net::ipport::cmp_ip>::map
{
	allocator
};

//
// init
//

ircd::client::init::init()
{
	spawn();
}

[[gnu::cold]]
ircd::client::init::~init()
noexcept
{
	const ctx::uninterruptible::nothrow ui;

	terminate_all();
	close_all();
	wait_all();

	log::debug
	{
		log, "All client contexts, connections, and requests are clear.",
	};

	assert(client::map.empty());
}

//
// util
//

ircd::string_view
ircd::loghead(const client &client)
{
	thread_local char buf[512];
	return loghead(buf, client);
}

ircd::string_view
ircd::loghead(const mutable_buffer &buf,
              const client &client)
{
	const string_view alpn
	{
		client.sock?
			client.sock->alpn:
			"h1"_sv
	};

	char rembuf[64], locbuf[64];
	return fmt::sprintf
	{
		buf, "socket:%lu fd:%d local:%s remote:%s client:%lu %s %lu:%lu",
		client.sock? net::id(*client.sock): -1UL,
		client.sock? net::native_handle(*client.sock): -1,
		string(locbuf, local(client)),
		string(rembuf, remote(client)),
		client.id,
		alpn,
		client.ready_count,
		client.request_count,
	};
}

ircd::ipport
ircd::local(const client &client)
{
	return likely(client.sock)?
		net::local_ipport(*client.sock):
		net::ipport{};
}

const ircd::ipport &
ircd::remote(const client &client)
{
	return client.it->first;
}

//
// tool
//

void
ircd::client::spawn()
{
	pool.add(size_t(settings.pool_size));
}

void
ircd::client::wait_all()
{
	if(pool.active())
		log::dwarning
		{
			log, "Waiting on %zu active of %zu client request contexts; %zu pending; %zu queued.",
			pool.active(),
			pool.size(),
			pool.pending(),
			pool.queued()
		};

	static const auto is_empty
	{
		[]() noexcept { return client::map.empty(); }
	};

	while(!dock.wait_for(seconds(3), is_empty))
	{
		for(const auto &[remote, client] : client::map)
		{
			assert(client);
			log::dwarning
			{
				log, "Waiting for client %s",
				loghead(*client),
			};

			assert(!client->sock || client->sock->fini);
		}

		log::warning
		{
			log, "Waiting for %zu clients to close...",
			client::map.size(),
		};
	}

	log::debug
	{
		log, "Joining %zu active of %zu client request contexts; %zu pending; %zu queued",
		pool.active(),
		pool.size(),
		pool.pending(),
		pool.queued()
	};

	pool.join();
}

void
ircd::client::close_all()
{
	if(!client::map.empty())
		log::debug
		{
			log, "Closing %zu clients",
			client::map.size()
		};

	auto it(begin(client::map));
	while(it != end(client::map))
	{
		auto c(shared_from(*it->second)); ++it; try
		{
			c->close(net::dc::RST, net::close_ignore);
		}
		catch(const std::exception &e)
		{
			log::derror
			{
				log, "Error disconnecting client @%p: %s",
				c.get(),
				e.what(),
			};
		}
	}
}

void
ircd::client::interrupt_all()
{
	if(pool.active())
		log::warning
		{
			log, "Interrupting %zu active of %zu client request contexts; %zu pending; %zu queued",
			pool.active(),
			pool.size(),
			pool.pending(),
			pool.queued()
		};

	pool.interrupt();
}

void
ircd::client::terminate_all()
{
	if(pool.active())
		log::warning
		{
			log, "Terminating %zu active of %zu client request contexts; %zu pending; %zu queued",
			pool.active(),
			pool.size(),
			pool.pending(),
			pool.queued()
		};

	pool.terminate();
}

void
ircd::client::create(net::acceptor &,
                     const std::shared_ptr<socket> &sock)
{
	const auto client
	{
		std::make_shared<ircd::client>(sock)
	};

	client->async();
}

size_t
ircd::client::count(const net::ipport &remote)
{
	return client::map.count(remote);
}

ircd::parse::read_closure
ircd::client::read_closure(client &client)
{
	// Returns a function the parser can call when it wants more data
	return [&client](char *&start, char *const &stop)
	{
		char *const got(start);
		read(client, start, stop);
		//std::cout << ">>>> " << std::distance(got, start) << std::endl;
		//std::cout << string_view{got, start} << std::endl;
		//std::cout << "----" << std::endl;
    };
}

char *
ircd::client::read(client &client,
                   char *&start,
                   char *const &stop)
{
	assert(client.sock);
	auto &sock(*client.sock);
	const mutable_buffer buf
	{
		start, stop
	};

	char *const base(start);
	start += net::read(sock, buf);
	return base;
}

//
// async loop
//

namespace ircd
{
	static bool handle_ec_default(client &, const error_code &);
	static bool handle_ec_timeout(client &);
	static bool handle_ec_short_read(client &);
	static bool handle_ec_eof(client &);
	static bool handle_ec(client &, const error_code &);
}

/// This function is the basis for the client's request loop. We still use
/// an asynchronous pattern until there is activity on the socket (a request)
/// in which case the switch to synchronous mode is made by jumping into an
/// ircd::context drawn from the request pool. When the request is finished,
/// the client exits back into asynchronous mode until the next request is
/// received and rinse and repeat.
//
/// This sequence exists to avoid any possible c10k-style limitation imposed by
/// dedicating a context and its stack space to the lifetime of a connection.
/// This is similar to the thread-per-request pattern before async was in vogue.
///
/// This call returns immediately so we no longer block the current context and
/// its stack while waiting for activity on idle connections between requests.
bool
ircd::client::async()
{
	assert(bool(this->sock));
	assert(bool(this->conf));
	auto &sock(*this->sock);
	if(unlikely(sock.fini))
		return false;

	const auto &timeout
	{
		conf->async_timeout
	};

	const net::wait_opts opts
	{
		net::ready::READ, timeout
	};

	auto handler
	{
		std::bind(client::handle_ready, shared_from(*this), ph::_1)
	};

	// Re-purpose the request time counter into an async timer by marking it.
	timer = ircd::timer{};

	net::wait(sock, opts, std::move(handler));
	return true;
}

/// The client's socket is ready for reading. This intermediate handler
/// intercepts any errors otherwise dispatches the client to the request
/// pool to be married with a stack. Right here this handler is executing on
/// the main stack (not in any ircd::context).
///
/// The context the closure ends up getting is the next available from the
/// request pool, which may not be available immediately so this handler might
/// be queued for some time after this call returns.
void
ircd::client::handle_ready(std::shared_ptr<client> client,
                           const error_code &ec)
{
	if(!handle_ec(*client, ec))
		return;

	auto handler
	{
		std::bind(client::handle_requests, std::move(client))
	};

	if(pool.avail() == 0)
		log::dwarning
		{
			log, "Client context pool exhausted. %zu requests queued.",
			pool.queued()
		};

	pool(std::move(handler));
}

/// A request context has been dispatched and is now handling this client.
/// This function is executing on that ircd::ctx stack. client::main() will
/// now be called and synchronous programming is possible. Afterward, the
/// client will release this ctx and its stack and fall back to async mode
/// or die.
void
ircd::client::handle_requests(std::shared_ptr<client> client)
try
{
	// The ircd::ctx now handling this request is referenced and accessible
	// in client for the duration of this handling.
	assert(ctx::current);
	assert(!client->reqctx);
	client->reqctx = ctx::current;
	client->ready_count++;
	const unwind reset{[&client]
	{
		assert(bool(client));
		assert(client->reqctx);
		assert(client->reqctx == ctx::current);
		client->reqctx = nullptr;
		if(pool.avail() <= 1)
			dock.notify_all();
	}};

	util::timer timer
	{
		RB_DEBUG_LEVEL
	};

	if constexpr(RB_LOG_LEVEL > 7)
		log::debug
		{
			log, "%s enter",
			loghead(*client),
		};

	if(!client->main())
	{
		client->close(net::dc::SSL_NOTIFY).wait();
		return;
	}

	if constexpr(RB_LOG_LEVEL > 7)
	{
		char buf[64];
		log::debug
		{
			log, "%s leave %s",
			loghead(*client),
			pretty(buf, timer.at<microseconds>(), true)
		};
	}

	client->async();
}
catch(const std::exception &e)
{
	log::error
	{
		log, "%s fault :%s",
		loghead(*client),
		e.what()
	};
}

bool
ircd::handle_ec(client &client,
                const error_code &ec)
{
	using std::errc;
	using boost::asio::error::get_ssl_category;
	using boost::asio::error::get_misc_category;

	if(unlikely(run::level != run::level::RUN && !ec))
	{
		log::dwarning
		{
			client::log, "%s refusing client request in runlevel %s",
			loghead(client),
			reflect(run::level)
		};

		client.close(net::dc::RST, net::close_ignore);
		return false;
	}

	if(system_category(ec)) switch(ec.value())
	{
		case 0:                              return true;
		case int(errc::operation_canceled):  return false;
		case int(errc::timed_out):           return handle_ec_timeout(client);
		default:                             return handle_ec_default(client, ec);
	}
	else if(ec.category() == get_ssl_category()) switch(uint8_t(ec.value()))
	{
		#ifdef SSL_R_SHORT_READ
		case SSL_R_SHORT_READ:               return handle_ec_short_read(client);
		#endif
		default:                             return handle_ec_default(client, ec);
	}
	else if(ec == net::eof)
		return handle_ec_eof(client);
	else
		return handle_ec_default(client, ec);
}

/// The client indicated they will not be sending the data we have been
/// waiting for. The proper behavior now is to initiate a clean shutdown.
bool
ircd::handle_ec_eof(client &client)
try
{
	log::debug
	{
		client::log, "%s end of file",
		loghead(client),
	};

	const net::close_opts opts
	{
		.type = net::dc::SSL_NOTIFY,
		.shutdown = net::dc::RST,
	};

	client.close(opts, net::close_ignore);
	return false;
}
catch(const std::exception &e)
{
	log::error
	{
		client::log, "%s end of file :%s",
		loghead(client),
		e.what()
	};

	return false;
}

/// The client terminated the connection, likely improperly, and SSL
/// is informing us with an opportunity to prevent truncation attacks.
/// Best behavior here is to just close the sd.
bool
ircd::handle_ec_short_read(client &client)
try
{
	log::dwarning
	{
		client::log, "%s short_read",
		loghead(client),
	};

	client.close(net::dc::RST, net::close_ignore);
	return false;
}
catch(const std::exception &e)
{
	log::error
	{
		client::log, "%s short_read :%s",
		loghead(client),
		e.what()
	};

	return false;
}

/// The net:: system determined the client timed out because we set a timer
/// on the socket waiting for data which never arrived. The client may very
/// well still be there, so the best thing to do is to attempt a clean
/// disconnect.
bool
ircd::handle_ec_timeout(client &client)
try
{
	assert(bool(client.sock));
	log::debug
	{
		client::log, "%s disconnecting after inactivity timeout",
		loghead(client),
	};

	client.close(net::dc::SSL_NOTIFY, net::close_ignore);
	return false;
}
catch(const std::exception &e)
{
	log::derror
	{
		client::log, "%s timeout :%s",
		loghead(client),
		e.what()
	};

	return false;
}

/// Unknown/untreated error. Probably not worth attempting a clean shutdown
/// so a hard / immediate disconnect given instead.
bool
ircd::handle_ec_default(client &client,
                        const error_code &ec)
{
	char buf[256];
	log::derror
	{
		client::log, "%s :%s",
		loghead(client),
		string(buf, ec)
	};

	client.close(net::dc::RST, net::close_ignore);
	return false;
}

//
// client
//

ircd::client::client(std::shared_ptr<socket> sock)
:instance_multimap
{
	net::remote_ipport(*sock)
}
,head_buffer
{
	conf->header_max_size
}
,sock
{
	std::move(sock)
}
{
	assert(size(head_buffer) >= 8_KiB);
}

ircd::client::~client()
noexcept try
{
	dock.notify_all();
	//assert(!sock || !connected(*sock));
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "~client(%p): %s",
		this,
		e.what()
	};

	return;
}

/// Client main loop.
///
/// Before main(), the client had been sitting in async mode waiting for
/// socket activity. Once activity with data was detected indicating a request,
/// the client was dispatched to the request pool where it is paired to an
/// ircd::ctx with a stack. main() is then invoked on that ircd::ctx stack.
/// Nothing from the socket has been read into userspace before main().
///
/// This function parses requests off the socket in a loop until there are no
/// more requests or there is a fatal error. The ctx will "block" to wait for
/// more data off the socket during the middle of a request until the request
/// timeout is reached. main() will not "block" to wait for more data after a
/// request; it will simply `return true` which puts this client back into
/// async mode and relinquishes this stack. returning false will disconnect
/// the client rather than putting it back into async mode.
///
/// Normal exceptions do not pass below main() therefor anything unhandled is an
/// internal server error and the client is disconnected. The exception handler
/// here though is executing on a request ctx stack, and we can choose to take
/// advantage of that; in contrast to the handle_ec() switch which handles
/// errors on the main/callback stack and must be asynchronous.
///
bool
ircd::client::main()
try
{
	parse::buffer pb{head_buffer};
	parse::capstan pc{pb, read_closure(*this)}; do
	{
		if(!handle_request(pc))
			return false;

		// After the request, the head and content has been read off the socket
		// and the capstan has advanced to the end of the content. The catch is
		// that reading off the socket could have read too much, bleeding into
		// the next request. This is rare, but pb.remove() will memmove() the
		// bleed back to the beginning of the head buffer for the next loop.
		pb.remove();
	}
	while(pc.unparsed());

	return true;
}
catch(const std::system_error &e)
{
	return handle_ec(*this, e.code());
}
catch(const ctx::interrupted &e)
{
	log::warning
	{
		log, "%s request interrupted :%s",
		loghead(*this),
		e.what()
	};

	close(net::dc::SSL_NOTIFY, net::close_ignore);
	return false;
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "%s :%s",
		loghead(*this),
		e.what()
	};

	return false;
}
catch(const ctx::terminated &)
{
	close(net::dc::RST, net::close_ignore);
	throw;
}

/// Handle a single request within the client main() loop.
///
/// This function returns false if the main() loop should exit
/// and thus disconnect the client. It should return true in most
/// cases even for lightly erroneous requests that won't affect
/// the next requests on the tape.
///
/// This function is timed. The timeout will prevent a client from
/// sending a partial request and leave us waiting for the rest.
bool
ircd::client::handle_request(parse::capstan &pc)
try
{
	timer = ircd::timer{};
	++request_count;

	// This timeout covers the reception of a complete HTTP head. If the
	// head was fragmented and has not entirely arrived yet this function
	// will block this request context below. The timeout limits that.
	net::scope_timeout timeout
	{
		*sock, conf->request_timeout
	};

	// This is the first read off the wire. The headers are entirely read and
	// the tape is advanced.
	const http::request::head head{pc};
	head_length = pc.parsed - data(head_buffer);
	content_consumed = std::min(pc.unparsed(), head.content_length);
	pc.parsed += content_consumed;
	assert(pc.parsed <= pc.read);

	// The resource being sought will have its own specific timeout, or none
	// at all. This timeout is now canceled to not conflict. Note that the
	// time spent so far is still being accumulated by client.timer.
	timeout.cancel();

	log::debug
	{
		resource::log, "%s HTTP %s `%s' content-length:%zu have:%zu",
		loghead(*this),
		head.method,
		head.uri,
		head.content_length,
		content_consumed
	};

	// Sets values in this->client::request based on everything we know from
	// the head for this scope. This gets updated again in the resource::
	// unit for their scope with more data including the content.
	const scope_restore request
	{
		this->request, resource::request
		{
			head, string_view{} // no content considered yet
		}
	};

	bool ret
	{
		resource_request(head)
	};

	if(ret && iequals(head.connection, "close"_sv))
		ret = false;

	return ret;
}
catch(const ctx::interrupted &e)
{
	throw;
}
catch(const std::system_error &e)
{
	static const auto operation_canceled
	{
		make_error_code(std::errc::operation_canceled)
	};

	if(e.code() != operation_canceled)
		throw;

	if(!sock || sock->fini)
		return false;

	const ctx::exception_handler eh;
	resource::response
	{
		*this,
		http::REQUEST_TIMEOUT,
		{},
		0L,
		{}
	};

	return false;
}
catch(const http::error &e)
{
	log::logf
	{
		log, log::level::DERROR,
		"%s HTTP %u %s :%s",
		loghead(*this),
		uint(e.code),
		http::status(e.code),
		e.content
	};

	if(!sock || sock->fini)
		return false;

	const ctx::exception_handler eh;
	resource::response
	{
		*this,
		e.content,
		"text/html; charset=utf-8",
		e.code,
		e.headers
	};

	return false;
}

bool
ircd::client::resource_request(const http::request::head &head)
try
{
	auto &resource
	{
		// throws HTTP 404 if not found.
		ircd::resource::find(head.path)
	};

	auto &method
	{
		// throws HTTP 405 if not found.
		resource[head.method]
	};

	const string_view content_partial
	{
		data(head_buffer) + head_length, content_consumed
	};

	method(*this, head, content_partial);
	discard_unconsumed(head);
	return true;
}
catch(const ctx::interrupted &)
{
	throw;
}
catch(const std::system_error &)
{
	throw;
}
catch(const http::error &e)
{
	const ctx::exception_handler eh;

	if(!empty(e.content))
		log::logf
		{
			resource::log, log::level::DERROR,
			"%s HTTP %u `%s' %s :%s",
			loghead(*this),
			uint(e.code),
			head.uri,
			http::status(e.code),
			e.content
		};

	if(!sock || sock->fini)
		return false;

	resource::response
	{
		*this,
		e.content,
		"text/html; charset=utf-8",
		e.code,
		e.headers
	};

	switch(e.code)
	{
		// These codes are "unrecoverable" errors and no more HTTP can be
		// conducted with this tape. The client must be disconnected.
		case http::BAD_REQUEST:
		case http::REQUEST_TIMEOUT:
		case http::PAYLOAD_TOO_LARGE:
		case http::INTERNAL_SERVER_ERROR:
			return false;

		// These codes are "recoverable" and allow the next HTTP request in
		// a pipeline to take place.
		default:
			discard_unconsumed(head);
			return true;
	}
}
catch(const std::exception &e)
{
	const ctx::exception_handler eh;

	log::error
	{
		resource::log, "%s HTTP 500 Internal Error `%s' :%s",
		loghead(*this),
		head.uri,
		e.what()
	};

	if(!sock || sock->fini)
		return false;

	resource::response
	{
		*this,
		e.what(),
		"text/html; charset=utf-8",
		http::INTERNAL_SERVER_ERROR
	};

	return false;
}

void
ircd::client::discard_unconsumed(const http::request::head &head)
{
	if(unlikely(!sock))
		return;

	const size_t unconsumed
	{
		head.content_length - content_consumed
	};

	if(!unconsumed)
		return;

	log::debug
	{
		log, "%s discarding %zu unconsumed of %zu bytes content...",
		loghead(*this),
		unconsumed,
		head.content_length
	};

	content_consumed += net::discard_all(*sock, unconsumed);
	assert(content_consumed == head.content_length);
}

ircd::ctx::future<void>
ircd::client::close(const net::dc type)
{
	return close(net::close_opts
	{
		.type = type,
	});
}

ircd::ctx::future<void>
ircd::client::close(const net::close_opts &opts)
{
	return likely(sock) && !sock->fini?
		net::close(*sock, opts):
		ctx::already;
}

void
ircd::client::close(const net::dc type,
                    net::close_callback callback)
{
	const net::close_opts opts
	{
		.type = type,
	};

	close(opts, std::move(callback));
}

void
ircd::client::close(const net::close_opts &opts,
                    net::close_callback callback)
{
	if(!sock)
		return;

	if(sock->fini)
		return callback({});

	net::close(*sock, opts, std::move(callback));
}

size_t
ircd::client::write_all(const net::const_buffers &bufs)
{
	if(unlikely(!sock))
		throw std::system_error
		{
			make_error_code(std::errc::bad_file_descriptor)
		};

	if(unlikely(sock->fini))
		throw std::system_error
		{
			make_error_code(std::errc::not_connected)
		};

	return net::write_all(*sock, bufs);
}
