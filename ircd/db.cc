// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include "db.h"

/// Dedicated logging facility for the database subsystem
decltype(ircd::db::log)
ircd::db::log
{
	"db", 'D'
};

/// Dedicated logging facility for rocksdb's log callbacks
decltype(ircd::db::rog)
ircd::db::rog
{
	"db.rocksdb"
};

decltype(ircd::db::version_api)
ircd::db::version_api
{
	"RocksDB", info::versions::API, 0,
	{
		ROCKSDB_MAJOR, ROCKSDB_MINOR, ROCKSDB_PATCH,
	}
};

decltype(ircd::db::version_abi)
ircd::db::version_abi
{
	"RocksDB", info::versions::ABI, 0, {0}, []
	(auto &, const mutable_buffer &buf)
	{
		#if defined(IRCD_DB_HAS_VERSION_ABI)
		fmt::sprintf
		{
			buf, "%s",
			rocksdb::GetRocksVersionAsString(true),
		};
		#endif
	}
};

ircd::conf::item<size_t>
ircd::db::request_pool_stack_size
{
	{ "name",     "ircd.db.request_pool.stack_size" },
	{ "default",  long(128_KiB)                     },
};

ircd::conf::item<size_t>
ircd::db::request_pool_size
{
	{
		{ "name",     "ircd.db.request_pool.size" },
		{ "default",  0L                          },
	},
	[](conf::item<void> &)
	{
		request.set(size_t(request_pool_size));
	}
};

decltype(ircd::db::request_pool_opts)
ircd::db::request_pool_opts
{
	.stack_size = size_t(request_pool_stack_size),
	.initial = size_t(request_pool_size),
};

/// Concurrent request pool. Requests to seek may be executed on this
/// pool in cases where a single context would find it advantageous.
/// Some examples are a db::row seek, or asynchronous prefetching.
///
/// The number of workers in this pool should upper bound at the
/// number of concurrent AIO requests which are effective on this
/// system. This is a static pool shared by all databases.
[[clang::always_destroy]]
decltype(ircd::db::request)
ircd::db::request
{
	"db req", request_pool_opts
};

///////////////////////////////////////////////////////////////////////////////
//
// init
//

decltype(ircd::db::init::direct_io_test_file_path)
ircd::db::init::direct_io_test_file_path
{
	fs::path_string(fs::path_views
	{
		fs::base::db, "SUPPORTS_DIRECT_IO"_sv
	})
};

ircd::db::init::init()
try
{
	const ctx::uninterruptible::nothrow ui;

	if constexpr(IRCD_DEFINED(IRCD_DB_HAS_ALLOCATOR))
		database::allocator::init();

	compressions();
	directory();
	request_pool();
	test_direct_io();
	test_hw_crc32();
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "Cannot start database system :%s",
		e.what()
	};

	throw;
}

[[gnu::cold]]
ircd::db::init::~init()
noexcept
{
	delete prefetcher;
	prefetcher = nullptr;

	if(request.active())
		log::warning
		{
			log, "Terminating %zu active of %zu client request contexts; %zu pending; %zu queued",
			request.active(),
			request.size(),
			request.pending(),
			request.queued()
		};

	request.terminate();
	log::logf
	{
		log, log::level::DEBUG,
		"Waiting for %zu active of %zu client request contexts; %zu pending; %zu queued",
		request.active(),
		request.size(),
		request.pending(),
		request.queued()
	};

	request.join();
	log::debug
	{
		log, "All contexts joined; all requests are clear."
	};

	if constexpr(IRCD_DEFINED(IRCD_DB_HAS_ALLOCATOR))
		database::allocator::fini();
}

void
ircd::db::init::directory()
try
{
	const string_view &dbdir
	{
		fs::base::db
	};

	if(!fs::is_dir(dbdir) && ircd::read_only)
		log::warning
		{
			log, "Not creating database directory `%s' in read-only/maintenance mode.",
			dbdir
		};
	else if(fs::mkdir(dbdir))
		log::notice
		{
			log, "Created new database directory at `%s'",
			dbdir
		};
	else
		log::logf
		{
			log, log::level::DEBUG,
			"Using database directory at `%s'",
			dbdir
		};
}
catch(const fs::error &e)
{
	log::error
	{
		log, "Database directory error: %s",
		e.what()
	};

	throw;
}

void
ircd::db::init::test_direct_io()
try
{
	const auto &test_file_path
	{
		direct_io_test_file_path
	};

	if(fs::support::direct_io(test_file_path))
		log::logf
		{
			log, log::level::DEBUG,
			"Detected Direct-IO works by opening test file at `%s'",
			test_file_path
		};
	else
		log::warning
		{
			log, "Direct-IO is not supported in the database directory `%s'"
			"; Concurrent database queries will not be possible.",
			string_view{fs::base::db}
		};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Failed to test if Direct-IO possible with test file `%s'"
		"; Concurrent database queries will not be possible :%s",
		direct_io_test_file_path,
		e.what()
	};
}

namespace rocksdb::crc32c
{
	extern std::string IsFastCrc32Supported();
}

void
ircd::db::init::test_hw_crc32()
try
{
	const auto supported_str
	{
		rocksdb::crc32c::IsFastCrc32Supported()
	};

	const bool supported
	{
		startswith(supported_str, "Supported")
	};

	assert(supported || startswith(supported_str, "Not supported"));

	if(!supported)
		log::warning
		{
			log, "crc32c hardware acceleration is not available on this platform."
		};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Failed to test crc32c hardware acceleration support :%s",
		e.what()
	};
}

[[clang::always_destroy]]
decltype(ircd::db::compressions)
ircd::db::compressions;

void
ircd::db::init::compressions()
try
{
	auto supported
	{
		rocksdb::GetSupportedCompressions()
	};

	size_t i(0);
	for(const rocksdb::CompressionType &type_ : supported) try
	{
		auto &[string, type]
		{
			db::compressions.at(i++)
		};

		type = type_;
		throw_on_error
		{
			rocksdb::GetStringFromCompressionType(&string, type_)
		};

		log::debug
		{
			log, "Detected supported compression #%zu type:%lu :%s",
			i,
			type,
			string,
		};
	}
	catch(const std::exception &e)
	{
		log::error
		{
			log, "Failed to identify compression type:%u :%s",
			uint(type_),
			e.what()
		};
	}

	if(supported.empty())
		log::warning
		{
			"No compression libraries have been linked with the DB."
			" This is probably not what you want."
		};
}
catch(const std::exception &e)
{
	log::error
	{
		log, "Failed to initialize database compressions :%s",
		e.what()
	};

	throw;
}

void
ircd::db::init::request_pool()
{
	char buf[32];
	const string_view value
	{
		conf::get(buf, "ircd.fs.aio.max_events")
	};

	const size_t aio_max_events
	{
		lex_castable<size_t>(value)?
			lex_cast<size_t>(value):
			0UL
	};

	const size_t new_size
	{
		size_t(request_pool_size)?
			request_pool_size:
		aio_max_events?
			aio_max_events:
			1UL
	};

	request_pool_size.set(lex_cast(new_size));
}

///////////////////////////////////////////////////////////////////////////////
//
// db/stats.h
//

std::string
ircd::db::string(const rocksdb::IOStatsContext &ic,
                 const bool &all)
{
	const bool exclude_zeros(!all);
	return ic.ToString(exclude_zeros);
}

const rocksdb::IOStatsContext &
ircd::db::iostats_current()
{
	const auto *const &ret
	{
		rocksdb::get_iostats_context()
	};

	if(unlikely(!ret))
		throw error
		{
			"IO counters are not available on this thread."
		};

	return *ret;
}

std::string
ircd::db::string(const rocksdb::PerfContext &pc,
                 const bool &all)
{
	const bool exclude_zeros(!all);
	return pc.ToString(exclude_zeros);
}

const rocksdb::PerfContext &
ircd::db::perf_current()
{
	const auto *const &ret
	{
		rocksdb::get_perf_context()
	};

	if(unlikely(!ret))
		throw error
		{
			"Performance counters are not available on this thread."
		};

	return *ret;
}

void
ircd::db::perf_level(const uint &level)
{
	if(level >= rocksdb::PerfLevel::kOutOfBounds)
		throw error
		{
			"Perf level of '%u' is invalid; maximum is '%u'",
			level,
			uint(rocksdb::PerfLevel::kOutOfBounds)
		};

	rocksdb::SetPerfLevel(rocksdb::PerfLevel(level));
}

uint
ircd::db::perf_level()
{
	return rocksdb::GetPerfLevel();
}

//
// ticker
//

uint64_t
ircd::db::ticker(const database &d,
                 const string_view &key)
{
	return ticker(d, ticker_id(key));
}

uint64_t
ircd::db::ticker(const database &d,
                 const uint32_t &id)
{
	return d.stats->getTickerCount(id);
}

uint32_t
ircd::db::ticker_id(const string_view &key)
{
	for(const auto &pair : rocksdb::TickersNameMap)
		if(key == pair.second)
			return pair.first;

	throw std::out_of_range
	{
		"No ticker with that key"
	};
}

ircd::string_view
ircd::db::ticker_id(const uint32_t &id)
{
	for(const auto &pair : rocksdb::TickersNameMap)
		if(id == pair.first)
			return pair.second;

	return {};
}

decltype(ircd::db::ticker_max)
ircd::db::ticker_max
{
	rocksdb::TICKER_ENUM_MAX
};

//
// histogram
//

const struct ircd::db::histogram &
ircd::db::histogram(const database &d,
                    const string_view &key)
{
	return histogram(d, histogram_id(key));
}

const struct ircd::db::histogram &
ircd::db::histogram(const database &d,
                    const uint32_t &id)
{
	return d.stats->histogram.at(id);
}

uint32_t
ircd::db::histogram_id(const string_view &key)
{
	for(const auto &pair : rocksdb::HistogramsNameMap)
		if(key == pair.second)
			return pair.first;

	throw std::out_of_range
	{
		"No histogram with that key"
	};
}

ircd::string_view
ircd::db::histogram_id(const uint32_t &id)
{
	for(const auto &pair : rocksdb::HistogramsNameMap)
		if(id == pair.first)
			return pair.second;

	return {};
}

decltype(ircd::db::histogram_max)
ircd::db::histogram_max
{
	rocksdb::HISTOGRAM_ENUM_MAX
};

///////////////////////////////////////////////////////////////////////////////
//
// db/prefetcher.h
//

decltype(ircd::db::prefetcher)
ircd::db::prefetcher;

//
// db::prefetcher
//

decltype(ircd::db::prefetcher::enable)
ircd::db::prefetcher::enable
{
	{ "name",     "ircd.db.prefetch.enable" },
	{ "default",  true                      },
};

decltype(ircd::db::prefetcher::worker_stack_size)
ircd::db::prefetcher::worker_stack_size
{
	{ "name",     "ircd.db.prefetch.worker.stack_size" },
	{ "default",  long(256_KiB)                        },
};

//
// db::prefetcher::prefetcher
//

ircd::db::prefetcher::prefetcher()
:ticker
{
	std::make_unique<struct ticker>()
}
,context
{
	"db.prefetcher",
	size_t(worker_stack_size),
	context::POST,
	std::bind(&prefetcher::worker, this)
}
{
}

ircd::db::prefetcher::~prefetcher()
noexcept
{
	log::debug
	{
		log, "Stopping prefetcher..."
	};

	while(!queue.empty())
	{
		log::warning
		{
			log, "Prefetcher waiting for %zu requests to clear...",
			queue.size(),
		};

		fini.wait_for(seconds(5), [this]() noexcept
		{
			return queue.empty();
		});
	}

	assert(queue.empty());
}

bool
ircd::db::prefetcher::operator()(column &c,
                                 const string_view &key,
                                 const gopts &opts)
{
	auto &d
	{
		static_cast<database &>(c)
	};

	assert(ticker);
	ticker->queries++;
	if(db::cached(c, key, opts))
	{
		ticker->rejects++;
		return false;
	}

	queue.emplace_back(d, c, key);
	queue.back().snd = now<steady_point>();
	ticker->request++;

	// Branch here based on whether it's not possible to directly dispatch
	// a db::request worker. If all request workers are busy we notify our own
	// prefetcher worker, and then it blocks on submitting to the request
	// worker instead of us blocking here. This is done to avoid use and growth
	// of any request pool queue, and allow for more direct submission.
	if(db::request.wouldblock())
	{
		work.notify_one();

		// If the user sets NO_BLOCKING we honor their request to not
		// context switch for a prefetch. However by default we want to
		// control queue growth, so we insert voluntary yield here to allow
		// prefetch operations to at least be processed before returning to
		// the user submitting more prefetches.
		if(likely(opts.blocking))
			ctx::yield();

		return true;
	}

	const ctx::critical_assertion ca;
	ticker->directs++;
	this->handle();
	return true;
}

size_t
ircd::db::prefetcher::cancel(column &c)
{
	return cancel([&c]
	(const auto &request) noexcept
	{
		return request.cid == id(c);
	});
}

size_t
ircd::db::prefetcher::cancel(database &d)
{
	return cancel([&d]
	(const auto &request) noexcept
	{
		return request.d == std::addressof(d);
	});
}

size_t
ircd::db::prefetcher::cancel(const closure &closure)
{
	size_t canceled(0);
	for(auto &request : queue)
	{
		// already finished
		if(request.fin != steady_point::min())
			continue;

		// in progress; can't cancel
		if(request.req != steady_point::min())
			continue;

		// allow user to accept or reject
		if(!closure(request))
			continue;

		// cancel by precociously setting the finish time.
		request.fin = now<steady_point>();
		++canceled;
	}

	if(canceled)
		work.notify_all();

	assert(ticker);
	ticker->cancels += canceled;
	return canceled;
}

size_t
ircd::db::prefetcher::wait_pending()
{
	const size_t fetched
	{
		ticker->fetched
	};

	fini.wait([this, &fetched]() noexcept
	{
		return this->ticker->fetched >= fetched + this->request_workers;
	});

	assert(ticker->fetched >= fetched);
	return ticker->fetched - fetched;
}

void
ircd::db::prefetcher::worker()
try
{
	while(1)
	{
		work.wait([this]() noexcept
		{
			if(queue.empty())
				return false;

			assert(ticker);
			if(ticker->request <= ticker->handles)
				return false;

			return true;
		});

		handle();
	}
}
catch(const std::exception &e)
{
	log::critical
	{
		log, "prefetcher worker: %s",
		e.what()
	};
}

void
ircd::db::prefetcher::handle()
{
	auto handler
	{
		std::bind(&prefetcher::request_worker, this)
	};

	ticker->handles++;
	db::request(std::move(handler));
}

void
ircd::db::prefetcher::request_worker()
{
	const ctx::scope_notify notify
	{
		this->fini, ctx::scope_notify::all
	};

	const scope_count request_workers
	{
		this->request_workers
	};

	// Garbage collection of the queue invoked unconditionally on unwind.
	const unwind cleanup_on_leave
	{
		std::bind(&prefetcher::request_cleanup, this)
	};

	// GC the queue here to get rid of any cancelled requests which have
	// arrived at the front so they don't become our request.
	const size_t cleanup_on_enter
	{
		request_cleanup()
	};

	// Find the first request in the queue which does not have its req
	// timestamp sent.
	auto request
	{
		std::find_if(begin(queue), end(queue), []
		(const auto &request)
		{
			return request.req == steady_point::min();
		})
	};

	if(request == end(queue))
		return;

	assert(ticker);
	assert(request->fin == steady_point::min());
	request->req = now<steady_point>();
	ticker->last_snd_req = duration_cast<microseconds>(request->req - request->snd);
	static_cast<microseconds &>(ticker->accum_snd_req) += ticker->last_snd_req;

	request_handle(*request);
	assert(request->fin != steady_point::min());
	ticker->fetched++;

	if constexpr(RB_DEBUG_DB_PREFETCH)
		log::debug
		{
			log, "prefetcher reject:%zu request:%zu handle:%zu fetch:%zu direct:%zu cancel:%zu queue:%zu rw:%zu",
			size_t(ticker->rejects),
			size_t(ticker->request),
			size_t(ticker->handles),
			size_t(ticker->fetched),
			size_t(ticker->directs),
			size_t(ticker->cancels),
			queue.size(),
			this->request_workers,
		};
}

size_t
ircd::db::prefetcher::request_cleanup()
noexcept
{
	size_t removed(0);
	const ctx::critical_assertion ca;
	for(; !queue.empty() && queue.front().fin != steady_point::min(); ++removed)
		queue.pop_front();

	return removed;
}

void
ircd::db::prefetcher::request_handle(request &request)
try
{
	assert(request.d);
	db::column column
	{
		(*request.d)[request.cid]
	};

	const string_view key
	{
		request
	};

	const auto it
	{
		seek(column, key, gopts{})
	};

	const ctx::critical_assertion ca;
	request.fin = now<steady_point>();
	ticker->last_req_fin = duration_cast<microseconds>(request.fin - request.req);
	static_cast<microseconds &>(ticker->accum_req_fin) += ticker->last_req_fin;
	const bool lte
	{
		valid_lte(*it, key)
	};

	if(likely(lte))
	{
		ticker->fetched_bytes_key += size(it->key());
		ticker->fetched_bytes_val += size(it->value());
	}

	char pbuf[3][32];
	if constexpr(RB_DEBUG_DB_PREFETCH)
		log::debug
		{
			log, "[%s][%s] completed prefetch "
			"len:%zu lte:%b k:%zu v:%zu snd-req:%s req-fin:%s snd-fin:%s queue:%zu",
			name(*request.d),
			name(column),
			size(key),
			lte,
			lte? size(it->key()) : 0UL,
			lte? size(it->value()) : 0UL,
			pretty(pbuf[0], request.req - request.snd, 1),
			pretty(pbuf[1], request.fin - request.req, 1),
			pretty(pbuf[2], request.fin - request.snd, 1),
			queue.size(),
		};
}
catch(const std::exception &e)
{
	assert(request.d);
	request.fin = now<steady_point>();

	log::error
	{
		log, "[%s][%u] :%s",
		name(*request.d),
		request.cid,
		e.what(),
	};
}
catch(...)
{
	request.fin = now<steady_point>();
	throw;
}

//
// prefetcher::request
//

ircd::db::prefetcher::request::request(database &d,
                                       const column &c,
                                       const string_view &key)
noexcept
:d
{
	std::addressof(d)
}
,cid
{
	db::id(c)
}
,len
{
	 uint32_t(std::min(size(key), sizeof(this->key)))
}
,snd
{
	steady_point::min()
}
,req
{
	steady_point::min()
}
,fin
{
	steady_point::min()
}
{
	const size_t &len
	{
		buffer::copy(this->key, key)
	};

	assert(this->len == len);
}

ircd::db::prefetcher::request::operator
ircd::string_view()
const noexcept
{
	return
	{
		key, len
	};
}

//
// prefetcher::ticker
//

ircd::db::prefetcher::ticker::ticker()
:queries
{
	{ "name", "ircd.db.prefetch.queries" },
}
,rejects
{
	{ "name", "ircd.db.prefetch.rejects" },
}
,request
{
	{ "name", "ircd.db.prefetch.request" },
}
,directs
{
	{ "name", "ircd.db.prefetch.directs" },
}
,handles
{
	{ "name", "ircd.db.prefetch.handles" },
}
,fetched
{
	{ "name", "ircd.db.prefetch.fetched" },
}
,cancels
{
	{ "name", "ircd.db.prefetch.cancels" },
}
,fetched_bytes_key
{
	{ "name", "ircd.db.prefetch.fetched_bytes_key" },
}
,fetched_bytes_val
{
	{ "name", "ircd.db.prefetch.fetched_bytes_val" },
}
,last_snd_req
{
	{ "name", "ircd.db.prefetch.last_snd_req" },
}
,last_req_fin
{
	{ "name", "ircd.db.prefetch.last_req_fin" },
}
,accum_snd_req
{
	{ "name", "ircd.db.prefetch.accum_snd_req" },
}
,accum_req_fin
{
	{ "name", "ircd.db.prefetch.accum_req_fin" },
}
{
}

///////////////////////////////////////////////////////////////////////////////
//
// db/txn.h
//

void
ircd::db::get(database &d,
              const uint64_t &seq,
              const seq_closure &closure)
{
	for_each(d, seq, seq_closure_bool{[&closure]
	(txn &txn, const uint64_t &seq)
	{
		closure(txn, seq);
		return false;
	}});
}

void
ircd::db::for_each(database &d,
                   const uint64_t &seq,
                   const seq_closure &closure)
{
	for_each(d, seq, seq_closure_bool{[&closure]
	(txn &txn, const uint64_t &seq)
	{
		closure(txn, seq);
		return true;
	}});
}

bool
ircd::db::for_each(database &d,
                   const uint64_t &seq,
                   const seq_closure_bool &closure)
{
	std::unique_ptr<rocksdb::TransactionLogIterator> tit;
	{
		const ctx::uninterruptible::nothrow ui;
		throw_on_error
		{
			d.d->GetUpdatesSince(seq, &tit)
		};
	}

	assert(bool(tit));
	for(; tit->Valid(); tit->Next())
	{
		const ctx::uninterruptible ui;

		auto batchres
		{
			tit->GetBatch()
		};

		throw_on_error
		{
			tit->status()
		};

		db::txn txn
		{
			d, std::move(batchres.writeBatchPtr)
		};

		assert(bool(txn.wb));
		if(!closure(txn, batchres.sequence))
			return false;
	}

	return true;
}

ircd::string_view
ircd::db::debug(const mutable_buffer &buf,
                database &d,
                const rocksdb::WriteBatch &wb_,
                const long &fmt)
{
	auto &wb
	{
		mutable_cast(wb_)
	};

	txn t
	{
		d, std::unique_ptr<rocksdb::WriteBatch>{&wb}
	};

	const unwind release
	{
		std::bind(&txn::release, &t)
	};

	return debug(buf, t, fmt);
}

ircd::string_view
ircd::db::debug(const mutable_buffer &buf,
                const txn &t,
                const long &fmt)
{
	size_t len(0);

	if(fmt >= 0)
	{
		const rocksdb::WriteBatch &wb(t);
		len += size(db::debug(buf, wb));
	}

	if(fmt == 1)
	{
		for_each(t, [&buf, &len]
		(const delta &d)
		{
			char pbuf[2][64];
			len += copy(buf + len, '\n');
			len += fmt::sprintf
			{
				buf + len, "%18s %-12s | [%s...] %-20s => [%s...] %-20s",
				std::get<delta::COL>(d),
				reflect(std::get<delta::OP>(d)),
				"????????"_sv, //std::get<d.KEY>(d),
				pretty(pbuf[0], iec(size(std::get<delta::KEY>(d)))),
				"????????"_sv, //std::get<d.VAL>(d),
				pretty(pbuf[1], iec(size(std::get<delta::VAL>(d)))),
			};
		});

		len += copy(buf + len, '\n');
	}

	return string_view
	{
		data(buf), len
	};
}

void
ircd::db::for_each(const txn &t,
                   const delta_closure &closure)
{
	const auto re{[&closure]
	(const delta &delta)
	{
		closure(delta);
		return true;
	}};

	const database &d(t);
	const rocksdb::WriteBatch &wb(t);
	txn::handler h{d, re};
	wb.Iterate(&h);
}

bool
ircd::db::for_each(const txn &t,
                   const delta_closure_bool &closure)
{
	const database &d(t);
	const rocksdb::WriteBatch &wb(t);
	txn::handler h{d, closure};
	wb.Iterate(&h);
	return h._continue;
}

///
/// handler (db/database/txn.h)
///

rocksdb::Status
ircd::db::txn::handler::PutCF(const uint32_t cfid,
                              const Slice &key,
                              const Slice &val)
noexcept
{
	return callback(cfid, op::SET, key, val);
}

rocksdb::Status
ircd::db::txn::handler::DeleteCF(const uint32_t cfid,
                                 const Slice &key)
noexcept
{
	return callback(cfid, op::DELETE, key, {});
}

rocksdb::Status
ircd::db::txn::handler::DeleteRangeCF(const uint32_t cfid,
                                      const Slice &begin,
                                      const Slice &end)
noexcept
{
	return callback(cfid, op::DELETE_RANGE, begin, end);
}

rocksdb::Status
ircd::db::txn::handler::SingleDeleteCF(const uint32_t cfid,
                                       const Slice &key)
noexcept
{
	return callback(cfid, op::SINGLE_DELETE, key, {});
}

rocksdb::Status
ircd::db::txn::handler::MergeCF(const uint32_t cfid,
                                const Slice &key,
                                const Slice &value)
noexcept
{
	return callback(cfid, op::MERGE, key, value);
}

rocksdb::Status
ircd::db::txn::handler::MarkBeginPrepare(bool b)
noexcept
{
	ircd::not_implemented{};
	return Status::OK();
}

rocksdb::Status
ircd::db::txn::handler::MarkEndPrepare(const Slice &xid)
noexcept
{
	ircd::not_implemented{};
	return Status::OK();
}

rocksdb::Status
ircd::db::txn::handler::MarkCommit(const Slice &xid)
noexcept
{
	ircd::not_implemented{};
	return Status::OK();
}

rocksdb::Status
ircd::db::txn::handler::MarkRollback(const Slice &xid)
noexcept
{
	ircd::not_implemented{};
	return Status::OK();
}

rocksdb::Status
ircd::db::txn::handler::callback(const uint32_t &cfid,
                                 const op &op,
                                 const Slice &a,
                                 const Slice &b)
noexcept try
{
	auto &c{d[cfid]};
	const delta delta
	{
		op,
		db::name(c),
		slice(a),
		slice(b)
	};

	return callback(delta);
}
catch(const std::exception &e)
{
	_continue = false;
	log::critical
	{
		log, "txn::handler: cfid[%u]: %s",
		cfid,
		e.what()
	};

	ircd::terminate();
	__builtin_unreachable();
}

rocksdb::Status
ircd::db::txn::handler::callback(const delta &delta)
noexcept try
{
	_continue = cb(delta);
	return Status::OK();
}
catch(const std::exception &e)
{
	_continue = false;
	return Status::OK();
}

bool
ircd::db::txn::handler::Continue()
noexcept
{
	return _continue;
}

//
// txn
//

ircd::db::txn::txn(database &d,
                   const opts &opts)
:d{&d}
,wb
{
	std::make_unique<rocksdb::WriteBatch>(opts.reserve_bytes, opts.max_bytes)
}
{
}

ircd::db::txn::txn(database &d,
                   std::unique_ptr<rocksdb::WriteBatch> &&wb)
:d{&d}
,wb{std::move(wb)}
{
}

ircd::db::txn::~txn()
noexcept
{
}

void
ircd::db::txn::operator()(database &d,
                          const sopts &opts)
{
	assert(bool(wb));
	assert(this->state == state::BUILD);
	this->state = state::COMMIT;
	commit(d, *wb, opts);
	this->state = state::COMMITTED;
}

void
ircd::db::txn::clear()
{
	assert(bool(wb));
	wb->Clear();
	this->state = state::BUILD;
}

size_t
ircd::db::txn::size()
const
{
	assert(bool(wb));
	return wb->Count();
}

size_t
ircd::db::txn::bytes()
const
{
	assert(bool(wb));
	return wb->GetDataSize();
}

bool
ircd::db::txn::has(const op &op)
const
{
	assert(bool(wb));
	switch(op)
	{
		case op::GET:              assert(0); return false;
		case op::SET:              return wb->HasPut();
		case op::MERGE:            return wb->HasMerge();
		case op::DELETE:           return wb->HasDelete();
		case op::DELETE_RANGE:     return wb->HasDeleteRange();
		case op::SINGLE_DELETE:    return wb->HasSingleDelete();
	}

	return false;
}

bool
ircd::db::txn::has(const op &op,
                   const string_view &col)
const
{
	return !for_each(*this, delta_closure_bool{[&op, &col]
	(const auto &delta) noexcept
	{
		return std::get<delta::OP>(delta) != op &&
		       std::get<delta::COL>(delta) != col;
	}});
}

void
ircd::db::txn::at(const op &op,
                  const string_view &col,
                  const delta_closure &closure)
const
{
	if(unlikely(!get(op, col, closure)))
		throw not_found
		{
			"db::txn::at(%s, %s): no matching delta in transaction",
			reflect(op),
			col
		};
}

bool
ircd::db::txn::get(const op &op,
                   const string_view &col,
                   const delta_closure &closure)
const
{
	return !for_each(*this, delta_closure_bool{[&op, &col, &closure]
	(const delta &delta)
	{
		if(std::get<delta::OP>(delta) == op &&
		   std::get<delta::COL>(delta) == col)
		{
			closure(delta);
			return false;
		}
		else return true;
	}});
}

bool
ircd::db::txn::has(const op &op,
                   const string_view &col,
                   const string_view &key)
const
{
	return !for_each(*this, delta_closure_bool{[&op, &col, &key]
	(const auto &delta) noexcept
	{
		return std::get<delta::OP>(delta) != op &&
		       std::get<delta::COL>(delta) != col &&
		       std::get<delta::KEY>(delta) != key;
	}});
}

void
ircd::db::txn::at(const op &op,
                  const string_view &col,
                  const string_view &key,
                  const value_closure &closure)
const
{
	if(unlikely(!get(op, col, key, closure)))
		throw not_found
		{
			"db::txn::at(%s, %s, %s): no matching delta in transaction",
			reflect(op),
			col,
			key
		};
}

bool
ircd::db::txn::get(const op &op,
                   const string_view &col,
                   const string_view &key,
                   const value_closure &closure)
const
{
	return !for_each(*this, delta_closure_bool{[&op, &col, &key, &closure]
	(const delta &delta)
	{
		if(std::get<delta::OP>(delta) == op &&
		   std::get<delta::COL>(delta) == col &&
		   std::get<delta::KEY>(delta) == key)
		{
			closure(std::get<delta::VAL>(delta));
			return false;
		}
		else return true;
	}});
}

//
// txn::checkpoint
//

ircd::db::txn::checkpoint::checkpoint(txn &t)
:t{t}
{
	assert(bool(t.wb));
	t.wb->SetSavePoint();
}

ircd::db::txn::checkpoint::~checkpoint()
noexcept
{
	const ctx::uninterruptible::nothrow ui;
	if(likely(!std::uncaught_exceptions()))
		throw_on_error
		{
			t.wb->PopSavePoint()
		};
	else
		throw_on_error
		{
			t.wb->RollbackToSavePoint()
		};
}

//
// txn::append
//

ircd::db::txn::append::append(txn &t,
                              const string_view &key,
                              const json::iov &iov)
{
	std::for_each(std::begin(iov), std::end(iov), [&t, &key]
	(const auto &member)
	{
		append
		{
			t, delta
			{
				member.first,   // col
				key,            // key
				member.second   // val
			}
		};
	});
}

__attribute__((noreturn))
ircd::db::txn::append::append(txn &t,
                              const row::delta &delta)
{
	throw ircd::not_implemented
	{
		"db::txn::append (row::delta)"
	};
}

ircd::db::txn::append::append(txn &t,
                              const cell::delta &delta)
{
	db::append(*t.wb, delta);
}

ircd::db::txn::append::append(txn &t,
                              column &c,
                              const column::delta &delta)
{
	db::append(*t.wb, c, delta);
}

ircd::db::txn::append::append(txn &t,
                              database &d,
                              const delta &delta)
{
	db::column c
	{
		d[std::get<1>(delta)]
	};

	db::append(*t.wb, c, db::column::delta
	{
		std::get<op>(delta),
		std::get<2>(delta),
		std::get<3>(delta)
	});
}

///////////////////////////////////////////////////////////////////////////////
//
// db/row.h
//

namespace ircd::db
{
	static std::vector<rocksdb::Iterator *>
	_make_iterators(database &d,
	                database::column *const *const &columns,
	                const size_t &columns_size,
	                const rocksdb::ReadOptions &opts);
}

void
ircd::db::del(row &row,
              const sopts &sopts)
{
	write(row::delta{op::DELETE, row}, sopts);
}

void
ircd::db::write(const row::delta *const &begin,
                const row::delta *const &end,
                const sopts &sopts)
{
	// Count the total number of cells for this transaction.
	const auto cells
	{
		std::accumulate(begin, end, size_t(0), []
		(auto ret, const row::delta &delta)
		{
			const auto &row(std::get<row *>(delta));
			return ret += row->size();
		})
	};

	//TODO: allocator?
	std::vector<cell::delta> deltas;
	deltas.reserve(cells);

	// Compose all of the cells from all of the rows into a single txn
	std::for_each(begin, end, [&deltas]
	(const auto &delta)
	{
		const auto &op(std::get<op>(delta));
		const auto &row(std::get<row *>(delta));
		std::for_each(std::begin(*row), std::end(*row), [&deltas, &op]
		(auto &cell)
		{
			// For operations like DELETE which don't require a value in
			// the delta, we can skip a potentially expensive load of the cell.
			const auto value
			{
				value_required(op)? cell.val() : string_view{}
			};

			deltas.emplace_back(op, cell, value);
		});
	});

	// Commitment
	write(&deltas.front(), &deltas.front() + deltas.size(), sopts);
}

size_t
ircd::db::seek(row &r,
               const string_view &key,
               const gopts &opts)
{
	// The following closure performs the seek() for a single cell in the row.
	// It may be executed on another ircd::ctx if the data isn't cached and
	// blocking IO is required. This frame can't be interrupted because it may
	// have requests pending in the request pool which must synchronize back
	// here.
	size_t ret{0};
	std::exception_ptr eptr;
	ctx::latch latch{r.size()};
	const ctx::uninterruptible ui;
	const auto closure{[&opts, &latch, &ret, &key, &eptr]
	(auto &cell) noexcept
	{
		// If there's a pending error from another cell by the time this
		// closure is executed we don't perform the seek() unless the user
		// specifies db::gopts::throwing=0 to suppress it.
		if(!eptr || opts.throwing == false) try
		{
			if(!seek(cell, key))
			{
				// If the cell is not_found that's not a thrown exception here;
				// the cell will just be !valid(). The user can option
				// throwing=1 to propagate a not_found from the seek(row).
				if(opts.throwing == true)
					throw not_found
					{
						"column '%s' key '%s'", cell.col(), key
					};
			}
			else ++ret;
		}
		catch(const not_found &e)
		{
			eptr = std::current_exception();
		}
		catch(const std::exception &e)
		{
			log::error
			{
				log, "row seek: column '%s' key '%s' :%s",
				cell.col(),
				key,
				e.what()
			};

			eptr = std::make_exception_ptr(e);
		}

		// The latch must always be hit here. No exception should propagate
		// to prevent this from being reached or beyond.
		latch.count_down();
	}};

	size_t submits{0};
	util::timer timer{util::timer::nostart};
	if constexpr(RB_DEBUG_DB_SEEK_ROW)
		timer = util::timer{};

	// Submit all the requests
	for(auto &cell : r)
	{
		db::column &column(cell);
		const auto reclosure{[&closure, &cell]
		() noexcept
		{
			closure(cell);
		}};

		// Whether to submit the request to another ctx or execute it here.
		// Explicit option to prevent submitting must not be set. If there
		// is a chance the data is already in the cache, we can avoid the
		// context switching and occupation of the request pool.
		const bool submit
		{
			r.size() > 1 &&
			opts.parallel &&
			!db::cached(column, key, opts)
		};

		if constexpr(RB_DEBUG_DB_SEEK_ROW)
			submits += submit;

		if(submit)
			request(reclosure);
		else
			reclosure();
	}

	// Wait for responses.
	latch.wait();
	assert(ret <= r.size());

	if constexpr(RB_DEBUG_DB_SEEK_ROW)
		if(likely(!r.empty()))
		{
			thread_local char tmbuf[32];
			const auto elapsed(timer.at<microseconds>());
			const column &c(r[0]);
			const database &d(c);
			log::debug
			{
				log, "'%s' SEEK ROW seq:%lu:%-10lu cnt:%-2zu req:%-2zu ret:%-2zu in %s %s",
				name(d),
				sequence(d),
				sequence(opts.snapshot),
				r.size(),
				submits,
				ret,
				pretty(tmbuf, elapsed, true),
				what(eptr)
			};
		}

	if(eptr && opts.throwing != false)
		std::rethrow_exception(eptr);

	return ret;
}

//
// row
//
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
__attribute__((stack_protect))
ircd::db::row::row(database &d,
                   const string_view &key,
                   const vector_view<const string_view> &colnames,
                   const vector_view<cell> &buf,
                   gopts opts)
{
	using std::end;
	using std::begin;

	if(!opts.snapshot)
		opts.snapshot = database::snapshot(d);

	const rocksdb::ReadOptions options
	{
		make_opts(opts)
	};

	assert(buf.size() >= colnames.size());
	const size_t request_count
	{
		std::min(colnames.size(), buf.size())
	};

	size_t count(0);
	database::column *colptr[request_count];
	for(size_t i(0); i < request_count; ++i)
	{
		const auto cfid
		{
			d.cfid(std::nothrow, colnames.at(i))
		};

		if(cfid >= 0)
			colptr[count++] = &d[cfid];
	}

	// All pointers returned by rocksdb in this vector must be free'd.
	const auto iterators
	{
		_make_iterators(d, colptr, count, options)
	};

	assert(iterators.size() == count);
	for(size_t i(0); i < iterators.size(); ++i)
	{
		std::unique_ptr<rocksdb::Iterator> it
		{
			iterators.at(i)
		};

		buf[i] = cell
		{
			*colptr[i], std::move(it), opts
		};
	}

	static_cast<vector_view<cell> &>(*this) =
	{
		buf.data(), iterators.size()
	};

	if(key)
		seek(*this, key, opts);
}
#pragma GCC diagnostic pop

static std::vector<rocksdb::Iterator *>
ircd::db::_make_iterators(database &d,
                          database::column *const *const &column,
                          const size_t &column_count,
                          const rocksdb::ReadOptions &opts)
{
	using rocksdb::Iterator;
	using rocksdb::ColumnFamilyHandle;
	assert(column_count <= d.columns.size());

	//const ctx::critical_assertion ca;
	// NewIterators() has been seen to lead to IO and block the ircd::ctx;
	// specifically when background options are aggressive and shortly
	// after db opens. It would be nice if we could maintain the
	// critical_assertion for this function, as we could eliminate the
	// vector allocation for ColumnFamilyHandle pointers.

	std::vector<ColumnFamilyHandle *> handles(column_count);
	std::transform(column, column + column_count, begin(handles), []
	(database::column *const &ptr)
	{
		assert(ptr);
		return ptr->handle.get();
	});

	std::vector<Iterator *> ret;
	const ctx::stack_usage_assertion sua;
	const ctx::uninterruptible::nothrow ui;
	throw_on_error
	{
		d.d->NewIterators(opts, handles, &ret)
	};

	return ret;
}

void
ircd::db::row::operator()(const op &op,
                          const string_view &col,
                          const string_view &val,
                          const sopts &sopts)
{
	write(cell::delta{op, (*this)[col], val}, sopts);
}

ircd::db::cell &
ircd::db::row::operator[](const string_view &column)
{
	const auto it(find(column));
	if(unlikely(it == end()))
		throw not_found
		{
			"column '%s' not specified in the descriptor schema", column
		};

	return *it;
}

const ircd::db::cell &
ircd::db::row::operator[](const string_view &column)
const
{
	const auto it(find(column));
	if(unlikely(it == end()))
		throw not_found
		{
			"column '%s' not specified in the descriptor schema", column
		};

	return *it;
}

ircd::db::row::iterator
ircd::db::row::find(const string_view &col)
{
	return std::find_if(std::begin(*this), std::end(*this), [&col]
	(const auto &cell)
	{
		return name(cell.c) == col;
	});
}

ircd::db::row::const_iterator
ircd::db::row::find(const string_view &col)
const
{
	return std::find_if(std::begin(*this), std::end(*this), [&col]
	(const auto &cell)
	{
		return name(cell.c) == col;
	});
}

bool
ircd::db::row::cached()
const
{
	return std::all_of(std::begin(*this), std::end(*this), []
	(const auto &cell)
	{
		db::column &column(mutable_cast(cell));
		return cell.valid() && db::cached(column, cell.key());
	});
}

bool
ircd::db::row::cached(const string_view &key)
const
{
	return std::all_of(std::begin(*this), std::end(*this), [&key]
	(const auto &cell)
	{
		db::column &column(mutable_cast(cell));
		return db::cached(column, key);
	});
}

bool
ircd::db::row::valid_all(const string_view &s)
const
{
	return !empty() && std::all_of(std::begin(*this), std::end(*this), [&s]
	(const auto &cell)
	{
		return cell.valid(s);
	});
}

bool
ircd::db::row::valid(const string_view &s)
const
{
	return std::any_of(std::begin(*this), std::end(*this), [&s]
	(const auto &cell)
	{
		return cell.valid(s);
	});
}

bool
ircd::db::row::valid_all()
const
{
	return !empty() && std::all_of(std::begin(*this), std::end(*this), []
	(const auto &cell)
	{
		return cell.valid();
	});
}

bool
ircd::db::row::valid()
const
{
	return std::any_of(std::begin(*this), std::end(*this), []
	(const auto &cell)
	{
		return cell.valid();
	});
}

///////////////////////////////////////////////////////////////////////////////
//
// db/cell.h
//

uint64_t
ircd::db::sequence(const cell &c)
{
	const database::snapshot &ss(c);
	return sequence(database::snapshot(c));
}

const std::string &
ircd::db::name(const cell &c)
{
	return name(c.c);
}

void
ircd::db::write(const cell::delta &delta,
                const sopts &sopts)
{
	write(&delta, &delta + 1, sopts);
}

void
ircd::db::write(const sopts &sopts,
                const std::initializer_list<cell::delta> &deltas)
{
	write(deltas, sopts);
}

void
ircd::db::write(const std::initializer_list<cell::delta> &deltas,
                const sopts &sopts)
{
	write(std::begin(deltas), std::end(deltas), sopts);
}

void
ircd::db::write(const cell::delta *const &begin,
                const cell::delta *const &end,
                const sopts &sopts)
{
	if(begin == end)
		return;

	// Find the database through one of the cell's columns. cell::deltas
	// may come from different columns so we do nothing else with this.
	auto &front(*begin);
	column &c(std::get<cell *>(front)->c);
	database &d(c);

	rocksdb::WriteBatch batch;
	std::for_each(begin, end, [&batch]
	(const cell::delta &delta)
	{
		append(batch, delta);
	});

	commit(d, batch, sopts);
}

template<class pos>
bool
ircd::db::seek(cell &c,
               const pos &p,
               gopts opts)
{
	column &cc(c);
	database::column &dc(cc);

	if(!opts.snapshot)
		opts.snapshot = c.ss;

	const auto ropts(make_opts(opts));
	return seek(dc, p, ropts, c.it);
}
template bool ircd::db::seek<ircd::db::pos>(cell &, const pos &, gopts);
template bool ircd::db::seek<ircd::string_view>(cell &, const string_view &, gopts);

// Linkage for incomplete rocksdb::Iterator
[[gnu::hot]]
ircd::db::cell::cell()
noexcept
{
}

ircd::db::cell::cell(database &d,
                     const string_view &colname,
                     const gopts &opts)
:cell
{
	column(d[colname]), std::unique_ptr<rocksdb::Iterator>{}, opts
}
{
}

ircd::db::cell::cell(database &d,
                     const string_view &colname,
                     const string_view &index,
                     const gopts &opts)
:cell
{
	column(d[colname]), index, opts
}
{
}

ircd::db::cell::cell(column column,
                     const string_view &index,
                     const gopts &opts)
:c{std::move(column)}
,ss{opts.snapshot}
,it
{
	!index.empty()?
		seek(this->c, index, opts):
		std::unique_ptr<rocksdb::Iterator>{}
}
{
	if(bool(this->it))
		if(!valid_eq(*this->it, index))
			this->it.reset();
}

ircd::db::cell::cell(column column,
                     const string_view &index,
                     std::unique_ptr<rocksdb::Iterator> it,
                     const gopts &opts)
:c{std::move(column)}
,ss{opts.snapshot}
,it{std::move(it)}
{
	if(index.empty())
		return;

	seek(*this, index, opts);
	if(!valid_eq(*this->it, index))
		this->it.reset();
}

ircd::db::cell::cell(column column,
                     std::unique_ptr<rocksdb::Iterator> it,
                     const gopts &opts)
:c{std::move(column)}
,ss{opts.snapshot}
,it{std::move(it)}
{
}

// Linkage for incomplete rocksdb::Iterator
ircd::db::cell::cell(cell &&o)
noexcept
:c{std::move(o.c)}
,ss{std::move(o.ss)}
,it{std::move(o.it)}
{
}

// Linkage for incomplete rocksdb::Iterator
ircd::db::cell &
ircd::db::cell::operator=(cell &&o)
noexcept
{
	c = std::move(o.c);
	ss = std::move(o.ss);
	it = std::move(o.it);

	return *this;
}

// Linkage for incomplete rocksdb::Iterator
[[gnu::hot]]
ircd::db::cell::~cell()
noexcept
{
}

bool
ircd::db::cell::load(const string_view &index,
                     gopts opts)
{
	database &d(c);
	if(valid(index) && !opts.snapshot && sequence(ss) == sequence(d))
		return true;

	if(bool(opts.snapshot))
	{
		this->it.reset();
		this->ss = std::move(opts.snapshot);
	}

	database::column &c(this->c);
	const auto _opts
	{
		make_opts(opts)
	};

	if(!seek(c, index, _opts, this->it))
		return false;

	return valid(index);
}

ircd::db::cell &
ircd::db::cell::operator=(const string_view &s)
{
	write(c, key(), s);
	return *this;
}

void
ircd::db::cell::operator()(const op &op,
                           const string_view &val,
                           const sopts &sopts)
{
	write(cell::delta{op, *this, val}, sopts);
}

ircd::string_view
ircd::db::cell::val()
{
	if(!valid())
		load();

	return likely(valid())? db::val(*it) : string_view{};
}

ircd::string_view
ircd::db::cell::key()
{
	if(!valid())
		load();

	return likely(valid())? db::key(*it) : string_view{};
}

ircd::string_view
ircd::db::cell::val()
const
{
	return likely(valid())? db::val(*it) : string_view{};
}

ircd::string_view
ircd::db::cell::key()
const
{
	return likely(valid())? db::key(*it) : string_view{};
}

bool
ircd::db::cell::valid(const string_view &s)
const
{
	return valid() && db::valid_eq(*it, s);
}

bool
ircd::db::cell::valid_gt(const string_view &s)
const
{
	return valid() && db::valid_gt(*it, s);
}

bool
ircd::db::cell::valid_lte(const string_view &s)
const
{
	return valid() && db::valid_lte(*it, s);
}

///////////////////////////////////////////////////////////////////////////////
//
// db/domain.h
//

bool
ircd::db::seek(domain::const_iterator_base &it,
               const pos &p)
{
	switch(p)
	{
		// This is inefficient as per RocksDB's prefix impl.
		case pos::BACK:
		{
			char buf[512];
			string_view key;
			assert(bool(it)); do
			{
				assert(size(it.it->key()) <= sizeof(buf));
				key = string_view(buf, copy(buf, slice(it.it->key())));
			}
			while(seek(it, pos::NEXT));

			assert(key);
			return seek(it, key);
		}

		default:
			break;
	}

	it.opts.prefix = true;
	return seek(static_cast<column::const_iterator_base &>(it), p);
}

ircd::db::domain::const_iterator
ircd::db::domain::begin(const string_view &key,
                        gopts opts)
{
	const_iterator ret
	{
		c, {}, std::move(opts)
	};

	seek(ret, key);
	return ret;
}

ircd::db::domain::const_iterator
ircd::db::domain::end(const string_view &key,
                      gopts opts)
{
	const_iterator ret
	{
		c, {}, std::move(opts)
	};

	if(seek(ret, key))
		seek(ret, pos::END);

	return ret;
}

/// NOTE: RocksDB says they don't support reverse iteration over a prefix range
/// This means we have to forward scan to the end and then walk back! Reverse
/// iterations of a domain should only be used for debugging and statistics! The
/// domain should be ordered the way it will be primarily accessed using the
/// comparator. If it will be accessed in different directions, make another
/// domain column.
ircd::db::domain::const_reverse_iterator
ircd::db::domain::rbegin(const string_view &key,
                         gopts opts)
{
	const_reverse_iterator ret
	{
		c, {}, std::move(opts)
	};

	if(seek(ret, key))
		seek(ret, pos::BACK);

	return ret;
}

ircd::db::domain::const_reverse_iterator
ircd::db::domain::rend(const string_view &key,
                       gopts opts)
{
	const_reverse_iterator ret
	{
		c, {}, std::move(opts)
	};

	if(seek(ret, key))
		seek(ret, pos::END);

	return ret;
}

//
// const_iterator
//

ircd::db::domain::const_iterator &
ircd::db::domain::const_iterator::operator--()
{
	if(likely(bool(*this)))
		seek(*this, pos::PREV);
	else
		seek(*this, pos::BACK);

	return *this;
}

ircd::db::domain::const_iterator &
ircd::db::domain::const_iterator::operator++()
{
	if(likely(bool(*this)))
		seek(*this, pos::NEXT);
	else
		seek(*this, pos::FRONT);

	return *this;
}

ircd::db::domain::const_reverse_iterator &
ircd::db::domain::const_reverse_iterator::operator--()
{
	if(likely(bool(*this)))
		seek(*this, pos::NEXT);
	else
		seek(*this, pos::FRONT);

	return *this;
}

ircd::db::domain::const_reverse_iterator &
ircd::db::domain::const_reverse_iterator::operator++()
{
	if(likely(bool(*this)))
		seek(*this, pos::PREV);
	else
		seek(*this, pos::BACK);

	return *this;
}

const ircd::db::domain::const_iterator_base::value_type &
ircd::db::domain::const_iterator_base::operator*()
const
{
	const auto &prefix
	{
		describe(*c).prefix
	};

	// Fetch the full value like a standard column first
	column::const_iterator_base::operator*();
	string_view &key{val.first};

	// When there's no prefixing this domain column is just
	// like a normal column. Otherwise, we remove the prefix
	// from the key the user will end up seeing.
	if(prefix.has && prefix.has(key))
	{
		const auto &first(prefix.get(key));
		const auto &second(key.substr(first.size()));
		key = second;
	}

	return val;
}

///////////////////////////////////////////////////////////////////////////////
//
// db/column.h
//

void
ircd::db::drop(column &column)
{
	database::column &c(column);
	drop(c);
}

void
ircd::db::check(column &column)
{
	database &d(column);
	const auto &files
	{
		db::files(column)
	};

	for(const auto &file : files)
	{
		const auto &path
		{
			 // remove false leading slash; the rest is relative to db.
			lstrip(file, '/')
		};

		db::check(d, path);
	}
}

void
ircd::db::sort(column &column,
               const bool &blocking,
               const bool &now)
{
	database::column &c(column);
	database &d(*c.d);

	rocksdb::FlushOptions opts;
	opts.wait = blocking;
	opts.allow_write_stall = now;

	const ctx::uninterruptible::nothrow ui;
	const std::lock_guard lock
	{
		d.write_mutex
	};

	log::debug
	{
		log, "[%s]'%s' @%lu FLUSH (sort) %s %s",
		name(d),
		name(c),
		sequence(d),
		blocking? "blocking"_sv: "non-blocking"_sv,
		now? "now"_sv: "later"_sv
	};

	throw_on_error
	{
		d.d->Flush(opts, c)
	};
}

void
ircd::db::compact(column &column,
                  const std::pair<int, int> &level,
                  const compactor &cb)
{
	database::column &c(column);
	database &d(*c.d);

	const auto &dst_level{level.second};
	const auto &src_level{level.first};

	rocksdb::ColumnFamilyMetaData cfmd;
	d.d->GetColumnFamilyMetaData(c, &cfmd);
	for(const auto &level : cfmd.levels)
	{
		if(src_level != -1 && src_level != level.level)
			continue;

		if(level.files.empty())
			continue;

		const ctx::uninterruptible ui;
		const std::lock_guard lock
		{
			d.write_mutex
		};

		const auto &to_level
		{
			dst_level > -1? dst_level : level.level
		};

		rocksdb::CompactionOptions opts;
		opts.output_file_size_limit = 1_GiB; //TODO: conf

		// RocksDB sez that setting this to Disable means that the column's
		// compression options are read instead. If we don't set this here,
		// rocksdb defaults to "snappy" (which is strange).
		opts.compression = rocksdb::kDisableCompressionOption;

		std::vector<std::string> files(level.files.size());
		std::transform(level.files.begin(), level.files.end(), files.begin(), []
		(auto &metadata)
		{
			return std::move(metadata.name);
		});

		log::debug
		{
			log, "[%s]'%s' COMPACT L%d -> L%d files:%zu size:%zu",
			name(d),
			name(c),
			level.level,
			to_level,
			level.files.size(),
			level.size,
		};

		// Save and restore the existing filter callback so we can allow our
		// caller to use theirs. Note that this manual compaction should be
		// exclusive for this column (no background compaction should be
		// occurring, at least one relying on this filter).
		assert(c.cfilter);
		auto their_filter(std::move(c.cfilter->user));
		const unwind unfilter{[&c, &their_filter]
		{
			assert(c.cfilter);
			c.cfilter->user = std::move(their_filter);
		}};

		c.cfilter->user = cb;
		throw_on_error
		{
			d.d->CompactFiles(opts, c, files, to_level)
		};
	}
}

void
ircd::db::compact(column &column,
                  const std::pair<string_view, string_view> &range,
                  const int &to_level,
                  const compactor &cb)
{
	database &d(column);
	database::column &c(column);
	const ctx::uninterruptible ui;

	const auto begin(slice(range.first));
	const rocksdb::Slice *const b
	{
		empty(range.first)? nullptr : &begin
	};

	const auto end(slice(range.second));
	const rocksdb::Slice *const e
	{
		empty(range.second)? nullptr : &end
	};

	rocksdb::CompactRangeOptions opts;
	opts.exclusive_manual_compaction = true;
	opts.allow_write_stall = true;
	opts.change_level = true;
	opts.target_level = std::max(to_level, -1);
	opts.bottommost_level_compaction = rocksdb::BottommostLevelCompaction::kForce;

	log::debug
	{
		log, "[%s]'%s' @%lu COMPACT [%s, %s] -> L:%d (Lmax:%d Lbase:%d)",
		name(d),
		name(c),
		sequence(d),
		range.first,
		range.second,
		opts.target_level,
		d.d->NumberLevels(c),
		d.d->MaxMemCompactionLevel(c),
	};

	// Save and restore the existing filter callback so we can allow our
	// caller to use theirs. Note that this manual compaction should be
	// exclusive for this column (no background compaction should be
	// occurring, at least one relying on this filter).
	assert(c.cfilter);
	auto their_filter(std::move(c.cfilter->user));
	const unwind unfilter{[&c, &their_filter]
	{
		assert(c.cfilter);
		c.cfilter->user = std::move(their_filter);
	}};

	c.cfilter->user = cb;
	throw_on_error
	{
		d.d->CompactRange(opts, c, b, e)
	};
}

void
ircd::db::setopt(column &column,
                 const string_view &key,
                 const string_view &val)
{
	database &d(column);
	database::column &c(column);
	const std::unordered_map<std::string, std::string> options
	{
		{ std::string{key}, std::string{val} }
	};

	const ctx::uninterruptible::nothrow ui;
	throw_on_error
	{
		d.d->SetOptions(c, options)
	};
}

void
ircd::db::ingest(column &column,
                 const string_view &path)
{
	database &d(column);
	database::column &c(column);

	rocksdb::IngestExternalFileOptions opts;
	opts.allow_global_seqno = true;
	opts.allow_blocking_flush = true;

	const ctx::uninterruptible::nothrow ui;
	const auto &copts
	{
		d.d->GetOptions(c)
	};

	// Automatically determine if we can avoid issuing new sequence
	// numbers by considering this ingestion as "backfill" of missing
	// data which did actually exist but was physically removed.
	opts.ingest_behind = copts.allow_ingest_behind;
	const std::vector<std::string> files
	{
		{ std::string{path} }
	};

	const std::lock_guard lock{d.write_mutex};
	throw_on_error
	{
		d.d->IngestExternalFile(c, files, opts)
	};
}

void
ircd::db::del(column &column,
              const std::pair<string_view, string_view> &range,
              const sopts &sopts)
{
	database &d(column);
	database::column &c(column);
	auto opts(make_opts(sopts));

	const std::lock_guard lock{d.write_mutex};
	const ctx::uninterruptible::nothrow ui;
	const ctx::stack_usage_assertion sua;
	log::debug
	{
		log, "'%s' %lu '%s' RANGE DELETE",
		name(d),
		sequence(d),
		name(c),
	};

	throw_on_error
	{
		d.d->DeleteRange(opts, c, slice(range.first), slice(range.second))
	};
}

void
ircd::db::del(column &column,
              const string_view &key,
              const sopts &sopts)
{
	database &d(column);
	database::column &c(column);
	auto opts(make_opts(sopts));

	const std::lock_guard lock{d.write_mutex};
	const ctx::uninterruptible::nothrow ui;
	const ctx::stack_usage_assertion sua;
	log::debug
	{
		log, "'%s' %lu '%s' DELETE key(%zu B)",
		name(d),
		sequence(d),
		name(c),
		key.size()
	};

	throw_on_error
	{
		d.d->Delete(opts, c, slice(key))
	};
}

void
ircd::db::write(column &column,
                const string_view &key,
                const const_buffer &val,
                const sopts &sopts)
{
	database &d(column);
	database::column &c(column);
	auto opts(make_opts(sopts));

	const std::lock_guard lock{d.write_mutex};
	const ctx::uninterruptible::nothrow ui;
	const ctx::stack_usage_assertion sua;
	log::debug
	{
		log, "'%s' %lu '%s' PUT key(%zu B) val(%zu B)",
		name(d),
		sequence(d),
		name(c),
		size(key),
		size(val)
	};

	throw_on_error
	{
		d.d->Put(opts, c, slice(key), slice(val))
	};
}

uint64_t
ircd::db::read(column &column,
               const keys &keys,
               const bufs &bufs,
               const gopts &opts)
{
	const columns columns
	{
		&column, 1
	};

	return read(columns, keys, bufs, opts);
}

uint64_t
ircd::db::read(const columns &c,
               const keys &key,
               const bufs &buf,
               const gopts &gopts)
{
	return read(c, key, gopts, [&buf]
	(const auto &view)
	{
		assert(buf.size() == view.size());
		for(uint i(0); i < buf.size(); ++i)
			buf[i] = mutable_buffer
			{
				buf[i], copy(buf[i], view[i])
			};
	});
}

uint64_t
ircd::db::read(const columns &c,
               const keys &key,
               const gopts &gopts,
               const views_closure &closure)
{
	if(c.empty())
		return 0UL;

	const auto &num
	{
		key.size()
	};

	if(unlikely(!num || num > 64))
		throw std::out_of_range
		{
			"db::read() :too many columns or vector size mismatch"
		};

	_read_op op[num];
	for(size_t i(0); i < num; ++i)
		op[i] =
		{
			c[std::min(c.size() - 1, i)], key[i]
		};

	uint64_t i(0), ret(0);
	string_view view[num];
	const auto opts(make_opts(gopts));
	_read({op, num}, opts, [&num, &i, &ret, &view, &closure]
	(column &, const column::delta &d, const rocksdb::Status &s)
	{
		const auto &val
		{
			std::get<column::delta::VAL>(d)
		};

		view[i] = val;
		ret |= (uint64_t(s.ok()) << i);

		// All results are available until _read() returns. The user is called
		// here with all results after the last result is set.
		if(++i == num)
			closure(views(view, num));

		return true;
	});

	assert(i == num);
	return ret;
}

std::string
ircd::db::read(column &column,
               const string_view &key,
               const gopts &gopts)
{
	std::string ret;
	const auto closure([&ret]
	(const string_view &src)
	{
		ret.assign(begin(src), end(src));
	});

	column(key, closure, gopts);
	return ret;
}

ircd::string_view
ircd::db::read(column &column,
               const string_view &key,
               const mutable_buffer &buf,
               const gopts &gopts)
{
	string_view ret;
	const auto closure([&ret, &buf]
	(const string_view &src)
	{
		ret = { data(buf), copy(buf, src) };
	});

	column(key, closure, gopts);
	return ret;
}

std::string
ircd::db::read(column &column,
               const string_view &key,
               bool &found,
               const gopts &gopts)
{
	std::string ret;
	const auto closure([&ret]
	(const string_view &src)
	{
		ret.assign(begin(src), end(src));
	});

	found = column(key, std::nothrow, closure, gopts);
	return ret;
}

ircd::string_view
ircd::db::read(column &column,
               const string_view &key,
               bool &found,
               const mutable_buffer &buf,
               const gopts &gopts)
{
	string_view ret;
	const auto closure([&buf, &ret]
	(const string_view &src)
	{
		ret = { data(buf), copy(buf, src) };
	});

	found = column(key, std::nothrow, closure, gopts);
	return ret;
}

size_t
ircd::db::bytes_value(column &column,
                      const string_view &key,
                      const gopts &gopts)
{
	size_t ret{0};
	column(key, std::nothrow, gopts, [&ret]
	(const string_view &value) noexcept
	{
		ret = value.size();
	});

	return ret;
}

size_t
ircd::db::bytes(column &column,
                const std::pair<string_view, string_view> &key,
                const gopts &gopts)
{
	const ctx::uninterruptible::nothrow ui;

	database &d(column);
	database::column &c(column);
	const rocksdb::Range range[1]
	{
		{ slice(key.first), slice(key.second) }
	};

	uint64_t ret[1] {0};
	d.d->GetApproximateSizes(c, range, 1, ret);
	return ret[0];
}

bool
ircd::db::has(column &column,
              const string_view &key,
              const gopts &gopts)
{
	database &d(column);
	database::column &c(column);

	// Perform a co-RP query to the filtration
	//
	// NOTE disabled for rocksdb >= v5.15 due to a regression
	// where rocksdb does not init SuperVersion data in the column
	// family handle and this codepath triggers null derefs and ub.
	//
	// NOTE works on rocksdb 6.6.4 but unconditionally copies value.
	auto opts(make_opts(gopts));
	if(c.table_opts.filter_policy && (false))
	{
		const ctx::uninterruptible::nothrow ui;

		auto opts(make_opts(gopts));
		const scope_restore read_tier
		{
			opts.read_tier, NON_BLOCKING
		};

		const scope_restore fill_cache
		{
			opts.fill_cache, false
		};

		std::string discard;
		bool value_found {false};
		const bool key_may_exist
		{
			d.d->KeyMayExist(opts, c, slice(key), &discard, &value_found)
		};

		if(!key_may_exist)
			return false;

		if(value_found)
			return true;
	}

	std::unique_ptr<rocksdb::Iterator> it;
	if(!seek(c, key, opts, it))
		return false;

	assert(bool(it));
	return valid_eq(*it, key);
}

uint64_t
ircd::db::has(column &column,
              const keys &key,
              const gopts &opts)
{
	const columns columns
	{
		&column, 1
	};

	return has(columns, key, opts);
}

uint64_t
ircd::db::has(const columns &c,
              const keys &key,
              const gopts &gopts)
{
	if(c.empty())
		return 0UL;

	const auto &num
	{
		key.size()
	};

	if(unlikely(!num || num > 64))
		throw std::out_of_range
		{
			"db::has() :too many columns or vector size mismatch"
		};

	_read_op op[num];
	for(size_t i(0); i < num; ++i)
		op[i] =
		{
			c[std::min(c.size() - 1, i)], key[i]
		};

	uint64_t i(0), ret(0);
	auto opts(make_opts(gopts));
	_read({op, num}, opts, [&i, &ret, &opts]
	(column &, const column::delta &, const rocksdb::Status &s)
	{
		uint64_t found {0};
		found |= s.ok();
		found |= s.IsIncomplete() & (opts.read_tier == NON_BLOCKING);
		ret |= (found << i++);
		return true;
	});

	return ret;
}

bool
ircd::db::prefetch(column &column,
                   const string_view &key,
                   const gopts &gopts)
{
	static construction instance{[]
	{
		if(bool(prefetcher::enable))
			prefetcher = new struct prefetcher();
	}};

	// Return true when prefetcher disabled because callers assume the value
	// is cached when a prefetch isn't launched and may try to query for it,
	// blocking their prefetch loop.
	if(!prefetcher)
		return true;

	assert(prefetcher);
	return (*prefetcher)(column, key, gopts);
}

#if 0
bool
ircd::db::cached(column &column,
                 const string_view &key,
                 const gopts &gopts)
{
	return exists(cache(column), key);
}
#endif

bool
ircd::db::cached(column &column,
                 const string_view &key,
                 const gopts &gopts)
{
	using rocksdb::Status;

	auto opts(make_opts(gopts));
	opts.read_tier = NON_BLOCKING;
	opts.fill_cache = false;

	std::unique_ptr<rocksdb::Iterator> it;
	database::column &c(column);
	const bool valid
	{
		seek(c, key, opts, it)
	};

	assert(it);
	const auto code
	{
		it->status().code()
	};

	return false
	|| (valid && valid_eq(*it, key))
	|| (!valid && code != rocksdb::Status::kIncomplete)
	;
}

[[gnu::hot]]
rocksdb::Cache *
ircd::db::cache(column &column)
{
	database::column &c(column);
	return c.table_opts.block_cache.get();
}

[[gnu::hot]]
const rocksdb::Cache *
ircd::db::cache(const column &column)
{
	const database::column &c(column);
	return c.table_opts.block_cache.get();
}

template<>
ircd::db::prop_str
ircd::db::property(const column &column,
                   const string_view &name)
{
	const ctx::uninterruptible::nothrow ui;

	std::string ret;
	database &d(mutable_cast(column));
	database::column &c(mutable_cast(column));
	if(!d.d->GetProperty(c, slice(name), &ret))
		throw not_found
		{
			"'property '%s' for column '%s' in '%s' not found.",
			name,
			db::name(column),
			db::name(d)
		};

	return ret;
}

template<>
ircd::db::prop_int
ircd::db::property(const column &column,
                   const string_view &name)
{
	const ctx::uninterruptible::nothrow ui;

	uint64_t ret(0);
	database &d(mutable_cast(column));
	database::column &c(mutable_cast(column));
	if(!d.d->GetIntProperty(c, slice(name), &ret))
		throw not_found
		{
			"property '%s' for column '%s' in '%s' not found or not an integer.",
			name,
			db::name(column),
			db::name(d)
		};

	return ret;
}

template<>
ircd::db::prop_map
ircd::db::property(const column &column,
                   const string_view &name)
{
	const ctx::uninterruptible::nothrow ui;

	std::map<std::string, std::string> ret;
	database &d(mutable_cast(column));
	database::column &c(mutable_cast(column));
	if(!d.d->GetMapProperty(c, slice(name), &ret))
		ret.emplace(std::string{name}, property<std::string>(column, name));

	return ret;
}

ircd::db::options
ircd::db::getopt(const column &column)
{
	const ctx::uninterruptible::nothrow ui;

	database &d(mutable_cast(column));
	database::column &c(mutable_cast(column));
	return options
	{
		static_cast<rocksdb::ColumnFamilyOptions>(d.d->GetOptions(c))
	};
}

size_t
ircd::db::bytes(const column &column)
{
	const ctx::uninterruptible::nothrow ui;

	rocksdb::ColumnFamilyMetaData cfm;
	database &d(mutable_cast(column));
	database::column &c(mutable_cast(column));

	assert(bool(c.handle));
	d.d->GetColumnFamilyMetaData(c.handle.get(), &cfm);
	return cfm.size;
}

size_t
ircd::db::file_count(const column &column)
{
	const ctx::uninterruptible::nothrow ui;

	rocksdb::ColumnFamilyMetaData cfm;
	database &d(mutable_cast(column));
	database::column &c(mutable_cast(column));

	assert(bool(c.handle));
	d.d->GetColumnFamilyMetaData(c.handle.get(), &cfm);
	return cfm.file_count;
}

std::vector<std::string>
ircd::db::files(const column &column)
{
	const ctx::uninterruptible::nothrow ui;

	database::column &c(mutable_cast(column));
	database &d(*c.d);

	rocksdb::ColumnFamilyMetaData cfmd;
	d.d->GetColumnFamilyMetaData(c, &cfmd);

	size_t count(0);
	for(const auto &level : cfmd.levels)
		count += level.files.size();

	std::vector<std::string> ret;
	ret.reserve(count);
	for(auto &level : cfmd.levels)
		for(auto &file : level.files)
			ret.emplace_back(std::move(file.name));

	return ret;
}

[[gnu::hot]]
const ircd::db::descriptor &
ircd::db::describe(const column &column)
noexcept
{
	const database::column &c(column);
	return describe(c);
}

[[gnu::hot]]
const std::string &
ircd::db::name(const column &column)
noexcept
{
	const database::column &c(column);
	return name(c);
}

[[gnu::hot]]
uint32_t
ircd::db::id(const column &column)
noexcept
{
	const database::column &c(column);
	return id(c);
}

//
// column
//

ircd::db::column::column(database &d,
                         const string_view &column_name)
:column
{
	d[column_name]
}
{
}

ircd::db::column::column(database &d,
                         const string_view &column_name,
                         const std::nothrow_t)
:c{[&d, &column_name]
{
	const int32_t cfid
	{
		d.cfid(std::nothrow, column_name)
	};

	return cfid >= 0?
		&d[cfid]:
		nullptr;
}()}
{
}

void
ircd::db::column::operator()(const delta *const &begin,
                             const delta *const &end,
                             const sopts &sopts)
{
	database &d(*this);

	rocksdb::WriteBatch batch;
	std::for_each(begin, end, [this, &batch]
	(const delta &delta)
	{
		append(batch, *this, delta);
	});

	commit(d, batch, sopts);
}

void
ircd::db::column::operator()(const string_view &key,
                             const view_closure &func,
                             const gopts &gopts)
{
	const auto opts(make_opts(gopts));
	throw_on_error
	{
		_read(*this, key, opts, func)
	};
}

bool
ircd::db::column::operator()(const string_view &key,
                             const std::nothrow_t,
                             const view_closure &func,
                             const gopts &gopts)
{
	const auto opts(make_opts(gopts));
	const auto status
	{
		_read(*this, key, opts, func)
	};

	return valid(status);
}

uint64_t
ircd::db::column::operator()(const keys &key,
                             const std::nothrow_t,
                             const views_closure &func,
                             const gopts &gopts)
{
	static const auto MAX
	{
		64UL
	};

	const auto num
	{
		key.size()
	};

	if(unlikely(num > MAX))
		throw std::out_of_range
		{
			"column() :too many keys for parallel fetch."
		};

	if(!num)
		return 0;

	_read_op op[num];
	for(size_t i(0); i < num; ++i)
		op[i] =
		{
			*this, key[i]
		};

	string_view buf[num];
	uint64_t i(0), ret(0);
	auto opts(make_opts(gopts));
	_read({op, num}, opts, [&func, &num, &i, &ret, &buf]
	(column &, const column::delta &d, const rocksdb::Status &s)
	{
		const auto &val
		{
			std::get<column::delta::VAL>(d)
		};

		buf[i] = val;
		ret |= (uint64_t(s.ok()) << i);

		// All results are available until _read() returns. The user is called
		// here with all results after the last result is set.
		if(++i == num)
			func({buf, num});

		return true;
	});

	return ret;
}

ircd::db::cell
ircd::db::column::operator[](const string_view &key)
const
{
	return { *this, key };
}

[[gnu::hot]]
ircd::db::column::operator
bool()
const noexcept
{
	return c && !dropped(*c);
}

//
// column::const_iterator
//

ircd::db::column::const_iterator
ircd::db::column::end(gopts gopts)
{
	const_iterator ret
	{
		c, {}, std::move(gopts)
	};

	seek(ret, pos::END);
	return ret;
}

ircd::db::column::const_iterator
ircd::db::column::last(gopts gopts)
{
	const_iterator ret
	{
		c, {}, std::move(gopts)
	};

	seek(ret, pos::BACK);
	return ret;
}

ircd::db::column::const_iterator
ircd::db::column::begin(gopts gopts)
{
	const_iterator ret
	{
		c, {}, std::move(gopts)
	};

	seek(ret, pos::FRONT);
	return ret;
}

ircd::db::column::const_reverse_iterator
ircd::db::column::rend(gopts gopts)
{
	const_reverse_iterator ret
	{
		c, {}, std::move(gopts)
	};

	seek(ret, pos::END);
	return ret;
}

ircd::db::column::const_reverse_iterator
ircd::db::column::rbegin(gopts gopts)
{
	const_reverse_iterator ret
	{
		c, {}, std::move(gopts)
	};

	seek(ret, pos::BACK);
	return ret;
}

ircd::db::column::const_iterator
ircd::db::column::upper_bound(const string_view &key,
                              gopts gopts)
{
	auto it(lower_bound(key, std::move(gopts)));
	if(it && it.it->key().compare(slice(key)) == 0)
		++it;

	return it;
}

ircd::db::column::const_iterator
ircd::db::column::find(const string_view &key,
                       gopts gopts)
{
	auto it(lower_bound(key, gopts));
	if(!it || it.it->key().compare(slice(key)) != 0)
		return end(gopts);

	return it;
}

ircd::db::column::const_iterator
ircd::db::column::lower_bound(const string_view &key,
                              gopts gopts)
{
	const_iterator ret
	{
		c, {}, std::move(gopts)
	};

	seek(ret, key);
	return ret;
}

ircd::db::column::const_iterator &
ircd::db::column::const_iterator::operator--()
{
	if(likely(bool(*this)))
		seek(*this, pos::PREV);
	else
		seek(*this, pos::BACK);

	return *this;
}

ircd::db::column::const_iterator &
ircd::db::column::const_iterator::operator++()
{
	if(likely(bool(*this)))
		seek(*this, pos::NEXT);
	else
		seek(*this, pos::FRONT);

	return *this;
}

ircd::db::column::const_reverse_iterator &
ircd::db::column::const_reverse_iterator::operator--()
{
	if(likely(bool(*this)))
		seek(*this, pos::NEXT);
	else
		seek(*this, pos::FRONT);

	return *this;
}

ircd::db::column::const_reverse_iterator &
ircd::db::column::const_reverse_iterator::operator++()
{
	if(likely(bool(*this)))
		seek(*this, pos::PREV);
	else
		seek(*this, pos::BACK);

	return *this;
}

ircd::db::column::const_iterator_base::const_iterator_base(const_iterator_base &&o)
noexcept
:c{std::move(o.c)}
,opts{std::move(o.opts)}
,it{std::move(o.it)}
,val{std::move(o.val)}
{
}

ircd::db::column::const_iterator_base &
ircd::db::column::const_iterator_base::operator=(const_iterator_base &&o)
noexcept
{
	c = std::move(o.c);
	opts = std::move(o.opts);
	it = std::move(o.it);
	val = std::move(o.val);
	return *this;
}

// linkage for incmplete rocksdb::Iterator
ircd::db::column::const_iterator_base::const_iterator_base()
noexcept
{
}

// linkage for incmplete rocksdb::Iterator
ircd::db::column::const_iterator_base::~const_iterator_base()
noexcept
{
}

ircd::db::column::const_iterator_base::const_iterator_base(database::column *const &c,
                                                           std::unique_ptr<rocksdb::Iterator> &&it,
                                                           gopts opts)
noexcept
:c{c}
,opts{std::move(opts)}
,it{std::move(it)}
{
}

const ircd::db::column::const_iterator_base::value_type &
ircd::db::column::const_iterator_base::operator*()
const
{
	assert(it && valid(*it));
	val.first = db::key(*it);
	val.second = db::val(*it);
	return val;
}

bool
ircd::db::operator!=(const column::const_iterator_base &a, const column::const_iterator_base &b)
noexcept
{
	const uint operands
	{
		uint(bool(a)) +
		uint(bool(b))
	};

	// Two invalid iterators are equal; one invalid iterator is not.
	if(likely(operands <= 1))
		return operands == 1;

	// Two valid iterators are compared
	assert(operands == 2);
	const auto &ak(a.it->key());
	const auto &bk(b.it->key());
	return ak.compare(bk) != 0;
}

bool
ircd::db::operator==(const column::const_iterator_base &a, const column::const_iterator_base &b)
noexcept
{
	const uint operands
	{
		uint(bool(a)) +
		uint(bool(b))
	};

	// Two valid iterators are compared
	if(likely(operands > 1))
	{
		const auto &ak(a.it->key());
		const auto &bk(b.it->key());
		return ak.compare(bk) == 0;
	}

	// Two invalid iterators are equal; one invalid iterator is not.
	return operands == 0;
}

bool
ircd::db::operator>(const column::const_iterator_base &a, const column::const_iterator_base &b)
noexcept
{
	if(a && b)
	{
		const auto &ak(a.it->key());
		const auto &bk(b.it->key());
		return ak.compare(bk) == 1;
	}

	if(!a && b)
		return true;

	if(!a && !b)
		return false;

	assert(!a && b);
	return false;
}

bool
ircd::db::operator<(const column::const_iterator_base &a, const column::const_iterator_base &b)
noexcept
{
	if(a && b)
	{
		const auto &ak(a.it->key());
		const auto &bk(b.it->key());
		return ak.compare(bk) == -1;
	}

	if(!a && b)
		return false;

	if(!a && !b)
		return false;

	assert(a && !b);
	return true;
}

template<class pos>
bool
ircd::db::seek(column::const_iterator_base &it,
               const pos &p)
{
	database::column &c(it);
	const auto opts(make_opts(it.opts));
	return seek(c, p, opts, it.it);
}
template bool ircd::db::seek<ircd::db::pos>(column::const_iterator_base &, const pos &);
template bool ircd::db::seek<ircd::string_view>(column::const_iterator_base &, const string_view &);

///////////////////////////////////////////////////////////////////////////////
//
// opts.h
//

//
// options
//

ircd::db::options::options(const database &d)
:options{d.d->GetDBOptions()}
{
}

ircd::db::options::options(const database::column &c)
:options
{
	rocksdb::ColumnFamilyOptions
	{
		c.d->d->GetOptions(c.handle.get())
	}
}{}

ircd::db::options::options(const rocksdb::DBOptions &opts)
{
	throw_on_error
	{
		rocksdb::GetStringFromDBOptions(this, opts)
	};
}

ircd::db::options::options(const rocksdb::ColumnFamilyOptions &opts)
{
	throw_on_error
	{
		rocksdb::GetStringFromColumnFamilyOptions(this, opts)
	};
}

ircd::db::options::operator rocksdb::PlainTableOptions()
const
{
	rocksdb::PlainTableOptions ret;
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	#endif
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetPlainTableOptionsFromString(opts, ret, *this, &ret)
		#else
		rocksdb::GetPlainTableOptionsFromString(ret, *this, &ret)
		#endif
	};

	return ret;
}

ircd::db::options::operator rocksdb::BlockBasedTableOptions()
const
{
	rocksdb::BlockBasedTableOptions ret;
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	#endif
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetBlockBasedTableOptionsFromString(opts, ret, *this, &ret)
		#else
		rocksdb::GetBlockBasedTableOptionsFromString(ret, *this, &ret)
		#endif
	};

	return ret;
}

ircd::db::options::operator rocksdb::ColumnFamilyOptions()
const
{
	rocksdb::ColumnFamilyOptions ret;
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	#endif
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetColumnFamilyOptionsFromString(opts, ret, *this, &ret)
		#else
		rocksdb::GetColumnFamilyOptionsFromString(ret, *this, &ret)
		#endif
	};

	return ret;
}

ircd::db::options::operator rocksdb::DBOptions()
const
{
	rocksdb::DBOptions ret;
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	#endif
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetDBOptionsFromString(opts, ret, *this, &ret)
		#else
		rocksdb::GetDBOptionsFromString(ret, *this, &ret)
		#endif
	};

	return ret;
}

ircd::db::options::operator rocksdb::Options()
const
{
	rocksdb::Options ret;
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	#endif
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetOptionsFromString(opts, ret, *this, &ret)
		#else
		rocksdb::GetOptionsFromString(ret, *this, &ret)
		#endif
	};

	return ret;
}

//
// options::map
//

ircd::db::options::map::map(const options &o)
{
	throw_on_error
	{
		rocksdb::StringToMap(o, this)
	};
}

ircd::db::options::map::operator rocksdb::BlockBasedTableOptions()
const
{
	rocksdb::BlockBasedTableOptions ret;
	return merge(ret);
}

ircd::db::options::map::operator rocksdb::PlainTableOptions()
const
{
	rocksdb::PlainTableOptions ret;
	return merge(ret);
}

ircd::db::options::map::operator rocksdb::ColumnFamilyOptions()
const
{
	rocksdb::ColumnFamilyOptions ret;
	return merge(ret);
}

ircd::db::options::map::operator rocksdb::DBOptions()
const
{
	rocksdb::DBOptions ret;
	return merge(ret);
}

rocksdb::BlockBasedTableOptions
ircd::db::options::map::merge(const rocksdb::BlockBasedTableOptions &in)
const
{
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	opts.ignore_unknown_options = true;
	#endif

	rocksdb::BlockBasedTableOptions ret;
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetBlockBasedTableOptionsFromMap(opts, in, *this, &ret)
		#else
		rocksdb::GetBlockBasedTableOptionsFromMap(in, *this, &ret, true, true)
		#endif
	};

	return ret;
}

rocksdb::PlainTableOptions
ircd::db::options::map::merge(const rocksdb::PlainTableOptions &in)
const
{
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	opts.ignore_unknown_options = true;
	#endif

	rocksdb::PlainTableOptions ret;
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetPlainTableOptionsFromMap(opts, in, *this, &ret)
		#else
		rocksdb::GetPlainTableOptionsFromMap(in, *this, &ret, true, true)
		#endif
	};

	return ret;
}

rocksdb::ColumnFamilyOptions
ircd::db::options::map::merge(const rocksdb::ColumnFamilyOptions &in)
const
{
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	opts.ignore_unknown_options = true;
	#endif

	rocksdb::ColumnFamilyOptions ret;
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetColumnFamilyOptionsFromMap(opts, in, *this, &ret)
		#else
		rocksdb::GetColumnFamilyOptionsFromMap(in, *this, &ret, true, true)
		#endif
	};

	return ret;
}

rocksdb::DBOptions
ircd::db::options::map::merge(const rocksdb::DBOptions &in)
const
{
	#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
	rocksdb::ConfigOptions opts;
	opts.ignore_unknown_options = true;
	#endif

	rocksdb::DBOptions ret;
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CONFIG_OPTIONS
		rocksdb::GetDBOptionsFromMap(opts, in, *this, &ret)
		#else
		rocksdb::GetDBOptionsFromMap(in, *this, &ret, true, true)
		#endif
	};

	return ret;
}

///////////////////////////////////////////////////////////////////////////////
//
// cache.h
//

void
ircd::db::clear(rocksdb::Cache &cache)
{
	cache.EraseUnRefEntries();
}

bool
ircd::db::remove(rocksdb::Cache &cache,
                 const string_view &key)
{
	cache.Erase(slice(key));
	return true;
}

bool
ircd::db::insert(rocksdb::Cache &cache,
                 const string_view &key,
                 const string_view &value)
{
	unique_buffer<const_buffer> buf
	{
		const_buffer{value}
	};

	return insert(cache, key, std::move(buf));
}

bool
ircd::db::insert(rocksdb::Cache &cache,
                 const string_view &key,
                 unique_buffer<const_buffer> &&value)
{
	const size_t value_size
	{
		size(value)
	};

	static const auto deleter{[]
	(const rocksdb::Slice &key, void *const value)
	{
		delete[] reinterpret_cast<const char *>(value);
	}};

	// Note that because of the nullptr handle argument below, rocksdb
	// will run the deleter if the insert throws; just make sure
	// the argument execution doesn't throw after release()
	throw_on_error
	{
		#ifdef IRCD_DB_HAS_CACHE_ITEMHELPER
		cache.Insert(slice(key),
		             mutable_cast(data(value.release())),
		             cache.GetCacheItemHelper(nullptr), // ???
		             value_size,
		             nullptr)
		#else
		cache.Insert(slice(key),
		             mutable_cast(data(value.release())),
		             value_size,
		             deleter,
		             nullptr)
		#endif
	};

	return true;
}

void
ircd::db::for_each(const rocksdb::Cache &cache,
                   const cache_closure &closure)
#ifdef IRCD_DB_HAS_CACHE_ITEMHELPER
{
	const auto _closure{[&closure]
	(const auto &slice, void *const value, size_t size, const auto *const helper)
	noexcept
	{
		const const_buffer buf
		{
			reinterpret_cast<const char *>(value), size
		};

		closure(buf);
	}};

	rocksdb::Cache::ApplyToAllEntriesOptions opts;
	mutable_cast(cache).ApplyToAllEntries(_closure, opts);
}
#else
{
	// Due to the use of the global variables which are required when using a
	// C-style callback for RocksDB, we have to make use of this function
	// exclusive for different contexts.
	thread_local ctx::mutex mutex;
	const std::lock_guard lock{mutex};

	thread_local rocksdb::Cache *_cache;
	_cache = mutable_cast(&cache);

	thread_local const cache_closure *_closure;
	_closure = &closure;

	_cache->ApplyToAllCacheEntries([]
	(void *const value_buffer, const size_t buffer_size)
	noexcept
	{
		assert(_cache);
		assert(_closure);
		const const_buffer buf
		{
			reinterpret_cast<const char *>(value_buffer), buffer_size
		};

		(*_closure)(buf);
	},
	true);
}
#endif

#ifdef IRCD_DB_HAS_CACHE_GETCHARGE
size_t
ircd::db::charge(const rocksdb::Cache &cache_,
                 const string_view &key)
{
	auto &cache
	{
		mutable_cast(cache_)
	};

	const custom_ptr<rocksdb::Cache::Handle> handle
	{
		cache.Lookup(slice(key)), [&cache](auto *const &handle)
		{
			cache.Release(handle);
		}
	};

	return cache.GetCharge(handle);
}
#else
size_t
ircd::db::charge(const rocksdb::Cache &cache,
                 const string_view &key)
{
	return 0UL;
}
#endif

[[gnu::hot]]
bool
ircd::db::exists(const rocksdb::Cache &cache_,
                 const string_view &key)
{
	auto &cache
	{
		mutable_cast(cache_)
	};

	const custom_ptr<rocksdb::Cache::Handle> handle
	{
		cache.Lookup(slice(key)), [&cache](auto *const &handle)
		{
			cache.Release(handle);
		}
	};

	return bool(handle);
}

size_t
ircd::db::count(const rocksdb::Cache &cache)
{
	size_t ret(0);
	for_each(cache, [&ret]
	(const const_buffer &) noexcept
	{
		++ret;
	});

	return ret;
}

size_t
ircd::db::pinned(const rocksdb::Cache &cache)
{
	return cache.GetPinnedUsage();
}

size_t
ircd::db::usage(const rocksdb::Cache &cache)
{
	return cache.GetUsage();
}

void
ircd::db::capacity(rocksdb::Cache &cache,
                   const size_t &cap)
{
	cache.SetCapacity(cap);
}

size_t
ircd::db::capacity(const rocksdb::Cache &cache)
{
	return cache.GetCapacity();
}

const uint64_t &
ircd::db::ticker(const rocksdb::Cache &cache,
                 const uint32_t &ticker_id)
{
	const auto &c
	{
		dynamic_cast<const database::cache &>(cache)
	};

	static const uint64_t &zero
	{
		0ULL
	};

	return c.stats?
		c.stats->ticker.at(ticker_id):
		zero;
}

///////////////////////////////////////////////////////////////////////////////
//
// error.h
//

//
// error::not_found
//

decltype(ircd::db::error::not_found::_not_found_)
ircd::db::error::not_found::_not_found_
{
	rocksdb::Status::NotFound()
};

//
// error::not_found::not_found
//

ircd::db::error::not_found::not_found()
:error
{
	generate_skip, _not_found_
}
{
	strlcpy(buf, "NotFound");
}

//
// error
//

decltype(ircd::db::error::_no_code_)
ircd::db::error::_no_code_
{
	rocksdb::Status::OK()
};

//
// error::error
//

ircd::db::error::error(internal_t,
                       const rocksdb::Status &s,
                       const string_view &fmt,
                       const va_rtti &ap)
:error
{
	s
}
{
	const string_view &msg{buf};
	const mutable_buffer remain
	{
		buf + size(msg), sizeof(buf) - size(msg)
	};

	fmt::vsprintf
	{
		remain, fmt, ap
	};
}

ircd::db::error::error(const rocksdb::Status &s)
:error
{
	generate_skip, s
}
{
	fmt::sprintf
	{
		buf, "(%u:%u:%u) %s %s :%s",
		this->code,
		this->subcode,
		this->severity,
		reflect(rocksdb::Status::Severity(this->severity)),
		reflect(rocksdb::Status::Code(this->code)),
		s.getState(),
	};
}

ircd::db::error::error(generate_skip_t,
                       const rocksdb::Status &s)
:ircd::error
{
	generate_skip
}
,code
{
	s.code()
}
,subcode
{
	s.subcode()
}
,severity
{
	s.severity()?
		s.severity():

	code == rocksdb::Status::kCorruption?
		rocksdb::Status::kHardError:

	rocksdb::Status::kNoError
}
{
}

///////////////////////////////////////////////////////////////////////////////
//
// merge.h
//

std::string
__attribute__((noreturn))
ircd::db::merge_operator(const string_view &key,
                         const std::pair<string_view, string_view> &delta)
{
	//ircd::json::index index{delta.first};
	//index += delta.second;
	//return index;

	throw ircd::not_implemented
	{
		"db::merge_operator()"
	};
}

///////////////////////////////////////////////////////////////////////////////
//
// comparator.h
//

//
// linkage placements for integer comparators so they all have the same addr
//

ircd::db::cmp_int64_t::cmp_int64_t()
{
}

ircd::db::cmp_int64_t::~cmp_int64_t()
noexcept
{
}

ircd::db::cmp_uint64_t::cmp_uint64_t()
{
}

ircd::db::cmp_uint64_t::~cmp_uint64_t()
noexcept
{
}

ircd::db::reverse_cmp_int64_t::reverse_cmp_int64_t()
{
}

ircd::db::reverse_cmp_int64_t::~reverse_cmp_int64_t()
noexcept
{
}

ircd::db::reverse_cmp_uint64_t::reverse_cmp_uint64_t()
{
}

ircd::db::reverse_cmp_uint64_t::~reverse_cmp_uint64_t()
noexcept
{
}

//
// cmp_string_view
//

ircd::db::cmp_string_view::cmp_string_view()
:db::comparator{"string_view", &less, &equal}
{
}

//
// reverse_cmp_string_view
//

ircd::db::reverse_cmp_string_view::reverse_cmp_string_view()
:db::comparator{"reverse_string_view", &less, &equal}
{
}

bool
ircd::db::reverse_cmp_string_view::less(const string_view &a,
                                        const string_view &b)
noexcept
{
	/// RocksDB sez things will not work correctly unless a shorter string
	/// result returns less than a longer string even if one intends some
	/// reverse ordering
	if(a.size() < b.size())
		return true;

	/// Furthermore, b.size() < a.size() returning false from this function
	/// appears to not be correct. The reversal also has to also come in
	/// the form of a bytewise forward iteration.
	return std::memcmp(a.data(), b.data(), std::min(a.size(), b.size())) > 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// delta.h
//

bool
ircd::db::value_required(const op op)
noexcept
{
	switch(op)
	{
		case op::SET:
		case op::MERGE:
		case op::DELETE_RANGE:
			return true;

		case op::GET:
		case op::DELETE:
		case op::SINGLE_DELETE:
			return false;
	}

	assert(0);
	return false;
}

///////////////////////////////////////////////////////////////////////////////
//
// db.h (internal)
//

//
// throw_on_error
//

ircd::db::throw_on_error::throw_on_error(const rocksdb::Status &status)
{
	using rocksdb::Status;

	switch(status.code())
	{
		[[likely]]
		case Status::kOk:
			return;

		case Status::kNotFound:
			throw not_found{};

		//case Status::kCorruption:
		case Status::kNotSupported:
		case Status::kInvalidArgument:
			if constexpr(RB_DEBUG_LEVEL)
				debugtrap();
			[[fallthrough]];

		[[unlikely]]
		default:
			throw error
			{
				status
			};
	}
}

//
// error_to_status
//

ircd::db::error_to_status::error_to_status(const std::exception &e)
:rocksdb::Status
{
	Status::Aborted(slice(string_view(e.what())))
}
{
}

ircd::db::error_to_status::error_to_status(const std::system_error &e)
:error_to_status{e.code()}
{
}

ircd::db::error_to_status::error_to_status(const std::error_code &e)
:rocksdb::Status{[&e]
{
	using std::errc;

	switch(e.value())
	{
		[[likely]]
		case 0:
			return Status::OK();

		case int(errc::no_such_file_or_directory):
			return Status::NotFound();

		case int(errc::not_supported):
			return Status::NotSupported();

		case int(errc::invalid_argument):
			return Status::InvalidArgument();

		case int(errc::io_error):
			 return Status::IOError();

		case int(errc::timed_out):
			return Status::TimedOut();

		case int(errc::device_or_resource_busy):
			return Status::Busy();

		case int(errc::resource_unavailable_try_again):
			return Status::TryAgain();

		case int(errc::no_space_on_device):
			return Status::NoSpace();

		case int(errc::not_enough_memory):
			return Status::MemoryLimit();

		default:
		{
			const auto &message(e.message());
			return Status::Aborted(slice(string_view(message)));
		}
	}
}()}
{
}

//
// writebatch suite
//

void
ircd::db::append(rocksdb::WriteBatch &batch,
                 const cell::delta &delta)
{
	auto &column
	{
		std::get<cell *>(delta)->c
	};

	append(batch, column, column::delta
	{
		std::get<op>(delta),
		std::get<cell *>(delta)->key(),
		std::get<string_view>(delta)
	});
}

void
ircd::db::append(rocksdb::WriteBatch &batch,
                 column &column,
                 const column::delta &delta)
{
	if(unlikely(!column))
	{
		// Note: Unknown at this time whether allowing attempts at writing
		// to a null column should be erroneous or silently ignored. It's
		// highly likely this log message will be removed soon to allow
		// toggling database columns for optimization without touching calls.
		log::critical
		{
			log, "Attempting to transact a delta for a null column"
		};

		return;
	}

	database::column &c(column);
	const auto k(slice(std::get<1>(delta)));
	const auto v(slice(std::get<2>(delta)));
	switch(std::get<0>(delta))
	{
		[[unlikely]]
		case op::GET:            assert(0);                    break;
		case op::SET:            batch.Put(c, k, v);           break;
		case op::MERGE:          batch.Merge(c, k, v);         break;
		case op::DELETE:         batch.Delete(c, k);           break;
		case op::DELETE_RANGE:   batch.DeleteRange(c, k, v);   break;
		case op::SINGLE_DELETE:  batch.SingleDelete(c, k);     break;
	}
}

void
ircd::db::commit(database &d,
                 rocksdb::WriteBatch &batch,
                 const sopts &sopts)
{
	const auto opts(make_opts(sopts));
	commit(d, batch, opts, sopts.cork);
}

void
ircd::db::commit(database &d,
                 rocksdb::WriteBatch &batch,
                 const rocksdb::WriteOptions &opts,
                 const bool cork)
{
	ircd::timer timer
	{
		RB_LOG_LEVEL >= log::level::DEBUG
	};

	const std::lock_guard lock
	{
		d.write_mutex
	};

	const auto delay{d.commit_delay};
	const auto delayed{delay > 0ms};
	ctx::sleep(delay);

	const ctx::uninterruptible ui;
	const ctx::stack_usage_assertion sua;
	throw_on_error
	{
		d.d->Write(opts, &batch)
	};

	if(likely(!cork && !opts.disableWAL))
		db::flush(d, opts.sync);

	if constexpr(RB_LOG_LEVEL >= log::level::DEBUG)
	{
		const auto took
		{
			timer.at<nanoseconds>()
		};

		char dbuf[192], pbuf[2][48];
		log::debug
		{
			log, "[%s] %lu COMMIT %s to %s in %s%s%s",
			d.name,
			sequence(d),
			debug(dbuf, batch),
			cork? "memory"_sv: "system"_sv,
			pretty(pbuf[0], took, 1),
			delayed? " stall "_sv: string_view{},
			delayed? pretty(pbuf[1], delay, 1): string_view{},
		};
	}
}

ircd::string_view
ircd::db::debug(const mutable_buffer &buf,
                const rocksdb::WriteBatch &batch)
{
	char pbuf[64] {0};
	const size_t len(::snprintf
	(
		data(buf), size(buf),
		"%d deltas; %s %s+%s+%s+%s+%s+%s+%s+%s+%s"
		,batch.Count()
		,pretty(pbuf, iec(batch.GetDataSize())).data()
		,batch.HasPut()? "PUT": ""
		,batch.HasDelete()? "DEL": ""
		,batch.HasSingleDelete()? "SDL": ""
		,batch.HasDeleteRange()? "DRG": ""
		,batch.HasMerge()? "MRG": ""
		,batch.HasBeginPrepare()? "BEG": ""
		,batch.HasEndPrepare()? "END": ""
		,batch.HasCommit()? "COM-": ""
		,batch.HasRollback()? "RB^": ""
	));

	return string_view
	{
		data(buf), len
	};
}

bool
ircd::db::has(const rocksdb::WriteBatch &wb,
              const op &op)
{
	switch(op)
	{
		case op::GET:              assert(0); return false;
		case op::SET:              return wb.HasPut();
		case op::MERGE:            return wb.HasMerge();
		case op::DELETE:           return wb.HasDelete();
		case op::DELETE_RANGE:     return wb.HasDeleteRange();
		case op::SINGLE_DELETE:    return wb.HasSingleDelete();
	}

	return false;
}

//
// read suite
//

namespace ircd::db
{
	static rocksdb::Status _seek(database::column &, rocksdb::PinnableSlice &, const string_view &, const rocksdb::ReadOptions &);
}

rocksdb::Status
ircd::db::_read(column &column,
                const string_view &key,
                const rocksdb::ReadOptions &opts,
                const column::view_closure &closure)
{
	std::string buf;
	rocksdb::PinnableSlice ps
	{
		&buf
	};

	database::column &c(column);
	const rocksdb::Status ret
	{
		_seek(c, ps, key, opts)
	};

	if(!valid(ret))
		return ret;

	const string_view value
	{
		slice(ps)
	};

	if(likely(closure))
		closure(value);

	// Update stats about whether the pinnable slices we obtained have internal
	// copies or referencing the cache copy.
	database &d(column);
	c.stats->get_referenced += buf.empty();
	d.stats->get_referenced += buf.empty();
	c.stats->get_copied += !buf.empty();
	d.stats->get_copied += !buf.empty();
	return ret;
}

rocksdb::Status
ircd::db::_seek(database::column &c,
                rocksdb::PinnableSlice &s,
                const string_view &key,
                const rocksdb::ReadOptions &ropts)
{
	const ctx::uninterruptible ui;
	const ctx::stack_usage_assertion sua;

	rocksdb::ColumnFamilyHandle *const &cf(c);
	database &d(*c.d);

	util::timer timer{util::timer::nostart};
	if constexpr(RB_DEBUG_DB_SEEK)
		timer = {};

	const rocksdb::Status ret
	{
		d.d->Get(ropts, cf, slice(key), &s)
	};

	if constexpr(RB_DEBUG_DB_SEEK)
		log::debug
		{
			log, "[%s] %lu:%lu SEEK %s in %ld$us '%s'",
			name(d),
			sequence(d),
			sequence(ropts.snapshot),
			ret.ok()? "OK"s: ret.ToString(),
			timer.at<microseconds>().count(),
			name(c)
		};

	return ret;
}

//
// parallel read suite
//

namespace ircd::db
{
	static void _seek(const vector_view<_read_op> &, const vector_view<rocksdb::Status> &, const vector_view<rocksdb::PinnableSlice> &, const rocksdb::ReadOptions &);
}

bool
ircd::db::_read(const vector_view<_read_op> &op,
                const rocksdb::ReadOptions &ropts,
                const _read_closure &closure)
{
	assert(op.size() >= 1);
	assert(op.size() <= IOV_MAX);
	const size_t &num
	{
		op.size()
	};

	std::string buf[num];
	rocksdb::PinnableSlice val[num];
	for(size_t i(0); i < num; ++i)
		new (val + i) rocksdb::PinnableSlice
		{
			buf + i
		};

	const bool parallelize
	{
		num > 1
		&& IRCD_DEFINED(IRCD_DB_HAS_MULTIGET_DIRECT)
		&& IRCD_DEFINED(IRCD_DB_HAS_MULTIREAD_FIX)
	};

	rocksdb::Status status[num];
	if(!parallelize)
		for(size_t i(0); i < num; ++i)
		{
			database::column &column(std::get<column>(op[i]));
			status[i] = _seek(column, val[i], std::get<1>(op[i]), ropts);
		}
	else
		_seek(op, {status, num}, {val, num}, ropts);

	bool ret(true);
	if(closure)
		for(size_t i(0); i < num && ret; ++i)
		{
			const column::delta delta(std::get<1>(op[i]), slice(val[i]));
			ret = closure(std::get<column>(op[i]), delta, status[i]);
		}

	// Update stats about whether the pinnable slices we obtained have internal
	// copies or referencing the cache copy.
	for(size_t i(0); i < num; ++i)
	{
		database &d(std::get<column>(op[i]));
		database::column &c(std::get<column>(op[i]));

		// Find the correct stats to update, one for the specific column and
		// one for the database total.
		ircd::stats::item<uint64_t> *item_[2]
		{
			parallelize && buf[i].empty()?    &c.stats->multiget_referenced:
			parallelize?                      &c.stats->multiget_copied:
			buf[i].empty()?                   &c.stats->get_referenced:
			                                  &c.stats->get_copied,

			parallelize && buf[i].empty()?    &d.stats->multiget_referenced:
			parallelize?                      &d.stats->multiget_copied:
			buf[i].empty()?                   &d.stats->get_referenced:
			                                  &d.stats->get_copied,
		};

		for(auto *const &item : item_)
			++(*item);
	}

	return ret;
}

void
ircd::db::_seek(const vector_view<_read_op> &op,
                const vector_view<rocksdb::Status> &ret,
                const vector_view<rocksdb::PinnableSlice> &val,
                const rocksdb::ReadOptions &ropts)
{
	assert(ret.size() == op.size());
	assert(ret.size() == val.size());

	const ctx::stack_usage_assertion sua;
	const ctx::uninterruptible ui;

	assert(op.size() >= 1);
	database &d(std::get<0>(op[0]));
	const size_t &num
	{
		op.size()
	};

	rocksdb::Slice key[num];
	std::transform(begin(op), end(op), key, []
	(const auto &op)
	{
		return slice(std::get<1>(op));
	});

	rocksdb::ColumnFamilyHandle *cf[num];
	std::transform(begin(op), end(op), cf, []
	(auto &op_)
	{
		auto &op(mutable_cast(op_));
		database::column &c(std::get<column>(op));
		return static_cast<rocksdb::ColumnFamilyHandle *>(c);
	});

	util::timer timer{util::timer::nostart};
	if constexpr(RB_DEBUG_DB_SEEK)
		timer = {};

	#ifdef IRCD_DB_HAS_MULTIGET_BATCHED
		d.d->MultiGet(ropts, num, cf, key, val.data(), ret.data());
	#else
		always_assert(false);
	#endif

	if constexpr(RB_DEBUG_DB_SEEK)
		log::debug
		{
			log, "[%s] %lu:%lu SEEK parallel:%zu ok:%zu nf:%zu inc:%zu in %ld$us",
			name(d),
			sequence(d),
			sequence(ropts.snapshot),
			ret.size(),
			std::count_if(begin(ret), end(ret), [](auto&& s) { return s.ok(); }),
			std::count_if(begin(ret), end(ret), [](auto&& s) { return s.IsNotFound(); }),
			std::count_if(begin(ret), end(ret), [](auto&& s) { return s.IsIncomplete(); }),
			timer.at<microseconds>().count(),
		};
}

//
// iterator seek suite
//

namespace ircd::db
{
	static rocksdb::Iterator &_seek_(rocksdb::Iterator &, const pos &);
	static rocksdb::Iterator &_seek_(rocksdb::Iterator &, const string_view &, const bool lte);
	static bool _seek(database::column &, const pos &, const rocksdb::ReadOptions &, rocksdb::Iterator &it, const bool lte);
	static bool _seek(database::column &, const string_view &, const rocksdb::ReadOptions &, rocksdb::Iterator &it, const bool lte);
}

std::unique_ptr<rocksdb::Iterator>
ircd::db::seek(column &column,
               const string_view &key,
               const gopts &opts,
               const bool lte)
{
	database &d(column);
	database::column &c(column);

	std::unique_ptr<rocksdb::Iterator> ret;
	const auto ropts(make_opts(opts));
	seek(c, key, ropts, ret, lte);
	return ret;
}

template<class pos>
bool
ircd::db::seek(database::column &c,
               const pos &p,
               const rocksdb::ReadOptions &opts,
               std::unique_ptr<rocksdb::Iterator> &it,
               const bool lte)
{
	const ctx::uninterruptible ui;
	const ctx::stack_usage_assertion sua;

	if(!it)
	{
		database &d(*c.d);
		rocksdb::ColumnFamilyHandle *const &cf(c);
		it.reset(d.d->NewIterator(opts, cf));
	}

	return _seek(c, p, opts, *it, lte);
}

bool
ircd::db::_seek(database::column &c,
                const string_view &p,
                const rocksdb::ReadOptions &opts,
                rocksdb::Iterator &it,
                const bool lte)
try
{
	util::timer timer{util::timer::nostart};
	if constexpr(RB_DEBUG_DB_SEEK)
		timer = util::timer{};

	_seek_(it, p, lte);

	database &d(*c.d);
	if constexpr(RB_DEBUG_DB_SEEK)
		log::debug
		{
			log, "[%s] %lu:%lu SEEK[%s] %s %s in %ld$us '%s'",
			name(d),
			sequence(d),
			sequence(opts.snapshot),
			lte? "LTE"_sv: "GTE"_sv,
			valid(it)? "VALID"_sv: "INVALID"_sv,
			it.status().ok()? "OK"s: it.status().ToString(),
			timer.at<microseconds>().count(),
			name(c)
		};

	return valid(it);
}
catch(const error &e)
{
	const database &d(*c.d);
	log::critical
	{
		log, "[%s][%s] %lu:%lu SEEK[%s] key :%s",
		name(d),
		name(c),
		sequence(d),
		sequence(opts.snapshot),
		lte? "LTE"_sv: "GTE"_sv,
		e.what(),
	};

	throw;
}

bool
ircd::db::_seek(database::column &c,
                const pos &p,
                const rocksdb::ReadOptions &opts,
                rocksdb::Iterator &it,
                const bool)
try
{
	bool valid_it;
	util::timer timer{util::timer::nostart};
	if constexpr(RB_DEBUG_DB_SEEK)
	{
		valid_it = valid(it);
		timer = util::timer{};
	}

	_seek_(it, p);

	database &d(*c.d);
	if constexpr(RB_DEBUG_DB_SEEK)
		log::debug
		{
			log, "[%s] %lu:%lu SEEK[%s] %s -> %s in %ld$us '%s'",
			name(d),
			sequence(d),
			sequence(opts.snapshot),
			reflect(p),
			valid_it? "VALID"_sv: "INVALID"_sv,
			it.status().ok()? "OK"s: it.status().ToString(),
			timer.at<microseconds>().count(),
			name(c)
		};

	return valid(it);
}
catch(const error &e)
{
	const database &d(*c.d);
	log::critical
	{
		log, "[%s][%s] %lu:%lu SEEK %s %s :%s",
		name(d),
		name(c),
		sequence(d),
		sequence(opts.snapshot),
		reflect(p),
		it.Valid()? "VALID"_sv: "INVALID"_sv,
		e.what(),
	};

	throw;
}

/// Defaults to _seek_upper_ because it has better support from RocksDB.
rocksdb::Iterator &
ircd::db::_seek_(rocksdb::Iterator &it,
                 const string_view &sv,
                 const bool lte)
{
	assert(!ctx::interruptible());

	if(lte)
		it.SeekForPrev(slice(sv));
	else
		it.Seek(slice(sv));

	return it;
}

rocksdb::Iterator &
ircd::db::_seek_(rocksdb::Iterator &it,
                 const pos &p)
{
	assert(!ctx::interruptible());

	switch(p)
	{
		case pos::NEXT:
			assert(valid(it));
			it.Next();
			break;

		case pos::PREV:
			assert(valid(it));
			it.Prev();
			break;

		case pos::FRONT:
			it.SeekToFirst();
			break;

		case pos::BACK:
			it.SeekToLast();
			break;

		case pos::END:
		{
			it.SeekToLast();
			if(it.Valid())
				it.Next();

			break;
		}

		default:
			assert(false);
			break;
	}

	return it;
}

//
// validation suite
//

void
ircd::db::valid_eq_or_throw(const rocksdb::Iterator &it,
                            const string_view &sv)
{
	assert(!empty(sv));
	if(!valid_eq(it, sv))
	{
		throw_on_error(it.status());
		throw not_found{};
	}
}

void
ircd::db::valid_or_throw(const rocksdb::Iterator &it)
{
	if(!valid(it))
	{
		throw_on_error(it.status());
		throw not_found{};
		//assert(0); // status == ok + !Valid() == ???
	}
}

bool
ircd::db::valid_lte(const rocksdb::Iterator &it,
                    const string_view &sv)
{
	return valid(it, [&sv](const auto &it)
	{
		return it.key().compare(slice(sv)) <= 0;
	});
}

bool
ircd::db::valid_gt(const rocksdb::Iterator &it,
                   const string_view &sv)
{
	return valid(it, [&sv](const auto &it)
	{
		return it.key().compare(slice(sv)) > 0;
	});
}

bool
ircd::db::valid_eq(const rocksdb::Iterator &it,
                   const string_view &sv)
{
	return valid(it, [&sv](const auto &it)
	{
		return it.key().compare(slice(sv)) == 0;
	});
}

bool
ircd::db::valid(const rocksdb::Iterator &it,
                const valid_proffer &proffer)
{
	return valid(it) && proffer(it);
}

bool
ircd::db::valid(const rocksdb::Iterator &it)
{
	if(likely(it.Valid()))
		return true;

	switch(it.status().code())
	{
		using rocksdb::Status;

		[[likely]]
		case Status::kOk:
		case Status::kNotFound:
		case Status::kIncomplete:
			return it.Valid();

		[[unlikely]]
		default:
			throw_on_error
			{
				it.status()
			};

			__builtin_unreachable();
	}
}

bool
ircd::db::valid(const rocksdb::Status &s)
{
	switch(s.code())
	{
		using rocksdb::Status;

		[[likely]]
		case Status::kOk:
			return true;

		[[likely]]
		case Status::kNotFound:
		case Status::kIncomplete:
			return false;

		[[unlikely]]
		default:
			throw_on_error{s};
			__builtin_unreachable();
	}
}

//
// column_names
//

std::vector<std::string>
ircd::db::column_names(const std::string &path,
                       const std::string &options)
{
	const rocksdb::DBOptions opts
	{
		db::options(options)
	};

	return column_names(path, opts);
}

/// Note that if there is no database found at path we still return a
/// vector containing the column name "default". This function is not
/// to be used as a test for whether the database exists. It returns
/// the columns required to be described at `path`. That will always
/// include the default column (RocksDB sez) even if database doesn't
/// exist yet.
std::vector<std::string>
ircd::db::column_names(const std::string &path,
                       const rocksdb::DBOptions &opts)
try
{
	std::vector<std::string> ret;

	throw_on_error
	{
		rocksdb::DB::ListColumnFamilies(opts, path, &ret)
	};

	return ret;
}
catch(const not_found &)
{
	return // No database found at path.
	{
		{ rocksdb::kDefaultColumnFamilyName }
	};
}

//
// Misc
//

namespace ircd::db
{
	extern conf::item<std::string> compression_default;
}

decltype(ircd::db::compression_default)
ircd::db::compression_default
{
	{ "name",     "ircd.db.compression.default"              },
	{ "default",  "kZSTD;kLZ4Compression;kSnappyCompression" },
};

rocksdb::CompressionType
ircd::db::find_supported_compression(const std::string &input)
{
	rocksdb::CompressionType ret
	{
		rocksdb::kNoCompression
	};

	const auto &list
	{
		input == "default"?
			string_view{compression_default}:
			string_view{input}
	};

	tokens(list, ';', [&ret]
	(const string_view &requested)
	{
		if(ret != rocksdb::kNoCompression)
			return;

		for(const auto &[name, type] : db::compressions)
			if(type != 0L && name == requested)
			{
				ret = rocksdb::CompressionType(type);
				break;
			}
	});

	return ret;
}

rocksdb::DBOptions
ircd::db::make_dbopts(std::string optstr,
                      std::string *const &out,
                      bool *const read_only,
                      bool *const fsck)
{
	// RocksDB doesn't parse a read_only option, so we allow that to be added
	// to open the database as read_only and then remove that from the string.
	if(read_only)
		*read_only |= optstr_find_and_remove(optstr, "read_only=true;"s);
	else
		optstr_find_and_remove(optstr, "read_only=true;"s);

	// We also allow the user to specify fsck=true to run a repair operation on
	// the db. This may be expensive to do by default every startup.
	if(fsck)
		*fsck |= optstr_find_and_remove(optstr, "fsck=true;"s);
	else
		optstr_find_and_remove(optstr, "fsck=true;"s);

	// Generate RocksDB options from string
	rocksdb::DBOptions opts
	{
		db::options(optstr)
	};

	if(out)
		*out = std::move(optstr);

	return opts;
}

bool
ircd::db::optstr_find_and_remove(std::string &optstr,
                                 const std::string &what)
{
	const auto pos(optstr.find(what));
	if(pos == std::string::npos)
		return false;

	optstr.erase(pos, what.size());
	return true;
}

std::vector<std::unique_ptr<ircd::conf::item<std::string>>>
ircd::db::make_confs(const db::options &opts,
                     const pair<string_view> &name,
                     const conf::set_cb &setter)
{
	const db::options::map map(opts);

	std::vector<std::unique_ptr<conf::item<std::string>>> ret;
	ret.reserve(map.size());

	char buf[512];
	for(const auto &[key, val] : map)
		ret.emplace_back(std::make_unique<conf::item<std::string>>
		(
			json::members
			{
				{ "name",     make_conf_name(buf, name, key) },
				{ "default",  string_view{val}               },
			},
			setter
		));

	return ret;
}

ircd::string_view
ircd::db::unmake_conf_name_key(const conf::item<void> &item)
{
	const auto &name
	{
		lstrip(lstrip(item.name, confs_prefix), '.')
	};

	const auto &[dbname, remain]
	{
		split(name, '.')
	};

	const auto &[colname, key]
	{
		split(remain, '.')
	};

	return key;
}

ircd::string_view
ircd::db::make_conf_name(const mutable_buffer &buf,
                         const pair<string_view> &name,
                         const string_view &key)
{
	return fmt::sprintf
	{
		buf, "%s.%s.%s.%s",
		confs_prefix,
		name.first,
		name.second,
		key,
	};
}

namespace ircd::db
{
	static const rocksdb::ReadOptions default_read_options;
}

decltype(ircd::db::read_checksum)
ircd::db::read_checksum
{
	{ "name",     "ircd.db.read.checksum" },
	{ "default",  false                   }
};

/// Convert our options structure into RocksDB's options structure.
rocksdb::ReadOptions
ircd::db::make_opts(const gopts &opts)
noexcept
{
	const auto &def{default_read_options};
	assume(def.iterate_lower_bound == nullptr);
	assume(def.iterate_upper_bound == nullptr);
	assume(def.pin_data == false);
	assume(def.fill_cache == true);
	assume(def.total_order_seek == false);
	assume(def.verify_checksums == true);
	assume(def.tailing == false);
	assume(def.read_tier == rocksdb::ReadTier::kReadAllTier);
	assume(def.readahead_size == 0);
	assume(def.prefix_same_as_start == false);
	assume(def.table_filter == nullptr);
	#ifdef IRCD_DB_HAS_AUTO_READAHEAD
	assume(def.adaptive_readahead == false);
	#endif

	rocksdb::ReadOptions ret{def};
	ret.snapshot = opts.snapshot;

	// slice* for exclusive upper bound. when prefixes are used this value must
	// have the same prefix because ordering is not guaranteed between prefixes
	ret.iterate_lower_bound = opts.lower_bound;
	ret.iterate_upper_bound = opts.upper_bound;

	ret.verify_checksums = opts.checksum <= -1?
		bool(read_checksum):
		opts.checksum;

	if(opts.readahead > 0)
		ret.readahead_size = opts.readahead;

	#ifdef IRCD_DB_HAS_AUTO_READAHEAD
	if(opts.readahead < 0)
		ret.adaptive_readahead = true;
	#endif

	if(opts.tailing)
		ret.tailing = true;

	if(opts.ordered)
		ret.total_order_seek = true;

	if(opts.pin)
		ret.pin_data = true;

	if(!opts.cache)
		ret.fill_cache = false;

	if(opts.prefix)
		ret.prefix_same_as_start = true;

	if(!opts.blocking)
		ret.read_tier = rocksdb::ReadTier::kBlockCacheTier;

	return ret;
}

namespace ircd::db
{
	static const rocksdb::WriteOptions default_write_options;
}

decltype(ircd::db::enable_wal)
ircd::db::enable_wal
{
	{ "name",      "ircd.db.wal.enable" },
	{ "default",   true                 },
	{ "persist",   false                },
};

rocksdb::WriteOptions
ircd::db::make_opts(const sopts &opts)
noexcept
{
	const auto &def{default_write_options};
	assume(def.sync == false);
	assume(def.disableWAL == false);
	assume(def.ignore_missing_column_families == false);
	assume(def.no_slowdown == false);
	assume(def.low_pri == false);

	rocksdb::WriteOptions ret{def};
	ret.sync = opts.fsync;
	ret.disableWAL = !opts.journal || !enable_wal;
	ret.ignore_missing_column_families = true;
	ret.no_slowdown = !opts.blocking;
	ret.low_pri = opts.prio_low;
	return ret;
}

//
//
//

void
ircd::db::chdir()
{
	init::directory();
}

std::vector<std::string>
ircd::db::available()
{
	const string_view &prefix
	{
		fs::base::db
	};

	const auto dirs
	{
		fs::ls(prefix)
	};

	std::vector<std::string> ret;
	for(const auto &dir : dirs)
	{
		if(!fs::is_dir(dir))
			continue;

		const auto name
		{
			lstrip(dir, prefix)
		};

		const auto checkpoints
		{
			fs::ls(dir)
		};

		for(const auto &cpdir : checkpoints) try
		{
			const auto checkpoint
			{
				lstrip(lstrip(cpdir, dir), '/') //TODO: x-platform
			};

			auto path
			{
				db::path(name, lex_cast<uint64_t>(checkpoint))
			};

			ret.emplace_back(std::move(path));
		}
		catch(const bad_lex_cast &e)
		{
			continue;
		}
	}

	return ret;
}

std::string
ircd::db::path(const string_view &name)
{
	const auto pair
	{
		namepoint(name)
	};

	return path(pair.first, pair.second);
}

std::string
ircd::db::path(const string_view &name,
               const uint64_t &checkpoint)
{
	const auto &prefix
	{
		fs::base::db
	};

	const string_view parts[]
	{
		prefix, name, lex_cast(checkpoint)
	};

	return fs::path_string(parts);
}

std::pair<ircd::string_view, uint64_t>
ircd::db::namepoint(const string_view &name_)
{
	const auto s
	{
		split(name_, ':')
	};

	return
	{
		s.first,
		s.second? lex_cast<uint64_t>(s.second) : uint64_t(-1)
	};
}

std::string
ircd::db::namepoint(const string_view &name,
                    const uint64_t &checkpoint)
{
	return std::string{name} + ':' + std::string{lex_cast(checkpoint)};
}

//
// Iterator
//

[[gnu::hot]]
std::pair<ircd::string_view, ircd::string_view>
ircd::db::operator*(const rocksdb::Iterator &it)
{
	return { key(it), val(it) };
}

[[gnu::hot]]
ircd::string_view
ircd::db::key(const rocksdb::Iterator &it)
{
	return slice(it.key());
}

[[gnu::hot]]
ircd::string_view
ircd::db::val(const rocksdb::Iterator &it)
{
	return slice(it.value());
}

//
// reflect
//

const std::string &
ircd::db::reflect(const rocksdb::Tickers type)
noexcept
{
	const auto &names(rocksdb::TickersNameMap);
	const auto it(std::find_if(begin(names), end(names), [&type]
	(const auto &pair)
	{
		return pair.first == type;
	}));

	static const auto empty{"<ticker>?????"s};
	return it != end(names)? it->second : empty;
}

const std::string &
ircd::db::reflect(const rocksdb::Histograms type)
noexcept
{
	const auto &names(rocksdb::HistogramsNameMap);
	const auto it(std::find_if(begin(names), end(names), [&type]
	(const auto &pair)
	{
		return pair.first == type;
	}));

	static const auto empty{"<histogram>?????"s};
	return it != end(names)? it->second : empty;
}

ircd::string_view
ircd::db::reflect(const pos pos)
noexcept
{
	switch(pos)
	{
		case pos::NEXT:     return "NEXT";
		case pos::PREV:     return "PREV";
		case pos::FRONT:    return "FRONT";
		case pos::BACK:     return "BACK";
		case pos::END:      return "END";
	}

	return "?????";
}

ircd::string_view
ircd::db::reflect(const op op)
noexcept
{
	switch(op)
	{
		case op::GET:             return "GET";
		case op::SET:             return "SET";
		case op::MERGE:           return "MERGE";
		case op::DELETE_RANGE:    return "DELETE_RANGE";
		case op::DELETE:          return "DELETE";
		case op::SINGLE_DELETE:   return "SINGLE_DELETE";
	}

	return "?????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::FlushReason r)
noexcept
{
	using Reason = rocksdb::FlushReason;

	switch(r)
	{
		case Reason::kOthers:                       return "Others";
		case Reason::kGetLiveFiles:                 return "GetLiveFiles";
		case Reason::kShutDown:                     return "ShutDown";
		case Reason::kExternalFileIngestion:        return "ExternalFileIngestion";
		case Reason::kManualCompaction:             return "ManualCompaction";
		case Reason::kWriteBufferManager:           return "WriteBufferManager";
		case Reason::kWriteBufferFull:              return "WriteBufferFull";
		case Reason::kTest:                         return "Test";
		case Reason::kDeleteFiles:                  return "DeleteFiles";
		case Reason::kAutoCompaction:               return "AutoCompaction";
		case Reason::kManualFlush:                  return "ManualFlush";
		case Reason::kErrorRecovery:                return "kErrorRecovery";
		#ifdef IRCD_DB_HAS_FLUSH_RETRY
		case Reason::kErrorRecoveryRetryFlush:      return "kErrorRecoveryRetryFlush";
		#endif
		#ifdef IRCD_DB_HAS_WAL_FULL
		case Reason::kWalFull:                      return "kWalFull";
		#endif
	}

	return "??????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::CompactionReason r)
noexcept
{
	using Reason = rocksdb::CompactionReason;

	switch(r)
	{
		case Reason::kUnknown:                      return "Unknown";
		case Reason::kLevelL0FilesNum:              return "LevelL0FilesNum";
		case Reason::kLevelMaxLevelSize:            return "LevelMaxLevelSize";
		case Reason::kUniversalSizeAmplification:   return "UniversalSizeAmplification";
		case Reason::kUniversalSizeRatio:           return "UniversalSizeRatio";
		case Reason::kUniversalSortedRunNum:        return "UniversalSortedRunNum";
		case Reason::kFIFOMaxSize:                  return "FIFOMaxSize";
		case Reason::kFIFOReduceNumFiles:           return "FIFOReduceNumFiles";
		case Reason::kFIFOTtl:                      return "FIFOTtl";
		case Reason::kManualCompaction:             return "ManualCompaction";
		case Reason::kFilesMarkedForCompaction:     return "FilesMarkedForCompaction";
		case Reason::kBottommostFiles:              return "BottommostFiles";
		case Reason::kTtl:                          return "Ttl";
		case Reason::kFlush:                        return "Flush";
		case Reason::kExternalSstIngestion:         return "ExternalSstIngestion";
		#ifdef IRCD_DB_HAS_PERIODIC_COMPACTIONS
		case Reason::kPeriodicCompaction:           return "kPeriodicCompaction";
		#endif
		#ifdef IRCD_DB_HAS_CHANGE_TEMPERATURE
		case Reason::kChangeTemperature:            return "kChangeTemperature";
		#endif
		#ifdef IRCD_DB_HAS_FORCED_BLOBGC
		case Reason::kForcedBlobGC:                 return "kForcedBlobGC";
		#endif
		#ifdef IRCD_DB_HAS_ROUND_ROBIN_TTL
		case Reason::kRoundRobinTtl:                return "kRoundRobinTtl";
		#endif
		#ifdef IRCD_DB_HAS_REFIT_LEVEL
		case Reason::kRefitLevel:                   return "RefitLevel";
		#endif

		case Reason::kNumOfReasons:
			break;
	}

	return "??????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::BackgroundErrorReason r)
noexcept
{
	using Reason = rocksdb::BackgroundErrorReason;

	switch(r)
	{
		case Reason::kFlush:               return "FLUSH";
		case Reason::kCompaction:          return "COMPACTION";
		case Reason::kWriteCallback:       return "WRITE";
		case Reason::kMemTable:            return "MEMTABLE";
		#ifdef IRCD_DB_HAS_MANIFEST_WRITE
		case Reason::kManifestWrite:       return "MANIFESTWRITE";
		#endif
		#ifdef IRCD_DB_HAS_FLUSH_RETRY
		case Reason::kFlushNoWAL:          return "FLUSHNOWAL";
		#endif
		#ifdef IRCD_DB_HAS_MANIFEST_WRITE_NOWAL
		case Reason::kManifestWriteNoWAL:  return "MANIFESTWRITENOWAL";
		#endif
	}

	return "??????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::WriteStallCondition c)
noexcept
{
	using Condition = rocksdb::WriteStallCondition;

	switch(c)
	{
		case Condition::kNormal:   return "NORMAL";
		case Condition::kDelayed:  return "DELAYED";
		case Condition::kStopped:  return "STOPPED";
	}

	return "??????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::Cache::Priority p)
noexcept
{
	using Priority = rocksdb::Cache::Priority;

	switch(p)
	{
		case Priority::HIGH:    return "HIGH";
		case Priority::LOW:     return "LOW";
		case Priority::BOTTOM:  return "BOTTOM";
	}

	return "????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::Env::Priority p)
noexcept
{
	using Priority = rocksdb::Env::Priority;

	switch(p)
	{
		case Priority::BOTTOM:  return "BOTTOM";
		case Priority::LOW:     return "LOW";
		case Priority::HIGH:    return "HIGH";
		#ifdef IRCD_DB_HAS_ENV_PRIO_USER
		case Priority::USER:    return "USER";
		#endif
		case Priority::TOTAL:
			assert(false);
	}

	return "????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::Env::IOPriority p)
noexcept
{
	using Priority = rocksdb::Env::IOPriority;

	switch(p)
	{
		case Priority::IO_LOW:     return "IO_LOW";
		#ifdef IRCD_DB_HAS_IO_MID
		case Priority::IO_MID:     return "IO_MID";
		#endif
		case Priority::IO_HIGH:    return "IO_HIGH";
		#ifdef IRCD_DB_HAS_IO_USER
		case Priority::IO_USER:    return "IO_USER";
		#endif
		case Priority::IO_TOTAL:   break;
	}

	return "IO_????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::Env::WriteLifeTimeHint h)
noexcept
{
	using Hint = rocksdb::Env::WriteLifeTimeHint;

	switch(h)
	{
		case Hint::WLTH_NOT_SET:   return "NOT_SET";
		case Hint::WLTH_NONE:      return "NONE";
		case Hint::WLTH_SHORT:     return "SHORT";
		case Hint::WLTH_MEDIUM:    return "MEDIUM";
		case Hint::WLTH_LONG:      return "LONG";
		case Hint::WLTH_EXTREME:   return "EXTREME";
	}

	return "WLTH_????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::Status::Severity s)
noexcept
{
	using Severity = rocksdb::Status::Severity;

	switch(s)
	{
		case Severity::kNoError:             return "NONE";
		case Severity::kSoftError:           return "SOFT";
		case Severity::kHardError:           return "HARD";
		case Severity::kFatalError:          return "FATAL";
		case Severity::kUnrecoverableError:  return "UNRECOVERABLE";
		case Severity::kMaxSeverity:         break;
	}

	return "?????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::Status::Code s)
noexcept
{
	using Code = rocksdb::Status::Code;

	switch(s)
	{
		case Code::kOk:                    return "Ok";
		case Code::kNotFound:              return "NotFound";
		case Code::kCorruption:            return "Corruption";
		case Code::kNotSupported:          return "NotSupported";
		case Code::kInvalidArgument:       return "InvalidArgument";
		case Code::kIOError:               return "IOError";
		case Code::kMergeInProgress:       return "MergeInProgress";
		case Code::kIncomplete:            return "Incomplete";
		case Code::kShutdownInProgress:    return "ShutdownInProgress";
		case Code::kTimedOut:              return "TimedOut";
		case Code::kAborted:               return "Aborted";
		case Code::kBusy:                  return "Busy";
		case Code::kExpired:               return "Expired";
		case Code::kTryAgain:              return "TryAgain";
		case Code::kCompactionTooLarge:    return "CompactionTooLarge";
		#ifdef IRCD_DB_HAS_CF_DROPPED
		case Code::kColumnFamilyDropped:   return "ColumnFamilyDropped";
		case Code::kMaxCode:               break;
		#endif
	}

	return "?????";
}

ircd::string_view
ircd::db::reflect(const rocksdb::RandomAccessFile::AccessPattern p)
noexcept
{
	using AccessPattern = rocksdb::RandomAccessFile::AccessPattern;

	switch(p)
	{
		case AccessPattern::NORMAL:      return "NORMAL";
		case AccessPattern::RANDOM:      return "RANDOM";
		case AccessPattern::SEQUENTIAL:  return "SEQUENTIAL";
		case AccessPattern::WILLNEED:    return "WILLNEED";
		case AccessPattern::DONTNEED:    return "DONTNEED";
	}

	return "??????";
}
