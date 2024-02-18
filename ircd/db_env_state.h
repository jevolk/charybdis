// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2019 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_DB_ENV_STATE_H

struct [[gnu::visibility("hidden")]]
ircd::db::database::env::state
{
	struct task;
	struct pool;

	static constexpr const size_t POOLS
	{
		rocksdb::Env::Priority::TOTAL
	};

	database &d;
	std::array<std::unique_ptr<pool>, POOLS> pool;

	state(database *const &);
	state(state &&) = delete;
	state(const state &) = delete;
	~state() noexcept;
};

struct [[gnu::visibility("hidden")]]
ircd::db::database::env::state::pool
{
	using Priority = rocksdb::Env::Priority;
	using IOPriority = rocksdb::Env::IOPriority;

	static conf::item<size_t> stack_size;
	static conf::item<ssize_t> hysteresis_high;
	static conf::item<ssize_t> hysteresis_low;

	database &d;
	Priority pri;
	IOPriority iopri;
	char namebuf[16];
	string_view name;
	ctx::dock dock;
	uint64_t taskctr {0};
	std::deque<task> tasks;
	ctx::pool::opts popts;
	ctx::pool p;

	void worker();
	void operator()(task &&);
	size_t cancel(void *const &tag);

	void wait();
	void join();

	pool(database &, const Priority &);
	pool(pool &&) = delete;
	pool(const pool &) = delete;
	~pool() noexcept;
};

struct [[gnu::visibility("hidden")]]
ircd::db::database::env::state::task
{
	void (*func)(void *arg);
	void (*cancel)(void *arg);
	void *arg;
	uint64_t _id {0};
};
