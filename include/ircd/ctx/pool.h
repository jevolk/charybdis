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
#define HAVE_IRCD_CTX_POOL_H

namespace ircd::ctx
{
	struct pool;

	const string_view &name(const pool &);
}

struct ircd::ctx::pool
{
	struct opts;
	using closure = std::function<void ()>;

	static const string_view default_name;
	static const opts default_opts;

	string_view name {default_name};
	const opts *opt {&default_opts};
	size_t running {0};
	size_t working {0};
	dock q_max;
	queue<closure> q;
	std::list<context> ctxs;

  private:
	bool done() const;
	void work();
	void leave() noexcept;
	void main() noexcept;

  public:
	explicit operator const opts &() const;

	// indicators
	auto size() const                  { return ctxs.size();                   }
	auto queued() const                { return q.size();                      }
	auto active() const                { return working;                       }
	auto avail() const                 { return running - active();            }
	auto pending() const               { return active() + queued();           }
	auto blocked() const               { return q_max.size();                  }
	bool wouldblock() const;

	// dispatch to pool
	template<class F, class... A> future_void<F, A...> async(F&&, A&&...);
	template<class F, class... A> future_value<F, A...> async(F&&, A&&...);
	void operator()(closure);

	// control panel
	size_t add(const size_t = 1);
	size_t del(const size_t = 1);
	size_t set(const size_t = -1);
	size_t min(const size_t = -1);
	size_t evict(const bool all = false, const bool now = false);
	size_t terminate();
	size_t interrupt();
	size_t join();

	pool(const string_view &name = default_name,
	     const opts & = default_opts);

	pool(pool &&) = delete;
	pool(const pool &) = delete;
	pool &operator=(pool &&) = delete;
	pool &operator=(const pool &) = delete;
	~pool() noexcept;

	friend const string_view &name(const pool &);
	friend void debug_stats(const pool &);
};

struct ircd::ctx::pool::opts
{
	/// When the pool spawns a new context this will be the stack size it has.
	size_t stack_size { DEFAULT_STACK_SIZE };

	/// When the pool is constructed this will be how many contexts it spawns
	/// This value may be ignored for static duration instances.
	size_t initial {0};

	/// Limit the number of spawned contexts to handle work. When set, calls to
	/// increase pool size will saturate at the limit.
	size_t limit {-1UL};

	/// Controls pool downsizing when `dynamic=true`. This is the number of
	/// idle contexts which are not removed during downscaling to prevent
	/// overzealous respawning. The default is 1. Setting to 0 allows for all
	/// contexts to be removed when there is no work running or queued. Setting
	/// to -1 disables automatic downsizing.
	size_t hysteresis {1};

	/// Hard-limit for jobs queued. A submit to the pool over this limit throws
	/// an exception. Default is -1, effectively unlimited.
	size_t queue_max_hard {-1UL};

	/// Soft-limit for jobs queued. The behavior of the limit is configurable.
	/// The default is 0, meaning if there is no context available to service
	/// the request being submitted then the soft limit is immediately reached.
	/// See the specific behavior options following this.
	size_t queue_max_soft {0};

	/// Yield a context submitting to the pool if it will violate the soft
	/// limit. This is true by default. Note the default of 0 for the
	/// soft-limit itself combined with this: by default there is no queueing
	/// of jobs at all! This behavior purposely propagates flow control by
	/// slowing down the submitting context and prevents flooding the queue.
	/// This option has no effect if the submitter is not on any ircd::ctx.
	bool queue_max_blocking {true};

	/// Dynamic pool sizing. When true, contexts may be spanwed on demand when
	/// jobs are submitted to the pool provided other options and limits are
	/// satisfied. Default is false.
	bool dynamic {false};

	/// Worker dispatch strategy.
	/// - FIFO: Dispatch fairly (round-robin).
	/// - LIFO: Dispatch the last to finish.
	/// - SORT: Like LIFO but lower ID's are given partial precedence.
	dock::opts dispatch {dock::opts::LIFO};

	/// Scheduler priority nice value for contexts in this pool.
	int8_t nice {0};

	/// IO priority nice value for contexts in this pool.
	int8_t ionice {0};
};

template<class F,
         class... A>
ircd::ctx::future_value<F, A...>
ircd::ctx::pool::async(F&& f,
                       A&&... a)
{
	using R = typename std::result_of<F (A...)>::type;

	auto func
	{
		std::bind(std::forward<F>(f), std::forward<A>(a)...)
	};

	promise<R> p;
	future<R> ret{p};
	operator()([p(std::move(p)), func(std::move(func))]
	{
		p.set_value(func());
	});

	return ret;
}

template<class F,
         class... A>
ircd::ctx::future_void<F, A...>
ircd::ctx::pool::async(F&& f,
                       A&&... a)
{
	using R = typename std::result_of<F (A...)>::type;

	auto func
	{
		std::bind(std::forward<F>(f), std::forward<A>(a)...)
	};

	promise<R> p;
	future<R> ret{p};
	operator()([p(std::move(p)), func(std::move(func))]
	{
		func();
		p.set_value();
	});

	return ret;
}

inline ircd::ctx::pool::operator
const opts &()
const
{
	assert(opt);
	return *opt;
}

inline const ircd::string_view &
ircd::ctx::name(const pool &pool)
{
	return pool.name;
}
