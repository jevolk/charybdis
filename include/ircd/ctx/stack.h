// The Construct
//
// Copyright (C) The Construct Developers, Authors & Contributors
// Copyright (C) 2016-2020 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

namespace boost::context
{
	struct stack_context;
}

namespace boost::coroutines
{
	struct stack_context;
}

namespace ircd::ctx
{
	struct stack;

	size_t evict(const stack &, const bool all = false, const bool now = false);
}

struct ircd::ctx::stack
{
	struct allocator;

	mutable_buffer buf;                    // complete allocation
	uintptr_t base {0};                    // base frame pointer
	size_t max {0};                        // User given stack size
	size_t at {0};                         // Updated for profiling at sleep
	size_t peak {0};                       // Updated for profiling; maximum

	stack(const mutable_buffer &) noexcept;

	static const stack &get(const ctx &) noexcept;
	static stack &get(ctx &) noexcept;
};

struct [[gnu::visibility("hidden")]]
ircd::ctx::stack::allocator
{
	mutable_buffer &buf;
	bool owner {false};

	void deallocate(boost::coroutines::stack_context &) noexcept;
	void allocate(boost::coroutines::stack_context &, size_t size);

	void deallocate(boost::context::stack_context &) noexcept;
	boost::context::stack_context allocate();
};
