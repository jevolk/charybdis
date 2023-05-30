// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2023 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_ALLOCATOR_SCOPE_H

namespace ircd::allocator
{
	struct scope;
}

struct ircd::allocator::scope
{
	using alloc_closure = std::function<void *(size_t)>;
	using realloc_closure = std::function<void *(void *ptr, size_t)>;
	using free_closure = std::function<bool (void *ptr)>;

	static void hook_init() noexcept;
	static void hook_fini() noexcept;

	static scope *current;
	scope *theirs;
	alloc_closure user_alloc;
	realloc_closure user_realloc;
	free_closure user_free;

  public:
	scope(alloc_closure = {}, realloc_closure = {}, free_closure = {});
	scope(const scope &) = delete;
	scope(scope &&) = delete;
	~scope() noexcept;
};

inline
ircd::allocator::scope::scope(alloc_closure ac,
                              realloc_closure rc,
                              free_closure fc)
:theirs
{
	std::exchange(current, this)
}
,user_alloc
{
	std::move(ac)
}
,user_realloc
{
	std::move(rc)
}
,user_free
{
	std::move(fc)
}
{
	// If an allocator::scope instance already exists somewhere
	// up the stack, *current will already be set. We only install
	// our global hook handlers at the first instance ctor and
	// uninstall it after that first instance dtors.
	if(!theirs)
		hook_init();
}

inline
ircd::allocator::scope::~scope()
noexcept
{
	assert(current == this);
	theirs = std::exchange(current, theirs);

	// Reinstall the pre-existing hooks after our last scope instance
	// has destructed (the first to have constructed). We know this when
	// current becomes null.
	if(!current)
		hook_fini();
}
