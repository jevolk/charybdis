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
#define HAVE_IRCD_ALLOCATOR_ALLOCATOR_H

/// Suite of custom allocator templates for special behavior and optimization
///
/// These tools can be used as alternatives to the standard allocator. Most
/// templates implement the std::allocator concept and can be used with
/// std:: containers by specifying them in the container's template parameter.
///
namespace ircd::allocator
{
	struct aligned_alloc;

	string_view info(const mutable_buffer &, const string_view &opts = {});
	string_view get(const string_view &var, const mutable_buffer &val);
	string_view set(const string_view &var, const string_view &val = {}, const mutable_buffer &cur = {});
	template<class T> T get(const string_view &var);
	template<class T, class R> R &set(const string_view &var, T val, R &cur);
	template<class T> T set(const string_view &var, T val);
	bool trim(const size_t &pad = 0) noexcept; // malloc_trim(3)

	size_t incore(const const_buffer &);                               // fincore
	size_t advise(const const_buffer &, const int);                    // madvise
	size_t prefetch(const const_buffer &);                             // WILLNEED
	size_t fetch(const const_buffer &, const bool w = false);          // POPULATE_*
	size_t evict(const const_buffer &, const bool now = true);         // FREE / DONTNEED
	size_t cold(const const_buffer &, const bool now = false);         // COLD / PAGEOUT
	size_t flush(const const_buffer &, const bool invd = false);       // msync
	size_t sync(const const_buffer &, const bool invd = false);        // msync

	size_t lock(const const_buffer &, const bool enable = true);       // mlock
	size_t protect(const const_buffer &, const bool enable = true);    // mprotect
	size_t readonly(const mutable_buffer &, const bool enable = true); // mprotect

	[[using gnu: malloc, alloc_align(1), alloc_size(2), returns_nonnull, warn_unused_result]]
	char *allocate(const size_t align, const size_t size);
}

/// jemalloc specific suite; note that some of the primary ircd::allocator
/// interface has different functionality when je::available.
namespace ircd::allocator::je
{
	struct cork;
	using mib_vec = vector_view<const size_t>;

	extern const bool available;
}

#include "rlimit.h"
#include "je_cork.h"
#include "profile.h"
#include "scope.h"
#include "state.h"
#include "fixed.h"
#include "dynamic.h"
#include "callback.h"
#include "node.h"
#include "monotonic.h"

namespace ircd
{
	using allocator::aligned_alloc;
	using allocator::incore;
}

struct ircd::allocator::aligned_alloc
:std::unique_ptr<char, decltype(&std::free)>
{
	aligned_alloc(const size_t &align, const size_t &size)
	:std::unique_ptr<char, decltype(&std::free)>
	{
		allocate(align?: sizeof(void *), pad_to(size, align?: sizeof(void *))),
		&std::free
	}
	{}
};

template<class T>
inline T
ircd::allocator::set(const string_view &var,
                     T val)
{
	return set(var, val, val);
}

template<class T,
         class R>
inline R &
ircd::allocator::set(const string_view &var,
                     T val,
                     R &ret)
{
	const string_view in
	{
		reinterpret_cast<const char *>(std::addressof(val)),
		sizeof(val)
	};

	const string_view &out
	{
		set(var, in, mutable_buffer
		{
			reinterpret_cast<char *>(std::addressof(ret)),
			sizeof(ret)
		})
	};

	if(unlikely(size(out) != sizeof(ret)))
		throw std::system_error
		{
			make_error_code(std::errc::invalid_argument)
		};

	return ret;
}

template<class T>
inline T
ircd::allocator::get(const string_view &var)
{
	T val;
	const string_view &out
	{
		get(var, mutable_buffer
		{
			reinterpret_cast<char *>(std::addressof(val)),
			sizeof(val)
		})
	};

	if(unlikely(size(out) != sizeof(val)))
		throw std::system_error
		{
			make_error_code(std::errc::invalid_argument)
		};

	return val;
}
