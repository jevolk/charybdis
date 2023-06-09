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
#define HAVE_IRCD_UTIL_SCOPE_COUNT_H

namespace ircd {
inline namespace util
{
	template<class T> struct scope_count;
}}

/// Increment a counter when constructed and decrement it when destructed.
/// This takes a runtime reference to that counter. The counter thus maintains
/// the number of reentrances (or entrances across different contexts).
///
template<class T>
struct ircd::util::scope_count
{
	T *count {nullptr};
	T inc {1};

	scope_count(T &count, const T & = 1);
	scope_count(const scope_count &) = delete;
	scope_count(scope_count &&) noexcept = delete;
	~scope_count() noexcept;
};

template<class T>
inline
ircd::util::scope_count<T>::scope_count(T &count,
                                        const T &inc)
:count{&count}
,inc{inc}
{
	count += inc;
}

template<class T>
inline
ircd::util::scope_count<T>::~scope_count()
noexcept
{
	assert(count);
	(*count) -= inc;
}
