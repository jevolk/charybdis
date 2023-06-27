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
#define HAVE_IRCD_ALLOCATOR_MONOTONIC_H

namespace ircd::allocator
{
	template<size_t = 512,
	         class T = char>
	struct monotonic;
}

/// The monotonic allocator combines std::pmr::monotonic_buffer_resource with
/// its backing buffer in a single template convenience object.
///
template<size_t SIZE,
         class T>
struct ircd::allocator::monotonic
:private std::array<T, SIZE>
,std::pmr::monotonic_buffer_resource
{
	monotonic();
	~monotonic() noexcept = default;
};

template<size_t SIZE,
         class T>
inline
ircd::allocator::monotonic<SIZE, T>::monotonic()
:std::pmr::monotonic_buffer_resource
{
	static_cast<std::array<T, SIZE> *>(this)->data(),
	static_cast<std::array<T, SIZE> *>(this)->size(),
}
{}
