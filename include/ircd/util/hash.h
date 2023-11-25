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
#define HAVE_IRCD_UTIL_HASH_H

// constexpr bernstein string hasher suite; these functions will hash the
// string at compile time leaving an integer residue at runtime. Decent
// primes are at least 7681 and 5381.

namespace ircd {
inline namespace util
{
	template<class T,
	         size_t PRIME,
	         class it>
	constexpr T hash(it, const it, T r = PRIME) noexcept;

	template<class T = size_t,
	         size_t PRIME = 7681>
	constexpr T hash(const string_view, T r = PRIME) noexcept;

	template<class T = size_t,
	         size_t PRIME = 7681>
	constexpr T hash(const std::u16string_view, T r = PRIME) noexcept;
}}

/// Hashing of a wider string_view. Non-cryptographic.
template<class T,
         size_t PRIME>
[[gnu::pure]]
constexpr T
ircd::util::hash(const std::u16string_view str,
                 T r)
noexcept
{
	return hash<T, PRIME>(begin(str), end(str), r);
}

/// Hashing of a string_view. Non-cryptographic.
template<class T,
         size_t PRIME>
[[gnu::pure]]
constexpr T
ircd::util::hash(const string_view str,
                 T r)
noexcept
{
	return hash<T, PRIME>(begin(str), end(str), r);
}

/// Hashing of an iterable range. Non-cryptographic.
template<class T,
         size_t PRIME,
         class it>
[[gnu::pure]]
constexpr T
ircd::util::hash(it a,
                 const it b,
                 T r)
noexcept
{
	for(; a != b; ++a)
		r = (*a) ^ (r * 33);

	r |= 1;
	r *= r;
	return r;
}
