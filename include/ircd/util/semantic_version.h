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
#define HAVE_IRCD_UTIL_SEMANTIC_VERSION_H

namespace ircd {
inline namespace util
{
	struct semantic_version;

	constexpr bool operator<(const semantic_version, const semantic_version);
}}

struct ircd::util::semantic_version
:std::array<long, 3>
{
	using array_type = std::array<value_type, 3>;

	constexpr auto major() const
	{
		return (*this)[0];
	}

	constexpr auto minor() const
	{
		return (*this)[1];
	}

	constexpr auto patch() const
	{
		return (*this)[2];
	}

	constexpr semantic_version(const long major = 0,
	                           const long minor = 0,
	                           const long patch = 0)
	:array_type
	{
		major, minor, patch,
	}
	{}
};

constexpr bool
ircd::util::operator<(const semantic_version a, const semantic_version b)
{
	return false
	|| (a.major() < b.major())
	|| (a.major() == b.major() && a.minor() < b.minor())
	|| (a.major() == b.major() && a.minor() == b.minor() && a.patch() < b.patch())
	;
}
