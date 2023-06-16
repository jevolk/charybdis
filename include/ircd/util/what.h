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
#define HAVE_IRCD_UTIL_WHAT_H

namespace ircd { inline namespace util
{
	[[gnu::pure]] string_view what(const std::exception_ptr & = std::current_exception()) noexcept;
	string_view what(const std::exception &) noexcept;
}}

inline ircd::string_view
ircd::util::what(const std::exception &e)
noexcept
{
	return e.what();
}
