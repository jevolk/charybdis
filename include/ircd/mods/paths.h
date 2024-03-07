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
#define HAVE_IRCD_MODS_PATHS_H

namespace ircd::mods
{
	struct paths extern paths;

	// Platform (.so|.dll) postfixing
	std::string postfixed(std::string);
	std::string unpostfixed(std::string);
	std::string prefix_if_relative(std::string);
}

/// Search paths vector for modules. These directories will be searched
/// when a relative path/name is given to various other places in the
/// ircd::mods interface.
///
class ircd::mods::paths
{
	static conf::item<std::string> list;

	std::vector<std::string> p;

  public:
	auto begin() const
	{
		return p.begin();
	}

	auto end() const
	{
		return p.end();
	}

	bool added(const string_view &dir) const;

	bool del(const string_view &dir);
	bool add(const string_view &dir, std::nothrow_t);
	bool add(const string_view &dir);

	paths();
};
