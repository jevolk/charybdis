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
#define HAVE_IRCD_M_FED_FILE_H

namespace ircd::m::fed
{
	struct file;
};

struct ircd::m::fed::file
:request
{
	struct opts;

	explicit operator const_buffer() const
	{
		return const_buffer
		{
			in.content
		};
	}

	file(const media::mxc &,
	     const mutable_buffer &,
	     opts);

	file() = default;
};

struct ircd::m::fed::file::opts
:request::opts
{
	/// Convenience to change the method to HEAD rathe than GET; useful for
	/// querying for existence without transfer.
	bool head {false};
};
