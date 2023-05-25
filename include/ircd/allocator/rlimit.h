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
#define HAVE_IRCD_ALLOCATOR_RLIMIT_H

namespace ircd::allocator::rlimit
{
	size_t virt();       // RLIMIT_AS
	size_t data();       // RLIMIT_DATA
	size_t stack();      // RLIMIT_STACK
	size_t memlock();    // RLIMIT_MEMLOCK

	size_t memlock(const size_t &request);
}
