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
#define HAVE_IRCD_ALLOCATOR_JE_CORK_H

struct ircd::allocator::je::cork
{
	struct opts;

  private:
	static size_t mib[][8];
	static const mib_vec dirty_mib;
	static const mib_vec muzzy_mib;
	static const mib_vec purge_mib;
	static const mib_vec decay_mib;

  public:
	ssize_t their_dirty {-2L};
	ssize_t their_muzzy {-2L};
	bool purge_post {false};
	bool decay_post {false};

	cork(const opts &);
	cork();
	cork(cork &&) noexcept;
	cork(const cork &) = delete;
	~cork() noexcept;
};

struct ircd::allocator::je::cork::opts
{
	/// Inhibit the dirty decay action.
	bool dirty {true};

	/// Inhibit the muzzy decay action.
	bool muzzy {false};

	/// Manual purge at the start of the cork.
	bool purge_pre {false};

	/// Manual purge at the end of the cork.
	bool purge_post {false};

	/// Manual decay at the end of the cork.
	bool decay_post {false};
};

inline
ircd::allocator::je::cork::cork()
:cork{opts{}}
{}

inline
ircd::allocator::je::cork::cork(cork &&o)
noexcept
:their_dirty
{
	std::exchange(o.their_dirty, -2L)
}
,their_muzzy
{
	std::exchange(o.their_muzzy, -2L)
}
,purge_post
{
	std::exchange(o.purge_post, false)
}
,decay_post
{
	std::exchange(o.decay_post, false)
}
{}
