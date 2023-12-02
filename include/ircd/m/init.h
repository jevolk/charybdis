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
#define HAVE_IRCD_M_INIT_H

namespace ircd::m::init
{
	struct modules;
	struct bootstrap;
}

/// Internal use only; do not call
namespace ircd::m::init::backfill
{
	extern size_t count;
	extern size_t complete;

	bool init();
	void term() noexcept;
	void fini() noexcept;
}

/// Internal use only; do not call
struct ircd::m::init::modules
{
	void init_imports();
	void fini_imports() noexcept;

	modules();
	~modules() noexcept;
};

/// Internal use only; do not call
struct ircd::m::init::bootstrap
{
	bootstrap();
};
