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
#define HAVE_IRCD_CACHE_H

namespace ircd
{
	struct cache extern *cache;
}

struct ircd::cache
{
	struct init;
	struct value;
	struct ticker;

	using key_type = uint128_t;
	using value_type = struct value;
	using get_closure = std::function<void (const_buffer)>;
	using put_closure = std::function<void (mutable_buffer)>;

	static conf::item<size_t> capacity_default;

	size_t capacity {0};
	std::unique_ptr<ticker> ticker;
	std::map<key_type, value> memcache;

	bool get(const key_type, const get_closure) const;
	bool put(const key_type, const size_t val_len, const put_closure);
	bool put(const key_type, const const_buffer val);
	bool del(const key_type);
	size_t trim(const size_t addl = 0);

	cache(const size_t capacity);
	~cache() noexcept;
};

struct ircd::cache::value
{
	shared_mutable_buffer buf;
};

struct ircd::cache::ticker
{
	template<class T> using item = ircd::stats::item<T>;

	// montonic event counts
	item<uint64_t> hit;
	item<uint64_t> miss;
	item<uint64_t> insert;
	item<uint64_t> remove;
	item<uint64_t> usage;

	ticker();
};

struct [[gnu::visibility("hidden")]]
ircd::cache::init
{
	init(), ~init() noexcept;
};
