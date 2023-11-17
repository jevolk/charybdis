// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2023 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

decltype(ircd::cache)
ircd::cache;

decltype(ircd::cache::capacity_default)
ircd::cache::capacity_default
{
	{ "name",     "ircd.cache.capacity" },
	{ "default",  0L                    },
};

ircd::cache::init::init()
{
	if(!capacity_default)
		return;

	assert(!ircd::cache);
	ircd::cache = new struct ircd::cache
	{
		size_t(capacity_default)
	};
}

ircd::cache::init::~init()
noexcept
{
	delete ircd::cache;
	ircd::cache = nullptr;
}

ircd::cache::cache(const size_t capacity)
:capacity
{
	capacity
}
,ticker
{
	std::make_unique<struct ticker>()
}
{
}

ircd::cache::~cache()
noexcept
{
}

size_t
ircd::cache::trim(const size_t addl)
{
	size_t ret(0);
	if(memcache.empty())
		return ret;

	assert(ticker);
	if(!capacity || ticker->usage + addl <= capacity)
		return ret;

	while(ticker->usage + addl > capacity)
	{
		assert(memcache.size() > 0);
		uint64_t choice
		{
			rand::integer(0, memcache.size() - 1)
		};

		auto it(memcache.begin());
		std::advance(it, choice);
		assert(it != memcache.end());
		ret += del(it->first); //XXX
	}

	return ret;
}

bool
ircd::cache::del(const uint128_t key)
{
	auto it
	{
		memcache.find(key)
	};

	if(it == memcache.end())
		return false;

	auto &val
	{
		it->second
	};

	const size_t val_len
	{
		size(val.buf)
	};

	it = memcache.erase(it);
	assert(ticker);
	ticker->usage -= val_len;
	ticker->remove++;
	return true;
}

bool
ircd::cache::put(const uint128_t key,
                 const const_buffer val)
{
	return put(key, size(val), [&val](const mutable_buffer buf)
	{
		return const_buffer
		{
			data(buf), copy(buf, val)
		};
	});
}

bool
ircd::cache::put(const uint128_t key,
                 const size_t val_len,
                 const put_closure closure)
{
	if(!val_len)
		return false;

	if(capacity && val_len > capacity / 1024)
		return false;

	const auto trimmed
	{
		trim(val_len)
	};

	auto it
	{
		memcache.lower_bound(key)
	};

	if(it == memcache.end() || it->first != key)
		it = memcache.emplace_hint(it, key, value
		{
			.buf = shared_mutable_buffer {val_len}
		});

	assert(it != memcache.end());
	assert(it->first == key);
	auto &value
	{
		it->second
	};

	const shared_mutable_buffer smb
	{
		value.buf
	};

	const mutable_buffer buf{smb};
	assert(size(buf) >= val_len);
	assert(closure); try
	{
		closure(buf);
	}
	catch(...)
	{
		memcache.erase(it);
		throw;
	}

	assert(ticker);
	ticker->usage += size(buf);
	ticker->insert++;
	return true;
}

bool
ircd::cache::get(const uint128_t key,
                 const get_closure closure)
const
{
	const auto it
	{
		memcache.find(key)
	};

	if(it == memcache.end())
	{
		assert(ticker);
		ticker->miss++;
		return false;
	}

	assert(ticker);
	ticker->hit++;

	assert(it->first == key);
	auto &value
	{
		it->second
	};

	if(likely(closure))
	{
		const shared_mutable_buffer smb
		{
			value.buf
		};

		closure(const_buffer(smb));
	}

	return true;
}

//
// cache::ticker
//

ircd::cache::ticker::ticker()
:hit
{
	{ "name", "ircd.cache.hit" },
}
,miss
{
	{ "name", "ircd.cache.miss" },
}
,insert
{
	{ "name", "ircd.cache.insert" },
}
,remove
{
	{ "name", "ircd.cache.remove" },
}
,usage
{
	{ "name", "ircd.cache.usage" },
}
{
}
