// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include <RB_INC_JEMALLOC_H

#if defined(IRCD_ALLOCATOR_USE_JEMALLOC) && defined(HAVE_JEMALLOC_H)
	#define IRCD_ALLOCATOR_JEMALLOC
#endif

namespace ircd::allocator::je
{
	using callback_prototype = void (std::ostream &, const string_view &);

	static void stats_handler(void *, const char *) noexcept;
	static mib_vec lookup(const vector_view<size_t> &, const string_view &);
	static string_view get(const mib_vec &, const mutable_buffer & = {});
	static string_view set(const mib_vec &, const string_view & = {}, const mutable_buffer & = {});

	static std::function<callback_prototype> stats_callback;
	extern info::versions malloc_version_api;
	extern info::versions malloc_version_abi;
}

#if defined(IRCD_ALLOCATOR_USE_JEMALLOC)
const char *
__attribute__((weak))
malloc_conf
{
	"narenas:1"
	",tcache:false"
	",metadata_thp:always"
};
#endif

decltype(ircd::allocator::je::malloc_version_api)
ircd::allocator::je::malloc_version_api
{
	"jemalloc", info::versions::API, 0,
	#ifdef HAVE_JEMALLOC_H
	{
		JEMALLOC_VERSION_MAJOR,
		JEMALLOC_VERSION_MINOR,
		JEMALLOC_VERSION_BUGFIX
	},
	JEMALLOC_VERSION
	#endif
};

decltype(ircd::allocator::je::malloc_version_abi)
ircd::allocator::je::malloc_version_abi
{
	"jemalloc", info::versions::ABI, 0, {0, 0, 0}, []
	(info::versions &v, const mutable_buffer &buf)
	{
		#ifdef IRCD_ALLOCATOR_JEMALLOC
		const string_view val
		{
			*reinterpret_cast<const char *const *>
			(
				data(allocator::get("version", mutable_buffer(buf, sizeof(char *))))
			)
		};

		if(!val)
			return;

		strlcpy(buf, val);
		const string_view semantic(split(val, '-').first);
		v.semantic[0] = lex_cast<ulong>(token(semantic, '.', 0));
		v.semantic[1] = lex_cast<ulong>(token(semantic, '.', 1));
		v.semantic[2] = lex_cast<ulong>(token(semantic, '.', 2));
		#endif
	}
};

decltype(ircd::allocator::je::available)
ircd::allocator::je::available
{
	#if defined(IRCD_ALLOCATOR_JEMALLOC)
		mods::ldso::has("jemalloc")
	#endif
};

//
// je::cork
//

[[gnu::visibility("internal")]]
decltype(ircd::allocator::je::cork::mib)
ircd::allocator::je::cork::mib
{
	{ 0 },
	{ 0 },
	{ 0 },
	{ 0 },
};

[[gnu::visibility("hidden")]]
decltype(ircd::allocator::je::cork::dirty_mib)
ircd::allocator::je::cork::dirty_mib
{
	#if defined(IRCD_ALLOCATOR_JEMALLOC)
	lookup(mib[0], "arena." IRCD_STRING(MALLCTL_ARENAS_ALL) ".dirty_decay_ms")
	#endif
};

[[gnu::visibility("hidden")]]
decltype(ircd::allocator::je::cork::muzzy_mib)
ircd::allocator::je::cork::muzzy_mib
{
	#if defined(IRCD_ALLOCATOR_JEMALLOC)
	lookup(mib[1], "arena." IRCD_STRING(MALLCTL_ARENAS_ALL) ".muzzy_decay_ms")
	#endif
};

[[gnu::visibility("hidden")]]
decltype(ircd::allocator::je::cork::purge_mib)
ircd::allocator::je::cork::purge_mib
{
	#if defined(IRCD_ALLOCATOR_JEMALLOC)
	lookup(mib[2], "arena." IRCD_STRING(MALLCTL_ARENAS_ALL) ".purge")
	#endif
};

[[gnu::visibility("hidden")]]
decltype(ircd::allocator::je::cork::decay_mib)
ircd::allocator::je::cork::decay_mib
{
	#if defined(IRCD_ALLOCATOR_JEMALLOC)
	lookup(mib[2], "arena." IRCD_STRING(MALLCTL_ARENAS_ALL) ".decay")
	#endif
};

ircd::allocator::je::cork::cork(const opts &opts)
:purge_post
{
	opts.purge_post
}
,decay_post
{
	opts.decay_post
}
{
	const byte_view<string_view> corked
	{
		-1L
	};

	if(opts.dirty)
	{
		const mutable_buffer out
		{
			 reinterpret_cast<char *>(&their_dirty), sizeof(their_dirty)
		};

		set(dirty_mib, corked, out);
	}

	if(opts.muzzy)
	{
		const mutable_buffer out
		{
			 reinterpret_cast<char *>(&their_muzzy), sizeof(their_muzzy)
		};

		set(muzzy_mib, corked, out);
	}

	if(opts.purge_pre)
		set(purge_mib);
}

ircd::allocator::je::cork::~cork()
noexcept try
{
	if(decay_post)
		set(decay_mib);

	if(purge_post)
		set(purge_mib);

	if(their_dirty != -2)
		set(dirty_mib, byte_view<string_view>(their_dirty));

	if(their_muzzy != -2)
		set(muzzy_mib, byte_view<string_view>(their_muzzy));
}
catch(const std::system_error &e)
{
	log::error
	{
		"allocator::je::~cork() :%s",
		e.what(),
	};

	return;
}

//
// ircd::allocator
//

#if defined(IRCD_ALLOCATOR_JEMALLOC)
bool
ircd::allocator::trim(const size_t &flag)
noexcept try
{
	if(flag & 1)
	{
		static const auto name
		{
			"arena." IRCD_STRING(MALLCTL_ARENAS_ALL) ".decay"
		};

		static size_t mib_buf[8];
		static const auto mib
		{
			je::lookup(mib_buf, name)
		};

		je::set(mib);
	}

	if(flag & 2 || flag == 0)
	{
		static const auto name
		{
			"arena." IRCD_STRING(MALLCTL_ARENAS_ALL) ".purge"
		};

		static size_t mib_buf[8];
		static const auto mib
		{
			je::lookup(mib_buf, name)
		};

		je::set(mib);
	}

	return true;
}
catch(const std::exception &e)
{
	log::error
	{
		"allocator::trim(%zu) :%s",
		flag,
		e.what(),
	};

	return false;
}
#endif

#if defined(IRCD_ALLOCATOR_JEMALLOC)
ircd::string_view
ircd::allocator::set(const string_view &key_,
                     const string_view &val,
                     const mutable_buffer &buf)
try
{
	std::array<size_t, 8> mib;
	return je::set(je::lookup(mib, key_), val, buf);
}
catch(const std::system_error &e)
{
	log::error
	{
		"allocator::set('%s') :%s",
		key_,
		e.what(),
	};

	throw;
}
#endif

#if defined(IRCD_ALLOCATOR_JEMALLOC)
ircd::string_view
ircd::allocator::get(const string_view &key_,
                     const mutable_buffer &buf)
try
{
	std::array<size_t, 8> mib;
	return je::get(je::lookup(mib, key_), buf);
}
catch(const std::system_error &e)
{
	log::error
	{
		"allocator::get('%s') :%s",
		key_,
		e.what(),
	};

	throw;
}

#endif

ircd::string_view
ircd::allocator::je::set(const mib_vec &mib,
                         const string_view &val,
                         const mutable_buffer &cur)
try
{
	size_t curlen(size(cur));
	const auto err
	{
		#if defined(IRCD_ALLOCATOR_JEMALLOC)
			::mallctlbymib
			(
				data(mib),
				size(mib),
				curlen? data(cur): nullptr,
				curlen? &curlen: nullptr,
				mutable_cast(data(val)),
				size(val)
			)
		#else
			int(std::errc::no_link)
		#endif
	};

	if(unlikely(err != 0))
		throw_system_error(err);

	return string_view
	{
		data(cur), std::min(curlen, size(cur))
	};
}
catch(const std::system_error &e)
{
	log::error
	{
		"allocator::set() :%s",
		e.what(),
	};

	throw;
}

ircd::string_view
ircd::allocator::je::get(const mib_vec &mib,
                         const mutable_buffer &buf)
try
{
	assert(!empty(buf));
	size_t len(size(buf));
	const auto err
	{
		#if defined(IRCD_ALLOCATOR_JEMALLOC)
			::mallctlbymib
			(
				data(mib),
				size(mib),
				data(buf),
				&len,
				nullptr,
				0UL
			)
		#else
			int(std::errc::no_link)
		#endif
	};

	if(unlikely(err != 0))
		throw_system_error(err);

	return string_view
	{
		data(buf), std::min(len, size(buf))
	};
}
catch(const std::system_error &e)
{
	log::error
	{
		"allocator::get() :%s",
		e.what(),
	};

	throw;
}

ircd::allocator::je::mib_vec
ircd::allocator::je::lookup(const vector_view<size_t> &out,
                            const string_view &key_)
{
	char buf[128];
	const string_view key
	{
		strlcpy(buf, key_)
	};

	size_t len(size(out));
	const auto err
	{
		#if defined(IRCD_ALLOCATOR_JEMALLOC)
			::mallctlnametomib(key.c_str(), data(out), &len)
		#else
			int(std::errc::no_link)
		#endif
	};

	if(unlikely(err != 0))
		throw_system_error(err);

	return vector_view<const size_t>
	{
		data(out), len
	};
}

void
ircd::allocator::je::stats_handler(void *const ptr,
                                   const char *const msg)
noexcept try
{
	auto &out
	{
		*reinterpret_cast<std::stringstream *>(ptr)
	};

	stats_callback(out, msg);
}
catch(const std::bad_function_call &)
{
	assert(0);
	return;
}

#if defined(IRCD_ALLOCATOR_JEMALLOC)
ircd::string_view
ircd::allocator::info(const mutable_buffer &buf,
                      const string_view &opts_)
{
	std::stringstream out;
	pubsetbuf(out, buf);

	je::stats_callback = []
	(auto &out, const string_view &msg)
	{
		out << msg;
	};

	char opts_buf[64];
	const char *const opts
	{
		opts_?
			data(strlcpy(opts_buf, opts_)):
			""
	};

	malloc_stats_print(je::stats_handler, &out, opts);
	out << std::endl;
	return view(out, buf);
}
#endif

#if defined(IRCD_ALLOCATOR_JEMALLOC)
void
ircd::allocator::scope::hook_init()
noexcept
{
}
#endif

#if defined(IRCD_ALLOCATOR_JEMALLOC)
void
ircd::allocator::scope::hook_fini()
noexcept
{
}
#endif
