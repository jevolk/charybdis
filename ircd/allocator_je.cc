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

#define IRCD_ALLOCATOR_JE_HOOK 0
#define RB_DEBUG_ALLOCATOR_JE 0

#if defined(IRCD_ALLOCATOR_USE_JEMALLOC) && defined(HAVE_JEMALLOC_H)
	#define IRCD_ALLOCATOR_JEMALLOC
#endif

namespace ircd::allocator::je
{
	using callback_prototype = void (std::ostream &, const string_view &);

	#if defined(IRCD_ALLOCATOR_USE_JEMALLOC)
	static void *arena_handle_alloc(extent_hooks_t *, void *, size_t, size_t, bool *, bool *, uint) noexcept;
	static bool arena_handle_dalloc(extent_hooks_t *, void *, size_t, bool, uint) noexcept;
	static void arena_handle_destroy(extent_hooks_t *, void *, size_t, bool, uint) noexcept;
	static bool arena_handle_commit(extent_hooks_t *, void *, size_t, size_t, size_t, uint) noexcept;
	static bool arena_handle_decommit(extent_hooks_t *, void *, size_t, size_t, size_t, uint) noexcept;
	static bool arena_handle_purge_lazy(extent_hooks_t *, void *, size_t, size_t, size_t, uint) noexcept;
	static bool arena_handle_purge_forced(extent_hooks_t *, void *, size_t, size_t, size_t, uint) noexcept;
	static bool arena_handle_split(extent_hooks_t *, void *, size_t, size_t, size_t, bool, uint) noexcept;
	static bool arena_handle_merge(extent_hooks_t *, void *, size_t, void *, size_t, bool, uint) noexcept;
	static void init(), fini() noexcept;
	extern extent_hooks_t arena_hooks, *their_arena_hooks;
	#endif

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
	",max_background_threads:0"
	",dirty_decay_ms:93000"
	",muzzy_decay_ms:305000"
	",lg_extent_max_active_fit:5"
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

///////////////////////////////////////////////////////////////////////////////
//
// arena hooks
//

#if defined(IRCD_ALLOCATOR_JEMALLOC)

decltype(ircd::allocator::je::their_arena_hooks)
ircd::allocator::je::their_arena_hooks;

decltype(ircd::allocator::je::arena_hooks)
ircd::allocator::je::arena_hooks
{
	#if RB_DEBUG_ALLOCATOR_JE == 1
	.alloc = arena_handle_alloc,
	.dalloc = arena_handle_dalloc,
	.destroy = arena_handle_destroy,
	.commit = arena_handle_commit,
	.decommit = arena_handle_decommit,
	.purge_lazy = arena_handle_purge_lazy,
	.purge_forced = arena_handle_purge_forced,
	.split = arena_handle_split,
	.merge = arena_handle_merge,
	#endif
};

static const auto
extent_hooks_key
{
	"arena.0.extent_hooks"
};

void
__attribute__((constructor))
ircd::allocator::je::init()
{
	if constexpr(IRCD_ALLOCATOR_JE_HOOK)
		allocator::set(extent_hooks_key, &arena_hooks, their_arena_hooks);
}

void
__attribute__((destructor))
ircd::allocator::je::fini()
noexcept
{
	extent_hooks_t *ours {nullptr};
	if constexpr(IRCD_ALLOCATOR_JE_HOOK)
		allocator::set(extent_hooks_key, their_arena_hooks, ours);

	assert(!ours || ours == &arena_hooks);
}

void *
ircd::allocator::je::arena_handle_alloc(extent_hooks_t *const hooks,
                                        void *const new_addr,
                                        size_t size,
                                        size_t alignment,
                                        bool *const zero,
                                        bool *const commit,
                                        unsigned arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);

	assert(zero);
	assert(commit);
	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u alloc addr:%p size:%zu align:%zu z:%b c:%b",
			arena_ind,
			new_addr,
			size,
			alignment,
			*zero,
			*commit,
		};

	void *const ret
	{
		their_hooks.alloc(hooks, new_addr, size, alignment, zero, commit, arena_ind)
	};

	return ret;
}

bool
ircd::allocator::je::arena_handle_dalloc(extent_hooks_t *hooks,
                                         void *const ptr,
                                         size_t size,
                                         bool committed,
                                         uint arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);

	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u dalloc addr:%p size:%zu align:%zu z:%b c:%b",
			arena_ind,
			ptr,
			size,
			committed,
		};

	const bool ret
	{
		their_hooks.dalloc(hooks, ptr, size, committed, arena_ind)
	};

	return ret;
}

void
ircd::allocator::je::arena_handle_destroy(extent_hooks_t *hooks,
                                          void *const ptr,
                                          size_t size,
                                          bool committed,
                                          uint arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);


	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u destroy addr:%p size:%zu align:%zu z:%b c:%b",
			arena_ind,
			ptr,
			size,
			committed,
		};

	return their_hooks.destroy(hooks, ptr, size, committed, arena_ind);
}

bool
ircd::allocator::je::arena_handle_commit(extent_hooks_t *const hooks,
                                         void *const ptr,
                                         size_t size,
                                         size_t offset,
                                         size_t length,
                                         uint arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);

	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u commit addr:%p size:%zu offset:%zu length:%zu",
			arena_ind,
			ptr,
			size,
			offset,
			length,
		};

	return their_hooks.commit(hooks, ptr, size, offset, length, arena_ind);
}

bool
ircd::allocator::je::arena_handle_decommit(extent_hooks_t *const hooks,
                                           void *const ptr,
                                           size_t size,
                                           size_t offset,
                                           size_t length,
                                           uint arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);

	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u decommit addr:%p size:%zu offset:%zu length:%zu",
			arena_ind,
			ptr,
			size,
			offset,
			length,
		};

	return their_hooks.decommit(hooks, ptr, size, offset, length, arena_ind);
}

bool
ircd::allocator::je::arena_handle_purge_lazy(extent_hooks_t *const hooks,
                                             void *const ptr,
                                             size_t size,
                                             size_t offset,
                                             size_t length,
                                             uint arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);

	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u purge lazy addr:%p size:%zu offset:%zu length:%zu",
			arena_ind,
			ptr,
			size,
			offset,
			length,
		};

	return their_hooks.purge_lazy(hooks, ptr, size, offset, length, arena_ind);
}

bool
ircd::allocator::je::arena_handle_purge_forced(extent_hooks_t *const hooks,
                                               void *const ptr,
                                               size_t size,
                                               size_t offset,
                                               size_t length,
                                               uint arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);

	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u purge forced addr:%p size:%zu offset:%zu length:%zu",
			arena_ind,
			ptr,
			size,
			offset,
			length,
		};

	return their_hooks.purge_forced(hooks, ptr, size, offset, length, arena_ind);
}

bool
ircd::allocator::je::arena_handle_split(extent_hooks_t *const hooks,
                                        void *const ptr,
                                        size_t size,
                                        size_t size_a,
                                        size_t size_b,
                                        bool committed,
                                        uint arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);

	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u split addr:%p size:%zu size_a:%zu size_b:%zu committed:%b",
			arena_ind,
			ptr,
			size,
			size_a,
			size_b,
			committed,
		};

	return their_hooks.split(hooks, ptr, size, size_a, size_b, committed, arena_ind);
}

bool
ircd::allocator::je::arena_handle_merge(extent_hooks_t *const hooks,
                                        void *const addr_a,
                                        size_t size_a,
                                        void *const addr_b,
                                        size_t size_b,
                                        bool committed,
                                        uint arena_ind)
noexcept
{
	assert(their_arena_hooks);
	const auto &their_hooks(*their_arena_hooks);

	if constexpr(RB_DEBUG_ALLOCATOR_JE)
		log::debug
		{
			"arena:%u merge a[addr:%p size:%zu] b[addr:%p size:%zu] committed:%b",
			arena_ind,
			addr_a,
			size_a,
			addr_b,
			size_b,
			committed,
		};

	return their_hooks.merge(hooks, addr_a, size_a, addr_b, size_b, committed, arena_ind);
}

#endif // defined(IRCD_ALLOCATOR_JEMALLOC)
