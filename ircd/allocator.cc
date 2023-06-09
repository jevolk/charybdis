// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include <RB_INC_SYS_RESOURCE_H
#include <RB_INC_SYS_MMAN_H

// Uncomment or -D this #define to enable our own crude but simple ability to
// profile dynamic memory usage. Global `new` and `delete` will be captured
// here by this definition file into thread_local counters accessible via
// ircd::allocator::profile. This feature allows the developer to find out if
// allocations are occurring during some scope by sampling the counters.
//
// #define RB_PROF_ALLOC

namespace ircd::allocator
{
	static void advise_hugepage(void *const &, const size_t &alignment, const size_t &size);
}

#if defined(MADV_NORMAL) && defined(POSIX_MADV_NORMAL)
	static_assert(MADV_NORMAL == POSIX_MADV_NORMAL);
#endif

#if defined(MADV_SEQUENTIAL) && defined(POSIX_MADV_SEQUENTIAL)
	static_assert(MADV_SEQUENTIAL == POSIX_MADV_SEQUENTIAL);
#endif

#if defined(MADV_RANDOM) && defined(POSIX_MADV_RANDOM)
	static_assert(MADV_RANDOM == POSIX_MADV_RANDOM);
#endif

#if defined(MADV_WILLNEED) && defined(POSIX_MADV_WILLNEED)
	static_assert(MADV_WILLNEED == POSIX_MADV_WILLNEED);
#endif

#if defined(MADV_DONTNEED) && defined(POSIX_MADV_DONTNEED)
	static_assert(MADV_DONTNEED == POSIX_MADV_DONTNEED);
#endif

[[gnu::hot]]
char *
ircd::allocator::allocate(const size_t alignment,
                          const size_t size)
{
	assume(alignment > 0);
	assume(size % alignment == 0);
	assume(alignment % sizeof(void *) == 0);

	void *ret;
	switch(int errc(::posix_memalign(&ret, alignment, size)); errc)
	{
		[[likely]]
		case 0:
			break;

		[[unlikely]]
		case int(std::errc::not_enough_memory):
			throw std::bad_alloc{};

		[[unlikely]]
		default:
			throw_system_error();
			__builtin_unreachable();
	}

	assert(ret != nullptr);
	assert(uintptr_t(ret) % alignment == 0);

	if(likely(info::thp_size))
		advise_hugepage(ret, alignment, size);

	#ifdef RB_PROF_ALLOC
	auto &this_thread(ircd::allocator::profile::this_thread);
	this_thread.alloc_bytes += size;
	this_thread.alloc_count++;
	#endif

	return reinterpret_cast<char *>(ret);
}

void
ircd::allocator::advise_hugepage(void *const &ptr,
                                 const size_t &alignment,
                                 const size_t &size)

#if defined(MADV_HUGEPAGE)
try
{
	if(likely(alignment < info::thp_size))
		return;

	if(likely(alignment % size_t(info::thp_size) != 0))
		return;

	if(!has(info::thp_enable, "[madvise]"))
		return;

	sys::call(::madvise, ptr, size, MADV_HUGEPAGE);
}
catch(const std::exception &e)
{
	log::critical
	{
		"Failed to madvise(%p, %zu, MADV_HUGEPAGE) :%s",
		ptr,
		size,
		e.what(),
	};
}
#else
{
}
#endif

void
ircd::allocator::readonly(const mutable_buffer &buf,
                          const bool enable)
#if defined(HAVE_MPROTECT)
{
	const int prot
	{
		enable?
			PROT_READ:
			PROT_READ|PROT_WRITE
	};

	void *const ptr(mutable_cast(data(buf)));
	sys::call(::mprotect, ptr, size(buf), prot);
}
#else
{
	#warning "mprotect(2) not available for this compilation."
}
#endif

#if defined(HAVE_MPROTECT)
void
ircd::allocator::protect(const const_buffer &buf,
                         const bool enable)
{
	const int prot
	{
		enable?
			PROT_NONE:
			PROT_READ|PROT_WRITE
	};

	void *const ptr(mutable_cast(data(buf)));
	sys::call(::mprotect, ptr, size(buf), prot);
}
#else
{
	#warning "mprotect(2) not available for this compilation."
}
#endif

void
ircd::allocator::lock(const const_buffer &buf,
                      const bool enable)
#if defined(HAVE_MLOCK2) && defined(MLOCK_ONFAULT)
{
	int flags {0};
	flags |= MLOCK_ONFAULT;

	// can't mlock w/ valgrind
	if(unlikely(vg::active))
		return;

	if(enable)
		syscall(::mlock2, data(buf), size(buf), flags);
	else
		syscall(::munlock, data(buf), size(buf));
}
#else
{
	#warning "mlock2(2) not available for this compilation."
}
#endif

size_t
ircd::allocator::sync(const const_buffer &buf,
                      const bool invd)
{
	assert(aligned(data(buf), info::page_size));
	const prof::syscall_usage_warning message
	{
		"msync(2) MS_SYNC MS_INVALIDATE:%b", invd
	};

	#if defined(HAVE_MSYNC)
		int flags {MS_SYNC};
		flags |= invd? MS_INVALIDATE: 0;
		sys::call(::msync, mutable_cast(data(buf)), size(buf), flags);
		return size(buf);
	#else
		return 0;
	#endif
}

size_t
ircd::allocator::flush(const const_buffer &buf,
                       const bool invd)
{
	assert(aligned(data(buf), info::page_size));
	const prof::syscall_usage_warning message
	{
		"msync(2) MS_ASYNC MS_INVALIDATE:%b", invd
	};

	#if defined(HAVE_MSYNC)
		int flags {MS_ASYNC};
		flags |= invd? MS_INVALIDATE: 0;
		sys::call(::msync, mutable_cast(data(buf)), size(buf), flags);
		return size(buf);
	#else
		return 0;
	#endif
}

size_t
ircd::allocator::cold(const const_buffer &buf,
                      const bool now)
{
	const auto advice
	{
		#if defined(MADV_COLD) && defined(MADV_PAGEOUT)
			now? MADV_PAGEOUT: MADV_COLD
		#elif defined(MADV_PAGEOUT)
			MADV_PAGEOUT
		#endif
	};

	#if defined(MADV_PAGEOUT) || defined(MADV_COLD)
		return advise(buf, advice);
	#else
		return 0;
	#endif
}

size_t
ircd::allocator::evict(const const_buffer &buf,
                       const bool now)
{
	const auto advice
	{
		#if defined(MADV_FREE) && defined(POSIX_MADV_DONTNEED)
			now? POSIX_MADV_DONTNEED: MADV_FREE
		#elif defined(POSIX_MADV_DONTNEED)
			POSIX_MADV_DONTNEED
		#endif
	};

	#if defined(POSIX_MADV_DONTNEED) || defined(MADV_FREE)
		return advise(buf, advice);
	#else
		return 0;
	#endif
}

size_t
ircd::allocator::fetch(const const_buffer &buf,
                       const bool w)
{
	#if defined(MADV_POPULATE_READ) && defined(MADV_POPULATE_WRITE)
		return advise(buf, w? MADV_POPULATE_WRITE: MADV_POPULATE_READ);
	#else
		return 0;
	#endif
}

size_t
ircd::allocator::prefetch(const const_buffer &buf)
{
	#if defined(POSIX_MADV_WILLNEED)
		return advise(buf, POSIX_MADV_WILLNEED);
	#else
		return 0;
	#endif
}

#if defined(HAVE_MADVISE)
size_t
ircd::allocator::advise(const const_buffer &buf,
                        const int advice)
{
	assert(aligned(data(buf), info::page_size));
	switch(const auto r(::madvise(mutable_cast(data(buf)), size(buf), advice)); r)
	{
		[[likely]]
		case 0:
			return size(buf);          // success

		[[unlikely]]
		default:
			throw_system_error(r);     // error
	}

	__builtin_unreachable();
}
#elif defined(HAVE_POSIX_MADVISE)
size_t
ircd::allocator::advise(const const_buffer &buf,
                        const int advice)
{
	const auto res
	{
		syscall(::posix_madvise, mutable_cast(data(buf)), size(buf), advice)
	};

	return size(buf);
}
#else
#warning "posix_madvise(2) not available for this compilation."
size_t
ircd::allocator::advise(const const_buffer &buf,
                        const int advice)
{
	return 0;
}
#endif

size_t
ircd::allocator::incore(const const_buffer &buf)
{
	const auto base
	{
		align(begin(buf), info::page_size)
	};

	if(unlikely(!base))
		return 0;

	const auto top
	{
		align_up(end(buf), info::page_size)
	};

	assert(base <= data(buf));
	const auto below
	{
		std::distance(base, begin(buf))
	};

	assert(top >= data(buf) + size(buf));
	const auto span
	{
		std::distance(base, top)
	};

	const auto above
	{
		std::distance(end(buf), top)
	};

	assert(span >= 0);
	assert(above >= 0);
	assert(below >= 0);
	assert(above < ssize_t(info::page_size));
	assert(below < ssize_t(info::page_size));
	assert(below + ssize_t(size(buf)) + above == span);

	auto remain(span), ret(0L);
	thread_local uint8_t vec alignas(64) [4096];
	for(auto i(0); i < span / ssizeof(vec) && remain > 0; ++i)
	{
		const auto len
		{
			std::min(ssizeof(vec) * ssize_t(info::page_size), remain)
		};

		assert(len > 0);
		assert(len <= span);
		const ssize_t vec_size
		(
			std::ceil(len / double(info::page_size))
		);

		assert(vec_size > 0);
		assert(vec_size <= ssizeof(vec));
		syscall(::mincore, mutable_cast(base), len, vec);
		for(auto j(0); j < vec_size; ++j)
			ret += (vec[j] & 0x01) * info::page_size;

		remain -= len;
		assert(remain >= 0);
		if(!remain && (vec[vec_size - 1] & 0x01)) // last iteration
			ret -= above;

		assert(ret >= 0);
		if(i == 0 && (vec[0] & 0x01)) // first iteration
			ret -= below;

		assert(ret >= 0);
	}

	assert(remain == 0);
	assert(ret <= ssize_t(size(buf)));
	assert(ret >= 0);
	return ret;
}

//
// control panel
//

bool
__attribute__((weak))
ircd::allocator::trim(const size_t &pad)
noexcept
{
	return false;
}

ircd::string_view
__attribute__((weak))
ircd::allocator::get(const string_view &key,
                     const mutable_buffer &buf)
{
	return {};
}

ircd::string_view
__attribute__((weak))
ircd::allocator::set(const string_view &key,
                     const string_view &val,
                     const mutable_buffer &cur)
{
	return {};
}

//
// allocator::state
//

void
ircd::allocator::state::deallocate(const uint &pos,
                                   const size_type &n)
{
	for(size_t i(0); i < n; ++i)
	{
		assert(test(pos + i));
		btc(pos + i);
	}

	last = pos;
}

uint
ircd::allocator::state::allocate(const size_type &n,
                                 const uint &hint)
{
	const auto ret
	{
		allocate(std::nothrow, n, hint)
	};

	if(unlikely(ret >= size))
		throw std::bad_alloc();

	return ret;
}

uint
ircd::allocator::state::allocate(std::nothrow_t,
                                 const size_type &n,
                                 const uint &hint)
{
	const auto next(this->next(n));
	if(unlikely(next >= size))         // No block of n was found anywhere (next is past-the-end)
		return next;

	for(size_t i(0); i < n; ++i)
	{
		assert(!test(next + i));
		bts(next + i);
	}

	last = next + n;
	return next;
}

uint
ircd::allocator::state::next(const size_t &n)
const
{
	uint ret(last), rem(n);
	for(; ret < size && rem; ++ret)
		if(test(ret))
			rem = n;
		else
			--rem;

	if(likely(!rem))
		return ret - n;

	for(ret = 0, rem = n; ret < last && rem; ++ret)
		if(test(ret))
			rem = n;
		else
			--rem;

	if(unlikely(rem))                  // The allocator should throw std::bad_alloc if !rem
		return size;

	return ret - n;
}

bool
ircd::allocator::state::available(const size_t &n)
const
{
	return this->next(n) < size;
}

//
// allocator::scope
//

decltype(ircd::allocator::scope::current)
ircd::allocator::scope::current;

ircd::allocator::scope::scope(alloc_closure ac,
                              realloc_closure rc,
                              free_closure fc)
:theirs
{
	current
}
,user_alloc
{
	std::move(ac)
}
,user_realloc
{
	std::move(rc)
}
,user_free
{
	std::move(fc)
}
{
	// If an allocator::scope instance already exists somewhere
	// up the stack, *current will already be set. We only install
	// our global hook handlers at the first instance ctor and
	// uninstall it after that first instance dtors.
	if(!current)
		hook_init();

	current = this;
}

ircd::allocator::scope::~scope()
noexcept
{
	assert(current);
	current = theirs;

	// Reinstall the pre-existing hooks after our last scope instance
	// has destructed (the first to have constructed). We know this when
	// current becomes null.
	if(!current)
		hook_fini();
}

void
__attribute__((weak))
ircd::allocator::scope::hook_init()
noexcept
{
}

void
__attribute__((weak))
ircd::allocator::scope::hook_fini()
noexcept
{
}

//
// allocator::profile
//

thread_local ircd::allocator::profile
ircd::allocator::profile::this_thread
{};

ircd::allocator::profile
ircd::allocator::operator-(const profile &a,
                           const profile &b)
{
	profile ret(a);
	ret -= b;
	return ret;
}

ircd::allocator::profile
ircd::allocator::operator+(const profile &a,
                           const profile &b)
{
	profile ret(a);
	ret += b;
	return ret;
}

ircd::allocator::profile &
ircd::allocator::operator-=(profile &a,
                            const profile &b)
{
	a.alloc_count -= b.alloc_count;
	a.free_count -= b.free_count;
	a.alloc_bytes -= b.alloc_bytes;
	a.free_bytes -= b.free_bytes;
	return a;
}

ircd::allocator::profile &
ircd::allocator::operator+=(profile &a,
                            const profile &b)
{
	a.alloc_count += b.alloc_count;
	a.free_count += b.free_count;
	a.alloc_bytes += b.alloc_bytes;
	a.free_bytes += b.free_bytes;
	return a;
}

//
// resource limits
//

#if defined(HAVE_SYS_RESOURCE_H) && defined(RLIMIT_MEMLOCK)
size_t
ircd::allocator::rlimit::memlock(const size_t &req)
try
{
	struct rlimit r {0};
	r.rlim_cur = req;
	syscall(setrlimit, RLIMIT_MEMLOCK, &r);

	char pbuf[48];
	log::info
	{
		"Raised resource limit for locked memory to %s",
		req != -1UL?
			pretty(pbuf, iec(req)):
			"unlimited"_sv,
	};

	return r.rlim_cur;
}
catch(const std::system_error &e)
{
	char pbuf[48];
	log::warning
	{
		"Failed to raise resource limit for locked memory to %s :%s",
		req != -1UL?
			pretty(pbuf, iec(req)):
			"unlimited"_sv,
		e.what(),
	};

	return memlock();
}
#else
size_t
ircd::allocator::rlimit::memlock(const size_t &req)
{
	return 0;
}
#endif

#if defined(HAVE_SYS_RESOURCE_H) && defined(RLIMIT_MEMLOCK)
size_t
ircd::allocator::rlimit::memlock()
{
	struct rlimit r;
	syscall(getrlimit, RLIMIT_MEMLOCK, &r);
	return r.rlim_cur;
}
#else
size_t
ircd::allocator::rlimit::memlock()
{
	return 0;
}
#endif

#if defined(HAVE_SYS_RESOURCE_H) && defined(RLIMIT_STACK)
size_t
ircd::allocator::rlimit::stack()
{
	struct rlimit r;
	syscall(getrlimit, RLIMIT_STACK, &r);
	return r.rlim_cur;
}
#else
size_t
ircd::allocator::rlimit::stack()
{
	return 0;
}
#endif

#if defined(HAVE_SYS_RESOURCE_H) && defined(RLIMIT_DATA)
size_t
ircd::allocator::rlimit::data()
{
	struct rlimit r;
	syscall(getrlimit, RLIMIT_DATA, &r);
	return r.rlim_cur;
}
#else
size_t
ircd::allocator::rlimit::data()
{
	return 0;
}
#endif

#if defined(HAVE_SYS_RESOURCE_H) && defined(RLIMIT_AS)
size_t
ircd::allocator::rlimit::virt()
{
	struct rlimit r;
	syscall(getrlimit, RLIMIT_AS, &r);
	return r.rlim_cur;
}
#else
size_t
ircd::allocator::rlimit::virt()
{
	return 0;
}
#endif

//
// Developer profiling
//

#ifdef RB_PROF_ALLOC // --------------------------------------------------

void *
__attribute__((alloc_size(1), malloc, returns_nonnull))
operator new(const size_t size)
{
	void *const &ptr(::malloc(size));
	if(unlikely(!ptr))
		throw std::bad_alloc();

	auto &this_thread(ircd::allocator::profile::this_thread);
	this_thread.alloc_bytes += size;
	this_thread.alloc_count++;

	return ptr;
}

void
operator delete(void *const ptr)
noexcept
{
	::free(ptr);

	auto &this_thread(ircd::allocator::profile::this_thread);
	this_thread.free_count++;
}

void
operator delete(void *const ptr,
                const size_t size)
noexcept
{
	::free(ptr);

	auto &this_thread(ircd::allocator::profile::this_thread);
	this_thread.free_bytes += size;
	this_thread.free_count++;
}

#endif // RB_PROF_ALLOC --------------------------------------------------

//
// Linker symbol wrapping hook
//

extern "C" [[gnu::weak]] void *__real_malloc(size_t size);
extern "C" [[gnu::weak]] void *__real_calloc(size_t nmemb, size_t size);
extern "C" [[gnu::weak]] void *__real_realloc(void *ptr, size_t size);
extern "C" [[gnu::weak]] void __real_free(void *ptr);

extern "C" void *
__wrap_malloc(size_t size)
{
	void *const &ptr(::__real_malloc(size));
	if(unlikely(!ptr))
		throw std::bad_alloc();

	auto &this_thread(ircd::allocator::profile::this_thread);
	this_thread.alloc_bytes += size;
	this_thread.alloc_count++;
	return ptr;
}

extern "C" void *
__wrap_calloc(size_t nmemb, size_t size)
{
	void *const &ptr(::__real_calloc(nmemb, size));
	if(unlikely(!ptr))
		throw std::bad_alloc();

	auto &this_thread(ircd::allocator::profile::this_thread);
	this_thread.alloc_bytes += nmemb * size;
	this_thread.alloc_count++;
	return __real_calloc(nmemb, size);
}

extern "C" void *
__wrap_realloc(void *ptr, size_t size)
{
	void *const &ret(::__real_realloc(ptr, size));
	if(unlikely(!ret))
		throw std::bad_alloc();

	auto &this_thread(ircd::allocator::profile::this_thread);
	this_thread.alloc_bytes += size;
	this_thread.alloc_count++;
	return ret;
}

extern "C" void
__wrap_free(void *ptr)
{
	__real_free(ptr);

	auto &this_thread(ircd::allocator::profile::this_thread);
	this_thread.free_bytes += 0UL; //TODO: XXX
	this_thread.free_count++;
}
