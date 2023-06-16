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
#define HAVE_IRCD_FS_FD_H

namespace ircd::fs
{
	struct fd;

	size_t size(const fd &);
	size_t block_size(const fd &);
	ulong fstype(const fd &);
	ulong device(const fd &);
	uint64_t write_life(const fd &) noexcept;
	void write_life(const fd &, const uint64_t);
	size_t advise(const fd &, const int, const size_t = 0, const opts & = opts_default);
	size_t evict(const fd &, const size_t size = 0, const opts & = opts_default);
}

/// File Desc++ptor. This is simply a native fd (i.e. integer) with c++ object
/// semantics.
struct ircd::fs::fd
{
	struct opts;

	int fdno {-1};

  public:
	operator const int &() const;
	operator bool() const;
	bool operator!() const;
	opts options() const;

	int release() noexcept;

	explicit fd(const int);
	fd(const int dirfd, const string_view &path, const opts &);
	fd(const string_view &path, const opts &);
	fd(const string_view &path);
	fd() = default;
	fd(fd &&) noexcept;
	fd(const fd &) = delete;
	fd &operator=(fd &&) noexcept;
	fd &operator=(const fd &) = delete;
	~fd() noexcept;
};

/// Descriptor options (open options)
struct ircd::fs::fd::opts
:fs::opts
{
	static conf::item<bool> direct_io_enable;

	/// std openmode passed from ctor.
	std::ios::openmode mode {std::ios::openmode(0)};

	/// open(2) flags. Usually generated from ios::open_mode ctor.
	ulong flags {0};

	/// open(2) mode_t mode used for file creation.
	ulong mask {0};

	/// Seek to end after open. This exists to convey the flag for open_mode.
	bool ate {false};

	/// (O_DIRECT) Direct IO bypassing the operating system caches.
	bool direct {false};

	/// (O_CLOEXEC) Close this descriptor on an exec().
	bool cloexec {true};

	/// Allows file to be created if it doesn't exist. Set this to false to
	/// prevent file from being created when opened with a write-mode.
	bool create {true};

	/// Allows file to opened if and only if it doesn't exist and will be
	/// created by this open().
	bool exclusive {false};

	/// Advise for random access (ignored when direct=true)
	bool random {false};

	/// Advise for sequential access (ignored when direct=true)
	bool sequential {false};

	/// Advise for dontneed access (ignored when direct=true)
	bool dontneed {false};
};

inline
ircd::fs::fd::fd(const int fdno)
:fdno{fdno}
{}

inline
ircd::fs::fd::fd(fd &&o)
noexcept
:fdno{std::move(o.fdno)}
{
	o.fdno = -1;
}

inline ircd::fs::fd &
ircd::fs::fd::operator=(fd &&o)
noexcept
{
	this->~fd();
	fdno = std::move(o.fdno);
	o.fdno = -1;
	return *this;
}

inline int
ircd::fs::fd::release()
noexcept
{
	return std::exchange(fdno, -1);
}

inline bool
ircd::fs::fd::operator!()
const
{
	return !bool(*this);
}

inline ircd::fs::fd::operator
bool()
const
{
	return int(*this) >= 0;
}

inline ircd::fs::fd::operator
const int &()
const
{
	return fdno;
}
