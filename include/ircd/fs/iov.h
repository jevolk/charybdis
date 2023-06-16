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
#define HAVE_IRCD_FS_IOV_H

extern "C"
{
	struct iovec;
};

namespace ircd::fs
{
	using const_iovec_view = vector_view<const struct ::iovec>;
	using iovec_view = vector_view<struct ::iovec>;
	using const_buffers = vector_view<const const_buffer>;
	using mutable_buffers = vector_view<const mutable_buffer>;

	// utility; count the total bytes of an iov.
	size_t bytes(const const_iovec_view &);

	// Transforms our buffers to struct iovec ones. The offset value allows
	// a front-truncation of the input buffers when transforming. This is
	// useful for progressive readv()'s filling the buffers.
	const_iovec_view make_iov(const iovec_view &, const const_buffers &, const size_t off = 0);
	const_iovec_view make_iov(const iovec_view &, const mutable_buffers &, const size_t off = 0);

	// For boost::asio; internal
	template<class T> vector_view<const T> make_iov(T *, const const_iovec_view &);
}
