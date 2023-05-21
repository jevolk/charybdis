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
#define HAVE_IRCD_NET_WRITE_H

namespace ircd::net
{
	using const_buffers = vector_view<const const_buffer>;
	using write_handler = std::function<void (const std::error_code &, size_t)>;

	// Observers
	size_t flushing(const socket &);
	size_t writable(const socket &);

	// Non-blocking; writes at most one system-determined amount of
	// bytes or less with at most a single syscall.
	size_t write_one(socket &, const const_buffers &);
	size_t write_one(socket &, const const_buffer &);

	// Non-blocking; writes as much as possible until the socket buffer
	// is full. This composes multiple write_one()'s.
	size_t write_any(socket &, const const_buffers &);
	size_t write_any(socket &, const const_buffer &);

	// Yields your ircd::ctx until at least some bytes have been written;
	// advise one uses a timeout when calling.
	size_t write_few(socket &, const const_buffers &);
	size_t write_few(socket &, const const_buffer &);

	// Yields your ircd::ctx until all bytes have been written;
	// advise one uses a timeout in conjunction to prevent DoS.
	size_t write_all(socket &, const const_buffers &);
	size_t write_all(socket &, const const_buffer &);

	// Alias to write_all();
	size_t write(socket &, const const_buffers &);
	size_t write(socket &, const const_buffer &);

	// Callback-based interface.
	void write_few(socket &, const const_buffers &, write_handler &&);
	void write_few(socket &, const const_buffer &, write_handler &&);
	void write_all(socket &, const const_buffers &, write_handler &&);
	void write_all(socket &, const const_buffer &, write_handler &&);
	void write(socket &, const const_buffers &, write_handler &&);
	void write(socket &, const const_buffer &, write_handler &&);

	// Toggles nodelay to force a transmission.
	void flush(socket &);
}

/// Alias to write_all();
inline void
ircd::net::write(socket &socket,
                 const const_buffer &buffer,
                 write_handler &&callback)
{
	write_all(socket, buffer, std::move(callback));
}

/// Alias to write_all();
inline void
ircd::net::write(socket &socket,
                 const const_buffers &buffers,
                 write_handler &&callback)
{
	write_all(socket, buffers, std::move(callback));
}

inline void
ircd::net::write_all(socket &socket,
                     const const_buffer &buffer,
                     write_handler &&callback)
{
	const const_buffer buffers[]
	{
		buffer
	};

	write_all(socket, buffers, std::move(callback));
}

inline void
ircd::net::write_few(socket &socket,
                     const const_buffer &buffer,
                     write_handler &&callback)
{
	const const_buffer buffers[]
	{
		buffer
	};

	write_few(socket, buffers, std::move(callback));
}

/// Alias to write_all();
inline size_t
ircd::net::write(socket &socket,
                 const const_buffer &buffer)
{
	return write_all(socket, buffer);
}

/// Alias to write_all();
inline size_t
ircd::net::write(socket &socket,
                 const const_buffers &buffers)
{
	return write_all(socket, buffers);
}

inline size_t
ircd::net::write_all(socket &socket,
                     const const_buffer &buffer)
{
	const const_buffer buffers[]
	{
		buffer
	};

	return write_all(socket, buffers);
}

inline size_t
ircd::net::write_few(socket &socket,
                     const const_buffer &buffer)
{
	const const_buffer buffers[]
	{
		buffer
	};

	return write_few(socket, buffers);
}

inline size_t
ircd::net::write_any(socket &socket,
                     const const_buffer &buffer)
{
	const const_buffer buffers[]
	{
		buffer
	};

	return write_any(socket, buffers);
}

inline size_t
ircd::net::write_one(socket &socket,
                     const const_buffer &buffer)
{
	const const_buffer buffers[]
	{
		buffer
	};

	return write_one(socket, buffers);
}
