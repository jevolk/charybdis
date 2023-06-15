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
#define HAVE_IRCD_SERVER_LINK_H

/// A single connection to a remote peer.
///
struct ircd::server::link
{
	using const_buffers = net::const_buffers;

	static net::sock_opts sock_opts;
	static conf::item<ssize_t> only_ipv6;
	static conf::item<ssize_t> sock_nodelay;
	static conf::item<ssize_t> sock_read_bufsz;
	static conf::item<ssize_t> sock_read_lowat;
	static conf::item<ssize_t> sock_write_bufsz;
	static conf::item<ssize_t> sock_write_lowat;
	static conf::item<size_t> tag_max_default;
	static conf::item<size_t> tag_commit_max_default;
	static conf::item<bool> write_async;
	static uint64_t ticker[];
	static stats::item<uint64_t *> ops_write_wait;
	static stats::item<uint64_t *> ops_write_now;
	static stats::item<uint64_t *> ops_write_nbio;
	static stats::item<uint64_t *> ops_write_async;
	static stats::item<uint64_t *> ops_write_more;
	static stats::item<uint64_t *> ops_read_wait;
	static stats::item<uint64_t *> ops_read_nbio;
	static stats::item<uint64_t *> ops_read_discard;
	static uint64_t ids;

	uint64_t id {++ids};                         ///< unique identifier of link.
	server::peer *peer;                          ///< backreference to peer
	std::shared_ptr<net::socket> socket;         ///< link's socket
	std::list<tag> queue;                        ///< link's work queue
	size_t tag_done {0L};                        ///< total tags processed
	time_t synack_ts {0L};                       ///< time socket was estab
	time_t read_ts {0L};                         ///< time of last read
	time_t write_ts {0L};                        ///< time of last write
	bool op_init {false};                        ///< link is connecting
	bool op_fini {false};                        ///< link is disconnecting
	bool op_open {false};
	bool op_write {false};                       ///< async operation state
	bool op_read {false};                        ///< async operation state
	bool exclude {false};                        ///< link is excluded

	template<class F> size_t accumulate_tags(F&&) const;

	void discard_read();
	const_buffer read(const mutable_buffer &buf);
	const_buffer process_read_next(const const_buffer &, tag &, bool &done);
	bool process_read(const_buffer &, unique_buffer<mutable_buffer> &);
	void handle_readable_success();
	void handle_readable(const error_code &) noexcept;
	void wait_readable();

	void handle_write_async(tag &, uint64_t, const std::error_code &, size_t);
	bool process_write_async(tag &, const const_buffers &);
	bool process_write_nbio(tag &, const const_buffers &);
	void handle_writable_success();
	void handle_writable(const error_code &) noexcept;
	void wait_writable();

	void handle_close(std::exception_ptr);
	void handle_open(std::exception_ptr);
	void cleanup_canceled();

  public:
	// config related
	size_t tag_max() const;
	size_t tag_commit_max() const;

	// indicator lights
	bool finished() const;
	bool opened() const;
	bool ready() const;
	bool busy() const;

	// stats for upload-side bytes across all tags
	size_t write_size() const;
	size_t write_completed() const;
	size_t write_remaining() const;

	// stats for download-side bytes ~across all tags~; note: this is not
	// accurate except for the one tag at the front of the queue having
	// its response processed.
	size_t read_size() const;          // see: tag::read_total() notes
	size_t read_completed() const;     // see: tag::read_completed() notes
	size_t read_remaining() const;     // see: tag::read_remaining() notes

	// stats accumulated
	size_t write_total() const;
	size_t read_total() const;

	// stats for tags
	size_t tag_count() const;
	size_t tag_committed() const;
	size_t tag_uncommitted() const;

	// request panel
	void cancel_uncommitted(std::exception_ptr);
	void cancel_committed(std::exception_ptr);
	void cancel_all(std::exception_ptr);
	void submit(request &);

	// control panel
	bool close(const net::close_opts &);
	bool close(const net::dc = net::dc::SSL_NOTIFY);
	bool open(const net::open_opts &);

	link(server::peer &);
	link(link &&) = delete;
	link(const link &) = delete;
	~link() noexcept;
};

inline bool
ircd::server::link::close(const net::dc type)
{
	return close(net::close_opts
	{
		.type = type,
	});
}

inline size_t
ircd::server::link::tag_count()
const
{
	return queue.size();
}

inline size_t
ircd::server::link::read_total()
const
{
	return socket? net::bytes(*socket).first: 0;
}

inline size_t
ircd::server::link::write_total()
const
{
	return socket? net::bytes(*socket).second: 0;
}

inline bool
ircd::server::link::busy()
const
{
	return !queue.empty();
}

inline bool
ircd::server::link::ready()
const
{
	return opened() && !op_init && !op_fini;
}

inline bool
ircd::server::link::opened()
const
{
	return bool(socket) && net::opened(*socket);
}

inline size_t
ircd::server::link::tag_commit_max()
const
{
	return tag_commit_max_default;
}

inline size_t
ircd::server::link::tag_max()
const
{
	return tag_max_default;
}
