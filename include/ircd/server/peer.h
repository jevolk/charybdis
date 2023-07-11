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
#define HAVE_IRCD_SERVER_PEER_H

/// Remote entity.
///
struct ircd::server::peer
{
	struct err;

	static const size_t MAX_LINK;
	static ios::descriptor close_desc;
	static conf::item<size_t> link_min_default;
	static conf::item<size_t> link_max_default;
	static conf::item<seconds> error_clear_default;
	static conf::item<seconds> remote_ttl_min;
	static conf::item<seconds> remote_ttl_max;
	static conf::item<bool> enable_ipv6;
	static uint64_t ids;

	uint64_t id {++ids};
	peers_node_type node;
	std::string hostcanon;        // hostname:service[:port]
	net::ipport remote;
	system_point remote_expires;
	net::sock_opts sock_opts;
	net::open_opts open_opts;
	std::list<link> links;
	std::unique_ptr<err> e;
	std::string server_version;
	size_t write_bytes {0};
	size_t read_bytes {0};
	size_t tag_done {0};
	bool op_resolve {false};
	bool op_fini {false};

	template<class F> size_t accumulate_links(F&&) const;
	template<class F> size_t accumulate_tags(F&&) const;

	void del();
	void handle_finished();
	void open_links();
	void handle_resolve_A(const hostport &, const json::array &);
	void handle_resolve_AAAA(const hostport &, const json::array &);
	void handle_resolve_SRV(const hostport &, const json::array &);
	void resolve(const hostport &, const net::dns::opts &);
	void resolve();

	void cleanup_canceled();
	void disperse_uncommitted(link &);
	void disperse(link &);
	void del(link &);

	void handle_head_recv(const link &, const tag &, const http::response::head &);
	void handle_link_done(link &);
	void handle_tag_done(link &, tag &) noexcept;
	void handle_finished(link &);
	void handle_error(link &, const std::system_error &);
	void handle_error(link &, std::exception_ptr);
	void handle_close_error(link &, std::exception_ptr);
	void handle_close(link &, std::exception_ptr);
	void handle_open_error(link &, std::exception_ptr);
	void handle_open(link &, std::exception_ptr);

  public:
	// indicator lights
	bool finished() const;
	bool expired() const;

	// config related
	size_t link_min() const;
	size_t link_max() const;

	// stats for all links in peer
	size_t link_count() const;
	size_t link_busy() const;
	size_t link_ready() const;
	size_t link_tag_done() const;

	// stats for all tags in all links in peer
	size_t tag_count() const;
	size_t tag_committed() const;
	size_t tag_uncommitted() const;

	// stats for all upload-side bytes in all tags in all links
	size_t write_size() const;
	size_t write_completed() const;
	size_t write_remaining() const;

	// stats for download-side bytes in all tags in all links (note:
	// see notes in link.h/tag.h about inaccuracy here).
	size_t read_size() const;
	size_t read_completed() const;
	size_t read_remaining() const;

	// stats accumulated over time
	size_t write_total() const;
	size_t read_total() const;

	// link control panel
	link &link_add(const bool open = true);
	link *link_get(const request &);

	// request panel
	void submit(request &);

	// Error related
	bool err_has() const;
	string_view err_msg() const;
	template<class... A> void err_set(A&&...);
	bool err_clear();
	bool err_check();

	// control panel
	void cancel();
	void close(const net::close_opts & = net::close_opts_default);

	peer(const net::hostport &hostport,
	     const net::open_opts &open_opts = {});
	peer(peer &&) = delete;
	peer(const peer &) = delete;
	~peer() noexcept;
};

struct ircd::server::peer::err
{
	std::exception_ptr eptr;
	system_point etime;

	err(std::exception_ptr);
	~err() noexcept;
};

inline ircd::string_view
ircd::server::peer::err_msg()
const
{
	return bool(e)?
		what(e->eptr):
		string_view{};
}

inline bool
ircd::server::peer::err_has()
const
{
	return bool(e);
}

inline size_t
ircd::server::peer::read_total()
const
{
	return read_bytes;
}

inline size_t
ircd::server::peer::write_total()
const
{
	return write_bytes;
}

inline size_t
ircd::server::peer::link_count()
const
{
	return links.size();
}

inline size_t
ircd::server::peer::link_min()
const
{
	return link_min_default;
}

inline size_t
ircd::server::peer::link_max()
const
{
	return link_max_default;
}

inline bool
ircd::server::peer::expired()
const
{
	return remote_expires < ircd::now<system_point>();
}

inline bool
ircd::server::peer::finished()
const
{
	return links.empty() && !op_resolve && op_fini;
}
