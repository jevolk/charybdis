// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2023 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#include <RB_INC_LINUX_ERRQUEUE_H
#include <RB_INC_LINUX_NET_TSTAMP_H

#ifndef IRCD_NET_ERRQ_DEBUG
	#define IRCD_NET_ERRQ_DEBUG 0
#endif

namespace ircd::net::errq
{
	struct msg;

	template<class F>
	static bool for_each(int, msghdr *, F&&);

	static void handle_ip_ee_txstatus(const msg &, const sock_extended_err *);
	static void handle_ip_ee(const msg &);
	static void handle_ip(const msg &);
	static void handle_so_ts(const msg &);
	static void handle_so(const msg &);
	static void handle(int, msghdr *) noexcept;

	static thread_local char cmsgbuf[1024];
}

struct ircd::net::errq::msg
{
	int fd {-1};
	const msghdr *msg {nullptr};
	const cmsghdr *cmsg {nullptr};
	const_buffer content;
};

decltype(ircd::net::errq::log)
ircd::net::errq::log
{
	"net.errq"
};

bool
ircd::net::sock_opts::enable_tstamp()
noexcept
{
	tstamp = 0;
	tstamp |= SOF_TIMESTAMPING_SOFTWARE;
	tstamp |= SOF_TIMESTAMPING_OPT_CMSG;
	tstamp |= SOF_TIMESTAMPING_OPT_ID;

	tstamp |= SOF_TIMESTAMPING_TX_SOFTWARE;
	//tstamp |= SOF_TIMESTAMPING_TX_SCHED;
	tstamp |= SOF_TIMESTAMPING_TX_ACK;
	//tstamp |= SOF_TIMESTAMPING_RX_SOFTWARE;

	return true;
}

extern "C" ssize_t
__real_recvmsg(int fd,
               struct msghdr *const msg,
               int flags);

extern "C" ssize_t
__wrap_recvmsg(int fd,
               struct msghdr *const msg,
               int flags)
{
	flags |= MSG_ERRQUEUE;
	msg->msg_control = ircd::net::errq::cmsgbuf;
	msg->msg_controllen = sizeof(ircd::net::errq::cmsgbuf);

	const auto ret
	{
		__real_recvmsg(fd, msg, flags)
	};

	ircd::net::errq::handle(fd, msg);
	return ret;
}

void
ircd::net::errq::handle(const int fd,
                        msghdr *const msg)
noexcept
{
	assert(~msg->msg_flags & MSG_CTRUNC);
	if constexpr(IRCD_NET_ERRQ_DEBUG)
		for_each(fd, msg, [](const auto &msg)
		{
			thread_local char hexbuf[sizeof(cmsgbuf)];
			log::logf
			{
				log, log::level::DEBUG,
				"fd:%d control message level:%08x type:%08x len:%zu :%s",
				msg.fd,
				msg.cmsg->cmsg_level,
				msg.cmsg->cmsg_type,
				msg.cmsg->cmsg_len,
				ircd::u2a(hexbuf, msg.content),
			};

			return true;
		});


	for_each(fd, msg, [](const auto &msg)
	{
		switch(msg.cmsg->cmsg_level)
		{
			case IPPROTO_IP:
				handle_ip(msg);
				break;

			case SOL_SOCKET:
				handle_so(msg);
				break;
		}

		return true;
	});
}

void
ircd::net::errq::handle_so(const msg &msg)
{
	assert(msg.cmsg->cmsg_level == SOL_SOCKET);
	switch(msg.cmsg->cmsg_type)
	{
		case SO_TIMESTAMPING:
			return handle_so_ts(msg);
	}
}

void
ircd::net::errq::handle_so_ts(const msg &msg)
{
	struct body
	{
		timespec tv;
	}
	const *const body
	{
		msg.content
	};

	if constexpr(IRCD_NET_ERRQ_DEBUG)
		log::logf
		{
			log, log::level::DEBUG,
			"fd:%d SOL_SOCKET:SO_TIMESTAMPING %ld.%09lu",
			msg.fd,
			body->tv.tv_sec,
			body->tv.tv_nsec,
		};
}

void
ircd::net::errq::handle_ip(const msg &msg)
{
	assert(msg.cmsg->cmsg_level == IPPROTO_IP);
	switch(msg.cmsg->cmsg_type)
	{
		case IP_RECVERR:
			return handle_ip_ee(msg);
	}
}

void
ircd::net::errq::handle_ip_ee(const msg &msg)
{
	const sock_extended_err *const ee
	{
		msg.content
	};

	if constexpr(IRCD_NET_ERRQ_DEBUG)
		log::logf
		{
			log, log::level::DEBUG,
			"fd:%d IPPROTO_IP:IP_RECVERR errno:%u origin:%u type:%u code:%u info:%u data:%u",
			msg.fd,
			ee->ee_errno,
			ee->ee_origin,
			ee->ee_type,
			ee->ee_code,
			ee->ee_info,
			ee->ee_data,
		};

	switch(ee->ee_origin)
	{
		case SO_EE_ORIGIN_TXSTATUS:
			return handle_ip_ee_txstatus(msg, ee);
	}
}

void
ircd::net::errq::handle_ip_ee_txstatus(const msg &msg,
                                       const sock_extended_err *const ee)
{
	assert(ee->ee_origin == SO_EE_ORIGIN_TXSTATUS);

}

template<class F>
bool
ircd::net::errq::for_each(const int fd,
                          msghdr *const msg,
                          F&& closure)
{
	for(auto *cmsg(CMSG_FIRSTHDR(msg)); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
	{
		const const_buffer content
		{
			reinterpret_cast<const char *>(CMSG_DATA(cmsg)), cmsg->cmsg_len
		};

		const errq::msg _msg
		{
			.fd = fd,
			.msg = msg,
			.cmsg = cmsg,
			.content = content,
		};

		if(!closure(_msg))
			return false;
	}

	return true;
}
