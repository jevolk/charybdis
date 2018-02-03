// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#pragma once
#define HAVE_IRCD_RFC1035_H

/// RFC 1035 (Nov. 1987)
///
namespace ircd::rfc1035
{
	IRCD_EXCEPTION(ircd::error, error)

	struct header;
	struct question;
	struct answer;
	struct record;
	enum class op :uint8_t;
	extern const std::array<string_view, 25> rcode;
	extern const std::unordered_map<string_view, uint16_t> qtype;

	const_buffer make_name(const mutable_buffer &out, const string_view &fqdn);
	size_t parse_name(const mutable_buffer &out, const const_buffer &in);

	mutable_buffer make_query(const mutable_buffer &, const header &, const vector_view<const question> &);
	mutable_buffer make_query(const mutable_buffer &, const uint16_t &id, const vector_view<const question> &);
	mutable_buffer make_query(const mutable_buffer &, const uint16_t &id, const question &);
}

/// Helper class to construct or parse a question. An object is constructed
/// with a fully qualified domain string and the query type (qtype). At the
/// appropriate time we will call print() which prints a properly binary-
/// formatted question for the question section in a DNS query; generally the
/// user does not need to do this.
///
/// Note that each part of the fqdn cannot be longer than 63 characters. The
/// supplied buffer must be large enough to hold the output, which is about
/// the length of the fqdn + 6 bytes. The qtype can be specified as a string
/// i.e "A" or "PTR" and it will be translated into the protocol number for
/// you in the constructor.
///
struct ircd::rfc1035::question
{
	uint16_t qtype;
	uint16_t qclass {0x01};
	size_t namelen {0};
	char name[256];

	/// Composes the question into buffer, returns used portion
	mutable_buffer print(const mutable_buffer &) const;
	const_buffer parse(const const_buffer &);

	/// Supply fully qualified domain name and numerical query type
	question(const string_view &fqdn, const uint16_t &qtype);

	/// Supply fully qualified domain name and name of query type i.e "A"
	question(const string_view &fqdn, const string_view &qtype)
	:question{fqdn, rfc1035::qtype.at(qtype)}
	{}

	question() = default;
};

/// Helper class to parse an answer.
///
struct ircd::rfc1035::answer
{
	uint16_t qtype;
	uint16_t qclass;
	uint32_t ttl;
	uint16_t rdlength;
	const_buffer rdata;
	string_view name;
	char namebuf[256];

	const_buffer parse(const const_buffer &);

	answer() = default;
};

/// Direct representation of the DNS header. This is laid out for
/// little-endian platforms only. The uint16_t's are still big-endian and
/// must be bswap()'ed.
///
struct ircd::rfc1035::header
{
	uint16_t id;         ///< query identification number
	uint8_t rd:1;        ///< 0 = recursion not desired; 1 = desired
	uint8_t tc:1;        ///< 0 = not-truncated; 1 = 512 bytes of reply only
	uint8_t aa:1;        ///< 0 = non-authoritative; 1 = authoritative
	uint8_t opcode:4;    ///< purpose of message
	uint8_t qr:1;        ///< 0 = query; 1 = respnse
	uint8_t rcode:4;     ///< response code
	uint8_t cd:1;        ///< checking disabled by resolver
	uint8_t ad:1;        ///< authentic data from named
	uint8_t unused:1;    ///< unused bits (MBZ as of 4.9.3a3)
	uint8_t ra:1;        ///< 1 = recursion available
	uint16_t qdcount;    ///< number of question entries
	uint16_t ancount;    ///< number of answer entries
	uint16_t nscount;    ///< number of authority entries
	uint16_t arcount;    ///< number of resource entries

	std::string debug() const;
}
__attribute__((packed));

static_assert
(
	sizeof(ircd::rfc1035::header) == 12,
	"The RFC1035 header is not the right size in this environment"
);

enum class ircd::rfc1035::op
:uint8_t
{
	QUERY    = 0,   ///< Query [RFC 1035]
	IQUERY   = 1,   ///< Inverse Query [RFC 1035, RFC 3425]
	STATUS   = 2,   ///< Server status request [RFC 1035]
	NOTIFY   = 4,   ///< Notify [RFC 1996]
	UPDATE   = 5,   ///< Update [RFC 2136]
};

struct ircd::rfc1035::record
{
	struct A;
	struct AAAA;
	struct CNAME;
	struct SRV;
};

struct ircd::rfc1035::record::A
{
	uint32_t ip4;

	A(const const_buffer &rdata);
};

struct ircd::rfc1035::record::AAAA
{
	uint128_t ip6;

	AAAA(const const_buffer &rdata);
};

struct ircd::rfc1035::record::CNAME
{
	string_view name;
	char namebuf[256];

	CNAME(const const_buffer &rdata);
};

struct ircd::rfc1035::record::SRV
{
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	string_view tgt;
	char tgtbuf[256];

	SRV(const const_buffer &rdata);
};
