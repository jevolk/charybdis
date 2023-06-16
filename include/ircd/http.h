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
#define HAVE_IRCD_HTTP_H

/// HyperText TransPort: formal grammars & tools
namespace ircd::http
{
	struct error;
	struct line;
	struct query;
	struct header;
	struct headers;
	struct request;
	struct response;

	enum code :ushort;
	enum code status(const string_view &);
	[[gnu::pure]] string_view status(const enum code) noexcept;

	enum class category :uint8_t;
	[[gnu::pure]] string_view category(const enum category) noexcept;
	[[gnu::pure]] enum category category(const enum code) noexcept;
	[[gnu::pure]] enum category category(const string_view &) noexcept;
	[[gnu::pure]] enum log::level severity(const enum category) noexcept;

	void writeline(window_buffer &);
	void writeline(window_buffer &, const window_buffer::closure &);
	void write(window_buffer &, const header &);
	void write(window_buffer &, const vector_view<const header> &);
	size_t serialized(const vector_view<const header> &);
	std::string strung(const vector_view<const header> &);
	void writechunk(window_buffer &, const uint32_t &size);
	const_buffer writechunk(const mutable_buffer &, const uint32_t &size);
	bool has(const headers &, const string_view &key);
	bool has(const vector_view<const header> &, const string_view &key);
}

/// HTTP Status classifications.
enum class ircd::http::category
:uint8_t
{
	NONE          = 0,   ///< Sentinel
	INFO          = 1,   ///< Informational  (100-199)
	SUCCESS       = 2,   ///< Successful     (200-299)
	REDIRECT      = 3,   ///< Redirectional  (300-399)
	ERROR         = 4,   ///< Client Error   (400-499)
	SERVER        = 5,   ///< Server Error   (501-599)
	INTERNAL      = 6,   ///< Internal Error (500 only)
	UNKNOWN       = 7,   ///< Pair with default case in switch/tables
};

/// HTTP Status codes.
enum ircd::http::code
:ushort
{
	CONTINUE                                = 100,
	SWITCHING_PROTOCOLS                     = 101,
	PROCESSING                              = 102,
	EARLY_HINTS                             = 103,

	OK                                      = 200,
	CREATED                                 = 201,
	ACCEPTED                                = 202,
	NON_AUTHORITATIVE_INFORMATION           = 203,
	NO_CONTENT                              = 204,
	PARTIAL_CONTENT                         = 206,

	MULTIPLE_CHOICES                        = 300,
	MOVED_PERMANENTLY                       = 301,
	FOUND                                   = 302,
	SEE_OTHER                               = 303,
	NOT_MODIFIED                            = 304,
	USE_PROXY                               = 305,
	SWITCH_PROXY                            = 306,
	TEMPORARY_REDIRECT                      = 307,
	PERMANENT_REDIRECT                      = 308,

	BAD_REQUEST                             = 400,
	UNAUTHORIZED                            = 401,
	FORBIDDEN                               = 403,
	NOT_FOUND                               = 404,
	METHOD_NOT_ALLOWED                      = 405,
	NOT_ACCEPTABLE                          = 406,
	REQUEST_TIMEOUT                         = 408,
	CONFLICT                                = 409,
	GONE                                    = 410,
	LENGTH_REQUIRED                         = 411,
	PAYLOAD_TOO_LARGE                       = 413,
	REQUEST_URI_TOO_LONG                    = 414,
	UNSUPPORTED_MEDIA_TYPE                  = 415,
	RANGE_NOT_SATISFIABLE                   = 416,
	EXPECTATION_FAILED                      = 417,
	IM_A_TEAPOT                             = 418,
	UNPROCESSABLE_ENTITY                    = 422,
	PRECONDITION_REQUIRED                   = 428,
	TOO_MANY_REQUESTS                       = 429,
	REQUEST_HEADER_FIELDS_TOO_LARGE         = 431,

	INTERNAL_SERVER_ERROR                   = 500,
	NOT_IMPLEMENTED                         = 501,
	BAD_GATEWAY                             = 502,
	SERVICE_UNAVAILABLE                     = 503,
	GATEWAY_TIMEOUT                         = 504,
	HTTP_VERSION_NOT_SUPPORTED              = 505,
	INSUFFICIENT_STORAGE                    = 507,

	CLOUDFLARE_REFUSED                      = 521,
	CLOUDFLARE_TIMEDOUT                     = 522,
	CLOUDFLARE_UNREACHABLE                  = 523,
	CLOUDFLARE_REQUEST_TIMEOUT              = 524,
};

/// Root exception for HTTP.
struct ircd::http::error
:ircd::error
{
	std::string content;
	std::string headers;
	enum code code {http::code(0)};

	explicit operator bool() const     { return code != http::code(0);         }
	bool operator!() const             { return !bool(*this);                  }

	error() = default;
	error(const enum code &, std::string content = {}, std::string headers = {});
	error(const enum code &, std::string content, const vector_view<const header> &);
	template<class... args> error(const string_view &fmt, const enum code &, args&&...);
	~error() noexcept override;
};

/// Represents a single \\r\\n delimited line used in HTTP.
///
/// This object is just a string_view of that line. The actual data backing
/// that view is the responsibility of the user. This object is constructed
/// with an ircd::parse::capstan argument which is used by the formal grammar
/// in the constructor.
///
struct ircd::http::line
:string_view
{
	struct request;
	struct response;

	static const string_view terminator; // "\r\n"

	using string_view::string_view;
	line(parse::capstan &);
};

/// Represents a 'request line' or the first line a client sends to a server.
///
/// This is a dual-use class. For HTTP clients, one may simply connect the
/// members to the proper strings and then pass this structure to a function
/// making a client request. For HTTP servers, pass an http::line to the ctor
/// and the formal grammar will set the members appropriately. The actual data
/// behind these members is the responsibility of the user.
///
struct ircd::http::line::request
{
	string_view method;
	string_view path;
	string_view query;
	string_view fragment;
	string_view version;

	operator string_view() const;      // full view of line

	request(const line &);
	request() = default;
};

/// Represents a 'response line' or the first line a server sends to a client.
///
/// This is a dual-use class and symmetric to the http::line::request class.
/// Servers may set the members and then use this object to respond to a client
/// while clients should provide an http::line to the constructor which will
/// fill in the members.
///
struct ircd::http::line::response
{
	string_view version;
	string_view status;
	string_view reason;

	response(const line &);
	response() = default;
};

/// Represents a single key/value pair in a query string.
///
/// This is used by the ircd::http::query::string object when parsing query
/// strings.
///
struct ircd::http::query
:std::pair<string_view, string_view>
{
	struct string;

	bool operator<(const string_view &s) const   { return iless(first, s);                         }
	bool operator==(const string_view &s) const  { return iequals(first, s);                       }

	using std::pair<string_view, string_view>::pair;
	query() = default;
};

/// Tool for parsing an HTTP query string.
///
/// Query string is read as a complete string off the tape (into request.query)
/// and not parsed further. To make queries into that string use this class to
/// view it. Once this object is constructed by viewing the whole query string,
/// the member functions invoke the formal grammar to get individual key/value
/// pairs.
///
struct ircd::http::query::string
:string_view
{
	using closure = util::function_bool<const query &>;

	bool for_each(const closure &) const;
	bool for_each(const string_view &key, const closure &) const;

	string_view _get(const string_view &key, size_t idx = 0) const;
	template<class T = string_view> T get(const string_view &key, const T &def = {}, const size_t &idx = 0) const;
	string_view operator[](const string_view &key) const;

	string_view at(const string_view &key, const size_t idx = 0) const;
	template<class T> T at(const string_view &key, const size_t &idx = 0) const;

	vector_view<string_view> array(const mutable_buffer &, const string_view &key, string_view *const &, size_t) const;
	template<size_t MAX> vector_view<string_view> array(const mutable_buffer &, const string_view &key, string_view (&)[MAX]) const;

	size_t count(const string_view &key) const;
	bool has(const string_view &key) const;

	using string_view::string_view;
};

/// Represents an HTTP header key/value pair.
///
/// This is a dual-use class. Those sending headers will simply fill in the
/// components of the std::pair. Those receiving headers can pass the ctor an
/// ircd::http::line which will construct the pair using the formal grammars.
///
struct ircd::http::header
:std::pair<string_view, string_view>
{
	bool operator<(const string_view &s) const   { return iless(first, s);                         }
	bool operator==(const string_view &s) const  { return iequals(first, s);                       }
	bool operator!=(const string_view &s) const  { return !operator==(s);                          }

	using std::pair<string_view, string_view>::pair;
	header(const line &);
	header() = default;
};

/// This device allows parsing HTTP headers directly off the wire without state
///
/// The constructor of this object contains the grammar to read HTTP headers
/// from the capstan and then proffer them one by one to the provided closure,
/// that's all it does.
///
struct ircd::http::headers
:string_view
{
	using closure = util::function_bool<const header &>;

	static const string_view terminator; // "\r\n\r\n"

	bool for_each(const closure &) const;
	string_view operator[](const string_view &key) const;
	string_view at(const string_view &key) const;
	bool has(const string_view &key) const;

	using string_view::string_view;
	headers(parse::capstan &, closure = {});
	headers() = default;

	friend bool has(const headers &, const string_view &key);
	friend bool has(const vector_view<const header> &, const string_view &key);
};

/// HTTP request suite. Functionality to send and receive requests.
///
struct ircd::http::request
{
	struct head;

	// compose a request into buffer
	request(window_buffer &,
	        const string_view &host,
	        const string_view &method          = "GET",
	        const string_view &uri             = "/",
	        const size_t &content_length       = 0,
	        const string_view &content_type    = {},
	        const vector_view<const header> &  = {},
	        const bool &termination            = true);
};

/// Represents an HTTP request head. This is only for receiving requests.
///
struct ircd::http::request::head
:line::request
{
	string_view host;
	string_view expect;
	string_view te;
	string_view authorization;
	string_view connection;
	string_view content_type;
	string_view user_agent;
	string_view upgrade;
	string_view range;
	string_view if_range;
	string_view forwarded[1];       // last forwarded
	string_view forwarded_for[1];   // last x-forwarded-for
	string_view forwarded_host[1];  // last x-forwarded-host
	size_t content_length {0};

	string_view uri;        // full view of (path, query, fragmet)
	http::headers headers;  // full view of all headers

	// full view of all head (request line and headers)
	operator string_view() const;

	head(parse::capstan &pc, const headers::closure &c = {});
	head() = default;
};

/// HTTP response suite. Functionality to send and receive responses.
///
struct ircd::http::response
{
	struct head;
	struct chunk;

	// compose a response into buffer
	response(window_buffer &,
	         const enum code &,
	         const size_t &content_length       = 0,
	         const string_view &content_type    = {},
	         const http::headers &headers       = {},
	         const vector_view<const header> &  = {},
	         const bool &termination            = true);

	response() = default;
};

/// Represents an HTTP response head. This is for receiving responses only.
///
struct ircd::http::response::head
:line::response
{
	string_view content_type;
	size_t content_length {0};
	string_view content_range;
	string_view accept_range;
	string_view transfer_encoding;
	string_view server;
	string_view location;

	http::headers headers;

	head(parse::capstan &pc, const headers::closure &c);
	head(parse::capstan &pc);
	head() = default;
};

struct ircd::http::response::chunk
:line
{
	uint32_t size {0};

	chunk(parse::capstan &pc);
	chunk() = default;
};

template<size_t MAX>
inline ircd::vector_view<ircd::string_view>
ircd::http::query::string::array(const mutable_buffer &buf,
                                 const string_view &key,
                                 string_view (&out)[MAX])
const
{
	return array(buf, key, out, MAX);
}

template<class T>
inline T
ircd::http::query::string::get(const string_view &key,
                               const T &def,
                               const size_t &idx)
const try
{
	const auto val(_get(key, idx));
	return val? lex_cast<T>(val) : def;
}
catch(const bad_lex_cast &)
{
	return def;
}

template<class T>
inline T
ircd::http::query::string::at(const string_view &key,
                              const size_t &idx)
const
{
	return lex_cast<T>(at(key, idx));
}

inline ircd::string_view
ircd::http::query::string::operator[](const string_view &key)
const
{
	return _get(key, 0);
}

template<class... args>
inline
ircd::http::error::error(const string_view &fmt,
                         const http::code &code,
                         args&&... a)
:error
{
	code,
	fmt::snstringf //TODO: XXX fmt::sstringf
	{
		3072, fmt, std::forward<args>(a)...
	}
}
{}
