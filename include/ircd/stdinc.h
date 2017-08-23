/*
 *  ircd-ratbox: A slightly useful ircd.
 *  stdinc.h: Pull in all of the necessary system headers
 *
 *  Copyright (C) 2002 Aaron Sethman <androsyn@ratbox.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 */

#include "config.h"

extern "C" {

#include <RB_INC_ASSERT_H
#include <RB_INC_STDARG_H
#include <RB_INC_SYS_TIME_H
#include <RB_INC_SYS_RESOURCE_H

} // extern "C"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <RB_INC_WINDOWS_H
#include <RB_INC_WINSOCK2_H
#include <RB_INC_WS2TCPIP_H
#include <RB_INC_IPHLPAPI_H
#endif

#include <RB_INC_CSTDDEF
#include <RB_INC_CSTDINT
#include <RB_INC_LIMITS
#include <RB_INC_TYPE_TRAITS
#include <RB_INC_TYPEINDEX
#include <RB_INC_VARIANT
#include <RB_INC_CERRNO
#include <RB_INC_UTILITY
#include <RB_INC_FUNCTIONAL
#include <RB_INC_ALGORITHM
#include <RB_INC_NUMERIC
#include <RB_INC_CMATH
#include <RB_INC_MEMORY
#include <RB_INC_EXCEPTION
#include <RB_INC_SYSTEM_ERROR
#include <RB_INC_ARRAY
#include <RB_INC_VECTOR
#include <RB_INC_STACK
#include <RB_INC_STRING
#include <RB_INC_CSTRING
#include <RB_INC_STRING_VIEW
#include <RB_INC_EXPERIMENTAL_STRING_VIEW
#include <RB_INC_LOCALE
#include <RB_INC_CODECVT
#include <RB_INC_MAP
#include <RB_INC_SET
#include <RB_INC_LIST
#include <RB_INC_FORWARD_LIST
#include <RB_INC_UNORDERED_MAP
#include <RB_INC_DEQUE
#include <RB_INC_QUEUE
#include <RB_INC_SSTREAM
#include <RB_INC_FSTREAM
#include <RB_INC_IOSTREAM
#include <RB_INC_IOMANIP
#include <RB_INC_CSTDIO
#include <RB_INC_CHRONO
#include <RB_INC_CTIME
#include <RB_INC_ATOMIC
#include <RB_INC_THREAD
#include <RB_INC_MUTEX
#include <RB_INC_CONDITION_VARIABLE

///////////////////////////////////////////////////////////////////////////////
//
// IRCd's namespacing is as follows:
//
// IRCD_     #define and macro namespace
// ircd_     C namespace and demangled bindings
// ircd::    C++ namespace
//

///////////////////////////////////////////////////////////////////////////////
//
// Pollution
//
// This section lists all of the items introduced outside of our namespace
// which may conflict with your project.
//

// Common branch prediction macros
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

// Legacy attribute format printf macros
#define AFP(a, b)       __attribute__((format(printf, a, b)))
#define AFGP(a, b)      __attribute__((format(gnu_printf, a, b)))

// Experimental std::string_view
namespace std {

using experimental::string_view;

} // namespace std

///////////////////////////////////////////////////////////////////////////////
//
// Forward declarations from third party namespaces not included here
//

// Boost is not exposed unless explicitly included by a definition file. This
// is a major improvement of project compile time.
namespace boost {
namespace asio  {

struct io_service;         // Allow a reference to an ios to be passed to ircd
struct const_buffer;       // ircd/buffer.h
struct mutable_buffer;     // ircd/buffer.h

} // namespace asio
} // namespace boost

///////////////////////////////////////////////////////////////////////////////
//
// Items imported into our namespace.
//

namespace ircd {

using std::nullptr_t;
using std::begin;
using std::end;
using std::get;
using std::chrono::seconds;
using std::chrono::milliseconds;
using std::chrono::microseconds;
using std::chrono::nanoseconds;
using std::chrono::duration_cast;
using std::static_pointer_cast;
using std::dynamic_pointer_cast;
using std::const_pointer_cast;
using ostream = std::ostream;
namespace ph = std::placeholders;
namespace asio = boost::asio;
using namespace std::string_literals;
using namespace std::literals::chrono_literals;

} // namespace ircd

///////////////////////////////////////////////////////////////////////////////
//
// libircd API
//

// Unsorted section
namespace ircd {

extern boost::asio::io_service *ios;
constexpr size_t BUFSIZE { 512 };

struct socket;
struct client;

} // namespace ircd

#include "util.h"
#include "timer.h"
#include "allocator.h"
#include "info.h"
#include "localee.h"
#include "life_guard.h"
#include "exception.h"
#include "color.h"
#include "lexical.h"
#include "params.h"
#include "buffer.h"
#include "parse.h"
#include "rfc1459.h"
#include "json.h"
#include "http.h"
#include "fmt.h"
#include "fs.h"
#include "ctx.h"
#include "resource.h"
#include "logger.h"
#include "db.h"
#include "js.h"
#include "client.h"
#include "mods.h"
