// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#define BOOST_DLL_USE_STD_FS
#include <boost/dll.hpp>
#include <ircd/mods/mapi.h>  // Module's internal API

namespace load_mode = boost::dll::load_mode;
namespace ircd::mods
{
	struct mod;
}

/// Internal module representation. This object closely wraps the dlopen()
/// handle and only one instance exists for a DSO when it's loaded. Loading
/// and unloading of the module is represented by construction and destruction
/// of this class, that involves static initialization and destruction of the
/// the module's assets, but not invocation of our user's supplied init. The
/// user's init is invoked after construction of this class which allows use of
/// the shared_ptr semantics from within the init.
///
/// It is a critical error if static initialization and destruction is not
/// congruent with the lifetime of this instance.
///
struct [[gnu::visibility("protected")]]
ircd::mods::mod
:std::enable_shared_from_this<mod>
{
	static std::forward_list<mod *> loading; // State of current dlopen() recursion.
	static std::forward_list<mod *> unloading; // dlclose() is not recursive but we have this
	static std::map<string_view, mod *, std::less<>> loaded;

	std::string path;
	load_mode::type mode;
	std::deque<mod *> children;
	boost::dll::shared_library handle;
	std::string _name;
	std::string _location;
	mapi::header *header;
	std::map<std::string, std::string> exports;

  public:
	// Metadata
	const string_view &operator[](const string_view &s) const;
	string_view &operator[](const string_view &s);

	// Convenience accessors
	auto &name() const                 { return _name;                         }
	auto &location() const             { return _location;                     }
	auto &description() const          { return (*this)["description"];        }
	auto version() const               { return header->version;               }

	explicit mod(std::string path, const load_mode::type &);

	mod(mod &&) = delete;
	mod(const mod &) = delete;
	mod &operator=(mod &&) = delete;
	mod &operator=(const mod &) = delete;
	~mod() noexcept;
};
