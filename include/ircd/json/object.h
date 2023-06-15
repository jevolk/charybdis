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
#define HAVE_IRCD_JSON_OBJECT_H

namespace ircd::json
{
	struct object;

	bool empty(const object &);
	bool operator!(const object &);
	size_t size(const object &);
	template<name_hash_t key, class T = string_view> T at(const object &);
	template<name_hash_t key, class T = string_view> T get(const object &, const T &def = {});

	bool sorted(const object &);
	size_t serialized(const object &);
	string_view stringify(mutable_buffer &, const object &);
	std::ostream &operator<<(std::ostream &, const object &);
}

/// Lightweight interface to a JSON object string.
///
/// This makes queries into a string of JSON. This is a read-only device.
/// It is merely functionality built on top of a string_view which is just a
/// pair of `const char*` pointers to the borders of the JSON object. The first
/// character should be '{' and the last character should be '}' but this is
/// not checked on construction.
///
/// This class computes over strings of JSON by parsing it on-the-fly
/// via forward iteration. The const_iterator is fundamental. All other member
/// functions are built from this forward iteration and have worst-case linear
/// complexity *every time you invoke them*. This is not necessarily a bad
/// thing in the appropriate use case. Our parser is pretty efficient; this
/// device conducts zero copies, zero allocations and zero indexing; instead
/// the parser provides string_views to members during the iteration.
///
/// The returned values are character ranges (string_view's) which themselves
/// are type agnostic to their contents. The type of a value is determined at
/// the user's discretion by querying the content of the string_view using a
/// util function like json::type() etc. In other words, a value carries type
/// data from its own original content. This means the user is responsible for
/// removing prefix and suffix characters like '{' or '"' after determining the
/// type if they want a truly pure value string_view. Note the contrast with
/// with json::value which hides '"' around keys and string values: this object
/// preserves all characters of the value for view because it carries no other
/// type information. see: ircd::unquote().
///
/// Recursive traversal cannot be achieved via a single key string value; so
/// any string_view argument for a key will not be recursive. In other words,
/// due to the fact that a JS identifier can have almost any character we have
/// to use a different *type* like a vector of strings.
///
struct ircd::json::object
:string_view
{
	struct member;
	struct const_iterator;

	using key_type = string_view;
	using mapped_type = string_view;
	using value_type = const member;
	using pointer = value_type *;
	using reference = value_type &;
	using iterator = const_iterator;
	using size_type = size_t;
	using difference_type = ptrdiff_t;
	using key_compare = std::less<member>;

	static constexpr const uint &max_recursion_depth {96};
	static constexpr const uint &max_sorted_members {1024};

	// fundamental
	const_iterator end() const;
	const_iterator begin() const;
	const_iterator find(const string_view &key) const;
	const_iterator find(const name_hash_t &key) const;

	// util
	bool empty() const;
	size_t count() const;
	size_t size() const; // warns if used; use count()
	bool has(const string_view &key) const;
	bool has(const string_view &key, const enum json::type &) const; // false if not type

	// returns value or default
	template<class T> T get(const string_view &key, const T &def = T{}) const;
	string_view get(const string_view &key, const string_view &def = {}) const;

	// returns value or throws not_found
	template<class T = string_view> T at(const string_view &key, const enum json::type &) const;
	template<class T = string_view> T at(const string_view &key) const;

	// returns value or empty
	string_view operator[](const string_view &key) const;

	// rewrite into allocated string copy
	explicit operator std::string() const;

	// constructor. Note that you are able to construct from invalid JSON. The
	// parser is not invoked until other operations and that's when it errors.
	using string_view::string_view;
};

#include "object_member.h"
#include "object_iterator.h"

template<ircd::json::name_hash_t key,
         class T>
inline T
ircd::json::at(const object &object)
try
{
	assert(key != 0);
	const auto it
	{
		object.find(key)
	};

	if(unlikely(it == end(object)))
		throw not_found
		{
			"[key hash] '%lu'", ulong(key)
		};

	return lex_cast<T>(it->second);
}
catch(const bad_lex_cast &e)
{
	throw type_error
	{
		"[key hash] '%lu' must cast to type %s",
		ulong(key),
		typeid(T).name()
	};
}

template<class T>
inline T
ircd::json::object::at(const string_view &key)
const try
{
	assert(ircd::defined(key));
	const auto it
	{
		find(key)
	};

	if(unlikely(it == end()))
		throw not_found
		{
			"'%s'", key
		};

	return lex_cast<T>(it->second);
}
catch(const bad_lex_cast &e)
{
	throw type_error
	{
		"'%s' must cast to type %s",
		key,
		typeid(T).name()
	};
}

template<class T>
inline T
ircd::json::object::at(const string_view &key,
                       const enum json::type &type)
const try
{
	assert(ircd::defined(key));
	const auto it
	{
		find(key)
	};

	if(unlikely(it == end()))
		throw not_found
		{
			"'%s'", key
		};

	if(unlikely(!json::type(it->second, type, strict)))
		throw type_error
		{
			"'%s' expected %s; got %s instead",
			key,
			reflect(type),
			reflect(json::type(it->second, std::nothrow)),
		};

	return lex_cast<T>(it->second);
}
catch(const bad_lex_cast &e)
{
	throw type_error
	{
		"'%s' must cast to type %s",
		key,
		typeid(T).name()
	};
}

template<ircd::json::name_hash_t key,
         class T>
inline T
ircd::json::get(const object &object,
                const T &def)
try
{
	const auto it
	{
		object.find(key)
	};

	if(it == end(object))
		return def;

	const string_view sv
	{
		it->second
	};

	return !sv.empty()?
		lex_cast<T>(sv):
		def;
}
catch(const bad_lex_cast &e)
{
	return def;
}

template<class T>
inline T
ircd::json::object::get(const string_view &key,
                        const T &def)
const try
{
	const string_view sv
	{
		operator[](key)
	};

	return !sv.empty()?
		lex_cast<T>(sv):
		def;
}
catch(const bad_lex_cast &e)
{
	return def;
}

inline size_t
ircd::json::object::size()
const
{
	return count();
}

inline ircd::json::object::const_iterator
ircd::json::object::end()
const
{
	return { string_view::end(), string_view::end() };
}

inline bool
ircd::json::object::empty()
const
{
	const string_view &sv{*this};
	assert(sv.size() > 2 || (sv.empty() || sv == empty_object));
	return sv.size() <= 2 || sv == literal_null;
}

inline size_t
ircd::json::size(const object &object)
{
	return object.size();
}

inline bool
ircd::json::operator!(const object &object)
{
	return empty(object);
}

inline bool
ircd::json::empty(const object &object)
{
	return object.empty();
}
