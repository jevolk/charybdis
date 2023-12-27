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
#define HAVE_IRCD_STRINGOPS_H

//
// Misc string utilities
//
namespace ircd
{
	// wrapper to find(T) != npos
	template<class T> bool has(const string_view &, const T &);
	inline bool ihas(const string_view &s, const string_view &t);
	inline size_t ifind(const string_view &s, const string_view &t);

	// Multi-string table suite; returns index past the end on no-match
	using string_views = vector_view<const string_view>;
	size_t indexof(const string_view &, const string_views &) noexcept;

	// return view without any {l=leading,r=trailing} characters contained in c
	string_view rstripa(const string_view &str, const string_view &c);
	string_view lstripa(const string_view &str, const string_view &c);
	string_view stripa(const string_view &str, const string_view &dict = "\t\n\v\f\r\x20");

	// return view without leading occurrences of c
	string_view lstrip(const string_view &str, const char &c = ' ');
	string_view lstrip(string_view str, const string_view &c);
	string_view lstrip(string_view str, const string_view &c, size_t n);
	string_view lstrip(string_view str, const char &c, size_t n);

	// return view without trailing occurrences of c
	string_view rstrip(const string_view &str, const char &c = ' ');
	string_view rstrip(string_view str, const string_view &c);
	string_view rstrip(string_view str, const string_view &c, size_t n);
	string_view rstrip(string_view str, const char &c, size_t n);

	// return view without leading and trailing occurrences of c
	string_view strip(const string_view &str, const char &c = ' ');
	string_view strip(const string_view &str, const string_view &c);
	string_view strip(const string_view &str, const string_view &c, const size_t n);
	string_view strip(const string_view &str, const char &c, const size_t n);

	// split view on first match of delim; delim not included; if no delim then .second empty
	std::pair<string_view, string_view> split(const string_view &str, const char &delim = ' ');
	std::pair<string_view, string_view> split(const string_view &str, const string_view &delim);

	// split view on last match of delim; delim not included; if no delim then .second empty
	std::pair<string_view, string_view> rsplit(const string_view &str, const char &delim = ' ');
	std::pair<string_view, string_view> rsplit(const string_view &str, const string_view &delim);

	// view between first match of delim a and first match of delim b after it
	string_view between(const string_view &str, const string_view &a, const string_view &b);
	string_view between(const string_view &str, const char &a = '(', const char &b = ')');

	// test string endswith delim; or any of the delims in iterable
	bool endswith(const string_view &str, const string_view &val);
	bool endswith(const string_view &str, const char &val);
	template<class It> bool endswith_any(const string_view &str, const It &begin, const It &end);

	// count occurrences of val at end of string
	size_t endswith_count(const string_view &str, const char &val);

	// test string startswith delim; or any of the delims in iterable
	bool startswith(const string_view &str, const string_view &val);
	bool startswith(const string_view &str, const char &val);
	template<class It> bool startswith_any(const string_view &str, const It &begin, const It &end);

	// count occurrences of val at start of string
	size_t startswith_count(const string_view &str, const char &val);

	// test string is surrounded by val (ex. surrounded by quote characters)
	bool surrounds(const string_view &str, const string_view &val);
	bool surrounds(const string_view &str, const char &val);

	// pop trailing char from view
	char chop(string_view &str);

	// remove trailing from view and return num chars removed
	size_t chomp(string_view &str, const char &c = '\n');
	size_t chomp(string_view &str, const string_view &c);
	template<class T, class delim> size_t chomp(iterators<T>, const delim &d);

	// Convenience to strip quotes
	string_view unquote(const string_view &str);
	std::string unquote(std::string &&);

	string_view replace(const mutable_buffer &, const char before, const char after) noexcept;
	string_view replace(const mutable_buffer &, const string_view &, const char before, const char after) noexcept;
	string_view replace(const mutable_buffer &, const string_view &, const char before, const string_view &after);
	string_view replace(const mutable_buffer &, const string_view &, const string_view &before, const string_view &after);
	std::string replace(const string_view &, const string_view &before, const string_view &after);
	std::string replace(const string_view &, const char before, const string_view &after);
	std::string replace(std::string, const string_view &before, const string_view &after);
	std::string replace(std::string, const char before, const char after);

	// Change a single character's case
	using std::tolower;
	using std::toupper;

	// Change case for all characters.
	string_view tolower(const mutable_buffer &out, const string_view &in) noexcept;
	string_view toupper(const mutable_buffer &out, const string_view &in) noexcept;

	// Truncate view at maximum length
	string_view trunc(const string_view &, const size_t &max);
}

inline ircd::string_view
ircd::trunc(const string_view &s,
            const size_t &max)
{
	return { s.data(), std::min(s.size(), max) };
}

inline std::string
ircd::replace(const string_view &s,
              const string_view &before,
              const string_view &after)
{
	return replace(std::string{s}, before, after);
}

inline std::string
ircd::replace(std::string s,
              const string_view &before,
              const string_view &after)
{
	size_t p(s.find(data(before), 0, size(before)));
	for(; p != s.npos; p = s.find(data(before), p + size(after), size(before)))
		s.replace(p, size(before), data(after), size(after));

	return s;
}

inline std::string
ircd::replace(std::string s,
              const char before,
              const char after)
{
	const auto &res
	{
		replace(mutable_buffer(s), before, after)
	};

	assert(res.data() == s.data());
	return s;
}

/// Remove quotes on an std::string. Only operates on an rvalue reference so
/// that a copy of the string is not created when no quotes are found, and
/// movements can take place if they are. This overload is not needed often;
/// use string_view.
inline std::string
ircd::unquote(std::string &&str)
{
	if(endswith(string_view{str}, '"'))
		str.pop_back();

	if(startswith(string_view{str}, '"'))
		str = str.substr(1);

	return std::move(str);
}

/// Common convenience to remove quotes around the view of the string
inline ircd::string_view
ircd::unquote(const string_view &str)
{
	return strip(str, '"', 1);
}

/// Chomps delim from all of the string views in the iterable (iterators<T> are
/// the T::iterator pair {begin(t), end(t)} of an iterable T) and returns the
/// total number of characters removed from all operations.
template<class T,
         class delim>
size_t
ircd::chomp(iterators<T> its,
            const delim &d)
{
	return std::accumulate(begin(its), end(its), size_t(0), [&d]
	(auto ret, const auto &s)
	{
		return ret += chomp(s, d);
	});
}

/// Removes all characters from the end of the view starting with the last
/// instance of c. Different from rstrip() in that this will remove more than
/// just the delim from the end; it removes both the delim and everything after
/// it from wherever the last delim may be. Removes nothing if no delim is.
inline size_t
ircd::chomp(string_view &str,
            const char &c)
{
	const auto pos(str.find_last_of(c));
	if(pos == string_view::npos)
		return 0;

	assert(str.size() - pos == 1);
	str = str.substr(0, pos);
	return 1;
}

/// Removes all characters from the end of the view starting with the last
/// instance of c. This matches the entire delim string c to chomp it and
/// everything after it.
inline size_t
ircd::chomp(string_view &str,
            const string_view &c)
{
	const auto pos(str.find_last_of(c));
	if(pos == string_view::npos)
		return 0;

	assert(str.size() - pos == c.size());
	str = str.substr(0, pos);
	return c.size();
}

/// Removes any last character from the view, modifying the view, and returning
/// that character.
inline char
ircd::chop(string_view &str)
{
	return !str.empty()? str.pop_back() : '\0';
}

/// Test if a string starts and ends with character
inline bool
ircd::surrounds(const string_view &str,
                const char &val)
{
	return str.size() >= 2 && str.front() == val && str.back() == val;
}

/// Test if a string starts and ends with a string
inline bool
ircd::surrounds(const string_view &str,
                const string_view &val)
{
	return startswith(str, val) && endswith(str, val);
}

/// Count occurrences of val at end of string
inline size_t
ircd::startswith_count(const string_view &str,
                       const char &v)
{
	const auto pos(str.find_first_not_of(v));
	return pos == string_view::npos?
		str.size():
		str.size() - pos - 1;
}

/// Test if a string starts with any of the values in the iterable
template<class It>
bool
ircd::startswith_any(const string_view &str,
                     const It &begin,
                     const It &end)
{
	return std::any_of(begin, end, [&str](const auto &val)
	{
		return startswith(str, val);
	});
}

/// Test if a string starts with a character
inline bool
ircd::startswith(const string_view &str,
                 const char &val)
{
	return !str.empty() && str.front() == val;
}

/// Test if a string starts with a string
inline bool
ircd::startswith(const string_view &str,
                 const string_view &val)
{
	return !str.empty() && !val.empty() && str.substr(0, val.size()) == val;
}

/// Count occurrences of val at end of string
inline size_t
ircd::endswith_count(const string_view &str,
                     const char &v)
{
	const auto pos(str.find_last_not_of(v));
	return pos == string_view::npos?
		str.size():
		str.size() - pos - 1;
}

/// Test if a string ends with any of the values in iterable
template<class It>
bool
ircd::endswith_any(const string_view &str,
                   const It &begin,
                   const It &end)
{
	return std::any_of(begin, end, [&str](const auto &val)
	{
		return endswith(str, val);
	});
}

/// Test if a string ends with character
inline bool
ircd::endswith(const string_view &str,
               const char &val)
{
	return !str.empty() && str.back() == val;
}

/// Test if a string ends with a string
inline bool
ircd::endswith(const string_view &str,
               const string_view &val)
{
	const ssize_t off(str.size() - val.size());
	return !str.empty() && !val.empty() && off >= 0 && str.substr(off) == val;
}

/// View a string between the first match of a and the first match of b
/// after a.
inline ircd::string_view
ircd::between(const string_view &str,
              const string_view &a,
              const string_view &b)
{
	return split(split(str, a).second, b).first;
}

/// View a string between the first match of a and the first match of b
/// after a.
inline ircd::string_view
ircd::between(const string_view &str,
              const char &a,
              const char &b)
{
	return split(split(str, a).second, b).first;
}

/// Split a string on the last match of delim. Delim not included; no match
/// will return original str in pair.first, pair.second empty.
inline std::pair<ircd::string_view, ircd::string_view>
ircd::rsplit(const string_view &str,
             const string_view &delim)
{
	using pair = std::pair<ircd::string_view, ircd::string_view>;

	const auto pos(str.rfind(delim));
	return pos == string_view::npos?
		pair { str, string_view{} }:
		pair { str.substr(std::nothrow, 0, pos), str.substr(std::nothrow, pos + delim.size()) };
}

/// Split a string on the last match of delim. Delim not included; no match
/// will return original str in pair.first, pair.second empty.
inline std::pair<ircd::string_view, ircd::string_view>
ircd::rsplit(const string_view &str,
             const char &delim)
{
	using pair = std::pair<ircd::string_view, ircd::string_view>;

	const auto pos(str.find_last_of(delim));
	return pos == string_view::npos?
		pair { str, string_view{} }:
		pair { str.substr(std::nothrow, 0, pos), str.substr(std::nothrow, pos + 1) };
}

/// Split a string on the first match of delim. Delim not included; no match
/// will return original str in pair.first, pair.second empty.
inline std::pair<ircd::string_view, ircd::string_view>
ircd::split(const string_view &str,
            const string_view &delim)
{
	using pair = std::pair<ircd::string_view, ircd::string_view>;

	const auto pos(str.find(delim));
	return pos == string_view::npos?
		pair { str, string_view{} }:
		pair { str.substr(std::nothrow, 0, pos), str.substr(std::nothrow, pos + delim.size()) };
}

/// Split a string on the first match of delim. Delim not included; no match
/// will return original str in pair.first, pair.second empty.
inline std::pair<ircd::string_view, ircd::string_view>
ircd::split(const string_view &str,
            const char &delim)
{
	using pair = std::pair<ircd::string_view, ircd::string_view>;

	const auto pos(str? str.find(delim): string_view::npos);
	return pos == string_view::npos?
		pair { str, string_view{} }:
		pair { str.substr(std::nothrow, 0, pos), str.substr(std::nothrow, pos + 1) };
}

/// Remove n leading and trailing instances of c from the returned view
inline ircd::string_view
ircd::strip(const string_view &str,
            const string_view &c,
            const size_t n)
{
	return lstrip(rstrip(str, c, n), c, n);
}

/// Remove n leading and trailing instances of c from the returned view
inline ircd::string_view
ircd::strip(const string_view &str,
            const char &c,
            const size_t n)
{
	return lstrip(rstrip(str, c, n), c, n);
}

/// Remove leading and trailing instances of c from the returned view
inline ircd::string_view
ircd::strip(const string_view &str,
            const string_view &c)
{
	return lstrip(rstrip(str, c), c);
}

/// Remove leading and trailing instances of c from the returned view
inline ircd::string_view
ircd::strip(const string_view &str,
            const char &c)
{
	return lstrip(rstrip(str, c), c);
}

/// Remove trailing instances of c from the returned view
inline ircd::string_view
ircd::rstrip(string_view str,
             const string_view &c)
{
	while(endswith(str, c))
		str = str.substr(0, size(str) - size(c));

	return str;
}

/// Remove trailing instances of c from the returned view
inline ircd::string_view
ircd::rstrip(string_view str,
             const string_view &c,
             size_t n)
{
	while(endswith(str, c) && n--)
		str = str.substr(0, size(str) - size(c));

	return str;
}

/// Remove trailing instances of c from the returned view
inline ircd::string_view
ircd::rstrip(string_view str,
             const char &c,
             size_t n)
{
	while(endswith(str, c) && n--)
		str.pop_back();

	return str;
}

/// Remove trailing instances of c from the returned view
inline ircd::string_view
ircd::rstrip(const string_view &str,
             const char &c)
{
	const auto pos(str.find_last_not_of(c));
	return pos != string_view::npos?
		string_view{str.substr(0, pos + 1)}:
		str;
}

/// Remove leading instances of c from the returned view
inline ircd::string_view
ircd::lstrip(string_view str,
             const string_view &c)
{
	if(c)
		while(startswith(str, c))
			str = str.substr(size(c));

	return str;
}

/// Remove n leading instances of c from the returned view
inline ircd::string_view
ircd::lstrip(string_view str,
             const string_view &c,
             size_t n)
{
	if(c)
		while(startswith(str, c) && n--)
			str = str.substr(size(c));

	return str;
}

/// Remove n leading instances of c from the returned view
inline ircd::string_view
ircd::lstrip(string_view str,
             const char &c,
             size_t n)
{
	while(startswith(str, c) && n--)
		str.pop_front();

	return str;
}

/// Remove leading instances of c from the returned view.
inline ircd::string_view
ircd::lstrip(const string_view &str,
             const char &c)
{
	const auto pos(str? str.find_first_not_of(c): string_view::npos);
	return pos != string_view::npos?
		string_view{str.substr(pos)}:
		string_view{str.data(), size_t{0}};
}

/// Strip any of the leading and trailing characters in the dictionary.
/// The default dictionary is std::isspace/whitespace.
inline ircd::string_view
ircd::stripa(const string_view &str,
             const string_view &dict)
{
	return rstripa(lstripa(str, dict), dict);
}

/// Remove leading instances of any character in c from the returned view
inline ircd::string_view
ircd::lstripa(const string_view &str,
              const string_view &c)
{
	const auto pos(str.find_first_not_of(c));
	return pos != string_view::npos?
		string_view{str.substr(pos)}:
		str;
}

/// Remove trailing instances of any character in c from the returned view
inline ircd::string_view
ircd::rstripa(const string_view &str,
              const string_view &c)
{
	const auto pos(str.find_last_not_of(c));
	return pos != string_view::npos?
		string_view{str.substr(0, pos + 1)}:
		str;
}

inline bool
ircd::ihas(const string_view &s,
           const string_view &t)
{
	return ifind(s, t) != string_view::npos;
}

inline size_t
ircd::ifind(const string_view &s,
            const string_view &t)
{
	const auto pos
	{
		std::search(begin(s), end(s), begin(t), end(t), []
		(const auto &a, const auto &b)
		{
			return tolower(a) == tolower(b);
		})
	};

	const auto ret
	{
		size_t(std::distance(begin(s), pos))
	};

	return ret < size(s)? ret : string_view::npos;
}

template<class T>
inline bool
ircd::has(const string_view &s,
          const T &t)
{
	return s.find(t) != s.npos;
}
