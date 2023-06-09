// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2018 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

namespace ircd::fmt
{
	using namespace ircd::spirit;

	struct spec;
	struct specifier;
	struct bool_specifier extern const bool_specifier;
	struct char_specifier extern const char_specifier;
	struct signed_specifier extern const signed_specifier;
	struct unsigned_specifier extern const unsigned_specifier;
	struct float_specifier extern const float_specifier;
	struct hex_uppercase_specifier extern const hex_uppercase_specifier;
	struct hex_lowercase_specifier extern const hex_lowercase_specifier;
	struct pointer_specifier extern const pointer_specifier;
	struct string_specifier extern const string_specifier;

	constexpr char SPECIFIER {'%'};
	constexpr char SPECIFIER_TERMINATOR {'$'};

	template<class generator>
	static bool generate_string(char *&out, const size_t &max, generator&&, const arg &val);

	template<class gen,
	         class... attr>
	static bool generate(mutable_buffer &, gen&&, attr&&...);

	template<class T,
	         class lambda>
	static bool visit_type(const arg &val, lambda&& closure);

	static void handle_specifier(mutable_buffer &out, const uint &idx, const spec &, const arg &);
}

/// Structural representation of a format specifier. The parse of each
/// specifier in the format string creates one of these.
struct [[gnu::visibility("internal")]]
ircd::fmt::spec
{
	char sign {'+'};
	char pad {' '};
	ushort width {0};
	ushort precision {0};
	string_view name;
};

/// Reflects the fmt::spec struct to allow the spirit::qi grammar to directly
/// fill in the spec struct.
#pragma GCC visibility push(internal)
BOOST_FUSION_ADAPT_STRUCT
(
	ircd::fmt::spec,
	( decltype(ircd::fmt::spec::sign),       sign       )
	( decltype(ircd::fmt::spec::pad),        pad        )
	( decltype(ircd::fmt::spec::width),      width      )
	( decltype(ircd::fmt::spec::precision),  precision  )
	( decltype(ircd::fmt::spec::name),       name       )
)
#pragma GCC visibility pop

/// The format string parser grammar.
namespace ircd::fmt::parser
{
	template<class R = unused_type>
	struct [[gnu::visibility("internal")]] rule
	:qi::rule<const char *, R>
	{
		using qi::rule<const char *, R>::rule;
	};

	const expr specsym
	{
		lit(SPECIFIER)
		,"format specifier"
	};

	const expr specterm
	{
		lit(SPECIFIER_TERMINATOR)
		,"specifier termination"
	};

	const expr name
	{
		raw[repeat(1,14)[char_("A-Za-z")]]
		,"specifier name"
	};

	const rule<fmt::spec> spec
	{
		(specsym >> !specsym)
		>> -(char_('+') | char_('-'))
		>> (-char_('0') | attr(' '))
		>> -ushort_
		>> -(lit('.') >> ushort_)
		>> name
		>> -specterm,
		"specifier"
	};
}

/// A format specifier handler module. This allows a new "%foo" to be defined
/// with custom handling by overriding. This abstraction is inserted into a
/// mapping key'ed by the supplied names leading to an instance of this.
///
class [[gnu::visibility("hidden")]]
ircd::fmt::specifier
{
	static std::map<string_view, const specifier *, std::less<>> registry;

	std::set<string_view> names;

  public:
	virtual bool operator()(char *&out, const size_t &max, const spec &, const arg &) const = 0;

	specifier(const std::initializer_list<string_view> &names);
	specifier(const string_view &name);
	virtual ~specifier() noexcept;

	static bool exists(const string_view &name);
	static const specifier &at(const string_view &name);
};

[[clang::always_destroy]]
decltype(ircd::fmt::specifier::registry)
ircd::fmt::specifier::registry;

struct [[gnu::visibility("hidden")]]
ircd::fmt::string_specifier
:specifier
{
	static const std::tuple
	<
		const char *,
		std::string,
		std::string_view,
		ircd::string_view,
		ircd::json::string,
		ircd::json::object,
		ircd::json::array
	>
	types;

	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::string_specifier
{
	"s"_sv
};

decltype(ircd::fmt::string_specifier::types)
ircd::fmt::string_specifier::types;

struct [[gnu::visibility("hidden")]]
ircd::fmt::bool_specifier
:specifier
{
	static const std::tuple
	<
		bool,
		char,       unsigned char,
		short,      unsigned short,
		int,        unsigned int,
		long,       unsigned long,
		long long,  unsigned long long
	>
	types;

	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::bool_specifier
{
	{ "b"_sv }
};

decltype(ircd::fmt::bool_specifier::types)
ircd::fmt::bool_specifier::types;

struct [[gnu::visibility("hidden")]]
ircd::fmt::signed_specifier
:specifier
{
	static const std::tuple
	<
		bool,
		char,       unsigned char,
		short,      unsigned short,
		int,        unsigned int,
		long,       unsigned long,
		long long,  unsigned long long
	>
	types;

	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::signed_specifier
{
	{ "d"_sv, "ld"_sv, "zd"_sv }
};

decltype(ircd::fmt::signed_specifier::types)
ircd::fmt::signed_specifier::types;

struct [[gnu::visibility("hidden")]]
ircd::fmt::unsigned_specifier
:specifier
{
	static const std::tuple
	<
		bool,
		char,       unsigned char,
		short,      unsigned short,
		int,        unsigned int,
		long,       unsigned long,
		long long,  unsigned long long
	>
	types;

	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::unsigned_specifier
{
	{ "u"_sv, "lu"_sv, "zu"_sv }
};

struct [[gnu::visibility("hidden")]]
ircd::fmt::hex_lowercase_specifier
:specifier
{
	static const std::tuple
	<
		bool,
		char,       unsigned char,
		short,      unsigned short,
		int,        unsigned int,
		long,       unsigned long,
		long long,  unsigned long long
	>
	types;

	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::hex_lowercase_specifier
{
	{ "x"_sv, "lx"_sv }
};

decltype(ircd::fmt::hex_lowercase_specifier::types)
ircd::fmt::hex_lowercase_specifier::types;

struct [[gnu::visibility("hidden")]]
ircd::fmt::hex_uppercase_specifier
:specifier
{
	static const std::tuple
	<
		bool,
		char,       unsigned char,
		short,      unsigned short,
		int,        unsigned int,
		long,       unsigned long,
		long long,  unsigned long long
	>
	types;

	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::hex_uppercase_specifier
{
	{ "X"_sv, "lX"_sv }
};

decltype(ircd::fmt::hex_uppercase_specifier::types)
ircd::fmt::hex_uppercase_specifier::types;

decltype(ircd::fmt::unsigned_specifier::types)
ircd::fmt::unsigned_specifier::types;

struct [[gnu::visibility("hidden")]]
ircd::fmt::float_specifier
:specifier
{
	static const std::tuple
	<
		char,        unsigned char,
		short,       unsigned short,
		int,         unsigned int,
		long,        unsigned long,
		float,       double,
		long double
	>
	types;

	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::float_specifier
{
	{ "f"_sv, "lf"_sv }
};

decltype(ircd::fmt::float_specifier::types)
ircd::fmt::float_specifier::types;

struct [[gnu::visibility("hidden")]]
ircd::fmt::char_specifier
:specifier
{
	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::char_specifier
{
	"c"_sv
};

struct [[gnu::visibility("hidden")]]
ircd::fmt::pointer_specifier
:specifier
{
	bool operator()(char *&out, const size_t &max, const spec &, const arg &val) const override;
	using specifier::specifier;
}
const ircd::fmt::pointer_specifier
{
	"p"_sv
};

//
// snprintf::snprintf
//

[[gnu::visibility("protected")]]
ircd::fmt::snprintf::snprintf(internal_t,
                              const mutable_buffer &out,
                              const string_view &fmt,
                              const va_rtti &v)
try
:out{out}
,fmt{[&fmt]
{
	// start the member fmt variable at the first specifier (or end)
	const auto pos(fmt.find(SPECIFIER));
	return pos != fmt.npos?
		fmt.substr(pos):
		string_view{};
}()}
,idx{0}
{
	// If out has no size we have nothing to do, not even null terminate it.
	if(unlikely(empty(out)))
		return;

	// If fmt has no specifiers then we can just copy the fmt as best as
	// possible to the out buffer.
	if(empty(this->fmt))
	{
		append(fmt);
		return;
	}

	// Copy everything from fmt up to the first specifier.
	assert(data(this->fmt) >= data(fmt));
	append(string_view(data(fmt), data(this->fmt)));

	// Iterate
	auto it(begin(v));
	for(size_t i(0); i < v.size() && !finished(); ++it, i++)
	{
		const void *const &ptr(get<0>(*it));
		const std::type_index type(*get<1>(*it));
		argument(std::make_tuple(ptr, type));
	}

	// Ensure null termination if out buffer is non-empty.
	assert(size(this->out) > 0);
	assert(this->out.remaining());
	copy(mutable_buffer(this->out), '\0');
}
catch(const std::out_of_range &e)
{
	throw invalid_format
	{
		"Format string requires more than %zu arguments.", v.size()
	};
}

[[gnu::visibility("hidden")]]
void
ircd::fmt::snprintf::argument(const arg &val)
{
	// The format string's front pointer is sitting on the specifier '%'
	// waiting to be parsed now.
	fmt::spec spec;
	auto &start(begin(this->fmt));
	const auto &stop(end(this->fmt));
	if(ircd::parse<invalid_format>(start, stop, parser::spec, spec))
		handle_specifier(this->out, idx++, spec, val);

	string_view fmt
	{
		start, stop
	};

	if(size(fmt) >= 2 && fmt[0] == SPECIFIER && fmt[1] == SPECIFIER)
	{
		append({&SPECIFIER, 1});
		consume(this->fmt, 2);
		fmt = string_view
		{
			start, stop
		};
	}

	const auto nextpos
	{
		fmt.find(SPECIFIER)
	};

	const string_view leg
	{
		fmt.substr(0, nextpos)
	};

	append(leg);
	consume(this->fmt, size(leg));
}

[[gnu::visibility("hidden")]]
void
ircd::fmt::snprintf::append(const string_view &src)
{
	out([&src](const mutable_buffer &buf)
	{
		return strlcpy(buf, src);
	});
}

[[gnu::visibility("hidden")]]
size_t
ircd::fmt::snprintf::remaining()
const noexcept
{
	return out.remaining()?
		out.remaining() - 1:
		0;
}

[[gnu::visibility("hidden")]]
bool
ircd::fmt::snprintf::finished()
const noexcept
{
	return empty(fmt) || !remaining();
}

//
// fmt::specifier
//

ircd::fmt::specifier::specifier(const string_view &name)
:specifier{{name}}
{
}

ircd::fmt::specifier::specifier(const std::initializer_list<string_view> &names)
:names{names}
{
	for(const auto &name : this->names)
		if(exists(name))
			throw error
			{
				"Specifier '%s' already registered\n", name
			};

	for(const auto &name : this->names)
		registry.emplace(name, this);
}

ircd::fmt::specifier::~specifier()
noexcept
{
	for(const auto &name : names)
		registry.erase(name);
}

inline bool
ircd::fmt::specifier::exists(const string_view &name)
{
	return registry.count(name);
}

inline const ircd::fmt::specifier &
ircd::fmt::specifier::at(const string_view &name)
{
	return *registry.at(name);
}

//
// Utils
//

void
ircd::fmt::handle_specifier(mutable_buffer &out,
                            const uint &idx,
                            const spec &spec,
                            const arg &val)
try
{
	auto &outp(std::get<0>(out));
	assert(size(out));
	const size_t max
	{
		size(out) - 1 // Leave room for null byte for later.
	};

	assert(spec.name);
	const auto &type(get<1>(val));
	const auto &handler(specifier::at(spec.name));
	if(unlikely(!handler(outp, max, spec, val)))
		throw invalid_type
		{
			"`%s' (%s) for format specifier '%s' for argument #%u",
			demangle(type.name()),
			type.name(),
			spec.name,
			idx
		};
}
catch(const std::out_of_range &e)
{
	throw invalid_format
	{
		"Unhandled specifier `%s' for argument #%u in format string",
		spec.name,
		idx
	};
}
catch(const illegal &e)
{
	throw illegal
	{
		"Specifier `%s' for argument #%u: %s",
		spec.name,
		idx,
		e.what()
	};
}

template<class T,
         class lambda>
bool
ircd::fmt::visit_type(const arg &val,
                      lambda&& closure)
{
	const auto &ptr(get<0>(val));
	const auto &type(get<1>(val));
	return type == typeid(T)? closure(*static_cast<const T *>(ptr)) : false;
}

template<class gen,
         class... attr>
bool
ircd::fmt::generate(mutable_buffer &out,
                    gen&& g,
                    attr&&... a)
{
	constexpr bool truncation
	{
		true
	};

	return ircd::generate<truncation>(out, std::forward<gen>(g), std::forward<attr>(a)...);
}

//
// Handlers
//

bool
ircd::fmt::pointer_specifier::operator()(char *&out,
                                         const size_t &max,
                                         const spec &spec,
                                         const arg &val)
const
{
	using karma::eps;

	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Not a pointer"
		};
	}};

	struct generator
	:karma::grammar<char *, uintptr_t()>
	{
		karma::rule<char *, uintptr_t()> rule
		{
			lit("0x") << karma::hex
		};

		_r1_type width;
		_r2_type pad;
		karma::rule<char *, uintptr_t(ushort, char)> aligned_left
		{
			karma::left_align(width, pad)[rule]
			,"left aligned"
		};

		karma::rule<char *, uintptr_t(ushort, char)> aligned_right
		{
			karma::right_align(width, pad)[rule]
			,"right aligned"
		};

		karma::rule<char *, uintptr_t(ushort, char)> aligned_center
		{
			karma::center(width, pad)[rule]
			,"center aligned"
		};

		generator(): generator::base_type{rule} {}
	}
	static const generator;

	static const auto &ep
	{
		eps[throw_illegal]
	};

	const auto &ptr(get<0>(val));
	const auto &type(get<1>(val));
	const void *const p
	{
		*static_cast<const void *const *>(ptr)
	};

	bool ret;
	mutable_buffer buf
	{
		out, max
	};

	if(!spec.width)
		ret = fmt::generate(buf, generator | ep, uintptr_t(p));

	else if(spec.sign == '-')
	{
		const auto &g(generator.aligned_left(spec.width, spec.pad));
		ret = fmt::generate(buf, g | ep, uintptr_t(p));
	} else {
		const auto &g(generator.aligned_right(spec.width, spec.pad));
		ret = fmt::generate(buf, g | ep, uintptr_t(p));
	}

	out = data(buf);
	return ret;
}

bool
ircd::fmt::char_specifier::operator()(char *&out,
                                      const size_t &max,
                                      const spec &,
                                      const arg &val)
const
{
	using karma::eps;

	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Not a printable character"
		};
	}};

	struct generator
	:karma::grammar<char *, char()>
	{
		karma::rule<char *, char()> printable
		{
			karma::print
			,"character"
		};

		generator(): generator::base_type{printable} {}
	}
	static const generator;

	const auto &ptr(get<0>(val));
	const auto &type(get<1>(val));
	if(type == typeid(const char))
	{
		mutable_buffer buf
		{
			out, max
		};

		const auto &c(*static_cast<const char *>(ptr));
		fmt::generate(buf, generator | eps[throw_illegal], c);
		out = data(buf);
		return true;
	}
	else return false;
}

bool
ircd::fmt::bool_specifier::operator()(char *&out,
                                      const size_t &max,
                                      const spec &,
                                      const arg &val)
const
{
	using karma::eps;

	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Failed to print signed value"
		};
	}};

	const auto closure([&](const bool &boolean)
	{
		struct generator
		:karma::grammar<char *, bool()>
		{
			karma::rule<char *, bool()> rule
			{
				karma::bool_
				,"boolean"
			};

			generator(): generator::base_type{rule} {}
		}
		static const generator;

		mutable_buffer buf
		{
			out, max
		};

		const auto ret
		{
			fmt::generate(buf, generator | eps[throw_illegal], boolean)
		};

		out = data(buf);
		return ret;
	});

	return test(types, [&](const auto type)
	{
		return visit_type<decltype(type)>(val, closure);
	});
}

bool
ircd::fmt::signed_specifier::operator()(char *&out,
                                        const size_t &max,
                                        const spec &spec,
                                        const arg &val)
const
{
	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Failed to print signed value"
		};
	}};

	const auto closure([&out, &max, &spec, &val]
	(const long &integer)
	{
		using karma::long_;

		struct generator
		:karma::grammar<char *, long()>
		{
			karma::rule<char *, long()> rule
			{
				long_
				,"signed long integer"
			};

			_r1_type width;
			_r2_type pad;
			karma::rule<char *, long(ushort, char)> aligned_left
			{
				karma::left_align(width, pad)[rule]
				,"left aligned"
			};

			karma::rule<char *, long(ushort, char)> aligned_right
			{
				karma::right_align(width, pad)[rule]
				,"right aligned"
			};

			karma::rule<char *, long(ushort, char)> aligned_center
			{
				karma::center(width, pad)[rule]
				,"center aligned"
			};

			generator(): generator::base_type{rule} {}
		}
		static const generator;

		static const auto &ep
		{
			eps[throw_illegal]
		};

		bool ret;
		mutable_buffer buf
		{
			out, max
		};

		if(!spec.width)
			ret = fmt::generate(buf, generator | ep, integer);

		else if(spec.sign == '-')
		{
			const auto &g(generator.aligned_left(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, integer);
		} else {
			const auto &g(generator.aligned_right(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, integer);
		}

		out = data(buf);
		return ret;
	});

	return test(types, [&](const auto type)
	{
		return visit_type<decltype(type)>(val, closure);
	});
}

bool
ircd::fmt::unsigned_specifier::operator()(char *&out,
                                          const size_t &max,
                                          const spec &spec,
                                          const arg &val)
const
{
	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Failed to print unsigned value"
		};
	}};

	const auto closure([&out, &max, &spec, &val]
	(const ulong &integer)
	{
		using karma::ulong_;

		struct generator
		:karma::grammar<char *, ulong()>
		{
			karma::rule<char *, ulong()> rule
			{
				ulong_
				,"unsigned long integer"
			};

			_r1_type width;
			_r2_type pad;
			karma::rule<char *, ulong(ushort, char)> aligned_left
			{
				karma::left_align(width, pad)[rule]
				,"left aligned"
			};

			karma::rule<char *, ulong(ushort, char)> aligned_right
			{
				karma::right_align(width, pad)[rule]
				,"right aligned"
			};

			karma::rule<char *, ulong(ushort, char)> aligned_center
			{
				karma::center(width, pad)[rule]
				,"center aligned"
			};

			generator(): generator::base_type{rule} {}
		}
		static const generator;

		static const auto &ep
		{
			eps[throw_illegal]
		};

		bool ret;
		mutable_buffer buf
		{
			out, max
		};

		if(!spec.width)
			ret = fmt::generate(buf, generator | ep, integer);

		else if(spec.sign == '-')
		{
			const auto &g(generator.aligned_left(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, integer);
		} else {
			const auto &g(generator.aligned_right(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, integer);
		}

		out = data(buf);
		return ret;
	});

	return test(types, [&](const auto type)
	{
		return visit_type<decltype(type)>(val, closure);
	});
}

bool
ircd::fmt::hex_lowercase_specifier::operator()(char *&out,
                                               const size_t &max,
                                               const spec &spec,
                                               const arg &val)
const
{
	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Failed to print hexadecimal value"
		};
	}};

	const auto closure([&](const ulong &integer)
	{
		struct generator
		:karma::grammar<char *, ulong()>
		{
			karma::rule<char *, ulong()> rule
			{
				karma::lower[karma::hex]
				,"unsigned lowercase hexadecimal"
			};

			_r1_type width;
			_r2_type pad;
			karma::rule<char *, ulong(ushort, char)> aligned_left
			{
				karma::left_align(width, pad)[rule]
				,"left aligned"
			};

			karma::rule<char *, ulong(ushort, char)> aligned_right
			{
				karma::right_align(width, pad)[rule]
				,"right aligned"
			};

			karma::rule<char *, ulong(ushort, char)> aligned_center
			{
				karma::center(width, pad)[rule]
				,"center aligned"
			};

			generator(): generator::base_type{rule} {}
		}
		static const generator;

		static const auto &ep
		{
			eps[throw_illegal]
		};

		bool ret;
		mutable_buffer buf
		{
			out, max
		};

		if(!spec.width)
			ret = fmt::generate(buf, generator | ep, integer);

		else if(spec.sign == '-')
		{
			const auto &g(generator.aligned_left(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, integer);
		} else {
			const auto &g(generator.aligned_right(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, integer);
		}

		out = data(buf);
		return ret;
	});

	return test(types, [&](const auto type)
	{
		return visit_type<decltype(type)>(val, closure);
	});
}

bool
ircd::fmt::hex_uppercase_specifier::operator()(char *&out,
                                               const size_t &max,
                                               const spec &spec,
                                               const arg &val)
const
{
	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Failed to print hexadecimal value"
		};
	}};

	const auto closure([&](const ulong &integer)
	{
		struct generator
		:karma::grammar<char *, ulong()>
		{
			karma::rule<char *, ulong()> rule
			{
				karma::upper[karma::hex]
				,"unsigned uppercase hexadecimal"
			};

			_r1_type width;
			_r2_type pad;
			karma::rule<char *, ulong(ushort, char)> aligned_left
			{
				karma::left_align(width, pad)[rule]
				,"left aligned"
			};

			karma::rule<char *, ulong(ushort, char)> aligned_right
			{
				karma::right_align(width, pad)[rule]
				,"right aligned"
			};

			karma::rule<char *, ulong(ushort, char)> aligned_center
			{
				karma::center(width, pad)[rule]
				,"center aligned"
			};

			generator(): generator::base_type{rule} {}
		}
		static const generator;

		static const auto &ep
		{
			eps[throw_illegal]
		};

		bool ret;
		mutable_buffer buf
		{
			out, max
		};

		if(!spec.width)
			ret = fmt::generate(buf, generator | ep, integer);

		else if(spec.sign == '-')
		{
			const auto &g(generator.aligned_left(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, integer);
		} else {
			const auto &g(generator.aligned_right(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, integer);
		}

		out = data(buf);
		return ret;
	});

	return test(types, [&](const auto type)
	{
		return visit_type<decltype(type)>(val, closure);
	});
}

//TODO: note long double is narrowed to double for now otherwise
//TODO: valgrind loops somewhere in here and eats all the system's RAM.
bool
ircd::fmt::float_specifier::operator()(char *&out,
                                       const size_t &max,
                                       const spec &spec,
                                       const arg &val)
const
{
	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Failed to print floating point value"
		};
	}};

	thread_local uint _precision_;
	_precision_ = spec.precision;

	const auto closure([&](const double &floating)
	{
		using karma::double_;

		struct generator
		:karma::grammar<char *, double()>
		{
			struct policy
			:karma::real_policies<double>
			{
				static uint precision(const double &)
				{
					return _precision_;
				}

				static bool trailing_zeros(const double &)
				{
					return _precision_ > 0;
				}

				static int floatfield(const double &)
				{
					return _precision_ > 0?
						fmtflags::fixed:
						fmtflags::scientific;
				}
			};

			karma::rule<char *, double()> rule
			{
				karma::real_generator<double, policy>()
				,"floating point real"
			};

			_r1_type width;
			_r2_type pad;
			karma::rule<char *, double(ushort, char)> aligned_left
			{
				karma::left_align(width, pad)[rule]
				,"left aligned"
			};

			karma::rule<char *, double(ushort, char)> aligned_right
			{
				karma::right_align(width, pad)[rule]
				,"right aligned"
			};

			karma::rule<char *, double(ushort, char)> aligned_center
			{
				karma::center(width, pad)[rule]
				,"center aligned"
			};

			generator(): generator::base_type{rule} {}
		}
		static const generator;

		static const auto ep
		{
			eps[throw_illegal]
		};

		bool ret;
		mutable_buffer buf
		{
			out, max
		};

		if(!spec.width)
			ret = fmt::generate(buf, generator | ep, floating);

		else if(spec.sign == '-')
		{
			const auto &g(generator.aligned_left(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, floating);
		} else {
			const auto &g(generator.aligned_right(spec.width, spec.pad));
			ret = fmt::generate(buf, g | ep, floating);
		}

		out = data(buf);
		return ret;
	});

	return test(types, [&](const auto type)
	{
		return visit_type<decltype(type)>(val, closure);
	});
}

bool
ircd::fmt::string_specifier::operator()(char *&out,
                                        const size_t &max,
                                        const spec &spec,
                                        const arg &val)
const
{
	using karma::char_;
	using karma::eps;
	using karma::unused_type;

	static const auto throw_illegal{[]
	{
		throw illegal
		{
			"Not a printable string"
		};
	}};

	struct generator
	:karma::grammar<char *, string_view>
	{
		karma::rule<char *, string_view> string
		{
			*(~ascii::cntrl)
			,"string"
		};

		_r1_type width;
		_r2_type pad;
		karma::rule<char *, string_view (ushort, char)> aligned_left
		{
			karma::left_align(width, pad)[string]
			,"left aligned"
		};

		karma::rule<char *, string_view (ushort, char)> aligned_right
		{
			karma::right_align(width, pad)[string]
			,"right aligned"
		};

		karma::rule<char *, string_view (ushort, char)> aligned_center
		{
			karma::center(width, pad)[string]
			,"center aligned"
		};

		generator() :generator::base_type{string} {}
	}
	static const generator;

	static const auto ep
	{
		eps[throw_illegal]
	};

	if(!spec.width)
		return generate_string(out, max, generator | ep, val);

	if(spec.sign == '-')
	{
		const auto &g(generator.aligned_left(spec.width, spec.pad));
		return generate_string(out, max, g | ep, val);
	}

	const auto &g(generator.aligned_right(spec.width, spec.pad));
	return generate_string(out, max, g | ep, val);
}

template<class generator>
bool
ircd::fmt::generate_string(char *&out,
                           const size_t &max,
                           generator&& gen,
                           const arg &val)
{
	using karma::eps;

	bool ret;
	mutable_buffer buf
	{
		out, max
	};

	const auto &ptr(get<0>(val));
	const auto &type(get<1>(val));
	if(type == typeid(ircd::string_view) ||
	   type == typeid(ircd::json::string) ||
	   type == typeid(ircd::json::object) ||
	   type == typeid(ircd::json::array))
	{
		const auto &str(*static_cast<const ircd::string_view *>(ptr));
		ret = fmt::generate(buf, std::forward<generator>(gen), str);
	}
	else if(type == typeid(std::string_view))
	{
		const auto &str(*static_cast<const std::string_view *>(ptr));
		ret = fmt::generate(buf, std::forward<generator>(gen), str);
	}
	else if(type == typeid(std::string))
	{
		const auto &str(*static_cast<const std::string *>(ptr));
		ret = fmt::generate(buf, std::forward<generator>(gen), string_view{str});
	}
	else if(type == typeid(const char *))
	{
		const char *const &str{*static_cast<const char *const *>(ptr)};
		ret = fmt::generate(buf, std::forward<generator>(gen), string_view{str});
	} else {
		// This for string literals which have unique array types depending on their size.
		// There is no reasonable way to match them. The best that can be hoped for is the
		// grammar will fail gracefully (most of the time) or not print something bogus when
		// it happens to be legal.
		const auto &str(static_cast<const char *>(ptr));
		ret = fmt::generate(buf, std::forward<generator>(gen), string_view{str});
	}

	out = data(buf);
	return ret;
}
