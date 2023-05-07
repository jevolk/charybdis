// The Construct
//
// Copyright (C) The Construct Developers, Authors & Contributors
// Copyright (C) 2016-2023 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_SIMD_TYPEDEF_H

namespace ircd::simd
{
	template<class T>
	using lane_type = typename std::remove_reference<decltype(T{}[0])>::type;

	template<class V,
	         class U = lane_type<V>>
	static constexpr size_t sizeof_lane() = delete;

	template<class T>
	static constexpr bool is()
	{
		return false;
	}
}

#define IRCD_SIMD_TYPEVEC(_T_, _U_, _V_)                      \
namespace ircd                                                \
{                                                             \
    namespace simd                                            \
    {                                                         \
        using _T_ = _U_                                       \
        __attribute__((vector_size((_V_))));                  \
    }                                                         \
                                                              \
    using simd::_T_;                                          \
}

#define IRCD_SIMD_TYPEUSE(_T_, _U_, _V_)                      \
namespace ircd                                                \
{                                                             \
    namespace simd                                            \
    {                                                         \
        using _T_ = _U_;                                      \
                                                              \
        template<>                                            \
        constexpr size_t sizeof_lane<_T_, _U_>()              \
        {                                                     \
            return sizeof(_U_);                               \
        }                                                     \
    }                                                         \
                                                              \
    using simd::_T_;                                          \
}

#define IRCD_SIMD_TYPEDEF(_T_, _U_, _V_)                      \
namespace ircd                                                \
{                                                             \
    namespace simd                                            \
    {                                                         \
        using _T_ = _U_                                       \
        __attribute__((vector_size((_V_))));                  \
                                                              \
        template<>                                            \
        constexpr size_t sizeof_lane<_T_, _U_>()              \
        {                                                     \
            return sizeof(_U_);                               \
        }                                                     \
                                                              \
        template<>                                            \
        constexpr bool is<_T_>()                              \
        {                                                     \
            return true;                                      \
        }                                                     \
    }                                                         \
                                                              \
    using simd::_T_;                                          \
}
