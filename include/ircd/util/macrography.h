// Matrix Construct
//
// Copyright (C) Matrix Construct Developers, Authors & Contributors
// Copyright (C) 2016-2023 Jason Volk <jason@zemos.net>
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice is present in all copies. The
// full license for this software is available in the LICENSE file.

#pragma once
#define HAVE_IRCD_UTIL_MACROGRAPHY_H

//
// Macro argument extraction
//

#define IRCD_ARG_0(a, ...) a
#define IRCD_ARG_1(a, b, ...) b
#define IRCD_ARG_2(a, b, c, ...) c
#define IRCD_ARG_3(a, b, c, d, ...) d

//
// String concatenation / literalization
//

#define IRCD_STRLIT(a) #a
#define IRCD_EXPCAT(a, b) a ## b
#define IRCD_STRING(a) IRCD_STRLIT(a)
#define IRCD_CONCAT(a, b) IRCD_EXPCAT(a, b)

//
// if constexpr(IRCD_DEFINED(MAYBE_UNDEFINED))
//

#define _IRCD_DEFINED(a, b) (!ircd::_constexpr_equal(a, b))
#define IRCD_DEFINED(a) _IRCD_DEFINED(#a, IRCD_STRLIT(a))

//
// Generate unique name0, name1, name2, etc for a unit.
//

#define IRCD_UNIQUE(a) IRCD_CONCAT(a, __COUNTER__)

