/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * This file contains the implementation of various functional forms
 * of the ctype tests, specifically the required by ISO C.  These are defined
 * in the "C" (POSIX) locale.
 */

#include "lint.h"
#include <ctype.h>
#include <locale.h>
#include "localeimpl.h"
#include "_ctype.h"
#include "lctype.h"

/*
 * We are supplying functional forms, so make sure to suppress any macros
 * we might have imported.
 */

/*
 * Performance note: ASCII test is *much* faster, as we can avoid expensive
 * function call overhead.  This is the hot case, so we try to do that
 * whenever possible.  As far as we know, *every* encoding we support
 * is a strict superset of ASCII.  So we can make things faster by trying
 * ASCII first, and only then falling to locale specific checks.
 */

static int
isctype_l(int c, int mask, locale_t loc)
{
	return ((unsigned)c > 255 ? 0 : (loc->ctype->lc_ctype_mask[c] & mask));
}

#define	ISTYPE_L(c, mask, loc)	\
	(isascii(c) ? (__ctype_mask[c] & (mask)) : isctype_l(c, mask, loc))

#define	ISTYPE(c, mask)	ISTYPE_L(c, mask, uselocale(NULL))

#define	DEFN_ISTYPE(type, mask)		\
int					\
is##type##_l(int c, locale_t l)	\
{					\
	return (ISTYPE_L(c, mask, l));	\
}					\
					\
int					\
is##type(int c)				\
{					\
	return (ISTYPE(c, mask));	\
}

#undef	isblank
#undef	isupper
#undef	islower
#undef	isdigit
#undef	isxdigit
#undef	isalpha
#undef	isalnum
#undef	isspace
#undef	iscntrl
#undef	isgraph
#undef	ispunct
#undef	isprint

DEFN_ISTYPE(blank, _ISBLANK)
DEFN_ISTYPE(upper, _ISUPPER)
DEFN_ISTYPE(lower, _ISLOWER)
DEFN_ISTYPE(digit, _ISDIGIT)
DEFN_ISTYPE(xdigit, _ISXDIGIT)
DEFN_ISTYPE(alpha, _ISALPHA)
DEFN_ISTYPE(alnum, _ISALNUM)
DEFN_ISTYPE(space, _ISSPACE)
DEFN_ISTYPE(cntrl, _ISCNTRL)
DEFN_ISTYPE(graph, _ISGRAPH)
DEFN_ISTYPE(punct, _ISPUNCT)
DEFN_ISTYPE(print, _ISPRINT)
