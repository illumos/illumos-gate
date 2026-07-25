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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * C11 mbrtoc16(3C) support.
 *
 * The char16_t represents a UTF-16 encoding. This means that we have to deal
 * with surrogate pairs.
 */

#include "thr_uberdata.h"
#include <locale.h>
#include <wchar.h>
#include <xlocale.h>
#include <uchar.h>
#include "mblocal.h"
#include "unicode.h"

#include <sys/debug.h>

/*
 * Ensure that we never cause our save state to ever exceed that of the
 * mbstate_t. See the block comment in mblocal.h.
 */
CTASSERT(sizeof (_CHAR16State) <= sizeof (mbstate_t));

static mbstate_t mbrtoc16_state;

size_t
mbrtoc16_l(char16_t *restrict pc16, const char *restrict str, size_t len,
    mbstate_t *restrict ps, locale_t restrict loc)
{
	size_t ret;
	char32_t c32;
	char16_t out;
	_CHAR16State *c16s;

	if (ps == NULL) {
		ps = &mbrtoc16_state;
	}

	if (str == NULL) {
		pc16 = NULL;
		str = "";
		len = 1;
	}

	c16s = (_CHAR16State *)ps;
	if (c16s->c16_surrogate != 0) {
		if (pc16 != NULL) {
			*pc16 = c16s->c16_surrogate;
		}
		c16s->c16_surrogate = 0;
		return ((size_t)-3);
	}

	ret = mbrtoc32_l(&c32, str, len, ps, loc);
	switch (ret) {
	case 0:
		c32 = 0;
		break;
	case (size_t)-1:
	case (size_t)-2:
		return (ret);
	case (size_t)-3:
	default:
		break;
	}

	/*
	 * If this character is not in the basic multilingual plane then we need
	 * a surrogate character to represent it in UTF-16 and we will need to
	 * write that out on the next iteration.
	 */
	if (c32 >= UNICODE_SUP_START) {
		c32 -= UNICODE_SUP_START;
		c16s->c16_surrogate = UNICODE_SUR_LOWER |
		    UNICODE_SUR_LMASK(c32);
		out = UNICODE_SUR_UPPER | UNICODE_SUR_UMASK(c32);
	} else {
		out = (char16_t)c32;
	}

	if (pc16 != NULL) {
		*pc16 = out;
	}

	return (ret);
}

size_t
mbrtoc16(char16_t *restrict pc16, const char *restrict str, size_t len,
    mbstate_t *restrict ps)
{
	return (mbrtoc16_l(pc16, str, len, ps, __curlocale()));
}
