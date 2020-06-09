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
 * Copyright 2020 Robert Mustacchi
 */

/*
 * C11 c32rtomb(3C) support.
 *
 * The char32_t type is designed to represent a UTF-32 value, which is what we
 * can represent with a wchar_t. This is basically a wrapper around wcrtomb().
 */

#include <locale.h>
#include <wchar.h>
#include <xlocale.h>
#include <uchar.h>
#include <errno.h>
#include "unicode.h"

static mbstate_t c32rtomb_state;

size_t
c32rtomb(char *restrict str, char32_t c32, mbstate_t *restrict ps)
{
	if ((c32 >= UNICODE_SUR_MIN && c32 <= UNICODE_SUR_MAX) ||
	    c32 > UNICODE_SUP_MAX) {
		errno = EILSEQ;
		return ((size_t)-1);
	}

	if (ps == NULL) {
		ps = &c32rtomb_state;
	}

	if (str == NULL) {
		c32 = L'\0';
	}

	return (wcrtomb_l(str, (wchar_t)c32, ps, uselocale((locale_t)0)));
}
