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
 * C11 c16rtomb(3C) support.
 *
 * Convert a series of char16_t values into a series of multi-byte characters.
 * We may be given a surrogate value, so we need to potentially store that in
 * the interim.
 */

#include <uchar.h>
#include <errno.h>
#include "mblocal.h"
#include "unicode.h"

static mbstate_t c16rtomb_state;

size_t
c16rtomb(char *restrict str, char16_t c16, mbstate_t *restrict ps)
{
	char32_t c32;
	_CHAR16State *c16s;

	if (ps == NULL) {
		ps = &c16rtomb_state;
	}

	if (str == NULL) {
		c16 = L'\0';
	}

	c16s = (_CHAR16State *)ps;
	if (c16s->c16_surrogate != 0) {
		if (c16 > UNICODE_SUR_MAX || c16 < UNICODE_SUR_MIN ||
		    (c16 & UNICODE_SUR_LOWER) != UNICODE_SUR_LOWER) {
			errno = EILSEQ;
			return ((size_t)-1);
		}

		c32 = UNICODE_SUR_UVALUE(c16s->c16_surrogate) |
		    UNICODE_SUR_LVALUE(c16);
		c32 += UNICODE_SUP_START;
		c16s->c16_surrogate = 0;
	} else if (c16 >= UNICODE_SUR_MIN && c16 <= UNICODE_SUR_MAX) {
		/*
		 * The lower surrogate pair mask (dc00) overlaps the upper mask
		 * (d800), hence why we do a binary and with the upper mask.
		 */
		if ((c16 & UNICODE_SUR_LOWER) != UNICODE_SUR_UPPER) {
			errno = EILSEQ;
			return ((size_t)-1);
		}

		c16s->c16_surrogate = c16;
		return (0);
	} else {
		c32 = c16;
	}

	/*
	 * Call c32rtomb() and not wcrtomb() so that way all of the unicode code
	 * point validation is performed.
	 */
	return (c32rtomb(str, c32, ps));
}
