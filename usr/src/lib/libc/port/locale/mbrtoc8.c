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
 * C23 mbrtoc8(3C) support.
 */

#include "thr_uberdata.h"
#include <locale.h>
#include <uchar.h>
#include <sys/bitext.h>
#include "mblocal.h"
#include "unicode.h"

/*
 * Ensure that we never cause our save state to ever exceed that of the
 * mbstate_t. See the block comment in mblocal.h.
 */
CTASSERT(sizeof (_CHAR8State) <= sizeof (mbstate_t));
static mbstate_t mbrtoc8_state;

size_t
mbrtoc8_l(char8_t *restrict pc8, const char *restrict str, size_t len,
    mbstate_t *restrict ps, locale_t restrict loc)
{
	size_t ret;
	char32_t c32;
	char8_t out;
	_CHAR8State *c8s;

	if (ps == NULL) {
		ps = &mbrtoc8_state;
	}

	if (str == NULL) {
		pc8 = NULL;
		str = "";
		len = 1;
	}

	/*
	 * First check if we have left overs from a prior conversion and if so,
	 * pull that out. When we encode this into the conversion state, we keep
	 * shuffle the data so the lowest byte is the one we need.
	 */
	c8s = (_CHAR8State *)ps;
	if (c8s->c8_count > 0) {
		c8s->c8_count--;
		char8_t c8 = c8s->c8_bytes[c8s->c8_count];
		if (pc8 != NULL)
			*pc8 = c8;
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
	 * We have managed to get a UTF-32 character. We must transform this
	 * into the corresponding sequence of UTF-8 characters. If required, we
	 * may need to split this up into multiple characters and store them.
	 */
	if (c32 <= UTF8_MAX_1B) {
		out = (char8_t)c32;
	} else if (c32 <= UTF8_MAX_2B) {
		c8s->c8_count = 1;
		out = UTF8_2B_PREFIX | bitx32(c32, 11, 6);
		c8s->c8_bytes[0] = UTF8_CONT_PREFIX | bitx32(c32, 5, 0);
	} else if (c32 <= UTF8_MAX_3B) {
		c8s->c8_count = 2;
		out = UTF8_3B_PREFIX | bitx32(c32, 17, 12);
		c8s->c8_bytes[1] = UTF8_CONT_PREFIX | bitx32(c32, 11, 6);
		c8s->c8_bytes[0] = UTF8_CONT_PREFIX | bitx32(c32, 5, 0);
	} else if (c32 <= UTF8_MAX_4B) {
		c8s->c8_count = 3;
		out = UTF8_4B_PREFIX | bitx32(c32, 20, 18);
		c8s->c8_bytes[2] = UTF8_CONT_PREFIX | bitx32(c32, 17, 12);
		c8s->c8_bytes[1] = UTF8_CONT_PREFIX | bitx32(c32, 11, 6);
		c8s->c8_bytes[0] = UTF8_CONT_PREFIX | bitx32(c32, 5, 0);
	} else {
		errno = EILSEQ;
		return ((size_t)-1);
	}

	if (pc8 != NULL) {
		*pc8 = out;
	}

	return (ret);
}

size_t
mbrtoc8(char8_t *restrict pc8, const char *restrict str, size_t len,
    mbstate_t *restrict ps)
{
	return (mbrtoc8_l(pc8, str, len, ps, __curlocale()));
}
