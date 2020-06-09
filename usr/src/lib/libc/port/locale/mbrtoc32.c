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
 * C11 mbrtoc32(3C) support.
 *
 * The char32_t type is designed to represent UTF-32. Conveniently, the wchar_t
 * is as well. In this case, we can just pass this directly to mbrtowc_l().
 */

#include <locale.h>
#include <wchar.h>
#include <xlocale.h>
#include <uchar.h>

static mbstate_t mbrtoc32_state;

size_t
mbrtoc32(char32_t *restrict pc32, const char *restrict str, size_t len,
    mbstate_t *restrict ps)
{
	if (ps == NULL) {
		ps = &mbrtoc32_state;
	}

	if (str == NULL) {
		pc32 = NULL;
		str = "";
		len = 1;
	}

	return (mbrtowc_l((wchar_t *)pc32, str, len, ps,
	    uselocale((locale_t)0)));
}
