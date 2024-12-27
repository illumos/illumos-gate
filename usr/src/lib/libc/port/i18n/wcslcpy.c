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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Wide character variant of strlcpy(3C). We must copy at most dstlen wide
 * characters (not bytes!) from src to dst or less if src is less than dstlen.
 * Like with strlcpy, this must return the total number of characters that are
 * in src and it must guarantee that dst is properly terminated with the null
 * wide-character.
 */

#include "lint.h"
#include <wchar.h>
#include <sys/sysmacros.h>

size_t
wcslcpy(wchar_t *restrict dst, const wchar_t *restrict src, size_t dstlen)
{
	size_t srclen = wcslen(src);
	size_t nwcs;

	if (dstlen == 0) {
		return (srclen);
	}

	nwcs = MIN(srclen, dstlen - 1);
	(void) wmemcpy(dst, src, nwcs);
	dst[nwcs] = L'\0';
	return (srclen);
}
