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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Wide character version of strlcat(3C). This appends up to dstlen - 1 wide
 * characters to dst, taking into account any string that already is present
 * there. The resulting string is always terminated with a NULL wide-character
 * unless the dst buffer is already full of data with no terminator. The number
 * of wide characters that would be in the fully concatenated string is
 * returned.
 */

#include "lint.h"
#include <wchar.h>
#include <sys/sysmacros.h>

size_t
wcslcat(wchar_t *restrict dst, const wchar_t *restrict src, size_t dstlen)
{
	size_t srclen = wcslen(src);
	size_t dstoff = wcsnlen(dst, dstlen);
	size_t nwcs;

	/*
	 * If there is no space in the destination buffer for the source string,
	 * then do not do anything. We check both for the case where there is no
	 * valid NUL in dst (dstoff == dstlen) or where there is one, which
	 * means that there is nothing to actually copy. It's also possible that
	 * there was never any space to begin with.
	 */
	if (dstlen == 0 || dstoff >= dstlen - 1) {
		return (srclen + dstoff);
	}

	nwcs = MIN(dstlen - 1 - dstoff, srclen);
	(void) wmemcpy(dst + dstoff, src, nwcs);
	dst[nwcs + dstoff] = L'\0';
	return (srclen + dstoff);
}
