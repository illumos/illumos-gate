/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Some wchar support functions used by this library.
 * Mostlly just wrappers that call sys/u8_textprep.h
 * functions: uconv_u8tou16, uconv_u16tou8.
 */

#include <sys/types.h>
#include <sys/u8_textprep.h>
#include <string.h>

#include "ndr_wchar.h"

/*
 * When we just want lengths, we need an output buffer to pass to the
 * uconv_... functions.  Nothing ever reads this output, so we can
 * use shared space for the unwanted output.
 */
static uint16_t junk_wcs[NDR_STRING_MAX];
static char junk_mbs[NDR_MB_CUR_MAX * NDR_STRING_MAX];

static size_t
ndr__mbstowcs_x(uint16_t *, const char *, size_t, int);

/*
 * Like mbstowcs(3C), but with UCS-2 wchar_t
 */
size_t
ndr__mbstowcs(uint16_t *wcs, const char *mbs, size_t nwchars)
{
	return (ndr__mbstowcs_x(wcs, mbs, nwchars,
	    UCONV_OUT_SYSTEM_ENDIAN));
}

/*
 * Like above, but put UCS-2 little-endian.
 */
size_t
ndr__mbstowcs_le(uint16_t *wcs, const char *mbs, size_t nwchars)
{
	return (ndr__mbstowcs_x(wcs, mbs, nwchars,
	    UCONV_OUT_LITTLE_ENDIAN));
}

/*
 * Like mbstowcs(3C), but with UCS-2 wchar_t, and
 * one extra arg for the byte order flags.
 */
static size_t
ndr__mbstowcs_x(uint16_t *wcs, const char *mbs, size_t nwchars, int flags)
{
	size_t obytes, mbslen, wcslen;
	int err;

	/* NULL or empty input is allowed. */
	if (mbs == NULL || *mbs == '\0') {
		if (wcs != NULL && nwchars > 0)
			*wcs = 0;
		return (0);
	}

	/*
	 * If wcs == NULL, caller just wants the length.
	 * Convert into some throw-away space.
	 */
	obytes = nwchars * 2;
	if (wcs == NULL) {
		if (obytes > sizeof (junk_wcs))
			return ((size_t)-1);
		wcs = junk_wcs;
	}

	mbslen = strlen(mbs);
	wcslen = nwchars;
	err = uconv_u8tou16((const uchar_t *)mbs, &mbslen,
	    wcs, &wcslen, flags);
	if (err != 0)
		return ((size_t)-1);

	if (wcslen < nwchars)
		wcs[wcslen] = 0;

	return (wcslen);
}

/*
 * Like wcstombs(3C), but with UCS-2 wchar_t.
 */
size_t
ndr__wcstombs(char *mbs, const uint16_t *wcs, size_t nbytes)
{
	size_t mbslen, wcslen;
	int err;

	/* NULL or empty input is allowed. */
	if (wcs == NULL || *wcs == 0) {
		if (mbs != NULL && nbytes > 0)
			*mbs = '\0';
		return (0);
	}

	/*
	 * If mbs == NULL, caller just wants the length.
	 * Convert into some throw-away space.
	 */
	if (mbs == NULL) {
		if (nbytes > sizeof (junk_mbs))
			return ((size_t)-1);
		mbs = junk_mbs;
	}

	wcslen = ndr__wcslen(wcs);
	mbslen = nbytes;
	err = uconv_u16tou8(wcs, &wcslen,
	    (uchar_t *)mbs, &mbslen, UCONV_IN_SYSTEM_ENDIAN);
	if (err != 0)
		return ((size_t)-1);

	if (mbslen < nbytes)
		mbs[mbslen] = '\0';

	return (mbslen);
}

/*
 * Like wcslen(3C), but with UCS-2 wchar_t.
 */
size_t
ndr__wcslen(const uint16_t *wc)
{
	size_t len = 0;
	while (*wc++)
		len++;
	return (len);
}
