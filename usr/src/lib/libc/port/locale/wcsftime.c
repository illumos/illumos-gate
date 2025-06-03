/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2002 Tim J. Robbins
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2025 Bill Sommerfeld
 */

#include "lint.h"
#include "mse_int.h"
#include <xlocale.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <alloca.h>

/*
 * Convert date and time to a wide-character string.
 *
 * This is the wide-character counterpart of strftime(). So that we do not
 * have to duplicate the code of strftime(), we convert the format string to
 * multibyte, call strftime(), then convert the result back into wide
 * characters.
 *
 * This technique loses in the presence of stateful multibyte encoding if any
 * of the conversions in the format string change conversion state. When
 * stateful encoding is implemented, we will need to reset the state between
 * format specifications in the format string.
 *
 * Note carefully that prior to xpg5, the format was char *, not wchar_t.
 */

/*
 * Hmmm this is probably a bit backwards.  As we are converting to single
 * byte formats, perhaps we should not be doing a redundant conversion.
 * Something to look at for the future.
 */

size_t
__wcsftime_xpg5(wchar_t *wcs, size_t maxsize, const wchar_t *format,
    const struct tm *timeptr)
{
	return (wcsftime_l(wcs, maxsize, format, timeptr,
	    uselocale(NULL)));
}


size_t
wcsftime_l(wchar_t *wcs, size_t maxsize, const wchar_t *format,
    const struct tm *timeptr, locale_t loc)
{
	static const mbstate_t initial = { 0 };
	mbstate_t mbs;
	char *dst, *sformat;
	const char *dstp;
	const wchar_t *formatp;
	size_t n, sflen;
	int sverrno;

	sformat = dst = NULL;

	/*
	 * Convert the supplied format string to a multibyte representation
	 * for strftime(), which only handles single-byte characters.
	 */
	mbs = initial;
	formatp = format;
	sflen = wcsrtombs_l(NULL, &formatp, 0, &mbs, loc);
	if (sflen == (size_t)-1)
		goto error;
	if ((sformat = malloc(sflen + 1)) == NULL)
		goto error;
	mbs = initial;
	(void) wcsrtombs_l(sformat, &formatp, sflen + 1, &mbs, loc);

	/*
	 * Allocate memory for longest multibyte sequence that will fit
	 * into the caller's buffer and call strftime() to fill it.
	 * Then, copy and convert the result back into wide characters in
	 * the caller's buffer.
	 */
	if (LONG_MAX / MB_CUR_MAX <= maxsize) {
		/* maxsize is prepostorously large - avoid int. overflow. */
		errno = EINVAL;
		goto error;
	}
	if ((dst = malloc(maxsize * MB_CUR_MAX)) == NULL)
		goto error;
	if (strftime_l(dst, maxsize, sformat, timeptr, loc) == 0)
		goto error;
	dstp = dst;
	mbs = initial;
	n = mbsrtowcs_l(wcs, &dstp, maxsize, &mbs, loc);
	if (n == (size_t)-2 || n == (size_t)-1 || dstp != NULL)
		goto error;

	free(sformat);
	free(dst);
	return (n);

error:
	sverrno = errno;
	free(sformat);
	free(dst);
	errno = sverrno;
	return (0);
}

size_t
wcsftime(wchar_t *wcs, size_t maxsize, const char *format,
    const struct tm *timeptr)
{
	int	len;
	wchar_t	*wfmt;
	size_t rv;
	locale_t loc = uselocale(NULL);

	/* Convert the format (mb string) to wide char array */
	len = strlen(format) + 1;
	wfmt = malloc(sizeof (wchar_t) * len);
	if (mbstowcs_l(wfmt, format, len, loc) == (size_t)-1) {
		free(wfmt);
		return (0);
	}
	rv = wcsftime_l(wcs, maxsize, wfmt, timeptr, loc);
	free(wfmt);
	return (rv);
}
