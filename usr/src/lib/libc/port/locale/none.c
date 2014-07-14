/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2002-2004 Tim J. Robbins. All rights reserved.
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Paul Borman at Krystal Technologies.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lint.h"
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <note.h>
#include "mblocal.h"
#include "lctype.h"

/* setup defaults */

void
_none_init(struct lc_ctype *lct)
{
	lct->lc_is_ascii = 1;
	lct->lc_mbrtowc = __mbrtowc_ascii;
	lct->lc_mbsinit = __mbsinit_ascii;
	lct->lc_mbsnrtowcs = __mbsnrtowcs_ascii;
	lct->lc_wcrtomb = __wcrtomb_ascii;
	lct->lc_wcsnrtombs = __wcsnrtombs_ascii;
	lct->lc_max_mblen = 1;
}

int
__mbsinit_ascii(const mbstate_t *unused)
{
	_NOTE(ARGUNUSED(unused));

	/*
	 * Encoding is not state dependent - we are always in the
	 * initial state.
	 */
	return (1);
}

size_t
__mbrtowc_ascii(wchar_t *_RESTRICT_KYWD pwc, const char *_RESTRICT_KYWD s,
    size_t n, mbstate_t *_RESTRICT_KYWD unused)
{
	_NOTE(ARGUNUSED(unused));

	if (s == NULL)
		/* Reset to initial shift state (no-op) */
		return (0);
	if (n == 0)
		/* Incomplete multibyte sequence */
		return ((size_t)-2);
	if (pwc != NULL)
		*pwc = (unsigned char)*s;
	return (*s == '\0' ? 0 : 1);
}

size_t
__wcrtomb_ascii(char *_RESTRICT_KYWD s, wchar_t wc,
    mbstate_t *_RESTRICT_KYWD unused)
{
	_NOTE(ARGUNUSED(unused));

	if (s == NULL)
		/* Reset to initial shift state (no-op) */
		return (1);
	if (wc < 0 || wc > UCHAR_MAX) {
		errno = EILSEQ;
		return ((size_t)-1);
	}
	*s = (unsigned char)wc;
	return (1);
}

size_t
__mbsnrtowcs_ascii(wchar_t *_RESTRICT_KYWD dst, const char **_RESTRICT_KYWD src,
    size_t nms, size_t len, mbstate_t *_RESTRICT_KYWD unused)
{
	const char *s;
	size_t nchr;

	_NOTE(ARGUNUSED(unused));

	if (dst == NULL) {
		s = memchr(*src, '\0', nms);
		return (s != NULL ? s - *src : nms);
	}

	s = *src;
	nchr = 0;
	while (len-- > 0 && nms-- > 0) {
		if ((*dst++ = (unsigned char)*s++) == L'\0') {
			*src = NULL;
			return (nchr);
		}
		nchr++;
	}
	*src = s;
	return (nchr);
}

size_t
__wcsnrtombs_ascii(char *_RESTRICT_KYWD dst, const wchar_t **_RESTRICT_KYWD src,
    size_t nwc, size_t len, mbstate_t *_RESTRICT_KYWD unused)
{
	const wchar_t *s;
	size_t nchr;

	_NOTE(ARGUNUSED(unused));

	if (dst == NULL) {
		for (s = *src; nwc > 0 && *s != L'\0'; s++, nwc--) {
			if (*s < 0 || *s > UCHAR_MAX) {
				errno = EILSEQ;
				return ((size_t)-1);
			}
		}
		return (s - *src);
	}

	s = *src;
	nchr = 0;
	while (len-- > 0 && nwc-- > 0) {
		if (*s < 0 || *s > UCHAR_MAX) {
			errno = EILSEQ;
			return ((size_t)-1);
		}
		if ((*dst++ = *s++) == '\0') {
			*src = NULL;
			return (nchr);
		}
		nchr++;
	}
	*src = s;
	return (nchr);
}
