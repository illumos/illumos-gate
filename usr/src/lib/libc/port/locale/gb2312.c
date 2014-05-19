/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2004 Tim J. Robbins. All rights reserved.
 * Copyright (c) 2003 David Xu <davidxu@freebsd.org>
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

#include "lint.h"
#include <sys/types.h>
#include <errno.h>
#include "runetype.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "mblocal.h"
#include "lctype.h"

static size_t	_GB2312_mbrtowc(wchar_t *_RESTRICT_KYWD,
		    const char *_RESTRICT_KYWD,
		    size_t, mbstate_t *_RESTRICT_KYWD);
static int	_GB2312_mbsinit(const mbstate_t *);
static size_t	_GB2312_wcrtomb(char *_RESTRICT_KYWD, wchar_t,
		    mbstate_t *_RESTRICT_KYWD);
static size_t	_GB2312_mbsnrtowcs(wchar_t *_RESTRICT_KYWD,
		    const char **_RESTRICT_KYWD, size_t, size_t,
		    mbstate_t *_RESTRICT_KYWD);
static size_t	_GB2312_wcsnrtombs(char *_RESTRICT_KYWD,
		    const wchar_t **_RESTRICT_KYWD, size_t, size_t,
		    mbstate_t *_RESTRICT_KYWD);


typedef struct {
	int	count;
	uchar_t	bytes[2];
} _GB2312State;

void
_GB2312_init(struct lc_ctype *lct)
{

	lct->lc_mbrtowc = _GB2312_mbrtowc;
	lct->lc_wcrtomb = _GB2312_wcrtomb;
	lct->lc_mbsinit = _GB2312_mbsinit;
	lct->lc_mbsnrtowcs = _GB2312_mbsnrtowcs;
	lct->lc_wcsnrtombs = _GB2312_wcsnrtombs;
	lct->lc_max_mblen = 2;
	lct->lc_is_ascii = 0;
}

static int
_GB2312_mbsinit(const mbstate_t *ps)
{

	return (ps == NULL || ((const _GB2312State *)ps)->count == 0);
}

static int
_GB2312_check(const char *str, size_t n)
{
	const uchar_t *s = (const uchar_t *)str;

	if (n == 0)
		/* Incomplete multibyte sequence */
		return (-2);
	if (s[0] >= 0xa1 && s[0] <= 0xfe) {
		if (n < 2)
			/* Incomplete multibyte sequence */
			return (-2);
		if (s[1] < 0xa1 || s[1] > 0xfe)
			/* Invalid multibyte sequence */
			return (-1);
		return (2);
	} else if (s[0] & 0x80) {
		/* Invalid multibyte sequence */
		return (-1);
	}
	return (1);
}

static size_t
_GB2312_mbrtowc(wchar_t *_RESTRICT_KYWD pwc, const char *_RESTRICT_KYWD s,
    size_t n, mbstate_t *_RESTRICT_KYWD ps)
{
	_GB2312State *gs;
	wchar_t wc;
	int i, len, ocount;
	size_t ncopy;

	gs = (_GB2312State *)ps;

	if (gs->count < 0 || gs->count > sizeof (gs->bytes)) {
		errno = EINVAL;
		return ((size_t)-1);
	}

	if (s == NULL) {
		s = "";
		n = 1;
		pwc = NULL;
	}

	ncopy = MIN(MIN(n, MB_CUR_MAX), sizeof (gs->bytes) - gs->count);
	(void) memcpy(gs->bytes + gs->count, s, ncopy);
	ocount = gs->count;
	gs->count += ncopy;
	s = (char *)gs->bytes;
	n = gs->count;

	if ((len = _GB2312_check(s, n)) < 0)
		return ((size_t)len);
	wc = 0;
	i = len;
	while (i-- > 0)
		wc = (wc << 8) | (unsigned char)*s++;
	if (pwc != NULL)
		*pwc = wc;
	gs->count = 0;
	return (wc == L'\0' ? 0 : len - ocount);
}

static size_t
_GB2312_wcrtomb(char *_RESTRICT_KYWD s, wchar_t wc,
    mbstate_t *_RESTRICT_KYWD ps)
{
	_GB2312State *gs;

	gs = (_GB2312State *)ps;

	if (gs->count != 0) {
		errno = EINVAL;
		return ((size_t)-1);
	}

	if (s == NULL)
		/* Reset to initial shift state (no-op) */
		return (1);
	if (wc & 0x8000) {
		*s++ = (wc >> 8) & 0xff;
		*s = wc & 0xff;
		return (2);
	}
	*s = wc & 0xff;
	return (1);
}

static size_t
_GB2312_mbsnrtowcs(wchar_t *_RESTRICT_KYWD dst,
    const char **_RESTRICT_KYWD src, size_t nms, size_t len,
    mbstate_t *_RESTRICT_KYWD ps)
{
	return (__mbsnrtowcs_std(dst, src, nms, len, ps, _GB2312_mbrtowc));
}

static size_t
_GB2312_wcsnrtombs(char *_RESTRICT_KYWD dst,
    const wchar_t **_RESTRICT_KYWD src, size_t nwc, size_t len,
    mbstate_t *_RESTRICT_KYWD ps)
{
	return (__wcsnrtombs_std(dst, src, nwc, len, ps, _GB2312_wcrtomb));
}
