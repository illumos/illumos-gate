/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2002-2004 Tim J. Robbins. All rights reserved.
 *
 *    ja_JP.SJIS locale table for BSD4.4/rune
 *    version 1.0
 *    (C) Sin'ichiro MIYATANI / Phase One, Inc
 *    May 12, 1995
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Phase One, Inc.
 * 4. The name of Phase One, Inc. may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "mblocal.h"
#include "lctype.h"

static size_t	_MSKanji_mbrtowc(wchar_t *_RESTRICT_KYWD,
		    const char *_RESTRICT_KYWD,
		    size_t, mbstate_t *_RESTRICT_KYWD);
static int	_MSKanji_mbsinit(const mbstate_t *);
static size_t	_MSKanji_wcrtomb(char *_RESTRICT_KYWD, wchar_t,
		    mbstate_t *_RESTRICT_KYWD);
static size_t	_MSKanji_mbsnrtowcs(wchar_t *_RESTRICT_KYWD,
		    const char **_RESTRICT_KYWD, size_t, size_t,
		    mbstate_t *_RESTRICT_KYWD);
static size_t	_MSKanji_wcsnrtombs(char *_RESTRICT_KYWD,
		    const wchar_t **_RESTRICT_KYWD, size_t, size_t,
		    mbstate_t *_RESTRICT_KYWD);

typedef struct {
	wchar_t	ch;
} _MSKanjiState;

void
_MSKanji_init(struct lc_ctype *lct)
{

	lct->lc_mbrtowc = _MSKanji_mbrtowc;
	lct->lc_wcrtomb = _MSKanji_wcrtomb;
	lct->lc_mbsnrtowcs = _MSKanji_mbsnrtowcs;
	lct->lc_wcsnrtombs = _MSKanji_wcsnrtombs;
	lct->lc_mbsinit = _MSKanji_mbsinit;
	lct->lc_max_mblen = 2;
	lct->lc_is_ascii = 0;
}

static int
_MSKanji_mbsinit(const mbstate_t *ps)
{

	return (ps == NULL || ((const _MSKanjiState *)ps)->ch == 0);
}

static size_t
_MSKanji_mbrtowc(wchar_t *_RESTRICT_KYWD pwc, const char *_RESTRICT_KYWD s,
    size_t n, mbstate_t *_RESTRICT_KYWD ps)
{
	_MSKanjiState *ms;
	wchar_t wc;

	ms = (_MSKanjiState *)ps;

	if ((ms->ch & ~0xFF) != 0) {
		/* Bad conversion state. */
		errno = EINVAL;
		return ((size_t)-1);
	}

	if (s == NULL) {
		s = "";
		n = 1;
		pwc = NULL;
	}

	if (n == 0)
		/* Incomplete multibyte sequence */
		return ((size_t)-2);

	if (ms->ch != 0) {
		if (*s == '\0') {
			errno = EILSEQ;
			return ((size_t)-1);
		}
		wc = (ms->ch << 8) | (*s & 0xFF);
		if (pwc != NULL)
			*pwc = wc;
		ms->ch = 0;
		return (1);
	}
	wc = *s++ & 0xff;
	if ((wc > 0x80 && wc < 0xa0) || (wc >= 0xe0 && wc < 0xfd)) {
		if (n < 2) {
			/* Incomplete multibyte sequence */
			ms->ch = wc;
			return ((size_t)-2);
		}
		if (*s == '\0') {
			errno = EILSEQ;
			return ((size_t)-1);
		}
		wc = (wc << 8) | (*s++ & 0xff);
		if (pwc != NULL)
			*pwc = wc;
		return (2);
	} else {
		if (pwc != NULL)
			*pwc = wc;
		return (wc == L'\0' ? 0 : 1);
	}
}

static size_t
_MSKanji_wcrtomb(char *_RESTRICT_KYWD s, wchar_t wc,
    mbstate_t *_RESTRICT_KYWD ps)
{
	_MSKanjiState *ms;
	int len, i;

	ms = (_MSKanjiState *)ps;

	if (ms->ch != 0) {
		errno = EINVAL;
		return ((size_t)-1);
	}

	if (s == NULL)
		/* Reset to initial shift state (no-op) */
		return (1);
	len = (wc > 0x100) ? 2 : 1;
	for (i = len; i-- > 0; )
		*s++ = wc >> (i << 3);
	return (len);
}

static size_t
_MSKanji_mbsnrtowcs(wchar_t *_RESTRICT_KYWD dst,
    const char **_RESTRICT_KYWD src, size_t nms,
    size_t len, mbstate_t *_RESTRICT_KYWD ps)
{
	return (__mbsnrtowcs_std(dst, src, nms, len, ps, _MSKanji_mbrtowc));
}

static size_t
_MSKanji_wcsnrtombs(char *_RESTRICT_KYWD dst,
    const wchar_t **_RESTRICT_KYWD src, size_t nwc,
    size_t len, mbstate_t *_RESTRICT_KYWD ps)
{
	return (__wcsnrtombs_std(dst, src, nwc, len, ps, _MSKanji_wcrtomb));
}
