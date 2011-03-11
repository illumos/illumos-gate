/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2002-2004 Tim J. Robbins.
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
#include "mse_int.h"
#include "file64.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "mblocal.h"
#include "mse.h"
#include "stdiom.h"
#include "libc.h"

/*
 * FreeBSD implementation here included a full version that tried to be more
 * efficient with memory strings.  However, for simplicity's sake, we are
 * going to just use fgetwc().  We also do the stream orientation thing for
 * XPG5 if we need to.
 */

wchar_t *
_fgetws_impl(wchar_t *_RESTRICT_KYWD ws, int n, FILE *_RESTRICT_KYWD fp,
    int orient)
{
	wint_t wc;
	wchar_t *wsp;
	rmutex_t *lk;

	FLOCKFILE(lk, fp);
	if (orient && GET_NO_MODE(fp))
		_setorientation(fp, _WC_MODE);

	if (n <= 0) {
		errno = EINVAL;
		FUNLOCKFILE(lk);
		return (NULL);
	}

	wsp = ws;
	while (--n) {
		wc = _fgetwc_unlocked(fp);
		if (wc == EOF) {
			/*
			 * This can happen because of an EOF on
			 * the stream, or because of a decoding error.
			 * Its up to the caller to check errno.
			 */
			if (wsp == ws) {
				/* EOF with no data read */
				FUNLOCKFILE(lk);
				return (NULL);
			}
			break;
		}
		*wsp++ = wc;

		if (wc == L'\n')
			break;
	}
	*wsp = 0;
	FUNLOCKFILE(lk);
	return (ws);
}

wchar_t *
fgetws(wchar_t *_RESTRICT_KYWD ws, int n, FILE *_RESTRICT_KYWD fp)
{
	return (_fgetws_impl(ws, n, fp, 0));
}

wchar_t *
__fgetws_xpg5(wchar_t *ws, int n, FILE *fp)
{
	return (_fgetws_impl(ws, n, fp, 1));
}

wchar_t *
getws(wchar_t *ws)
{
	wint_t wc;
	wchar_t *wsp;
	rmutex_t *lk;

	FLOCKFILE(lk, stdin);

	wsp = ws;
	for (;;) {
		wc = _fgetwc_unlocked(stdin);
		if (wc == EOF) {
			/*
			 * This can happen because of an EOF on
			 * the stream, or because of a decoding error.
			 * Its up to the caller to check errno.
			 */
			if (wsp == ws) {
				/* EOF with no data read */
				FUNLOCKFILE(lk);
				return (NULL);
			}
			break;
		}
		*wsp++ = wc;

		if (wc == L'\n')
			break;
	}
	*wsp = 0;
	FUNLOCKFILE(lk);
	return (ws);
}
