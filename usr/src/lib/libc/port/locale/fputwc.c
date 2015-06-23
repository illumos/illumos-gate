/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
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

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include "file64.h"
#include "mtlib.h"
#include "mse_int.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <synch.h>
#include "mblocal.h"
#include "stdiom.h"
#include "mse.h"

#pragma weak	_putwc = putwc

/*
 * FreeBSD had both a MT safe and non-MT safe version.  For whatever reason,
 * we don't need the non-MT safe version.  We do this because its faster,
 * since we don't have to lock the file while doing the potentially expensive
 * conversion from wide to mb.
 *
 * Solaris also has XPG5 and legacy semantics.  The new standard requires
 * that the stream orientation change, but legacy calls don't do that.
 *
 * Note that we had the source for the XPG5 version of this, but it relied
 * on closed implementation bits that we lack, so we supply replacements
 * here.
 */
static wint_t
__fputwc_impl(wchar_t wc, FILE *fp, int orient)
{
	char buf[MB_LEN_MAX];
	size_t		i, len;
	rmutex_t	*mx;

	/* If we are given WEOF, then we have to stop */
	if (wc == WEOF)
		return (WEOF);

	if (MB_CUR_MAX == 1 && wc > 0 && wc <= UCHAR_MAX) {
		/*
		 * Assume single-byte locale with no special encoding.
		 */
		*buf = (unsigned char)wc;
		len = 1;
	} else {
		/*
		 * FreeBSD used restartable wcrtomb.  I think we can use
		 * the simpler wctomb form here.  We should have a complete
		 * decode.
		 */
		if ((len = wctomb(buf, wc)) == (size_t)-1) {
			fp->_flag |= _IOERR;
			errno = EILSEQ;
			return (WEOF);
		}
	}

	FLOCKFILE(mx, fp);
	/*
	 * This is used for XPG 5 semantics, which requires the stream
	 * orientation to be changed when the function is called.
	 */
	if (orient && GET_NO_MODE(fp)) {
		_setorientation(fp, _WC_MODE);
	}
	for (i = 0; i < len; i++) {
		if (PUTC((unsigned char)buf[i], fp) == EOF) {
			FUNLOCKFILE(mx);
			return (WEOF);
		}
	}
	FUNLOCKFILE(mx);
	return ((wint_t)wc);
}

wint_t
fputwc(wchar_t wc, FILE *fp)
{
	return (__fputwc_impl(wc, fp, 0));
}

/*
 * Trivial functional form of the typical macro.
 */
#undef __putwc
wint_t
putwc(wchar_t wc, FILE *fp)
{
	return (__fputwc_impl(wc, fp, 0));
}

wint_t
__fputwc_xpg5(wint_t wc, FILE *fp)
{
	return (__fputwc_impl(wc, fp, 1));
}

#undef __putwc_xpg5
wint_t
__putwc_xpg5(wint_t wc, FILE *fp)
{
	return (__fputwc_impl(wc, fp, 1));
}
