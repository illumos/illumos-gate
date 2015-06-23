/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
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
#include "mtlib.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "mblocal.h"
#include "stdiom.h"
#include "localeimpl.h"
#include "lctype.h"

/*
 * Non-MT-safe version.
 */
wint_t
_fgetwc_unlocked_l(FILE *fp, locale_t loc)
{
	wchar_t wc;
	size_t nconv;
	int	c;
	mbstate_t	*statep;
	const struct lc_ctype *lct;

	if ((c = GETC(fp)) == EOF)
		return (WEOF);

	lct = loc->ctype;
	if (lct->lc_max_mblen == 1) {
		/* Fast path for single-byte encodings. */
		return ((wint_t)c);
	}
	if ((statep = _getmbstate(fp)) == NULL) {
		fp->_flag = _IOERR;
		errno = EBADF;
		return (WEOF);
	}
	do {
		char	x = (char)c;
		nconv = lct->lc_mbrtowc(&wc, &x, 1, statep);
		if (nconv == (size_t)-1) {
			break;
		} else if (nconv == (size_t)-2) {
			/* Incompletely decoded, consume another char */
			continue;
		} else if (nconv == 0) {
			/*
			 * Assume that the only valid representation of
			 * the null wide character is a single null byte.
			 */
			return (L'\0');
		} else {
			return (wc);
		}
	} while ((c = GETC(fp)) != EOF);

	/*
	 * If we got here it means we got truncated in a character, or
	 * the character did not decode properly.  Note that in the case
	 * of a botched decoding, we don't UNGETC the bad bytes.  Should
	 * we?
	 */
	fp->_flag |= _IOERR;
	errno = EILSEQ;
	return (WEOF);
}

wint_t
_fgetwc_unlocked(FILE *fp)
{
	return (_fgetwc_unlocked_l(fp, uselocale(NULL)));
}


/*
 * MT safe version
 */
#undef getwc
#pragma weak getwc = fgetwc
wint_t
fgetwc(FILE *fp)
{
	wint_t		r;
	rmutex_t	*l;
	locale_t	loc = uselocale(NULL);

	FLOCKFILE(l, fp);
	r = _fgetwc_unlocked_l(fp, loc);
	FUNLOCKFILE(l);

	return (r);
}

/*
 * XPG5 version.
 */
#undef	__getwc_xpg5
#pragma weak __getwc_xpg5 = __fgetwc_xpg5
wint_t
__fgetwc_xpg5(FILE *fp)
{
	wint_t		r;
	rmutex_t	*l;
	locale_t	loc = uselocale(NULL);

	FLOCKFILE(l, fp);
	if (GET_NO_MODE(fp))
		_setorientation(fp, _WC_MODE);
	r = _fgetwc_unlocked_l(fp, loc);
	FUNLOCKFILE(l);

	return (r);
}

#pragma weak getwc_l = fgetwc_l
wint_t
fgetwc_l(FILE *fp, locale_t loc)
{
	wint_t		r;
	rmutex_t	*l;
	FLOCKFILE(l, fp);
	if (GET_NO_MODE(fp))
		_setorientation(fp, _WC_MODE);
	r = _fgetwc_unlocked_l(fp, loc);
	FUNLOCKFILE(l);

	return (r);
}
