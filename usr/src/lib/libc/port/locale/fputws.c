/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "mblocal.h"
#include "stdiom.h"

static int
_fputws_impl(const wchar_t *_RESTRICT_KYWD ws, FILE *_RESTRICT_KYWD fp,
    int orient)
{
	int nchars;
	int nwritten;
	char buf[BUFSIZ];
	rmutex_t *lk;

	/*
	 * The FreeBSD implementation here was a bit more complex, because
	 * it repeated much of what is in fputs.  For simplicity's sake, we
	 * juse wctomb to convert the wide string to a mbs, and then use
	 * fputs to print the mbs.
	 */

	nchars = wcslen(ws);
	nwritten = 0;

	FLOCKFILE(lk, fp);
	if (orient && GET_NO_MODE(fp))
		_setorientation(fp, _WC_MODE);

	while (nchars > 0) {
		int nbytes = 0;
		char *ptr = buf;
		while ((nbytes < (BUFSIZ - (MB_LEN_MAX * 2))) && nchars) {
			int n;
			if ((n = wctomb(ptr, *ws)) < 0) {
				FUNLOCKFILE(lk);
				fp->_flag |= _IOERR;
				errno = EILSEQ;
				return (EOF);
			}
			ws++;
			ptr += n;
			nbytes += n;
			nchars--;
		}
		*ptr = '\0';
		if (fputs(buf, fp) < nbytes) {
			FUNLOCKFILE(lk);
			return (EOF);
		}
		nwritten += nbytes;
	}
	FUNLOCKFILE(lk);
	return (nwritten);
}

int
fputws(const wchar_t *_RESTRICT_KYWD ws, FILE *_RESTRICT_KYWD fp)
{
	return (_fputws_impl(ws, fp, 0));
}

int
__fputws_xpg5(const wchar_t *ws, FILE *fp)
{
	return (_fputws_impl(ws, fp, 1));
}
