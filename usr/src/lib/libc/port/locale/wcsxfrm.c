/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1995 Alex Tatmanjants <alex@elvisti.kiev.ua>
 *		at Electronni Visti IA, Kiev, Ukraine.
 *			All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "lint.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <assert.h>
#include "collate.h"

#define	WCS_XFRM_OFFSET	1

size_t
wcsxfrm_l(wchar_t *_RESTRICT_KYWD dest,
    const wchar_t *_RESTRICT_KYWD src, size_t len, locale_t loc)
{
	size_t slen;
	const struct lc_collate *lcc = loc->collate;

	if (*src == L'\0') {
		if (len != 0)
			*dest = L'\0';
		return (0);
	}

	if ((lcc->lc_is_posix) ||
	    ((slen = _collate_wxfrm(lcc, src, dest, len)) == (size_t)-1)) {
		goto error;
	}

	/* Add null termination at the correct location. */
	if (len > slen) {
		dest[slen] = 0;
	} else if (len != 0) {
		dest[len-1] = 0;
	}

	return (slen);

error:
	slen = wcslen(src);
	if (slen < len)
		(void) wcscpy(dest, src);
	else if (len != 0) {
		(void) wcsncpy(dest, src, len - 1);
		dest[len - 1] = L'\0';
	}
	return (slen);
}

size_t
wcsxfrm(wchar_t *_RESTRICT_KYWD dest,
    const wchar_t *_RESTRICT_KYWD src, size_t len)
{
	return (wcsxfrm_l(dest, src, len, uselocale(NULL)));
}
