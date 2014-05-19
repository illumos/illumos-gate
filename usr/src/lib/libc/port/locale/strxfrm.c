/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
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
#include <errno.h>
#include <wchar.h>
#include <assert.h>
#include <xlocale.h>
#include "collate.h"

size_t
strxfrm_l(char *_RESTRICT_KYWD xf, const char *_RESTRICT_KYWD src,
    size_t dlen, locale_t loc)
{
	size_t slen;
	size_t xlen;
	wchar_t *wcs = NULL;

	if (!*src) {
		if (dlen > 0)
			*xf = '\0';
		return (0);
	}

	/*
	 * The conversion from multibyte to wide character strings is
	 * strictly reducing (one byte of an mbs cannot expand to more
	 * than one wide character.)
	 */
	slen = strlen(src);

	if (loc->collate->lc_is_posix)
		goto error;

	if ((wcs = malloc((slen + 1) * sizeof (wchar_t))) == NULL)
		goto error;

	if (mbstowcs_l(wcs, src, slen + 1, loc) == (size_t)-1)
		goto error;

	if ((xlen = _collate_sxfrm(wcs, xf, dlen, loc)) == (size_t)-1)
		goto error;

	if (wcs)
		free(wcs);

	if (dlen > xlen) {
		xf[xlen] = 0;
	} else if (dlen) {
		xf[dlen-1] = 0;
	}

	return (xlen);

error:
	/* errno should be set to ENOMEM if malloc failed */
	if (wcs)
		free(wcs);
	(void) strlcpy(xf, src, dlen);

	return (slen);
}

size_t
strxfrm(char *_RESTRICT_KYWD xf, const char *_RESTRICT_KYWD src, size_t dlen)
{
	return (strxfrm_l(xf, src, dlen, uselocale(NULL)));
}
