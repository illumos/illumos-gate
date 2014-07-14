/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "lint.h"
#include <wchar.h>
#include "_ctype.h"
#include "runetype.h"
#include "localeimpl.h"

#undef wcwidth

int
wcwidth_l(wchar_t wc, locale_t loc)
{
	unsigned int x;
	const _RuneLocale *rl = loc->runelocale;

	if (wc == 0)
		return (0);

	x = ((wc < 0 || wc >= _CACHED_RUNES) ? __runetype(rl, wc) :
	    rl->__runetype[wc]) & (_CTYPE_SWM|_CTYPE_R);

	if ((x & _CTYPE_SWM) != 0)
		return ((x & _CTYPE_SWM) >> _CTYPE_SWS);
	return ((x & _CTYPE_R) != 0 ? 1 : -1);
}

int
wcwidth(wchar_t wc)
{
	return (wcwidth_l(wc, uselocale(NULL)));
}

#pragma weak _scrwidth = scrwidth

/*
 * This is a Solaris extension.  It never returns a negative width, even for
 * non-printable characters.  It is used internally by the printf
 * implementation for %ws.
 */
int
scrwidth(wchar_t wc)
{
	int	v = wcwidth(wc);
	return (v > 0 ? v : 0);
}
