/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
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

#include "lint.h"
#include <wctype.h>
#include <stdio.h>
#include "localeimpl.h"
#include "lctype.h"
#include "runetype.h"

static wint_t
change_case_ext(locale_t loc, wint_t c, int lower)
{
	const _RuneLocale *rl;
	const _RuneRange *rr;
	const _RuneEntry *base, *re;
	size_t lim;

	if (c < 0 || c == EOF)
		return (c);

	rl = loc->runelocale;
	rr = lower ? &rl->__maplower_ext : &rl->__mapupper_ext;
	/* Binary search -- see bsearch.c for explanation. */
	base = rr->__ranges;
	for (lim = rr->__nranges; lim != 0; lim >>= 1) {
		re = base + (lim >> 1);
		if (re->__min <= c && c <= re->__max) {
			return (re->__map + c - re->__min);
		} else if (c > re->__max) {
			base = re + 1;
			lim--;
		}
	}

	return (c);
}

wint_t
towlower_l(wint_t wc, locale_t loc)
{
	return (iswascii(wc) ? __trans_lower[wc] :
	    (wc < 0 || wc >= _CACHED_RUNES) ?
	    change_case_ext(loc, wc, 1) :
	    loc->runelocale->__maplower[wc]);
}

#undef towlower
wint_t
towlower(wint_t wc)
{
	return (iswascii(wc) ? __trans_lower[wc] :
	    (wc < 0 || wc >= _CACHED_RUNES) ?
	    change_case_ext(uselocale(NULL), wc, 1) :
	    uselocale(NULL)->runelocale->__maplower[wc]);
}

wint_t
towupper_l(wint_t wc, locale_t loc)
{
	return (iswascii(wc) ? __trans_upper[wc] :
	    (wc < 0 || wc >= _CACHED_RUNES) ?
	    change_case_ext(loc, wc, 0) :
	    loc->runelocale->__mapupper[wc]);
}

#undef towupper
wint_t
towupper(wint_t wc)
{
	return (iswascii(wc) ? __trans_upper[wc] :
	    (wc < 0 || wc >= _CACHED_RUNES) ?
	    change_case_ext(uselocale(NULL), wc, 0) :
	    uselocale(NULL)->runelocale->__mapupper[wc]);
}
