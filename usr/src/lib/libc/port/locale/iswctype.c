/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
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
#include <locale.h>
#include "runefile.h"
#include "runetype.h"
#include "localeimpl.h"
#include "_ctype.h"

/*
 * Note that the standard requires iswascii to be a macro, so it is defined
 * in our headers.
 *
 * We aliased (per Solaris) iswideogram, iswspecial, iswspecial to the
 * equivalent values without "w".  The Solaris specific function isenglish()
 * is here, but does not get an isw* equivalent.
 *
 * Note that various code assumes that "numbers" (iswdigit, iswxdigit)
 * only return true for characters in the portable set.  While the assumption
 * is not technically correct, it turns out that for all of our locales this
 * is true.  iswhexnumber is aliased to iswxdigit.
 */

static int
__istype_l(locale_t loc, wint_t c, unsigned int f)
{
	unsigned int rt;

	if (c < 0 || c >= _CACHED_RUNES)
		rt = __runetype(loc->runelocale, c);
	else
		rt = loc->runelocale->__runetype[c];
	return (rt & f);
}

static int
__istype(wint_t c, unsigned int f)
{
	return (__istype_l(uselocale(NULL), c, f));
}

int
iswctype_l(wint_t wc, wctype_t class, locale_t loc)
{
	if (iswascii(wc))
		return (__ctype_mask[wc] & class);
	return (__istype_l(loc, wc, class));
}

#undef iswctype
int
iswctype(wint_t wc, wctype_t class)
{
	/*
	 * Note that we don't just call iswctype_l because we optimize for
	 * the iswascii() case, so that most of the time we have no need to
	 * call uselocale().
	 */
	if (iswascii(wc))
		return (__ctype_mask[wc] & class);
	return (__istype(wc, class));
}

/*
 * This is a legacy version, baked into binaries.
 */
#undef _iswctype
unsigned
_iswctype(wchar_t wc, int class)
{
	if (iswascii(wc))
		return (__ctype_mask[wc] & class);
	return (__istype((wint_t)wc, (unsigned int)class));
}

#define	DEFN_ISWTYPE(type, mask)		\
int						\
isw##type##_l(wint_t wc, locale_t loc)		\
{						\
	return (iswascii(wc) ?			\
		(__ctype_mask[wc] & (mask)) :	\
		__istype_l(loc, wc, mask));	\
}						\
						\
int						\
isw##type(wint_t wc)				\
{						\
	return (iswascii(wc) ?			\
		(__ctype_mask[wc] & (mask)) :	\
		__istype(wc, mask));		\
}

/* kill off any macros */
#undef	iswalnum
#undef	iswalpha
#undef	iswblank

DEFN_ISWTYPE(alnum, _CTYPE_A|_CTYPE_D)
DEFN_ISWTYPE(alpha, _CTYPE_A)
DEFN_ISWTYPE(blank, _CTYPE_B)
DEFN_ISWTYPE(cntrl, _CTYPE_C)
DEFN_ISWTYPE(digit, _CTYPE_D)
DEFN_ISWTYPE(graph, _CTYPE_D)
DEFN_ISWTYPE(lower, _CTYPE_L)
DEFN_ISWTYPE(upper, _CTYPE_U)
DEFN_ISWTYPE(print, _CTYPE_R)
DEFN_ISWTYPE(punct, _CTYPE_P)
DEFN_ISWTYPE(space, _CTYPE_S)
DEFN_ISWTYPE(xdigit, _CTYPE_X)
DEFN_ISWTYPE(ideogram, _CTYPE_I)
DEFN_ISWTYPE(phonogram, _CTYPE_Q)
DEFN_ISWTYPE(special, _CTYPE_T)
DEFN_ISWTYPE(number, _CTYPE_N)


#undef iswhexnumber
#pragma weak iswhexnumber = iswxdigit
#pragma weak iswhexnumber_l = iswxdigit_l

#undef isideogram
#pragma weak isideogram = iswideogram

#undef isphonogram
#pragma weak isphonogram = iswphonogram

#undef isspecial
#pragma weak isspecial = iswspecial

#undef isnumber
#pragma weak isnumber = iswnumber

/*
 * FreeBSD has iswrune() for use by external programs, and this is used by
 * the "tr" program.  As that program is part of our consolidation, we
 * provide an _ILLUMOS_PRIVATE version of this function that we can use.
 *
 * No programs that are not part of the illumos stack itself should use
 * this function -- programs that do reference will not be portable to
 * other versions of SunOS or Solaris.
 */
int
__iswrune(wint_t wc)
{
	/*
	 * Note, FreeBSD ignored the low order byte, as they encode their
	 * ctype values differently.  We can't do that (ctype is baked into
	 * applications), but instead can just check if *any* bit is set in
	 * the ctype.  Any bit being set indicates its a valid rune.
	 *
	 * NB: For ASCII all positions except NULL are runes.
	 */
	return (wc == 0 ? 0 : iswascii(wc) ? 1 : __istype(wc, 0xffffffffU));
}

/*
 * isenglish is a Solaris legacy.  No isw* equivalent.  Note that this most
 * likely doesn't work, as the locale data we have doesn't include it.  It
 * specifically is only valid for non-ASCII characters.  We're not sure this
 * is in actual use in the wild.
 */
#undef isenglish
int
isenglish(wint_t wc)
{
	return (__istype(wc, _CTYPE_E));
}
