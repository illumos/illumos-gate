/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 */

#include "lint.h"
#include <locale.h>
#include "localeimpl.h"
#include "lctype.h"
#include "mblocal.h"

int
mbsinit_l(const mbstate_t *s, locale_t loc)
{

	/*
	 * To implement support for the C11 char16_t conversion functions
	 * (mbrtoc16() and c16rtomb()) we opted to leverage all of the existing
	 * conversion infrastructure, including the per-locale conversion
	 * structures. The char16_t conversion functions tack an extra member in
	 * the mbstate_t that occurs after all others have placed their data.
	 * Therefore, before we go to the per-locale backend we need to see if
	 * there is any outstanding state in the char16_t specific state.
	 */
	if (s != NULL) {
		const _CHAR16State *c16s = (const _CHAR16State *)s;
		if (c16s->c16_surrogate != 0) {
			return (0);
		}
	}

	return (loc->ctype->lc_mbsinit(s));
}

int
mbsinit(const mbstate_t *s)
{
	return (mbsinit_l(s, uselocale(NULL)));
}
