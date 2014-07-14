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

int
mbsinit_l(const mbstate_t *s, locale_t loc)
{
	return (loc->ctype->lc_mbsinit(s));
}

int
mbsinit(const mbstate_t *s)
{
	return (mbsinit_l(s, uselocale(NULL)));
}
