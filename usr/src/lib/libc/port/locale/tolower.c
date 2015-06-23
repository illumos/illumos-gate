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
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */
#include "lint.h"
#include <ctype.h>
#include <locale.h>
#include "localeimpl.h"
#include "lctype.h"

#pragma weak _tolower = tolower
#pragma weak _toupper = toupper

int
tolower_l(int c, locale_t loc)
{
	return (((unsigned)c > 255) ? c : loc->ctype->lc_trans_lower[c]);
}

int
toupper_l(int c, locale_t loc)
{
	return (((unsigned)c > 255) ? c : loc->ctype->lc_trans_upper[c]);
}

#undef tolower
int
tolower(int c)
{
	return (isascii(c) ? __trans_lower[c] : tolower_l(c, uselocale(NULL)));
}

#undef toupper
int
toupper(int c)
{
	return (isascii(c) ? __trans_upper[c] : toupper_l(c, uselocale(NULL)));
}
