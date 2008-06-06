/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * uses wcspbrk and wcsspn to break string into tokens on
 * sequentially subsequent calls. returns WNULL when no
 * non-separator characters remain.
 * 'subsequent' calls are calls with first argument WNULL.
 */

#pragma weak _wstok = wstok

#include "lint.h"
#include "mtlib.h"
#include "mse_int.h"
#include <stdlib.h>
#include <wchar.h>
#include <thread.h>
#include "libc.h"
#include "tsd.h"

#ifndef WNULL
#define	WNULL	(wchar_t *)0
#endif

wchar_t *
__wcstok_xpg5(wchar_t *string, const wchar_t *sepset, wchar_t **ptr)
{
	wchar_t *q, *r;

	/* first or subsequent call */
	if ((string == WNULL && (string = *ptr) == 0) ||
	    (((q = string + wcsspn(string, sepset)) != WNULL) && *q == L'\0'))
		return (WNULL);

	/* sepset becomes next string after separator */
	if ((r = wcspbrk(q, sepset)) == WNULL)	/* move past token */
		*ptr = 0;	/* indicate this is last token */
	else {
		*r = L'\0';
		*ptr = r + 1;
	}
	return (q);
}


wchar_t *
wcstok(wchar_t *string, const wchar_t *sepset)
{
	wchar_t **lasts = tsdalloc(_T_WCSTOK, sizeof (wchar_t *), NULL);

	if (lasts == NULL)
		return (NULL);
	return (__wcstok_xpg5(string, sepset, lasts));
}

wchar_t *
wstok(wchar_t *string, const wchar_t *sepset)
{
	return (wcstok(string, sepset));
}
