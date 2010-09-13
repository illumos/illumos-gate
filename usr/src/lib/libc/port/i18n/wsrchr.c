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
 * Return the ptr in sp at which the character c last appears;
 * Null if not found.
 */

#pragma weak _wcsrchr = wcsrchr
#pragma weak _wsrchr = wsrchr

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

wchar_t *
wcsrchr(const wchar_t *sp, wchar_t c)
{
	const wchar_t *r = NULL;

	do {
		if (*sp == c)
			r = sp; /* found c in sp */
	} while (*sp++);
	return ((wchar_t *)r);
}

wchar_t *
wsrchr(const wchar_t *sp, wchar_t c)
{
	return (wcsrchr(sp, c));
}
