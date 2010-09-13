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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Convert longs to and from 3-byte disk addresses
 */
#pragma weak _l3tol = l3tol
#pragma weak _ltol3 = ltol3

#include "lint.h"

void
ltol3(char *cp, const long *lp, int n)
{
	register i;
	register char *a, *b;

	a = cp;
	b = (char *)lp;
	for (i = 0; i < n; ++i) {
#if interdata || u370 || u3b || M32
		b++;
		*a++ = *b++;
		*a++ = *b++;
		*a++ = *b++;
#endif
#if vax || i286 || i386
		*a++ = *b++;
		*a++ = *b++;
		*a++ = *b++;
		b++;
#endif
#if pdp11
		*a++ = *b++;
		b++;
		*a++ = *b++;
		*a++ = *b++;
#endif
	}
}

void
l3tol(long *lp, const char *cp, int n)
{
	register i;
	register char *a, *b;

	a = (char *)lp;
	b = cp;
	for (i = 0; i < n; ++i) {
#if interdata || u370 || u3b || M32
		*a++ = 0;
		*a++ = *b++;
		*a++ = *b++;
		*a++ = *b++;
#endif
#if vax || i286 || i386
		*a++ = *b++;
		*a++ = *b++;
		*a++ = *b++;
		*a++ = 0;
#endif
#if pdp11
		*a++ = *b++;
		*a++ = 0;
		*a++ = *b++;
		*a++ = *b++;
#endif
	}
}
