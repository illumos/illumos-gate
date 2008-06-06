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
 * Concatenate s2 on the end of s1. S1's space must be large enough.
 * At most n characters are moved.
 * return s1.
 */

#pragma weak _wcsncat = wcsncat
#pragma weak _wsncat = wsncat

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

wchar_t *
wcsncat(wchar_t *s1, const wchar_t *s2, size_t n)
{
	wchar_t *os1 = s1;

	while (*s1++) /* find end of s1 */
		;
	++n;
	--s1;
	while (*s1++ = *s2++) /* copy s2 to s1 */
		if (--n == 0) {  /* at most n chars */
			*--s1 = 0;
			break;
		}
	return (os1);
}

wchar_t *
wsncat(wchar_t *s1, const wchar_t *s2, size_t n)
{
	return (wcsncat(s1, s2, n));
}
