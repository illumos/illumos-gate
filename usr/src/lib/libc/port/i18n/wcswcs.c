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
 * Returns a pointer to the first occurrnce of ws1 in ws2.
 */

#pragma weak _wcswcs = wcswcs

#include "lint.h"
#include <stdlib.h>

wchar_t *
wcswcs(const wchar_t *ws1, const wchar_t *ws2)
{
	const wchar_t *s1, *s2;
	const wchar_t *tptr;
	wchar_t c;

	s1 = ws1;
	s2 = ws2;

	if (s2 == NULL || *s2 == 0)
		return ((wchar_t *)s1);
	c = *s2;

	while (*s1)
		if (*s1++ == c) {
			tptr = s1;
			while ((c = *++s2) == *s1++ && c)
				;
			if (c == 0)
				return ((wchar_t *)tptr - 1);
			s1 = tptr;
			s2 = ws2;
			c = *s2;
		}
	return (NULL);
}
