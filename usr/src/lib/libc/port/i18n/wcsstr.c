/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/types.h>
#include <wchar.h>
#include "libc.h"

wchar_t *
wcsstr(const wchar_t *ws1, const wchar_t *ws2)
{
	const wchar_t	*os1, *os2;
	const wchar_t	*tptr;
	wchar_t	c;

	os1 = ws1;
	os2 = ws2;

	if (os1 == NULL || *os2 == L'\0')
		return ((wchar_t *)os1);
	c = *os2;

	while (*os1)
		if (*os1++ == c) {
			tptr = os1;
			while (((c = *++os2) == *os1++) && (c != L'\0'))
				;
			if (c == L'\0')
				return ((wchar_t *)tptr - 1);
			os1 = tptr;
			os2 = ws2;
			c = *os2;
		}
	return (NULL);
}
