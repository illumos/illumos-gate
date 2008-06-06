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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/types.h>
#include <wchar.h>
#include <limits.h>
#include <string.h>
#include "libc.h"

wchar_t *
wmemcpy(wchar_t *ws1, const wchar_t *ws2, size_t n)
{
	wchar_t	*p1, *p2;
	size_t	len;
	size_t	max = SIZE_MAX / sizeof (wchar_t);

	if (n <= max) {
		return ((wchar_t *)memcpy((void *)ws1,
		    (const void *)ws2, n * sizeof (wchar_t)));
	}

	p1 = ws1;
	p2 = (wchar_t *)ws2;
	do {
		if (n > max) {
			len = max;
		} else {
			len = n;
		}
		(void) memcpy((void *)p1,
		    (const void *)p2, len * sizeof (wchar_t));
		n = n - len;
		p1 += len;
		p2 += len;
	} while (n != 0);
	return (ws1);
}
