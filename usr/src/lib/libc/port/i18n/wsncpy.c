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
 * Copy s2 to s1, truncating or null-padding to always copy n characters.
 * Return s1.
 */

#pragma weak _wcsncpy = wcsncpy
#pragma weak _wsncpy = wsncpy

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

wchar_t *
wcsncpy(wchar_t *s1, const wchar_t *s2, size_t n)
{
	wchar_t *os1 = s1;

	n++;
	while ((--n > 0) && ((*s1++ = *s2++) != 0))
		;
	if (n > 0)
		while (--n > 0)
			*s1++ = 0;
	return (os1);
}

wchar_t *
wsncpy(wchar_t *s1, const wchar_t *s2, size_t n)
{
	return (wcsncpy(s1, s2, n));
}
