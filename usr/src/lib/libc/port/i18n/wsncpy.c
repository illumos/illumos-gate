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

/*	Copyright (c) 1986 AT&T	*/
/*	  All Rights Reserved  	*/


/*	This module is created for NLS on Sep.03.86		*/

/*
 * Copy s2 to s1, truncating or null-padding to always copy n characters.
 * Return s1.
 */

#pragma weak wcsncpy = _wcsncpy
#pragma weak wsncpy = _wsncpy

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

wchar_t *
_wcsncpy(wchar_t *s1, const wchar_t *s2, size_t n)
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
_wsncpy(wchar_t *s1, const wchar_t *s2, size_t n)
{
	return (_wcsncpy(s1, s2, n));
}
