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


/*
 * Copy string s2 to s1. S1 must be large enough.
 * Return s1.
 */

#pragma weak wcscpy = _wcscpy
#pragma weak wscpy = _wscpy

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

wchar_t *
_wcscpy(wchar_t *s1, const wchar_t *s2)
{
	wchar_t *os1 = s1;

	while (*s1++ = *s2++)
		;
	return (os1);
}

wchar_t *
_wscpy(wchar_t *s1, const wchar_t *s2)
{
	return (_wcscpy(s1, s2));
}
