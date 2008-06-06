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
 * Compare strings:  s1>s2: >0  s1==s2: 0  s1<s2: <0
 */

#pragma weak _wcscmp = wcscmp
#pragma weak _wscmp = wscmp

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

int
wcscmp(const wchar_t *s1, const wchar_t *s2)
{
	if (s1 == s2)
		return (0);

	while (*s1 == *s2++)
		if (*s1++ == 0)
			return (0);
	return (*s1 - *(s2 - 1));
}

int
wscmp(const wchar_t *s1, const wchar_t *s2)
{
	return (wcscmp(s1, s2));
}
