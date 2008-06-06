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
 * Return ptr to first occurance of any character from 'brkset'
 * in the wchar_t array 'string'; NULL if none exists.
 */

#pragma weak _wcspbrk = wcspbrk
#pragma weak _wspbrk = wspbrk

#include "lint.h"
#include <stdlib.h>
#include <wchar.h>

wchar_t *
wcspbrk(const wchar_t *string, const wchar_t *brkset)
{
	const wchar_t *p;

	do {
		for (p = brkset; *p && *p != *string; ++p)
			;
		if (*p)
			return ((wchar_t *)string);
	} while (*string++);
	return (NULL);
}

wchar_t *
wspbrk(const wchar_t *string, const wchar_t *brkset)
{
	return (wcspbrk(string, brkset));
}
