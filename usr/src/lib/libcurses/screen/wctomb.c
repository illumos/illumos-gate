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
/*  Copyright (c) 1988 AT&T */
/*    All Rights Reserved   */


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <widec.h>
#include <ctype.h>
#include "curses_wchar.h"

int
_curs_wctomb(char *s, wchar_t wchar)
{
	char *olds = s;
	int size, index;
	unsigned char d;
	if (!s)
		return (0);
	if (wchar <= 0177 || (wchar <= 0377 && (iscntrl((int)wchar) != 0)))  {
		/* LINTED */
		*s++ = (char)wchar;
		return (1);
	}
	switch (wchar & EUCMASK) {

		case P11:
			size = eucw1;
			break;

		case P01:
			/* LINTED */
			*s++ = (char)SS2;
			size = eucw2;
			break;

		case P10:
			/* LINTED */
			*s++ = (char)SS3;
			size = eucw3;
			break;

		default:
			return (-1);
	}
	if ((index = size) <= 0)
		return (-1);
	while (index--) {
		/* LINTED */
		d = wchar | 0200;
		wchar >>= 7;
		if (iscntrl(d))
			return (-1);
		s[index] = d;
	}
	/* LINTED */
	return ((int)(s - olds) + size);
}
