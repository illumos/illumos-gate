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

#include <widec.h>
#include <limits.h>
#include <sys/types.h>
#include "curses_inc.h"

size_t
_curs_wcstombs(char *s, const wchar_t *pwcs, size_t n)
{
	int	val;
	int	total = 0;
	char	temp[MB_LEN_MAX];
	int	i;

	for (; ; ) {
		if (*pwcs == 0) {
			*s = '\0';
			break;
		}
		if ((val = _curs_wctomb(temp, *pwcs++)) == -1)
			return (val);
		if ((total += val) > n) {
			total -= val;
			break;
		}
		for (i = 0; i < val; i++)
			*s++ = temp[i];
	}
	return (total);
}
