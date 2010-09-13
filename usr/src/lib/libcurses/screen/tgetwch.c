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

#include	<sys/types.h>
#include	"curses_inc.h"

/*
 *	Read a process code from the terminal
 *	cntl:	= 0 for single-char key only
 *		= 1 for matching function key and macro patterns.
 *		= 2 same as 1 but no time-out for funckey matching.
 */

wchar_t
tgetwch(int cntl)
{
	int	c, n, type, width;
	char	buf[CSMAX];
	wchar_t	wchar;

	/* get the first byte */
	/* LINTED */
	if ((c = (int)tgetch(cntl)) == ERR)
		return (ERR);

	type = TYPE(c);
	width = cswidth[type] - ((type == 1 || type == 2) ? 0 : 1);
	/* LINTED */
	buf[0] = (char)c;
	for (n = 1; n < width; ++n) {
		/* LINTED */
		if ((c = (int)tgetch(cntl)) == ERR)
			return (ERR);
		if (TYPE(c) != 0)
			return (ERR);
		/* LINTED */
		buf[n] = (char)c;
		}

	/* translate it to process code */
	(void) _curs_mbtowc(&wchar, buf, n);
	return (wchar);
}
