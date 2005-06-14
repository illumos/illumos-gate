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
 *	Insert to 'win' a process code at(curx, cury).
 */
int
winswch(WINDOW *win, chtype c)
{
	int	i, width;
	char	buf[CSMAX];
	chtype	a;
	wchar_t	code;
	a = c & A_WATTRIBUTES;
	code = c & A_WCHARTEXT;

	/* translate the process code to character code */
	if ((width = _curs_wctomb(buf, code & TRIM)) < 0)
		return (ERR);

	/* now call winsch to do the real work */
	for (i = 0; i < width; ++i)
		if (winsch(win, a|(unsigned char)buf[i]) == ERR)
			return (ERR);
	return (OK);
}
