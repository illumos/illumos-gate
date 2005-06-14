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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

#include <stdio.h>
#include <curses.h>
#include "token.h"
#include "winp.h"
#include "fmacs.h"

/*
 * FCLEAR will clear the field from the current cursor position to
 * the end of the field
 */
fclear()
{
	register int row, col;
	register int saverow, savecol;

	saverow = Cfld->currow;
	savecol = Cfld->curcol;
	for (row = saverow, col = savecol; row <= LASTROW; row++, col = 0) {
		fgo(row, col);
		for (; col <= LASTCOL; col++)
			fputchar(' ');
	}
	fgo(saverow, savecol);
}

fclearline()
{
	register int col, savecol;

	savecol = Cfld->curcol;
	for (col = savecol; col <= LASTCOL; col++)
		fputchar(' ');
	fgo(Cfld->currow, savecol);
}
