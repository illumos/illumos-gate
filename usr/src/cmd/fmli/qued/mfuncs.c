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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <curses.h>
/*#include "curses.h"*/
#include "wish.h"
/* #include "vtdefs.h" */
/* #include "token.h" */
#include "fmacs.h"
#include "winp.h"
#include "vt.h"

static void fcopyline(int src, int dest);

int
fdelline(num)
int num;
{
	register int saverow, i;
	register struct vt *v = &VT_array[VT_curid];

	saverow = Cfld->currow;
	if (Cfld->flags & I_FULLWIN) {
		/*
		 * Use the subwindow to delete lines
		 */
		if (v->subwin) {
			wmove(v->subwin, saverow + Cfld->frow, Cfld->fcol);
			winsdelln(v->subwin, -num);
			wsyncup(v->subwin);
		}
		else
			winsdelln (v->win, -num);
	}
	else {
		/*
		 * only a partial window (scroll field)
		 * don't use a subwindow
		 */
		for (i = saverow; i <= LASTROW; i++) {
			if ((i + num) <= LASTROW)
				fcopyline(i + num, i);
			else {
				fgo(i, 0);
				fclearline();
			}
		}
	}
	fgo(saverow, 0);
	return (0);
}

int
finsline(num, after)
int num, after;
{
	register int saverow, start, i;
	register struct vt      *v = &VT_array[VT_curid];

	start = saverow = Cfld->currow;
	if (after == TRUE)
		start++;
	fgo(start, 0);
	if (Cfld->flags & I_FULLWIN) {	
		if (v->subwin) {
			wmove(v->subwin, start + Cfld->frow, Cfld->fcol);
			winsdelln(v->subwin, num);
			wsyncup(v->subwin);
		}
		else
			winsdelln(v->win, num);
	}
	else {
		/*
		 * only a partial window (scroll field)
		 * don't use a subwindow
		 */
		for (i = LASTROW; i >= start; i--) {
		  	if ((i - num) >= start)
				fcopyline(i - num, i);
			else {
				fgo(i, 0);
				fclearline();
			}
		}
	}
	fgo(start, 0);
	return (0);
}

#define STR_SIZE	256

static void
fcopyline(int src, int dest)
{
	register struct vt      *v = &VT_array[VT_curid];
	register int len;
	chtype ch_string[STR_SIZE];

	/*
	 * Call winchnstr() to get a line and
	 * waddchnstr() to copy it to dest
	 */
	fgo (src, 0);
	len = winchnstr(v->win, ch_string, LASTCOL + 1);
	fgo (dest, 0);
	waddchnstr(v->win, ch_string, len);
}
