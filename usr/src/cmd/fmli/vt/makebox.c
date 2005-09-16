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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<curses.h>
#include	"wish.h"
#include	"vt.h"
#include	"vtdefs.h"
#include	"attrs.h"

#define TL	0
#define BL	1
#define BR	2
#define TR	3

static vt_id	side[4] = { -1, -1, -1, -1 };
static bool corner(int which, int row, int col, chtype ch, int flag);
static void remove_box(void);

bool
make_box(flag, srow, scol, rows, cols)
bool	flag;
register int	srow;
register int	scol;
register int	rows;
register int	cols;
{
	if (srow < 0 || scol < 0 || cols < 1 || rows < 1) {
		remove_box();
		return FALSE;
	}
	if (side[TL] >= 0)
		remove_box();
	rows--;
	cols--;
	if (!corner(TL, srow, scol, ACS_ULCORNER, flag))
		return FALSE;
	if (!corner(BL, srow + rows, scol, ACS_LLCORNER, TRUE))
		return FALSE;
	if (!corner(BR, srow + rows, scol + cols, ACS_LRCORNER, !flag))
		return FALSE;
	if (!corner(TR, srow, scol + cols, ACS_URCORNER, TRUE))
		return FALSE;
	if (flag)
	    vt_current(side[BR]);
	else
	    vt_current(side[TL]);
/*	vt_current(side[flag ? BR : TL]); amdahl compatibility */
	return TRUE;
}

static bool
corner(int which, int row, int col, chtype ch, int flag)
{
	register vt_id	vid;
	register struct vt	*v;

	if ((vid = side[which] = vt_create(NULL, VT_NONUMBER | VT_NOBORDER, row, col, 1, 1)) < 0) {
		remove_box();
		return FALSE;
	}
	vt_current(vid);
	v = &VT_array[vid];
	scrollok(v->win, FALSE);
	if (flag)
		waddch(v->win, ch | Attr_visible);
	else
		waddch(v->win, ch);
	v->flags |= VT_DIRTY;
	return TRUE;
}

static void
remove_box(void)
{
	register int	i;

	for (i = 0; i < 4; i++) {
		if (side[i] >= 0)
			vt_close(side[i]);
		side[i] = -1;
	}
}
