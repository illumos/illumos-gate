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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<curses.h>
#include	<term.h>
#include	"wish.h"
#include	"vt.h"
#include	"vtdefs.h"
#include	"color_pair.h"

/*
 * reshape a VT
 */
int
vt_reshape(vid, srow, scol, rows, cols)
vt_id	vid;
int	srow;
int	scol;
unsigned	rows;
unsigned	cols;
{
	register struct vt	*v;
	extern int	VT_firstline;

	if (off_screen(srow, scol, rows, cols)) {
#ifdef _DEBUG
		_debug(stderr, "off_screen FAILED!!!  This should never happen here!!!\n");
#endif
		return FAIL;
	}
	srow += VT_firstline;
	/* pick a window number (if appropriate) */
	v = &VT_array[vid];
	/* set up v */
	_vt_hide(vid, TRUE);
	if ((v->win = newwin(rows, cols, srow, scol)) == NULL) {
#ifdef _DEBUG
		_debug(stderr, "newwin\n");
#endif
		return FAIL;
	}
	notimeout(v->win, TRUE);
	if (v->subwin) {
		if ((v->subwin = subwin(v->win, rows-2, cols-2, srow+1, scol+1)) == NULL) {
#ifdef _DEBUG3
			_debug3(stderr, "subwin\n");
#endif
			return FAIL;
	    	}
		notimeout(v->subwin, TRUE);
	}
 	if (Color_terminal == TRUE) {
 		wbkgd(v->win, COL_ATTR(0, WINDOW_PAIR));
 		wattrset(v->win, COL_ATTR(0, WINDOW_PAIR));
 	}
	keypad(v->win, TRUE);
	if (v->flags & VT_NOBORDER)
		wmove(v->win, 0, 0);
	else
		wmove(v->win, 1, 1);
	v->flags |= VT_ANYDIRTY;
	vt_current(vid);
	return SUCCESS;
}
