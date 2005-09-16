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
#include	"wish.h"
#include	"vt.h"
#include	"vtdefs.h"

/*
 * moves a vt to row, col
 */
int
vt_move(newrow, newcol)
unsigned	newrow;
unsigned	newcol;
{
	register struct vt	*v;
	int	n;
	int	row;
	int	col;
	extern unsigned	VT_firstline;

	n = VT_curid;
	v = &VT_array[n];
	getmaxyx(v->win, row, col);
	if (off_screen(newrow, newcol, row, col))
		return FAIL;
	_vt_hide(n, FALSE);
	mvwin(v->win, newrow + VT_firstline, newcol);
	vt_current(n);
	return TRUE;
}
