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

#include	<stdio.h>
#include	"wish.h"
#include	"menu.h"
#include	"menudefs.h"
#include	"vtdefs.h"
#include	"var_arrays.h"
#include	"ctl.h"

struct menu	*MNU_array;

int
_menu_reshape(m, srow, scol, rows, cols)
register struct menu	*m;
register int	srow;
register int	scol;
register unsigned	rows;
register unsigned	cols;
{
	int	ncols;
	int	nrows;
	register int	oldindex;

	if (rows < 3 || cols < 5) {
		mess_temp("Too small, try again");
		return FAIL;
	}
	vt_reshape(m->vid, srow, scol, rows, cols);
	vt_ctl(m->vid, CTGETSIZ, &nrows, &ncols);
	/* set up m */
	oldindex = m->index;
	m->index = -1;
	m->topline = -MENU_ALL;
	m->flags |= MENU_DIRTY;
	m->hcols = MENU_ALL;
	if (m->dwidth == 0 && m->number > nrows) {
		/* try for multi-column */
		m->ncols = (ncols - 1) / (m->hwidth + 1);
		if (m->ncols * nrows < m->number)
			m->ncols = 1;
	}
	else
		m->ncols = 1;
	menu_index(m, oldindex, MENU_ALL);
	return SUCCESS;
}
