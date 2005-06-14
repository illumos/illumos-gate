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
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

#include	<stdio.h>
#include	"wish.h"
#include	"menu.h"
#include	"menudefs.h"
#include	"vtdefs.h"
#include	"var_arrays.h"
#include	"ctl.h"

struct menu	*MNU_array;

menu_id
menu_custom(vid, flags, mcols, hcols, dcols, total, disp, arg)
vt_id	vid;
unsigned	flags;
unsigned	mcols;
unsigned	hcols;
unsigned	dcols;
unsigned	total;
struct menu_line	(*disp)();
char	*arg;
{
	register int	i;
	int	cols;
	int	dummy;
	register struct menu	*m;

	vt_ctl(vid, CTGETSIZ, &dummy, &cols);
	/* find a free menu structure */
	for (m = MNU_array, i = array_len(MNU_array); i > 0; m++, i--)
		if (!(m->flags & MENU_USED))
			break;
	if (i <= 0) {
		var_append(struct menu, MNU_array, NULL);
		m = &MNU_array[array_len(MNU_array) - 1];
	}
	/* set up m */
	/* "givens" */
	m->vid = vid;
	m->flags = (MENU_DIRTY | MENU_USED | (flags & ALL_MNU_FLAGS));
	m->hwidth = hcols;
	m->dwidth = dcols;
	m->number = total;
	m->disp = disp;
	m->arg = arg;
	m->index = 0;
	m->hcols = MENU_ALL;
	m->topline = -2;	/* to force complete repaint */
	if (mcols < 1)
		mcols = 1;
	m->ncols = mcols;
	return m - MNU_array;
}
