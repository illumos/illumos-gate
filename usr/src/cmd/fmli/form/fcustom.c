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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5 */

#include <stdio.h>
#include <curses.h>
#include "wish.h"
#include	"token.h"
#include	"winp.h"
#include	"form.h"
#include "var_arrays.h"

form_id
form_custom(vid, flags, rows, cols, disp, ptr)
vt_id vid;
unsigned flags;
int rows, cols;
formfield (*disp)();
char *ptr;
{
	register int	num;
	register struct form	*f;

	/* find a free form structure */
	for (f = FORM_array, num = array_len(FORM_array); num > 0; f++, num--)
		if (!(f->flags & FORM_USED))
			break;
	if (num <= 0) {
		var_append(struct form, FORM_array, NULL);
		f = &FORM_array[array_len(FORM_array) - 1];
	}
	/* set up f */
	f->display = disp;
	f->argptr = ptr;
	f->flags = FORM_USED | FORM_DIRTY;
	f->vid = vid;
	f->curfldnum = 0;
	f->rows = rows;
	f->cols = cols;

	return(f - FORM_array);
}
