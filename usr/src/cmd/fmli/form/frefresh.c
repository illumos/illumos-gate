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

#include <stdio.h>
#include <curses.h>
#include "wish.h"
#include "token.h"
#include "winp.h"
#include "form.h"
#include "attrs.h"

int
form_refresh(fid)
form_id fid;
{
	register int i, maxrows, maxcols;
	register char *argptr;
	struct ifield *curfld = NULL;
	int curmaxrows, curmaxcols;
	formfield ff, (*disp)();
	struct form *fptr;
	vt_id oldvid;
	int   retval;		/* abs */

	fptr = &FORM_array[fid];
	oldvid = vt_current(fptr->vid);
	disp = fptr->display;
	argptr = fptr->argptr;
	curmaxrows = fptr->rows;
	curmaxcols = fptr->cols;
	maxrows = maxcols = 0;

	ff = (*disp)(0, argptr);
	for (i = 0; ff.name != NULL; ff = (*disp)(++i, argptr)) {
		/*
		 * For all fields that are visible on the current page ...
		 * display/hide/update the field as appropriate
		 * (see fcheck.c) 
		 *
		 * ... also, determine the size of the entire form.
		 */
		checkffield(fptr, &ff);
		maxrows = max(maxrows, max(ff.frow + ff.rows, ff.nrow + 1));
		maxcols = max(maxcols, max(ff.fcol + ff.cols, ff.ncol + strlen(ff.name)));
		if (i == (fptr->curfldnum))
			curfld = (struct ifield *) *(ff.ptr);
	}
	if (maxrows > curmaxrows || maxcols > curmaxcols) {
		/*
		 * If the form should grow in size then reinitialize
		 * the form altogether.
		 */
	        retval = form_reinit(fid, fptr->flags, disp, argptr);
		fptr->flags &= ~(FORM_DIRTY | FORM_ALLDIRTY);
		return(retval);	/* abs */
	}
	else {
		/*
		 * clear dirty bits ... set/reset the form to the
		 * previously current field ... make the "oldvid"
		 * current again.
		 */
		fptr->flags &= ~(FORM_DIRTY | FORM_ALLDIRTY);
		gotofield(curfld, 0, 0);
		(void) vt_current(oldvid);
		return(SUCCESS);		/* abs */
	}
}
