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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5 */

#include	<stdio.h>
#include        <curses.h>
#include	"wish.h"
#include	"token.h"
#include	"winp.h"
#include	"form.h"
#include	"vtdefs.h"
#include	"var_arrays.h"

int
form_close(fid)
form_id	fid;
{
	register int i;
	register char *argptr;
	register struct form *fptr;
	formfield ff, (*disp)();

	if (fid < 0 || !(FORM_array[fid].flags & FORM_USED)) {
#ifdef _DEBUG
		_debug(stderr, "form_close(%d) - bad form number\n", fid);
#endif
		return(FAIL);
	}
	fptr = &FORM_array[fid];
	disp = fptr->display;
	argptr = fptr->argptr;
	for (i = 0, ff = (*disp)(0, argptr); ff.name != NULL; ff = (*disp)(++i, argptr)) 
		if (*(ff.ptr))
			endfield(*(ff.ptr));
	if (FORM_curid == fid)
		FORM_curid = -1;
	fptr->flags = 0;
	vt_close(fptr->vid);	/* close the window associated with the form */
	return(SUCCESS);
}
