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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

#include        <curses.h>
#include	"wish.h"
#include	"token.h"
#include	"winp.h"
#include	"form.h"
#include	"vtdefs.h"

form_id		FORM_curid = -1;
struct form	*FORM_array;

/*
 * makes the given form current and old form noncurrent
 */
int
form_current(fid)
form_id	fid;
{

	register struct form	*f;

	if (fid != FORM_curid)	/* if changing to different form.. abs k13 */
	    form_noncurrent();	

	FORM_curid = fid;
	f = &FORM_array[FORM_curid];
	vt_current(f->vid);
	if (f->flags & (FORM_DIRTY | FORM_ALLDIRTY))
		form_refresh(fid);
	return(SUCCESS);
}

/*
 * makes current form noncurrent
 */
int
form_noncurrent()
{
	if (FORM_curid >= 0)
		FORM_array[FORM_curid].flags |= FORM_DIRTY;
	return(SUCCESS);
}
