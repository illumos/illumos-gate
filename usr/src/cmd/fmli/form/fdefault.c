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
#include "terror.h"
#include "token.h"
#include "winp.h"
#include "form.h"
#include "vtdefs.h"
#include "ctl.h"

static void getformsize();

form_id
form_default(title, flags, startrow, startcol, disp, ptr)
char	  *title;
unsigned  flags;
int	  startrow;
int	  startcol;
formfield (*disp)();
char	  *ptr;
{
	vt_id	vid;
	int maxheight, maxlength;

	getformsize(disp, ptr, title, &maxheight, &maxlength);
	if (maxheight == 0)
		return((form_id) FAIL);
	if ((vid = vt_create(title, flags, startrow, startcol, maxheight, maxlength + 1)) < 0)
		/* just try to put the window anywhere */
		vid = vt_create(title, flags, VT_UNDEFINED, VT_UNDEFINED, maxheight, maxlength + 1);
	if (vid == VT_UNDEFINED) {
		mess_temp("Object can not be displayed, frame may be too large for the screen");
		return((form_id) FAIL);
	}
	return(form_custom(vid, flags, maxheight, maxlength, disp, ptr));
}

form_id
form_reinit(fid, flags, disp, arg)
form_id  fid;
unsigned flags;
formfield	(*disp)();
char	*arg;
{
	char	*s;
	register form_id currfid;
	register vt_id	savevid, newvid, formvid;
	struct	form *f;
	int	formrows, formcols, retval, num;

	f = &FORM_array[fid];
	currfid = FORM_curid;
	formvid = f->vid;
	savevid = vt_current(formvid);

	vt_ctl(VT_UNDEFINED, CTGETITLE, &s);
	num = vt_ctl(VT_UNDEFINED, CTGETWDW);
	getformsize(disp, arg, s, &formrows, &formcols);
	if ((newvid = vt_create(s, flags | VT_COVERCUR, VT_UNDEFINED, VT_UNDEFINED, formrows, formcols)) == VT_UNDEFINED) {
		
		/* 
		 * try putting the VT anywhere 
		 */
		newvid = vt_create(s, flags, VT_UNDEFINED, VT_UNDEFINED, formrows, formcols);
	}
	if (newvid != VT_UNDEFINED) {
		vt_close(formvid);
		f->flags |= FORM_ALLDIRTY;
		f->vid = newvid;
		f->rows = formrows;
		f->cols = formcols;
		vt_current(newvid); /* moved from after vt_ctl() abs */
		vt_ctl(VT_UNDEFINED, CTSETWDW, num);
		retval = SUCCESS;
	}
	else
	{
	    retval = FAIL;
	    form_noncurrent();
	    if (formvid != savevid)  /* the corrupted form was'nt current.. */
		vt_current(savevid); /* so make the old frame current again */
	    return(retval);
	}

	form_current(fid);
	if (savevid != formvid) {
		form_noncurrent();
		if (currfid >= 0)
			form_current(currfid);
		else
			vt_current(savevid);
	}

	return(retval);
}


/* _form_reshape really reshapes text objects  */
int
_form_reshape(fid, srow, scol, rows, cols)
int	fid;
int	srow;
int	scol;
unsigned	rows;
unsigned	cols;
{
	int numrows, numcols;
	int header_rows;
	struct form *f;
	register char *argptr;

	formfield ff, (*disp)();

	/*****
	mess_temp("Cannot reshape Forms or Text Objects");
	return FAIL;
	*****/

	f = &FORM_array[fid];
	if (rows < 4 /* f->rows */ || cols < 5 /* f->cols */) {
		mess_temp("Too small, try again");
		return FAIL;
	}
	vt_reshape(f->vid, srow, scol, rows, cols);
	vt_ctl(f->vid, CTGETSIZ, &numrows, &numcols);
	/*
	f->rows = numrows;
	f->cols = numcols;
	*/
	f->flags |= (FORM_DIRTY | FORM_ALLDIRTY);

	/* Text object stuff */
	disp = f->display;
	argptr = f->argptr;
	ff = (*disp)(0, argptr); /* header field */
	if (*(ff.ptr)) {
	    endfield((ifield *) *(ff.ptr));
	    *(ff.ptr) = (char *) newfield(ff.frow, ff.fcol,
					  rows - 2 , cols - 2, ff.flags);
	    header_rows = ff.rows;
	    ff.cols = cols - 2;
	    putfield((ifield *) *(ff.ptr), ff.value);
	}

	ff = (*disp)(1, argptr); /* text field */
	if (*(ff.ptr)) {
	    endfield((ifield *) *(ff.ptr));
	    *(ff.ptr) = (char *) newfield(ff.frow, ff.fcol,
				 rows - 2 - header_rows , cols - 2, ff.flags);
	    ff.rows = rows - 2 - header_rows;
	    ff.cols = cols - 2;
	    putfield((ifield *) *(ff.ptr), ff.value);
	}
	form_current(fid);
	return SUCCESS;
}

static void
getformsize(disp, ptr, title, formrows, formcols)
formfield (*disp)();
char	  *ptr;
char	  *title;
int    	  *formrows;
int	  *formcols;
{
	register int	i, maxrows, maxcols;
	formfield	ff;

	i = maxrows = maxcols = 0;
	for (ff = (*disp)(0, ptr); ff.name != NULL; ff = (*disp)(++i, ptr)) {
		maxrows = max(maxrows, max(ff.frow + ff.rows, ff.nrow + 1));
		maxcols = max(maxcols, max(ff.fcol + ff.cols, ff.ncol + strlen(ff.name)));
	}
	if (maxcols < (i = strlen(title) + 3))
		maxcols = i;
	*formrows = maxrows;
	*formcols = maxcols;
}
