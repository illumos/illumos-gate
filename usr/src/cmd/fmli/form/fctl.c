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
#include	<stdarg.h>
#include        <curses.h>
#include	"wish.h"
#include	"ctl.h"
#include	"token.h"
#include	"winp.h"
#include	"form.h"
#include	"vtdefs.h"

int
form_ctl(form_id fid, unsigned cmd, ...)
{
	register struct form *f;
	register int	retval;
	va_list	args;

#ifdef _DEBUG
	if (fid < 0) {
		if ((fid = FORM_curid) < 0)
			_debug(stderr, "NO CURRENT FORM!\n");
	}
#endif
	f = &FORM_array[fid];
	retval = SUCCESS;
	va_start(args, cmd);
	switch (cmd) {
	case CTSETDIRTY:
		if (fid == FORM_curid)
			form_refresh(fid);	/* refresh now */
		else
			f->flags |= FORM_DIRTY;	/* refresh when made current */
		break;
	case CTSETPOS:
		{
			formfield ffld;

 			f->curfldnum = va_arg(args, int);
 			ffld = (*(f->display))(f->curfldnum, f->argptr);
			checkffield(f, &ffld);
			gotofield(*(ffld.ptr), va_arg(args, int), va_arg(args, int));
		}
		break;
	case CTSETPAGE:
		{
			int doclear, curpage, lastpage, line;

			doclear = va_arg(args, int);
			curpage = va_arg(args, int);
			lastpage = va_arg(args, int);
			f->flags |= FORM_ALLDIRTY;
			line = 0;
			if (curpage > 1)
				line |= VT_UPPARROW;
			if (curpage < lastpage)
				line |= VT_DNPARROW;
			if (doclear) {
				wgo(0, 0);
				wclrwin();
				vt_ctl(f->vid, CTSETPARROWS, line);
				retval = form_refresh(fid); /* abs */
			}
			else {
				vt_ctl(f->vid, CTSETPARROWS, line);
			}
			break;
		}
	case CTGETARG:
		{
			char **strptr;

			strptr = va_arg(args, char **);
			if (*strptr == NULL)
				*strptr = (char *) getfield(NULL, NULL);
			else
				(void) getfield(NULL, *strptr);
		}
		break;
	case CTGETWDW:
		retval = vt_ctl(f->vid, CTGETWDW);
		break;
	case CTGETITLE:
		retval = vt_ctl(f->vid, CTGETITLE, va_arg(args, char *));
		break;
	case CTGETVT:
		retval = f->vid;
		break;
	case CTGETPARMS:
		*(va_arg(args, int *)) = f->rows;
		*(va_arg(args, int *)) = f->cols;
		break;
	case CTSETPARMS:
		f->rows = va_arg(args, int);
		f->cols = va_arg(args, int);
		f->flags |= FORM_DIRTY;
		break;
	case CTSETSHAPE:
		{
			int	srow, scol, rows, cols;

			srow = va_arg(args, int);
			scol = va_arg(args, int);
			rows = va_arg(args, int);
			cols = va_arg(args, int);
			if (srow >= 0)
				_form_reshape(fid, srow, scol, rows, cols);
		}
 		break;
 	case CTCLEARWIN:
 		vt_ctl(f->vid, CTCLEARWIN, 0);
		break;
	default:
#ifdef _DEBUG
		_debug(stderr, "form_ctl(%d, %d, ...) unknown command\n", fid, cmd);
#endif
		retval = FAIL;
		break;
	}
	va_end(args);
	return retval;
}
