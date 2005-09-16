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
#include "ctl.h"
#include "winp.h"
#include "fmacs.h"
#include "terror.h"
#include "vtdefs.h"

extern void acsputstring();

int
scroll_up(num)
int num;
{
	register int i;
	register chtype *currptr;
	int saverow, savecol;
	int pagelines, pagebytes, lastpage;

	pagelines = num;
	pagebytes = pagelines * LINEBYTES;
	lastpage = Fieldrows - pagelines;

	if (Buffoffset == 0) {
		setarrows();
		return(FALSE);		/* top of file */
	}
	saverow = Cfld->currow;
	savecol = Cfld->curcol;
	if (Buffoffset < pagebytes) {	/* if a partial scroll */
		pagelines = (int) (Buffoffset / LINEBYTES);
		pagebytes = pagelines * LINEBYTES;
		lastpage = Fieldrows - pagelines;
	}

	/*
	 * first, store bottom lines
	 */
	syncbuf(Buffoffset + FIELDBYTES - pagebytes, lastpage, Fieldrows - 1);
	Buffoffset -= pagebytes;

	/*
	 * second, push displayed lines off the bottom
	 */
	fgo(0, 0);
	finsline(pagelines, FALSE);

	/*
	 * thirdly, put buffered text at the top
	 */
	currptr = Scrollbuf + Buffoffset;
	for (i = 0; i < pagelines; i++, currptr += LINEBYTES) {
		fgo(i, 0);
		acsputstring(currptr);
	}

	/*
	 * finally, adjust cursor so that is points to the same character
	 * that it did before the scroll (if possible)
	 *
	 * Also, update the scroll indicator before returning TRUE
	 */
	if (pagelines != 1 && (saverow = (saverow + pagelines)) > LASTROW)
		saverow = LASTROW;
	fgo(saverow, savecol);
	setarrows();
	return(TRUE);
}

int
scroll_down(num)
int num;
{
	register int i;
	register unsigned fieldoffset;
	int saverow, savecol;
	int pagelines, pagebytes, lastpage;

	pagelines = num;
	pagebytes = pagelines * LINEBYTES;
	lastpage = Fieldrows - pagelines;
	fieldoffset = Buffoffset + FIELDBYTES;

	if (Scrollbuf == NULL)		/* make sure scroll buffer exists */
		growbuf(FIELDBYTES);
	if (fieldoffset >= Bufflast && Valptr == NULL) /* abs k17 */
	{
	    setarrows();		/* at the end of the scroll buffer */
	    return(FALSE);
	}

	saverow = Cfld->currow;
	savecol = Cfld->curcol;
	/*
	 * first, synchronize the scroll buffer with the window
	 */
	syncbuf(Buffoffset, 0, pagelines - 1);
	Buffoffset += pagebytes;
	if (Buffoffset + FIELDBYTES >= Buffsize)
		growbuf(Buffoffset + FIELDBYTES);   /* need more buffer space */

	/*
	 * secondly, delete displayed lines form the top of the field 
	 */
	fgo(0, 0);
	fdelline(pagelines);

	/*
	 * thirdly, display buffered text at the bottom of the field 
	 */
	fgo(lastpage, 0);
	for (i = 0; i < pagelines; i++) {
		/*
		 * If you are at the end of the scroll buffer then,
		 * if there is more text (Valptr != NULL), display
		 * it on the screen.
		 */ 
		if (fieldoffset >= Bufflast) {
			if (Valptr) 
				Valptr = (char *) fputstring(Valptr);
			Bufflast = Buffoffset + FIELDBYTES;
			break;
		}
		fgo(lastpage + i, 0);
		acsputstring(Scrollbuf + fieldoffset);
		fieldoffset += LINEBYTES;
	}

	/*
	 * finally, adjust cursor so that is points to the same character
	 * that it did before the scroll (if possible)
	 *
	 * Also, update the scroll indicator before returning TRUE
	 */
	if (pagelines != 1 && (saverow = (saverow - pagelines)) < 0)
		saverow = 0;
	fgo(saverow, savecol);
	setarrows();
	return(TRUE);
}

int
scroll_left(num)
int num;
{
	register int savecol, pagechars;


	pagechars = num;
	if (Buffoffset == 0) {
		/* 
		 * if at top of the buffer then update scroll arrows
		 * and return FALSE
		 */
		setarrows();
		return(FALSE);
	}
	savecol = Cfld->curcol;		/* keep track of where cursor was */
	if (Buffoffset < pagechars)	/* if a partial scroll */
		pagechars = Buffoffset;
	 
	/* 
	 * first sync buffer to the visible contents of the field
	 */
	syncbuf(Buffoffset, 0, 0);
	Buffoffset -= pagechars;

	/*
	 * next, shift visible window 
	 */
	fgo(0, 0);
	fclearline();
	fgo(0, 0);
	acsputstring(Scrollbuf + Buffoffset);

	/*
	 * finally, adjust cursor so that is points to the same character
	 * that it did before the scroll (if possible)
	 *
	 * Also, update the scroll indicator before returning TRUE
	 */
	if ((savecol += pagechars) > LASTCOL)
		savecol = LASTCOL;
	fgo(0, savecol);
	setarrows();
	return(TRUE);
}

int
scroll_right(num, just_synced)
int num;
bool just_synced;		/* for performance.  abs f15 */
{
	register int savecol, pagechars;
	register unsigned fieldoffset;

	pagechars = num;
	fieldoffset = Buffoffset + Fieldcols;

	/*
	 * if you are at the end of the "used" part of the buffer
	 * (Bufflast), simply update the scroll indicator and
	 * return FALSE
	 */
	if (fieldoffset >= Bufflast)  /* was >  abs k17 */
	{
		setarrows();
		return(FALSE);
	}

	savecol = Cfld->curcol;
	/* 
	 * First sync the field buffer to the visible contents of the field ...
	 * unless it was done just before calling this function ...
	 * Secondly, bump the buffer offset by pagechars (growing the buffer if
	 * necessary) 
	 */
	if (just_synced == FALSE)                  /* abs f15 */
	    syncbuf(Buffoffset, 0, 0);
	Buffoffset += pagechars;
	if (Buffoffset + Fieldcols > Buffsize)     /* was >=  abs f15 */
		growbuf(Buffoffset + Fieldcols);   /* need more buffer space */

	/*
	 * Next, shift the visible window
	 */
	fgo(0, 0);
	fclearline();
	fgo(0, 0);
	acsputstring(Scrollbuf + Buffoffset);

	/*
	 * Finally, adjust cursor so that is points to the same character
	 * that it did before the scroll (if possible)
	 *
	 * Also, update the scroll indicator before returning TRUE
	 */
	if ((savecol = (savecol - num)) < 0)
		savecol = 0;
	fgo(0, savecol);
	setarrows();
	return(TRUE);
}
