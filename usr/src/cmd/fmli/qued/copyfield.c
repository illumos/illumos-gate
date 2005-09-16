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
#include <memory.h>
#include <curses.h>
#include "wish.h"
#include "token.h"
#include "winp.h"
#include "fmacs.h"
#include "moremacros.h"
#include "terror.h"

extern char   *fputstring();
extern void   acsputstring();

/*
 * COPYFIELD will copy a field form one part of the screen to another
 * (including all of the field status information)
 */
int
copyfield(srcfld, destfld) 
ifield *srcfld, *destfld;
{
    ifield *savefield;
    long tmpoffset;
	

    if (srcfld == NULL || destfld == NULL)
	return(FAIL);
    savefield = Cfld;
    Cfld = destfld;
    if (srcfld->scrollbuf) {	/* if a scrollable field */
	register int linesize, i;

	if (destfld->scrollbuf)	/* ehr3 */
	    free(destfld->scrollbuf); /* ehr3 */

	if ((destfld->scrollbuf = (chtype *)malloc      /* added +1 abs k15 */
	     ((srcfld->buffsize + 1) * sizeof(*srcfld->scrollbuf))) == NULL)
	    fatal(NOMEM, "");
		
	destfld->buffsize = srcfld->buffsize;
	memcpy(destfld->scrollbuf, srcfld->scrollbuf,   /* added +1 abs k15 */
	       (srcfld->buffsize +1) * sizeof(*srcfld->scrollbuf));
	linesize = destfld->cols + 1;
	tmpoffset = 0L;
	for (i = 0; i < srcfld->rows; i++) {
	    /* print the copied field to the screen */
	    fgo(i, 0);
	    acsputstring(destfld->scrollbuf + tmpoffset);
	    tmpoffset += linesize;
	}
    }
    if (srcfld->value) {
	if (destfld->value)	/* ehr3 */
	    free(destfld->value); /* ehr3 */

	destfld->value = strsave(srcfld->value);

	if (!destfld->scrollbuf) /* if not a scroll field */
	    destfld->valptr = fputstring(destfld->value);
    }
    destfld->currow = srcfld->currow;
    destfld->curcol = srcfld->curcol;
    Cfld = savefield;
    return(SUCCESS);
}

/*
 * HIDEFIELD will remove the field from screen WITHOUT destroying the
 * ifield structure.
 */
int
hidefield(fld)
ifield *fld;
{
	ifield *savefield;
	int flags;

	savefield = Cfld;
	if (fld != NULL)
		Cfld = fld;
	flags = fld->flags;
	setfieldflags(fld, (fld->flags & ~I_FILL));
	fgo(0, 0);
	fclear();
	setfieldflags(fld, flags);
	Cfld = savefield;
	return (0);
}
