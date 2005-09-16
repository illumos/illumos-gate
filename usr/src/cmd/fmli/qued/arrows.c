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
#include "winp.h"
#include "wish.h"
#include "ctl.h"
#include "fmacs.h"
#include "vtdefs.h"

/*
 * SETARROWS is used to set/clear scroll indicators for both
 * single-line and multi-line scrollable fields
 */
int
setarrows(void)
{
    register unsigned line;
    register int ch, savecol;

    line = 0;
    if (!(Flags & I_SCROLL))
	vt_ctl(VT_UNDEFINED, CTSETSARROWS, 0);
    else if (Cfld->rows == 1) {
	vt_ctl(VT_UNDEFINED, CTSETSARROWS, 0);
	savecol = Cfld->curcol;
	if (Buffoffset > 0)
	    line |= VT_UPSARROW;
	if ((Buffoffset + Cfld->cols + 1) < Bufflast) 
	    line |= VT_DNSARROW;
	if (line & VT_UPSARROW) {
	    if (line & VT_DNSARROW)
		ch = '=';
	    else
		ch = '<';
	}
	else if (line & VT_DNSARROW) {
	    if (line & VT_UPSARROW)
		ch = '=';
	    else
		ch = '>';
	}
	else
	    ch = ' ';
	fgo(0, LASTCOL + 1);
	fputchar(ch);
	fgo(0, savecol);
    }
    else {
	/*
	 * If the field takes up the entire frame
	 * or is a text object, then use the
	 * scroll box rather than the scroll indicators
	 */
	if (Buffoffset > 0)
	    line |= (Flags & (I_FULLWIN | I_TEXT)) ? VT_UPPARROW : VT_UPSARROW;
	if ((Valptr != NULL) || ((Buffoffset + FIELDBYTES) < Bufflast)) 
	    line |= (Flags & (I_FULLWIN | I_TEXT)) ? VT_DNPARROW : VT_DNSARROW;
	vt_ctl(VT_UNDEFINED, (Flags & (I_FULLWIN | I_TEXT)) ?
	       CTSETPARROWS : CTSETSARROWS, line);
    }
	return (0);
}
