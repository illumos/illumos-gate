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

#include	<curses.h>
#include	<term.h>
#include	"color_pair.h"

/*
 * the UNDERLINE flag is the second bit of the "ncv" (no_color_video) 
 * terminfo variable (see set_underline_attrs() below)
 */ 
#define UNDERLINE	(0x02)

chtype Attr_normal; 	/* normal video */
chtype Attr_hide;	/* border of non-current window */
chtype Attr_highlight;	/* border of current window */
chtype Attr_select;	/* attribute of "selector bar" */
chtype Attr_show;	/* something visible (errors, etc) */
chtype Attr_visible;	/* the most annoying thing terminal can do */
chtype Attr_underline;	/* attribute of underline */
chtype Attr_mark;	/* attribute of "marked" items */



int
setvt_attrs(void)
{
	static chtype	modes;

	/*
	 * Determine modes
	 */
	if (enter_blink_mode)
		modes |= A_BLINK;
	if (enter_bold_mode)
		modes |= A_BOLD;
	if (enter_dim_mode)
		modes |= A_DIM;
	if (enter_reverse_mode)
		modes |= A_REVERSE;
	if (enter_standout_mode)
		modes |= A_STANDOUT;
	if (enter_underline_mode)
		modes |= A_UNDERLINE;

	/*
	 * Set up Attribute array
	 */
	Attr_normal = A_NORMAL;
	Attr_underline = A_UNDERLINE;	/* let curses decide */
	Attr_highlight = modes & A_STANDOUT;
	if (modes & A_REVERSE)
		Attr_highlight = A_REVERSE;
	Attr_visible = Attr_show = Attr_select = Attr_hide = Attr_highlight;
	if (modes & A_DIM)
		Attr_select = Attr_hide = modes & (A_REVERSE | A_DIM);
	else if (modes & A_BOLD) {
		Attr_highlight |= A_BOLD;
		Attr_select = A_BOLD;
	}
	if (modes & A_BLINK)
		Attr_visible |= A_BLINK;
	Attr_mark = Attr_select;
	if (modes & A_UNDERLINE)
		Attr_mark = A_UNDERLINE;
	return (0);
}

/*
 * SET_UNDERLINE_COLOR will change the underline attribute to be
 * "colpair" IF the terminal supports color BUT the terminal CAN NOT
 * support color attributes with underlining. 
 */
int
set_underline_attr(colpair)
int colpair;
{
	if (Color_terminal == TRUE && no_color_video >= 0 &&
	   (no_color_video & UNDERLINE))
		Attr_underline = COL_ATTR(A_REVERSE, colpair);
	return (0);
}
