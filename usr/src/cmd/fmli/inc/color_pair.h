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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.7 */

/*
 * NOTE:
 *
 * If the terminal does not support more than 7 color pairs
 * then pairs 8 and greater will be ignored 
 * (The hp color terminal is one such terminal that only supports 7
 * color pairs)
 */ 

/* definable color pairs */
#define NUMDEFPAIRS		11	

#define WINDOW_PAIR		1
#define ACTIVE_TITLE_PAIR	2
#define INACTIVE_TITLE_PAIR	3
#define ACTIVE_BORD_PAIR	4
#define INACTIVE_BORD_PAIR	5
#define BANNER_PAIR		6
#define BAR_PAIR		7
#define SLK_PAIR		8
#define ACTIVE_SCROLL_PAIR	9
#define INACTIVE_SCROLL_PAIR	10	
#define FIELD_PAIR		11	

/* number of default colors and maximum total colors */
#define NUMDEFCOLORS	8
#define MAXCOLORS	64
#define MAXCOLPAIRS	64

extern int Color_terminal;		/* is the terminal a color terminal */
extern int Border_colors_differ;	/* do active/inactive border colors differ? */
extern int Pair_set[MAXCOLPAIRS];	/* is color pair set ? */

/*
 * If the color pair is greater than the number of COLOR_PAIRS ... 
 * or the color pair is not set by the application ...
 * then expand to JUST the video attribute ...
 * else expand to JUST the color attribute ...
 */
#define CHK_PAIR(vid, col) \
	((col > COLOR_PAIRS) || !Pair_set[col] ? vid : COLOR_PAIR(col))

/*
 * If the terminal is a color device ...
 * AND there are more color pairs then 7 ... 
 * then expand to CHK_PAIR(vid, col) ... 
 * else expand to vid 
 */
#define COL_ATTR(vid, col) \
	((Color_terminal == TRUE) && COLOR_PAIRS >= 7 ? CHK_PAIR(vid, col) :vid)
