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

#include <curses.h>
#include <term.h>
#include "wish.h"
#include "color_pair.h"
#include "moremacros.h"
#include "vtdefs.h"
#include "vt.h"

static int Numcolors = NUMDEFCOLORS; 
int Pair_set[MAXCOLPAIRS];
static int add_color(char *colorstr);
static int lookup_color(char *colorstr);

/*
 * Table of known colors
 */
struct ctab {
	char *colorstr;
	int id;
} Color_tab[MAXCOLORS] = {
	{ "black", COLOR_BLACK },
	{ "blue", COLOR_BLUE },
	{ "green", COLOR_GREEN },
	{ "cyan", COLOR_CYAN },
	{ "red", COLOR_RED },
	{ "magenta", COLOR_MAGENTA },
	{ "yellow", COLOR_YELLOW },
	{ "white", COLOR_WHITE },
	{ NULL, 0 }
};

/*
 * SET_SCR_COLOR sets the screen background color and refreshes
 * the screen
 */
int
set_scr_color(colpair, dorefresh)
int colpair;
int dorefresh;
{
	if (Pair_set[colpair]) { 
		wbkgd(stdscr, COL_ATTR(A_NORMAL, colpair));
		/*
		 * Set color attributes for the banner, message and
		 * command lines
		 */
		wbkgd(VT_array[STATUS_WIN].win, COL_ATTR(A_NORMAL, colpair));
		wattrset(VT_array[STATUS_WIN].win, COL_ATTR(A_NORMAL, colpair));
		wbkgd(VT_array[MESS_WIN].win, COL_ATTR(A_NORMAL, colpair));
		wattrset(VT_array[MESS_WIN].win, COL_ATTR(A_NORMAL, colpair));
		wbkgd(VT_array[CMD_WIN].win, COL_ATTR(A_NORMAL, colpair));
		wattrset(VT_array[CMD_WIN].win, COL_ATTR(A_NORMAL, colpair));
	}
	if (dorefresh) {
		refresh();
		/*
		 * The following lines are necessary since curses
		 * has problems with reverse video screens (e.g., xterm
		 * by default comes up with a white background)
		 */
		if (orig_colors)
			putp(orig_colors);
		if (orig_pair)
			putp(orig_pair);
	}
	return (0);
}

/*
 * SET_SLK_COLOR simply sets the slk color pair
 */ 
int
set_slk_color(colpair)
{
	slk_attrset(COL_ATTR(A_REVERSE | A_DIM, colpair));
	return (0);
}
	
/*
 * SETPAIR creates new color pair combinations
 */
int
setpair(pairnum, foreground, background)
int pairnum, foreground, background;
{
	if (foreground < 0 || background < 0) 
		Pair_set[pairnum] = FALSE;
	else if (init_pair(pairnum, foreground, background) != ERR)
		Pair_set[pairnum] = TRUE;
	else
		Pair_set[pairnum] = FALSE;
	return(Pair_set[pairnum]);
}

/*
 * SETCOLOR creates new color specifications or "tweeks" old ones.
 * (returns 1 on success and 0 on failure)
 */
int
setcolor(colorstr, r, g, b)
char *colorstr;
int r, g, b;
{
	register int cindex, id; 
	short oldr, oldg, oldb;
	int cant_init;

	if (!can_change_color())
		return(-1);
	cant_init = 0;
	if ((cindex = lookup_color(colorstr)) >= 0) {
		/*
		 * The color has been previously defined ...
		 * If you can't change the color specification then
		 * restore the old specification. 
		 */
		color_content(cindex, &oldr, &oldg, &oldb);
		if (init_color(cindex, r, g, b) == ERR) {
			cant_init++;
			if (init_color(cindex, oldr, oldg, oldb) == ERR)
				id = -1; 	/* just in case */
			else
				id = cindex;
		}
		else
			id = cindex;
		Color_tab[cindex].id = id;
	}
	else if ((cindex = add_color(colorstr)) >= 0) {
		/*
		 * The color is NEW ...
		 */
		if (init_color(cindex, r, g, b) == ERR)
			id = -1;
		else
			id = cindex;
		Color_tab[cindex].id = id;
	}
	else
		id = -1;
	return(cant_init ? 0 : (id >= 0));
} 

/*
 * GETCOLOR_ID returns the color identifier of the passed color string
 */
int
getcolor_id(colorstr)
char *colorstr;
{
	int index;

	index = lookup_color(colorstr);
	if (index >= 0)
		return(Color_tab[index].id);
	else
		return(-1);
}

/*
 * LOOKUP_COLOR returns the index of the passed color string from the
 * color table (or "-1" if the color is not in the table).
 */ 
static int
lookup_color(char *colorstr)
{
	register int i;

	/* put it in the color table */
	for (i = 0; i < Numcolors; i++) {
		if (strcmp(colorstr, Color_tab[i].colorstr) == 0)
			return(i);
	}
	return(-1);
}

/*
 * ADD_COLOR adds a new color to the color table if the number of colors
 * is less than COLORS (curses define for the number of colors the terminal
 * can support) and less than MAXCOLORS (color table size)
 */
static int 
add_color(char *colorstr)
{
	if (Numcolors < COLORS && Numcolors < MAXCOLORS) {
		Color_tab[Numcolors].colorstr = strsave(colorstr);
		return(Numcolors++);
	}
	else
		return(-1);
} 
