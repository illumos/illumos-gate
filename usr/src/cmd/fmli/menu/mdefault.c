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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.22 */

#include	<stdio.h>
#include	"wish.h"
#include	"menu.h"
#include	"menudefs.h"
#include	"vtdefs.h"
#include	"terror.h"
#include	"ctl.h"
#include 	"sizes.h"

char *shrink_descriptor();

#define MAX_MITEMS	10

menu_id
menu_make(num, title, flags, startrow, startcol, menurows, menucols, disp, arg)
int	num;		/* menu number */
char	*title;		/* menu title */
unsigned flags;		/* menu/vt flags */	
int	startrow;	/* start row for the menu frame */
int     startcol;	/* start column for the menu frame */
int 	menurows;	/* default menu rows */
int	menucols;	/* default menu cols */
struct	menu_line (*disp)();
char	*arg;
{
    register int	total;	/* total items */
    register int	itemwidth; /* width of longest item */
    register int	descwidth; /* width of longest description */
    register int	menuwidth; /* width of the menu */
    int	 cols_specified;	/* are number of cols specified? */
    int	 rows_specified;	/* are number of rows specified? */
    struct	 menu_line ml;	/* item offset into menu */
    vt_id    vid;		/* vt identifier of new frame */
    int	 probrows, probcols, probwidth;	/* tmp vars */
    int	 oitemwidth, chop, i_num;	/* tmp vars */
    int mflags = flags;		/* menu flags (as opposed to vt flags) */
    bool has_description = FALSE;

    /*
     * Determine ITEMWIDTH and DESCRIPTION WIDTH
     * as well as the TOTAL number of items
     */
    itemwidth = descwidth = 0;
    ml = (*disp)(0, arg);
    for (total = 0; ml.highlight; ml = (*disp)(++total, arg))
    {	
	ml.highlight = shrink_descriptor(ml.highlight, FIXED_COLS);
	itemwidth = max(itemwidth, strlen(ml.highlight));
	if ((ml.description != NULL) && (*(ml.description) != '\0')) {
	    		has_description = TRUE;
	} /* no description */
    }
    if (!total)
	return((menu_id) FAIL);	/* empty menu */

    /* an item which fits may still need truncation to show that description
     * didn't fit.  - 4 becaue of " - " and min 1 char of description
     */
    if (has_description && (itemwidth >= COLS - FIXED_COLS - 4) )
    {
	    mflags |= MENU_TRUNC;
	    descwidth = 1;
    }
    else	    /* full name fits, truncate description if needed */
	{
	    for (i_num = 0; i_num < total; i_num++)
	    {
		ml = (*disp)(i_num, arg);
		if (ml.description) 	
		{
		    /* the "3" below is for the " - " separator */

		    ml.description = shrink_descriptor(ml.description,
					       FIXED_COLS + itemwidth + 3 -1);
		    descwidth = max(descwidth, strlen(ml.description));
		}
	    }
	}
    
    rows_specified = (menurows > 0 ? TRUE : FALSE);
    cols_specified = (menucols > 0 ? TRUE : FALSE);

    if (descwidth) {
	/*
	 * If ANY item has a description, then stay single column,
	 *
	 *	width = longest highlight +
	 *		longest description +
	 *		3 (for the " - ") +
	 *		2 (for space between text and sides)
	 *
	 */
	if (rows_specified) {
	    /*
	     * actual rows = min(specified rows, 
	     *		     fittable rows,
	     *		     needed rows);
	     */ 
	    for ( ; !fits(flags, menurows, 1); menurows--)
		;
	    if (menurows > total)
		menurows = total;
	}
	else {
	    /*
	     * actual rows = min(MAX_MITEMS, needed rows);
	     */
	    menurows = min(total, MAX_MITEMS);
	}
	menucols = 1;
	menuwidth = itemwidth + descwidth + 5;

	/*
	 * if the description is too long, then truncate 
	 */
	for ( ; !fits(flags, menurows, menuwidth); menuwidth--) 
	    ;

    }
    else if (rows_specified && !cols_specified) {
	/*
	 * determine probable rows, then probable columns
	 *
	 * probable rows = min(specified rows, "fittable" rows) 
	 */ 
	for (probrows = menurows; !fits(flags, probrows, 1); probrows--)
	    ;
	probcols = (total / probrows) + (total % probrows ? 1 : 0); 
	probwidth = 1 + probcols * (1 + itemwidth);

	/*
	 * determine actual rows and columns
	 */
	if (!fits(flags, probrows, probwidth)) {
	    /*
	     * menu not displayable in multi-columns ...
	     *
	     * actual rows = probable rows
	     * actual cols = 1
	     *
	     * truncate the menu if necessary
	     */
	    menurows = probrows;
	    menucols = 1;
	    menuwidth = 2 + itemwidth;
	    for (; !fits(flags, 1, menuwidth); )
		menuwidth--;
	}
	else {
	    /*
	     * actual rows = probable cols == 1 ?
	     *		 min(specified rows, fittable rows) :
	     * 		 probable rows 
	     * actual cols = probable cols
	     */
	    if (probcols == 1) {
		for ( ; !fits(flags, menurows, 1); menurows--)
		    ;
	    }
	    else 
		menurows = probrows;
	    menucols = probcols;
	    menuwidth = probwidth; 
	}

	/*
	 * Eliminate white-space from unused rows
	 */
	if (menurows > total)
	    menurows = total;
    }
    else if (cols_specified && !rows_specified) {
	/*
	 * determine probable columns, then probable rows 
	 *
	 * If necessary, truncate the length of each 
	 * column until the menu fits
	 */ 
	probcols = menucols;
	probwidth = 1 + probcols * (1 + itemwidth);
	oitemwidth = itemwidth;	
	while (!fits(flags, 1, probwidth)) {
	    itemwidth--;
	    probwidth = 1 + probcols * (1 + itemwidth);
	    if (itemwidth <= 0) {
		/*
		 * give up ...
		 * default to single column and
		 * truncate the menu if necessary.
		 */
		probcols = 1;
		itemwidth = oitemwidth;
		probwidth = 2 + itemwidth;
		for (; !fits(flags, 1, probwidth); )
		    probwidth--;
		break;
	    }
	}
	probrows = (total / probcols) + (total % probcols ? 1 : 0); 

	/*
	 * determine actual rows and columns
	 */
	if (!fits(flags, probrows, probwidth)) {
	    /*
	     * menu too big ...
	     *
	     * actual cols = 1
	     * actual rows = min(MAX_MITEMS, total)
	     */
	    menucols = 1;
	    menuwidth = 2 + itemwidth;
	    for (; !fits(flags, 1, menuwidth); )
		menuwidth--;
	    menurows = min(MAX_MITEMS, total);
	}
	else { 
	    menucols = probcols;
	    menuwidth = probwidth;
	    menurows = probrows;
	}

	/*
	 * Eliminate white-space from unused columns ...
	 * First compute the number of columns to chop and
	 * then subtract it from menucols
	 */
	if (menucols > 1) {
	    chop = ((menurows * menucols) - total) / menurows;
	    if (chop) { 
		menucols -= chop; 
		menuwidth = 1 + menucols * (1 + itemwidth);
	    }
	}
    }
    else if (rows_specified && cols_specified) { 
	/*
	 * determine probable columns, then probable rows 
	 *
	 * If necessary, truncate the length of each 
	 * column until the menu fits
	 */ 
	probcols = menucols;
	probwidth = 1 + probcols * (1 + itemwidth);
	oitemwidth = itemwidth;
	while (!fits(flags, 1, probwidth)) { 
	    itemwidth--;
	    probwidth = 1 + probcols * (1 + itemwidth);
	    if (itemwidth <= 0) {
		/*
		 * give up ...
		 * default to single column and
		 * truncate the menu if necessary.
		 */
		probcols = 1;
		itemwidth = oitemwidth;
		probwidth = 2 + itemwidth;
		for (; !fits(flags, 1, probwidth); )
		    probwidth--;
		break;
	    }
	}
	probrows = (total / probcols) + (total % probcols ? 1 : 0);

	/*
	 * determine actual rows and columns
	 */
	if (!fits(flags, probrows, probwidth)) {
	    /*
	     * Menu can't be displayed in multi-columns ...
	     *
	     * actual cols = 1; 
	     * actual rows = min(specified rows, fittable rows);
	     */
	    menucols = 1;
	    menuwidth = 2 + itemwidth;
	    for (; !fits(flags, 1, menuwidth); )
		menuwidth--;
	    for ( ; !fits(flags, menurows, 1); menurows--)
		;
	}
	else {
	    /*
	     * actual rows = probable cols == 1 ?
	     *		 min(specified rows, fittable rows) :
	     * 		 probable rows 
	     * actual cols = probable cols
	     */
	    if (probcols == 1) {
		for ( ; !fits(flags, menurows, 1); menurows--)
		    ;
	    }
	    else 
		menurows = probrows;
	    menucols = probcols;
	    menuwidth = probwidth;
	}

	/*
	 * Eliminate white-space from unused columns ...
	 * First compute the number of columns to chop and
	 * then subtract it from menucols
	 */
	if (menucols > 1) {
	    chop = ((menurows * menucols) - total) / menurows;
	    if (chop) { 
		menucols -= chop; 
		menuwidth = 1 + menucols * (1 + itemwidth);
	    }
	}
    }
    else {
	/*
	 * ROWS and COLUMNS are not specified so churn away ... 
	 */
	if (total <= MAX_MITEMS) {
	    /*
	     * use single column ... truncate menu if necessary
	     */
	    menurows = min(total, MAX_MITEMS);
	    menucols = 1;
	    menuwidth = itemwidth + 2; /* 1 column */
	    while (!fits(flags, 1, menuwidth))
		menuwidth--;	/* truncate until it fits */
	}
	else {
	    /*
	     *	1) make menu at least as wide as the title,
	     *
	     *	2) make its aspect as close to 1:3
	     *	   (height:width) as possible).
	     *
	     *	 These are arbitrarily pleasing values.
	     *
	     */
	    menucols = 1;
	    menuwidth = itemwidth + 2;
	    menurows = MAX_MITEMS;

	    while (fits(flags, menurows, menuwidth)) {
		if ((menurows * 3 <= menuwidth) &&
		    (menuwidth >= strlen(title) + 3))
		    break;
		menucols++;
		menuwidth = 1 + menucols * (1 + itemwidth);
		menurows = (total + menucols - 1) / menucols;
	    }
	    if (!fits(flags, menurows, menuwidth)) {
		/*
		 * try "backing-off" one column and
		 * recomputing rows.
		 */
		menucols = max(menucols - 1, 1);
		menuwidth = 1 + menucols * (1 + itemwidth);
		menurows = (total + menucols - 1) / menucols;

		if (!fits(flags, menurows, menuwidth)) {
		    /*
		     * if all else fails ... resort to
		     * single column.
		     */ 
		    menucols = 1;
		    menuwidth = itemwidth + 2;
		    menurows = min(total, MAX_MITEMS);
		    while (!fits(flags, 1, menuwidth))
			menuwidth--;
		}
	    }
	    if (menucols == 1)
		menurows = min(menurows, MAX_MITEMS);
	}
    }

    /*
     * Make sure the menu VT (frame) can house the title
     * vt_create adds the border cols hence FIXED_TITLE - 2
     */

    menuwidth = max(menuwidth, strlen(title) + FIXED_TITLE - 2); /* abs f16 */


    /*
     * Create a VT (frame) to house the menu
     */
    if ((vid = vt_create(title, flags, startrow, startcol, menurows,
			 menuwidth)) == VT_UNDEFINED)
    {
		
	/* 
	 * try putting the VT anywhere 
	 */
	vid = vt_create(title, flags, VT_UNDEFINED, VT_UNDEFINED,
			menurows, menuwidth);
    }
    /*
     * If the menu still can't be displayed then return FAIL
     */
    if (vid == VT_UNDEFINED) {
	mess_temp("Object can not be displayed, frame may be too large for the screen");
	return((menu_id) FAIL);
    }

    if (num >= 0)
	vt_ctl(vid, CTSETWDW, num);
    return(menu_custom(vid, mflags, menucols, itemwidth, descwidth, total, disp, arg));
}


menu_id
menu_reinit(mid, flags, menurows, menucols, disp, arg)
menu_id  mid;
unsigned flags;
int	 menurows;
int	 menucols;
struct menu_line	(*disp)();
char	*arg;
{
	char	*s;
	register menu_id	newmid;
	register vt_id	oldvid;
	register menu_id	oldmid;
	int	top, line;

	oldmid = MNU_curid;
	oldvid = vt_current(MNU_array[mid].vid);
	vt_ctl(VT_UNDEFINED, CTGETITLE, &s);
	newmid = menu_make(vt_ctl(VT_UNDEFINED, CTGETWDW), s,
		flags | VT_COVERCUR, VT_UNDEFINED, VT_UNDEFINED,
		menurows, menucols, disp, arg);
	menu_ctl(mid, CTGETPARMS, &top, &line);
	menu_close(mid);
	menu_ctl(newmid, CTSETPARMS, top, line);
	menu_current(newmid);
	if (MNU_array[mid].vid != oldvid) {
		menu_noncurrent();
		if (oldmid >= 0)
			menu_current(oldmid);
		else
			vt_current(oldvid);
	}
	return newmid;
}


/*   shrink_descriptor truncates the provided string so it will fit in a 
**   window thats the screen width minus reserved_col wide.  The
**   end of the string is replaced with TRUNCATE_STR to show that
**   the string was truncated.
**   RETURN VALUE: Pointer to the truncated string.
**   SIDE AFFECTS: The string parameter is itself may be modified. 
**                 this routine does not make a copy before truncation.
**		   If called with  the result of a multi_eval, the
**		   cur field of the attribute will be modified, affecting
**		   future multi_evals if the descriptor is not
**		   EVAL_ALWAYS
*/
char *
shrink_descriptor(str, reserved_cols)
char *str;
int   reserved_cols;
{
    int max_len;

    max_len = COLS - reserved_cols;	/* longest string desired */
    if (strlen(str) > max_len && max_len >= LEN_TRUNC_STR)
	strcpy((str + max_len - LEN_TRUNC_STR), TRUNCATE_STR);
    return(str);
}
