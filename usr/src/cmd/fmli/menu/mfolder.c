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

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#include	<stdio.h>
#include	"wish.h"
#include	"menu.h"
#include	"menudefs.h"
#include	"vtdefs.h"
#include	"terror.h"
#include	"ctl.h"
#include 	"sizes.h"

/*
 *	This is a special version of menu_make ( called folder_make ) and
 *	menu_reinit ( called folder_reinit ) that are used soley for
 *	file folder display.  Lots of assumptions are made, like that
 *	rows is always specified as 18.
 */

menu_id
folder_make(num, title, flags, startrow, startcol, menurows, menucols, disp, arg)
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
    struct	 menu_line ml;	/* item offset into menu */
    vt_id    vid;		/* vt identifier of new frame */
    int	 probrows, probcols, probwidth;	/* tmp vars */
    int	 i_num;		/* tmp var */
    int mflags = flags;		/* menu flags (as opposed to vt flags) */
    char *shrink_folder();
    bool has_description = FALSE;

	menurows = 18;
	menucols = 0;

    /*
     * Determine ITEMWIDTH and DESCRIPTION WIDTH
     * as well as the TOTAL number of items
     */
    itemwidth = descwidth = 0;
    ml = (*disp)(0, arg);
    for (total = 0; ml.highlight; ml = (*disp)(++total, arg)) {	
	itemwidth = max(itemwidth, strlen(ml.highlight));
	if (ml.description) {
	    has_description = TRUE;
	    descwidth = max(descwidth, strlen(ml.description));
	}
    }

    if (!total)
	return((menu_id) FAIL);	/* empty menu */

    
    if (has_description) {
/*
 *	Now truncate the highlite so that the entire description fits
 *	we only truncate the highlight if there was a description.
 *	If there is no description, we have already truncated the
 *	highlite in the dir_disp.
 */

	itemwidth = 0;

	for (i_num = 0; i_num < total; i_num++) {
	    ml = (*disp)(i_num, arg);
	    ml.highlight = shrink_folder(ml.highlight,
			( COLS - FIXED_COLS - descwidth - 3 ));
	    itemwidth = max(itemwidth, strlen(ml.highlight));
	}
	/*
	 * If ANY item has a description, then stay single column,
	 *
	 *	width = longest highlight +
	 *		longest description +
	 *		3 (for the " - ") +
	 *		2 (for space between text and sides)
	 *
	 */
	/*
	 * actual rows = min(specified rows, 
	 *		     fittable rows,
	 *		     needed rows);
	 */ 
	for ( ; !fits(flags, menurows, 1); menurows--)
	    ;
	if (menurows > total)
	    menurows = total;
	menucols = 1;
	menuwidth = itemwidth + descwidth + 5;

	/*
	 * if the description is too long, then truncate 
	 */
	for ( ; !fits(flags, menurows, menuwidth); menuwidth--) 
	    ;

    }
    else {
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

    /*
     * Make sure the menu VT (frame) can house the title
     * vt_create adds the border cols hence FIXED_TITLE - 2
     */
    /* made it FIXED_TITLE -3 to min. testing impact. -2 is better in longterm */
    menuwidth = max(menuwidth, strlen(title) + FIXED_TITLE - 3);


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
folder_reinit(mid, flags, menurows, menucols, disp, arg)
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
	newmid = folder_make(vt_ctl(VT_UNDEFINED, CTGETWDW), s,
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

/*   shrink_folder truncates the provided string so it will fit in a 
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
shrink_folder(str, max_len)
char *str;
int   max_len;
{
    if (strlen(str) > max_len)
	strcpy((str + max_len - 1), ">");
    return(str);
}
