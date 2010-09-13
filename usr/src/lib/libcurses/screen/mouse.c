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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include "curses_inc.h"

int
mouse_set(long int mbe)
{
	if (get_mouse) {
		SP->_trap_mbe = mbe;
		(void) tputs(tparm_p1(get_mouse, mbe), 1, _outch);
		(void) fflush(SP->term_file);
		return (OK);
	}
	return (ERR);
}

int
mouse_on(long int mbe)
{
	if (get_mouse) {
		SP->_trap_mbe |= mbe;
		(void) tputs(tparm_p1(get_mouse, (long) SP->_trap_mbe),
		    1, _outch);
		(void) fflush(SP->term_file);
		return (OK);
	}
	return (ERR);
}

int
mouse_off(long int mbe)
{
	if (get_mouse) {
		SP->_trap_mbe &= ~mbe;
		(void) tputs(tparm_p1(get_mouse, (long) SP->_trap_mbe),
		    1, _outch);
		(void) fflush(SP->term_file);
		return (OK);
	}
	return (ERR);
}


int
request_mouse_pos(void)
{
	int i;

	if (req_mouse_pos) {
		(void) tputs(req_mouse_pos, 1, _outch);
		(void) fflush(SP->term_file);

		/* we now must wait for report of mouse position. How do  */
		/* we know that this is mouse position report an not any- */
		/* thing else?  thetch() returns KEY_MOUSE and the status */
		/* off all the buttons remains unchanged.		  */
		/* just to avoid going into infinite loop, we have a	  */
		/* counter.  if 1000 responses won't have what we need,	  */
		/* we'll return error					  */

		for (i = 0; i < 1000; i++) {
			if ((tgetch(1) == KEY_MOUSE) && MOUSE_POS_REPORT)
				break;
		}
		if (i == 1000)
			return (ERR);
		return (OK);
	}
	return (ERR);
}

void
wmouse_position(WINDOW *win, int *x, int *y)
{
	/* mouse pointer outside the window, store -1's into x and y */

	if (win->_begy > MOUSE_Y_POS || win->_begx > MOUSE_X_POS ||
	    win->_begy+win->_maxy < MOUSE_Y_POS ||
	    win->_begx+win->_maxx < MOUSE_X_POS) {
		*x = -1;  *y = -1;
	} else {
		*x = MOUSE_X_POS - win->_begx;
		*y = MOUSE_Y_POS - win->_begy;
	}
}


int
map_button(unsigned long a)
{
	SP->_map_mbe_to_key = a;
	return (OK);
}


unsigned long
getmouse(void)
{
	return (SP->_trap_mbe);
}


unsigned long
getbmap(void)
{
	return (SP->_map_mbe_to_key);
}
