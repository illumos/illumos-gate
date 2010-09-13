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
/*  Copyright (c) 1988 AT&T */
/*    All Rights Reserved   */


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

/*
 *  These routines short-circuit much of the innards of curses in order to get
 *  a single character output to the screen quickly!
 *
 *  pechochar(WINDOW *pad, chtype ch) is functionally equivalent to
 *  waddch(WINDOW *pad, chtype ch), prefresh(WINDOW *pad, `the same arguments
 *  as in the last prefresh or pnoutrefresh')
 */

#include	<sys/types.h>
#include	"curses_inc.h"

int
pechowchar(WINDOW *pad, chtype ch)
{
	WINDOW *padwin;
	int	rv;

	/*
	 * If pad->_padwin exists(meaning that p*refresh have been
	 * previously called), call wechochar on it.  Otherwise, call
	 * wechochar on the pad itself
	 */

	if ((padwin = pad->_padwin) != NULL) {
		padwin->_cury = pad->_cury - padwin->_pary;
		padwin->_curx = pad->_curx - padwin->_parx;
		rv = wechowchar(padwin, ch);
		pad->_cury = padwin->_cury + padwin->_pary;
		pad->_curx = padwin->_curx + padwin->_parx;
		return (rv);
	} else
	return (wechowchar(pad, ch));
}
