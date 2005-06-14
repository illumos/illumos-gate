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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

#include	<curses.h>
#include	"wish.h"
#include	"vt.h"
#include	"vtdefs.h"

/* set in if_init.c */
extern int	Work_col;
extern char	*Work_msg;

/*
 * puts up or removes "Working" message on status line at "Work_col"
 */

void
working(flag)
bool	flag;
{
/* new */
	WINDOW		*win;

	win = VT_array[ STATUS_WIN ].win;
	if (flag)
		mvwaddstr(win, 0, Work_col, Work_msg);
	else {
		wmove(win, 0, Work_col);
		wclrtoeol(win);		/* assumes right-most! */
	}
	wnoutrefresh( win );
	if ( flag )
		doupdate();
}
