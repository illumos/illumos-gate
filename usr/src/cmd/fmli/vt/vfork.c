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
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5 */

#include	<curses.h>
#include	<term.h>
#include	"wish.h"

/* Functions for use before and after forking processes */

void
vt_before_fork()
{
	endwin();
}

void
vt_after_fork()
{
	/*
	 * Reset color pairs upon return from UNIX ....
	 * If this isn't a color terminal then set_def_colors()
	 * returns without doing anything
	 *
	 * Also re-set mouse information (vinit.c)
	 */
        /*
         * Reset PFK for terminals like DMD and 5620
         */
        init_sfk(FALSE);
	set_def_colors();
	set_mouse_info();
}

void
fork_clrscr()
{
	putp(tparm(clear_screen));
	fflush(stdout);
}
