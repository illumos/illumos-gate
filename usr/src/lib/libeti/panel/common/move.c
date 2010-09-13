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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

/* A panels subsystem built on curses--Move a panel */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <curses.h>
#include "private.h"

/*  move_panel    */
int
move_panel(PANEL *panel, int starty, int startx)
{
	if (!panel)
		return (ERR);

	/* Check for hidden panels and move the window */

	if (panel == panel -> below) {
		if (mvwin(panel -> win, starty, startx) == ERR)
			return (ERR);
	} else {

		/*
		 * allocate nodes for overlap of new panel and move
		 * the curses window, removing it from the old location.
		 */

		if (!_alloc_overlap(_Panel_cnt - 1) ||
		    mvwin(panel -> win, starty, startx) == ERR)
			return (ERR);

		_remove_overlap(panel);
	}

	/* Make sure we know where the window is */

	getbegyx(panel -> win, panel -> wstarty, panel -> wstartx);
	getmaxyx(panel -> win, panel -> wendy, panel -> wendx);
	panel -> wendy += panel -> wstarty - 1;
	panel -> wendx += panel -> wstartx - 1;

	/* Determine which panels the new panel obscures (if not hidden) */

	if (panel != panel -> below)
		_intersect_panel(panel);
	return (OK);
}
