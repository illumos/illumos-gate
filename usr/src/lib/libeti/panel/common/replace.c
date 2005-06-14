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

/* A panels subsystem built on curses--Replace the window in a panel */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <curses.h>
#include "private.h"

/*  replace_panel    */
int
replace_panel(PANEL *panel, WINDOW *window)
{
	if (!panel || !window)
		return (ERR);

	/* pre-allocate the overlap nodes if the panel is not hidden */

	if (panel != panel -> below) {
		if (!_alloc_overlap(_Panel_cnt - 1))
			return (ERR);

		/* Remove the window from the old location. */

		_remove_overlap(panel);
	}

	/* Find the size of the new window */

	getbegyx(window, panel -> wstarty, panel -> wstartx);
	getmaxyx(window, panel -> wendy, panel -> wendx);
	panel -> win = window;
	panel -> wendy += panel -> wstarty - 1;
	panel -> wendx += panel -> wstartx - 1;

	/* Determine which panels the new panel obscures (if not hidden) */

	if (panel != panel -> below)
		_intersect_panel(panel);
	(void) touchwin(window);
	return (OK);
}
