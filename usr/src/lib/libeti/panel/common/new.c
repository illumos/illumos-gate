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

/* A panels subsystem built on curses--create a new panel */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include <curses.h>
#include "private.h"

/* add_top - Put a new or hidden panel on top of the pile */
static void
add_top(PANEL *panel)
{
	if (!_Top_panel) {
		panel-> below = 0;
		_Bottom_panel = panel;
	} else {
		_Top_panel -> above = panel;
		panel -> below = _Top_panel;
	}

	_Top_panel = panel;
	panel -> above = 0;
	panel -> obscured = 0;
	_Panel_cnt++;

	/* Determine which panels the new panel obscures */

	_intersect_panel(panel);
}

/*  new_panel    */
PANEL *
new_panel(WINDOW *window)
{
	PANEL	*panel;
	int	lines, cols;

	/* create a panel */

	if (!window || !_alloc_overlap(_Panel_cnt) ||
	    !(panel = (PANEL *) malloc(sizeof (PANEL))))
		return ((PANEL *) 0);

	panel -> win = window;
	getbegyx(window, panel -> wstarty, panel -> wstartx);
	getmaxyx(window, lines, cols);
	panel -> wendy = panel->wstarty + lines - 1;
	panel -> wendx = panel->wstartx + cols - 1;
	panel -> user = 0;

	/* put the new panel on top of the pile */

	add_top(panel);
	return (panel);
}

/*  show_panel    */
int
show_panel(PANEL *panel)
{
	/* Allocate the obscured nodes for the new panel */

	if (!panel || panel != panel -> below || !_alloc_overlap(_Panel_cnt))
		return (ERR);

	/* put the new panel on top of the pile */

	add_top(panel);
	(void) touchwin(panel -> win);
	return (OK);
}
