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

/* A panels subsystem built on curses--Update the pile of panels */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include <curses.h>
#include "private.h"

/*
 * touch_top - Touch the line in all windows
 * which is visible above a given line
 */
static void
touch_top(PANEL *panel, int line, _obscured_list *obs, int start_x, int end_x)
{
	PANEL		*pnl;
	_obscured_list	*next_obs;

	do {
		pnl = obs -> panel_p;
		if ((next_obs = obs->next) == panel -> obscured -> next)
			next_obs = 0;

		if (line >= obs -> start && line <= obs -> end &&
		    pnl->wstartx <= end_x && pnl->wendx >= start_x) {
			(void) touchline(pnl->win, line - pnl->wstarty, 1);
			if (pnl->wstartx > start_x && pnl->wendx < end_x) {
				if (next_obs)
					touch_top(panel, line, next_obs,
					    pnl->wendx+1, end_x);
				end_x = pnl -> wstartx - 1;
			} else {
				if (pnl->wstartx <= start_x)
					start_x = pnl -> wendx + 1;
				if (pnl->wendx >= end_x)
					end_x = pnl -> wstartx - 1;
				if (start_x > end_x)
					return;
			}
		}
	}
	while ((obs = next_obs) != 0);
}

/*
 *  std_touch_top
 *  Touch the line in all windows which is visible above a given line.
 *  This routine is almost identical to touch_top, except that the "panel"
 *  is stdscr in this case.  The "obscured" list is the list of panels.
 */
static void
std_touch_top(int line, PANEL *obs_pnl, int start_x, int end_x)
{
	PANEL	*next_obs;

	do {
		next_obs = obs_pnl -> below;

		if (line >= obs_pnl->wstarty && line <= obs_pnl->wendy &&
		    obs_pnl->wstartx <= end_x && obs_pnl->wendx >= start_x) {
			(void) touchline(obs_pnl->win,
			    line - obs_pnl->wstarty, 1);
			if (obs_pnl->wstartx > start_x &&
			    obs_pnl->wendx < end_x) {
				if (next_obs)
					std_touch_top(line, next_obs,
					    obs_pnl->wendx+1, end_x);
				end_x = obs_pnl -> wstartx - 1;
			} else {
				if (obs_pnl->wstartx <= start_x)
					start_x = obs_pnl -> wendx + 1;
				if (obs_pnl->wendx >= end_x)
					end_x = obs_pnl -> wstartx - 1;
				if (start_x > end_x)
					return;
			}
		}
	}
	while ((obs_pnl = next_obs) != 0);
}

/* touchup - Touch lines in obscuring panals as necessary */
static void
touchup(PANEL *panel)
{
	int	screen_y, i;

	/*
	 * for each line in the window which has been touched,
	 * touch lines in panals above it.
	 */

	screen_y = panel->wendy;

	for (i = panel->wendy - panel->wstarty; i >= 0; screen_y--, i--) {
		if (is_linetouched(panel -> win, i) == TRUE)
			touch_top(panel, screen_y, panel->obscured->next,
			    panel->wstartx, panel->wendx);
	}
}

/*
 * std_touchup
 * Touch lines in obscuring panals as necessary.  This routine is
 * almost exactly like touchup, except that the "panel" is stdscr,
 * and the obscured list is the list of panels.
 */
static void
std_touchup(void)
{
	int	screen_y;

	/*
	 * for each line in stdscr which has been touched,
	 * touch lines in panals above it.
	 */

	for (screen_y = LINES - 1; screen_y >= 0; screen_y--) {
		if (is_linetouched(stdscr, screen_y) == TRUE)
			std_touch_top(screen_y, _Top_panel, 0, COLS - 1);
	}
}

/* update_panels - Refresh the pile of panels */
void
update_panels(void)
{
	PANEL	*panel;

	/*
	 * if stdscr has been touched, touch the visible lines
	 * in each panel.
	 */

	if (is_wintouched(stdscr)) {
	    if (_Bottom_panel)
		std_touchup();

	    (void) wnoutrefresh(stdscr);
	}

	/*
	 * Refresh panals starting at the bottom of the pile.
	 * If a line in a window has been touched, touch all
	 * corresponding lines in the obscuring windows.
	 */

	for (panel = _Bottom_panel; panel; panel = panel -> above) {
		if (is_wintouched(panel -> win)) {
			if (panel -> obscured)
				touchup(panel);
			(void) wnoutrefresh(panel -> win);
		}
	}
}
