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

/* A panels subsystem built on curses--Delete panel routines */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include <curses.h>
#include "private.h"

/* hide_panel - Unlink a panel from the pile and remove it from the screen. */
int
hide_panel(PANEL *panel)
{
	if (!panel)
		return (ERR);

	/* It is ok to hide a panel that is already hidden. */

	if (panel == panel -> below)
		return (OK);

	/* unlink panel */

	_remove_overlap(panel);
	if (panel == _Bottom_panel)
		_Bottom_panel = panel -> above;
	else
		panel -> below -> above = panel -> above;

	if (panel == _Top_panel)
		_Top_panel = panel -> below;
	else
		panel -> above -> below = panel -> below;

	_Panel_cnt--;
	panel -> below = panel;
	return (OK);
}

/*
 * del_panel - Delete a panel from the pile
 * and free all memory associated with it.
 */
int
del_panel(PANEL *panel)
{
	return ((hide_panel(panel) == OK) ? free(panel), OK : ERR);
}

/*
 *  _remove_overlap
 * Remove all references to a panel from the obscured lists of all panels.
 * Also remove all obscured nodes from the given panel.  This routine
 * touches the appropriate places to ensure that everybody is properly
 * updated.
 */
void
_remove_overlap(PANEL *panel)
{
	PANEL		*pnl;
	_obscured_list	*obs;
	_obscured_list	*prev_obs;

	/* Make sure that the background gets updated */

	(void) touchline(stdscr, panel->wstarty,
	    panel->wendy - panel->wstarty + 1);

	/* Remove all references to the panel from the remaining panels */

	for (pnl = _Bottom_panel; pnl != panel; pnl = pnl->above) {
		if (obs = _unlink_obs(pnl, panel))
			_free_overlap(obs);
	}

	/* delete the obscured list from the panel */

	if ((obs = panel -> obscured) != 0) {
		do {
			prev_obs = obs;
			obs = obs -> next;
			_free_overlap(prev_obs);
		}
		while (obs != panel -> obscured);
		panel -> obscured = 0;
	}
}
