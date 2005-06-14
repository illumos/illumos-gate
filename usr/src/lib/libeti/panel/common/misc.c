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

/* A panels subsystem built on curses--Miscellaneous routines */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include <curses.h>
#include "private.h"

PANEL	*_Bottom_panel;
PANEL	*_Top_panel;
int	_Panel_cnt;

static	_obscured_list	*_Free_list;
static int	_Free_list_cnt;


/* panel_window - Return the window pointer */
WINDOW *
panel_window(PANEL *panel)
{
	return (panel ? panel -> win : 0);
}

/* panel_userptr - Return the user pointer */
char *
panel_userptr(PANEL *panel)
{
	return (panel ? panel -> user : 0);
}

/* set_panel_userptr - set the user pointer */
int
set_panel_userptr(PANEL *panel, char *ptr)
{
	if (panel) {
		panel -> user = ptr;
		return (OK);
	} else
		return (ERR);
}

/*
 * panel_above - Return the panel above the
 * given panel (or the bottom panel in 0)
 */
PANEL *
panel_above(PANEL *panel)
{

	if (!panel)
		return (_Bottom_panel);

	return ((panel == panel -> below) ? ((PANEL *) 0) : panel -> above);
}


/*
 * panel_below - Return the panel below the
 * given panel (or the top panel in 0)
 */
PANEL *
panel_below(PANEL *panel)
{

	if (!panel)
		return (_Top_panel);

	return ((panel == panel -> below) ? ((PANEL *) 0) : panel -> below);
}

/* panel_hidden - Return TRUE if the panel is hidden, FALSE if not.  */
int
panel_hidden(PANEL *panel)
{
	return ((!panel || (panel != panel -> below)) ? FALSE : TRUE);
}

/* _get_overlap - Get an overlap node from the free list. */
static _obscured_list *
_get_overlap(void)
{
	_obscured_list	*overlap;

	if (_Free_list_cnt-- > 0) {
		overlap = _Free_list;
		_Free_list = _Free_list -> next;
	} else {
		_Free_list_cnt = 0;
		overlap = 0;
	}

	return (overlap);
}


/*
 * _unlink_obs - Find the obscured node, if any,
 * in the first panel which refers the second panel.
 */
_obscured_list *
_unlink_obs(PANEL *pnl, PANEL *panel)
{
	_obscured_list	*obs;
	_obscured_list	*prev_obs;

	if (!pnl -> obscured || !_panels_intersect(pnl, panel))
		return ((_obscured_list *) 0);

	obs = pnl -> obscured;
	do {
		prev_obs = obs;
		obs = obs -> next;
	}
	while (obs->panel_p != panel && obs != pnl->obscured);
	if (obs -> panel_p != panel) {
#ifdef DEBUG
		fprintf(stderr, "_unlink_obs:  Obscured panel lost\n");
#endif
		return ((_obscured_list *) 0);
	}

	if (obs == prev_obs)
		pnl -> obscured = 0;
	else {
		prev_obs -> next = obs -> next;
		if (obs == pnl -> obscured)
			pnl -> obscured = prev_obs;
	}
	return (obs);
}

/*
 * add_obs - Add an obscured node to a panel, ensuring
 * that the obscured list is ordered from top to bottom.
 */
static void
add_obs(PANEL *panel, _obscured_list *obs)
{
	PANEL		*pnl;
	_obscured_list	*curr_obs;
	_obscured_list	*prev_obs;

	if ((prev_obs = panel -> obscured) == 0) {
		panel -> obscured = obs -> next = obs;
		return;
	}

	curr_obs = prev_obs -> next;

	for (pnl = _Top_panel; pnl != panel; pnl = pnl->below) {
		if (curr_obs -> panel_p == pnl) {
			prev_obs = curr_obs;
			curr_obs = curr_obs -> next;
			if (prev_obs == panel -> obscured) {
				panel -> obscured = obs;
				break;
			}
		}
	}

	obs -> next = curr_obs;
	prev_obs -> next = obs;
}


/*
 *  _intersect_panel
 * Create an obscured node for each panel that the given panel intersects.
 * The overlap record is always attached to the panel which is covered up.
 *
 * This routine assumes that _alloc_overlap() has been called to ensure
 * that there are enough overlap nodes to satisfy the requests.
 */
void
_intersect_panel(PANEL *panel)
{
	PANEL		*pnl;
	_obscured_list	*obs;
	int		above_panel;

	above_panel = FALSE;

	for (pnl = _Bottom_panel; pnl; pnl = pnl -> above) {
		if (pnl == panel) {
			above_panel = TRUE;
			continue;
		}

		if (!_panels_intersect(pnl, panel))
			continue;	/* no overlap */

		obs = _get_overlap();
		obs->start = (panel->wstarty >= pnl->wstarty) ?
				panel->wstarty : pnl->wstarty;
		obs->end = (panel->wendy <= pnl->wendy) ?
				panel->wendy : pnl->wendy;

		if (above_panel) {
			obs -> panel_p = pnl;
			if (panel -> obscured) {
				obs -> next = panel -> obscured -> next;
				panel -> obscured -> next = obs;
			} else
				obs -> next = panel -> obscured = obs;
		} else {
			obs -> panel_p = panel;
			add_obs(pnl, obs);
		}

	}
}

/*
 *  _alloc_overlap
 * Create enough obscured nodes to record all overlaps of a given
 * panel.  The obscured nodes must be pre-allocated by this routine
 * to preserve the integrity of the pile during move.
 * If the move operation fails, the pile is supposed to remain
 * unchanged.  If the obscured nodes are not allocated in advance,
 * then an allocation failure in the middle of a move could
 * leave the pile in a corrupted state with possibly no way to
 * restore the pile to its original state.
 *
 * The cnt parameter is the(worst case) number of overlap nodes which
 * are required to satisfy any request.  Return 0 on error, else non-zero
 */
int
_alloc_overlap(int cnt)
{
	_obscured_list	*overlap;
	int		i;

	for (i = cnt-_Free_list_cnt; i > 0; i--) {
		if (!(overlap = (_obscured_list *)
		    malloc(sizeof (_obscured_list))))
			return (0);

		overlap -> next = _Free_list;
		_Free_list = overlap;
		_Free_list_cnt++;
	}

	return (1);
}


/*
 * _free_overlap - Free a single overlap node.  Don't
 * really free it; just save it on a list.
 */
void
_free_overlap(_obscured_list *overlap)
{
	overlap -> next = _Free_list;
	_Free_list = overlap;
	_Free_list_cnt++;
}
