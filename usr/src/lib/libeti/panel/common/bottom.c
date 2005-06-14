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

/* A panels subsystem built on curses--Move a panel to the bottom */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <curses.h>
#include "private.h"

/*  bottom_panel    */
int
bottom_panel(PANEL *panel)
{
	PANEL	*pnl;
	_obscured_list	*obs;

	if (!panel || panel == panel -> below)
		return (ERR);

	/* If the panel is already on bottom, there is nothing to do */

	if (_Bottom_panel == panel)
		return (OK);

	/*
	 * All the panels that this panel used to obscure now
	 * obscure this panel.
	 */

	for (pnl = panel->below; pnl; pnl = pnl->below) {
		if (obs = _unlink_obs(pnl, panel)) {
			obs -> panel_p = pnl;
			if (panel -> obscured) {
				obs -> next = panel -> obscured -> next;
				panel->obscured = panel->obscured->next = obs;
			}
			else
				obs -> next = panel -> obscured = obs;
		}
	}

	/* Move the panel to the bottom */

	if (panel == _Top_panel)
		(_Top_panel = panel -> below) -> above = 0;
	else {
		panel -> above -> below = panel -> below;
		panel -> below -> above = panel -> above;
	}

	panel -> below = 0;
	panel -> above = _Bottom_panel;
	_Bottom_panel = _Bottom_panel -> below = panel;
	(void) touchwin(panel -> win);

	return (OK);
}
