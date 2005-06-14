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

/* A panels subsystem built on curses--Move a panel to the top */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <curses.h>
#include "private.h"

/*  top_panel    */
int
top_panel(PANEL *panel)
{
	_obscured_list	*obs;
	_obscured_list	*prev_obs, *tmp;

	if (!panel || panel == panel -> below)
		return (ERR);

	/* If the panel is already on top, there is nothing to do */

	if (_Top_panel == panel)
		return (OK);

	/*
	 * All the panels that used to obscure this panel are
	 * now obscured by this panel.
	 */

	if ((obs = panel -> obscured) != 0) {
		do {
			prev_obs = obs;
			obs = obs -> next;
			if ((tmp = prev_obs -> panel_p -> obscured) != 0) {
				prev_obs->next = tmp->next;
				tmp->next = prev_obs;
			} else
				prev_obs->next =
				    prev_obs->panel_p->obscured = prev_obs;
			prev_obs -> panel_p = panel;
		}
		while (obs != panel -> obscured);
		panel -> obscured = 0;
	}

	/* Move the panel to the top */

	if (panel == _Bottom_panel)
		(_Bottom_panel = panel -> above) -> below = 0;
	else {
		panel -> above -> below = panel -> below;
		panel -> below -> above = panel -> above;
	}

	panel -> above = 0;
	panel -> below = _Top_panel;
	_Top_panel = _Top_panel -> above = panel;
	(void) touchwin(panel -> win);

	return (OK);
}
