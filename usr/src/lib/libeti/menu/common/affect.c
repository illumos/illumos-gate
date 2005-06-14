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
 * Copyright (c) 1997, by Sun Mircrosystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

/*
 * This routine checks the supplied values against the values of
 * current and top items.  If a value has changed then one of
 * terminate routines is called.  Following the actual change of
 * the value is the calling of the initialize routines.
 */

void
_affect_change(MENU *m, int newtop, ITEM *newcurrent)
{
	ITEM *oldcur;
	int topchange = FALSE, curchange = FALSE;

	/* Call term and init routines if posted */
	if (Posted(m)) {

		/* If current has changed terminate the old item. */
		if (newcurrent != Current(m)) {
			Iterm(m);
			curchange = TRUE;
		}

		/* If top has changed then call menu init function */
		if (newtop != Top(m)) {
			Mterm(m);
			topchange = TRUE;
		}

		oldcur = Current(m);
		Top(m) = newtop;
		Current(m) = newcurrent;

		if (topchange) {
			/* Init the new page if top has changed */
			Minit(m);
		}

		if (curchange) {
			/* Unmark the old item and mark  the new one */
			_movecurrent(m, oldcur);
			/* Init the new item if current changed */
			Iinit(m);
		}

		/* If anything changed go change user's copy of menu */
		if (topchange || curchange) {
			_show(m);
		} else {
			_position_cursor(m);
		}

	} else {
		/* Just change Top and Current if not posted */
		Top(m) = newtop;
		Current(m) = newcurrent;
	}
}
