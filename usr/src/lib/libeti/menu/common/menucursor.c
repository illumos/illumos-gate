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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

/* Position the cursor in the user's subwindow. */

void
_position_cursor(MENU *m)
{
	int y, x;
	WINDOW *us, *uw;

	if (Posted(m)) {
		/* x and y represent the position in our subwindow */
		y = Y(Current(m)) - Top(m);
		x = X(Current(m))*(Itemlen(m)+1);

		if (ShowMatch(m)) {
			if (Pindex(m)) {
				x += Pindex(m) + Marklen(m) - 1;
			}
		}

		uw = UW(m);
		us = US(m);
		(void) wmove(us, y, x);

		if (us != uw) {
			wcursyncup(us);
			wsyncup(us);
			/*
			 * The next statement gets around some aberrant
			 * behavior in curses. The subwindow is never being
			 * untouched and this results in the parent window
			 * being touched every time a syncup is done.
			 */
			(void) untouchwin(us);
		}
	}
}

int
pos_menu_cursor(MENU *m)
{
	if (!m) {
		return (E_BAD_ARGUMENT);
	}
	if (!Posted(m)) {
		return (E_NOT_POSTED);
	}
	_position_cursor(m);
	return (E_OK);
}
