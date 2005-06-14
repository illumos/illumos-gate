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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

int
set_top_row(MENU *m, int top)
{
	ITEM *current;

	if (m) {
		if (Indriver(m)) {
			return (E_BAD_STATE);
		}
		if (!Items(m)) {
			return (E_NOT_CONNECTED);
		}
		if (top < 0 || top > Rows(m) - Height(m)) {
			return (E_BAD_ARGUMENT);
		}
		if (top != Top(m)) {
			/* Get linking information if not already there */
			if (LinkNeeded(m)) {
				_link_items(m);
			}
			/* Set current to toprow */
			current = IthItem(m, RowMajor(m) ? top * Cols(m) : top);
			Pindex(m) = 0;		/* Clear the pattern buffer */
			IthPattern(m, Pindex(m)) = '\0';
			_affect_change(m, top, current);
		}
	} else {
		return (E_BAD_ARGUMENT);
	}
	return (E_OK);
}

int
top_row(MENU *m)
{
	if (m && Items(m) && IthItem(m, 0)) {
		return (Top(m));
	} else {
		return (-1);
	}
}
