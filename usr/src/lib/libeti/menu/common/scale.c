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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

/* Calculate the numbers of rows and columns needed to display the menu */

void
_scale(MENU *m)
{
	int width;

	if (Items(m) && IthItem(m, 0)) {
		/* Get the width of one column */
		width = MaxName(m) + Marklen(m);

		if (ShowDesc(m) && MaxDesc(m)) {
			width += MaxDesc(m) + 1;
		}
		Itemlen(m) = width;

		/* Multiply this by the number of columns */
		width = width * Cols(m);
		/* Add in the number of spaces between columns */
		width += Cols(m) - 1;
		Width(m) = width;
	}
}

int
scale_menu(MENU *m, int *r, int *c)
{
	if (!m) {
		return (E_BAD_ARGUMENT);
	}
	if (Items(m) && IthItem(m, 0)) {
		*r = Height(m);
		*c = Width(m);
		return (E_OK);
	}
	return (E_NOT_CONNECTED);
}
