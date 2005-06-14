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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.8	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

int
set_menu_format(MENU *m, int rows, int cols)
{
	if (rows < 0 || cols < 0) {
		return (E_BAD_ARGUMENT);
	}
	if (m) {
		if (Posted(m)) {
			return (E_POSTED);
		}
		if (rows == 0) {
			rows = FRows(m);
		}
		if (cols == 0) {
			cols = FCols(m);
		}

		/* The pattern buffer is allocated after items have been */
		/* connected */
		if (Pattern(m)) {
			IthPattern(m, 0) = '\0';
			Pindex(m) = 0;
		}

		FRows(m) = rows;
		FCols(m) = cols;
		Cols(m) = min(cols, Nitems(m));
		Rows(m) = (Nitems(m)-1) / cols + 1;
		Height(m) = min(rows, Rows(m));
		Top(m) = 0;
		Current(m) = IthItem(m, 0);
		SetLink(m);
		_scale(m);
	} else {
		if (rows > 0) {
			FRows(Dfl_Menu) = rows;
		}
		if (cols > 0) {
			FCols(Dfl_Menu) = cols;
		}
	}
	return (E_OK);
}

void
menu_format(MENU *m, int *rows, int *cols)
{
	if (m) {
		*rows = FRows(m);
		*cols = FCols(m);
	} else {
		*rows = FRows(Dfl_Menu);
		*cols = FCols(Dfl_Menu);
	}
}
