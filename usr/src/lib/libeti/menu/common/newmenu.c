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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "private.h"

MENU *
new_menu(ITEM **items)
{
	MENU *m;

	if ((m = (MENU *) calloc(1, sizeof (MENU))) != (MENU *)0) {
		*m = *Dfl_Menu;
		Rows(m) = FRows(m);
		Cols(m) = FCols(m);
		if (items) {
			if (*items == (ITEM *)0 || !_connect(m, items)) {
				free(m);
				return ((MENU *)0);
			}
		}
		return (m);
	}
	return ((MENU *)0);
}

int
free_menu(MENU *m)
{
	if (!m) {
		return (E_BAD_ARGUMENT);
	}
	if (Posted(m)) {
		return (E_POSTED);
	}
	if (Items(m)) {
		_disconnect(m);
	}
	free(m);
	return (E_OK);
}
