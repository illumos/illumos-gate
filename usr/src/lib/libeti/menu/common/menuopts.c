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
set_menu_opts(MENU *m, int opt)
{
	ITEM **ip;

	if (m) {
		if (Posted(m)) {
			return (E_POSTED);
		}

		/* Check to see if the ROWMAJOR option is changing.  If so, */
		/* set top and current to 0. */
		if ((opt & O_ROWMAJOR) != RowMajor(m)) {
			Top(m) = 0;
			Current(m) = IthItem(m, 0);
			(void) set_menu_format(m, FRows(m), FCols(m));
		}

		/* if O_NONCYCLIC option changed, set bit to re-link items */
		if ((opt & O_NONCYCLIC) != (Mopt(m) & O_NONCYCLIC)) {
			SetLink(m);
		}

		Mopt(m) = opt;
		if (OneValue(m) && Items(m)) {
			for (ip = Items(m); *ip; ip++) {
				/* Unset values if selection not allowed. */
				Value(*ip) = FALSE;
			}
		}
		_scale(m);		/* Redo sizing information */
	} else {
		Mopt(Dfl_Menu) = opt;
	}
	return (E_OK);
}

int
menu_opts_off(MENU *m, OPTIONS opt)
{
	return (set_menu_opts(m, (Mopt(m ? m : Dfl_Menu)) & ~opt));
}

int
menu_opts_on(MENU *m, OPTIONS opt)
{
	return (set_menu_opts(m, (Mopt(m ? m : Dfl_Menu)) | opt));
}

OPTIONS
menu_opts(MENU *m)
{
	return (Mopt(m ? m : Dfl_Menu));
}
