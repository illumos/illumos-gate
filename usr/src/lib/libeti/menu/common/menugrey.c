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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

int
set_menu_grey(MENU *m, chtype attr)
{
	/*LINTED [E_CONST_PROMOTED_UNSIGNED_LONG]*/
	if (InvalidAttr(attr)) {
		return (E_BAD_ARGUMENT);
	}
	if (m) {
		Grey(m) = attr;
		if (Posted(m)) {
			_draw(m);		/* Redraw the menu */
			_show(m);		/* Redisplay menu */
		}
	} else {
		Grey(Dfl_Menu) = attr;
	}
	return (E_OK);
}

chtype
menu_grey(MENU *m)
{
	return (Grey(m ? m : Dfl_Menu));
}
