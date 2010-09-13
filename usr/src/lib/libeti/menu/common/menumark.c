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
#include <strings.h>
#include "private.h"

int
set_menu_mark(MENU *m, char *mark)
{
	int len;	/* Length of mark */

	if (mark && *mark) {
		/*LINTED [E_ASSIGN_INT_TO_SMALL_INT]*/
		len = strlen(mark);
	} else {
		return (E_BAD_ARGUMENT);
	}
	if (m) {
		if (Posted(m) && len != Marklen(m)) {
			return (E_BAD_ARGUMENT);
		}
		Mark(m) = mark;
		Marklen(m) = len;
		if (Posted(m)) {
			_draw(m);		/* Redraw menu */
			_show(m);		/* Redisplay menu */
		} else {
			_scale(m);		/* Redo sizing information */
		}
	} else {
		Mark(Dfl_Menu) = mark;
		Marklen(Dfl_Menu) = len;
	}
	return (E_OK);
}

char *
menu_mark(MENU *m)
{
	return (Mark(m ? m : Dfl_Menu));
}
