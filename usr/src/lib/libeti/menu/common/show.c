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

/* Display that portion of the menu visable to the user */

void
_show(MENU *m)
{
	int r, c;
	WINDOW *us;

	if (Posted(m) || Indriver(m)) {
		(void) mvderwin(Sub(m), Top(m), 0);
		us = US(m);
		getmaxyx(us, r, c);
		r = min(Height(m), r);
		c = min(Width(m), c);
		(void) copywin(Sub(m), us, 0, 0, 0, 0, r-1, c-1, FALSE);
		_position_cursor(m);
	}
}
