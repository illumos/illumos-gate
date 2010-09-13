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

/* Make sure top is not within a page of the end of the menu */

void
_chk_top(MENU *m, int *top, ITEM *current)
{
	if (Y(current) < *top) {
		*top = Y(current);
	}
	if (Y(current) >= *top + Height(m)) {
		*top = Y(current) - Height(m) + 1;
	}
}

/*
 * This routine makes sure top is in the correct position
 * relative to current.  It is only used when current is
 * explicitly set.
 */

void
_chk_current(MENU *m, int *top, ITEM *current)
{
	if (Y(current) < *top) {
		*top = Y(current);
	}
	if (Y(current) >= *top + Height(m)) {
		*top = min(Y(current), Rows(m) - Height(m));
	}
}
