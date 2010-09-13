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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.6	*/

/*LINTLIBRARY*/

#include <sys/types.h>
#include "private.h"

int
set_menu_items(MENU *m, ITEM **i)
{
	if (!m) {
		return (E_BAD_ARGUMENT);
	}
	if (i && *i == (ITEM *) NULL) {
		return (E_BAD_ARGUMENT);
	}
	if (Posted(m)) {
		return (E_POSTED);
	}

	if (Items(m)) {
		_disconnect(m);
	}
	if (i) {
		/* Go test the item and make sure its not already connected */
		/* to another menu and then connect it to this one. */
		if (!_connect(m, i)) {
			return (E_CONNECTED);
		}
	} else {
		Items(m) = i;
	}
	return (E_OK);
}

ITEM **
menu_items(MENU *m)
{
	if (!m) {
		return ((ITEM **) NULL);
	}
	return (Items(m));
}
