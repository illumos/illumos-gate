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

int
set_item_opts(ITEM *i, OPTIONS opt)
{
	if (i) {
		if (Iopt(i) != opt) {
			Iopt(i) = opt;
			/* If the item is being deactivated then unselect it */
			if ((opt & O_SELECTABLE) == 0) {
				if (Value(i)) {
					Value(i) = FALSE;
				}
			}
			if (Imenu(i) && Posted(Imenu(i))) {
				_move_post_item(Imenu(i), i);
				_show(Imenu(i));
			}
		}
	} else {
		Iopt(Dfl_Item) = opt;
	}
	return (E_OK);
}

int
item_opts_off(ITEM *i, OPTIONS opt)
{
	return (set_item_opts(i, (Iopt(i ? i : Dfl_Item)) & ~opt));
}

int
item_opts_on(ITEM *i, OPTIONS opt)
{
	return (set_item_opts(i, (Iopt(i ? i : Dfl_Item)) | opt));
}

int
item_opts(ITEM *i)
{
	return (Iopt(i ? i : Dfl_Item));
}
