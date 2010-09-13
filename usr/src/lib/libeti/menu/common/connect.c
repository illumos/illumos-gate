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
#include <stdlib.h>
#include "private.h"

/* Connect and disconnect an item list from a menu */


/* Find the maximum length name and description */

static void
maxlengths(MENU *m)
{
	int maxn, maxd;
	ITEM **ip;

	maxn = maxd = 0;
	for (ip = Items(m); *ip; ip++) {
		if (NameLen(*ip) > maxn) {
			maxn = NameLen(*ip);
		}
		if (DescriptionLen(*ip) > maxd) {
			maxd = DescriptionLen(*ip);
		}
	}
	MaxName(m) = maxn;
	MaxDesc(m) = maxd;
}

int
_connect(MENU *m, ITEM **items)
{
	ITEM **ip;
	int i;

	/* Is the list of items connected to any other menu? */
	for (ip = items; *ip; ip++) {
		/* Return Null if item points to a menu */
		if (Imenu(*ip)) {
			return (FALSE);
		}
	}

	for (i = 0, ip = items; *ip; ip++) {
		/* Return FALSE if this item is a prevoious item */
		if (Imenu(*ip)) {
			for (ip = items; *ip; ip++) {
				/* Reset index and menu pointers */
				Index(*ip) = 0;
				Imenu(*ip) = (MENU *) NULL;
			}
			return (FALSE);
		}
		if (OneValue(m)) {
			/* Set all values to FALSE if selection not allowed */
			Value(*ip) = FALSE;
		}
		Index(*ip) = i++;
		Imenu(*ip) = m;
	}

	Nitems(m) = i;
	Items(m) = items;

	/* Go pick up the sizes of names and descriptions */
	maxlengths(m);

	/* Set up match buffer */
	if ((Pattern(m) = (char *)malloc((unsigned)MaxName(m)+1)) ==
	    (char *)0) {
		return (FALSE);
	}

	IthPattern(m, 0) = '\0';
	Pindex(m) = 0;
	(void) set_menu_format(m, FRows(m), FCols(m));
	Current(m) = IthItem(m, 0);
	Top(m) = 0;
	return (TRUE);
}

void
_disconnect(MENU *m)
{
	ITEM **ip;

	for (ip = Items(m); *ip; ip++) {
		/* Release items for another menu */
		Imenu(*ip) = (MENU *) NULL;
	}
	free(Pattern(m));
	Pattern(m) = NULL;
	Items(m) = (ITEM **) NULL;
	Nitems(m) = 0;
}
