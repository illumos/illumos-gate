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
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <strings.h>
#include "cryptoadm.h"


/*
 * Create one item of type mechlist_t with the mechanism name.  A null is
 * returned to indicate that the storage space available is insufficient.
 */
mechlist_t *
create_mech(char *name)
{
	mechlist_t *pres = NULL;
	char *first, *last;

	if (name == NULL) {
		return (NULL);
	}

	pres = malloc(sizeof (mechlist_t));
	if (pres == NULL) {
		cryptodebug("out of memory.");
		return (NULL);
	}

	first = name;
	while (isspace(*first)) /* nuke leading whitespace */
	    first++;
	(void) strlcpy(pres->name, first, sizeof (pres->name));

	last = strrchr(pres->name, '\0');
	last--;
	while (isspace(*last))  /* nuke trailing whitespace */
	    *last-- = '\0';

	pres->next = NULL;

	return (pres);
}



void
free_mechlist(mechlist_t *plist)
{
	mechlist_t *pnext;

	while (plist != NULL) {
		pnext = plist->next;
		free(plist);
		plist = pnext;
	}
}



/*
 * Check if the mechanism is in the mechanism list.
 */
boolean_t
is_in_list(char *mechname, mechlist_t *plist)
{
	boolean_t found = B_FALSE;

	if (mechname == NULL) {
		return (B_FALSE);
	}

	while (plist != NULL) {
		if (strcmp(plist->name, mechname) == 0) {
			found = B_TRUE;
			break;
		}
		plist = plist->next;
	}

	return (found);
}
