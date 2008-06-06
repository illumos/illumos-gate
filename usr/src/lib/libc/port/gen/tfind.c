/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Tree search algorithm, generalized from Knuth (6.2.2) Algorithm T.
 *
 * The NODE * arguments are declared in the lint files as char *,
 * because the definition of NODE isn't available to the user.
 */

#pragma weak _tfind = tfind

#include "lint.h"
#include <mtlib.h>
#include <sys/types.h>
#include <search.h>
#include <thread.h>
#include <synch.h>

typedef struct node { void *key; struct node *llink, *rlink; } NODE;


/*	tfind - find a node, or return 0	*/
/*
 * ky is Key to be located
 * rtp is the Address of the root of the tree
 * compar is the Comparison function
 */
void *
tfind(const void *ky, void *const *rtp,
    int (*compar)(const void *, const void *))
{
	void *key = (char *)ky;
	NODE **rootp = (NODE **)rtp;
	if (rootp == NULL)
		return (NULL);
	while (*rootp != NULL) {			/* T1: */
		int r = (*compar)(key, (*rootp)->key);	/* T2: */
		if (r == 0)
			return ((void *)*rootp);	/* Key found */
		rootp = (r < 0) ?
		    &(*rootp)->llink :		/* T3: Take left branch */
		    &(*rootp)->rlink;		/* T4: Take right branch */
	}
	return (NULL);
}
