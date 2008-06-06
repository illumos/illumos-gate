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
 *
 * The NODE * arguments are declared in the lint files as char *,
 * because the definition of NODE isn't available to the user.
 */

#pragma weak _tdelete = tdelete
#pragma weak _tsearch = tsearch
#pragma weak _twalk = twalk

#include "lint.h"
#include "mtlib.h"
#include "libc.h"
#include <sys/types.h>
#include <search.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>



typedef struct node { char *key; struct node *llink, *rlink; } NODE;

static void __twalk(NODE *, void (*)(const void *, VISIT, int), int);


/* Find or insert key into search tree */
void *
tsearch(const void *ky, void **rtp, int (*compar)())
{
	char *key = (char *)ky;
	NODE **rootp = (NODE **)rtp;
	NODE *q;	/* New node if key not found */

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
	q = lmalloc(sizeof (NODE));		/* T5: Not found */
	if (q != NULL) {			/* Allocate new node */
		*rootp = q;			/* Link new node to old */
		q->key = key;			/* Initialize new node */
		q->llink = q->rlink = NULL;
	}
	return ((void *)q);
}

/* Delete node with key key */
void *
tdelete(const void *ky, void **rtp, int (*compar)())
{
	char *key = (char *)ky;
	NODE **rootp = (NODE **)rtp;
	NODE *p;		/* Parent of node to be deleted */
	NODE *q;	/* Successor node */
	NODE *r;	/* Right son node */
	int ans;		/* Result of comparison */

	if (rootp == NULL || (p = *rootp) == NULL)
		return (NULL);
	while ((ans = (*compar)(key, (*rootp)->key)) != 0) {
		p = *rootp;
		rootp = (ans < 0) ?
		    &(*rootp)->llink :		/* Take left branch */
		    &(*rootp)->rlink;		/* Take right branch */
		if (*rootp == NULL)
			return (NULL);		/* Key not found */
	}
	r = (*rootp)->rlink;			/* D1: */
	if ((q = (*rootp)->llink) == NULL)	/* Llink NULL? */
		q = r;
	else if (r != NULL) {			/* Rlink NULL? */
		if (r->llink == NULL) {		/* D2: Find successor */
			r->llink = q;
			q = r;
		} else {			/* D3: Find NULL link */
			for (q = r->llink; q->llink != NULL; q = r->llink)
				r = q;
			r->llink = q->rlink;
			q->llink = (*rootp)->llink;
			q->rlink = (*rootp)->rlink;
		}
	}
	lfree(*rootp, sizeof (NODE));		/* D4: Free node */
	*rootp = q;			/* Link parent to replacement */
	return ((void *)p);
}


/* Walk the nodes of a tree */
void
twalk(const void *rt,		/* Root of the tree to be walked */
	void (*action)(const void *, VISIT, int))
{
	NODE *root = (NODE *)rt;

	if (root != NULL && action != NULL)
		__twalk(root, action, 0);
}


/* Walk the nodes of a tree */
static void
__twalk(NODE *root,		/* Root of the tree to be walked */
	void (*action)(const void *, VISIT, int),
	int level)
{
	if (root->llink == NULL && root->rlink == NULL)
		(*action)(root, leaf, level);
	else {
		(*action)(root, preorder, level);
		if (root->llink != NULL)
			__twalk(root->llink, action, level + 1);
		(*action)(root, postorder, level);
		if (root->rlink != NULL)
			__twalk(root->rlink, action, level + 1);
		(*action)(root, endorder, level);
	}
}
