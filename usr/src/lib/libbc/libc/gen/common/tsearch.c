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
/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
/*
 * Tree search algorithm, generalized from Knuth (6.2.2) Algorithm T.
 *
 *
 * The NODE * arguments are declared in the lint files as char *,
 * because the definition of NODE isn't available to the user.
 */

#include <search.h>
#include <stdio.h>
#include <malloc.h>

typedef char *POINTER;
typedef struct node { POINTER key; struct node *llink, *rlink; } NODE;

/*
 * Find or insert key into search tree
 *
 * Arguments
 *	key:	Key to be located
 *	rootp:	Address of the root of the tree
 *	compar:	Comparison function
 */
NODE *
tsearch(POINTER key, NODE **rootp, int (*compar)(POINTER, POINTER))
{
	NODE *q;	/* New node if key not found */

	if (rootp == NULL)
		return (NULL);
	while (*rootp != NULL) {			/* T1: */
		int r = (*compar)(key, (*rootp)->key);	/* T2: */
		if (r == 0)
			return (*rootp);	/* Key found */
		rootp = (r < 0) ?
		    &(*rootp)->llink :		/* T3: Take left branch */
		    &(*rootp)->rlink;		/* T4: Take right branch */
	}
	q = (NODE *) malloc(sizeof(NODE));	/* T5: Not found */
	if (q != NULL) {			/* Allocate new node */
		*rootp = q;			/* Link new node to old */
		q->key = key;			/* Initialize new node */
		q->llink = q->rlink = NULL;
	}
	return (q);
}

/*
 * Delete node with key key
 *
 * Arguments
 *	key:	Key to be deleted
 *	rootp:	Address of the root of tree
 *	compar:	Comparison function
 */
NODE *
tdelete(POINTER key, NODE **rootp, int (*compar)(POINTER, POINTER))
{
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
	free((POINTER) *rootp);		/* D4: Free node */
	*rootp = q;			/* Link parent to replacement */
	return (p);
}

static void	_twalk(NODE *, void (*)(NODE *, VISIT, int), int);

/*
 * Walk the nodes of a tree
 *
 * Arguments
 *	root:	Root of the tree to be walked
 *	action:	Function to be called at each node
 */
void
twalk(NODE *root, void (*action)(NODE *, VISIT, int))
{

	if (root != NULL && action != NULL)
		_twalk(root, action, 0);
}

/*
 * Walk the nodes of a tree
 *
 * Arguments
 *	root:	Root of the tree to be walked
 *	action:	Function to be called at each node
 */
static void
_twalk(NODE *root, void (*action)(NODE *, VISIT, int), int level)
{
	if (root->llink == NULL && root->rlink == NULL)
		(*action)(root, leaf, level);
	else {
		(*action)(root, preorder, level);
		if (root->llink != NULL)
			_twalk(root->llink, action, level + 1);
		(*action)(root, postorder, level);
		if (root->rlink != NULL)
			_twalk(root->rlink, action, level + 1);
		(*action)(root, endorder, level);
	}
}
