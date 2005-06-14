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

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 2.3 */

/*LINTLIBRARY*/
/*
 * Tree search algorithm, generalized from Knuth (6.2.2) Algorithm T.
 *
 *
 * The NODE * arguments are declared in the lint files as char *,
 * because the definition of NODE isn't available to the user.
 */

#include <search.h>
typedef char *POINTER;
typedef struct node { POINTER key; struct node *llink, *rlink; } NODE;

#define	NULL	0

extern char *malloc();

NODE *
tsearch(key, rootp, compar)	/* Find or insert key into search tree*/
POINTER	key;			/* Key to be located */
register NODE	**rootp;	/* Address of the root of the tree */
int	(*compar)();		/* Comparison function */
{
	register NODE *q;	/* New node if key not found */

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

NODE *
tdelete(key, rootp, compar)	/* Delete node with key key */
POINTER	key;			/* Key to be deleted */
register NODE	**rootp;	/* Address of the root of tree */
int	(*compar)();		/* Comparison function */
{
	NODE *p;		/* Parent of node to be deleted */
	register NODE *q;	/* Successor node */
	register NODE *r;	/* Right son node */
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

void
twalk(root, action)		/* Walk the nodes of a tree */
NODE	*root;			/* Root of the tree to be walked */
void	(*action)();		/* Function to be called at each node */
{
	void _twalk();

	if (root != NULL && action != NULL)
		_twalk(root, action, 0);
}

static void
_twalk(root, action, level)	/* Walk the nodes of a tree */
register NODE	*root;		/* Root of the tree to be walked */
register void	(*action)();	/* Function to be called at each node */
register int	level;
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
