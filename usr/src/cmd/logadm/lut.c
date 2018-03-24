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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * logadm/lut.c -- simple lookup table module
 *
 * this file contains a very simple lookup table (lut) implementation.
 * the tables only support insert & lookup, no delete, and can
 * only be walked in lexical order.  if the key already exists
 * for something being inserted, the previous entry is simply
 * replaced.  the left-hand-side (lhs), which is the key, is
 * copied into malloc'd memory.  the right-hand-side (rhs), which
 * is the datum, is not copied (in fact, the lut routines don't
 * know the size or type of the datum, just the void * pointer to it).
 *
 * yea, this module could be much fancier and do much more, but
 * the idea was to keep it really simple and just provide what
 * was needed by logadm for options processing.
 */

#include <stdio.h>
#include <strings.h>
#include "err.h"
#include "lut.h"

/* forward declarations of functions private to this module */
static void dooper(const char *lhs, void *rhs, void *arg);

/* info created by lut_add() and lut_dup(), private to this module */
struct lut {
	struct lut *lut_left;
	struct lut *lut_right;
	char *lut_lhs;		/* search key */
	void *lut_rhs;		/* the datum */
};

/*
 * lut_add -- add an entry to the table
 *
 * use it like this:
 *	struct lut *root = NULL;
 *	root = lut_add(root, "key", value);
 *
 * the key string gets strdup'd by lut_add(), but the memory holding
 * the *value should not be freed until the lut is freed by lut_free().
 */
struct lut *
lut_add(struct lut *root, const char *lhs, void *rhs)
{
	int diff = 0;

	if (root == NULL) {
		/* not in tree, create new node */
		root = MALLOC(sizeof (*root));
		root->lut_lhs = STRDUP(lhs);
		root->lut_rhs = rhs;
		root->lut_left = root->lut_right = NULL;
	} else if (lhs != NULL && (diff = strcmp(root->lut_lhs, lhs)) == 0) {
		/* already in tree, replace node */
		root->lut_rhs = rhs;
	} else if (diff > 0)
		root->lut_left = lut_add(root->lut_left, lhs, rhs);
	else
		root->lut_right = lut_add(root->lut_right, lhs, rhs);
	return (root);
}

/* helper function for lut_dup() */
static void
dooper(const char *lhs, void *rhs, void *arg)
{
	struct lut **rootp = (struct lut **)arg;

	*rootp = lut_add(*rootp, lhs, rhs);
}

/*
 * lut_dup -- duplicate a lookup table
 *
 * caller is responsible for keeping track of how many tables are keeping
 * pointers to the void * datum values.
 */
struct lut *
lut_dup(struct lut *root)
{
	struct lut *ret = NULL;

	lut_walk(root, dooper, &ret);

	return (ret);
}

/*
 * lut_lookup -- find an entry
 */
void *
lut_lookup(struct lut *root, const char *lhs)
{
	int diff;

	if (root == NULL || lhs == NULL)
		return (NULL);
	else if ((diff = strcmp(root->lut_lhs, lhs)) == 0)
		return (root->lut_rhs);
	else if (diff > 0)
		return (lut_lookup(root->lut_left, lhs));
	else
		return (lut_lookup(root->lut_right, lhs));
}

/*
 * lut_walk -- walk the table in lexical order
 */
void
lut_walk(struct lut *root,
    void (*callback)(const char *lhs, void *rhs, void *arg), void *arg)
{
	if (root) {
		lut_walk(root->lut_left, callback, arg);
		(*callback)(root->lut_lhs, root->lut_rhs, arg);
		lut_walk(root->lut_right, callback, arg);
	}
}

/*
 * lut_free -- free a lut
 *
 * if callback is provided, it is called for each value in the table.
 * it the values are things that the caller malloc'd, then you can do:
 *	lut_free(root, free);
 */
void
lut_free(struct lut *root, void (*callback)(void *rhs))
{
	if (root != NULL) {
		lut_free(root->lut_left, callback);
		lut_free(root->lut_right, callback);
		FREE(root->lut_lhs);
		if (callback)
			(*callback)(root->lut_rhs);
		FREE(root);
	}
}


#ifdef	TESTMODULE

void
printer(const char *lhs, void *rhs, void *arg)
{
	printf("<%s> <%s> (<%s>)\n", lhs, (char *)rhs,
	    (char *)lut_lookup(arg, lhs));
}

/*
 * test main for lut module, usage: a.out [lhs[=rhs]...]
 */
int
main(int argc, char *argv[])
{
	struct lut *r = NULL;
	struct lut *dupr = NULL;
	char *equals;

	err_init(argv[0]);
	setbuf(stdout, NULL);

	for (argv++; *argv; argv++)
		if ((equals = strchr(*argv, '=')) != NULL) {
			*equals++ = '\0';
			r = lut_add(r, *argv, equals);
		} else
			r = lut_add(r, *argv, "NULL");

	printf("lut contains:\n");
	lut_walk(r, printer, r);

	dupr = lut_dup(r);

	lut_free(r, NULL);

	printf("dup lut contains:\n");
	lut_walk(dupr, printer, dupr);

	lut_free(dupr, NULL);

	err_done(0);
	/* NOTREACHED */
	return (0);
}

#endif	/* TESTMODULE */
