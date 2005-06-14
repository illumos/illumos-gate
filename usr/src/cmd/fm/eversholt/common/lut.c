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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * lut.c -- simple lookup table module
 *
 * this file contains a very simple lookup table (lut) implementation.
 * the tables only support insert & lookup, no delete, and can
 * only be walked in one order.  if the key already exists
 * for something being inserted, the previous entry is simply
 * replaced.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include "alloc.h"
#include "out.h"
#include "stats.h"
#include "lut.h"
#include "tree.h"

/* info created by lut_add(), private to this module */
struct lut {
	struct lut *lut_left;
	struct lut *lut_right;
	void *lut_lhs;		/* search key */
	void *lut_rhs;		/* the datum */
};

static struct stats *Addtotal;
static struct stats *Lookuptotal;
static struct stats *Freetotal;

void
lut_init(void)
{
	Addtotal = stats_new_counter("lut.adds", "total adds", 1);
	Lookuptotal = stats_new_counter("lut.lookup", "total lookups", 1);
	Freetotal = stats_new_counter("lut.frees", "total frees", 1);
}

void
lut_fini(void)
{
	stats_delete(Addtotal);
	stats_delete(Lookuptotal);
	stats_delete(Freetotal);
}

/*
 * lut_add -- add an entry to the table
 *
 * use it like this:
 *	struct lut *root = NULL;
 *	root = lut_add(root, key, value, cmp_func);
 *
 * the cmp_func can be strcmp().  pass in NULL and instead of
 * calling a cmp_func the routine will just look at the difference
 * between key pointers (useful when all strings are kept in a
 * string table so they are equal if their pointers are equal).
 *
 */
struct lut *
lut_add(struct lut *root, void *lhs, void *rhs, lut_cmp cmp_func)
{
	int diff;

	if (root == NULL) {
		/* not in tree, create new node */
		root = MALLOC(sizeof (*root));
		root->lut_lhs = lhs;
		root->lut_rhs = rhs;
		root->lut_left = root->lut_right = NULL;
		stats_counter_bump(Addtotal);
		return (root);
	}

	if (cmp_func)
		diff = (*cmp_func)(root->lut_lhs, lhs);
	else
		diff = (const char *)lhs - (const char *)root->lut_lhs;

	if (diff == 0) {
		/* already in tree, replace node */
		root->lut_rhs = rhs;
	} else if (diff > 0)
		root->lut_left = lut_add(root->lut_left, lhs, rhs, cmp_func);
	else
		root->lut_right = lut_add(root->lut_right, lhs, rhs, cmp_func);
	return (root);
}

/*
 * lut_lookup -- find an entry
 */
void *
lut_lookup(struct lut *root, void *lhs, lut_cmp cmp_func)
{
	int diff;

	stats_counter_bump(Lookuptotal);

	if (root == NULL)
		return (NULL);

	if (cmp_func)
		diff = (*cmp_func)(root->lut_lhs, lhs);
	else
		diff = (const char *)lhs - (const char *)root->lut_lhs;

	if (diff == 0) {
		return (root->lut_rhs);
	} else if (diff > 0)
		return (lut_lookup(root->lut_left, lhs, cmp_func));
	else
		return (lut_lookup(root->lut_right, lhs, cmp_func));
}

/*
 * lut_lookup_lhs -- find an entry, return the matched key (lut_lhs)
 */
void *
lut_lookup_lhs(struct lut *root, void *lhs, lut_cmp cmp_func)
{
	int diff;

	stats_counter_bump(Lookuptotal);

	if (root == NULL)
		return (NULL);

	if (cmp_func)
		diff = (*cmp_func)(root->lut_lhs, lhs);
	else
		diff = (const char *)lhs - (const char *)root->lut_lhs;

	if (diff == 0) {
		return (root->lut_lhs);
	} else if (diff > 0)
		return (lut_lookup_lhs(root->lut_left, lhs, cmp_func));
	else
		return (lut_lookup_lhs(root->lut_right, lhs, cmp_func));
}

/*
 * lut_walk -- walk the table in lexical order
 */
void
lut_walk(struct lut *root, lut_cb callback, void *arg)
{
	if (root) {
		lut_walk(root->lut_left, callback, arg);
		(*callback)(root->lut_lhs, root->lut_rhs, arg);
		lut_walk(root->lut_right, callback, arg);
	}
}

/*
 * lut_free -- free the lut
 */
void
lut_free(struct lut *root, lut_cb callback, void *arg)
{
	if (root) {
		lut_free(root->lut_left, callback, arg);
		root->lut_left = NULL;
		lut_free(root->lut_right, callback, arg);
		root->lut_right = NULL;
		if (callback)
			(*callback)(root->lut_lhs, root->lut_rhs, arg);
		FREE(root);
		stats_counter_bump(Freetotal);
	}
}
