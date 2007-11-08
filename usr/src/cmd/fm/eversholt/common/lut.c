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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include "lut_impl.h"
#include "tree.h"

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
	struct lut **tmp_hdl = &root, *parent = NULL, *tmp = root;

	while (tmp) {
		if (cmp_func)
			diff = (*cmp_func)(tmp->lut_lhs, lhs);
		else
			diff = (const char *)lhs - (const char *)tmp->lut_lhs;

		if (diff == 0) {
			/* already in tree, replace node */
			tmp->lut_rhs = rhs;
			return (root);
		} else if (diff > 0) {
			tmp_hdl = &(tmp->lut_left);
			parent = tmp;
			tmp = tmp->lut_left;
		} else {
			tmp_hdl = &(tmp->lut_right);
			parent = tmp;
			tmp = tmp->lut_right;
		}
	}

	/* either empty tree or not in tree, so create new node */
	*tmp_hdl = MALLOC(sizeof (*root));
	(*tmp_hdl)->lut_lhs = lhs;
	(*tmp_hdl)->lut_rhs = rhs;
	(*tmp_hdl)->lut_parent = parent;
	(*tmp_hdl)->lut_left = (*tmp_hdl)->lut_right = NULL;
	stats_counter_bump(Addtotal);

	return (root);
}

void *
lut_lookup(struct lut *root, void *lhs, lut_cmp cmp_func)
{
	int diff;

	stats_counter_bump(Lookuptotal);

	while (root) {
		if (cmp_func)
			diff = (*cmp_func)(root->lut_lhs, lhs);
		else
			diff = (const char *)lhs - (const char *)root->lut_lhs;

		if (diff == 0)
			return (root->lut_rhs);
		else if (diff > 0)
			root = root->lut_left;
		else
			root = root->lut_right;
	}
	return (NULL);
}

void *
lut_lookup_lhs(struct lut *root, void *lhs, lut_cmp cmp_func)
{
	int diff;

	stats_counter_bump(Lookuptotal);

	while (root) {
		if (cmp_func)
			diff = (*cmp_func)(root->lut_lhs, lhs);
		else
			diff = (const char *)lhs - (const char *)root->lut_lhs;

		if (diff == 0)
			return (root->lut_lhs);
		else if (diff > 0)
			root = root->lut_left;
		else
			root = root->lut_right;
	}
	return (NULL);
}

/*
 * lut_walk -- walk the table in lexical order
 */
void
lut_walk(struct lut *root, lut_cb callback, void *arg)
{
	struct lut *tmp = root;
	struct lut *prev_child = NULL;

	if (root == NULL)
		return;

	while (tmp->lut_left != NULL)
		tmp = tmp->lut_left;

	/* do callback on leftmost node */
	(*callback)(tmp->lut_lhs, tmp->lut_rhs, arg);

	for (;;) {
		if (tmp->lut_right != NULL && tmp->lut_right != prev_child) {
			tmp = tmp->lut_right;
			while (tmp->lut_left != NULL)
				tmp = tmp->lut_left;

			/* do callback on leftmost node */
			(*callback)(tmp->lut_lhs, tmp->lut_rhs, arg);
		} else if (tmp->lut_parent != NULL) {
			prev_child = tmp;
			tmp = tmp->lut_parent;
			/*
			 * do callback on parent only if we're coming up
			 * from the left
			 */
			if (tmp->lut_right != prev_child)
				(*callback)(tmp->lut_lhs, tmp->lut_rhs, arg);
		} else
			return;
	}
}

/*
 * lut_free -- free the lut
 */
void
lut_free(struct lut *root, lut_cb callback, void *arg)
{
	struct lut *tmp = root;
	struct lut *prev_child = NULL;

	if (root == NULL)
		return;

	while (tmp->lut_left != NULL)
		tmp = tmp->lut_left;

	/* do callback on leftmost node */
	if (callback)
		(*callback)(tmp->lut_lhs, tmp->lut_rhs, arg);

	for (;;) {
		if (tmp->lut_right != NULL && tmp->lut_right != prev_child) {
			tmp = tmp->lut_right;
			while (tmp->lut_left != NULL)
				tmp = tmp->lut_left;

			/* do callback on leftmost node */
			if (callback)
				(*callback)(tmp->lut_lhs, tmp->lut_rhs, arg);
		} else if (tmp->lut_parent != NULL) {
			prev_child = tmp;
			tmp = tmp->lut_parent;
			FREE(prev_child);
			/*
			 * do callback on parent only if we're coming up
			 * from the left
			 */
			if (tmp->lut_right != prev_child && callback)
				(*callback)(tmp->lut_lhs, tmp->lut_rhs, arg);
		} else {
			/*
			 * free the root node and then we're done
			 */
			FREE(tmp);
			return;
		}
	}
}
