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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <fm/libtopo.h>
#include "topo_impl.h"

/*ARGSUSED*/
void
tnode_print(tnode_t *node, void *ignore)
{
	const char *propn, *propv;
	int inum, min, max;

	topo_indent();
	topo_out(TOPO_DEBUG, "%s ", topo_name(node));
	if ((inum = topo_get_instance_num(node)) >= 0) {
		topo_out(TOPO_DEBUG, "(%d)", inum);
	} else {
		topo_get_instance_range(node, &min, &max);
		topo_out(TOPO_DEBUG, "(%d - %d)", min, max);
	}
	topo_out(TOPO_DEBUG, " [%p]\n", (void *)node);

	propn = NULL;
	while ((propn = topo_next_prop(node, propn)) != NULL) {
		propv = topo_get_prop(node, propn);
		topo_indent();
		topo_out(TOPO_DEBUG, "    %s = %s\n", propn, propv);
	}
}

tnode_t *
tnode_add_child(tnode_t *node, tnode_t *child)
{
	struct tnode_list *newchild;
	struct tnode_list *lc = NULL;
	struct tnode_list *wc;

	for (wc = node->children; wc != NULL; wc = wc->next)
		lc = wc;

	newchild = topo_zalloc(sizeof (struct tnode_list));
	newchild->tnode = child;

	if (lc == NULL)
		node->children = newchild;
	else
		lc->next = newchild;

	child->parent = node;
	child->root = node->root;
	return (child);
}

void
tnode_destroy(tnode_t *node)
{
	struct tnode_list *dc, *nc;

	topo_free((void *)node->name);
	node->parent = NULL;

	dc = node->children;
	while (dc != NULL) {
		tnode_destroy(dc->tnode);
		nc = dc->next;
		topo_free(dc);
		dc = nc;
	}
	node->children = NULL;

	tprop_hash_destroy(node->props);
	node->props = NULL;

	topo_free(node);
}

struct tnode_list *
tnode_del_child(tnode_t *node, tnode_t *child)
{
	struct tnode_list *lc = NULL;
	struct tnode_list *dc;

	if (node == NULL)
		return (NULL);

	for (dc = node->children; dc != NULL; dc = dc->next) {
		if (dc->tnode == child)
			break;
		lc = dc;
	}

	/* XXX this should actually be an assert */
	if (dc == NULL) {
		topo_out(TOPO_INFO, "topo_del_child: ");
		topo_out(TOPO_INFO, "Deleting a child that doesn't exist?\n");
		return (NULL);
	}

	if (lc == NULL)
		node->children = dc->next;
	else
		lc->next = dc->next;

	return (dc);
}

tnode_t *
tnode_dup(tnode_t *src)
{
	const char *propn;
	tnode_t *tmpc;
	tnode_t *new;
	tnode_t *nc;

	new = topo_zalloc(sizeof (tnode_t));
	new->name = topo_strdup(src->name);
	new->state = src->state;
	new->u.range.min = src->u.range.min;
	new->u.range.max = src->u.range.max;

	tmpc = NULL;
	while ((tmpc = topo_next_child(src, tmpc)) != NULL) {
		nc = tnode_dup(tmpc);
		(void) tnode_add_child(new, nc);
	}

	propn = NULL;
	while ((propn = topo_next_prop(src, propn)) != NULL)
		(void) topo_set_prop(new, propn, topo_get_prop(src, propn));

	return (new);
}

uint_t
tnode_depth(tnode_t *node)
{
	if (node == NULL || node->state == TOPO_ROOT)
		return (0);
	else
		return (1 + tnode_depth(topo_parent(node)));
}

const char *
topo_name(tnode_t *node)
{
	return (node->name);
}

tnode_t *
topo_getroot(tnode_t *node)
{
	return (node->root);
}

tnode_t *
topo_create(tnode_t *parent, const char *nodename)
{
	tnode_t *new;

	new = topo_zalloc(sizeof (tnode_t));
	new->name = topo_strdup(nodename);
	new->state = TOPO_LIMBO;

	if (parent == NULL) {
		new->state = TOPO_ROOT;
		new->root = new;
		return (new);
	}

	return (tnode_add_child(parent, new));
}
