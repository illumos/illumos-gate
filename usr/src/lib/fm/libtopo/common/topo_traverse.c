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
#include "topo_impl.h"
#include "libtopo.h"

tnode_t *
topo_parent(tnode_t *node)
{
	return (node->parent);
}

tnode_t *
topo_next_child(tnode_t *parent, tnode_t *prevchild)
{
	struct tnode_list *wc;

	if (parent == NULL && prevchild == NULL)
		return (topo_root());

	if (parent->children == NULL)
		return (NULL);

	if (prevchild == NULL)
		return (parent->children->tnode);

	for (wc = parent->children; wc != NULL; wc = wc->next)
		if (wc->tnode == prevchild)
			break;

	if (wc == NULL || wc->next == NULL)
		return (NULL);

	return (wc->next->tnode);
}

tnode_t *
topo_next_sibling(tnode_t *node, tnode_t *prevsib)
{
	tnode_t *parent;

	if (node == NULL && prevsib == NULL)
		return (topo_root());

	if (node == NULL)
		return (NULL);

	parent = topo_parent(node);
	if (parent == NULL)
		return (NULL);

	return (topo_next_child(parent, prevsib));
}

int
topo_get_instance_num(tnode_t *node)
{
	if (node->state == TOPO_LIMBO || node->state == TOPO_RANGE)
		return (-1);
	return (node->u.inst);
}

void
topo_get_instance_range(tnode_t *node, int *min, int *max)
{
	if (node->state == TOPO_LIMBO || node->state == TOPO_INST) {
		if (min != NULL)
			*min = -1;
		if (max != NULL)
			*max = -1;
		return;
	}
	if (min != NULL)
		*min = node->u.range.min;
	if (max != NULL)
		*max = node->u.range.max;
}

extern int Topo_depth;

void
topo_walk(tnode_t *start, int flag, void *arg,
    void (*cb)(tnode_t *, void *))
{
	struct tnode_list *nwc, *wc;

	if (flag & TOPO_VISIT_SELF_FIRST && start->state != TOPO_ROOT)
		cb(start, arg);

	/*
	 * Go through the children but do so in a manner such that we
	 * never use a pointer that could have changed from underneath
	 * us.  We can't just use a simple loop.  A child might delete
	 * itself from our list and if we just loop we'll follow a
	 * stray pointer.  A child might establish more children, and
	 * we don't want to miss out on visiting them, either. (For
	 * example when we are enumerating).
	 */
	Topo_depth++;
	for (wc = start->children; wc != NULL; ) {
		if (flag & TOPO_DESTRUCTIVE_WALK)
			nwc = wc->next;
		topo_walk(wc->tnode, flag, arg, cb);
		if (flag & TOPO_DESTRUCTIVE_WALK)
			wc = nwc;
		else
			wc = wc->next;
	}
	Topo_depth--;

	if (flag & TOPO_VISIT_SELF_FIRST && !(flag & TOPO_REVISIT_SELF))
		return;

	if (start->state != TOPO_ROOT)
		cb(start, arg);
}
