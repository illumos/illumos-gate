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

int
topo_set_prop(tnode_t *node, const char *name, const char *val)
{
	struct tprop *newp = NULL;
	struct tprop *wp;

	/* does a properties table even exist yet? */
	if (node->props == NULL) {
		node->props = tprop_hash_create();
		topo_out(TOPO_HASH, "prop hash for %p is %p\n", (void *)node,
		    (void *)node->props);
		newp = tprop_create(name, val);
		tprop_hash_insert(node->props, name, newp);
		if (node->state == TOPO_INST)
			tprop_index(node, name);
		return (0);
	}

	wp = tprop_hash_lookup(node->props, name);
	for (; wp != NULL; wp = wp->p_next) {
		if ((strcmp(wp->p_name, name)) == 0) {
			newp = wp;
			break;
		}
	}

	/*
	 * XXX any issue here for someone who's already looked up the
	 * property and saved that pointer?  Probably not, as they
	 * would have just used it right away...  Does that argue we
	 * should return an alloc'd buffer?
	 */
	if (newp != NULL) {
		/* replacing existing property */
		topo_out(TOPO_DEBUG,
		    "in %p replace %s (= %s) with %s\n",
		    (void *)node->props, name, newp->p_val, val);
		topo_free((void *)newp->p_val);
		newp->p_val = topo_strdup(val);
		return (0);
	}

	newp = tprop_create(name, val);
	tprop_hash_insert(node->props, name, newp);
	if (node->state == TOPO_INST)
		tprop_index(node, name);
	return (0);
}

const char *
topo_get_prop(tnode_t *node, const char *propname)
{
	struct tprop *wp;
	int c = -1;

	if (node->props == NULL)
		return (NULL);

	wp = tprop_hash_lookup(node->props, propname);
	for (; wp != NULL; wp = wp->p_next)
		if ((c = strcmp(wp->p_name, propname)) == 0)
			break;
	return ((c == 0) ? wp->p_val : NULL);
}

const char *
topo_next_prop(tnode_t *node, const char *prevprop)
{
	struct tprop *wp = NULL;

	if (node->props == NULL)
		return (NULL);

	if (prevprop != NULL) {
		wp = tprop_hash_lookup(node->props, prevprop);
		for (; wp != NULL; wp = wp->p_next)
			if (strcmp(wp->p_name, prevprop) == 0)
				break;
	}

	if ((wp = tprop_hash_lookup_next(node->props, prevprop, wp)) == NULL)
		return (NULL);
	return (wp->p_name);
}

tnode_t *
topo_match_childr(tnode_t *node, int min, int max)
{
	tnode_t *tmp = NULL;

	while ((tmp = topo_next_child(topo_parent(node), tmp)) != NULL) {
		if (tmp->state == TOPO_RANGE &&
		    tmp->u.range.min == min && tmp->u.range.max == max &&
		    strcmp(topo_name(tmp), topo_name(node)) == 0)
			break;
	}
	return (tmp);
}

tnode_t *
topo_match_childi(tnode_t *node, int instance)
{
	tnode_t *tmp = NULL;

	while ((tmp = topo_next_child(topo_parent(node), tmp)) != NULL)
		if (tmp->state == TOPO_INST && tmp->u.inst == instance &&
		    strcmp(topo_name(tmp), topo_name(node)) == 0)
			break;
	return (tmp);
}

static void
dup_children(tnode_t *from, tnode_t *to)
{
	tnode_t *tmp = NULL;
	tnode_t *nc;

	if (from == NULL || from->children == NULL)
		return;

	while ((tmp = topo_next_child(from, tmp)) != NULL) {
		nc = tnode_dup(tmp);
		(void) tnode_add_child(to, nc);
	}
}

static void
dup_props(tnode_t *from, tnode_t *to)
{
	const char *propn;

	propn = NULL;
	while ((propn = topo_next_prop(from, propn)) != NULL)
		(void) topo_set_prop(to, propn, topo_get_prop(from, propn));
}

static void
inherit_props(tnode_t *node)
{
	tnode_t *tmp = NULL;

	while ((tmp = topo_next_child(topo_parent(node), tmp)) != NULL)
		if (tmp->state == TOPO_RANGE &&
		    strcmp(topo_name(tmp), topo_name(node)) == 0 &&
		    tmp->u.range.min <= node->u.inst &&
		    tmp->u.range.max >= node->u.inst)
			dup_props(tmp, node);
}

static void
inherit_children(tnode_t *node)
{
	/*
	 * for a confirmed instance number, have it inherit copies of the
	 * children of any 'range' nodes it falls within
	 */
	tnode_t *tmp = NULL;

	while ((tmp = topo_next_child(topo_parent(node), tmp)) != NULL) {
		if (tmp->state == TOPO_RANGE &&
		    strcmp(topo_name(tmp), topo_name(node)) == 0 &&
		    tmp->u.range.min <= node->u.inst &&
		    tmp->u.range.max >= node->u.inst)
			dup_children(tmp, node);
	}
}

tnode_t *
topo_set_instance_num(tnode_t *node, int instance)
{
	tnode_t *tmp;
	tnode_t *new;

	topo_out(TOPO_DEBUG, "topo_set_instance_num:  %p [%d].\n",
	    (void *)node, instance);

	if (node->state == TOPO_LIMBO) {
		node->state = TOPO_INST;
		node->u.inst = instance;
		return (node);
		/*NOTREACHED*/
	}

	tmp = topo_match_childi(node, instance);
	if (tmp != NULL) {
		return (tmp);
		/*NOTREACHED*/
	}

	new = topo_create(topo_parent(node), topo_name(node));
	(void) topo_set_instance_num(new, instance);

	inherit_props(new);
	inherit_children(new);
	return (new);
}

tnode_t *
topo_set_instance_range(tnode_t *node, int min, int max)
{
	tnode_t *tmp;
	tnode_t *new;

	if (min > max || node == NULL)
		return (NULL);

	if (node->state == TOPO_LIMBO) {
		node->state = TOPO_RANGE;
		node->u.range.min = min;
		node->u.range.max = max;
		return (node);
		/*NOTREACHED*/
	}

	tmp = topo_match_childr(node, min, max);
	if (tmp != NULL) {
		return (tmp);
		/*NOTREACHED*/
	}

	new = topo_create(topo_parent(node), topo_name(node));
	(void) topo_set_instance_range(new, min, max);

	return (new);
}
