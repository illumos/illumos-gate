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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * lgroup topology
 */

#include <sys/cpupart.h>
#include <sys/lgrp.h>
#include <sys/promif.h>
#include <sys/types.h>


#define	LGRP_TOPO_LEVELS	4	/* default height limit */
#define	LGRP_TOPO_LEVELS_MAX	4	/* max height limit */


/*
 * Only collapse lgroups which have same latency (and resources)
 */
int		lgrp_collapse_equidist = 1;

int		lgrp_collapse_off = 1;	/* disable collapsing of duplicates */

/*
 * Height to limit lgroup topology
 */
unsigned int	lgrp_topo_levels = LGRP_TOPO_LEVELS;

int		lgrp_split_off = 1;	/* disable splitting lgroups */

#ifdef	DEBUG
/*
 * Debugging output
 * - 0: off
 * - >0: on and bigger means more
 */
int	lgrp_topo_debug = 0;


void
klgrpset_print(klgrpset_t lgrpset)
{
	int	i;


	prom_printf("0x%llx(", (u_longlong_t)lgrpset);
	for (i = 0; i <= lgrp_alloc_max; i++)
		if (klgrpset_ismember(lgrpset, i))
			prom_printf("%d ", i);
	prom_printf(")\n");
}


void
lgrp_rsets_print(char *string, klgrpset_t *rsets)
{
	int	i;

	prom_printf("%s\n", string);
	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		klgrpset_print(rsets[i]);
}
#endif	/* DEBUG */


/*
 * Add "from" lgroup resources to "to" lgroup resources
 */
void
lgrp_rsets_add(klgrpset_t *from, klgrpset_t *to)
{
	int	i;

	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		klgrpset_or(to[i], from[i]);
}


/*
 * Copy "from" lgroup resources to "to" lgroup resources
 */
void
lgrp_rsets_copy(klgrpset_t *from, klgrpset_t *to)
{
	int	i;

	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		to[i] = from[i];
}


/*
 * Delete given lgroup ID from lgroup resource set of specified lgroup
 * and its ancestors if "follow_parent" is set
 */
void
lgrp_rsets_delete(lgrp_t *lgrp, lgrp_id_t lgrpid, int follow_parent)
{
	int	i;

	while (lgrp != NULL) {
		for (i = 0; i < LGRP_RSRC_COUNT; i++)
			klgrpset_del(lgrp->lgrp_set[i], lgrpid);
		if (!follow_parent)
			break;
		lgrp = lgrp->lgrp_parent;
	}
}


/*
 * Return whether given lgroup resource set empty
 */
int
lgrp_rsets_empty(klgrpset_t *rset)
{
	int	i;

	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		if (!klgrpset_isempty(rset[i]))
			return (0);

	return (1);
}


/*
 * Return whether given lgroup resource sets are same
 */
int
lgrp_rsets_equal(klgrpset_t *rset1, klgrpset_t *rset2)
{
	int	i;

	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		if (rset1[i] != rset2[i])
			return (0);

	return (1);
}


/*
 * Return whether specified lgroup ID is in given lgroup resource set
 */
int
lgrp_rsets_member(klgrpset_t *rset, lgrp_id_t lgrpid)
{
	int	i;

	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		if (klgrpset_ismember(rset[i], lgrpid))
			return (1);

	return (0);
}


/*
 * Return whether specified lgroup ID is in all lgroup resources
 */
int
lgrp_rsets_member_all(klgrpset_t *rset, lgrp_id_t lgrpid)
{
	int	i;

	for (i = 0; i < LGRP_RSRC_COUNT; i++)
		if (!klgrpset_ismember(rset[i], lgrpid))
			return (0);

	return (1);
}


/*
 * Replace resources for given lgroup with specified resources at given
 * latency and shift its old resources to its parent and its parent's resources
 * to its parent, etc. until root lgroup reached
 */
void
lgrp_rsets_replace(klgrpset_t *rset, int latency, lgrp_t *lgrp, int shift)
{
	lgrp_t		*cur;
	int		lat_new;
	int		lat_saved;
	klgrpset_t	rset_new[LGRP_RSRC_COUNT];
	klgrpset_t	rset_saved[LGRP_RSRC_COUNT];

	cur = lgrp;
	lat_saved = latency;
	lgrp_rsets_copy(rset, rset_saved);
	while (cur && cur != lgrp_root) {
		/*
		 * Save current resources and latency to insert in parent and
		 * then replace with new resources and latency
		 */
		lgrp_rsets_copy(rset_saved, rset_new);
		lgrp_rsets_copy(cur->lgrp_set, rset_saved);
		lgrp_rsets_copy(rset_new, cur->lgrp_set);

		lat_new = lat_saved;
		lat_saved = cur->lgrp_latency;
		cur->lgrp_latency = lat_new;
		if (!shift)
			break;
		cur = cur->lgrp_parent;
	}
}


/*
 * Set "to" lgroup resource set with given lgroup ID
 */
void
lgrp_rsets_set(klgrpset_t *to, lgrp_id_t lgrpid)
{
	klgrpset_t	from;
	int		i;

	klgrpset_clear(from);
	klgrpset_add(from, lgrpid);
	for (i = 0; i < LGRP_RSRC_COUNT; i++) {
		klgrpset_clear(to[i]);
		klgrpset_or(to[i], from);
	}
}


/*
 * Delete any ancestors of given child lgroup which don't have any other
 * children
 */
int
lgrp_ancestor_delete(lgrp_t *child, klgrpset_t *changed)
{
	int		count;
	lgrp_t		*current;
	lgrp_id_t	lgrpid;
	lgrp_t		*parent;

#ifdef	DEBUG
	if (lgrp_topo_debug > 1) {
		prom_printf("lgrp_ancestor_delete(0x%p[%d],0x%p)\n",
		    (void *)child, child->lgrp_id, (void *)changed);
	}
#endif	/* DEBUG */

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	/*
	 * Visit ancestors, decrement child count for each, and remove any
	 * that don't have any children left until we reach an ancestor that
	 * has multiple children
	 */
	current = child;
	parent = child->lgrp_parent;
	lgrpid = current->lgrp_id;
	while (parent != NULL) {
#ifdef	DEBUG
		if (lgrp_topo_debug > 1)
			prom_printf("lgrp_ancestor_delete: parent %d,"
			    " current %d\n",
			    parent->lgrp_id, lgrpid);
#endif	/* DEBUG */

		klgrpset_del(parent->lgrp_leaves, lgrpid);
		klgrpset_del(parent->lgrp_children, lgrpid);
		parent->lgrp_childcnt--;
		if (changed)
			klgrpset_add(*changed, parent->lgrp_id);
		count++;
		if (parent->lgrp_childcnt != 0)
			break;

		current = parent;
		parent = current->lgrp_parent;
		lgrpid = current->lgrp_id;

#ifdef	DEBUG
		if (lgrp_topo_debug > 0)
			prom_printf("lgrp_ancestor_delete: destroy"
			    " lgrp %d at 0x%p\n",
			    current->lgrp_id, (void *)current);
#endif	/* DEBUG */
		lgrp_destroy(current);
	}

#ifdef	DEBUG
	if (lgrp_topo_debug > 1 && changed)
		prom_printf("lgrp_ancestor_delete: changed %d lgrps: 0x%llx\n",
		    count, (u_longlong_t)*changed);
#endif	/* DEBUG */

	return (count);
}


/*
 * Consolidate lgrp1 into lgrp2
 */
int
lgrp_consolidate(lgrp_t *lgrp1, lgrp_t *lgrp2, klgrpset_t *changed)
{
	klgrpset_t	changes;
	lgrp_t		*child;
	int		count;
	int		i;
	lgrp_t		*parent;

	/*
	 * Leaf lgroups should never need to be consolidated
	 */
	if (lgrp1 == NULL || lgrp2 == NULL || lgrp1->lgrp_childcnt < 1 ||
	    lgrp2->lgrp_childcnt < 1)
		return (0);

#ifdef	DEBUG
	if (lgrp_topo_debug > 0)
		prom_printf("lgrp_consolidate(0x%p[%d],0x%p[%d],0x%p)\n",
		    (void *)lgrp1, lgrp1->lgrp_id, (void *)lgrp2,
		    lgrp2->lgrp_id, (void *)changed);
#endif	/* DEBUG */

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	/*
	 * Lgroup represents resources within certain latency, so need to keep
	 * biggest latency value of lgroups being consolidated
	 */
	if (lgrp1->lgrp_latency > lgrp2->lgrp_latency)
		lgrp2->lgrp_latency = lgrp1->lgrp_latency;

	/*
	 * Delete ancestors of lgrp1 that don't have any other children
	 */
#ifdef	DEBUG
	if (lgrp_topo_debug > 1)
		prom_printf("lgrp_consolidate: delete ancestors\n");
#endif	/* DEBUG */
	count += lgrp_ancestor_delete(lgrp1, &changes);
	if (changed) {
		klgrpset_or(*changed, changes);
		klgrpset_or(*changed, lgrp1->lgrp_id);
		count++;
	}

	/*
	 * Reparent children lgroups of lgrp1 to lgrp2
	 */
	for (i = 0; i <= lgrp_alloc_max; i++) {
		if (i == lgrp2->lgrp_id ||
		    !klgrpset_ismember(lgrp1->lgrp_children, i))
			continue;
		child = lgrp_table[i];
		if (!LGRP_EXISTS(child))
			continue;
#ifdef	DEBUG
		if (lgrp_topo_debug > 0)
			prom_printf("lgrp_consolidate: reparent "
			    "lgrp %d to lgrp %d\n",
			    child->lgrp_id, lgrp2->lgrp_id);
#endif	/* DEBUG */
		klgrpset_or(lgrp2->lgrp_leaves, child->lgrp_leaves);
		klgrpset_add(lgrp2->lgrp_children, child->lgrp_id);
		lgrp2->lgrp_childcnt++;
		child->lgrp_parent = lgrp2;
		if (changed) {
			klgrpset_add(*changed, child->lgrp_id);
			klgrpset_add(*changed, lgrp2->lgrp_id);
		}
		count += 2;
	}

	/*
	 * Proprogate leaves from lgrp2 to root
	 */
	child = lgrp2;
	parent = child->lgrp_parent;
	while (parent != NULL) {
		klgrpset_or(parent->lgrp_leaves, child->lgrp_leaves);
		if (changed)
			klgrpset_add(*changed, parent->lgrp_id);
		count++;
		child = parent;
		parent = parent->lgrp_parent;
	}

#ifdef	DEBUG
	if (lgrp_topo_debug > 0)
		prom_printf("lgrp_consolidate: destroy lgrp %d at 0x%p\n",
		    lgrp1->lgrp_id, (void *)lgrp1);
	if (lgrp_topo_debug > 1 && changed)
		prom_printf("lgrp_consolidate: changed %d lgrps: 0x%llx\n",
		    count, (u_longlong_t)*changed);
#endif	/* DEBUG */

	lgrp_destroy(lgrp1);

	return (count);
}

/*
 * Collapse duplicates of target lgroups given
 */
int
lgrp_collapse_dups(klgrpset_t target_set, int equidist_only,
    klgrpset_t *changed)
{
	klgrpset_t	changes;
	int		count;
	int		i;

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	if (lgrp_collapse_off)
		return (0);

#ifdef	DEBUG
	if (lgrp_topo_debug > 0)
		prom_printf("lgrp_collapse_dups(0x%llx)\n",
		    (u_longlong_t)target_set);
#endif	/* DEBUG */

	/*
	 * Look for duplicates of each target lgroup
	 */
	for (i = 0; i <= lgrp_alloc_max; i++) {
		int	j;
		lgrp_t	*keep;
		lgrp_t	*target;

		target = lgrp_table[i];

		/*
		 * Skip to next lgroup if there isn't one here, this is root
		 * or leaf lgroup, or this isn't a target lgroup
		 */
		if (!LGRP_EXISTS(target) ||
		    target == lgrp_root || target->lgrp_childcnt == 0 ||
		    !klgrpset_ismember(target_set, target->lgrp_id))
			continue;

		/*
		 * Find all lgroups with same resources and latency
		 */
#ifdef	DEBUG
		if (lgrp_topo_debug > 1)
			prom_printf("lgrp_collapse_dups: find "
			    "dups of lgrp %d at 0x%p\n",
			    target->lgrp_id, (void *)target);
#endif	/* DEBUG */
		keep = NULL;
		for (j = 0; j <= lgrp_alloc_max; j++) {
			lgrp_t	*lgrp;

			lgrp = lgrp_table[j];

			/*
			 * Skip lgroup if there isn't one here, this is root
			 * lgroup or leaf (which shouldn't have dups), or this
			 * lgroup doesn't have same resources
			 */
			if (!LGRP_EXISTS(lgrp) ||
			    lgrp->lgrp_childcnt == 0 ||
			    !lgrp_rsets_equal(lgrp->lgrp_set,
			    target->lgrp_set) ||
			    (lgrp->lgrp_latency != target->lgrp_latency &&
			    equidist_only))
				continue;

			/*
			 * Keep first matching lgroup (but always keep root)
			 * and consolidate other duplicates into it
			 */
			if (keep == NULL) {
				keep = lgrp;
#ifdef	DEBUG
				if (lgrp_topo_debug > 1)
					prom_printf("lgrp_collapse_dups: "
					    "keep lgrp %d at 0x%p\n",
					    keep->lgrp_id, (void *)keep);
#endif	/* DEBUG */
			} else {
				if (lgrp == lgrp_root) {
					lgrp = keep;
					keep = lgrp_root;
				}
#ifdef	DEBUG
				if (lgrp_topo_debug > 0)
					prom_printf("lgrp_collapse_dups:"
					    " consolidate lgrp %d at 0x%p"
					    " into lgrp %d at 0x%p\n",
					    lgrp->lgrp_id, (void *)lgrp,
					    keep->lgrp_id, (void *)keep);
#endif	/* DEBUG */
				count += lgrp_consolidate(lgrp, keep,
				    &changes);
				if (changed)
					klgrpset_or(*changed, changes);
			}
		}
	}

#ifdef	DEBUG
	if (lgrp_topo_debug > 1 && changed)
		prom_printf("lgrp_collapse_dups: changed %d lgrps: 0x%llx\n",
		    count, (u_longlong_t)*changed);
#endif	/* DEBUG */

	return (count);
}


/*
 * Create new parent lgroup with given latency and resources for
 * specified child lgroup, and insert it into hierarchy
 */
int
lgrp_new_parent(lgrp_t *child, int latency, klgrpset_t *rset,
    klgrpset_t *changed)
{
	int	count;
	lgrp_t	*new;
	lgrp_t	*old;

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	/*
	 * Create lgroup and set its latency and resources
	 */
	new = lgrp_create();
	new->lgrp_latency = latency;
	lgrp_rsets_add(rset, new->lgrp_set);

	/*
	 * Insert new lgroup into hierarchy
	 */
	old = child->lgrp_parent;
	new->lgrp_parent = old;
	klgrpset_add(new->lgrp_children, child->lgrp_id);
	new->lgrp_childcnt++;
	klgrpset_add(new->lgrp_children, child->lgrp_id);
	klgrpset_copy(new->lgrp_leaves, child->lgrp_leaves);

	child->lgrp_parent = new;
	if (old) {
		klgrpset_del(old->lgrp_children, child->lgrp_id);
		klgrpset_add(old->lgrp_children, new->lgrp_id);
		if (changed)
			klgrpset_add(*changed, old->lgrp_id);
		count++;
	}

	if (changed) {
		klgrpset_add(*changed, child->lgrp_id);
		klgrpset_add(*changed, new->lgrp_id);
	}
	count += 2;

#ifdef	DEBUG
	if (lgrp_topo_debug > 1 && changed)
		prom_printf("lgrp_new_parent: changed %d lgrps: 0x%llx\n",
		    count, (u_longlong_t)*changed);
#endif	/* DEBUG */

	return (count);
}


/*
 * Proprogate resources of new leaf into parent lgroup of given child
 */
int
lgrp_proprogate(lgrp_t *newleaf, lgrp_t *child, int latency,
    klgrpset_t *changed)
{
	int	count;
	lgrp_t	*parent;

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	if (child == NULL || child->lgrp_parent == NULL)
		return (0);

	parent = child->lgrp_parent;
	klgrpset_or(parent->lgrp_leaves, child->lgrp_leaves);
	if (changed)
		klgrpset_add(*changed, parent->lgrp_id);
	count++;

	/*
	 * Don't proprogate new leaf resources to parent if it already
	 * contains these resources
	 */
	if (lgrp_rsets_member_all(parent->lgrp_set, newleaf->lgrp_id)) {
#ifdef	DEBUG
		if (lgrp_topo_debug > 1 && changed)
			prom_printf("lgrp_proprogate: changed %d lgrps:"
			    " 0x%llx\n",
			    count, (u_longlong_t)*changed);
#endif	/* DEBUG */
		return (count);
	}

	/*
	 * Add leaf resources to parent lgroup
	 */
	lgrp_rsets_add(newleaf->lgrp_set, parent->lgrp_set);

#ifdef	DEBUG
	if (lgrp_topo_debug > 1) {
		prom_printf("lgrp_proprogate: newleaf %d(0x%p), "
		    "latency %d, child %d(0x%p), parent %d(0x%p)\n",
		    newleaf->lgrp_id, (void *)newleaf, latency, child->lgrp_id,
		    (void *)child, parent->lgrp_id, (void *)parent);
		prom_printf("lgrp_proprogate: parent's leaves becomes 0x%llx\n",
		    (u_longlong_t)parent->lgrp_leaves);
	}
	if (lgrp_topo_debug > 0) {
		prom_printf("lgrp_proprogate: adding to parent %d (0x%p)\n",
		    parent->lgrp_id, (void *)parent);
		lgrp_rsets_print("parent resources become:", parent->lgrp_set);
	}

	if (lgrp_topo_debug > 2 && changed)
		prom_printf("lgrp_proprogate: changed %d lgrps: 0x%llx\n",
		    count, (u_longlong_t)*changed);

#endif	/* DEBUG */

	return (count);
}


/*
 * Split parent lgroup of given child if child's leaf decendant (oldleaf) has
 * different latency to new leaf lgroup (newleaf) than leaf lgroups of given
 * child's siblings
 */
int
lgrp_split(lgrp_t *oldleaf, lgrp_t *newleaf, lgrp_t *child,
    klgrpset_t *changed)
{
	klgrpset_t	changes;
	int		count;
	int		i;
	int		latency;
	lgrp_t		*parent;

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	if (lgrp_split_off || newleaf == NULL || child == NULL)
		return (0);

	/*
	 * Parent must have more than one child to have a child split from it
	 * and root lgroup contains all resources and never needs to be split
	 */
	parent = child->lgrp_parent;
	if (parent == NULL || parent->lgrp_childcnt < 2 || parent == lgrp_root)
		return (0);

#ifdef	DEBUG
	if (lgrp_topo_debug > 1)
		prom_printf("lgrp_split(0x%p[%d],0x%p[%d],0x%p[%d],0x%p)\n",
		    (void *)oldleaf, oldleaf->lgrp_id,
		    (void *)newleaf, newleaf->lgrp_id,
		    (void *)child, child->lgrp_id, (void *)changed);
#endif	/* DEBUG */

	/*
	 * Get latency between new leaf and old leaf whose lineage it is
	 * being added
	 */
	latency = lgrp_plat_latency(oldleaf->lgrp_plathand,
	    newleaf->lgrp_plathand);

	/*
	 * Check whether all sibling leaves of given child lgroup have same
	 * latency to new leaf
	 */
	for (i = 0; i <= lgrp_alloc_max; i++) {
		lgrp_t		*grandparent;
		lgrp_t		*lgrp;
		int		sibling_latency;

		lgrp = lgrp_table[i];

		/*
		 * Skip non-existent lgroups, old leaf, and any lgroups that
		 * don't have parent as common ancestor
		 */
		if (!LGRP_EXISTS(lgrp) || lgrp == oldleaf ||
		    !klgrpset_ismember(parent->lgrp_leaves, lgrp->lgrp_id))
			continue;

		/*
		 * Same latency, so skip
		 */
		sibling_latency = lgrp_plat_latency(lgrp->lgrp_plathand,
		    newleaf->lgrp_plathand);
#ifdef	DEBUG
		if (lgrp_topo_debug > 1)
			prom_printf("lgrp_split: latency(%d,%d) %d,"
			    " latency(%d,%d) %d\n",
			    oldleaf->lgrp_id, newleaf->lgrp_id, latency,
			    lgrp->lgrp_id, newleaf->lgrp_id, sibling_latency);
#endif	/* DEBUG */
		if (sibling_latency == latency)
			continue;

		/*
		 * Different latencies, so  remove child from its parent and
		 * make new parent for old leaf with same latency and same
		 * resources
		 */
		parent->lgrp_childcnt--;
		klgrpset_del(parent->lgrp_children, child->lgrp_id);
		klgrpset_del(parent->lgrp_leaves, oldleaf->lgrp_id);
		grandparent = parent->lgrp_parent;
		if (grandparent) {
			grandparent->lgrp_childcnt++;
			klgrpset_add(grandparent->lgrp_children,
			    child->lgrp_id);
			count++;
			if (changed)
				klgrpset_add(*changed, grandparent->lgrp_id);
		}
		child->lgrp_parent = grandparent;

		count += lgrp_new_parent(child, parent->lgrp_latency,
		    parent->lgrp_set, &changes);
		if (changed) {
			klgrpset_or(*changed, changes);

			klgrpset_add(*changed, parent->lgrp_id);
			klgrpset_add(*changed, child->lgrp_id);
			count += 2;
		}

		parent = child->lgrp_parent;
#ifdef	DEBUG
		if (lgrp_topo_debug > 0) {
			prom_printf("lgrp_split: new parent %d (0x%p) for"
			    " lgrp %d (0x%p)\n",
			    parent->lgrp_id, (void *)parent,
			    child->lgrp_id, (void *)child);
			lgrp_rsets_print("new parent resources:",
			    parent->lgrp_set);
		}

		if (lgrp_topo_debug > 1 && changed)
			prom_printf("lgrp_split: changed %d lgrps: 0x%llx\n",
			    count, (u_longlong_t)*changed);
#endif	/* DEBUG */

		return (count);
	}

#ifdef	DEBUG
	if (lgrp_topo_debug > 1)
		prom_printf("lgrp_split: no changes\n");
#endif	/* DEBUG */

	return (count);
}


/*
 * Return height of lgroup topology from given lgroup to root
 */
int
lgrp_topo_height(lgrp_t *lgrp)
{
	int	nlevels;

	if (!LGRP_EXISTS(lgrp))
		return (0);

	nlevels = 0;
	while (lgrp != NULL) {
		lgrp = lgrp->lgrp_parent;
		nlevels++;
	}
	return (nlevels);
}


/*
 * Add resources of new leaf to old leaf's lineage
 *
 * Assumes the following:
 * - Lgroup hierarchy consists of at least a root lgroup and its leaves
 *   including old and new ones given below
 * - New leaf lgroup has been created and does not need to have its resources
 *   added to it
 * - Latencies have been set for root and leaf lgroups
 */
int
lgrp_lineage_add(lgrp_t *newleaf, lgrp_t *oldleaf, klgrpset_t *changed)
{
	klgrpset_t	changes;
	lgrp_t		*child;
	klgrpset_t	collapse;
	int		count;
	int		latency;
	int		nlevels;
	lgrp_t		*parent;
	int		proprogate;
	int		total;


	count = total = 0;
	if (changed)
		klgrpset_clear(*changed);

	if (newleaf == NULL || oldleaf == NULL || newleaf == oldleaf)
		return (0);

#ifdef	DEBUG
	if (lgrp_topo_debug > 0)
		prom_printf("\nlgrp_lineage_add(0x%p[%d],0x%p[%d],0x%p)\n",
		    (void *)newleaf, newleaf->lgrp_id,
		    (void *)oldleaf, oldleaf->lgrp_id,
		    (void *)changed);
#endif	/* DEBUG */

	/*
	 * Get latency between old and new leaves, so we can determine
	 * where the new leaf fits in the old leaf's lineage
	 */
	latency = lgrp_plat_latency(oldleaf->lgrp_plathand,
	    newleaf->lgrp_plathand);

	/*
	 * Determine height of lgroup topology from old leaf to root lgroup,
	 * so height of topology may be limited if necessary
	 */
	nlevels = lgrp_topo_height(oldleaf);

#ifdef	DEBUG
	if (lgrp_topo_debug > 1)
		prom_printf("lgrp_lineage_add: latency(%d,%d) 0x%x, ht %d\n",
		    oldleaf->lgrp_id, newleaf->lgrp_id, latency, nlevels);
#endif	/* DEBUG */

	/*
	 * Can't add new leaf to old leaf's lineage if we haven't
	 * determined latency between them yet
	 */
	if (latency == 0)
		return (0);

	child = oldleaf;
	parent = child->lgrp_parent;
	proprogate = 0;
	klgrpset_clear(collapse);

	/*
	 * Lineage of old leaf is basically a sorted list of the other leaves
	 * from closest to farthest, so find where to add new leaf to the
	 * lineage and proprogate its resources from that point up to the root
	 * lgroup since parent lgroups contain all the resources of their
	 * children
	 */
	do {
		klgrpset_t	rset[LGRP_RSRC_COUNT];

#ifdef	DEBUG
		if (lgrp_topo_debug > 1)
			prom_printf("lgrp_lineage_add: child %d (0x%p), parent"
			    " %d (0x%p)\n",
			    child->lgrp_id, (void *)child,
			    parent->lgrp_id, (void *)parent);
#endif	/* DEBUG */

		/*
		 * See whether parent lgroup needs to be split
		 *
		 * May need to split parent lgroup when it is ancestor to more
		 * than one leaf, but all its leaves don't have latency to new
		 * leaf within the parent lgroup's latency
		 * NOTE: Don't want to collapse this lgroup since we just split
		 * it from parent
		 */
		count = lgrp_split(oldleaf, newleaf, child, &changes);
		if (count) {
#ifdef	DEBUG
			if (lgrp_topo_debug > 0)
				prom_printf("lgrp_lineage_add: setting parent"
				    " for child %d from %d to %d\n",
				    child->lgrp_id, parent->lgrp_id,
				    child->lgrp_parent->lgrp_id);
#endif	/* DEBUG */
			parent = child->lgrp_parent;
			total += count;
			if (changed)
				klgrpset_or(*changed, changes);
		}

		/*
		 * Already found where resources of new leaf belong in old
		 * leaf's lineage, so proprogate resources of new leaf up
		 * through rest of ancestors
		 */
		if (proprogate) {
			total += lgrp_proprogate(newleaf, child, latency,
			    &changes);
			if (changed)
				klgrpset_or(*changed, changes);

			parent = child->lgrp_parent;
			klgrpset_add(collapse, parent->lgrp_id);
			child = parent;
			parent = parent->lgrp_parent;
			continue;
		}

#ifdef	DEBUG
		if (lgrp_topo_debug > 1)
			prom_printf("lgrp_lineage_add: latency 0x%x,"
			    " parent latency 0x%x\n",
			    latency, parent->lgrp_latency);
#endif	/* DEBUG */
		/*
		 * As we work our way from the old leaf to the root lgroup,
		 * new leaf resources should go in between two lgroups or into
		 * one of the parent lgroups somewhere along the line
		 */
		if (latency < parent->lgrp_latency) {
			lgrp_t	*intermed;

			/*
			 * New leaf resources should go in between current
			 * child and parent
			 */
#ifdef	DEBUG
			if (lgrp_topo_debug > 0)
				prom_printf("lgrp_lineage_add: "
				    "latency < parent latency\n");
#endif	/* DEBUG */

			/*
			 * Create lgroup with desired resources and insert it
			 * between child and parent
			 */
			lgrp_rsets_copy(child->lgrp_set, rset);
			lgrp_rsets_add(newleaf->lgrp_set, rset);
			if (nlevels >= lgrp_topo_levels) {

#ifdef	DEBUG
				if (lgrp_topo_debug > 0) {
					prom_printf("lgrp_lineage_add: nlevels "
					    "%d > lgrp_topo_levels %d\n",
					    nlevels, lgrp_topo_levels);
					lgrp_rsets_print("rset ", rset);
				}
#endif	/* DEBUG */

				if (parent == lgrp_root) {
					/*
					 * Don't proprogate new leaf resources
					 * to parent, if it already contains
					 * these resources
					 */
					if (lgrp_rsets_member_all(
					    parent->lgrp_set, newleaf->lgrp_id))
						break;

					total += lgrp_proprogate(newleaf, child,
					    latency, &changes);
					break;
				}

#ifdef	DEBUG
				if (lgrp_topo_debug > 0) {
					prom_printf("lgrp_lineage_add: "
					    "replaced parent lgrp %d at 0x%p"
					    " for lgrp %d\n",
					    parent->lgrp_id, (void *)parent,
					    child->lgrp_id);
					lgrp_rsets_print("old parent"
					    " resources:", parent->lgrp_set);
					lgrp_rsets_print("new parent "
					    "resources:", rset);
				}
#endif	/* DEBUG */
				/*
				 * Replace contents of parent with new
				 * leaf + child resources since new leaf is
				 * closer and shift its parent's resources to
				 * its parent, etc. until root lgroup reached
				 */
				lgrp_rsets_replace(rset, latency, parent, 1);
				if (*changed)
					klgrpset_or(*changed, parent->lgrp_id);
				total++;
				proprogate++;
			} else {

#ifdef	DEBUG
				if (lgrp_topo_debug > 0) {
					prom_printf("lgrp_lineage_add: "
					    "lgrp_new_parent(0x%p,%d)\n",
					    (void *)child, latency);
					lgrp_rsets_print("rset ", rset);
				}
#endif	/* DEBUG */

				total += lgrp_new_parent(child, latency, rset,
				    &changes);
				intermed = child->lgrp_parent;
				klgrpset_add(collapse, intermed->lgrp_id);
				if (changed)
					klgrpset_or(*changed, changes);
				child = intermed;
				proprogate++;
#ifdef	DEBUG
				if (lgrp_topo_debug > 0) {
					prom_printf("lgrp_lineage_add: new "
					    "parent lgrp %d at 0x%p for "
					    "lgrp %d\n", intermed->lgrp_id,
					    (void *)intermed, child->lgrp_id);
					lgrp_rsets_print("new parent "
					    "resources:", rset);
				}
#endif	/* DEBUG */
				continue;
			}

		} else if (latency == parent->lgrp_latency) {
			/*
			 * New leaf resources should go into parent
			 */
#ifdef	DEBUG
			if (lgrp_topo_debug > 0)
				prom_printf("lgrp_lineage_add: latency == "
				    "parent latency\n");
#endif	/* DEBUG */

			/*
			 * It's already there, so don't need to do anything.
			 */
			if (lgrp_rsets_member_all(parent->lgrp_set,
			    newleaf->lgrp_id))
				break;

			total += lgrp_proprogate(newleaf, child, latency,
			    &changes);
			parent = child->lgrp_parent;
			klgrpset_add(collapse, parent->lgrp_id);
			if (changed)
				klgrpset_or(*changed, changes);

			proprogate++;
		}

		child = parent;
		parent = parent->lgrp_parent;
	} while (parent != NULL);

	/*
	 * Consolidate any duplicate lgroups of ones just changed
	 * Assume that there were no duplicates before last round of changes
	 */
#ifdef	DEBUG
	if (lgrp_topo_debug > 1)
		prom_printf("lgrp_lineage_add: collapsing dups....\n");
#endif	/* DEBUG */

	total += lgrp_collapse_dups(collapse, lgrp_collapse_equidist,
	    &changes);
	if (changed)
		klgrpset_or(*changed, changes);

#ifdef	DEBUG
	if (lgrp_topo_debug > 1 && changed)
		prom_printf("lgrp_lineage_add: changed %d lgrps: 0x%llx\n",
		    total, (u_longlong_t)*changed);
#endif	/* DEBUG */

	return (total);
}


/*
 * Add leaf lgroup to lgroup topology
 */
int
lgrp_leaf_add(lgrp_t *leaf, lgrp_t **lgrps, int lgrp_count,
    klgrpset_t *changed)
{
	klgrpset_t	changes;
	int		count;
	int		i;
	int		latency;

	ASSERT(MUTEX_HELD(&cpu_lock) || curthread->t_preempt > 0 ||
	    !lgrp_initialized);

#ifdef	DEBUG
	if (lgrp_topo_debug > 1)
		prom_printf("\nlgrp_leaf_add(0x%p[%d],0x%p,%d,0x%p)\n",
		    (void *)leaf, leaf->lgrp_id, (void *)lgrps, lgrp_count,
		    (void *)changed);
#endif	/* DEBUG */

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	/*
	 * Initialize parent of leaf lgroup to root
	 */
	if (leaf->lgrp_parent == NULL) {
		leaf->lgrp_parent = lgrp_root;
		lgrp_root->lgrp_childcnt++;
		klgrpset_add(lgrp_root->lgrp_children, leaf->lgrp_id);

		klgrpset_or(lgrp_root->lgrp_leaves, leaf->lgrp_leaves);
		lgrp_rsets_add(leaf->lgrp_set, lgrp_root->lgrp_set);

#ifdef	DEBUG
		if (lgrp_topo_debug > 1)
			lgrp_rsets_print("lgrp_leaf_add: root lgrp resources",
			    lgrp_root->lgrp_set);
#endif	/* DEBUG */

		if (changed) {
			klgrpset_add(*changed, lgrp_root->lgrp_id);
			klgrpset_add(*changed, leaf->lgrp_id);
		}
		count += 2;
	}

	/*
	 * Can't add leaf lgroup to rest of topology (and vice versa) unless
	 * latency for it is available
	 */
	latency = lgrp_plat_latency(leaf->lgrp_plathand, leaf->lgrp_plathand);
	if (latency == 0) {
#ifdef	DEBUG
		if (lgrp_topo_debug > 1 && changed)
			prom_printf("lgrp_leaf_add: changed %d lgrps: 0x%llx\n",
			    count, (u_longlong_t)*changed);
#endif	/* DEBUG */
		return (count);
	}

	/*
	 * Make sure that root and leaf lgroup latencies are set
	 */
	lgrp_root->lgrp_latency = lgrp_plat_latency(lgrp_root->lgrp_plathand,
	    lgrp_root->lgrp_plathand);
	leaf->lgrp_latency = latency;

	/*
	 * Add leaf to lineage of other leaves and vice versa
	 * since leaves come into existence at different times
	 */
	for (i = 0; i < lgrp_count; i++) {
		lgrp_t		*lgrp;

		lgrp = lgrps[i];

		/*
		 * Skip non-existent lgroups, new leaf lgroup, and
		 * non-leaf lgroups
		 */
		if (!LGRP_EXISTS(lgrp) || lgrp == leaf ||
		    lgrp->lgrp_childcnt != 0) {
#ifdef	DEBUG
			if (lgrp_topo_debug > 1)
				prom_printf("lgrp_leaf_add: skip "
				    "lgrp %d at 0x%p\n",
				    lgrp->lgrp_id, (void *)lgrp);
#endif	/* DEBUG */
			continue;
		}

#ifdef	DEBUG
		if (lgrp_topo_debug > 0)
			prom_printf("lgrp_leaf_add: lgrp %d (0x%p) =>"
			    " lgrp %d (0x%p)\n",
			    leaf->lgrp_id, (void *)leaf, lgrp->lgrp_id,
			    (void *)lgrp);
#endif	/* DEBUG */

		count += lgrp_lineage_add(leaf, lgrp, &changes);
		if (changed)
			klgrpset_or(*changed, changes);

		count += lgrp_lineage_add(lgrp, leaf, &changes);
		if (changed)
			klgrpset_or(*changed, changes);
	}

#ifdef	DEBUG
	if (lgrp_topo_debug > 1 && changed)
		prom_printf("lgrp_leaf_add: changed %d lgrps: 0x%llx\n",
		    count, (u_longlong_t)*changed);
#endif	/* DEBUG */

	return (count);
}


/*
 * Remove resources of leaf from lgroup hierarchy
 */
int
lgrp_leaf_delete(lgrp_t *leaf, lgrp_t **lgrps, int lgrp_count,
    klgrpset_t *changed)
{
	klgrpset_t	changes;
	klgrpset_t	collapse;
	int		count;
	int		i;
	lgrp_t		*lgrp;

	ASSERT(MUTEX_HELD(&cpu_lock) || curthread->t_preempt > 0 ||
	    !lgrp_initialized);

	count = 0;
	klgrpset_clear(collapse);
	if (changed)
		klgrpset_clear(*changed);

	/*
	 * Nothing to do if no leaf given
	 */
	if (leaf == NULL)
		return (0);

#ifdef	DEBUG
	if (lgrp_topo_debug > 0)
		prom_printf("lgrp_leaf_delete(0x%p[%d],0x%p,%d,0x%p)\n",
		    (void *)leaf, leaf->lgrp_id, (void *)lgrps, lgrp_count,
		    (void *)changed);
#endif	/* DEBUG */

	/*
	 * Remove leaf from any lgroups containing its resources
	 */
	for (i = 0; i < lgrp_count; i++) {
		lgrp = lgrps[i];
		if (lgrp == NULL || lgrp->lgrp_id == LGRP_NONE ||
		    !lgrp_rsets_member(lgrp->lgrp_set, leaf->lgrp_id))
			continue;

#ifdef	DEBUG
		if (lgrp_topo_debug > 0)
			prom_printf("lgrp_leaf_delete: remove leaf from"
			    " lgrp %d at %p\n", lgrp->lgrp_id, (void *)lgrp);
#endif	/* DEBUG */

		lgrp_rsets_delete(lgrp, leaf->lgrp_id, 0);
		klgrpset_del(lgrp->lgrp_leaves, leaf->lgrp_id);

		klgrpset_add(collapse, lgrp->lgrp_id);
		count++;
	}

	/*
	 * Remove leaf and its ancestors that don't have any other children
	 */
#ifdef	DEBUG
	if (lgrp_topo_debug > 1)
		prom_printf("lgrp_leaf_delete: remove leaf and ancestors\n");
#endif	/* DEBUG */

	count += lgrp_ancestor_delete(leaf, &changes);
	klgrpset_or(collapse, changes);
	klgrpset_add(collapse, leaf->lgrp_id);
	count++;
	lgrp_destroy(leaf);

	/*
	 * Consolidate any duplicate lgroups of ones just changed
	 * Assume that there were no duplicates before last round of changes
	 */
#ifdef	DEBUG
	if (lgrp_topo_debug > 1)
		prom_printf("lgrp_leaf_delete: collapsing dups\n");
#endif	/* DEBUG */
	count += lgrp_collapse_dups(collapse, lgrp_collapse_equidist,
	    &changes);
	klgrpset_or(collapse, changes);
	if (changed)
		klgrpset_copy(*changed, collapse);

#ifdef	DEBUG
	if (lgrp_topo_debug > 1 && changed)
		prom_printf("lgrp_leaf_delete: changed %d lgrps: 0x%llx\n",
		    count, (u_longlong_t)*changed);
#endif	/* DEBUG */

	return (count);
}


/*
 * Flatten lgroup topology down to height specified
 */
int
lgrp_topo_flatten(int levels, lgrp_t **lgrps, int lgrp_count,
    klgrpset_t *changed)
{
	int	count;
	int	i;
	lgrp_t	*lgrp;
	lgrp_handle_t hdl;

	/*
	 * Only flatten down to 2 level for now
	 */
	if (levels != 2)
		return (0);

	/*
	 * Look for non-leaf lgroups to remove and leaf lgroups to reparent
	 */
	count = 0;
	for (i = 0; i <= lgrp_count; i++) {
		/*
		 * Skip non-existent lgroups and root
		 */
		lgrp = lgrps[i];
		if (!LGRP_EXISTS(lgrp))
			continue;

		hdl = lgrp->lgrp_plathand;

		if (lgrp == lgrp_root) {
			lgrp->lgrp_latency = lgrp_plat_latency(hdl, hdl);
			continue;
		}

		if (lgrp->lgrp_childcnt > 0) {
			lgrp_t	*parent;

			/*
			 * Remove non-leaf lgroup from lgroup topology
			 */
			parent = lgrp->lgrp_parent;
			if (changed) {
				klgrpset_add(*changed, lgrp->lgrp_id);
				klgrpset_add(*changed, parent->lgrp_id);
				count += 2;
			}
			if (parent) {
				klgrpset_del(parent->lgrp_children,
				    lgrp->lgrp_id);
				parent->lgrp_childcnt--;
			}
			lgrp_destroy(lgrp);
		} else if (lgrp->lgrp_parent != lgrp_root) {
			/*
			 * Reparent leaf lgroup to root
			 */
			if (changed) {
				klgrpset_add(*changed, lgrp_root->lgrp_id);
				klgrpset_add(*changed, lgrp->lgrp_id);
				count += 2;
			}
			lgrp->lgrp_parent = lgrp_root;
			klgrpset_add(lgrp_root->lgrp_children, lgrp->lgrp_id);
			lgrp_root->lgrp_childcnt++;
			klgrpset_add(lgrp_root->lgrp_leaves, lgrp->lgrp_id);

			lgrp->lgrp_latency = lgrp_plat_latency(hdl, hdl);
		}
	}

	return (count);
}


/*
 * Return current height limit for lgroup topology
 */
int
lgrp_topo_ht_limit(void)
{
	return (lgrp_topo_levels);
}


/*
 * Return default height limit for lgroup topology
 */
int
lgrp_topo_ht_limit_default(void)
{
	return (LGRP_TOPO_LEVELS);
}


/*
 * Set height limit for lgroup topology
 */
int
lgrp_topo_ht_limit_set(int ht)
{
	if (ht > LGRP_TOPO_LEVELS_MAX)
		lgrp_topo_levels = LGRP_TOPO_LEVELS_MAX;
	else
		lgrp_topo_levels = ht;

	return (ht);
}


/*
 * Update lgroup topology for any leaves that don't have their latency set
 *
 * This may happen on some machines when the lgroup platform support doesn't
 * know the latencies between nodes soon enough to provide it when the
 * resources are being added.  If the lgroup platform code needs to probe
 * memory to determine the latencies between nodes, it must wait until the
 * CPUs become active so at least one CPU in each node can probe memory in
 * each node.
 */
int
lgrp_topo_update(lgrp_t **lgrps, int lgrp_count, klgrpset_t *changed)
{
	klgrpset_t	changes;
	int		count;
	int		i;
	lgrp_t		*lgrp;

	count = 0;
	if (changed)
		klgrpset_clear(*changed);

	/*
	 * For UMA machines, make sure that root lgroup contains all
	 * resources.  The root lgrp should also name itself as its own leaf
	 */
	if (nlgrps == 1) {
		for (i = 0; i < LGRP_RSRC_COUNT; i++)
			klgrpset_add(lgrp_root->lgrp_set[i],
			    lgrp_root->lgrp_id);
		klgrpset_add(lgrp_root->lgrp_leaves, lgrp_root->lgrp_id);
		return (0);
	}

	mutex_enter(&cpu_lock);
	pause_cpus(NULL, NULL);

	/*
	 * Look for any leaf lgroup without its latency set, finish adding it
	 * to the lgroup topology assuming that it exists and has the root
	 * lgroup as its parent, and update the memory nodes of all lgroups
	 * that have it as a memory resource.
	 */
	for (i = 0; i < lgrp_count; i++) {
		lgrp = lgrps[i];

		/*
		 * Skip non-existent and non-leaf lgroups and any lgroup
		 * with its latency set already
		 */
		if (lgrp == NULL || lgrp->lgrp_id == LGRP_NONE ||
		    lgrp->lgrp_childcnt != 0 || lgrp->lgrp_latency != 0)
			continue;

#ifdef	DEBUG
		if (lgrp_topo_debug > 1) {
			prom_printf("\nlgrp_topo_update: updating lineage "
			    "of lgrp %d at 0x%p\n", lgrp->lgrp_id,
			    (void *)lgrp);
		}
#endif	/* DEBUG */

		count += lgrp_leaf_add(lgrp, lgrps, lgrp_count, &changes);
		if (changed)
			klgrpset_or(*changed, changes);

		if (!klgrpset_isempty(changes))
			(void) lgrp_mnode_update(changes, NULL);

#ifdef	DEBUG
		if (lgrp_topo_debug > 1 && changed)
			prom_printf("lgrp_topo_update: changed %d lgrps: "
			    "0x%llx\n",
			    count, (u_longlong_t)*changed);
#endif	/* DEBUG */
	}

	if (lgrp_topo_levels < LGRP_TOPO_LEVELS && lgrp_topo_levels == 2) {
		count += lgrp_topo_flatten(2, lgrps, lgrp_count, changed);
		(void) lpl_topo_flatten(2);
	}

	start_cpus();
	mutex_exit(&cpu_lock);

	return (count);
}

#ifdef	DEBUG
void
lgrp_print(lgrp_t *lgrp)
{
	lgrp_t	*parent;

	prom_printf("LGRP %d", lgrp->lgrp_id);
	if (lgrp->lgrp_childcnt == 0)
		prom_printf(" (plathand %p)\n",
		    (void *)lgrp->lgrp_plathand);
	else
		prom_printf("\n");

	prom_printf("\tlatency %d\n", lgrp->lgrp_latency);

	lgrp_rsets_print("\tresources", lgrp->lgrp_set);

	parent = lgrp->lgrp_parent;
	prom_printf("\tparent 0x%p", (void *)parent);
	if (parent)
		prom_printf("[%d]\n", parent->lgrp_id);
	else
		prom_printf("\n");

	prom_printf("\tchild count %d, children ", lgrp->lgrp_childcnt);
	klgrpset_print(lgrp->lgrp_children);

	prom_printf("\tleaves ");
	klgrpset_print(lgrp->lgrp_leaves);
}


void
lgrp_topo_print(lgrp_t **lgrps, int lgrp_max)
{
	klgrpset_t	siblings;

	lgrp_print(lgrp_root);
	siblings = lgrp_root->lgrp_children;
	while (!klgrpset_isempty(siblings)) {
		klgrpset_t	children;
		int		i;

		klgrpset_clear(children);
		for (i = 0; i <= lgrp_max; i++) {
			lgrp_t	*lgrp;

			lgrp = lgrps[i];
			if (lgrp == NULL || !klgrpset_ismember(siblings, i))
				continue;
			lgrp_print(lgrp);
			klgrpset_or(children, lgrp->lgrp_children);
		}
		klgrpset_copy(siblings, children);
	}
}
#endif	/* DEBUG */
