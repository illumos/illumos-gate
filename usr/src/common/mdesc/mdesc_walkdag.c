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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <string.h>
#include <strings.h>
#endif

#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>

static int
mdl_walk_dag(md_impl_t *, mde_cookie_t, mde_cookie_t, mde_str_cookie_t,
    mde_str_cookie_t, uint8_t *, md_walk_fn_t, void *, int);


/*
 * Walk the machine description directed graph from a starting
 * node searching for nodes of a given node name and using a
 * given arc type.  Call a callback function for each node found.
 * Each node will be visited only once.
 *
 * Input		Description
 * -------------------	----------------------------------------
 * md_t *		Pointer to md session
 * mde_cookie_t		Index of the starting node
 * mde_str_cookie_t	Node name cookie of the nodes to call
 *			the walk function
 * mde_str_cookie_t	Arc name cookie of the path to follow
 * md_walk_fn_t		The function to call for each node
 * void *		Private data to pass to the walker function
 *
 */
int
md_walk_dag(md_t *ptr, mde_cookie_t startnode,
    mde_str_cookie_t node_name_cookie, mde_str_cookie_t arc_name_cookie,
    md_walk_fn_t func, void *private)
{
	int		res;
	uint8_t		*seenp;
	md_impl_t	*mdp;
	mde_cookie_t	start;

	mdp = (md_impl_t *)ptr;
	if (mdp == NULL) {
		return (-1);
	}

	/*
	 * Possible the caller was lazy and didn't check the
	 * validitiy of either the node name or the arc name
	 * on calling ... in which case fail to find any
	 * nodes.
	 * This is distinct, from a fail (-1) since we return
	 * that nothing was found.
	 */
	if (node_name_cookie == MDE_INVAL_STR_COOKIE ||
	    arc_name_cookie == MDE_INVAL_STR_COOKIE) {
		return (0);
	}

	/*
	 * if we want to start at the top, start at index 0
	 */
	start = startnode;
	if (start == MDE_INVAL_ELEM_COOKIE) {
		start = 0;
	}

	/*
	 * Scan from the start point until the first node.
	 */
	while (start < mdp->element_count &&
	    MDE_TAG(&mdp->mdep[start]) == MDET_NULL) {
		start++;
	}

	/*
	 * This was a bogus start point if no node found
	 */
	if (MDE_TAG(&mdp->mdep[start]) != MDET_NODE) {
		return (-1);	/* illegal start node specified */
	}

	/*
	 * Allocate a recursion detection structure so we only visit
	 * each node once.
	 */
	seenp = (uint8_t *)mdp->allocp(mdp->element_count);
	if (seenp == NULL) {
		return (-1);
	}
	(void) memset(seenp, 0, mdp->element_count);

	/*
	 * Now build the list of requested nodes.
	 */
	res = mdl_walk_dag(mdp, MDE_INVAL_ELEM_COOKIE, start,
	    node_name_cookie, arc_name_cookie, seenp, func, private, 0);

	mdp->freep(seenp, mdp->element_count);

	return (res >= 0 ? 0 : res);
}


static int
mdl_walk_dag(md_impl_t *mdp, mde_cookie_t parentidx, mde_cookie_t nodeidx,
    mde_str_cookie_t node_name_cookie, mde_str_cookie_t arc_name_cookie,
    uint8_t *seenp, md_walk_fn_t func, void *private, int level)
{
	int		result;
	md_element_t	*mdep;

	/* Get the node element from the session */
	mdep = &(mdp->mdep[nodeidx]);

	/* see if cookie is infact a node */
	if (MDE_TAG(mdep) != MDET_NODE) {
		return (MDE_WALK_ERROR);
	}

	/* have we been here before ? */
	if (seenp[nodeidx]) {
		return (MDE_WALK_NEXT);
	}
	seenp[nodeidx] = 1;

#ifdef	DEBUG_LIBMDESC
	{
		int x;
		for (x = 0; x < level; x++) {
			printf("-");
		}
		printf("%d (%s)\n", nodeidx,
		    (char *)(mdp->datap + MDE_NAME(mdep)));
	}
#endif

	/* is this node of the type we seek ? */
	if (MDE_NAME(mdep) == node_name_cookie) {
		/*
		 * Yes.  Call the callback function.
		 */
		result = (func)((md_t *)mdp, parentidx, nodeidx, private);
		if (result != MDE_WALK_NEXT) {
			return (result);
		}
	}

	/*
	 * Simply walk the elements in the node.
	 * if we find a matching arc, then recursively call
	 * the subordinate looking for a match
	 */
	result = MDE_WALK_NEXT;
	for (mdep++; MDE_TAG(mdep) != MDET_NODE_END; mdep++) {
		if (MDE_TAG(mdep) == MDET_PROP_ARC &&
		    MDE_NAME(mdep) == arc_name_cookie) {
			/*
			 * The current node becomes the parent node, and the
			 * arc index is the new current node.
			 */
			result = mdl_walk_dag(mdp, nodeidx, mdep->d.prop_idx,
			    node_name_cookie, arc_name_cookie, seenp, func,
			    private, level+1);
			if (result != MDE_WALK_NEXT) {
				/* The walk is complete or terminated. */
				return (result);
			}
		}
	}

	return (result);
}
