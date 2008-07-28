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
#include <sys/mdesc.h>
#include <sys/mdesc_impl.h>

static int md_find_node_arcs(md_impl_t *, mde_cookie_t, mde_str_cookie_t, int,
    mde_cookie_t *, size_t);


/*
 * Return an array containing the node indexes for the arcs in
 * the given node.  The array is allocated using the allocator
 * defined at machine description initialization time and the
 * number of arcs found returned.
 *
 * Input		Description
 * -------------------	----------------------------------------
 * md_t *		Pointer to md session
 * mde_cookie_t		Node containing arcs
 * char *		Arc name to count (e.g. "fwd" or "back")
 * mde_cookie_t *	Buffer to store indexes, or NULL
 * size_t		Size of buffer
 *
 * Output		Description
 * -------------------	----------------------------------------
 * int			Count of arcs in node
 */
int
md_get_prop_arcs(md_t *ptr, mde_cookie_t node, char *namep, mde_cookie_t *arcp,
    size_t arcsize)
{
	int		 result;
	mde_str_cookie_t prop_name;
	md_impl_t	*mdp;

	mdp = (md_impl_t *)ptr;

	if (node == MDE_INVAL_ELEM_COOKIE) {
		return (-1);
	}

	prop_name = md_find_name(ptr, namep);
	if (prop_name == MDE_INVAL_STR_COOKIE) {
		return (-1);
	}

	result = md_find_node_arcs(mdp, node, prop_name, MDET_PROP_ARC, arcp,
	    arcsize);

	return (result);
}


/*
 * Find the number of arcs in the node of the requested prop_name.  If storage
 * is given in arcp, store the first arcsize number of node indexes.
 */
static int
md_find_node_arcs(md_impl_t *mdp, mde_cookie_t node,
    mde_str_cookie_t prop_name, int tag_type, mde_cookie_t *arcp,
    size_t arcsize)
{
	int		result;
	md_element_t	*mdep;
	int		idx;

	/* Get the private node information from session data */
	idx = (int)node;
	mdep = &(mdp->mdep[idx]);

	/* Make sure the cookie is in fact a node */
	if (MDE_TAG(mdep) != MDET_NODE) {
		return (-1);
	}

	/*
	 * Walk the elements in the node and find all the arcs of the
	 * requested type, and store them in an array.
	 */
	result = 0;
	for (idx++, mdep++; MDE_TAG(mdep) != MDET_NODE_END; idx++, mdep++) {
		if ((MDE_TAG(mdep) == tag_type) &&
		    (MDE_NAME(mdep) == prop_name)) {
			if (arcp != NULL && result < arcsize) {
				arcp[result] =
				    (mde_cookie_t)MDE_PROP_INDEX(mdep);
			}

			/* Increment the count of arcs found */
			result++;
		}
	}

	/* Return the total count of arcs in the node */
	return (result);
}
