/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2022 Oxide Computer Company
 */

/*
 * A collection of utility functions for interacting with fabric IDs.
 */

#include "zen_umc.h"

/*
 * Validate whether a fabric ID actually represents a valid ID for a given data
 * fabric.
 */
boolean_t
zen_fabric_id_valid_fabid(const df_fabric_decomp_t *decomp,
    const uint32_t fabid)
{
	uint32_t mask = decomp->dfd_node_mask | decomp->dfd_comp_mask;
	return ((fabid & ~mask) == 0);
}

/*
 * Validate whether the parts of a fabric ID (e.g. the socket, die, and
 * component) are in fact valid for a given data fabric.
 */
boolean_t
zen_fabric_id_valid_parts(const df_fabric_decomp_t *decomp, const uint32_t sock,
    const uint32_t die, const uint32_t comp)
{
	uint32_t node;

	if (((sock << decomp->dfd_sock_shift) & ~decomp->dfd_sock_mask) != 0) {
		return (B_FALSE);
	}
	if (((die << decomp->dfd_die_shift) & ~decomp->dfd_die_mask) != 0) {
		return (B_FALSE);
	}
	if ((comp & ~decomp->dfd_comp_mask) != 0) {
		return (B_FALSE);
	}

	node = die << decomp->dfd_die_shift;
	node |= sock << decomp->dfd_sock_shift;

	if (((node << decomp->dfd_node_shift) & ~decomp->dfd_node_mask) != 0) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Take apart a fabric ID into its constituent parts. The decomposition
 * information has the die and socket information relative to the node ID.
 */
void
zen_fabric_id_decompose(const df_fabric_decomp_t *decomp, const uint32_t fabid,
    uint32_t *sockp, uint32_t *diep, uint32_t *compp)
{
	uint32_t node;

	ASSERT(zen_fabric_id_valid_fabid(decomp, fabid));

	*compp = (fabid & decomp->dfd_comp_mask) >> decomp->dfd_comp_shift;
	node = (fabid & decomp->dfd_node_mask) >> decomp->dfd_node_shift;
	*diep = (node & decomp->dfd_die_mask) >> decomp->dfd_die_shift;
	*sockp = (node & decomp->dfd_sock_mask) >> decomp->dfd_sock_shift;
}

/*
 * Compose a fabric ID from its constituent parts: the socket, die, and fabric.
 */
void
zen_fabric_id_compose(const df_fabric_decomp_t *decomp, const uint32_t sock,
    const uint32_t die, const uint32_t comp, uint32_t *fabidp)
{
	uint32_t node;

	ASSERT(zen_fabric_id_valid_parts(decomp, sock, die, comp));

	node = die << decomp->dfd_die_shift;
	node |= sock << decomp->dfd_sock_shift;
	*fabidp = (node << decomp->dfd_node_shift) |
	    (comp << decomp->dfd_comp_shift);
}
