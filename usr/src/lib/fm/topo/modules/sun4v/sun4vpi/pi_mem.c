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

/*
 * Enumerate a DIMM node
 */
#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include "pi_impl.h"

#define	_ENUM_NAME	"enum_mem"

int
pi_enum_mem(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t **t_node)
{
	int		result;
	int		err;
	nvlist_t	*rsrc = NULL;

	*t_node = NULL;

	/*
	 * Create the basic topology node for the DIMM using the generic
	 * enumerator.  The dimm serial is added to the resource so
	 * the retire agent can retire correct page whether the dimm
	 * has been moved or not.
	 */
	result = pi_enum_generic_impl(mod, mdp, mde_node, inst, t_parent,
	    t_parent, hc_name, _ENUM_NAME, t_node, SUN4VPI_ENUM_ADD_SERIAL);
	if (result != 0) {
		/* Error messages are printed by the generic routine */
		return (result);
	}

	/*
	 * Set ASRU compute method, using resource as argument.
	 */
	result = topo_node_resource(*t_node, &rsrc, &err);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to get resource: %s\n",
		    _ENUM_NAME, (uint64_t)mde_node, topo_strerror(err));
		return (-1);
	}

	/* Set the ASRU on the node with COMPUTE flag */
	result = topo_node_asru_set(*t_node, rsrc, TOPO_ASRU_COMPUTE, &err);
	nvlist_free(rsrc);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set ASRU: %s\n", _ENUM_NAME,
		    (uint64_t)mde_node, topo_strerror(err));
		return (-1);
	}

	return (0);
}
