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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Create a topology node for a PRI node of type 'hostbridge'
 */
#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include "pi_impl.h"

#define	_ENUM_NAME		"enum_hostbridge"


/*
 * Create a hostbridge topo node.
 */
int
pi_enum_hostbridge(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t **t_node)
{
	int		result;

	topo_mod_dprintf(mod, "%s called for node_0x%llx type %s\n",
	    _ENUM_NAME, (uint64_t)mde_node, hc_name);

	*t_node = NULL;

	/*
	 * Create the hostbridge topo node.  Use the generic enumerator to
	 * do this, and then we will add more attributes below.
	 */
	result = pi_enum_generic_impl(mod, mdp, mde_node, inst, t_parent,
	    t_parent, hc_name, _ENUM_NAME, t_node, 0);
	if (result != 0 || *t_node == NULL) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to create topo node: %s\n",
		    _ENUM_NAME, (uint64_t)mde_node,
		    topo_strerror(topo_mod_errno(mod)));
		return (result);
	}

	/* Update the topo node with more specific information */
	result = pi_enum_update(mod, mdp, mde_node, t_parent, *t_node,
	    hc_name);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to create node properites: %s\n",
		    _ENUM_NAME, (uint64_t)mde_node,
		    topo_strerror(topo_mod_errno(mod)));
		return (result);
	}

	topo_mod_dprintf(mod, "%s added node_0x%llx type %s\n",
	    _ENUM_NAME, (uint64_t)mde_node, hc_name);

	return (result);
}
