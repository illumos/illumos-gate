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

/*
 * Create a generic topology node for a given PRI node.
 */
#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include "pi_impl.h"

#define	_ENUM_NAME	"enum_generic"

int
pi_enum_generic(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t **t_node)
{
	int		result;

	/*
	 * For a generic node that is not a top-level node, we use the
	 * same parent topology node to generate the FMRI as well as
	 * to bind the new node.
	 */
	result = pi_enum_generic_impl(mod, mdp, mde_node, inst, t_parent,
	    t_parent, hc_name, _ENUM_NAME, t_node);

	return (result);
}


/*
 * Create a generic topo node based on the PRI information in the machine
 * description information.
 */
int
pi_enum_generic_impl(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_bindparent, tnode_t *t_fmriparent,
    const char *hc_name, const char *enum_name, tnode_t **t_node)
{
	nvlist_t	*fmri;
	nvlist_t	*auth;

	topo_mod_dprintf(mod, "%s adding entry for node_0x%llx type %s\n",
	    enum_name, (uint64_t)mde_node, hc_name);

	if (t_bindparent == NULL) {
		topo_mod_dprintf(mod,
		    "%s called with NULL parent for node_0x%llx type %s\n",
		    enum_name, (uint64_t)mde_node, hc_name);
		return (-1);
	}

	/* Create the FMRI for this node */
	auth = topo_mod_auth(mod, t_bindparent);
	fmri = topo_mod_hcfmri(mod, t_fmriparent, FM_HC_SCHEME_VERSION, hc_name,
	    inst, NULL, auth, NULL, NULL, NULL);
	if (fmri == NULL) {
		topo_mod_dprintf(mod,
		    "%s failed to create fmri node_0x%llx: %s\n", enum_name,
		    (uint64_t)mde_node, topo_strerror(topo_mod_errno(mod)));
		nvlist_free(auth);
		return (-1);
	}

	/* Bind this node to the parent */
	*t_node = pi_node_bind(mod, mdp, mde_node, t_bindparent, hc_name, inst,
	    fmri);
	nvlist_free(fmri);
	nvlist_free(auth);
	if (*t_node == NULL) {
		topo_mod_dprintf(mod,
		    "%s failed to bind node_0x%llx instance %d: %s\n",
		    enum_name, (uint64_t)mde_node, (uint32_t)inst,
		    topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	topo_mod_dprintf(mod, "%s added node_0x%llx type %s\n",
	    enum_name, (uint64_t)mde_node, hc_name);

	return (0);
}
