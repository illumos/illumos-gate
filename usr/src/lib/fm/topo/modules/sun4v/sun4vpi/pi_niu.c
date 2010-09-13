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
 * Create a topology node for a PRI node of type 'niu'
 */
#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include "pi_impl.h"

#define	_ENUM_NAME	"enum_niu"


/* ARGSUSED */
int
pi_enum_niu(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t **t_node)
{
	int		result;

	*t_node = NULL;

	topo_mod_dprintf(mod,
	    "%s node_0x%llx enumeration starting\n", _ENUM_NAME,
	    (uint64_t)mde_node);

	/* Make sure our dependent modules are loaded */
	if (topo_mod_load(mod, NIU, TOPO_VERSION) == NULL) {
		topo_mod_dprintf(mod, "%s could not load %s module: %s\n",
		    _ENUM_NAME, NIU, topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	/*
	 * Invoke the niu enumerator for this node.
	 */
	result = topo_mod_enumerate(mod, t_parent, NIU, hc_name, inst, inst,
	    NULL);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx enumeration failed: %s\n", _ENUM_NAME,
		    (uint64_t)mde_node, topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	topo_mod_dprintf(mod, "%s added node_0x%llx type %s\n",
	    _ENUM_NAME, (uint64_t)mde_node, hc_name);

	return (0);
}
