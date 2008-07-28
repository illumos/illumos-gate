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
 * Create a topology node for a top level PRI node, one that is a child
 * of the 'components' node.
 */
#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include "pi_impl.h"

#define	_ENUM_NAME	"enum_top"

/*
 * This enumerator is the same as the generic enumerator, except that when
 * the FMRI is created, the parent node must be NULL.  This is true for all
 * top level nodes.
 */
int
pi_enum_top(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t **t_node)
{
	int	result;

	/*
	 * This is a top-level topology node and there is no resource data
	 * from which to generate an FMRI.  We use a NULL value for the FMRI
	 * parent when creating the FMRI for this node so that the underlying
	 * libtopo method does not fail.
	 */
	result = pi_enum_generic_impl(mod, mdp, mde_node, inst, t_parent,
	    NULL, hc_name, _ENUM_NAME, t_node);
	return (result);
}
