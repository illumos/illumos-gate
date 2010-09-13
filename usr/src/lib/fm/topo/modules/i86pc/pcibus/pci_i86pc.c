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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <fm/topo_mod.h>

#include "pcibus.h"
#include "pcibus_labels.h"
#include <string.h>
#include <strings.h>

/*
 * Including the following file gives us definitions of the three
 * global arrays used to adjust labels, Slot_Rewrites, Physlot_Names,
 * and Missing_Names.  With those defined we can use the common labeling
 * routines for pci.
 */
#include "pci_i86pc.h"

int
platform_pci_label(topo_mod_t *mod, tnode_t *node, nvlist_t *in,
    nvlist_t **out)
{
	return (pci_label_cmn(mod, node, in, out));
}
/*ARGSUSED*/
int
platform_pci_fru(topo_mod_t *mod, tnode_t *node, nvlist_t *in,
    nvlist_t **out)
{
	return (pci_fru_cmn(mod, node, in, out));
}

/*
 * return true if pciexbus node whose parent is a pciexrc node
 */
/*ARGSUSED*/
int
parent_is_rc(topo_mod_t *mod, did_t *dp)
{
	return (strcmp(topo_node_name(did_gettnode(dp)), PCIEX_ROOT) == 0);
}

/*
 * Look for down-stream switch "2" on riser card. First find this node's parent.
 * If it is a pciexfn node and it has dev=2 and node 6 levels further up
 * from it has a physlot then return true.
 */
int
ba_is_2(topo_mod_t *mod, did_t *dp)
{
	tnode_t *ptp;
	did_t *pdp;
	int i, d;

	ptp = did_gettnode(dp);
	if (strcmp(topo_node_name(ptp), PCIEX_FUNCTION) != 0)
		return (0);
	pdp = did_find(mod, topo_node_getspecific(ptp));
	if (!pdp)
		return (0);
	did_BDF(pdp, NULL, &d, NULL);
	if (d != 2)
		return (0);

	for (i = 0; i < 6; i++)
		if ((ptp = topo_node_parent(ptp)) == NULL)
			return (0);
	pdp = did_find(mod, topo_node_getspecific(ptp));
	return (pdp && did_physlot_exists(pdp));
}

/*
 * Look for down-stream switch "4" on riser card. First find this node's parent.
 * If it is a pciexfn node and it has dev=4 and node 6 levels further up
 * from it has a physlot then return true.
 */
int
ba_is_4(topo_mod_t *mod, did_t *dp)
{
	tnode_t *ptp;
	did_t *pdp;
	int i, d;

	ptp = did_gettnode(dp);
	if (strcmp(topo_node_name(ptp), PCIEX_FUNCTION) != 0)
		return (0);
	pdp = did_find(mod, topo_node_getspecific(ptp));
	if (!pdp)
		return (0);
	did_BDF(pdp, NULL, &d, NULL);
	if (d != 4)
		return (0);

	for (i = 0; i < 6; i++)
		if ((ptp = topo_node_parent(ptp)) == NULL)
			return (0);
	pdp = did_find(mod, topo_node_getspecific(ptp));
	return (pdp && did_physlot_exists(pdp));
}
