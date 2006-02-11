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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "hb_sun4.h"
#include "hostbridge.h"
#include "pcibus.h"
#include "util.h"

static int
rcs_process(busorrc_t *list, tnode_t *ptn)
{
	busorrc_t *p;
	int nrc = 0;

	if (list == NULL) {
		topo_mod_dprintf(HbHdl, "No root complexes found.\n");
		return (0);
	}

	/*
	 * At press time, all sun4v machines have 1 FIRE ASIC as a
	 * hostbridge, and then each PX driver instance we see is a
	 * PCI-Express root complex.
	 */
	for (p = list; p != NULL; p = p->br_nextbus)
		nrc++;

	topo_mod_dprintf(HbHdl, "root complex count: %d\n", nrc);
	return (declare_exbuses(list, ptn, 1, nrc));
}

static int
pci_hostbridges_find(tnode_t *ptn)
{
	busorrc_t *rcs = NULL;
	di_node_t devtree;
	di_node_t pnode;

	/* Scan for buses, top-level devinfo nodes with the right driver */
	devtree = di_init("/", DINFOCPYALL);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(HbHdl, "devinfo init failed.");
		topo_node_range_destroy(ptn, HOSTBRIDGE);
		return (0);
	}
	pnode = di_drv_first_node(PX, devtree);
	while (pnode != DI_NODE_NIL) {
		if (busorrc_add(&rcs, pnode) < 0) {
			di_fini(devtree);
			return (-1);
		}
		pnode = di_drv_next_node(pnode);
	}
	rcs_process(rcs, ptn);
	busorrc_free(rcs);
	di_fini(devtree);
	return (0);
}

/*ARGSUSED*/
int
platform_hb_enum(tnode_t *parent, const char *name,
    topo_instance_t imin, topo_instance_t imax)
{
	return (pci_hostbridges_find(parent));
}

/*ARGSUSED*/
int
platform_hb_label(tnode_t *node, nvlist_t *in, nvlist_t **out)
{
	return (labelmethod_inherit(HbHdl, node, in, out));
}
