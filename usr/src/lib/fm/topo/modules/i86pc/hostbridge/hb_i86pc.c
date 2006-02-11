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

#include <fm/topo_mod.h>
#include <libdevinfo.h>
#include "pcibus.h"
#include "hostbridge.h"
#include "did.h"
#include "util.h"

extern did_hash_t *Didhash;

static int
hb_process(tnode_t *ptn, topo_instance_t hbi, di_node_t bn)
{
	tnode_t *hb;

	if (did_create(Didhash, bn, 0, hbi, NO_RC, TRUST_BDF) == NULL)
		return (-1);
	if ((hb = pcihostbridge_declare(ptn, bn, hbi)) == NULL)
		return (-1);
	return (topo_mod_enumerate(HbHdl,
	    hb, PCI_BUS, PCI_BUS, 0, MAX_HB_BUSES));
}

static int
rc_process(tnode_t *ptn, topo_instance_t hbi, di_node_t bn)
{
	tnode_t *hb;
	tnode_t *rc;

	if (did_create(Didhash, bn, 0, hbi, hbi, TRUST_BDF) == NULL)
		return (-1);
	if ((hb = pciexhostbridge_declare(ptn, bn, hbi)) == NULL)
		return (-1);
	if ((rc = pciexrc_declare(hb, bn, hbi)) == NULL)
		return (-1);
	return (topo_mod_enumerate(HbHdl,
	    rc, PCI_BUS, PCIEX_BUS, 0, MAX_HB_BUSES));
}


int
pci_hostbridges_find(tnode_t *ptn)
{
	di_node_t devtree;
	di_node_t pnode;
	char *eplain;
	int hbcnt = 0;

	/* Scan for buses, top-level devinfo nodes with the right driver */
	devtree = di_init("/", DINFOCPYALL);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(HbHdl, "devinfo init failed.");
		topo_node_range_destroy(ptn, HOSTBRIDGE);
		return (0);
	}

	/*
	 * By default we do not enumerate generic PCI on x86
	 */
	eplain = getenv("TOPOENUMPLAINPCI");
	if (eplain != NULL) {
		pnode = di_drv_first_node(PCI, devtree);
		while (pnode != DI_NODE_NIL) {
			if (hb_process(ptn, hbcnt++, pnode) < 0) {
				di_fini(devtree);
				topo_node_range_destroy(ptn, HOSTBRIDGE);
				return (topo_mod_seterrno(HbHdl,
				    EMOD_PARTIAL_ENUM));
			}
			pnode = di_drv_next_node(pnode);
		}
	}

	pnode = di_drv_first_node(NPE, devtree);
	while (pnode != DI_NODE_NIL) {
		if (rc_process(ptn, hbcnt++, pnode) < 0) {
			di_fini(devtree);
			topo_node_range_destroy(ptn, HOSTBRIDGE);
			return (topo_mod_seterrno(HbHdl, EMOD_PARTIAL_ENUM));
		}
		pnode = di_drv_next_node(pnode);
	}
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
