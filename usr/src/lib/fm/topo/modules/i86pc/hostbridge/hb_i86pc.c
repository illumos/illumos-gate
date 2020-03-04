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

#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <strings.h>
#include <pcibus.h>
#include <hostbridge.h>
#include <did.h>
#include <util.h>

static int
hb_process(topo_mod_t *mod, tnode_t *ptn, topo_instance_t hbi, di_node_t bn)
{
	tnode_t *hb;
	did_t *hbdid;

	if ((hbdid = did_create(mod, bn, 0, hbi, NO_RC, TRUST_BDF)) == NULL)
		return (-1);
	if ((hb = pcihostbridge_declare(mod, ptn, bn, hbi)) == NULL)
		return (-1);
	if (topo_mod_enumerate(mod,
	    hb, PCI_BUS, PCI_BUS, 0, MAX_HB_BUSES, (void *)hbdid) < 0) {
		topo_node_unbind(hb);
		return (-1);
	}

	return (0);
}

static int
rc_process(topo_mod_t *mod, tnode_t *ptn, topo_instance_t hbi, di_node_t bn)
{
	tnode_t *hb;
	tnode_t *rc;
	did_t *hbdid;

	if ((hbdid = did_create(mod, bn, 0, hbi, hbi, TRUST_BDF)) == NULL)
		return (-1);
	if ((hb = pciexhostbridge_declare(mod, ptn, bn, hbi)) == NULL)
		return (-1);
	if ((rc = pciexrc_declare(mod, hb, bn, hbi)) == NULL)
		return (-1);
	if (topo_mod_enumerate(mod,
	    rc, PCI_BUS, PCIEX_BUS, 0, MAX_HB_BUSES, (void *)hbdid) < 0) {
		topo_node_unbind(hb);
		topo_node_unbind(rc);
		return (-1);
	}

	return (0);
}


int
pci_hostbridges_find(topo_mod_t *mod, tnode_t *ptn)
{
	di_node_t devtree;
	di_node_t pnode, cnode;
	int hbcnt = 0;

	/* Scan for buses, top-level devinfo nodes with the right driver */
	devtree = topo_mod_devinfo(mod);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed.");
		topo_node_range_destroy(ptn, HOSTBRIDGE);
		return (0);
	}

	pnode = di_drv_first_node(PCI, devtree);
	while (pnode != DI_NODE_NIL) {
		/*
		 * We've seen cases where certain phantom PCI hostbridges have
		 * appeared on systems. If we encounter a host bridge without a
		 * bus address assigned to it, then we should skip processing it
		 * here as that indicates that it generally doesn't have any
		 * devices under it and we'll otherwise blow up in devinfo.
		 */
		if (di_bus_addr(pnode) == NULL) {
			pnode = di_drv_next_node(pnode);
			continue;
		}

		if (hb_process(mod, ptn, hbcnt, pnode) < 0) {
			if (hbcnt == 0)
				topo_node_range_destroy(ptn, HOSTBRIDGE);
			return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
		}
		hbcnt++;
		pnode = di_drv_next_node(pnode);
	}

	pnode = di_drv_first_node(NPE, devtree);
	while (pnode != DI_NODE_NIL) {
		for (cnode = di_child_node(pnode); cnode != DI_NODE_NIL;
		    cnode = di_sibling_node(cnode)) {
			if (di_driver_name(cnode) == NULL)
				continue;
			if (strcmp(di_driver_name(cnode), PCI_PCI) == 0) {
				if (hb_process(mod, ptn, hbcnt, cnode) < 0) {
					if (hbcnt == 0)
						topo_node_range_destroy(ptn,
						    HOSTBRIDGE);
					return (topo_mod_seterrno(mod,
					    EMOD_PARTIAL_ENUM));
				}
				hbcnt++;
			}
			if (strcmp(di_driver_name(cnode), PCIEB) == 0) {
				if (rc_process(mod, ptn, hbcnt, cnode) < 0) {
					if (hbcnt == 0)
						topo_node_range_destroy(ptn,
						    HOSTBRIDGE);
					return (topo_mod_seterrno(mod,
					    EMOD_PARTIAL_ENUM));
				}
				hbcnt++;
			}
		}
		pnode = di_drv_next_node(pnode);
	}
	return (0);
}

/*ARGSUSED*/
int
platform_hb_enum(topo_mod_t *mod, tnode_t *parent, const char *name,
    topo_instance_t imin, topo_instance_t imax)
{
	return (pci_hostbridges_find(mod, parent));
}

/*ARGSUSED*/
int
platform_hb_label(topo_mod_t *mod, tnode_t *node, nvlist_t *in, nvlist_t **out)
{
	return (labelmethod_inherit(mod, node, in, out));
}
