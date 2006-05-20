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
#include "did.h"

int
count_busorrc(busorrc_t *list, int *hbc, int *bph, topo_mod_t *mod)
{
	ulong_t start;
	busorrc_t *p;
	int bt;

	start = list->br_ba_ac;
	p = list->br_nextbus;
	bt = *hbc = 1;
	while (p != NULL) {
		if (p->br_ba_ac == start)
			(*hbc)++;
		bt++;
		p = p->br_nextbus;
	}

	/*
	 * sanity check that we have the correct number of buses/root
	 * complexes in the list to have the same number of buses on
	 * each hostbridge
	 */
	if (bt % *hbc != 0) {
		topo_mod_dprintf(mod,
		    "Imbalance between bus/root complex count and "
		    "the number of hostbridges.\n");
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}
	*bph = bt / *hbc;
	topo_mod_dprintf(mod,
	    "%d hostbridge%s\n", *hbc, (*hbc > 1) ? "s." : ".");
	topo_mod_dprintf(mod, "%d buses total.\n", bt);
	return (0);
}

static int
busorrc_process(busorrc_t *list, int isrc, tnode_t *ptn,
    did_hash_t *didhash, di_prom_handle_t promtree, topo_mod_t *mod)
{
	int hbc, busper;

	if (list == NULL) {
		if (isrc == 1)
			topo_mod_dprintf(mod, "No root complexes found.\n");
		else
			topo_mod_dprintf(mod, "No pci buses found.\n");
		return (0);
	}

	/*
	 * At this point we've looked through all the top-level device
	 * tree nodes for instances of drivers that represent logical
	 * PCI buses or root complexes.  We've sorted them into a
	 * list, ordered by "bus address".  We retrieved "bus address"
	 * using di_bus_addr().  That gave us a string that contains
	 * either a single hex number or a pair of them separated by a
	 * comma.  If there was a single number, we've assumed the
	 * second number to be zero.
	 *
	 * So, we always have a pair of numbers describing a bus/root
	 * complex, X1 and X2, with X1 being the number before the
	 * comma, and X2 being the number after (or the assumed zero).
	 * As each node was examined, we then sorted these buses/root
	 * complexes, first by the value of X2, and using X1 to order
	 * amongst buses/root complexes with the same value for X2.
	 *
	 * We infer the existence of hostbridges by observing a
	 * pattern that X2 is recycled for different hostbridges, and
	 * that sorting by X1 within buses/root complexes with equal
	 * values of X2 maintains the correct associations of
	 * buses/root complexes and bridges.
	 */
	if (count_busorrc(list, &hbc, &busper, mod) < 0)
		return (-1);
	if (isrc == 1)
		return (declare_exbuses(list, ptn, hbc, busper, didhash,
		    promtree, mod));
	else
		return (declare_buses(list, ptn, hbc, didhash, promtree, mod));
}

static int
pci_hostbridges_find(tnode_t *ptn, did_hash_t *didhash,
    di_prom_handle_t promtree, topo_mod_t *mod)
{
	busorrc_t *buses = NULL;
	busorrc_t *rcs = NULL;
	di_node_t devtree;
	di_node_t pnode;

	/* Scan for buses, top-level devinfo nodes with the right driver */
	devtree = di_init("/", DINFOCPYALL);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed.");
		topo_node_range_destroy(ptn, HOSTBRIDGE);
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}

	pnode = di_drv_first_node(PCI, devtree);
	while (pnode != DI_NODE_NIL) {
		if (busorrc_add(&buses, pnode, mod) < 0) {
			di_fini(devtree);
			return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
		}
		pnode = di_drv_next_node(pnode);
	}
	pnode = di_drv_first_node(PSYCHO, devtree);
	while (pnode != DI_NODE_NIL) {
		if (busorrc_add(&buses, pnode, mod) < 0) {
			di_fini(devtree);
			return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
		}
		pnode = di_drv_next_node(pnode);
	}
	pnode = di_drv_first_node(SCHIZO, devtree);
	while (pnode != DI_NODE_NIL) {
		if (busorrc_add(&buses, pnode, mod) < 0) {
			di_fini(devtree);
			return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
		}
		pnode = di_drv_next_node(pnode);
	}
	pnode = di_drv_first_node(PX, devtree);
	while (pnode != DI_NODE_NIL) {
		if (busorrc_add(&rcs, pnode, mod) < 0) {
			di_fini(devtree);
			return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
		}
		pnode = di_drv_next_node(pnode);
	}
	if (busorrc_process(buses, 0, ptn, didhash, promtree, mod) < 0)
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));

	if (busorrc_process(rcs, 1, ptn, didhash, promtree, mod) < 0)
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));

	busorrc_free(buses, mod);
	busorrc_free(rcs, mod);
	di_fini(devtree);
	return (0);
}

/*ARGSUSED*/
int
platform_hb_enum(tnode_t *parent, const char *name,
    topo_instance_t imin, topo_instance_t imax, did_hash_t *didhash,
    di_prom_handle_t promtree, topo_mod_t *mod)
{
	return (pci_hostbridges_find(parent, didhash, promtree, mod));
}

/*ARGSUSED*/
int
platform_hb_label(tnode_t *node, nvlist_t *in, nvlist_t **out, topo_mod_t *mod)
{
	return (labelmethod_inherit(mod, node, in, out));
}
