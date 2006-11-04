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

/*
 * SUNW,Sun-Fire platform ioboard topology enumerator
 */

#include <string.h>
#include <libdevinfo.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>

#include <did.h>
#include <hostbridge.h>
#include <ioboard.h>
#include <util.h>

/*ARGSUSED*/
int
platform_iob_label(topo_mod_t *mod, tnode_t *node, nvlist_t *ignored,
    nvlist_t **out)
{
	/*
	 * For SUNW,Sun-Fire the label is simply N0.IBXX where XX is the
	 * instance number of the ioboard.
	 */
	char buf[13];	/* up to a million I/O boards :-) */

	*out = NULL;
	(void) snprintf(buf, 10, "N0.IB%d", topo_node_instance(node));
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) == 0 &&
	    nvlist_add_string(*out, TOPO_METH_LABEL_RET_STR, buf) == 0)
		return (0);
	nvlist_free(*out);
	*out = NULL;
	return (-1);
}

#define	IOB_BASEADDR	0x18
#define	BUS_ADDRDIST	0x2

/*ARGSUSED*/
int
platform_iob_enum(topo_mod_t *mod, tnode_t *parent, topo_instance_t imin,
    topo_instance_t imax)
{
	/*
	 * A SUNW,Sun-Fire and its successors may have up to 4 I/O boards,
	 * numbered 6 through 9.  Each board has two hostbridges, and
	 * there are a pair of PCI buses under each hostbridge.  We can
	 * discover the existence of a board by the presence of
	 * devinfo nodes for those hostbridges.  We let the hostbridge
	 * enumerator actually create nodes for the hostbridges,
	 * passing them the did_t's for all the hostbridge nodes we
	 * know indicate that the ioboard exists.
	 */
	di_node_t devtree;
	di_node_t pnode;
	did_t *iobs[18][2][2];
	int brd, br, bus, i;

	devtree = topo_mod_devinfo(mod);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed.");
		return (-1);
	}

	for (i = 6; i <= 9; i++) {
		iobs[i][0][0] = iobs[i][0][1] = NULL;
		iobs[i][1][0] = iobs[i][1][1] = NULL;
	}

	pnode = di_drv_first_node(SCHIZO, devtree);
	while (pnode != DI_NODE_NIL) {
		did_t *d;

		d = split_bus_address(mod,
		    pnode, IOB_BASEADDR, BUS_ADDRDIST, 6, 9, &brd, &br, &bus);
		if (d == NULL) {
			pnode = di_drv_next_node(pnode);
			continue;
		}
		iobs[brd][br][bus] = d;
		pnode = di_drv_next_node(pnode);
	}

	for (i = 6; i < 9; i++) {
		tnode_t *ion;
		/*
		 * Make sure we found all the buses and bridges
		 */
		if (iobs[i][0][0] == NULL || iobs[i][0][1] == NULL ||
		    iobs[i][1][0] == NULL || iobs[i][1][1] == NULL)
			continue;
		did_did_link_set(iobs[i][0][0], iobs[i][0][1]);
		did_did_link_set(iobs[i][1][0], iobs[i][1][1]);
		did_did_chain_set(iobs[i][0][0], iobs[i][1][0]);
		if ((ion = ioboard_declare(mod, parent, i, iobs[i][0][0]))
		    == NULL) {
			topo_mod_dprintf(mod,
			    "Creation of tnode for %s%d failed.\n", IOBOARD, i);
			continue;
		}
		if (topo_mod_enumerate(mod,
		    ion, HOSTBRIDGE, HOSTBRIDGE, 0, 0, iobs[i][0][0]) < 0) {
			topo_mod_dprintf(mod,
			    "Enumeration of %s%d/%s%d failed.\n",
			    IOBOARD, i, HOSTBRIDGE, 0);
			continue;
		}
		if (topo_mod_enumerate(mod,
		    ion, HOSTBRIDGE, HOSTBRIDGE, 1, 1, iobs[i][0][0]) < 0) {
			topo_mod_dprintf(mod,
			    "Enumeration of %s%d/%s%d failed.\n",
			    IOBOARD, i, HOSTBRIDGE, 1);
			continue;
		}
	}
	return (0);
}
