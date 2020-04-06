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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_hc.h>
#include <fm/topo_mod.h>

#include <hb_sun4.h>
#include <hostbridge.h>
#include <pcibus.h>
#include <did.h>
#include <util.h>

#include "hb_mdesc.h"

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t pci_pgroup =
	{ TOPO_PGROUP_PCI, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

/*
 * get_rcs()
 * Description:
 *     Return a list of PX instances in the dev tree.
 */
static busorrc_t *
get_rcs(topo_mod_t *mod)
{
	busorrc_t *rcs = NULL;
	di_node_t devtree;
	di_node_t pnode;

	/* Scan for buses, top-level devinfo nodes with the right driver */
	devtree = topo_mod_devinfo(mod);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed.\n");
		return (NULL);
	}
	pnode = di_drv_first_node(PX, devtree);
	while (pnode != DI_NODE_NIL) {
		if (busorrc_add(mod, &rcs, pnode) < 0) {
			topo_mod_dprintf(mod, "busorrc_add() failed.\n");
			busorrc_free(mod, rcs);
			return (NULL);
		}
		pnode = di_drv_next_node(pnode);
	}
	return (rcs);
}

/*
 * find_dnode()
 * Description:
 *     Find the dev pointer of a rc given its bus address, ba
 */
static di_node_t
find_dnode(busorrc_t *rcs, uint64_t ba)
{
	busorrc_t *p;
	for (p = rcs; p != NULL; p = p->br_nextbus) {
		if (ba == p->br_ba_bc) {
			return (p->br_din);
		}
	}
	return (NULL);
}

/*
 * hb_tnode_create()
 * Description:
 *     Create a topo node
 */
static tnode_t *
hb_tnode_create(topo_mod_t *mod, tnode_t *parent, const char *name,
    int inst, void *priv)
{
	int err;
	tnode_t *node;
	nvlist_t *fmri;
	nvlist_t *auth = topo_mod_auth(mod, parent);

	if (parent == NULL || inst < 0) {
		return (NULL);
	}

	/* Create FMRI */
	if ((fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name,
	    inst, NULL, auth, NULL, NULL, NULL)) == NULL) {
		topo_mod_dprintf(mod, "create of tnode for %s failed: %s\n",
		    name, topo_strerror(topo_mod_errno(mod)));
		nvlist_free(auth);
		return (NULL);
	}
	nvlist_free(auth);

	/* Create and bind node  */
	node = topo_node_bind(mod, parent, name, inst, fmri);
	if (node == NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mod, "unable to bind a node(%s): %s\n",
		    name, topo_strerror(topo_mod_errno(mod)));
		return (NULL); /* mod_errno already set */
	}

	nvlist_free(fmri);
	topo_node_setspecific(node, priv);

	/* Inherit the parent 's FRU and label */
	(void) topo_node_fru_set(node, NULL, 0, &err);
	(void) topo_node_label_set(node, NULL, &err);

	return (node);
}

/*
 * platform_pciexhostbridge_declare()
 * Description:
 *     This is a sun4v specific function to create the hostbridge topo node.
 */
tnode_t *
platform_pciexhostbridge_declare(topo_mod_t *mod, tnode_t *parent,
    topo_instance_t inst)
{
	tnode_t *hbn;
	void *priv = NULL;

	topo_mod_dprintf(mod, "Create node %s=%d\n", HOSTBRIDGE, inst);

	hbn = hb_tnode_create(mod, parent, HOSTBRIDGE, inst, priv);
	if (hbn == NULL) {
		topo_mod_dprintf(mod, "Failed to create node %s=%d\n",
		    HOSTBRIDGE, inst);
		return (NULL);
	}

	/* Make room for children */
	(void) topo_node_range_create(mod, hbn, PCIEX_ROOT, 0, MAX_HB_BUSES);

	return (hbn);
}

/*
 * platform_pciexhostbridge_declare()
 * Description:
 *     This is a sun4v specific function to create a root complex topo node,
 *     but do not enumerate its pci buses.
 */
static tnode_t *
platform_pciexrc_declare(topo_mod_t *mod, tnode_t *parent, int inst,
    uint64_t ba)
{
	int err;
	tnode_t *rcn;
	char dnpath[MAXPATHLEN];
	nvlist_t *fmri;

	topo_mod_dprintf(mod, "Create node %s=%d\n", PCIEX_ROOT, inst);

	rcn = hb_tnode_create(mod, parent, PCIEX_ROOT, inst, NULL);
	if (rcn == NULL) {
		topo_mod_dprintf(mod, "Failed to create node %s=%d\n",
		    PCIEX_ROOT, inst);
		return (NULL);
	}

	/* Set ASRU to be the dev-scheme asru */
	(void) snprintf(dnpath, sizeof (dnpath), "/pci@%llx", ba);
	fmri = topo_mod_devfmri(mod, FM_DEV_SCHEME_VERSION, dnpath, NULL);
	if (fmri == NULL) {
		topo_mod_dprintf(mod, "dev:///%s fmri creation failed.\n",
		    dnpath);
		return (NULL);
	}
	if (topo_node_asru_set(rcn, fmri, 0, &err) < 0) {
		topo_mod_dprintf(mod, "topo_node_asru_set failed\n");
		(void) topo_mod_seterrno(mod, err);
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);

	/*
	 * Set properties of the root complex node pciexrc
	 */

	/* Add the io and pci property groups */
	if (topo_pgroup_create(rcn, &io_pgroup, &err) < 0) {
		topo_mod_dprintf(mod, "topo_pgroup_create(iogrp) failed\n");
		(void) topo_mod_seterrno(mod, err);
		return (NULL);
	}
	if (topo_pgroup_create(rcn, &pci_pgroup, &err) < 0) {
		topo_mod_dprintf(mod, "topo_pgroup_create(pcigrp) failed\n");
		(void) topo_mod_seterrno(mod, err);
		return (NULL);
	}
	/* Add the devfs path property */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DEV,
	    TOPO_PROP_IMMUTABLE, dnpath, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to set %s property\n",
		    TOPO_IO_DEV);
		(void) topo_mod_seterrno(mod, err);
		return (NULL);
	}

	/* for sun4v,  device type is always pciex */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DEVTYPE,
	    TOPO_PROP_IMMUTABLE, PCIEXTYPE, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to set %s property\n",
		    TOPO_IO_DEVTYPE);
	}

	/* sun4v rc driver is always "px" */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DRIVER,
	    TOPO_PROP_IMMUTABLE, PX, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to set %s property\n",
		    TOPO_IO_DRIVER);
	}
	if ((fmri = topo_mod_modfmri(mod, FM_MOD_SCHEME_VERSION, PX)) == NULL ||
	    (topo_prop_set_fmri(rcn, TOPO_PGROUP_IO, TOPO_IO_MODULE,
	    TOPO_PROP_IMMUTABLE, fmri,  &err) != 0)) {
		topo_mod_dprintf(mod, "Failed to set %s property\n",
		    TOPO_IO_MODULE);
	}
	nvlist_free(fmri);

	/* This is a PCIEX Root Complex */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_PCI, TOPO_PCI_EXCAP,
	    TOPO_PROP_IMMUTABLE, PCIEX_ROOT, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to set %s property\n",
		    TOPO_PCI_EXCAP);
	}

	/* Make room for children */
	(void) topo_node_range_create(mod, rcn, PCIEX_BUS, 0, MAX_HB_BUSES);

	return (rcn);
}

/*
 * platform_hb_enum()
 * Description:
 *   This is an entry function to enumerate the sun4v hostbridges. First, it
 *   reads the hostbridges and their pciexrc root complexes from the PRI or
 *   MD.
 *   For the current sun4v platforms, it is assummed that there is only one
 *   hostbridge. All the pciex root complexes belong to this single hostbridge.
 *   Given the hostbridge/pciexrc information, this enumerator creates the
 *   the hostbridge topo node and pciexrc nodes. If the domain owns the
 *   the root complex, it uses the common hostbridge code to enumerate the
 *   pcibus. If not, it simply create the hostbridge/pciexrc nodes without the
 *   fabric.
 */
/*ARGSUSED*/
int
platform_hb_enum(topo_mod_t *mod, tnode_t *parent, const char *name,
    topo_instance_t imin, topo_instance_t imax)
{
	int i, j;
	int err = 0;
	md_hb_t *hbp;
	md_rc_t *rcp;
	md_info_t hbmd;
	tnode_t **hbnode;
	int nhbnode = 0;
	tnode_t **rcnode;
	int nrcs, nrcnode = 0;
	busorrc_t *rcs;

	if (imin > imax) {
		topo_mod_dprintf(mod, "Invalid hb range(%d,%d)\n", imin, imax);
		return (-1);
	}

	/* get the hostbrige and rootcomplex information in the PRI/MD */
	(void) bzero((void *) &hbmd, sizeof (hbmd));
	if (hb_mdesc_init(mod, &hbmd) != 0) {
		topo_mod_dprintf(mod, "failed to get hb from the PRI/MD\n");
		return (-1);
	}

	/* count the number of hb and rc in the PRI/MD */
	nrcs = 0;
	for (i = 0, hbp = hbmd.hbs; i < hbmd.shbs; i++, hbp++) {
		if (hbp->id < 0)
			continue;
		nrcs += hbp->srcs;
	}
	if (hbmd.shbs <= 0 || nrcs <= 0) {
		topo_mod_dprintf(mod, "No hostbridge or pciex bus is found\n");
		topo_node_range_destroy(parent, HOSTBRIDGE);
		hb_mdesc_fini(mod, &hbmd);
		return (0);
	}
	hbnode = topo_mod_zalloc(mod, hbmd.shbs * sizeof (tnode_t *));
	rcnode = topo_mod_zalloc(mod, nrcs * sizeof (tnode_t *));
	rcs = get_rcs(mod);

	/* process the hostbridge */
	for (i = imin; (i <= imax) && (err == 0); i++) {
		int brd = 0;
		di_node_t dnode1, dnode2;

		if ((hbp = hb_find_hb(&hbmd, i)) == NULL) {
			continue;
		}

		dnode2 = NULL;
		for (j = 0, rcp = hbp->rcs; j < hbp->srcs; j++, rcp++) {
			if (rcp->id < 0)
				continue;
			dnode1 = find_dnode(rcs, rcp->cfg_handle);
			if (dnode1 != NULL) {
				dnode2 = dnode1;
				if (did_create(mod, dnode1, brd, hbp->id,
				    rcp->id, rcp->id) == NULL) {
					err = -1;
					break;
				}
			}
		}

		if (err != 0)
			break;

		/*
		 * If this hb has a rc in the dev tree, use the common code to
		 * create a hostbridge node
		 */
		if (dnode2 != NULL) {
			hbnode[nhbnode] = pciexhostbridge_declare(mod, parent,
			    dnode2, hbp->id);
		} else {
			/* platformm specific */
			hbnode[nhbnode] = platform_pciexhostbridge_declare(mod,
			    parent, hbp->id);
		}
		if (hbnode[nhbnode] == NULL) {
			err = -1;
			break;
		}

		/*
		 * Create the pciexrc nodes under the hostbridge node
		 * If a rc exists in the dev tree, use the common code to
		 * create a pciexrc node and enumerate the fabric.
		 * Otherwise, only create the pciexrc node.
		 */
		for (j = 0, rcp = hbp->rcs; j < hbp->nrcs; j++, rcp++) {
			if (rcp->id < 0) {
				topo_mod_dprintf(mod, "skip invalid rc[%d]\n",
				    j);
				continue;
			}
			dnode1 = find_dnode(rcs, rcp->cfg_handle);
			if (dnode1 != NULL) {
				/* declare a pciexrc and enumerate its pcibus */
				rcnode[nrcnode] = rc_process(mod,
				    hbnode[nhbnode], rcp->id, dnode1);
			} else {
				/* only declare the pciexrc */
				rcnode[nrcnode] = platform_pciexrc_declare(mod,
				    hbnode[nhbnode], rcp->id, rcp->cfg_handle);
			}
			if (rcnode[nrcnode] == NULL) {
				err = -1;
				break;
			}
			nrcnode++;
		}

		nhbnode++;
	}

	/* failure: unbind all hb and rc tnodes */
	if (err != 0) {
		for (i = 0; i < nhbnode; i++)
			topo_node_unbind(hbnode[i]);
		for (i = 0; i < nrcnode; i++)
			topo_node_unbind(rcnode[i]);
	}

	topo_mod_free(mod, hbnode, hbmd.shbs * sizeof (tnode_t *));
	topo_mod_free(mod, rcnode, nrcs * sizeof (tnode_t *));
	hb_mdesc_fini(mod, &hbmd);
	busorrc_free(mod, rcs);

	return (err);
}

/*ARGSUSED*/
int
platform_hb_label(topo_mod_t *mod, tnode_t *node, nvlist_t *in, nvlist_t **out)
{
	return (labelmethod_inherit(mod, node, in, out));
}
