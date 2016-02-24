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

#include <string.h>
#include <strings.h>
#include <libdevinfo.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/fm/protocol.h>
#include "cpuboard_topo.h"

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t pci_pgroup =
	{ TOPO_PGROUP_PCI, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static tnode_t *
cpuboard_node_create(topo_mod_t *mp, tnode_t *parent, const char *name,
    int inst, void *priv)
{
	tnode_t *node;
	nvlist_t *fmri;
	nvlist_t *auth = topo_mod_auth(mp, parent);

	topo_mod_dprintf(mp, "cpuboard_node_create:\n");

	if (parent == NULL || inst < 0) {
		return (NULL);
	}

	/* Create FMRI */
	if ((fmri = topo_mod_hcfmri(mp, parent, FM_HC_SCHEME_VERSION, name,
	    inst, NULL, auth, NULL, NULL, NULL)) == NULL) {
		topo_mod_dprintf(mp, "create of tnode for %s failed: %s",
		    name, topo_strerror(topo_mod_errno(mp)));
		nvlist_free(auth);
		return (NULL);
	}
	nvlist_free(auth);

	/* Create and bind node  */
	node = topo_node_bind(mp, parent, name, inst, fmri);
	if (node == NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mp, "unable to bind root complex: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (NULL); /* mod_errno already set */
	}

	nvlist_free(fmri);
	topo_node_setspecific(node, priv);

	return (node);
}

/*
 * cpuboard_rc_node_create()
 * Description:
 *     Create a root complex node pciexrc
 * Parameters:
 *     mp: topo module pointer
 *     parent: topo parent node of the newly created pciexrc node
 *     dnode: Solaris device node of the root complex
 *     rcpath: Used to populated the dev property of the topo pciexrc node if
 *          the local host does not own the root complex.
 */
static tnode_t *
cpuboard_rc_node_create(topo_mod_t *mp, tnode_t *parent, di_node_t dnode,
    char *rcpath, int inst)
{
	int err;
	tnode_t *rcn;
	char *dnpath;
	nvlist_t *mod;

	topo_mod_dprintf(mp, "cpuboard_rc_node_create:\n");

	rcn = cpuboard_node_create(mp, parent, PCIEX_ROOT, inst, (void *)dnode);
	if (rcn == NULL) {
		return (NULL);
	}

	/* Inherit parent FRU's label */
	(void) topo_node_fru_set(rcn, NULL, 0, &err);
	(void) topo_node_label_set(rcn, NULL, &err);

	/*
	 * Set ASRU to be the dev-scheme ASRU
	 */
	if ((dnpath = di_devfs_path(dnode)) != NULL) {
		nvlist_t *fmri;

		/*
		 * The local host owns the root complex, so use the dev path
		 * from the di_devfs_path(), instead of the passed in rcpath,
		 * to populate the dev property.
		 */
		rcpath = dnpath;
		fmri = topo_mod_devfmri(mp, FM_DEV_SCHEME_VERSION,
		    dnpath, NULL);
		if (fmri == NULL) {
			topo_mod_dprintf(mp,
			    "dev:///%s fmri creation failed.\n",
			    dnpath);
			(void) topo_mod_seterrno(mp, err);
			di_devfs_path_free(dnpath);
			return (NULL);
		}
		if (topo_node_asru_set(rcn, fmri, 0, &err) < 0) {
			topo_mod_dprintf(mp, "topo_node_asru_set failed\n");
			(void) topo_mod_seterrno(mp, err);
			nvlist_free(fmri);
			di_devfs_path_free(dnpath);
			return (NULL);
		}
		nvlist_free(fmri);
	} else {
		topo_mod_dprintf(mp, "NULL di_devfs_path.\n");
	}

	/*
	 * Set pciexrc properties for root complex nodes
	 */

	/* Add the io and pci property groups */
	if (topo_pgroup_create(rcn, &io_pgroup, &err) < 0) {
		topo_mod_dprintf(mp, "topo_pgroup_create failed\n");
		di_devfs_path_free(dnpath);
		(void) topo_mod_seterrno(mp, err);
		return (NULL);
	}
	if (topo_pgroup_create(rcn, &pci_pgroup, &err) < 0) {
		topo_mod_dprintf(mp, "topo_pgroup_create failed\n");
		di_devfs_path_free(dnpath);
		(void) topo_mod_seterrno(mp, err);
		return (NULL);
	}
	/* Add the devfs path property */
	if (rcpath) {
		if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DEV,
		    TOPO_PROP_IMMUTABLE, rcpath, &err) != 0) {
			topo_mod_dprintf(mp, "Failed to set DEV property\n");
			(void) topo_mod_seterrno(mp, err);
		}
	}
	if (dnpath) {
		di_devfs_path_free(dnpath);
	}
	/* T5440 device type is always "pciex" */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DEVTYPE,
	    TOPO_PROP_IMMUTABLE, CPUBOARD_PX_DEVTYPE, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set DEVTYPE property\n");
	}
	/* T5440 driver is always "px" */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DRIVER,
	    TOPO_PROP_IMMUTABLE, CPUBOARD_PX_DRV, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set DRIVER property\n");
	}
	if ((mod = topo_mod_modfmri(mp, FM_MOD_SCHEME_VERSION, CPUBOARD_PX_DRV))
	    == NULL || topo_prop_set_fmri(rcn, TOPO_PGROUP_IO,
	    TOPO_IO_MODULE, TOPO_PROP_IMMUTABLE, mod,  &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set MODULE property\n");
	}
	nvlist_free(mod);

	/* This is a PCIEX Root Complex */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_PCI, TOPO_PCI_EXCAP,
	    TOPO_PROP_IMMUTABLE, PCIEX_ROOT, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set EXCAP property\n");
	}
	/* BDF of T5440 root complex is constant */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_PCI,
	    TOPO_PCI_BDF, TOPO_PROP_IMMUTABLE, CPUBOARD_PX_BDF, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set EXCAP property\n");
	}

	/* Make room for children */
	(void) topo_node_range_create(mp, rcn, PCIEX_BUS, 0, CPUBOARD_MAX);
	return (rcn);
}

/*
 * Create a hostbridge node.
 */
static tnode_t *
cpuboard_hb_node_create(topo_mod_t *mp, tnode_t *parent, int inst)
{
	int err;
	tnode_t *hbn;

	topo_mod_dprintf(mp, "cpuboard_hb_node_create: parent=%p, inst=%d\n",
	    parent, inst);

	hbn = cpuboard_node_create(mp, parent, HOSTBRIDGE, inst, NULL);
	if (hbn == NULL) {
		topo_mod_dprintf(mp, "cpuboard_hb_node_create: "
		    "cpuboard_node_create() failed.\n");
		return (NULL);
	}

	/* Inherit parent FRU's label */
	(void) topo_node_fru_set(hbn, NULL, 0, &err);
	(void) topo_node_label_set(hbn, NULL, &err);

	/* Make room for children */
	(void) topo_node_range_create(mp, hbn, PCIEX_ROOT, 0, CPUBOARD_MAX);

	topo_mod_dprintf(mp, "cpuboard_hb_node_create: EXIT hbn=%p\n", hbn);

	return (hbn);
}

/*
 * Enumerate hostbridge on the cpuboard.  Hostbridge and root complex instances
 * match the cpuboard instance.
 */
int
cpuboard_hb_enum(topo_mod_t *mp, di_node_t dnode, char *rcpath,
    tnode_t *cpubn, int brd)
{
	int hb;
	int rc;
	tnode_t *hbnode;
	tnode_t *rcnode;
	topo_mod_t *pcimod;

	topo_mod_dprintf(mp, "cpuboard_hb_enum: brd: %d, cpubn=%p\n",
	    brd, cpubn);

	/* Load the pcibus module. We'll need it later. */
	pcimod = topo_mod_load(mp, PCI_BUS, PCI_BUS_VERS);
	if (pcimod == NULL) {
		topo_mod_dprintf(mp, "can't load pcibus module: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (-1);
	}
	hb = rc = brd;

	/* The root complex exists! */
	topo_mod_dprintf(mp, "declaring "
	    "/motherboard=0/cpuboard=%d/hostbridge=%d/"
	    "pciexrc=%d\n", brd, hb, rc);

	/* Create the hostbridge node */
	hbnode = cpuboard_hb_node_create(mp, cpubn, hb);
	if (hbnode == NULL) {
		topo_mod_dprintf(mp,
		    "unable to create hbnode: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		topo_mod_unload(pcimod);
		return (-1);
	}
	/* Create the root complex node */
	rcnode = cpuboard_rc_node_create(mp, hbnode, dnode, rcpath, rc);
	if (rcnode == NULL) {
		topo_mod_dprintf(mp,
		    "unable to create rcnode: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		topo_mod_unload(pcimod);
		return (-1);
	}
	/*
	 * If dnode not NULL, enumerate pcibus nodes under the root complex.
	 * If dnode NULL, skip enumeration.  Condition could occur if the RC
	 * is assigned to non-control domain.
	 */
	if ((dnode != NULL) && topo_mod_enumerate(pcimod, rcnode,
	    PCI_BUS, PCIEX_BUS, 0, 255, NULL) != 0) {
		topo_mod_dprintf(mp,
		    "error enumerating pcibus: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		topo_mod_unload(pcimod);
		return (-1);
	}
	topo_mod_unload(pcimod);
	return (0);
}
