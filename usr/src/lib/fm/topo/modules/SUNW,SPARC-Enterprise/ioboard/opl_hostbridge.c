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
#include "opl_topo.h"

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };
static const topo_pgroup_info_t pci_pgroup =
	{ TOPO_PGROUP_PCI, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

/*
 * Check the root complex device node for a slot-names property.
 */
const char *
opl_get_slot_name(topo_mod_t *mod, di_node_t n)
{
	di_prom_handle_t ptp = DI_PROM_HANDLE_NIL;
	di_prom_prop_t pp = DI_PROM_PROP_NIL;
	uchar_t *buf;

	if ((ptp = topo_mod_prominfo(mod)) == DI_PROM_PROP_NIL)
		return (NULL);

	for (pp = di_prom_prop_next(ptp, n, pp);
	    pp != DI_PROM_PROP_NIL;
	    pp = di_prom_prop_next(ptp, n, pp)) {
		if (strcmp(di_prom_prop_name(pp), OPL_SLOT_NAMES) == 0) {
			if (di_prom_prop_data(pp, &buf) <= sizeof (uint32_t))
				continue;
			return ((const char *)&buf[4]);
		}
	}
	return (NULL);
}

static tnode_t *
opl_node_create(topo_mod_t *mp, tnode_t *parent, const char *name, int inst,
    void *priv)
{
	tnode_t *node;
	nvlist_t *fmri;
	nvlist_t *auth = topo_mod_auth(mp, parent);

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
 * Create a root complex node.
 */
static tnode_t *
opl_rc_node_create(topo_mod_t *mp, tnode_t *parent, di_node_t dnode, int inst)
{
	int err;
	tnode_t *rcn;
	const char *slot_name;
	char *dnpath;
	nvlist_t *mod;

	rcn = opl_node_create(mp, parent, PCIEX_ROOT, inst, (void *)dnode);
	if (rcn == NULL) {
		return (NULL);
	}

	/*
	 * If this root complex connects to a slot, it will have a
	 * slot-names property.
	 */
	slot_name = opl_get_slot_name(mp, dnode);
	if (slot_name) {
		char fru_str[64];
		nvlist_t *fru_fmri;
		/* Add FRU fmri */
		(void) snprintf(fru_str, sizeof (fru_str), "hc:///component=%s",
		    slot_name);
		if (topo_mod_str2nvl(mp, fru_str, &fru_fmri) == 0) {
			(void) topo_node_fru_set(rcn, fru_fmri, 0, &err);
			nvlist_free(fru_fmri);
		}
		/* Add label */
		(void) topo_node_label_set(rcn, (char *)slot_name, &err);
	} else {
		/* Inherit parent FRU's label */
		(void) topo_node_fru_set(rcn, NULL, 0, &err);
		(void) topo_node_label_set(rcn, NULL, &err);
	}

	/*
	 * Set ASRU to be the dev-scheme ASRU
	 */
	if ((dnpath = di_devfs_path(dnode)) != NULL) {
		nvlist_t *fmri;

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
	if (dnpath) {
		if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DEV,
		    TOPO_PROP_IMMUTABLE, dnpath, &err) != 0) {
			topo_mod_dprintf(mp, "Failed to set DEV property\n");
			di_devfs_path_free(dnpath);
			(void) topo_mod_seterrno(mp, err);
		}
		di_devfs_path_free(dnpath);
	}
	/* Oberon device type is always "pciex" */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DEVTYPE,
	    TOPO_PROP_IMMUTABLE, OPL_PX_DEVTYPE, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set DEVTYPE property\n");
	}
	/* Oberon driver is always "px" */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_IO_DRIVER,
	    TOPO_PROP_IMMUTABLE, OPL_PX_DRV, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set DRIVER property\n");
	}
	if ((mod = topo_mod_modfmri(mp, FM_MOD_SCHEME_VERSION, OPL_PX_DRV))
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
	/* BDF of Oberon root complex is constant */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_PCI,
	    TOPO_PCI_BDF, TOPO_PROP_IMMUTABLE, OPL_PX_BDF, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set EXCAP property\n");
	}

	/* Make room for children */
	(void) topo_node_range_create(mp, rcn, PCIEX_BUS, 0, OPL_BUS_MAX);
	return (rcn);
}

/*
 * Create a hostbridge node.
 */
static tnode_t *
opl_hb_node_create(topo_mod_t *mp, tnode_t *parent, int inst)
{
	int err;
	tnode_t *hbn;

	hbn = opl_node_create(mp, parent, HOSTBRIDGE, inst, NULL);
	if (hbn == NULL) {
		return (NULL);
	}

	/* Inherit parent FRU's label */
	(void) topo_node_fru_set(hbn, NULL, 0, &err);
	(void) topo_node_label_set(hbn, NULL, &err);

	/* Make room for children */
	(void) topo_node_range_create(mp, hbn, PCIEX_ROOT, 0, OPL_RC_MAX);

	return (hbn);
}

/*
 * opl_hb_enum gets the ioboard instance passed in, and determines the
 * hostbridge and root complex instances numbers based on the bus addresses.
 */
int
opl_hb_enum(topo_mod_t *mp, const ioboard_contents_t *iob, tnode_t *ion,
    int brd)
{
	int hb;
	int rc;
	di_node_t p;
	tnode_t *hbnode;
	tnode_t *rcnode;
	topo_mod_t *pcimod;

	/* Load the pcibus module. We'll need it later. */
	pcimod = topo_mod_load(mp, PCI_BUS, PCI_BUS_VERS);
	if (pcimod == NULL) {
		topo_mod_dprintf(mp, "can't load pcibus module: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (-1);
	}

	/* For each hostbridge on an ioboard... */
	for (hb = 0; hb < OPL_HB_MAX; hb++) {
		hbnode = NULL;
		/* For each root complex in a hostbridge... */
		for (rc = 0; rc < OPL_RC_MAX; rc++) {
			p = iob->rcs[hb][rc];
			/* If no root complex, continue */
			if (p == DI_NODE_NIL) {
				continue;
			}

			/* The root complex exists! */
			topo_mod_dprintf(mp, "declaring "
			    "/chassis=0/ioboard=%d/hostbridge=%d/pciexrc=%d\n",
			    brd, hb, rc);

			/*
			 * If we haven't created a hostbridge node yet, do it
			 * now.
			 */
			if (hbnode == NULL) {
				hbnode = opl_hb_node_create(mp, ion, hb);
				if (hbnode == NULL) {
					topo_mod_dprintf(mp,
					    "unable to create hbnode: %s\n",
					    topo_strerror(topo_mod_errno(mp)));
					topo_mod_unload(pcimod);
					return (-1);
				}

			}

			/* Create the root complex node */
			rcnode = opl_rc_node_create(mp, hbnode, p, rc);
			if (rcnode == NULL) {
				topo_mod_dprintf(mp,
				    "unable to create rcnode: %s\n",
				    topo_strerror(topo_mod_errno(mp)));
				topo_mod_unload(pcimod);
				return (-1);
			}

			/* Enumerate pcibus nodes under the root complex */
			if (topo_mod_enumerate(pcimod, rcnode,
			    PCI_BUS, PCIEX_BUS, 0, 255, NULL) != 0) {
				topo_mod_dprintf(mp,
				    "error enumerating pcibus: %s\n",
				    topo_strerror(topo_mod_errno(mp)));
				topo_mod_unload(pcimod);
				return (-1);
			}
		}
	}
	topo_mod_unload(pcimod);
	return (0);
}
