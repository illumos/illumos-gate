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

#include <string.h>
#include <strings.h>
#include <libdevinfo.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>
#include "opl_topo.h"

/*
 * The following #define's are also in did_props.h, but I can't include that
 * header file here. They should probably be moved to a centrally-located
 * header file somewhere, since they may also be needed by diagnosis engines
 * or agents.
 */
#define	TOPO_PGROUP_IO		"io"
#define	TOPO_PROP_DEVTYPE	"DEVTYPE"
#define	TOPO_PROP_DRIVER	"DRIVER"
#define	TOPO_PROP_DEV		"DEV"

#define	TOPO_PGROUP_PCI		"pci"
#define	TOPO_PROP_EXCAP		"EXCAP"
#define	TOPO_PROP_BDF		"BDF"
#define	TOPO_PROP_VENDID	"VENDOR-ID"
#define	TOPO_PROP_DEVID		"DEVICE-ID"
#define	TOPO_PROP_CLASS		"CLASS-CODE"

#define	PCIEX_ROOT		"pciexrc"


/*
 * Check the root complex device node for a slot-names property.
 */
const char *
opl_get_slot_name(di_node_t n, di_prom_handle_t opl_promtree)
{
	di_prom_prop_t pp = DI_PROM_PROP_NIL;
	uchar_t *buf;

	for (pp = di_prom_prop_next(opl_promtree, n, pp);
	    pp != DI_PROM_PROP_NIL;
	    pp = di_prom_prop_next(opl_promtree, n, pp)) {
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
	int err;
	tnode_t *node;
	nvlist_t *fmri;
	nvlist_t *args = NULL;
	nvlist_t *pfmri = NULL;
	topo_hdl_t *thp = topo_mod_handle(mp);

	if (parent == NULL || inst < 0) {
		return (NULL);
	}

	/* Get parent FMRI */
	(void) topo_node_resource(parent, &pfmri, &err);
	if (pfmri != NULL) {
		if (topo_mod_nvalloc(mp, &args, NV_UNIQUE_NAME) != 0 ||
		    nvlist_add_nvlist(args, TOPO_METH_FMRI_ARG_PARENT, pfmri)
		    != 0) {
			nvlist_free(pfmri);
			nvlist_free(args);
			(void) topo_mod_seterrno(mp, EMOD_FMRI_NVL);
			return (NULL);
		}
		nvlist_free(pfmri);
	}

	/* Create FMRI */
	if ((fmri = topo_fmri_create(thp, FM_FMRI_SCHEME_HC, name, inst,
	    args, &err)) == NULL) {
		topo_mod_dprintf(mp, "create of tnode for %s failed: %s\n",
		    name, topo_strerror(topo_mod_errno(mp)));
		(void) topo_mod_seterrno(mp, err);
		nvlist_free(args);
		return (NULL);
	}
	nvlist_free(args);

	/* Create and bind node  */
	node = topo_node_bind(mp, parent, name, inst, fmri, priv);
	if (node == NULL) {
		nvlist_free(fmri);
		topo_mod_dprintf(mp, "unable to bind root complex: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (NULL); /* mod_errno already set */
	}
	nvlist_free(fmri);

	return (node);
}

/*
 * Create a root complex node.
 */
static tnode_t *
opl_rc_node_create(topo_mod_t *mp, tnode_t *parent, di_node_t dnode, int inst,
    di_prom_handle_t opl_promtree)
{
	int err;
	tnode_t *rcn;
	topo_hdl_t *thp = topo_mod_handle(mp);
	const char *slot_name;
	char *dnpath;

	rcn = opl_node_create(mp, parent, PCIEXRC, inst, (void *)dnode);
	if (rcn == NULL) {
		return (NULL);
	}

	/*
	 * If this root complex connects to a slot, it will have a
	 * slot-names property.
	 */
	slot_name = opl_get_slot_name(dnode, opl_promtree);
	if (slot_name) {
		char fru_str[64];
		nvlist_t *fru_fmri;
		/* Add FRU fmri */
		snprintf(fru_str, sizeof (fru_str), "hc:///component=%s",
		    slot_name);
		if (topo_fmri_str2nvl(thp, fru_str, &fru_fmri, &err) == 0) {
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
		nvlist_t *in;
		nvlist_t *fmri;
		if (topo_mod_nvalloc(mp, &in, NV_UNIQUE_NAME) != 0) {
			topo_mod_dprintf(mp, "topo_mod_nvalloc failed\n");
			di_devfs_path_free(dnpath);
			topo_mod_seterrno(mp, EMOD_FMRI_NVL);
			return (NULL);
		}
		if (nvlist_add_string(in, FM_FMRI_DEV_PATH,
		    dnpath) != 0) {
			topo_mod_dprintf(mp, "nvlist_add_string failed\n");
			nvlist_free(in);
			di_devfs_path_free(dnpath);
			topo_mod_seterrno(mp, EMOD_NOMEM);
			return (NULL);
		}
		fmri = topo_fmri_create(thp, FM_FMRI_SCHEME_DEV,
		    FM_FMRI_SCHEME_DEV, 0, in, &err);
		nvlist_free(in);
		if (fmri == NULL) {
			topo_mod_dprintf(mp,
			    "dev:///%s fmri creation failed.\n",
			    dnpath);
			topo_mod_seterrno(mp, err);
			di_devfs_path_free(dnpath);
			return (NULL);
		}
		if (topo_node_asru_set(rcn, fmri, 0, &err) < 0) {
			topo_mod_dprintf(mp, "topo_node_asru_set failed\n");
			topo_mod_seterrno(mp, err);
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
	if (topo_pgroup_create(rcn, TOPO_PGROUP_IO,
	    TOPO_STABILITY_PRIVATE, &err) < 0) {
		topo_mod_dprintf(mp, "topo_pgroup_create failed\n");
		di_devfs_path_free(dnpath);
		topo_mod_seterrno(mp, err);
		return (NULL);
	}
	if (topo_pgroup_create(rcn, TOPO_PGROUP_PCI,
	    TOPO_STABILITY_PRIVATE, &err) < 0) {
		topo_mod_dprintf(mp, "topo_pgroup_create failed\n");
		di_devfs_path_free(dnpath);
		topo_mod_seterrno(mp, err);
		return (NULL);
	}
	/* Add the devfs path property */
	if (dnpath) {
		if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_PROP_DEV,
		    TOPO_PROP_SET_ONCE, dnpath, &err) != 0) {
			topo_mod_dprintf(mp, "Failed to set DEV property\n");
			di_devfs_path_free(dnpath);
			topo_mod_seterrno(mp, err);
		}
		di_devfs_path_free(dnpath);
	}
	/* Oberon device type is always "pciex" */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_PROP_DEVTYPE,
	    TOPO_PROP_SET_ONCE, OPL_PX_DEVTYPE, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set DEVTYPE property\n");
	}
	/* Oberon driver is always "px" */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_IO, TOPO_PROP_DRIVER,
	    TOPO_PROP_SET_ONCE, OPL_PX_DRV, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set DRIVER property\n");
	}
	/* This is a PCIEX Root Complex */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_PCI, TOPO_PROP_EXCAP,
	    TOPO_PROP_SET_ONCE, PCIEX_ROOT, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set EXCAP property\n");
	}
	/* BDF of Oberon root complex is constant */
	if (topo_prop_set_string(rcn, TOPO_PGROUP_PCI,
	    TOPO_PROP_BDF, TOPO_PROP_SET_ONCE, OPL_PX_BDF, &err) != 0) {
		topo_mod_dprintf(mp, "Failed to set EXCAP property\n");
	}

	/* Make room for children */
	topo_node_range_create(mp, rcn, PCIEX_BUS, 0, OPL_BUS_MAX);
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
	topo_node_range_create(mp, hbn, PCIEXRC, 0, OPL_RC_MAX);

	return (hbn);
}

/*
 * opl_hb_enum gets the ioboard instance passed in, and determines the
 * hostbridge and root complex instances numbers based on the bus addresses.
 */
int
opl_hb_enum(topo_mod_t *mp, const ioboard_contents_t *iob, tnode_t *ion,
    int brd, di_prom_handle_t opl_promtree)
{
	int hb;
	int rc;
	di_node_t p;
	tnode_t *hbnode;
	tnode_t *rcnode;
	topo_mod_t *pcimod;

	/* Load the pcibus module. We'll need it later. */
	pcimod = topo_mod_load(mp, PCI_MOD_PATH);
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
			rcnode = opl_rc_node_create(mp, hbnode, p, rc,
			    opl_promtree);
			if (rcnode == NULL) {
				topo_mod_dprintf(mp,
				    "unable to create rcnode: %s\n",
				    topo_strerror(topo_mod_errno(mp)));
				topo_mod_unload(pcimod);
				return (-1);
			}

			/* Enumerate pcibus nodes under the root complex */
			if (topo_mod_enumerate(pcimod, rcnode,
			    PCI_BUS, PCIEX_BUS, 0, 255) != 0) {
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
