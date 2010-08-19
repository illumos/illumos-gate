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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Create a topology node for a PRI node of type 'bay'. Call the disk
 * enumerator to enumerate any disks that may be attached.
 */

#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <sys/pci.h>
#include <sys/mdesc.h>
#include "pi_impl.h"

#define	_ENUM_NAME	"enum_bay"
#define	HBA_DRV_NAME	"mpt_sas"
#define	DEVICES		"/devices"

#define	PI_BAY_AP	DDI_NT_SCSI_ATTACHMENT_POINT
#define	PI_MAX_LUN	255

static boolean_t MPxIO_ENABLED = B_FALSE;

static const topo_pgroup_info_t io_pgroup = {
	TOPO_PGROUP_IO,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t binding_pgroup = {
	TOPO_PGROUP_BINDING,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};


/*
 * Return the MPxIO occupant path bay property.
 *
 * The string must be freed with topo_mod_strfree().
 */
static char *
pi_bay_ocpath(topo_mod_t *mod, di_node_t dnode)
{

	int		lun;
	boolean_t	got_w;
	char		buf[MAXPATHLEN];
	char		*tgt_port = NULL;

	/* 'target-port' property */
	tgt_port = pi_get_target_port(mod, dnode);
	if (tgt_port == NULL) {
		topo_mod_dprintf(mod, "pi_bay_ocpath: failed to get "
		    "'target-port' property\n");
		return (NULL);
	}

	/* 'lun' property */
	lun = pi_get_lun(mod, dnode);
	if (lun < 0 || lun > PI_MAX_LUN) {
		topo_mod_dprintf(mod, "pi_bay_ocpath: failed to get 'lun' "
		    "property\n");
		topo_mod_strfree(mod, tgt_port);
		return (NULL);
	}

	/* 'target-port' leading 'w' is not consistent */
	got_w = tgt_port[0] == 'w' ? B_TRUE : B_FALSE;

	/*
	 * Build occupatnt path:
	 * 'devfs_path' + "/disk@w" + 'target-port' + "," + 'lun'
	 */
	(void) snprintf(buf, MAXPATHLEN, "%s%s%s,%x", di_devfs_path(dnode),
	    (got_w ? "/disk@" : "/disk@w"), tgt_port, lun);

	topo_mod_strfree(mod, tgt_port);
	return (topo_mod_strdup(mod, buf));
}


/*
 * Create bay "io" pgroup, create and add "ap_path" property.
 * Create bay "binding" pgroup, create and add "oc_path" property.
 */
static int
pi_bay_pgroups(topo_mod_t *mod, tnode_t *t_node, di_node_t cnode,
    di_minor_t cminor)
{
	int	rv;
	int	err;
	char	*ap_path;
	char	*oc_path;

	/* Create "io" pgroup and attachment point. */
	rv = topo_pgroup_create(t_node, &io_pgroup, &err);
	if (rv != 0) {
		topo_mod_dprintf(mod, "pi_bay_pgroups: failed to create "
		    "\"io\" pgroup: %s\n", topo_mod_seterrno(mod, err));
		return (err);
	}

	/*
	 * Create the ap_path property:
	 */
	ap_path = topo_mod_alloc(mod, MAXPATHLEN);
	if (ap_path == NULL) {
		topo_mod_dprintf(mod, "pi_bay_pgroups: EMOD_NOMEM for "
		    "ap_path\n");
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	/* attachment point path: "/devices" + minor node path */
	(void) snprintf(ap_path, MAXPATHLEN, "%s%s", DEVICES,
	    di_devfs_minor_path(cminor));
	topo_mod_dprintf(mod, "pi_bay_pgroups: ap_path (%s)\n", ap_path);

	/* add ap_path prop to io pgroup */
	rv = topo_prop_set_string(t_node, TOPO_PGROUP_IO, TOPO_IO_AP_PATH,
	    TOPO_PROP_IMMUTABLE, ap_path, &err);
	if (rv != 0) {
		topo_mod_dprintf(mod, "pi_bay_pgroups: failed to set "
		    "ap-path: %s\n", topo_strerror(err));
		topo_mod_free(mod, ap_path, MAXPATHLEN);
		(void) topo_mod_seterrno(mod, err);
		return (err);
	}
	topo_mod_free(mod, ap_path, MAXPATHLEN);

	/* Create "binding" pgroup */
	rv = topo_pgroup_create(t_node, &binding_pgroup, &err);
	if (rv != 0) {
		topo_mod_dprintf(mod, "pi_bay_pgroups: failed to "
		    "create \"binding\" pgroup: %s\n", topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		return (err);
	}

	/*
	 * Create the oc_path property:
	 */
	if (MPxIO_ENABLED) {
		oc_path = pi_bay_ocpath(mod, cnode);
	} else {
		oc_path = di_devfs_path(cnode);
	}
	if (oc_path == NULL) {
		topo_mod_dprintf(mod, "pi_bay_pgroups: no occupant path\n");
		return (-1);
	}
	topo_mod_dprintf(mod, "pi_bay_proups: oc_path (%s)\n", oc_path);

	/* add oc_path to binding pgroup */
	rv = topo_prop_set_string(t_node, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_OCCUPANT, TOPO_PROP_IMMUTABLE, oc_path, &err);
	if (rv != 0) {
		topo_mod_dprintf(mod, "pi_bay_pgroups: failed to set "
		    "oc_path: %s\n", topo_strerror(err));
		(void) topo_mod_seterrno(mod, err);
		rv = err;
	}

	if (MPxIO_ENABLED) {
		topo_mod_strfree(mod, oc_path);
	} else {
		di_devfs_path_free(oc_path);
	}
	return (rv);
}


/*
 * Find the child devinfo node of the HBA that matches the PHY, capture the
 * minor attachment point node.
 */
static void
pi_bay_find_nodes(topo_mod_t *mod, di_node_t *nodep, di_node_t *sibp,
    di_minor_t *minorp, int phy)
{
	di_node_t	sib = DI_NODE_NIL;
	di_node_t	gsib = DI_NODE_NIL;
	di_minor_t	minor = DI_MINOR_NIL;

	/*
	 * When MPxIO is enabled the child node of the HBA (iport) contains
	 * the pathinfo property we're looking for; when MPxIO is disabled
	 * the grand-child of the HBA (disk) contains the devinfo property
	 * we're looking for.
	 */
	sib = di_child_node(*nodep);
	while (sib != DI_NODE_NIL) {
		/* match the PHY */
		if (phy == pi_get_phynum(mod, sib)) {
			while ((minor = di_minor_next(sib, minor)) !=
			    DI_MINOR_NIL) {
				/* scsi attachment point */
				if (strncmp(di_minor_nodetype(minor),
				    PI_BAY_AP,
				    strlen(di_minor_nodetype(minor))) == 0) {
					goto out;
				}
			}
		} else {
			/* look in grandchildren */
			gsib = di_child_node(sib);
			while (gsib != DI_NODE_NIL) {
				/* match the PHY */
				if (phy == pi_get_phynum(mod, gsib)) {
					while ((minor = di_minor_next(sib,
					    minor)) != DI_MINOR_NIL) {
						/* scsi attachment point */
						if (strncmp(
						    di_minor_nodetype(minor),
						    PI_BAY_AP,
						    strlen(di_minor_nodetype(
						    minor))) == 0) {
							sib = gsib;
							goto out;
						}
					}
				}
				gsib = di_sibling_node(gsib);
			}
		}
		sib = di_sibling_node(sib);
	}
out:
	if (sib == DI_NODE_NIL) {
		*sibp = DI_NODE_NIL;
	} else {
		bcopy(&sib, sibp, sizeof (di_node_t));
	}

	if (minor == DI_MINOR_NIL) {
		*minorp = DI_MINOR_NIL;
	} else {
		bcopy(&minor, minorp, sizeof (di_minor_t));
	}
}


/*
 * Decoreate "bay" node with required properties for disk enumerator.
 */
static int
pi_bay_update_node(topo_mod_t *mod, tnode_t *t_node, uint8_t phy,
    char *pri_path)
{
	int		rv;
	char		*hba_path;
	char		*mpxio_prop;
	di_node_t	devtree;
	di_node_t	dnode, sib;
	di_minor_t	minor = DI_MINOR_NIL;

	/*
	 * The hba path and bay PHY come from the PRI; find the
	 * driver node that coresponds to the PHY and it's minor
	 * node name and create the occupant path/attachmeent_point
	 * path
	 */
	devtree = di_init("/", DINFOFORCE | DINFOSUBTREE | DINFOMINOR |
	    DINFOPROP | DINFOPATH);

	for (dnode = di_drv_first_node(HBA_DRV_NAME, devtree);
	    dnode != DI_NODE_NIL;
	    dnode = di_drv_next_node(dnode)) {
		/* find the dnode path that matches the pri path */
		hba_path = pi_get_dipath(mod, dnode);
		if (strcmp(pri_path, hba_path) == 0) {
			/* found our dnode */
			topo_mod_strfree(mod, hba_path);
			break;
		}
		topo_mod_strfree(mod, hba_path);
	}
	if (dnode == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "pi_bay_update_node: failed to find "
		    "devinfo path.\n");
		return (-1);
	}

	/*
	 * The "mpxio-disable" variable determines if MPxIO (multipathing)
	 * is disabled (or enabled).
	 */
	if (di_prop_lookup_strings(DDI_DEV_T_ANY, dnode, "mpxio-disable",
	    &mpxio_prop) < 0) {
		/* no way to determine if MPxIO is enabled */
		topo_mod_dprintf(mod,
		    "pi_bay_update_node: no \"mpxio-disable\" property\n");
		return (-1);
	}

	/* set MPxIO_ENABLED inverse to "mpxio-disable" */
	topo_mod_dprintf(mod, "\"mpxio-disable\" = (%s)\n", mpxio_prop);
	MPxIO_ENABLED = strncmp("no", mpxio_prop, strlen(mpxio_prop)) == 0 ?
	    B_TRUE : B_FALSE;
	topo_mod_dprintf(mod, "MPxIO_ENABLED: %s\n", MPxIO_ENABLED ? "TRUE" :
	    "FALSE");

	/*
	 * Find the child node matching the PRI phy_number and determine the
	 * minor attachment point.
	 */
	pi_bay_find_nodes(mod, &dnode, &sib, &minor, phy);
	if (sib == DI_NODE_NIL || minor == DI_MINOR_NIL) {
		topo_mod_dprintf(mod, "pi_bay_update_node: no disk on "
		    "PHY %d.\n", phy);
		return (-1);
	}

	/* add pgroups */
	rv = pi_bay_pgroups(mod, t_node, sib, minor);
	if (rv != 0) {
		topo_mod_dprintf(mod, "pi_bay_update_node: failed to add "
		    "pgroups.\n", _ENUM_NAME);
		return (rv);
	}
	return (0);
}

/* ARGSUSED */
int
pi_enum_bay(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t **t_node)
{
	int		i, rv;
	int		min = 0, max = 0;
	int		num_arcs;
	int		nphy;
	size_t		arcsize;
	uint8_t		*phy = NULL;
	char		*hba_pri_path;
	mde_cookie_t	*arcp;

	/* count how many PHYs the bay node has */
	nphy = pi_get_priphy(mod, mdp, mde_node, phy);
	if (nphy <= 0) {
		topo_mod_dprintf(mod, "%s: node_0x%llx has no PHY\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		return (-1);
	}

	phy = topo_mod_alloc(mod, (nphy * sizeof (uint8_t)));
	if (phy == NULL) {
		topo_mod_dprintf(mod, "%s: node_0x%llx ENOMEM\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		return (-1);
	}

	/* get the PHY(s) for this bay node */
	rv = pi_get_priphy(mod, mdp, mde_node, phy);
	if (rv != nphy) {
		topo_mod_dprintf(mod, "%s: node_0x%llx failed to get PHY\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		return (-1);
	}
	topo_mod_dprintf(mod, "%s: node_0x%llx PHY: %d\n", _ENUM_NAME,
	    mde_node, *phy);

	/* determine how many parent (HBA) nodes */
	num_arcs = md_get_prop_arcs(mdp, mde_node, MD_STR_BACK, NULL, 0);
	if (num_arcs == 0) {
		topo_mod_dprintf(mod, "%s: node_0x%llx has no \"back\" arcs\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		return (-1); /* return partial here? */
	}
	topo_mod_dprintf(mod, "%s: node_0x%llx has %d \"back\" arcs\n",
	    _ENUM_NAME, mde_node, num_arcs);

	/* get the "back" nodes */
	arcsize = sizeof (mde_cookie_t) * num_arcs;
	arcp = topo_mod_zalloc(mod, arcsize);
	if (arcp == NULL) {
		topo_mod_dprintf(mod, "%s: no memory\n", _ENUM_NAME);
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		return (-1);
	}
	num_arcs = md_get_prop_arcs(mdp, mde_node, MD_STR_BACK, arcp, arcsize);

	/* make sure there are as many HBA nodes as PHYs */
	if (num_arcs != nphy) {
		topo_mod_dprintf(mod, "%s: %d PHYs for %d back arcs.\n",
		    _ENUM_NAME, nphy, num_arcs);
		return (-1);
	}

	/* create topo bay node for each HBA attached to this bay */
	for (i = 0; i < num_arcs; i++) {
		/* skip if topo-hc-skip = 1 */
		if (pi_skip_node(mod, mdp, arcp[i])) {
			topo_mod_dprintf(mod, "%s: skipping node_0x%llx\n",
			    (uint64_t)arcp[i]);
			continue;
		}

		/*
		 * Create a generic "bay" node; decorate below.
		 *
		 * If we have more than one HBA the bay inst here will be
		 * the same for both. This is okay since the paths will
		 * be different for each HBA.
		 */
		rv = pi_enum_generic_impl(mod, mdp, mde_node, inst, t_parent,
		    t_parent, hc_name, _ENUM_NAME, t_node, 0);
		if (rv != 0 || *t_node == NULL) {
			topo_mod_dprintf(mod,
			    "%s: node_0x%llx failed to create topo node: %s\n",
			    _ENUM_NAME, (uint64_t)mde_node,
			    topo_strerror(topo_mod_errno(mod)));
			return (rv);
		}

		/* must be an ses expander if no path property - skip */
		rv = md_get_prop_str(mdp, arcp[i], MD_STR_PATH, &hba_pri_path);
		if (rv != 0 || hba_pri_path == NULL ||
		    strlen(hba_pri_path) == 0) {
			topo_mod_dprintf(mod, "%s: node_0x%llx: no path "
			    "property\n", _ENUM_NAME, (uint64_t)arcp[i]);
			continue;
		}

		/* Decorate the bay tnode */
		rv = pi_bay_update_node(mod, *t_node, phy[i], hba_pri_path);
		if (rv != 0) {
			topo_mod_dprintf(mod, "%s: failed to update "
			    "node_0x%llx.\n", _ENUM_NAME, (uint64_t)mde_node);
			continue;
		}


		/*
		 * Call the disk enum passing in decorated bay tnode.
		 */
		if (topo_mod_load(mod, DISK, TOPO_VERSION) == NULL) {
			topo_mod_dprintf(mod,
			    "%s: Failed to load %s module: %s\n",
			    _ENUM_NAME, DISK,
			    topo_strerror(topo_mod_errno(mod)));
			return (topo_mod_errno(mod));
		}

		rv = topo_node_range_create(mod, *t_node, DISK, min, max);
		if (rv != 0) {
			topo_mod_dprintf(mod,
			    "%s: failed to create range: %s\n", _ENUM_NAME,
			    topo_strerror(topo_mod_errno(mod)));
			return (topo_mod_errno(mod));
		}

		rv = topo_mod_enumerate(mod, *t_node, DISK, DISK, min, max,
		    NULL);
		if (rv != 0) {
			topo_mod_dprintf(mod,
			    "%s: %s enumeration failed: %s\n", _ENUM_NAME,
			    DISK, topo_strerror(topo_mod_errno(mod)));
			return (topo_mod_errno(mod));
		}
	}

	/* clean up */
	topo_mod_free(mod, arcp, arcsize);
	topo_mod_free(mod, phy, (nphy * sizeof (uint8_t)));
	return (0);
}
