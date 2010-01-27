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

/*
 * Create a topology node for a PRI node of type 'pciexrc'
 */
#include <sys/types.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <sys/pci.h>
#include "pi_impl.h"

#define	PCIEX_MAX_DEVICE	255
#define	PCIEX_MAX_BDF_SIZE	23	/* '0x' + sizeof (UNIT64_MAX) + '\0' */

#define	TOPO_PGROUP_PCIEX	"pciex"
#define	_ENUM_NAME		"enum_pciexrc"

static char *drv_name = NULL;

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_pgroup_info_t pci_pgroup =
	{ TOPO_PGROUP_PCI, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static int pi_enum_pciexrc_finddev(topo_mod_t *, md_t *, mde_cookie_t,
    tnode_t *);

static char *pi_enum_pciexrc_findbdf(topo_mod_t *, di_node_t);

static int pi_enum_pciexrc_defer(topo_mod_t *, md_t *, mde_cookie_t,
    topo_instance_t, tnode_t *, const char *, tnode_t *, void *);


/*
 * Create a pciexrc topo by calling the pciexrc enumerator for this instance.
 */
int
pi_enum_pciexrc(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t **t_node)
{
	int		result;

	topo_mod_dprintf(mod, "%s called for node_0x%llx type %s\n",
	    _ENUM_NAME, (uint64_t)mde_node, hc_name);

	*t_node = NULL;

	/*
	 * Create the root complex topo node.  Use the generic enumerator to
	 * do this, and then we will add more attributes below.
	 */
	result = pi_enum_generic_impl(mod, mdp, mde_node, inst, t_parent,
	    t_parent, hc_name, _ENUM_NAME, t_node, 0);
	if (result != 0 || *t_node == NULL) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to create topo node: %s\n",
		    _ENUM_NAME, (uint64_t)mde_node,
		    topo_strerror(topo_mod_errno(mod)));
		return (result);
	}

	/* Update the topo node with more specific information */
	result = pi_enum_update(mod, mdp, mde_node, t_parent, *t_node,
	    hc_name);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to create node properites: %s\n",
		    _ENUM_NAME, (uint64_t)mde_node,
		    topo_strerror(topo_mod_errno(mod)));
		return (result);
	}

	result = pi_enum_pciexrc_finddev(mod, mdp, mde_node, *t_node);
	if (result == 0) {
		/*
		 * The node exists in this domain.  We will call the PCIBUS
		 * enumerator after the entire PRI graph has been walked so
		 * that all the possible FRU nodes are available for bus's
		 * that span multiple FRU boundaries.
		 */
		result = pi_defer_add(mod, mde_node, t_parent, *t_node,
		    pi_enum_pciexrc_defer, NULL);
		if (result != 0) {
			/* We cannot defer the call, so we need to do it now */
			result = pi_enum_pciexrc_defer(mod, mdp, mde_node, inst,
			    t_parent, hc_name, *t_node, NULL);
		}
	} else {
		/*
		 * It is OK if the node does not exist for further PCIBUS
		 * enumeration.  We can return success having created the
		 * root complex node itself.
		 */
		result = 0;
	}
	topo_mod_dprintf(mod, "%s added node_0x%llx type %s\n",
	    _ENUM_NAME, (uint64_t)mde_node, hc_name);

	return (result);
}


/* ARGSUSED */
static int
pi_enum_pciexrc_defer(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    topo_instance_t inst, tnode_t *t_parent, const char *hc_name,
    tnode_t *t_node, void *private)
{
	int		result;
	topo_instance_t	min;
	topo_instance_t	max;

	topo_mod_dprintf(mod,
	    "%s node_0x%llx deferred enumeration starting\n", _ENUM_NAME,
	    (uint64_t)mde_node);

	/* Make sure our dependent modules are loaded */
	if (topo_mod_load(mod, PCI_BUS, TOPO_VERSION) == NULL) {
		topo_mod_dprintf(mod, "%s could not load %s module: %s\n",
		    _ENUM_NAME, PCI_BUS, topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	/* Create a node range for children of this bus */
	min = 0;
	max = PCIEX_MAX_DEVICE;
	result = topo_node_range_create(mod, t_node, PCI_BUS, min, max);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to create node range: %s\n",
		    _ENUM_NAME, topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}

	/*
	 * Invoke the pcibus enumerator for this node.
	 */
	result = topo_mod_enumerate(mod, t_node, PCI_BUS, PCIEX_BUS,
	    min, max, NULL);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx enumeration failed: %s\n", _ENUM_NAME,
		    (uint64_t)mde_node, topo_strerror(topo_mod_errno(mod)));
	}

	topo_mod_dprintf(mod, "%s added node_0x%llx type %s\n",
	    _ENUM_NAME, (uint64_t)mde_node, hc_name);

	return (result);
}


/*
 * Update PCIEXRC/HOSTBRIDGE topo node with node-specific information
 *
 * The following is mostly a duplicate of code contained in:
 *	usr/src/lib/fm/topo/modules/sun4v/cpuboard/
 *	    cpuboard_hostbridge.c:cpuboard_rc_node_create
 */
int
pi_enum_update(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    tnode_t *t_parent, tnode_t *t_node, const char *hc_name)
{
	int		result;
	int		err;
	int		is_hbridge = 0;
	int		is_pciexrc = 0;
	char		*path = NULL;
	char		*bdf = NULL;
	char		*_enum_name;
	nvlist_t	*modfmri;
	nvlist_t	*devfmri;
	di_node_t	dnode;

	/*
	 * Determine if decorating a PCIE root complex or a hostbridge
	 * node.
	 */
	if (strncmp(hc_name, PCIEX_ROOT, strlen(hc_name)) == 0) {
		is_pciexrc = 1;
		_enum_name = "enum_pciexrc";
	} else if (strncmp(hc_name, HOSTBRIDGE, strlen(hc_name)) == 0) {
		is_hbridge = 1;
		_enum_name = "enum_hostbridge";
	} else {
		topo_mod_dprintf(mod,
		    "pi_enum_update node_0x%llx unknown hc name %s\n",
		    (uint64_t)mde_node, hc_name);
		return (-1);
	}

	if (t_parent == NULL || t_node == NULL) {
		topo_mod_dprintf(mod, "%s node_0x%llx has no parent\n",
		    _enum_name, (uint64_t)mde_node);
		return (-1);
	}

	/*
	 * Calculate the device path for this root complex node.
	 */
	path = pi_get_path(mod, mdp, mde_node);
	if (path == NULL) {
		if (is_hbridge == 1) {
			/* "path" not required for hostbridge */
			return (0);
		}
		topo_mod_dprintf(mod, "%s node_0x%llx has no path\n",
		    _enum_name, (uint64_t)mde_node);
		return (-1);
	}

	/*
	 * Set the ASRU for this node using the dev scheme
	 */
	devfmri = topo_mod_devfmri(mod, FM_DEV_SCHEME_VERSION, path, NULL);
	if (devfmri == NULL) {
		topo_mod_dprintf(mod, "%s node_0x%llx fmri creation failed\n",
		    _enum_name, (uint64_t)mde_node);
		result = -1;
		goto out;
	}

	result = topo_node_asru_set(t_node, devfmri, 0, &err);
	nvlist_free(devfmri);
	if (result != 0) {
		topo_mod_dprintf(mod, "%s node_0x%llx failed to set ASRU\n",
		    _enum_name, (uint64_t)mde_node);
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	/*
	 * Create property groups.
	 */
	result = topo_pgroup_create(t_node, &io_pgroup, &err);
	if (result < 0) {
		topo_mod_dprintf(mod, "%s node_0x%llx "
		    "topo_pgroup_create for io pgroup failed\n",
		    _enum_name, (uint64_t)mde_node);
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	if (is_pciexrc == 1) {
		result = topo_pgroup_create(t_node, &pci_pgroup, &err);
		if (result < 0) {
			topo_mod_dprintf(mod, "%s node_0x%llx "
			    "topo_pgroup_create for pci pgroup failed\n",
			    _enum_name, (uint64_t)mde_node);
			(void) topo_mod_seterrno(mod, err);
			goto out;
		}
	}

	result = topo_prop_set_string(t_node, TOPO_PGROUP_IO, TOPO_IO_DEV,
	    TOPO_PROP_IMMUTABLE, path, &err);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set DEV property\n",
		    _enum_name, (uint64_t)mde_node);
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	/* device type is always "pciex" */
	result = topo_prop_set_string(t_node, TOPO_PGROUP_IO, TOPO_IO_DEVTYPE,
	    TOPO_PROP_IMMUTABLE, TOPO_PGROUP_PCIEX, &err);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set DEVTYPE property\n",
		    _enum_name, (uint64_t)mde_node);
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	/*
	 * Derived the driver name from the device path.
	 */
	dnode = di_init(path, DIIOC);
	if (dnode == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "%s node_0x%llx failed to get node\n",
		    _enum_name, (uint64_t)mde_node);
		result = -1;
		goto out;
	}
	drv_name = di_driver_name(dnode);
	if (drv_name == NULL) {
		topo_mod_dprintf(mod, "%s node_0x%llx failed to get driver "
		    " name\n", _enum_name, (uint64_t)mde_node);
		di_fini(dnode);
		result = -1;
		goto out;
	}

	if (is_pciexrc == 1) {
		/*
		 * Derived the BDF property from the devinfo node.
		 */
		bdf = pi_enum_pciexrc_findbdf(mod, dnode);
		if (bdf == NULL) {
			topo_mod_dprintf(mod, "%s: node_0x%llx failed to "
			    "find BDF", _enum_name, (uint64_t)mde_node);
			di_fini(dnode);
			result = -1;
			goto out;
		}
	}
	di_fini(dnode);
	topo_mod_dprintf(mod, "%s node_0x%llx driver name is %s\n",
	    _enum_name, (uint64_t)mde_node, drv_name);

	result = topo_prop_set_string(t_node, TOPO_PGROUP_IO, TOPO_IO_DRIVER,
	    TOPO_PROP_IMMUTABLE, drv_name, &err);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set DRIVER property\n",
		    _enum_name, (uint64_t)mde_node);
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	modfmri = topo_mod_modfmri(mod, FM_MOD_SCHEME_VERSION, drv_name);
	if (modfmri == NULL) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to create module fmri\n",
		    _enum_name, (uint64_t)mde_node);
		(void) topo_mod_seterrno(mod, err);
		result = -1;
		goto out;
	}
	result = topo_prop_set_fmri(t_node, TOPO_PGROUP_IO, TOPO_IO_MODULE,
	    TOPO_PROP_IMMUTABLE, modfmri, &err);
	nvlist_free(modfmri);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set MODULE property\n",
		    _enum_name, (uint64_t)mde_node);
		(void) topo_mod_seterrno(mod, err);
		goto out;
	}

	if (is_pciexrc == 1) {
		/* This is a PCIEX root complex */
		result = topo_prop_set_string(t_node, TOPO_PGROUP_PCI,
		    TOPO_PCI_EXCAP, TOPO_PROP_IMMUTABLE, PCIEX_ROOT, &err);
		if (result < 0) {
			topo_mod_dprintf(mod,
			    "%s node_0x%llx failed to set EXCAP property\n",
			    _enum_name, (uint64_t)mde_node);
			(void) topo_mod_seterrno(mod, err);
			goto out;
		}

		/* Set BDF for root complex */
		result = topo_prop_set_string(t_node, TOPO_PGROUP_PCI,
		    TOPO_PCI_BDF, TOPO_PROP_IMMUTABLE, bdf, &err);
		if (result < 0) {
			topo_mod_dprintf(mod,
			    "%s node_0x%llx failed to set BDF property\n",
			    _enum_name, (uint64_t)mde_node);
			(void) topo_mod_seterrno(mod, err);
			goto out;
		}

		/* Create a node range for the children of this root complex */
		result = topo_node_range_create(mod, t_node, PCIEX_BUS, 0,
		    PCIEX_MAX_DEVICE);
		if (result != 0) {
			topo_mod_dprintf(mod,
			    "%s node_0x%llx failed to create %s range\n",
			    _enum_name, (uint64_t)mde_node, PCIEX_BUS);
			result = -1;
		}
	}

out:
	if (path != NULL) {
		topo_mod_strfree(mod, path);
	}
	if (bdf != NULL) {
		topo_mod_strfree(mod, bdf);
	}
	return (result);
}


static int
pi_enum_pciexrc_finddev(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    tnode_t *t_node)
{
	di_node_t	devtree;
	di_node_t	dnode;
	char		*path;

	/* Initialize the device information structure for this module */
	devtree = topo_mod_devinfo(mod);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed\n");
		return (-1);
	}

	/*
	 * Find the PRI node path property. This will be used to associate
	 * the PRI node with the device node.
	 */
	path = pi_get_path(mod, mdp, mde_node);
	if (path == NULL) {
		topo_mod_dprintf(mod, "node_0x%llx has no path\n",
		    (uint64_t)mde_node);
		return (-1);
	}

	/*
	 * Scan the device node list and find the node associated with
	 * the given PRI node.  Equality is defined when the PRI path
	 * is the same as the device node path.
	 */
	dnode = di_drv_first_node(drv_name, devtree);
	while (dnode != DI_NODE_NIL) {
		char	*devfs_path;

		devfs_path = di_devfs_path(dnode);
		if (devfs_path != NULL) {
			if (strncmp(devfs_path, path, strlen(path)) == 0) {
				/* We have found the matching dnode */
				break;
			}
		}

		/* We have not found the matching dnode yet */
		dnode = di_drv_next_node(dnode);
	}
	if (dnode != DI_NODE_NIL) {
		topo_mod_dprintf(mod, "%s node_0x%llx found dev path %s\n",
		    _ENUM_NAME, (uint64_t)mde_node, path);

		/*
		 * Associate this dnode with the topo node.  The PCI
		 * enumerator requires this information.
		 */
		topo_node_setspecific(t_node, (void *)dnode);
	}

	topo_mod_strfree(mod, path);
	return (0);
}


/*
 * Find the BDF property and return as a string.
 *
 * The string must be freed with topo_mod_strfree()
 */
static char *
pi_enum_pciexrc_findbdf(topo_mod_t *mod, di_node_t dnode)
{
	uint_t		 reg;
	uint_t		 bdf;
	char		 bdf_str[PCIEX_MAX_BDF_SIZE];
	unsigned char	 *buf;
	di_prop_t	 di_prop;
	di_prom_handle_t di_prom_hdl;
	di_prom_prop_t	 di_prom_prop;

	/*
	 * Look for the "reg" property from the devinfo node.
	 */
	for (di_prop = di_prop_next(dnode, DI_PROP_NIL);
	    di_prop != DI_PROP_NIL;
	    di_prop = di_prop_next(dnode, di_prop)) {
		if (strncmp(di_prop_name(di_prop), "reg",
		    sizeof (reg)) == 0) {
			if (di_prop_bytes(di_prop, &buf) < sizeof (uint_t)) {
				continue;
			}
			bcopy(buf, &reg, sizeof (uint_t));
			break;
		}
	}

	/*
	 * If the "reg" property is not found in the di_node; look for it in
	 * OBP prom data.
	 */
	if (di_prop == DI_PROP_NIL) {
		if ((di_prom_hdl = topo_mod_prominfo(mod)) ==
		    DI_PROM_HANDLE_NIL) {
			topo_mod_dprintf(mod,
			    "%s failed to get prom handle\n", _ENUM_NAME);
			return (NULL);
		}
		for (di_prom_prop =
		    di_prom_prop_next(di_prom_hdl, dnode, DI_PROM_PROP_NIL);
		    di_prom_prop != DI_PROM_PROP_NIL;
		    di_prom_prop =
		    di_prom_prop_next(di_prom_hdl, dnode, di_prom_prop)) {
			if (strncmp(di_prom_prop_name(di_prom_prop), "reg",
			    sizeof (reg)) == 0) {
				if (di_prom_prop_data(di_prom_prop, &buf) <
				    sizeof (uint_t)) {
					continue;
				}
				bcopy(buf, &reg, sizeof (uint_t));
				break;
			}
		}
		if (di_prom_prop == DI_PROP_NIL) {
			topo_mod_dprintf(mod,
			    "%s failed to get reg property\n", _ENUM_NAME);
			return (NULL);
		}
	}

	/*
	 * Caculate BDF
	 *
	 * The reg property is divided like this:
	 * -----------------------------------------------------
	 * | 23  Bus  16 | 15  Dev  11 | 10  Fn  8 | 7  Reg  0 |
	 * -----------------------------------------------------
	 *
	 * PCI_REG_* macros strip off Reg and shift to get individual
	 * Bus/Dev/Fn bits. Shift and OR each to get bdf value.
	 */
	bdf = (PCI_REG_BUS_G(reg) << 8) | (PCI_REG_DEV_G(reg) << 3) |
	    PCI_REG_FUNC_G(reg);

	/* Pass BDF back as a string */
	(void) snprintf(bdf_str, PCIEX_MAX_BDF_SIZE, "0x%x", bdf);
	topo_mod_dprintf(mod, "%s found BDF %s\n", _ENUM_NAME, bdf_str);

	return (topo_mod_strdup(mod, bdf_str));
}
