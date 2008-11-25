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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#include "pi_impl.h"

#define	TOPO_PGROUP_PCIEX	"pciex"
#define	TOPO_PCIEX_DRIVER	"px"
#define	PCIEX_MAX_DEVICE	255

#define	_ENUM_NAME	"enum_pciexrc"

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static const topo_pgroup_info_t pci_pgroup =
	{ TOPO_PGROUP_PCI, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

static int pi_enum_pciexrc_finddev(topo_mod_t *, md_t *, mde_cookie_t,
    tnode_t *);
static int pi_enum_pciexrc_update(topo_mod_t *, md_t *, mde_cookie_t,
    tnode_t *, tnode_t *);

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
		    _ENUM_NAME, topo_strerror(topo_mod_errno(mod)));
		return (result);
	}

	/* Update the topo node with more specific information */
	result = pi_enum_pciexrc_update(mod, mdp, mde_node, t_parent, *t_node);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to create node properites: %s\n",
		    _ENUM_NAME, topo_strerror(topo_mod_errno(mod)));
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
 * Update a PCIEXRC topo node with node-specific information
 *
 * The following is mostly a duplicate of code contained in:
 *	usr/src/lib/fm/topo/modules/sun4v/cpuboard/
 *	    cpuboard_hostbridge.c:cpuboard_rc_node_create
 */
static int
pi_enum_pciexrc_update(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    tnode_t *t_parent, tnode_t *t_node)
{
	int		result;
	int		err;
	char		dnpath[MAXPATHLEN];
	uint64_t	cfg_handle;
	nvlist_t	*modfmri;
	nvlist_t	*devfmri;

	if (t_parent == NULL || t_node == NULL) {
		topo_mod_dprintf(mod, "%s node_0x%llx has no parent\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		return (-1);
	}

	/*
	 * Calculate the device path for this root complex node.
	 */
	result = pi_get_cfg_handle(mod, mdp, mde_node, &cfg_handle);
	if (result != 0) {
		topo_mod_dprintf(mod, "node_0x%llx has no cfg-handle\n",
		    (uint64_t)mde_node);
		return (result);
	}
	(void) snprintf(dnpath, sizeof (dnpath), "/pci@%llx", cfg_handle);

	/*
	 * Set the ASRU for this node using the dev scheme
	 */
	devfmri = topo_mod_devfmri(mod, FM_DEV_SCHEME_VERSION, dnpath, NULL);
	if (devfmri == NULL) {
		topo_mod_dprintf(mod, "%s node_0x%llx fmri creation failed\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		return (-1);
	}

	result = topo_node_asru_set(t_node, devfmri, 0, &err);
	nvlist_free(devfmri);
	if (result != 0) {
		topo_mod_dprintf(mod, "%s node_0x%llx failed to set ASRU\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (-1);
	}

	/*
	 * Set PCIEXRC properties for root complex nodes
	 */
	result = topo_pgroup_create(t_node, &io_pgroup, &err);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx topo_pgroup_create for io pgroup failed\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (result);
	}
	result = topo_pgroup_create(t_node, &pci_pgroup, &err);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx topo_pgroup_create for pci pgroup failed\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (result);
	}

	result = topo_prop_set_string(t_node, TOPO_PGROUP_IO, TOPO_IO_DEV,
	    TOPO_PROP_IMMUTABLE, dnpath, &err);
	if (result != 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set DEV property\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (result);
	}

	/* device type is always "pciex" */
	result = topo_prop_set_string(t_node, TOPO_PGROUP_IO, TOPO_IO_DEVTYPE,
	    TOPO_PROP_IMMUTABLE, TOPO_PGROUP_PCIEX, &err);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set DEVTYPE property\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (result);
	}

	/*
	 * driver is always "px"
	 */
	result = topo_prop_set_string(t_node, TOPO_PGROUP_IO, TOPO_IO_DRIVER,
	    TOPO_PROP_IMMUTABLE, TOPO_PCIEX_DRIVER, &err);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set DRIVER property\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (result);
	}

	modfmri = topo_mod_modfmri(mod, FM_MOD_SCHEME_VERSION,
	    TOPO_PCIEX_DRIVER);
	if (modfmri == NULL) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to create module fmri\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (result);
	}
	result = topo_prop_set_fmri(t_node, TOPO_PGROUP_IO, TOPO_IO_MODULE,
	    TOPO_PROP_IMMUTABLE, modfmri, &err);
	nvlist_free(modfmri);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set MODULE property\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (result);
	}

	/* This is a PCIEX root complex */
	result = topo_prop_set_string(t_node, TOPO_PGROUP_PCI, TOPO_PCI_EXCAP,
	    TOPO_PROP_IMMUTABLE, PCIEX_ROOT, &err);
	if (result < 0) {
		topo_mod_dprintf(mod,
		    "%s node_0x%llx failed to set EXCAP property\n",
		    _ENUM_NAME, (uint64_t)mde_node);
		topo_mod_seterrno(mod, err);
		return (result);
	}

	/* Create a node range for the children of this root complex */
	topo_node_range_create(mod, t_node, PCIEX_BUS, 0, PCIEX_MAX_DEVICE);

	return (0);
}


static int
pi_enum_pciexrc_finddev(topo_mod_t *mod, md_t *mdp, mde_cookie_t mde_node,
    tnode_t *t_node)
{
	int		result;
	di_node_t	devtree;
	di_node_t	dnode;
	uint64_t	cfg_handle;

	/* Initialize the device information structure for this module */
	devtree = topo_mod_devinfo(mod);
	if (devtree == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed\n");
		return (-1);
	}

	/*
	 * Find the PRI node cfg-handle.  This will be used to associate the
	 * PRI node with the device node
	 */
	result = pi_get_cfg_handle(mod, mdp, mde_node, &cfg_handle);
	if (result != 0) {
		topo_mod_dprintf(mod, "node_0x%llx has no cfg-handle\n",
		    (uint64_t)mde_node);
		return (result);
	}
	topo_mod_dprintf(mod, "node_0x%llx has cfg-handle = /pci@%llx\n",
	    (uint64_t)mde_node, cfg_handle);

	/*
	 * Scan the device node list and find the node associated with
	 * the given PRI node.  Equality is defined as the PRI cfg-handle
	 * equalling the device node bus address.
	 */
	dnode = di_drv_first_node(TOPO_PCIEX_DRIVER, devtree);
	while (dnode != DI_NODE_NIL) {
		uint64_t	bus_addr;
		char		*addr;

		addr = di_bus_addr(dnode);
		if (addr != NULL) {
			bus_addr = strtoull(addr, NULL, 16);
			if (bus_addr == cfg_handle) {
				/* We have found the matching dnode */
				break;
			}
		}

		/* We have not found the matching dnode yet */
		dnode = di_drv_next_node(dnode);
	}
	if (dnode != DI_NODE_NIL) {
		topo_mod_dprintf(mod, "%s node_0x%llx found bus 0x%llx\n",
		    _ENUM_NAME, (uint64_t)mde_node, cfg_handle);

		/*
		 * Associate this dnode with the topo node.  The PCI
		 * enumerator requires this information.
		 */
		topo_node_setspecific(t_node, (void *)dnode);
	}

	return (0);
}
