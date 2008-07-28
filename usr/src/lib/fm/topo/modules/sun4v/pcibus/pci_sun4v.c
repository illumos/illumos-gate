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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>
#include <string.h>
#include <alloca.h>
#include <libdevinfo.h>
#include <did_props.h>

/*
 * Including the following file gives us definitions of the three
 * global arrays used to adjust labels, Slot_Rewrites, Physlot_Names,
 * and Missing_Names.  With those defined we can use the common labeling
 * routines for pci.
 */
#include "pci_sun4v.h"
#include "pci_sun4.h"

#define	PI_PROP_CHASSIS_LOCATION_NAME		"chassis-location-name"

typedef struct _pci_fru {
	tnode_t	*node;
	char	*location;
	int	locsiz;
} _pci_fru_t;


static int platform_pci_fru_location(topo_mod_t *, tnode_t *, uchar_t *, int);
static int platform_pci_fru_cb(topo_mod_t *, tnode_t *, void *);


int
platform_pci_label(topo_mod_t *mod, tnode_t *node, nvlist_t *in,
    nvlist_t **out)
{
	int	result;
	int	err;
	int	locsiz = 0;
	uchar_t	*loc = NULL;
	char	*nac = NULL;

	topo_mod_dprintf(mod, "entering platform_pci_label\n");

	*out = NULL;
	result = di_bytes_get(mod, topo_node_getspecific(node),
	    PI_PROP_CHASSIS_LOCATION_NAME, &locsiz, &loc);
	if (result == -1 || locsiz < 0) {
		topo_mod_dprintf(mod, "platform_pci_label: %s not found (%s)\n",
		    PI_PROP_CHASSIS_LOCATION_NAME, strerror(errno));

		/* Invoke the generic label generator for this node */
		return (pci_label_cmn(mod, node, in, out));
	}

	/*
	 * We have crossed a FRU boundary.  Use the value in the
	 * chassis-location-name property as the node label.
	 */
	nac = alloca(locsiz+1);
	(void) memset(nac, 0, locsiz+1);
	(void) memcpy(nac, loc, locsiz);
	result = topo_node_label_set(node, nac, &err);
	if (result < 0) {
		if (err != ETOPO_PROP_NOENT) {
			return (topo_mod_seterrno(mod, err));
		}
	}

	return (0);
}


int
platform_pci_fru(topo_mod_t *mod, tnode_t *node, nvlist_t *in,
    nvlist_t **out)
{
	int err = 0;
	uint64_t ptr;
	did_t *dp, *pdp;
	tnode_t *pnode;
	char *nm, *plat, *pp, **cp;
	const char *label;
	int found_t1plat = 0;
	uchar_t *loc;
	int locsiz;

	topo_mod_dprintf(mod, "entering platform_pci_fru\n");

	if (topo_prop_get_string(node, FM_FMRI_AUTHORITY,
	    FM_FMRI_AUTH_PRODUCT, &plat, &err) < 0) {
		(void) topo_mod_seterrno(mod, err);
		return (-1);
	}
	/* Delete the "SUNW," */
	pp = strchr(plat, ',');
	if (pp == NULL)
		pp = plat;
	else
		++pp;

	/* Is this an UltraSPARC-T1 platform? */
	cp = usT1_plats;
	while ((*cp != NULL) && (found_t1plat == 0)) {
		if (strcmp(pp, *cp) == 0)
			found_t1plat = 1;
		cp++;
	}

	topo_mod_strfree(mod, plat);

	/*
	 * On UltraSPARC-T1 systems, use the legacy hc scheme on
	 * the adapter slots to ensure ALOM on the SP can interpret
	 * the FRU correctly. For everything else, follow the normal
	 * code flow
	 */
	if (found_t1plat) {
		*out = NULL;
		nm = topo_node_name(node);
		if (strcmp(nm, PCI_DEVICE) != 0 &&
		    strcmp(nm, PCIEX_DEVICE) != 0 &&
		    strcmp(nm, PCIEX_BUS) != 0)
			return (0);

		if (nvlist_lookup_uint64(in, "nv1", &ptr) != 0) {
			topo_mod_dprintf(mod, "label method argument "
			    "not found.\n");
			return (-1);
		}
		dp = (did_t *)(uintptr_t)ptr;
		pnode = did_gettnode(dp);
		pdp = did_find(mod, topo_node_getspecific(pnode));

		/*
		 * Is there a slotname associated with the device?
		 */
		if ((label = pci_slotname_lookup(mod, pnode, dp, pdp))
		    != NULL) {
			nvlist_t *rnvl;
			char buf[PATH_MAX];

			(void) snprintf(buf, PATH_MAX, "hc:///component=%s",
			    label);
			if (topo_mod_str2nvl(mod, buf, &rnvl) < 0)
				return (-1);
			*out = rnvl;
		}
		return (0);
	} else if (di_bytes_get(mod, topo_node_getspecific(node),
	    PI_PROP_CHASSIS_LOCATION_NAME, &locsiz, &loc) == 0 && locsiz > 0) {
		/*
		 * We have crossed a FRU boundary and need to find the parent
		 * node with this location and set our FMRI to that value.
		 */
		return (platform_pci_fru_location(mod, node, loc, locsiz));
	} else {
		return (pci_fru_compute(mod, node, in, out));
	}
}


static int
platform_pci_fru_location(topo_mod_t *mod, tnode_t *node, uchar_t *loc,
    int locsiz)
{
	int		err;
	tnode_t		*parent;
	tnode_t		*top;
	topo_walk_t	*wp;
	_pci_fru_t	walkdata;

	topo_mod_dprintf(mod, "entering platform_pci_fru_location\n");

	/* Find the root node */
	top = node;
	while ((parent = topo_node_parent(top)) != NULL) {
		top = parent;
	}
	walkdata.node = node;
	walkdata.locsiz = locsiz;
	walkdata.location = alloca(locsiz+1);
	(void) memset(walkdata.location, 0, locsiz+1);
	(void) memcpy(walkdata.location, loc, locsiz);

	/* Create a walker starting at the root node */
	wp = topo_mod_walk_init(mod, top, platform_pci_fru_cb, &walkdata, &err);
	if (wp == NULL) {
		return (topo_mod_seterrno(mod, err));
	}

	/*
	 * Walk the tree breadth first to hopefully avoid visiting too many
	 * nodes while searching for the node with the appropriate FMRI.
	 */
	(void) topo_walk_step(wp, TOPO_WALK_SIBLING);
	topo_walk_fini(wp);

	return (0);
}


static int
platform_pci_fru_cb(topo_mod_t *mod, tnode_t *node, void *private)
{
	int		err;
	_pci_fru_t	*walkdata = (_pci_fru_t *)private;
	nvlist_t	*fmri;
	char		*location;
	int 		result, rc;

	if (node == walkdata->node) {
		/* This is the starting node.  Do not check the location */
		return (TOPO_WALK_NEXT);
	}

	if (topo_node_label(node, &location, &err) != 0) {
		/* This node has no location property.  Continue the walk */
		return (TOPO_WALK_NEXT);
	}

	result = TOPO_WALK_NEXT;
	if (strncmp(location, walkdata->location, walkdata->locsiz) == 0) {
		/*
		 * We have a match.  Set the node's FRU FMRI to this nodes
		 * FRU FMRI
		 */
		rc = topo_node_fru(node, &fmri, NULL, &err);
		if (rc == 0) {
			rc = topo_node_fru_set(walkdata->node, fmri, 0, &err);
			nvlist_free(fmri);
		}
		if (rc != 0) {
			result = TOPO_WALK_TERMINATE;
			topo_mod_seterrno(mod, err);
		}
	}
	topo_mod_strfree(mod, location);
	return (result);
}
