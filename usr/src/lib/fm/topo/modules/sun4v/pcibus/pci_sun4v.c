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
/*
 * Including the following file gives us definitions of the three
 * global arrays used to adjust labels, Slot_Rewrites, Physlot_Names,
 * and Missing_Names.  With those defined we can use the common labeling
 * routines for pci.
 */
#include "pci_sun4v.h"

#include "pci_sun4.h"

int
platform_pci_label(topo_mod_t *mod, tnode_t *node, nvlist_t *in,
    nvlist_t **out)
{
	return (pci_label_cmn(mod, node, in, out));
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
	} else {
		return (pci_fru_compute(mod, node, in, out));
	}
}
