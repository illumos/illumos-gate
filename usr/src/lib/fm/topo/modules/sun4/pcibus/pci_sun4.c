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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string.h>
#include <fm/topo_mod.h>
#include <libnvpair.h>
#include <util.h>
#include <pcibus.h>
#include <did.h>
#include <pcibus_labels.h>

int
pci_fru_compute(topo_mod_t *mod, tnode_t *node, nvlist_t *in, nvlist_t **out)
{
	char *nm;
	uint64_t ptr;
	did_t *dp;
	const char *l;
	char *plabel;
	tnode_t *pn;
	int err;
	nvlist_t *fmri = NULL;

	*out = NULL;
	nm = topo_node_name(node);
	if (strcmp(nm, PCI_DEVICE) != 0 && strcmp(nm, PCIEX_DEVICE) != 0 &&
	    strcmp(nm, PCIEX_BUS) != 0)
		return (0);

	if (nvlist_lookup_uint64(in, "nv1", &ptr) != 0) {
		topo_mod_dprintf(mod,
		    "label method argument not found.\n");
		return (-1);
	}
	dp = (did_t *)(uintptr_t)ptr;

	if (topo_node_resource(node, &fmri, &err) < 0 ||
	    fmri == NULL) {
		topo_mod_dprintf(mod, "pci_fru_compute error: %s\n",
			topo_strerror(topo_mod_errno(mod)));
		return (topo_mod_seterrno(mod, err));
	}

	/*
	 * Is there a slotname associated with the device?
	 */
	if ((l = pci_slotname_lookup(mod, node, dp)) != NULL) {
		/*
		 * Get parent label. If l is the same as parent label,
		 * inherit parent's FRU property.
		 */
		pn = did_gettnode(dp);
		if (pn != NULL &&
		    (topo_prop_get_string(pn,
			TOPO_PGROUP_PROTOCOL,
			TOPO_PROP_LABEL, &plabel, &err) == 0)) {
			if (strcmp(plabel, l) == 0) {
				topo_mod_strfree(mod, plabel);
				nvlist_free(fmri);
				return (0);
			}
			topo_mod_strfree(mod, plabel);
		}
		*out = fmri;
	} else
		nvlist_free(fmri);

	return (0);
}
