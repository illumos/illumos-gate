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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <fm/topo_mod.h>
#include <did_props.h>

/*
 * Including the following file gives us definitions of the three
 * global arrays used to adjust labels, Slot_Rewrites, Physlot_Names,
 * and Missing_Names.  With those defined we can use the common labeling
 * routines for pci.
 */
#include "pci_sun4u.h"

#include "pci_sun4.h"
#include <strings.h>

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
	return (pci_fru_compute(mod, node, in, out));
}

/*
 * Sun-Fire platform function to test whether the hostbridge which
 * this PCI device is associated with is an Xmits or not. This
 * function applies to E3800, E48xx, E4900, E6800, and E6900.
 *
 * Return 1 if the hostbridge is an Xmits otherwise return 0.
 *
 * This check is done by walking up the topo tree and checking the
 * associated device info nodes for a binding name or a compatible
 * name matching that of Xmits.
 */
int
sunfire_test_func(topo_mod_t *mod, did_t *dp)
{
	tnode_t *tp;
	int done, xmits_found, i, n;
	char *compatible_names, *binding_name;

	done = xmits_found = 0;
	tp = did_gettnode(dp);

	while (!done) {
		topo_mod_dprintf(mod, "%s: dp=0x%p, tp=0x%p\n",
		    __func__, dp, tp);

		/*
		 * Check binding name.
		 */
		binding_name = di_binding_name(did_dinode(dp));
		if (binding_name != NULL) {
			topo_mod_dprintf(mod, "%s: binding_name=%s\n",
			    __func__, binding_name);
			if (strncmp(binding_name, XMITS_COMPAT,
			    sizeof (XMITS_COMPAT)) == 0) {
				done = xmits_found = 1;
				break;
			}
		}

		/*
		 * Check compatible names.
		 */
		n = di_compatible_names(did_dinode(dp), &compatible_names);
		for (i = 0; i < n; i++) {
			topo_mod_dprintf(mod, "%s: compatible_name[%d]=%s\n",
			    __func__, i, compatible_names);
			if (strncmp(compatible_names, XMITS_COMPAT,
			    sizeof (XMITS_COMPAT)) == 0) {
				done = xmits_found = 1;
				break;
			}
			compatible_names += strlen(compatible_names) + 1;
		}

		/*
		 * Walk up the tree until we hit the top or hit
		 * a non-PCI device.
		 */
		if (((tp = topo_node_parent(tp)) == NULL) ||
		    (dp = did_find(mod, topo_node_getspecific(tp))) == NULL) {
			done = 1;
			break;
		}
	}

	return (xmits_found);
}
