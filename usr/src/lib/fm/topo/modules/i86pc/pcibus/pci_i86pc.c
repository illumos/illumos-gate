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

#include <fm/topo_mod.h>

#include "pcibus.h"
#include "pcibus_labels.h"
#include <string.h>
#include <strings.h>

slotnm_rewrite_t *Slot_Rewrites = NULL;
physlot_names_t *Physlot_Names = NULL;
missing_names_t *Missing_Names = NULL;

int
platform_pci_label(topo_mod_t *mod, tnode_t *node, nvlist_t *in,
    nvlist_t **out)
{
	return (pci_label_cmn(mod, node, in, out));
}
/*ARGSUSED*/
int
platform_pci_fru(topo_mod_t *mod, tnode_t *node, nvlist_t *in,
    nvlist_t **out)
{
	char *nm, *label;
	char buf[PATH_MAX];
	nvlist_t *fmri;
	int e;

	*out = NULL;
	nm = topo_node_name(node);
	if (strcmp(nm, PCI_DEVICE) != 0 && strcmp(nm, PCIEX_DEVICE) != 0 &&
	    strcmp(nm, PCIEX_BUS) != 0)
		return (0);

	if (topo_prop_get_string(node,
		TOPO_PGROUP_PROTOCOL, TOPO_PROP_LABEL, &label, &e) < 0) {
		if (e != ETOPO_PROP_NOENT)
			return (topo_mod_seterrno(mod, e));
		return (0);
	}

	(void) snprintf(buf, PATH_MAX, "hc:///component=%s", label);
	topo_mod_strfree(mod, label);
	if (topo_mod_str2nvl(mod, buf, &fmri) < 0)
		return (-1);

	*out = fmri;
	return (0);
}
