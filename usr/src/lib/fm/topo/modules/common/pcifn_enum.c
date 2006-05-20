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

#include <limits.h>
#include <fm/libtopo.h>
#include "did.h"
#include "did_props.h"
#include "pcifn_enum.h"

static topo_mod_t *
module_load(topo_mod_t *mp, tnode_t *parent, const char *name)
{
	topo_mod_t *rp = NULL;
	char *plat, *mach;
	char *path;
	char *rootdir;
	int err;

	plat = mach = NULL;

	if (topo_prop_get_string(parent,
	    TOPO_PGROUP_SYSTEM, TOPO_PROP_PLATFORM, &plat, &err) < 0) {
		(void) topo_mod_seterrno(mp, err);
		return (NULL);
	}
	if (topo_prop_get_string(parent,
	    TOPO_PGROUP_SYSTEM, TOPO_PROP_MACHINE, &mach, &err) < 0) {
		(void) topo_mod_seterrno(mp, err);
		return (NULL);
	}
	path = topo_mod_alloc(mp, PATH_MAX);
	rootdir = topo_mod_rootdir(mp);
	(void) snprintf(path, PATH_MAX,
	    PATH_TEMPLATE, rootdir ? rootdir : "", plat, name);

	if ((rp = topo_mod_load(mp, path)) == NULL) {
		topo_mod_dprintf(mp, "Unable to load %s.\n", path);
		(void) snprintf(path, PATH_MAX,
		    PATH_TEMPLATE, rootdir ? rootdir : "", mach, name);
		if ((rp = topo_mod_load(mp, path)) == NULL)
			topo_mod_dprintf(mp, "Unable to load %s.\n", path);
	}
	topo_mod_strfree(mp, plat);
	topo_mod_strfree(mp, mach);
	topo_mod_free(mp, path, PATH_MAX);
	return (rp);
}

static int
module_run(topo_mod_t *mp, tnode_t *parent, pfn_enum_t *ep)
{
	return (topo_mod_enumerate(mp, parent,
	    ep->pfne_modname, ep->pfne_childname,
	    ep->pfne_imin, ep->pfne_imax));
}

int
pcifn_enum(topo_mod_t *mp, tnode_t *parent)
{
	char *ccstr;
	int rv = 0;
	int i, e;
	uint_t cc;
	topo_mod_t *child_mod;

	topo_mod_dprintf(mp, "Enumerating beneath pci(ex) function.\n");

	/*
	 * Extract the class code of the PCI function and make sure
	 * it matches the type that the module cares about.
	 */
	if (topo_prop_get_string(parent,
	    TOPO_PGROUP_PCI, TOPO_PROP_CLASS, &ccstr, &e) < 0)
		return (0);
	if (sscanf(ccstr, "%x", &cc) != 1) {
		topo_mod_strfree(mp, ccstr);
		return (0);
	}
	topo_mod_strfree(mp, ccstr);
	cc = cc >> 16;

	for (i = 0; i < Pcifn_enumerator_count; i++) {

		if (cc != Pcifn_enumerators[i].pfne_class)
			continue;

		child_mod = module_load(mp, parent,
		    Pcifn_enumerators[i].pfne_modname);

		if (child_mod) {
			rv = module_run(mp, parent,
			    &Pcifn_enumerators[i]) != 0 ? -1 : 0;
			topo_mod_unload(child_mod);
		}
	}
	return (rv);
}
