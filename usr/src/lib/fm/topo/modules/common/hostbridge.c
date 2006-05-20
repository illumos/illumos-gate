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
#include <fm/topo_mod.h>
#include <libdevinfo.h>
#include <limits.h>
#include <sys/fm/protocol.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <assert.h>
#include <pthread.h>

#include "pcibus.h"
#include "hostbridge.h"
#include "did.h"
#include "did_props.h"
#include "util.h"

/*
 * hostbridge.c
 *	Generic code shared by all the hostbridge enumerators
 */

static void hb_release(topo_mod_t *, tnode_t *);
static int hb_contains(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hb_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hb_label(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hb_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *);

extern txprop_t ExHB_common_props[];
extern txprop_t HB_common_props[];
extern txprop_t RC_common_props[];
extern int ExHB_propcnt;
extern int HB_propcnt;
extern int RC_propcnt;

static int specific_hb_enum(tnode_t *, const char *, topo_instance_t,
    topo_instance_t, di_prom_handle_t, topo_mod_t *);

const topo_modinfo_t Hb_info =
	{ HOSTBRIDGE, HB_ENUMR_VERS, hb_enum, hb_release };

const topo_method_t Hb_methods[] = {
	{ "hb_contains", "hb element contains other element", HB_ENUMR_VERS,
	    TOPO_STABILITY_INTERNAL, hb_contains },
	{ "hb_present", "hb element currently present", HB_ENUMR_VERS,
	    TOPO_STABILITY_INTERNAL, hb_present },
	{ TOPO_METH_LABEL, TOPO_METH_LABEL_DESC,
	    TOPO_METH_LABEL_VERSION, TOPO_STABILITY_INTERNAL, hb_label },
	{ NULL }
};

void
_topo_init(topo_mod_t *modhdl)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOHBDBG") != NULL)
		topo_mod_setdebug(modhdl, TOPO_DBG_ALL);
	topo_mod_dprintf(modhdl, "initializing hostbridge enumerator\n");

	topo_mod_register(modhdl, &Hb_info, NULL);
	topo_mod_dprintf(modhdl, "Hostbridge enumr initd\n");
}

void
_topo_fini(topo_mod_t *modhdl)
{
	topo_mod_unregister(modhdl);
}

/*ARGSUSED*/
static int
hb_contains(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (0);
}

/*ARGSUSED*/
static int
hb_present(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (0);
}

static int
hb_label(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_LABEL_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));
	return (platform_hb_label(node, in, out, mp));
}

static topo_mod_t *
pci_enumr_load(topo_mod_t *mp, tnode_t *parent)
{
	topo_mod_t *rp = NULL;
	char *plat, *mach;
	char *pcipath;
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
	pcipath = topo_mod_alloc(mp, PATH_MAX);
	rootdir = topo_mod_rootdir(mp);
	(void) snprintf(pcipath,
	    PATH_MAX, PATH_TO_PCI_ENUM, rootdir ? rootdir : "", plat);

	if ((rp = topo_mod_load(mp, pcipath)) == NULL) {
		topo_mod_dprintf(mp,
		    "%s enumerator could not load %s.\n", HOSTBRIDGE, pcipath);
		(void) snprintf(pcipath,
		    PATH_MAX, PATH_TO_PCI_ENUM, rootdir ? rootdir : "", mach);
		if ((rp = topo_mod_load(mp, pcipath)) == NULL) {
			topo_mod_dprintf(mp,
			    "%s enumerator could not load %s.\n",
			    HOSTBRIDGE, pcipath);
		}
	}
	topo_mod_strfree(mp, plat);
	topo_mod_strfree(mp, mach);
	topo_mod_free(mp, pcipath, PATH_MAX);
	return (rp);
}

/*ARGSUSED*/
static int
hb_enum(topo_mod_t *mp, tnode_t *pn, const char *name, topo_instance_t imin,
    topo_instance_t imax, void *notused)
{
	topo_mod_t *pcimod;
	did_hash_t *didhash;
	di_prom_handle_t promtree;
	int rv;

	if (strcmp(name, HOSTBRIDGE) != 0) {
		topo_mod_dprintf(mp,
		    "Currently only know how to enumerate %s components.\n",
		    HOSTBRIDGE);
		return (0);
	}

	/*
	 * Load the pcibus enumerator, we'll soon need it!
	 */
	if ((pcimod = pci_enumr_load(mp, pn)) == NULL)
		return (-1);

	if ((promtree = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		topo_mod_unload(pcimod);
		topo_mod_dprintf(mp,
		    "Hostbridge enumerator: di_prom_handle_init failed.\n");
		return (-1);
	}

	/*
	 * If we're asked to enumerate a whole range of hostbridges, then
	 * we need to find them all.  If we're just asked to enumerate a
	 * single hostbridge, we expect our caller to have passed us linked
	 * did_t structures we can use to enumerate the singled out hostbridge.
	 */
	if (imin != imax) {

		if ((didhash = did_hash_init(mp)) == NULL) {
			topo_mod_dprintf(mp,
			    "Hash initialization for hostbridge "
			    "enumerator failed.\n");
			topo_mod_unload(pcimod);
			return (-1);
		}
		if ((rv = platform_hb_enum(pn, name, imin, imax, didhash,
		    promtree, mp)) < 0)
			topo_mod_seterrno(mp, EMOD_PARTIAL_ENUM);
		di_prom_fini(promtree);
		did_hash_fini(didhash);
		topo_mod_unload(pcimod);
		return (rv);
	} else {
		rv = specific_hb_enum(pn, name, imin, imax, promtree, mp);
		di_prom_fini(promtree);
		topo_mod_unload(pcimod);
		return (rv);
	}
}

/*ARGSUSED*/
static void
hb_release(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);
}

static tnode_t *
hb_tnode_create(tnode_t *parent,
    const char *name, topo_instance_t i, void *priv, topo_mod_t *mod)
{
	topo_hdl_t *thp;
	nvlist_t *args, *fmri, *pfmri;
	tnode_t *ntn;
	int err;

	thp = topo_mod_handle(mod);

	if (topo_node_resource(parent, &pfmri, &err) < 0) {
		topo_mod_seterrno(mod, err);
		topo_mod_dprintf(mod,
		    "Unable to retrieve parent resource.\n");
		return (NULL);
	}
	if (topo_mod_nvalloc(mod, &args, NV_UNIQUE_NAME) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
		nvlist_free(pfmri);
		return (NULL);
	}
	err = nvlist_add_nvlist(args, TOPO_METH_FMRI_ARG_PARENT, pfmri);
	if (err != 0) {
		nvlist_free(pfmri);
		nvlist_free(args);
		(void) topo_mod_seterrno(mod, EMOD_FMRI_NVL);
		return (NULL);
	}

	fmri = topo_fmri_create(thp, FM_FMRI_SCHEME_HC, name, i, args, &err);
	if (fmri == NULL) {
		nvlist_free(pfmri);
		nvlist_free(args);
		(void) topo_mod_seterrno(mod, err);
		topo_mod_dprintf(mod,
		    "Unable to make nvlist for %s bind: %s.\n",
		    name, topo_strerror(err));
		return (NULL);
	}

	nvlist_free(pfmri);
	nvlist_free(args);
	ntn = topo_node_bind(mod, parent, name, i, fmri, priv);
	if (ntn == NULL) {
		topo_mod_dprintf(mod,
		    "topo_node_bind (%s%d/%s%d) failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);
	if (topo_method_register(mod, ntn, Hb_methods) < 0) {
		topo_mod_dprintf(mod, "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pcihostbridge_declare(tnode_t *parent, di_node_t din, topo_instance_t i,
    did_hash_t *didhash, di_prom_handle_t promtree, topo_mod_t *mod)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(didhash, din)) == NULL)
		return (NULL);
	if ((ntn = hb_tnode_create(parent, HOSTBRIDGE, i, pd, mod)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, HB_common_props, HB_propcnt,
	    promtree) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We expect to find pci buses beneath the hostbridge.
	 */
	if (child_range_add(mod, ntn, PCI_BUS, 0, MAX_HB_BUSES) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pciexhostbridge_declare(tnode_t *parent, di_node_t din, topo_instance_t hi,
    did_hash_t *didhash, di_prom_handle_t promtree, topo_mod_t *mod)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(didhash, din)) == NULL)
		return (NULL);
	if ((ntn = hb_tnode_create(parent, HOSTBRIDGE, hi, din, mod)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, ExHB_common_props, ExHB_propcnt,
	    promtree) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We expect to find root complexes beneath the hostbridge.
	 */
	if (child_range_add(mod, ntn, PCIEX_ROOT, 0, MAX_HB_BUSES) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pciexrc_declare(tnode_t *parent, di_node_t din, topo_instance_t ri,
    did_hash_t *didhash, di_prom_handle_t promtree, topo_mod_t *mod)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(didhash, din)) == NULL)
		return (NULL);
	did_markrc(pd);
	if ((ntn = hb_tnode_create(parent, PCIEX_ROOT, ri, din, mod)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, RC_common_props, RC_propcnt,
	    promtree) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We expect to find pci-express buses beneath a root complex
	 */
	if (child_range_add(mod, ntn, PCIEX_BUS, 0, MAX_HB_BUSES) < 0) {
		topo_node_range_destroy(ntn, PCIEX_BUS);
		return (NULL);
	}
	return (ntn);
}

/*ARGSUSED*/
static int
specific_hb_enum(tnode_t *pn, const char *name, topo_instance_t imin,
    topo_instance_t imax, di_prom_handle_t promtree, topo_mod_t *mod)
{
	tnode_t *hb;
	did_t *iodid, *didp;
	did_hash_t *didhash;
	char *pname;
	int brc = 0;
	int bus;

	pname = topo_node_name(pn);
	if ((iodid = topo_node_private(pn)) == NULL) {
		topo_mod_dprintf(mod,
		    "Parent %s node missing private data.\n"
		    "Unable to proceed with %s enumeration.\n",
		    pname, name);
		return (-1);
	}
	didhash = did_hash(iodid);

	/*
	 * Find the hostbridge of interest
	 */
	didp = iodid;
	for (brc = 0; brc < imin; brc++)
		didp = did_chain_get(didp);
	assert(didp != NULL);

	if ((hb = pcihostbridge_declare(pn, did_dinode(didp), imin, didhash,
	    promtree, mod)) == NULL)
		return (-1);
	while (didp != NULL) {
		did_BDF(didp, &bus, NULL, NULL);
		if (topo_mod_enumerate(mod,
		    hb, PCI_BUS, PCI_BUS, bus, bus) != 0)
			return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
		didp = did_link_get(didp);
	}
	return (0);
}
