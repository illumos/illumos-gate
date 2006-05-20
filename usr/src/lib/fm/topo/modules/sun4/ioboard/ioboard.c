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
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <libdevinfo.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/systeminfo.h>

#include "hostbridge.h"
#include "ioboard.h"
#include "did.h"
#include "did_props.h"
#include "util.h"

/*
 * ioboard.c
 *	Generic code shared by all the ioboard enumerators
 */
static void iob_release(topo_mod_t *, tnode_t *);
static int iob_contains(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int iob_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int iob_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *);
static int iob_label(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

extern txprop_t IOB_common_props[];
extern int IOB_propcnt;

const topo_modinfo_t Iob_info =
	{ IOBOARD, IOB_ENUMR_VERS, iob_enum, iob_release };

const topo_method_t Iob_methods[] = {
	{ "iob_contains", "ioboard element contains other element",
	    IOB_ENUMR_VERS, TOPO_STABILITY_INTERNAL, iob_contains },
	{ "iob_present", "ioboard element currently present",
	    IOB_ENUMR_VERS, TOPO_STABILITY_INTERNAL, iob_present },
	{ TOPO_METH_LABEL, TOPO_METH_LABEL_DESC,
	    TOPO_METH_LABEL_VERSION, TOPO_STABILITY_INTERNAL, iob_label },
	{ NULL }
};

void
_topo_init(topo_mod_t *modhdl)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOIOBDBG") != NULL)
		topo_mod_setdebug(modhdl, TOPO_DBG_ALL);
	topo_mod_dprintf(modhdl, "initializing ioboard enumerator\n");

	topo_mod_register(modhdl, &Iob_info, NULL);
	topo_mod_dprintf(modhdl, "Ioboard enumr initd\n");
}

void
_topo_fini(topo_mod_t *modhdl)
{
	topo_mod_unregister(modhdl);
}

/*ARGSUSED*/
static int
iob_contains(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (0);
}

/*ARGSUSED*/
static int
iob_present(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (0);
}

static int
iob_label(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_LABEL_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));
	return (platform_iob_label(node, in, out, mp));
}

static topo_mod_t *
hb_enumr_load(topo_mod_t *mp, tnode_t *parent)
{
	topo_mod_t *rp = NULL;
	char *plat, *mach;
	char *hbpath;
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
	hbpath = topo_mod_alloc(mp, PATH_MAX);
	rootdir = topo_mod_rootdir(mp);
	(void) snprintf(hbpath,
	    PATH_MAX, PATH_TO_HB_ENUM, rootdir ? rootdir : "", plat);

	if ((rp = topo_mod_load(mp, hbpath)) == NULL) {
		topo_mod_dprintf(mp,
		    "%s enumerator could not load %s.\n", IOBOARD, hbpath);
		(void) snprintf(hbpath,
		    PATH_MAX, PATH_TO_HB_ENUM, rootdir ? rootdir : "", mach);
		if ((rp = topo_mod_load(mp, hbpath)) == NULL) {
			topo_mod_dprintf(mp,
			    "%s enumerator could not load %s.\n",
			    IOBOARD, hbpath);
		}
	}
	topo_mod_strfree(mp, plat);
	topo_mod_strfree(mp, mach);
	topo_mod_free(mp, hbpath, PATH_MAX);
	return (rp);
}

/*ARGSUSED*/
static int
iob_enum(topo_mod_t *mp, tnode_t *pn, const char *name, topo_instance_t imin,
    topo_instance_t imax, void *notused)
{
	topo_mod_t *hbmod;
	int rv;
	did_hash_t *didhash;
	di_prom_handle_t promtree;

	if (strcmp(name, IOBOARD) != 0) {
		topo_mod_dprintf(mp,
		    "Currently only know how to enumerate %s components.\n",
		    IOBOARD);
		return (0);
	}

	if ((promtree = di_prom_init()) == DI_PROM_HANDLE_NIL) {
		topo_mod_dprintf(mp,
		    "Ioboard enumerator: di_prom_handle_init failed.\n");
		return (-1);
	}

	/*
	 * Load the hostbridge enumerator, we'll soon need it!
	 */
	if ((hbmod = hb_enumr_load(mp, pn)) == NULL) {
		di_prom_fini(promtree);
		return (-1);
	}

	if ((didhash = did_hash_init(mp)) == NULL) {
		topo_mod_dprintf(mp,
		    "Hash initialization for ioboard enumerator failed.\n");
		di_prom_fini(promtree);
		topo_mod_unload(hbmod);
		return (-1);
	}

	rv = platform_iob_enum(pn, imin, imax, didhash, promtree, mp);

	did_hash_fini(didhash);
	di_prom_fini(promtree);
	topo_mod_unload(hbmod);

	if (rv < 0)
		return (topo_mod_seterrno(mp, EMOD_PARTIAL_ENUM));
	else
		return (0);
}

/*ARGSUSED*/
static void
iob_release(topo_mod_t *mp, tnode_t *node)
{

	/*
	 * node private data (did_t) for this node is destroyed in
	 * did_hash_destroy()
	 */

	topo_method_unregister_all(mp, node);
}

static tnode_t *
iob_tnode_create(tnode_t *parent,
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
		topo_mod_dprintf(mod,
		    "Unable to make nvlist for %s bind.\n", name);
		return (NULL);
	}
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
	if (topo_method_register(mod, ntn, Iob_methods) < 0) {
		topo_mod_dprintf(mod, "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
ioboard_declare(tnode_t *parent, topo_instance_t i, void *priv,
    di_prom_handle_t promtree, topo_mod_t *mod)
{
	tnode_t *ntn;

	if ((ntn = iob_tnode_create(parent, IOBOARD, i, priv, mod)) == NULL)
		return (NULL);
	if (did_props_set(ntn, priv, IOB_common_props, IOB_propcnt,
	    promtree) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	/*
	 * We expect to find host bridges beneath the ioboard.
	 */
	if (child_range_add(mod, ntn, HOSTBRIDGE, 0, MAX_HBS) < 0) {
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

did_t *
split_bus_address(did_hash_t *dhash, di_node_t dp, uint_t baseaddr,
    uint_t bussep, int minbrd, int maxbrd, int *brd, int *br, int *bus,
    di_prom_handle_t promtree, topo_mod_t *mod)
{
	uint_t bc, ac;
	char *comma;
	char *bac;
	char *ba;
	int e;

	if ((ba = di_bus_addr(dp)) == NULL ||
	    (bac = topo_mod_strdup(mod, ba)) == NULL)
		return (NULL);

	topo_mod_dprintf(mod,
	    "Transcribing %s into board, bus, etc.\n", bac);

	if ((comma = strchr(bac, ',')) == NULL) {
		topo_mod_strfree(mod, bac);
		return (NULL);
	}
	*comma = '\0';
	bc = strtonum(mod, bac, &e);
	*comma = ',';
	if (e < 0) {
		topo_mod_dprintf(mod,
		    "Trouble interpreting %s before comma.\n", bac);
		topo_mod_strfree(mod, bac);
		return (NULL);
	}
	ac = strtonum(mod, comma + 1, &e);
	if (e < 0) {
		topo_mod_dprintf(mod,
		    "Trouble interpreting %s after comma.\n", bac);
		topo_mod_strfree(mod, bac);
		return (NULL);
	}
	topo_mod_strfree(mod, bac);

	*brd = ((bc - baseaddr) / bussep) + minbrd;
	*br = (bc - baseaddr) % bussep;
	*bus = ((ac == IOB_BUSADDR1) ? 0 : 1);
	if (*brd < minbrd || *brd > maxbrd || (*br != 0 && *br != 1) ||
	    (ac != IOB_BUSADDR1 && ac != IOB_BUSADDR2)) {
		topo_mod_dprintf(mod, "Trouble with transcription\n");
		topo_mod_dprintf(mod, "brd=%d br=%d bus=%d bc=%x ac=%x\n",
		    *brd, *br, *bus, bc, ac);
		return (NULL);
	}
	return (did_create(dhash, dp, *brd, *br, NO_RC, *bus, promtree));
}
