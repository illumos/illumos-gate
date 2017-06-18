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

#include <string.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/systeminfo.h>

#include <hostbridge.h>
#include <ioboard.h>
#include <did.h>
#include <did_props.h>
#include <util.h>

/*
 * ioboard.c
 *	Generic code shared by all the ioboard enumerators
 */

static void iob_release(topo_mod_t *, tnode_t *);
static int iob_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static int iob_label(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);

extern int platform_iob_enum(topo_mod_t *, tnode_t *, topo_instance_t,
    topo_instance_t);
extern int platform_iob_label(topo_mod_t *, tnode_t *, nvlist_t *, nvlist_t **);

extern txprop_t IOB_common_props[];
extern int IOB_propcnt;

static const topo_modops_t Iob_ops =
	{ iob_enum, iob_release };
static const topo_modinfo_t Iob_info =
	{ IOBOARD, FM_FMRI_SCHEME_HC, IOB_ENUMR_VERS, &Iob_ops };

static const topo_method_t Iob_methods[] = {
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
		topo_mod_setdebug(modhdl);
	topo_mod_dprintf(modhdl, "initializing ioboard enumerator\n");

	(void) topo_mod_register(modhdl, &Iob_info, TOPO_VERSION);

	topo_mod_dprintf(modhdl, "Ioboard enumr initd\n");
}

void
_topo_fini(topo_mod_t *modhdl)
{
	topo_mod_unregister(modhdl);
}

static int
iob_label(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_LABEL_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));
	return (platform_iob_label(mp, node, in, out));
}

static topo_mod_t *
hb_enumr_load(topo_mod_t *mp)
{
	topo_mod_t *rp = NULL;

	if ((rp = topo_mod_load(mp, HOSTBRIDGE, HB_ENUMR_VERS)) == NULL) {
		topo_mod_dprintf(mp,
		    "%s enumerator could not load %s.\n", IOBOARD, HOSTBRIDGE);
	}
	return (rp);
}

/*ARGSUSED*/
static int
iob_enum(topo_mod_t *mp, tnode_t *pn, const char *name, topo_instance_t imin,
    topo_instance_t imax, void *notused1, void *notused2)
{
	topo_mod_t *hbmod;
	int rv;

	if (strcmp(name, IOBOARD) != 0) {
		topo_mod_dprintf(mp,
		    "Currently only know how to enumerate %s components.\n",
		    IOBOARD);
		return (0);
	}
	/*
	 * Load the hostbridge enumerator, we'll soon need it!
	 */
	if ((hbmod = hb_enumr_load(mp)) == NULL) {
		return (-1);
	}

	if (did_hash_init(mp) != 0)
		return (-1);

	rv = platform_iob_enum(mp, pn, imin, imax);

	did_hash_fini(mp);
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
iob_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, void *priv)
{
	nvlist_t *fmri;
	tnode_t *ntn;
	nvlist_t *auth = topo_mod_auth(mod, parent);

	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name, i,
	    NULL, auth, NULL, NULL, NULL);
	nvlist_free(auth);
	if (fmri == NULL) {
		topo_mod_dprintf(mod,
		    "Unable to make nvlist for %s bind.\n", name);
		return (NULL);
	}
	ntn = topo_node_bind(mod, parent, name, i, fmri);
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
	topo_node_setspecific(ntn, priv);

	if (topo_method_register(mod, ntn, Iob_methods) < 0) {
		topo_mod_dprintf(mod, "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
ioboard_declare(topo_mod_t *mod, tnode_t *parent, topo_instance_t i, void *priv)
{
	tnode_t *ntn;

	if ((ntn = iob_tnode_create(mod, parent, IOBOARD, i, priv)) == NULL)
		return (NULL);
	if (did_props_set(ntn, priv, IOB_common_props, IOB_propcnt) < 0) {
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
split_bus_address(topo_mod_t *mod, di_node_t dp, uint_t baseaddr,
    uint_t bussep, int minbrd, int maxbrd, int *brd, int *br, int *bus)
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
	bc = fm_strtonum(mod, bac, &e);
	*comma = ',';
	if (e < 0) {
		topo_mod_dprintf(mod,
		    "Trouble interpreting %s before comma.\n", bac);
		topo_mod_strfree(mod, bac);
		return (NULL);
	}
	ac = fm_strtonum(mod, comma + 1, &e);
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
	return (did_create(mod, dp, *brd, *br, NO_RC, *bus));
}
