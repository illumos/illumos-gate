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

#include <string.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <limits.h>
#include <sys/fm/protocol.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <assert.h>

#include <hostbridge.h>
#include <pcibus.h>
#include <did.h>
#include <did_props.h>
#include <util.h>

/*
 * hostbridge.c
 *	Generic code shared by all the hostbridge enumerators
 */
static void hb_release(topo_mod_t *, tnode_t *);
static int hb_label(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hb_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);

extern int platform_hb_label(topo_mod_t *, tnode_t *, nvlist_t *, nvlist_t **);
extern int platform_hb_enum(topo_mod_t *, tnode_t *,
    const char *, topo_instance_t, topo_instance_t);

extern txprop_t ExHB_common_props[];
extern txprop_t HB_common_props[];
extern txprop_t RC_common_props[];
extern int ExHB_propcnt;
extern int HB_propcnt;
extern int RC_propcnt;

static int specific_hb_enum(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t, void *);

static const topo_modops_t Hb_ops =
	{ hb_enum, hb_release };
static const topo_modinfo_t Hb_info =
	{ HOSTBRIDGE, FM_FMRI_SCHEME_HC, HB_ENUMR_VERS, &Hb_ops };

static const topo_method_t Hb_methods[] = {
	{ TOPO_METH_LABEL, TOPO_METH_LABEL_DESC,
	    TOPO_METH_LABEL_VERSION, TOPO_STABILITY_INTERNAL, hb_label },
	{ NULL }
};

static const topo_pgroup_info_t hb_auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

int
_topo_init(topo_mod_t *modhdl, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOHBDBG") != NULL)
		topo_mod_setdebug(modhdl);
	topo_mod_dprintf(modhdl, "initializing hostbridge enumerator\n");

	if (version != HB_ENUMR_VERS)
		return (topo_mod_seterrno(modhdl, EMOD_VER_NEW));

	if (topo_mod_register(modhdl, &Hb_info, TOPO_VERSION) < 0) {
		topo_mod_dprintf(modhdl, "hostbridge registration failed: %s\n",
		    topo_mod_errmsg(modhdl));
		return (-1); /* mod errno already set */
	}

	topo_mod_dprintf(modhdl, "Hostbridge enumr initd\n");

	return (0);
}

void
_topo_fini(topo_mod_t *modhdl)
{
	topo_mod_unregister(modhdl);
}

static int
hb_label(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_LABEL_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));
	return (platform_hb_label(mp, node, in, out));
}

static topo_mod_t *
pci_enumr_load(topo_mod_t *mp)
{
	topo_mod_t *rp = NULL;

	if ((rp = topo_mod_load(mp, PCI_ENUM, PCI_ENUMR_VERS)) == NULL) {
		topo_mod_dprintf(mp,
		    "%s enumerator could not load %s.\n", HOSTBRIDGE, PCI_ENUM);
	}
	return (rp);
}

/*ARGSUSED*/
static int
hb_enum(topo_mod_t *mp, tnode_t *pn, const char *name, topo_instance_t imin,
    topo_instance_t imax, void *notused, void *data)
{
	int rv;
	topo_mod_t *pcimod;

	if (strcmp(name, HOSTBRIDGE) != 0) {
		topo_mod_dprintf(mp,
		    "Currently only know how to enumerate %s components.\n",
		    HOSTBRIDGE);
		return (0);
	}
	/*
	 * Load the pcibus enumerator
	 */
	if ((pcimod = pci_enumr_load(mp)) == NULL)
		return (-1);

	/*
	 * If we're asked to enumerate a whole range of hostbridges, then
	 * we need to find them all.  If we're just asked to enumerate a
	 * single hostbridge, we expect our caller to have passed us linked
	 * did_t structures we can use to enumerate the singled out hostbridge.
	 */
	if (imin != imax) {

		if (did_hash_init(mp) < 0) {
			topo_mod_dprintf(mp,
			    "Hash initialization for hostbridge "
			    "enumerator failed.\n");
			topo_mod_unload(pcimod);
			return (-1);
		}
		rv = platform_hb_enum(mp, pn, name, imin, imax);
		did_hash_fini(mp);
	} else {
		rv = specific_hb_enum(mp, pn, name, imin, imax, data);
	}

	return (rv);
}

/*ARGSUSED*/
static void
hb_release(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);
}

static tnode_t *
hb_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, void *priv)
{
	int err;
	nvlist_t *fmri;
	tnode_t *ntn;
	nvlist_t *auth = topo_mod_auth(mod, parent);

	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name, i,
	    NULL, auth, NULL, NULL, NULL);
	nvlist_free(auth);
	if (fmri == NULL) {
		topo_mod_dprintf(mod,
		    "Unable to make nvlist for %s bind: %s.\n",
		    name, topo_mod_errmsg(mod));
		return (NULL);
	}

	ntn = topo_node_bind(mod, parent, name, i, fmri);
	if (ntn == NULL) {
		topo_mod_dprintf(mod,
		    "topo_node_bind (%s%" PRIu64 "/%s%" PRIu64 ") failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);
	topo_node_setspecific(ntn, priv);

	if (topo_pgroup_create(ntn, &hb_auth_pgroup, &err) == 0) {
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT_SN, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &err);
	}

	if (topo_method_register(mod, ntn, Hb_methods) < 0) {
		topo_mod_dprintf(mod, "topo_method_register failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(ntn);
		return (NULL);
	}
	return (ntn);
}

tnode_t *
pcihostbridge_declare(topo_mod_t *mod, tnode_t *parent, di_node_t din,
    topo_instance_t i)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(mod, din)) == NULL)
		return (NULL);
	if ((ntn = hb_tnode_create(mod, parent, HOSTBRIDGE, i, din)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, HB_common_props, HB_propcnt) < 0) {
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
pciexhostbridge_declare(topo_mod_t *mod, tnode_t *parent, di_node_t din,
    topo_instance_t hi)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(mod, din)) == NULL)
		return (NULL);
	if ((ntn = hb_tnode_create(mod, parent, HOSTBRIDGE, hi, din)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, ExHB_common_props, ExHB_propcnt) < 0) {
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
pciexrc_declare(topo_mod_t *mod, tnode_t *parent, di_node_t din,
    topo_instance_t ri)
{
	did_t *pd;
	tnode_t *ntn;

	if ((pd = did_find(mod, din)) == NULL)
		return (NULL);
	did_markrc(pd);
	if ((ntn = hb_tnode_create(mod, parent, PCIEX_ROOT, ri, din)) == NULL)
		return (NULL);
	if (did_props_set(ntn, pd, RC_common_props, RC_propcnt) < 0) {
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
specific_hb_enum(topo_mod_t *mod, tnode_t *pn, const char *name,
    topo_instance_t imin, topo_instance_t imax, void *priv)
{
	tnode_t *hb;
	did_t *iodid = (did_t *)priv;
	did_t *didp;
	int brc = 0;
	int bus;

	did_setspecific(mod, priv);

	/*
	 * Find the hostbridge of interest
	 */
	didp = iodid;
	for (brc = 0; brc < imin; brc++)
		didp = did_chain_get(didp);
	assert(didp != NULL);

	if ((hb = pcihostbridge_declare(mod, pn, did_dinode(didp), imin))
	    == NULL) {
		return (-1);
	}
	while (didp != NULL) {
		did_BDF(didp, &bus, NULL, NULL);
		if (topo_mod_enumerate(mod,
		    hb, PCI_BUS, PCI_BUS, bus, bus, didp) != 0) {
			return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
		}
		didp = did_link_get(didp);
	}

	return (0);
}
