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
#include <sys/fm/protocol.h>
#include "xaui.h"

/*
 * xaui.c
 *	sun4v specific xaui enumerators
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	XAUI_VERSION	TOPO_VERSION
#define	XFP_MAX	1	/* max number of xfp per xaui card */

static int xaui_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
		    topo_instance_t, void *, void *);

static const topo_modops_t xaui_ops =
	{ xaui_enum, NULL };

const topo_modinfo_t xaui_info =
	{XAUI, FM_FMRI_SCHEME_HC, XAUI_VERSION, &xaui_ops};

static const topo_pgroup_info_t xaui_auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

/*ARGSUSED*/
void
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOXAUIDBG") != NULL)
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing xaui enumerator\n");

	if (topo_mod_register(mod, &xaui_info, TOPO_VERSION) < 0) {
		topo_mod_dprintf(mod, "xaui registration failed: %s\n",
		    topo_mod_errmsg(mod));
		return; /* mod errno already set */
	}
	topo_mod_dprintf(mod, "xaui enum initd\n");
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static tnode_t *
xaui_tnode_create(topo_mod_t *mod, tnode_t *parent,
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
	nvlist_free(fmri);
	if (ntn == NULL) {
		topo_mod_dprintf(mod,
		    "topo_node_bind (%s%d/%s%d) failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mod)));
		return (NULL);
	}

	topo_node_setspecific(ntn, priv);
	if (topo_pgroup_create(ntn, &xaui_auth_pgroup, &err) == 0) {
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT_SN, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &err);
	}
	return (ntn);
}


static int
xaui_fru_set(topo_mod_t *mp, tnode_t *tn)
{
	nvlist_t *fmri;
	int err, e;

	if (topo_node_resource(tn, &fmri, &err) < 0 ||
	    fmri == NULL) {
		topo_mod_dprintf(mp, "FRU_fmri_set error: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		return (topo_mod_seterrno(mp, err));
	}
	e = topo_node_fru_set(tn, fmri, 0, &err);
	nvlist_free(fmri);
	if (e < 0)
		return (topo_mod_seterrno(mp, err));
	return (0);
}

static int
xaui_label_set(topo_mod_t *mod, tnode_t *node, topo_instance_t n)
{
	const char *label = NULL;
	char *plat, *pp;
	int err;
	int i, p;

	if (Phyxaui_Names == NULL)
		return (-1);

	if (topo_prop_get_string(node,
	    FM_FMRI_AUTHORITY, FM_FMRI_AUTH_PRODUCT, &plat, &err) < 0) {
		return (topo_mod_seterrno(mod, err));
	}
	/*
	 * Trim SUNW, from the platform name
	 */
	pp = strchr(plat, ',');
	if (pp == NULL)
		pp = plat;
	else
		++pp;

	for (p = 0; p < Phyxaui_Names->psn_nplats; p++) {
		if (strcmp(Phyxaui_Names->psn_names[p].pnm_platform,
		    pp) != 0)
			continue;
		for (i = 0; i < Phyxaui_Names->psn_names[p].pnm_nnames; i++) {
			physnm_t ps;
			ps = Phyxaui_Names->psn_names[p].pnm_names[i];
			if (ps.ps_num == n) {
				label = ps.ps_label;
				break;
			}
		}
		break;
	}
	topo_mod_strfree(mod, plat);

	if (label != NULL) {
		if (topo_prop_set_string(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_LABEL, TOPO_PROP_IMMUTABLE,
		    label, &err) != 0) {
			return (topo_mod_seterrno(mod, err));
		}
	}
	return (0);
}
/*ARGSUSED*/
static tnode_t *
xaui_declare(tnode_t *parent, const char *name, topo_instance_t i,
	void *priv, topo_mod_t *mod)
{
	tnode_t *ntn;
	nvlist_t *fmri = NULL;
	int e;

	if ((ntn = xaui_tnode_create(mod, parent, name, i, NULL)) == NULL) {
		topo_mod_dprintf(mod, "%s ntn = NULL\n", name);
		return (NULL);
	}

	(void) xaui_fru_set(mod, ntn);

	(void) xaui_label_set(mod, ntn, i);

	/* set ASRU to resource fmri */
	if (topo_prop_get_fmri(ntn, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_RESOURCE, &fmri, &e) == 0)
		(void) topo_node_asru_set(ntn, fmri, 0, &e);
	nvlist_free(fmri);

	if (topo_node_range_create(mod, ntn, XFP,
	    0, XFP_MAX) < 0) {
		topo_node_unbind(ntn);
		topo_mod_dprintf(mod, "child_range_add of XFP"
		    "failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		return (NULL); /* mod_errno already set */
	}
	return (ntn);
}

static topo_mod_t *
xfp_enum_load(topo_mod_t *mp)
{
	topo_mod_t *rp = NULL;

	if ((rp = topo_mod_load(mp, XFP, TOPO_VERSION)) == NULL) {
		topo_mod_dprintf(mp,
		    "%s enumerator could not load %s enum.\n", XAUI, XFP);
	}
	return (rp);
}
/*ARGSUSED*/
static int
xaui_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
	topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	tnode_t *xauin;

	if (strcmp(name, XAUI) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    XAUI);
		return (0);
	}
	/*
	 * Load XFP enum
	 */
	if (xfp_enum_load(mod) == NULL)
		return (-1);

	if ((xauin = xaui_declare(rnode, name, min, arg, mod)) == NULL)
		return (-1);

	/* set the private data to be the instance number of niufn */
	if (topo_mod_enumerate(mod,
	    xauin, XFP, XFP, 0, 0, NULL) != 0) {
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}
	return (0);
}
