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
/*
 * xfp.c
 *	sun4v specific xfp enumerators
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	XFP_VERSION	TOPO_VERSION

static int xfp_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
		    topo_instance_t, void *, void *);

static const topo_modops_t xfp_ops =
	{ xfp_enum, NULL };

const topo_modinfo_t xfp_info =
	{XFP, FM_FMRI_SCHEME_HC, XFP_VERSION, &xfp_ops};

static const topo_pgroup_info_t xfp_auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOXFPDBG") != NULL)
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing xfp enumerator\n");

	if (topo_mod_register(mod, &xfp_info, TOPO_VERSION) < 0) {
		topo_mod_dprintf(mod, "xfp registration failed: %s\n",
		    topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}
	topo_mod_dprintf(mod, "xfp enum initd\n");
	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static tnode_t *
xfp_tnode_create(topo_mod_t *mod, tnode_t *parent,
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
		    "topo_node_bind (%s%" PRIu64 "/%s%" PRIu64 ") failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i, topo_strerror(topo_mod_errno(mod)));
		return (NULL);
	}

	topo_node_setspecific(ntn, priv);
	if (topo_pgroup_create(ntn, &xfp_auth_pgroup, &err) == 0) {
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
xfp_fru_set(topo_mod_t *mp, tnode_t *tn)
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
xfp_label_set(topo_mod_t *mod, tnode_t *parent, tnode_t *node,
    topo_instance_t n)
{
	char *label = NULL;
	char *plabel = NULL;
	const char *xfplabel = "/XFP";
	int err, len;

	if (topo_node_label(parent, &plabel, &err) != 0 ||
	    plabel == NULL) {
		return (-1);
	}

	len = strlen(plabel) + strlen(xfplabel) + 2;
	label = topo_mod_alloc(mod, len);
	(void) snprintf(label, len, "%s%s%d", plabel, xfplabel, n);
	topo_mod_strfree(mod, plabel);

	if (label != NULL) {
		if (topo_prop_set_string(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_LABEL, TOPO_PROP_IMMUTABLE, label,
		    &err) != 0) {
			topo_mod_strfree(mod, label);
			return (topo_mod_seterrno(mod, err));
		}
	}
	topo_mod_free(mod, label, len);
	return (0);
}
/*ARGSUSED*/
static tnode_t *
xfp_declare(tnode_t *parent, const char *name, topo_instance_t i,
    void *priv, topo_mod_t *mod)
{
	tnode_t *ntn;
	nvlist_t *fmri = NULL;
	int e;

	if ((ntn = xfp_tnode_create(mod, parent, name, i, NULL)) == NULL) {
		topo_mod_dprintf(mod, "%s ntn = NULL\n", name);
		return (NULL);
	}

	(void) xfp_fru_set(mod, ntn);

	(void) xfp_label_set(mod, parent, ntn, i);
	/* set ASRU to resource fmri */
	if (topo_prop_get_fmri(ntn, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_RESOURCE, &fmri, &e) == 0)
		(void) topo_node_asru_set(ntn, fmri, 0, &e);
	nvlist_free(fmri);

	return (ntn);
}

/*ARGSUSED*/
static int
xfp_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused, void *data)
{
	if (strcmp(name, XFP) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    XFP);
		return (0);
	}
	if (xfp_declare(rnode, name, min, data, mod) == NULL)
		return (-1);

	return (0);
}
