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
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <limits.h>
#include <sys/fm/protocol.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <assert.h>

/*
 * zambezi.c
 *	sun4v specific zambezi enumerators
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	ZAMBEZI_VERSION	TOPO_VERSION
#define	ZAMBEZI_MAX	4

static int zambezi_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
		    topo_instance_t, void *, void *);

static const topo_modops_t zambezi_ops =
	{ zambezi_enum, NULL };

const topo_modinfo_t zambezi_info =
	{INTERCONNECT, FM_FMRI_SCHEME_HC, ZAMBEZI_VERSION, &zambezi_ops};

static const topo_pgroup_info_t zambezi_auth_pgroup = {
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
	if (getenv("TOPOZAMDBG") != NULL)
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing zambezi enumerator\n");

	if (topo_mod_register(mod, &zambezi_info, TOPO_VERSION) < 0) {
		topo_mod_dprintf(mod, "zambezi registration failed: %s\n",
		    topo_mod_errmsg(mod));
		return; /* mod errno already set */
	}
	topo_mod_dprintf(mod, "zambezi enumr initd\n");
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static tnode_t *
zam_tnode_create(topo_mod_t *mod, tnode_t *parent,
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
	if (topo_pgroup_create(ntn, &zambezi_auth_pgroup, &err) == 0) {
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &err);
	}
	return (ntn);
}

/*ARGSUSED*/
static tnode_t *
zam_declare(tnode_t *parent, const char *name, topo_instance_t i,
	void *priv, topo_mod_t *mod)
{
	tnode_t *ntn;
	nvlist_t *fmri = NULL;
	int err;

	if ((ntn = zam_tnode_create(mod, parent, name, i, NULL)) == NULL) {
		topo_mod_dprintf(mod, "%s ntn = NULL\n", name);
		return (NULL);
	}
	/* inherit FRU from parent */
	(void) topo_node_fru_set(ntn, NULL, 0, &err);

	/* inherit parent's label */
	if (topo_node_label_set(ntn, NULL, &err) < 0) {
		topo_mod_dprintf(mod, "cpuboard label error %d\n", err);
	}

	/* set ASRU to resource fmri */
	if (topo_prop_get_fmri(ntn, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_RESOURCE, &fmri, &err) == 0)
		(void) topo_node_asru_set(ntn, fmri, 0, &err);
	nvlist_free(fmri);

	return (ntn);
}

/*ARGSUSED*/
static int
zambezi_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
	topo_instance_t min, topo_instance_t max, void *notused, void *data)
{
	int i;

	if (strcmp(name, INTERCONNECT) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    INTERCONNECT);
		return (0);
	}

	if (max >= ZAMBEZI_MAX)
		max = ZAMBEZI_MAX;

	for (i = 0; i <= max; i++) {
		if (zam_declare(rnode, name, i, data, mod) == NULL)
			return (-1);
	}

	return (0);
}
