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
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <limits.h>
#include <sys/fm/protocol.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <assert.h>

/*
 * niu.c
 *	sun4v specific niu enumerators
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	NIU_VERSION	TOPO_VERSION
#define	NIUFN_MAX	2

static int niu_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
		    topo_instance_t, void *, void *);

static const topo_modops_t niu_ops =
	{ niu_enum, NULL };

const topo_modinfo_t niu_info =
	{NIU, FM_FMRI_SCHEME_HC, NIU_VERSION, &niu_ops};

static const topo_pgroup_info_t niu_auth_pgroup = {
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
	if (getenv("TOPONIUDBG") != NULL)
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing niu enumerator\n");

	if (topo_mod_register(mod, &niu_info, TOPO_VERSION) < 0) {
		topo_mod_dprintf(mod, "niu registration failed: %s\n",
			topo_mod_errmsg(mod));
		return; /* mod errno already set */
	}
	topo_mod_dprintf(mod, "NIU enumr initd\n");
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static tnode_t *
niu_tnode_create(topo_mod_t *mod, tnode_t *parent,
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
		    "topo_node_bind (%s%d/%s%d) failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);
	topo_node_setspecific(ntn, priv);

	if (topo_pgroup_create(ntn, &niu_auth_pgroup, &err) == 0) {
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
niu_declare(tnode_t *parent, const char *name, topo_instance_t i,
	void *priv, topo_mod_t *mod)
{
	tnode_t *ntn;
	int err;

	if ((ntn = niu_tnode_create(mod, parent, name, 0, NULL)) == NULL) {
		topo_mod_dprintf(mod, "%s ntn = NULL\n", name);
		return (NULL);
	}

	/* inherit FRU from parent */
	(void) topo_node_fru_set(ntn, NULL, 0, &err);
	/* inherit parent's label */
	if (topo_node_label_set(ntn, NULL, &err) < 0) {
		topo_mod_dprintf(mod, "niu label error %d\n", err);
	}
	return (ntn);
}

/*ARGSUSED*/
static tnode_t *
niufn_declare(tnode_t *parent, const char *name, topo_instance_t i,
	void *priv, topo_mod_t *mod)
{
	tnode_t *ntn;
	int err;

	if ((ntn = niu_tnode_create(mod, parent, name, i, priv)) == NULL)
		return (NULL);

	/* inherit FRU from parent */
	(void) topo_node_fru_set(ntn, NULL, 0, &err);
	/* inherit parent's label */
	(void) topo_node_label_set(ntn, NULL, &err);

	return (ntn);
}

static int
niufn_instantiate(tnode_t *parent, const char *name, di_node_t pnode,
	topo_mod_t *mod)
{
	di_node_t sib;
	int i = 0;

	if (strcmp(name, NIUFN) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
			NIUFN);
		return (0);
	}

	sib = di_child_node(pnode);
	while (sib != DI_NODE_NIL) {
		topo_mod_dprintf(mod, "Found NIUFN node %d\n", i);
		if (niufn_declare(parent, NIUFN, i, sib, mod) == NULL) {
			topo_mod_dprintf(mod, "Enumeration of %s=%d "
				"failed: %s\n", NIUFN, i,
				topo_strerror(topo_mod_errno(mod)));
			return (-1);
		}
		sib = di_sibling_node(sib);
		i++;
	}
	return (0);
}

/*ARGSUSED*/
static int
niu_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
	topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	tnode_t *niun;
	di_node_t devtree;
	di_node_t dnode;

	if (strcmp(name, NIU) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    NIU);
		return (0);
	}

	if ((devtree = topo_mod_devinfo(mod)) == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed.");
		return (-1);
	}
	dnode = di_drv_first_node("niumx", devtree);
	if (dnode != DI_NODE_NIL) {
		topo_mod_dprintf(mod, "Found NIU node.\n");
		niun = niu_declare(rnode, name, 0, dnode, mod);
		if (niun == NULL) {
			topo_mod_dprintf(mod, "Enumeration of niu failed: %s\n",
				topo_strerror(topo_mod_errno(mod)));
			return (-1); /* mod_errno already set */
		}
		if (topo_node_range_create(mod, niun, NIUFN,
			0, NIUFN_MAX) < 0) {
			topo_node_unbind(niun);
			topo_mod_dprintf(mod, "child_range_add of NIUFN"
				"failed: %s\n",
				topo_strerror(topo_mod_errno(mod)));
			return (-1); /* mod_errno already set */
		}
		if (niufn_instantiate(niun, NIUFN, dnode, mod) < 0) {
			topo_mod_dprintf(mod, "Enumeration of niufn "
				"failed %s\n",
				topo_strerror(topo_mod_errno(mod)));
		}
	}
	if (di_drv_next_node(dnode) != DI_NODE_NIL)
		topo_mod_dprintf(mod,
			"Currently only know how to enumerate one niu "
			"components.\n");

	return (0);
}
