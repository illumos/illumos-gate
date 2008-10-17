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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
#include <stdlib.h>

/*
 * niu.c
 *	sun4v specific niu enumerators
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	NIU_VERSION	TOPO_VERSION
#define	NIUFN_MAX	2
#define	XAUI_MAX	1	/* max number of XAUIs per niufn */

static int niu_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
		    topo_instance_t, void *, void *);

static const topo_modops_t niu_ops =
	{ niu_enum, NULL };

const topo_modinfo_t niu_info =
	{NIU, FM_FMRI_SCHEME_HC, NIU_VERSION, &niu_ops};

static const topo_pgroup_info_t io_pgroup =
	{ TOPO_PGROUP_IO, TOPO_STABILITY_PRIVATE, TOPO_STABILITY_PRIVATE, 1 };

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
static int
devprop_set(tnode_t *tn, di_node_t dn,
	const char *tpgrp, const char *tpnm, topo_mod_t *mod)
{
	char *path;
	int err, e;

	if ((path = di_devfs_path(dn)) == NULL) {
		topo_mod_dprintf(mod, "NULL di_devfs_path.\n");
		return (topo_mod_seterrno(mod, ETOPO_PROP_NOENT));
	}
	e = topo_prop_set_string(tn, tpgrp, tpnm, TOPO_PROP_IMMUTABLE,
	    path, &err);
	di_devfs_path_free(path);
	if (e != 0)
		return (topo_mod_seterrno(mod, err));
	return (0);
}
/*ARGSUSED*/
static int
driverprop_set(tnode_t *tn, di_node_t dn,
	const char *tpgrp, const char *tpnm, topo_mod_t *mod)
{
	char *dnm;
	int err;

	if ((dnm = di_driver_name(dn)) == NULL)
		return (0);
	if (topo_prop_set_string(tn,
	    tpgrp, tpnm, TOPO_PROP_IMMUTABLE, dnm, &err) < 0)
		return (topo_mod_seterrno(mod, err));
	return (0);
}
/*ARGSUSED*/
static int
moduleprop_set(tnode_t *tn, di_node_t dn,
	const char *tpgrp, const char *tpnm, topo_mod_t *mod)
{
	nvlist_t *module;
	char *dnm;
	int err;

	if ((dnm = di_driver_name(dn)) == NULL)
		return (0);

	if ((module = topo_mod_modfmri(mod, FM_MOD_SCHEME_VERSION, dnm))
	    == NULL)
		return (0); /* driver maybe detached, return success */

	if (topo_prop_set_fmri(tn, tpgrp, tpnm, TOPO_PROP_IMMUTABLE, module,
	    &err) < 0) {
		nvlist_free(module);
		return (topo_mod_seterrno(mod, err));
	}
	nvlist_free(module);
	return (0);
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

	if (topo_pgroup_create(ntn, &io_pgroup, &err) == 0) {
		(void) devprop_set(ntn, priv, TOPO_PGROUP_IO, TOPO_IO_DEV, mod);
		(void) driverprop_set(ntn, priv, TOPO_PGROUP_IO, TOPO_IO_DRIVER,
		    mod);
		(void) moduleprop_set(ntn, priv, TOPO_PGROUP_IO, TOPO_IO_MODULE,
		    mod);
	}
	return (ntn);
}
static int
niu_asru_set(tnode_t *tn, di_node_t dn, topo_mod_t *mod)
{
	char *path;
	nvlist_t *fmri;
	int e;

	if ((path = di_devfs_path(dn)) != NULL) {
		fmri = topo_mod_devfmri(mod, FM_DEV_SCHEME_VERSION, path, NULL);
		if (fmri == NULL) {
			topo_mod_dprintf(mod,
			    "dev:///%s fmri creation failed.\n", path);
			di_devfs_path_free(path);
			return (-1);
		}
		di_devfs_path_free(path);
	} else {
		topo_mod_dprintf(mod, "NULL di_devfs_path.\n");
		if (topo_prop_get_fmri(tn, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_RESOURCE, &fmri, &e) < 0)
			return (topo_mod_seterrno(mod, e));
	}
	if (topo_node_asru_set(tn, fmri, 0, &e) < 0) {
		nvlist_free(fmri);
		return (topo_mod_seterrno(mod, e));
	}
	nvlist_free(fmri);
	return (0);
}

/*ARGSUSED*/
static tnode_t *
niu_declare(tnode_t *parent, const char *name, topo_instance_t i,
	void *priv, topo_mod_t *mod)
{
	tnode_t *ntn;
	int err;

	if ((ntn = niu_tnode_create(mod, parent, name, 0, priv)) == NULL) {
		topo_mod_dprintf(mod, "%s ntn = NULL\n", name);
		return (NULL);
	}

	/* inherit FRU from parent */
	(void) topo_node_fru_set(ntn, NULL, 0, &err);
	/* inherit parent's label */
	if (topo_node_label_set(ntn, NULL, &err) < 0) {
		topo_mod_dprintf(mod, "niu label error %d\n", err);
	}
	/* set ASRU */
	(void) niu_asru_set(ntn, priv, mod);

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

	/* set ASRU */
	(void) niu_asru_set(ntn, priv, mod);

	if (topo_node_range_create(mod, ntn, XAUI,
	    0, XAUI_MAX) < 0) {
		topo_node_unbind(ntn);
		topo_mod_dprintf(mod, "child_range_add of XAUI"
		    "failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		return (NULL); /* mod_errno already set */
	}
	return (ntn);
}

/*
 * Get the NIU/Neptune ethernet function number from the reg property
 */
static int
niufn_instance_get(topo_mod_t *mod, di_node_t node, topo_instance_t *inst)
{
	di_prom_handle_t phan;
	int rval, *intp;

	*inst = (topo_instance_t)0;
	rval = -1;
	if ((phan = topo_mod_prominfo(mod)) != DI_PROM_HANDLE_NIL) {
		rval = di_prom_prop_lookup_ints(phan, node,
		    DI_PROP_REG, &intp);
	}
	if (rval < 0) {
		rval = di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    DI_PROP_REG, &intp);
		if (rval < 0)
			return (-1);
	}
	*inst = (topo_instance_t)intp[0];

	return (0);
}

static int
niufn_instantiate(tnode_t *parent, const char *name, di_node_t pnode,
	topo_mod_t *mod)
{
	di_node_t sib;
	tnode_t *ntn;
	topo_instance_t inst;

	if (strcmp(name, NIUFN) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    NIUFN);
		return (0);
	}

	sib = di_child_node(pnode);
	while (sib != DI_NODE_NIL) {
		if (niufn_instance_get(mod, sib, &inst) != 0) {
			topo_mod_dprintf(mod, "Enumeration of %s "
			    "instance failed.\n", NIUFN);
			sib = di_sibling_node(sib);
			continue;
		}
		if ((ntn = niufn_declare(parent, NIUFN, inst, sib, mod))
		    == NULL) {
			topo_mod_dprintf(mod, "Enumeration of %s=%d "
			    "failed: %s\n", NIUFN, inst,
			    topo_strerror(topo_mod_errno(mod)));
			return (-1);
		}
		if (topo_mod_enumerate(mod,
		    ntn, XAUI, XAUI, inst, inst, sib) != 0) {
			return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
		}
		sib = di_sibling_node(sib);
	}
	return (0);
}

static topo_mod_t *
xaui_enum_load(topo_mod_t *mp)
{
	topo_mod_t *rp = NULL;

	if ((rp = topo_mod_load(mp, XAUI, TOPO_VERSION)) == NULL) {
		topo_mod_dprintf(mp,
		    "%s enumerator could not load %s enum.\n", NIU, XAUI);
	}
	return (rp);
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
	/*
	 * Load XAUI Enum
	 */
	if (xaui_enum_load(mod) == NULL)
		return (-1);

	dnode = di_drv_first_node("niumx", devtree);
	if (dnode != DI_NODE_NIL) {
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
