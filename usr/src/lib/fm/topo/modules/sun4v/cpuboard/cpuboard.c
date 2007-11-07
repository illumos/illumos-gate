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

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <libdevinfo.h>
#include <limits.h>
#include <sys/fm/protocol.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <assert.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <fm/fmd_fmri.h>
#include <sys/types.h>
#include <sys/mdesc.h>
#include <sys/fm/ldom.h>

#include "cpuboard_topo.h"

/*
 * cpuboard.c
 *	sun4v specific cpuboard enumerator
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	CPUBOARD_VERSION	TOPO_VERSION

/* Until future PRI changes, make connection between cpuboard id and RC */
char *cpub_rcs[] = { CPUBOARD0_RC, CPUBOARD1_RC, CPUBOARD2_RC, CPUBOARD3_RC };

static int cpuboard_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
		    topo_instance_t, void *, void *);

static const topo_modops_t cpuboard_ops =
	{ cpuboard_enum, NULL };

const topo_modinfo_t cpuboard_info =
	{CPUBOARD, FM_FMRI_SCHEME_HC, CPUBOARD_VERSION, &cpuboard_ops};

static const topo_pgroup_info_t cpuboard_auth_pgroup =
	{ FM_FMRI_AUTHORITY, TOPO_STABILITY_PRIVATE,
	    TOPO_STABILITY_PRIVATE, 1 };

static topo_mod_t *cpuboard_mod_hdl = NULL;

static void *
cpuboard_topo_alloc(size_t size)
{
	assert(cpuboard_mod_hdl != NULL);
	return (topo_mod_alloc(cpuboard_mod_hdl, size));
}

static void
cpuboard_topo_free(void *data, size_t size)
{
	assert(cpuboard_mod_hdl != NULL);
	topo_mod_free(cpuboard_mod_hdl, data, size);
}

static int
cpuboard_get_pri_info(topo_mod_t *mod, cpuboard_contents_t cpubs[])
{
	char isa[MAXNAMELEN];
	md_t *mdp;
	mde_cookie_t *listp;
	uint64_t *bufp;
	ssize_t bufsize = 0;
	int  ncomp, num_nodes, i, len;
	char *pstr = NULL;
	char *sn = NULL, *pn = NULL;
	char *dn = NULL;
	ldom_hdl_t *lhp;
	uint64_t id;

	lhp = ldom_init(cpuboard_topo_alloc, cpuboard_topo_free);
	if (lhp == NULL) {
		topo_mod_dprintf(mod, "ldom_init failed\n");
		return (-1);
	}

	(void) sysinfo(SI_MACHINE, isa, MAXNAMELEN);
	if (strcmp(isa, "sun4v") != 0) {
		topo_mod_dprintf(mod, "not sun4v architecture%s\n", isa);
		ldom_fini(lhp);
		return (-1);
	}

	if ((bufsize = ldom_get_core_md(lhp, &bufp)) < 1) {
		topo_mod_dprintf(mod, "ldom_get_core_md error, bufsize=%d\n",
		    bufsize);
		ldom_fini(lhp);
		return (-1);
	}
	topo_mod_dprintf(mod, "pri bufsize=%d\n", bufsize);

	if ((mdp = md_init_intern(bufp, cpuboard_topo_alloc,
	    cpuboard_topo_free)) == NULL ||
	    (num_nodes = md_node_count(mdp)) < 1) {
		topo_mod_dprintf(mod, "md_init_intern error\n");
		cpuboard_topo_free(bufp, (size_t)bufsize);
		ldom_fini(lhp);
		return (-1);
	}
	topo_mod_dprintf(mod, "num_nodes=%d\n", num_nodes);

	if ((listp = (mde_cookie_t *)cpuboard_topo_alloc(
	    sizeof (mde_cookie_t) * num_nodes)) == NULL) {
		topo_mod_dprintf(mod, "alloc listp error\n");
		cpuboard_topo_free(bufp, (size_t)bufsize);
		(void) md_fini(mdp);
		ldom_fini(lhp);
		return (-1);
	}
	ncomp = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"), listp);
	topo_mod_dprintf(mod, "ncomp=%d\n", ncomp);
	if (ncomp <= 0) {
		cpuboard_topo_free(listp, sizeof (mde_cookie_t) * num_nodes);
		cpuboard_topo_free(bufp, (size_t)bufsize);
		(void) md_fini(mdp);
		ldom_fini(lhp);
		return (-1);
	}
	for (id = 0; id < CPUBOARD_MAX; id++)
		cpubs[id].present = 0;

	for (i = 0; i < ncomp; i++) {
		/*
		 * PRI nodes are still named "cpu-board", but the canonical
		 * names are "cpuboard".
		 */
		if (md_get_prop_str(mdp, listp[i], "type", &pstr) == 0 &&
		    pstr != NULL && strcmp(pstr, "cpu-board") == 0) {
			if (md_get_prop_val(mdp, listp[i], "id", &id) < 0) {
				topo_mod_dprintf(mod, "cpuboard_get_pri_info: "
				    "id md_get_prop_val() failed. (%d: %s)\n",
				    errno, strerror(errno));
				continue;
			}
			if ((id >= CPUBOARD_MAX) || cpubs[id].present) {
				topo_mod_seterrno(mod, EMOD_NVL_INVAL);
				topo_mod_dprintf(mod, "cpuboard_get_pri_info: "
				    "id %llx out of range. (%d: %s)\n",
				    id, errno, strerror(errno));
				continue;
			}
			cpubs[id].present = 1;

			topo_mod_dprintf(mod, "got cpu-board: %llx\n", id);

			sn = pn = dn = NULL;

			(void) md_get_prop_str(mdp, listp[i],
			    "serial_number", &sn);
			cpubs[id].sn = topo_mod_strdup(mod, sn);

			(void) md_get_prop_str(mdp, listp[i],
			    "part_number", &pn);

			(void) md_get_prop_str(mdp, listp[i],
			    "dash_number", &dn);
			len = (pn ? strlen(pn) : 0) + (dn ? strlen(dn) : 0) + 1;
			pstr = cpuboard_topo_alloc(len);
			(void) snprintf(pstr, len, "%s%s",
			    pn ? pn : "", dn ? dn : "");
			cpubs[id].pn = topo_mod_strdup(mod, pstr);
			cpuboard_topo_free(pstr, len);
		}
	}
	cpuboard_topo_free(listp, sizeof (mde_cookie_t) * num_nodes);
	cpuboard_topo_free(bufp, (size_t)bufsize);
	(void) md_fini(mdp);
	ldom_fini(lhp);

	return (0);
}

/*ARGSUSED*/
void
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOCPUBOARDDBG") != NULL) {
		topo_mod_setdebug(mod);
	}
	topo_mod_dprintf(mod, "initializing cpuboard enumerator\n");

	if (topo_mod_register(mod, &cpuboard_info, TOPO_VERSION) < 0) {
		topo_mod_dprintf(mod, "cpuboard registration failed: %s\n",
		    topo_mod_errmsg(mod));
		return; /* mod errno already set */
	}
	topo_mod_dprintf(mod, "cpuboard enumr initd\n");
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static tnode_t *
cpuboard_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, void *priv, cpuboard_contents_t *cpubc)
{
	int err;
	nvlist_t *fmri;
	tnode_t *ntn;
	nvlist_t *auth = topo_mod_auth(mod, parent);

	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name, i,
	    NULL, auth, cpubc->pn, NULL, cpubc->sn);
	nvlist_free(auth);

	topo_mod_strfree(mod, cpubc->sn);
	topo_mod_strfree(mod, cpubc->pn);

	cpubc->sn = cpubc->pn = NULL;

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
	topo_mod_dprintf(mod,
	    "cpuboard_tnode_create: topo_node_bind (%s%d/%s%d) created!\n",
	    topo_node_name(parent), topo_node_instance(parent), name, i);
	nvlist_free(fmri);
	topo_node_setspecific(ntn, priv);

	if (topo_pgroup_create(ntn, &cpuboard_auth_pgroup, &err) == 0) {
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, &err);
		(void) topo_prop_inherit(ntn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, &err);
	}

	return (ntn);
}

static int
cpuboard_fru_set(topo_mod_t *mp, tnode_t *tn)
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
cpuboard_label_set(topo_mod_t *mod, tnode_t *parent, tnode_t *node,
	topo_instance_t n)
{
	char *label = NULL;
	char *plabel = NULL;
	const char *cpuboard_label = "/CPU";
	int err, len;

	if (topo_node_label(parent, &plabel, &err) != 0 ||
	    plabel == NULL) {
		return (-1);
	}

	len = strlen(plabel) + strlen(cpuboard_label) + 2;
	label = topo_mod_alloc(mod, len);
	(void) snprintf(label, len, "%s%s%d", plabel, cpuboard_label, n);
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
cpuboard_declare(tnode_t *parent, const char *name, topo_instance_t i,
	void *priv, topo_mod_t *mod, cpuboard_contents_t *cpubc)
{
	tnode_t *ntn;
	nvlist_t *fmri = NULL;
	int err;

	if ((ntn = cpuboard_tnode_create(mod, parent, name, i, priv,
	    cpubc)) == NULL) {
		topo_mod_dprintf(mod, "%s ntn = NULL\n", name);
		return (NULL);
	}

	(void) cpuboard_fru_set(mod, ntn);

	(void) cpuboard_label_set(mod, parent, ntn, i);

	/* set ASRU to resource fmri */
	if (topo_prop_get_fmri(ntn, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_RESOURCE, &fmri, &err) == 0)
		(void) topo_node_asru_set(ntn, fmri, 0, &err);
	nvlist_free(fmri);

	return (ntn);
}

static int
chip_instantiate(tnode_t *parent, const char *name, topo_mod_t *mod,
    topo_instance_t inst)
{
	if (strcmp(name, CPUBOARD) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    CPUBOARD);
		return (0);
	}
	topo_mod_dprintf(mod,
	    "Calling chip_enum for inst: %lx\n", inst);
	if (topo_mod_enumerate(mod,
	    parent, CHIP, CHIP, inst, inst, NULL) != 0) {
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}
	return (0);
}

static topo_mod_t *
chip_enum_load(topo_mod_t *mp)
{
	topo_mod_t *rp = NULL;

	topo_mod_dprintf(mp, "chip_enum_load: %s\n", CPUBOARD);
	if ((rp = topo_mod_load(mp, CHIP, TOPO_VERSION)) == NULL) {
		topo_mod_dprintf(mp,
		    "%s enumerator could not load %s enum. (%d: %s)\n",
		    CPUBOARD, CHIP, errno, strerror(errno));
	}
	topo_mod_dprintf(mp, "chip_enum_load(EXIT): %s, rp=%p\n", CPUBOARD, rp);
	return (rp);
}

static di_node_t
cpuboard_findrc(topo_mod_t *mod, uint64_t id)
{
	di_node_t devtree;
	di_node_t dnode;

	if ((devtree = topo_mod_devinfo(mod)) == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "devinfo init failed.");
		return (NULL);
	}
	dnode = di_drv_first_node(CPUBOARD_PX_DRV, devtree);
	while (dnode != DI_NODE_NIL) {
		char *path;

		if ((path = di_devfs_path(dnode)) == NULL) {
			topo_mod_dprintf(mod, "cpuboard_findrc: "
			    "NULL di_devfs_path.\n");
			(void) topo_mod_seterrno(mod, ETOPO_PROP_NOENT);
			return (NULL);
		}
		topo_mod_dprintf(mod, "cpuboard_findrc: "
		    "got px %d, node named: %s, path: %s\n",
		    di_instance(dnode), di_node_name(dnode), path);

		if (strcmp(cpub_rcs[id], path) == 0) {
			di_devfs_path_free(path);
			return (dnode);
		}

		di_devfs_path_free(path);

		dnode = di_drv_next_node(dnode);
	}
	return (NULL);
}

/*ARGSUSED*/
static int
cpuboard_enum(topo_mod_t *mod, tnode_t *parent, const char *name,
	topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	tnode_t *cpuboardn;
	topo_instance_t i = 0;
	cpuboard_contents_t cpuboard_list[CPUBOARD_MAX];

	if (strcmp(name, CPUBOARD) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    CPUBOARD);
		return (-1);
	}
	/* Make sure we don't exceed CPUBOARD_MAX */
	if (max >= CPUBOARD_MAX) {
		max = CPUBOARD_MAX;
	}

	bzero(cpuboard_list, sizeof (cpuboard_list));

	/* Scan PRI for cpu-boards. */
	cpuboard_mod_hdl = mod;
	(void) cpuboard_get_pri_info(mod, cpuboard_list);

	if (chip_enum_load(mod) == NULL)
		return (-1);

	for (i = min; i <= max; i++) {
		if (cpuboard_list[i].present == 0)
			continue;

		cpuboardn = cpuboard_declare(parent, name, i,
		    NULL, mod, &cpuboard_list[i]);
		if (cpuboardn == NULL) {
			topo_mod_dprintf(mod,
			    "Enumeration of cpuboard failed: %s\n",
			    topo_strerror(topo_mod_errno(mod)));
			return (-1); /* mod_errno already set */
		}
		if (topo_node_range_create(mod, cpuboardn, CHIP, 0,
		    CHIP_MAX) < 0) {
			topo_node_unbind(cpuboardn);
			topo_mod_dprintf(mod, "topo_node_range_create CHIP "
			    "failed: %s\n", topo_strerror(topo_mod_errno(mod)));
			return (-1); /* mod_errno already set */
		}
		if (chip_instantiate(cpuboardn, CPUBOARD, mod, i) < 0) {
			topo_mod_dprintf(mod, "Enumeration of chip "
			    "failed %s\n",
			    topo_strerror(topo_mod_errno(mod)));
			return (-1);
		}
		if (topo_node_range_create(mod, cpuboardn, HOSTBRIDGE, 0,
		    HOSTBRIDGE_MAX) < 0) {
			topo_node_unbind(cpuboardn);
			topo_mod_dprintf(mod, "topo_node_range_create: "
			    "HOSTBRIDGE failed: %s\n",
			    topo_strerror(topo_mod_errno(mod)));
			return (-1);
		}
		if (cpuboard_hb_enum(mod, cpuboard_findrc(mod, i),
		    cpuboardn, i) < 0) {
			topo_node_unbind(cpuboardn);
			topo_mod_dprintf(mod, "cpuboard_hb_enum: "
			    "failed: %s\n",
			    topo_strerror(topo_mod_errno(mod)));
			return (-1);
		}
	}
	return (0);
}
