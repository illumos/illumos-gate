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

/*
 * motherboard.c
 *	sun4v specific motherboard enumerators
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	MB_VERSION	TOPO_VERSION

static int mb_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
		topo_instance_t, void *, void *);

static const topo_modops_t Mb_ops =
	{ mb_enum, NULL};
static const topo_modinfo_t mb_info =
	{ MOTHERBOARD, FM_FMRI_SCHEME_HC, MB_VERSION, &Mb_ops};

static const topo_pgroup_info_t mb_auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t mb_sys_pgroup = {
	TOPO_PGROUP_SYSTEM,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static topo_mod_t *mb_mod_hdl = NULL;

/*ARGSUSED*/
void
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOMBDBG") != NULL)
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing motherboard enumerator\n");

	if (topo_mod_register(mod, &mb_info, TOPO_VERSION) < 0) {
		topo_mod_dprintf(mod, "motherboard registration failed: %s\n",
		    topo_mod_errmsg(mod));
		return; /* mod errno already set */
	}
	topo_mod_dprintf(mod, "MB enumr initd\n");
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static void *
mb_topo_alloc(size_t size)
{
	assert(mb_mod_hdl != NULL);
	return (topo_mod_alloc(mb_mod_hdl, size));
}

static void
mb_topo_free(void *data, size_t size)
{
	assert(mb_mod_hdl != NULL);
	topo_mod_free(mb_mod_hdl, data, size);
}

static int
mb_get_pri_info(topo_mod_t *mod, char **serialp, char **partp, char **csnp)
{
	char isa[MAXNAMELEN];
	md_t *mdp;
	mde_cookie_t *listp;
	uint64_t *bufp;
	ssize_t bufsize = 0;
	int  nfrus, num_nodes, i;
	char *pstr = NULL;
	char *sn, *pn, *dn, *csn;
	uint32_t type = 0;
	ldom_hdl_t *lhp;

	lhp = ldom_init(mb_topo_alloc, mb_topo_free);
	if (lhp == NULL) {
		topo_mod_dprintf(mod, "ldom_init failed\n");
		return (-1);
	}

	(void) sysinfo(SI_MACHINE, isa, MAXNAMELEN);
	if (strcmp(isa, "sun4v") != 0) {
		topo_mod_dprintf(mod, "not sun4v architecture%s\n",
		    isa);
		ldom_fini(lhp);
		return (-1);
	}

	(void) ldom_get_type(lhp, &type);
	if ((type & LDOM_TYPE_CONTROL) != 0) {
		bufsize = ldom_get_core_md(lhp, &bufp);
	} else {
		bufsize = ldom_get_local_md(lhp, &bufp);
	}
	if (bufsize < 1) {
		topo_mod_dprintf(mod, "Failed to get the pri/md (bufsize=%d)\n",
		    bufsize);
		ldom_fini(lhp);
		return (-1);
	}
	topo_mod_dprintf(mod, "pri/md bufsize=%d\n", bufsize);

	if ((mdp = md_init_intern(bufp, mb_topo_alloc, mb_topo_free)) == NULL ||
	    (num_nodes = md_node_count(mdp)) < 1) {
		topo_mod_dprintf(mod, "md_init_intern error\n");
		mb_topo_free(bufp, (size_t)bufsize);
		ldom_fini(lhp);
		return (-1);
	}
	topo_mod_dprintf(mod, "num_nodes=%d\n", num_nodes);

	if ((listp = (mde_cookie_t *)mb_topo_alloc(
	    sizeof (mde_cookie_t) * num_nodes)) == NULL) {
		topo_mod_dprintf(mod, "alloc listp error\n");
		mb_topo_free(bufp, (size_t)bufsize);
		(void) md_fini(mdp);
		ldom_fini(lhp);
		return (-1);
	}

	nfrus = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"), listp);
	if (nfrus <= 0) {
		topo_mod_dprintf(mod, "error: nfrus=%d\n", nfrus);
		mb_topo_free(listp, sizeof (mde_cookie_t) * num_nodes);
		mb_topo_free(bufp, (size_t)bufsize);
		(void) md_fini(mdp);
		ldom_fini(lhp);
		return (-1);
	}
	topo_mod_dprintf(mod, "nfrus=%d\n", nfrus);
	for (i = 0; i < nfrus; i++) {
		if (md_get_prop_str(mdp, listp[i], "type", &pstr) == 0) {
			/* systemboard/motherboard component */
			if (strcmp("systemboard", pstr) == 0) {
				if (md_get_prop_str(mdp, listp[i],
				    "serial_number", &sn) < 0)
					sn = NULL;
				if (md_get_prop_str(mdp, listp[i],
				    "part_number", &pn) < 0)
					pn = NULL;
				if (md_get_prop_str(mdp, listp[i],
				    "dash_number", &dn) < 0)
					dn = NULL;
			}
		}
		/* redefined access method for chassis serial number */
		if (md_get_prop_str(mdp, listp[i], "nac", &pstr) == 0) {
			if (strcmp("SYS", pstr) == 0) {
				if (md_get_prop_str(mdp, listp[i],
				    "serial_number", &csn) < 0)
					csn = NULL;
			}
		}
	}

	*serialp = topo_mod_strdup(mod, sn);

	i = (pn ? strlen(pn) : 0) + (dn ? strlen(dn) : 0) + 1;
	pstr = mb_topo_alloc(i);
	(void) snprintf(pstr, i, "%s%s", pn ? pn : "", dn ? dn : "");
	*partp = topo_mod_strdup(mod, pstr);
	mb_topo_free(pstr, i);

	*csnp = topo_mod_strdup(mod, csn);

	mb_topo_free(listp, sizeof (mde_cookie_t) * num_nodes);
	mb_topo_free(bufp, (size_t)bufsize);
	(void) md_fini(mdp);
	ldom_fini(lhp);

	return (0);
}

static void
mb_prop_set(tnode_t *node, nvlist_t *auth)
{
	int err;
	char isa[MAXNAMELEN];
	struct utsname uts;
	char *prod, *csn, *server;

	if ((topo_pgroup_create(node, &mb_auth_pgroup, &err) != 0) &&
	    (err != ETOPO_PROP_DEFD))
		return;

	if (nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT, &prod) == 0)
		(void) topo_prop_set_string(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, TOPO_PROP_IMMUTABLE, prod, &err);
	if (nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS, &csn) == 0)
		(void) topo_prop_set_string(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, TOPO_PROP_IMMUTABLE, csn, &err);
	if (nvlist_lookup_string(auth, FM_FMRI_AUTH_SERVER, &server) == 0)
		(void) topo_prop_set_string(node, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, TOPO_PROP_IMMUTABLE, server, &err);

	if (topo_pgroup_create(node, &mb_sys_pgroup, &err) != 0)
		return;

	isa[0] = '\0';
	(void) sysinfo(SI_ARCHITECTURE, isa, sizeof (isa));
	(void) uname(&uts);
	(void) topo_prop_set_string(node, TOPO_PGROUP_SYSTEM, TOPO_PROP_ISA,
	    TOPO_PROP_IMMUTABLE, isa, &err);
	(void) topo_prop_set_string(node, TOPO_PGROUP_SYSTEM, TOPO_PROP_MACHINE,
	    TOPO_PROP_IMMUTABLE, uts.machine, &err);
}

static tnode_t *
mb_tnode_create(topo_mod_t *mod, tnode_t *parent,
    const char *name, topo_instance_t i, void *priv)
{
	nvlist_t *fmri;
	tnode_t *ntn;
	char *serial = NULL, *part = NULL;
	char *csn = NULL, *pstr = NULL;
	nvlist_t *auth = topo_mod_auth(mod, parent);

	/* Get Chassis ID, MB Serial Number and Part Number from PRI */
	(void) mb_get_pri_info(mod, &serial, &part, &csn);

	if (nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS, &pstr) != 0 &&
	    csn != NULL) {
		if (nvlist_add_string(auth, FM_FMRI_AUTH_CHASSIS, csn) != 0) {
			topo_mod_dprintf(mod,
			    "failed to add chassis to auth");
			nvlist_free(auth);
			return (NULL);
		}
	}

	fmri = topo_mod_hcfmri(mod, NULL, FM_HC_SCHEME_VERSION, name, i,
	    NULL, auth, part, NULL, serial);

	topo_mod_strfree(mod, serial);
	topo_mod_strfree(mod, part);
	topo_mod_strfree(mod, csn);

	if (fmri == NULL) {
		topo_mod_dprintf(mod,
		    "Unable to make nvlist for %s bind: %s.\n",
		    name, topo_mod_errmsg(mod));
		nvlist_free(auth);
		return (NULL);
	}

	ntn = topo_node_bind(mod, parent, name, i, fmri);
	if (ntn == NULL) {
		topo_mod_dprintf(mod,
		    "topo_node_bind (%s%d/%s%d) failed: %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i,
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(auth);
		nvlist_free(fmri);
		return (NULL);
	}

	mb_prop_set(ntn, auth);

	nvlist_free(auth);
	nvlist_free(fmri);

	topo_node_setspecific(ntn, priv);

	return (ntn);
}

/*ARGSUSED*/
static tnode_t *
mb_declare(tnode_t *parent, const char *name, topo_instance_t i,
	void *priv, topo_mod_t *mp)
{
	tnode_t *ntn;
	nvlist_t *fmri;
	char *label = "MB";
	int err;

	if ((ntn = mb_tnode_create(mp, parent, name, 0, NULL)) == NULL)
		return (NULL);

	/* Set FRU */
	if (topo_node_resource(ntn, &fmri, &err) < 0) {
		(void) topo_mod_seterrno(mp, err);
		topo_node_unbind(ntn);
		return (NULL);
	}
	if (topo_node_fru_set(ntn, fmri, 0, &err) < 0)
		(void) topo_mod_seterrno(mp, err);
	nvlist_free(fmri);

	/* Label is MB */
	if (topo_prop_set_string(ntn, TOPO_PGROUP_PROTOCOL,
	    TOPO_PROP_LABEL,  TOPO_PROP_IMMUTABLE, label, &err) < 0) {
		(void) topo_mod_seterrno(mp, err);
	}

	return (ntn);
}

/*ARGSUSED*/
static int
mb_enum(topo_mod_t *mod, tnode_t *pn, const char *name,
	topo_instance_t min, topo_instance_t max, void *arg, void *notused)
{
	tnode_t *mbn;

	if (strcmp(name, MOTHERBOARD) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    MOTHERBOARD);
		return (0);
	}

	mb_mod_hdl = mod;

	mbn = mb_declare(pn, name, 0, NULL, mod);

	if (mbn == NULL) {
		topo_mod_dprintf(mod, "Enumeration of motherboard "
		    "failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		return (-1); /* mod_errno already set */
	}

	return (0);
}
