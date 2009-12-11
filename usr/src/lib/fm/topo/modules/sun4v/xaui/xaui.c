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


#include <strings.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/fm/protocol.h>
#include <sys/fm/ldom.h>
#include <sys/mdesc.h>
#include <assert.h>
#include <sys/systeminfo.h>
#include "xaui.h"

/*
 * xaui.c
 *	sun4v specific xaui enumerators
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	XAUI_VERSION		TOPO_VERSION
#define	XFP_MAX			1	/* max number of xfp per xaui card */
#define	MAX_PCIADDR_DEPTH	3	/* Bus/Dev/Func */

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

static topo_mod_t *xaui_mod_hdl = NULL;
static int freeprilabel = 0;
static int ispci = 0;

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


static void *
xaui_topo_alloc(size_t size)
{
	assert(xaui_mod_hdl != NULL);
	return (topo_mod_alloc(xaui_mod_hdl, size));
}


static void
xaui_topo_free(void *data, size_t size)
{
	assert(xaui_mod_hdl != NULL);
	topo_mod_free(xaui_mod_hdl, data, size);
}


static char *
xaui_get_path(topo_mod_t *mod, void *priv, topo_instance_t inst)
{
	int i = 0;
	int rv;
	di_node_t dnode;
	char *devfs_path;
	char *path;
	char *buf = NULL;
	char *freebuf;
	char *addr[MAX_PCIADDR_DEPTH] = { NULL };
	char *token;
	char *lastp;
	size_t buf_len;
	size_t path_len = 0;

	/*
	 * There are two ways to get here:
	 * 1. niu enum  - private data is the di_node_t for this xaui
	 *		- instance is the ethernet function number
	 *    device path looks like: /niu@80/network@0:nxge@0
	 *    PRI path looks like:    /@80/@0
	 *
	 * 2. pcibus enum - private data is the parent tnode_t
	 *		  - instance is the pci function number
	 *    device path looks like: /pci@500/pci@0/pci@8/network@0:nxge0
	 *    PRI path looks like:    /@500/@0/@8/@0
	 *
	 *    PRI path for pciex is /@Bus/@Dev/@Func/@Instance
	 *
	 *    The parent topo_node for xaui is pciexfn; check to see if the
	 *    private data is a topo_node by looking for the "pciexfn" name.
	 */
	if (ispci == 1) {
		/* coming from pcibus */
		topo_mod_dprintf(mod, "from pcibus\n");
		/* PCI Func tnode */
		dnode = topo_node_getspecific((tnode_t *)priv);
	} else {
		/* coming from niu */
		topo_mod_dprintf(mod, "from niu\n");
		dnode = (struct di_node *)priv;
	}
	if (dnode == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "DI_NODE_NIL\n");
		return (NULL);
	}

	/* get device path */
	devfs_path = di_devfs_path(dnode);
	if (devfs_path == NULL) {
		topo_mod_dprintf(mod, "NULL devfs_path\n");
		return (NULL);
	}

	/* alloc enough space to hold the path */
	topo_mod_dprintf(mod, "devfs_path (%s)\n", devfs_path);
	buf_len = strlen(devfs_path) + 1;
	buf = (char *)xaui_topo_alloc(buf_len);
	if (buf == NULL) {
		return (NULL);
	}
	freebuf = buf; /* strtok_r is destructive */
	(void) strcpy(buf, devfs_path);

	if (ispci == 1) {
		/*
		 * devfs path for pciexfn looks like
		 * /pci@BUS/pci@DEV/pci@FUNC
		 *
		 * Strip "/pci@" chars from path and add /@Instance
		 */
		topo_mod_dprintf(mod, "ispci\n");
		if ((token = strtok_r(buf, "/pci@", &lastp)) != NULL) {
			addr[i] = topo_mod_strdup(mod, token);
			path_len = strlen(token);
			while ((token = strtok_r(NULL, "/pci@", &lastp)) !=
			    NULL) {
				if (++i < MAX_PCIADDR_DEPTH) {
					addr[i] = topo_mod_strdup(mod, token);
					path_len += strlen(token);
				} else {
					xaui_topo_free(freebuf, buf_len);
					return (NULL);
				}
			}
		} else {
			xaui_topo_free(freebuf, buf_len);
			return (NULL);
		}
		xaui_topo_free(freebuf, buf_len);

		/* path: addresses + '/@' + '/@instance' (0/1)  + '\0' */
		path_len += ((MAX_PCIADDR_DEPTH * 2) + 3 + 1);
		path = (char *)xaui_topo_alloc(path_len);
		rv = snprintf(path, path_len, "/@%s/@%s/@%s/@%d",
		    addr[0], addr[1], addr[2], inst);
		if (rv < 0) {
			return (NULL);
		}
	} else {
		/* need to strip "/niu@" chars from path and add /@Instance */
		token = strtok_r(buf, "/niu@", &lastp);
		addr[0] = topo_mod_strdup(mod, token);
		path_len = strlen(token);
		xaui_topo_free(freebuf, buf_len);

		/* path: address + '/@' + '/@instance' (0/1) + '\0' */
		path_len += (2 + 3 +1);
		path = (char *)xaui_topo_alloc(path_len);
		rv = snprintf(path, path_len, "/@%s/@%d", addr[0], inst);
		if (rv < 0) {
			return (NULL);
		}
	}
	topo_mod_dprintf(mod, "xaui_get_path: path (%s)\n", path);

	/* cleanup */
	for (i = 0; i < MAX_PCIADDR_DEPTH; i++) {
		if (addr[i] != NULL) {
			xaui_topo_free(addr[i], strlen(addr[i]) + 1);
		}
	}

	/* should return something like /@500/@0/@8/@0 or /@80/@0 */
	return (path);
}


static int
xaui_get_pri_label(topo_mod_t *mod, topo_instance_t n, void *priv,
    char **labelp)
{
	ldom_hdl_t *hdlp;
	uint32_t type = 0;
	ssize_t bufsize = 0;
	uint64_t *bufp;
	md_t *mdp;
	int num_nodes, ncomp;
	mde_cookie_t *listp;
	char *pstr = NULL;
	int i;
	char *path;

	/* Get device path minus the device names */
	path = xaui_get_path(mod, priv, n);
	if (path == NULL) {
		topo_mod_dprintf(mod, "can't get path\n");
		return (-1);
	}

	hdlp = ldom_init(xaui_topo_alloc, xaui_topo_free);
	if (hdlp == NULL) {
		topo_mod_dprintf(mod, "ldom_init failed\n");
		return (-1);
	}

	(void) ldom_get_type(hdlp, &type);
	if ((type & LDOM_TYPE_CONTROL) != 0) {
		bufsize = ldom_get_core_md(hdlp, &bufp);
	} else {
		bufsize = ldom_get_local_md(hdlp, &bufp);
	}
	if (bufsize < 1) {
		topo_mod_dprintf(mod, "failed to get pri/md (%d)\n", bufsize);
		ldom_fini(hdlp);
		return (-1);
	}

	if ((mdp = md_init_intern(bufp, xaui_topo_alloc, xaui_topo_free)) ==
	    NULL || (num_nodes = md_node_count(mdp)) < 1) {
		topo_mod_dprintf(mod, "md_init_intern failed\n");
		xaui_topo_free(bufp, (size_t)bufsize);
		ldom_fini(hdlp);
		return (-1);
	}

	if ((listp = (mde_cookie_t *)xaui_topo_alloc(
	    sizeof (mde_cookie_t) * num_nodes)) == NULL) {
		topo_mod_dprintf(mod, "can't alloc listp\n");
		xaui_topo_free(bufp, (size_t)bufsize);
		(void) md_fini(mdp);
		ldom_fini(hdlp);
		return (-1);
	}

	ncomp = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "component"),
	    md_find_name(mdp, "fwd"), listp);
	if (ncomp <= 0) {
		topo_mod_dprintf(mod, "no component nodes found\n");
		xaui_topo_free(listp, sizeof (mde_cookie_t) * num_nodes);
		xaui_topo_free(bufp, (size_t)bufsize);
		(void) md_fini(mdp);
		ldom_fini(hdlp);
		return (-1);
	}
	topo_mod_dprintf(mod, "number of comps (%d)\n", ncomp);

	for (i = 0; i < ncomp; i++) {
		/*
		 * Look for type == "io", topo-hc-name == "xaui";
		 * match "path" md property.
		 */
		if ((md_get_prop_str(mdp, listp[i], "type", &pstr) == 0) &&
		    (pstr != NULL) &&
		    (strncmp(pstr, "io", strlen(pstr)) == 0) &&
		    (md_get_prop_str(mdp, listp[i], "topo-hc-name", &pstr)
		    == 0) && (pstr != NULL) &&
		    (strncmp(pstr, "xaui", strlen(pstr)) == 0) &&
		    (md_get_prop_str(mdp, listp[i], "path", &pstr) == 0) &&
		    (pstr != NULL)) {
			/* check node path */
			if (strncmp(pstr, path, sizeof (path)) == 0) {
				/* this is the node, grab the label */
				if (md_get_prop_str(mdp, listp[i], "nac",
				    &pstr) == 0) {
					*labelp = topo_mod_strdup(mod, pstr);
					/* need to free this later */
					freeprilabel = 1;
					break;
				}
			}
		}
	}

	xaui_topo_free(listp, sizeof (mde_cookie_t) * num_nodes);
	xaui_topo_free(bufp, (size_t)bufsize);
	(void) md_fini(mdp);
	ldom_fini(hdlp);

	if (path != NULL) {
		xaui_topo_free(path, strlen(path) + 1);
	}
	return (0);
}


static int
xaui_label_set(topo_mod_t *mod, tnode_t *node, topo_instance_t n, void *priv)
{
	const char *label = NULL;
	char *plat, *pp;
	int err;
	int i, p;

	(void) xaui_get_pri_label(mod, n, priv, (char **)&label);
	if (label == NULL) {
		topo_mod_dprintf(mod, "no PRI node for label\n");
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
			for (i = 0; i < Phyxaui_Names->psn_names[p].pnm_nnames;
			    i++) {
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
	}

	if (label != NULL) {
		if (topo_prop_set_string(node, TOPO_PGROUP_PROTOCOL,
		    TOPO_PROP_LABEL, TOPO_PROP_IMMUTABLE,
		    label, &err) != 0) {
			if (freeprilabel == 1) {
				topo_mod_strfree(mod, (char *)label);
			}
			return (topo_mod_seterrno(mod, err));
		}
		if (freeprilabel == 1) {
			topo_mod_strfree(mod, (char *)label);
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

	/* when coming from pcibus: private data == parent tnode */
	if (priv == (void *)parent) {
		ispci = 1;
	}

	(void) xaui_label_set(mod, ntn, i, priv);

	/* reset pcibus/niu switch */
	ispci = 0;

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
	topo_instance_t min, topo_instance_t max, void *arg, void *priv)
{
	tnode_t *xauin;

	if (strcmp(name, XAUI) != 0) {
		topo_mod_dprintf(mod,
		    "Currently only know how to enumerate %s components.\n",
		    XAUI);
		return (0);
	}

	xaui_mod_hdl = mod;

	/*
	 * Load XFP enum
	 */
	if (xfp_enum_load(mod) == NULL)
		return (-1);

	if ((xauin = xaui_declare(rnode, name, min, priv, mod)) == NULL)
		return (-1);

	/* set the private data to be the instance number of niufn */
	if (topo_mod_enumerate(mod,
	    xauin, XFP, XFP, 0, 0, NULL) != 0) {
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}
	return (0);
}
