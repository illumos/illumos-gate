/*
 *
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <alloca.h>
#include <limits.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/fm/protocol.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>

#include <topo_method.h>
#include <topo_subr.h>
#include <topo_prop.h>
#include <hc.h>

static int hc_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void hc_release(topo_mod_t *, tnode_t *);
static int hc_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int hc_fmri_str2nvl(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int hc_compare(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hc_fmri_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hc_fmri_unusable(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hc_fmri_create_meth(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int hc_fmri_prop_get(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int hc_fmri_prop_set(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int hc_fmri_pgrp_get(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static nvlist_t *hc_fmri_create(topo_mod_t *, nvlist_t *, int, const char *,
    topo_instance_t inst, const nvlist_t *, const char *, const char *,
    const char *);

const topo_method_t hc_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_fmri_nvl2str },
	{ TOPO_METH_STR2NVL, TOPO_METH_STR2NVL_DESC, TOPO_METH_STR2NVL_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_fmri_str2nvl },
	{ TOPO_METH_COMPARE, TOPO_METH_COMPARE_DESC, TOPO_METH_COMPARE_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_compare },
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC, TOPO_METH_PRESENT_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_fmri_present },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL,
	    hc_fmri_unusable },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_fmri_create_meth },
	{ TOPO_METH_PROP_GET, TOPO_METH_PROP_GET_DESC,
	    TOPO_METH_PROP_GET_VERSION, TOPO_STABILITY_INTERNAL,
	    hc_fmri_prop_get },
	{ TOPO_METH_PROP_SET, TOPO_METH_PROP_SET_DESC,
	    TOPO_METH_PROP_SET_VERSION, TOPO_STABILITY_INTERNAL,
	    hc_fmri_prop_set },
	{ TOPO_METH_PGRP_GET, TOPO_METH_PGRP_GET_DESC,
	    TOPO_METH_PGRP_GET_VERSION, TOPO_STABILITY_INTERNAL,
	    hc_fmri_pgrp_get },
	{ NULL }
};

static const topo_modops_t hc_ops =
	{ hc_enum, hc_release };
static const topo_modinfo_t hc_info =
	{ HC, FM_FMRI_SCHEME_HC, HC_VERSION, &hc_ops };

static const hcc_t hc_canon[] = {
	{ BAY, TOPO_STABILITY_PRIVATE },
	{ BRANCH, TOPO_STABILITY_PRIVATE },
	{ CMP, TOPO_STABILITY_PRIVATE },
	{ CENTERPLANE, TOPO_STABILITY_PRIVATE },
	{ CHASSIS, TOPO_STABILITY_PRIVATE },
	{ CHIP, TOPO_STABILITY_PRIVATE },
	{ CHIP_SELECT, TOPO_STABILITY_PRIVATE },
	{ CPU, TOPO_STABILITY_PRIVATE },
	{ CPUBOARD, TOPO_STABILITY_PRIVATE },
	{ DIMM, TOPO_STABILITY_PRIVATE },
	{ DISK, TOPO_STABILITY_PRIVATE },
	{ DRAMCHANNEL, TOPO_STABILITY_PRIVATE },
	{ FAN, TOPO_STABILITY_PRIVATE },
	{ FANMODULE, TOPO_STABILITY_PRIVATE },
	{ HOSTBRIDGE, TOPO_STABILITY_PRIVATE },
	{ INTERCONNECT, TOPO_STABILITY_PRIVATE },
	{ IOBOARD, TOPO_STABILITY_PRIVATE },
	{ MEMBOARD, TOPO_STABILITY_PRIVATE },
	{ MEMORYCONTROL, TOPO_STABILITY_PRIVATE },
	{ MOTHERBOARD, TOPO_STABILITY_PRIVATE },
	{ NIU, TOPO_STABILITY_PRIVATE },
	{ NIUFN, TOPO_STABILITY_PRIVATE },
	{ PCI_BUS, TOPO_STABILITY_PRIVATE },
	{ PCI_DEVICE, TOPO_STABILITY_PRIVATE },
	{ PCI_FUNCTION, TOPO_STABILITY_PRIVATE },
	{ PCIEX_BUS, TOPO_STABILITY_PRIVATE },
	{ PCIEX_DEVICE, TOPO_STABILITY_PRIVATE },
	{ PCIEX_FUNCTION, TOPO_STABILITY_PRIVATE },
	{ PCIEX_ROOT, TOPO_STABILITY_PRIVATE },
	{ PCIEX_SWUP, TOPO_STABILITY_PRIVATE },
	{ PCIEX_SWDWN, TOPO_STABILITY_PRIVATE },
	{ POWERMODULE, TOPO_STABILITY_PRIVATE },
	{ PSU, TOPO_STABILITY_PRIVATE },
	{ RANK, TOPO_STABILITY_PRIVATE },
	{ SYSTEMBOARD, TOPO_STABILITY_PRIVATE },
	{ XAUI, TOPO_STABILITY_PRIVATE },
	{ XFP, TOPO_STABILITY_PRIVATE }
};

static int hc_ncanon = sizeof (hc_canon) / sizeof (hcc_t);

int
hc_init(topo_mod_t *mod, topo_version_t version)
{
	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPOHCDEBUG"))
		topo_mod_setdebug(mod);

	topo_mod_dprintf(mod, "initializing hc builtin\n");

	if (version != HC_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &hc_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1); /* mod errno already set */
	}

	return (0);
}

void
hc_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}


static const topo_pgroup_info_t sys_pgroup = {
	TOPO_PGROUP_SYSTEM,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t auth_pgroup = {
	FM_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static void
hc_prop_set(tnode_t *node, nvlist_t *auth)
{
	int err;
	char isa[MAXNAMELEN];
	struct utsname uts;
	char *prod, *csn, *server;

	if (auth == NULL)
		return;

	if (topo_pgroup_create(node, &auth_pgroup, &err) != 0) {
		if (err != ETOPO_PROP_DEFD)
			return;
	}

	/*
	 * Inherit if we can, it saves memory
	 */
	if ((topo_prop_inherit(node, FM_FMRI_AUTHORITY, FM_FMRI_AUTH_PRODUCT,
	    &err) != 0) && (err != ETOPO_PROP_DEFD)) {
		if (nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT, &prod)
		    == 0)
			(void) topo_prop_set_string(node, FM_FMRI_AUTHORITY,
			    FM_FMRI_AUTH_PRODUCT, TOPO_PROP_IMMUTABLE, prod,
			    &err);
	}
	if ((topo_prop_inherit(node, FM_FMRI_AUTHORITY, FM_FMRI_AUTH_CHASSIS,
	    &err) != 0) && (err != ETOPO_PROP_DEFD)) {
		if (nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS, &csn) == 0)
			(void) topo_prop_set_string(node, FM_FMRI_AUTHORITY,
			    FM_FMRI_AUTH_CHASSIS, TOPO_PROP_IMMUTABLE, csn,
			    &err);
	}
	if ((topo_prop_inherit(node, FM_FMRI_AUTHORITY, FM_FMRI_AUTH_SERVER,
	    &err) != 0) && (err != ETOPO_PROP_DEFD)) {
		if (nvlist_lookup_string(auth, FM_FMRI_AUTH_SERVER, &server)
		    == 0)
			(void) topo_prop_set_string(node, FM_FMRI_AUTHORITY,
			    FM_FMRI_AUTH_SERVER, TOPO_PROP_IMMUTABLE, server,
			    &err);
	}

	if (topo_pgroup_create(node, &sys_pgroup, &err) != 0)
		return;

	isa[0] = '\0';
	(void) sysinfo(SI_ARCHITECTURE, isa, sizeof (isa));
	(void) uname(&uts);
	(void) topo_prop_set_string(node, TOPO_PGROUP_SYSTEM, TOPO_PROP_ISA,
	    TOPO_PROP_IMMUTABLE, isa, &err);
	(void) topo_prop_set_string(node, TOPO_PGROUP_SYSTEM, TOPO_PROP_MACHINE,
	    TOPO_PROP_IMMUTABLE, uts.machine, &err);
}

/*ARGSUSED*/
int
hc_enum(topo_mod_t *mod, tnode_t *pnode, const char *name, topo_instance_t min,
    topo_instance_t max, void *notused1, void *notused2)
{
	nvlist_t *pfmri = NULL;
	nvlist_t *nvl;
	nvlist_t *auth;
	tnode_t *node;
	int err;
	/*
	 * Register root node methods
	 */
	if (strcmp(name, HC) == 0) {
		(void) topo_method_register(mod, pnode, hc_methods);
		return (0);
	}
	if (min != max) {
		topo_mod_dprintf(mod,
		    "Request to enumerate %s component with an "
		    "ambiguous instance number, min (%d) != max (%d).\n",
		    HC, min, max);
		return (topo_mod_seterrno(mod, EINVAL));
	}

	(void) topo_node_resource(pnode, &pfmri, &err);
	auth = topo_mod_auth(mod, pnode);
	nvl = hc_fmri_create(mod, pfmri, FM_HC_SCHEME_VERSION, name, min,
	    auth, NULL, NULL, NULL);
	nvlist_free(pfmri);	/* callee ignores NULLs */
	if (nvl == NULL) {
		nvlist_free(auth);
		return (-1);
	}

	if ((node = topo_node_bind(mod, pnode, name, min, nvl)) == NULL) {
		topo_mod_dprintf(mod, "topo_node_bind failed: %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		nvlist_free(auth);
		nvlist_free(nvl);
		return (-1);
	}

	/*
	 * Set FRU for the motherboard node
	 */
	if (strcmp(name, MOTHERBOARD) == 0)
		(void) topo_node_fru_set(node, nvl, 0, &err);

	hc_prop_set(node, auth);
	nvlist_free(nvl);
	nvlist_free(auth);

	return (0);
}

/*ARGSUSED*/
static void
hc_release(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);
}

static int
fmri_compare(topo_mod_t *mod, nvlist_t *nv1, nvlist_t *nv2)
{
	uint8_t v1, v2;
	nvlist_t **hcp1, **hcp2;
	int err, i;
	uint_t nhcp1, nhcp2;

	if (nvlist_lookup_uint8(nv1, FM_VERSION, &v1) != 0 ||
	    nvlist_lookup_uint8(nv2, FM_VERSION, &v2) != 0 ||
	    v1 > FM_HC_SCHEME_VERSION || v2 > FM_HC_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_VERSION));

	err = nvlist_lookup_nvlist_array(nv1, FM_FMRI_HC_LIST, &hcp1, &nhcp1);
	err |= nvlist_lookup_nvlist_array(nv2, FM_FMRI_HC_LIST, &hcp2, &nhcp2);
	if (err != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nhcp1 != nhcp2)
		return (0);

	for (i = 0; i < nhcp1; i++) {
		char *nm1 = NULL;
		char *nm2 = NULL;
		char *id1 = NULL;
		char *id2 = NULL;

		(void) nvlist_lookup_string(hcp1[i], FM_FMRI_HC_NAME, &nm1);
		(void) nvlist_lookup_string(hcp2[i], FM_FMRI_HC_NAME, &nm2);
		(void) nvlist_lookup_string(hcp1[i], FM_FMRI_HC_ID, &id1);
		(void) nvlist_lookup_string(hcp2[i], FM_FMRI_HC_ID, &id2);
		if (nm1 == NULL || nm2 == NULL || id1 == NULL || id2 == NULL)
			return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

		if (strcmp(nm1, nm2) == 0 && strcmp(id1, id2) == 0)
			continue;

		return (0);
	}

	return (1);
}

/*ARGSUSED*/
static int
hc_compare(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int ret;
	uint32_t compare;
	nvlist_t *nv1, *nv2;

	if (version > TOPO_METH_COMPARE_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NV1, &nv1) != 0 ||
	    nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NV2, &nv2) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	ret = fmri_compare(mod, nv1, nv2);
	if (ret < 0)
		return (-1);

	compare = ret;
	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) == 0) {
		if (nvlist_add_uint32(*out, TOPO_METH_COMPARE_RET,
		    compare) == 0)
			return (0);
		else
			nvlist_free(*out);
	}

	return (-1);
}

static ssize_t
fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	nvlist_t **hcprs = NULL;
	nvlist_t *anvl = NULL;
	uint8_t version;
	ssize_t size = 0;
	uint_t hcnprs;
	char *achas = NULL;
	char *adom = NULL;
	char *aprod = NULL;
	char *asrvr = NULL;
	char *ahost = NULL;
	char *serial = NULL;
	char *part = NULL;
	char *root = NULL;
	char *rev = NULL;
	int more_auth = 0;
	int err, i;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_HC_SCHEME_VERSION)
		return (-1);

	/* Get authority, if present */
	err = nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &anvl);
	if (err != 0 && err != ENOENT)
		return (-1);

	if ((err = nvlist_lookup_string(nvl, FM_FMRI_HC_ROOT, &root)) != 0)
		return (-1);

	err = nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcprs, &hcnprs);
	if (err != 0 || hcprs == NULL)
		return (-1);

	if (anvl != NULL) {
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_PRODUCT, &aprod);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_CHASSIS, &achas);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_DOMAIN, &adom);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_SERVER, &asrvr);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_HOST, &ahost);
		if (aprod != NULL)
			more_auth++;
		if (achas != NULL)
			more_auth++;
		if (adom != NULL)
			more_auth++;
		if (asrvr != NULL)
			more_auth++;
		if (ahost != NULL)
			more_auth++;
	}

	(void) nvlist_lookup_string(nvl, FM_FMRI_HC_SERIAL_ID, &serial);
	(void) nvlist_lookup_string(nvl, FM_FMRI_HC_PART, &part);
	(void) nvlist_lookup_string(nvl, FM_FMRI_HC_REVISION, &rev);

	/* hc:// */
	topo_fmristr_build(&size, buf, buflen, FM_FMRI_SCHEME_HC, NULL, "://");

	/* authority, if any */
	if (aprod != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, aprod, ":" FM_FMRI_AUTH_PRODUCT "=", NULL);
	if (achas != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, achas, ":" FM_FMRI_AUTH_CHASSIS "=", NULL);
	if (adom != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, adom, ":" FM_FMRI_AUTH_DOMAIN "=", NULL);
	if (asrvr != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, asrvr, ":" FM_FMRI_AUTH_SERVER "=", NULL);
	if (ahost != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, ahost, ":" FM_FMRI_AUTH_HOST "=", NULL);

	/* hardware-id part */
	topo_fmristr_build(&size,
	    buf, buflen, serial, ":" FM_FMRI_HC_SERIAL_ID "=", NULL);
	topo_fmristr_build(&size,
	    buf, buflen, part, ":" FM_FMRI_HC_PART "=", NULL);
	topo_fmristr_build(&size,
	    buf, buflen, rev, ":" FM_FMRI_HC_REVISION "=", NULL);

	/* separating slash */
	topo_fmristr_build(&size, buf, buflen, "/", NULL, NULL);

	/* hc-root */
	topo_fmristr_build(&size, buf, buflen, root, NULL, NULL);

	/* all the pairs */
	for (i = 0; i < hcnprs; i++) {
		char *nm = NULL;
		char *id = NULL;

		if (i > 0)
			topo_fmristr_build(&size,
			    buf, buflen, "/", NULL, NULL);
		(void) nvlist_lookup_string(hcprs[i], FM_FMRI_HC_NAME, &nm);
		(void) nvlist_lookup_string(hcprs[i], FM_FMRI_HC_ID, &id);
		if (nm == NULL || id == NULL)
			return (0);
		topo_fmristr_build(&size, buf, buflen, nm, NULL, "=");
		topo_fmristr_build(&size, buf, buflen, id, NULL, NULL);
	}

	return (size);
}

/*ARGSUSED*/
static int
hc_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	ssize_t len;
	char *name = NULL;
	nvlist_t *fmristr;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if ((len = fmri_nvl2str(nvl, NULL, 0)) == 0 ||
	    (name = topo_mod_alloc(mod, len + 1)) == NULL ||
	    fmri_nvl2str(nvl, name, len + 1) == 0) {
		if (name != NULL)
			topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	if (topo_mod_nvalloc(mod, &fmristr, NV_UNIQUE_NAME) != 0) {
		topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	if (nvlist_add_string(fmristr, "fmri-string", name) != 0) {
		topo_mod_free(mod, name, len + 1);
		nvlist_free(fmristr);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	topo_mod_free(mod, name, len + 1);
	*out = fmristr;

	return (0);
}

static nvlist_t *
hc_base_fmri_create(topo_mod_t *mod, const nvlist_t *auth, const char *part,
    const char *rev, const char *serial)
{
	nvlist_t *fmri;
	int err = 0;

	/*
	 * Create base HC nvlist
	 */
	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0)
		return (NULL);

	err = nvlist_add_uint8(fmri, FM_VERSION, FM_HC_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC);
	err |= nvlist_add_string(fmri, FM_FMRI_HC_ROOT, "");
	if (err != 0) {
		nvlist_free(fmri);
		return (NULL);
	}

	/*
	 * Add optional payload members
	 */
	if (serial != NULL)
		(void) nvlist_add_string(fmri, FM_FMRI_HC_SERIAL_ID, serial);
	if (part != NULL)
		(void) nvlist_add_string(fmri, FM_FMRI_HC_PART, part);
	if (rev != NULL)
		(void) nvlist_add_string(fmri, FM_FMRI_HC_REVISION, rev);
	if (auth != NULL)
		(void) nvlist_add_nvlist(fmri, FM_FMRI_AUTHORITY,
		    (nvlist_t *)auth);

	return (fmri);
}

static nvlist_t **
make_hc_pairs(topo_mod_t *mod, char *fmri, int *num)
{
	nvlist_t **pa;
	char *hc, *fromstr;
	char *starti, *startn, *endi, *endi2;
	char *ne, *ns;
	char *cname = NULL;
	char *find;
	char *cid = NULL;
	int nslashes = 0;
	int npairs = 0;
	int i, hclen;

	if ((hc = topo_mod_strdup(mod, fmri + 5)) == NULL)
		return (NULL);

	hclen = strlen(hc) + 1;

	/*
	 * Count equal signs and slashes to determine how many
	 * hc-pairs will be present in the final FMRI.  There should
	 * be at least as many slashes as equal signs.  There can be
	 * more, though if the string after an = includes them.
	 */
	if ((fromstr = strchr(hc, '/')) == NULL)
		return (NULL);

	find = fromstr;
	while ((ne = strchr(find, '=')) != NULL) {
		find = ne + 1;
		npairs++;
	}

	find = fromstr;
	while ((ns = strchr(find, '/')) != NULL) {
		find = ns + 1;
		nslashes++;
	}

	/*
	 * Do we appear to have a well-formed string version of the FMRI?
	 */
	if (nslashes < npairs || npairs == 0) {
		topo_mod_free(mod, hc, hclen);
		return (NULL);
	}

	*num = npairs;

	find = fromstr;

	if ((pa = topo_mod_zalloc(mod, npairs * sizeof (nvlist_t *))) == NULL) {
		topo_mod_free(mod, hc, hclen);
		return (NULL);
	}

	/*
	 * We go through a pretty complicated procedure to find the
	 * name and id for each pair.  That's because, unfortunately,
	 * we have some ids that can have slashes within them.  So
	 * we can't just search for the next slash after the equal sign
	 * and decide that starts a new pair.  Instead we have to find
	 * an equal sign for the next pair and work our way back to the
	 * slash from there.
	 */
	for (i = 0; i < npairs; i++) {
		startn = strchr(find, '/');
		if (startn == NULL)
			break;
		startn++;
		starti = strchr(find, '=');
		if (starti == NULL)
			break;
		*starti = '\0';
		if ((cname = topo_mod_strdup(mod, startn)) == NULL)
			break;
		*starti++ = '=';
		endi = strchr(starti, '=');
		if (endi != NULL) {
			*endi = '\0';
			endi2 = strrchr(starti, '/');
			if (endi2 == NULL)
				break;
			*endi = '=';
			*endi2 = '\0';
			if ((cid = topo_mod_strdup(mod, starti)) == NULL)
				break;
			*endi2 = '/';
			find = endi2;
		} else {
			if ((cid = topo_mod_strdup(mod, starti)) == NULL)
				break;
			find = starti + strlen(starti);
		}
		if (topo_mod_nvalloc(mod, &pa[i], NV_UNIQUE_NAME) < 0)
			break;

		if (nvlist_add_string(pa[i], FM_FMRI_HC_NAME, cname) ||
		    nvlist_add_string(pa[i], FM_FMRI_HC_ID, cid))
			break;

		topo_mod_strfree(mod, cname);
		topo_mod_strfree(mod, cid);
		cname = NULL;
		cid = NULL;
	}

	topo_mod_strfree(mod, cname);
	topo_mod_strfree(mod, cid);

	if (i < npairs) {
		for (i = 0; i < npairs; i++)
			nvlist_free(pa[i]);
		topo_mod_free(mod, pa, npairs * sizeof (nvlist_t *));
		topo_mod_free(mod, hc, hclen);
		return (NULL);
	}

	topo_mod_free(mod, hc, hclen);

	return (pa);
}

void
make_hc_auth(topo_mod_t *mod, char *fmri, char **serial, char **part,
char **rev, nvlist_t **auth)
{
	char *starti, *startn, *endi, *copy;
	char *aname, *aid, *fs;
	nvlist_t *na = NULL;
	size_t len;

	if ((copy = topo_mod_strdup(mod, fmri + 5)) == NULL)
		return;

	len = strlen(copy);

	/*
	 * Make sure there are a valid authority members
	 */
	startn = strchr(copy, ':');
	fs = strchr(copy, '/');

	if (startn == NULL || fs == NULL) {
		topo_mod_strfree(mod, copy);
		return;
	}

	/*
	 * The first colon we encounter must occur before the
	 * first slash
	 */
	if (startn > fs)
		return;

	do {
		if (++startn >= copy + len)
			break;

		if ((starti = strchr(startn, '=')) == NULL)
			break;

		*starti = '\0';
		if (++starti > copy + len)
			break;

		if ((aname = topo_mod_strdup(mod, startn)) == NULL)
			break;

		startn = endi = strchr(starti, ':');
		if (endi == NULL)
			if ((endi = strchr(starti, '/')) == NULL)
				break;

		*endi = '\0';
		if ((aid = topo_mod_strdup(mod, starti)) == NULL) {
			topo_mod_strfree(mod, aname);
			break;
		}

		/*
		 * Return possible serial, part and revision
		 */
		if (strcmp(aname, FM_FMRI_HC_SERIAL_ID) == 0) {
			*serial = topo_mod_strdup(mod, aid);
		} else if (strcmp(aname, FM_FMRI_HC_PART) == 0) {
			*part = topo_mod_strdup(mod, aid);
		} else if (strcmp(aname, FM_FMRI_HC_REVISION) == 0) {
			*rev = topo_mod_strdup(mod, aid);
		} else {
			if (na == NULL) {
				if (topo_mod_nvalloc(mod, &na,
				    NV_UNIQUE_NAME) == 0) {
					(void) nvlist_add_string(na, aname,
					    aid);
				}
			} else {
				(void) nvlist_add_string(na, aname, aid);
			}
		}
		topo_mod_strfree(mod, aname);
		topo_mod_strfree(mod, aid);

	} while (startn != NULL);

	*auth = na;

	topo_mod_free(mod, copy, len + 1);
}

/*ARGSUSED*/
static int
hc_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t **pa = NULL;
	nvlist_t *nf = NULL;
	nvlist_t *auth = NULL;
	char *str;
	char *serial = NULL, *part = NULL, *rev = NULL;
	int npairs;
	int i, e;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, "fmri-string", &str) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	/* We're expecting a string version of an hc scheme FMRI */
	if (strncmp(str, "hc://", 5) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if ((pa = make_hc_pairs(mod, str, &npairs)) == NULL)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	make_hc_auth(mod, str, &serial, &part, &rev, &auth);
	if ((nf = hc_base_fmri_create(mod, auth, part, rev, serial)) == NULL)
		goto hcfmbail;
	if ((e = nvlist_add_uint32(nf, FM_FMRI_HC_LIST_SZ, npairs)) == 0)
		e = nvlist_add_nvlist_array(nf, FM_FMRI_HC_LIST, pa, npairs);
	if (e != 0) {
		topo_mod_dprintf(mod, "construction of new hc nvl failed");
		goto hcfmbail;
	}
	for (i = 0; i < npairs; i++)
		nvlist_free(pa[i]);
	topo_mod_free(mod, pa, npairs * sizeof (nvlist_t *));
	if (serial != NULL)
		topo_mod_strfree(mod, serial);
	if (part != NULL)
		topo_mod_strfree(mod, part);
	if (rev != NULL)
		topo_mod_strfree(mod, rev);
	nvlist_free(auth);

	*out = nf;

	return (0);

hcfmbail:
	if (nf != NULL)
		nvlist_free(nf);
	for (i = 0; i < npairs; i++)
		nvlist_free(pa[i]);
	topo_mod_free(mod, pa, npairs * sizeof (nvlist_t *));
	if (serial != NULL)
		topo_mod_strfree(mod, serial);
	if (part != NULL)
		topo_mod_strfree(mod, part);
	if (rev != NULL)
		topo_mod_strfree(mod, rev);
	nvlist_free(auth);
	return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));
}

static nvlist_t *
hc_list_create(topo_mod_t *mod, const char *name, char *inst)
{
	int err;
	nvlist_t *hc;

	if (topo_mod_nvalloc(mod, &hc, NV_UNIQUE_NAME) != 0)
		return (NULL);

	err = nvlist_add_string(hc, FM_FMRI_HC_NAME, name);
	err |= nvlist_add_string(hc, FM_FMRI_HC_ID, inst);
	if (err != 0) {
		nvlist_free(hc);
		return (NULL);
	}

	return (hc);
}

static nvlist_t *
hc_create_seterror(topo_mod_t *mod, nvlist_t **hcl, int n, nvlist_t *fmri,
    int err)
{
	int i;

	if (hcl != NULL) {
		for (i = 0; i < n + 1; ++i)
			nvlist_free(hcl[i]);

		topo_mod_free(mod, hcl, sizeof (nvlist_t *) * (n + 1));
	}

	nvlist_free(fmri);

	(void) topo_mod_seterrno(mod, err);

	topo_mod_dprintf(mod, "unable to create hc FMRI: %s\n",
	    topo_mod_errmsg(mod));

	return (NULL);
}

static int
hc_name_canonical(topo_mod_t *mod, const char *name)
{
	int i;

	if (getenv("NOHCCHECK") != NULL)
		return (1);

	/*
	 * Only enumerate elements with correct canonical names
	 */
	for (i = 0; i < hc_ncanon; i++) {
		if (strcmp(name, hc_canon[i].hcc_name) == 0)
			break;
	}
	if (i >= hc_ncanon) {
		topo_mod_dprintf(mod, "non-canonical name %s\n",
		    name);
		return (0);
	} else {
		return (1);
	}
}

static nvlist_t *
hc_fmri_create(topo_mod_t *mod, nvlist_t *pfmri, int version, const char *name,
    topo_instance_t inst, const nvlist_t *auth, const char *part,
    const char *rev, const char *serial)
{
	int i;
	char str[21]; /* sizeof (UINT64_MAX) + '\0' */
	uint_t pelems = 0;
	nvlist_t **phcl = NULL;
	nvlist_t **hcl = NULL;
	nvlist_t *fmri = NULL;

	if (version > FM_HC_SCHEME_VERSION)
		return (hc_create_seterror(mod,
		    hcl, pelems, fmri, EMOD_VER_OLD));
	else if (version < FM_HC_SCHEME_VERSION)
		return (hc_create_seterror(mod,
		    hcl, pelems, fmri, EMOD_VER_NEW));

	/*
	 * Check that the requested name is in our canonical list
	 */
	if (hc_name_canonical(mod, name) == 0)
		return (hc_create_seterror(mod,
		    hcl, pelems, fmri, EMOD_NONCANON));
	/*
	 * Copy the parent's HC_LIST
	 */
	if (pfmri != NULL) {
		if (nvlist_lookup_nvlist_array(pfmri, FM_FMRI_HC_LIST,
		    &phcl, &pelems) != 0)
			return (hc_create_seterror(mod,
			    hcl, pelems, fmri, EMOD_FMRI_MALFORM));
	}

	hcl = topo_mod_zalloc(mod, sizeof (nvlist_t *) * (pelems + 1));
	if (hcl == NULL)
		return (hc_create_seterror(mod,  hcl, pelems, fmri,
		    EMOD_NOMEM));

	for (i = 0; i < pelems; ++i)
		if (topo_mod_nvdup(mod, phcl[i], &hcl[i]) != 0)
			return (hc_create_seterror(mod,
			    hcl, pelems, fmri, EMOD_FMRI_NVL));

	(void) snprintf(str, sizeof (str), "%d", inst);
	if ((hcl[i] = hc_list_create(mod, name, str)) == NULL)
		return (hc_create_seterror(mod,
		    hcl, pelems, fmri, EMOD_FMRI_NVL));

	if ((fmri = hc_base_fmri_create(mod, auth, part, rev, serial)) == NULL)
		return (hc_create_seterror(mod,
		    hcl, pelems, fmri, EMOD_FMRI_NVL));

	if (nvlist_add_nvlist_array(fmri, FM_FMRI_HC_LIST, hcl, pelems + 1)
	    != 0)
		return (hc_create_seterror(mod,
		    hcl, pelems, fmri, EMOD_FMRI_NVL));

	if (hcl != NULL) {
		for (i = 0; i < pelems + 1; ++i) {
			if (hcl[i] != NULL)
				nvlist_free(hcl[i]);
		}
		topo_mod_free(mod, hcl, sizeof (nvlist_t *) * (pelems + 1));
	}

	return (fmri);
}

/*ARGSUSED*/
static int
hc_fmri_create_meth(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int ret;
	nvlist_t *args, *pfmri = NULL;
	nvlist_t *auth;
	uint32_t inst;
	char *name, *serial, *rev, *part;

	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	/* First the must-have fields */
	if (nvlist_lookup_string(in, TOPO_METH_FMRI_ARG_NAME, &name) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	if (nvlist_lookup_uint32(in, TOPO_METH_FMRI_ARG_INST, &inst) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	/*
	 * args is optional
	 */
	pfmri = NULL;
	auth = NULL;
	serial = rev = part = NULL;
	if ((ret = nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NVL, &args))
	    != 0) {
		if (ret != ENOENT)
			return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	} else {

		/* And then optional arguments */
		(void) nvlist_lookup_nvlist(args, TOPO_METH_FMRI_ARG_PARENT,
		    &pfmri);
		(void) nvlist_lookup_nvlist(args, TOPO_METH_FMRI_ARG_AUTH,
		    &auth);
		(void) nvlist_lookup_string(args, TOPO_METH_FMRI_ARG_PART,
		    &part);
		(void) nvlist_lookup_string(args, TOPO_METH_FMRI_ARG_REV, &rev);
		(void) nvlist_lookup_string(args, TOPO_METH_FMRI_ARG_SER,
		    &serial);
	}

	*out = hc_fmri_create(mod, pfmri, version, name, inst, auth, part,
	    rev, serial);
	if (*out == NULL)
		return (-1);
	return (0);
}

struct hc_walk {
	topo_mod_walk_cb_t hcw_cb;
	void *hcw_priv;
	topo_walk_t *hcw_wp;
	nvlist_t **hcw_list;
	uint_t hcw_index;
	uint_t hcw_end;
};

/*
 * Generic walker for the hc-scheme topo tree.  This function uses the
 * hierachical nature of the hc-scheme to step through efficiently through
 * the topo hc tree.  Node lookups are done by topo_walk_byid() and
 * topo_walk_bysibling()  at each component level to avoid unnecessary
 * traversal of the tree.  hc_walker() never returns TOPO_WALK_NEXT, so
 * whether TOPO_WALK_CHILD or TOPO_WALK_SIBLING is specified by
 * topo_walk_step() doesn't affect the traversal.
 */
static int
hc_walker(topo_mod_t *mod, tnode_t *node, void *pdata)
{
	int i, err;
	struct hc_walk *hwp = (struct hc_walk *)pdata;
	char *name, *id;
	topo_instance_t inst;

	i = hwp->hcw_index;
	if (i > hwp->hcw_end) {
		(void) topo_mod_seterrno(mod, ETOPO_PROP_NOENT);
		return (TOPO_WALK_TERMINATE);
	}

	err = nvlist_lookup_string(hwp->hcw_list[i], FM_FMRI_HC_NAME, &name);
	err |= nvlist_lookup_string(hwp->hcw_list[i], FM_FMRI_HC_ID, &id);

	if (err != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (TOPO_WALK_ERR);
	}

	inst = atoi(id);

	/*
	 * Special case for the root node.  We need to walk by siblings
	 * until we find a matching node for cases where there may be multiple
	 * nodes just below the hc root.
	 */
	if (i == 0) {
		if (strcmp(name, topo_node_name(node)) != 0 ||
		    inst != topo_node_instance(node)) {
			return (topo_walk_bysibling(hwp->hcw_wp, name, inst));
		}
	}

	topo_mod_dprintf(mod, "hc_walker: walking node:%s=%d for hc:"
	    "%s=%d at %d, end at %d \n", topo_node_name(node),
	    topo_node_instance(node), name, inst, i, hwp->hcw_end);
	if (i == hwp->hcw_end) {
		/*
		 * We are at the end of the hc-list.  Verify that
		 * the last node contains the name/instance we are looking for.
		 */
		if (strcmp(topo_node_name(node), name) == 0 &&
		    inst == topo_node_instance(node)) {
			if ((err = hwp->hcw_cb(mod, node, hwp->hcw_priv))
			    != 0) {
				(void) topo_mod_seterrno(mod, err);
				topo_mod_dprintf(mod, "hc_walker: callback "
				    "failed: %s\n ", topo_mod_errmsg(mod));
				return (TOPO_WALK_ERR);
			}
			topo_mod_dprintf(mod, "hc_walker: callback "
			    "complete: terminate walk\n");
			return (TOPO_WALK_TERMINATE);
		} else {
			topo_mod_dprintf(mod, "hc_walker: %s=%d\n "
			    "not found\n", name, inst);
			return (TOPO_WALK_TERMINATE);
		}
	}

	hwp->hcw_index = ++i;
	err = nvlist_lookup_string(hwp->hcw_list[i], FM_FMRI_HC_NAME, &name);
	err |= nvlist_lookup_string(hwp->hcw_list[i], FM_FMRI_HC_ID, &id);
	if (err != 0) {
		(void) topo_mod_seterrno(mod, err);
		return (TOPO_WALK_ERR);
	}
	inst = atoi(id);

	topo_mod_dprintf(mod, "hc_walker: walk byid of %s=%d \n", name,
	    inst);
	return (topo_walk_byid(hwp->hcw_wp, name, inst));

}

static struct hc_walk *
hc_walk_init(topo_mod_t *mod, tnode_t *node, nvlist_t *rsrc,
    topo_mod_walk_cb_t cb, void *pdata)
{
	int err;
	uint_t sz;
	struct hc_walk *hwp;
	topo_walk_t *wp;

	if ((hwp = topo_mod_alloc(mod, sizeof (struct hc_walk))) == NULL)
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);

	if (nvlist_lookup_nvlist_array(rsrc, FM_FMRI_HC_LIST, &hwp->hcw_list,
	    &sz) != 0) {
		topo_mod_free(mod, hwp, sizeof (struct hc_walk));
		(void) topo_mod_seterrno(mod, EMOD_METHOD_INVAL);
		return (NULL);
	}

	hwp->hcw_end = sz - 1;
	hwp->hcw_index = 0;
	hwp->hcw_priv = pdata;
	hwp->hcw_cb = cb;
	if ((wp = topo_mod_walk_init(mod, node, hc_walker, (void *)hwp, &err))
	    == NULL) {
		topo_mod_free(mod, hwp, sizeof (struct hc_walk));
		(void) topo_mod_seterrno(mod, err);
		return (NULL);
	}

	hwp->hcw_wp = wp;

	return (hwp);
}

struct prop_lookup {
	const char *pl_pgroup;
	const char *pl_pname;
	int pl_flag;
	nvlist_t *pl_args;
	nvlist_t *pl_rsrc;
	nvlist_t *pl_prop;
};

/*ARGSUSED*/
static int
hc_prop_get(topo_mod_t *mod, tnode_t *node, void *pdata)
{
	int err = 0;

	struct prop_lookup *plp = (struct prop_lookup *)pdata;

	(void) topo_prop_getprop(node, plp->pl_pgroup, plp->pl_pname,
	    plp->pl_args, &plp->pl_prop, &err);

	return (err);
}

static int
hc_fmri_prop_get(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int err;
	struct hc_walk *hwp;
	struct prop_lookup *plp;

	if (version > TOPO_METH_PROP_GET_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if ((plp = topo_mod_alloc(mod, sizeof (struct prop_lookup))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	err = nvlist_lookup_string(in, TOPO_PROP_GROUP,
	    (char **)&plp->pl_pgroup);
	err |= nvlist_lookup_string(in, TOPO_PROP_VAL_NAME,
	    (char **)&plp->pl_pname);
	err |= nvlist_lookup_nvlist(in, TOPO_PROP_RESOURCE, &plp->pl_rsrc);
	if (err != 0) {
		topo_mod_free(mod, plp, sizeof (struct prop_lookup));
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	}

	/*
	 * Private args to prop method are optional
	 */
	if ((err = nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &plp->pl_args))
	    != 0) {
		if (err != ENOENT) {
			topo_mod_free(mod, plp, sizeof (struct prop_lookup));
			return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
		} else {
			plp->pl_args = NULL;
		}
	}

	plp->pl_prop = NULL;
	if ((hwp = hc_walk_init(mod, node, plp->pl_rsrc, hc_prop_get,
	    (void *)plp)) != NULL) {
		if (topo_walk_step(hwp->hcw_wp, TOPO_WALK_CHILD) ==
		    TOPO_WALK_ERR)
			err = -1;
		else
			err = 0;
		topo_walk_fini(hwp->hcw_wp);
	} else {
		err = -1;
	}

	topo_mod_free(mod, hwp, sizeof (struct hc_walk));

	if (plp->pl_prop != NULL)
		*out = plp->pl_prop;

	topo_mod_free(mod, plp, sizeof (struct prop_lookup));

	return (err);
}

/*ARGSUSED*/
static int
hc_pgrp_get(topo_mod_t *mod, tnode_t *node, void *pdata)
{
	int err = 0;

	struct prop_lookup *plp = (struct prop_lookup *)pdata;

	(void) topo_prop_getpgrp(node, plp->pl_pgroup, &plp->pl_prop, &err);

	return (err);
}

static int
hc_fmri_pgrp_get(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int err;
	struct hc_walk *hwp;
	struct prop_lookup *plp;

	if (version > TOPO_METH_PGRP_GET_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if ((plp = topo_mod_alloc(mod, sizeof (struct prop_lookup))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	err = nvlist_lookup_string(in, TOPO_PROP_GROUP,
	    (char **)&plp->pl_pgroup);
	err |= nvlist_lookup_nvlist(in, TOPO_PROP_RESOURCE, &plp->pl_rsrc);
	if (err != 0) {
		topo_mod_free(mod, plp, sizeof (struct prop_lookup));
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	}

	plp->pl_prop = NULL;
	if ((hwp = hc_walk_init(mod, node, plp->pl_rsrc, hc_pgrp_get,
	    (void *)plp)) != NULL) {
		if (topo_walk_step(hwp->hcw_wp, TOPO_WALK_CHILD) ==
		    TOPO_WALK_ERR)
			err = -1;
		else
			err = 0;
		topo_walk_fini(hwp->hcw_wp);
	} else {
		err = -1;
	}

	topo_mod_free(mod, hwp, sizeof (struct hc_walk));

	if (plp->pl_prop != NULL)
		*out = plp->pl_prop;

	topo_mod_free(mod, plp, sizeof (struct prop_lookup));

	return (err);
}

/*ARGSUSED*/
static int
hc_prop_setprop(topo_mod_t *mod, tnode_t *node, void *pdata)
{
	int err = 0;

	struct prop_lookup *plp = (struct prop_lookup *)pdata;

	(void) topo_prop_setprop(node, plp->pl_pgroup, plp->pl_prop,
	    plp->pl_flag, plp->pl_args, &err);

	return (err);
}

/*ARGSUSED*/
static int
hc_fmri_prop_set(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int err;
	struct hc_walk *hwp;
	struct prop_lookup *plp;

	if (version > TOPO_METH_PROP_SET_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if ((plp = topo_mod_alloc(mod, sizeof (struct prop_lookup))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	err = nvlist_lookup_string(in, TOPO_PROP_GROUP,
	    (char **)&plp->pl_pgroup);
	err |= nvlist_lookup_nvlist(in, TOPO_PROP_RESOURCE, &plp->pl_rsrc);
	err |= nvlist_lookup_nvlist(in, TOPO_PROP_VAL, &plp->pl_prop);
	err |= nvlist_lookup_int32(in, TOPO_PROP_FLAG, &plp->pl_flag);
	if (err != 0) {
		topo_mod_free(mod, plp, sizeof (struct prop_lookup));
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	}

	/*
	 * Private args to prop method are optional
	 */
	if ((err = nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &plp->pl_args))
	    != 0) {
		if (err != ENOENT)
			return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
		else
			plp->pl_args = NULL;
	}

	if ((hwp = hc_walk_init(mod, node, plp->pl_rsrc, hc_prop_setprop,
	    (void *)plp)) != NULL) {
		if (topo_walk_step(hwp->hcw_wp, TOPO_WALK_CHILD) ==
		    TOPO_WALK_ERR)
			err = -1;
		else
			err = 0;
		topo_walk_fini(hwp->hcw_wp);
	} else {
		err = -1;
	}

	topo_mod_free(mod, hwp, sizeof (struct hc_walk));
	topo_mod_free(mod, plp, sizeof (struct prop_lookup));

	return (err);
}

struct hc_args {
	nvlist_t *ha_fmri;
	nvlist_t *ha_nvl;
};

static int
hc_is_present(topo_mod_t *mod, tnode_t *node, void *pdata)
{
	int err;
	struct hc_args *hap = (struct hc_args *)pdata;

	/*
	 * check with the enumerator that created this FMRI
	 * (topo node)
	 */
	if (topo_method_invoke(node, TOPO_METH_PRESENT,
	    TOPO_METH_PRESENT_VERSION, hap->ha_fmri, &hap->ha_nvl,
	    &err) < 0) {

		/*
		 * Err on the side of caution and return present
		 */
		if (topo_mod_nvalloc(mod, &hap->ha_nvl, NV_UNIQUE_NAME) == 0)
			if (nvlist_add_uint32(hap->ha_nvl,
			    TOPO_METH_PRESENT_RET, 1) == 0)
				return (0);

		return (ETOPO_PROP_NVL);
	}

	return (0);
}

static int
hc_fmri_present(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int err;
	struct hc_walk *hwp;
	struct hc_args *hap;

	if (version > TOPO_METH_PRESENT_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if ((hap = topo_mod_alloc(mod, sizeof (struct hc_args))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	hap->ha_fmri = in;
	hap->ha_nvl = NULL;
	if ((hwp = hc_walk_init(mod, node, hap->ha_fmri, hc_is_present,
	    (void *)hap)) != NULL) {
		if (topo_walk_step(hwp->hcw_wp, TOPO_WALK_CHILD) ==
		    TOPO_WALK_ERR)
			err = -1;
		else
			err = 0;
		topo_walk_fini(hwp->hcw_wp);
	} else {
		err = -1;
	}

	topo_mod_free(mod, hwp, sizeof (struct hc_walk));

	if (hap->ha_nvl != NULL)
		*out = hap->ha_nvl;

	topo_mod_free(mod, hap, sizeof (struct hc_args));

	return (err);
}

static int
hc_unusable(topo_mod_t *mod, tnode_t *node, void *pdata)
{
	int err;
	struct hc_args *hap = (struct hc_args *)pdata;

	/*
	 * check with the enumerator that created this FMRI
	 * (topo node)
	 */
	if (topo_method_invoke(node, TOPO_METH_UNUSABLE,
	    TOPO_METH_UNUSABLE_VERSION, hap->ha_fmri, &hap->ha_nvl,
	    &err) < 0) {

		/*
		 * Err on the side of caution and return usable
		 */
		if (topo_mod_nvalloc(mod, &hap->ha_nvl, NV_UNIQUE_NAME) == 0)
			if (nvlist_add_uint32(hap->ha_nvl,
			    TOPO_METH_UNUSABLE_RET, 0) == 0)
				return (0);

		return (ETOPO_PROP_NVL);
	}

	return (err);
}

static int
hc_fmri_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	int err;
	struct hc_walk *hwp;
	struct hc_args *hap;

	if (version > TOPO_METH_UNUSABLE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if ((hap = topo_mod_alloc(mod, sizeof (struct hc_args))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	hap->ha_fmri = in;
	hap->ha_nvl = NULL;
	if ((hwp = hc_walk_init(mod, node, hap->ha_fmri, hc_unusable,
	    (void *)hap)) != NULL) {
		if (topo_walk_step(hwp->hcw_wp, TOPO_WALK_CHILD) ==
		    TOPO_WALK_ERR)
			err = -1;
		else
			err = 0;
		topo_walk_fini(hwp->hcw_wp);
	} else {
		err = -1;
	}

	topo_mod_free(mod, hwp, sizeof (struct hc_walk));

	if (hap->ha_nvl != NULL)
		*out = hap->ha_nvl;

	topo_mod_free(mod, hap, sizeof (struct hc_args));

	return (err);
}
