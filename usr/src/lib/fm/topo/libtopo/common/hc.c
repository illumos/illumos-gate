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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/param.h>
#include <sys/systeminfo.h>
#include <sys/fm/protocol.h>
#include <topo_parse.h>

#include <hc_canon.h>

#define	HC			"hc"
#define	HC_VERSION		TOPO_VERSION

static int hc_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *);
static void hc_release(topo_mod_t *, tnode_t *);
static int hc_contains(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hc_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hc_unusable(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hc_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int hc_fmri_str2nvl(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int hc_compare(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int hc_fmri_create_meth(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static nvlist_t *hc_fmri_create(topo_mod_t *, nvlist_t *, int, const char *,
    topo_instance_t inst, const nvlist_t *, const char *, const char *,
    const char *);

const topo_method_t hc_methods[] = {
	{ "hc_contains", "Hardware Component Contains", HC_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_contains },
	{ "hc_present", "Hardware Component Present", HC_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_present },
	{ "hc_unusable", "Hardware Component Unusable", HC_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_unusable },
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_fmri_nvl2str },
	{ TOPO_METH_STR2NVL, TOPO_METH_STR2NVL_DESC, TOPO_METH_STR2NVL_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_fmri_str2nvl },
	{ TOPO_METH_COMPARE, TOPO_METH_COMPARE_DESC, TOPO_METH_COMPARE_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_compare },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, hc_fmri_create_meth },
	{ NULL }
};

const topo_modinfo_t hc_info =
	{ HC, HC_VERSION, hc_enum, hc_release };

void
hc_init(topo_mod_t *mp)
{
	/*
	 * Turn on module debugging output
	 */
	topo_mod_setdebug(mp, TOPO_DBG_ALL);
	topo_mod_dprintf(mp, "initializing hc builtin\n");

	if (topo_mod_register(mp, &hc_info, NULL) != 0) {
		topo_mod_dprintf(mp, "failed to register hc: "
		    "%s\n", topo_mod_errmsg(mp));
	}
}

void
hc_fini(topo_mod_t *mp)
{
	topo_mod_unregister(mp);
}

/*ARGSUSED*/
int
hc_enum(topo_mod_t *mp, tnode_t *pnode, const char *name, topo_instance_t min,
    topo_instance_t max, void *notused)
{
	nvlist_t *pfmri = NULL;
	nvlist_t *nvl;
	int err;
	/*
	 * Register root node methods
	 */
	if (strcmp(name, HC) == 0) {
		(void) topo_method_register(mp, pnode, hc_methods);
		return (0);
	}
	if (min != max) {
		topo_mod_dprintf(mp,
		    "Request to enumerate %s component with an "
		    "ambiguous instance number, min (%d) != max (%d).\n",
		    HC, min, max);
		return (topo_mod_seterrno(mp, EINVAL));
	}

	(void) topo_node_resource(pnode, &pfmri, &err);
	nvl = hc_fmri_create(mp, pfmri, FM_HC_SCHEME_VERSION, name, min,
	    NULL, NULL, NULL, NULL);
	nvlist_free(pfmri);	/* callee ignores NULLs */
	if (nvl == NULL)
		return (-1);

	if (topo_node_bind(mp, pnode, name, min, nvl, NULL) == NULL) {
		topo_mod_dprintf(mp, "topo_node_bind failed: %s\n",
		    topo_strerror(topo_mod_errno(mp)));
		nvlist_free(nvl);
		return (-1);
	}
	nvlist_free(nvl);
	return (0);
}

/*ARGSUSED*/
static void
hc_release(topo_mod_t *mp, tnode_t *node)
{
	topo_method_unregister_all(mp, node);
}

/*ARGSUSED*/
static int
hc_contains(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (topo_mod_seterrno(mp, EMOD_METHOD_NOTSUP));
}

/*ARGSUSED*/
static int
hc_present(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (topo_mod_seterrno(mp, EMOD_METHOD_NOTSUP));
}

/*ARGSUSED*/
static int
hc_unusable(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	return (topo_mod_seterrno(mp, EMOD_METHOD_NOTSUP));
}

/*ARGSUSED*/
static int
hc_compare(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t v1, v2;
	nvlist_t *nv1, *nv2;
	nvlist_t **hcp1, **hcp2;
	int err, i;
	uint_t nhcp1, nhcp2;

	if (version > TOPO_METH_COMPARE_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));

	if (nvlist_lookup_nvlist(in, "nv1", &nv1) != 0 ||
	    nvlist_lookup_nvlist(in, "nv2", &nv2) != 0)
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));

	if (nvlist_lookup_uint8(nv1, FM_VERSION, &v1) != 0 ||
	    nvlist_lookup_uint8(nv2, FM_VERSION, &v2) != 0 ||
	    v1 > FM_HC_SCHEME_VERSION || v2 > FM_HC_SCHEME_VERSION)
		return (topo_mod_seterrno(mp, EMOD_FMRI_VERSION));

	err = nvlist_lookup_nvlist_array(nv1, FM_FMRI_HC_LIST, &hcp1, &nhcp1);
	err |= nvlist_lookup_nvlist_array(nv2, FM_FMRI_HC_LIST, &hcp2, &nhcp2);
	if (err != 0)
		return (topo_mod_seterrno(mp, EMOD_FMRI_NVL));

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
			return (topo_mod_seterrno(mp, EMOD_FMRI_NVL));

		if (strcmp(nm1, nm2) == 0 && strcmp(id1, id2) == 0)
			continue;

		return (0);
	}

	return (1);
}

/*
 * buf_append -- Append str to buf (if it's non-NULL).  Place prepend
 * in buf in front of str and append behind it (if they're non-NULL).
 * Continue to update size even if we run out of space to actually
 * stuff characters in the buffer.
 */
static void
buf_append(ssize_t *sz, char *buf, size_t buflen, char *str,
    char *prepend, char *append)
{
	ssize_t left;

	if (str == NULL)
		return;

	if (buflen == 0 || (left = buflen - *sz) < 0)
		left = 0;

	if (buf != NULL && left != 0)
		buf += *sz;

	if (prepend == NULL && append == NULL)
		*sz += snprintf(buf, left, "%s", str);
	else if (append == NULL)
		*sz += snprintf(buf, left, "%s%s", prepend, str);
	else if (prepend == NULL)
		*sz += snprintf(buf, left, "%s%s", str, append);
	else
		*sz += snprintf(buf, left, "%s%s%s", prepend, str, append);
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
	buf_append(&size, buf, buflen, FM_FMRI_SCHEME_HC, NULL, "://");

	/* authority, if any */
	if (aprod != NULL)
		buf_append(&size, buf, buflen, aprod, FM_FMRI_AUTH_PRODUCT "=",
		    --more_auth > 0 ? "," : NULL);
	if (achas != NULL)
		buf_append(&size, buf, buflen, achas, FM_FMRI_AUTH_CHASSIS "=",
		    --more_auth > 0 ? "," : NULL);
	if (adom != NULL)
		buf_append(&size, buf, buflen, adom, FM_FMRI_AUTH_DOMAIN "=",
		    --more_auth > 0 ? "," : NULL);
	if (asrvr != NULL)
		buf_append(&size, buf, buflen, asrvr, FM_FMRI_AUTH_SERVER "=",
		    --more_auth > 0 ? "," : NULL);
	if (ahost != NULL)
		buf_append(&size, buf, buflen, ahost, FM_FMRI_AUTH_HOST "=",
		    NULL);

	/* separating slash */
	if (serial != NULL || part != NULL || rev != NULL)
		buf_append(&size, buf, buflen, "/", NULL, NULL);

	/* hardware-id part */
	buf_append(&size, buf, buflen, serial, ":" FM_FMRI_HC_SERIAL_ID "=",
	    NULL);
	buf_append(&size, buf, buflen, part, ":" FM_FMRI_HC_PART "=", NULL);
	buf_append(&size, buf, buflen, rev, ":" FM_FMRI_HC_REVISION "=", NULL);

	/* separating slash */
	buf_append(&size, buf, buflen, "/", NULL, NULL);

	/* hc-root */
	buf_append(&size, buf, buflen, root, NULL, NULL);

	/* all the pairs */
	for (i = 0; i < hcnprs; i++) {
		char *nm = NULL;
		char *id = NULL;

		if (i > 0)
			buf_append(&size, buf, buflen, "/", NULL, NULL);
		(void) nvlist_lookup_string(hcprs[i], FM_FMRI_HC_NAME, &nm);
		(void) nvlist_lookup_string(hcprs[i], FM_FMRI_HC_ID, &id);
		if (nm == NULL || id == NULL)
			return (0);
		buf_append(&size, buf, buflen, nm, NULL, "=");
		buf_append(&size, buf, buflen, id, NULL, NULL);
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

	if (topo_mod_nvalloc(mod, &fmristr, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
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
make_hc_pairs(topo_mod_t *mod, char *fromstr, int *num)
{
	nvlist_t **pa;
	char *starti, *startn, *endi, *endi2;
	char *ne, *ns;
	char *cname;
	char *find;
	char *cid;
	int nslashes = 0;
	int npairs = 0;
	int i, e;

	/*
	 * Count equal signs and slashes to determine how many
	 * hc-pairs will be present in the final FMRI.  There should
	 * be at least as many slashes as equal signs.  There can be
	 * more, though if the string after an = includes them.
	 */
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
	if (nslashes < npairs || npairs == 0)
		return (NULL);

	*num = npairs;

	find = fromstr;

	pa = topo_mod_alloc(mod, npairs * sizeof (nvlist_t *));
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
		pa[i] = NULL;
		startn = strchr(find, '/');
		if (startn == NULL)
			break;
		startn++;
		starti = strchr(find, '=');
		if (starti == NULL)
			break;
		*starti = '\0';
		cname = topo_mod_strdup(mod, startn);
		*starti++ = '=';
		endi = strchr(starti, '=');
		if (endi != NULL) {
			*endi = '\0';
			endi2 = strrchr(starti, '/');
			if (endi2 == NULL)
				break;
			*endi = '=';
			*endi2 = '\0';
			cid = topo_mod_strdup(mod, starti);
			*endi2 = '/';
			find = endi2;
		} else {
			cid = topo_mod_strdup(mod, starti);
			find = starti + strlen(starti);
		}
		if ((e = topo_mod_nvalloc(mod, &pa[i], NV_UNIQUE_NAME)) != 0) {
			topo_mod_strfree(mod, cname);
			topo_mod_strfree(mod, cid);
			break;
		}

		e = nvlist_add_string(pa[i], FM_FMRI_HC_NAME, cname);
		e |= nvlist_add_string(pa[i], FM_FMRI_HC_ID, cid);

		topo_mod_strfree(mod, cname);
		topo_mod_strfree(mod, cid);

		if (e != 0) {
			break;
		}
	}
	if (i < npairs) {
		while (i >= 0)
			if (pa[i--] != NULL)
				nvlist_free(pa[i + 1]);
		topo_mod_free(mod, pa, npairs * sizeof (nvlist_t *));
		return (NULL);
	}

	return (pa);
}

/*ARGSUSED*/
static int
hc_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t **pa = NULL;
	nvlist_t *nf = NULL;
	char *str, *copy;
	int npairs;
	int i, e;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, "fmri-string", &str) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	/* We're expecting a string version of an hc scheme FMRI */
	if (strncmp(str, "hc:///", 6) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	copy = topo_mod_strdup(mod, str + 5);
	if ((pa = make_hc_pairs(mod, copy, &npairs)) == NULL) {
		topo_mod_strfree(mod, copy);
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));
	}
	topo_mod_strfree(mod, copy);

	if ((nf = hc_base_fmri_create(mod, NULL, NULL, NULL, NULL)) == NULL)
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
	*out = nf;

	return (0);

hcfmbail:
	if (nf != NULL)
		nvlist_free(nf);
	for (i = 0; i < npairs; i++)
		nvlist_free(pa[i]);
	topo_mod_free(mod, pa, npairs * sizeof (nvlist_t *));
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
hc_name_canonical(const char *name)
{
	int i;
	/*
	 * Only enumerate elements with correct canonical names
	 */
	for (i = 0; i < Hc_ncanon; i++) {
		if (strcmp(name, Hc_canon[i]) == 0)
			break;
	}
	if (i >= Hc_ncanon)
		return (0);
	else
		return (1);
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
	if (hc_name_canonical(name) == 0)
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
hc_fmri_create_meth(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *args, *pfmri;
	nvlist_t *auth;
	uint32_t inst;
	char *name, *serial, *rev, *part;

	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));

	/* First the must-have fields */
	if (nvlist_lookup_string(in, TOPO_METH_FMRI_ARG_NAME, &name) != 0)
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));
	if (nvlist_lookup_uint32(in, TOPO_METH_FMRI_ARG_INST, &inst) != 0)
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));
	if (nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NVL, &args) != 0)
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));
	if (nvlist_lookup_nvlist(args, TOPO_METH_FMRI_ARG_PARENT, &pfmri) != 0)
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));

	/* And then optional arguments */
	auth = NULL;
	serial = rev = part = NULL;
	(void) nvlist_lookup_nvlist(args, TOPO_METH_FMRI_ARG_AUTH, &auth);
	(void) nvlist_lookup_string(args, TOPO_METH_FMRI_ARG_PART, &part);
	(void) nvlist_lookup_string(args, TOPO_METH_FMRI_ARG_REV, &rev);
	(void) nvlist_lookup_string(args, TOPO_METH_FMRI_ARG_SER, &serial);

	*out = hc_fmri_create(mp,
	    pfmri, version, name, inst, auth, part, rev, serial);
	if (*out == NULL)
		return (-1);
	return (0);
}
