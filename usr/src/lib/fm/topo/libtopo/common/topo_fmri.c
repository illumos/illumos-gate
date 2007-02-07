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
#include <limits.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>
#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_method.h>
#include <topo_subr.h>
#include <topo_string.h>

/*ARGSUSED*/
static int
set_error(topo_hdl_t *thp, int err, int *errp, char *method, nvlist_t *nvlp)
{
	if (nvlp != NULL)
		nvlist_free(nvlp);

	topo_dprintf(thp, TOPO_DBG_ERR, "%s failed: %s\n", method,
	    topo_strerror(err));

	*errp = err;
	return (-1);
}

/*ARGSUSED*/
static nvlist_t *
set_nverror(topo_hdl_t *thp, int err, int *errp, char *method, nvlist_t *nvlp)
{
	if (nvlp != NULL)
		nvlist_free(nvlp);

	topo_dprintf(thp, TOPO_DBG_ERR, "%s failed: %s\n", method,
	    topo_strerror(err));

	*errp = err;
	return (NULL);
}

int
topo_fmri_nvl2str(topo_hdl_t *thp, nvlist_t *fmri, char **fmristr, int *err)
{
	char *scheme, *str;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_NVL2STR, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_NVL2STR, out));

	if (topo_method_invoke(rnode, TOPO_METH_NVL2STR,
	    TOPO_METH_NVL2STR_VERSION, fmri, &out, err) != 0)
		return (set_error(thp, *err, err, TOPO_METH_NVL2STR, out));

	if (out == NULL || nvlist_lookup_string(out, "fmri-string", &str) != 0)
		return (set_error(thp, ETOPO_METHOD_INVAL, err,
		    TOPO_METH_NVL2STR, out));

	if ((*fmristr = topo_hdl_strdup(thp, str)) == NULL)
		return (set_error(thp, ETOPO_NOMEM, err,
		    TOPO_METH_NVL2STR, out));

	nvlist_free(out);

	return (0);
}

int
topo_fmri_str2nvl(topo_hdl_t *thp, const char *fmristr, nvlist_t **fmri,
    int *err)
{
	char *f, buf[PATH_MAX];
	nvlist_t *out = NULL, *in = NULL;
	tnode_t *rnode;

	(void) strlcpy(buf, fmristr, sizeof (buf));
	if ((f = strchr(buf, ':')) == NULL)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_STR2NVL, in));

	*f = '\0'; /* strip trailing FMRI path */

	if ((rnode = topo_hdl_root(thp, buf)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_STR2NVL, in));

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_STR2NVL,
		    in));

	if (nvlist_add_string(in, "fmri-string", fmristr) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_STR2NVL,
		    in));

	if (topo_method_invoke(rnode, TOPO_METH_STR2NVL,
	    TOPO_METH_STR2NVL_VERSION, in, &out, err) != 0)
		return (set_error(thp, *err, err, TOPO_METH_STR2NVL, in));

	if (out == NULL ||
	    topo_hdl_nvdup(thp, out, fmri) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_STR2NVL, in));

	nvlist_free(out);
	nvlist_free(in);

	return (0);
}

/* ARGSUSED */
static int
is_present(topo_hdl_t *thp, tnode_t *node, void *data)
{
	int err;
	uint32_t present = 0;
	nvlist_t *out = NULL;
	nvlist_t *fmri = (nvlist_t *)data;

	if (topo_method_invoke(node, TOPO_METH_PRESENT,
	    TOPO_METH_PRESENT_VERSION, fmri, &out, &err) < 0) {
		if (out != NULL)
			nvlist_free(out);
		return (present);
	}

	(void) nvlist_lookup_uint32(out, TOPO_METH_PRESENT_RET, &present);

	nvlist_free(out);

	return (present);
}

int
topo_fmri_present(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	int ret = 0;
	uint32_t present = 0;
	char *scheme;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (topo_fmri_invoke(thp, fmri, is_present, fmri, &ret) == 0)
		return (ret);

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_PRESENT, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_PRESENT, out));

	if (topo_method_invoke(rnode, TOPO_METH_PRESENT,
	    TOPO_METH_PRESENT_VERSION, fmri, &out, err) < 0) {
		(void) set_error(thp, *err, err, TOPO_METH_PRESENT, out);
		return (present);
	}

	(void) nvlist_lookup_uint32(out, TOPO_METH_PRESENT_RET, &present);
	nvlist_free(out);

	return (present);
}

int
topo_fmri_contains(topo_hdl_t *thp, nvlist_t *fmri, nvlist_t *subfmri, int *err)
{
	int rc;
	char *scheme;
	nvlist_t *in, *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_CONTAINS, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_CONTAINS, out));

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_CONTAINS,
		    out));

	if (nvlist_add_nvlist(in, "fmri", fmri) != 0 ||
	    nvlist_add_nvlist(in, "subfmri", subfmri) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_CONTAINS,
		    out));

	if (topo_hdl_nvalloc(thp, &out, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_CONTAINS,
		    out));

	if ((rc = topo_method_invoke(rnode, TOPO_METH_CONTAINS,
	    TOPO_METH_CONTAINS_VERSION, fmri, &out, err)) < 0)
		return (set_error(thp, *err, err, TOPO_METH_CONTAINS, out));

	return (rc);
}

int
topo_fmri_unusable(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	int rc;
	char *scheme;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_UNUSABLE, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_UNUSABLE, out));

	if ((rc = topo_method_invoke(rnode, TOPO_METH_UNUSABLE,
	    TOPO_METH_UNUSABLE_VERSION, fmri, &out, err)) < 0)
		return (set_error(thp, *err, err, TOPO_METH_UNUSABLE, out));

	return (rc);
}

int
topo_fmri_expand(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	char *scheme;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_EXPAND, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_EXPAND, out));

	if (topo_method_invoke(rnode, TOPO_METH_EXPAND,
	    TOPO_METH_EXPAND_VERSION, fmri, &out, err) != 0)
		return (set_error(thp, *err, err, TOPO_METH_EXPAND, out));

	return (0);
}

struct prop_lookup {
	int pl_err;
	topo_type_t pl_type;
	const char *pl_group;
	const char *pl_name;
	nvlist_t **pl_prop;
	nvlist_t *pl_resource;
};

static int
prop_lookup(topo_hdl_t *thp, tnode_t *node, void *pdata)
{
	int rc;
	nvlist_t *r1;
	struct prop_lookup *plp = (struct prop_lookup *)pdata;

	if (topo_node_resource(node, &r1, &plp->pl_err) != 0)
		return (TOPO_WALK_ERR);

	rc = topo_fmri_compare(thp, r1, plp->pl_resource, &plp->pl_err);
	nvlist_free(r1);
	if (rc == 0)
		return (TOPO_WALK_NEXT);
	if (rc < 0)
		return (TOPO_WALK_ERR);

	/*
	 * Special case for dynamically created ASRU and FRU
	 */
	if (strcmp(plp->pl_group, TOPO_PGROUP_PROTOCOL) == 0) {
		if (strcmp(plp->pl_name, TOPO_PROP_ASRU) == 0) {
			if (topo_node_asru(node, plp->pl_prop, plp->pl_resource,
			    &plp->pl_err) < 0) {
				return (TOPO_WALK_ERR);
			}
			return (0);
		} else if (strcmp(plp->pl_name, TOPO_PROP_FRU) == 0) {
			if (topo_node_fru(node, plp->pl_prop, plp->pl_resource,
			    &plp->pl_err) < 0) {
				return (TOPO_WALK_ERR);
			}
			return (0);
		}
	}

	switch (plp->pl_type) {
		case TOPO_TYPE_STRING:
		{
			char *str;
			if (topo_prop_get_string(node, plp->pl_group,
			    plp->pl_name, &str, &plp->pl_err) < 0)
				return (TOPO_WALK_ERR);

			if (nvlist_add_string(*plp->pl_prop, "prop", str)
			    != 0) {
				topo_hdl_strfree(thp, str);
				plp->pl_err = ETOPO_PROP_NVL;
				return (TOPO_WALK_ERR);
			}
			topo_hdl_strfree(thp, str);
			return (TOPO_WALK_TERMINATE);
		}
		default:
			plp->pl_err = ETOPO_PROP_TYPE;
			return (TOPO_WALK_ERR);
	}

}

static int
fmri_prop(topo_hdl_t *thp, nvlist_t *resource, const char *pgname,
    const char *pname, topo_type_t type, nvlist_t **prop, int *err)
{
	int rc;
	topo_walk_t *wp;
	char *scheme;
	struct prop_lookup pl;

	if (nvlist_lookup_string(resource, FM_FMRI_SCHEME, &scheme)   != 0)
		return (set_error(thp, ETOPO_METHOD_INVAL, err,
		    "fmri_prop", NULL));

	*prop = NULL;
	pl.pl_resource = resource;
	pl.pl_err = 0;
	pl.pl_type = type;
	pl.pl_group = pgname;
	pl.pl_name = pname;
	pl.pl_prop = prop;
	if ((wp = topo_walk_init(thp, scheme, prop_lookup, &pl, err)) == NULL)
		return (set_error(thp, pl.pl_err, err, "fmri_prop", NULL));

	rc = topo_walk_step(wp, TOPO_WALK_CHILD);
	topo_walk_fini(wp);

	if (rc == TOPO_WALK_ERR) {
		return (set_error(thp, pl.pl_err, err, "fmri_prop", NULL));
	}

	/*
	 * Walk terminated without finding resource or property
	 */
	if (*prop == NULL)
		return (set_error(thp, ETOPO_PROP_NOENT, err, "fmri_prop",
		    NULL));

	return (0);
}

int
topo_fmri_asru(topo_hdl_t *thp, nvlist_t *nvl, nvlist_t **asru, int *err)
{

	if (fmri_prop(thp, nvl, TOPO_PGROUP_PROTOCOL, TOPO_PROP_ASRU,
	    TOPO_TYPE_FMRI, asru, err) < 0)
		return (set_error(thp, *err, err, "topo_fmri_asru", NULL));

	return (0);
}

int
topo_fmri_fru(topo_hdl_t *thp, nvlist_t *nvl, nvlist_t **fru, int *err)
{

	if (fmri_prop(thp, nvl, TOPO_PGROUP_PROTOCOL, TOPO_PROP_FRU,
	    TOPO_TYPE_FMRI, fru, err) < 0)
		return (set_error(thp, *err, err, "topo_fmri_fru", NULL));

	return (0);
}

int
topo_fmri_label(topo_hdl_t *thp, nvlist_t *fmri, char **label, int *err)
{
	nvlist_t *nvl, *fru;
	char *str;

	if (topo_fmri_fru(thp, fmri, &fru, err) < 0)
		return (set_error(thp, *err, err, "topo_fmri_label", NULL));

	if (topo_hdl_nvalloc(thp, &nvl, NV_UNIQUE_NAME) < 0)
		return (set_error(thp, ETOPO_PROP_NVL, err, "topo_fmri_label",
		    NULL));

	if (fmri_prop(thp, fru, TOPO_PGROUP_PROTOCOL, TOPO_PROP_LABEL,
	    TOPO_TYPE_STRING, &nvl, err) < 0) {
		nvlist_free(fru);
		return (set_error(thp, *err, err, "topo_fmri_label", nvl));
	}

	nvlist_free(fru);

	if (nvlist_lookup_string(nvl, "prop", &str) != 0)
		return (set_error(thp, ETOPO_PROP_NVL, err, "topo_fmri_label",
		    nvl));

	if ((*label = topo_hdl_strdup(thp, str)) == NULL)
		return (set_error(thp, ETOPO_PROP_NOMEM, err,
		    "topo_fmri_label", nvl));

	nvlist_free(nvl);

	return (0);
}

int
topo_fmri_compare(topo_hdl_t *thp, nvlist_t *f1, nvlist_t *f2, int *err)
{
	int rc;
	char *scheme1, *scheme2;
	nvlist_t *in;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(f1, FM_FMRI_SCHEME, &scheme1) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_COMPARE, NULL));
	if (nvlist_lookup_string(f2, FM_FMRI_SCHEME, &scheme2) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_COMPARE, NULL));

	if (strcmp(scheme1, scheme2) != 0)
		return (0);

	if ((rnode = topo_hdl_root(thp, scheme1)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_COMPARE, NULL));

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_COMPARE,
		    NULL));

	if (nvlist_add_nvlist(in, "nv1", f1) != 0 ||
	    nvlist_add_nvlist(in, "nv2", f2) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_COMPARE,
		    in));

	if ((rc = topo_method_invoke(rnode, TOPO_METH_COMPARE,
	    TOPO_METH_COMPARE_VERSION, in, &out, err)) < 0)
		return (set_error(thp, *err, err, TOPO_METH_COMPARE, in));

	nvlist_free(in);

	return (rc);
}

struct topo_invoke {
	nvlist_t *tl_resource;
	topo_walk_cb_t tl_func;
	int tl_ret;
	void *tl_pdata;
};

static int
walk_invoke(topo_hdl_t *thp, tnode_t *node, void *pdata)
{
	int rc;
	struct topo_invoke *tlp = (struct topo_invoke *)pdata;
	nvlist_t *r1, *r2 = tlp->tl_resource;

	if (topo_node_resource(node, &r1, &tlp->tl_ret) != 0)
		return (TOPO_WALK_ERR);

	rc = topo_fmri_compare(thp, r1, r2, &tlp->tl_ret);
	nvlist_free(r1);
	if (rc == 0)
		return (TOPO_WALK_NEXT);
	else if (rc == -1)
		return (TOPO_WALK_ERR);

	tlp->tl_ret = tlp->tl_func(thp, node, tlp->tl_pdata);

	return (TOPO_WALK_TERMINATE);
}

int
topo_fmri_invoke(topo_hdl_t *thp, nvlist_t *nvl, topo_walk_cb_t cb_f,
    void *pdata, int *ret)
{
	int err;
	topo_walk_t *wp;
	char *scheme;
	struct topo_invoke tl;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &scheme)   != 0)
		return (set_error(thp, ETOPO_METHOD_INVAL, ret,
		    "topo_fmri_invoke", NULL));

	tl.tl_resource = nvl;
	tl.tl_func = cb_f;
	tl.tl_pdata = pdata;
	tl.tl_ret = 0;
	if ((wp = topo_walk_init(thp, scheme, walk_invoke, &tl, &err)) == NULL)
		return (set_error(thp, err, ret, "topo_fmri_invoke", NULL));

	err = topo_walk_step(wp, TOPO_WALK_CHILD);
	topo_walk_fini(wp);

	if (err == TOPO_WALK_ERR) {
		*ret = err;
		return (-1);
	}

	*ret = tl.tl_ret;

	return (0);
}

/*
 * topo_fmri_create
 *
 *	If possible, creates an FMRI of the requested version in the
 *	requested scheme.  Args are passed as part of the inputs to the
 *	fmri-create method of the scheme.
 */
nvlist_t *
topo_fmri_create(topo_hdl_t *thp, const char *scheme, const char *name,
    topo_instance_t inst, nvlist_t *nvl, int *err)
{
	nvlist_t *ins;
	nvlist_t *out;
	tnode_t *rnode;

	ins = out = NULL;

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_nverror(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_FMRI, NULL));

	if ((*err = topo_hdl_nvalloc(thp, &ins, NV_UNIQUE_NAME)) != 0)
		return (set_nverror(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_FMRI, NULL));

	if (nvlist_add_string(ins, TOPO_METH_FMRI_ARG_NAME, name) != 0 ||
	    nvlist_add_uint32(ins, TOPO_METH_FMRI_ARG_INST, inst) != 0) {
		return (set_nverror(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_FMRI, ins));
	}

	if (nvl != NULL &&
	    nvlist_add_nvlist(ins, TOPO_METH_FMRI_ARG_NVL, nvl) != 0) {
		return (set_nverror(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_FMRI, ins));
	}
	if (topo_method_invoke(rnode,
	    TOPO_METH_FMRI, TOPO_METH_FMRI_VERSION, ins, &out, err) != 0) {
		return (set_nverror(thp, *err, err, TOPO_METH_FMRI, ins));
	}
	nvlist_free(ins);
	return (out);
}
