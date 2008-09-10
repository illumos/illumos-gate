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

#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <fm/topo_mod.h>
#include <fm/fmd_fmri.h>
#include <sys/fm/protocol.h>
#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_hc.h>
#include <topo_method.h>
#include <topo_subr.h>
#include <topo_string.h>

/*
 * Topology node properties and method operations may be accessed by FMRI.
 * The FMRI used to perform property look-ups and method operations is
 * the FMRI contained in the matching topology node's protocol property
 * grouping for the resource property. The full range of fmd(1M)
 * scheme plugin operations are supported as long as a backend method is
 * supplied by a scheme-specific enumerator or the enumerator module that
 * created the matching topology node.  Support for fmd scheme operations
 * include:
 *
 *	- expand
 *	- present
 *	- replaced
 *	- contains
 *	- unusable
 *	- service_state
 *	- nvl2str
 *	- retire
 *	- unretire
 *
 * In addition, the following operations are supported per-FMRI:
 *
 *	- str2nvl: convert string-based FMRI to nvlist
 *	- compare: compare two FMRIs
 *	- asru: lookup associated ASRU property by FMRI
 *	- fru: lookup associated FRU by FMRI
 *	- create: an FMRI nvlist by scheme type
 *	- propery lookup
 *
 * These routines may only be called by consumers of a topology snapshot.
 * They may not be called by libtopo enumerator or method modules.
 */

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

	nvlist_free(in);

	if (out == NULL ||
	    topo_hdl_nvdup(thp, out, fmri) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_STR2NVL, out));

	nvlist_free(out);

	return (0);
}

int
topo_fmri_present(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	uint32_t present = 0;
	char *scheme;
	nvlist_t *out = NULL;
	tnode_t *rnode;

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
topo_fmri_replaced(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	uint32_t replaced = FMD_OBJ_STATE_NOT_PRESENT;
	char *scheme;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_REPLACED, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_REPLACED, out));

	if (topo_method_invoke(rnode, TOPO_METH_REPLACED,
	    TOPO_METH_REPLACED_VERSION, fmri, &out, err) < 0) {
		(void) set_error(thp, *err, err, TOPO_METH_REPLACED, out);
		return (FMD_OBJ_STATE_UNKNOWN);
	}

	(void) nvlist_lookup_uint32(out, TOPO_METH_REPLACED_RET, &replaced);
	nvlist_free(out);

	return (replaced);
}

int
topo_fmri_contains(topo_hdl_t *thp, nvlist_t *fmri, nvlist_t *subfmri, int *err)
{
	uint32_t contains;
	char *scheme;
	nvlist_t *in = NULL, *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_CONTAINS, NULL));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_CONTAINS, NULL));

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_CONTAINS,
		    NULL));

	if (nvlist_add_nvlist(in, TOPO_METH_FMRI_ARG_FMRI, fmri) != 0 ||
	    nvlist_add_nvlist(in, TOPO_METH_FMRI_ARG_SUBFMRI, subfmri) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_CONTAINS,
		    in));

	if (topo_method_invoke(rnode, TOPO_METH_CONTAINS,
	    TOPO_METH_CONTAINS_VERSION, in, &out, err) < 0)
		return (set_error(thp, *err, err, TOPO_METH_CONTAINS, in));

	(void) nvlist_lookup_uint32(out, TOPO_METH_CONTAINS_RET, &contains);
	nvlist_free(in);
	nvlist_free(out);

	return (contains);
}

int
topo_fmri_unusable(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	char *scheme;
	uint32_t unusable = 0;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_UNUSABLE, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_UNUSABLE, out));

	if (topo_method_invoke(rnode, TOPO_METH_UNUSABLE,
	    TOPO_METH_UNUSABLE_VERSION, fmri, &out, err) < 0)
		return (set_error(thp, *err, err, TOPO_METH_UNUSABLE, out));

	(void) nvlist_lookup_uint32(out, TOPO_METH_UNUSABLE_RET, &unusable);
	nvlist_free(out);

	return (unusable);
}

int
topo_fmri_retire(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	char *scheme;
	uint32_t status;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_RETIRE, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_RETIRE, out));

	if (topo_method_invoke(rnode, TOPO_METH_RETIRE,
	    TOPO_METH_RETIRE_VERSION, fmri, &out, err) < 0)
		return (set_error(thp, *err, err, TOPO_METH_RETIRE, out));

	if (nvlist_lookup_uint32(out, TOPO_METH_RETIRE_RET, &status) != 0)
		return (set_error(thp, ETOPO_METHOD_FAIL, err,
		    TOPO_METH_RETIRE, out));
	nvlist_free(out);

	return (status);
}

int
topo_fmri_unretire(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	char *scheme;
	uint32_t status;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_UNRETIRE, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_UNRETIRE, out));

	if (topo_method_invoke(rnode, TOPO_METH_UNRETIRE,
	    TOPO_METH_UNRETIRE_VERSION, fmri, &out, err) < 0)
		return (set_error(thp, *err, err, TOPO_METH_UNRETIRE, out));

	if (nvlist_lookup_uint32(out, TOPO_METH_UNRETIRE_RET, &status) != 0) {
		nvlist_free(out);
		return (set_error(thp, ETOPO_METHOD_FAIL, err,
		    TOPO_METH_UNRETIRE, out));
	}
	nvlist_free(out);

	return (status);
}

int
topo_fmri_service_state(topo_hdl_t *thp, nvlist_t *fmri, int *err)
{
	char *scheme;
	uint32_t service_state = FMD_SERVICE_STATE_UNKNOWN;
	nvlist_t *out = NULL;
	tnode_t *rnode;

	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_SERVICE_STATE, out));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_SERVICE_STATE, out));

	if (topo_method_invoke(rnode, TOPO_METH_SERVICE_STATE,
	    TOPO_METH_SERVICE_STATE_VERSION, fmri, &out, err) < 0)
		return (set_error(thp, *err, err, TOPO_METH_SERVICE_STATE,
		    out));

	(void) nvlist_lookup_uint32(out, TOPO_METH_SERVICE_STATE_RET,
	    &service_state);
	nvlist_free(out);

	return (service_state);
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

static int
fmri_prop(topo_hdl_t *thp, nvlist_t *rsrc, const char *pgname,
    const char *pname, nvlist_t *args, nvlist_t **prop,
    int *err)
{
	int rv;
	nvlist_t *in = NULL;
	tnode_t *rnode;
	char *scheme;

	if (nvlist_lookup_string(rsrc, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_PROP_GET, in));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_PROP_GET, in));

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_PROP_GET, in));

	rv = nvlist_add_nvlist(in, TOPO_PROP_RESOURCE, rsrc);
	rv |= nvlist_add_string(in, TOPO_PROP_GROUP, pgname);
	rv |= nvlist_add_string(in, TOPO_PROP_VAL_NAME, pname);
	if (args != NULL)
		rv |= nvlist_add_nvlist(in, TOPO_PROP_PARGS, args);
	if (rv != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_PROP_GET, in));

	*prop = NULL;
	rv = topo_method_invoke(rnode, TOPO_METH_PROP_GET,
	    TOPO_METH_PROP_GET_VERSION, in, prop, err);

	nvlist_free(in);

	if (rv != 0)
		return (-1); /* *err is set for us */

	if (*prop == NULL)
		return (set_error(thp, ETOPO_PROP_NOENT, err,
		    TOPO_METH_PROP_GET, NULL));
	return (0);
}

int
topo_fmri_asru(topo_hdl_t *thp, nvlist_t *nvl, nvlist_t **asru, int *err)
{
	nvlist_t *ap, *prop = NULL;

	if (fmri_prop(thp, nvl, TOPO_PGROUP_PROTOCOL, TOPO_PROP_ASRU,
	    nvl, &prop, err) < 0)
		return (set_error(thp, *err, err, "topo_fmri_asru", NULL));

	if (nvlist_lookup_nvlist(prop, TOPO_PROP_VAL_VAL, &ap) != 0)
		return (set_error(thp, ETOPO_PROP_NVL, err, "topo_fmri_asru",
		    prop));

	if (topo_hdl_nvdup(thp, ap, asru) < 0)
		return (set_error(thp, ETOPO_PROP_NOMEM, err, "topo_fmri_asru",
		    prop));

	nvlist_free(prop);

	return (0);
}

int
topo_fmri_fru(topo_hdl_t *thp, nvlist_t *nvl, nvlist_t **fru, int *err)
{
	nvlist_t *fp, *prop = NULL;

	if (fmri_prop(thp, nvl, TOPO_PGROUP_PROTOCOL, TOPO_PROP_FRU,
	    nvl, &prop, err) < 0)
		return (set_error(thp, *err, err, "topo_fmri_fru", NULL));

	if (nvlist_lookup_nvlist(prop, TOPO_PROP_VAL_VAL, &fp) != 0)
		return (set_error(thp, ETOPO_PROP_NVL, err, "topo_fmri_fru",
		    prop));

	if (topo_hdl_nvdup(thp, fp, fru) < 0)
		return (set_error(thp, ETOPO_PROP_NOMEM, err, "topo_fmri_fru",
		    prop));

	nvlist_free(prop);

	return (0);
}

int
topo_fmri_label(topo_hdl_t *thp, nvlist_t *nvl, char **label, int *err)
{
	nvlist_t *prop = NULL;
	char *lp;

	if (fmri_prop(thp, nvl, TOPO_PGROUP_PROTOCOL, TOPO_PROP_LABEL,
	    NULL, &prop, err) < 0)
		return (set_error(thp, *err, err, "topo_fmri_label", NULL));

	if (nvlist_lookup_string(prop, TOPO_PROP_VAL_VAL, &lp) != 0)
		return (set_error(thp, ETOPO_PROP_NVL, err, "topo_fmri_label",
		    prop));

	if ((*label = topo_hdl_strdup(thp, lp)) == NULL)
		return (set_error(thp, ETOPO_PROP_NOMEM, err, "topo_fmri_label",
		    prop));

	nvlist_free(prop);

	return (0);
}

int
topo_fmri_serial(topo_hdl_t *thp, nvlist_t *nvl, char **serial, int *err)
{
	nvlist_t *prop = NULL;
	char *sp;

	if (fmri_prop(thp, nvl, TOPO_PGROUP_PROTOCOL, FM_FMRI_HC_SERIAL_ID,
	    NULL, &prop, err) < 0)
		return (set_error(thp, *err, err, "topo_fmri_serial", NULL));

	if (nvlist_lookup_string(prop, TOPO_PROP_VAL_VAL, &sp) != 0)
		return (set_error(thp, ETOPO_PROP_NVL, err, "topo_fmri_serial",
		    prop));

	if ((*serial = topo_hdl_strdup(thp, sp)) == NULL)
		return (set_error(thp, ETOPO_PROP_NOMEM, err,
		    "topo_fmri_serial", prop));

	nvlist_free(prop);

	return (0);
}

int topo_fmri_getprop(topo_hdl_t *thp, nvlist_t *nvl, const char *pg,
    const char *pname, nvlist_t *args,  nvlist_t **prop,
    int *err)
{
	*prop = NULL;

	return (fmri_prop(thp, nvl, pg, pname, args, prop, err));
}

int topo_fmri_setprop(topo_hdl_t *thp, nvlist_t *nvl, const char *pg,
    nvlist_t *prop, int flag, nvlist_t *args, int *err)
{
	int rv;
	nvlist_t *in = NULL, *out = NULL;
	tnode_t *rnode;
	char *scheme;

	if (nvlist_lookup_string(nvl, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_PROP_SET, in));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_PROP_SET, in));

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_PROP_SET, in));

	rv = nvlist_add_nvlist(in, TOPO_PROP_RESOURCE, nvl);
	rv |= nvlist_add_string(in, TOPO_PROP_GROUP, pg);
	rv |= nvlist_add_nvlist(in, TOPO_PROP_VAL, prop);
	rv |= nvlist_add_int32(in, TOPO_PROP_FLAG, (int32_t)flag);
	if (args != NULL)
		rv |= nvlist_add_nvlist(in, TOPO_PROP_PARGS, args);
	if (rv != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_PROP_SET, in));

	rv = topo_method_invoke(rnode, TOPO_METH_PROP_SET,
	    TOPO_METH_PROP_SET_VERSION, in, &out, err);

	nvlist_free(in);

	/* no return values */
	if (out != NULL)
		nvlist_free(out);

	if (rv)
		return (-1);

	return (0);

}

int
topo_fmri_getpgrp(topo_hdl_t *thp, nvlist_t *rsrc, const char *pgname,
    nvlist_t **pgroup, int *err)
{
	int rv;
	nvlist_t *in = NULL;
	tnode_t *rnode;
	char *scheme;

	if (nvlist_lookup_string(rsrc, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_PROP_GET, in));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_PROP_GET, in));

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_PROP_GET, in));

	rv = nvlist_add_nvlist(in, TOPO_PROP_RESOURCE, rsrc);
	rv |= nvlist_add_string(in, TOPO_PROP_GROUP, pgname);
	if (rv != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_PROP_GET, in));

	*pgroup = NULL;
	rv = topo_method_invoke(rnode, TOPO_METH_PGRP_GET,
	    TOPO_METH_PGRP_GET_VERSION, in, pgroup, err);

	nvlist_free(in);

	if (rv != 0)
		return (-1); /* *err is set for us */

	if (*pgroup == NULL)
		return (set_error(thp, ETOPO_PROP_NOENT, err,
		    TOPO_METH_PROP_GET, NULL));
	return (0);
}

int
topo_fmri_compare(topo_hdl_t *thp, nvlist_t *f1, nvlist_t *f2, int *err)
{
	uint32_t compare;
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

	if (nvlist_add_nvlist(in, TOPO_METH_FMRI_ARG_NV1, f1) != 0 ||
	    nvlist_add_nvlist(in, TOPO_METH_FMRI_ARG_NV2, f2) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err, TOPO_METH_COMPARE,
		    in));

	if (topo_method_invoke(rnode, TOPO_METH_COMPARE,
	    TOPO_METH_COMPARE_VERSION, in, &out, err) < 0)
		return (set_error(thp, *err, err, TOPO_METH_COMPARE, in));

	(void) nvlist_lookup_uint32(out, TOPO_METH_COMPARE_RET, &compare);
	nvlist_free(out);
	nvlist_free(in);

	return (compare);
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

/*
 * These private utility functions are used by fmd to maintain its resource
 * cache.  Because hc instance numbers are not guaranteed, it's possible to
 * have two different FMRI strings represent the same logical entity.  These
 * functions hide this implementation detail from unknowing consumers such as
 * fmd.
 *
 * Ideally, we'd like to do a str2nvl() and then a full FMRI hash and
 * comparison, but these functions are designed to be fast and efficient.
 * Given that there is only a single hc node that has this property
 * (ses-enclosure), we hard-code this behavior here.  If there are more
 * instances of this behavior in the future, this function could be made more
 * generic.
 */
static ulong_t
topo_fmri_strhash_one(const char *fmri, size_t len)
{
	ulong_t g, h = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		h = (h << 4) + fmri[i];

		if ((g = (h & 0xf0000000)) != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}

	return (h);
}

/*ARGSUSED*/
ulong_t
topo_fmri_strhash(topo_hdl_t *thp, const char *fmri)
{
	char *e;
	ulong_t h;

	if (strncmp(fmri, "hc://", 5) != 0 ||
	    (e = strstr(fmri, SES_ENCLOSURE)) == NULL)
		return (topo_fmri_strhash_one(fmri, strlen(fmri)));

	h = topo_fmri_strhash_one(fmri, e - fmri);
	e += sizeof (SES_ENCLOSURE);

	while (isdigit(*e))
		e++;

	h += topo_fmri_strhash_one(e, strlen(e));

	return (h);
}

/*ARGSUSED*/
boolean_t
topo_fmri_strcmp(topo_hdl_t *thp, const char *a, const char *b)
{
	char *ea, *eb;

	if (strncmp(a, "hc://", 5) != 0 ||
	    strncmp(b, "hc://", 5) != 0 ||
	    (ea = strstr(a, SES_ENCLOSURE)) == NULL ||
	    (eb = strstr(b, SES_ENCLOSURE)) == NULL)
		return (strcmp(a, b) == 0);

	if ((ea - a) != (eb - b))
		return (B_FALSE);

	if (strncmp(a, b, ea - a) != 0)
		return (B_FALSE);

	ea += sizeof (SES_ENCLOSURE);
	eb += sizeof (SES_ENCLOSURE);

	while (isdigit(*ea))
		ea++;
	while (isdigit(*eb))
		eb++;

	return (strcmp(ea, eb) == 0);
}

int
topo_fmri_facility(topo_hdl_t *thp, nvlist_t *rsrc, const char *fac_type,
    uint32_t fac_subtype, topo_walk_cb_t cb, void *cb_args, int *err)
{
	int rv;
	nvlist_t *in = NULL, *out;
	tnode_t *rnode;
	char *scheme;

	if (nvlist_lookup_string(rsrc, FM_FMRI_SCHEME, &scheme) != 0)
		return (set_error(thp, ETOPO_FMRI_MALFORM, err,
		    TOPO_METH_PROP_GET, in));

	if ((rnode = topo_hdl_root(thp, scheme)) == NULL)
		return (set_error(thp, ETOPO_METHOD_NOTSUP, err,
		    TOPO_METH_PROP_GET, in));

	if (topo_hdl_nvalloc(thp, &in, NV_UNIQUE_NAME) != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_PROP_GET, in));

	rv = nvlist_add_nvlist(in, TOPO_PROP_RESOURCE, rsrc);
	rv |= nvlist_add_string(in, FM_FMRI_FACILITY_TYPE, fac_type);
	rv |= nvlist_add_uint32(in, "type", fac_subtype);
#ifdef _LP64
	rv |= nvlist_add_uint64(in, "callback", (uint64_t)cb);
	rv |= nvlist_add_uint64(in, "callback-args", (uint64_t)cb_args);
#else
	rv |= nvlist_add_uint32(in, "callback", (uint32_t)cb);
	rv |= nvlist_add_uint32(in, "callback-args", (uint32_t)cb_args);
#endif
	if (rv != 0)
		return (set_error(thp, ETOPO_FMRI_NVL, err,
		    TOPO_METH_PROP_GET, in));

	rv = topo_method_invoke(rnode, TOPO_METH_FACILITY,
	    TOPO_METH_FACILITY_VERSION, in, &out, err);

	nvlist_free(in);

	if (rv != 0)
		return (-1); /* *err is set for us */

	return (0);
}
