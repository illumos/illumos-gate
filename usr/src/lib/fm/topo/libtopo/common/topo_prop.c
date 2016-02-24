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
#include <assert.h>
#include <fm/libtopo.h>
#include <topo_prop.h>
#include <topo_string.h>
#include <topo_alloc.h>
#include <topo_error.h>
#include <topo_method.h>

/*
 * Topology nodes are permitted to contain property information.
 * Property information is organized according to property grouping.
 * Each property group defines a name, a stability level for that name,
 * a stability level for all underlying property data (name, type, values),
 * a version for the property group definition and and a list of uniquely
 * defined properties.  Property group versions are incremented when one of
 * the following changes occurs:
 *	- a property name changes
 *	- a property type changes
 *	- a property definition is removed from the group
 * Compatible changes such as new property definitions in the group do
 * not require version changes.
 *
 * Each property defines a unique (within the group) name, a type and
 * a value.  Properties may be statically defined as int32, uint32, int64,
 * uint64, fmri, string or arrays of each type.  Properties may also be
 * dynamically exported via module registered methods.  For example, a module
 * may register a method to export an ASRU property that is dynamically
 * contructed when a call to topo_node_fmri() is invoked for a particular
 * topology node.
 *
 * Static properties are persistently attached to topology nodes during
 * enumeration by an enumeration module or as part of XML statements in a
 * toplogy map file using the topo_prop_set* family of routines.  Similarly,
 * property methods are registered during enumeration or as part of
 * statements in topololgy map files.  Set-up of property methods is performed
 * by calling topo_prop_method_register().
 *
 * All properties, whether statically persisted in a snapshot or dynamically
 * obtained, may be read via the topo_prop_get* family of interfaces.
 * Callers wishing to receive all property groups and properties for a given
 * node may use topo_prop_getall().  This routine returns a nested nvlist
 * of all groupings and property (name, type, value) sets.  Groupings
 * are defined by TOPO_PROP_GROUP (name, data stability, name stability and
 * version) and a nested nvlist of properties (TOPO_PROP_VAL).  Each property
 * value is defined by its name, type and value.
 */
static void topo_propval_destroy(topo_propval_t *);

static topo_pgroup_t *
pgroup_get(tnode_t *node, const char *pgname)
{
	topo_pgroup_t *pg;
	/*
	 * Check for an existing pgroup
	 */
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (strcmp(pg->tpg_info->tpi_name, pgname) == 0) {
			return (pg);
		}
	}

	return (NULL);
}

static topo_propval_t *
propval_get(topo_pgroup_t *pg, const char *pname)
{
	topo_proplist_t *pvl;

	if (pg == NULL)
		return (NULL);

	for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
	    pvl = topo_list_next(pvl)) {
		if (strcmp(pvl->tp_pval->tp_name, pname) == 0)
			return (pvl->tp_pval);
	}

	return (NULL);
}

static int
method_geterror(nvlist_t *nvl, int err, int *errp)
{
	nvlist_free(nvl);

	*errp = err;

	return (-1);
}

static int
prop_method_get(tnode_t *node, topo_propval_t *pv, topo_propmethod_t *pm,
    nvlist_t *pargs, int *err)
{
	int ret;
	nvlist_t *args, *nvl;
	char *name;
	topo_type_t type;

	if (topo_hdl_nvalloc(pv->tp_hdl, &args, NV_UNIQUE_NAME) < 0 ||
	    nvlist_add_nvlist(args, TOPO_PROP_ARGS, pm->tpm_args) != 0)
		return (method_geterror(NULL, ETOPO_PROP_NVL, err));

	if (pargs != NULL)
		if (nvlist_add_nvlist(args, TOPO_PROP_PARGS, pargs) != 0)
			return (method_geterror(args, ETOPO_PROP_NVL, err));

	/*
	 * Now, get the latest value
	 *
	 * Grab a reference to the property and then unlock the node.  This will
	 * allow property methods to safely re-enter the prop_get codepath,
	 * making it possible for property methods to access other property
	 * values on the same node w\o causing a deadlock.
	 */
	topo_prop_hold(pv);
	topo_node_unlock(node);
	if (topo_method_call(node, pm->tpm_name, pm->tpm_version,
	    args, &nvl, err) < 0) {
		topo_node_lock(node);
		topo_prop_rele(pv);
		return (method_geterror(args, *err, err));
	}
	topo_node_lock(node);
	topo_prop_rele(pv);

	nvlist_free(args);

	/* Verify the property contents */
	ret = nvlist_lookup_string(nvl, TOPO_PROP_VAL_NAME, &name);
	if (ret != 0 || strcmp(name, pv->tp_name) != 0)
		return (method_geterror(nvl, ETOPO_PROP_NAME, err));

	ret = nvlist_lookup_uint32(nvl, TOPO_PROP_VAL_TYPE, (uint32_t *)&type);
	if (ret != 0 || type != pv->tp_type)
		return (method_geterror(nvl, ETOPO_PROP_TYPE, err));

	/* Release the last value and re-assign to the new value */
	nvlist_free(pv->tp_val);
	pv->tp_val = nvl;

	return (0);
}

static topo_propval_t *
prop_get(tnode_t *node, const char *pgname, const char *pname, nvlist_t *pargs,
    int *err)
{
	topo_propval_t *pv = NULL;

	if ((pv = propval_get(pgroup_get(node, pgname), pname)) == NULL) {
		*err = ETOPO_PROP_NOENT;
		return (NULL);
	}

	if (pv->tp_flag & TOPO_PROP_NONVOLATILE && pv->tp_val != NULL)
		return (pv);

	if (pv->tp_method != NULL) {
		if (prop_method_get(node, pv, pv->tp_method, pargs, err) < 0)
			return (NULL);
	}

	return (pv);
}

static int
get_properror(tnode_t *node, int *errp, int err)
{
	topo_node_unlock(node);
	*errp = err;
	return (-1);
}

static int
prop_getval(tnode_t *node, const char *pgname, const char *pname, void *val,
    topo_type_t type, uint_t *nelems, int *err)
{
	int i, j, ret = 0;
	topo_hdl_t *thp = node->tn_hdl;
	topo_propval_t *pv;

	topo_node_lock(node);
	if ((pv = prop_get(node, pgname, pname, NULL, err))
	    == NULL)
		return (get_properror(node, err, *err));

	if (pv->tp_type != type)
		return (get_properror(node, err, ETOPO_PROP_TYPE));

	switch (type) {
		case TOPO_TYPE_INT32:
			ret = nvlist_lookup_int32(pv->tp_val, TOPO_PROP_VAL_VAL,
			    (int32_t *)val);
			break;
		case TOPO_TYPE_UINT32:
			ret = nvlist_lookup_uint32(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (uint32_t *)val);
			break;
		case TOPO_TYPE_INT64:
			ret = nvlist_lookup_int64(pv->tp_val, TOPO_PROP_VAL_VAL,
			    (int64_t *)val);
			break;
		case TOPO_TYPE_UINT64:
			ret = nvlist_lookup_uint64(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (uint64_t *)val);
			break;
		case TOPO_TYPE_DOUBLE:
			ret = nvlist_lookup_double(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (double *)val);
			break;
		case TOPO_TYPE_STRING: {
			char *str;

			ret = nvlist_lookup_string(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &str);
			if (ret == 0) {
				char *s2;
				if ((s2 = topo_hdl_strdup(thp, str)) == NULL)
					ret = -1;
				else
					*(char **)val = s2;
			}
			break;
		}
		case TOPO_TYPE_FMRI: {
			nvlist_t *nvl;

			ret = nvlist_lookup_nvlist(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &nvl);
			if (ret == 0)
				ret = topo_hdl_nvdup(thp, nvl,
				    (nvlist_t **)val);
			break;
		}
		case TOPO_TYPE_INT32_ARRAY: {
			int32_t *a1, *a2;

			if ((ret = nvlist_lookup_int32_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &a2, nelems)) != 0)
				break;
			if ((a1 = topo_hdl_alloc(thp, sizeof (int32_t) *
			    *nelems)) == NULL) {
				ret = ETOPO_NOMEM;
				break;
			}
			for (i = 0; i < *nelems; ++i)
				a1[i] = a2[i];
			*(int32_t **)val = a1;
			break;
		}
		case TOPO_TYPE_UINT32_ARRAY: {
			uint32_t *a1, *a2;

			if ((ret = nvlist_lookup_uint32_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &a2, nelems)) != 0)
				break;
			if ((a1 = topo_hdl_alloc(thp, sizeof (uint32_t) *
			    *nelems)) == NULL) {
				ret = ETOPO_NOMEM;
				break;
			}
			for (i = 0; i < *nelems; ++i)
				a1[i] = a2[i];
			*(uint32_t **)val = a1;
			break;
		}
		case TOPO_TYPE_INT64_ARRAY: {
			int64_t *a1, *a2;

			if ((ret = nvlist_lookup_int64_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &a2, nelems)) != 0)
				break;
			if ((a1 = topo_hdl_alloc(thp, sizeof (int64_t) *
			    *nelems)) == NULL) {
				ret = ETOPO_NOMEM;
				break;
			}
			for (i = 0; i < *nelems; ++i)
				a1[i] = a2[i];
			*(int64_t **)val = a1;
			break;
		}
		case TOPO_TYPE_UINT64_ARRAY: {
			uint64_t *a1, *a2;

			if ((ret = nvlist_lookup_uint64_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &a2, nelems)) != 0)
				break;
			if ((a1 = topo_hdl_alloc(thp, sizeof (uint64_t) *
			    *nelems)) == NULL) {
				ret = ETOPO_NOMEM;
				break;
			}
			for (i = 0; i < *nelems; ++i)
				a1[i] = a2[i];
			*(uint64_t **)val = a1;
			break;
		}
		case TOPO_TYPE_STRING_ARRAY: {
			char **a1, **a2;

			if ((ret = nvlist_lookup_string_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &a2, nelems)) != 0)
				break;
			if ((a1 = topo_hdl_alloc(thp, sizeof (char *) *
			    *nelems)) == NULL) {
				ret = ETOPO_NOMEM;
				break;
			}
			for (i = 0; i < *nelems; ++i) {
				if ((a1[i] = topo_hdl_strdup(thp, a2[i]))
				    == NULL) {
					for (j = 0; j < i; ++j)
						topo_hdl_free(thp, a1[j],
						    sizeof (char *));
					topo_hdl_free(thp, a1,
					    sizeof (char *) * *nelems);
					break;
				}
			}
			*(char ***)val = a1;
			break;
		}
		case TOPO_TYPE_FMRI_ARRAY: {
			nvlist_t **a1, **a2;

			if ((ret = nvlist_lookup_nvlist_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &a2, nelems)) != 0)
				break;
			if ((a1 = topo_hdl_alloc(thp, sizeof (nvlist_t *) *
			    *nelems)) == NULL) {
				ret = ETOPO_NOMEM;
				break;
			}
			for (i = 0; i < *nelems; ++i) {
				if (topo_hdl_nvdup(thp, a2[i], &a1[i]) < 0) {
					for (j = 0; j < i; ++j)
						nvlist_free(a1[j]);
					topo_hdl_free(thp, a1,
					    sizeof (nvlist_t *) * *nelems);
					break;
				}
			}
			*(nvlist_t ***)val = a1;
			break;
		}
		default:
			ret = ETOPO_PROP_NOENT;
	}

	if (ret != 0)
		if (ret == ENOENT)
			return (get_properror(node, err, ETOPO_PROP_NOENT));
		else if (ret < ETOPO_UNKNOWN)
			return (get_properror(node, err, ETOPO_PROP_NVL));
		else
			return (get_properror(node, err, ret));

	topo_node_unlock(node);
	return (0);
}

int
topo_prop_get_int32(tnode_t *node, const char *pgname, const char *pname,
    int32_t *val, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val, TOPO_TYPE_INT32,
	    NULL, err));
}

int
topo_prop_get_uint32(tnode_t *node, const char *pgname, const char *pname,
    uint32_t *val, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val, TOPO_TYPE_UINT32,
	    NULL, err));
}

int
topo_prop_get_int64(tnode_t *node, const char *pgname, const char *pname,
    int64_t *val, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val, TOPO_TYPE_INT64,
	    NULL, err));
}

int
topo_prop_get_uint64(tnode_t *node, const char *pgname, const char *pname,
    uint64_t *val, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val, TOPO_TYPE_UINT64,
	    NULL, err));
}

int
topo_prop_get_double(tnode_t *node, const char *pgname, const char *pname,
    double *val, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val, TOPO_TYPE_DOUBLE,
	    NULL, err));
}

int
topo_prop_get_string(tnode_t *node, const char *pgname, const char *pname,
    char **val, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val, TOPO_TYPE_STRING,
	    NULL, err));
}

int
topo_prop_get_fmri(tnode_t *node, const char *pgname, const char *pname,
    nvlist_t **val, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val, TOPO_TYPE_FMRI,
	    NULL, err));
}

int
topo_prop_get_int32_array(tnode_t *node, const char *pgname, const char *pname,
    int32_t **val, uint_t *nelem, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val,
	    TOPO_TYPE_INT32_ARRAY, nelem, err));
}

int
topo_prop_get_uint32_array(tnode_t *node, const char *pgname, const char *pname,
    uint32_t **val, uint_t *nelem, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val,
	    TOPO_TYPE_UINT32_ARRAY, nelem, err));
}

int
topo_prop_get_int64_array(tnode_t *node, const char *pgname, const char *pname,
    int64_t **val, uint_t *nelem, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val,
	    TOPO_TYPE_INT64_ARRAY, nelem, err));
}

int
topo_prop_get_uint64_array(tnode_t *node, const char *pgname, const char *pname,
    uint64_t **val, uint_t *nelem, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val,
	    TOPO_TYPE_UINT64_ARRAY, nelem, err));
}

int
topo_prop_get_string_array(tnode_t *node, const char *pgname, const char *pname,
    char ***val, uint_t *nelem, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val,
	    TOPO_TYPE_STRING_ARRAY, nelem, err));
}

int
topo_prop_get_fmri_array(tnode_t *node, const char *pgname, const char *pname,
    nvlist_t ***val, uint_t *nelem, int *err)
{
	return (prop_getval(node, pgname, pname, (void *)val,
	    TOPO_TYPE_FMRI_ARRAY, nelem, err));
}

static topo_propval_t *
set_seterror(tnode_t *node, topo_proplist_t *pvl, int *errp, int err)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_propval_t *pv;

	if (pvl != NULL) {
		pv = pvl->tp_pval;
		topo_propval_destroy(pv);
		topo_hdl_free(thp, pvl, sizeof (topo_proplist_t));
	}

	topo_node_unlock(node);
	*errp = err;

	return (NULL);
}

static topo_propval_t *
prop_create(tnode_t *node, const char *pgname, const char *pname,
    topo_type_t type, int flag, int *err)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_pgroup_t *pg;
	topo_propval_t *pv;
	topo_proplist_t *pvl;

	/*
	 * Replace existing prop value with new one
	 */
	if ((pg = pgroup_get(node, pgname)) == NULL) {
		topo_node_unlock(node);
		*err = ETOPO_PROP_NOENT;
		return (NULL);
	}

	if ((pv = propval_get(pg, pname)) != NULL) {
		if (pv->tp_type != type)
			return (set_seterror(node, NULL, err, ETOPO_PROP_TYPE));
		else if (! (pv->tp_flag & TOPO_PROP_MUTABLE))
			return (set_seterror(node, NULL, err, ETOPO_PROP_DEFD));

		nvlist_free(pv->tp_val);
		pv->tp_val = NULL;
	} else {
		if ((pvl = topo_hdl_zalloc(thp, sizeof (topo_proplist_t)))
		    == NULL)
			return (set_seterror(node, NULL, err, ETOPO_NOMEM));

		if ((pv = topo_hdl_zalloc(thp, sizeof (topo_propval_t)))
		    == NULL)
			return (set_seterror(node, pvl, err, ETOPO_NOMEM));

		pv->tp_hdl = thp;
		pvl->tp_pval = pv;

		if ((pv->tp_name = topo_hdl_strdup(thp, pname))
		    == NULL)
			return (set_seterror(node, pvl, err, ETOPO_NOMEM));
		pv->tp_flag = flag;
		pv->tp_type = type;
		topo_prop_hold(pv);
		topo_list_append(&pg->tpg_pvals, pvl);
	}

	return (pv);
}

static int
topo_prop_set(tnode_t *node, const char *pgname, const char *pname,
    topo_type_t type, int flag, void *val, int nelems, int *err)
{
	int ret;
	topo_hdl_t *thp = node->tn_hdl;
	nvlist_t *nvl;

	if (topo_hdl_nvalloc(thp, &nvl, NV_UNIQUE_NAME) < 0) {
		*err = ETOPO_PROP_NVL;
		return (-1);
	}

	ret = nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, pname);
	ret |= nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, type);
	switch (type) {
		case TOPO_TYPE_INT32:
			ret |= nvlist_add_int32(nvl, TOPO_PROP_VAL_VAL,
			    *(int32_t *)val);
			break;
		case TOPO_TYPE_UINT32:
			ret |= nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL,
			    *(uint32_t *)val);
			break;
		case TOPO_TYPE_INT64:
			ret |= nvlist_add_int64(nvl, TOPO_PROP_VAL_VAL,
			    *(int64_t *)val);
			break;
		case TOPO_TYPE_UINT64:
			ret |= nvlist_add_uint64(nvl, TOPO_PROP_VAL_VAL,
			    *(uint64_t *)val);
			break;
		case TOPO_TYPE_DOUBLE:
			ret |= nvlist_add_double(nvl, TOPO_PROP_VAL_VAL,
			    *(double *)val);
			break;
		case TOPO_TYPE_STRING:
			ret |= nvlist_add_string(nvl, TOPO_PROP_VAL_VAL,
			    (char *)val);
			break;
		case TOPO_TYPE_FMRI:
			ret |= nvlist_add_nvlist(nvl, TOPO_PROP_VAL_VAL,
			    (nvlist_t *)val);
			break;
		case TOPO_TYPE_INT32_ARRAY:
			ret |= nvlist_add_int32_array(nvl,
			    TOPO_PROP_VAL_VAL, (int32_t *)val, nelems);
			break;
		case TOPO_TYPE_UINT32_ARRAY:
			ret |= nvlist_add_uint32_array(nvl,
			    TOPO_PROP_VAL_VAL, (uint32_t *)val, nelems);
			break;
		case TOPO_TYPE_INT64_ARRAY:
			ret |= nvlist_add_int64_array(nvl,
			    TOPO_PROP_VAL_VAL, (int64_t *)val, nelems);
			break;
		case TOPO_TYPE_UINT64_ARRAY:
			ret |= nvlist_add_uint64_array(nvl,
			    TOPO_PROP_VAL_VAL, (uint64_t *)val, nelems);
			break;
		case TOPO_TYPE_STRING_ARRAY:
			ret |= nvlist_add_string_array(nvl,
			    TOPO_PROP_VAL_VAL, (char **)val, nelems);
			break;
		case TOPO_TYPE_FMRI_ARRAY:
			ret |= nvlist_add_nvlist_array(nvl,
			    TOPO_PROP_VAL_VAL, (nvlist_t **)val, nelems);
			break;
		default:
			*err = ETOPO_PROP_TYPE;
			return (-1);
	}

	if (ret != 0) {
		nvlist_free(nvl);
		if (ret == ENOMEM) {
			*err = ETOPO_PROP_NOMEM;
			return (-1);
		} else {
			*err = ETOPO_PROP_NVL;
			return (-1);
		}
	}

	if (topo_prop_setprop(node, pgname, nvl, flag, nvl, err) != 0) {
		nvlist_free(nvl);
		return (-1); /* err set */
	}
	nvlist_free(nvl);
	return (ret);
}

int
topo_prop_set_int32(tnode_t *node, const char *pgname, const char *pname,
    int flag, int32_t val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_INT32, flag,
	    &val, 1, err));
}

int
topo_prop_set_uint32(tnode_t *node, const char *pgname, const char *pname,
    int flag, uint32_t val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_UINT32, flag,
	    &val, 1, err));
}

int
topo_prop_set_int64(tnode_t *node, const char *pgname, const char *pname,
    int flag, int64_t val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_INT64, flag,
	    &val, 1, err));
}

int
topo_prop_set_uint64(tnode_t *node, const char *pgname, const char *pname,
    int flag, uint64_t val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_UINT64, flag,
	    &val, 1, err));
}

int
topo_prop_set_double(tnode_t *node, const char *pgname, const char *pname,
    int flag, double val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_DOUBLE, flag,
	    &val, 1, err));
}

int
topo_prop_set_string(tnode_t *node, const char *pgname, const char *pname,
    int flag, const char *val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_STRING, flag,
	    (void *)val, 1, err));
}

int
topo_prop_set_fmri(tnode_t *node, const char *pgname, const char *pname,
    int flag, const nvlist_t *fmri, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_FMRI, flag,
	    (void *)fmri, 1, err));
}

int
topo_prop_set_int32_array(tnode_t *node, const char *pgname, const char *pname,
    int flag, int32_t *val, uint_t nelems, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_INT32_ARRAY, flag,
	    val, nelems, err));
}

int
topo_prop_set_uint32_array(tnode_t *node, const char *pgname, const char *pname,
    int flag, uint32_t *val, uint_t nelems, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_UINT32_ARRAY, flag,
	    val, nelems, err));
}

int
topo_prop_set_int64_array(tnode_t *node, const char *pgname, const char *pname,
    int flag, int64_t *val, uint_t nelems, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_INT64_ARRAY, flag,
	    val, nelems, err));
}

int
topo_prop_set_uint64_array(tnode_t *node, const char *pgname, const char *pname,
    int flag, uint64_t *val, uint_t nelems, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_UINT64_ARRAY, flag,
	    val, nelems, err));
}

int
topo_prop_set_string_array(tnode_t *node, const char *pgname, const char *pname,
    int flag, const char **val, uint_t nelems, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_STRING_ARRAY, flag,
	    (void *)val, nelems, err));
}

int
topo_prop_set_fmri_array(tnode_t *node, const char *pgname, const char *pname,
    int flag, const nvlist_t **fmri, uint_t nelems, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_FMRI_ARRAY, flag,
	    (void *)fmri, nelems, err));
}

/*
 * topo_prop_setprop() is a private project function for fmtopo
 */
int
topo_prop_setprop(tnode_t *node, const char *pgname, nvlist_t *prop,
    int flag, nvlist_t *pargs, int *err)
{
	int ret;
	topo_hdl_t *thp = node->tn_hdl;
	topo_propval_t *pv;
	nvlist_t *nvl, *args;
	char *name;
	topo_type_t type;

	if (nvlist_lookup_string(prop, TOPO_PROP_VAL_NAME, &name) != 0) {
		*err = ETOPO_PROP_NAME;
		return (-1);
	}
	if (nvlist_lookup_uint32(prop, TOPO_PROP_VAL_TYPE, (uint32_t *)&type)
	    != 0) {
		*err = ETOPO_PROP_TYPE;
		return (-1);
	}

	topo_node_lock(node);
	if ((pv = prop_create(node, pgname, name, type, flag, err)) == NULL)
		return (-1); /* unlocked and err set */

	/*
	 * Set by method or set to new prop value.  If we fail, leave
	 * property in list with old value.
	 */
	if (pv->tp_method != NULL) {
		topo_propmethod_t *pm = pv->tp_method;

		if (topo_hdl_nvalloc(pv->tp_hdl, &args, NV_UNIQUE_NAME) < 0) {
			topo_node_unlock(node);
			*err = ETOPO_PROP_NOMEM;
			return (-1);
		}
		ret = nvlist_add_nvlist(args, TOPO_PROP_ARGS, pm->tpm_args);
		if (pargs != NULL)
			ret |= nvlist_add_nvlist(args, TOPO_PROP_PARGS, pargs);

		if (ret != 0) {
			topo_node_unlock(node);
			nvlist_free(args);
			*err = ETOPO_PROP_NVL;
			return (-1);
		}

		/*
		 *
		 * Grab a reference to the property and then unlock the node.
		 * This will allow property methods to safely re-enter the
		 * prop_get codepath, making it possible for property methods
		 * to access other property values on the same node w\o causing
		 * a deadlock.
		 *
		 * We don't technically need this now, since this interface is
		 * currently only used by fmtopo (which is single-threaded), but
		 * we may make this interface available to other parts of
		 * libtopo in the future, so best to make it MT-safe now.
		 */
		topo_prop_hold(pv);
		topo_node_unlock(node);
		ret = topo_method_call(node, pm->tpm_name, pm->tpm_version,
		    args, &nvl, err);
		topo_node_lock(node);
		topo_prop_rele(pv);

		nvlist_free(args);
	} else {
		if ((ret = topo_hdl_nvdup(thp, prop, &nvl)) != 0)
			*err = ETOPO_PROP_NOMEM;
	}

	if (ret != 0) {
		topo_node_unlock(node);
		return (-1);
	}

	pv->tp_val = nvl;
	topo_node_unlock(node);
	return (0);
}

static int
register_methoderror(tnode_t *node, topo_propmethod_t *pm, int *errp, int l,
    int err)
{
	topo_hdl_t *thp = node->tn_hdl;

	if (pm != NULL) {
		if (pm->tpm_name != NULL)
			topo_hdl_strfree(thp, pm->tpm_name);
		nvlist_free(pm->tpm_args);
		topo_hdl_free(thp, pm, sizeof (topo_propmethod_t));
	}

	*errp = err;

	if (l != 0)
		topo_node_unlock(node);

	return (-1);
}

int
prop_method_register(tnode_t *node, const char *pgname, const char *pname,
    topo_type_t ptype, const char *mname, topo_version_t version,
    const nvlist_t *args, int *err)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_propmethod_t *pm = NULL;
	topo_propval_t *pv = NULL;

	if ((pm = topo_hdl_zalloc(thp, sizeof (topo_propmethod_t))) == NULL)
		return (register_methoderror(node, pm, err, 1,
		    ETOPO_PROP_NOMEM));

	if ((pm->tpm_name = topo_hdl_strdup(thp, mname)) == NULL)
		return (register_methoderror(node, pm, err, 1,
		    ETOPO_PROP_NOMEM));

	pm->tpm_version = version;

	if (topo_hdl_nvdup(thp, (nvlist_t *)args, &pm->tpm_args) != 0)
		return (register_methoderror(node, pm, err, 1,
		    ETOPO_PROP_NOMEM));

	/*
	 * It's possible the property may already exist.  However we still want
	 * to allow the method to be registered.  This is to handle the case
	 * where we specify a prop method in an xml map to override the value
	 * that was set by the enumerator.
	 *
	 * By default, propmethod-backed properties are not MUTABLE.  This is
	 * done to simplify the programming model for modules that implement
	 * property methods as most propmethods tend to only support get
	 * operations.  Enumerator modules can override this by calling
	 * topo_prop_setmutable().  Propmethods that are registered via XML can
	 * be set as mutable via the optional "mutable" attribute, which will
	 * result in the xml parser calling topo_prop_setflags() after
	 * registering the propmethod.
	 */
	if ((pv = propval_get(pgroup_get(node, pgname), pname)) == NULL)
		if ((pv = prop_create(node, pgname, pname, ptype,
		    TOPO_PROP_IMMUTABLE, err)) == NULL) {
			/* node unlocked */
			return (register_methoderror(node, pm, err, 0, *err));
		}

	if (pv->tp_method != NULL)
		return (register_methoderror(node, pm, err, 1,
		    ETOPO_METHOD_DEFD));

	if (pv->tp_val != NULL) {
		nvlist_free(pv->tp_val);
		pv->tp_val = NULL;
	}
	pv->tp_method = pm;

	topo_node_unlock(node);

	return (0);
}

int
topo_prop_method_register(tnode_t *node, const char *pgname, const char *pname,
    topo_type_t ptype, const char *mname, const nvlist_t *args, int *err)
{
	topo_imethod_t *mp;

	topo_node_lock(node);

	if ((mp = topo_method_lookup(node, mname)) == NULL)
		return (register_methoderror(node, NULL, err, 1,
		    ETOPO_METHOD_NOTSUP)); /* node unlocked */

	topo_node_lock(node);

	return (prop_method_register(node, pgname, pname, ptype, mname,
	    mp->tim_version, args, err)); /* err set and node unlocked */
}

int
topo_prop_method_version_register(tnode_t *node, const char *pgname,
    const char *pname, topo_type_t ptype, const char *mname,
    topo_version_t version, const nvlist_t *args, int *err)
{
	topo_imethod_t *mp;

	topo_node_lock(node);

	if ((mp = topo_method_lookup(node, mname)) == NULL)
		return (register_methoderror(node, NULL, err, 1,
		    ETOPO_METHOD_NOTSUP)); /* node unlocked */

	topo_node_lock(node);

	if (version < mp->tim_version)
		return (register_methoderror(node, NULL, err, 1,
		    ETOPO_METHOD_VEROLD));
	if (version > mp->tim_version)
		return (register_methoderror(node, NULL, err, 1,
		    ETOPO_METHOD_VERNEW));

	return (prop_method_register(node, pgname, pname, ptype, mname,
	    version, args, err)); /* err set and node unlocked */
}

void
topo_prop_method_unregister(tnode_t *node, const char *pgname,
    const char *pname)
{
	topo_propval_t *pv;
	topo_pgroup_t *pg;
	topo_proplist_t *pvl;
	topo_hdl_t *thp = node->tn_hdl;

	topo_node_lock(node);

	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (strcmp(pg->tpg_info->tpi_name, pgname) == 0) {
			break;
		}
	}

	if (pg == NULL) {
		topo_node_unlock(node);
		return;
	}

	for (pvl = topo_list_next(&pg->tpg_list); pvl != NULL;
	    pvl = topo_list_next(pvl)) {
		pv = pvl->tp_pval;
		if (strcmp(pv->tp_name, pname) == 0) {
			topo_list_delete(&pg->tpg_pvals, pvl);
			assert(pv->tp_refs == 1);
			topo_prop_rele(pv);
			topo_hdl_free(thp, pvl, sizeof (topo_proplist_t));
			break;
		}
	}

	topo_node_unlock(node);
}

int
topo_prop_setmutable(tnode_t *node, const char *pgname, const char *pname,
    int *err)
{
	topo_propval_t *pv = NULL;

	topo_node_lock(node);
	if ((pv = propval_get(pgroup_get(node, pgname), pname)) == NULL) {
		topo_node_unlock(node);
		*err = ETOPO_PROP_NOENT;
		return (-1);
	}

	/*
	 * If the property is being inherited then we don't want to allow a
	 * change from IMMUTABLE to MUTABLE.
	 */
	if (pv->tp_refs > 1) {
		topo_node_unlock(node);
		*err = ETOPO_PROP_DEFD;
		return (-1);
	}
	pv->tp_flag |= TOPO_PROP_MUTABLE;

	topo_node_unlock(node);

	return (0);
}
int
topo_prop_setnonvolatile(tnode_t *node, const char *pgname, const char *pname,
    int *err)
{
	topo_propval_t *pv = NULL;

	topo_node_lock(node);
	if ((pv = propval_get(pgroup_get(node, pgname), pname)) == NULL) {
		topo_node_unlock(node);
		*err = ETOPO_PROP_NOENT;
		return (-1);
	}

	pv->tp_flag |= TOPO_PROP_NONVOLATILE;

	topo_node_unlock(node);

	return (0);
}

static int
inherit_seterror(tnode_t *node, int *errp, int err)
{
	topo_node_unlock(node);
	topo_node_unlock(node->tn_parent);

	*errp = err;

	return (-1);
}

int
topo_prop_inherit(tnode_t *node, const char *pgname, const char *name, int *err)
{
	topo_hdl_t *thp = node->tn_hdl;
	tnode_t *pnode = node->tn_parent;
	topo_pgroup_t *pg;
	topo_propval_t *pv;
	topo_proplist_t *pvl;

	topo_node_lock(pnode);
	topo_node_lock(node);

	/*
	 * Check if the requested property group and prop val are already set
	 * on the node.
	 */
	if (propval_get(pgroup_get(node, pgname), name) != NULL)
		return (inherit_seterror(node, err, ETOPO_PROP_DEFD));

	/*
	 * Check if the requested property group and prop val exists on the
	 * parent node
	 */
	if ((pv = propval_get(pgroup_get(pnode, pgname), name)) == NULL)
		return (inherit_seterror(node, err, ETOPO_PROP_NOENT));

	/*
	 * Can this propval be inherited?
	 */
	if (pv->tp_flag & TOPO_PROP_MUTABLE)
		return (inherit_seterror(node, err, ETOPO_PROP_NOINHERIT));

	/*
	 * Property group should already exist: bump the ref count for this
	 * propval and add it to the node's property group
	 */
	if ((pg = pgroup_get(node, pgname)) == NULL)
		return (inherit_seterror(node, err, ETOPO_PROP_NOENT));

	if ((pvl = topo_hdl_zalloc(thp, sizeof (topo_proplist_t)))
	    == NULL)
		return (inherit_seterror(node, err, ETOPO_NOMEM));

	topo_prop_hold(pv);
	pvl->tp_pval = pv;
	topo_list_append(&pg->tpg_pvals, pvl);

	topo_node_unlock(node);
	topo_node_unlock(pnode);

	return (0);
}

topo_pgroup_info_t *
topo_pgroup_info(tnode_t *node, const char *pgname, int *err)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_pgroup_t *pg;
	topo_ipgroup_info_t *pip;
	topo_pgroup_info_t *info;

	topo_node_lock(node);
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (strcmp(pgname, pg->tpg_info->tpi_name) == 0) {
			if ((info = topo_hdl_alloc(thp,
			    sizeof (topo_pgroup_info_t))) == NULL)
				return (NULL);

			pip = pg->tpg_info;
			if ((info->tpi_name =
			    topo_hdl_strdup(thp, pip->tpi_name)) == NULL) {
				*err = ETOPO_PROP_NOMEM;
				topo_hdl_free(thp, info,
				    sizeof (topo_pgroup_info_t));
				topo_node_unlock(node);
				return (NULL);
			}
			info->tpi_namestab = pip->tpi_namestab;
			info->tpi_datastab = pip->tpi_datastab;
			info->tpi_version = pip->tpi_version;
			topo_node_unlock(node);
			return (info);
		}
	}

	*err = ETOPO_PROP_NOENT;
	topo_node_unlock(node);
	return (NULL);
}

static int
pgroup_seterr(tnode_t *node, topo_pgroup_t *pg, topo_ipgroup_info_t *pip,
    int *err)
{
	topo_hdl_t *thp = node->tn_hdl;

	if (pip != NULL) {
		if (pip->tpi_name != NULL)
			topo_hdl_strfree(thp, (char *)pip->tpi_name);
		topo_hdl_free(thp, pip, sizeof (topo_ipgroup_info_t));
	}

	topo_hdl_free(thp, pg, sizeof (topo_pgroup_t));
	*err = ETOPO_NOMEM;

	topo_node_unlock(node);

	return (-1);
}

int
topo_pgroup_create(tnode_t *node, const topo_pgroup_info_t *pinfo, int *err)
{
	topo_pgroup_t *pg;
	topo_ipgroup_info_t *pip;
	topo_hdl_t *thp = node->tn_hdl;

	*err = 0;

	topo_node_lock(node);
	/*
	 * Check for an existing pgroup
	 */
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (strcmp(pg->tpg_info->tpi_name, pinfo->tpi_name) == 0) {
			*err = ETOPO_PROP_DEFD;
			topo_node_unlock(node);
			return (-1);
		}
	}

	if ((pg = topo_hdl_zalloc(thp, sizeof (topo_pgroup_t))) == NULL) {
		*err = ETOPO_NOMEM;
		topo_node_unlock(node);
		return (-1);
	}

	if ((pip = topo_hdl_zalloc(thp, sizeof (topo_ipgroup_info_t)))
	    == NULL)
		return (pgroup_seterr(node, pg, pip, err));

	if ((pip->tpi_name = topo_hdl_strdup(thp, pinfo->tpi_name))
	    == NULL)
		return (pgroup_seterr(node, pg, pip, err));

	pip->tpi_namestab = pinfo->tpi_namestab;
	pip->tpi_datastab = pinfo->tpi_datastab;
	pip->tpi_version = pinfo->tpi_version;

	pg->tpg_info = pip;

	topo_list_append(&node->tn_pgroups, pg);
	topo_node_unlock(node);

	return (0);
}

void
topo_pgroup_destroy(tnode_t *node, const char *pname)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_pgroup_t *pg;
	topo_proplist_t *pvl;
	topo_ipgroup_info_t *pip;

	topo_node_lock(node);
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (strcmp(pg->tpg_info->tpi_name, pname) == 0) {
			break;
		}
	}

	if (pg == NULL) {
		topo_node_unlock(node);
		return;
	}

	while ((pvl = topo_list_next(&pg->tpg_list)) != NULL) {
		topo_list_delete(&pg->tpg_pvals, pvl);
		topo_prop_rele(pvl->tp_pval);
		topo_hdl_free(thp, pvl, sizeof (topo_proplist_t));
	}

	topo_list_delete(&node->tn_pgroups, pg);
	topo_node_unlock(node);

	pip = pg->tpg_info;
	if (pip != NULL) {
		if (pip->tpi_name != NULL)
			topo_hdl_strfree(thp, (char *)pip->tpi_name);
		topo_hdl_free(thp, pip, sizeof (topo_ipgroup_info_t));
	}

	topo_hdl_free(thp, pg, sizeof (topo_pgroup_t));
}

void
topo_pgroup_destroy_all(tnode_t *node)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_pgroup_t *pg;
	topo_proplist_t *pvl;
	topo_ipgroup_info_t *pip;

	topo_node_lock(node);
	while ((pg = topo_list_next(&node->tn_pgroups)) != NULL) {
		while ((pvl = topo_list_next(&pg->tpg_pvals)) != NULL) {
			topo_list_delete(&pg->tpg_pvals, pvl);
			topo_prop_rele(pvl->tp_pval);
			topo_hdl_free(thp, pvl, sizeof (topo_proplist_t));
		}

		topo_list_delete(&node->tn_pgroups, pg);

		pip = pg->tpg_info;
		if (pip != NULL) {
			if (pip->tpi_name != NULL)
				topo_hdl_strfree(thp, (char *)pip->tpi_name);
			topo_hdl_free(thp, pip, sizeof (topo_pgroup_info_t));
		}

		topo_hdl_free(thp, pg, sizeof (topo_pgroup_t));
	}
	topo_node_unlock(node);
}

static void
propmethod_destroy(topo_hdl_t *thp, topo_propval_t *pv)
{
	topo_propmethod_t *pm;

	pm = pv->tp_method;
	if (pm != NULL) {
		if (pm->tpm_name != NULL)
			topo_hdl_strfree(thp, pm->tpm_name);
		nvlist_free(pm->tpm_args);
		topo_hdl_free(thp, pm, sizeof (topo_propmethod_t));
		pv->tp_method = NULL;
	}
}

static void
topo_propval_destroy(topo_propval_t *pv)
{
	topo_hdl_t *thp;

	if (pv == NULL)
		return;

	thp = pv->tp_hdl;

	if (pv->tp_name != NULL)
		topo_hdl_strfree(thp, pv->tp_name);

	nvlist_free(pv->tp_val);

	propmethod_destroy(thp, pv);

	topo_hdl_free(thp, pv, sizeof (topo_propval_t));
}

void
topo_prop_hold(topo_propval_t *pv)
{
	pv->tp_refs++;
}

void
topo_prop_rele(topo_propval_t *pv)
{
	pv->tp_refs--;

	assert(pv->tp_refs >= 0);

	if (pv->tp_refs == 0)
		topo_propval_destroy(pv);
}

/*
 * topo_prop_getprop() and topo_prop_getprops() are private project functions
 * for fmtopo
 */
int
topo_prop_getprop(tnode_t *node, const char *pgname, const char *pname,
    nvlist_t *args, nvlist_t **prop, int *err)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_propval_t *pv;

	topo_node_lock(node);
	if ((pv = prop_get(node, pgname, pname, args, err)) == NULL) {
		(void) get_properror(node, err, *err);
		return (-1);
	}

	if (topo_hdl_nvdup(thp, pv->tp_val, prop) != 0) {
		(void) get_properror(node, err, ETOPO_NOMEM);
		return (-1);
	}
	topo_node_unlock(node);

	return (0);
}

static int
prop_val_add(tnode_t *node, nvlist_t **nvl, topo_propval_t *pv, int *err)
{
	if (pv->tp_method != NULL)
		if (prop_method_get(node, pv, pv->tp_method, NULL, err) < 0)
			return (-1);

	if (pv->tp_val == NULL) {
		*err = ETOPO_PROP_NOENT;
		return (-1);
	}

	if (topo_hdl_nvdup(pv->tp_hdl, pv->tp_val, nvl) != 0) {
		*err = ETOPO_PROP_NOMEM;
		return (-1);
	}

	return (0);
}

static int
get_pgrp_seterror(tnode_t *node, nvlist_t *nvl, int *errp, int err)
{
	topo_node_unlock(node);

	nvlist_free(nvl);

	*errp = err;

	return (-1);
}

int
topo_prop_getpgrp(tnode_t *node, const char *pgname, nvlist_t **pgrp,
    int *err)
{
	int ret;
	topo_hdl_t *thp = node->tn_hdl;
	nvlist_t *nvl, *pvnvl;
	topo_pgroup_t *pg;
	topo_propval_t *pv;
	topo_proplist_t *pvl;

	if (topo_hdl_nvalloc(thp, &nvl, 0) != 0) {
		*err = ETOPO_NOMEM;
		return (-1);
	}

	topo_node_lock(node);
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {

		if (strcmp(pgname, pg->tpg_info->tpi_name) != 0)
			continue;

		if (nvlist_add_string(nvl, TOPO_PROP_GROUP_NAME,
		    pg->tpg_info->tpi_name) != 0 ||
		    nvlist_add_string(nvl, TOPO_PROP_GROUP_NSTAB,
		    topo_stability2name(pg->tpg_info->tpi_namestab)) != 0 ||
		    nvlist_add_string(nvl, TOPO_PROP_GROUP_DSTAB,
		    topo_stability2name(pg->tpg_info->tpi_datastab)) != 0 ||
		    nvlist_add_int32(nvl, TOPO_PROP_GROUP_VERSION,
		    pg->tpg_info->tpi_version) != 0)
			return (get_pgrp_seterror(node, nvl, err,
			    ETOPO_PROP_NVL));

		for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
		    pvl = topo_list_next(pvl)) {

			pv = pvl->tp_pval;
			if (prop_val_add(node, &pvnvl, pv, err) < 0) {
				return (get_pgrp_seterror(node, nvl, err,
				    *err));
			}
			if ((ret = nvlist_add_nvlist(nvl, TOPO_PROP_VAL,
			    pvnvl)) != 0) {
				nvlist_free(pvnvl);
				return (get_pgrp_seterror(node, nvl, err, ret));
			}

			nvlist_free(pvnvl);
		}
		topo_node_unlock(node);
		*pgrp = nvl;
		return (0);
	}

	topo_node_unlock(node);
	*err = ETOPO_PROP_NOENT;
	return (-1);
}

static nvlist_t *
get_all_seterror(tnode_t *node, nvlist_t *nvl, int *errp, int err)
{
	topo_node_unlock(node);

	nvlist_free(nvl);

	*errp = err;

	return (NULL);
}

nvlist_t *
topo_prop_getprops(tnode_t *node, int *err)
{
	int ret;
	topo_hdl_t *thp = node->tn_hdl;
	nvlist_t *nvl, *pgnvl, *pvnvl;
	topo_pgroup_t *pg;
	topo_propval_t *pv;
	topo_proplist_t *pvl;

	topo_node_lock(node);
	if (topo_hdl_nvalloc(thp, &nvl, 0) != 0) {
		return (get_all_seterror(node, NULL, err, ETOPO_NOMEM));
	}

	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (topo_hdl_nvalloc(thp, &pgnvl, 0) != 0)
			return (get_all_seterror(node, nvl, err, ETOPO_NOMEM));

		if (nvlist_add_string(pgnvl, TOPO_PROP_GROUP_NAME,
		    pg->tpg_info->tpi_name) != 0 ||
		    nvlist_add_string(pgnvl, TOPO_PROP_GROUP_NSTAB,
		    topo_stability2name(pg->tpg_info->tpi_namestab)) != 0 ||
		    nvlist_add_string(pgnvl, TOPO_PROP_GROUP_DSTAB,
		    topo_stability2name(pg->tpg_info->tpi_datastab)) != 0 ||
		    nvlist_add_int32(pgnvl, TOPO_PROP_GROUP_VERSION,
		    pg->tpg_info->tpi_version) != 0)
			return (get_all_seterror(node, nvl, err,
			    ETOPO_PROP_NVL));

		for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
		    pvl = topo_list_next(pvl)) {

			pv = pvl->tp_pval;
			if (prop_val_add(node, &pvnvl, pv, err) < 0) {
				nvlist_free(pgnvl);
				return (get_all_seterror(node, nvl, err, *err));
			}
			if ((ret = nvlist_add_nvlist(pgnvl, TOPO_PROP_VAL,
			    pvnvl)) != 0) {
				nvlist_free(pgnvl);
				nvlist_free(pvnvl);
				return (get_all_seterror(node, nvl, err, ret));
			}

			nvlist_free(pvnvl);
		}
		if ((ret = nvlist_add_nvlist(nvl, TOPO_PROP_GROUP, pgnvl))
		    != 0) {
			nvlist_free(pgnvl);
			return (get_all_seterror(node, nvl, err, ret));
		}

		nvlist_free(pgnvl);
	}

	topo_node_unlock(node);

	return (nvl);
}
