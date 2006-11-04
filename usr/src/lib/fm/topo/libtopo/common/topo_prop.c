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

#include <strings.h>
#include <assert.h>
#include <fm/libtopo.h>
#include <topo_prop.h>
#include <topo_string.h>
#include <topo_alloc.h>
#include <topo_error.h>

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

	for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
	    pvl = topo_list_next(pvl)) {
		if (strcmp(pvl->tp_pval->tp_name, pname) == 0)
			return (pvl->tp_pval);
	}

	return (NULL);
}

static topo_propval_t *
topo_prop_get(tnode_t *node, const char *pgname, const char *pname, int *err)
{
	topo_pgroup_t *pg = NULL;
	topo_propval_t *pv = NULL;

	if ((pg = pgroup_get(node, pgname)) == NULL) {
		*err = ETOPO_PROP_NOENT;
		return (NULL);
	}

	if ((pv = propval_get(pg, pname)) == NULL) {
		*err = ETOPO_PROP_NOENT;
		return (NULL);
	}

	return (pv);
}

static int
prop_val_add(nvlist_t *nvl, topo_propval_t *pv, int *err)
{
	int ret = 0;
	uint_t nelems;

	if (nvlist_add_int32(nvl, TOPO_PROP_VAL_TYPE, pv->tp_type) != 0)
		return (-1);

	switch (pv->tp_type) {
		case TOPO_TYPE_INT32:
		{
			int32_t val;
			if ((ret = nvlist_lookup_int32(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val)) < 0)
				break;
			ret = nvlist_add_int32(nvl, TOPO_PROP_VAL_VAL, val);
		}
		break;
		case TOPO_TYPE_UINT32:
		{
			uint32_t val;
			if ((ret = nvlist_lookup_uint32(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val)) < 0)
				break;
			ret = nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, val);
		}
		break;
		case TOPO_TYPE_INT64:
		{
			int64_t val;
			if ((ret = nvlist_lookup_int64(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val)) < 0)
				break;
			ret = nvlist_add_int64(nvl, TOPO_PROP_VAL_VAL, val);
		}
		break;
		case TOPO_TYPE_UINT64:
		{
			uint64_t val;
			if ((ret = nvlist_lookup_uint64(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val)) < 0)
				break;
			ret = nvlist_add_uint64(nvl, TOPO_PROP_VAL_VAL, val);
		}
		break;
		case TOPO_TYPE_STRING:
		{
			char *val;
			if ((ret = nvlist_lookup_string(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val)) < 0)
				break;
			ret = nvlist_add_string(nvl, TOPO_PROP_VAL_VAL, val);
		}
		break;
		case TOPO_TYPE_FMRI:
		{
			nvlist_t *val;
			if ((ret = nvlist_lookup_nvlist(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val)) < 0)
				break;
			ret =  nvlist_add_nvlist(nvl, TOPO_PROP_VAL_VAL, val);
		}
		break;
		case TOPO_TYPE_INT32_ARRAY:
		{
			int32_t *val;
			if ((ret = nvlist_lookup_int32_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val, &nelems)) < 0)
				break;
			ret = nvlist_add_int32_array(nvl, TOPO_PROP_VAL_VAL,
			    val, nelems);
		}
		break;
		case TOPO_TYPE_UINT32_ARRAY:
		{
			uint32_t *val;
			if ((ret = nvlist_lookup_uint32_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val, &nelems)) < 0)
				break;
			ret = nvlist_add_uint32_array(nvl, TOPO_PROP_VAL_VAL,
			    val, nelems);
		}
		break;
		case TOPO_TYPE_INT64_ARRAY:
		{
			int64_t *val;
			if ((ret = nvlist_lookup_int64_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val, &nelems)) < 0)
				break;
			ret = nvlist_add_int64_array(nvl, TOPO_PROP_VAL_VAL,
			    val, nelems);
		}
		break;
		case TOPO_TYPE_UINT64_ARRAY:
		{
			uint64_t *val;
			if ((ret = nvlist_lookup_uint64_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val, &nelems)) < 0)
				break;
			ret = nvlist_add_uint64_array(nvl, TOPO_PROP_VAL_VAL,
			    val, nelems);
		}
		break;
		case TOPO_TYPE_STRING_ARRAY:
		{
			char **val;
			if ((ret = nvlist_lookup_string_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val, &nelems)) < 0)
				break;
			ret = nvlist_add_string_array(nvl, TOPO_PROP_VAL_VAL,
			    val, nelems);
		}
		break;
		case TOPO_TYPE_FMRI_ARRAY:
		{
			nvlist_t **val;
			if ((ret = nvlist_lookup_nvlist_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &val, &nelems)) < 0)
				break;
			ret = nvlist_add_nvlist_array(nvl, TOPO_PROP_VAL_VAL,
			    val, nelems);
		}
		break;
		default:
			ret = ETOPO_PROP_TYPE;
	}

	if (ret != 0) {
		if (ret == ENOMEM)
			*err = ETOPO_NOMEM;
		else
			*err = ETOPO_PROP_NVL;
		return (-1);
	}

	return (0);
}

nvlist_t *
get_all_seterror(tnode_t *node, nvlist_t *nvl, int *errp, int err)
{
	topo_node_unlock(node);

	if (nvl != NULL)
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

	if (topo_hdl_nvalloc(thp, &nvl, 0) != 0) {
		return (get_all_seterror(node, NULL, err, ETOPO_NOMEM));
	}

	topo_node_lock(node);
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
			if (topo_hdl_nvalloc(thp, &pvnvl, 0)
			    != 0) {
				nvlist_free(pgnvl);
				return (get_all_seterror(node, nvl, err,
				    ETOPO_NOMEM));
			}
			if ((ret = nvlist_add_string(pvnvl, TOPO_PROP_VAL_NAME,
			    pv->tp_name)) != 0) {
				nvlist_free(pgnvl);
				nvlist_free(pvnvl);
				return (get_all_seterror(node, nvl, err, ret));
			}
			if (prop_val_add(pvnvl, pv, err) < 0) {
				nvlist_free(pgnvl);
				nvlist_free(pvnvl);
				return (get_all_seterror(node, nvl, err, ret));
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

static int
get_seterror(tnode_t *node, int *errp, int err)
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
	if ((pv = topo_prop_get(node, pgname, pname, err))
	    == NULL)
		return (get_seterror(node, err, *err));

	if (pv->tp_type != type)
		return (get_seterror(node, err, ETOPO_PROP_TYPE));

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
		case TOPO_TYPE_STRING: {
			char *str;

			ret = nvlist_lookup_string(pv->tp_val,
			    TOPO_PROP_VAL_VAL, &str);
			if (ret == 0)
				*(char **)val = topo_hdl_strdup(thp, str);
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
			return (get_seterror(node, err, ETOPO_PROP_NOENT));
		else if (ret < ETOPO_UNKNOWN)
			return (get_seterror(node, err, ETOPO_PROP_NVL));
		else
			return (get_seterror(node, err, ret));

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

static int
set_seterror(tnode_t *node, topo_proplist_t *pvl, int *errp, int err)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_propval_t *pv;

	if (pvl != NULL) {
		pv = pvl->tp_pval;
		if (pv != NULL) {
			if (pv->tp_name != NULL)
				topo_hdl_strfree(thp, pv->tp_name);
			if (pv->tp_val != NULL)
				nvlist_free(pv->tp_val);
			topo_hdl_free(thp, pv, sizeof (topo_propval_t));
		}
		topo_hdl_free(thp, pvl, sizeof (topo_proplist_t));
	}

	topo_node_unlock(node);
	*errp = err;

	return (-1);
}

static int
topo_prop_set(tnode_t *node, const char *pgname, const char *pname,
    topo_type_t type, int flag, void *val, int nelems, int *err)
{
	int ret, new_prop = 0;
	topo_hdl_t *thp = node->tn_hdl;
	topo_pgroup_t *pg;
	topo_propval_t *pv;
	topo_proplist_t *pvl;

	topo_node_lock(node);
	if ((pg = pgroup_get(node, pgname)) == NULL)
		return (set_seterror(node, NULL, err, ETOPO_PROP_NOENT));

	/*
	 * Replace existing prop value with new one
	 */
	if ((pv = propval_get(pg, pname)) != NULL) {
		if (pv->tp_type != type)
			return (set_seterror(node, NULL, err, ETOPO_PROP_TYPE));
		else if (pv->tp_flag == TOPO_PROP_IMMUTABLE)
			return (set_seterror(node, NULL, err, ETOPO_PROP_DEFD));
		nvlist_free(pv->tp_val);
		pv->tp_val = NULL;
	} else {
		/*
		 * Property values may be a shared resources among
		 * different nodes.  We will allocate resources
		 * on a per-handle basis.
		 */
		if ((pvl = topo_hdl_zalloc(thp, sizeof (topo_proplist_t)))
		    == NULL)
			return (set_seterror(node, NULL, err, ETOPO_NOMEM));

		if ((pv = topo_hdl_zalloc(thp, sizeof (topo_propval_t)))
		    == NULL)
			return (set_seterror(node, pvl, err, ETOPO_NOMEM));
		pvl->tp_pval = pv;

		if ((pv->tp_name = topo_hdl_strdup(thp, pname))
		    == NULL)
			return (set_seterror(node, pvl, err, ETOPO_NOMEM));
		pv->tp_flag = flag;
		pv->tp_type = type;
		pv->tp_hdl = thp;
		topo_prop_hold(pv);
		new_prop++;
	}

	if (topo_hdl_nvalloc(thp, &pv->tp_val, NV_UNIQUE_NAME) < 0)
		return (set_seterror(node, pvl, err, ETOPO_PROP_NVL));

	ret = 0;
	switch (type) {
		case TOPO_TYPE_INT32:
			ret = nvlist_add_int32(pv->tp_val, TOPO_PROP_VAL_VAL,
			    *(int32_t *)val);
			break;
		case TOPO_TYPE_UINT32:
			ret = nvlist_add_uint32(pv->tp_val, TOPO_PROP_VAL_VAL,
			    *(uint32_t *)val);
			break;
		case TOPO_TYPE_INT64:
			ret = nvlist_add_int64(pv->tp_val, TOPO_PROP_VAL_VAL,
			    *(int64_t *)val);
			break;
		case TOPO_TYPE_UINT64:
			ret = nvlist_add_uint64(pv->tp_val, TOPO_PROP_VAL_VAL,
			    *(uint64_t *)val);
			break;
		case TOPO_TYPE_STRING:
			ret = nvlist_add_string(pv->tp_val, TOPO_PROP_VAL_VAL,
			    (char *)val);
			break;
		case TOPO_TYPE_FMRI:
			ret = nvlist_add_nvlist(pv->tp_val, TOPO_PROP_VAL_VAL,
			    (nvlist_t *)val);
			break;
		case TOPO_TYPE_INT32_ARRAY:
			ret = nvlist_add_int32_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (int32_t *)val, nelems);
			break;
		case TOPO_TYPE_UINT32_ARRAY:
			ret = nvlist_add_uint32_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (uint32_t *)val, nelems);
			break;
		case TOPO_TYPE_INT64_ARRAY:
			ret = nvlist_add_int64_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (int64_t *)val, nelems);
			break;
		case TOPO_TYPE_UINT64_ARRAY:
			ret = nvlist_add_uint64_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (uint64_t *)val, nelems);
			break;
		case TOPO_TYPE_STRING_ARRAY:
			ret = nvlist_add_string_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (char **)val, nelems);
			break;
		case TOPO_TYPE_FMRI_ARRAY:
			ret = nvlist_add_nvlist_array(pv->tp_val,
			    TOPO_PROP_VAL_VAL, (nvlist_t **)val, nelems);
			break;
		default:
			return (set_seterror(node, pvl, err, ETOPO_PROP_TYPE));
	}

	if (ret != 0) {
		if (ret == ENOMEM)
			return (set_seterror(node, pvl, err, ETOPO_NOMEM));
		else
			return (set_seterror(node, pvl, err, ETOPO_PROP_NVL));
	}

	if (new_prop > 0)
		topo_list_append(&pg->tpg_pvals, pvl);

	topo_node_unlock(node);

	return (0);
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
	 * Check for an existing property group and prop val
	 */
	if ((pg = pgroup_get(pnode, pgname)) == NULL)
		return (inherit_seterror(node, err, ETOPO_PROP_NOENT));

	if ((pv = propval_get(pg, name)) == NULL)
		return (inherit_seterror(node, err, ETOPO_PROP_NOENT));

	/*
	 * Can this propval be inherited?
	 */
	if (pv->tp_flag != TOPO_PROP_IMMUTABLE)
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
topo_propval_destroy(topo_propval_t *pv)
{
	topo_hdl_t *thp = pv->tp_hdl;

	if (pv->tp_name != NULL)
		topo_hdl_strfree(thp, pv->tp_name);

	if (pv->tp_val != NULL)
		nvlist_free(pv->tp_val);

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
