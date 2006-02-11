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
		if (strcmp(pg->tpg_name, pgname) == 0) {
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
prop_val_add(nvlist_t *nvl, topo_propval_t *pv)
{
	switch (pv->tp_type) {
		case TOPO_TYPE_INT32:
			return (nvlist_add_int32(nvl, TOPO_PROP_VAL_VAL,
			    pv->tp_u.tp_int32));
		case TOPO_TYPE_UINT32:
			return (nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL,
			    pv->tp_u.tp_uint32));
		case TOPO_TYPE_INT64:
			return (nvlist_add_int64(nvl, TOPO_PROP_VAL_VAL,
			    pv->tp_u.tp_int64));
		case TOPO_TYPE_UINT64:
			return (nvlist_add_uint64(nvl, TOPO_PROP_VAL_VAL,
			    pv->tp_u.tp_uint64));
		case TOPO_TYPE_STRING:
			return (nvlist_add_string(nvl, TOPO_PROP_VAL_VAL,
			    pv->tp_u.tp_string));
		case TOPO_TYPE_FMRI:
			return (nvlist_add_nvlist(nvl, TOPO_PROP_VAL_VAL,
			    pv->tp_u.tp_fmri));
		default:
			return (ETOPO_PROP_TYPE);
	}
}

nvlist_t *
get_all_seterror(topo_hdl_t *thp, nvlist_t *nvl, int err)
{
	if (nvl != NULL)
		nvlist_free(nvl);

	(void) topo_hdl_seterrno(thp, err);

	return (NULL);
}

nvlist_t *
topo_prop_get_all(topo_hdl_t *thp, tnode_t *node)
{
	int err;
	nvlist_t *nvl, *pgnvl, *pvnvl;
	topo_pgroup_t *pg;
	topo_propval_t *pv;
	topo_proplist_t *pvl;

	if (topo_hdl_nvalloc(thp, &nvl, 0) != 0) {
		return (get_all_seterror(thp, NULL, ETOPO_NOMEM));
	}

	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		err = 0;
		if (topo_hdl_nvalloc(thp, &pgnvl, 0) != 0)
			return (get_all_seterror(thp, nvl, ETOPO_NOMEM));

		if ((err = nvlist_add_string(pgnvl, TOPO_PROP_GROUP_NAME,
		    pg->tpg_name)) != 0)
			return (get_all_seterror(thp, nvl, err));

		for (pvl = topo_list_next(&pg->tpg_pvals); pvl != NULL;
		    pvl = topo_list_next(pvl)) {

			pv = pvl->tp_pval;
			if (topo_hdl_nvalloc(thp, &pvnvl, 0)
			    != 0) {
				nvlist_free(pgnvl);
				return (get_all_seterror(thp, nvl,
				    ETOPO_NOMEM));
			}
			if ((err = nvlist_add_string(pvnvl, TOPO_PROP_VAL_NAME,
			    pv->tp_name)) != 0) {
				nvlist_free(pgnvl);
				nvlist_free(pvnvl);
				return (get_all_seterror(thp, nvl, err));
			}
			if ((err = prop_val_add(pvnvl, pv)) != 0) {
				nvlist_free(pgnvl);
				nvlist_free(pvnvl);
				return (get_all_seterror(thp, nvl, err));
			}
			if ((err = nvlist_add_nvlist(pgnvl, TOPO_PROP_VAL,
			    pvnvl)) != 0) {
				nvlist_free(pgnvl);
				nvlist_free(pvnvl);
				return (get_all_seterror(thp, nvl, err));
			}

			nvlist_free(pvnvl);
		}
		if ((err = nvlist_add_nvlist(nvl, TOPO_PROP_GROUP, pgnvl))
		    != 0) {
			nvlist_free(pgnvl);
			return (get_all_seterror(thp, nvl, err));
		}

		nvlist_free(pgnvl);
	}

	return (nvl);
}

static int
get_seterror(tnode_t *node, int *errp, int err)
{
	topo_node_unlock(node);
	*errp = err;
	return (-1);
}

int
topo_prop_get_int32(tnode_t *node, const char *pgname, const char *pname,
    int32_t *val, int *err)
{
	topo_propval_t *pv;

	topo_node_lock(node);
	if ((pv = topo_prop_get(node, pgname, pname, err))
	    == NULL)
		return (get_seterror(node, err, *err));

	if (pv->tp_type != TOPO_TYPE_INT32)
		return (get_seterror(node, err, ETOPO_PROP_TYPE));

	*val = pv->tp_u.tp_int32;

	topo_node_unlock(node);

	return (0);
}

int
topo_prop_get_uint32(tnode_t *node, const char *pgname, const char *pname,
    uint32_t *val, int *err)
{
	topo_propval_t *pv;

	topo_node_lock(node);
	if ((pv = topo_prop_get(node, pgname, pname, err))
	    == NULL)
		return (get_seterror(node, err, *err));

	if (pv->tp_type != TOPO_TYPE_UINT32)
		return (get_seterror(node, err, ETOPO_PROP_TYPE));

	*val = pv->tp_u.tp_uint32;

	topo_node_unlock(node);

	return (0);
}

int
topo_prop_get_int64(tnode_t *node, const char *pgname, const char *pname,
    int64_t *val, int *err)
{
	topo_propval_t *pv;

	topo_node_lock(node);
	if ((pv = topo_prop_get(node, pgname, pname, err))
	    == NULL)
		return (get_seterror(node, err, *err));

	if (pv->tp_type != TOPO_TYPE_INT64)
		return (get_seterror(node, err, ETOPO_PROP_TYPE));

	*val = pv->tp_u.tp_int64;

	topo_node_unlock(node);

	return (0);
}

int
topo_prop_get_uint64(tnode_t *node, const char *pgname, const char *pname,
    uint64_t *val, int *err)
{
	topo_propval_t *pv;

	topo_node_lock(node);
	if ((pv = topo_prop_get(node, pgname, pname, err))
	    == NULL)
		return (get_seterror(node, err, *err));

	if (pv->tp_type != TOPO_TYPE_UINT64)
		return (get_seterror(node, err, ETOPO_PROP_TYPE));

	*val = pv->tp_u.tp_int64;

	topo_node_unlock(node);

	return (0);
}

int
topo_prop_get_string(tnode_t *node, const char *pgname, const char *pname,
    char **val, int *err)
{
	topo_propval_t *pv;

	topo_node_lock(node);
	if ((pv = topo_prop_get(node, pgname, pname, err)) == NULL)
		return (get_seterror(node, err, *err));

	if (pv->tp_type != TOPO_TYPE_STRING)
		return (get_seterror(node, err, ETOPO_PROP_TYPE));

	if ((*val = topo_hdl_strdup(node->tn_hdl, pv->tp_u.tp_string))
	    == NULL)
		return (get_seterror(node, err, ETOPO_NOMEM));

	topo_node_unlock(node);

	return (0);
}

int
topo_prop_get_fmri(tnode_t *node, const char *pgname, const char *pname,
    nvlist_t **val, int *err)
{
	topo_propval_t *pv;

	topo_node_lock(node);
	if ((pv = topo_prop_get(node, pgname, pname, err)) == NULL)
		return (get_seterror(node, err, *err));

	if (pv->tp_type != TOPO_TYPE_FMRI)
		return (get_seterror(node, err, ETOPO_PROP_TYPE));

	if (topo_hdl_nvdup(node->tn_hdl, pv->tp_u.tp_fmri, val) < 0)
		return (get_seterror(node, err, ETOPO_NOMEM));

	topo_node_unlock(node);

	return (0);
}

static void
topo_propval_strfree(topo_propval_t *pv)
{
	topo_hdl_strfree(pv->tp_hdl, pv->tp_u.tp_string);
}

static void
topo_propval_nvlfree(topo_propval_t *pv)
{
	nvlist_free(pv->tp_u.tp_fmri);
}

static int
set_seterror(tnode_t *node, int *errp, int err)
{
	topo_node_unlock(node);

	*errp = err;

	return (-1);
}

static int
topo_prop_set(tnode_t *node, const char *pgname, const char *pname,
    topo_type_t type, int flag, void *val, int *err)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_pgroup_t *pg;
	topo_propval_t *pv;
	topo_proplist_t *pvl;

	topo_node_lock(node);
	if ((pg = pgroup_get(node, pgname)) == NULL)
		return (set_seterror(node, err, ETOPO_PROP_NOENT));

	if ((pv = propval_get(pg, pname)) != NULL) {
		if (pv->tp_type != type)
			return (set_seterror(node, err, ETOPO_PROP_TYPE));
		else if (pv->tp_flag == TOPO_PROP_SET_ONCE)
			return (set_seterror(node, err, ETOPO_PROP_DEFD));
	} else {
		/*
		 * Property values may be a shared resources among
		 * different nodes.  We will allocate resources
		 * on a per-handle basis.
		 */
		if ((pvl = topo_hdl_zalloc(thp, sizeof (topo_proplist_t)))
		    == NULL)
			return (set_seterror(node, err, ETOPO_NOMEM));

		if ((pv = topo_hdl_zalloc(thp, sizeof (topo_propval_t)))
		    == NULL) {
			topo_hdl_free(thp, pvl, sizeof (topo_proplist_t));
			return (set_seterror(node, err, ETOPO_NOMEM));
		}
		if ((pv->tp_name = topo_hdl_strdup(thp, pname))
		    == NULL) {
			topo_hdl_free(thp, pvl, sizeof (topo_proplist_t));
			topo_hdl_free(thp, pv, sizeof (topo_propval_t));
			return (set_seterror(node, err, ETOPO_NOMEM));
		}
		pv->tp_flag = flag;
		pv->tp_type = type;
		pv->tp_hdl = thp;
		topo_prop_hold(pv);
		pvl->tp_pval = pv;
		topo_list_append(&pg->tpg_pvals, pvl);


	}

	switch (type) {
		case TOPO_TYPE_INT32:
			pv->tp_u.tp_int32 = *(int32_t *)val;
			break;
		case TOPO_TYPE_UINT32:
			pv->tp_u.tp_uint32 = *(uint32_t *)val;
			break;
		case TOPO_TYPE_INT64:
			pv->tp_u.tp_int64 = *(int64_t *)val;
			break;
		case TOPO_TYPE_UINT64:
			pv->tp_u.tp_uint64 = *(uint64_t *)val;
			break;
		case TOPO_TYPE_STRING:
			pv->tp_u.tp_string = topo_hdl_strdup(thp, (char *)val);
			if (pv->tp_u.tp_string == NULL)
				return (set_seterror(node, err, ETOPO_NOMEM));
			pv->tp_free = topo_propval_strfree;
			break;
		case TOPO_TYPE_FMRI:
			if (topo_hdl_nvdup(thp,
			    (nvlist_t *)val, &pv->tp_u.tp_fmri) < 0)
				return (set_seterror(node, err, ETOPO_NOMEM));
			pv->tp_free = topo_propval_nvlfree;
			break;
		default:
			return (set_seterror(node, err, ETOPO_PROP_TYPE));
	}

	topo_node_unlock(node);

	return (0);
}

int
topo_prop_set_int32(tnode_t *node, const char *pgname, const char *pname,
    int flag, int32_t val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_INT32, flag,
	    &val, err));
}

int
topo_prop_set_uint32(tnode_t *node, const char *pgname, const char *pname,
    int flag, uint32_t val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_UINT32, flag,
	    &val, err));
}

int
topo_prop_set_int64(tnode_t *node, const char *pgname, const char *pname,
    int flag, int64_t val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_INT64, flag,
	    &val, err));
}

int
topo_prop_set_uint64(tnode_t *node, const char *pgname, const char *pname,
    int flag, uint64_t val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_UINT64, flag,
	    &val, err));
}

int
topo_prop_set_string(tnode_t *node, const char *pgname, const char *pname,
    int flag, const char *val, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_STRING, flag,
	    (void *)val, err));
}

int
topo_prop_set_fmri(tnode_t *node, const char *pgname, const char *pname,
    int flag, const nvlist_t *fmri, int *err)
{
	return (topo_prop_set(node, pgname, pname, TOPO_TYPE_FMRI, flag,
	    (void *)fmri, err));
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
	if (pv->tp_flag != TOPO_PROP_SET_ONCE)
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

int
topo_prop_stability(tnode_t *node, const char *pgname, topo_stability_t *stab)
{
	topo_pgroup_t *pg;

	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (strcmp(pgname, pg->tpg_name) == 0) {
			*stab = pg->tpg_stability;
			return (0);
		}
	}

	return (-1);
}

int
topo_pgroup_create(tnode_t *node, const char *pname, topo_stability_t stab,
    int *err)
{
	topo_pgroup_t *pg;

	*err = 0;

	/*
	 * Check for an existing pgroup
	 */
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (strcmp(pg->tpg_name, pname) == 0) {
			*err = ETOPO_PROP_DEFD;
			return (-1);
		}
	}

	if ((pg = topo_hdl_zalloc(node->tn_hdl,
	    sizeof (topo_pgroup_t))) == NULL) {
		*err = ETOPO_NOMEM;
		return (-1);
	}

	if ((pg->tpg_name = topo_hdl_strdup(node->tn_hdl, pname)) == NULL) {
		topo_hdl_free(node->tn_hdl, pg, sizeof (topo_pgroup_t));
		*err = ETOPO_NOMEM;
		return (-1);
	}

	pg->tpg_stability = stab;

	topo_list_append(&node->tn_pgroups, pg);

	return (0);
}

void
topo_pgroup_destroy(tnode_t *node, const char *pname)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_pgroup_t *pg;
	topo_proplist_t *pvl;

	topo_node_lock(node);
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		if (strcmp(pg->tpg_name, pname) == 0) {
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

	if (pg->tpg_name != NULL)
		topo_hdl_strfree(thp, pg->tpg_name);
	topo_hdl_free(thp, pg, sizeof (topo_pgroup_t));

	topo_node_unlock(node);
}

void
topo_pgroup_destroy_all(tnode_t *node)
{
	topo_hdl_t *thp = node->tn_hdl;
	topo_pgroup_t *pg;
	topo_proplist_t *pvl;

	topo_node_lock(node);
	while ((pg = topo_list_next(&node->tn_pgroups)) != NULL) {
		while ((pvl = topo_list_next(&pg->tpg_pvals)) != NULL) {
			topo_list_delete(&pg->tpg_pvals, pvl);
			topo_prop_rele(pvl->tp_pval);
			topo_hdl_free(thp, pvl, sizeof (topo_proplist_t));
		}

		topo_list_delete(&node->tn_pgroups, pg);

		if (pg->tpg_name != NULL)
			topo_hdl_strfree(thp, pg->tpg_name);
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

	if (pv->tp_free != NULL)
		pv->tp_free(pv);

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
