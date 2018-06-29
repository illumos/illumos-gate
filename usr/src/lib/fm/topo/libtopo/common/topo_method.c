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
/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>

#include <topo_mod.h>

#include <topo_error.h>
#include <topo_module.h>
#include <topo_subr.h>
#include <topo_tree.h>

topo_imethod_t *
topo_method_lookup(tnode_t *node, const char *name)
{
	topo_imethod_t *mp;

	for (mp = topo_list_next(&node->tn_methods); mp != NULL;
	    mp = topo_list_next(mp)) {
		if (strcmp(name, mp->tim_name) == 0) {
			topo_node_unlock(node);
			return (mp);
		}
	}

	return (NULL);
}

/*
 * Simple API to determine if the specified node supports a given topo method
 * (specified by the method name and version).  Returns true if supported, false
 * otherwise.
 */
boolean_t
topo_method_supported(tnode_t *node, const char *name, topo_version_t vers)
{
	topo_imethod_t *mp;

	topo_node_lock(node);
	for (mp = topo_list_next(&node->tn_methods); mp != NULL;
	    mp = topo_list_next(mp)) {
		if ((strcmp(name, mp->tim_name) == 0) &&
		    (vers == mp->tim_version)) {
			topo_node_unlock(node);
			return (B_TRUE);
		}
	}
	topo_node_unlock(node);
	return (B_FALSE);
}

static void
topo_method_enter(topo_imethod_t *mp)
{
	(void) pthread_mutex_lock(&mp->tim_lock);

	while (mp->tim_busy != 0)
		(void) pthread_cond_wait(&mp->tim_cv, &mp->tim_lock);

	++mp->tim_busy;

	(void) pthread_mutex_unlock(&mp->tim_lock);
}

static void
topo_method_exit(topo_imethod_t *mp)
{
	(void) pthread_mutex_lock(&mp->tim_lock);
	--mp->tim_busy;

	assert(mp->tim_busy == 0);

	(void) pthread_cond_broadcast(&mp->tim_cv);
	(void) pthread_mutex_unlock(&mp->tim_lock);
}

static int
set_methregister_error(topo_mod_t *mod, tnode_t *node, topo_imethod_t *mp,
    int err)
{
	if (mp != NULL) {
		topo_list_delete(&node->tn_methods, mp);
		if (mp->tim_name != NULL)
			topo_mod_strfree(mod, mp->tim_name);
		if (mp->tim_desc != NULL)
			topo_mod_strfree(mod, mp->tim_desc);

		topo_mod_free(mod, mp, sizeof (topo_imethod_t));
	}

	topo_node_unlock(node);

	topo_dprintf(mod->tm_hdl, TOPO_DBG_ERR,
	    "method registration failed for %s: %s\n",
	    mod->tm_name, topo_strerror(err));

	return (topo_mod_seterrno(mod, err));
}

int
topo_method_register(topo_mod_t *mod, tnode_t *node, const topo_method_t *mp)
{
	topo_imethod_t *imp;
	const topo_method_t *meth;

	/*
	 * Initialize module methods
	 */
	for (meth = &mp[0]; meth->tm_name != NULL; meth++) {

		topo_node_lock(node);
		if (topo_method_lookup(node, meth->tm_name) != NULL) {
			topo_node_unlock(node);
			continue;
		}

		if (meth->tm_stability < TOPO_STABILITY_INTERNAL ||
		    meth->tm_stability > TOPO_STABILITY_MAX ||
		    meth->tm_func == NULL)
			return (set_methregister_error(mod, node, NULL,
			    ETOPO_METHOD_INVAL));

		imp = topo_mod_zalloc(mod, sizeof (topo_imethod_t));
		if (imp == NULL)
			return (set_methregister_error(mod, node, imp,
			    ETOPO_METHOD_NOMEM));

		if ((imp->tim_name = topo_mod_strdup(mod, meth->tm_name))
		    == NULL)
			return (set_methregister_error(mod, node, imp,
			    ETOPO_METHOD_NOMEM));

		if ((imp->tim_desc = topo_mod_strdup(mod, meth->tm_desc))
		    == NULL)
			return (set_methregister_error(mod, node, imp,
			    ETOPO_METHOD_NOMEM));


		imp->tim_stability = meth->tm_stability;
		imp->tim_version = meth->tm_version;
		imp->tim_func = meth->tm_func;
		imp->tim_mod = mod;

		topo_list_append(&node->tn_methods, imp);
		topo_node_unlock(node);

		topo_dprintf(mod->tm_hdl, TOPO_DBG_MODSVC,
		    "registered module %s method "
		    "%s for %s=%d\n", mod->tm_name, imp->tim_name,
		    topo_node_name(node), topo_node_instance(node));

	}

	return (0);
}

void
topo_method_unregister(topo_mod_t *mod, tnode_t *node, const char *name)
{
	topo_imethod_t *mp;

	topo_node_lock(node);
	for (mp = topo_list_next(&node->tn_methods); mp != NULL;
	    mp = topo_list_next(mp)) {
		if (strcmp(name, mp->tim_name) == 0)
			break;
	}

	if (mp == NULL) {
		topo_node_unlock(node);
		return;
	}

	topo_list_delete(&node->tn_methods, mp);
	topo_node_unlock(node);

	if (mp->tim_name != NULL)
		topo_mod_strfree(mod, mp->tim_name);
	if (mp->tim_desc != NULL)
		topo_mod_strfree(mod, mp->tim_desc);

	topo_mod_free(mod, mp, sizeof (topo_imethod_t));
}

void
topo_method_unregister_all(topo_mod_t *mod, tnode_t *node)
{
	topo_imethod_t *mp;

	topo_node_lock(node);
	while ((mp = topo_list_next(&node->tn_methods)) != NULL) {
		topo_list_delete(&node->tn_methods, mp);
		if (mp->tim_name != NULL)
			topo_mod_strfree(mod, mp->tim_name);
		if (mp->tim_desc != NULL)
			topo_mod_strfree(mod, mp->tim_desc);
		topo_mod_free(mod, mp, sizeof (topo_imethod_t));
	}
	topo_node_unlock(node);
}


int
topo_method_call(tnode_t *node, const char *method,
    topo_version_t version, nvlist_t *in, nvlist_t **out, int *err)
{
	int rc, save;
	topo_imethod_t *mp;

	for (mp = topo_list_next(&node->tn_methods); mp != NULL;
	    mp = topo_list_next(mp)) {
		if (strcmp(method, mp->tim_name) != 0)
			continue;

		if (version < mp->tim_version) {
			*err = ETOPO_METHOD_VEROLD;
			return (-1);
		} else if (version > mp->tim_version) {
			*err = ETOPO_METHOD_VERNEW;
			return (-1);
		}

		topo_method_enter(mp);
		save = mp->tim_mod->tm_errno;
		mp->tim_mod->tm_errno = 0;
		if ((rc = mp->tim_func(mp->tim_mod, node, version, in, out))
		    < 0) {
			if (mp->tim_mod->tm_errno == 0)
				*err = ETOPO_METHOD_FAIL;
			else
				*err = mp->tim_mod->tm_errno;
		}
		mp->tim_mod->tm_errno = save;
		topo_method_exit(mp);

		return (rc);

	}

	*err = ETOPO_METHOD_NOTSUP;
	return (-1);
}

int
topo_method_invoke(tnode_t *node, const char *method,
    topo_version_t version, nvlist_t *in, nvlist_t **out, int *err)
{
	int rc;

	topo_node_hold(node);
	rc = topo_method_call(node, method, version, in, out, err);
	topo_node_rele(node);

	return (rc);
}

struct sensor_errinfo
{
	boolean_t se_predictive;
	boolean_t se_nonrecov;
	uint32_t se_src;
};

static boolean_t
topo_sensor_failed(int32_t type, uint32_t state, struct sensor_errinfo *seinfo)
{
	boolean_t failed;

	failed = B_FALSE;
	/*
	 * Unless the sensor explicitely says otherwise, all failures are
	 * non-recoverable, hard failures, coming from an unknown source.
	 */
	seinfo->se_predictive = B_FALSE;
	seinfo->se_nonrecov = B_TRUE;
	seinfo->se_src = TOPO_SENSOR_ERRSRC_UNKNOWN;

	switch (type) {
	case TOPO_SENSOR_TYPE_THRESHOLD_STATE:
		if (state & (TOPO_SENSOR_STATE_THRESH_LOWER_NONREC |
		    TOPO_SENSOR_STATE_THRESH_UPPER_NONREC)) {
			failed = B_TRUE;
		} else if (state & (TOPO_SENSOR_STATE_THRESH_LOWER_CRIT |
		    TOPO_SENSOR_STATE_THRESH_UPPER_CRIT)) {
			failed = B_TRUE;
			seinfo->se_nonrecov = B_FALSE;
		}
		break;

	case TOPO_SENSOR_TYPE_POWER_SUPPLY:
		if (state & TOPO_SENSOR_STATE_POWER_SUPPLY_PREDFAIL) {
			failed = B_TRUE;
			seinfo->se_predictive = B_TRUE;
			seinfo->se_src = TOPO_SENSOR_ERRSRC_INTERNAL;
		} else if (state & TOPO_SENSOR_STATE_POWER_SUPPLY_FAILURE) {
			failed = B_TRUE;
			seinfo->se_src = TOPO_SENSOR_ERRSRC_INTERNAL;
		} else if (state &
		    (TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_LOST |
		    TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_RANGE |
		    TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_RANGE_PRES)) {
			seinfo->se_src = TOPO_SENSOR_ERRSRC_EXTERNAL;
			failed = B_TRUE;
		}
		break;

	case TOPO_SENSOR_TYPE_GENERIC_FAILURE:
		if (state & TOPO_SENSOR_STATE_GENERIC_FAIL_NONRECOV) {
			failed = B_TRUE;
		} else if (state & TOPO_SENSOR_STATE_GENERIC_FAIL_CRITICAL) {
			failed = B_TRUE;
			seinfo->se_nonrecov = B_FALSE;
		}
		break;

	case TOPO_SENSOR_TYPE_GENERIC_OK:
		if (state & TOPO_SENSOR_STATE_GENERIC_OK_DEASSERTED)
			failed = B_TRUE;
		break;
	case TOPO_SENSOR_TYPE_GENERIC_PREDFAIL:
		if (state & TOPO_SENSOR_STATE_GENERIC_PREDFAIL_ASSERTED) {
			failed = B_TRUE;
			seinfo->se_predictive = B_TRUE;
		}
		break;
	}

	return (failed);
}

static boolean_t
topo_spoof_apply(topo_hdl_t *thp, tnode_t *node, tnode_t *facnode,
    nvlist_t *in, uint32_t *state)
{
	nvpair_t *elem = NULL;
	nvlist_t *spoof, *rsrc = NULL;
	char *fmrimatch, *fmri, *facmatch;
	uint32_t spoof_state;
	int err;

	while ((elem = nvlist_next_nvpair(in, elem)) != NULL) {
		if (nvpair_value_nvlist(elem, &spoof) != 0)
			return (B_FALSE);

		if (nvlist_lookup_string(spoof, ST_SPOOF_FMRI, &fmrimatch) !=
		    0 || nvlist_lookup_string(spoof, ST_SPOOF_SENSOR,
		    &facmatch) != 0 || nvlist_lookup_uint32(spoof,
		    ST_SPOOF_STATE, &spoof_state) != 0)
			continue;

		if (topo_node_resource(node, &rsrc, &err) != 0 ||
		    topo_fmri_nvl2str(thp, rsrc, &fmri, &err) != 0) {
			nvlist_free(rsrc);
			continue;
		}
		nvlist_free(rsrc);

		if (fnmatch(fmrimatch, fmri, 0) == 0 &&
		    strcmp(facmatch, topo_node_name(facnode)) == 0) {
			*state = spoof_state;
			topo_hdl_strfree(thp, fmri);
			return (B_TRUE);
		}
		topo_hdl_strfree(thp, fmri);
	}
	return (B_FALSE);
}

/*
 * Determine whether there are any sensors indicating failure.  This function
 * is used internally to determine whether a given component is usable, as well
 * by external monitoring software that wants additional information such as
 * which sensors indicated failure.  The return value is an nvlist of nvlists
 * indexed by sensor name, each entry with the following contents:
 *
 *	type, state, units, reading
 *
 *	Identical to sensor node.
 *
 *	nonrecov
 *
 *		Boolean value that is set to indicate that the error is
 *		non-recoverable (the unit is out of service).  The default is
 *		critical failure, which indicates a fault but the unit is still
 *		operating.
 *
 *	injected
 *
 *		Boolean value indicating that the sensor state was injected.
 */
/*ARGSUSED*/
int
topo_method_sensor_failure(topo_mod_t *mod, tnode_t *node,
    topo_version_t version, nvlist_t *in, nvlist_t **out)
{
	topo_faclist_t faclist, *fp;
	int err;
	nvlist_t *nvl, *props, *propval, *tmp;
	int ret = -1;
	uint32_t type, state, units;
	nvpair_t *elem;
	double reading;
	char *propname;
	boolean_t has_reading, is_spoofed = B_FALSE;
	struct sensor_errinfo seinfo;

	if (topo_node_facility(mod->tm_hdl, node, TOPO_FAC_TYPE_SENSOR,
	    TOPO_FAC_TYPE_ANY, &faclist, &err) != 0)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_NOTSUP));

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		goto error;

	for (fp = topo_list_next(&faclist.tf_list); fp != NULL;
	    fp = topo_list_next(fp)) {
		if (topo_prop_getpgrp(fp->tf_node, TOPO_PGROUP_FACILITY,
		    &props, &err) != 0) {
			nvlist_free(nvl);
			goto error;
		}
		type = state = units = 0;
		reading = 0;
		has_reading = B_FALSE;

		elem = NULL;
		while ((elem = nvlist_next_nvpair(props, elem)) != NULL) {
			if (strcmp(nvpair_name(elem), TOPO_PROP_VAL) != 0 ||
			    nvpair_type(elem) != DATA_TYPE_NVLIST)
				continue;

			(void) nvpair_value_nvlist(elem, &propval);
			if (nvlist_lookup_string(propval,
			    TOPO_PROP_VAL_NAME, &propname) != 0)
				continue;

			if (strcmp(propname, TOPO_FACILITY_TYPE) == 0) {
				(void) nvlist_lookup_uint32(propval,
				    TOPO_PROP_VAL_VAL, &type);
			} else if (strcmp(propname, TOPO_SENSOR_STATE) == 0) {
				(void) nvlist_lookup_uint32(propval,
				    TOPO_PROP_VAL_VAL, &state);
			} else if (strcmp(propname, TOPO_SENSOR_UNITS) == 0) {
				(void) nvlist_lookup_uint32(propval,
				    TOPO_PROP_VAL_VAL, &units);
			} else if (strcmp(propname, TOPO_SENSOR_READING) == 0) {
				has_reading = B_TRUE;
				(void) nvlist_lookup_double(propval,
				    TOPO_PROP_VAL_VAL, &reading);
			}
		}

		if (in != NULL)
			is_spoofed = topo_spoof_apply(mod->tm_hdl, node,
			    fp->tf_node, in, &state);

		if (topo_sensor_failed(type, state, &seinfo)) {
			tmp = NULL;
			if (topo_mod_nvalloc(mod, &tmp, NV_UNIQUE_NAME) != 0 ||
			    nvlist_add_uint32(tmp, TOPO_FACILITY_TYPE,
			    type) != 0 ||
			    nvlist_add_uint32(tmp, TOPO_SENSOR_STATE,
			    state) != 0 ||
			    nvlist_add_uint32(tmp, TOPO_SENSOR_UNITS,
			    units) != 0 ||
			    nvlist_add_boolean_value(tmp,
			    "nonrecov", seinfo.se_nonrecov) != 0 ||
			    nvlist_add_boolean_value(tmp,
			    "predictive", seinfo.se_predictive) != 0 ||
			    nvlist_add_uint32(tmp, "source",
			    seinfo.se_src) != 0 ||
			    nvlist_add_boolean_value(nvl, "injected",
			    is_spoofed) != 0 ||
			    (has_reading && nvlist_add_double(tmp,
			    TOPO_SENSOR_READING, reading) != 0) ||
			    nvlist_add_nvlist(nvl, topo_node_name(fp->tf_node),
			    tmp) != 0) {
				nvlist_free(props);
				nvlist_free(tmp);
				nvlist_free(nvl);
				ret = topo_mod_seterrno(mod,
				    ETOPO_METHOD_NOMEM);
				goto error;
			}

			nvlist_free(tmp);
		}

		nvlist_free(props);
		is_spoofed = B_FALSE;
	}

	*out = nvl;
	ret = 0;
error:
	while ((fp = topo_list_next(&faclist.tf_list)) != NULL) {
		topo_list_delete(&faclist.tf_list, fp);
		topo_mod_free(mod, fp, sizeof (topo_faclist_t));
	}
	return (ret);
}
