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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <assert.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libscf.h>
#include "libnwam_impl.h"
#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * Functions to support creating, modifying, destroying, querying the
 * state of and changing the state of ENM (External Network Modifier)
 * objects.  ENMs represent services or scripts that can be enabled
 * either manually or conditionally for a combination of the set of
 * available conditions (an IP address is present, a location is active etc).
 */

typedef nwam_error_t (*nwam_enm_prop_validate_func_t)(nwam_value_t);

static nwam_error_t valid_enm_activation_mode(nwam_value_t);

struct nwam_prop_table_entry enm_prop_table_entries[] = {
	{NWAM_ENM_PROP_ACTIVATION_MODE, NWAM_VALUE_TYPE_UINT64, B_FALSE, 1, 1,
	    valid_enm_activation_mode,
	    "specifies the ENM activation mode - valid values are:\n"
	    "\'manual\', \'conditional-any\' and \'conditional-all\'",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_ENM_PROP_CONDITIONS, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    NWAM_MAX_NUM_VALUES, nwam_valid_condition,
	    "specifies the activation condition. Conditions are of the form:\n"
	    "ncp|ncu|enm|loc name is|is-not active\n"
	    "ip-address is|is-not|is-in-range|is-not-in-range| 1.2.3.4[/24]\n"
	    "advertised-domain is|is-not|contains|does-not-contain string\n"
	    "system-domain is|is-not|contains|does-not-contain string\n"
	    "essid is|is-not|contains|does-not-contain string\n"
	    "bssid is|is-not string",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_ENM_PROP_ENABLED, NWAM_VALUE_TYPE_BOOLEAN, B_TRUE, 0, 1,
	    nwam_valid_boolean,
	    "specifies if manual ENM is to be enabled",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_ENM_PROP_FMRI, NWAM_VALUE_TYPE_STRING, B_FALSE, 0, 1,
	    nwam_valid_fmri,
	    "specifies SMF FMRI of service to be enabled on ENM activation",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_ENM_PROP_START, NWAM_VALUE_TYPE_STRING, B_FALSE, 0, 1,
	    nwam_valid_file,
	    "specifies absolute path to start script to be run on ENM "
	    "activation",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_ENM_PROP_STOP, NWAM_VALUE_TYPE_STRING, B_FALSE, 0, 1,
	    nwam_valid_file,
	    "specifies absolute path to stop script to be run on ENM "
	    "deactivation",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY}
};

#define	NWAM_NUM_ENM_PROPS	(sizeof (enm_prop_table_entries) / \
				sizeof (*enm_prop_table_entries))

struct nwam_prop_table enm_prop_table =
	{ NWAM_NUM_ENM_PROPS, enm_prop_table_entries };

static uint64_t
nwam_enm_activation_to_flag(nwam_activation_mode_t activation)
{
	switch (activation) {
	case NWAM_ACTIVATION_MODE_MANUAL:
		return (NWAM_FLAG_ACTIVATION_MODE_MANUAL);
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ANY:
		return (NWAM_FLAG_ACTIVATION_MODE_CONDITIONAL_ANY);
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ALL:
		return (NWAM_FLAG_ACTIVATION_MODE_CONDITIONAL_ALL);
	default:
		return (0);
	}
}

nwam_error_t
nwam_enm_read(const char *name, uint64_t flags, nwam_enm_handle_t *enmhp)
{
	return (nwam_read(NWAM_OBJECT_TYPE_ENM, NWAM_ENM_CONF_FILE, name,
	    flags, enmhp));
}

nwam_error_t
nwam_enm_create(const char *name, const char *fmri, nwam_enm_handle_t *enmhp)
{
	nwam_error_t err;
	nwam_value_t actval = NULL, falseval = NULL, fmrival = NULL;

	assert(enmhp != NULL && name != NULL);

	if ((err = nwam_create(NWAM_OBJECT_TYPE_ENM, NWAM_ENM_CONF_FILE, name,
	    enmhp)) != NWAM_SUCCESS)
		return (err);

	/*
	 * Create new object list for ENM.  The initial activation mode is set,
	 * and the FMRI property is set, if specified.
	 */
	if ((err = nwam_alloc_object_list(&((*enmhp)->nwh_data)))
	    != NWAM_SUCCESS)
		goto finish;

	if ((err = nwam_value_create_uint64(NWAM_ACTIVATION_MODE_MANUAL,
	    &actval)) != NWAM_SUCCESS ||
	    ((fmri != NULL) &&
	    (err = nwam_value_create_string((char *)fmri, &fmrival))
	    != NWAM_SUCCESS) ||
	    (err = nwam_value_create_boolean(B_FALSE, &falseval))
	    != NWAM_SUCCESS) {
		goto finish;
	}
	if ((err = nwam_set_prop_value((*enmhp)->nwh_data,
	    NWAM_ENM_PROP_ACTIVATION_MODE, actval)) == NWAM_SUCCESS &&
	    (err = nwam_set_prop_value((*enmhp)->nwh_data,
	    NWAM_ENM_PROP_ENABLED, falseval)) == NWAM_SUCCESS) {
		if (fmri != NULL) {
			err = nwam_set_prop_value((*enmhp)->nwh_data,
			    NWAM_ENM_PROP_FMRI, fmrival);
		}
	}

finish:
	nwam_value_free(actval);
	nwam_value_free(falseval);
	if (fmrival != NULL)
		nwam_value_free(fmrival);

	if (err != NWAM_SUCCESS) {
		nwam_enm_free(*enmhp);
		*enmhp = NULL;
	}

	return (err);
}

nwam_error_t
nwam_enm_get_name(nwam_enm_handle_t enmh, char **namep)
{
	return (nwam_get_name(enmh, namep));
}

nwam_error_t
nwam_enm_set_name(nwam_enm_handle_t enmh, const char *name)
{
	return (nwam_set_name(enmh, name));
}

boolean_t
nwam_enm_can_set_name(nwam_enm_handle_t enmh)
{
	return (!enmh->nwh_committed);
}

/* ARGSUSED2 */
static int
enm_selectcb(struct nwam_handle *hp, uint64_t flags, void *data)
{
	nwam_enm_handle_t enmh = hp;
	uint64_t activation, actflag, walkfilter;
	nwam_value_t actval;

	/*
	 * Get a bitmapped flag value corresponding to this enm's
	 * activation value - if the activation value is not recognized,
	 * actflag will be set to 0, and will thus fail to match
	 * any bit flag passed in by the caller.
	 */
	if (nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_ACTIVATION_MODE,
	    &actval) != NWAM_SUCCESS) {
		return (NWAM_INVALID_ARG);
	}
	if (nwam_value_get_uint64(actval, &activation) != NWAM_SUCCESS) {
		nwam_value_free(actval);
		return (NWAM_INVALID_ARG);
	}

	actflag = nwam_enm_activation_to_flag(activation);
	nwam_value_free(actval);
	if ((walkfilter = flags & NWAM_WALK_FILTER_MASK) == 0)
		walkfilter = NWAM_FLAG_ACTIVATION_MODE_ALL;
	if (actflag & walkfilter)
		return (NWAM_SUCCESS);
	return (NWAM_INVALID_ARG);
}

nwam_error_t
nwam_walk_enms(int(*cb)(nwam_enm_handle_t, void *), void *data, uint64_t flags,
    int *retp)
{
	nwam_error_t err = nwam_valid_flags(flags,
	    NWAM_FLAG_ACTIVATION_MODE_ALL | NWAM_FLAG_BLOCKING);

	if (err != NWAM_SUCCESS)
		return (err);

	return (nwam_walk(NWAM_OBJECT_TYPE_ENM, NWAM_ENM_CONF_FILE,
	    cb, data, flags, retp, enm_selectcb));
}

void
nwam_enm_free(nwam_enm_handle_t enmh)
{
	nwam_free(enmh);
}

nwam_error_t
nwam_enm_copy(nwam_enm_handle_t oldenmh, const char *newname,
    nwam_enm_handle_t *newenmhp)
{
	return (nwam_copy(NWAM_ENM_CONF_FILE, oldenmh, newname, newenmhp));
}

nwam_error_t
nwam_enm_delete_prop(nwam_enm_handle_t enmh, const char *propname)
{
	nwam_error_t err;
	boolean_t ro;
	void *olddata;
	boolean_t manual;

	assert(enmh != NULL && propname != NULL);

	if ((err = nwam_enm_prop_read_only(propname, &ro)) != NWAM_SUCCESS)
		return (err);
	if (ro) {
		/*
		 * If the activation-mode is not manual, allow the enabled
		 * property to be deleted.
		 */
		if (strcmp(propname, NWAM_ENM_PROP_ENABLED) != 0)
			return (NWAM_ENTITY_READ_ONLY);

		if ((err = nwam_enm_is_manual(enmh, &manual)) != NWAM_SUCCESS)
			return (err);
		if (manual)
			return (NWAM_ENTITY_READ_ONLY);
	}

	/*
	 * Duplicate data, remove property and validate. If validation
	 * fails, revert to data duplicated prior to remove.
	 */
	if ((err = nwam_dup_object_list(enmh->nwh_data, &olddata))
	    != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_delete_prop(enmh->nwh_data, propname))
	    != NWAM_SUCCESS) {
		nwam_free_object_list(enmh->nwh_data);
		enmh->nwh_data = olddata;
		return (err);
	}
	if ((err = nwam_enm_validate(enmh, NULL)) != NWAM_SUCCESS) {
		nwam_free_object_list(enmh->nwh_data);
		enmh->nwh_data = olddata;
		return (err);
	}
	nwam_free_object_list(olddata);

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_enm_set_prop_value(nwam_enm_handle_t enmh, const char *propname,
    nwam_value_t value)
{
	nwam_error_t err;
	boolean_t ro;

	assert(enmh != NULL && propname != NULL && value != NULL);

	if ((err = nwam_enm_validate_prop(enmh, propname, value))
	    != NWAM_SUCCESS ||
	    (err = nwam_enm_prop_read_only(propname, &ro)) != NWAM_SUCCESS)
		return (err);
	if (ro)
		return (NWAM_ENTITY_READ_ONLY);

	return (nwam_set_prop_value(enmh->nwh_data, propname, value));
}

nwam_error_t
nwam_enm_get_prop_value(nwam_enm_handle_t enmh, const char *propname,
    nwam_value_t *valuep)
{
	return (nwam_get_prop_value(enmh->nwh_data, propname, valuep));
}

nwam_error_t
nwam_enm_walk_props(nwam_enm_handle_t enmh,
    int (*cb)(const char *, nwam_value_t, void *),
    void *data, uint64_t flags, int *retp)
{
	return (nwam_walk_props(enmh, cb, data, flags, retp));
}

nwam_error_t
nwam_enm_commit(nwam_enm_handle_t enmh, uint64_t flags)
{
	nwam_error_t err;

	assert(enmh != NULL && enmh->nwh_data != NULL);

	if ((err = nwam_enm_validate(enmh, NULL)) != NWAM_SUCCESS)
		return (err);

	return (nwam_commit(NWAM_ENM_CONF_FILE, enmh, flags));
}

nwam_error_t
nwam_enm_destroy(nwam_enm_handle_t enmh, uint64_t flags)
{
	return (nwam_destroy(NWAM_ENM_CONF_FILE, enmh, flags));
}

nwam_error_t
nwam_enm_get_prop_description(const char *propname, const char **descriptionp)
{
	return (nwam_get_prop_description(enm_prop_table, propname,
	    descriptionp));
}

nwam_error_t
nwam_enm_prop_read_only(const char *propname, boolean_t *readp)
{
	return (nwam_prop_read_only(enm_prop_table, propname, readp));
}

/* Property-specific value validation functions follow */

static nwam_error_t
valid_enm_activation_mode(nwam_value_t value)
{
	uint64_t activation_mode;

	if (nwam_value_get_uint64(value, &activation_mode) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	switch (activation_mode) {
	case NWAM_ACTIVATION_MODE_MANUAL:
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ANY:
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ALL:
		return (NWAM_SUCCESS);
	}
	return (NWAM_ENTITY_INVALID_VALUE);
}

nwam_error_t
nwam_enm_validate(nwam_enm_handle_t enmh, const char **errpropp)
{
	uint64_t activation;
	nwam_value_t activationval, enabledval, fmrival = NULL, startval = NULL;
	nwam_value_t conditionval = NULL;
	char **conditions, *name;
	uint_t i, numvalues;
	nwam_condition_object_type_t object_type;
	nwam_condition_t condition;

	assert(enmh != NULL);

	/*
	 * Make sure enm is internally consistent: must have either
	 * an fmri or a start string; and if activation type is conditional,
	 * the condition string must be specified.
	 */
	if ((nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_FMRI, &fmrival)
	    != NWAM_SUCCESS) &&
	    (nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_START, &startval)
	    != NWAM_SUCCESS)) {
		if (fmrival != NULL) {
			if (errpropp != NULL)
				*errpropp = NWAM_ENM_PROP_START;
			nwam_value_free(fmrival);
		} else {
			if (errpropp != NULL)
				*errpropp = NWAM_ENM_PROP_FMRI;
		}
		return (NWAM_ENTITY_MISSING_MEMBER);
	}
	if (fmrival != NULL)
		nwam_value_free(fmrival);
	if (startval != NULL)
		nwam_value_free(startval);

	if (nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_ACTIVATION_MODE,
	    &activationval) != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_ENM_PROP_ACTIVATION_MODE;
		return (NWAM_ENTITY_MISSING_MEMBER);
	}
	if (nwam_value_get_uint64(activationval, &activation)
	    != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_ENM_PROP_ACTIVATION_MODE;
		return (NWAM_ENTITY_INVALID_VALUE);
	}
	nwam_value_free(activationval);

	if (activation == NWAM_ACTIVATION_MODE_CONDITIONAL_ANY ||
	    activation == NWAM_ACTIVATION_MODE_CONDITIONAL_ALL) {
		if (nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_CONDITIONS,
		    &conditionval) != NWAM_SUCCESS) {
			if (errpropp != NULL)
				*errpropp = NWAM_ENM_PROP_CONDITIONS;
			return (NWAM_ENTITY_MISSING_MEMBER);
		}
		/*
		 * Are conditions self-referential? In other words, do any
		 * of the activation conditions refer to this ENM?
		 */
		if (nwam_value_get_string_array(conditionval, &conditions,
		    &numvalues) != NWAM_SUCCESS) {
			nwam_value_free(conditionval);
			if (errpropp != NULL)
				*errpropp = NWAM_ENM_PROP_CONDITIONS;
			return (NWAM_ENTITY_INVALID_VALUE);
		}
		if (nwam_enm_get_name(enmh, &name) != NWAM_SUCCESS) {
			nwam_value_free(conditionval);
			return (NWAM_INVALID_ARG);
		}
		for (i = 0; i < numvalues; i++) {
			char *object_name = NULL;

			if (nwam_condition_string_to_condition(conditions[i],
			    &object_type, &condition, &object_name)
			    != NWAM_SUCCESS) {
				if (errpropp != NULL)
					*errpropp = NWAM_ENM_PROP_CONDITIONS;
				free(name);
				nwam_value_free(conditionval);
				return (NWAM_ENTITY_INVALID_VALUE);
			}
			if (object_name != NULL &&
			    object_type == NWAM_CONDITION_OBJECT_TYPE_ENM &&
			    strcmp(object_name, name) == 0) {
				if (errpropp != NULL)
					*errpropp = NWAM_ENM_PROP_CONDITIONS;
				free(name);
				free(object_name);
				nwam_value_free(conditionval);
				return (NWAM_ENTITY_INVALID_VALUE);
			}
			free(object_name);
		}
		free(name);
		nwam_value_free(conditionval);
	}

	if (activation == NWAM_ACTIVATION_MODE_MANUAL) {
		if (nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_ENABLED,
		    &enabledval) != NWAM_SUCCESS) {
			if (errpropp != NULL)
				*errpropp = NWAM_ENM_PROP_ENABLED;
			return (NWAM_ENTITY_MISSING_MEMBER);
		}
		nwam_value_free(enabledval);
	}

	return (nwam_validate(enm_prop_table, enmh, errpropp));
}

nwam_error_t
nwam_enm_validate_prop(nwam_enm_handle_t enmh, const char *propname,
    nwam_value_t value)
{
	assert(enmh != NULL);

	return (nwam_validate_prop(enm_prop_table, enmh, propname, value));
}

/*
 * Given a property, return expected property data type
 */
nwam_error_t
nwam_enm_get_prop_type(const char *propname, nwam_value_type_t *typep)
{
	return (nwam_get_prop_type(enm_prop_table, propname, typep));
}

nwam_error_t
nwam_enm_prop_multivalued(const char *propname, boolean_t *multip)
{
	return (nwam_prop_multivalued(enm_prop_table, propname, multip));
}

/*
 * Determine if the ENM has manual activation-mode or not.
 */
nwam_error_t
nwam_enm_is_manual(nwam_enm_handle_t enmh, boolean_t *manualp)
{
	nwam_error_t err;
	nwam_value_t actval;
	uint64_t activation;

	assert(enmh != NULL);

	if ((err = nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_ACTIVATION_MODE,
	    &actval)) != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_uint64(actval, &activation);
	nwam_value_free(actval);
	if (err != NWAM_SUCCESS)
		return (err);

	if (activation == NWAM_ACTIVATION_MODE_MANUAL)
		*manualp = B_TRUE;
	else
		*manualp = B_FALSE;
	return (NWAM_SUCCESS);
}

/* Determine if ENM is enabled or not */
static nwam_error_t
nwam_enm_is_enabled(nwam_enm_handle_t enmh, boolean_t *enabledp)
{
	nwam_error_t err;
	nwam_value_t enabledval;

	assert(enmh != NULL);

	if ((err = nwam_enm_get_prop_value(enmh, NWAM_ENM_PROP_ENABLED,
	    &enabledval)) != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_boolean(enabledval, enabledp);
	nwam_value_free(enabledval);
	return (err);
}

/* Update the enabled property */
static nwam_error_t
nwam_enm_update_enabled(nwam_enm_handle_t enmh, boolean_t enabled)
{
	nwam_error_t err;
	nwam_value_t enabledval;

	if ((err = nwam_value_create_boolean(enabled, &enabledval))
	    != NWAM_SUCCESS)
		return (err);
	err = nwam_set_prop_value(enmh->nwh_data, NWAM_ENM_PROP_ENABLED,
	    enabledval);
	nwam_value_free(enabledval);
	if (err != NWAM_SUCCESS)
		return (err);
	return (nwam_enm_commit(enmh, NWAM_FLAG_ENTITY_ENABLE));
}

nwam_error_t
nwam_enm_enable(nwam_enm_handle_t enmh)
{
	nwam_error_t err;
	boolean_t manual, enabled;

	assert(enmh != NULL);

	/* Only enms with manual activation-mode can be enabled */
	if ((err = nwam_enm_is_manual(enmh, &manual)) != NWAM_SUCCESS)
		return (err);
	if (!manual)
		return (NWAM_ENTITY_NOT_MANUAL);

	/* Make sure ENM is not enabled */
	if ((err = nwam_enm_is_enabled(enmh, &enabled)) != NWAM_SUCCESS)
		return (err);
	if (enabled)
		return (NWAM_SUCCESS);

	if ((err = nwam_enm_update_enabled(enmh, B_TRUE)) != NWAM_SUCCESS)
		return (err);

	err = nwam_enable(NULL, enmh);

	/* nwamd may not be running, that's okay. */
	if (err == NWAM_ERROR_BIND)
		return (NWAM_SUCCESS);
	else
		return (err);
}

nwam_error_t
nwam_enm_disable(nwam_enm_handle_t enmh)
{
	nwam_error_t err;
	boolean_t manual, enabled;

	assert(enmh != NULL);

	/* Only enms with manual activation-mode can be disabled */
	if ((err = nwam_enm_is_manual(enmh, &manual)) != NWAM_SUCCESS)
		return (err);
	if (!manual)
		return (NWAM_ENTITY_NOT_MANUAL);

	/* Make sure ENM is enabled */
	if ((err = nwam_enm_is_enabled(enmh, &enabled)) != NWAM_SUCCESS)
		return (err);
	if (!enabled)
		return (NWAM_SUCCESS);

	if ((err = nwam_enm_update_enabled(enmh, B_FALSE)) != NWAM_SUCCESS)
		return (err);

	err = nwam_disable(NULL, enmh);

	/* nwamd may not be running, that's okay. */
	if (err == NWAM_ERROR_BIND)
		return (NWAM_SUCCESS);
	else
		return (err);
}

nwam_error_t
nwam_enm_get_default_proplist(const char ***prop_list, uint_t *numvaluesp)
{
	return (nwam_get_default_proplist(enm_prop_table,
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY, prop_list, numvaluesp));
}

nwam_error_t
nwam_enm_get_state(nwam_enm_handle_t enmh, nwam_state_t *statep,
    nwam_aux_state_t *auxp)
{
	return (nwam_get_state(NULL, enmh, statep, auxp));
}
