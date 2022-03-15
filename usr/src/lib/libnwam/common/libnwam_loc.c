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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
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
 * state of and changing the state of location objects. Locations
 * represent the configuration to be applied once basic network configuration
 * has been established - name services, IPsec config, etc, and can be enabled
 * either manually or conditionally for a combination of the set of
 * available conditions (an IP address is present, an ENM is active etc).
 */

#define	NSSWITCH_PREFIX		"/etc/nsswitch."

typedef nwam_error_t (*nwam_loc_prop_validate_func_t)(nwam_value_t);

static nwam_error_t valid_loc_activation_mode(nwam_value_t);
static nwam_error_t valid_loc_condition(nwam_value_t);
static nwam_error_t valid_nameservices(nwam_value_t);
static nwam_error_t valid_configsrc(nwam_value_t);

struct nwam_prop_table_entry loc_prop_table_entries[] = {
	{NWAM_LOC_PROP_ACTIVATION_MODE, NWAM_VALUE_TYPE_UINT64, B_FALSE, 1, 1,
	    valid_loc_activation_mode,
	    "specifies the location activation mode - valid values are:\n"
	    "\'manual\', \'conditional-any\' and \'conditional-all\'",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_CONDITIONS, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    NWAM_MAX_NUM_VALUES, valid_loc_condition,
	    "specifies the activation condition. Conditions are of the form:\n"
	    "ncp|ncu|enm name is|is-not active\n"
	    "ip-address is|is-not|is-in-range|is-not-in-range| 1.2.3.4[/24]\n"
	    "advertised-domain is|is-not|contains|does-not-contain string\n"
	    "system-domain is|is-not|contains|does-not-contain string\n"
	    "essid is|is-not|contains|does-not-contain string\n"
	    "bssid is|is-not string",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_ENABLED, NWAM_VALUE_TYPE_BOOLEAN, B_TRUE, 1, 1,
	    nwam_valid_boolean,
	    "specifies if location is to be enabled",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_NAMESERVICES, NWAM_VALUE_TYPE_UINT64, B_FALSE, 1,
	    NWAM_MAX_NUM_VALUES, valid_nameservices,
	    "specifies name service(s) to be used - valid values are:\n"
	    "\'files\', \'dns\', \'nis\', and \'ldap\'",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE, NWAM_VALUE_TYPE_STRING,
	    B_FALSE, 0, 1, nwam_valid_file,
	    "specifies path to configuration file for name services switch "
	    "for this location - see nsswitch.conf(5)",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC, NWAM_VALUE_TYPE_UINT64,
	    B_FALSE, 0, NWAM_MAX_NUM_VALUES, valid_configsrc,
	    "specifies sources of DNS configuration parameters - valid values "
	    "are:\n\'dhcp\', or \'manual\'",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_DNS_NAMESERVICE_DOMAIN, NWAM_VALUE_TYPE_STRING, B_FALSE,
	    0, 1, nwam_valid_domain,
	    "specifies DNS domain name to be set for this location",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_DNS_NAMESERVICE_SERVERS, NWAM_VALUE_TYPE_STRING, B_FALSE,
	    0, NWAM_MAX_NUM_VALUES, nwam_valid_host_any,
	    "specifies DNS server host address(es)",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_DNS_NAMESERVICE_SEARCH, NWAM_VALUE_TYPE_STRING, B_FALSE,
	    0, NWAM_MAX_NUM_VALUES, nwam_valid_domain,
	    "specifies DNS search list for host name lookup",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC, NWAM_VALUE_TYPE_UINT64,
	    B_FALSE, 0, NWAM_MAX_NUM_VALUES, valid_configsrc,
	    "specifies sources of NIS configuration parameters - valid values "
	    "are:\n\'dhcp\', or \'manual\'",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_NIS_NAMESERVICE_SERVERS, NWAM_VALUE_TYPE_STRING, B_FALSE,
	    0, NWAM_MAX_NUM_VALUES, nwam_valid_host_any,
	    "specifies NIS server host address(es)",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC, NWAM_VALUE_TYPE_UINT64,
	    B_FALSE, 0, NWAM_MAX_NUM_VALUES, valid_configsrc,
	    "specifies sources of NIS configuration parameters - currently, "
	    "the only valid value is \'manual\'",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_LDAP_NAMESERVICE_SERVERS, NWAM_VALUE_TYPE_STRING,
	    B_FALSE, 0, NWAM_MAX_NUM_VALUES, nwam_valid_host_or_domain,
	    "specifies LDAP server host address(es)",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_DEFAULT_DOMAIN, NWAM_VALUE_TYPE_STRING, B_FALSE, 0, 1,
	    nwam_valid_domain,
	    "specifies the domainname(8) to be set for this location",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_NFSV4_DOMAIN, NWAM_VALUE_TYPE_STRING, B_FALSE, 0, 1,
	    nwam_valid_domain,
	    "specifies an NFSv4 domain for this location",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_IPFILTER_CONFIG_FILE, NWAM_VALUE_TYPE_STRING, B_FALSE,
	    0, 1, nwam_valid_file,
	    "specifies an absolute path to an ipf.conf(5) file for this "
	    "location",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_IPFILTER_V6_CONFIG_FILE, NWAM_VALUE_TYPE_STRING,
	    B_FALSE, 0, 1, nwam_valid_file,
	    "specifies an absolute path to an ipf6.conf file for this "
	    "location",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_IPNAT_CONFIG_FILE, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    1, nwam_valid_file,
	    "specifies an absolute path to an ipnat.conf(5) file for this "
	    "location",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_IPPOOL_CONFIG_FILE, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    1, nwam_valid_file,
	    "specifies an absolute path to an ippool.conf(5) file for this "
	    "location",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_IKE_CONFIG_FILE, NWAM_VALUE_TYPE_STRING, B_FALSE, 0, 1,
	    nwam_valid_file,
	    "specifies an absolute path to an ike config file "
	    "(see ike.config(5))",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
	{NWAM_LOC_PROP_IPSECPOLICY_CONFIG_FILE, NWAM_VALUE_TYPE_STRING,
	    B_FALSE, 0, 1, nwam_valid_file,
	    "specifies an absolute path to an IPsec policy configuration file "
	    "(see ipsecconf(8)",
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY},
};

#define	NWAM_NUM_LOC_PROPS	(sizeof (loc_prop_table_entries) / \
				sizeof (*loc_prop_table_entries))

struct nwam_prop_table loc_prop_table =
	{ NWAM_NUM_LOC_PROPS, loc_prop_table_entries };

static uint64_t
nwam_loc_activation_to_flag(nwam_activation_mode_t activation)
{
	switch (activation) {
	case NWAM_ACTIVATION_MODE_MANUAL:
		return (NWAM_FLAG_ACTIVATION_MODE_MANUAL);
	case NWAM_ACTIVATION_MODE_SYSTEM:
		return (NWAM_FLAG_ACTIVATION_MODE_SYSTEM);
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ANY:
		return (NWAM_FLAG_ACTIVATION_MODE_CONDITIONAL_ANY);
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ALL:
		return (NWAM_FLAG_ACTIVATION_MODE_CONDITIONAL_ALL);
	default:
		return (0);
	}
}

nwam_error_t
nwam_loc_read(const char *name, uint64_t flags, nwam_loc_handle_t *lochp)
{
	return (nwam_read(NWAM_OBJECT_TYPE_LOC, NWAM_LOC_CONF_FILE, name,
	    flags, lochp));
}

nwam_error_t
nwam_loc_create(const char *name, nwam_loc_handle_t *lochp)
{
	nwam_error_t err;
	nwam_value_t val = NULL;
	char *nsswitch = NULL;

	assert(lochp != NULL && name != NULL);

	if ((err = nwam_create(NWAM_OBJECT_TYPE_LOC, NWAM_LOC_CONF_FILE, name,
	    lochp)) != NWAM_SUCCESS)
		return (err);

	/* Create new object list for loc */
	if ((err = nwam_alloc_object_list(&((*lochp)->nwh_data)))
	    != NWAM_SUCCESS)
		goto finish;

	/* NWAM_LOC_PROP_ACTIVATION_MODE is mandatory */
	if ((err = nwam_value_create_uint64(NWAM_ACTIVATION_MODE_MANUAL, &val))
	    != NWAM_SUCCESS) {
		goto finish;
	}
	if ((err = nwam_set_prop_value((*lochp)->nwh_data,
	    NWAM_LOC_PROP_ACTIVATION_MODE, val)) != NWAM_SUCCESS) {
		goto finish;
	}
	nwam_value_free(val);
	val = NULL;

	/*
	 * NWAM_LOC_PROP_ENABLED defaults to false.
	 */
	if ((err = nwam_value_create_boolean(B_FALSE, &val)) != NWAM_SUCCESS)
		goto finish;
	if ((err = nwam_set_prop_value((*lochp)->nwh_data,
	    NWAM_LOC_PROP_ENABLED, val)) != NWAM_SUCCESS)
		goto finish;
	nwam_value_free(val);
	val = NULL;

	/*
	 * Initialize name service properties: use DNS, configured
	 * via DHCP, with default nsswitch (/etc/nsswitch.dns).
	 */
	if ((err = nwam_value_create_uint64(NWAM_NAMESERVICES_DNS, &val)) !=
	    NWAM_SUCCESS)
		goto finish;
	if ((err = nwam_set_prop_value((*lochp)->nwh_data,
	    NWAM_LOC_PROP_NAMESERVICES, val)) != NWAM_SUCCESS)
		goto finish;
	nwam_value_free(val);
	val = NULL;

	if ((err = nwam_value_create_uint64(NWAM_CONFIGSRC_DHCP, &val)) !=
	    NWAM_SUCCESS)
		goto finish;
	if ((err = nwam_set_prop_value((*lochp)->nwh_data,
	    NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC, val)) != NWAM_SUCCESS)
		goto finish;
	nwam_value_free(val);
	val = NULL;

	/* concatenate these two strings */
	nsswitch = strdup(NSSWITCH_PREFIX NWAM_NAMESERVICES_DNS_STRING);
	if (nsswitch == NULL) {
		err = NWAM_NO_MEMORY;
		goto finish;
	}
	if ((err = nwam_value_create_string(nsswitch, &val)) != NWAM_SUCCESS)
		goto finish;
	err = nwam_set_prop_value((*lochp)->nwh_data,
	    NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE, val);

finish:
	if (nsswitch != NULL)
		free(nsswitch);
	if (val != NULL)
		nwam_value_free(val);
	if (err != NWAM_SUCCESS) {
		nwam_loc_free(*lochp);
		*lochp = NULL;
	}
	return (err);
}

nwam_error_t
nwam_loc_get_name(nwam_loc_handle_t loch, char **namep)
{
	return (nwam_get_name(loch, namep));
}

nwam_error_t
nwam_loc_set_name(nwam_loc_handle_t loch, const char *name)
{
	return (nwam_set_name(loch, name));
}

boolean_t
nwam_loc_can_set_name(nwam_loc_handle_t loch)
{
	return (!loch->nwh_committed);
}

/* ARGSUSED2 */
static int
loc_selectcb(struct nwam_handle *hp, uint64_t flags, void *data)
{
	nwam_loc_handle_t loch = hp;
	char *locname;
	uint64_t activation, actflag, walkfilter;
	nwam_value_t activationval;

	/* Skip the Legacy location in all cases */
	if (nwam_loc_get_name(loch, &locname) != NWAM_SUCCESS)
		return (NWAM_INVALID_ARG);
	if (strcmp(locname, NWAM_LOC_NAME_LEGACY) == 0) {
		free(locname);
		return (NWAM_INVALID_ARG);
	}
	free(locname);

	/*
	 * Get a bitmapped flag value corresponding to this loc's
	 * activation.
	 */
	if (nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_ACTIVATION_MODE,
	    &activationval) != NWAM_SUCCESS) {
		return (NWAM_INVALID_ARG);
	}
	if (nwam_value_get_uint64(activationval, &activation) != NWAM_SUCCESS) {
		nwam_value_free(activationval);
		return (NWAM_INVALID_ARG);
	}

	actflag = nwam_loc_activation_to_flag(activation);
	nwam_value_free(activationval);
	if ((walkfilter = (flags & NWAM_WALK_FILTER_MASK)) == 0)
		walkfilter = NWAM_FLAG_ACTIVATION_MODE_ALL;
	if (actflag & walkfilter)
		return (NWAM_SUCCESS);
	return (NWAM_INVALID_ARG);
}

nwam_error_t
nwam_walk_locs(int(*cb)(nwam_loc_handle_t, void *), void *data, uint64_t flags,
    int *retp)
{
	nwam_error_t err = nwam_valid_flags(flags,
	    NWAM_FLAG_ACTIVATION_MODE_ALL | NWAM_FLAG_BLOCKING);

	if (err != NWAM_SUCCESS)
		return (err);

	return (nwam_walk(NWAM_OBJECT_TYPE_LOC, NWAM_LOC_CONF_FILE,
	    cb, data, flags, retp, loc_selectcb));
}

void
nwam_loc_free(nwam_loc_handle_t loch)
{
	nwam_free(loch);
}

nwam_error_t
nwam_loc_delete_prop(nwam_loc_handle_t loch, const char *propname)
{
	nwam_error_t err;
	boolean_t ro;
	void *olddata;

	assert(loch != NULL && propname != NULL);

	if ((err = nwam_loc_prop_read_only(propname, &ro)) != NWAM_SUCCESS)
		return (err);
	if (ro)
		return (NWAM_ENTITY_READ_ONLY);

	/*
	 * Duplicate data, remove property and validate. If validation
	 * fails, revert to data duplicated prior to remove.
	 */
	if ((err = nwam_dup_object_list(loch->nwh_data, &olddata))
	    != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_delete_prop(loch->nwh_data, propname))
	    != NWAM_SUCCESS) {
		nwam_free_object_list(loch->nwh_data);
		loch->nwh_data = olddata;
		return (err);
	}
	if ((err = nwam_loc_validate(loch, NULL)) != NWAM_SUCCESS) {
		nwam_free_object_list(loch->nwh_data);
		loch->nwh_data = olddata;
		return (err);
	}
	nwam_free_object_list(olddata);

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_loc_set_prop_value(nwam_loc_handle_t loch, const char *propname,
    nwam_value_t value)
{
	nwam_error_t err;
	boolean_t ro;

	assert(loch != NULL && propname != NULL && value  != NULL);

	if ((err = nwam_loc_validate_prop(loch, propname, value))
	    != NWAM_SUCCESS ||
	    (err = nwam_loc_prop_read_only(propname, &ro)) != NWAM_SUCCESS)
		return (err);
	if (ro)
		return (NWAM_ENTITY_READ_ONLY);

	return (nwam_set_prop_value(loch->nwh_data, propname, value));
}

nwam_error_t
nwam_loc_get_prop_value(nwam_loc_handle_t loch, const char *propname,
    nwam_value_t *valuep)
{
	return (nwam_get_prop_value(loch->nwh_data, propname, valuep));
}

nwam_error_t
nwam_loc_walk_props(nwam_loc_handle_t loch,
    int (*cb)(const char *, nwam_value_t, void *),
    void *data, uint64_t flags, int *retp)
{
	return (nwam_walk_props(loch, cb, data, flags, retp));
}

nwam_error_t
nwam_loc_commit(nwam_loc_handle_t loch, uint64_t flags)
{
	nwam_error_t err;

	assert(loch != NULL && loch->nwh_data != NULL);

	if ((err = nwam_loc_validate(loch, NULL)) != NWAM_SUCCESS)
		return (err);

	return (nwam_commit(NWAM_LOC_CONF_FILE, loch, flags));
}

nwam_error_t
nwam_loc_destroy(nwam_loc_handle_t loch, uint64_t flags)
{
	nwam_error_t err;
	nwam_value_t actval;
	uint64_t activation;

	/*
	 * Automatic and NoNet are not destroyable and Legacy is
	 * destroyable by netadm only.  These have system activation-mode.
	 */
	if ((err = nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_ACTIVATION_MODE,
	    &actval)) != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_uint64(actval, &activation);
	nwam_value_free(actval);
	if (err != NWAM_SUCCESS)
		return (err);

	if (activation == NWAM_ACTIVATION_MODE_SYSTEM) {
		if (strcmp(loch->nwh_name, NWAM_LOC_NAME_LEGACY) == 0) {
			if (!nwam_uid_is_special())
				return (NWAM_ENTITY_NOT_DESTROYABLE);
		} else {
			return (NWAM_ENTITY_NOT_DESTROYABLE);
		}
	}

	return (nwam_destroy(NWAM_LOC_CONF_FILE, loch, flags));
}

nwam_error_t
nwam_loc_get_prop_description(const char *propname, const char **descriptionp)
{
	return (nwam_get_prop_description(loc_prop_table, propname,
	    descriptionp));
}

nwam_error_t
nwam_loc_prop_read_only(const char *propname, boolean_t *readp)
{
	return (nwam_prop_read_only(loc_prop_table, propname, readp));
}

static nwam_error_t
valid_loc_activation_mode(nwam_value_t value)
{
	uint64_t activation_mode;

	if (nwam_value_get_uint64(value, &activation_mode) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	switch (activation_mode) {
	case NWAM_ACTIVATION_MODE_MANUAL:
	case NWAM_ACTIVATION_MODE_SYSTEM:
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ANY:
	case NWAM_ACTIVATION_MODE_CONDITIONAL_ALL:
		return (NWAM_SUCCESS);
	}
	return (NWAM_ENTITY_INVALID_VALUE);
}

/*
 * Identical to nwam_valid_condition(), except locations cannot specify other
 * location's activation as a condition, e.g. loc2 cannot specify
 * "loc1 is active" since only one location is active at a time, and
 * as a consequence the condition is unsatisfiable.
 */
nwam_error_t
valid_loc_condition(nwam_value_t value)
{
	char **conditions;
	uint_t i, numvalues;
	nwam_condition_object_type_t object_type;
	nwam_condition_t condition;

	if (nwam_value_get_string_array(value, &conditions, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		char *object_name = NULL;

		if (nwam_condition_string_to_condition(conditions[i],
		    &object_type, &condition, &object_name) != NWAM_SUCCESS)
			return (NWAM_ENTITY_INVALID_VALUE);
		if (object_type == NWAM_CONDITION_OBJECT_TYPE_LOC &&
		    condition == NWAM_CONDITION_IS) {
			free(object_name);
			return (NWAM_ENTITY_INVALID_VALUE);
		}
		if (object_name != NULL)
			free(object_name);
	}
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_nameservices(nwam_value_t value)
{
	uint64_t *nameservices;
	uint_t i, numvalues;

	if (nwam_value_get_uint64_array(value, &nameservices, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		if (nameservices[i] > NWAM_NAMESERVICES_LDAP)
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_configsrc(nwam_value_t value)
{
	uint64_t *configsrcs;
	uint_t i, numvalues;

	if (nwam_value_get_uint64_array(value, &configsrcs, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		if (configsrcs[i] > NWAM_CONFIGSRC_DHCP)
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

/*
 * Validates that the activation-mode is system for Automatic and NoNet
 * locations, and not system for all other locations.
 */
static nwam_error_t
nwam_loc_validate_activation_mode(nwam_loc_handle_t loch, nwam_value_t actval)
{
	nwam_error_t err;
	uint64_t activation;

	if ((err = nwam_value_get_uint64(actval, &activation)) != NWAM_SUCCESS)
		return (err);

	if (NWAM_LOC_NAME_PRE_DEFINED(loch->nwh_name)) {
		if (activation != NWAM_ACTIVATION_MODE_SYSTEM)
			return (NWAM_ENTITY_INVALID_VALUE);
	} else {
		if (activation == NWAM_ACTIVATION_MODE_SYSTEM)
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

/*
 * Helper function to validate one nameservice, used by
 * nwam_loc_validate_all_nameservices().
 *
 * requiredprop denotes the property that is mandatory when the
 * configsrcprop is manual.  errpropp is used to return the invalid
 * property.
 */
static nwam_error_t
nwam_loc_validate_one_nameservice(nwam_loc_handle_t loch,
    const char *configsrcprop, const char *requiredprop, const char **errpropp)
{
	nwam_value_t configsrcval, requiredval;
	uint64_t *configsrcs;
	uint_t i, numvalues;

	if (nwam_loc_get_prop_value(loch, configsrcprop, &configsrcval)
	    != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = configsrcprop;
		return (NWAM_ENTITY_MISSING_MEMBER);
	}

	if (nwam_value_get_uint64_array(configsrcval, &configsrcs, &numvalues)
	    != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = configsrcprop;
		nwam_value_free(configsrcval);
		return (NWAM_ENTITY_NO_VALUE);
	}

	/* If -configsrc is manual, requiredprop is required */
	for (i = 0; i < numvalues; i++) {
		if (configsrcs[i] == NWAM_CONFIGSRC_MANUAL) {
			if (nwam_loc_get_prop_value(loch, requiredprop,
			    &requiredval) != NWAM_SUCCESS) {
				if (errpropp != NULL)
					*errpropp = requiredprop;
				return (NWAM_ENTITY_MISSING_MEMBER);
			}
			nwam_value_free(requiredval);
		}
	}
	nwam_value_free(configsrcval);

	return (NWAM_SUCCESS);
}

/*
 * Helper function to validate LDAP nameservice, used by
 * nwam_loc_validate_all_nameservices().  Separated because LDAP must be
 * configured manually only and both default-domain and -servers are required.
 */
static nwam_error_t
nwam_loc_validate_ldap_nameservice(nwam_loc_handle_t loch,
    const char **errpropp)
{
	nwam_value_t val;
	uint64_t *configsrcs;
	uint_t i, numvalues;

	if (nwam_loc_get_prop_value(loch,
	    NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC, &val) != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC;
		return (NWAM_ENTITY_MISSING_MEMBER);
	}
	/* -configsrc is defined as an array */
	if (nwam_value_get_uint64_array(val, &configsrcs, &numvalues)
	    != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC;
		nwam_value_free(val);
		return (NWAM_ENTITY_NO_VALUE);
	}

	/* -configsrc must be manual */
	for (i = 0; i < numvalues; i++) {
		if (configsrcs[i] != NWAM_CONFIGSRC_MANUAL) {
			if (errpropp != NULL)
				*errpropp =
				    NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC;
			nwam_value_free(val);
			return (NWAM_ENTITY_INVALID_VALUE);
		}
	}
	nwam_value_free(val);

	/* both default-domain and -servers are required */
	if (nwam_loc_get_prop_value(loch,
	    NWAM_LOC_PROP_DEFAULT_DOMAIN, &val) != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_LOC_PROP_DEFAULT_DOMAIN;
		return (NWAM_ENTITY_MISSING_MEMBER);
	}
	nwam_value_free(val);

	if (nwam_loc_get_prop_value(loch,
	    NWAM_LOC_PROP_LDAP_NAMESERVICE_SERVERS, &val) != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_LOC_PROP_LDAP_NAMESERVICE_SERVERS;
		return (NWAM_ENTITY_MISSING_MEMBER);
	}
	nwam_value_free(val);

	return (NWAM_SUCCESS);
}

/*
 * Validates the different nameservices properties.
 *
 * If "nameservices" property has more than one nameservice to configure,
 * "nameservices-config-file" must be specified.  If only one nameservice
 * is configured and "nameservices-config-file" is missing, set the
 * property with the appropriately suffixed nsswitch file.
 *
 * For any nameservice being configured, the respective -configsrc property
 * must be specified.  For DNS, -servers is required if -configsrc is
 * manual.  For NIS and LDAP, default-domain is required if -configsrc is
 * manual.  For LDAP, -configsrc must be manual and -servers is required.
 */
static nwam_error_t
nwam_loc_validate_all_nameservices(nwam_loc_handle_t loch,
    nwam_value_t nameservicesval, const char **errpropp)
{
	nwam_error_t err;
	nwam_value_t val;
	uint64_t *nameservices;
	uint_t i, numvalues;

	if ((err = nwam_value_get_uint64_array(nameservicesval, &nameservices,
	    &numvalues)) != NWAM_SUCCESS)
		return (err);

	/*
	 * nameservices-config-file is required if nameservices has more
	 * than one value.
	 */
	if (numvalues > 1) {
		if (nwam_loc_get_prop_value(loch,
		    NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE, &val)
		    != NWAM_SUCCESS) {
			if (errpropp != NULL)
				*errpropp =
				    NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE;
			return (NWAM_ENTITY_MISSING_MEMBER);
		}
		nwam_value_free(val);
	} else if (numvalues == 1) {
		/*
		 * If only one nameservice is being configured and
		 * nameservices-config-file doesn't exist, create it to
		 * point to the respective nsswitch file.
		 */
		err = nwam_loc_get_prop_value(loch,
		    NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE, &val);
		if (err == NWAM_INVALID_ARG || err == NWAM_ENTITY_NOT_FOUND) {
			char *nsswitch;
			const char *nsswitch_suffix;

			/* get the single nameservice being configured */
			if ((err = nwam_uint64_get_value_string(
			    NWAM_LOC_PROP_NAMESERVICES, nameservices[0],
			    &nsswitch_suffix)) != NWAM_SUCCESS)
				goto config_file_fail;
			if ((nsswitch = malloc(MAXPATHLEN)) == NULL) {
				err = NWAM_NO_MEMORY;
				goto config_file_fail;
			}

			/* create appropriately suffixed nsswitch name */
			(void) snprintf(nsswitch, MAXPATHLEN, "%s%s",
			    NSSWITCH_PREFIX, nsswitch_suffix);
			if ((err = nwam_value_create_string(nsswitch, &val))
			    != NWAM_SUCCESS) {
				free(nsswitch);
				goto config_file_fail;
			}

			err = nwam_set_prop_value(loch->nwh_data,
			    NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE, val);
			free(nsswitch);
			nwam_value_free(val);
			if (err != NWAM_SUCCESS) {
				nwam_value_free(val);
				goto config_file_fail;
			}
		} else if (err != NWAM_SUCCESS) {
			goto config_file_fail;
		} else {
			nwam_value_free(val);
		}
	}

	/*
	 * validate the -configsrc property and the required default-domain
	 * and/or -servers property for each nameservice being configured.
	 */
	for (i = 0; i < numvalues; i++) {
		switch (nameservices[i]) {
		case NWAM_NAMESERVICES_DNS:
			if ((err = nwam_loc_validate_one_nameservice(loch,
			    NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC,
			    NWAM_LOC_PROP_DNS_NAMESERVICE_SERVERS, errpropp))
			    != NWAM_SUCCESS)
				return (err);
			break;
		case NWAM_NAMESERVICES_NIS:
			if ((err = nwam_loc_validate_one_nameservice(loch,
			    NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC,
			    NWAM_LOC_PROP_DEFAULT_DOMAIN, errpropp))
			    != NWAM_SUCCESS)
				return (err);
			break;
		case NWAM_NAMESERVICES_LDAP:
			if ((err = nwam_loc_validate_ldap_nameservice(loch,
			    errpropp)) != NWAM_SUCCESS)
				return (err);
			break;
		case NWAM_NAMESERVICES_FILES:
			break;
		default:
			return (NWAM_ENTITY_INVALID_VALUE);
		}
	}
	return (NWAM_SUCCESS);

config_file_fail:
	if (errpropp != NULL)
		*errpropp =  NWAM_LOC_PROP_NAMESERVICES_CONFIG_FILE;
	return (err);
}

nwam_error_t
nwam_loc_validate(nwam_loc_handle_t loch, const char **errpropp)
{
	nwam_error_t err;
	nwam_value_t activationval, conditionval, nameservicesval;
	uint64_t activation;
	char **conditions, *name;
	uint_t i, numvalues;
	nwam_condition_object_type_t object_type;
	nwam_condition_t condition;

	assert(loch != NULL);

	/*
	 * Make sure loc is internally consistent: if activation type is
	 * conditional, the condition string must be specified.
	 */
	if (nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_ACTIVATION_MODE,
	    &activationval) != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_LOC_PROP_ACTIVATION_MODE;
		return (NWAM_ENTITY_MISSING_MEMBER);
	}

	if (nwam_value_get_uint64(activationval, &activation)
	    != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_LOC_PROP_ACTIVATION_MODE;
		nwam_value_free(activationval);
		return (NWAM_ENTITY_NO_VALUE);
	}

	/* validate activation against the location first */
	if ((err = nwam_loc_validate_activation_mode(loch, activationval))
	    != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_LOC_PROP_ACTIVATION_MODE;
		nwam_value_free(activationval);
		return (err);
	}
	nwam_value_free(activationval);

	if (activation == NWAM_ACTIVATION_MODE_CONDITIONAL_ANY ||
	    activation == NWAM_ACTIVATION_MODE_CONDITIONAL_ALL) {
		if (nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_CONDITIONS,
		    &conditionval) != NWAM_SUCCESS) {
			if (errpropp != NULL)
				*errpropp = NWAM_LOC_PROP_CONDITIONS;
			return (NWAM_ENTITY_MISSING_MEMBER);
		}
		/*
		 * Are conditions self-referential? In other words, do any
		 * of the activation conditions refer to this location?
		 */
		if (nwam_value_get_string_array(conditionval, &conditions,
		    &numvalues) != NWAM_SUCCESS) {
			nwam_value_free(conditionval);
			if (errpropp != NULL)
				*errpropp = NWAM_LOC_PROP_CONDITIONS;
			return (NWAM_ENTITY_INVALID_VALUE);
		}
		if (nwam_loc_get_name(loch, &name) != NWAM_SUCCESS) {
			nwam_value_free(conditionval);
			return (NWAM_INVALID_ARG);
		}
		for (i = 0; i < numvalues; i++) {
			char *object_name = NULL;

			if (nwam_condition_string_to_condition(conditions[i],
			    &object_type, &condition, &object_name)
			    != NWAM_SUCCESS) {
				if (errpropp != NULL)
					*errpropp = NWAM_LOC_PROP_CONDITIONS;
				free(name);
				nwam_value_free(conditionval);
				return (NWAM_ENTITY_INVALID_VALUE);
			}
			if (object_name != NULL &&
			    object_type == NWAM_CONDITION_OBJECT_TYPE_LOC &&
			    strcmp(object_name, name) == 0) {
				if (errpropp != NULL)
					*errpropp = NWAM_LOC_PROP_CONDITIONS;
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

	/* validate namerservices */
	if (nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_NAMESERVICES,
	    &nameservicesval) != NWAM_SUCCESS) {
		if (errpropp != NULL)
			*errpropp = NWAM_LOC_PROP_NAMESERVICES;
		return (NWAM_ENTITY_MISSING_MEMBER);
	}
	err = nwam_loc_validate_all_nameservices(loch, nameservicesval,
	    errpropp);
	nwam_value_free(nameservicesval);
	if (err != NWAM_SUCCESS)
		return (err);

	return (nwam_validate(loc_prop_table, loch, errpropp));
}

nwam_error_t
nwam_loc_validate_prop(nwam_loc_handle_t loch, const char *propname,
    nwam_value_t value)
{
	nwam_error_t err;

	assert(loch != NULL);

	if (strcmp(propname, NWAM_LOC_PROP_ACTIVATION_MODE) == 0) {
		if ((err = nwam_loc_validate_activation_mode(loch, value))
		    != NWAM_SUCCESS)
			return (err);
	}

	return (nwam_validate_prop(loc_prop_table, loch, propname, value));
}

nwam_error_t
nwam_loc_copy(nwam_loc_handle_t oldloch, const char *newname,
    nwam_loc_handle_t *newlochp)
{
	nwam_error_t err;
	nwam_value_t val;

	if ((err = nwam_copy(NWAM_LOC_CONF_FILE, oldloch, newname, newlochp))
	    != NWAM_SUCCESS)
		return (err);

	/* If the activation-mode is system, change it to manual */
	if ((err = nwam_loc_get_prop_value(*newlochp,
	    NWAM_LOC_PROP_ACTIVATION_MODE, &val)) != NWAM_SUCCESS)
		goto finish;
	err = nwam_loc_validate_activation_mode(*newlochp, val);
	nwam_value_free(val);
	if (err != NWAM_SUCCESS) {
		if ((err = nwam_value_create_uint64(NWAM_ACTIVATION_MODE_MANUAL,
		    &val)) != NWAM_SUCCESS)
			goto finish;
		err = nwam_set_prop_value((*newlochp)->nwh_data,
		    NWAM_LOC_PROP_ACTIVATION_MODE, val);
		nwam_value_free(val);
		if (err != NWAM_SUCCESS)
			goto finish;

		if ((err = nwam_value_create_boolean(B_FALSE, &val))
		    != NWAM_SUCCESS)
			goto finish;
		err = nwam_set_prop_value((*newlochp)->nwh_data,
		    NWAM_LOC_PROP_ENABLED, val);
		nwam_value_free(val);
		if (err != NWAM_SUCCESS)
			goto finish;
	}

	return (NWAM_SUCCESS);

finish:
	nwam_loc_free(*newlochp);
	*newlochp = NULL;
	return (err);
}

/*
 * Given a property, return expected property data type
 */
nwam_error_t
nwam_loc_get_prop_type(const char *propname, nwam_value_type_t *typep)
{
	return (nwam_get_prop_type(loc_prop_table, propname, typep));
}

nwam_error_t
nwam_loc_prop_multivalued(const char *propname, boolean_t *multip)
{
	return (nwam_prop_multivalued(loc_prop_table, propname, multip));
}

/*
 * Determine if the location has manual activation-mode or not.
 */
nwam_error_t
nwam_loc_is_manual(nwam_loc_handle_t loch, boolean_t *manualp)
{
	nwam_error_t err;
	nwam_value_t actval;
	uint64_t activation;

	assert(loch != NULL);

	if ((err = nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_ACTIVATION_MODE,
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

/* Determine if location is enabled or not */
static nwam_error_t
nwam_loc_is_enabled(nwam_loc_handle_t loch, boolean_t *enabledp)
{
	nwam_error_t err;
	nwam_value_t enabledval;

	assert(loch != NULL);

	if ((err = nwam_loc_get_prop_value(loch, NWAM_LOC_PROP_ENABLED,
	    &enabledval)) != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_boolean(enabledval, enabledp);
	nwam_value_free(enabledval);
	return (err);
}

/*
 * Callback to disable all locations other than one to enable, the handle
 * of which we pass in as an argument. If the argument is NULL, we disable
 * all locations.
 */
static int
loc_set_enabled(nwam_loc_handle_t loch, void *data)
{
	nwam_value_t enabledval;
	boolean_t curr_state, enabled = B_FALSE;
	nwam_loc_handle_t testloch = data;
	nwam_error_t err = NWAM_SUCCESS;

	if (testloch != NULL) {
		char *name, *testname;

		if (nwam_loc_get_name(loch, &name) == NWAM_SUCCESS &&
		    nwam_loc_get_name(testloch, &testname) == NWAM_SUCCESS &&
		    strcmp(name, testname) == 0) {
			/* We enable this location. */
			enabled = B_TRUE;
		}
	}

	/* If the enabled property is not changing, don't do anything. */
	if (nwam_loc_is_enabled(loch, &curr_state) == NWAM_SUCCESS &&
	    curr_state == enabled)
		return (0);

	if (nwam_value_create_boolean(enabled, &enabledval) != NWAM_SUCCESS)
		return (0);
	if (nwam_set_prop_value(loch->nwh_data, NWAM_LOC_PROP_ENABLED,
	    enabledval) == NWAM_SUCCESS)
		err = nwam_loc_commit(loch, NWAM_FLAG_ENTITY_ENABLE);

	nwam_value_free(enabledval);
	return (err);
}

/*
 * Update the enabled property for this location (and for all others
 * if necessary.
 */
static int
nwam_loc_update_enabled(nwam_loc_handle_t loch, boolean_t enabled)
{
	nwam_error_t err;
	int cb_ret;

	if (enabled) {
		/*
		 * Disable all other locations that are manually enabled
		 * and enable this one - a maximum of 1 location can be
		 * enabled at once.
		 */
		err = nwam_walk_locs(loc_set_enabled, loch, 0, &cb_ret);
		if (err != NWAM_SUCCESS && err != NWAM_WALK_HALTED)
			cb_ret = err;
	} else {
		cb_ret = loc_set_enabled(loch, NULL);
	}
	return (cb_ret);
}

nwam_error_t
nwam_loc_enable(nwam_loc_handle_t loch)
{
	nwam_error_t err;
	boolean_t enabled;

	assert(loch != NULL);

	/* Make sure location is not enabled */
	if ((err = nwam_loc_is_enabled(loch, &enabled)) != NWAM_SUCCESS)
		return (err);
	if (enabled)
		return (NWAM_SUCCESS);

	if ((err = nwam_loc_update_enabled(loch, B_TRUE)) != NWAM_SUCCESS)
		return (err);

	err = nwam_enable(NULL, loch);

	/* nwamd may not be running, that's okay. */
	if (err == NWAM_ERROR_BIND)
		return (NWAM_SUCCESS);
	else
		return (err);
}

nwam_error_t
nwam_loc_disable(nwam_loc_handle_t loch)
{
	nwam_error_t err;
	boolean_t enabled;

	assert(loch != NULL);

	/* Make sure location is enabled */
	if ((err = nwam_loc_is_enabled(loch, &enabled)) != NWAM_SUCCESS)
		return (err);
	if (!enabled)
		return (NWAM_SUCCESS);

	if ((err = nwam_loc_update_enabled(loch, B_FALSE)) != NWAM_SUCCESS)
		return (err);

	err = nwam_disable(NULL, loch);

	/* nwamd may not be running, that's okay. */
	if (err == NWAM_ERROR_BIND)
		return (NWAM_SUCCESS);
	else
		return (err);
}

nwam_error_t
nwam_loc_get_default_proplist(const char ***prop_list, uint_t *numvaluesp)
{
	return (nwam_get_default_proplist(loc_prop_table,
	    NWAM_TYPE_ANY, NWAM_CLASS_ANY, prop_list, numvaluesp));
}

nwam_error_t
nwam_loc_get_state(nwam_loc_handle_t loch, nwam_state_t *statep,
    nwam_aux_state_t *auxp)
{
	return (nwam_get_state(NULL, loch, statep, auxp));
}
