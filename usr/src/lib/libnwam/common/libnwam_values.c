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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <libdlwlan.h>
#include <libnvpair.h>

#include "libnwam_impl.h"
#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * Internal implementation of libnwam in-memory objects and values.  Objects
 * are nvlists.
 */

void
nwam_value_free(nwam_value_t value)
{
	uint_t i;

	if (value == NULL)
		return;

	switch (value->nwv_value_type) {
	case NWAM_VALUE_TYPE_BOOLEAN:
		free(value->nwv_values.nwv_boolean);
		break;
	case NWAM_VALUE_TYPE_INT64:
		free(value->nwv_values.nwv_int64);
		break;
	case NWAM_VALUE_TYPE_UINT64:
		free(value->nwv_values.nwv_uint64);
		break;
	case NWAM_VALUE_TYPE_STRING:
		for (i = 0; i < value->nwv_value_numvalues; i++)
			free(value->nwv_values.nwv_string[i]);
		free(value->nwv_values.nwv_string);
		break;
	}
	free(value);
}

nwam_error_t
nwam_value_create(nwam_value_type_t value_type, void *values, uint_t numvalues,
    nwam_value_t *valuep)
{
	nwam_value_t newvalue;
	boolean_t *values_boolean;
	int64_t *values_int64;
	uint64_t *values_uint64;
	char **values_string;
	int i, j;
	nwam_error_t err = NWAM_SUCCESS;

	*valuep = NULL;

	if ((newvalue = calloc(1, sizeof (struct nwam_value))) == NULL)
		return (NWAM_NO_MEMORY);

	newvalue->nwv_value_type = value_type;
	newvalue->nwv_value_numvalues = numvalues;

	switch (value_type) {
	case NWAM_VALUE_TYPE_BOOLEAN:
		values_boolean = values;
		if ((newvalue->nwv_values.nwv_boolean =
		    calloc(numvalues, sizeof (boolean_t))) == NULL) {
			free(newvalue);
			return (NWAM_NO_MEMORY);
		}
		for (i = 0; i < numvalues; i++)
			newvalue->nwv_values.nwv_boolean[i] = values_boolean[i];
		break;
	case NWAM_VALUE_TYPE_INT64:
		values_int64 = values;
		if ((newvalue->nwv_values.nwv_int64 =
		    calloc(numvalues, sizeof (int64_t))) == NULL) {
			free(newvalue);
			return (NWAM_NO_MEMORY);
		}
		for (i = 0; i < numvalues; i++)
			newvalue->nwv_values.nwv_int64[i] = values_int64[i];
		break;
	case NWAM_VALUE_TYPE_UINT64:
		values_uint64 = values;
		if ((newvalue->nwv_values.nwv_uint64 =
		    calloc(numvalues, sizeof (uint64_t))) == NULL) {
			free(newvalue);
			return (NWAM_NO_MEMORY);
		}
		for (i = 0; i < numvalues; i++)
			newvalue->nwv_values.nwv_uint64[i] = values_uint64[i];
		break;
	case NWAM_VALUE_TYPE_STRING:
		values_string = values;
		if ((newvalue->nwv_values.nwv_string =
		    calloc(numvalues, sizeof (char *))) == NULL) {
			free(newvalue);
			return (NWAM_NO_MEMORY);
		}
		for (i = 0; i < numvalues; i++) {
			if (strnlen(values_string[i], NWAM_MAX_VALUE_LEN) ==
			    NWAM_MAX_VALUE_LEN) {
				err = NWAM_ENTITY_INVALID_VALUE;
			} else if ((newvalue->nwv_values.nwv_string[i] =
			    strdup(values_string[i])) == NULL) {
				err = NWAM_NO_MEMORY;
			}
			if (err != NWAM_SUCCESS) {
				for (j = 0; j < i; j++)
					free(
					    newvalue->nwv_values.nwv_string[i]);
				free(newvalue->nwv_values.nwv_string);
				free(newvalue);
				return (err);
			}
		}
		break;
	default:
		break;
	}

	*valuep = newvalue;
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_copy(nwam_value_t old, nwam_value_t *newp)
{
	void *values;

	assert(old != NULL && newp != NULL);

	switch (old->nwv_value_type) {
	case NWAM_VALUE_TYPE_BOOLEAN:
		values = old->nwv_values.nwv_boolean;
		break;
	case NWAM_VALUE_TYPE_INT64:
		values = old->nwv_values.nwv_int64;
		break;
	case NWAM_VALUE_TYPE_UINT64:
		values = old->nwv_values.nwv_uint64;
		break;
	case NWAM_VALUE_TYPE_STRING:
		values = old->nwv_values.nwv_string;
		break;
	default:
		return (NWAM_INVALID_ARG);
	}
	return (nwam_value_create(old->nwv_value_type, values,
	    old->nwv_value_numvalues, newp));
}
nwam_error_t
nwam_value_create_boolean_array(boolean_t *values, uint_t numvalues,
    nwam_value_t *valuep)
{
	return (nwam_value_create(NWAM_VALUE_TYPE_BOOLEAN, values, numvalues,
	    valuep));
}

nwam_error_t
nwam_value_create_boolean(boolean_t value, nwam_value_t *valuep)
{
	return (nwam_value_create_boolean_array(&value, 1, valuep));
}

nwam_error_t
nwam_value_create_int64_array(int64_t *values, uint_t numvalues,
    nwam_value_t *valuep)
{
	return (nwam_value_create(NWAM_VALUE_TYPE_INT64, values, numvalues,
	    valuep));
}

nwam_error_t
nwam_value_create_int64(int64_t value, nwam_value_t *valuep)
{
	return (nwam_value_create_int64_array(&value, 1, valuep));
}

nwam_error_t
nwam_value_create_uint64_array(uint64_t *values, uint_t numvalues,
    nwam_value_t *valuep)
{
	return (nwam_value_create(NWAM_VALUE_TYPE_UINT64, values, numvalues,
	    valuep));
}

nwam_error_t
nwam_value_create_uint64(uint64_t value, nwam_value_t *valuep)
{
	return (nwam_value_create_uint64_array(&value, 1, valuep));
}

nwam_error_t
nwam_value_create_string_array(char **values, uint_t numvalues,
    nwam_value_t *valuep)
{
	return (nwam_value_create(NWAM_VALUE_TYPE_STRING, values, numvalues,
	    valuep));
}

nwam_error_t
nwam_value_create_string(char *value, nwam_value_t *valuep)
{
	return (nwam_value_create_string_array(&value, 1, valuep));
}

nwam_error_t
nwam_value_get_boolean_array(nwam_value_t value, boolean_t **valuesp,
    uint_t *numvaluesp)
{
	assert(value != NULL && numvaluesp != NULL && valuesp != NULL);

	*numvaluesp = value->nwv_value_numvalues;
	*valuesp = value->nwv_values.nwv_boolean;
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_boolean(nwam_value_t value, boolean_t *valuep)
{
	uint_t numvalues;
	boolean_t *myvaluesp;
	nwam_error_t err;

	err = nwam_value_get_boolean_array(value, &myvaluesp, &numvalues);
	if (err != NWAM_SUCCESS)
		return (err);
	if (numvalues != 1)
		return (NWAM_ENTITY_MULTIPLE_VALUES);

	*valuep = myvaluesp[0];
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_int64_array(nwam_value_t value, int64_t **valuesp,
    uint_t *numvaluesp)
{
	assert(value != NULL && numvaluesp != NULL && valuesp != NULL);

	*numvaluesp = value->nwv_value_numvalues;
	*valuesp = value->nwv_values.nwv_int64;
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_int64(nwam_value_t value, int64_t *valuep)
{
	uint_t numvalues;
	int64_t *myvaluesp;
	nwam_error_t err;

	err = nwam_value_get_int64_array(value, &myvaluesp, &numvalues);
	if (err != NWAM_SUCCESS)
		return (err);
	if (numvalues != 1)
		return (NWAM_ENTITY_MULTIPLE_VALUES);

	*valuep = myvaluesp[0];
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_uint64_array(nwam_value_t value, uint64_t **valuesp,
    uint_t *numvaluesp)
{
	assert(value != NULL && numvaluesp != NULL && valuesp != NULL);

	*numvaluesp = value->nwv_value_numvalues;
	*valuesp = value->nwv_values.nwv_uint64;
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_uint64(nwam_value_t value, uint64_t *valuep)
{
	uint_t numvalues;
	uint64_t *myvaluesp;
	nwam_error_t err;

	err = nwam_value_get_uint64_array(value, &myvaluesp, &numvalues);
	if (err != NWAM_SUCCESS)
		return (err);
	if (numvalues != 1)
		return (NWAM_ENTITY_MULTIPLE_VALUES);

	*valuep = myvaluesp[0];
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_string_array(nwam_value_t value, char ***valuesp,
    uint_t *numvaluesp)
{
	assert(value != NULL && numvaluesp != NULL && valuesp != NULL);

	*numvaluesp = value->nwv_value_numvalues;
	*valuesp = value->nwv_values.nwv_string;
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_string(nwam_value_t value, char **valuep)
{
	uint_t numvalues;
	char **myvaluesp;
	nwam_error_t err;

	err = nwam_value_get_string_array(value, &myvaluesp, &numvalues);
	if (err != NWAM_SUCCESS)
		return (err);
	if (numvalues != 1)
		return (NWAM_ENTITY_MULTIPLE_VALUES);

	*valuep = myvaluesp[0];
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_type(nwam_value_t value, nwam_value_type_t *typep)
{
	*typep = value->nwv_value_type;
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_value_get_numvalues(nwam_value_t value, uint_t *numvaluesp)
{
	*numvaluesp = value->nwv_value_numvalues;
	return (NWAM_SUCCESS);
}

/*
 * Generic object data functions. We hide nvlist implementation
 * from NCP, ENM and location implementations.
 */
nwam_error_t
nwam_alloc_object_list(void *list)
{
	int nverr;

	assert(list != NULL);

	if ((nverr = nvlist_alloc((nvlist_t **)list, NV_UNIQUE_NAME, 0)) != 0)
		return (nwam_errno_to_nwam_error(nverr));

	return (NWAM_SUCCESS);
}

void
nwam_free_object_list(void *list)
{
	nvlist_free(list);
}

nwam_error_t
nwam_dup_object_list(void *oldlist, void *newlist)
{
	int nverr;

	assert(oldlist != NULL && newlist != NULL);

	if ((nverr = nvlist_dup(oldlist, newlist, 0)) != 0)
		return (nwam_errno_to_nwam_error(nverr));

	return (NWAM_SUCCESS);
}

/* Add child object list to parent object list using property name childname */
nwam_error_t
nwam_object_list_add_object_list(void *parentlist, char *childname,
    void *childlist)
{
	return (nwam_errno_to_nwam_error(nvlist_add_nvlist(parentlist,
	    childname, childlist)));
}

/* Remove object list from parent object list */
nwam_error_t
nwam_object_list_remove_object_list(void *parentlist, char *childname)
{
	return (nwam_errno_to_nwam_error(nvlist_remove_all(parentlist,
	    childname)));
}

/*
 * Get next object list (nvlist) after lastname.  Used to walk NCUs, ENMs and
 * locations, each of which is internally represented as an nvlist.
 */
nwam_error_t
nwam_next_object_list(void *parentlist, char *lastname, char **childnamep,
    void *childlistp)
{
	nvpair_t *last = NULL, *next;
	int nverr;

	if (lastname != NULL) {
		if ((nverr = nvlist_lookup_nvpair(parentlist, lastname, &last))
		    != 0)
			return (nwam_errno_to_nwam_error(nverr));
	}
	if ((next = nvlist_next_nvpair(parentlist, last)) == NULL)
		return (NWAM_LIST_END);

	*childnamep = nvpair_name(next);

	if (nvpair_type(next) != DATA_TYPE_NVLIST)
		return (NWAM_ERROR_INTERNAL);

	if ((nverr = nvpair_value_nvlist(next, childlistp)) != NWAM_SUCCESS)
		return (nwam_errno_to_nwam_error(nverr));

	return (NWAM_SUCCESS);
}

/*
 * Pack nvlist into contiguous memory. If packed_listp is NULL, we just
 * return the size of the memory needed to do so.
 */
nwam_error_t
nwam_pack_object_list(void *list, char **packed_listp, size_t *packed_sizep)
{
	int nverr;

	assert(list != NULL && packed_sizep != NULL);

	if (packed_listp == NULL) {
		nverr = nvlist_size(list, packed_sizep, NV_ENCODE_XDR);
	} else {
		nverr = nvlist_pack(list, packed_listp, packed_sizep,
		    NV_ENCODE_XDR, 0);
	}

	if (nverr != 0)
		return (nwam_errno_to_nwam_error(nverr));

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_unpack_object_list(char *packed_list, size_t packed_size,
    void *list)
{
	int nverr;

	assert(packed_list != NULL && list != NULL);

	*((nvlist_t **)list) = NULL;

	nverr = nvlist_unpack(packed_list, packed_size, (nvlist_t **)list, 0);

	if (nverr != 0)
		return (nwam_errno_to_nwam_error(nverr));

	return (NWAM_SUCCESS);
}

/*
 * Functions to walk, set and get properties in nvlist, translating
 * between nwam_value_t and nvlist/nvpair representations.
 */
nwam_error_t
nwam_next_object_prop(void *list, char *lastname, char **namep,
    nwam_value_t *valuep)
{
	nvpair_t *last = NULL, *next;
	int nverr;

	if (lastname != NULL) {
		if ((nverr = nvlist_lookup_nvpair(list, lastname, &last)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
	}
	if ((next = nvlist_next_nvpair(list, last)) == NULL)
		return (NWAM_LIST_END);

	*namep = nvpair_name(next);

	return (nwam_get_prop_value(list, (const char *)*namep, valuep));
}

nwam_error_t
nwam_get_prop_value(void *list, const char *name, nwam_value_t *valuep)
{
	nvpair_t *prop;
	nwam_error_t err;
	int nverr;
	boolean_t *valbool;
	int64_t *valint64;
	uint64_t *valuint64;
	char **valstr;
	uint_t numvalues;

	assert(valuep != NULL);

	*valuep = NULL;

	if ((nverr = nvlist_lookup_nvpair(list, name, &prop)) != 0) {
		/* convert EINVAL to NOT_FOUND */
		if (nverr == EINVAL)
			return (NWAM_ENTITY_NOT_FOUND);
		return (nwam_errno_to_nwam_error(nverr));
	}

	switch (nvpair_type(prop)) {
	case DATA_TYPE_BOOLEAN_ARRAY:
		if ((nverr = nvpair_value_boolean_array(prop,
		    &valbool, &numvalues)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
		if ((err = nwam_value_create_boolean_array(valbool, numvalues,
		    valuep)) != NWAM_SUCCESS)
			return (err);
		break;
	case DATA_TYPE_INT64_ARRAY:
		if ((nverr = nvpair_value_int64_array(prop,
		    &valint64, &numvalues)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
		if ((err = nwam_value_create_int64_array(valint64, numvalues,
		    valuep)) != NWAM_SUCCESS)
			return (err);
		break;
	case DATA_TYPE_UINT64_ARRAY:
		if ((nverr = nvpair_value_uint64_array(prop,
		    &valuint64, &numvalues)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
		if ((err = nwam_value_create_uint64_array(valuint64, numvalues,
		    valuep)) != NWAM_SUCCESS)
			return (err);
		break;
	case DATA_TYPE_STRING_ARRAY:
		if ((nverr = nvpair_value_string_array(prop,
		    &valstr, &numvalues)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
		if ((err = nwam_value_create_string_array(valstr, numvalues,
		    valuep)) != NWAM_SUCCESS)
			return (err);
		break;
	default:
		/* Should not happen */
		return (NWAM_ERROR_INTERNAL);
	}
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_delete_prop(void *list, const char *name)
{
	int nverr;

	if ((nverr = nvlist_remove_all(list, name)) != 0)
		return (nwam_errno_to_nwam_error(nverr));
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_set_prop_value(void *list, const char *propname, nwam_value_t value)
{
	int nverr;
	nwam_error_t err;
	nwam_value_type_t type;
	uint_t numvalues;
	boolean_t *valbool;
	int64_t *valint64;
	uint64_t *valuint64;
	char **valstr;

	assert(list != NULL && value != NULL);

	if ((err = nwam_value_get_type(value, &type)) != NWAM_SUCCESS)
		return (err);

	switch (type) {
	case NWAM_VALUE_TYPE_BOOLEAN:
		if ((err = nwam_value_get_boolean_array(value, &valbool,
		    &numvalues)) != NWAM_SUCCESS)
			return (err);
		if ((nverr = nvlist_add_boolean_array(list, propname,
		    valbool, numvalues)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
		break;
	case NWAM_VALUE_TYPE_INT64:
		if ((err = nwam_value_get_int64_array(value, &valint64,
		    &numvalues)) != NWAM_SUCCESS)
			return (err);
		if ((nverr = nvlist_add_int64_array(list, propname,
		    valint64, numvalues)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
		break;
	case NWAM_VALUE_TYPE_UINT64:
		if ((err = nwam_value_get_uint64_array(value, &valuint64,
		    &numvalues)) != NWAM_SUCCESS)
			return (err);
		if ((nverr = nvlist_add_uint64_array(list, propname,
		    valuint64, numvalues)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
		break;
	case NWAM_VALUE_TYPE_STRING:
		if ((err = nwam_value_get_string_array(value, &valstr,
		    &numvalues)) != NWAM_SUCCESS)
			return (err);
		if ((nverr = nvlist_add_string_array(list, propname,
		    valstr, numvalues)) != 0)
			return (nwam_errno_to_nwam_error(nverr));
		break;
	default:
		return (NWAM_INVALID_ARG);
	}

	return (NWAM_SUCCESS);
}

/* Map uint64 values to their string counterparts */

struct nwam_value_entry {
	const char	*value_string;
	uint64_t		value;
};

struct nwam_value_entry prop_activation_mode_value_entries[] =
{
	{ NWAM_ACTIVATION_MODE_MANUAL_STRING, NWAM_ACTIVATION_MODE_MANUAL },
	{ NWAM_ACTIVATION_MODE_SYSTEM_STRING, NWAM_ACTIVATION_MODE_SYSTEM },
	{ NWAM_ACTIVATION_MODE_CONDITIONAL_ANY_STRING,
	NWAM_ACTIVATION_MODE_CONDITIONAL_ANY },
	{ NWAM_ACTIVATION_MODE_CONDITIONAL_ALL_STRING,
	NWAM_ACTIVATION_MODE_CONDITIONAL_ALL },
	{ NWAM_ACTIVATION_MODE_PRIORITIZED_STRING,
	NWAM_ACTIVATION_MODE_PRIORITIZED },
	{ NULL, 0 }
};

struct nwam_value_entry ncu_prop_type_entries[] =
{
	{ NWAM_NCU_TYPE_LINK_STRING, NWAM_NCU_TYPE_LINK },
	{ NWAM_NCU_TYPE_INTERFACE_STRING, NWAM_NCU_TYPE_INTERFACE },
	{ NULL, 0 }
};

struct nwam_value_entry ncu_prop_class_entries[] =
{
	{ NWAM_NCU_CLASS_PHYS_STRING, NWAM_NCU_CLASS_PHYS },
	{ NWAM_NCU_CLASS_IP_STRING, NWAM_NCU_CLASS_IP },
	{ NULL, 0 }
};

struct nwam_value_entry ncu_prop_ip_version_entries[] =
{
	{ NWAM_IP_VERSION_IPV4_STRING, IPV4_VERSION },
	{ NWAM_IP_VERSION_IPV6_STRING, IPV6_VERSION },
	{ NULL, 0 }
};

struct nwam_value_entry ncu_prop_ipv4_addrsrc_entries[] =
{
	{ NWAM_ADDRSRC_DHCP_STRING, NWAM_ADDRSRC_DHCP },
	{ NWAM_ADDRSRC_STATIC_STRING, NWAM_ADDRSRC_STATIC },
	{ NULL, 0 }
};

struct nwam_value_entry ncu_prop_ipv6_addrsrc_entries[] =
{
	{ NWAM_ADDRSRC_DHCP_STRING, NWAM_ADDRSRC_DHCP },
	{ NWAM_ADDRSRC_STATIC_STRING, NWAM_ADDRSRC_STATIC },
	{ NWAM_ADDRSRC_AUTOCONF_STRING, NWAM_ADDRSRC_AUTOCONF },
	{ NULL, 0 }
};

struct nwam_value_entry ncu_prop_priority_mode_entries[] =
{
	{ NWAM_PRIORITY_MODE_EXCLUSIVE_STRING, NWAM_PRIORITY_MODE_EXCLUSIVE },
	{ NWAM_PRIORITY_MODE_SHARED_STRING, NWAM_PRIORITY_MODE_SHARED },
	{ NWAM_PRIORITY_MODE_ALL_STRING, NWAM_PRIORITY_MODE_ALL },
	{ NULL, 0 }
};

struct nwam_value_entry loc_prop_nameservices_entries[] =
{
	{ NWAM_NAMESERVICES_DNS_STRING, NWAM_NAMESERVICES_DNS },
	{ NWAM_NAMESERVICES_FILES_STRING, NWAM_NAMESERVICES_FILES },
	{ NWAM_NAMESERVICES_NIS_STRING, NWAM_NAMESERVICES_NIS },
	{ NWAM_NAMESERVICES_LDAP_STRING, NWAM_NAMESERVICES_LDAP },
	{ NULL, 0 }
};

struct nwam_value_entry loc_prop_nameservice_configsrc_entries[] =
{
	{ NWAM_CONFIGSRC_MANUAL_STRING, NWAM_CONFIGSRC_MANUAL },
	{ NWAM_CONFIGSRC_DHCP_STRING, NWAM_CONFIGSRC_DHCP },
	{ NULL, 0 }
};

struct nwam_value_entry known_wlan_prop_security_mode_entries[] =
{
	{ "none", DLADM_WLAN_SECMODE_NONE },
	{ "wep", DLADM_WLAN_SECMODE_WEP },
	{ "wpa", DLADM_WLAN_SECMODE_WPA },
	{ NULL, 0 }
};

struct nwam_prop_value_entry {
	const char		*prop_name;
	struct nwam_value_entry	*value_entries;
} prop_value_entry_table[] =
{
	{ NWAM_NCU_PROP_ACTIVATION_MODE, prop_activation_mode_value_entries },
	{ NWAM_NCU_PROP_TYPE, ncu_prop_type_entries },
	{ NWAM_NCU_PROP_CLASS, ncu_prop_class_entries },
	{ NWAM_NCU_PROP_IP_VERSION, ncu_prop_ip_version_entries },
	{ NWAM_NCU_PROP_IPV4_ADDRSRC, ncu_prop_ipv4_addrsrc_entries },
	{ NWAM_NCU_PROP_IPV6_ADDRSRC, ncu_prop_ipv6_addrsrc_entries },
	{ NWAM_NCU_PROP_PRIORITY_MODE, ncu_prop_priority_mode_entries },
	{ NWAM_ENM_PROP_ACTIVATION_MODE, prop_activation_mode_value_entries },
	{ NWAM_LOC_PROP_ACTIVATION_MODE, prop_activation_mode_value_entries },
	{ NWAM_LOC_PROP_NAMESERVICES, loc_prop_nameservices_entries },
	{ NWAM_LOC_PROP_DNS_NAMESERVICE_CONFIGSRC,
	    loc_prop_nameservice_configsrc_entries },
	{ NWAM_LOC_PROP_NIS_NAMESERVICE_CONFIGSRC,
	    loc_prop_nameservice_configsrc_entries },
	{ NWAM_LOC_PROP_LDAP_NAMESERVICE_CONFIGSRC,
	    loc_prop_nameservice_configsrc_entries },
	{ NWAM_KNOWN_WLAN_PROP_SECURITY_MODE,
	    known_wlan_prop_security_mode_entries },
	{ NULL, NULL }
};

/*
 * Convert uint64 values for property propname into a string representing
 * that value. Used by enum values.
 */
nwam_error_t
nwam_uint64_get_value_string(const char *propname, uint64_t val,
    const char **valstrp)
{
	int i, j;
	int max = 0; /* largest enum value seen so far */
	struct nwam_value_entry *value_entries;

	assert(propname != NULL && valstrp != NULL);

	for (i = 0; prop_value_entry_table[i].prop_name != NULL; i++) {
		if (strcmp(prop_value_entry_table[i].prop_name, propname) != 0)
			continue;

		value_entries = prop_value_entry_table[i].value_entries;

		for (j = 0; value_entries[j].value_string != NULL; j++) {
			if (value_entries[j].value == val) {
				*valstrp = value_entries[j].value_string;
				return (NWAM_SUCCESS);
			}
			max = value_entries[j].value > max ?
			    value_entries[j].value : max;
		}
		/*
		 * If trying to get the string for an enum value that doesn't
		 * exist, return NWAM_LIST_END.  Otherwise, the input enum
		 * value doesn't exist for the given property.
		 */
		if (val > max)
			return (NWAM_LIST_END);
		else
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_INVALID_ARG);
}

/*
 * Convert string to appropriate uint64 value.
 */
nwam_error_t
nwam_value_string_get_uint64(const char *propname, const char *valstr,
    uint64_t *valp)
{
	int i, j;
	struct nwam_value_entry *value_entries;

	assert(propname != NULL && valstr != NULL && valp != NULL);

	for (i = 0; prop_value_entry_table[i].prop_name != NULL; i++) {
		if (strcmp(prop_value_entry_table[i].prop_name, propname) != 0)
			continue;

		value_entries = prop_value_entry_table[i].value_entries;

		for (j = 0; value_entries[j].value_string != NULL; j++) {
			if (strcasecmp(value_entries[j].value_string, valstr)
			    == 0) {
				*valp = value_entries[j].value;
				return (NWAM_SUCCESS);
			}
		}
		return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_INVALID_ARG);
}

/* Conditional activation functions */

nwam_error_t
nwam_condition_to_condition_string(nwam_condition_object_type_t object_type,
    nwam_condition_t condition, const char *object_name, char **stringp)
{
	char *object_type_string, *condition_string;
	char *string;

	assert(stringp != NULL);

	*stringp = NULL;

	switch (object_type) {
	case NWAM_CONDITION_OBJECT_TYPE_NCP:
		object_type_string = NWAM_CONDITION_OBJECT_TYPE_NCP_STRING;
		break;
	case NWAM_CONDITION_OBJECT_TYPE_NCU:
		object_type_string = NWAM_CONDITION_OBJECT_TYPE_NCU_STRING;
		break;
	case NWAM_CONDITION_OBJECT_TYPE_ENM:
		object_type_string = NWAM_CONDITION_OBJECT_TYPE_ENM_STRING;
		break;
	case NWAM_CONDITION_OBJECT_TYPE_LOC:
		object_type_string = NWAM_CONDITION_OBJECT_TYPE_LOC_STRING;
		break;
	case NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS:
		object_type_string =
		    NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS_STRING;
		break;
	case NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN:
		object_type_string =
		    NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN_STRING;
		break;
	case NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN:
		object_type_string =
		    NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN_STRING;
		break;
	case NWAM_CONDITION_OBJECT_TYPE_ESSID:
		object_type_string = NWAM_CONDITION_OBJECT_TYPE_ESSID_STRING;
		break;
	case NWAM_CONDITION_OBJECT_TYPE_BSSID:
		object_type_string = NWAM_CONDITION_OBJECT_TYPE_BSSID_STRING;
		break;
	default:
		return (NWAM_INVALID_ARG);

	}
	switch (condition) {
	case NWAM_CONDITION_IS:
		condition_string = NWAM_CONDITION_IS_STRING;
		break;
	case NWAM_CONDITION_IS_NOT:
		condition_string = NWAM_CONDITION_IS_NOT_STRING;
		break;
	case NWAM_CONDITION_CONTAINS:
		if (object_type != NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN &&
		    object_type != NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN &&
		    object_type != NWAM_CONDITION_OBJECT_TYPE_ESSID)
			return (NWAM_INVALID_ARG);
		condition_string = NWAM_CONDITION_CONTAINS_STRING;
		break;
	case NWAM_CONDITION_DOES_NOT_CONTAIN:
		if (object_type != NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN &&
		    object_type != NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN &&
		    object_type != NWAM_CONDITION_OBJECT_TYPE_ESSID)
			return (NWAM_INVALID_ARG);

		condition_string = NWAM_CONDITION_DOES_NOT_CONTAIN_STRING;
		break;
	case NWAM_CONDITION_IS_IN_RANGE:
		if (object_type != NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS)
			return (NWAM_INVALID_ARG);
		condition_string = NWAM_CONDITION_IS_IN_RANGE_STRING;
		break;
	case NWAM_CONDITION_IS_NOT_IN_RANGE:
		if (object_type != NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS)
			return (NWAM_INVALID_ARG);
		condition_string = NWAM_CONDITION_IS_NOT_IN_RANGE_STRING;
		break;
	default:
		return (NWAM_INVALID_ARG);
	}
	if ((string = malloc(NWAM_MAX_VALUE_LEN)) == NULL)
		return (NWAM_NO_MEMORY);
	switch (object_type) {
	case NWAM_CONDITION_OBJECT_TYPE_NCP:
	case NWAM_CONDITION_OBJECT_TYPE_NCU:
	case NWAM_CONDITION_OBJECT_TYPE_ENM:
	case NWAM_CONDITION_OBJECT_TYPE_LOC:
		(void) snprintf(string, NWAM_MAX_VALUE_LEN,
		    "%s %s %s active", object_type_string,
		    object_name, condition_string);
		*stringp = string;
		break;

	case NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS:
	case NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN:
	case NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN:
	case NWAM_CONDITION_OBJECT_TYPE_ESSID:
	case NWAM_CONDITION_OBJECT_TYPE_BSSID:
		(void) snprintf(string, NWAM_MAX_VALUE_LEN,
		    "%s %s %s", object_type_string,
		    condition_string, object_name);
		*stringp = string;
		break;

	default:
		free(string);
		return (NWAM_INVALID_ARG);

	}
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_condition_string_to_condition(const char *string,
    nwam_condition_object_type_t *object_typep,
    nwam_condition_t *conditionp, char **object_namep)
{
	char *copy, *lasts;
	char *object_type_string, *object_name;
	char *condition_string, *active_string;

	assert(string != NULL && object_typep != NULL && conditionp != NULL &&
	    object_namep != NULL);

	if ((copy = strdup(string)) == NULL)
		return (NWAM_NO_MEMORY);

	if ((object_type_string = strtok_r(copy, " \t", &lasts)) == NULL) {
		free(copy);
		return (NWAM_INVALID_ARG);
	}

	if (strcmp(object_type_string, NWAM_CONDITION_OBJECT_TYPE_NCP_STRING)
	    == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_NCP;
	else if (strcmp(object_type_string,
	    NWAM_CONDITION_OBJECT_TYPE_NCU_STRING) == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_NCU;
	else if (strcmp(object_type_string,
	    NWAM_CONDITION_OBJECT_TYPE_ENM_STRING) == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_ENM;
	else if (strcmp(object_type_string,
	    NWAM_CONDITION_OBJECT_TYPE_LOC_STRING) == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_LOC;
	else if (strcmp(object_type_string,
	    NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS_STRING) == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS;
	else if (strcmp(object_type_string,
	    NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN_STRING) == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN;
	else if (strcmp(object_type_string,
	    NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN_STRING) == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN;
	else if (strcmp(object_type_string,
	    NWAM_CONDITION_OBJECT_TYPE_ESSID_STRING) == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_ESSID;
	else if (strcmp(object_type_string,
	    NWAM_CONDITION_OBJECT_TYPE_BSSID_STRING) == 0)
		*object_typep = NWAM_CONDITION_OBJECT_TYPE_BSSID;
	else {
		free(copy);
		return (NWAM_INVALID_ARG);
	}

	if (*object_typep == NWAM_CONDITION_OBJECT_TYPE_NCP ||
	    *object_typep == NWAM_CONDITION_OBJECT_TYPE_NCU ||
	    *object_typep == NWAM_CONDITION_OBJECT_TYPE_ENM ||
	    *object_typep == NWAM_CONDITION_OBJECT_TYPE_LOC) {
		if ((object_name = strtok_r(NULL, " \t", &lasts)) == NULL) {
			free(copy);
			return (NWAM_INVALID_ARG);
		}
		if ((*object_namep = strdup(object_name)) == NULL) {
			free(copy);
			return (NWAM_NO_MEMORY);
		}

	}

	if ((condition_string = strtok_r(NULL, " \t", &lasts)) == NULL) {
		free(copy);
		if (*object_namep != NULL)
			free(*object_namep);
		return (NWAM_INVALID_ARG);
	}
	if (strcmp(condition_string, NWAM_CONDITION_IS_STRING) == 0)
		*conditionp = NWAM_CONDITION_IS;
	else if (strcmp(condition_string, NWAM_CONDITION_IS_NOT_STRING) == 0)
		*conditionp = NWAM_CONDITION_IS_NOT;
	else if (strcmp(condition_string, NWAM_CONDITION_CONTAINS_STRING) == 0)
		*conditionp = NWAM_CONDITION_CONTAINS;
	else if (strcmp(condition_string,
	    NWAM_CONDITION_DOES_NOT_CONTAIN_STRING) == 0)
		*conditionp = NWAM_CONDITION_DOES_NOT_CONTAIN;
	else if (strcmp(condition_string,
	    NWAM_CONDITION_IS_IN_RANGE_STRING) == 0)
		*conditionp = NWAM_CONDITION_IS_IN_RANGE;
	else if (strcmp(condition_string,
	    NWAM_CONDITION_IS_NOT_IN_RANGE_STRING) == 0)
		*conditionp = NWAM_CONDITION_IS_NOT_IN_RANGE;
	else {
		free(copy);
		if (*object_namep != NULL)
			free(*object_namep);
		return (NWAM_INVALID_ARG);
	}

	if (*object_typep == NWAM_CONDITION_OBJECT_TYPE_NCP ||
	    *object_typep == NWAM_CONDITION_OBJECT_TYPE_NCU ||
	    *object_typep == NWAM_CONDITION_OBJECT_TYPE_ENM ||
	    *object_typep == NWAM_CONDITION_OBJECT_TYPE_LOC) {
		if ((*conditionp != NWAM_CONDITION_IS &&
		    *conditionp != NWAM_CONDITION_IS_NOT) ||
		    (active_string = strtok_r(NULL, " \t", &lasts)) == NULL ||
		    strcmp(active_string, NWAM_CONDITION_ACTIVE_STRING) != 0) {
			free(copy);
			free(*object_namep);
			return (NWAM_INVALID_ARG);
		}
	} else {
		switch (*conditionp) {
		case NWAM_CONDITION_CONTAINS:
		case NWAM_CONDITION_DOES_NOT_CONTAIN:
			if (*object_typep !=
			    NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN &&
			    *object_typep !=
			    NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN &&
			    *object_typep != NWAM_CONDITION_OBJECT_TYPE_ESSID) {
				free(copy);
				free(*object_namep);
				return (NWAM_INVALID_ARG);
			}
			break;
		case NWAM_CONDITION_IS_IN_RANGE:
		case NWAM_CONDITION_IS_NOT_IN_RANGE:
			if (*object_typep !=
			    NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS) {
				free(copy);
				free(*object_namep);
				return (NWAM_INVALID_ARG);
			}
			break;
		}

		if ((object_name = strtok_r(NULL, " \t", &lasts)) == NULL) {
			free(copy);
			free(*object_namep);
			return (NWAM_INVALID_ARG);
		}
		if ((*object_namep = strdup(object_name)) == NULL) {
			free(copy);
			free(*object_namep);
			return (NWAM_NO_MEMORY);
		}
	}

	free(copy);
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_condition_rate(nwam_condition_object_type_t object_type,
    nwam_condition_t condition, uint64_t *ratep)
{
	assert(ratep != NULL);

	*ratep = 0;

	switch (object_type) {
	case NWAM_CONDITION_OBJECT_TYPE_NCP:
	case NWAM_CONDITION_OBJECT_TYPE_NCU:
	case NWAM_CONDITION_OBJECT_TYPE_ENM:
	case NWAM_CONDITION_OBJECT_TYPE_LOC:
		(*ratep)++;
		/* FALLTHRU */
	case NWAM_CONDITION_OBJECT_TYPE_SYS_DOMAIN:
		(*ratep)++;
		/* FALLTHRU */
	case NWAM_CONDITION_OBJECT_TYPE_ADV_DOMAIN:
		(*ratep)++;
		/* FALLTHRU */
	case NWAM_CONDITION_OBJECT_TYPE_IP_ADDRESS:
		(*ratep)++;
		/* FALLTHRU */
	case NWAM_CONDITION_OBJECT_TYPE_BSSID:
		(*ratep)++;
		/* FALLTHRU */
	case NWAM_CONDITION_OBJECT_TYPE_ESSID:
		(*ratep)++;
		break;
	default:
		return (NWAM_INVALID_ARG);
	}

	switch (condition) {
	case NWAM_CONDITION_IS:
		(*ratep)++;
		/* FALLTHRU */
	case NWAM_CONDITION_CONTAINS:
	case NWAM_CONDITION_IS_IN_RANGE:
		(*ratep)++;
		/* FALLTHRU */
	case NWAM_CONDITION_DOES_NOT_CONTAIN:
	case NWAM_CONDITION_IS_NOT_IN_RANGE:
		(*ratep)++;
		/* FALLTHRU */
	case NWAM_CONDITION_IS_NOT:
		(*ratep)++;
		break;
	default:
		return (NWAM_INVALID_ARG);
	}
	return (NWAM_SUCCESS);
}
