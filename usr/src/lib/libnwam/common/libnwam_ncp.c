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
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#include <assert.h>
#include <ctype.h>
#include <libgen.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <libdladm.h>
#include <libipadm.h>

#include "libnwam_impl.h"
#include <libnwam_priv.h>
#include <libnwam.h>

/*
 * Functions to support creating, modifying, destroying, querying the
 * state of and changing the state of NCP (Network Configuration Profiles)
 * and the NCUs (Network Configuration Units) that are contained in those
 * NCP objects.  An NCP is simply a container for a set of NCUs which represent
 * the datalink and interface configuration preferences for the system.
 * An NCP can consist a set of prioritized link NCUs, e.g. wired links preferred
 * over wireless, a set of manually enabled/diasbled NCUs, or a combination
 * of both. Interface NCUs inherit activation from their underlying links,
 * so if wired is preferred over wireless and a cable is plugged in,
 * the wired link NCU will be active, as will the IP interface NCU above it.
 */

/*
 * The NCU property table is used to mapping property types to property name
 * strings, their associated value types etc. The table is used for validation
 * purposes, and for commit()ing and read()ing NCUs.
 */

static nwam_error_t valid_type(nwam_value_t);
static nwam_error_t valid_class(nwam_value_t);
static nwam_error_t valid_ncp(nwam_value_t);
static nwam_error_t valid_priority_mode(nwam_value_t);
static nwam_error_t valid_ncu_activation_mode(nwam_value_t);
static nwam_error_t valid_link_autopush(nwam_value_t);
static nwam_error_t valid_link_mtu(nwam_value_t);
static nwam_error_t valid_ip_version(nwam_value_t);
static nwam_error_t valid_addrsrc_v4(nwam_value_t);
static nwam_error_t valid_addrsrc_v6(nwam_value_t);
static nwam_error_t valid_reqhost(nwam_value_t);

struct nwam_prop_table_entry ncu_prop_table_entries[] = {
	{NWAM_NCU_PROP_TYPE, NWAM_VALUE_TYPE_UINT64, B_FALSE, 1, 1, valid_type,
	    "specifies the NCU type - valid values are \'datalink\' and \'ip\'",
	    NWAM_FLAG_NCU_TYPE_ALL, NWAM_FLAG_NCU_CLASS_ALL},
	{NWAM_NCU_PROP_CLASS, NWAM_VALUE_TYPE_UINT64, B_FALSE, 1, 1,
	    valid_class,
	    "specifies the NCU class - valid values are "
	    "\'phys\' and \'ip\'",
	    NWAM_FLAG_NCU_TYPE_ALL, NWAM_FLAG_NCU_CLASS_ALL},
	{NWAM_NCU_PROP_PARENT_NCP, NWAM_VALUE_TYPE_STRING, B_FALSE, 1, 1,
	    valid_ncp,
	    "specifies the parent NCP name",
	    NWAM_FLAG_NCU_TYPE_ALL, NWAM_FLAG_NCU_CLASS_ALL},
	{NWAM_NCU_PROP_ACTIVATION_MODE, NWAM_VALUE_TYPE_UINT64, B_FALSE, 1, 1,
	    valid_ncu_activation_mode,
	    "specifies the NCU activation mode - valid values are:\n"
	    "\'prioritized\' and \'manual\'",
	    NWAM_FLAG_NCU_TYPE_LINK, NWAM_FLAG_NCU_CLASS_ALL_LINK},
	{NWAM_NCU_PROP_ENABLED, NWAM_VALUE_TYPE_BOOLEAN, B_TRUE, 0, 1,
	    nwam_valid_boolean,
	    "specifies if manual NCU is to be enabled",
	    NWAM_FLAG_NCU_TYPE_ALL, NWAM_FLAG_NCU_CLASS_ALL},
	{NWAM_NCU_PROP_PRIORITY_GROUP, NWAM_VALUE_TYPE_UINT64, B_FALSE, 0, 1,
	    nwam_valid_uint64,
	    "specifies the priority grouping of NCUs - lower values are "
	    "prioritized, negative values are invalid",
	    NWAM_FLAG_NCU_TYPE_LINK, NWAM_FLAG_NCU_CLASS_ALL_LINK},
	{NWAM_NCU_PROP_PRIORITY_MODE, NWAM_VALUE_TYPE_UINT64, B_FALSE, 0, 1,
	    valid_priority_mode,
	    "specifies the mode of prioritization - valid values are:\n"
	    "\'exclusive\', \'shared\' and \'all\'",
	    NWAM_FLAG_NCU_TYPE_LINK, NWAM_FLAG_NCU_CLASS_ALL_LINK},
	{NWAM_NCU_PROP_LINK_MAC_ADDR, NWAM_VALUE_TYPE_STRING, B_FALSE, 0, 1,
	    nwam_valid_mac_addr,
	    "specifies MAC address of form aa:bb:cc:dd:ee:ff for the link",
	    NWAM_FLAG_NCU_TYPE_LINK, NWAM_FLAG_NCU_CLASS_ALL_LINK},
	{NWAM_NCU_PROP_LINK_AUTOPUSH, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    NWAM_MAX_NUM_VALUES, valid_link_autopush,
	    "specifies modules to autopush on link",
	    NWAM_FLAG_NCU_TYPE_LINK, NWAM_FLAG_NCU_CLASS_ALL_LINK},
	{NWAM_NCU_PROP_LINK_MTU, NWAM_VALUE_TYPE_UINT64, B_FALSE, 0, 1,
	    valid_link_mtu,
	    "specifies MTU for link",
	    NWAM_FLAG_NCU_TYPE_LINK, NWAM_FLAG_NCU_CLASS_ALL_LINK},
	{NWAM_NCU_PROP_IP_VERSION, NWAM_VALUE_TYPE_UINT64, B_FALSE, 0,
	    NWAM_MAX_NUM_VALUES, valid_ip_version,
	    "specifies IP versions for IP NCU - valid values are:\n"
	    "\'ipv4\' and \'ipv6\'",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
	{NWAM_NCU_PROP_IPV4_ADDRSRC, NWAM_VALUE_TYPE_UINT64, B_FALSE, 0,
	    NWAM_MAX_NUM_VALUES, valid_addrsrc_v4,
	    "specifies IPv4 address source(s) - valid values are:\n"
	    "\'dhcp\' and \'static\'",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
	{NWAM_NCU_PROP_IPV4_ADDR, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    NWAM_MAX_NUM_VALUES, nwam_valid_host_v4,
	    "specifies static IPv4 host address(es)",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
	{NWAM_NCU_PROP_IPV4_DEFAULT_ROUTE, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    1, nwam_valid_route_v4,
	    "specifies per-interface default IPv4 route",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
	{NWAM_NCU_PROP_IPV6_ADDRSRC, NWAM_VALUE_TYPE_UINT64, B_FALSE, 0,
	    NWAM_MAX_NUM_VALUES, valid_addrsrc_v6,
	    "specifies IPv6 address source(s) - valid values are:\n"
	    "\'dhcp\', \'autoconf\' and \'static\'.\n"
	    "\'dhcp\' and \'autoconf\' are mandatory values.",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
	{NWAM_NCU_PROP_IPV6_ADDR, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    NWAM_MAX_NUM_VALUES, nwam_valid_host_v6,
	    "specifies static IPv6 host address(es)",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
	{NWAM_NCU_PROP_IPV6_DEFAULT_ROUTE, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    1, nwam_valid_route_v6,
	    "specifies per-interface default IPv6 route",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
	{NWAM_NCU_PROP_IP_PRIMARY, NWAM_VALUE_TYPE_BOOLEAN, B_FALSE, 0,
	    1, nwam_valid_boolean,
	    "specifies the status of an interface as primary for the delivery"
	    " of client-wide configuration data",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
	{NWAM_NCU_PROP_IP_REQHOST, NWAM_VALUE_TYPE_STRING, B_FALSE, 0,
	    1, valid_reqhost,
	    "specifies a requested hostname for the interface",
	    NWAM_FLAG_NCU_TYPE_INTERFACE, NWAM_FLAG_NCU_CLASS_ALL_INTERFACE},
};

#define	NWAM_NUM_NCU_PROPS	(sizeof (ncu_prop_table_entries) / \
				sizeof (*ncu_prop_table_entries))

struct nwam_prop_table ncu_prop_table =
	{ NWAM_NUM_NCU_PROPS, ncu_prop_table_entries };

nwam_error_t
nwam_ncp_get_name(nwam_ncp_handle_t ncph, char **namep)
{
	return (nwam_get_name(ncph, namep));
}

static nwam_error_t
nwam_ncp_name_to_file(const char *name, char **filename)
{
	assert(name != NULL && filename != NULL);

	if ((*filename = malloc(MAXPATHLEN)) == NULL)
		return (NWAM_NO_MEMORY);

	(void) snprintf(*filename, MAXPATHLEN, "%s%s%s%s", NWAM_CONF_DIR,
	    NWAM_NCP_CONF_FILE_PRE, name, NWAM_NCP_CONF_FILE_SUF);

	return (NWAM_SUCCESS);
}

/* ARGSUSED1 */
nwam_error_t
nwam_ncp_create(const char *name, uint64_t flags, nwam_ncp_handle_t *ncphp)
{
	nwam_error_t err;
	char *ncpfile;

	if ((err = nwam_handle_create(NWAM_OBJECT_TYPE_NCP, name, ncphp))
	    != NWAM_SUCCESS)
		return (err);

	/* Create empty container for NCUs */
	if ((err = nwam_ncp_name_to_file(name, &ncpfile))
	    != NWAM_SUCCESS) {
		nwam_free(*ncphp);
		*ncphp = NULL;
		return (err);
	}

	if ((err = nwam_commit(ncpfile, *ncphp, flags)) != NWAM_SUCCESS) {
		nwam_free(*ncphp);
		*ncphp = NULL;
	}

	free(ncpfile);

	return (err);
}

/* Used by libnwam_files.c */
nwam_error_t
nwam_ncp_file_to_name(const char *path, char **name)
{
	char path_copy[MAXPATHLEN];
	char *filename, *suffix;

	assert(path != NULL && name != NULL);

	/* Make a copy as basename(3c) may modify string */
	(void) strlcpy(path_copy, path, MAXPATHLEN);

	if ((*name = malloc(NWAM_MAX_NAME_LEN)) == NULL)
		return (NWAM_NO_MEMORY);

	if ((filename = basename(path_copy)) == NULL) {
		free(*name);
		return (NWAM_ENTITY_INVALID);
	}

	/* Ensure filename begins/ends with right prefix/suffix */
	if (sscanf(filename, NWAM_NCP_CONF_FILE_PRE "%256[^\n]s", *name) < 1) {
		free(*name);
		return (NWAM_ENTITY_INVALID);
	}
	suffix = *name + strlen(*name) - strlen(NWAM_NCP_CONF_FILE_SUF);
	if (strstr(*name, NWAM_NCP_CONF_FILE_SUF) != suffix) {
		free(*name);
		return (NWAM_ENTITY_INVALID);
	}
	suffix[0] = '\0';

	return (NWAM_SUCCESS);
}

/* ARGSUSED1 */
nwam_error_t
nwam_ncp_read(const char *name, uint64_t flags, nwam_ncp_handle_t *ncphp)
{
	char *filename;
	nwam_error_t err;

	assert(name != NULL && ncphp != NULL);

	/* try to read the associated ncp configuration */
	if ((err = nwam_ncp_name_to_file(name, &filename)) != NWAM_SUCCESS) {
		*ncphp = NULL;
		return (err);
	}

	err = nwam_read(NWAM_OBJECT_TYPE_NCP, filename, name, flags, ncphp);
	free(filename);
	return (err);
}

static nwam_error_t
nwam_ncu_get_parent_ncp_name(nwam_ncu_handle_t ncuh, char **parentnamep)
{
	nwam_value_t parentval = NULL;
	char *parentname;
	nwam_error_t err;

	if ((err = nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_PARENT_NCP,
	    &parentval)) != NWAM_SUCCESS ||
	    (err = nwam_value_get_string(parentval, &parentname))
	    != NWAM_SUCCESS ||
	    (*parentnamep = strdup(parentname)) == NULL) {
		if (parentval != NULL)
			nwam_value_free(parentval);
		*parentnamep = NULL;
		return (err);
	}
	nwam_value_free(parentval);

	return (NWAM_SUCCESS);
}

static int
nwam_ncp_copy_callback(nwam_ncu_handle_t oldncuh, void *arg)
{
	nwam_error_t err;
	nwam_ncu_handle_t newncuh = NULL;
	char *oldparent;
	char *oldfilename = NULL, *newfilename = NULL;
	nwam_ncp_handle_t newncph = (nwam_ncp_handle_t)arg;
	nwam_value_t newparentval;

	/* Get filenames for the new and old NCU's */
	if ((err = nwam_ncu_get_parent_ncp_name(oldncuh, &oldparent))
	    != NWAM_SUCCESS)
		return (err);
	err = nwam_ncp_name_to_file(oldparent, &oldfilename);
	free(oldparent);
	if (err != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_ncp_name_to_file(newncph->nwh_name, &newfilename))
	    != NWAM_SUCCESS)
		goto fail;

	/* new NCU name (and typedname) is the same as the old name */
	if ((err = nwam_handle_create(NWAM_OBJECT_TYPE_NCU, oldncuh->nwh_name,
	    &newncuh)) != NWAM_SUCCESS)
		goto fail;
	/* Duplicate the old NCU's data */
	if ((err = nwam_dup_object_list(oldncuh->nwh_data,
	    &(newncuh->nwh_data))) != NWAM_SUCCESS)
		goto fail;

	/* Update the parent property for the new NCU */
	if ((err = nwam_value_create_string(newncph->nwh_name, &newparentval))
	    != NWAM_SUCCESS)
		goto fail;
	err = nwam_set_prop_value(newncuh->nwh_data, NWAM_NCU_PROP_PARENT_NCP,
	    newparentval);
	nwam_value_free(newparentval);
	if (err != NWAM_SUCCESS)
		goto fail;

	/* Save the new NCU */
	err = nwam_commit(newfilename, newncuh, 0);

fail:
	free(oldfilename);
	free(newfilename);
	nwam_ncu_free(newncuh);
	return (err);
}

nwam_error_t
nwam_ncp_copy(nwam_ncp_handle_t oldncph, const char *newname,
    nwam_ncp_handle_t *newncphp)
{
	nwam_ncp_handle_t ncph;
	nwam_error_t err;
	int cb_ret;

	assert(oldncph != NULL && newname != NULL && newncphp != NULL);

	/* check if newname NCP already exists */
	if (nwam_ncp_read(newname, 0,  &ncph) == NWAM_SUCCESS) {
		nwam_ncp_free(ncph);
		*newncphp = NULL;
		return (NWAM_ENTITY_EXISTS);
	}

	/* create new handle */
	if ((err = nwam_ncp_create(newname, 0, newncphp)) != NWAM_SUCCESS)
		return (err);

	err = nwam_ncp_walk_ncus(oldncph, nwam_ncp_copy_callback, *newncphp,
	    NWAM_FLAG_NCU_TYPE_CLASS_ALL, &cb_ret);
	if (err != NWAM_SUCCESS) {
		/* remove the NCP even if any NCU's had already been copied */
		(void) nwam_ncp_destroy(*newncphp, 0);
		*newncphp = NULL;
		if (err == NWAM_WALK_HALTED)
			return (cb_ret);
		else
			return (err);
	}

	return (NWAM_SUCCESS);
}

/*
 * Convert type to flag
 */
static uint64_t
nwam_ncu_type_to_flag(nwam_ncu_type_t type)
{
	switch (type) {
	case NWAM_NCU_TYPE_LINK:
		return (NWAM_FLAG_NCU_TYPE_LINK);
	case NWAM_NCU_TYPE_INTERFACE:
		return (NWAM_FLAG_NCU_TYPE_INTERFACE);
	case NWAM_NCU_TYPE_ANY:
		return (NWAM_FLAG_NCU_TYPE_ALL);
	default:
		return (0);
	}
}

/*
 * Convert class to flag
 */
uint64_t
nwam_ncu_class_to_flag(nwam_ncu_class_t class)
{
	switch (class) {
	case NWAM_NCU_CLASS_PHYS:
		return (NWAM_FLAG_NCU_CLASS_PHYS);
	case NWAM_NCU_CLASS_IP:
		return (NWAM_FLAG_NCU_CLASS_IP);
	case NWAM_NCU_CLASS_ANY:
		return (NWAM_FLAG_NCU_CLASS_ALL);
	default:
		return (0);
	}
}

/*
 * Infer NCU type from NCU class
 */
nwam_ncu_type_t
nwam_ncu_class_to_type(nwam_ncu_class_t class)
{
	switch (class) {
	case NWAM_NCU_CLASS_PHYS:
		return (NWAM_NCU_TYPE_LINK);
	case NWAM_NCU_CLASS_IP:
		return (NWAM_NCU_TYPE_INTERFACE);
	case NWAM_NCU_CLASS_ANY:
		return (NWAM_NCU_TYPE_ANY);
	default:
		return (NWAM_NCU_TYPE_UNKNOWN);
	}
}

/*
 * Make ncp active, deactivating any other active ncp.
 */
nwam_error_t
nwam_ncp_enable(nwam_ncp_handle_t ncph)
{
	nwam_error_t err;
	char *name;

	assert(ncph != NULL);

	err = nwam_enable(NULL, ncph);

	if (err == NWAM_ERROR_BIND) {
		/*
		 * nwamd is not running, set active_ncp property so when
		 * nwamd is next started, this NCP will be used.
		 */
		if ((err = nwam_ncp_get_name(ncph, &name)) != NWAM_SUCCESS)
			return (err);

		err = nwam_set_smf_string_property(NWAM_FMRI, NWAM_PG,
		    NWAM_PROP_ACTIVE_NCP, name);
		free(name);
	}

	return (err);
}

/* Compare NCP names c1 and c2 using strcasecmp() */
static int
ncpname_cmp(const void *c1, const void *c2)
{
	return (strcasecmp(*(const char **)c1, *(const char **)c2));
}

/* ARGSUSED1 */
nwam_error_t
nwam_walk_ncps(int (*cb)(nwam_ncp_handle_t, void *), void *data,
    uint64_t flags, int *retp)
{
	char *ncpname, **ncpfiles;
	nwam_ncp_handle_t ncph;
	nwam_error_t err;
	nwam_value_t value;
	void *objlist;
	uint_t i, num_ncpfiles;
	int ret = 0;

	assert(cb != NULL);

	if ((err = nwam_valid_flags(flags, NWAM_FLAG_BLOCKING)) != NWAM_SUCCESS)
		return (err);
	/*
	 * To get list of NCP files, call nwam_read_object_from_backend()
	 * with "parent" argument set to NULL. We get back an object list
	 * consisting of string arrays for each object type - NCP, ENM
	 * and location. We retrieve the NCP list, which corresponds to
	 * the set of NCP backend parent objects (these are files at present).
	 */
	if ((err = nwam_read_object_from_backend(NULL, NULL, flags,
	    &objlist)) != NWAM_SUCCESS)
		return (err);

	if ((err = nwam_get_prop_value(objlist, NWAM_NCP_OBJECT_STRING, &value))
	    != NWAM_SUCCESS) {
		nwam_free_object_list(objlist);
		return (err);
	}
	if ((err = nwam_value_get_string_array(value, &ncpfiles,
	    &num_ncpfiles)) != NWAM_SUCCESS) {
		nwam_value_free(value);
		nwam_free_object_list(objlist);
		return (err);
	}

	/* sort the NCP names alphabetically */
	qsort(ncpfiles, num_ncpfiles, sizeof (char *), ncpname_cmp);

	for (i = 0; i < num_ncpfiles; i++) {
		if (nwam_ncp_file_to_name(ncpfiles[i], &ncpname)
		    != NWAM_SUCCESS)
			continue;
		if ((err = nwam_handle_create(NWAM_OBJECT_TYPE_NCP, ncpname,
		    &ncph)) != NWAM_SUCCESS) {
			free(ncpname);
			break;
		}
		ret = cb(ncph, data);
		free(ncph);
		free(ncpname);
		if (ret != 0) {
			err = NWAM_WALK_HALTED;
			break;
		}
	}
	nwam_value_free(value);
	nwam_free_object_list(objlist);

	if (retp != NULL)
		*retp = ret;
	return (err);
}

/*
 * Checks if NCP is read-only.  Only NWAM_NCP_NAME_AUTOMATIC is read-only
 * for all but the netadm user (which nwamd runs as).
 */
nwam_error_t
nwam_ncp_get_read_only(nwam_ncp_handle_t ncph, boolean_t *readp)
{
	nwam_error_t err;
	char *name;

	assert(ncph != NULL && readp != NULL);

	if ((err = nwam_ncp_get_name(ncph, &name)) != NWAM_SUCCESS)
		return (err);

	if (NWAM_NCP_AUTOMATIC(name))
		*readp = !nwam_uid_is_special();
	else
		*readp = B_FALSE;

	free(name);
	return (NWAM_SUCCESS);
}

/* Checks if NCU is writable depending on its parent */
nwam_error_t
nwam_ncu_get_read_only(nwam_ncu_handle_t ncuh, boolean_t *readp)
{
	nwam_error_t err;
	nwam_ncp_handle_t ncph;

	assert(ncuh != NULL && readp != NULL);

	if ((err = nwam_ncu_get_ncp(ncuh, &ncph)) != NWAM_SUCCESS)
		return (err);

	err = nwam_ncp_get_read_only(ncph, readp);
	nwam_ncp_free(ncph);
	return (err);
}

/* Returns true if the NCP is active */
static boolean_t
nwam_ncp_is_active(nwam_ncp_handle_t ncph)
{
	char *active_ncp, *name;
	boolean_t ret;

	assert(ncph != NULL);

	/*
	 * Determine which NCP is active via the nwamd/active_ncp property
	 * value.  This allows us to determine which NCP is active even
	 * if nwamd is not running.
	 */
	if (nwam_ncp_get_name(ncph, &name) != NWAM_SUCCESS ||
	    nwam_get_smf_string_property(NWAM_FMRI, NWAM_PG,
	    NWAM_PROP_ACTIVE_NCP, &active_ncp) != NWAM_SUCCESS)
		return (B_FALSE);

	ret = (strcmp(name, active_ncp) == 0);

	free(active_ncp);
	free(name);

	return (ret);
}

nwam_error_t
nwam_ncp_destroy(nwam_ncp_handle_t ncph, uint64_t flags)
{
	char *filename;
	nwam_error_t err;
	boolean_t read_only;

	assert(ncph != NULL);

	if ((err = nwam_ncp_get_read_only(ncph, &read_only)) != NWAM_SUCCESS)
		return (err);
	if (read_only)
		return (NWAM_ENTITY_NOT_DESTROYABLE);

	if (nwam_ncp_is_active(ncph))
		return (NWAM_ENTITY_IN_USE);

	if ((err = nwam_ncp_name_to_file(ncph->nwh_name, &filename))
	    != NWAM_SUCCESS)
		return (err);

	err = nwam_destroy(filename, ncph, flags);
	free(filename);

	return (NWAM_SUCCESS);
}

static nwam_error_t
nwam_ncu_internal_name_to_name(const char *internalname,
    nwam_ncu_type_t *typep, char **namep)
{
	char *prefixstr;

	assert(internalname != NULL && namep != NULL);

	if (strncasecmp(internalname, NWAM_NCU_LINK_NAME_PRE,
	    strlen(NWAM_NCU_LINK_NAME_PRE)) == 0) {
		prefixstr = NWAM_NCU_LINK_NAME_PRE;
		*typep = NWAM_NCU_TYPE_LINK;
	} else if (strncasecmp(internalname, NWAM_NCU_INTERFACE_NAME_PRE,
	    strlen(NWAM_NCU_INTERFACE_NAME_PRE)) == 0) {
		prefixstr = NWAM_NCU_INTERFACE_NAME_PRE;
		*typep = NWAM_NCU_TYPE_INTERFACE;
	} else {
		return (NWAM_INVALID_ARG);
	}

	*namep = strdup(internalname + strlen(prefixstr));
	if (*namep == NULL)
		return (NWAM_NO_MEMORY);
	return (NWAM_SUCCESS);
}

/* ARGSUSED2 */
static int
ncu_selectcb(struct nwam_handle *hp, uint64_t flags, void *data)
{
	nwam_ncu_handle_t ncuh = hp;
	nwam_value_t typeval = NULL, classval = NULL;
	uint64_t type, class, matchflags, walkfilter;

	if (nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_TYPE, &typeval)
	    != NWAM_SUCCESS ||
	    nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_CLASS, &classval)
	    != NWAM_SUCCESS) {
		if (typeval != NULL)
			nwam_value_free(typeval);
		return (NWAM_INVALID_ARG);
	}
	if (nwam_value_get_uint64(typeval, &type) != NWAM_SUCCESS ||
	    nwam_value_get_uint64(classval, &class) != NWAM_SUCCESS) {
		nwam_value_free(typeval);
		nwam_value_free(classval);
		return (NWAM_INVALID_ARG);
	}

	matchflags = nwam_ncu_type_to_flag(type) |
	    nwam_ncu_class_to_flag(class);
	nwam_value_free(typeval);
	nwam_value_free(classval);

	if ((walkfilter = (flags & NWAM_WALK_FILTER_MASK)) == 0)
		walkfilter = NWAM_FLAG_NCU_TYPE_CLASS_ALL;

	if (matchflags & walkfilter)
		return (NWAM_SUCCESS);
	return (NWAM_INVALID_ARG);
}

nwam_error_t
nwam_ncp_walk_ncus(nwam_ncp_handle_t ncph,
    int(*cb)(nwam_ncu_handle_t, void *), void *data, uint64_t flags, int *retp)
{
	char *ncpfile;
	nwam_error_t err;

	assert(ncph != NULL && cb != NULL);

	if ((err = nwam_valid_flags(flags,
	    NWAM_FLAG_NCU_TYPE_CLASS_ALL | NWAM_FLAG_BLOCKING)) != NWAM_SUCCESS)
		return (err);

	if ((err = nwam_ncp_name_to_file(ncph->nwh_name, &ncpfile))
	    != NWAM_SUCCESS)
		return (err);

	err = nwam_walk(NWAM_OBJECT_TYPE_NCU, ncpfile, cb, data, flags,
	    retp, ncu_selectcb);
	free(ncpfile);

	return (err);
}

void
nwam_ncp_free(nwam_ncp_handle_t ncph)
{
	nwam_free(ncph);
}

/*
 * Are ncu type and class compatible?
 */
static boolean_t
nwam_ncu_type_class_compatible(nwam_ncu_type_t type, nwam_ncu_class_t class)
{
	switch (type) {
	case NWAM_NCU_TYPE_LINK:
		return (class == NWAM_NCU_CLASS_PHYS);
	case NWAM_NCU_TYPE_INTERFACE:
		return (class == NWAM_NCU_CLASS_IP);
	default:
		return (B_FALSE);
	}
}

/* Name to validate may be internal name. If so, convert it before validating */
static boolean_t
valid_ncu_name(const char *name)
{
	char *n;
	boolean_t ret;
	nwam_ncu_type_t type;

	if (nwam_ncu_internal_name_to_name(name, &type, &n) == NWAM_SUCCESS) {

		ret = dladm_valid_linkname(n);
		free(n);
	} else {
		ret = dladm_valid_linkname(name);
	}

	return (ret);
}

nwam_error_t
nwam_ncu_create(nwam_ncp_handle_t ncph, const char *name,
    nwam_ncu_type_t type, nwam_ncu_class_t class, nwam_ncu_handle_t *ncuhp)
{
	nwam_ncu_handle_t ncuh;
	nwam_value_t typeval = NULL, classval = NULL, parentval = NULL;
	nwam_value_t enabledval = NULL;
	nwam_error_t err;
	boolean_t read_only;
	char *typedname;

	assert(ncph != NULL && name != NULL && ncuhp != NULL);

	if (!valid_ncu_name(name))
		return (NWAM_INVALID_ARG);

	if ((err = nwam_ncp_get_read_only(ncph, &read_only)) != NWAM_SUCCESS)
		return (err);
	if (read_only)
		return (NWAM_ENTITY_READ_ONLY);

	if (nwam_ncu_read(ncph, name, type, 0, &ncuh) == NWAM_SUCCESS) {
		nwam_ncu_free(ncuh);
		return (NWAM_ENTITY_EXISTS);
	}

	if (!valid_ncu_name(name) ||
	    !nwam_ncu_type_class_compatible(type, class))
		return (NWAM_INVALID_ARG);

	if ((err = nwam_ncu_name_to_typed_name(name, type, &typedname))
	    != NWAM_SUCCESS)
		return (err);

	/* Create handle */
	if ((err = nwam_handle_create(NWAM_OBJECT_TYPE_NCU, typedname, ncuhp))
	    != NWAM_SUCCESS)
		return (err);
	free(typedname);

	/*
	 * Create new object list for NCU.  The new NCU is initialized with
	 * the appropriate type and class.
	 */
	if ((err = nwam_alloc_object_list(&(*ncuhp)->nwh_data)) != NWAM_SUCCESS)
		goto finish;

	if ((err = nwam_value_create_uint64(type, &typeval))
	    != NWAM_SUCCESS ||
	    (err = nwam_value_create_uint64(class, &classval))
	    != NWAM_SUCCESS ||
	    (err = nwam_value_create_string(ncph->nwh_name, &parentval))
	    != NWAM_SUCCESS ||
	    (err = nwam_value_create_boolean(B_TRUE, &enabledval))
	    != NWAM_SUCCESS) {
		goto finish;
	}
	if ((err = nwam_set_prop_value((*ncuhp)->nwh_data, NWAM_NCU_PROP_TYPE,
	    typeval)) != NWAM_SUCCESS ||
	    (err = nwam_set_prop_value((*ncuhp)->nwh_data, NWAM_NCU_PROP_CLASS,
	    classval)) != NWAM_SUCCESS ||
	    (err = nwam_set_prop_value((*ncuhp)->nwh_data,
	    NWAM_NCU_PROP_PARENT_NCP, parentval)) != NWAM_SUCCESS ||
	    (err = nwam_set_prop_value((*ncuhp)->nwh_data,
	    NWAM_NCU_PROP_ENABLED, enabledval)) != NWAM_SUCCESS) {
		goto finish;
	}

	/* Set default IP, datalink properties */
	if (type == NWAM_NCU_TYPE_INTERFACE && class == NWAM_NCU_CLASS_IP) {

		uint64_t ver[] = { IPV4_VERSION, IPV6_VERSION };
		uint64_t v6src[] = { NWAM_ADDRSRC_DHCP, NWAM_ADDRSRC_AUTOCONF };
		uint_t vercnt = 2, v6srccnt = 2;
		nwam_value_t ipver = NULL, v4addrsrc = NULL, v6addrsrc = NULL;

		if ((err = nwam_value_create_uint64_array(ver, vercnt, &ipver))
		    != NWAM_SUCCESS ||
		    (err = nwam_value_create_uint64(NWAM_ADDRSRC_DHCP,
		    &v4addrsrc)) != NWAM_SUCCESS ||
		    (err = nwam_value_create_uint64_array(v6src, v6srccnt,
		    &v6addrsrc)) != NWAM_SUCCESS) {
			nwam_value_free(ipver);
			nwam_value_free(v4addrsrc);
			goto finish;
		}
		if ((err = nwam_set_prop_value((*ncuhp)->nwh_data,
		    NWAM_NCU_PROP_IP_VERSION, ipver)) == NWAM_SUCCESS &&
		    (err = nwam_set_prop_value((*ncuhp)->nwh_data,
		    NWAM_NCU_PROP_IPV4_ADDRSRC, v4addrsrc)) == NWAM_SUCCESS) {
			err = nwam_set_prop_value((*ncuhp)->nwh_data,
			    NWAM_NCU_PROP_IPV6_ADDRSRC, v6addrsrc);
		}
		nwam_value_free(ipver);
		nwam_value_free(v4addrsrc);
		nwam_value_free(v6addrsrc);
	} else {
		nwam_value_t actval = NULL;
		if ((err = nwam_value_create_uint64(NWAM_ACTIVATION_MODE_MANUAL,
		    &actval)) != NWAM_SUCCESS)
			goto finish;
		err = nwam_set_prop_value((*ncuhp)->nwh_data,
		    NWAM_NCU_PROP_ACTIVATION_MODE, actval);
		nwam_value_free(actval);
	}

finish:
	nwam_value_free(typeval);
	nwam_value_free(classval);
	nwam_value_free(parentval);
	nwam_value_free(enabledval);
	if (err != NWAM_SUCCESS) {
		nwam_ncu_free(*ncuhp);
		*ncuhp = NULL;
	}
	return (err);
}

nwam_error_t
nwam_ncu_read(nwam_ncp_handle_t ncph, const char *name,
    nwam_ncu_type_t type, uint64_t flags, nwam_ncu_handle_t *ncuhp)
{
	char *ncpfile, *typedname;
	nwam_error_t err, err_ip, err_link;
	nwam_ncu_handle_t ncuh_ip, ncuh_link;

	assert(ncph != NULL && name != NULL && ncuhp != NULL);

	if ((err = nwam_ncp_name_to_file(ncph->nwh_name, &ncpfile))
	    != NWAM_SUCCESS)
		return (err);

	if (type == NWAM_NCU_TYPE_ANY) {

		free(ncpfile);

		/*
		 * If we get to this point, we have discovered that no
		 * NCU type is discernable from name or type arguments.
		 * Either exactly one NCU called name must exist of either
		 * type, or the operation should fail.
		 */
		err_ip = nwam_ncu_read(ncph, name, NWAM_NCU_TYPE_INTERFACE,
		    flags, &ncuh_ip);
		err_link = nwam_ncu_read(ncph, name, NWAM_NCU_TYPE_LINK,
		    flags, &ncuh_link);

		*ncuhp = NULL;

		if (err_ip == NWAM_SUCCESS && err_link == NWAM_SUCCESS) {
			nwam_ncu_free(ncuh_ip);
			nwam_ncu_free(ncuh_link);
			err = NWAM_ENTITY_MULTIPLE_VALUES;
		} else if (err_ip != NWAM_SUCCESS && err_link != NWAM_SUCCESS) {
			err = NWAM_ENTITY_NOT_FOUND;
		} else {
			if (err_ip == NWAM_SUCCESS) {
				*ncuhp = ncuh_ip;
			} else {
				*ncuhp = ncuh_link;
			}
			err = NWAM_SUCCESS;
		}

		return (err);
	}
	if ((err = nwam_ncu_name_to_typed_name(name, type, &typedname)) !=
	    NWAM_SUCCESS) {
		free(ncpfile);
		return (err);
	}
	err = nwam_read(NWAM_OBJECT_TYPE_NCU, ncpfile, typedname, flags, ncuhp);

	free(typedname);
	free(ncpfile);

	return (err);
}

nwam_error_t
nwam_ncu_get_name(nwam_ncu_handle_t ncuh, char **namep)
{
	nwam_ncu_type_t type;

	assert(ncuh != NULL && namep != NULL);

	return (nwam_ncu_internal_name_to_name(ncuh->nwh_name, &type, namep));
}

nwam_error_t
nwam_ncu_name_to_typed_name(const char *name, nwam_ncu_type_t type,
    char **typednamep)
{
	char *prefixstr;
	size_t typednamesz;

	assert(name != NULL && typednamep != NULL);

	switch (type) {
	case NWAM_NCU_TYPE_INTERFACE:
		prefixstr = NWAM_NCU_INTERFACE_NAME_PRE;
		break;
	case NWAM_NCU_TYPE_LINK:
		prefixstr = NWAM_NCU_LINK_NAME_PRE;
		break;
	default:
		return (NWAM_INVALID_ARG);
	}
	typednamesz = strlen(name) + strlen(prefixstr) + 1;
	if ((*typednamep = malloc(typednamesz)) == NULL)
		return (NWAM_NO_MEMORY);

	/* Name may be already qualified by type */
	if (strncasecmp(prefixstr, name, strlen(prefixstr)) == 0) {
		(void) snprintf(*typednamep, typednamesz, "%s", name);
	} else {
		(void) snprintf(*typednamep, typednamesz, "%s%s",
		    prefixstr, name);
	}

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_ncu_typed_name_to_name(const char *typed_name, nwam_ncu_type_t *typep,
    char **name)
{
	return (nwam_ncu_internal_name_to_name(typed_name, typep, name));
}

void
nwam_ncu_free(nwam_ncu_handle_t ncuh)
{
	nwam_free(ncuh);
}

nwam_error_t
nwam_ncu_copy(nwam_ncu_handle_t oldncuh, const char *newname,
    nwam_ncu_handle_t *newncuhp)
{
	nwam_ncp_handle_t ncph;
	nwam_ncu_handle_t ncuh;
	nwam_error_t err;
	nwam_value_t typeval;
	uint64_t type;
	char *typednewname;

	assert(oldncuh != NULL && newname != NULL && newncuhp != NULL);

	if (nwam_ncu_get_prop_value(oldncuh, NWAM_NCU_PROP_TYPE,
	    &typeval) != NWAM_SUCCESS) {
		return (NWAM_INVALID_ARG);
	}
	if (nwam_value_get_uint64(typeval, &type) != NWAM_SUCCESS) {
		nwam_value_free(typeval);
		return (NWAM_INVALID_ARG);
	}
	nwam_value_free(typeval);

	/* check if newname NCU already exists */
	if ((err = nwam_ncu_get_ncp(oldncuh, &ncph)) != NWAM_SUCCESS)
		return (err);
	if (nwam_ncu_read(ncph, newname, type, 0, &ncuh) == NWAM_SUCCESS) {
		nwam_ncu_free(ncuh);
		nwam_ncp_free(ncph);
		return (NWAM_ENTITY_EXISTS);
	}
	nwam_ncp_free(ncph);

	if ((err = nwam_ncu_name_to_typed_name(newname, type, &typednewname))
	    != NWAM_SUCCESS)
		return (err);

	err = nwam_handle_create(NWAM_OBJECT_TYPE_NCU, typednewname, newncuhp);
	free(typednewname);
	if (err != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_dup_object_list(oldncuh->nwh_data,
	    &((*newncuhp)->nwh_data))) != NWAM_SUCCESS) {
		free(*newncuhp);
		*newncuhp = NULL;
		return (err);
	}

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_ncu_delete_prop(nwam_ncu_handle_t ncuh, const char *propname)
{
	boolean_t ro_ncu, ro_prop;
	nwam_error_t err;
	void *olddata;

	assert(ncuh != NULL && propname != NULL);

	if ((err = nwam_ncu_get_read_only(ncuh, &ro_ncu)) != NWAM_SUCCESS ||
	    (err = nwam_ncu_prop_read_only(propname, &ro_prop)) != NWAM_SUCCESS)
		return (err);
	if (ro_ncu || ro_prop)
		return (NWAM_ENTITY_READ_ONLY);

	/*
	 * Duplicate data, remove property and validate. If validation
	 * fails, revert to data duplicated prior to remove.
	 */
	if ((err = nwam_dup_object_list(ncuh->nwh_data, &olddata))
	    != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_delete_prop(ncuh->nwh_data, propname))
	    != NWAM_SUCCESS) {
		nwam_free_object_list(ncuh->nwh_data);
		ncuh->nwh_data = olddata;
		return (err);
	}
	if ((err = nwam_ncu_validate(ncuh, NULL)) != NWAM_SUCCESS) {
		nwam_free_object_list(ncuh->nwh_data);
		ncuh->nwh_data = olddata;
		return (err);
	}
	nwam_free_object_list(olddata);

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_ncu_set_prop_value(nwam_ncu_handle_t ncuh, const char *propname,
    nwam_value_t value)
{
	boolean_t ro_ncu, ro_prop;
	nwam_error_t err;
	nwam_ncp_handle_t ncph;

	assert(ncuh != NULL && propname != NULL && value != NULL);

	if ((err = nwam_ncu_get_read_only(ncuh, &ro_ncu)) != NWAM_SUCCESS ||
	    (err = nwam_ncu_prop_read_only(propname, &ro_prop)) != NWAM_SUCCESS)
		return (err);
	if (ro_ncu || ro_prop)
		return (NWAM_ENTITY_READ_ONLY);

	err = nwam_ncu_get_ncp(ncuh, &ncph);
	if (err != NWAM_SUCCESS && err != NWAM_INVALID_ARG) {
		/*
		 * If "parent" property doesn't exist, NWAM_INVALID_ARG
		 * is returned.  Allow the setting to continue.
		 */
		return (err);
	}
	nwam_ncp_free(ncph);

	/* Need to ensure property, type and value are valid */
	if ((err = nwam_ncu_validate_prop(ncuh, propname, value))
	    != NWAM_SUCCESS)
		return (err);

	return (nwam_set_prop_value(ncuh->nwh_data, propname, value));
}

nwam_error_t
nwam_ncu_get_prop_value(nwam_ncu_handle_t ncuh, const char *propname,
    nwam_value_t *valuep)
{
	assert(ncuh != NULL && propname != NULL && valuep != NULL);

	return (nwam_get_prop_value(ncuh->nwh_data, propname, valuep));
}

nwam_error_t
nwam_ncu_walk_props(nwam_ncu_handle_t ncuh,
    int (*cb)(const char *, nwam_value_t, void *),
    void *data, uint64_t flags, int *retp)
{
	return (nwam_walk_props(ncuh, cb, data, flags, retp));
}

nwam_error_t
nwam_ncu_get_ncp(nwam_ncu_handle_t ncuh, nwam_ncp_handle_t *ncphp)
{
	nwam_error_t err;
	char *parentname = NULL;

	if ((err = nwam_ncu_get_parent_ncp_name(ncuh, &parentname))
	    != NWAM_SUCCESS ||
	    (err = nwam_handle_create(NWAM_OBJECT_TYPE_NCP, parentname, ncphp))
	    != NWAM_SUCCESS) {
		if (parentname != NULL)
			free(parentname);
		return (err);
	}
	free(parentname);

	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_ncu_commit(nwam_ncu_handle_t ncuh, uint64_t flags)
{
	nwam_error_t err;
	boolean_t read_only;
	char *ncpfile, *ncpname;

	assert(ncuh != NULL && ncuh->nwh_data != NULL);

	if ((err = nwam_ncu_get_read_only(ncuh, &read_only)) != NWAM_SUCCESS)
		return (err);
	if (read_only)
		return (NWAM_ENTITY_READ_ONLY);

	if ((err = nwam_ncu_validate(ncuh, NULL)) != NWAM_SUCCESS ||
	    (err = nwam_ncu_get_parent_ncp_name(ncuh, &ncpname))
	    != NWAM_SUCCESS)
		return (err);

	if ((err = nwam_ncp_name_to_file(ncpname, &ncpfile)) != NWAM_SUCCESS) {
		free(ncpname);
		return (err);
	}

	err = nwam_commit(ncpfile, ncuh, flags);

	free(ncpname);
	free(ncpfile);

	return (err);
}
/* Get the NCU type */
nwam_error_t
nwam_ncu_get_ncu_type(nwam_ncu_handle_t ncuh, nwam_ncu_type_t *typep)
{
	nwam_error_t err;
	nwam_value_t typeval;
	uint64_t type;

	if ((err = nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_TYPE, &typeval))
	    != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_uint64(typeval, &type);
	nwam_value_free(typeval);
	if (err != NWAM_SUCCESS)
		return (err);

	*typep = type;
	return (NWAM_SUCCESS);
}

/* Get the NCU class */
nwam_error_t
nwam_ncu_get_ncu_class(nwam_ncu_handle_t ncuh, nwam_ncu_class_t *classp)
{
	nwam_error_t err;
	nwam_value_t classval;
	uint64_t class;

	if ((err = nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_CLASS,
	    &classval)) != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_uint64(classval, &class);
	nwam_value_free(classval);
	if (err != NWAM_SUCCESS)
		return (err);

	*classp = class;
	return (NWAM_SUCCESS);
}

/*
 * Determine if the NCU has manual activation-mode or not.
 */
nwam_error_t
nwam_ncu_is_manual(nwam_ncu_handle_t ncuh, boolean_t *manualp)
{
	nwam_error_t err;
	nwam_value_t actval;
	uint64_t activation;

	assert(ncuh != NULL);

	if ((err = nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_ACTIVATION_MODE,
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

/* Determine if NCU is enabled or not */
static nwam_error_t
nwam_ncu_is_enabled(nwam_ncu_handle_t ncuh, boolean_t *enabledp)
{
	nwam_error_t err;
	nwam_value_t enabledval;

	assert(ncuh != NULL);

	if ((err = nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_ENABLED,
	    &enabledval)) != NWAM_SUCCESS)
		return (err);
	err = nwam_value_get_boolean(enabledval, enabledp);
	nwam_value_free(enabledval);
	return (err);
}

/* Update the enabled property */
static nwam_error_t
nwam_ncu_update_enabled(nwam_ncu_handle_t ncuh, boolean_t enabled)
{
	nwam_error_t err;
	nwam_value_t enabledval;

	if ((err = nwam_value_create_boolean(enabled, &enabledval))
	    != NWAM_SUCCESS)
		return (err);
	err = nwam_set_prop_value(ncuh->nwh_data, NWAM_NCU_PROP_ENABLED,
	    enabledval);
	nwam_value_free(enabledval);
	if (err != NWAM_SUCCESS)
		return (err);
	return (nwam_ncu_commit(ncuh, NWAM_FLAG_ENTITY_ENABLE));
}

/*
 * Make ncu active; fails if the NCU's parent NCP is not active.
 */
nwam_error_t
nwam_ncu_enable(nwam_ncu_handle_t ncuh)
{
	char *ncpname = NULL;
	nwam_error_t err;
	nwam_ncu_type_t type;
	boolean_t read_only, enabled, manual;

	assert(ncuh != NULL);

	/* Don't allow NCUs of Automatic NCP to be enabled */
	if ((err = nwam_ncu_get_read_only(ncuh, &read_only)) != NWAM_SUCCESS)
		return (err);
	if (read_only)
		return (NWAM_ENTITY_NOT_MANUAL);

	/* Link NCUs with manual activation-mode or IP NCUs can be enabled */
	if ((err = nwam_ncu_get_ncu_type(ncuh, &type)) != NWAM_SUCCESS)
		return (err);

	if (type == NWAM_NCU_TYPE_LINK) {
		if ((err = nwam_ncu_is_manual(ncuh, &manual)) != NWAM_SUCCESS)
			return (err);
		if (!manual)
			return (NWAM_ENTITY_NOT_MANUAL);
	}

	/* Make sure NCU is not enabled */
	if ((err = nwam_ncu_is_enabled(ncuh, &enabled)) != NWAM_SUCCESS ||
	    (err = nwam_ncu_get_parent_ncp_name(ncuh, &ncpname))
	    != NWAM_SUCCESS)
		return (err);

	if (enabled) {
		free(ncpname);
		return (NWAM_SUCCESS);
	}

	if ((err = nwam_ncu_update_enabled(ncuh, B_TRUE)) != NWAM_SUCCESS) {
		free(ncpname);
		return (err);
	}

	err = nwam_enable(ncpname, ncuh);
	free(ncpname);

	/* nwamd may not be running, that's okay. */
	if (err == NWAM_ERROR_BIND)
		return (NWAM_SUCCESS);
	else
		return (err);
}

/*
 * Disable ncu; fails if the NCU's parent NCP is not active, or if the
 * NCU is not currently active.
 */
nwam_error_t
nwam_ncu_disable(nwam_ncu_handle_t ncuh)
{
	char *ncpname = NULL;
	nwam_error_t err;
	nwam_ncu_type_t type;
	boolean_t read_only, enabled, manual;

	assert(ncuh != NULL);

	/* Don't allow NCUs of Automatic NCP to be disabled */
	if ((err = nwam_ncu_get_read_only(ncuh, &read_only)) != NWAM_SUCCESS)
		return (err);
	if (read_only)
		return (NWAM_ENTITY_NOT_MANUAL);

	/* Link NCUs with manual activation-mode or IP NCUs can be disabled */
	if ((err = nwam_ncu_get_ncu_type(ncuh, &type)) != NWAM_SUCCESS)
		return (err);

	if (type == NWAM_NCU_TYPE_LINK) {
		if ((err = nwam_ncu_is_manual(ncuh, &manual)) != NWAM_SUCCESS)
			return (err);
		if (!manual)
			return (NWAM_ENTITY_NOT_MANUAL);
	}

	/* Make sure NCU is enabled */
	if ((err = nwam_ncu_is_enabled(ncuh, &enabled)) != NWAM_SUCCESS ||
	    (err = nwam_ncu_get_parent_ncp_name(ncuh, &ncpname))
	    != NWAM_SUCCESS)
		return (err);

	if (!enabled) {
		free(ncpname);
		return (NWAM_SUCCESS);
	}

	if ((err = nwam_ncu_update_enabled(ncuh, B_FALSE)) != NWAM_SUCCESS) {
		free(ncpname);
		return (err);
	}

	err = nwam_disable(ncpname, ncuh);
	free(ncpname);

	/* nwamd may not be running, that's okay. */
	if (err == NWAM_ERROR_BIND)
		return (NWAM_SUCCESS);
	else
		return (err);
}

nwam_error_t
nwam_ncu_destroy(nwam_ncu_handle_t ncuh, uint64_t flags)
{
	char *ncpname, *ncpfile;
	boolean_t read_only;
	nwam_error_t err;

	assert(ncuh != NULL);

	if ((err = nwam_ncu_get_read_only(ncuh, &read_only)) != NWAM_SUCCESS)
		return (err);
	if (read_only)
		return (NWAM_ENTITY_NOT_DESTROYABLE);

	if ((err = nwam_ncu_get_parent_ncp_name(ncuh, &ncpname))
	    != NWAM_SUCCESS)
		return (err);
	if ((err = nwam_ncp_name_to_file(ncpname, &ncpfile))
	    != NWAM_SUCCESS) {
		free(ncpname);
		return (err);
	}

	err = nwam_destroy(ncpfile, ncuh, flags);

	free(ncpname);
	free(ncpfile);

	return (err);
}

nwam_error_t
nwam_ncu_get_prop_description(const char *propname, const char **descriptionp)
{
	return (nwam_get_prop_description(ncu_prop_table, propname,
	    descriptionp));
}

/* Get expected property data type */
nwam_error_t
nwam_ncu_get_prop_type(const char *propname, nwam_value_type_t *typep)
{
	return (nwam_get_prop_type(ncu_prop_table, propname, typep));
}

nwam_error_t
nwam_ncu_prop_read_only(const char *propname, boolean_t *readp)
{
	if ((*readp = NWAM_NCU_PROP_SETONCE(propname)) == B_TRUE)
		return (NWAM_SUCCESS);

	return (nwam_prop_read_only(ncu_prop_table, propname, readp));
}

nwam_error_t
nwam_ncu_prop_multivalued(const char *propname, boolean_t *multip)
{
	return (nwam_prop_multivalued(ncu_prop_table, propname, multip));
}

/*
 * Ensure that the properties in the ncu, determined by that ncu's
 * type and class, belong there.
 */
static nwam_error_t
nwam_ncu_validate_prop_membership(nwam_ncu_handle_t ncuh, const char *propname)
{
	struct nwam_prop_table_entry *pte;
	nwam_value_t typeval, classval;
	uint64_t type, class;
	uint64_t typeflags = 0, classflags = 0;

	/* Get type/class from ncu */
	if (nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_TYPE, &typeval)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID);
	if (nwam_value_get_uint64(typeval, &type) != NWAM_SUCCESS) {
		nwam_value_free(typeval);
		return (NWAM_ENTITY_INVALID);
	}
	typeflags = nwam_ncu_type_to_flag((nwam_ncu_type_t)type);
	nwam_value_free(typeval);

	if (nwam_ncu_get_prop_value(ncuh, NWAM_NCU_PROP_CLASS, &classval)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID);
	if (nwam_value_get_uint64(classval, &class) != NWAM_SUCCESS) {
		nwam_value_free(classval);
		return (NWAM_ENTITY_INVALID);
	}
	classflags = nwam_ncu_class_to_flag((nwam_ncu_class_t)class);
	nwam_value_free(classval);

	if ((pte = nwam_get_prop_table_entry(ncu_prop_table, propname)) == NULL)
		return (NWAM_INVALID_ARG);

	if (typeflags & pte->prop_type_membership &&
	    classflags & pte->prop_class_membership) {
		return (NWAM_SUCCESS);
	} else {
		return (NWAM_ENTITY_INVALID_MEMBER);
	}
}

/* Validate property's ncu membership and type, number and range of values */
nwam_error_t
nwam_ncu_validate_prop(nwam_ncu_handle_t ncuh, const char *propname,
    nwam_value_t value)
{
	nwam_error_t err;

	assert(ncuh != NULL && propname != NULL);

	/* First, determine if this property is valid for this ncu */
	if ((err = nwam_ncu_validate_prop_membership(ncuh, propname))
	    != NWAM_SUCCESS)
		return (err);

	return (nwam_validate_prop(ncu_prop_table, ncuh, propname, value));
}

/* Property-specific value validation functions follow */

static nwam_error_t
valid_type(nwam_value_t value)
{
	uint64_t type;

	if (nwam_value_get_uint64(value, &type) != NWAM_SUCCESS ||
	    type > NWAM_NCU_TYPE_INTERFACE)
		return (NWAM_ENTITY_INVALID_VALUE);
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_class(nwam_value_t value)
{
	uint64_t class;

	if (nwam_value_get_uint64(value, &class) != NWAM_SUCCESS ||
	    class > NWAM_NCU_CLASS_IP)
		return (NWAM_ENTITY_INVALID_VALUE);
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_ncp(nwam_value_t value)
{
	char *ncp;

	if (nwam_value_get_string(value, &ncp) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_priority_mode(nwam_value_t value)
{
	uint64_t priority_mode;

	if (nwam_value_get_uint64(value, &priority_mode) != NWAM_SUCCESS ||
	    priority_mode > NWAM_PRIORITY_MODE_ALL)
		return (NWAM_ENTITY_INVALID_VALUE);
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_ncu_activation_mode(nwam_value_t value)
{
	uint64_t activation_mode;

	if (nwam_value_get_uint64(value, &activation_mode) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	switch (activation_mode) {
	case NWAM_ACTIVATION_MODE_MANUAL:
	case NWAM_ACTIVATION_MODE_PRIORITIZED:
		return (NWAM_SUCCESS);
	}
	return (NWAM_ENTITY_INVALID_VALUE);
}

/* ARGSUSED0 */
static nwam_error_t
valid_link_autopush(nwam_value_t value)
{
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_ip_version(nwam_value_t value)
{
	uint64_t *versions;
	uint_t i, numvalues;

	if (nwam_value_get_uint64_array(value, &versions, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		if (versions[i] != IPV4_VERSION &&
		    versions[i] != IPV6_VERSION)
		return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_addrsrc_v4(nwam_value_t value)
{
	uint64_t *addrsrc;
	uint_t i, numvalues;

	if (nwam_value_get_uint64_array(value, &addrsrc, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		if (addrsrc[i] != NWAM_ADDRSRC_DHCP &&
		    addrsrc[i] != NWAM_ADDRSRC_STATIC)
			return (NWAM_ENTITY_INVALID_VALUE);
	}
	return (NWAM_SUCCESS);
}

static nwam_error_t
valid_addrsrc_v6(nwam_value_t value)
{
	uint64_t *addrsrc;
	uint_t i, numvalues;
	boolean_t dhcp_found = B_FALSE, autoconf_found = B_FALSE;

	if (nwam_value_get_uint64_array(value, &addrsrc, &numvalues)
	    != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);

	for (i = 0; i < numvalues; i++) {
		if (addrsrc[i] != NWAM_ADDRSRC_DHCP &&
		    addrsrc[i] != NWAM_ADDRSRC_STATIC &&
		    addrsrc[i] != NWAM_ADDRSRC_AUTOCONF)
			return (NWAM_ENTITY_INVALID_VALUE);
		if (addrsrc[i] == NWAM_ADDRSRC_DHCP)
			dhcp_found = B_TRUE;
		if (addrsrc[i] == NWAM_ADDRSRC_AUTOCONF)
			autoconf_found = B_TRUE;
	}
	/*
	 * DHCP and AUTOCONF need to be specified as v6 address sources
	 * since there is no way to switch them off in NWAM at present.
	 */
	if (dhcp_found && autoconf_found)
		return (NWAM_SUCCESS);
	else
		return (NWAM_ENTITY_INVALID_VALUE);
}

static nwam_error_t
valid_reqhost(nwam_value_t value)
{
	char *hostname;

	if (nwam_value_get_string(value, &hostname) != NWAM_SUCCESS)
		return (NWAM_ENTITY_INVALID_VALUE);
	return (ipadm_is_valid_hostname(hostname) ? NWAM_SUCCESS
	    : NWAM_ENTITY_INVALID_VALUE);
}

/* ARGSUSED0 */
static nwam_error_t
valid_link_mtu(nwam_value_t value)
{
	return (NWAM_SUCCESS);
}

nwam_error_t
nwam_ncu_validate(nwam_ncu_handle_t ncuh, const char **errpropp)
{
	return (nwam_validate(ncu_prop_table, ncuh, errpropp));
}

/*
 * Given the ncu type and ncu class, return the list of properties that needs
 * to be set. Note this list is a complete property list that includes both
 * the required ones and the optional ones. Caller needs to free prop_list.
 */
nwam_error_t
nwam_ncu_get_default_proplist(nwam_ncu_type_t type, nwam_ncu_class_t class,
    const char ***prop_list, uint_t *numvalues)
{
	uint64_t typeflags = nwam_ncu_type_to_flag(type);
	uint64_t classflags = nwam_ncu_class_to_flag(class);

	return (nwam_get_default_proplist(ncu_prop_table, typeflags,
	    classflags, prop_list, numvalues));
}

nwam_error_t
nwam_ncp_get_state(nwam_ncp_handle_t ncph, nwam_state_t *statep,
    nwam_aux_state_t *auxp)
{
	return (nwam_get_state(ncph->nwh_name, ncph, statep, auxp));
}

nwam_error_t
nwam_ncu_get_state(nwam_ncu_handle_t ncuh, nwam_state_t *statep,
    nwam_aux_state_t *auxp)
{
	nwam_ncp_handle_t ncph;
	char *ncpname;
	nwam_error_t err;

	assert(ncuh != NULL);

	if ((err = nwam_ncu_get_ncp(ncuh, &ncph)) != NWAM_SUCCESS)
		return (err);
	if (!nwam_ncp_is_active(ncph)) {
		nwam_ncp_free(ncph);
		return (NWAM_ENTITY_INVALID);
	}
	nwam_ncp_free(ncph);

	if ((err = nwam_ncu_get_parent_ncp_name(ncuh, &ncpname))
	    != NWAM_SUCCESS)
		return (err);

	err = nwam_request_state(NWAM_OBJECT_TYPE_NCU, ncuh->nwh_name, ncpname,
	    statep, auxp);
	free(ncpname);
	return (err);
}

nwam_error_t
nwam_ncp_get_active_priority_group(int64_t *priorityp)
{
	return (nwam_request_active_priority_group(priorityp));
}
