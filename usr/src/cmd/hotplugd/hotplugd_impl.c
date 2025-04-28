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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <alloca.h>
#include <libnvpair.h>
#include <libhotplug.h>
#include <libhotplug_impl.h>
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi_hp.h>
#include <sys/modctl.h>
#include "hotplugd_impl.h"

/*
 * All operations affecting kernel state are serialized.
 */
static pthread_mutex_t	hotplug_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Local functions.
 */
static boolean_t	check_rcm_required(hp_node_t, int);
static int		pack_properties(const char *, ddi_hp_property_t *);
static void		unpack_properties(ddi_hp_property_t *, char **);
static void		free_properties(ddi_hp_property_t *);

/*
 * changestate()
 *
 *	Perform a state change operation.
 *
 *	NOTE: all operations are serialized, using a global lock.
 */
int
changestate(const char *path, const char *connection, int state, uint_t flags,
    int *old_statep, hp_node_t *resultsp)
{
	hp_node_t	root = NULL;
	char		**rsrcs = NULL;
	boolean_t	use_rcm = B_FALSE;
	int		rv;

	hp_dprintf("changestate(path=%s, connection=%s, state=0x%x, "
	    "flags=0x%x)\n", path, connection, state, flags);

	/* Initialize results */
	*resultsp = NULL;
	*old_statep = -1;

	(void) pthread_mutex_lock(&hotplug_lock);

	/* Get an information snapshot, without usage details */
	if ((rv = getinfo(path, connection, 0, &root)) != 0) {
		(void) pthread_mutex_unlock(&hotplug_lock);
		hp_dprintf("changestate: getinfo() failed (%s)\n",
		    strerror(rv));
		return (rv);
	}

	/* Record current state (used in hotplugd_door.c for auditing) */
	*old_statep = hp_state(root);

	/* Check if RCM interactions are required */
	use_rcm = check_rcm_required(root, state);

	/* If RCM is required, perform RCM offline */
	if (use_rcm) {

		hp_dprintf("changestate: RCM offline is required.\n");

		/* Get RCM resources */
		if ((rv = rcm_resources(root, &rsrcs)) != 0) {
			hp_dprintf("changestate: rcm_resources() failed.\n");
			(void) pthread_mutex_unlock(&hotplug_lock);
			hp_fini(root);
			return (rv);
		}

		/* Request RCM offline */
		if ((rsrcs != NULL) &&
		    ((rv = rcm_offline(rsrcs, flags, root)) != 0)) {
			hp_dprintf("changestate: rcm_offline() failed.\n");
			rcm_online(rsrcs);
			(void) pthread_mutex_unlock(&hotplug_lock);
			free_rcm_resources(rsrcs);
			*resultsp = root;
			return (rv);
		}
	}

	/* The information snapshot is no longer needed */
	hp_fini(root);

	/* Stop now if QUERY flag was specified */
	if (flags & HPQUERY) {
		hp_dprintf("changestate: operation was QUERY only.\n");
		rcm_online(rsrcs);
		(void) pthread_mutex_unlock(&hotplug_lock);
		free_rcm_resources(rsrcs);
		return (0);
	}

	/* Do state change in kernel */
	rv = 0;
	if (modctl(MODHPOPS, MODHPOPS_CHANGE_STATE, path, connection, state))
		rv = errno;
	hp_dprintf("changestate: modctl(MODHPOPS_CHANGE_STATE) = %d.\n", rv);

	/*
	 * If RCM is required, then perform an RCM online or RCM remove
	 * operation.  Which depends upon if modctl succeeded or failed.
	 */
	if (use_rcm && (rsrcs != NULL)) {

		/* RCM online if failure, or RCM remove if successful */
		if (rv == 0)
			rcm_remove(rsrcs);
		else
			rcm_online(rsrcs);

		/* RCM resources no longer required */
		free_rcm_resources(rsrcs);
	}

	(void) pthread_mutex_unlock(&hotplug_lock);

	*resultsp = NULL;
	return (rv);
}

/*
 * private_options()
 *
 *	Implement set/get of bus private options.
 */
int
private_options(const char *path, const char *connection, hp_cmd_t cmd,
    const char *options, char **resultsp)
{
	ddi_hp_property_t	prop;
	ddi_hp_property_t	results;
	char			*values = NULL;
	int			rv;

	hp_dprintf("private_options(path=%s, connection=%s, options='%s')\n",
	    path, connection, options);

	/* Initialize property arguments */
	if ((rv = pack_properties(options, &prop)) != 0) {
		hp_dprintf("private_options: failed to pack properties.\n");
		return (rv);
	}

	/* Initialize results */
	(void) memset(&results, 0, sizeof (ddi_hp_property_t));
	results.buf_size = HP_PRIVATE_BUF_SZ;
	results.nvlist_buf = (char *)calloc(1, HP_PRIVATE_BUF_SZ);
	if (results.nvlist_buf == NULL) {
		hp_dprintf("private_options: failed to allocate buffer.\n");
		free_properties(&prop);
		return (ENOMEM);
	}

	/* Lock hotplug */
	(void) pthread_mutex_lock(&hotplug_lock);

	/* Perform the command */
	rv = 0;
	if (cmd == HP_CMD_GETPRIVATE) {
		if (modctl(MODHPOPS, MODHPOPS_BUS_GET, path, connection,
		    &prop, &results))
			rv = errno;
		hp_dprintf("private_options: modctl(MODHPOPS_BUS_GET) = %d\n",
		    rv);
	} else {
		if (modctl(MODHPOPS, MODHPOPS_BUS_SET, path, connection,
		    &prop, &results))
			rv = errno;
		hp_dprintf("private_options: modctl(MODHPOPS_BUS_SET) = %d\n",
		    rv);
	}

	/* Unlock hotplug */
	(void) pthread_mutex_unlock(&hotplug_lock);

	/* Parse results */
	if (rv == 0) {
		unpack_properties(&results, &values);
		*resultsp = values;
	}

	/* Cleanup */
	free_properties(&prop);
	free_properties(&results);

	return (rv);
}

/*
 * check_rcm_required()
 *
 *	Given the root of a changestate operation and the target
 *	state, determine if RCM interactions will be required.
 */
static boolean_t
check_rcm_required(hp_node_t root, int target_state)
{
	/*
	 * RCM is required when transitioning an ENABLED
	 * connector to a non-ENABLED state.
	 */
	if ((root->hp_type == HP_NODE_CONNECTOR) &&
	    HP_IS_ENABLED(root->hp_state) && !HP_IS_ENABLED(target_state))
		return (B_TRUE);

	/*
	 * RCM is required when transitioning an OPERATIONAL
	 * port to a non-OPERATIONAL state.
	 */
	if ((root->hp_type == HP_NODE_PORT) &&
	    HP_IS_ONLINE(root->hp_state) && HP_IS_OFFLINE(target_state))
		return (B_TRUE);

	/* RCM is not required in other cases */
	return (B_FALSE);
}

/*
 * pack_properties()
 *
 *	Given a specified set/get command and an options string,
 *	construct the structure containing a packed nvlist that
 *	contains the specified options.
 */
static int
pack_properties(const char *options, ddi_hp_property_t *prop)
{
	nvlist_t	*nvl;
	char		*buf, *tmp, *name, *value, *next;
	size_t		len;

	/* Initialize results */
	(void) memset(prop, 0, sizeof (ddi_hp_property_t));

	/* Do nothing if options string is empty */
	if ((len = strlen(options)) == 0) {
		hp_dprintf("pack_properties: options string is empty.\n");
		return (ENOENT);
	}

	/* Avoid modifying the input string by using a copy on the stack */
	if ((tmp = (char *)alloca(len + 1)) == NULL) {
		log_err("Failed to allocate buffer for private options.\n");
		return (ENOMEM);
	}
	(void) strlcpy(tmp, options, len + 1);

	/* Allocate the nvlist */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		log_err("Failed to allocate private options nvlist.\n");
		return (ENOMEM);
	}

	/* Add each option from the string */
	for (name = tmp; name != NULL; name = next) {

		/* Isolate current name/value, and locate the next */
		if ((next = strchr(name, ',')) != NULL) {
			*next = '\0';
			next++;
		}

		/* Split current name/value pair */
		if ((value = strchr(name, '=')) != NULL) {
			*value = '\0';
			value++;
		} else {
			value = "";
		}

		/* Add the option to the nvlist */
		if (nvlist_add_string(nvl, name, value) != 0) {
			log_err("Failed to add private option to nvlist.\n");
			nvlist_free(nvl);
			return (EFAULT);
		}
	}

	/* Pack the nvlist */
	len = 0;
	buf = NULL;
	if (nvlist_pack(nvl, &buf, &len, NV_ENCODE_NATIVE, 0) != 0) {
		log_err("Failed to pack private options nvlist.\n");
		nvlist_free(nvl);
		return (EFAULT);
	}

	/* Save results */
	prop->nvlist_buf = buf;
	prop->buf_size = len;

	/* The nvlist is no longer needed */
	nvlist_free(nvl);

	return (0);
}

/*
 * unpack_properties()
 *
 *	Given a structure possibly containing a packed nvlist of
 *	bus private options, unpack the nvlist and expand its
 *	contents into an options string.
 */
static void
unpack_properties(ddi_hp_property_t *prop, char **optionsp)
{
	nvlist_t	*nvl = NULL;
	nvpair_t	*nvp;
	boolean_t	first_flag;
	char		*name, *value, *options;
	size_t		len;

	/* Initialize results */
	*optionsp = NULL;

	/* Do nothing if properties do not exist */
	if ((prop->nvlist_buf == NULL) || (prop->buf_size == 0)) {
		hp_dprintf("unpack_properties: no properties exist.\n");
		return;
	}

	/* Unpack the nvlist */
	if (nvlist_unpack(prop->nvlist_buf, prop->buf_size, &nvl, 0) != 0) {
		log_err("Failed to unpack private options nvlist.\n");
		return;
	}

	/* Compute the size of the options string */
	for (len = 0, nvp = NULL; nvp = nvlist_next_nvpair(nvl, nvp); ) {

		name = nvpair_name(nvp);

		/* Skip the command, and anything not a string */
		if ((strcmp(name, "cmd") == 0) ||
		    (nvpair_type(nvp) != DATA_TYPE_STRING))
			continue;

		(void) nvpair_value_string(nvp, &value);

		/* Account for '=' signs, commas, and terminating NULL */
		len += (strlen(name) + strlen(value) + 2);
	}

	/* Allocate the resulting options string */
	if ((options = (char *)calloc(len, sizeof (char))) == NULL) {
		log_err("Failed to allocate private options string.\n");
		nvlist_free(nvl);
		return;
	}

	/* Copy name/value pairs into the options string */
	first_flag = B_TRUE;
	for (nvp = NULL; nvp = nvlist_next_nvpair(nvl, nvp); ) {

		name = nvpair_name(nvp);

		/* Skip the command, and anything not a string */
		if ((strcmp(name, "cmd") == 0) ||
		    (nvpair_type(nvp) != DATA_TYPE_STRING))
			continue;

		if (!first_flag)
			(void) strlcat(options, ",", len);

		(void) strlcat(options, name, len);

		(void) nvpair_value_string(nvp, &value);

		if (strlen(value) > 0) {
			(void) strlcat(options, "=", len);
			(void) strlcat(options, value, len);
		}

		first_flag = B_FALSE;
	}

	/* The unpacked nvlist is no longer needed */
	nvlist_free(nvl);

	/* Save results */
	*optionsp = options;
}

/*
 * free_properties()
 *
 *	Destroy a structure containing a packed nvlist of bus
 *	private properties.
 */
static void
free_properties(ddi_hp_property_t *prop)
{
	if (prop) {
		if (prop->nvlist_buf)
			free(prop->nvlist_buf);
		(void) memset(prop, 0, sizeof (ddi_hp_property_t));
	}
}
