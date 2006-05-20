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

/*
 * Block comment that describes the contents of this file.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <link.h>
#include <assert.h>
#include <pthread.h>

#include "util.h"
#include "sfx4500-disk.h"
#include "plugin_mgr.h"

static dm_plugin_t *plugin_list = NULL;
static pthread_mutex_t plugin_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static dm_plugin_action_handle_impl_t *handle_list = NULL;
static pthread_mutex_t handle_list_mutex = PTHREAD_MUTEX_INITIALIZER;

static boolean_t
safe_protocol_string(const char *protocol)
{
	while (*protocol != 0) {

		if (!isalnum(*protocol))
			return (B_FALSE);

		protocol++;
	}
	return (B_TRUE);
}

/*
 * Initialize the plugin.
 * Returns DMPE_SUCCESS if the _init entry point of the plugin
 * executed successfully, otherwise returns DMPE_FAILURE.
 */
static dm_plugin_error_t
init_dm_plugin(dm_plugin_t *dmpip)
{
	dm_plugin_error_t ec;

	if (dmpip->state != DMPS_INITED && dmpip->ops->_init) {
		if ((ec = dmpip->ops->_init()) == DMPE_SUCCESS) {
			dmpip->state = DMPS_INITED;
		} else {
			log_warn("_init failed for %s plugin; unloading it\n",
			    dmpip->protocol);
		}
	} else if (dmpip->ops->_init == NULL)	/* No _init, no problem */
		dmpip->state = DMPS_INITED;

	return (ec);
}

static dm_plugin_t *
new_dm_plugin(const char *protocol)
{
	dm_plugin_t *newpi = (dm_plugin_t *)dmalloc(sizeof (dm_plugin_t));

	newpi->protocol = dstrdup(protocol);
	newpi->state = DMPS_NONE;
	newpi->ops = NULL;
	newpi->next = NULL;

	return (newpi);
}

static void
unload_dm_plugin(dm_plugin_t *pluginp)
{
	pluginp->ops = NULL;
}

static void
free_dm_plugin(dm_plugin_t **dmpipp)
{
	dm_plugin_t *dmpip = *dmpipp;
	dm_plugin_error_t ec;

	if (dmpip) {
		if (dmpip->state == DMPS_INITED && dmpip->ops->_fini) {
			ec = dmpip->ops->_fini();
			if (ec != DMPE_SUCCESS) {
				log_warn("_fini failed for plugin %s.\n",
				    dmpip->protocol);
			}
		}

		unload_dm_plugin(dmpip);

		if (dmpip->protocol)
			dstrfree(dmpip->protocol);

		dmpip->state = DMPS_NONE;
		dmpip->ops = NULL;

		dfree(dmpip, sizeof (dm_plugin_t));
		*dmpipp = NULL;
	}
}

static boolean_t
do_load_dm_plugin(dm_plugin_t *dmpip)
{
	boolean_t plugin_loaded = B_FALSE;
	int len;
	char *buf;

	len = strlen(dmpip->protocol) + strlen(DM_PLUGIN_OPS_NAME) + 2;
	buf = (char *)dmalloc(len);

	/*
	 * Currently, plugins are baked into the module, and the name of the
	 * ops structure is formed by concatenating the plugin's protocol
	 * with a static string:
	 */

	(void) snprintf(buf, len, "%s_%s", dmpip->protocol,
	    DM_PLUGIN_OPS_NAME);

	dmpip->ops = (dm_plugin_ops_t *)dlsym(RTLD_SELF, buf);

	if (dmpip->ops != NULL) {
		if (dmpip->ops->version > DM_PLUGIN_VERSION) {
			log_warn("Plugin error: cannot handle "
			    "plugin %s with version %d.\n",
			    dmpip->protocol, dmpip->ops->version);
		} else
			plugin_loaded = B_TRUE;
	} else {
		log_warn("Plugin error: dlsym(%s) = NULL\n",
		    buf);
		unload_dm_plugin(dmpip);
	}

	dfree(buf, len);
	return (plugin_loaded);
}

static dm_plugin_t *
load_dm_plugin(const char *protocol)
{
	dm_plugin_t *dmpip = NULL;
	boolean_t plugin_loaded = B_FALSE;

	/*
	 * Validate the protocol string -- if there are any non-alphanumeric
	 * characters, it's not a valid protocol string.
	 */
	if (safe_protocol_string(protocol) == B_FALSE) {
		log_warn("Invalid characters in plugin protocol `%s'.\n",
		    protocol);
		goto fpi_out;
	}

	dmpip = new_dm_plugin(protocol);

	plugin_loaded = do_load_dm_plugin(dmpip);

fpi_out:
	if (plugin_loaded) {
		assert(dmpip != NULL);
		dmpip->state = DMPS_LOADED;
	} else if (!plugin_loaded && dmpip != NULL)
		free_dm_plugin(&dmpip);

	return (dmpip);
}

static char *
extract_protocol(const char *action)
{
	char *s = strchr(action, PROTOCOL_SEPARATOR);
	char *proto = NULL;
	int len;
	int i = 0;

	/* The protocol is the string before the separator, but in lower-case */
	if (s) {
		len = (uintptr_t)s - (uintptr_t)action;
		proto = (char *)dmalloc(len + 1);
		while (i < len) {
			proto[i] = tolower(action[i]);
			i++;
		}
		proto[len] = 0;
	}

	return (proto);
}

static char *
extract_action(const char *action)
{
	/* The action is the string after the separator */
	char *s = strchr(action, PROTOCOL_SEPARATOR);

	return (s ? (s + 1) : NULL);
}

static dm_plugin_t *
load_and_init_dm_plugin(const char *protocol)
{
	dm_plugin_t *plugin = load_dm_plugin(protocol);

	if (plugin) {
		/* If _init succeeded, add the plugin to the list */
		if (init_dm_plugin(plugin) == DMPE_SUCCESS) {
			plugin->next = plugin_list;
			plugin_list = plugin;
		} else {
			/* Otherwise, free it. */
			free_dm_plugin(&plugin);
		}
	} else {
		log_warn("Could not load `%s' plugin!\n",
		    protocol);
	}

	return (plugin);
}

static dm_plugin_t *
protocol_to_dm_plugin(const char *protocol)
{
	dm_plugin_t *plugin;

	/*
	 * Traversing the plugin list must be atomic with
	 * respect to plugin loads
	 */
	assert(pthread_mutex_lock(&plugin_list_mutex) == 0);

	plugin = plugin_list;

	while (plugin != NULL) {
		if (strcmp(plugin->protocol, protocol) == 0) {
			break;
		}

		plugin = plugin->next;
	}

	/* Wasn't found -- load, initialize, and return it */
	plugin = (plugin == NULL) ? load_and_init_dm_plugin(protocol) :
	    plugin;

	assert(pthread_mutex_unlock(&plugin_list_mutex) == 0);

	return (plugin);
}

static dm_plugin_action_handle_impl_t *
new_action_handle(const char *action, dm_plugin_t *pluginp)
{
	dm_plugin_action_handle_impl_t *hip;

	hip = (dm_plugin_action_handle_impl_t *)dmalloc(
	    sizeof (dm_plugin_action_handle_impl_t));

	hip->actionString = dstrdup(action);
	hip->plugin = pluginp;
	hip->handle = (dm_plugin_action_handle_t)NULL;

	/* Add the handle to the global list */
	assert(pthread_mutex_lock(&handle_list_mutex) == 0);
	hip->next = handle_list;
	handle_list = hip;
	assert(pthread_mutex_unlock(&handle_list_mutex) == 0);

	return (hip);
}

static void
free_action_handle(dm_plugin_action_handle_impl_t **hipp)
{
	dm_plugin_action_handle_impl_t *hip = *hipp;
	dm_plugin_t *dmpip;

	if (hip) {
		if (hip->actionString)
			dstrfree(hip->actionString);

		dmpip = hip->plugin;

		if (dmpip->state == DMPS_INITED &&
		    dmpip->ops->indicator_free_handle)
			if (dmpip->ops->indicator_free_handle(&hip->handle)
			    != DMPE_SUCCESS) {
				log_warn("indicator_free_handle failed for %s"
				    " plugin\n",
				    dmpip->protocol);
			}

		dfree(hip, sizeof (dm_plugin_action_handle_impl_t));
		*hipp = NULL;
	}
}

static dm_plugin_action_handle_impl_t *
lookup_handle_by_action(const char *action)
{
	dm_plugin_action_handle_impl_t *handle;

	assert(pthread_mutex_lock(&handle_list_mutex) == 0);

	handle = handle_list;

	while (handle != NULL) {
		if (strcmp(handle->actionString, action) == 0)
			break;

		handle = handle->next;
	}

	assert(pthread_mutex_unlock(&handle_list_mutex) == 0);

	return (handle);
}

int
init_plugin_manager(void)
{
	return (0);
}

void
cleanup_plugin_manager(void)
{
	dm_plugin_t *next_plugin;
	dm_plugin_action_handle_impl_t *next_handle;

	while (handle_list != NULL) {
		next_handle = handle_list->next;

		free_action_handle(&handle_list);

		handle_list = next_handle;
	}

	while (plugin_list != NULL) {

		next_plugin = plugin_list->next;

		free_dm_plugin(&plugin_list);

		plugin_list = next_plugin;
	}
}

static dm_plugin_error_t
bind_action_handle(dm_plugin_t *dmpip, const char *action,
    dm_plugin_action_handle_t *hdlp)
{
	dm_plugin_action_handle_impl_t *hip;

	hip = new_action_handle(action, dmpip);
	*hdlp = hip;

	assert(dmpip->state == DMPS_INITED);
	if (dmpip->ops->indicator_bind_handle)
		return (dmpip->ops->indicator_bind_handle(action,
		    &hip->handle));

	return (DMPE_FAILURE);
}

dm_plugin_error_t
dm_pm_update_fru(const char *action, dm_fru_t *frup)
{
	char *protocol = extract_protocol(action);	/* mem alloced here */
	char *actionp = extract_action(action);
	dm_plugin_t *dmpip;

	if (protocol == NULL) {
		log_warn("FRU update: Invalid protocol specified in action "
		    "`%s'\n", action);
		return (DMPE_FAILURE);
	}

	dmpip = protocol_to_dm_plugin(protocol);
	dstrfree(protocol);

	if (dmpip != NULL) {
		assert(dmpip->state == DMPS_INITED);
		if (dmpip->ops->indicator_fru_update)
			return (dmpip->ops->indicator_fru_update(actionp,
			    frup));
	}

	return (DMPE_FAILURE);
}

dm_plugin_error_t
dm_pm_indicator_execute(const char *action)
{
	dm_plugin_t *dmpip;
	char *protocol = extract_protocol(action); /* memory allocated here */
	char *actionp = extract_action(action);
	dm_plugin_action_handle_impl_t *hip;

	dmpip = protocol_to_dm_plugin(protocol);
	dstrfree(protocol);

	if (dmpip != NULL) {

		if ((hip = lookup_handle_by_action(actionp)) == NULL) {
			if (bind_action_handle(dmpip, actionp,
			    (dm_plugin_action_handle_t *)&hip) != DMPE_SUCCESS)
				return (DMPE_FAILURE);
		}

		assert(dmpip->state == DMPS_INITED);
		if (dmpip->ops->indicator_execute)
			return (dmpip->ops->indicator_execute(hip->handle));
	}

	return (DMPE_FAILURE);
}

pthread_t
dm_plugin_thr_create(void (*fn)(void *), void *arg)
{
	return (fmd_thr_create(g_fm_hdl, fn, arg));
}

void
dm_plugin_thr_signal(pthread_t tid)
{
	fmd_thr_signal(g_fm_hdl, tid);
}

void
dm_plugin_thr_destroy(pthread_t tid)
{
	fmd_thr_destroy(g_fm_hdl, tid);
}

const char *
dm_plugin_prop_lookup(const char *propname)
{
	return (dm_prop_lookup(dm_global_proplist(), propname));
}
