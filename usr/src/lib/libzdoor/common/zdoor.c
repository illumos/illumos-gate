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
 * Copyright 2018 Joyent, Inc.
 */

#include <alloca.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <libzonecfg.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <zdoor.h>
#include <zone.h>

#include "zdoor-int.h"
#include "zerror.h"
#include "ztree.h"

extern void *
zonecfg_notify_bind(int(*func)(const char *zonename, zoneid_t zid,
    const char *newstate, const char *oldstate, hrtime_t when,
    void *p), void *p);

extern void
zonecfg_notify_unbind(void *handle);

/*
 * _callback(cookie, door_args...) is our private function that we tell
 * the Solaris door API about.  This function does some sanity checking on
 * arguments and issues a callback to the owner of this door.  That API
 * will return us memory that needs to be sent back to the client on the
 * other end of the door, but since the door_return API never gives you
 * back control of the function, this does a simple alloca/memcpy and
 * frees up the memory pointed to by the parent.  While this really doesn't
 * let a client do much other than pass a simple struct of primitives (or
 * more likely more common a char *), that's the way the door API works,
 * and so this isn't really imposing any restriction that didn't already
 * need to be dealt with by someone.  This is why the zdoor_result structure
 * takes a char *, rather than a void * for the data pointer.
 */
static void
_callback(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t n_desc)
{
	zdoor_result_t *result = NULL;
	void *door_response = NULL;
	int size = 0;
	dtree_entry_t *entry = (dtree_entry_t *)cookie;

	if (entry == NULL) {
		zdoor_warn("_callback: NULL cookie? door_returning");
		(void) door_return(NULL, 0, NULL, 0);
	}

	(void) pthread_mutex_lock(&entry->dte_parent->zte_parent->zdh_lock);
	zdoor_debug("_callback: calling back with %p", entry->dte_cookie);
	result = entry->dte_callback(entry->dte_cookie, argp, arg_size);
	zdoor_debug("_callback: app callback returned %p", result);
	(void) pthread_mutex_unlock(&entry->dte_parent->zte_parent->zdh_lock);

	if (result == NULL) {
		zdoor_debug("_callback: door_returning NULL");
		(void) door_return(NULL, 0, NULL, 0);
	}

	if (result->zdr_data != NULL && result->zdr_size > 0) {
		door_response = alloca(result->zdr_size);
		if (door_response != NULL) {
			size = result->zdr_size;
			(void) memcpy(door_response,
			    (void *) result->zdr_data, size);
		}
	}

	if (result->zdr_data != NULL)
		free(result->zdr_data);
	free(result);

	zdoor_debug("_callback: door_returning %p, %d", door_response, size);
	(void) door_return(door_response, size, NULL, 0);
}

static void
zdoor_stop(dtree_entry_t *entry)
{
	zoneid_t zid = -1;

	if (entry == NULL) {
		zdoor_debug("zdoor_stop: NULL arguments");
		return;
	}

	zdoor_debug("zdoor_stop: entry=%p, zone=%s, service=%s",
	    entry, entry->dte_parent->zte_zonename, entry->dte_service);

	zid = getzoneidbyname(entry->dte_parent->zte_zonename);
	(void) zdoor_fattach(zid, entry->dte_service, entry->dte_door, 1);
	(void) door_revoke(entry->dte_door);
	entry->dte_door = -1;

	zdoor_debug("zdoor_stop returning");
}

/*
 * zdoor_create is called both by the main API
 * call zdoor_open, as well as by the zone_monitor code upon a zone restart
 * (assuming it already has a door in it).  This code assumes that the
 * permissions were correct (e.g., the target door is not a GZ, that this
 * program is being run out of the GZ), but does not assume that the target
 * door file has not changed out from under us, so that is explicitly rechecked.
 *
 * This also assumes the parent has already locked handle.
 */
static int
zdoor_create(dtree_entry_t *entry)
{
	int status = ZDOOR_OK;
	zoneid_t zid = -1;

	if (entry == NULL) {
		zdoor_debug("zdoor_create: NULL arguments");
		return (ZDOOR_ARGS_ERROR);
	}

	zdoor_debug("zdoor_create: entry=%p, zone=%s, service=%s",
	    entry, entry->dte_parent->zte_zonename, entry->dte_service);

	zid = getzoneidbyname(entry->dte_parent->zte_zonename);
	if (zid < 0) {
		zdoor_info("zdoor_create: %s is a non-existient zone",
		    entry->dte_parent->zte_zonename);
		return (ZDOOR_ERROR);
	}
	if (!zdoor_zone_is_running(zid)) {
		zdoor_debug("zdoor_create: %s is not running",
		    entry->dte_parent->zte_zonename);
		return (ZDOOR_ZONE_NOT_RUNNING);
	}

	entry->dte_door = door_create(_callback, entry, 0);
	zdoor_info("zdoor_create: door_create returned %d", entry->dte_door);
	if (entry->dte_door < 0) {
		zdoor_stop(entry);
		return (ZDOOR_ERROR);
	}

	status = zdoor_fattach(zid, entry->dte_service, entry->dte_door, 0);

	zdoor_debug("zdoor_create: returning %d", status);
	return (status);
}


/*
 * door_visitor(entry) is a callback from the ztree code that checks whether
 * or not we should be taking some action on a given door.  Note that the
 * callpath to this API is:
 *  SYSTEM ->
 *    zone_monitor ->
 *      ztree_walk ->
 *        door_visitor
 *
 * Which is important to note that this API assumes that all things needing
 * locking are locked by a parent caller (which is the zone_monitor).
 */
static void
zdoor_visitor(dtree_entry_t *entry)
{
	if (entry == NULL) {
		zdoor_info("zdoor_visitor: entered with NULL entry");
		return;
	}

	zdoor_debug("zdoor_visitor: entered for entry=%p, service=%s",
	    entry, entry->dte_service);

	if (entry->dte_parent->zte_action == ZDOOR_ACTION_STOP) {
		zdoor_debug("  stopping zdoor");
		zdoor_stop(entry);
	} else if (entry->dte_parent->zte_action == ZDOOR_ACTION_START) {
		zdoor_debug("  starting zdoor");
		if (zdoor_create(entry) != ZDOOR_OK) {
			zdoor_error("door_visitor: Unable to restart zdoor\n");
		}
	}
}

/*
 * zone_monitor(zonename, zid, newstate, oldstate, when, cookie) is our
 * registered callback with libzonecfg to notify us of any changes to a
 * given zone.  This activates a walk on all doors for a zone iff the state
 * is changing from running or into running.
 */
static int
zone_monitor(const char *zonename, zoneid_t zid, const char *newstate,
    const char *oldstate, hrtime_t when, void *p)
{
	zdoor_handle_t handle = (zdoor_handle_t)p;
	ztree_entry_t *entry = NULL;

	if (handle == NULL) {
		zdoor_warn("zone_monitor: entered with NULL handle?");
		return (-1);
	}

	zdoor_info("zone_monitor: zone=%s, zid=%d, newst=%s, oldst=%s, p=%p",
	    zonename, zid, newstate, oldstate, p);

	(void) pthread_mutex_lock(&(handle->zdh_lock));
	entry = ztree_zone_find(handle, zonename);
	if (entry != NULL) {
		zdoor_debug("  found entry in ztree");
		entry->zte_action = ZDOOR_ACTION_NOOP;
		if (strcmp("running", newstate) == 0) {
			if (strcmp("ready", oldstate) == 0)
				entry->zte_action = ZDOOR_ACTION_START;
		} else if (strcmp("shutting_down", newstate) == 0) {
			if (strcmp("running", oldstate) == 0)
				entry->zte_action = ZDOOR_ACTION_STOP;
		}
		zdoor_debug("    set state to: %d", entry->zte_action);
		if (entry->zte_action != ZDOOR_ACTION_NOOP)
			ztree_walk_doors(handle, zonename);
	}
	(void) pthread_mutex_unlock(&(handle->zdh_lock));

	zdoor_info("zone_monitor: returning");
	return (0);
}

zdoor_handle_t
zdoor_handle_init()
{
	zdoor_handle_t handle = NULL;

	zdoor_debug("zdoor_handle_init entered");

	handle = (zdoor_handle_t)calloc(1, sizeof (struct zdoor_handle));
	if (handle == NULL) {
		OUT_OF_MEMORY();
		return (NULL);
	}

	(void) pthread_mutex_init(&(handle->zdh_lock), NULL);
	handle->zdh_zonecfg_handle = zonecfg_notify_bind(zone_monitor, handle);
	if (handle->zdh_zonecfg_handle == NULL) {
		zdoor_error("zonecfg_notify_bind failure: %s", strerror(errno));
		return (NULL);
	}

	zdoor_debug("zdoor_handle_init returning %p", handle);
	return (handle);
}

void
zdoor_handle_destroy(zdoor_handle_t handle)
{
	if (handle == NULL) {
		zdoor_debug("zdoor_handle_destroy: NULL arguments");
		return;
	}

	zdoor_debug("zdoor_handle_destroy: handle=%p", handle);

	(void) pthread_mutex_lock(&(handle->zdh_lock));
	zonecfg_notify_unbind(handle->zdh_zonecfg_handle);
	(void) pthread_mutex_unlock(&(handle->zdh_lock));
	(void) pthread_mutex_destroy(&(handle->zdh_lock));
	free(handle);
}

/*
 * zdoor_open(zone, service, biscuit, callback) is the main public facing API in
 * libzdoor.  It will open a door with the name .[service] under
 * [zonepath]/root/var/tmp, where [zonepath] is resolved on the fly.  Note this
 * API can only be invoked from the global zone, and will not allow you to open
 * a zdoor in the global zone.
 */
int
zdoor_open(zdoor_handle_t handle, const char *zonename, const char *service,
    void *biscuit, zdoor_callback callback)
{
	zdoor_cookie_t *zdoor_cookie = NULL;
	int rc = -1;
	int status = ZDOOR_OK;
	zoneid_t zid = -1;
	dtree_entry_t *entry = NULL;

	if (handle == NULL || zonename == NULL ||
	    service == NULL || callback == NULL) {
		zdoor_debug("zdoor_open: NULL arguments");
		return (ZDOOR_ARGS_ERROR);
	}
	zdoor_debug("zdoor_open: entered: handle=%p, zone=%s, service=%s",
	    handle, zonename, service);

	if (getzoneid() != GLOBAL_ZONEID) {
		zdoor_warn("zdoor_open: not invoked from global zone");
		return (ZDOOR_NOT_GLOBAL_ZONE);
	}


	zid = getzoneidbyname(zonename);
	if (zid < 0) {
		zdoor_info("zdoor_open: %s is a non-existent zone", zonename);
		return (ZDOOR_ARGS_ERROR);
	}

	if (zid == GLOBAL_ZONEID) {
		zdoor_warn("zdoor_open: zdoors not allowed in global zone");
		return (ZDOOR_ZONE_FORBIDDEN);
	}

	if (!zdoor_zone_is_running(zid)) {
		zdoor_info("zdoor_open: %s is not running", zonename);
		return (ZDOOR_ZONE_NOT_RUNNING);
	}

	zdoor_cookie = zdoor_cookie_create(zonename, service, biscuit);
	if (zdoor_cookie == NULL) {
		OUT_OF_MEMORY();
		return (ZDOOR_OUT_OF_MEMORY);
	}

	(void) pthread_mutex_lock(&(handle->zdh_lock));
	rc = ztree_zone_add(handle, zonename, zdoor_visitor);
	if (rc != ZTREE_SUCCESS && rc != ZTREE_ALREADY_EXISTS) {
		zdoor_debug("zdoor_open: unable to add zone to ztree: %d", rc);
		status = ZDOOR_ERROR;
		goto out;
	}
	rc = ztree_door_add(handle, zonename, service, callback,
	    zdoor_cookie);
	if (rc != ZTREE_SUCCESS) {
		zdoor_debug("zdoor_open: unable to add door to ztree: %d", rc);
		if (rc == ZTREE_ALREADY_EXISTS) {
			zdoor_warn("service %s already has a zdoor", service);
		}
		status = ZDOOR_ERROR;
		goto out;
	}

	entry = ztree_door_find(handle, zonename, service);
	if (entry == NULL) {
		zdoor_debug("zdoor_open: unable to find door in ztree?");
		status = ZDOOR_ERROR;
		goto out;
	}
	if (zdoor_create(entry) != ZDOOR_OK) {
		zdoor_info("zdoor_open: zdoor_create failed.");
		status = ZDOOR_ERROR;
		goto out;
	}
out:
	if (status != ZDOOR_OK) {
		zdoor_debug("zdoor_open: status not ok, stopping and cleaning");
		zdoor_stop(entry);
		ztree_door_remove(handle, entry);
		zdoor_cookie_free(zdoor_cookie);
	}
	(void) pthread_mutex_unlock(&(handle->zdh_lock));
	zdoor_debug("zdoor_open: returning %d", status);
	return (status);
}

/*
 * zdoor_close(zone, service) unregisters a previously created zdoor, and
 * returns the biscuit provided at creation time, so the caller can free it.
 * Returns NULL on any error.
 */
void *
zdoor_close(zdoor_handle_t handle, const char *zonename, const char *service)
{
	dtree_entry_t *entry = NULL;
	zdoor_cookie_t *cookie = NULL;
	void *biscuit = NULL;

	if (handle == NULL || zonename == NULL || service == NULL) {
		zdoor_debug("zdoor_close: NULL arguments");
		return (NULL);
	}

	zdoor_debug("zdoor_close: entered handle=%p, zone=%s, service=%s",
	    handle, zonename, service);

	(void) pthread_mutex_lock(&(handle->zdh_lock));

	entry = ztree_door_find(handle, zonename, service);
	if (entry != NULL) {
		zdoor_debug("zdoor_close: found door in ztree, stopping");
		zdoor_stop(entry);
		cookie = ztree_door_remove(handle, entry);
		if (cookie != NULL) {
			biscuit = cookie->zdc_biscuit;
			zdoor_cookie_free(cookie);
		}
	} else {
		zdoor_debug("zdoor_close: didn't find door in ztree");
	}

	(void) pthread_mutex_unlock(&(handle->zdh_lock));

	zdoor_debug("zdoor_close: returning %p", biscuit);
	return (biscuit);
}
