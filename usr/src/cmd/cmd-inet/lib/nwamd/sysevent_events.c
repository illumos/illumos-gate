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
#include <errno.h>
#include <libsysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dev.h>
#include <sys/types.h>
#include <libnvpair.h>
#include <string.h>
#include <unistd.h>

#include "events.h"
#include "ncp.h"
#include "ncu.h"
#include "objects.h"
#include "util.h"

/*
 * sysevent_events.c - this file contains routines to retrieve sysevents
 * from the system and package them for high level processing.
 */

static sysevent_handle_t *sysevent_handle;

/*
 * At present, we only handle EC_DEV_ADD/EC_DEV_REMOVE sysevents of
 * subclass ESC_NETWORK.  These signify hotplug addition/removal.
 * For EC_DEV_ADD, we:
 *      - extract the driver/instance sysevent attributes
 *      - combine these to get interface name and create associated NCUs
 *      at the link/IP level if required
 *      - enable those instances
 * For EC_DEV_REMOVE, we:
 *      - disable the associated link/IP NCUs
 */
static void
sysevent_handler(sysevent_t *ev)
{
	int32_t instance;
	char *driver;
	char if_name[LIFNAMSIZ];
	boolean_t link_added;
	nvlist_t *attr_list;
	char *event_class = sysevent_get_class_name(ev);
	char *event_subclass = sysevent_get_subclass_name(ev);
	nwamd_event_t link_event = NULL;

	nlog(LOG_DEBUG, "sysevent_handler: event %s/%s", event_class,
	    event_subclass);

	/* Make sure sysevent is of expected class/subclass */
	if ((strcmp(event_class, EC_DEV_ADD) != 0 &&
	    strcmp(event_class, EC_DEV_REMOVE) != 0) ||
	    strcmp(event_subclass, ESC_NETWORK) != 0) {
		nlog(LOG_ERR, "sysevent_handler: unexpected sysevent "
		    "class/subclass %s/%s", event_class, event_subclass);
		return;
	}

	link_added = (strcmp(event_class, EC_DEV_ADD) == 0);

	/*
	 * Retrieve driver name and instance attributes, and combine to
	 * get interface name.
	 */
	if (sysevent_get_attr_list(ev, &attr_list) != 0) {
		nlog(LOG_ERR, "sysevent_handler: sysevent_get_attr_list: %m");
		return;
	}
	if (nvlist_lookup_string(attr_list, DEV_DRIVER_NAME, &driver) != 0 ||
	    nvlist_lookup_int32(attr_list, DEV_INSTANCE, &instance) != 0) {
		nlog(LOG_ERR, "sysevent_handler: nvlist_lookup "
		    "of attributes failed: %m");
		nvlist_free(attr_list);
		return;
	}
	(void) snprintf(if_name, LIFNAMSIZ, "%s%d", driver, instance);
	nvlist_free(attr_list);

	/* Ignore sysevent events for other zones */
	if (!nwamd_link_belongs_to_this_zone(if_name))
		return;

	/* Create event for link */
	link_event = nwamd_event_init_link_action(if_name,
	    link_added ? NWAM_ACTION_ADD : NWAM_ACTION_REMOVE);
	if (link_event != NULL)
		nwamd_event_enqueue(link_event);
}

/* ARGSUSED0 */
static void *
sysevent_initialization(void *arg)
{
	const char *subclass = ESC_NETWORK;

	do {
		nwamd_to_root();
		sysevent_handle = sysevent_bind_handle(sysevent_handler);
		nwamd_from_root();

		(void) sleep(1);
	} while (sysevent_handle == NULL);

	/*
	 * Subscribe to ESC_NETWORK subclass of EC_DEV_ADD and EC_DEV_REMOVE
	 * events.  As a result,  we get sysevent notification of hotplug
	 * add/remove events,  which we handle above in sysevent_handler().
	 */
	if (sysevent_subscribe_event(sysevent_handle, EC_DEV_ADD, &subclass, 1)
	    != 0 ||
	    sysevent_subscribe_event(sysevent_handle, EC_DEV_REMOVE, &subclass,
	    1) != 0)
		pfail("sysevent_subscribe_event: %s", strerror(errno));

	return (NULL);
}

/*
 * We can't initialize in the main thread because we may need to wait until
 * svc:/system/sysevent:default finishes starting up.  So we create a thread to
 * initialize in.
 */
void
nwamd_sysevent_events_init(void)
{
	int rc;
	pthread_attr_t attr;

	rc = pthread_attr_init(&attr);
	if (rc != 0) {
		pfail("nwamd_sysevents_init: pthread_attr_init failed: %s",
		    strerror(rc));
	}

	rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (rc != 0) {
		pfail("nwamd_sysevents_init: pthread_attr_setdetachstate "
		    "failed: %s", strerror(rc));
	}

	rc = pthread_create(NULL, &attr, sysevent_initialization, NULL);
	if (rc != 0) {
		pfail("nwamd_sysevents_init: couldn't start sysevent init "
		    "thread: %s", strerror(rc));
	}

	(void) pthread_attr_destroy(&attr);
}

void
nwamd_sysevent_events_fini(void)
{
	if (sysevent_handle != NULL) {
		nwamd_to_root();
		sysevent_unbind_handle(sysevent_handle);
		nwamd_from_root();
	}
	sysevent_handle = NULL;
}
