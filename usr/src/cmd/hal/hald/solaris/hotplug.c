/***************************************************************************
 *
 * hotplug.c : HAL-internal hotplug events
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include "../osspec.h"
#include "../logger.h"
#include "../hald.h"
#include "../device_info.h"

#include "osspec_solaris.h"
#include "hotplug.h"
#include "devinfo.h"

/** Queue of ordered hotplug events */
GQueue *hotplug_event_queue;

/** List of HotplugEvent objects we are currently processing */
GSList *hotplug_events_in_progress = NULL;

static void hotplug_event_begin (HotplugEvent *hotplug_event);

void
hotplug_event_end (void *end_token)
{
	HotplugEvent *hotplug_event = (HotplugEvent *) end_token;

	hotplug_events_in_progress = g_slist_remove (hotplug_events_in_progress, hotplug_event);
	g_free (hotplug_event);
	hotplug_event_process_queue ();
}

static void
hotplug_event_begin_devfs_add (HotplugEvent *hotplug_event, HalDevice *d)
{
	HalDevice *parent;
	const gchar *parent_udi;
	void (*begin_add_func) (HalDevice *, HalDevice *, DevinfoDevHandler *, void *);

	if (d != NULL) {
		/* XXX */
		HAL_ERROR (("devpath %s already present in store, ignore event", hotplug_event->un.devfs.devfs_path));

		goto out;
	}

	/* find parent */
	parent_udi = hal_device_property_get_string (hotplug_event->d, "info.parent");
	if (parent_udi == NULL || strlen(parent_udi) == 0) {
		parent = NULL;
	} else {
		parent = hal_device_store_match_key_value_string (hald_get_gdl (), "info.udi", parent_udi);
	}
	/* only root node is allowed to be orphan */
	if (parent == NULL) {
		if (strcmp(hotplug_event->un.devfs.devfs_path, "/") != 0) {
			HAL_ERROR (("Parent is NULL devfs_path=%s parent_udi=%s", hotplug_event->un.devfs.devfs_path, parent_udi ? parent_udi : "<null>"));

			goto out;
		}
	}

	/* children of ignored parent should be ignored */
	if (parent != NULL && hal_device_property_get_bool (parent, "info.ignore")) {
		HAL_INFO (("parent ignored %s", parent_udi));

		goto out;
	}

	/* custom or generic add function */
	begin_add_func = hotplug_event->un.devfs.handler->hotplug_begin_add;
	if (begin_add_func == NULL) {
		begin_add_func = hotplug_event_begin_add_devinfo;
	}
	begin_add_func (hotplug_event->d,
			 parent,
			 hotplug_event->un.devfs.handler,
			 (void *) hotplug_event);
	 return;

out:
	g_object_unref (hotplug_event->d);
	hotplug_event_end ((void *) hotplug_event);

	return;
}

static void
hotplug_event_begin_devfs_remove (HotplugEvent *hotplug_event, HalDevice *d)
{
	if (d == NULL) {
		HAL_ERROR (("devpath %s not present in store, ignore event", hotplug_event->un.devfs.devfs_path));
		hotplug_event_end ((void *) hotplug_event);
		return;
	}
	HAL_INFO (("hotplug_event_begin_devfs_remove %s", hal_device_get_udi (d)));

	hotplug_event_begin_remove_devinfo(d,
			 hotplug_event->un.devfs.devfs_path,
			 (void *) hotplug_event);
}

static void
hotplug_event_begin_devfs (HotplugEvent *hotplug_event)
{
	HalDevice *d;

	HAL_INFO (("hotplug_event_begin_devfs: %s", hotplug_event->un.devfs.devfs_path));
	d = hal_device_store_match_key_value_string (hald_get_gdl (),
						"solaris.devfs_path",
						hotplug_event->un.devfs.devfs_path);

	if (hotplug_event->action == HOTPLUG_ACTION_ADD) {
		hotplug_event_begin_devfs_add (hotplug_event, d);
	} else if (hotplug_event->action == HOTPLUG_ACTION_REMOVE) {
		hotplug_event_begin_devfs_remove (hotplug_event, d);
	} else {
		HAL_ERROR (("unsupported action %d", hotplug_event->action));
		g_object_unref (hotplug_event->d);
		hotplug_event_end ((void *) hotplug_event);
	}
}

static void
hotplug_event_begin (HotplugEvent *hotplug_event)
{
	switch (hotplug_event->type) {

	case HOTPLUG_EVENT_DEVFS:
		hotplug_event_begin_devfs (hotplug_event);
		break;

	default:
		HAL_ERROR (("Unknown hotplug event type %d", hotplug_event->type));
		g_object_unref (hotplug_event->d);
		hotplug_event_end ((void *) hotplug_event);
		break;
	}
}

void
hotplug_event_enqueue (HotplugEvent *hotplug_event, int front)
{
	if (hotplug_event_queue == NULL)
		hotplug_event_queue = g_queue_new ();

	if (front) {
		g_queue_push_head (hotplug_event_queue, hotplug_event);
	} else {
		g_queue_push_tail (hotplug_event_queue, hotplug_event);
	}
}

void
hotplug_event_process_queue (void)
{
	HotplugEvent *hotplug_event;

	if (hotplug_events_in_progress == NULL &&
	    (hotplug_event_queue == NULL || g_queue_is_empty (hotplug_event_queue))) {
		hotplug_queue_now_empty ();
		goto out;
	}

	/* do not process events if some other event is in progress */
	if (hotplug_events_in_progress != NULL && g_slist_length (hotplug_events_in_progress) > 0)
		goto out;

	hotplug_event = g_queue_pop_head (hotplug_event_queue);
	if (hotplug_event == NULL)
		goto out;

	hotplug_events_in_progress = g_slist_append (hotplug_events_in_progress, hotplug_event);
	hotplug_event_begin (hotplug_event);

out:
	;
}
