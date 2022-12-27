/***************************************************************************
 *
 * hotplug.h : definitions for HAL-internal hotplug events
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifndef HOTPLUG_H
#define HOTPLUG_H

#include <glib.h>

#include "../device.h"
#include "../util.h"

#include "devinfo.h"

typedef enum {
	HOTPLUG_ACTION_ADD,
	HOTPLUG_ACTION_REMOVE,
} HotplugActionType;

typedef enum {
	HOTPLUG_EVENT_DEVFS       = 0,
} HotplugEventType;

/** Data structure representing a hotplug event; also used for
 *  coldplugging.
 */
typedef struct
{
	HotplugActionType action;               /**< Whether the event is add or remove */
	HotplugEventType type;                  /**< Type of hotplug event */

	HalDevice *d;

	union {
		struct {
			char devfs_path[HAL_PATH_MAX];
			DevinfoDevHandler *handler;
		} devfs;
	} un;

} HotplugEvent;

void hotplug_event_enqueue (HotplugEvent *event, int front);

void hotplug_event_process_queue (void);

void hotplug_event_end (void *end_token);

void hotplug_queue_now_empty (void);

#endif /* HOTPLUG_H */
