/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <libhal.h>
#include <logger.h>

#include <glib.h>

#include "network-discovery.h"

/*
 * The interfaces in this file comprise a means of keeping track of devices
 * that we have already seen and those that have gone missing.  This allows
 * us to quickly determine if we need to probe the device and quickly search
 * for devices that are no longer available.
 */

typedef struct {
	LibHalContext *ctx;
	time_t timestamp;
} removal_args_t;

static GHashTable *seen = NULL;

static gboolean
device_remove_if_stale(gpointer key, gpointer value, gpointer user_data)
{
	gboolean result = FALSE;
	removal_args_t *args = user_data;
	char *name = key;
	time_t *val = value;

	HAL_DEBUG(("test stale: %s (%d > %d)", name, args->timestamp, *val));
	if (args->timestamp > *val) {
		DBusError error;
		char **udi = NULL;
		int num = 0;

		dbus_error_init(&error);
		udi = libhal_manager_find_device_string_match(args->ctx,
					"network_device.address", name,
					&num, &error);

		if (udi != NULL) {
			int i;

			for (i = 0; i < num; i++) {
				libhal_remove_device(args->ctx, udi[i], &error);
				HAL_DEBUG(("remove: %s (%s)", name, udi[i]));
			}
			libhal_free_string_array(udi);
			result = TRUE;
		}
		if (dbus_error_is_set(&error))
			dbus_error_free(&error);
	}

	return (result);
}

void
scan_for_stale_devices(LibHalContext *ctx, time_t timestamp)
{
	if (seen != NULL) {
		removal_args_t args[1];

		args->ctx = ctx;
		args->timestamp = timestamp;

		g_hash_table_foreach_remove(seen, device_remove_if_stale, args);
	}
}

gboolean
device_seen(char *name)
{
	gboolean result;
	char *key;
	time_t *val;

	if (seen == NULL)
		seen = g_hash_table_new_full(g_str_hash, g_str_equal,
						free, free);

	result = g_hash_table_lookup_extended(seen, name,
				(gpointer)&key, (gpointer)&val);

	if ((result == FALSE) && ((val = calloc(1, sizeof (*val))) != NULL)) {
		g_hash_table_insert(seen, strdup(name), val);
	}
	(void) time(val);
	HAL_DEBUG(("seen: %s (%d)", name, *val));

	return (result);
}
