/***************************************************************************
 *
 * devinfo_misc : misc devices
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <libdevinfo.h>
#include <sys/uadmin.h>

#include "../osspec.h"
#include "../logger.h"
#include "../hald.h"
#include "../hald_dbus.h"
#include "../device_info.h"
#include "../util.h"
#include "devinfo_misc.h"

static HalDevice *devinfo_computer_add(HalDevice *, di_node_t, char *, char *);
static HalDevice *devinfo_cpu_add(HalDevice *, di_node_t, char *, char *);
static HalDevice *devinfo_keyboard_add(HalDevice *, di_node_t, char *, char *);
static HalDevice *devinfo_default_add(HalDevice *, di_node_t, char *, char *);

DevinfoDevHandler devinfo_computer_handler = {
	devinfo_computer_add,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
DevinfoDevHandler devinfo_cpu_handler = {
	devinfo_cpu_add,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
DevinfoDevHandler devinfo_keyboard_handler = {
	devinfo_keyboard_add,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};
DevinfoDevHandler devinfo_default_handler = {
	devinfo_default_add,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

static HalDevice *
devinfo_computer_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	HalDevice *d, *local_d;
	struct utsname un;

	if (strcmp (devfs_path, "/") != 0) {
		return (NULL);
	}

	d = hal_device_new ();

	hal_device_property_set_string (d, "info.subsystem", "unknown");
	hal_device_property_set_string (d, "info.product", "Computer");
	hal_device_property_set_string (d, "info.udi", "/org/freedesktop/Hal/devices/computer");
	hal_device_set_udi (d, "/org/freedesktop/Hal/devices/computer");
	hal_device_property_set_string (d, "solaris.devfs_path", devfs_path);

	if (uname (&un) >= 0) {
		hal_device_property_set_string (d, "system.kernel.name", un.sysname);
		hal_device_property_set_string (d, "system.kernel.version", un.release);
		hal_device_property_set_string (d, "system.kernel.machine", un.machine);
	}

	hal_device_property_set_bool(d, "power_management.can_hibernate",
	    (uadmin(A_FREEZE, AD_CHECK_SUSPEND_TO_DISK, 0) == 0));
	hal_device_property_set_bool(d, "power_management.can_suspend",
	    (uadmin(A_FREEZE, AD_CHECK_SUSPEND_TO_RAM, 0) == 0));

	hal_device_add_capability(d, "button");

	/*
	 * Let computer be in TDL while synthesizing all other events
	 * because some may write to the object
	 */
	hal_device_store_add (hald_get_tdl (), d);

	devinfo_add_enqueue (d, devfs_path, &devinfo_computer_handler);

	/* all devinfo devices belong to the 'local' branch */
	local_d = hal_device_new ();

	hal_device_property_set_string (local_d, "info.parent", hal_device_get_udi (d));
	hal_device_property_set_string (local_d, "info.subsystem", "unknown");
	hal_device_property_set_string (local_d, "info.product", "Local devices");
	hal_device_property_set_string (local_d, "info.udi", "/org/freedesktop/Hal/devices/local");
	hal_device_set_udi (local_d, "/org/freedesktop/Hal/devices/local");
	hal_device_property_set_string (local_d, "solaris.devfs_path", "/local");

	devinfo_add_enqueue (local_d, "/local", &devinfo_default_handler);

	return (local_d);
}

static HalDevice *
devinfo_cpu_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	HalDevice *d;

	if ((device_type == NULL) || (strcmp(device_type, "cpu") != 0)) {
		return (NULL);
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
	hal_device_add_capability (d, "processor");

	devinfo_add_enqueue (d, devfs_path, &devinfo_cpu_handler);

	return (d);
}

static HalDevice *
devinfo_keyboard_add(HalDevice *parent, di_node_t node, char *devfs_path,
    char *device_type)
{
	HalDevice *d;

	if (strcmp(di_node_name(node), "keyboard") != 0) {
		return (NULL);
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
	hal_device_add_capability (d, "input.keyboard");
	hal_device_add_capability(d, "button");

	devinfo_add_enqueue (d, devfs_path, &devinfo_keyboard_handler);

	return (d);
}

static HalDevice *
devinfo_default_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	char *driver_name;
	const char *parent_path;
	HalDevice *d;

	/* ignore all children of the 'pseudo' node except lofi */
	if (parent != NULL) {
		parent_path = hal_device_property_get_string(parent, "solaris.devfs_path");
		if ((parent_path != NULL) &&
		    (strcmp (parent_path, "/pseudo") == 0)) {
			driver_name = di_driver_name (node);
			if ((driver_name != NULL) &&
			    (strcmp (driver_name, "lofi") != 0)) {
				return (NULL);
			}
		}
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);

	devinfo_add_enqueue (d, devfs_path, &devinfo_default_handler);

	return (d);
}
