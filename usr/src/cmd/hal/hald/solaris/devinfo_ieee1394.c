/***************************************************************************
 *
 * devinfo_ieee1394.c : IEEE 1394/FireWire devices
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
#include <libdevinfo.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>

#include "../osspec.h"
#include "../logger.h"
#include "../hald.h"
#include "../hald_dbus.h"
#include "../device_info.h"
#include "../util.h"
#include "../ids.h"
#include "hotplug.h"
#include "devinfo.h"
#include "devinfo_ieee1394.h"

HalDevice *devinfo_ieee1394_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);
static HalDevice *devinfo_scsa1394_add(HalDevice *d, di_node_t node, gchar *devfs_path);

DevinfoDevHandler devinfo_ieee1394_handler = {
        devinfo_ieee1394_add,
	NULL,
	NULL,
	NULL,
	NULL,
        NULL
};

HalDevice *
devinfo_ieee1394_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	HalDevice *d = NULL;
	char	*compat;
	char	*driver_name;

	/*
	 * we distinguish 1394 devices by compatible name
	 * starting with 'firewire'
	 */
	if ((di_compatible_names (node, &compat) < 1) ||
	    (strncmp (compat, "firewire", sizeof ("firewire") - 1) != 0)) {
		return (NULL);
	}

	if ((driver_name = di_driver_name (node)) == NULL) {
		return (NULL);
	}

	if (strcmp (driver_name, "scsa1394") == 0) {
		d = devinfo_scsa1394_add (parent, node, devfs_path);
	}

	return (d);
}

static HalDevice *
devinfo_scsa1394_add(HalDevice *parent, di_node_t node, gchar *devfs_path)
{
	HalDevice *d = NULL;

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
	hal_device_property_set_string (d, "info.subsystem", "ieee1394");
	hal_device_property_set_string (d, "info.product", "FireWire SBP-2 device");

	devinfo_add_enqueue (d, devfs_path, &devinfo_ieee1394_handler);

	return (d);
}

