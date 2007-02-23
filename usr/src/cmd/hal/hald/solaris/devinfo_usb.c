/***************************************************************************
 *
 * devinfo_usb.h : USB devices
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include "devinfo_usb.h"

HalDevice *devinfo_usb_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);
static HalDevice *devinfo_usb_if_add(HalDevice *d, di_node_t node, gchar *devfs_path, int ifnum);
static HalDevice *devinfo_usb_scsa2usb_add(HalDevice *d, di_node_t node, gchar *devfs_path);
static HalDevice *devinfo_usb_printer_add(HalDevice *usbd, di_node_t node, gchar *devfs_path);
const gchar *devinfo_printer_prnio_get_prober (HalDevice *d, int *timeout);

DevinfoDevHandler devinfo_usb_handler = {
        devinfo_usb_add,
	NULL,
	NULL,
	NULL,
	NULL,
        NULL
};

DevinfoDevHandler devinfo_usb_printer_handler = {
        devinfo_usb_add,
	NULL,
	NULL,
	NULL,
	NULL,
        devinfo_printer_prnio_get_prober
};

static gboolean
is_usb_node(di_node_t node)
{
	int rc;
	char *s;

	/*
	 * USB device nodes will have "compatible" propety values that
	 * begins with "usb".
	 */
        rc = di_prop_lookup_strings(DDI_DEV_T_ANY, node, "compatible", &s);
	while (rc-- > 0) {
		if (strncmp(s, "usb", 3) == 0) {
			return (TRUE);
		}
		s += (strlen(s) + 1);
	}

	return (FALSE);
}

HalDevice *
devinfo_usb_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	HalDevice *d, *nd = NULL;
	char	*s;
	int	*i;
	char	*driver_name, *binding_name;
        char    if_devfs_path[HAL_PATH_MAX];

        if (is_usb_node(node) == FALSE) {
		return (NULL);
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
	hal_device_property_set_string (d, "info.bus", "usb_device");
	PROP_STR(d, node, s, "usb-product-name", "info.product");
	PROP_STR(d, node, s, "usb-product-name", "usb_device.product");
	PROP_STR(d, node, s, "usb-vendor-name", "usb_device.vendor");
	PROP_INT(d, node, i, "usb-vendor-id", "usb_device.vendor_id");
	PROP_INT(d, node, i, "usb-product-id", "usb_device.product_id");
	PROP_INT(d, node, i, "usb-revision-id", "usb_device.device_revision_bcd");
	PROP_INT(d, node, i, "usb-release-id", "usb_device.version_bcd");
	PROP_STR(d, node, s, "usb-serialno", "usb_device.serial");

	/* class, subclass */
	/* hal_device_property_set_int (d, "usb_device.device_class", 8); */

	/* binding name tells us if driver is bound to interface or device */
	if (((binding_name = di_binding_name(node)) != NULL) &&
	    (strncmp(binding_name, "usbif,", sizeof ("usbif,") - 1) == 0)) {
		snprintf(if_devfs_path, sizeof (if_devfs_path), "%s:if%d", devfs_path, 0);
		if ((nd = devinfo_usb_if_add(d, node, if_devfs_path, 0)) != NULL) {
			d = nd;
			nd = NULL;
			devfs_path = if_devfs_path;
		}
	}

	/* driver specific */
	driver_name = di_driver_name (node);
	if ((driver_name != NULL) && (strcmp (driver_name, "scsa2usb") == 0)) {
		nd = devinfo_usb_scsa2usb_add (d, node, devfs_path);
	} else if ((driver_name != NULL) &&
		    (strcmp (driver_name, "usbprn") == 0)) {
		nd = devinfo_usb_printer_add (d, node, devfs_path);
	} else {
		devinfo_add_enqueue (d, devfs_path, &devinfo_usb_handler);
	}

out:
	if (nd != NULL) {
		return (nd);
	} else {
		return (d);
	}
}

static HalDevice *
devinfo_usb_if_add(HalDevice *parent, di_node_t node, gchar *devfs_path, int ifnum)
{
	HalDevice *d = NULL;
        char    udi[HAL_PATH_MAX];

	devinfo_add_enqueue (parent, devfs_path, &devinfo_usb_handler);

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
        hal_device_property_set_string (d, "info.bus", "usb");
        hal_device_property_set_string (d, "info.product", "USB Device Interface");

	/* copy parent's usb_device.* properties */
	hal_device_merge_with_rewrite (d, parent, "usb.", "usb_device.");

	return (d);
}


static void
get_dev_link_path(di_node_t node, char *nodetype, char *re, char **devlink, char **minor_path)
{
	di_devlink_handle_t devlink_hdl;
        int     major;
        di_minor_t minor;
        dev_t   devt;

	*devlink = NULL;
        *minor_path = NULL;

        if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL) {
                printf("di_devlink_init() failed\n");
                return;
        }

        major = di_driver_major(node);
        minor = DI_MINOR_NIL;
        while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
                devt = di_minor_devt(minor);
                if (major != major(devt)) {
                        continue;
                }

                if (di_minor_type(minor) != DDM_MINOR) {
                        continue;
                }

                if ((*minor_path = di_devfs_minor_path(minor)) == NULL) {
                        continue;
                }

		if ((strcmp (di_minor_nodetype(minor), nodetype) == 0) &&
		    ((*devlink = get_devlink(devlink_hdl, re, *minor_path)) != NULL)) {
			break;
		}
		di_devfs_path_free (*minor_path);
		*minor_path = NULL;
	}
	di_devlink_fini (&devlink_hdl);
}

static HalDevice *
devinfo_usb_scsa2usb_add(HalDevice *usbd, di_node_t node, gchar *devfs_path)
{
	HalDevice *d = NULL;
	di_devlink_handle_t devlink_hdl;
        int     major;
        di_minor_t minor;
        dev_t   devt;
        char    *minor_path = NULL;
	char	*devlink = NULL;
        char    udi[HAL_PATH_MAX];

	devinfo_add_enqueue (usbd, devfs_path, &devinfo_usb_handler);

	get_dev_link_path(node, "ddi_ctl:devctl:scsi", NULL,  &devlink, &minor_path);

	if ((devlink == NULL) || (minor_path == NULL)) {
		goto out;
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, usbd, node, minor_path);
       	hal_device_property_set_string (d, "scsi_host.solaris.device", devlink);
        hal_device_property_set_string (d, "info.category", "scsi_host");
        hal_device_property_set_int (d, "scsi_host.host", 0);

        hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
		"%s/scsi_host%d", hal_device_get_udi (usbd),
		hal_device_property_get_int (d, "scsi_host.host"));
        hal_device_set_udi (d, udi);
        hal_device_property_set_string (d, "info.udi", udi);
        hal_device_property_set_string (d, "info.product", "SCSI Host Adapter");

	devinfo_add_enqueue (d, minor_path, &devinfo_usb_handler);

out:
	if (devlink) {
		free(devlink);
	}
	if (minor_path) {
		di_devfs_path_free (minor_path);
	}

	return (d);
}

static HalDevice *
devinfo_usb_printer_add(HalDevice *parent, di_node_t node, gchar *devfs_path)
{
	HalDevice *d = NULL;
        char    udi[HAL_PATH_MAX];
	char *s;
	char *devlink = NULL, *minor_path = NULL;

	devinfo_add_enqueue (parent, devfs_path, &devinfo_usb_handler);

	get_dev_link_path(node, "ddi_printer", "printers/.+", &devlink, &minor_path);

	if ((devlink == NULL) || (minor_path == NULL)) {
		goto out;
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, minor_path);
        hal_device_property_set_string (d, "info.category", "printer");
	hal_device_add_capability (d, "printer");

	/* copy parent's usb_device.* properties */
	hal_device_merge_with_rewrite (d, parent, "usb.", "usb_device.");

	/* add printer properties */
        hal_device_property_set_string (d, "printer.device", devlink);
	PROP_STR(d, node, s, "usb-vendor-name", "printer.vendor");
	PROP_STR(d, node, s, "usb-product-name", "printer.product");
	PROP_STR(d, node, s, "usb-serialno", "printer.serial");

	devinfo_add_enqueue (d, minor_path, &devinfo_usb_printer_handler);

out:
	if (devlink) {
		free(devlink);
	}
	if (minor_path) {
		di_devfs_path_free (minor_path);
	}

	return (d);
}

const gchar *
devinfo_printer_prnio_get_prober (HalDevice *d, int *timeout)
{
	*timeout = 5 * 1000;	/* 5 second timeout */
	return ("hald-probe-printer");
}
