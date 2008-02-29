/***************************************************************************
 *
 * devinfo_pci.c : PCI devices
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

#include "../osspec.h"
#include "../logger.h"
#include "../hald.h"
#include "../hald_dbus.h"
#include "../device_info.h"
#include "../util.h"
#include "../ids.h"
#include "devinfo_pci.h"

HalDevice *devinfo_pci_add (HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);

DevinfoDevHandler devinfo_pci_handler = {
        devinfo_pci_add,
	NULL,
	NULL,
	NULL,
	NULL,
        NULL
};

HalDevice *devinfo_pci_add (HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	HalDevice *d;
	char	*s;
	int	*i;
	int	vid, pid, svid, spid;

	if ((device_type == NULL) ||
	    ((strcmp (device_type, "pci") != 0) &&
	    (strcmp (device_type, "pci-ide") != 0))) {
		if (parent == NULL) {
			return (NULL);
		} else {
			s = (char *)hal_device_property_get_string (parent, "info.subsystem");
			if ((s == NULL) || (strcmp (s, "pci") != 0)) {
				return (NULL);
			}
		}
	}

	d = hal_device_new ();
	devinfo_set_default_properties (d, parent, node, devfs_path);

	hal_device_property_set_string (d, "info.subsystem", "pci");

	vid = pid = svid = spid = 0;
        if (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "vendor-id", &i) > 0) {
		vid = i[0];
	}
        if (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "device-id", &i) > 0) {
		pid = i[0];
	}
        if (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "subsystem-vendor-id", &i) > 0) {
		svid = i[0];
	}
        if (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "subsystem-id", &i) > 0) {
		spid = i[0];
	}
	hal_device_property_set_int (d, "pci.vendor_id", vid);
	hal_device_property_set_int (d, "pci.product_id", pid);
	hal_device_property_set_int (d, "pci.subsys_vendor_id", svid);
	hal_device_property_set_int (d, "pci.subsys_product_id", spid);

        {
                char *vendor_name;
                char *product_name;
                char *subsys_vendor_name;
                char *subsys_product_name;

                ids_find_pci (hal_device_property_get_int (d, "pci.vendor_id"),
                              hal_device_property_get_int (d, "pci.product_id"),
                              hal_device_property_get_int (d, "pci.subsys_vendor_id"),
                              hal_device_property_get_int (d, "pci.subsys_product_id"),
                              &vendor_name, &product_name, &subsys_vendor_name,
&subsys_product_name);

                if (vendor_name != NULL) {
                        hal_device_property_set_string (d, "pci.vendor", vendor_name);
                        hal_device_property_set_string (d, "info.vendor", vendor_name);
                }

                if (product_name != NULL) {
                        hal_device_property_set_string (d, "pci.product", product_name);
                        hal_device_property_set_string (d, "info.product", product_name);
                }

                if (subsys_vendor_name != NULL) {
                        hal_device_property_set_string (d, "pci.subsys_vendor",
subsys_vendor_name);
                }

                if (subsys_product_name != NULL) {
                        hal_device_property_set_string (d, "pci.subsys_product", subsys_product_name);
                }
        }

	devinfo_add_enqueue (d, devfs_path, &devinfo_pci_handler);

	return (d);
}

