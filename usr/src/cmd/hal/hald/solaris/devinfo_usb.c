/***************************************************************************
 *
 * devinfo_usb.h : USB devices
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
#include <libdevinfo.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/usb/usbai.h>

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

static HalDevice *devinfo_usb_if_add(HalDevice *d, di_node_t node, gchar *devfs_path,
				     gchar *if_devfs_path, int ifnum);
static HalDevice *devinfo_usb_scsa2usb_add(HalDevice *d, di_node_t node);
static HalDevice *devinfo_usb_printer_add(HalDevice *usbd, di_node_t node);
static HalDevice *devinfo_usb_input_add(HalDevice *usbd, di_node_t node);
static HalDevice *devinfo_usb_video4linux_add(HalDevice *usbd, di_node_t node);
const gchar *devinfo_printer_prnio_get_prober(HalDevice *d, int *timeout);
const gchar *devinfo_keyboard_get_prober(HalDevice *d, int *timeout);
static void set_usb_properties(HalDevice *d, di_node_t node, gchar *devfs_path, char *driver_name);

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

DevinfoDevHandler devinfo_usb_keyboard_handler = {
	devinfo_usb_add,
	NULL,
	NULL,
	NULL,
	NULL,
	devinfo_keyboard_get_prober
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

static char *
get_usb_devlink(char *devfs_path, const char *dir_name)
{
	char *result = NULL;
	DIR *dp;

	if ((dp = opendir(dir_name)) != NULL) {
		struct dirent *ep;

		while ((ep = readdir(dp)) != NULL) {
			char path[MAXPATHLEN], lpath[MAXPATHLEN];

			strncpy(path, dir_name, strlen(dir_name));
			strncat(path, ep->d_name, strlen(ep->d_name));
			memset(lpath, 0, sizeof (lpath));
			if ((readlink(path, lpath, sizeof (lpath)) > 0) &&
			    (strstr(lpath, devfs_path) != NULL)) {
				result = strdup(path);
				break;
			}
			memset(path, 0, sizeof (path));
		}
		closedir(dp);
	}

	return (result);
}

HalDevice *
devinfo_usb_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	HalDevice *d, *nd = NULL;
	char	*s;
	int	*i;
	char	*driver_name, *binding_name;
	char	if_devfs_path[HAL_PATH_MAX];
	di_devlink_handle_t hdl;
	double	k;

	if (is_usb_node(node) == FALSE) {
		return (NULL);
	}

	driver_name = di_driver_name (node);

	if (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "interface", &i) < 0) {
		/* It is a USB device node. */

		d = hal_device_new ();

		devinfo_set_default_properties (d, parent, node, devfs_path);
		hal_device_property_set_string (d, "info.subsystem", "usb_device");
		PROP_STR(d, node, s, "usb-product-name", "info.product");
		PROP_STR(d, node, s, "usb-product-name", "usb_device.product");
		PROP_STR(d, node, s, "usb-vendor-name", "usb_device.vendor");
		PROP_INT(d, node, i, "usb-vendor-id", "usb_device.vendor_id");
		PROP_INT(d, node, i, "usb-product-id", "usb_device.product_id");
		PROP_INT(d, node, i, "usb-revision-id", "usb_device.device_revision_bcd");
		PROP_STR(d, node, s, "usb-serialno", "usb_device.serial");
		PROP_INT(d, node, i, "usb-port-count", "usb_device.num_ports");
		PROP_INT(d, node, i, "usb-num-configs", "usb_device.num_configurations");
		PROP_INT(d, node, i, "assigned-address", "usb_device.bus_number");

		if  (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "usb-release", &i) > 0) {
			k = (double)bcd(*i);
			hal_device_property_set_double (d, "usb_device.version", k / 100);
		}

		if (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "low-speed", &i) >= 0) {
			k = 1.5;
		} else if (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "high-speed", &i) >= 0) {
			k = 480.0;
		} else {
			/* It is the full speed device. */
			k = 12.0;
		}
		hal_device_property_set_double (d, "usb_device.speed", k);

		set_usb_properties (d, node, devfs_path, driver_name);

		/* wait for the ugen node's creation */
		if ((driver_name != NULL) && (strcmp (driver_name, "usb_mid") == 0)) {
			if (hdl = di_devlink_init (devfs_path, DI_MAKE_LINK)) {
				di_devlink_fini (&hdl);
			}
		}

		devinfo_add_enqueue (d, devfs_path, &devinfo_usb_handler);

		/* add to TDL so preprobing callouts and prober can access it */
		hal_device_store_add (hald_get_tdl (), d);

		if (((binding_name = di_binding_name (node)) != NULL) &&
		    (strncmp (binding_name, "usbif,", sizeof ("usbif,") - 1) == 0)) {

			snprintf (if_devfs_path, sizeof (if_devfs_path), "%s:if%d",
			    devfs_path, 0);
			if ((nd = devinfo_usb_if_add (d, node, if_devfs_path,
			    if_devfs_path, 0)) != NULL) {
				d = nd;
				nd = NULL;
				devfs_path = if_devfs_path;
			}
		}
	} else {
		/* It is a USB interface node or IA node. */
		int *j;

		if (di_prop_lookup_ints (DDI_DEV_T_ANY, node, "interface-count", &j) > 0) {
			/*
			 * The USB IA node properties are not defined in
			 * HAL spec so far. So IA node udi has "ia" sign
			 * now, different from the IF node udi with "if".
			 */
			snprintf (if_devfs_path, sizeof (if_devfs_path),
			    "%s:ia%d", devfs_path, *i);
		} else {
			snprintf (if_devfs_path, sizeof (if_devfs_path),
			    "%s:if%d", devfs_path, *i);
		}

		d = devinfo_usb_if_add (parent, node, devfs_path, if_devfs_path, *i);
	}

	/* driver specific */
	if (driver_name != NULL) {
		if (strcmp (driver_name, "scsa2usb") == 0) {
			nd = devinfo_usb_scsa2usb_add (d, node);
		} else if (strcmp (driver_name, "usbprn") == 0) {
			nd = devinfo_usb_printer_add (d, node);
		} else if (strcmp(driver_name, "hid") == 0) {
			if (hdl = di_devlink_init(devfs_path, DI_MAKE_LINK)) {
				di_devlink_fini(&hdl);
			}
			nd = devinfo_usb_input_add(d, node);
		} else if (strcmp(driver_name, "usbvc") == 0) {
			if (hdl = di_devlink_init(devfs_path, DI_MAKE_LINK)) {
				di_devlink_fini(&hdl);
			}
			nd = devinfo_usb_video4linux_add(d, node);
		}
	}

	if (nd != NULL) {
		return (nd);
	} else {
		return (d);
	}
}


static void
set_usb_properties(HalDevice *d, di_node_t node, gchar *devfs_path, char *driver_name)
{
	usb_dev_descr_t	*dev_descrp = NULL;	/* device descriptor */
	usb_cfg_descr_t	*cfg_descrp = NULL;	/* configuration descriptor */
	unsigned char	*rdata = NULL;
	char *p;
	int i = 0;

	hal_device_property_set_int (d, "usb_device.port_number",
	    atoi (devfs_path + strlen (devfs_path) -1));

	if (di_prop_lookup_bytes (DDI_DEV_T_ANY, node, "usb-dev-descriptor",
	    &rdata) > 0) {
		dev_descrp = (usb_dev_descr_t *)rdata;

		if (dev_descrp != NULL) {
			hal_device_property_set_int (d, "usb_device.device_class",
			    dev_descrp->bDeviceClass);
			hal_device_property_set_int (d, "usb_device.device_subclass",
			    dev_descrp->bDeviceSubClass);
			hal_device_property_set_int (d, "usb_device.device_protocol",
			    dev_descrp->bDeviceProtocol);
		}
	}

	if (di_prop_lookup_bytes (DDI_DEV_T_ANY, node, "usb-raw-cfg-descriptors",
	    &rdata) > 0) {
		cfg_descrp = (usb_cfg_descr_t *)(rdata);

		if (cfg_descrp != NULL) {
			hal_device_property_set_int (d, "usb_device.configuration_value",
			    cfg_descrp->bConfigurationValue);
			hal_device_property_set_int (d, "usb_device.max_power",
			    cfg_descrp->bMaxPower);
			hal_device_property_set_int (d, "usb_device.num_interfaces",
			    cfg_descrp->bNumInterfaces);
			hal_device_property_set_bool (d, "usb_device.can_wake_up",
			    (cfg_descrp->bmAttributes & 0x20) ? TRUE : FALSE);
			hal_device_property_set_bool (d, "usb_device.is_self_powered",
			    (cfg_descrp->bmAttributes & 0x40) ? TRUE : FALSE);
		}
	}

	/* get the node's usb tree level by counting hub numbers */
	do {
		if (p = strstr (devfs_path, "/hub@")) {
			devfs_path = p + strlen ("/hub@");
			i ++;
		}
	} while (p != NULL);

	if ((driver_name != NULL) && (strcmp (driver_name, "hubd") == 0) && (i > 0))
		i --;

	hal_device_property_set_int (d, "usb_device.level_number", i);
}


static usb_if_descr_t *
parse_usb_if_descr(di_node_t node, int ifnum)
{
	unsigned char	*rdata = NULL;
	usb_if_descr_t	*if_descrp=NULL;	/* interface descriptor */
	di_node_t	tmp_node = DI_NODE_NIL;
	uint8_t num, length, type;
	int rlen;
	gchar *devpath = NULL;

	if ((rlen = di_prop_lookup_bytes (DDI_DEV_T_ANY, node,
	     "usb-raw-cfg-descriptors", &rdata)) < 0) {

		char *p;
		int i;

		if ((devpath = di_devfs_path (node)) == NULL)
			goto out;

		/* Look up its parent that may be a USB IA or USB mid. */
		for (i = 0; i < 2; i++) {
			p = strrchr (devpath, '/');
			if (p == NULL)
				goto out;
			*p = '\0';

			if ((tmp_node = di_init (devpath, DINFOCPYALL)) == DI_NODE_NIL)
				goto out;

			if ((rlen = di_prop_lookup_bytes (DDI_DEV_T_ANY, tmp_node,
			     "usb-raw-cfg-descriptors", &rdata)) > 0)
				break;

			di_fini (tmp_node);
		}
	}

	if (rdata == NULL)
		goto out;

	do {
		length = (uint8_t)*rdata;
		type = (uint8_t)*(rdata + 1);
		if (type == USB_DESCR_TYPE_IF) {
			num = (uint8_t)*(rdata + 2);
			if (num == ifnum) {
				if_descrp = (usb_if_descr_t *)rdata;
				break;
			}
		}
		rdata += length;
		rlen -= length;
	} while ((length > 0 ) && (rlen > 0));

out:
	if (devpath != NULL)
		di_devfs_path_free (devpath);
	if (tmp_node != DI_NODE_NIL)
		di_fini (tmp_node);
	return (if_descrp);
}


static HalDevice *
devinfo_usb_if_add(HalDevice *parent, di_node_t node, gchar *devfs_path,
		   gchar *if_devfs_path, int ifnum)
{
	HalDevice	*d = NULL;
	char		udi[HAL_PATH_MAX];
	const char	*parent_info;
	usb_if_descr_t	*if_descrp=NULL;	/* interface descriptor */

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, if_devfs_path);

	/* Set the existed physical device path. */
	hal_device_property_set_string (d, "solaris.devfs_path", devfs_path);
	hal_device_property_set_string (d, "info.subsystem", "usb");
	hal_device_property_set_string (d, "info.product", "USB Device Interface");

	/* Set usb interface properties to interface node. */
	if (strstr (if_devfs_path, ":ia") == NULL) {
		if_descrp = parse_usb_if_descr (node, ifnum);

		if (if_descrp != NULL) {
			hal_device_property_set_int (d, "usb.interface.class",
			    if_descrp->bInterfaceClass);
			hal_device_property_set_int (d, "usb.interface.subclass",
			    if_descrp->bInterfaceSubClass);
			hal_device_property_set_int (d, "usb.interface.protocol",
			    if_descrp->bInterfaceProtocol);
			hal_device_property_set_int (d, "usb.interface.number",
			    if_descrp->bInterfaceNumber);
		}
	}

	/* copy parent's usb_device.* properties */
	parent_info = hal_device_property_get_string (parent, "info.subsystem");
	if (parent_info != NULL) {
		if (strcmp (parent_info, "usb_device") == 0) {
			hal_device_merge_with_rewrite (d, parent, "usb.", "usb_device.");
		} else if (strcmp (parent_info, "usb") == 0) {
			/* for the case that the parent is IA node */
			hal_device_merge_with_rewrite (d, parent, "usb.", "usb.");
		}
	}

	devinfo_add_enqueue (d, devfs_path, &devinfo_usb_handler);

	/* add to TDL so preprobing callouts and prober can access it */
	hal_device_store_add (hald_get_tdl (), d);

	return (d);
}


static void
get_dev_link_path(di_node_t node, char *nodetype, char *re, char **devlink, char **minor_path, char **minor_name)
{
	di_devlink_handle_t devlink_hdl;
	int	major;
	di_minor_t minor;
	dev_t	devt;

	*devlink = NULL;
	*minor_path = NULL;
	*minor_name = NULL;

	if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL) {
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

		if (strcmp(di_minor_nodetype(minor), nodetype) == 0) {
			*devlink = get_devlink(devlink_hdl, re, *minor_path);
			/*
			 * During hotplugging, devlink could be NULL for usb
			 * devices due to devlink database has not yet been
			 * updated when hal try to read from it although the
			 * actually dev link path has been created. In such a
			 * situation, we will read the devlink name from
			 * /dev/usb directory.
			 */
			if ((*devlink == NULL) && (re != NULL) &&
			    ((strstr(re, "hid") != NULL) || (strstr(re, "video") != NULL))) {
				*devlink = get_usb_devlink(*minor_path, "/dev/usb/");
			}

			if (*devlink != NULL) {
				*minor_name = di_minor_name(minor);
				break;
			}
		}

		di_devfs_path_free (*minor_path);
		*minor_path = NULL;
	}
	di_devlink_fini (&devlink_hdl);
}

static HalDevice *
devinfo_usb_video4linux_add(HalDevice *usbd, di_node_t node)
{
	HalDevice *d = NULL;
	int	major;
	di_minor_t minor;
	dev_t	devt;
	char	*devlink = NULL;
	char	*dev_videolink = NULL;
	char	*minor_path = NULL;
	char	*minor_name = NULL;
	char	udi[HAL_PATH_MAX];
	char	*s;

	get_dev_link_path(node, "usb_video",
	    "^usb/video[0-9]+",  &devlink, &minor_path, &minor_name);

	if ((minor_path == NULL) || (devlink == NULL)) {

		goto out;
	}

	HAL_DEBUG(("devlink %s, minor_name %s", devlink, minor_name));
	if (strcmp(minor_name, "usbvc") != 0) {

		goto out;
	}

	d = hal_device_new();

	devinfo_set_default_properties(d, usbd, node, minor_path);
	hal_device_property_set_string(d, "info.subsystem", "video4linux");
	hal_device_property_set_string(d, "info.category", "video4linux");

	hal_device_add_capability(d, "video4linux");

	/* Get logic link under /dev (/dev/video+) */
	dev_videolink = get_usb_devlink(strstr(devlink, "usb"), "/dev/");

	hal_device_property_set_string(d, "video4linux.device", dev_videolink);

	hal_util_compute_udi(hald_get_gdl(), udi, sizeof (udi),
	    "%s_video4linux", hal_device_get_udi(usbd));

	hal_device_set_udi(d, udi);
	hal_device_property_set_string(d, "info.udi", udi);
	PROP_STR(d, node, s, "usb-product-name", "info.product");

	devinfo_add_enqueue(d, minor_path, &devinfo_usb_handler);


out:
	if (devlink) {
		free(devlink);
	}

	if (minor_path) {
		di_devfs_path_free(minor_path);
	}

	return (d);
}

static HalDevice *
devinfo_usb_input_add(HalDevice *usbd, di_node_t node)
{
	HalDevice *d = NULL;
	int	major;
	di_minor_t minor;
	dev_t	devt;
	char	*devlink = NULL;
	char	*minor_path = NULL;
	char	*minor_name = NULL;
	char	udi[HAL_PATH_MAX];

	get_dev_link_path(node, "ddi_pseudo",
	    "^usb/hid[0-9]+",  &devlink, &minor_path, &minor_name);

	if ((minor_path == NULL) || (devlink == NULL)) {

		goto out;
	}

	HAL_DEBUG(("devlink %s, minor_name %s", devlink, minor_name));
	if ((strcmp(minor_name, "keyboard") != 0) &&
	    (strcmp(minor_name, "mouse") != 0)) {

		goto out;
	}

	d = hal_device_new();

	devinfo_set_default_properties(d, usbd, node, minor_path);
	hal_device_property_set_string(d, "info.subsystem", "input");
	hal_device_property_set_string(d, "info.category", "input");

	hal_device_add_capability(d, "input");

	if (strcmp(minor_name, "keyboard") == 0) {
		hal_device_add_capability(d, "input.keyboard");
		hal_device_add_capability(d, "input.keys");
		hal_device_add_capability(d, "button");
	} else if (strcmp(minor_name, "mouse") == 0) {
		hal_device_add_capability (d, "input.mouse");
	}

	hal_device_property_set_string(d, "input.device", devlink);
	hal_device_property_set_string(d, "input.originating_device",
	    hal_device_get_udi(usbd));

	hal_util_compute_udi(hald_get_gdl(), udi, sizeof (udi),
	    "%s_logicaldev_input", hal_device_get_udi(usbd));

	hal_device_set_udi(d, udi);
	hal_device_property_set_string(d, "info.udi", udi);

	if (strcmp(minor_name, "keyboard") == 0) {
		devinfo_add_enqueue(d, minor_path, &devinfo_usb_keyboard_handler);
	} else {
		devinfo_add_enqueue(d, minor_path, &devinfo_usb_handler);
	}

	/* add to TDL so preprobing callouts and prober can access it */
	hal_device_store_add(hald_get_tdl(), d);

out:
	if (devlink) {
		free(devlink);
	}

	if (minor_path) {
		di_devfs_path_free(minor_path);
	}

	return (d);
}

static HalDevice *
devinfo_usb_scsa2usb_add(HalDevice *usbd, di_node_t node)
{
	HalDevice *d = NULL;
	di_devlink_handle_t devlink_hdl;
	int	major;
	di_minor_t minor;
	dev_t	devt;
	char	*minor_path = NULL;
	char	*minor_name = NULL;
	char	*devlink = NULL;
	char	udi[HAL_PATH_MAX];

	get_dev_link_path(node, "ddi_ctl:devctl:scsi",
	    "^usb/mass-storage[0-9]+", &devlink, &minor_path, &minor_name);

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
devinfo_usb_printer_add(HalDevice *parent, di_node_t node)
{
	char *properties[] = { "vendor", "product", "serial", NULL };
	int i;
	HalDevice *d = NULL;
	char	udi[HAL_PATH_MAX];
	char *s;
	char *devlink = NULL, *minor_path = NULL, *minor_name = NULL;
	const char	*subsystem;

	get_dev_link_path(node, "ddi_printer", "printers/.+", &devlink, &minor_path, &minor_name);

	if ((devlink == NULL) || (minor_path == NULL)) {
		goto out;
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, minor_path);
	hal_device_property_set_string (d, "info.category", "printer");
	hal_device_add_capability (d, "printer");

	/* add printer properties */
	hal_device_property_set_string (d, "printer.device", devlink);

	/* copy parent's selected usb* properties to printer properties */
	subsystem = hal_device_property_get_string (parent, "info.subsystem");
	for (i = 0; properties[i] != NULL; i++) {
		char src[32], dst[32]; /* "subsystem.property" names */

		snprintf(src, sizeof (src), "%s.%s", subsystem, properties[i]);
		snprintf(dst, sizeof (dst), "printer.%s", properties[i]);
		hal_device_copy_property(parent, src, d, dst);
	}

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

const gchar *
devinfo_keyboard_get_prober(HalDevice *d, int *timeout)
{
	*timeout = 5 * 1000;	/* 5 second timeout */
	return ("hald-probe-xkb");
}
