/***************************************************************************
 *
 * devinfo_storage.c : storage devices
 *
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <libdevinfo.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>

#include "../osspec.h"
#include "../logger.h"
#include "../hald.h"
#include "../hald_dbus.h"
#include "../device_info.h"
#include "../util.h"
#include "../hald_runner.h"
#include "hotplug.h"
#include "devinfo.h"
#include "devinfo_misc.h"
#include "devinfo_storage.h"
#include "osspec_solaris.h"

#ifdef sparc
#define	WHOLE_DISK	"s2"
#else
#define	WHOLE_DISK	"p0"
#endif

/* some devices,especially CDROMs, may take a while to be probed (values in ms) */
#define	DEVINFO_PROBE_STORAGE_TIMEOUT	60000
#define	DEVINFO_PROBE_VOLUME_TIMEOUT	60000

typedef struct devinfo_storage_minor {
	char	*devpath;
	char	*devlink;
	char	*slice;
	dev_t	dev;
	int	dosnum;	/* dos disk number or -1 */
} devinfo_storage_minor_t;

HalDevice *devinfo_ide_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);
static HalDevice *devinfo_ide_host_add(HalDevice *parent, di_node_t node, char *devfs_path);
static HalDevice *devinfo_ide_device_add(HalDevice *parent, di_node_t node, char *devfs_path);
static HalDevice *devinfo_ide_storage_add(HalDevice *parent, di_node_t node, char *devfs_path);
HalDevice *devinfo_scsi_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);
static HalDevice *devinfo_scsi_storage_add(HalDevice *parent, di_node_t node, char *devfs_path);
HalDevice *devinfo_blkdev_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);
static HalDevice *devinfo_blkdev_storage_add(HalDevice *parent, di_node_t node, char *devfs_path);
HalDevice *devinfo_floppy_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);
static void devinfo_floppy_add_volume(HalDevice *parent, di_node_t node);
static HalDevice *devinfo_lofi_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type);
static void devinfo_lofi_add_minor(HalDevice *parent, di_node_t node, char *minor_path, char *devlink, dev_t dev);
static void devinfo_storage_minors(HalDevice *parent, di_node_t node, gchar *devfs_path, gboolean);
static struct devinfo_storage_minor *devinfo_storage_new_minor(char *maindev_path, char *slice,
    char *devlink, dev_t dev, int dosnum);
static void devinfo_storage_free_minor(struct devinfo_storage_minor *m);
HalDevice *devinfo_volume_add(HalDevice *parent, di_node_t node, devinfo_storage_minor_t *m);
static void devinfo_volume_preprobing_done(HalDevice *d, gpointer userdata1, gpointer userdata2);
static void devinfo_volume_hotplug_begin_add (HalDevice *d, HalDevice *parent, DevinfoDevHandler *handler, void *end_token);
static void devinfo_storage_hotplug_begin_add (HalDevice *d, HalDevice *parent, DevinfoDevHandler *handler, void *end_token);
static void devinfo_storage_probing_done (HalDevice *d, guint32 exit_type, gint return_code, char **error, gpointer userdata1, gpointer userdata2);
const gchar *devinfo_volume_get_prober (HalDevice *d, int *timeout);
const gchar *devinfo_storage_get_prober (HalDevice *d, int *timeout);

static char *devinfo_scsi_dtype2str(int dtype);
static char *devinfo_volume_get_slice_name (char *devlink);
static gboolean dos_to_dev(char *path, char **devpath, int *partnum);
static gboolean is_dos_path(char *path, int *partnum);

static void devinfo_storage_set_nicknames (HalDevice *d);

DevinfoDevHandler devinfo_ide_handler = {
        devinfo_ide_add,
	NULL,
	NULL,
	NULL,
	NULL,
        NULL
};
DevinfoDevHandler devinfo_scsi_handler = {
        devinfo_scsi_add,
	NULL,
	NULL,
	NULL,
	NULL,
        NULL
};
DevinfoDevHandler devinfo_blkdev_handler = {
        devinfo_blkdev_add,
	NULL,
	NULL,
	NULL,
	NULL,
        NULL
};
DevinfoDevHandler devinfo_floppy_handler = {
        devinfo_floppy_add,
	NULL,
	NULL,
	NULL,
	NULL,
        NULL
};
DevinfoDevHandler devinfo_lofi_handler = {
        devinfo_lofi_add,
	NULL,
	NULL,
	NULL,
	NULL,
        NULL
};
DevinfoDevHandler devinfo_storage_handler = {
	NULL,
	NULL,
	devinfo_storage_hotplug_begin_add,
	NULL,
	devinfo_storage_probing_done,
	devinfo_storage_get_prober
};
DevinfoDevHandler devinfo_volume_handler = {
	NULL,
	NULL,
	devinfo_volume_hotplug_begin_add,
	NULL,
	NULL,
	devinfo_volume_get_prober
};

/* IDE */

HalDevice *
devinfo_ide_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	char	*s;

	if ((device_type != NULL) && (strcmp(device_type, "ide") == 0)) {
		return (devinfo_ide_host_add(parent, node, devfs_path));
	}

        if ((di_prop_lookup_strings (DDI_DEV_T_ANY, node, "class", &s) > 0) &&
	    (strcmp (s, "dada") == 0)) {
		return (devinfo_ide_device_add(parent, node, devfs_path));
	}

	return (NULL);
}

static HalDevice *
devinfo_ide_host_add(HalDevice *parent, di_node_t node, char *devfs_path)
{
	HalDevice *d;

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
	hal_device_property_set_string (d, "info.product", "IDE host controller");
	hal_device_property_set_string (d, "info.subsystem", "ide_host");
	hal_device_property_set_int (d, "ide_host.number", 0); /* XXX */

	devinfo_add_enqueue (d, devfs_path, &devinfo_ide_handler);

	return (d);
}

static HalDevice *
devinfo_ide_device_add(HalDevice *parent, di_node_t node, char *devfs_path)
{
	HalDevice *d;

	d = hal_device_new();

	devinfo_set_default_properties (d, parent, node, devfs_path);
        hal_device_property_set_string (parent, "info.product", "IDE device");
	hal_device_property_set_string (parent, "info.subsystem", "ide");
	hal_device_property_set_int (parent, "ide.host", 0); /* XXX */
	hal_device_property_set_int (parent, "ide.channel", 0);

	devinfo_add_enqueue (d, devfs_path, &devinfo_ide_handler);

	return (devinfo_ide_storage_add (d, node, devfs_path));
}

static HalDevice *
devinfo_ide_storage_add(HalDevice *parent, di_node_t node, char *devfs_path)
{
	HalDevice *d;
	char	*s;
	int	*i;
	char	*driver_name;
	char	udi[HAL_PATH_MAX];

	if ((driver_name = di_driver_name (node)) == NULL) {
		return (NULL);
	}

        d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
        hal_device_property_set_string (d, "info.category", "storage");

        hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
                "%s/%s%d", hal_device_get_udi (parent), driver_name, di_instance (node));
        hal_device_set_udi (d, udi);
        hal_device_property_set_string (d, "info.udi", udi);
	PROP_STR(d, node, s, "devid", "info.product");

        hal_device_add_capability (d, "storage");
        hal_device_property_set_string (d, "storage.bus", "ide");
        hal_device_property_set_int (d, "storage.lun", 0);
	hal_device_property_set_string (d, "storage.drive_type", "disk");

	PROP_BOOL(d, node, i, "hotpluggable", "storage.hotpluggable");
	PROP_BOOL(d, node, i, "removable-media", "storage.removable");

        hal_device_property_set_bool (d, "storage.media_check_enabled", FALSE);

	/* XXX */
        hal_device_property_set_bool (d, "storage.requires_eject", FALSE);

	hal_device_add_capability (d, "block");

	devinfo_storage_minors (d, node, (char *)devfs_path, FALSE);

	return (d);
}

/* SCSI */

HalDevice *
devinfo_scsi_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	int	*i;
	char	*driver_name;
	HalDevice *d;
	char	udi[HAL_PATH_MAX];

	driver_name = di_driver_name (node);
	if ((driver_name == NULL) || (strcmp (driver_name, "sd") != 0)) {
		return (NULL);
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
	hal_device_property_set_string (d, "info.subsystem", "scsi");

        hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
                "%s/%s%d", hal_device_get_udi (parent), di_node_name(node), di_instance (node));
        hal_device_set_udi (d, udi);
        hal_device_property_set_string (d, "info.udi", udi);

	hal_device_property_set_int (d, "scsi.host", 
		hal_device_property_get_int (parent, "scsi_host.host"));
	hal_device_property_set_int (d, "scsi.bus", 0);
	PROP_INT(d, node, i, "target", "scsi.target");
	PROP_INT(d, node, i, "lun", "scsi.lun");
        hal_device_property_set_string (d, "info.product", "SCSI Device");

        devinfo_add_enqueue (d, devfs_path, &devinfo_scsi_handler);

        return (devinfo_scsi_storage_add (d, node, devfs_path));
}

static HalDevice *
devinfo_scsi_storage_add(HalDevice *parent, di_node_t node, char *devfs_path)
{
	HalDevice *d;
	int	*i;
	char	*s;
	char	udi[HAL_PATH_MAX];

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
        hal_device_property_set_string (d, "info.category", "storage");

        hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
		"%s/sd%d", hal_device_get_udi (parent), di_instance (node));
        hal_device_set_udi (d, udi);
        hal_device_property_set_string (d, "info.udi", udi);
	PROP_STR(d, node, s, "inquiry-product-id", "info.product");

        hal_device_add_capability (d, "storage");

        hal_device_property_set_int (d, "storage.lun",
		hal_device_property_get_int (parent, "scsi.lun"));
	PROP_BOOL(d, node, i, "hotpluggable", "storage.hotpluggable");
	PROP_BOOL(d, node, i, "removable-media", "storage.removable");
        hal_device_property_set_bool (d, "storage.requires_eject", FALSE);

	/*
	 * We have to enable polling not only for drives with removable media,
	 * but also for hotpluggable devices, because when a disk is
	 * unplugged while busy/mounted, there is not sysevent generated.
	 * Instead, the HBA driver (scsa2usb, scsa1394) will notify sd driver
	 * and the latter will report DKIO_DEV_GONE via DKIOCSTATE ioctl.
	 * So we have to enable media check so that hald-addon-storage notices
	 * the "device gone" condition and unmounts all associated volumes.
	 */
	hal_device_property_set_bool (d, "storage.media_check_enabled",
	    ((di_prop_lookup_ints(DDI_DEV_T_ANY, node, "removable-media", &i) >= 0) ||
	    (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "hotpluggable", &i) >= 0)));

        if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "inquiry-device-type",
	    &i) > 0) {
		s = devinfo_scsi_dtype2str (*i);
        	hal_device_property_set_string (d, "storage.drive_type", s);

		if (strcmp (s, "cdrom") == 0) {
			hal_device_add_capability (d, "storage.cdrom");
			hal_device_property_set_bool (d, "storage.no_partitions_hint", TRUE);
        		hal_device_property_set_bool (d, "storage.requires_eject", TRUE);
		}
	}

        hal_device_add_capability (d, "block");

	devinfo_storage_minors (d, node, devfs_path, FALSE);

	return (d);
}

static char *
devinfo_scsi_dtype2str(int dtype)
{
        char *dtype2str[] = {
                "disk"	,         /* DTYPE_DIRECT         0x00 */
                "tape"	,         /* DTYPE_SEQUENTIAL     0x01 */
                "printer",         /* DTYPE_PRINTER        0x02 */
                "processor",         /* DTYPE_PROCESSOR      0x03 */
                "worm"	,         /* DTYPE_WORM           0x04 */
                "cdrom"	,         /* DTYPE_RODIRECT       0x05 */
                "scanner",         /* DTYPE_SCANNER        0x06 */
                "cdrom"	,         /* DTYPE_OPTICAL        0x07 */
                "changer",         /* DTYPE_CHANGER        0x08 */
                "comm"	,         /* DTYPE_COMM           0x09 */
                "scsi"	,         /* DTYPE_???            0x0A */
                "scsi"	,         /* DTYPE_???            0x0B */
                "array_ctrl",         /* DTYPE_ARRAY_CTRL     0x0C */
                "esi"	,         /* DTYPE_ESI            0x0D */
                "disk"	          /* DTYPE_RBC            0x0E */
        };

        if (dtype < NELEM(dtype2str)) {
                return (dtype2str[dtype]);
        } else {
		return ("scsi");
        }

}

/* blkdev */

HalDevice *
devinfo_blkdev_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	int	*i;
	char	*driver_name;
	HalDevice *d;
	char	udi[HAL_PATH_MAX];

	driver_name = di_driver_name (node);
	if ((driver_name == NULL) || (strcmp (driver_name, "blkdev") != 0)) {
		return (NULL);
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
	hal_device_property_set_string (d, "info.subsystem", "pseudo");

        hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
                "%s/%s%d", hal_device_get_udi (parent), di_node_name(node), di_instance (node));
        hal_device_set_udi (d, udi);
        hal_device_property_set_string (d, "info.udi", udi);
        hal_device_property_set_string (d, "info.product", "Block Device");

        devinfo_add_enqueue (d, devfs_path, &devinfo_blkdev_handler);

        return (devinfo_blkdev_storage_add (d, node, devfs_path));
}

static HalDevice *
devinfo_blkdev_storage_add(HalDevice *parent, di_node_t node, char *devfs_path)
{
	HalDevice *d;
	char	*driver_name;
	int	*i;
	char	*s;
	char	udi[HAL_PATH_MAX];

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
	hal_device_property_set_string (d, "info.category", "storage");

	hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
		"%s/blkdev%d", hal_device_get_udi (parent), di_instance (node));
	hal_device_set_udi (d, udi);
	hal_device_property_set_string (d, "info.udi", udi);

	hal_device_add_capability (d, "storage");

	hal_device_property_set_int (d, "storage.lun", 0);

	PROP_BOOL(d, node, i, "hotpluggable", "storage.hotpluggable");
	PROP_BOOL(d, node, i, "removable-media", "storage.removable");

	hal_device_property_set_bool (d, "storage.requires_eject", FALSE);
	hal_device_property_set_bool (d, "storage.media_check_enabled", TRUE);
       	hal_device_property_set_string (d, "storage.drive_type", "disk");

	hal_device_add_capability (d, "block");

	devinfo_storage_minors (d, node, devfs_path, FALSE);

	return (d);
}

/* floppy */

HalDevice *
devinfo_floppy_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	char	*driver_name;
	char	*raw;
	char	udi[HAL_PATH_MAX];
	di_devlink_handle_t devlink_hdl;
        int     major;
        di_minor_t minor;
        dev_t   dev;
	HalDevice *d = NULL;
        char    *minor_path = NULL;
	char	*devlink = NULL;

	driver_name = di_driver_name (node);
	if ((driver_name == NULL) || (strcmp (driver_name, "fd") != 0)) {
		return (NULL);
	}

	/*
	 * The only minor node we're interested in is /dev/diskette*
	 */
	major = di_driver_major(node);
	if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL) {
		return (NULL);
	}
	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		dev = di_minor_devt(minor);
		if ((major != major(dev)) ||
		    (di_minor_type(minor) != DDM_MINOR) ||
		    (di_minor_spectype(minor) != S_IFBLK) ||
		    ((minor_path = di_devfs_minor_path(minor)) == NULL)) {
			continue;
		}
		if ((devlink = get_devlink(devlink_hdl, "diskette.+" , minor_path)) != NULL) {
			break;
		}
		di_devfs_path_free (minor_path);
		minor_path = NULL;
		free(devlink);
		devlink = NULL;
	}
	di_devlink_fini (&devlink_hdl);

	if ((devlink == NULL) || (minor_path == NULL)) {
		HAL_INFO (("floppy devlink not found %s", devfs_path));
		goto out;
	}

	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
        hal_device_property_set_string (d, "info.category", "storage");
        hal_device_add_capability (d, "storage");
       	hal_device_property_set_string (d, "storage.bus", "platform");
        hal_device_property_set_bool (d, "storage.hotpluggable", FALSE);
        hal_device_property_set_bool (d, "storage.removable", TRUE);
        hal_device_property_set_bool (d, "storage.requires_eject", TRUE);
        hal_device_property_set_bool (d, "storage.media_check_enabled", FALSE);
       	hal_device_property_set_string (d, "storage.drive_type", "floppy");

        hal_device_add_capability (d, "block");
	hal_device_property_set_bool (d, "block.is_volume", FALSE);
	hal_device_property_set_int (d, "block.major", major(dev));
	hal_device_property_set_int (d, "block.minor", minor(dev));
	hal_device_property_set_string (d, "block.device", devlink);
	raw = dsk_to_rdsk (devlink);
	hal_device_property_set_string (d, "block.solaris.raw_device", raw);
	free (raw);

	devinfo_add_enqueue (d, devfs_path, &devinfo_storage_handler);

	/* trigger initial probe-volume */
	devinfo_floppy_add_volume(d, node);

out:
	di_devfs_path_free (minor_path);
	free(devlink);

	return (d);
}

static void
devinfo_floppy_add_volume(HalDevice *parent, di_node_t node)
{
	char	*devlink;
	char	*devfs_path;
	int	minor, major;
	dev_t	dev;
	struct devinfo_storage_minor *m;

	devfs_path = (char *)hal_device_property_get_string (parent, "solaris.devfs_path");
	devlink = (char *)hal_device_property_get_string (parent, "block.device");
	major = hal_device_property_get_int (parent, "block.major");
	minor = hal_device_property_get_int (parent, "block.minor");
	dev = makedev (major, minor);

	m = devinfo_storage_new_minor (devfs_path, WHOLE_DISK, devlink, dev, -1);
	devinfo_volume_add (parent, node, m);
	devinfo_storage_free_minor (m);
}

/*
 * After reprobing storage, reprobe its volumes.
 */
static void
devinfo_floppy_rescan_probing_done (HalDevice *d, guint32 exit_type, gint return_code,
    char **error, gpointer userdata1, gpointer userdata2)
{
        void *end_token = (void *) userdata1;
	const char *devfs_path;
	di_node_t node;
	HalDevice *v;

	if (!hal_device_property_get_bool (d, "storage.removable.media_available")) {
		HAL_INFO (("no floppy media", hal_device_get_udi (d)));

		/* remove child (can only be single volume) */
		if (((v = hal_device_store_match_key_value_string (hald_get_gdl(),
        	    "info.parent", hal_device_get_udi (d))) != NULL) &&
		    ((devfs_path = hal_device_property_get_string (v,
		    "solaris.devfs_path")) != NULL)) {
			devinfo_remove_enqueue ((char *)devfs_path, NULL);
		}
	} else {
		HAL_INFO (("floppy media found", hal_device_get_udi (d)));

		if ((devfs_path = hal_device_property_get_string(d, "solaris.devfs_path")) == NULL) {
			HAL_INFO (("no devfs_path", hal_device_get_udi (d)));
			hotplug_event_process_queue ();
			return;
		}
		if ((node = di_init (devfs_path, DINFOCPYALL)) == DI_NODE_NIL) {
			HAL_INFO (("di_init %s failed %d", devfs_path, errno));
			hotplug_event_process_queue ();
			return;
		}

		devinfo_floppy_add_volume (d, node);

		di_fini (node);
	}

	hotplug_event_process_queue ();
}
	
/* lofi */

HalDevice *
devinfo_lofi_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{
	return (devinfo_lofi_add_major(parent,node, devfs_path, device_type, FALSE, NULL));
}

HalDevice *
devinfo_lofi_add_major(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type,
    gboolean rescan, HalDevice *lofi_d)
{
	char	*driver_name;
	HalDevice *d = NULL;
	char	udi[HAL_PATH_MAX];
	di_devlink_handle_t devlink_hdl;
        int     major;
        di_minor_t minor;
        dev_t   dev;
        char    *minor_path = NULL;
        char    *devlink = NULL;

	driver_name = di_driver_name (node);
	if ((driver_name == NULL) || (strcmp (driver_name, "lofi") != 0)) {
		return (NULL);
	}

	if (!rescan) {
		d = hal_device_new ();

		devinfo_set_default_properties (d, parent, node, devfs_path);
		hal_device_property_set_string (d, "info.subsystem", "pseudo");

        	hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
                	"%s/%s%d", hal_device_get_udi (parent), di_node_name(node), di_instance (node));
        	hal_device_set_udi (d, udi);
        	hal_device_property_set_string (d, "info.udi", udi);

        	devinfo_add_enqueue (d, devfs_path, &devinfo_lofi_handler);
	} else {
		d = lofi_d;
	}

	/*
	 * Unlike normal storage, as in devinfo_storage_minors(), where
	 * sd instance -> HAL storage, sd minor node -> HAL volume,
	 * lofi always has one instance, lofi minor -> HAL storage.
	 * lofi storage never has slices, but it can have
	 * embedded pcfs partitions that fstyp would recognize
	 */
	major = di_driver_major(node);
	if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL) {
		return (d);
	}
	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		dev = di_minor_devt(minor);
		if ((major != major(dev)) ||
		    (di_minor_type(minor) != DDM_MINOR) ||
		    (di_minor_spectype(minor) != S_IFBLK) ||
		    ((minor_path = di_devfs_minor_path(minor)) == NULL)) {
			continue;
		}
		if ((devlink = get_devlink(devlink_hdl, NULL, minor_path)) == NULL) {
			di_devfs_path_free (minor_path);
        		continue;
		}

		if (!rescan ||
		    (hal_device_store_match_key_value_string (hald_get_gdl (),
		    "solaris.devfs_path", minor_path) == NULL)) {
			devinfo_lofi_add_minor(d, node, minor_path, devlink, dev);
		}

		di_devfs_path_free (minor_path);
		free(devlink);
	}
	di_devlink_fini (&devlink_hdl);

	return (d);
}

static void
devinfo_lofi_add_minor(HalDevice *parent, di_node_t node, char *minor_path, char *devlink, dev_t dev)
{
	HalDevice *d;
	char	*raw;
	char	*doslink;
	char	dospath[64];
	struct devinfo_storage_minor *m;
	int	i;

	/* add storage */
	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, minor_path);
        hal_device_property_set_string (d, "info.category", "storage");
        hal_device_add_capability (d, "storage");
       	hal_device_property_set_string (d, "storage.bus", "lofi");
        hal_device_property_set_bool (d, "storage.hotpluggable", TRUE);
        hal_device_property_set_bool (d, "storage.removable", FALSE);
        hal_device_property_set_bool (d, "storage.requires_eject", FALSE);
       	hal_device_property_set_string (d, "storage.drive_type", "disk");
        hal_device_add_capability (d, "block");
	hal_device_property_set_int (d, "block.major", major(dev));
	hal_device_property_set_int (d, "block.minor", minor(dev));
	hal_device_property_set_string (d, "block.device", devlink);
	raw = dsk_to_rdsk (devlink);
	hal_device_property_set_string (d, "block.solaris.raw_device", raw);
	free (raw);
	hal_device_property_set_bool (d, "block.is_volume", FALSE);

	devinfo_add_enqueue (d, minor_path, &devinfo_storage_handler);

	/* add volumes: one on main device and a few pcfs candidates */
	m = devinfo_storage_new_minor(minor_path, WHOLE_DISK, devlink, dev, -1);
	devinfo_volume_add (d, node, m);
	devinfo_storage_free_minor (m);

	doslink = (char *)calloc (1, strlen (devlink) + sizeof (":NNN") + 1);
	if (doslink != NULL) {
		for (i = 1; i < 16; i++) {
			snprintf(dospath, sizeof (dospath), WHOLE_DISK":%d", i);
			sprintf(doslink, "%s:%d", devlink, i);
			m = devinfo_storage_new_minor(minor_path, dospath, doslink, dev, i);
			devinfo_volume_add (d, node, m);
			devinfo_storage_free_minor (m);
		}
		free (doslink);
	}
}

void
devinfo_lofi_remove_minor(char *parent_devfs_path, char *name)
{
	GSList *i;
	GSList *devices;
	HalDevice *d = NULL;
	const char *devfs_path;

	devices = hal_device_store_match_multiple_key_value_string (hald_get_gdl(),
		"block.solaris.raw_device", name);
        for (i = devices; i != NULL; i = g_slist_next (i)) {
		if (hal_device_has_capability (HAL_DEVICE (i->data), "storage")) {
			d = HAL_DEVICE (i->data);
			break;
		}
	}
	g_slist_free (devices);

	if (d == NULL) {
		HAL_INFO (("device not found %s", name));
		return;
	}

	if ((devfs_path = hal_device_property_get_string (d,
	    "solaris.devfs_path")) == NULL) {
		HAL_INFO (("devfs_path not found %s", hal_device_get_udi (d)));
		return;
	}

	if (d != NULL) {
		devinfo_remove_branch ((char *)devfs_path, d);
	}
}

/* common storage */

static void
devinfo_storage_free_minor(struct devinfo_storage_minor *m)
{
	if (m != NULL) {
		free (m->slice);
		free (m->devlink);
		free (m->devpath);
		free (m);
	}
}

static struct devinfo_storage_minor *
devinfo_storage_new_minor(char *maindev_path, char *slice, char *devlink, dev_t dev, int dosnum)
{
	struct devinfo_storage_minor *m;
	int pathlen;
	char *devpath;

	m = (struct devinfo_storage_minor *)calloc (sizeof (struct devinfo_storage_minor), 1);
	if (m != NULL) {
		/*
		 * For volume's devfs_path we'll use minor_path/slice instead of
		 * minor_path which we use for parent storage device.
		 */
		pathlen = strlen (maindev_path) + strlen (slice) + 2;
		devpath = (char *)calloc (1, pathlen);
		snprintf(devpath, pathlen, "%s/%s", maindev_path, slice);

		m->devpath = devpath;
		m->devlink = strdup (devlink);
		m->slice = strdup (slice);
		m->dev = dev;
		m->dosnum = dosnum;
		if ((m->devpath == NULL) || (m->devlink == NULL)) {
			devinfo_storage_free_minor (m);
			m = NULL;
		}
	}
	return (m);
}

/*
 * Storage minor nodes are potential "volume" objects.
 * This function also completes building the parent object (main storage device).
 */
static void
devinfo_storage_minors(HalDevice *parent, di_node_t node, gchar *devfs_path, gboolean rescan)
{
	di_devlink_handle_t devlink_hdl;
	gboolean is_cdrom;
	const char *whole_disk;
	int     major;
	di_minor_t minor;
	dev_t   dev;
	char    *minor_path = NULL;
	char    *maindev_path = NULL;
	char    *devpath, *devlink;
	int	doslink_len;
	char	*doslink;
	char	dospath[64];
	char    *slice;
	int	pathlen;
	int	i;
	char	*raw;
	boolean_t maindev_is_d0;
	GQueue	*mq;
	HalDevice *volume;
	struct devinfo_storage_minor *m;
	struct devinfo_storage_minor *maindev = NULL;

	/* for cdroms whole disk is always s2 */
	is_cdrom = hal_device_has_capability (parent, "storage.cdrom");
	whole_disk = is_cdrom ? "s2" : WHOLE_DISK;

	major = di_driver_major(node);

	/* the "whole disk" p0/s2/d0 node must come first in the hotplug queue
	 * so we put other minor nodes on the local queue and move to the
	 * hotplug queue up in the end
	 */
	if ((mq = g_queue_new()) == NULL) {
		goto err;
	}
	if ((devlink_hdl = di_devlink_init(NULL, 0)) == NULL) {
		g_queue_free (mq);
		goto err;
	}
	minor = DI_MINOR_NIL;
	while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		dev = di_minor_devt(minor);
		if ((major != major(dev)) ||
		    (di_minor_type(minor) != DDM_MINOR) ||
		    (di_minor_spectype(minor) != S_IFBLK) ||
		    ((minor_path = di_devfs_minor_path(minor)) == NULL)) {
			continue;
		}
		if ((devlink = get_devlink(devlink_hdl, NULL, minor_path)) == NULL) {
			di_devfs_path_free (minor_path);
        		continue;
		}

		slice = devinfo_volume_get_slice_name (devlink);
		if (strlen (slice) < 2) {
			free (devlink);
			di_devfs_path_free (minor_path);
			continue;
		}

		/* ignore p1..N - we'll use p0:N instead */
		if ((strlen (slice) > 1) && (slice[0] == 'p') && isdigit(slice[1]) &&
		    ((atol(&slice[1])) > 0)) {
			free (devlink);
			di_devfs_path_free (minor_path);
			continue;
		}

		m = devinfo_storage_new_minor(minor_path, slice, devlink, dev, -1);
		if (m == NULL) {
			free (devlink);
			di_devfs_path_free (minor_path);
			continue;
		}

		/* main device is either s2/p0 or d0, the latter taking precedence */
		if ((strcmp (slice, "d0") == 0) ||
		    (((strcmp (slice, whole_disk) == 0) && (maindev == NULL)))) {
			if (maindev_path != NULL) {
				di_devfs_path_free (maindev_path);
			}
			maindev_path = minor_path;
			maindev = m;
			g_queue_push_head (mq, maindev);
		} else {
			di_devfs_path_free (minor_path);
			g_queue_push_tail (mq, m);
		}

		free (devlink);
	}
	di_devlink_fini (&devlink_hdl);

	if (maindev == NULL) {
		/* shouldn't typically happen */
		while (!g_queue_is_empty (mq)) {
			devinfo_storage_free_minor (g_queue_pop_head (mq));
		}
		goto err;
	}

	/* first enqueue main storage device */
	if (!rescan) {
		hal_device_property_set_int (parent, "block.major", major);
		hal_device_property_set_int (parent, "block.minor", minor(maindev->dev));
		hal_device_property_set_string (parent, "block.device", maindev->devlink);
		raw = dsk_to_rdsk (maindev->devlink);
		hal_device_property_set_string (parent, "block.solaris.raw_device", raw);
		free (raw);
		hal_device_property_set_bool (parent, "block.is_volume", FALSE);
		hal_device_property_set_string (parent, "solaris.devfs_path", maindev_path);
		devinfo_add_enqueue (parent, maindev_path, &devinfo_storage_handler);
	}

	/* add virtual dos volumes to enable pcfs probing */
	if (!is_cdrom) {
		doslink_len = strlen (maindev->devlink) + sizeof (":NNN") + 1;
		if ((doslink = (char *)calloc (1, doslink_len)) != NULL) {
			for (i = 1; i < 16; i++) {
				snprintf(dospath, sizeof (dospath), "%s:%d", maindev->slice, i);
				snprintf(doslink, doslink_len, "%s:%d", maindev->devlink, i);
				m = devinfo_storage_new_minor(maindev_path, dospath, doslink, maindev->dev, i);
				g_queue_push_tail (mq, m);
			}
			free (doslink);
		}
	}

	maindev_is_d0 = (strcmp (maindev->slice, "d0") == 0);

	/* enqueue all volumes */
	while (!g_queue_is_empty (mq)) {
		m = g_queue_pop_head (mq);

		/* if main device is d0, we'll throw away s2/p0 */
		if (maindev_is_d0 && (strcmp (m->slice, whole_disk) == 0)) {
			devinfo_storage_free_minor (m);
			continue;
		}
		/* don't do p0 on cdrom */
		if (is_cdrom && (strcmp (m->slice, "p0") == 0)) {
			devinfo_storage_free_minor (m);
			continue;
		}
		if (rescan) {
			/* in rescan mode, don't reprobe existing volumes */
			/* XXX detect volume removal? */
			volume = hal_device_store_match_key_value_string (hald_get_gdl (),
			    "solaris.devfs_path", m->devpath);
			if ((volume == NULL) || !hal_device_has_capability(volume, "volume")) {
				devinfo_volume_add (parent, node, m);
			} else {
				HAL_INFO(("rescan volume exists %s", m->devpath));
			}
		} else {
			devinfo_volume_add (parent, node, m);
		}
		devinfo_storage_free_minor (m);
	}

	if (maindev_path != NULL) {
		di_devfs_path_free (maindev_path);
	}

	return;

err:
	if (maindev_path != NULL) {
		di_devfs_path_free (maindev_path);
	}
	if (!rescan) {
		devinfo_add_enqueue (parent, devfs_path, &devinfo_storage_handler);
	}
}

HalDevice *
devinfo_volume_add(HalDevice *parent, di_node_t node, devinfo_storage_minor_t *m)
{
	HalDevice *d;
	char	*raw;
        char    udi[HAL_PATH_MAX];
	char	*devfs_path = m->devpath;
	char	*devlink = m->devlink;
	dev_t	dev = m->dev;
	int	dosnum = m->dosnum;
	char	*slice = m->slice;

	HAL_INFO (("volume_add: devfs_path=%s devlink=%s", devfs_path, devlink));
	d = hal_device_new ();

	devinfo_set_default_properties (d, parent, node, devfs_path);
        hal_device_property_set_string (d, "info.category", "volume");

       	hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
		"%s/%s", hal_device_get_udi (parent), slice);
        hal_device_set_udi (d, udi);
        hal_device_property_set_string (d, "info.udi", udi);
        hal_device_property_set_string (d, "info.product", slice);

       	hal_device_add_capability (d, "volume");
       	hal_device_add_capability (d, "block");
	hal_device_property_set_int (d, "block.major", major (dev));
	hal_device_property_set_int (d, "block.minor", minor (dev));
	hal_device_property_set_string (d, "block.device", devlink);
	raw = dsk_to_rdsk (devlink);
	hal_device_property_set_string (d, "block.solaris.raw_device", raw);
	free (raw);
	hal_device_property_set_string (d, "block.solaris.slice", slice);
	hal_device_property_set_bool (d, "block.is_volume", TRUE); /* XXX */

	hal_device_property_set_string (d, "block.storage_device", hal_device_get_udi (parent));

	/* set volume defaults */
	hal_device_property_set_string (d, "volume.fstype", "");
	hal_device_property_set_string (d, "volume.fsusage", "");
	hal_device_property_set_string (d, "volume.fsversion", "");
	hal_device_property_set_string (d, "volume.uuid", "");
	hal_device_property_set_string (d, "volume.label", "");
	hal_device_property_set_string (d, "volume.mount_point", "");
	hal_device_property_set_bool (d, "volume.is_mounted", FALSE);
	if (strcmp (hal_device_property_get_string (parent, "storage.drive_type"), "cdrom") == 0) {
		hal_device_property_set_bool (d, "volume.is_disc", TRUE);
		hal_device_add_capability (d, "volume.disc");
	} else {
		hal_device_property_set_bool (d, "volume.is_disc", FALSE);
	}

	if (dosnum > 0) {
		hal_device_property_set_bool (d, "volume.is_partition", TRUE);
		hal_device_property_set_int (d, "volume.partition.number", dosnum);
	} else {
		hal_device_property_set_bool (d, "volume.is_partition", FALSE);
	}

	/* prober may override these */
        hal_device_property_set_int (d, "volume.block_size", 512);

	devinfo_add_enqueue (d, devfs_path, &devinfo_volume_handler);

	return (d);
}

static void
devinfo_volume_preprobing_done (HalDevice *d, gpointer userdata1, gpointer userdata2)
{
	void *end_token = (void *) userdata1;
	char *whole_disk;
	char *block_device;
	const char *storage_udi;
	HalDevice *storage_d;
	const char *slice;
	int dos_num;

	if (hal_device_property_get_bool (d, "info.ignore")) {
		HAL_INFO (("Preprobing merged info.ignore==TRUE %s", hal_device_get_udi (d)));
		goto skip;
	}

	/*
	 * Optimizations: only probe if there's a chance to find something
	 */
	block_device = (char *)hal_device_property_get_string (d, "block.device");
	storage_udi = hal_device_property_get_string (d, "block.storage_device");
	slice = hal_device_property_get_string(d, "block.solaris.slice");
	if ((block_device == NULL) || (storage_udi == NULL) ||
	    (slice == NULL) || (strlen (slice) < 2)) {
		HAL_INFO (("Malformed volume properties %s", hal_device_get_udi (d)));
		goto skip;
	}
	storage_d = hal_device_store_match_key_value_string (hald_get_gdl (), "info.udi", storage_udi);
	if (storage_d == NULL) {
		HAL_INFO (("Storage device not found %s", hal_device_get_udi (d)));
		goto skip;
	}

	whole_disk = hal_device_has_capability (storage_d,
	    "storage.cdrom") ? "s2" : WHOLE_DISK;

	if (is_dos_path(block_device, &dos_num)) {
		/* don't probe more dos volumes than probe-storage found */
		if ((hal_device_property_get_bool (storage_d, "storage.no_partitions_hint") ||
		    (dos_num > hal_device_property_get_int (storage_d, "storage.solaris.num_dos_partitions")))) {
			    HAL_INFO (("%d > %d %s", dos_num, hal_device_property_get_int (storage_d,
				"storage.solaris.num_dos_partitions"), hal_device_get_udi (storage_d)));
			goto skip;
		}
	} else {
		/* if no VTOC slices found, don't probe slices except s2 */
		if ((slice[0] == 's') && (isdigit(slice[1])) && ((strcmp (slice, whole_disk)) != 0) &&
		    !hal_device_property_get_bool (storage_d, "storage.solaris.vtoc_slices")) {
			HAL_INFO (("Not probing slice %s", hal_device_get_udi (d)));
			goto skip;
		}
	}

	HAL_INFO(("Probing udi=%s", hal_device_get_udi (d)));
	hald_runner_run (d,
			"hald-probe-volume", NULL,
			DEVINFO_PROBE_VOLUME_TIMEOUT,
			devinfo_callouts_probing_done,
			(gpointer) end_token, userdata2);

	return;

skip:
	hal_device_store_remove (hald_get_tdl (), d);
	g_object_unref (d);
	hotplug_event_end (end_token);
}

static void
devinfo_volume_hotplug_begin_add (HalDevice *d, HalDevice *parent, DevinfoDevHandler *handler, void *end_token)
{
	HAL_INFO(("Preprobing volume udi=%s", hal_device_get_udi (d)));

	if (parent == NULL) {
		HAL_INFO (("no parent %s", hal_device_get_udi (d)));
		goto skip;
	}

	if (hal_device_property_get_bool (parent, "info.ignore")) {
		HAL_INFO (("Ignoring volume: parent's info.ignore is TRUE"));
		goto skip;
	}

        /* add to TDL so preprobing callouts and prober can access it */
        hal_device_store_add (hald_get_tdl (), d);

        /* Process preprobe fdi files */
        di_search_and_merge (d, DEVICE_INFO_TYPE_PREPROBE);

        /* Run preprobe callouts */
        hal_util_callout_device_preprobe (d, devinfo_volume_preprobing_done, end_token, handler);

	return;

skip:
	g_object_unref (d);
	hotplug_event_end (end_token);
}

void
devinfo_storage_hotplug_begin_add (HalDevice *d, HalDevice *parent, DevinfoDevHandler *handler, void *end_token)
{
	const char *drive_type;
	const char *p_udi;
	HalDevice *p_d;
	HalDevice *phys_d = NULL;
	const char *phys_bus;
	const char *bus;
	static const char *busses[] = { "usb", "ide", "scsi", "ieee1394",
					"pseudo" };
	int i;

	HAL_INFO (("Preprobing udi=%s", hal_device_get_udi (d)));

	if (parent == NULL) {
		HAL_INFO (("no parent %s", hal_device_get_udi (d)));
		goto error;
	}

	/*
	 * figure out physical device and bus, except for floppy
	 */
	drive_type = hal_device_property_get_string (d, "storage.drive_type");
	if ((drive_type != NULL) && (strcmp (drive_type, "floppy") == 0)) {
		goto skip_bus;
	}

	p_d = parent;
	for (;;) {
		bus = hal_device_property_get_string (p_d, "info.subsystem");
		if (bus != NULL) {
			for (i = 0; i < NELEM(busses); i++) {
				if (strcmp(bus, busses[i]) == 0) {
					phys_d = p_d;
					phys_bus = busses[i];
					break;
				}
			}
		}
		/* up the tree */
		p_udi = hal_device_property_get_string (p_d, "info.parent");
		if (p_udi == NULL) {
			break;
		}
		p_d = hal_device_store_find (hald_get_gdl (), p_udi);
	}
	if (phys_d == NULL) {
		HAL_INFO (("no physical device %s", hal_device_get_udi (d)));
	} else {
		hal_device_property_set_string (d, "storage.physical_device", hal_device_get_udi (phys_d));
		hal_device_property_set_string (d, "storage.bus", phys_bus);
	}

skip_bus:

	/* add to TDL so preprobing callouts and prober can access it */
	hal_device_store_add (hald_get_tdl (), d);

	/* Process preprobe fdi files */
	di_search_and_merge (d, DEVICE_INFO_TYPE_PREPROBE);

	/* Run preprobe callouts */
	hal_util_callout_device_preprobe (d, devinfo_callouts_preprobing_done, end_token, handler);

	return;

error:
	g_object_unref (d);
	hotplug_event_end (end_token);
}

static void
devinfo_storage_probing_done (HalDevice *d, guint32 exit_type, gint return_code, char **error, gpointer userdata1, gpointer userdata2)
{
        void *end_token = (void *) userdata1;

	HAL_INFO (("devinfo_storage_probing_done %s", hal_device_get_udi (d)));

        /* Discard device if probing reports failure */
        if (exit_type != HALD_RUN_SUCCESS || return_code != 0) {
		HAL_INFO (("devinfo_storage_probing_done returning exit_type=%d return_code=%d", exit_type, return_code));
                hal_device_store_remove (hald_get_tdl (), d);
                g_object_unref (d);
                hotplug_event_end (end_token);
		return;
        }

	devinfo_storage_set_nicknames (d);

        /* Merge properties from .fdi files */
        di_search_and_merge (d, DEVICE_INFO_TYPE_INFORMATION);
        di_search_and_merge (d, DEVICE_INFO_TYPE_POLICY);

	hal_util_callout_device_add (d, devinfo_callouts_add_done, end_token, NULL);
}

const gchar *
devinfo_storage_get_prober (HalDevice *d, int *timeout)
{
	*timeout = DEVINFO_PROBE_STORAGE_TIMEOUT;
	return "hald-probe-storage";
}

const gchar *
devinfo_volume_get_prober (HalDevice *d, int *timeout)
{
	*timeout = DEVINFO_PROBE_VOLUME_TIMEOUT;
	return "hald-probe-volume";
}

/*
 * After reprobing storage, reprobe its volumes.
 */
static void
devinfo_storage_rescan_probing_done (HalDevice *d, guint32 exit_type, gint return_code, char **error, gpointer userdata1, gpointer userdata2)
{
        void *end_token = (void *) userdata1;
	const char *devfs_path_orig = NULL;
	char *devfs_path = NULL;
	char *p;
	di_node_t node;

	HAL_INFO (("devinfo_storage_rescan_probing_done %s", hal_device_get_udi (d)));

	devfs_path_orig = hal_device_property_get_string (d, "solaris.devfs_path");
	if (devfs_path_orig == NULL) {
		HAL_INFO (("device has no solaris.devfs_path"));
		hotplug_event_process_queue ();
		return;
	}

	/* strip trailing minor part if any */
	if (strrchr(devfs_path_orig, ':') != NULL) {
		if ((devfs_path = strdup (devfs_path_orig)) != NULL) {
			p = strrchr(devfs_path, ':');
			*p = '\0';
		}
	} else {
		devfs_path = (char *)devfs_path_orig;
	}

	if ((node = di_init (devfs_path, DINFOCPYALL)) == DI_NODE_NIL) {
		HAL_INFO (("di_init %s failed %d %s", devfs_path, errno, hal_device_get_udi (d)));
		hotplug_event_process_queue ();
		return;
	} else {
		devinfo_storage_minors (d, node, (char *)devfs_path, TRUE);
		di_fini (node);
	}

	if (devfs_path != devfs_path_orig) {
		free (devfs_path);
	}

	hotplug_event_process_queue ();
}

/*
 * For removable media devices, check for "storage.removable.media_available".
 * For non-removable media devices, assume media is always there.
 *
 * If media is gone, enqueue remove events for all children volumes.
 * If media is there, first reprobe storage, then probe for new volumes (but leave existing volumes alone).
 */
gboolean
devinfo_storage_device_rescan (HalDevice *d)
{
	GSList *i;
	GSList *volumes;
	HalDevice *v;
	gchar *v_devfs_path;
	const char *drive_type;
	gboolean is_floppy;
	gboolean media_available;

	HAL_INFO (("devinfo_storage_device_rescan udi=%s", hal_device_get_udi (d)));

	if (hal_device_property_get_bool (d, "block.is_volume")) {
		HAL_INFO (("nothing to do for volume"));
		return (FALSE);
	}

	drive_type = hal_device_property_get_string (d, "storage.drive_type");
	is_floppy = (drive_type != NULL) && (strcmp (drive_type, "floppy") == 0);
		
	media_available = !hal_device_property_get_bool (d, "storage.removable") ||
	    hal_device_property_get_bool (d, "storage.removable.media_available");

	if (!media_available && !is_floppy) {
		HAL_INFO (("media gone %s", hal_device_get_udi (d)));

		volumes = hal_device_store_match_multiple_key_value_string (hald_get_gdl(),
        	    "block.storage_device", hal_device_get_udi (d));
		for (i = volumes; i != NULL; i = g_slist_next (i)) {
        		v = HAL_DEVICE (i->data);
			v_devfs_path = (gchar *)hal_device_property_get_string (v, "solaris.devfs_path");
			HAL_INFO (("child volume %s", hal_device_get_udi (v)));
			if ((v_devfs_path != NULL) && hal_device_has_capability (v, "volume")) {
				HAL_INFO (("removing volume %s", hal_device_get_udi (v)));
				devinfo_remove_enqueue (v_devfs_path, NULL);
			} else {
				HAL_INFO (("not a volume %s", hal_device_get_udi (v)));
			}
		}
		g_slist_free (volumes);

		hotplug_event_process_queue ();
	} else if (is_floppy) {
		HAL_INFO (("rescanning floppy %s", hal_device_get_udi (d)));
		
		hald_runner_run (d,
				 "hald-probe-storage --only-check-for-media", NULL,
				 DEVINFO_PROBE_STORAGE_TIMEOUT,
				 devinfo_floppy_rescan_probing_done,
				 NULL, NULL);
	} else {
		HAL_INFO (("media available %s", hal_device_get_udi (d)));

		hald_runner_run (d,
				 "hald-probe-storage --only-check-for-media", NULL,
				 DEVINFO_PROBE_STORAGE_TIMEOUT,
				 devinfo_storage_rescan_probing_done,
				 NULL, NULL);
	}

	return TRUE;
}

static char *
devinfo_volume_get_slice_name (char *devlink)
{
	char	*part, *slice, *disk;
	char	*s = NULL;
	char	*p;

	if ((p = strstr(devlink, "/lofi/")) != 0) {
		return (p + sizeof ("/lofi/") - 1);
	}

	part = strrchr(devlink, 'p');
	slice = strrchr(devlink, 's');
	disk = strrchr(devlink, 'd');

	if ((part != NULL) && (part > slice) && (part > disk)) {
		s = part;
	} else if ((slice != NULL) && (slice > disk)) {
		s = slice;
	} else {
		s = disk;
	}
	if ((s != NULL) && isdigit(s[1])) {
		return (s);
	} else {
		return ("");
	}
}

static gboolean
is_dos_path(char *path, int *partnum)
{
	char *p;

	if ((p = strrchr (path, ':')) == NULL) {
		return (FALSE);
	}
	return ((*partnum = atoi(p + 1)) != 0);
}

static gboolean
dos_to_dev(char *path, char **devpath, int *partnum)
{
	char *p;

	if ((p = strrchr (path, ':')) == NULL) {
		return (FALSE);
	}
	if ((*partnum = atoi(p + 1)) == 0) {
		return (FALSE);
	}
	p[0] = '\0';
	*devpath = strdup(path);
	p[0] = ':';
	return (*devpath != NULL);
}

static void
devinfo_storage_cleanup_mountpoint_cb (HalDevice *d, guint32 exit_type, 
		       gint return_code, gchar **error,
		       gpointer data1, gpointer data2)
{
	char *mount_point = (char *) data1;

	HAL_INFO (("Cleaned up mount point '%s'", mount_point));
	g_free (mount_point);
}


void
devinfo_storage_mnttab_event (HalDevice *hal_volume)
{
	FILE *fp = NULL;
        struct extmnttab m;
	HalDevice *d;
	unsigned int major;
	unsigned int minor;
	GSList *volumes = NULL;
	GSList *v;
	char *mount_point;
	dbus_bool_t is_partition;
	const char *fstype;
	int partition_number;

	if (hal_volume != NULL) {
		volumes = g_slist_append (NULL, hal_volume);
	} else {
		volumes = hal_device_store_match_multiple_key_value_string (hald_get_gdl (), "info.category", "volume");
	}
	if (volumes == NULL) {
		return;
	}

	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		HAL_ERROR (("Open failed %s errno %d", MNTTAB, errno));
		return;
	}

	while (getextmntent(fp, &m, 1) == 0) {
		for (v = volumes; v != NULL; v = g_slist_next (v)) {
			d = HAL_DEVICE (v->data);
			major = hal_device_property_get_int (d, "block.major");
			minor = hal_device_property_get_int (d, "block.minor");

			/*
			 * special handling for pcfs, which encodes logical
			 * drive number into the 6 upper bits of the minor
			 */
			is_partition = hal_device_property_get_bool (d, "volume.is_partition");
			partition_number = hal_device_property_get_int (d, "volume.partition.number");
			fstype = hal_device_property_get_string (d, "volume.fstype");

			if (is_partition && (partition_number > 0) && (strcmp (fstype, "pcfs") == 0)) {
				minor |= partition_number << 12;
			}

			if (m.mnt_major != major || m.mnt_minor != minor) {
				continue;
			}

			/* this volume matches the mnttab entry */
			device_property_atomic_update_begin ();
			hal_device_property_set_bool (d, "volume.is_mounted", TRUE);
			hal_device_property_set_bool (d, "volume.is_mounted_read_only",
						      hasmntopt ((struct mnttab *)&m, "ro") ? TRUE : FALSE);
			hal_device_property_set_string (d, "volume.mount_point", m.mnt_mountp);
			device_property_atomic_update_end ();

			HAL_INFO (("set %s to be mounted at %s",
				   hal_device_get_udi (d), m.mnt_mountp));
			volumes = g_slist_delete_link (volumes, v);
		}
	}

	/* all remaining volumes are not mounted */
	for (v = volumes; v != NULL; v = g_slist_next (v)) {
		d = HAL_DEVICE (v->data);
		mount_point = g_strdup (hal_device_property_get_string (d, "volume.mount_point"));
		if (mount_point == NULL || strlen (mount_point) == 0) {
			g_free (mount_point);
			continue;
		}

		device_property_atomic_update_begin ();
		hal_device_property_set_bool (d, "volume.is_mounted", FALSE);
		hal_device_property_set_bool (d, "volume.is_mounted_read_only", FALSE);
		hal_device_property_set_string (d, "volume.mount_point", "");
		device_property_atomic_update_end ();

		HAL_INFO (("set %s to unmounted", hal_device_get_udi (d)));

		/* cleanup if was mounted by us */
		if (hal_util_is_mounted_by_hald (mount_point)) {
			char *cleanup_stdin;
			char *extra_env[2];

			HAL_INFO (("Cleaning up '%s'", mount_point));

			extra_env[0] = g_strdup_printf ("HALD_CLEANUP=%s", mount_point);
			extra_env[1] = NULL;
			cleanup_stdin = "\n";

			hald_runner_run_method (d, 
						"hal-storage-cleanup-mountpoint", 
						extra_env, 
						cleanup_stdin, TRUE,
						0,
						devinfo_storage_cleanup_mountpoint_cb,
						g_strdup (mount_point), NULL);

			g_free (extra_env[0]);
		}

		g_free (mount_point);
	}
	g_slist_free (volumes);

	(void) fclose (fp);
}

static void
devinfo_volume_force_unmount_cb (HalDevice *d, guint32 exit_type, 
		  gint return_code, gchar **error,
		  gpointer data1, gpointer data2)
{
	void *end_token = (void *) data1;

	HAL_INFO (("devinfo_volume_force_unmount_cb for udi='%s', exit_type=%d, return_code=%d", hal_device_get_udi (d), exit_type, return_code));

	if (exit_type == HALD_RUN_SUCCESS && error != NULL && 
	    error[0] != NULL && error[1] != NULL) {
		char *exp_name = NULL;
		char *exp_detail = NULL;

		exp_name = error[0];
		if (error[0] != NULL) {
			exp_detail = error[1];
		}
		HAL_INFO (("failed with '%s' '%s'", exp_name, exp_detail));
	}

	hal_util_callout_device_remove (d, devinfo_callouts_remove_done, end_token, NULL);
}

static void
devinfo_volume_force_unmount (HalDevice *d, void *end_token)
{
	const char *mount_point;
	char *unmount_stdin;
	char *extra_env[2];
	extra_env[0] = "HAL_METHOD_INVOKED_BY_UID=0";
	extra_env[1] = NULL;

	mount_point = hal_device_property_get_string (d, "volume.mount_point");

	if (mount_point == NULL || strlen (mount_point) == 0 || !hal_util_is_mounted_by_hald (mount_point)) {
		hal_util_callout_device_remove (d, devinfo_callouts_remove_done, end_token, NULL);
		return;
	}

	HAL_INFO (("devinfo_volume_force_unmount for udi='%s'", hal_device_get_udi (d)));
		
	unmount_stdin = "\n";
		
	hald_runner_run_method (d, 
				"hal-storage-unmount", 
				extra_env, 
				unmount_stdin, TRUE,
				0,
				devinfo_volume_force_unmount_cb,
				end_token, NULL);
}

void
devinfo_volume_hotplug_begin_remove (HalDevice *d, char *devfs_path, void *end_token)
{
	if (hal_device_property_get_bool (d, "volume.is_mounted")) {
		devinfo_volume_force_unmount (d, end_token);
	} else {
		hal_util_callout_device_remove (d, devinfo_callouts_remove_done, end_token, NULL);
	}
}


enum {
	LEGACY_CDROM,
	LEGACY_FLOPPY,
	LEGACY_RMDISK
};

static const char *legacy_media_str[] = {
	"cdrom",
	"floppy",
	"rmdisk"
};

struct enum_nick {
	const char *type;
	GSList	*nums;
};

static int
devinfo_storage_get_legacy_media(HalDevice *d)
{
	const char *drive_type;

	if (hal_device_has_capability (d, "storage.cdrom")) {
		return (LEGACY_CDROM);
	} else if (((drive_type = hal_device_property_get_string (d,
	    "storage.drive_type")) != NULL) && (strcmp (drive_type, "floppy") == 0)) {
		return (LEGACY_FLOPPY);
	} else if (hal_device_property_get_bool (d, "storage.removable") ||
	           hal_device_property_get_bool (d, "storage.hotpluggable")) {
		return (LEGACY_RMDISK);
	} else {
		return (-1);
	}
}

static gboolean
devinfo_storage_foreach_nick (HalDeviceStore *store, HalDevice *d, gpointer user_data)
{
	struct enum_nick *en = (struct enum_nick *) user_data;
	const char *media_type;
	int media_num;

	media_type = hal_device_property_get_string (d, "storage.solaris.legacy.media_type");
	media_num = hal_device_property_get_int (d, "storage.solaris.legacy.media_num");
	if ((media_type != NULL) && (strcmp (media_type, en->type) == 0) &&
	    (media_num >= 0)) {
		en->nums = g_slist_prepend (en->nums, GINT_TO_POINTER(media_num));
	}
	return TRUE;
}

static void
devinfo_storage_append_nickname (HalDevice *d, const char *media_type, int media_num)
{
	char buf[64];

	if (media_num == 0) {
		hal_device_property_strlist_append (d, "storage.solaris.nicknames", media_type);
	}
	snprintf(buf, sizeof (buf), "%s%d", media_type, media_num);
	hal_device_property_strlist_append (d, "storage.solaris.nicknames", buf);
}

static void
devinfo_storage_set_nicknames (HalDevice *d)
{
	int media;
	const char *media_type;
	int media_num;
	GSList *i;
	struct enum_nick en;
	char buf[64];

	if ((media = devinfo_storage_get_legacy_media (d)) < 0) {
		return;
	}
	media_type = legacy_media_str[media];

	/* enumerate all storage devices of this media type */
	en.type = media_type;
	en.nums = NULL;
	hal_device_store_foreach (hald_get_gdl (), devinfo_storage_foreach_nick, &en);

	/* find a free number */
	for (media_num = 0; ; media_num++) {
		for (i = en.nums; i != NULL; i = g_slist_next (i)) {
        		if (GPOINTER_TO_INT (i->data) == media_num) {
				break;
			}
		}
		if (i == NULL) {
			break;
		}
	}
	g_slist_free (en.nums);

	hal_device_property_set_string (d, "storage.solaris.legacy.media_type", media_type);
	hal_device_property_set_int (d, "storage.solaris.legacy.media_num", media_num);

	/* primary nickname, and also vold-style symdev */
	snprintf(buf, sizeof (buf), "%s%d", media_type, media_num);
	hal_device_property_set_string (d, "storage.solaris.legacy.symdev", buf);
	devinfo_storage_append_nickname(d, media_type, media_num);

	/* additional nicknames */
	if (media == LEGACY_CDROM) {
		devinfo_storage_append_nickname(d, "cd", media_num);
		devinfo_storage_append_nickname(d, "sr", media_num);
	} else if (media == LEGACY_FLOPPY) {
		devinfo_storage_append_nickname(d, "fd", media_num);
		devinfo_storage_append_nickname(d, "diskette", media_num);
		devinfo_storage_append_nickname(d, "rdiskette", media_num);
	}
}
