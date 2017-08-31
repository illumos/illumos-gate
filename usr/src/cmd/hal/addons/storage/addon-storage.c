/***************************************************************************
 *
 * addon-storage.c : watch removable media state changes
 *
 * Copyright 2017 Gary Mills
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mnttab.h>
#include <sys/dkio.h>
#include <priv.h>
#include <libsysevent.h>
#include <sys/sysevent/dev.h>

#include <libhal.h>

#include "../../hald/logger.h"

#define	SLEEP_PERIOD	5

static char			*udi;
static char			*devfs_path;
LibHalContext			*ctx = NULL;
static sysevent_handle_t	*shp = NULL;

static void	sysevent_dev_handler(sysevent_t *);

static void
my_dbus_error_free(DBusError *error)
{
	if (dbus_error_is_set(error)) {
		dbus_error_free(error);
	}
}

static void
sysevent_init ()
{
	const char	*subcl[1];

	shp = sysevent_bind_handle (sysevent_dev_handler);
	if (shp == NULL) {
		HAL_DEBUG (("sysevent_bind_handle failed %d", errno));
		return;
	}

	subcl[0] = ESC_DEV_EJECT_REQUEST;
	if (sysevent_subscribe_event (shp, EC_DEV_STATUS, subcl, 1) != 0) {
		HAL_INFO (("subscribe(dev_status) failed %d", errno));
		sysevent_unbind_handle (shp);
		return;
	}
}

static void
sysevent_fini ()
{
	if (shp != NULL) {
		sysevent_unbind_handle (shp);
		shp = NULL;
	}
}

static void
sysevent_dev_handler (sysevent_t *ev)
{
	char		*class;
	char		*subclass;
	nvlist_t	*attr_list;
	char		*phys_path, *path;
	char		*p;
	int		len;
	DBusError	error;

	if ((class = sysevent_get_class_name (ev)) == NULL)
		return;

	if ((subclass = sysevent_get_subclass_name (ev)) == NULL)
		return;

	if ((strcmp (class, EC_DEV_STATUS) != 0) ||
	    (strcmp (subclass, ESC_DEV_EJECT_REQUEST) != 0))
		return;

	if (sysevent_get_attr_list (ev, &attr_list) != 0)
		return;

	if (nvlist_lookup_string (attr_list, DEV_PHYS_PATH, &phys_path) != 0) {
		goto out;
	}

	/* see if event belongs to our LUN (ignore slice and "/devices" ) */
	if (strncmp (phys_path, "/devices", sizeof ("/devices") - 1) == 0)
		path = phys_path + sizeof ("/devices") - 1;
	else
		path = phys_path;

	if ((p = strrchr (path, ':')) == NULL)
		goto out;
	len = (uintptr_t)p - (uintptr_t)path;
	if (strncmp (path, devfs_path, len) != 0)
		goto out;

	HAL_DEBUG (("sysevent_dev_handler %s %s", subclass, phys_path));

	/* we got it, tell the world */
	dbus_error_init (&error);
	libhal_device_emit_condition (ctx, udi, "EjectPressed", "", &error);
	dbus_error_free (&error);

out:
	nvlist_free(attr_list);
}

static void
force_unmount (LibHalContext *ctx, const char *udi)
{
	DBusError error;
	DBusMessage *msg = NULL;
	DBusMessage *reply = NULL;
	char **options = NULL;
	unsigned int num_options = 0;
	DBusConnection *dbus_connection;
	char *device_file;

	dbus_error_init (&error);

	dbus_connection = libhal_ctx_get_dbus_connection (ctx);

	msg = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
					    "org.freedesktop.Hal.Device.Volume",
					    "Unmount");
	if (msg == NULL) {
		HAL_DEBUG (("Could not create dbus message for %s", udi));
		goto out;
	}


	options = calloc (1, sizeof (char *));
	if (options == NULL) {
		HAL_DEBUG (("Could not allocate options array"));
		goto out;
	}

	device_file = libhal_device_get_property_string (ctx, udi, "block.device", &error);
	if (device_file != NULL) {
		libhal_free_string (device_file);
	}
	dbus_error_free (&error);

	if (!dbus_message_append_args (msg, 
				       DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &options, num_options,
				       DBUS_TYPE_INVALID)) {
		HAL_DEBUG (("Could not append args to dbus message for %s", udi));
		goto out;
	}
	
	if (!(reply = dbus_connection_send_with_reply_and_block (dbus_connection, msg, -1, &error))) {
		HAL_DEBUG (("Unmount failed for %s: %s : %s\n", udi, error.name, error.message));
		goto out;
	}

	if (dbus_error_is_set (&error)) {
		HAL_DEBUG (("Unmount failed for %s\n%s : %s\n", udi, error.name, error.message));
		goto out;
	}

	HAL_DEBUG (("Succesfully unmounted udi '%s'", udi));

out:
	dbus_error_free (&error);
	if (options != NULL)
		free (options);
	if (msg != NULL)
		dbus_message_unref (msg);
	if (reply != NULL)
		dbus_message_unref (reply);
}

static void 
unmount_childs (LibHalContext *ctx, const char *udi)
{
	DBusError error;
	int num_volumes;
	char **volumes;

	dbus_error_init (&error);

	/* need to force unmount all partitions */
	if ((volumes = libhal_manager_find_device_string_match (
	     ctx, "block.storage_device", udi, &num_volumes, &error)) != NULL) {
		dbus_error_free (&error);
		int i;

		for (i = 0; i < num_volumes; i++) {
			char *vol_udi;

			vol_udi = volumes[i];
			if (libhal_device_get_property_bool (ctx, vol_udi, "block.is_volume", &error)) {
				dbus_error_free (&error);
				if (libhal_device_get_property_bool (ctx, vol_udi, "volume.is_mounted", &error)) {
					dbus_error_free (&error);
					HAL_DEBUG (("Forcing unmount of child '%s'", vol_udi));
					force_unmount (ctx, vol_udi);
				}
			}
		}
		libhal_free_string_array (volumes);
	}
	my_dbus_error_free (&error);
}

/** Check if a filesystem on a special device file is mounted
 *
 *  @param  device_file         Special device file, e.g. /dev/cdrom
 *  @return                     TRUE iff there is a filesystem system mounted
 *                              on the special device file
 */
static dbus_bool_t
is_mounted (const char *device_file)
{
	FILE *f;
	dbus_bool_t rc = FALSE;
	struct mnttab mp;
	struct mnttab mpref;

	if ((f = fopen ("/etc/mnttab", "r")) == NULL)
		return rc;

	bzero(&mp, sizeof (mp));
	bzero(&mpref, sizeof (mpref));
	mpref.mnt_special = (char *)device_file;
	if (getmntany(f, &mp, &mpref) == 0) {
		rc = TRUE;
	}

	fclose (f);
	return rc;
}

void
close_device (int *fd)
{
	if (*fd > 0) {
		close (*fd);
		*fd = -1;
	}
}

void
drop_privileges ()
{
	priv_set_t *pPrivSet = NULL;
	priv_set_t *lPrivSet = NULL;

	/*
	 * Start with the 'basic' privilege set and then remove any
	 * of the 'basic' privileges that will not be needed.
	 */
	if ((pPrivSet = priv_str_to_set("basic", ",", NULL)) == NULL) {
		return;
	}

	/* Clear privileges we will not need from the 'basic' set */
	(void) priv_delset(pPrivSet, PRIV_FILE_LINK_ANY);
	(void) priv_delset(pPrivSet, PRIV_PROC_INFO);
	(void) priv_delset(pPrivSet, PRIV_PROC_SESSION);

	/* to open logindevperm'd devices */
	(void) priv_addset(pPrivSet, PRIV_FILE_DAC_READ);

	/* to receive sysevents */
	(void) priv_addset(pPrivSet, PRIV_SYS_CONFIG);

	/* Set the permitted privilege set. */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, pPrivSet) != 0) {
		return;
	}

	/* Clear the limit set. */
	if ((lPrivSet = priv_allocset()) == NULL) {
		return;
	}

	priv_emptyset(lPrivSet);

	if (setppriv(PRIV_SET, PRIV_LIMIT, lPrivSet) != 0) {
		return;
	}

	priv_freeset(lPrivSet);
}

int 
main (int argc, char *argv[])
{
	char *device_file, *raw_device_file;
	DBusError error;
	char *bus;
	char *drive_type;
	int state, last_state;
	int fd = -1;

	if ((udi = getenv ("UDI")) == NULL)
		goto out;
	if ((device_file = getenv ("HAL_PROP_BLOCK_DEVICE")) == NULL)
		goto out;
	if ((raw_device_file = getenv ("HAL_PROP_BLOCK_SOLARIS_RAW_DEVICE")) == NULL)
		goto out;
	if ((bus = getenv ("HAL_PROP_STORAGE_BUS")) == NULL)
		goto out;
	if ((drive_type = getenv ("HAL_PROP_STORAGE_DRIVE_TYPE")) == NULL)
		goto out;
	if ((devfs_path = getenv ("HAL_PROP_SOLARIS_DEVFS_PATH")) == NULL)
		goto out;

	drop_privileges ();

	setup_logger ();

	sysevent_init ();

	dbus_error_init (&error);

	if ((ctx = libhal_ctx_init_direct (&error)) == NULL) {
		goto out;
	}
	my_dbus_error_free (&error);

	if (!libhal_device_addon_is_ready (ctx, udi, &error)) {
		goto out;
	}
	my_dbus_error_free (&error);

	printf ("Doing addon-storage for %s (bus %s) (drive_type %s) (udi %s)\n", device_file, bus, drive_type, udi);

	last_state = state = DKIO_NONE;

	/* Linux version of this addon attempts to re-open the device O_EXCL
	 * every 2 seconds, trying to figure out if some other app,
	 * like a cd burner, is using the device. Aside from questionable
	 * value of this (apps should use HAL's locked property or/and
	 * Solaris in_use facility), but also frequent opens/closes
	 * keeps media constantly spun up. All this needs more thought.
	 */
	for (;;) {
		if (is_mounted (device_file)) {
			close_device (&fd);
			sleep (SLEEP_PERIOD);
		} else if ((fd < 0) && ((fd = open (raw_device_file, O_RDONLY | O_NONBLOCK)) < 0)) {
			HAL_DEBUG (("open failed for %s: %s", raw_device_file, strerror (errno)));
			sleep (SLEEP_PERIOD);
		} else {
			/* Check if a disc is in the drive */
			/* XXX initial call always returns inserted
			 * causing unnecessary rescan - optimize?
			 */
			if (ioctl (fd, DKIOCSTATE, &state) == 0) {
				if (state == last_state) {
					HAL_DEBUG (("state has not changed %d %s", state, device_file));
					continue;
				} else {
					HAL_DEBUG (("new state %d %s", state, device_file));
				}

				switch (state) {
				case DKIO_EJECTED:
					HAL_DEBUG (("Media removal detected on %s", device_file));
					last_state = state;

					libhal_device_set_property_bool (ctx, udi, "storage.removable.media_available", FALSE, &error);
					my_dbus_error_free (&error);

					/* attempt to unmount all childs */
					unmount_childs (ctx, udi);

					/* could have a fs on the main block device; do a rescan to remove it */
					libhal_device_rescan (ctx, udi, &error);
					my_dbus_error_free (&error);
					break;

				case DKIO_INSERTED:
					HAL_DEBUG (("Media insertion detected on %s", device_file));
					last_state = state;

					libhal_device_set_property_bool (ctx, udi, "storage.removable.media_available", TRUE, &error);
					my_dbus_error_free (&error);

					/* could have a fs on the main block device; do a rescan to add it */
					libhal_device_rescan (ctx, udi, &error);
					my_dbus_error_free (&error);
					break;

				case DKIO_DEV_GONE:
					HAL_DEBUG (("Device gone detected on %s", device_file));
					last_state = state;

					unmount_childs (ctx, udi);
					close_device (&fd);
					goto out;

				case DKIO_NONE:
				default:
					break;
				}
			} else {
				HAL_DEBUG (("DKIOCSTATE failed: %s\n", strerror(errno)));
				sleep (SLEEP_PERIOD);
			}
		}
	}

out:
	sysevent_fini ();
	if (ctx != NULL) {
		my_dbus_error_free (&error);
		libhal_ctx_shutdown (ctx, &error);
		libhal_ctx_free (ctx);
	}

	return 0;
}
