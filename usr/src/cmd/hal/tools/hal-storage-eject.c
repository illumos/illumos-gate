/***************************************************************************
 *
 * hal-storage-eject.c : Eject method handler
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <libhal.h>
#include <libhal-storage.h>
#ifdef HAVE_POLKIT
#include <libpolkit.h>
#endif

#include "hal-storage-shared.h"

/* possible values: "Volume", "Storage" */
static char *devtype = "Volume";


static void
usage (void)
{
	fprintf (stderr, "This program should only be started by hald.\n");
	exit (1);
}


void static
unknown_eject_error (const char *detail)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.%s.UnknownFailure\n", devtype);
	fprintf (stderr, "%s\n", detail);
	exit (1);
}


static void
invalid_eject_option (const char *option, const char *uid)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.InvalidEjectOption\n");
	fprintf (stderr, "The option '%s' is not allowed for uid=%s\n", option, uid);
	exit (1);
}


int
main (int argc, char *argv[])
{
	char *udi;
	char *device;
	const char *drive_udi;
	LibHalDrive *drive;
	LibHalVolume *volume;
	DBusError error;
	LibHalContext *hal_ctx = NULL;
	DBusConnection *system_bus = NULL;
#ifdef HAVE_POLKIT
	LibPolKitContext *pol_ctx = NULL;
#endif
	char *invoked_by_uid;
	char *invoked_by_syscon_name;
	char **volume_udis;
	int num_volumes;
	int i;
	char eject_options[1024];
	char **given_options;
	const char *end;

	device = getenv ("HAL_PROP_BLOCK_DEVICE");
	if (device == NULL)
		usage ();

	udi = getenv ("HAL_PROP_INFO_UDI");
	if (udi == NULL)
		usage ();

	invoked_by_uid = getenv ("HAL_METHOD_INVOKED_BY_UID");

	invoked_by_syscon_name = getenv ("HAL_METHOD_INVOKED_BY_SYSTEMBUS_CONNECTION_NAME");

	dbus_error_init (&error);
	if ((hal_ctx = libhal_ctx_init_direct (&error)) == NULL) {
		printf ("Cannot connect to hald\n");
		LIBHAL_FREE_DBUS_ERROR (&error);
		usage ();
	}

	dbus_error_init (&error);
	system_bus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (system_bus == NULL) {
		printf ("Cannot connect to the system bus\n");
		LIBHAL_FREE_DBUS_ERROR (&error);
		usage ();
	}
#ifdef HAVE_POLKIT
	pol_ctx = libpolkit_new_context (system_bus);
	if (pol_ctx == NULL) {
		printf ("Cannot get libpolkit context\n");
		unknown_eject_error ("Cannot get libpolkit context");
	}
#endif

	/* read from stdin */
	if (strlen (fgets (eject_options, sizeof (eject_options), stdin)) > 0)
		eject_options [strlen (eject_options) - 1] = '\0';
	/* validate that input from stdin is UTF-8 */
	if (!g_utf8_validate (eject_options, -1, &end))
		unknown_eject_error ("Error validating eject_options as UTF-8");
#ifdef DEBUG
	printf ("eject_options  = '%s'\n", eject_options);
#endif

	/* delete any trailing whitespace options from splitting the string */
	given_options = g_strsplit (eject_options, "\t", 0);
	for (i = g_strv_length (given_options) - 1; i >= 0; --i) {
		if (strlen (given_options[i]) > 0)
			break;
		given_options[i] = NULL;
	}

	/* check eject options */
	for (i = 0; given_options[i] != NULL; i++) {
		char *given = given_options[i];

		/* none supported right now */

		invalid_eject_option (given, invoked_by_uid);
	}
	g_strfreev (given_options);

	/* should be either volume or storage */
	if ((volume = libhal_volume_from_udi (hal_ctx, udi)) != NULL) {
		drive_udi = libhal_volume_get_storage_device_udi (volume);
	} else {
		drive_udi = g_strdup (udi);
		devtype = "Storage";
	}
	if (drive_udi == NULL) {
		unknown_eject_error ("Cannot get drive udi");
	}
	if ((drive = libhal_drive_from_udi (hal_ctx, drive_udi)) == NULL) {
		unknown_eject_error ("Cannot get drive from udi");
	}

	/* first, unmount all volumes */
	volume_udis = libhal_drive_find_all_volumes (hal_ctx, drive, &num_volumes);
	if (volume_udis == NULL)
		unknown_eject_error ("Cannot get all enclosed volumes");
	for (i = 0; i < num_volumes; i++) {
		char *volume_udi;
		LibHalVolume *volume_to_unmount;

		volume_udi = volume_udis[i];

#ifdef DEBUG
		printf ("processing drive's volume %s (%d of %d)\n", volume_udi, i + 1, num_volumes);
#endif
		volume_to_unmount = libhal_volume_from_udi (hal_ctx, volume_udi);
		if (volume_to_unmount == NULL) {
			unknown_eject_error ("Cannot get volume object");
		}

		if (libhal_volume_is_mounted (volume_to_unmount)) {
#ifdef DEBUG
			printf (" unmounting\n");
#endif
			/* only lock around unmount call because hald's /proc/mounts handler
			 * will also want to lock the /media/.hal-mtab-lock file for peeking
			 */
			if (!lock_hal_mtab ()) {
				unknown_eject_error ("Cannot obtain lock on /media/.hal-mtab");
			}
			handle_unmount (hal_ctx,
#ifdef HAVE_POLKIT
					pol_ctx,
#endif
					volume_udi, volume_to_unmount, drive,
					libhal_volume_get_device_file (volume_to_unmount),
					invoked_by_uid, invoked_by_syscon_name,
					FALSE, FALSE, system_bus); /* use neither lazy nor force */
			unlock_hal_mtab ();
		} else {
#ifdef DEBUG
			printf (" not mounted\n");
#endif
		}

		libhal_volume_free (volume_to_unmount);

	}
	libhal_free_string_array (volume_udis);

	/* now attempt the eject */
	handle_eject (hal_ctx,
#ifdef HAVE_POLKIT
		      pol_ctx,
#endif
		      libhal_drive_get_udi (drive),
		      drive,
		      libhal_drive_get_device_file (drive),
		      invoked_by_uid,
		      invoked_by_syscon_name,
		      FALSE, system_bus);

	return 0;
}


