/***************************************************************************
 * CVSID: $Id$
 *
 * hal-storage-unmount.c : Unmount wrapper
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
#ifdef __FreeBSD__
#include <fstab.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>
#include <limits.h>
#include <pwd.h>
#elif sun
#include <fcntl.h>
#include <sys/mnttab.h>
#include <sys/vfstab.h>
#else
#include <mntent.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#include <libhal.h>
#include <libhal-storage.h>
#ifdef HAVE_POLKIT
#include <libpolkit.h>
#endif

#include "hal-storage-shared.h"


static void
usage (void)
{
	fprintf (stderr, "This program should only be started by hald.\n");
	exit (1);
}

static void
invalid_unmount_option (const char *option, const char *uid)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.InvalidUnmountOption\n");
	fprintf (stderr, "The option '%s' is not allowed for uid=%s\n", option, uid);
	exit (1);
}

int
main (int argc, char *argv[])
{
	char *udi;
	char *device;
	LibHalVolume *volume;
	DBusError error;
	LibHalContext *hal_ctx = NULL;
	DBusConnection *system_bus = NULL;
#ifdef HAVE_POLKIT
	LibPolKitContext *pol_ctx = NULL;
#endif
	char *invoked_by_uid;
	char *invoked_by_syscon_name;
	int i;
	char unmount_options[1024];
	char **given_options;
	gboolean use_lazy;
	gboolean use_force;
	const char *end;

	if (!lock_hal_mtab ()) {
		unknown_error ("Cannot obtain lock on /media/.hal-mtab");
	}

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
		unknown_error ("Cannot get libpolkit context");
	}
#endif

	/* read from stdin */
	if (strlen (fgets (unmount_options, sizeof (unmount_options), stdin)) > 0)
		unmount_options [strlen (unmount_options) - 1] = '\0';
	/* validate that input from stdin is UTF-8 */
	if (!g_utf8_validate (unmount_options, -1, &end))
		unknown_error ("Error validating unmount_options as UTF-8");
#ifdef DEBUG
	printf ("unmount_options  = '%s'\n", unmount_options);
#endif

	/* delete any trailing whitespace options from splitting the string */
	given_options = g_strsplit (unmount_options, "\t", 0);
	for (i = g_strv_length (given_options) - 1; i >= 0; --i) {
		if (strlen (given_options[i]) > 0)
			break;
		given_options[i] = NULL;
	}

	use_lazy = FALSE;
	use_force = FALSE;

	/* check unmount options */
	for (i = 0; given_options[i] != NULL; i++) {
		char *given = given_options[i];

		if (strcmp (given, "lazy") == 0) {
			use_lazy = TRUE;
		} else if (strcmp (given, "force") == 0) {
			use_force = TRUE;
		} else {
			invalid_unmount_option (given, invoked_by_uid);
		}
	}
	g_strfreev (given_options);


	volume = libhal_volume_from_udi (hal_ctx, udi);
	if (volume == NULL) {
		LibHalDrive *drive;

		drive = libhal_drive_from_udi (hal_ctx, udi);
		if (drive == NULL) {
			usage ();
		} else {
			handle_unmount (hal_ctx,
#ifdef HAVE_POLKIT
					pol_ctx,
#endif
					udi, NULL, drive, device, invoked_by_uid,
					invoked_by_syscon_name, use_lazy, use_force,
					system_bus);
		}

	} else {
		const char *drive_udi;
		LibHalDrive *drive;

		drive_udi = libhal_volume_get_storage_device_udi (volume);

		if (drive_udi == NULL)
			unknown_error ("Cannot get drive_udi from volume");
		drive = libhal_drive_from_udi (hal_ctx, drive_udi);
		if (drive == NULL)
			unknown_error ("Cannot get drive from hal");

		handle_unmount (hal_ctx,
#ifdef HAVE_POLKIT
				pol_ctx,
#endif
				udi, volume, drive, device, invoked_by_uid,
				invoked_by_syscon_name, use_lazy, use_force,
				system_bus);

	}

	unlock_hal_mtab ();

	return 0;
}
