/***************************************************************************
 *
 * hal-storage-closetray.c : CloseTray method handler
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 * Copyright (C) 2006 Sun Microsystems, Inc.
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


static void
usage (void)
{
	fprintf (stderr, "This program should only be started by hald.\n");
	exit (1);
}


void static
unknown_closetray_error (const char *detail)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Storage.UnknownFailure\n");
	fprintf (stderr, "%s\n", detail);
	exit (1);
}


static void
invalid_closetray_option (const char *option, const char *uid)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Storage.InvalidCloseTrayOption\n");
	fprintf (stderr, "The option '%s' is not allowed for uid=%s\n", option, uid);
	exit (1);
}

#ifdef __FreeBSD__
#error Need FreeBSD specific changes here
#endif


int
main (int argc, char *argv[])
{
	char *udi;
	char *device;
	LibHalDrive *drive;
	DBusError error;
	LibHalContext *hal_ctx = NULL;
	DBusConnection *system_bus = NULL;
#ifdef HAVE_POLKIT
	LibPolKitContext *pol_ctx = NULL;
#endif
	char *invoked_by_uid;
	char *invoked_by_syscon_name;
	int i;
	char closetray_options[1024];
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
		unknown_closetray_error ("Cannot get libpolkit context");
	}
#endif

	/* read from stdin */
	if (strlen (fgets (closetray_options, sizeof (closetray_options), stdin)) > 0)
		closetray_options [strlen (closetray_options) - 1] = '\0';
	/* validate that input from stdin is UTF-8 */
	if (!g_utf8_validate (closetray_options, -1, &end))
		unknown_closetray_error ("Error validating closetray_options as UTF-8");
#ifdef DEBUG
	printf ("closetray_options  = '%s'\n", closetray_options);
#endif

	/* delete any trailing whitespace options from splitting the string */
	given_options = g_strsplit (closetray_options, "\t", 0);
	for (i = g_strv_length (given_options) - 1; i >= 0; --i) {
		if (strlen (given_options[i]) > 0)
			break;
		given_options[i] = NULL;
	}

	/* check options */
	for (i = 0; given_options[i] != NULL; i++) {
		char *given = given_options[i];

		/* none supported right now */

		invalid_closetray_option (given, invoked_by_uid);
	}
	g_strfreev (given_options);

	/* should be storage */
	if ((drive = libhal_drive_from_udi (hal_ctx, udi)) == NULL) {
		unknown_closetray_error ("Cannot get drive");
	}

	/* use handle_eject() with the closetray option */
	handle_eject (hal_ctx,
#ifdef HAVE_POLKIT
		      pol_ctx,
#endif
		      libhal_drive_get_udi (drive),
		      drive,
		      libhal_drive_get_device_file (drive),
		      invoked_by_uid,
		      invoked_by_syscon_name,
		      TRUE /* closetray option */,
		      system_bus);

	return 0;
}


