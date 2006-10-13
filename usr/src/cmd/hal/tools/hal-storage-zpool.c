/***************************************************************************
 *
 * hal-storage-zpool.c : ZFS pool methods
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <sys/types.h>
#include <wait.h>
#include <unistd.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>

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
unknown_zpool_error (const char *detail)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.UnknownFailure\n");
	fprintf (stderr, "%s\n", detail);
	exit (1);
}

void
audit_pool(const adt_export_data_t *imported_state, au_event_t event_id,
    int result, const char *auth_used, const char *pool, const char *device)
{
	adt_session_data_t      *ah;
	adt_event_data_t        *event;

	if (adt_start_session(&ah, imported_state, 0) != 0) {
        	printf ("adt_start_session failed %d\n", errno);
        	return;
	}
	if ((event = adt_alloc_event(ah, event_id)) == NULL) {
        	printf ("adt_alloc_event(ADT_attach)\n", errno);
        	return;
	}

	switch (event_id) {
	case ADT_pool_export:
		event->adt_pool_export.auth_used = (char *)auth_used;
		event->adt_pool_export.pool = (char *)pool;
		event->adt_pool_export.device = (char *)device;
		break;
	case ADT_pool_import:
		event->adt_pool_import.auth_used = (char *)auth_used;
		event->adt_pool_import.pool = (char *)pool;
		event->adt_pool_import.device = (char *)device;
		break;
	default:
		goto out;
	}

	if (result == 0) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
			printf ("adt_put_event(%d, success)\n", event_id);
		}
	} else {
		if (adt_put_event(event, ADT_FAILURE, result) != 0) {
			printf ("adt_put_event(%d, failure)\n", event_id);
		}
	}
out:
	adt_free_event(event);
	(void) adt_end_session(ah);
}


void
handle_zpool (LibHalContext *hal_ctx, 
#ifdef HAVE_POLKIT
	      LibPolKitContext *pol_ctx, 
#endif
	      char *subcmd, const char *pool, const char *device,
	      const char *invoked_by_uid, const char *invoked_by_syscon_name,
	      DBusConnection *system_bus)
{
	GError *err = NULL;
	char *sout = NULL;
	char *serr = NULL;
	int exit_status = 0;
	char *args[10];
	int na;
	adt_export_data_t *adt_data;
	size_t adt_data_size;
	au_event_t event_id;

#ifdef DEBUG
	printf ("subcmd                           = %s\n", subcmd);
	printf ("pool                             = %s\n", pool);
	printf ("device                           = %s\n", device);
	printf ("invoked by uid                   = %s\n", invoked_by_uid);
	printf ("invoked by system bus connection = %s\n", invoked_by_syscon_name);
#endif

	na = 0;
	args[na++] = "/usr/sbin/zpool";
	args[na++] = subcmd;
	if ((strcmp (subcmd, "import") == 0) &&
	    (strncmp (device, "/dev/lofi", 9) == 0)) {
		args[na++] = "-d";
		args[na++] = "/dev/lofi";
	}
	args[na++] = (char *) pool;
	args[na++] = NULL;

	/* invoke eject command */
	if (!g_spawn_sync ("/",
			   args,
			   NULL,
			   0,
			   NULL,
			   NULL,
			   &sout,
			   &serr,
			   &exit_status,
			   &err)) {
		printf ("Cannot execute zpool %s\n", subcmd);
		unknown_zpool_error ("Cannot spawn zpool");
	}

	if ((adt_data = get_audit_export_data (system_bus,
	    invoked_by_syscon_name, &adt_data_size)) != NULL) {
		event_id = (strcmp (subcmd, "import") == 0) ?
		    ADT_pool_import : ADT_pool_export;
		audit_pool (adt_data, event_id, WEXITSTATUS(exit_status),
		    "solaris.device.mount.removable", pool, device);
		free (adt_data);
	}

	if (exit_status != 0) {
		printf ("zpool error %d, stdout='%s', stderr='%s'\n", exit_status, sout, serr);

		unknown_zpool_error (serr);
	}

	g_free (sout);
	g_free (serr);
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
		unknown_zpool_error ("Cannot get libpolkit context");
	}
#endif

	/* should be a volume */
	if ((volume = libhal_volume_from_udi (hal_ctx, udi)) == NULL) {
		unknown_zpool_error ("Invalid volume");
	}
	if ((drive_udi = libhal_volume_get_storage_device_udi (volume)) == NULL ) {
		unknown_zpool_error ("Cannot get drive udi");
	}
	if ((drive = libhal_drive_from_udi (hal_ctx, drive_udi)) == NULL) {
		unknown_zpool_error ("Cannot get drive from udi");
	}
	if ((libhal_volume_get_fstype (volume) == NULL) ||
	    (strcmp (libhal_volume_get_fstype (volume), "zfs") != 0)) {
		unknown_zpool_error ("Not a zpool");
	}
	if ((libhal_volume_get_label (volume) == NULL) ||
	    (strlen (libhal_volume_get_label (volume)) == 0)) {
		unknown_zpool_error ("Invalid zpool name");
	}

        handle_zpool (hal_ctx,
#ifdef HAVE_POLKIT
		      pol_ctx,
#endif
                      ZPOOL_SUBCMD,
                      libhal_volume_get_label (volume),
		      device,
                      invoked_by_uid,
                      invoked_by_syscon_name,
		      system_bus);

	return 0;
}

