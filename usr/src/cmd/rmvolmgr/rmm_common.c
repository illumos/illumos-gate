/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <fcntl.h>
#include <libintl.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mnttab.h>

#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <libhal.h>
#include <libhal-storage.h>

#include "rmm_common.h"

#define	RMM_PRINT_DEVICE_WIDTH	20

extern int rmm_debug;

static const char *action_strings[] = {
	"eject",
	"mount",
	"remount",
	"unmount",
	"clear_mounts",
	"closetray"
};


LibHalContext *
rmm_hal_init(LibHalDeviceAdded devadd_cb, LibHalDeviceRemoved devrem_cb,
    LibHalDevicePropertyModified propmod_cb, LibHalDeviceCondition cond_cb,
    DBusError *error, rmm_error_t *rmm_error)
{
	DBusConnection	*dbus_conn;
	LibHalContext	*ctx;
	char		**devices;
	int		nr;

	dbus_error_init(error);

	/*
	 * setup D-Bus connection
	 */
	if (!(dbus_conn = dbus_bus_get(DBUS_BUS_SYSTEM, error))) {
		dbgprintf("cannot get system bus: %s\n",
		    rmm_strerror(error, -1));
		*rmm_error = RMM_EDBUS_CONNECT;
		return (NULL);
	}
	rmm_dbus_error_free(error);

	dbus_connection_setup_with_g_main(dbus_conn, NULL);
	dbus_connection_set_exit_on_disconnect(dbus_conn, B_TRUE);

	if ((ctx = libhal_ctx_new()) == NULL) {
		dbgprintf("libhal_ctx_new failed");
		*rmm_error = RMM_EHAL_CONNECT;
		return (NULL);
	}

	libhal_ctx_set_dbus_connection(ctx, dbus_conn);

	/*
	 * register callbacks
	 */
	if (devadd_cb != NULL) {
		libhal_ctx_set_device_added(ctx, devadd_cb);
	}
	if (devrem_cb != NULL) {
		libhal_ctx_set_device_removed(ctx, devrem_cb);
	}
	if (propmod_cb != NULL) {
		libhal_ctx_set_device_property_modified(ctx, propmod_cb);
		if (!libhal_device_property_watch_all(ctx, error)) {
			dbgprintf("property_watch_all failed %s",
			    rmm_strerror(error, -1));
			libhal_ctx_free(ctx);
			*rmm_error = RMM_EHAL_CONNECT;
			return (NULL);
		}
	}
	if (cond_cb != NULL) {
		libhal_ctx_set_device_condition(ctx, cond_cb);
	}

	if (!libhal_ctx_init(ctx, error)) {
		dbgprintf("libhal_ctx_init failed: %s",
		    rmm_strerror(error, -1));
		libhal_ctx_free(ctx);
		*rmm_error = RMM_EHAL_CONNECT;
		return (NULL);
	}
	rmm_dbus_error_free(error);

	/*
	 * The above functions do not guarantee that HAL is actually running.
	 * Check by invoking a method.
	 */
	if (!(devices = libhal_get_all_devices(ctx, &nr, error))) {
		dbgprintf("HAL is not running: %s", rmm_strerror(error, -1));
		libhal_ctx_shutdown(ctx, NULL);
		libhal_ctx_free(ctx);
		*rmm_error = RMM_EHAL_CONNECT;
		return (NULL);
	} else {
		rmm_dbus_error_free(error);
		libhal_free_string_array(devices);
	}

	return (ctx);
}


void
rmm_hal_fini(LibHalContext *hal_ctx)
{
	DBusConnection	*dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);

	(void) dbus_connection_unref(dbus_conn);
	(void) libhal_ctx_free(hal_ctx);
}


/*
 * find volume from any type of name, similar to the old media_findname()
 * returns the LibHalDrive object and a list of LibHalVolume objects.
 */
LibHalDrive *
rmm_hal_volume_find(LibHalContext *hal_ctx, const char *name, DBusError *error,
    GSList **volumes)
{
	LibHalDrive	*drive;
	char		*p;
	char		lastc;

	*volumes = NULL;

	/* temporarily remove trailing slash */
	p = (char *)name + strlen(name) - 1;
	if (*p == '/') {
		lastc = *p;
		*p = '\0';
	} else {
		p = NULL;
	}

	if (name[0] == '/') {
		if (((drive = rmm_hal_volume_findby(hal_ctx,
		    "info.udi", name, volumes)) != NULL) ||
		    ((drive = rmm_hal_volume_findby(hal_ctx,
		    "block.device", name, volumes)) != NULL) ||
		    ((drive = rmm_hal_volume_findby(hal_ctx,
		    "block.solaris.raw_device", name, volumes)) != NULL) ||
		    ((drive = rmm_hal_volume_findby(hal_ctx,
		    "volume.mount_point", name, volumes)) != NULL)) {
			goto out;
		} else {
			goto out;
		}
	}

	/* try volume label */
	if ((drive = rmm_hal_volume_findby(hal_ctx,
	    "volume.label", name, volumes)) != NULL) {
		goto out;
	}

	drive = rmm_hal_volume_findby_nickname(hal_ctx, name, volumes);

out:
	if (p != NULL) {
		*p = lastc;
	}
	return (drive);
}

/*
 * find default volume. Returns volume pointer and name in 'name'.
 */
LibHalDrive *
rmm_hal_volume_find_default(LibHalContext *hal_ctx, DBusError *error,
    const char **name_out, GSList **volumes)
{
	LibHalDrive	*drive;
	static const char *names[] = { "floppy", "cdrom", "rmdisk" };
	int		i;

	*volumes = NULL;

	for (i = 0; i < NELEM(names); i++) {
		if ((drive = rmm_hal_volume_findby_nickname(hal_ctx,
		    names[i], volumes)) != NULL) {
			/*
			 * Skip floppy if it has no media.
			 * XXX might want to actually check for media
			 * every time instead of relying on volcheck.
			 */
			if ((strcmp(names[i], "floppy") != 0) ||
			    libhal_device_get_property_bool(hal_ctx,
			    libhal_drive_get_udi(drive),
			    "storage.removable.media_available", NULL)) {
				*name_out = names[i];
				break;
			}
		}
		rmm_dbus_error_free(error);
	}

	return (drive);
}

/*
 * find volume by property=value
 * returns the LibHalDrive object and a list of LibHalVolume objects.
 * XXX add support for multiple properties, reduce D-Bus traffic
 */
LibHalDrive *
rmm_hal_volume_findby(LibHalContext *hal_ctx, const char *property,
    const char *value, GSList **volumes)
{
	DBusError	error;
	LibHalDrive	*drive = NULL;
	LibHalVolume	*v = NULL;
	char		**udis;
	int		num_udis;
	int		i;
	int		i_drive = -1;

	*volumes = NULL;

	dbus_error_init(&error);

	/* get all devices with property=value */
	if ((udis = libhal_manager_find_device_string_match(hal_ctx, property,
	    value, &num_udis, &error)) == NULL) {
		rmm_dbus_error_free(&error);
		return (NULL);
	}

	/* find volumes and drives among these devices */
	for (i = 0; i < num_udis; i++) {
		rmm_dbus_error_free(&error);
		if (libhal_device_query_capability(hal_ctx, udis[i], "volume",
		    &error)) {
			v = libhal_volume_from_udi(hal_ctx, udis[i]);
			if (v != NULL) {
				*volumes = g_slist_prepend(*volumes, v);
			}
		} else if ((*volumes == NULL) &&
		    libhal_device_query_capability(hal_ctx, udis[i], "storage",
		    &error)) {
			i_drive = i;
		}
	}

	if (*volumes != NULL) {
		/* used prepend, preserve original order */
		*volumes = g_slist_reverse(*volumes);

		v = (LibHalVolume *)(*volumes)->data;
		drive = libhal_drive_from_udi(hal_ctx,
		    libhal_volume_get_storage_device_udi(v));
		if (drive == NULL) {
			rmm_volumes_free (*volumes);
			*volumes = NULL;
		}
	} else if (i_drive >= 0) {
		drive = libhal_drive_from_udi(hal_ctx, udis[i_drive]);
	}

	libhal_free_string_array(udis);
	rmm_dbus_error_free(&error);

	return (drive);
}

static void
rmm_print_nicknames_one(LibHalDrive *d, LibHalVolume *v,
    const char *device, char **drive_nicknames)
{
	const char	*volume_label = NULL;
	const char	*mount_point = NULL;
	boolean_t	comma;
	int		i;

	(void) printf("%-*s ", RMM_PRINT_DEVICE_WIDTH, device);
	comma = B_FALSE;

	if (drive_nicknames != NULL) {
		for (i = 0; drive_nicknames[i] != NULL; i++) {
			(void) printf("%s%s", comma ? "," : "",
			    drive_nicknames[i]);
			comma = B_TRUE;
		}
	}

	if ((v != NULL) &&
	    ((volume_label = libhal_volume_get_label(v)) != NULL) &&
	    (strlen(volume_label) > 0)) {
		(void) printf("%s%s", comma ? "," : "", volume_label);
		comma = B_TRUE;
	}

	if ((v != NULL) &&
	    ((mount_point = libhal_volume_get_mount_point(v)) != NULL) &&
	    (strlen(mount_point) > 0)) {
		(void) printf("%s%s", comma ? "," : "", mount_point);
		comma = B_TRUE;
	}

	(void) printf("\n");
}

/*
 * print nicknames for each available volume
 *
 * print_mask:
 *   RMM_PRINT_MOUNTABLE	print only mountable volumes
 *   RMM_PRINT_EJECTABLE	print volume-less ejectable drives
 */
void
rmm_print_volume_nicknames(LibHalContext *hal_ctx, DBusError *error,
    int print_mask)
{
	char		**udis;
	int		num_udis;
	GSList		*volumes = NULL;
	LibHalDrive	*d, *d_tmp;
	LibHalVolume	*v;
	const char	*device;
	char		**nicknames;
	int		i;
	GSList		*j;
	int		nprinted;

	dbus_error_init(error);

	if ((udis = libhal_find_device_by_capability(hal_ctx, "storage",
	    &num_udis, error)) == NULL) {
		rmm_dbus_error_free(error);
		return;
	}

	for (i = 0; i < num_udis; i++) {
		if ((d = libhal_drive_from_udi(hal_ctx, udis[i])) == NULL) {
			continue;
		}

		/* find volumes belonging to this drive */
		if ((d_tmp = rmm_hal_volume_findby(hal_ctx,
		    "block.storage_device", udis[i], &volumes)) != NULL) {
			libhal_drive_free(d_tmp);
		}

		nicknames = libhal_device_get_property_strlist(hal_ctx,
		    udis[i], "storage.solaris.nicknames", NULL);

		nprinted = 0;
		for (j = volumes; j != NULL; j = g_slist_next(j)) {
			v = (LibHalVolume *)(j->data);

			if ((device = libhal_volume_get_device_file(v)) ==
			    NULL) {
				continue;
			}
			if ((print_mask & RMM_PRINT_MOUNTABLE) &&
			    (libhal_volume_get_fsusage(v) !=
			    LIBHAL_VOLUME_USAGE_MOUNTABLE_FILESYSTEM)) {
				continue;
			}

			rmm_print_nicknames_one(d, v, device, nicknames);
			nprinted++;
		}

		if ((nprinted == 0) &&
		    (print_mask & RMM_PRINT_EJECTABLE) &&
		    libhal_drive_requires_eject(d) &&
		    ((device = libhal_drive_get_device_file(d)) != NULL)) {
			rmm_print_nicknames_one(d, NULL, device, nicknames);
		}

		libhal_free_string_array(nicknames);
		libhal_drive_free(d);
		rmm_volumes_free(volumes);
		volumes = NULL;
	}

	libhal_free_string_array(udis);
}

/*
 * find volume by nickname
 * returns the LibHalDrive object and a list of LibHalVolume objects.
 */
LibHalDrive *
rmm_hal_volume_findby_nickname(LibHalContext *hal_ctx, const char *name,
    GSList **volumes)
{
	DBusError	error;
	LibHalDrive	*drive = NULL;
	LibHalDrive	*drive_tmp;
	char		**udis;
	int		num_udis;
	char		**nicknames;
	int		i, j;

	*volumes = NULL;

	dbus_error_init(&error);

	if ((udis = libhal_find_device_by_capability(hal_ctx, "storage",
	    &num_udis, &error)) == NULL) {
		rmm_dbus_error_free(&error);
		return (NULL);
	}

	/* find a drive by nickname */
	for (i = 0; (i < num_udis) && (drive == NULL); i++) {
		if ((nicknames = libhal_device_get_property_strlist(hal_ctx,
		    udis[i], "storage.solaris.nicknames", &error)) == NULL) {
			rmm_dbus_error_free(&error);
			continue;
		}
		for (j = 0; (nicknames[j] != NULL) && (drive == NULL); j++) {
			if (strcmp(nicknames[j], name) == 0) {
				drive = libhal_drive_from_udi(hal_ctx, udis[i]);
			}
		}
		libhal_free_string_array(nicknames);
	}
	libhal_free_string_array(udis);

	if (drive != NULL) {
		/* found the drive, now find its volumes */
		if ((drive_tmp = rmm_hal_volume_findby(hal_ctx,
		    "block.storage_device", libhal_drive_get_udi(drive),
		    volumes)) != NULL) {
			libhal_drive_free(drive_tmp);
		}
	}

	rmm_dbus_error_free(&error);

	return (drive);
}

void
rmm_volumes_free(GSList *volumes)
{
	GSList	*i;

	for (i = volumes; i != NULL; i = g_slist_next(i)) {
		libhal_volume_free((LibHalVolume *)(i->data));
	}
	g_slist_free(volumes);
}

/*
 * Call HAL's Mount() method on the given device
 */
boolean_t
rmm_hal_mount(LibHalContext *hal_ctx, const char *udi,
    char **opts, int num_opts, char *mountpoint, DBusError *error)
{
	DBusConnection	*dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);
	DBusMessage	*dmesg, *reply;
	char		*fstype;

	dbgprintf("mounting %s...\n", udi);

	if (!(dmesg = dbus_message_new_method_call("org.freedesktop.Hal", udi,
	    "org.freedesktop.Hal.Device.Volume", "Mount"))) {
		dbgprintf(
		    "mount failed for %s: cannot create dbus message\n", udi);
		return (B_FALSE);
	}

	fstype = "";
	if (mountpoint == NULL) {
		mountpoint = "";
	}

	if (!dbus_message_append_args(dmesg, DBUS_TYPE_STRING, &mountpoint,
	    DBUS_TYPE_STRING, &fstype,
	    DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &opts, num_opts,
	    DBUS_TYPE_INVALID)) {
		dbgprintf("mount failed for %s: cannot append args\n", udi);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbus_error_init(error);
	if (!(reply = dbus_connection_send_with_reply_and_block(dbus_conn,
	    dmesg, RMM_MOUNT_TIMEOUT, error))) {
		dbgprintf("mount failed for %s: %s\n", udi, error->message);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbgprintf("mounted %s\n", udi);

	dbus_message_unref(dmesg);
	dbus_message_unref(reply);

	rmm_dbus_error_free(error);

	return (B_TRUE);
}


/*
 * Call HAL's Unmount() method on the given device
 */
boolean_t
rmm_hal_unmount(LibHalContext *hal_ctx, const char *udi, DBusError *error)
{
	DBusConnection *dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);
	DBusMessage *dmesg, *reply;
	char **opts = NULL;

	dbgprintf("unmounting %s...\n", udi);

	if (!(dmesg = dbus_message_new_method_call("org.freedesktop.Hal", udi,
	    "org.freedesktop.Hal.Device.Volume", "Unmount"))) {
		dbgprintf(
		    "unmount failed %s: cannot create dbus message\n", udi);
		return (B_FALSE);
	}

	if (!dbus_message_append_args(dmesg, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
	    &opts, 0, DBUS_TYPE_INVALID)) {
		dbgprintf("unmount failed %s: cannot append args\n", udi);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbus_error_init(error);
	if (!(reply = dbus_connection_send_with_reply_and_block(dbus_conn,
	    dmesg, RMM_UNMOUNT_TIMEOUT, error))) {
		dbgprintf("unmount failed for %s: %s\n", udi, error->message);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbgprintf("unmounted %s\n", udi);

	dbus_message_unref(dmesg);
	dbus_message_unref(reply);

	rmm_dbus_error_free(error);

	return (B_TRUE);
}


/*
 * Call HAL's Eject() method on the given device
 */
boolean_t
rmm_hal_eject(LibHalContext *hal_ctx, const char *udi, DBusError *error)
{
	DBusConnection	*dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);
	DBusMessage	*dmesg, *reply;
	char		**options = NULL;
	uint_t		num_options = 0;

	dbgprintf("ejecting %s...\n", udi);

	if (!(dmesg = dbus_message_new_method_call("org.freedesktop.Hal", udi,
	    "org.freedesktop.Hal.Device.Storage", "Eject"))) {
		dbgprintf("eject %s: cannot create dbus message\n", udi);
		return (B_FALSE);
	}

	if (!dbus_message_append_args(dmesg,
	    DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &options, num_options,
	    DBUS_TYPE_INVALID)) {
		dbgprintf("eject %s: cannot append args to dbus message ", udi);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbus_error_init(error);
	if (!(reply = dbus_connection_send_with_reply_and_block(dbus_conn,
	    dmesg, RMM_EJECT_TIMEOUT, error))) {
		dbgprintf("eject %s: %s\n", udi, error->message);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbgprintf("ejected %s\n", udi);

	dbus_message_unref(dmesg);
	dbus_message_unref(reply);

	rmm_dbus_error_free(error);

	return (B_TRUE);
}

/*
 * Call HAL's CloseTray() method on the given device
 */
boolean_t
rmm_hal_closetray(LibHalContext *hal_ctx, const char *udi, DBusError *error)
{
	DBusConnection	*dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);
	DBusMessage	*dmesg, *reply;
	char		**options = NULL;
	uint_t		num_options = 0;

	dbgprintf("closing tray %s...\n", udi);

	if (!(dmesg = dbus_message_new_method_call("org.freedesktop.Hal", udi,
	    "org.freedesktop.Hal.Device.Storage", "CloseTray"))) {
		dbgprintf(
		    "closetray failed for %s: cannot create dbus message\n",
		    udi);
		return (B_FALSE);
	}

	if (!dbus_message_append_args(dmesg,
	    DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &options, num_options,
	    DBUS_TYPE_INVALID)) {
		dbgprintf("closetray %s: cannot append args to dbus message ",
		    udi);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbus_error_init(error);
	if (!(reply = dbus_connection_send_with_reply_and_block(dbus_conn,
	    dmesg, RMM_CLOSETRAY_TIMEOUT, error))) {
		dbgprintf("closetray failed for %s: %s\n", udi, error->message);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbgprintf("closetray ok %s\n", udi);

	dbus_message_unref(dmesg);
	dbus_message_unref(reply);

	rmm_dbus_error_free(error);

	return (B_TRUE);
}

/*
 * Call HAL's Rescan() method on the given device
 */
boolean_t
rmm_hal_rescan(LibHalContext *hal_ctx, const char *udi, DBusError *error)
{
	DBusConnection	*dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);
	DBusMessage	*dmesg, *reply;

	dbgprintf("rescanning %s...\n", udi);

	if (!(dmesg = dbus_message_new_method_call("org.freedesktop.Hal", udi,
	    "org.freedesktop.Hal.Device", "Rescan"))) {
		dbgprintf("rescan failed for %s: cannot create dbus message\n",
		    udi);
		return (B_FALSE);
	}

	dbus_error_init(error);
	if (!(reply = dbus_connection_send_with_reply_and_block(dbus_conn,
	    dmesg, -1, error))) {
		dbgprintf("rescan failed for %s: %s\n", udi, error->message);
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbgprintf("rescan ok %s\n", udi);

	dbus_message_unref(dmesg);
	dbus_message_unref(reply);

	rmm_dbus_error_free(error);

	return (B_TRUE);
}

boolean_t
rmm_hal_claim_branch(LibHalContext *hal_ctx, const char *udi)
{
	DBusError error;
	DBusConnection	*dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);
	DBusMessage *dmesg, *reply;
	const char *claimed_by = "rmvolmgr";

	dbgprintf("claiming branch %s...\n", udi);

	if (!(dmesg = dbus_message_new_method_call("org.freedesktop.Hal",
	    "/org/freedesktop/Hal/Manager", "org.freedesktop.Hal.Manager",
	    "ClaimBranch"))) {
		dbgprintf("cannot create dbus message\n");
		return (B_FALSE);
	}

	if (!dbus_message_append_args(dmesg, DBUS_TYPE_STRING, &udi,
	    DBUS_TYPE_STRING, &claimed_by, DBUS_TYPE_INVALID)) {
		dbgprintf("cannot append args to dbus message\n");
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbus_error_init(&error);
	if (!(reply = dbus_connection_send_with_reply_and_block(dbus_conn,
	    dmesg, -1, &error))) {
		dbgprintf("cannot send dbus message\n");
		dbus_message_unref(dmesg);
		rmm_dbus_error_free(&error);
		return (B_FALSE);
	}

	dbgprintf("claim branch ok %s\n", udi);

	dbus_message_unref(dmesg);
	dbus_message_unref(reply);

	return (B_TRUE);
}

boolean_t
rmm_hal_unclaim_branch(LibHalContext *hal_ctx, const char *udi)
{
	DBusError error;
	DBusConnection	*dbus_conn = libhal_ctx_get_dbus_connection(hal_ctx);
	DBusMessage *dmesg, *reply;
	const char *claimed_by = "rmvolmgr";

	dbgprintf("unclaiming branch %s...\n", udi);

	if (!(dmesg = dbus_message_new_method_call("org.freedesktop.Hal",
	    "/org/freedesktop/Hal/Manager", "org.freedesktop.Hal.Manager",
	    "UnclaimBranch"))) {
		dbgprintf("cannot create dbus message\n");
		return (B_FALSE);
	}

	if (!dbus_message_append_args(dmesg, DBUS_TYPE_STRING, &udi,
	    DBUS_TYPE_STRING, &claimed_by, DBUS_TYPE_INVALID)) {
		dbgprintf("cannot append args to dbus message\n");
		dbus_message_unref(dmesg);
		return (B_FALSE);
	}

	dbus_error_init(&error);
	if (!(reply = dbus_connection_send_with_reply_and_block(dbus_conn,
	    dmesg, -1, &error))) {
		dbgprintf("cannot send dbus message\n");
		dbus_message_unref(dmesg);
		rmm_dbus_error_free(&error);
		return (B_FALSE);
	}

	dbgprintf("unclaim branch ok %s\n", udi);

	dbus_message_unref(dmesg);
	dbus_message_unref(reply);

	return (B_TRUE);
}

static boolean_t
rmm_action_one(LibHalContext *hal_ctx, const char *name, action_t action,
    const char *dev, const char *udi, LibHalVolume *v,
    char **opts, int num_opts, char *mountpoint)
{
	char		dev_str[MAXPATHLEN];
	char		*mountp;
	DBusError	error;
	boolean_t	ret = B_FALSE;

	if (strcmp(name, dev) == 0) {
		(void) snprintf(dev_str, sizeof (dev_str), name);
	} else {
		(void) snprintf(dev_str, sizeof (dev_str), "%s %s", name, dev);
	}

	dbus_error_init(&error);

	switch (action) {
	case EJECT:
		ret = rmm_hal_eject(hal_ctx, udi, &error);
		break;
	case INSERT:
	case REMOUNT:
		if (libhal_volume_is_mounted(v)) {
			goto done;
		}
		ret = rmm_hal_mount(hal_ctx, udi,
		    opts, num_opts, mountpoint, &error);
		break;
	case UNMOUNT:
		if (!libhal_volume_is_mounted(v)) {
			goto done;
		}
		ret = rmm_hal_unmount(hal_ctx, udi, &error);
		break;
	case CLOSETRAY:
		ret = rmm_hal_closetray(hal_ctx, udi, &error);
		break;
	}

	if (!ret) {
		(void) fprintf(stderr, gettext("%s of %s failed: %s\n"),
		    action_strings[action], dev_str, rmm_strerror(&error, -1));
		goto done;
	}

	switch (action) {
	case EJECT:
		(void) printf(gettext("%s ejected\n"), dev_str);
		break;
	case INSERT:
	case REMOUNT:
		mountp = rmm_get_mnttab_mount_point(dev);
		if (mountp != NULL) {
			(void) printf(gettext("%s mounted at %s\n"),
			    dev_str, mountp);
			free(mountp);
		}
		break;
	case UNMOUNT:
		(void) printf(gettext("%s unmounted\n"), dev_str);
		break;
	case CLOSETRAY:
		(void) printf(gettext("%s tray closed\n"), dev_str);
		break;
	}

done:
	rmm_dbus_error_free(&error);
	return (ret);
}

/*
 * top level action routine
 *
 * If non-null 'aa' is passed, it will be used, otherwise a local copy
 * will be created.
 */
boolean_t
rmm_action(LibHalContext *hal_ctx, const char *name, action_t action,
    struct action_arg *aap, char **opts, int num_opts, char *mountpoint)
{
	DBusError	error;
	GSList		*volumes, *i;
	LibHalDrive	*d;
	LibHalVolume	*v;
	const char	*udi, *d_udi;
	const char	*dev, *d_dev;
	struct action_arg aa_local;
	boolean_t	ret = B_FALSE;

	dbgprintf("rmm_action %s %s\n", name, action_strings[action]);

	if (aap == NULL) {
		bzero(&aa_local, sizeof (aa_local));
		aap = &aa_local;
	}

	dbus_error_init(&error);

	/* find the drive and its volumes */
	d = rmm_hal_volume_find(hal_ctx, name, &error, &volumes);
	rmm_dbus_error_free(&error);
	if (d == NULL) {
		(void) fprintf(stderr, gettext("cannot find '%s'\n"), name);
		return (B_FALSE);
	}
	d_udi = libhal_drive_get_udi(d);
	d_dev = libhal_drive_get_device_file(d);
	if ((d_udi == NULL) || (d_dev == NULL)) {
		goto out;
	}

	/*
	 * For those drives that do not require media eject,
	 * EJECT turns into UNMOUNT.
	 */
	if ((action == EJECT) && !libhal_drive_requires_eject(d)) {
		action = UNMOUNT;
	}

	/* per drive action */
	if ((action == EJECT) || (action == CLOSETRAY)) {
		ret = rmm_action_one(hal_ctx, name, action, d_dev, d_udi, NULL,
		    opts, num_opts, NULL);

		if (!ret || (action == CLOSETRAY)) {
			goto out;
		}
	}

	/* per volume action */
	for (i = volumes; i != NULL; i = g_slist_next(i)) {
		v = (LibHalVolume *)i->data;
		udi = libhal_volume_get_udi(v);
		dev = libhal_volume_get_device_file(v);

		if ((udi == NULL) || (dev == NULL)) {
			continue;
		}
		if (aap == &aa_local) {
			if (!rmm_volume_aa_from_prop(hal_ctx, udi, v, aap)) {
				dbgprintf("rmm_volume_aa_from_prop failed %s\n",
				    udi);
				continue;
			}
		}
		aap->aa_action = action;

		/* ejected above, just need postprocess */
		if (action != EJECT) {
			ret = rmm_action_one(hal_ctx, name, action, dev, udi, v,
			    opts, num_opts, mountpoint);
		}
		if (ret) {
			(void) vold_postprocess(hal_ctx, udi, aap);
		}

		if (aap == &aa_local) {
			rmm_volume_aa_free(aap);
		}
	}

out:
	rmm_volumes_free(volumes);
	libhal_drive_free(d);

	return (ret);
}


/*
 * rescan by name
 * if name is NULL, rescan all drives
 */
boolean_t
rmm_rescan(LibHalContext *hal_ctx, const char *name, boolean_t query)
{
	DBusError	error;
	GSList		*volumes;
	LibHalDrive	*drive = NULL;
	const char	*drive_udi;
	char		**udis;
	int		num_udis;
	char		*nickname;
	char		**nicks = NULL;
	boolean_t	do_free_udis = FALSE;
	int		i;
	boolean_t	ret = B_FALSE;

	dbgprintf("rmm_rescan %s\n", name != NULL ? name : "all");

	dbus_error_init(&error);

	if (name != NULL) {
		if ((drive = rmm_hal_volume_find(hal_ctx, name, &error,
		    &volumes)) == NULL) {
			rmm_dbus_error_free(&error);
			(void) fprintf(stderr,
			    gettext("cannot find '%s'\n"), name);
			return (B_FALSE);
		}
		rmm_dbus_error_free(&error);
		g_slist_free(volumes);

		drive_udi = libhal_drive_get_udi(drive);
		udis = (char **)&drive_udi;
		num_udis = 1;
	} else {
		if ((udis = libhal_find_device_by_capability(hal_ctx,
		    "storage", &num_udis, &error)) == NULL) {
			rmm_dbus_error_free(&error);
			return (B_TRUE);
		}
		rmm_dbus_error_free(&error);
		do_free_udis = TRUE;
	}

	for (i = 0; i < num_udis; i++) {
		if (name == NULL) {
			nicks = libhal_device_get_property_strlist(hal_ctx,
			    udis[i], "storage.solaris.nicknames", NULL);
			if (nicks != NULL) {
				nickname = nicks[0];
			} else {
				nickname = "";
			}
		}
		if (!(ret = rmm_hal_rescan(hal_ctx, udis[i], &error))) {
			(void) fprintf(stderr,
			    gettext("rescan of %s failed: %s\n"),
			    name ? name : nickname,
			    rmm_strerror(&error, -1));
			libhal_free_string_array(nicks);
			continue;
		}
		if (query) {
			ret = libhal_device_get_property_bool(hal_ctx, udis[i],
			    "storage.removable.media_available", NULL);
			if (ret) {
				printf(gettext("%s is available\n"),
				    name ? name : nickname);
			} else {
				printf(gettext("%s is not available\n"),
				    name ? name : nickname);
			}
		}
		libhal_free_string_array(nicks);
	}

	if (drive != NULL) {
		libhal_drive_free(drive);
	}
	if (do_free_udis) {
		libhal_free_string_array(udis);
	}

	return (ret);
}


/*
 * set action_arg from volume properties
 */
boolean_t
rmm_volume_aa_from_prop(LibHalContext *hal_ctx, const char *udi_arg,
    LibHalVolume *volume_arg, struct action_arg *aap)
{
	LibHalVolume	*volume = volume_arg;
	const char	*udi = udi_arg;
	const char	*drive_udi;
	char		*volume_label;
	char		*mountpoint;
	int		len;
	int		ret = B_FALSE;

	/* at least udi or volume must be supplied */
	if ((udi == NULL) && (volume == NULL)) {
		return (B_FALSE);
	}
	if (volume == NULL) {
		if ((volume = libhal_volume_from_udi(hal_ctx, udi)) == NULL) {
			dbgprintf("cannot get volume %s\n", udi);
			goto out;
		}
	}
	if (udi == NULL) {
		if ((udi = libhal_volume_get_udi(volume)) == NULL) {
			dbgprintf("cannot get udi\n");
			goto out;
		}
	}
	drive_udi = libhal_volume_get_storage_device_udi(volume);

	if (!(aap->aa_symdev = libhal_device_get_property_string(hal_ctx,
	    drive_udi, "storage.solaris.legacy.symdev", NULL))) {
		dbgprintf("property %s not found %s\n",
		    "storage.solaris.legacy.symdev", drive_udi);
		goto out;
	}
	if (!(aap->aa_media = libhal_device_get_property_string(hal_ctx,
	    drive_udi, "storage.solaris.legacy.media_type", NULL))) {
		dbgprintf("property %s not found %s\n",
		    "storage.solaris.legacy.media_type", drive_udi);
		goto out;
	}

	/* name is derived from volume label */
	aap->aa_name = NULL;
	if ((volume_label = (char *)libhal_device_get_property_string(hal_ctx,
	    udi, "volume.label", NULL)) != NULL) {
		if ((len = strlen(volume_label)) > 0) {
			aap->aa_name = rmm_vold_convert_volume_label(
			    volume_label, len);
			if (strlen(aap->aa_name) == 0) {
				free(aap->aa_name);
				aap->aa_name = NULL;
			}
		}
		libhal_free_string(volume_label);
	}
	/* if no label, then unnamed_<mediatype> */
	if (aap->aa_name == NULL) {
		aap->aa_name = (char *)calloc(1, sizeof ("unnamed_floppyNNNN"));
		if (aap->aa_name == NULL) {
			goto out;
		}
		(void) snprintf(aap->aa_name, sizeof ("unnamed_floppyNNNN"),
		    "unnamed_%s", aap->aa_media);
	}

	if (!(aap->aa_path = libhal_device_get_property_string(hal_ctx, udi,
	    "block.device", NULL))) {
		dbgprintf("property %s not found %s\n", "block.device", udi);
		goto out;
	}
	if (!(aap->aa_rawpath = libhal_device_get_property_string(hal_ctx, udi,
	    "block.solaris.raw_device", NULL))) {
		dbgprintf("property %s not found %s\n",
		    "block.solaris.raw_device", udi);
		goto out;
	}
	if (!(aap->aa_type = libhal_device_get_property_string(hal_ctx, udi,
	    "volume.fstype", NULL))) {
		dbgprintf("property %s not found %s\n", "volume.fstype", udi);
		goto out;
	}
	if (!libhal_device_get_property_bool(hal_ctx, udi,
	    "volume.is_partition", NULL)) {
		aap->aa_partname = NULL;
	} else if (!(aap->aa_partname = libhal_device_get_property_string(
	    hal_ctx, udi, "block.solaris.slice", NULL))) {
		dbgprintf("property %s not found %s\n",
		    "block.solaris.slice", udi);
		goto out;
	}
	if (!(mountpoint = libhal_device_get_property_string(hal_ctx, udi,
	    "volume.mount_point", NULL))) {
		dbgprintf("property %s not found %s\n",
		    "volume.mount_point", udi);
		goto out;
	}
	/*
	 * aa_mountpoint can be reallocated in rmm_volume_aa_update_mountpoint()
	 * won't have to choose between free() or libhal_free_string() later on
	 */
	aap->aa_mountpoint = strdup(mountpoint);
	libhal_free_string(mountpoint);
	if (aap->aa_mountpoint == NULL) {
		dbgprintf("mountpoint is NULL %s\n", udi);
		goto out;
	}

	ret = B_TRUE;

out:
	if ((volume != NULL) && (volume != volume_arg)) {
		libhal_volume_free(volume);
	}
	if (!ret) {
		rmm_volume_aa_free(aap);
	}
	return (ret);
}

/* ARGSUSED */
void
rmm_volume_aa_update_mountpoint(LibHalContext *hal_ctx, const char *udi,
    struct action_arg *aap)
{
	if (aap->aa_mountpoint != NULL) {
		free(aap->aa_mountpoint);
	}
	aap->aa_mountpoint = rmm_get_mnttab_mount_point(aap->aa_path);
}

void
rmm_volume_aa_free(struct action_arg *aap)
{
	if (aap->aa_symdev != NULL) {
		libhal_free_string(aap->aa_symdev);
		aap->aa_symdev = NULL;
	}
	if (aap->aa_name != NULL) {
		free(aap->aa_name);
		aap->aa_name = NULL;
	}
	if (aap->aa_path != NULL) {
		libhal_free_string(aap->aa_path);
		aap->aa_path = NULL;
	}
	if (aap->aa_rawpath != NULL) {
		libhal_free_string(aap->aa_rawpath);
		aap->aa_rawpath = NULL;
	}
	if (aap->aa_type != NULL) {
		libhal_free_string(aap->aa_type);
		aap->aa_type = NULL;
	}
	if (aap->aa_media != NULL) {
		libhal_free_string(aap->aa_media);
		aap->aa_media = NULL;
	}
	if (aap->aa_partname != NULL) {
		libhal_free_string(aap->aa_partname);
		aap->aa_partname = NULL;
	}
	if (aap->aa_mountpoint != NULL) {
		free(aap->aa_mountpoint);
		aap->aa_mountpoint = NULL;
	}
}

/*
 * get device's mount point from mnttab
 */
char *
rmm_get_mnttab_mount_point(const char *special)
{
	char		*mount_point = NULL;
	FILE		*f;
	struct mnttab	mnt;
	struct mnttab	mpref = { NULL, NULL, NULL, NULL, NULL };

	if ((f = fopen(MNTTAB, "r")) != NULL) {
		mpref.mnt_special = (char *)special;
		if (getmntany(f, &mnt, &mpref) == 0) {
			mount_point = strdup(mnt.mnt_mountp);
		}
		fclose(f);
	}

	return (mount_point);
}


/*
 * get human readable string from error values
 */
const char *
rmm_strerror(DBusError *dbus_error, int rmm_error)
{
	const char	*str;

	if ((dbus_error != NULL) && dbus_error_is_set(dbus_error)) {
		str = dbus_error->message;
	} else {
		switch (rmm_error) {
		case RMM_EOK:
			str = gettext("success");
			break;
		case RMM_EDBUS_CONNECT:
			str = gettext("cannot connect to D-Bus");
			break;
		case RMM_EHAL_CONNECT:
			str = gettext("cannot connect to HAL");
			break;
		default:
			str = gettext("undefined error");
			break;
		}
	}

	return (str);
}

void
rmm_dbus_error_free(DBusError *error)
{
	if (error != NULL && dbus_error_is_set(error)) {
		dbus_error_free(error);
	}
}

static int
rmm_vold_isbadchar(int c)
{
	int	ret_val = 0;


	switch (c) {
	case '/':
	case ';':
	case '|':
		ret_val = 1;
		break;
	default:
		if (iscntrl(c) || isspace(c)) {
			ret_val = 1;
		}
	}

	return (ret_val);
}

char *
rmm_vold_convert_volume_label(const char *name, size_t len)
{
	char	buf[MAXNAMELEN+1];
	char	*s = buf;
	int	i;

	if (len > MAXNAMELEN) {
		len = MAXNAMELEN;
	}

	for (i = 0; i < len; i++) {
		if (name[i] == '\0') {
			break;
		}
		if (isgraph((int)name[i])) {
			if (isupper((int)name[i])) {
				*s++ = tolower((int)name[i]);
			} else if (rmm_vold_isbadchar((int)name[i])) {
				*s++ = '_';
			} else {
				*s++ = name[i];
			}
		}
	}
	*s = '\0';
	s = strdup(buf);

	return (s);
}

/*
 * swiped from mkdir.c
 */
int
makepath(char *dir, mode_t mode)
{
	int		err;
	char		*slash;


	if ((mkdir(dir, mode) == 0) || (errno == EEXIST)) {
		return (0);
	}
	if (errno != ENOENT) {
		return (-1);
	}
	if ((slash = strrchr(dir, '/')) == NULL) {
		return (-1);
	}
	*slash = '\0';
	err = makepath(dir, mode);
	*slash++ = '/';

	if (err || (*slash == '\0')) {
		return (err);
	}

	return (mkdir(dir, mode));
}


void
dbgprintf(const char *fmt, ...)
{

	va_list		ap;
	const char	*p;
	char		msg[BUFSIZ];
	char		*errmsg = strerror(errno);
	char		*s;

	if (rmm_debug == 0) {
		return;
	}

	(void) memset(msg, 0, BUFSIZ);

	/* scan for %m and replace with errno msg */
	s = &msg[strlen(msg)];
	p = fmt;

	while (*p != '\0') {
		if ((*p == '%') && (*(p+1) == 'm')) {
			(void) strcat(s, errmsg);
			p += 2;
			s += strlen(errmsg);
			continue;
		}
		*s++ = *p++;
	}
	*s = '\0';	/* don't forget the null byte */

	va_start(ap, fmt);
	(void) vfprintf(stderr, msg, ap);
	va_end(ap);
}
