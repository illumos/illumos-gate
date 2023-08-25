/***************************************************************************
 * CVSID: $Id: hal-storage-mount.c,v 1.7 2006/06/21 00:44:03 david Exp $
 *
 * hal-storage-mount.c : Mount wrapper
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#else
#include <mntent.h>
#endif
#include <sys/types.h>
#include <unistd.h>
#include <sys/file.h>
#include <errno.h>
#include <syslog.h>

#include "hal-storage-shared.h"

#ifdef __FreeBSD__
struct mtab_handle
{
  struct statfs	*mounts;
  int		n_mounts;
  int		iter;
};
#endif


gboolean
mtab_open (gpointer *handle)
{
#ifdef __FreeBSD__
	struct mtab_handle *mtab;

	mtab = g_new0 (struct mtab_handle, 1);
	mtab->n_mounts = getmntinfo (&mtab->mounts, MNT_NOWAIT);
	if (mtab->n_mounts == 0) {
		g_free (mtab);
		return FALSE;
	}

	*handle = mtab;
	return TRUE;
#elif sun
	*handle = fopen (MNTTAB, "r");
	return *handle != NULL;
#else
	*handle = fopen ("/proc/mounts", "r");
	return *handle != NULL;
#endif
}

char *
mtab_next (gpointer handle, char **mount_point)
{
#ifdef __FreeBSD__
	struct mtab_handle *mtab = handle;

	if (mtab->iter < mtab->n_mounts)
		return mtab->mounts[mtab->iter++].f_mntfromname;
	else
		return NULL;
#error TODO: set *mount_point to g_strdup()-ed value if mount_point!=NULL
#elif sun
	static struct mnttab mnt;

	if (getmntent (handle, &mnt) == 0) {
		if (mount_point != NULL) {
			*mount_point = g_strdup (mnt.mnt_mountp);
		}
		return mnt.mnt_special;
	} else {
		return NULL;
	}
#else
	struct mntent *mnt;

	mnt = getmntent (handle);

	if (mnt != NULL) {
		if (mount_point != NULL) {
			*mount_point = g_strdup (mnt->mnt_dir);
		}
		return mnt->mnt_fsname;
	} else {
		return NULL;
	}
#endif
}

void
mtab_close (gpointer handle)
{
#ifdef __FreeBSD__
	g_free (handle);
#else
	fclose (handle);
#endif
}



gboolean
fstab_open (gpointer *handle)
{
#ifdef __FreeBSD__
	return setfsent () == 1;
#elif sun
	*handle = fopen (VFSTAB, "r");
	return *handle != NULL;
#else
	*handle = fopen ("/etc/fstab", "r");
	return *handle != NULL;
#endif
}

char *
fstab_next (gpointer handle, char **mount_point)
{
#ifdef __FreeBSD__
	struct fstab *fstab;

	fstab = getfsent ();

	/* TODO: fill out mount_point */
	if (mount_point != NULL && fstab != NULL) {
		*mount_point = fstab->fs_file;
	}

	return fstab ? fstab->fs_spec : NULL;
#elif sun
	static struct vfstab v;

	return getvfsent (handle, &v) == 0 ? v.vfs_special : NULL;
#else
	struct mntent *mnt;

	mnt = getmntent (handle);

	if (mount_point != NULL && mnt != NULL) {
		*mount_point = mnt->mnt_dir;
	}

	return mnt ? mnt->mnt_fsname : NULL;
#endif
}

void
fstab_close (gpointer handle)
{
#ifdef __FreeBSD__
	endfsent ();
#else
	fclose (handle);
#endif
}

#ifdef __FreeBSD__
#define UMOUNT		"/sbin/umount"
#elif sun
#define UMOUNT		"/sbin/umount"
#else
#define UMOUNT		"/bin/umount"
#endif

void
unknown_error (const char *detail)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.UnknownFailure\n");
	fprintf (stderr, "%s\n", detail);
	exit (1);
}


static void
device_busy (const char *detail)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.Busy\n");
	fprintf (stderr, "%s\n", detail);
	exit (1);
}


static void
not_mounted (const char *detail)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.NotMounted\n");
	fprintf (stderr, "%s\n", detail);
	exit (1);
}


static void
not_mounted_by_hal (const char *detail)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.NotMountedByHal\n");
	fprintf (stderr, "%s\n", detail);
	exit (1);
}

static void
permission_denied_privilege (const char *privilege, const char *uid)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.PermissionDeniedByPolicy\n");
	fprintf (stderr, "%s refused uid %s\n", privilege, uid);
	exit (1);
}

static void
permission_denied_volume_ignore (const char *device)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.PermissionDenied\n");
	fprintf (stderr, "Device has %s volume.ignore set to TRUE. Refusing to mount.\n", device);
	exit (1);
}

void
handle_unmount (LibHalContext *hal_ctx,
#ifdef HAVE_POLKIT
		LibPolKitContext *pol_ctx,
#endif
		const char *udi,
		LibHalVolume *volume, LibHalDrive *drive, const char *device,
		const char *invoked_by_uid, const char *invoked_by_syscon_name,
		gboolean option_lazy, gboolean option_force,
		DBusConnection *system_bus)
{
	int i, j;
	DBusError error;
	GError *err = NULL;
	char *sout = NULL;
	char *serr = NULL;
	int exit_status;
	char *args[10];
	int na;
	FILE *hal_mtab_orig;
	int hal_mtab_orig_len;
	int num_read;
	char *hal_mtab_buf;
	char **lines;
	char *mount_point_to_unmount;
	gboolean mounted_by_other_uid;
	FILE *hal_mtab_new;
#ifdef sun
	adt_export_data_t *adt_data;
	size_t adt_data_size;
#endif

#ifdef DEBUG
	printf ("device                           = %s\n", device);
	printf ("invoked by uid                   = %s\n", invoked_by_uid);
	printf ("invoked by system bus connection = %s\n", invoked_by_syscon_name);
#endif

	if (volume != NULL) {
		dbus_error_init (&error);
		if (libhal_device_get_property_bool (hal_ctx, udi, "volume.ignore", &error) ||
		    dbus_error_is_set (&error)) {
			if (dbus_error_is_set (&error)) {
				LIBHAL_FREE_DBUS_ERROR (&error);
			}
			/*
			 * When device allocation is enabled (bsmconv or TX), we
			 * set volume.ignore on all volumes, but still want
			 * Mount() to succeed when called from the euid=0
			 * device allocation program.
			 */
			if (atol (invoked_by_uid) != 0) {
				permission_denied_volume_ignore (device);
			}
		}

		if (!libhal_volume_is_mounted (volume)) {
			not_mounted ("According to HAL, the volume is not mounted");
		}
	}


	/* check hal's mtab file to verify the device to unmount is actually mounted by hal */
	hal_mtab_orig = fopen ("/media/.hal-mtab", "r");
	if (hal_mtab_orig == NULL) {
		unknown_error ("Cannot open /media/.hal-mtab");
	}
	if (fseek (hal_mtab_orig, 0L, SEEK_END) != 0) {
		unknown_error ("Cannot seek to end of /media/.hal-mtab");
	}
	hal_mtab_orig_len = ftell (hal_mtab_orig);
	if (hal_mtab_orig_len < 0) {
		unknown_error ("Cannot determine size of /media/.hal-mtab");
	}
	rewind (hal_mtab_orig);
	hal_mtab_buf = g_new0 (char, hal_mtab_orig_len + 1);
	num_read = fread (hal_mtab_buf, 1, hal_mtab_orig_len, hal_mtab_orig);
	if (num_read != hal_mtab_orig_len) {
		unknown_error ("Cannot read from /media/.hal-mtab");
	}
	fclose (hal_mtab_orig);

#ifdef DEBUG
	printf ("hal_mtab = '%s'\n", hal_mtab_buf);
#endif

	lines = g_strsplit (hal_mtab_buf, "\n", 0);
	g_free (hal_mtab_buf);

	mount_point_to_unmount = NULL;
	mounted_by_other_uid = TRUE;

	/* find the entry we're going to unmount */
	for (i = 0; lines[i] != NULL; i++) {
		char **line_elements;
		char *special, *dosp;
		struct stat st;

#ifdef DEBUG
		printf (" line = '%s'\n", lines[i]);
#endif

		if ((lines[i])[0] == '#')
			continue;

		line_elements = g_strsplit (lines[i], "\t", 6);
		if (g_strv_length (line_elements) == 6) {

#ifdef DEBUG
			printf ("  devfile     = '%s'\n", line_elements[0]);
			printf ("  uid         = '%s'\n", line_elements[1]);
			printf ("  session id  = '%s'\n", line_elements[2]);
			printf ("  fs          = '%s'\n", line_elements[3]);
			printf ("  options     = '%s'\n", line_elements[4]);
			printf ("  mount_point = '%s'\n", line_elements[5]);
#endif

			if (strcmp (line_elements[0], device) == 0) {
				char *line_to_free;

				if (strcmp (line_elements[1], invoked_by_uid) == 0) {
					mounted_by_other_uid = FALSE;
				}
#ifdef sun
				if (stat("/dev/vt/console_user", &st) == 0 &&
				    st.st_uid == atoi (invoked_by_uid)) {
					/*
					 * Owner is allowed to take over. Before we have real
					 * ownership in HAL, assume it's the console owner.
					 */
					mounted_by_other_uid = FALSE;
				}
#endif /* sun */
				mount_point_to_unmount = g_strdup (line_elements[5]);

				line_to_free = lines[i];

				for (j = i; lines[j] != NULL; j++) {
					lines[j] = lines[j+1];
				}
				lines[j] = NULL;

				g_free (line_to_free);

				g_strfreev (line_elements);
				goto line_found;

			}

		}

		g_strfreev (line_elements);
	}
line_found:

	if (mount_point_to_unmount == NULL) {
		not_mounted_by_hal ("Device to unmount is not in /media/.hal-mtab so it is not mounted by HAL");
	}

	/* bail out, unless if we got the "hal-storage-can-unmount-volumes-mounted-by-others" privilege only
	 * if mounted_by_other_uid==TRUE
	 *
	 * We allow uid 0 to actually ensure that Unmount(options=["lazy"], "/dev/blah") works from addon-storage.
	 */
	if ((strcmp (invoked_by_uid, "0") != 0) && mounted_by_other_uid) {
		/* TODO: actually check for privilege "hal-storage-can-unmount-volumes-mounted-by-others" */
		permission_denied_privilege ("hal-storage-can-unmount-volumes-mounted-by-others", invoked_by_uid);
	}

	/* create new .hal-mtab~ file without the entry we're going to unmount */
	hal_mtab_new = fopen ("/media/.hal-mtab~", "w");
	if (hal_mtab_new == NULL) {
		unknown_error ("Cannot create /media/.hal-mtab~");
	}
	for (i = 0; lines[i] != NULL; i++) {
		if (i > 0) {
			char anewl[2] = "\n\0";
			if (fwrite (anewl, 1, 1, hal_mtab_new) != 1) {
				unknown_error ("Cannot write to /media/.hal-mtab~");
			}
		}

		if (fwrite (lines[i], 1, strlen (lines[i]), hal_mtab_new) != strlen (lines[i])) {
			unknown_error ("Cannot write to /media/.hal-mtab~");
		}

	}
	fclose (hal_mtab_new);

	g_strfreev (lines);

	/* construct arguments to /bin/umount */
	na = 0;
	args[na++] = UMOUNT;
	if (option_lazy)
		args[na++] = "-l";
	if (option_force)
		args[na++] = "-f";
	args[na++] = (char *) device;
	args[na++] = NULL;

#ifdef DEBUG
	printf ("will umount %s (mounted at '%s'), mounted_by_other_uid=%d\n",
		device, mount_point_to_unmount, mounted_by_other_uid);
#endif

	/* invoke /bin/umount */
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
		printf ("Cannot execute %s\n", UMOUNT);
		unlink ("/media/.hal-mtab~");
		unknown_error ("Cannot spawn " UMOUNT);
	}

	/* check if unmount was succesful */
	if (exit_status != 0) {
		printf ("%s error %d, stdout='%s', stderr='%s'\n", UMOUNT, exit_status, sout, serr);

		if (strstr (serr, "device is busy") != NULL) {
			unlink ("/media/.hal-mtab~");
			device_busy (serr);
		} else {
			unlink ("/media/.hal-mtab~");
			unknown_error (serr);
		}
	}

#ifdef sun
	if ((adt_data = get_audit_export_data (system_bus,
	    invoked_by_syscon_name, &adt_data_size)) != NULL) {
		audit_volume (adt_data, ADT_detach, WEXITSTATUS(exit_status),
		    "solaris.device.mount.removable",
		    mount_point_to_unmount, device, NULL);
		free (adt_data);
	}
#endif

	/* unmount was succesful, remove directory we created in Mount() */
#ifdef sun
	if (strncmp (mount_point_to_unmount, "/media/", 7) == 0)
#endif
	if (g_rmdir (mount_point_to_unmount) != 0) {
		unlink ("/media/.hal-mtab~");
		unknown_error ("Cannot remove directory");
	}

	/* set new .hal-mtab file */
	if (rename ("/media/.hal-mtab~", "/media/.hal-mtab") != 0) {
		unlink ("/media/.hal-mtab~");
		unknown_error ("Cannot rename /media/.hal-mtab~ to /media/.hal-mtab");
	}

#ifdef DEBUG
	printf ("done unmounting\n");
#endif
	openlog ("hald", 0, LOG_DAEMON);
	syslog (LOG_INFO, "unmounted %s from '%s' on behalf of uid %s", device, mount_point_to_unmount, invoked_by_uid);
	closelog ();

	g_free (sout);
	g_free (serr);
	g_free (mount_point_to_unmount);
}

#define EJECT "/usr/bin/eject"

void
handle_eject (LibHalContext *hal_ctx,
#ifdef HAVE_POLKIT
	      LibPolKitContext *pol_ctx,
#endif
	      const char *udi,
	      LibHalDrive *drive, const char *device,
	      const char *invoked_by_uid, const char *invoked_by_syscon_name,
	      gboolean closetray, DBusConnection *system_bus)
{
	GError *err = NULL;
	char *sout = NULL;
	char *serr = NULL;
	int exit_status;
	char *args[10];
	int na;
#ifdef sun
	adt_export_data_t *adt_data;
	size_t adt_data_size;
#endif
	/* TODO: should we require privileges here? */

#ifdef DEBUG
	printf ("device                           = %s\n", device);
	printf ("invoked by uid                   = %s\n", invoked_by_uid);
	printf ("invoked by system bus connection = %s\n", invoked_by_syscon_name);
#endif

	/* construct arguments to EJECT (e.g. /usr/bin/eject) */
	na = 0;
	args[na++] = EJECT;
	if (closetray) {
		args[na++] = "-t";
	}
	args[na++] = (char *) device;
	args[na++] = NULL;

#ifdef sun
	putenv("EJECT_DIRECT=1");
#endif

#ifdef DEBUG
	printf ("will eject %s\n", device);
#endif

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
		printf ("Cannot execute %s\n", EJECT);
		unknown_error ("Cannot spawn " EJECT);
	}

#ifdef sun
	/*
	 * Solaris eject returns 4 for manually ejectable media like floppy.
	 * Consider it success.
	 */
	if (WEXITSTATUS(exit_status) == 4) {
		exit_status = 0;
	}

	if ((adt_data = get_audit_export_data (system_bus,
	    invoked_by_syscon_name, &adt_data_size)) != NULL) {
		audit_volume (adt_data, ADT_remove, WEXITSTATUS(exit_status),
		    "solaris.device.mount.removable", NULL, device, NULL);
		free (adt_data);
	}
#endif /* sun */

	/* check if eject was succesful */
	if (exit_status != 0) {
		printf ("%s error %d, stdout='%s', stderr='%s'\n", EJECT, exit_status, sout, serr);

		unknown_error (serr);
	}

	/* eject was succesful... */

#ifdef DEBUG
	printf ("done ejecting\n");
#endif

	g_free (sout);
	g_free (serr);
}


static int lock_mtab_fd = -1;

gboolean
lock_hal_mtab (void)
{
	if (lock_mtab_fd >= 0)
		return TRUE;

	printf ("%d: XYA attempting to get lock on /media/.hal-mtab-lock\n", getpid ());

	lock_mtab_fd = open ("/media/.hal-mtab-lock", O_CREAT | O_RDWR);

	if (lock_mtab_fd < 0)
		return FALSE;

tryagain:
#if sun
	if (lockf (lock_mtab_fd, F_LOCK, 0) != 0) {
#else
	if (flock (lock_mtab_fd, LOCK_EX) != 0) {
#endif
		if (errno == EINTR)
			goto tryagain;
		return FALSE;
	}

	printf ("%d: XYA got lock on /media/.hal-mtab-lock\n", getpid ());


	return TRUE;
}

void
unlock_hal_mtab (void)
{
#if sun
	lockf (lock_mtab_fd, F_ULOCK, 0);
#else
	flock (lock_mtab_fd, LOCK_UN);
#endif
	close (lock_mtab_fd);
	lock_mtab_fd = -1;
	printf ("%d: XYA released lock on /media/.hal-mtab-lock\n", getpid ());
}

#if sun

/* map PolicyKit privilege to RBAC authorization */
char *
auth_from_privilege(const char *privilege)
{
	char *authname;
	int i;

	if (strcmp (privilege, "hal-storage-removable-mount") == 0) {
		authname = g_strdup ("solaris.device.mount.removable");
	} else if (strcmp (privilege, "hal-storage-removable-mount-all-options") == 0) {
		authname = g_strdup ("solaris.device.mount.alloptions.removable");
	} else if (strcmp (privilege, "hal-storage-fixed-mount") == 0) {
		authname = g_strdup ("solaris.device.mount.fixed");
	} else if (strcmp (privilege, "hal-storage-fixed-mount-all-options") == 0) {
		authname = g_strdup ("solaris.device.mount.alloptions.fixed");
	} else {
		/* replace '-' with '.' */
		authname = g_strdup (privilege);
		for (i = 0; i < strlen (authname); i++) {
			if (authname[i] == '-') {
				authname[i] = '.';
			}
		}
	}
	return (authname);
}

void
audit_volume(const adt_export_data_t *imported_state, au_event_t event_id,
    int result, const char *auth_used, const char *mount_point,
    const char *device, const char *options)
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
	case ADT_attach:
		event->adt_attach.auth_used = (char *)auth_used;
		event->adt_attach.mount_point = (char *)mount_point;
		event->adt_attach.device = (char *)device;
		event->adt_attach.options = (char *)options;
		break;
	case ADT_detach:
		event->adt_detach.auth_used = (char *)auth_used;
		event->adt_detach.mount_point = (char *)mount_point;
		event->adt_detach.device = (char *)device;
		event->adt_detach.options = (char *)options;
		break;
	case ADT_remove:
		event->adt_remove.auth_used = (char *)auth_used;
		event->adt_remove.mount_point = (char *)mount_point;
		event->adt_remove.device = (char *)device;
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

#endif /* sun */
