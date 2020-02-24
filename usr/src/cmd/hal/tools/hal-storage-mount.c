/***************************************************************************
 * CVSID: $Id$
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
#include <sys/mnttab.h>
#include <sys/vfstab.h>
#include <sys/wait.h>
#else
#include <mntent.h>
#endif
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <libhal.h>
#include <libhal-storage.h>
#ifdef HAVE_POLKIT
#include <libpolkit.h>
#endif

#include "hal-storage-shared.h"

#ifdef __FreeBSD__
#define MOUNT		"/sbin/mount"
#define MOUNT_OPTIONS	"noexec,nosuid"
#define MOUNT_TYPE_OPT	"-t"
#elif sun
#define MOUNT		"/sbin/mount"
#define MOUNT_OPTIONS	"nosuid"
#define MOUNT_TYPE_OPT	"-F"
#else
#define MOUNT		"/bin/mount"
#define MOUNT_OPTIONS	"noexec,nosuid,nodev"
#define MOUNT_TYPE_OPT	"-t"
#endif

static void
usage (void)
{
	fprintf (stderr, "This program should only be started by hald.\n");
	exit (1);
}

static void
permission_denied_volume_ignore (const char *device)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.PermissionDenied\n");
	fprintf (stderr, "Device has %s volume.ignore set to TRUE. Refusing to mount.\n", device);
	exit (1);
}

static void
permission_denied_etc_fstab (const char *device)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.PermissionDenied\n");
	fprintf (stderr, "Device %s is listed in /etc/fstab. Refusing to mount.\n", device);
	exit (1);
}

static void
already_mounted (const char *device)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.AlreadyMounted\n");
	fprintf (stderr, "Device %s is already mounted.\n", device);
	exit (1);
}

static void
invalid_mount_option (const char *option, const char *uid)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.InvalidMountOption\n");
	fprintf (stderr, "The option '%s' is not allowed for uid=%s\n", option, uid);
	exit (1);
}

static void
unknown_filesystem (const char *filesystem)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.UnknownFilesystemType\n");
	fprintf (stderr, "Unknown file system '%s'\n", filesystem);
	exit (1);
}

static void
invalid_mount_point (const char *mount_point)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.InvalidMountpoint\n");
	fprintf (stderr, "The mount point '%s' is invalid\n", mount_point);
	exit (1);
}

static void
mount_point_not_available (const char *mount_point)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.MountPointNotAvailable\n");
	fprintf (stderr, "The mount point '%s' is already occupied\n", mount_point);
	exit (1);
}


static void
cannot_remount (const char *device)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.Volume.CannotRemount\n");
	fprintf (stderr, "%s not mounted already\n", device);
	exit (1);
}

#ifdef HAVE_POLKIT
static void
permission_denied_privilege (const char *privilege, const char *uid)
{
	fprintf (stderr, "org.freedesktop.Hal.Device.PermissionDeniedByPolicy\n");
	fprintf (stderr, "%s refused uid %s\n", privilege, uid);
	exit (1);
}
#endif


/* borrowed from gtk/gtkfilesystemunix.c in GTK+ on 02/23/2006 */
static void
canonicalize_filename (gchar *filename)
{
	gchar *p, *q;
	gboolean last_was_slash = FALSE;
	
	p = filename;
	q = filename;
	
	while (*p)
	{
		if (*p == G_DIR_SEPARATOR)
		{
			if (!last_was_slash)
				*q++ = G_DIR_SEPARATOR;
			
			last_was_slash = TRUE;
		}
		else
		{
			if (last_was_slash && *p == '.')
			{
				if (*(p + 1) == G_DIR_SEPARATOR ||
				    *(p + 1) == '\0')
				{
					if (*(p + 1) == '\0')
						break;
					
					p += 1;
				}
				else if (*(p + 1) == '.' &&
					 (*(p + 2) == G_DIR_SEPARATOR ||
					  *(p + 2) == '\0'))
				{
					if (q > filename + 1)
					{
						q--;
						while (q > filename + 1 &&
						       *(q - 1) != G_DIR_SEPARATOR)
							q--;
					}
					
					if (*(p + 2) == '\0')
						break;
					
					p += 2;
				}
				else
				{
					*q++ = *p;
					last_was_slash = FALSE;
				}
			}
			else
			{
				*q++ = *p;
				last_was_slash = FALSE;
			}
		}
		
		p++;
	}
	
	if (q > filename + 1 && *(q - 1) == G_DIR_SEPARATOR)
		q--;
	
	*q = '\0';
}

static char *
resolve_symlink (const char *file)
{
	GError *error = NULL;
	char *dir;
	char *link;
	char *f;
	char *f1;

	f = g_strdup (file);

	while (g_file_test (f, G_FILE_TEST_IS_SYMLINK)) {
		link = g_file_read_link (f, &error);
		if (link == NULL) {
			g_warning ("Cannot resolve symlink %s: %s", f, error->message);
			g_error_free (error);
			g_free (f);
			f = NULL;
			goto out;
		}
		
		dir = g_path_get_dirname (f);
		f1 = g_strdup_printf ("%s/%s", dir, link);
		g_free (dir);
		g_free (link);
		g_free (f);
		f = f1;
	}

out:
	if (f != NULL)
		canonicalize_filename (f);
	return f;
}

static LibHalVolume *
volume_findby (LibHalContext *hal_ctx, const char *property, const char *value)
{
	int i;
	char **hal_udis;
	int num_hal_udis;
	LibHalVolume *result = NULL;
	char *found_udi = NULL;
	DBusError error;

	dbus_error_init (&error);
	if ((hal_udis = libhal_manager_find_device_string_match (hal_ctx, property, 
								 value, &num_hal_udis, &error)) == NULL) {
		LIBHAL_FREE_DBUS_ERROR (&error);
		goto out;
	}
	for (i = 0; i < num_hal_udis; i++) {
		char *udi;
		udi = hal_udis[i];
		if (libhal_device_query_capability (hal_ctx, udi, "volume", &error)) {
			found_udi = strdup (udi);
			break;
		}
	}

	libhal_free_string_array (hal_udis);

	if (found_udi != NULL)
		result = libhal_volume_from_udi (hal_ctx, found_udi);

	free (found_udi);
out:
	return result;
}

static void
bailout_if_in_fstab (LibHalContext *hal_ctx, const char *device, const char *label, const char *uuid)
{
	gpointer handle;
	char *entry;
	char *_mount_point;

	printf (" label '%s'  uuid '%s'\n", label ? label : "" , uuid ? uuid : "");

	/* check if /etc/fstab mentions this device... (with symlinks etc) */
	if (! fstab_open (&handle)) {
		printf ("cannot open /etc/fstab\n");
		unknown_error ("Cannot open /etc/fstab");		
	}
	while ((entry = fstab_next (handle, &_mount_point)) != NULL) {
		char *resolved;

#ifdef DEBUG
		printf ("Looking at /etc/fstab entry '%s'\n", entry);
#endif
		if (label != NULL && g_str_has_prefix (entry, "LABEL=")) {
			if (strcmp (entry + 6, label) == 0) {
				gboolean skip_fstab_entry;

				skip_fstab_entry = FALSE;

				/* (heck, we also do the stuff below in gnome-mount) */

				/* OK, so what's if someone attaches an external disk with the label '/' and
				 * /etc/fstab has
				 *
				 *    LABEL=/    /    ext3    defaults    1 1
				 *
				 * in /etc/fstab as most Red Hat systems do? Bugger, this is a very common use
				 * case; suppose that you take the disk from your Fedora server and attaches it
				 * to your laptop. Bingo, you now have two disks with the label '/'. One must
				 * seriously wonder if using things like LABEL=/ for / is a good idea; just
				 * what happens if you boot in this configuration? (answer: the initrd gets
				 * it wrong most of the time.. sigh)
				 *
				 * To work around this, check if the listed entry in /etc/fstab is already mounted,
				 * if it is, then check if it's the same device_file as the given one...
				 */

				/* see if a volume is mounted at this mount point  */
				if (_mount_point != NULL) {
					LibHalVolume *mounted_vol;

					mounted_vol = volume_findby (hal_ctx, "volume.mount_point", _mount_point);
					if (mounted_vol != NULL) {
						const char *mounted_vol_device_file;

						mounted_vol_device_file = libhal_volume_get_device_file (mounted_vol);
						/* no need to resolve symlinks, hal uses the canonical device file */
						if (mounted_vol_device_file != NULL &&
						    strcmp (mounted_vol_device_file, device) !=0) {
#ifdef DEBUG
							printf ("Wanting to mount %s that has label %s, but /etc/fstab says LABEL=%s is to be mounted at mount point '%s'. However %s (that also has label %s), is already mounted at said mount point. So, skipping said /etc/fstab entry.\n", 
								   device, label, label, _mount_point, mounted_vol_device_file, _mount_point);
#endif
							skip_fstab_entry = TRUE;
						}
						libhal_volume_free (mounted_vol);
					}
				}
				
				if (!skip_fstab_entry) {
					printf ("%s found in /etc/fstab. Not mounting.\n", entry);
					permission_denied_etc_fstab (device);
				}
			}
		} else if (uuid != NULL && g_str_has_prefix (entry, "UUID=")) {
			if (strcmp (entry + 5, uuid) == 0) {
				printf ("%s found in /etc/fstab. Not mounting.\n", entry);
				permission_denied_etc_fstab (device);
			}
		} else {

			resolved = resolve_symlink (entry);
#ifdef DEBUG
			printf ("/etc/fstab: device %s -> %s \n", entry, resolved);
#endif
			if (strcmp (device, resolved) == 0) {
				printf ("%s (-> %s) found in /etc/fstab. Not mounting.\n", entry, resolved);
				permission_denied_etc_fstab (device);
			}

			g_free (resolved);
		}
	}
	fstab_close (handle);
}

static gboolean
device_is_mounted (const char *device, char **mount_point)
{
	gpointer handle;
	char *entry;
	gboolean ret;

	ret = FALSE;

	/* check if /proc/mounts mentions this device... (with symlinks etc) */
	if (! mtab_open (&handle)) {
		printf ("cannot open mount list\n");
		unknown_error ("Cannot open /etc/mtab or equivalent");		
	}
	while (((entry = mtab_next (handle, mount_point)) != NULL) && (ret == FALSE)) {
		char *resolved;

		resolved = resolve_symlink (entry);
#ifdef DEBUG
		printf ("/proc/mounts: device %s -> %s \n", entry, resolved);
#endif
		if (strcmp (device, resolved) == 0) {
			printf ("%s (-> %s) found in mount list. Not mounting.\n", entry, resolved);
			ret = TRUE;
		}

		g_free (resolved);
	}
	mtab_close (handle);
	return ret;
}

/* maps volume_id fs types to the appropriate -t mount option */
static const char *
map_fstype (const char *fstype)
{
#ifdef __FreeBSD__
	if (! strcmp (fstype, "iso9660"))
		return "cd9660";
	else if (! strcmp (fstype, "ext2"))
		return "ext2fs";
	else if (! strcmp (fstype, "vfat"))
		return "msdosfs";
#elif sun
	if (! strcmp (fstype, "iso9660"))
		return "hsfs";
	else if (! strcmp (fstype, "vfat"))
		return "pcfs";
#endif

	return fstype;
}

static void
handle_mount (LibHalContext *hal_ctx, 
#ifdef HAVE_POLKIT
	      LibPolKitContext *pol_ctx, 
#endif
	      const char *udi,
	      LibHalVolume *volume, LibHalDrive *drive, const char *device, 
	      const char *invoked_by_uid, const char *invoked_by_syscon_name,
	      DBusConnection *system_bus)
{
	int i, j;
	DBusError error;
	char mount_point[256];
	char mount_fstype[256];
	char mount_options[1024];
	char **allowed_options;
	char **given_options;
	gboolean wants_to_change_uid;
	char *mount_dir;
	GError *err = NULL;
	char *sout = NULL;
	char *serr = NULL;
	int exit_status;
	char *args[10];
	int na;
	GString *mount_option_str;
	gboolean pol_is_fixed;
	gboolean pol_change_uid;
	char *privilege;
	gboolean is_remount;
#ifdef HAVE_POLKIT
	gboolean allowed_by_privilege;
	gboolean is_temporary_privilege;
#endif
	gboolean explicit_mount_point_given;
	const char *end;
#ifdef __FreeBSD__
	struct passwd *pw;
	uid_t calling_uid;
	gid_t calling_gid;
#endif
	const char *label;
	const char *uuid;
	const char *model;
	const char *drive_type;
#ifdef sun
	adt_export_data_t *adt_data;
	size_t adt_data_size;
	gboolean append_ro = FALSE;
	gboolean is_abs_path = FALSE;
	uid_t calling_uid;

	calling_uid = atol (invoked_by_uid);
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

		label = libhal_volume_get_label (volume);
		uuid = libhal_volume_get_uuid (volume);
	} else {
		label = NULL;
		uuid = NULL;
	}

	bailout_if_in_fstab (hal_ctx, device, label, uuid);

	/* TODO: sanity check that what hal exports is correct (cf. Martin Pitt's email) */

	/* read from stdin */
	if (strlen (fgets (mount_point, sizeof (mount_point), stdin)) > 0)
		mount_point   [strlen (mount_point)   - 1] = '\0';
	if (strlen (fgets (mount_fstype, sizeof (mount_fstype), stdin)) > 0)
		mount_fstype  [strlen (mount_fstype)  - 1] = '\0';
	if (strlen (fgets (mount_options, sizeof (mount_options), stdin)) > 0)
		mount_options [strlen (mount_options) - 1] = '\0';
	/* validate that input from stdin is UTF-8 */
	if (!g_utf8_validate (mount_point, -1, &end))
		unknown_error ("Error validating mount_point as UTF-8");
	if (!g_utf8_validate (mount_fstype, -1, &end))
		unknown_error ("Error validating mount_fstype as UTF-8");
	if (!g_utf8_validate (mount_options, -1, &end))
		unknown_error ("Error validating mount_options as UTF-8");

#ifdef sun
	if (calling_uid != 0) {
#endif
	for (i = 0; mount_point[i] != '\0'; i++) {
		if (mount_point[i] == '\n' ||
		    mount_point[i] == G_DIR_SEPARATOR) {
			unknown_error ("mount_point cannot contain the following characters: newline, G_DIR_SEPARATOR (usually /)");
		}
	}
#ifdef sun
	}
	is_abs_path = (mount_point[0] == G_DIR_SEPARATOR);
#endif

#ifdef DEBUG
	printf ("mount_point    = '%s'\n", mount_point);
	printf ("mount_fstype   = '%s'\n", mount_fstype);
	printf ("mount_options  = '%s'\n", mount_options);
#endif

	/* delete any trailing whitespace options from splitting the string */
	given_options = g_strsplit (mount_options, "\t", 0);
	for (i = g_strv_length (given_options) - 1; i >= 0; --i) {
		if (strlen (given_options[i]) > 0)
			break;
		given_options[i] = NULL;
	}

#ifdef sun
	/* for read-only media append 'ro' option if not already */
	append_ro = libhal_device_get_property_bool (hal_ctx, libhal_drive_get_udi(drive),
	    "storage.removable.solaris.read_only", NULL);

	if (append_ro) {
		for (i = 0; i < (int) g_strv_length (given_options); i++) {
			if (strcmp (given_options[i], "ro") == 0) {
				append_ro = FALSE;
			}
		}
	}
#endif /* sun */

	/* is option 'remount' included? */
	is_remount = FALSE;
	for (i = 0; i < (int) g_strv_length (given_options); i++) {
		if (strcmp (given_options[i], "remount") == 0) {
			is_remount = TRUE;
		}
	}

	mount_dir = NULL;
	if (is_remount) {
		if (volume != NULL) {
			if (!libhal_volume_is_mounted (volume)) {
				cannot_remount (device);
			}
			mount_dir = g_strdup (libhal_volume_get_mount_point (volume));
		} else {
			if (!device_is_mounted (device, &mount_dir)) {
				cannot_remount (device);
			}
		}

		if (mount_dir == NULL) {
			unknown_error ("Cannot get mount_dir for remount even though volume is mounted!");
		}

	} else {
		if (volume != NULL) {
			if (libhal_volume_is_mounted (volume)) {
				already_mounted (device);
			}
		} else {
			if (device_is_mounted (device, NULL)) {
				already_mounted (device);
			}
		}
	}

	if (!is_remount) {
		/* figure out mount point if no mount point is given... */
		explicit_mount_point_given = FALSE;
		if (strlen (mount_point) == 0) {
			char *p;
			const char *label;
			
			if (volume != NULL)
				label = libhal_volume_get_label (volume);
			else
				label = NULL;
			
			model = libhal_drive_get_model (drive);
			drive_type = libhal_drive_get_type_textual (drive);

			if (label != NULL) {
				/* best - use label */
				g_strlcpy (mount_point, label, sizeof (mount_point));
				
			} else if ((model != NULL) && (strlen (model) > 0)) {
				g_strlcpy (mount_point, model, sizeof (mount_point));
			} else if ((drive_type != NULL) && (strlen (drive_type) > 0)) {
				g_strlcpy (mount_point, drive_type, sizeof (mount_point));
			} else {
				/* fallback - use "disk" */
				g_snprintf (mount_point, sizeof (mount_point), "disk");
			}
			
			/* sanitize computed mount point name, e.g. replace invalid chars with '-' */
			p = mount_point;
			while (TRUE) {
				p = g_utf8_strchr (mount_point, -1, G_DIR_SEPARATOR);
				if (p == NULL)
					break;
				*p = '-';
			};
			
		} else {
			explicit_mount_point_given = TRUE;
		}

		/* check mount point name - only forbid separators */
#ifdef sun
		if (calling_uid != 0) {
#endif
		if (g_utf8_strchr (mount_point, -1, G_DIR_SEPARATOR) != NULL) {
			printf ("'%s' is an invalid mount point\n", mount_point);
			invalid_mount_point (mount_point);
		}
#ifdef sun
		}
#endif
		
		/* check if mount point is available - append number to mount point */
		i = 0;
		mount_dir = NULL;
		while (TRUE) {
			g_free (mount_dir);
#ifdef sun
			if (is_abs_path)
				mount_dir = g_strdup (mount_point);
			else
#endif
			if (i == 0)
				mount_dir = g_strdup_printf ("/media/%s", mount_point);
			else
				mount_dir = g_strdup_printf ("/media/%s-%d", mount_point, i);

#ifdef DEBUG
			printf ("trying dir %s\n", mount_dir);
#endif

			/* XXX should test for being a mount point */
			if (!g_file_test (mount_dir, G_FILE_TEST_EXISTS)) {
				break;
			}

			if (explicit_mount_point_given) {
				mount_point_not_available (mount_dir);
			}
			
			i++;
		}
	}

	dbus_error_init (&error);
	allowed_options = libhal_device_get_property_strlist (hal_ctx, udi, "volume.mount.valid_options", &error);
	if (dbus_error_is_set (&error)) {
		unknown_error ("Cannot get volume.mount.valid_options");
		dbus_error_free (&error);
	}

#ifdef DEBUG
	for (i = 0; given_options[i] != NULL; i++)
		printf ("given_options[%d] = '%s'\n", i, given_options[i]);
	for (i = 0; allowed_options[i] != NULL; i++)
		printf ("allowed_options[%d] = '%s'\n", i, allowed_options[i]);
#endif

	wants_to_change_uid = FALSE;

	/* check mount options */
	for (i = 0; given_options[i] != NULL; i++) {
		char *given = given_options[i];

		for (j = 0; allowed_options[j] != NULL; j++) {
			char *allow = allowed_options[j];
			int allow_len = strlen (allow);

			if (strcmp (given, allow) == 0) {
				goto option_ok;
			}

			if ((allow[allow_len - 1] == '=') && 
			    (strncmp (given, allow, allow_len) == 0) &&
			    (int) strlen (given) > allow_len) {

				/* option matched allowed ending in '=', e.g.
				 * given == "umask=foobar" and allowed == "umask="
				 */
				if (strcmp (allow, "uid=") == 0) {
					uid_t uid;
					char *endp;
					/* check for uid=, it requires special handling */
					uid = (uid_t) strtol (given + allow_len, &endp, 10);
					if (*endp != '\0') {
						printf ("'%s' is not a number?\n", given);
						unknown_error ("option uid is malformed");
					}
#ifdef DEBUG
					printf ("%s with uid %d\n", allow, uid);
#endif
					wants_to_change_uid = TRUE;

					goto option_ok;
				} else {

					goto option_ok;
				}
			}
		}

		/* apparently option was not ok */
		invalid_mount_option (given, invoked_by_uid);

	option_ok:
		;
	}

	/* Check privilege */
	pol_is_fixed = TRUE;
	if (libhal_drive_is_hotpluggable (drive) || libhal_drive_uses_removable_media (drive))
		pol_is_fixed = FALSE;

	pol_change_uid = FALSE;
	/* don't consider uid= on non-pollable drives for the purpose of policy 
	 * (since these drives normally use vfat)
	 */
	if (volume != NULL) {
		/* don't consider uid= on vfat, iso9660, udf change-uid for the purpose of policy
		 * (since these doesn't contain uid/gid bits) 
		 */
		if (strcmp (libhal_volume_get_fstype (volume), "vfat") != 0 &&
		    strcmp (libhal_volume_get_fstype (volume), "iso9660") != 0 &&
		    strcmp (libhal_volume_get_fstype (volume), "udf") != 0) {
			pol_change_uid = wants_to_change_uid;
		}
	}

	if (pol_is_fixed) {
		if (pol_change_uid) {
			privilege = "hal-storage-fixed-mount-all-options";
		} else {
			privilege = "hal-storage-fixed-mount";
		}
	} else {
		if (pol_change_uid) {
			privilege = "hal-storage-removable-mount-all-options";
		} else {
			privilege = "hal-storage-removable-mount";
		}
	}

#ifdef DEBUG
	printf ("using privilege %s for uid %s, system_bus_connection %s\n", privilege, invoked_by_uid, 
		invoked_by_syscon_name);
#endif

#ifdef HAVE_POLKIT
	if (libpolkit_is_uid_allowed_for_privilege (pol_ctx, 
						    invoked_by_syscon_name,
						    invoked_by_uid,
						    privilege,
						    udi,
						    &allowed_by_privilege,
						    &is_temporary_privilege,
						    NULL) != LIBPOLKIT_RESULT_OK) {
		printf ("cannot lookup privilege\n");
		unknown_error ("Cannot lookup privilege from PolicyKit");
	}

	if (!allowed_by_privilege) {
		printf ("caller don't possess privilege\n");
		permission_denied_privilege (privilege, invoked_by_uid);
	}
#endif

#ifdef DEBUG
	printf ("passed privilege\n");
#endif

	if (!is_remount) {
		/* create directory */
#ifdef sun
		if (!g_file_test (mount_dir, G_FILE_TEST_EXISTS) &&
		    (g_mkdir (mount_dir, 0755) != 0)) {
#else
		if (g_mkdir (mount_dir, 0700) != 0) {
#endif
			printf ("Cannot create '%s'\n", mount_dir);
			unknown_error ("Cannot create mount directory");
		}
		
#ifdef __FreeBSD__
		calling_uid = (uid_t) strtol (invoked_by_uid, (char **) NULL, 10);
		pw = getpwuid (calling_uid);
		if (pw != NULL) {
			calling_gid = pw->pw_gid;
		} else {
			calling_gid = 0;
		}
		if (chown (mount_dir, calling_uid, calling_gid) != 0) {
			printf ("Cannot chown '%s' to uid: %d, gid: %d\n", mount_dir,
				calling_uid, calling_gid);
			g_rmdir (mount_dir);
			unknown_error ();
		}
#endif
	}

	char *mount_option_commasep = NULL;
	char *mount_do_fstype = "auto";

	/* construct arguments to mount */
	na = 0;
	args[na++] = MOUNT;
	if (strlen (mount_fstype) > 0) {
		mount_do_fstype = (char *) map_fstype (mount_fstype);
	} else if (volume == NULL) {
		/* non-pollable drive; force auto */
		mount_do_fstype = "auto";
	} else if (libhal_volume_get_fstype (volume) != NULL && strlen (libhal_volume_get_fstype (volume)) > 0) {
		mount_do_fstype = (char *) map_fstype (libhal_volume_get_fstype (volume));
	}
	args[na++] = MOUNT_TYPE_OPT;
	args[na++] = mount_do_fstype;

	args[na++] = "-o";
	mount_option_str = g_string_new (MOUNT_OPTIONS);
	for (i = 0; given_options[i] != NULL; i++) {
		g_string_append (mount_option_str, ",");
		g_string_append (mount_option_str, given_options[i]);
	}
#ifdef sun
	if (append_ro) {
		g_string_append (mount_option_str, ",ro");
	}
#endif
	mount_option_commasep = g_string_free (mount_option_str, FALSE); /* leak! */
	args[na++] = mount_option_commasep;
	args[na++] = (char *) device;
	args[na++] = mount_dir;
	args[na++] = NULL;

	/* TODO FIXME XXX HACK: OK, so we should rewrite the options in /media/.hal-mtab .. 
	 *                      but it doesn't really matter much at this point */
	if (!is_remount) {
		FILE *hal_mtab;
		char *mount_dir_escaped;
		FILE *hal_mtab_orig;
		int hal_mtab_orig_len;
		int num_read;
		char *hal_mtab_buf;
		char *hal_mtab_buf_old;
		
		/* Maintain a list in /media/.hal-mtab with entries of the following format
		 *
		 *  <device_file>\t<uid>\t<session-id>\t<fstype>\t<options_sep_by_comma>\t<mount point>\n
		 *
		 * where session-id currently is unused and thus set to 0.
		 *
		 * Example:
		 *
		 *  /dev/sda2	500	0	hfsplus	noexec,nosuid,nodev	/media/Macintosh HD
		 *  /dev/sda4	500	0	ntfs	noexec,nosuid,nodev,umask=222	/media/Windows
		 *  /dev/sdb1	500	0	vfat	noexec,nosuid,nodev,shortname=winnt,uid=500	/media/davidz
		 */
		
		
		if (g_file_test ("/media/.hal-mtab", G_FILE_TEST_EXISTS)) {
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
		} else {
			hal_mtab_buf = g_strdup ("");
		}
		
		mount_dir_escaped = g_strescape (mount_dir, NULL);
#ifdef DEBUG
		printf ("%d: XYA creating /media/.hal-mtab~\n", getpid ());
#endif
		hal_mtab = fopen ("/media/.hal-mtab~", "w");
		if (hal_mtab == NULL) {
			unknown_error ("Cannot create /media/.hal-mtab~");
		}
		hal_mtab_buf_old = hal_mtab_buf;
		hal_mtab_buf = g_strdup_printf ("%s%s\t%s\t0\t%s\t%s\t%s\n", 
						hal_mtab_buf_old,
						device, invoked_by_uid, mount_do_fstype, 
						mount_option_commasep, mount_dir_escaped);
		g_free (hal_mtab_buf_old);
		if (hal_mtab_buf_old == NULL) {
			unknown_error ("Out of memory appending to /media/.hal-mtab~");
		}
		if (fwrite (hal_mtab_buf, 1, strlen (hal_mtab_buf), hal_mtab) != strlen (hal_mtab_buf)) {
			unknown_error ("Cannot write to /media/.hal-mtab~");
		}
		fclose (hal_mtab);
		g_free (hal_mtab_buf);
		g_free (mount_dir_escaped);
#ifdef DEBUG
		printf ("%d: XYA closing /media/.hal-mtab~\n", getpid ());
#endif
	} /* !is_remount */
		
	/* now try to mount */
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
		printf ("Cannot execute %s\n", MOUNT);
		g_rmdir (mount_dir);
		unlink ("/media/.hal-mtab~");
		unknown_error ("Cannot spawn " MOUNT);
	}


	if (exit_status != 0) {
		char errstr[]  = "mount: unknown filesystem type";

		printf ("%s error %d, stdout='%s', stderr='%s'\n", MOUNT, exit_status, sout, serr);

		if (!is_remount) {
			g_rmdir (mount_dir);
			unlink ("/media/.hal-mtab~");
		}

		if (strncmp (errstr, serr, sizeof (errstr) - 1) == 0) {
			unknown_filesystem (strlen (mount_fstype) > 0 ? 
					    mount_fstype : 
					    (volume != NULL ? libhal_volume_get_fstype (volume) : "") );
		} else {
			int n;
			for (n = 0; serr[n] != '\0'; n++) {
				if (serr[n] == '\n') {
					serr[n] = ' ';
				}
			}
			unknown_error (serr);
		}
	}

	if (!is_remount) {
		if (rename ("/media/.hal-mtab~", "/media/.hal-mtab") != 0) {
			printf ("rename(2) failed, errno=%d -> '%s'\n", errno, strerror (errno));
			unlink ("/media/.hal-mtab~");
#ifdef DEBUG
			printf ("%d: XYA failed renaming /media/.hal-mtab~ to /media/.hal-mtab\n", getpid ());
#endif
			unknown_error ("Cannot rename /media/.hal-mtab~ to /media/.hal-mtab");
		}
#ifdef DEBUG
		printf ("%d: XYA done renaming /media/.hal-mtab~ to /media/.hal-mtab\n", getpid ());
#endif
	}

	openlog ("hald", 0, LOG_DAEMON);
	if (is_remount) {
		syslog (LOG_INFO, "remounted %s at '%s' on behalf of uid %s", device, mount_dir, invoked_by_uid);
	} else {
		syslog (LOG_INFO, "mounted %s on behalf of uid %s", device, invoked_by_uid);
	}
	closelog ();

#ifdef sun
	if ((adt_data = get_audit_export_data (system_bus,
	    invoked_by_syscon_name, &adt_data_size)) != NULL) {
		audit_volume (adt_data, ADT_attach,
		    WEXITSTATUS(exit_status), auth_from_privilege(privilege),
		    mount_dir, device, mount_option_commasep);
		free (adt_data);
	}
#endif

	g_free (sout);
	g_free (serr);
	g_free (mount_dir);
	libhal_free_string_array (allowed_options);
	g_strfreev (given_options);
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

	volume = libhal_volume_from_udi (hal_ctx, udi);
	if (volume == NULL) {
		LibHalDrive *drive;

		drive = libhal_drive_from_udi (hal_ctx, udi);
		if (drive == NULL) {
			usage ();
		} else {
			handle_mount (hal_ctx, 
#ifdef HAVE_POLKIT
				      pol_ctx, 
#endif
				      udi, NULL, drive, device, invoked_by_uid, 
				      invoked_by_syscon_name, system_bus);
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
		
		handle_mount (hal_ctx, 
#ifdef HAVE_POLKIT
			      pol_ctx, 
#endif
			      udi, volume, drive, device, invoked_by_uid, 
			      invoked_by_syscon_name, system_bus);

	}

	unlock_hal_mtab ();

	return 0;
}
