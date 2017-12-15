/***************************************************************************
 * CVSID: $Id$
 *
 * libhal-storage.c : HAL convenience library for storage devices and volumes
 *
 * Copyright (C) 2004 Red Hat, Inc.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dbus/dbus.h>

#include <libhal.h>
#include "libhal-storage.h"


#ifdef ENABLE_NLS
# include <libintl.h>
# define _(String) dgettext (GETTEXT_PACKAGE, String)
# ifdef gettext_noop
#   define N_(String) gettext_noop (String)
# else
#   define N_(String) (String)
# endif
#else
/* Stubs that do something close enough.  */
# define textdomain(String) (String)
# define gettext(String) (String)
# define dgettext(Domain,Message) (Message)
# define dcgettext(Domain,Message,Type) (Message)
# define bindtextdomain(Domain,Directory) (Domain)
# define _(String) (String)
# define N_(String) (String)
#endif

typedef struct IconMappingEntry_s {
	LibHalStoragePolicyIcon icon;
	char *path;
	struct IconMappingEntry_s *next;
} IconMappingEntry;

struct LibHalStoragePolicy_s {
	IconMappingEntry *icon_mappings;
};

LibHalStoragePolicy *
libhal_storage_policy_new ()
{
	LibHalStoragePolicy *p;

	p = malloc (sizeof (LibHalStoragePolicy));
	if (p == NULL)
		goto out;

	p->icon_mappings = NULL;
out:
	return p;
}

void
libhal_storage_policy_free (LibHalStoragePolicy *policy)
{
	IconMappingEntry *i;
	IconMappingEntry *j;

	/* free all icon mappings */
	for (i = policy->icon_mappings; i != NULL; i = j) {
		j = i->next;
		free (i->path);
		free (i);
	}

	free (policy);
}

void
libhal_storage_policy_set_icon_path (LibHalStoragePolicy *policy, LibHalStoragePolicyIcon icon, const char *path)
{
	IconMappingEntry *i;

	/* see if it already exist */
	for (i = policy->icon_mappings; i != NULL; i = i->next) {
		if (i->icon == icon) {
			free (i->path);
			i->path = strdup (path);
			goto out;
		}
	}

	i = malloc (sizeof (IconMappingEntry));
	if (i == NULL)
		goto out;
	i->icon = icon;
	i->path = strdup (path);
	i->next = policy->icon_mappings;
	policy->icon_mappings = i;

out:
	return;
}

void
libhal_storage_policy_set_icon_mapping (LibHalStoragePolicy *policy, LibHalStoragePolicyIconPair *pairs)
{
	LibHalStoragePolicyIconPair *i;

	for (i = pairs; i->icon != 0x00; i++) {
		libhal_storage_policy_set_icon_path (policy, i->icon, i->icon_path);
	}
}

const char *
libhal_storage_policy_lookup_icon (LibHalStoragePolicy *policy, LibHalStoragePolicyIcon icon)
{
	IconMappingEntry *i;
	const char *path;

	path = NULL;
	for (i = policy->icon_mappings; i != NULL; i = i->next) {
		if (i->icon == icon) {
			path = i->path;
			goto out;
		}
	}
out:
	return path;
}


#define MAX_STRING_SZ 256

char *
libhal_volume_policy_compute_size_as_string (LibHalVolume *volume)
{
	dbus_uint64_t size;
	char *result;
	char* sizes_str[] = {"K", "M", "G", "T", NULL};
	dbus_uint64_t cur = 1000L;
	dbus_uint64_t base = 10L;
	dbus_uint64_t step = 10L*10L*10L;
	int cur_str = 0;
	char buf[MAX_STRING_SZ];

	result = NULL;

	size = libhal_volume_get_size (volume);

	do {
		if (sizes_str[cur_str+1] == NULL || size < cur*step) {
			/* found the unit, display a comma number if result is a single digit */
			if (size < cur*base) {
				snprintf (buf, MAX_STRING_SZ, "%.01f%s", 
					  ((double)size)/((double)cur), sizes_str[cur_str]);
				result = strdup (buf);
			} else {
				snprintf (buf, MAX_STRING_SZ, "%llu%s", (long long unsigned int) size / cur, sizes_str[cur_str]);
				result = strdup (buf);
				}
			goto out;
		}

		cur *= step;
		cur_str++;
	} while (1);

out:
	return result;
}

static void
fixup_string (char *s)
{
	/* TODO: first strip leading and trailing whitespace */
	/*g_strstrip (s);*/

	/* TODO: could do nice things on all-upper case strings */
}

/* volume may be NULL (e.g. if drive supports removable media) */
char *
libhal_drive_policy_compute_display_name (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy)
{
	char *name;
	char *size_str;
	char *vendormodel_str;
	const char *model;
	const char *vendor;
	LibHalDriveType drive_type;
	dbus_bool_t drive_is_hotpluggable;
	dbus_bool_t drive_is_removable;
	LibHalDriveCdromCaps drive_cdrom_caps;
	char buf[MAX_STRING_SZ];

	model = libhal_drive_get_model (drive);
	vendor = libhal_drive_get_vendor (drive);
	drive_type = libhal_drive_get_type (drive);
	drive_is_hotpluggable = libhal_drive_is_hotpluggable (drive);
	drive_is_removable = libhal_drive_uses_removable_media (drive);
	drive_cdrom_caps = libhal_drive_get_cdrom_caps (drive);

	if (volume != NULL)
		size_str = libhal_volume_policy_compute_size_as_string (volume);
	else
		size_str = NULL;

	if (vendor == NULL || strlen (vendor) == 0) {
		if (model == NULL || strlen (model) == 0)
			vendormodel_str = strdup ("");
		else
			vendormodel_str = strdup (model);
	} else {
		if (model == NULL || strlen (model) == 0)
			vendormodel_str = strdup (vendor);
		else {
			snprintf (buf, MAX_STRING_SZ, "%s %s", vendor, model);
			vendormodel_str = strdup (buf);
		}
	}

	fixup_string (vendormodel_str);

	if (drive_type==LIBHAL_DRIVE_TYPE_CDROM) {

		/* Optical drive handling */
		char *first;
		char *second;


		first = "CD-ROM";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_CDR)
			first = "CD-R";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_CDRW)
			first = "CD-RW";

		second = "";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDROM)
			second = "/DVD-ROM";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSR)
			second = "/DVD+R";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRW)
			second = "/DVD+RW";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDR)
			second = "/DVD-R";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDRW)
			second = "/DVD-RW";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDRAM)
			second = "/DVD-RAM";
		if ((drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDR) &&
		    (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSR)) {
			if(drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRDL)
				second = "/DVD±R DL";
			else
				second = "/DVD±R";
		}
		if ((drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDRW) &&
		    (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRW)) {
                        if(drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRDL || 
			   drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRWDL)
                                second = "/DVD±RW DL";
                        else
                                second = "/DVD±RW";
                }
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_BDROM)
			second = "/BD-ROM";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_BDR)
			second = "/BD-R";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_BDRE)
			second = "/BD-RE";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_HDDVDROM)
			second = "/HD DVD-ROM";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_HDDVDR)
			second = "/HD DVD-R";
		if (drive_cdrom_caps & LIBHAL_DRIVE_CDROM_CAPS_HDDVDRW)
			second = "/HD DVD-RW";

		if (drive_is_hotpluggable) {
			snprintf (buf, MAX_STRING_SZ, _("External %s%s Drive"), first, second);
			name = strdup (buf);
		} else {
			snprintf (buf, MAX_STRING_SZ, _("%s%s Drive"), first, second);
			name = strdup (buf);
		}
			
	} else if (drive_type==LIBHAL_DRIVE_TYPE_FLOPPY) {

		/* Floppy Drive handling */

		if (drive_is_hotpluggable)
			name = strdup (_("External Floppy Drive"));
		else
			name = strdup (_("Floppy Drive"));
	} else if (drive_type==LIBHAL_DRIVE_TYPE_DISK && !drive_is_removable) {

		/* Harddisks */

		if (size_str != NULL) {
			if (drive_is_hotpluggable) {
				snprintf (buf, MAX_STRING_SZ, _("%s External Hard Drive"), size_str);
				name = strdup (buf);
			} else {
				snprintf (buf, MAX_STRING_SZ, _("%s Hard Drive"), size_str);
				name = strdup (buf);
			}
		} else {
			if (drive_is_hotpluggable)
				name = strdup (_("External Hard Drive"));
			else
				name = strdup (_("Hard Drive"));
		}
	} else {

		/* The rest - includes drives with removable Media */

		if (strlen (vendormodel_str) > 0)
			name = strdup (vendormodel_str);
		else
			name = strdup (_("Drive"));
	}

	free (vendormodel_str);
	free (size_str);

	return name;
}

char *
libhal_volume_policy_compute_display_name (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy)
{
	char *name;
	char *size_str;
	const char *volume_label;
	LibHalDriveType drive_type;
	dbus_bool_t drive_is_removable;
	char buf[MAX_STRING_SZ];

	volume_label = libhal_volume_get_label (volume);
	drive_type = libhal_drive_get_type (drive);
	drive_is_removable = libhal_drive_uses_removable_media (drive);

	size_str = libhal_volume_policy_compute_size_as_string (volume);

	/* If the volume label is available use that 
	 *
	 * TODO: If label is a fully-qualified UNIX path don't use that
	 */
	if (volume_label != NULL) {
		name = strdup (volume_label);
		goto out;
	}

	/* Handle media in optical drives */
	if (drive_type==LIBHAL_DRIVE_TYPE_CDROM) {
		switch (libhal_volume_get_disc_type (volume)) {

		default:
			/* explict fallthrough */
		case LIBHAL_VOLUME_DISC_TYPE_CDROM:
			name = strdup (_("CD-ROM "));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_CDR:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank CD-R"));
			else
				name = strdup (_("CD-R"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_CDRW:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank CD-RW"));
			else
				name = strdup (_("CD-RW"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_DVDROM:
			name = strdup (_("DVD-ROM"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_DVDRAM:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank DVD-RAM"));
			else
				name = strdup (_("DVD-RAM"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_DVDR:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank DVD-R"));
			else
				name = strdup (_("DVD-R"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_DVDRW:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank DVD-RW"));
			else
				name = strdup (_("DVD-RW"));
			break;

		case LIBHAL_VOLUME_DISC_TYPE_DVDPLUSR:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank DVD+R"));
			else
				name = strdup (_("DVD+R"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_DVDPLUSRW:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank DVD+RW"));
			else
				name = strdup (_("DVD+RW"));
			break;
		
		case LIBHAL_VOLUME_DISC_TYPE_DVDPLUSR_DL:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank DVD+R Dual-Layer"));
			else
				name = strdup (_("DVD+R Dual-Layer"));
			break;
		
		case LIBHAL_VOLUME_DISC_TYPE_BDROM:
			name = strdup (_("BD-ROM"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_BDR:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank BD-R"));
			else
				name = strdup (_("BD-R"));
			break;
		
		case LIBHAL_VOLUME_DISC_TYPE_BDRE:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank BD-RE"));
			else
				name = strdup (_("BD-RE"));
			break;
		
		case LIBHAL_VOLUME_DISC_TYPE_HDDVDROM:
			name = strdup (_("HD DVD-ROM"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_HDDVDR:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank HD DVD-R"));
			else
				name = strdup (_("HD DVD-R"));
			break;
			
		case LIBHAL_VOLUME_DISC_TYPE_HDDVDRW:
			if (libhal_volume_disc_is_blank (volume))
				name = strdup (_("Blank HD DVD-RW"));
			else
				name = strdup (_("HD DVD-RW"));
			break;

		}
		
		/* Special case for pure audio disc */
		if (libhal_volume_disc_has_audio (volume) && !libhal_volume_disc_has_data (volume)) {
			free (name);
			name = strdup (_("Audio CD"));
		}

		goto out;
	}

	/* Fallback: size of media */
	if (drive_is_removable) {
		snprintf (buf, MAX_STRING_SZ, _("%s Removable Media"), size_str);
		name = strdup (buf);
	} else {
		snprintf (buf, MAX_STRING_SZ, _("%s Media"), size_str);
		name = strdup (buf);
	}

	/* Fallback: Use drive name */
	/*name = libhal_drive_policy_compute_display_name (drive, volume);*/

out:
	free (size_str);
	return name;
}

char *
libhal_drive_policy_compute_icon_name (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy)
{
	const char *name;
	LibHalDriveBus bus;
	LibHalDriveType drive_type;

	bus        = libhal_drive_get_bus (drive);
	drive_type = libhal_drive_get_type (drive);

	/* by design, the enums are laid out so we can do easy computations */

	switch (drive_type) {
	case LIBHAL_DRIVE_TYPE_REMOVABLE_DISK:
	case LIBHAL_DRIVE_TYPE_DISK:
	case LIBHAL_DRIVE_TYPE_CDROM:
	case LIBHAL_DRIVE_TYPE_FLOPPY:
		name = libhal_storage_policy_lookup_icon (policy, 0x10000 + drive_type*0x100 + bus);
		break;

	default:
		name = libhal_storage_policy_lookup_icon (policy, 0x10000 + drive_type*0x100);
	}

	if (name != NULL)
		return strdup (name);
	else
		return NULL;
}

char *
libhal_volume_policy_compute_icon_name (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy)
{
	const char *name;
	LibHalDriveBus bus;
	LibHalDriveType drive_type;
	LibHalVolumeDiscType disc_type;

	/* by design, the enums are laid out so we can do easy computations */

	if (libhal_volume_is_disc (volume)) {
		disc_type = libhal_volume_get_disc_type (volume);
		name = libhal_storage_policy_lookup_icon (policy, 0x30000 + disc_type);
		goto out;
	}

	if (drive == NULL) {
		name = libhal_storage_policy_lookup_icon (policy, LIBHAL_STORAGE_ICON_VOLUME_REMOVABLE_DISK);
		goto out;
	}

	bus        = libhal_drive_get_bus (drive);
	drive_type = libhal_drive_get_type (drive);

	switch (drive_type) {
	case LIBHAL_DRIVE_TYPE_REMOVABLE_DISK:
	case LIBHAL_DRIVE_TYPE_DISK:
	case LIBHAL_DRIVE_TYPE_CDROM:
	case LIBHAL_DRIVE_TYPE_FLOPPY:
		name = libhal_storage_policy_lookup_icon (policy, 0x20000 + drive_type*0x100 + bus);
		break;

	default:
		name = libhal_storage_policy_lookup_icon (policy, 0x20000 + drive_type*0x100);
	}
out:
	if (name != NULL)
		return strdup (name);
	else
		return NULL;
}

/** Policy function to determine if a volume should be visible in a desktop 
 *  environment. This is useful to hide certain system volumes as bootstrap
 *  partitions, the /usr partition, swap partitions and other volumes that
 *  a unprivileged desktop user shouldn't know even exists.
 *
 *  @param  drive               Drive that the volume is stemming from
 *  @param  volume              Volume
 *  @param  policy              Policy object
 *  @param  target_mount_point  The mount point that the volume is expected to
 *                              be mounted at if not already mounted. This may
 *                              e.g. stem from /etc/fstab. If this is NULL the
 *                              then mount point isn't taking into account when
 *                              evaluating whether the volume should be visible
 *  @return                     Whether the volume should be shown in a desktop
 *                              environment.
 */
dbus_bool_t
libhal_volume_policy_should_be_visible (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy, 
				     const char *target_mount_point)
{
	unsigned int i;
	dbus_bool_t is_visible;
	const char *label;
	const char *mount_point;
	const char *fstype;
	const char *fhs23_toplevel_mount_points[] = {
		"/",
		"/bin",
		"/boot",
		"/dev",
		"/etc",
		"/home",
		"/lib",
		"/lib64",
		"/media",
		"/mnt",
		"/opt",
		"/root",
		"/sbin",
		"/srv",
		"/tmp",
		"/usr",
		"/var",
		"/proc",
		"/sbin",
		NULL
	};

	is_visible = FALSE;

	/* skip if hal says it's not used as a filesystem */
	if (libhal_volume_get_fsusage (volume) != LIBHAL_VOLUME_USAGE_MOUNTABLE_FILESYSTEM)
		goto out;

	label = libhal_volume_get_label (volume);
	mount_point = libhal_volume_get_mount_point (volume);
	fstype = libhal_volume_get_fstype (volume);

	/* use target mount point if we're not mounted yet */
	if (mount_point == NULL)
		mount_point = target_mount_point;

	/* bail out if we don't know the filesystem */
	if (fstype == NULL)
		goto out;

	/* blacklist fhs2.3 top level mount points */
	if (mount_point != NULL) {
		for (i = 0; fhs23_toplevel_mount_points[i] != NULL; i++) {
			if (strcmp (mount_point, fhs23_toplevel_mount_points[i]) == 0)
				goto out;
		}
	}

	/* blacklist partitions with name 'bootstrap' of type HFS (Apple uses that) */
	if (label != NULL && strcmp (label, "bootstrap") == 0 && strcmp (fstype, "hfs") == 0)
		goto out;

	/* only the real lucky mount points will make it this far :-) */
	is_visible = TRUE;

out:
	return is_visible;
}

/*************************************************************************/

#define MOUNT_OPTIONS_SIZE 256

struct LibHalDrive_s {
	char *udi;

	int device_major;
	int device_minor;
	char *device_file;

	LibHalDriveBus bus;
	char *vendor;             /* may be "", is never NULL */
	char *model;              /* may be "", is never NULL */
	dbus_bool_t is_hotpluggable;
	dbus_bool_t is_removable;
	dbus_bool_t is_media_detected;
	dbus_bool_t requires_eject;

	LibHalDriveType type;
	char *type_textual;

	char *physical_device;  /* UDI of physical device, e.g. the 
				 * IDE, USB, IEEE1394 device */

	char *dedicated_icon_drive;
	char *dedicated_icon_volume;

	char *serial;
	char *firmware_version;
	LibHalDriveCdromCaps cdrom_caps;

	char *desired_mount_point;
	char *mount_filesystem;
	dbus_bool_t should_mount;

	dbus_bool_t no_partitions_hint;

	dbus_uint64_t drive_size;
	dbus_uint64_t drive_media_size;
	char *partition_scheme;

	LibHalContext *hal_ctx;

	char **capabilities;

	char mount_options[MOUNT_OPTIONS_SIZE];
};

struct LibHalVolume_s {
	char *udi;

	int device_major;
	int device_minor;
	char *device_file;
	char *volume_label; /* may be NULL, is never "" */
	dbus_bool_t is_mounted;
	dbus_bool_t is_mounted_read_only; /* TRUE iff is_mounted and r/o fs */
	char *mount_point;  /* NULL iff !is_mounted */
	char *fstype;       /* NULL iff !is_mounted or unknown */
	char *fsversion;
	char *uuid;
	char *storage_device;

	LibHalVolumeUsage fsusage;

	dbus_bool_t is_partition;
	unsigned int partition_number;
	char *partition_scheme;
	char *partition_type;
	char *partition_label;
	char *partition_uuid;
	char **partition_flags;

	int msdos_part_table_type;
	dbus_uint64_t msdos_part_table_start;
	dbus_uint64_t msdos_part_table_size;
	
	dbus_bool_t is_disc;
	LibHalVolumeDiscType disc_type;
	dbus_bool_t disc_has_audio;
	dbus_bool_t disc_has_data;
	dbus_bool_t disc_is_appendable;
	dbus_bool_t disc_is_blank;
	dbus_bool_t disc_is_rewritable;

	unsigned int block_size;
	unsigned int num_blocks;

	char *desired_mount_point;
	char *mount_filesystem;
	dbus_bool_t should_mount;

	dbus_bool_t ignore_volume;

	char *crypto_backing_volume;

	char mount_options[MOUNT_OPTIONS_SIZE];

	dbus_uint64_t volume_size;
	dbus_uint64_t disc_capacity;

	dbus_uint64_t partition_start_offset;
	dbus_uint64_t partition_media_size;
};

const char *
libhal_drive_get_dedicated_icon_drive (LibHalDrive *drive)
{
	return drive->dedicated_icon_drive;
}

const char *
libhal_drive_get_dedicated_icon_volume (LibHalDrive *drive)
{
	return drive->dedicated_icon_volume;
}

/** Free all resources used by a LibHalDrive object.
 *
 *  @param  drive               Object to free
 */
void
libhal_drive_free (LibHalDrive *drive)
{
	if (drive == NULL )
		return;

	free (drive->udi);
	libhal_free_string (drive->device_file);
	libhal_free_string (drive->vendor);
	libhal_free_string (drive->model);
	libhal_free_string (drive->type_textual);
	libhal_free_string (drive->physical_device);
	libhal_free_string (drive->dedicated_icon_drive);
	libhal_free_string (drive->dedicated_icon_volume);
	libhal_free_string (drive->serial);
	libhal_free_string (drive->firmware_version);
	libhal_free_string (drive->desired_mount_point);
	libhal_free_string (drive->mount_filesystem);
	libhal_free_string_array (drive->capabilities);
	libhal_free_string (drive->partition_scheme);

	free (drive);
}


/** Free all resources used by a LibHalVolume object.
 *
 *  @param  vol              Object to free
 */
void
libhal_volume_free (LibHalVolume *vol)
{
	if (vol == NULL )
		return;

	free (vol->udi);
	libhal_free_string (vol->device_file);
	libhal_free_string (vol->volume_label);
	libhal_free_string (vol->fstype);
	libhal_free_string (vol->mount_point);
	libhal_free_string (vol->fsversion);
	libhal_free_string (vol->uuid);
	libhal_free_string (vol->desired_mount_point);
	libhal_free_string (vol->mount_filesystem);
	libhal_free_string (vol->crypto_backing_volume);
	libhal_free_string (vol->storage_device);

	libhal_free_string (vol->partition_scheme);
	libhal_free_string (vol->partition_type);
	libhal_free_string (vol->partition_label);
	libhal_free_string (vol->partition_uuid);
	libhal_free_string_array (vol->partition_flags);

	free (vol);
}


static char **
my_strvdup (char **strv)
{
	unsigned int num_elems;
	unsigned int i;
	char **res;

	for (num_elems = 0; strv[num_elems] != NULL; num_elems++)
		;

	res = calloc (num_elems + 1, sizeof (char*));
	if (res == NULL)
		goto out;

	for (i = 0; i < num_elems; i++)
		res[i] = strdup (strv[i]);
	res[i] = NULL;

out:
	return res;
}

/* ok, hey, so this is a bit ugly */

#define LIBHAL_PROP_EXTRACT_BEGIN if (FALSE)
#define LIBHAL_PROP_EXTRACT_END ;
#define LIBHAL_PROP_EXTRACT_INT(_property_, _where_) else if (strcmp (key, _property_) == 0 && type == LIBHAL_PROPERTY_TYPE_INT32) _where_ = libhal_psi_get_int (&it)
#define LIBHAL_PROP_EXTRACT_UINT64(_property_, _where_) else if (strcmp (key, _property_) == 0 && type == LIBHAL_PROPERTY_TYPE_UINT64) _where_ = libhal_psi_get_uint64 (&it)
#define LIBHAL_PROP_EXTRACT_STRING(_property_, _where_) else if (strcmp (key, _property_) == 0 && type == LIBHAL_PROPERTY_TYPE_STRING) _where_ = (libhal_psi_get_string (&it) != NULL && strlen (libhal_psi_get_string (&it)) > 0) ? strdup (libhal_psi_get_string (&it)) : NULL
#define LIBHAL_PROP_EXTRACT_BOOL(_property_, _where_) else if (strcmp (key, _property_) == 0 && type == LIBHAL_PROPERTY_TYPE_BOOLEAN) _where_ = libhal_psi_get_bool (&it)
#define LIBHAL_PROP_EXTRACT_BOOL_BITFIELD(_property_, _where_, _field_) else if (strcmp (key, _property_) == 0 && type == LIBHAL_PROPERTY_TYPE_BOOLEAN) _where_ |= libhal_psi_get_bool (&it) ? _field_ : 0
#define LIBHAL_PROP_EXTRACT_STRLIST(_property_, _where_) else if (strcmp (key, _property_) == 0 && type == LIBHAL_PROPERTY_TYPE_STRLIST) _where_ = my_strvdup (libhal_psi_get_strlist (&it))

/** Given a UDI for a HAL device of capability 'storage', this
 *  function retrieves all the relevant properties into convenient
 *  in-process data structures.
 *
 *  @param  hal_ctx             libhal context
 *  @param  udi                 HAL UDI
 *  @return                     LibHalDrive object or NULL if UDI is invalid
 */
LibHalDrive *
libhal_drive_from_udi (LibHalContext *hal_ctx, const char *udi)
{	
	char *bus_textual;
	LibHalDrive *drive;
	LibHalPropertySet *properties;
	LibHalPropertySetIterator it;
	DBusError error;
	unsigned int i;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, NULL);

	drive = NULL;
	properties = NULL;
	bus_textual = NULL;

	dbus_error_init (&error);
	if (!libhal_device_query_capability (hal_ctx, udi, "storage", &error))
		goto error;

	drive = malloc (sizeof (LibHalDrive));
	if (drive == NULL)
		goto error;
	memset (drive, 0x00, sizeof (LibHalDrive));

	drive->hal_ctx = hal_ctx;

	drive->udi = strdup (udi);
	if (drive->udi == NULL)
		goto error;

	properties = libhal_device_get_all_properties (hal_ctx, udi, &error);
	if (properties == NULL)
		goto error;

	/* we can count on hal to give us all these properties */
	for (libhal_psi_init (&it, properties); libhal_psi_has_more (&it); libhal_psi_next (&it)) {
		int type;
		char *key;
		
		type = libhal_psi_get_type (&it);
		key = libhal_psi_get_key (&it);

		LIBHAL_PROP_EXTRACT_BEGIN;

		LIBHAL_PROP_EXTRACT_INT    ("block.minor",               drive->device_minor);
		LIBHAL_PROP_EXTRACT_INT    ("block.major",               drive->device_major);
		LIBHAL_PROP_EXTRACT_STRING ("block.device",              drive->device_file);
		LIBHAL_PROP_EXTRACT_STRING ("storage.bus",               bus_textual);
		LIBHAL_PROP_EXTRACT_STRING ("storage.vendor",            drive->vendor);
		LIBHAL_PROP_EXTRACT_STRING ("storage.model",             drive->model);
		LIBHAL_PROP_EXTRACT_STRING ("storage.drive_type",        drive->type_textual);
		LIBHAL_PROP_EXTRACT_UINT64 ("storage.size", 		 drive->drive_size); 

		LIBHAL_PROP_EXTRACT_STRING ("storage.icon.drive",        drive->dedicated_icon_drive);
		LIBHAL_PROP_EXTRACT_STRING ("storage.icon.volume",       drive->dedicated_icon_volume);

		LIBHAL_PROP_EXTRACT_BOOL   ("storage.hotpluggable",      drive->is_hotpluggable);
		LIBHAL_PROP_EXTRACT_BOOL   ("storage.removable",         drive->is_removable);
		LIBHAL_PROP_EXTRACT_BOOL   ("storage.removable.media_available", drive->is_media_detected);
		LIBHAL_PROP_EXTRACT_UINT64 ("storage.removable.media_size", drive->drive_media_size); 
		LIBHAL_PROP_EXTRACT_BOOL   ("storage.requires_eject",    drive->requires_eject);

		LIBHAL_PROP_EXTRACT_STRING ("storage.partitioning_scheme", drive->partition_scheme); 

		LIBHAL_PROP_EXTRACT_STRING ("storage.physical_device",   drive->physical_device);
		LIBHAL_PROP_EXTRACT_STRING ("storage.firmware_version",  drive->firmware_version);
		LIBHAL_PROP_EXTRACT_STRING ("storage.serial",            drive->serial);

		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.cdr", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_CDR);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.cdrw", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_CDRW);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.dvd", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_DVDROM);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.dvdplusr", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSR);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.dvdplusrw", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRW);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.dvdplusrwdl", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRWDL);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.dvdplusrdl", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRDL);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.dvdr", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_DVDR);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.dvdrw", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_DVDRW);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.dvdram", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_DVDRAM);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.bd", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_BDROM);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.bdr", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_BDR);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.bdre", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_BDRE);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.hddvd", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_HDDVDROM);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.hddvdr", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_HDDVDR);
		LIBHAL_PROP_EXTRACT_BOOL_BITFIELD ("storage.cdrom.hddvdrw", drive->cdrom_caps, LIBHAL_DRIVE_CDROM_CAPS_HDDVDRW);

		LIBHAL_PROP_EXTRACT_BOOL   ("storage.policy.should_mount",        drive->should_mount);
		LIBHAL_PROP_EXTRACT_STRING ("storage.policy.desired_mount_point", drive->desired_mount_point);
		LIBHAL_PROP_EXTRACT_STRING ("storage.policy.mount_filesystem",    drive->mount_filesystem);

		LIBHAL_PROP_EXTRACT_BOOL   ("storage.no_partitions_hint",        drive->no_partitions_hint);

		LIBHAL_PROP_EXTRACT_STRLIST ("info.capabilities",                drive->capabilities);

		LIBHAL_PROP_EXTRACT_END;
	}

	if (drive->type_textual != NULL) {
		if (strcmp (drive->type_textual, "cdrom") == 0) {
			drive->cdrom_caps |= LIBHAL_DRIVE_CDROM_CAPS_CDROM;
			drive->type = LIBHAL_DRIVE_TYPE_CDROM;
		} else if (strcmp (drive->type_textual, "floppy") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_FLOPPY;
		} else if (strcmp (drive->type_textual, "disk") == 0) {
			if (drive->is_removable)
				drive->type = LIBHAL_DRIVE_TYPE_REMOVABLE_DISK;
			else
				drive->type = LIBHAL_DRIVE_TYPE_DISK;				
		} else if (strcmp (drive->type_textual, "tape") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_TAPE;
		} else if (strcmp (drive->type_textual, "compact_flash") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_COMPACT_FLASH;
		} else if (strcmp (drive->type_textual, "memory_stick") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_MEMORY_STICK;
		} else if (strcmp (drive->type_textual, "smart_media") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_SMART_MEDIA;
		} else if (strcmp (drive->type_textual, "sd_mmc") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_SD_MMC;
		} else if (strcmp (drive->type_textual, "zip") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_ZIP;
		} else if (strcmp (drive->type_textual, "jaz") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_JAZ;
		} else if (strcmp (drive->type_textual, "flashkey") == 0) {
			drive->type = LIBHAL_DRIVE_TYPE_FLASHKEY;
		} else {
		        drive->type = LIBHAL_DRIVE_TYPE_DISK; 
		}

	}

	if (drive->capabilities != NULL) {
		for (i = 0; drive->capabilities[i] != NULL; i++) {
			if (strcmp (drive->capabilities[i], "portable_audio_player") == 0) {
				drive->type = LIBHAL_DRIVE_TYPE_PORTABLE_AUDIO_PLAYER;
				break;
			} else if (strcmp (drive->capabilities[i], "camera") == 0) {
				drive->type = LIBHAL_DRIVE_TYPE_CAMERA;
				break;
			}
		}
	}

	if (bus_textual != NULL) {
		if (strcmp (bus_textual, "usb") == 0) {
			drive->bus = LIBHAL_DRIVE_BUS_USB;
		} else if (strcmp (bus_textual, "ieee1394") == 0) {
			drive->bus = LIBHAL_DRIVE_BUS_IEEE1394;
		} else if (strcmp (bus_textual, "ide") == 0) {
			drive->bus = LIBHAL_DRIVE_BUS_IDE;
		} else if (strcmp (bus_textual, "scsi") == 0) {
			drive->bus = LIBHAL_DRIVE_BUS_SCSI;
		} else if (strcmp (bus_textual, "ccw") == 0) {
			drive->bus = LIBHAL_DRIVE_BUS_CCW;
		}
	}

	libhal_free_string (bus_textual);
	libhal_free_property_set (properties);

	return drive;

error:
	LIBHAL_FREE_DBUS_ERROR(&error);
	libhal_free_string (bus_textual);
	libhal_free_property_set (properties);
	libhal_drive_free (drive);
	return NULL;
}

const char *
libhal_volume_get_storage_device_udi (LibHalVolume *volume)
{
	return volume->storage_device;
}

const char *libhal_drive_get_physical_device_udi (LibHalDrive *drive)
{
	return drive->physical_device;
}

dbus_bool_t
libhal_drive_requires_eject (LibHalDrive *drive)
{
	return drive->requires_eject;
}

/** Given a UDI for a LIBHAL device of capability 'volume', this
 *  function retrieves all the relevant properties into convenient
 *  in-process data structures.
 *
 *  @param  hal_ctx             libhal context
 *  @param  udi                 HAL UDI
 *  @return                     LibHalVolume object or NULL if UDI is invalid
 */
LibHalVolume *
libhal_volume_from_udi (LibHalContext *hal_ctx, const char *udi)
{
	char *disc_type_textual;
	char *vol_fsusage_textual;
	LibHalVolume *vol;
	LibHalPropertySet *properties;
	LibHalPropertySetIterator it;
	DBusError error;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, NULL);

	vol = NULL;
	properties = NULL;
	disc_type_textual = NULL;
	vol_fsusage_textual = NULL;

	dbus_error_init (&error);
	if (!libhal_device_query_capability (hal_ctx, udi, "volume", &error))
		goto error;

	vol = malloc (sizeof (LibHalVolume));
	if (vol == NULL)
		goto error;
	memset (vol, 0x00, sizeof (LibHalVolume));

	vol->udi = strdup (udi);

	properties = libhal_device_get_all_properties (hal_ctx, udi, &error);
	if (properties == NULL)
		goto error;

	/* we can count on hal to give us all these properties */
	for (libhal_psi_init (&it, properties); libhal_psi_has_more (&it); libhal_psi_next (&it)) {
		int type;
		char *key;
		
		type = libhal_psi_get_type (&it);
		key = libhal_psi_get_key (&it);

		LIBHAL_PROP_EXTRACT_BEGIN;

		LIBHAL_PROP_EXTRACT_BOOL   ("volume.is_partition",                    vol->is_partition);
		LIBHAL_PROP_EXTRACT_INT    ("volume.partition.number",                vol->partition_number);
		LIBHAL_PROP_EXTRACT_STRING ("volume.partition.scheme",                vol->partition_scheme);
		LIBHAL_PROP_EXTRACT_STRING ("volume.partition.type",                  vol->partition_type);
		LIBHAL_PROP_EXTRACT_STRING ("volume.partition.label",                 vol->partition_label);
		LIBHAL_PROP_EXTRACT_STRING ("volume.partition.uuid",                  vol->partition_uuid);
		LIBHAL_PROP_EXTRACT_STRLIST ("volume.partition.flags",                vol->partition_flags);

		LIBHAL_PROP_EXTRACT_UINT64 ("volume.partition.start", 		      vol->partition_start_offset); 
		LIBHAL_PROP_EXTRACT_UINT64 ("volume.partition.media_size",            vol->partition_media_size); 
		LIBHAL_PROP_EXTRACT_INT    ("volume.partition.msdos_part_table_type", vol->msdos_part_table_type);
		LIBHAL_PROP_EXTRACT_UINT64 ("volume.partition.msdos_part_table_start", vol->msdos_part_table_start);
		LIBHAL_PROP_EXTRACT_UINT64 ("volume.partition.msdos_part_table_size", vol->msdos_part_table_size);

		LIBHAL_PROP_EXTRACT_INT    ("block.minor",               vol->device_minor);
		LIBHAL_PROP_EXTRACT_INT    ("block.major",               vol->device_major);
		LIBHAL_PROP_EXTRACT_STRING ("block.device",              vol->device_file);

		LIBHAL_PROP_EXTRACT_STRING ("block.storage_device",      vol->storage_device);

		LIBHAL_PROP_EXTRACT_STRING ("volume.crypto_luks.clear.backing_volume", vol->crypto_backing_volume);

		LIBHAL_PROP_EXTRACT_INT    ("volume.block_size",         vol->block_size);
		LIBHAL_PROP_EXTRACT_INT    ("volume.num_blocks",         vol->num_blocks);
		LIBHAL_PROP_EXTRACT_UINT64 ("volume.size", 		 vol->volume_size); 
		LIBHAL_PROP_EXTRACT_STRING ("volume.label",              vol->volume_label);
		LIBHAL_PROP_EXTRACT_STRING ("volume.mount_point",        vol->mount_point);
		LIBHAL_PROP_EXTRACT_STRING ("volume.fstype",             vol->fstype);
		LIBHAL_PROP_EXTRACT_STRING ("volume.fsversion",             vol->fsversion);
		LIBHAL_PROP_EXTRACT_BOOL   ("volume.is_mounted",         vol->is_mounted);
		LIBHAL_PROP_EXTRACT_BOOL   ("volume.is_mounted_read_only", vol->is_mounted_read_only);
		LIBHAL_PROP_EXTRACT_STRING ("volume.fsusage",            vol_fsusage_textual);
		LIBHAL_PROP_EXTRACT_STRING ("volume.uuid",               vol->uuid);

		LIBHAL_PROP_EXTRACT_BOOL   ("volume.ignore",             vol->ignore_volume);

		LIBHAL_PROP_EXTRACT_BOOL   ("volume.is_disc",            vol->is_disc);
		LIBHAL_PROP_EXTRACT_STRING ("volume.disc.type",          disc_type_textual);
		LIBHAL_PROP_EXTRACT_BOOL   ("volume.disc.has_audio",     vol->disc_has_audio);
		LIBHAL_PROP_EXTRACT_BOOL   ("volume.disc.has_data",      vol->disc_has_data);
		LIBHAL_PROP_EXTRACT_BOOL   ("volume.disc.is_appendable", vol->disc_is_appendable);
		LIBHAL_PROP_EXTRACT_BOOL   ("volume.disc.is_blank",      vol->disc_is_blank);
		LIBHAL_PROP_EXTRACT_BOOL   ("volume.disc.is_rewritable", vol->disc_is_rewritable);
		LIBHAL_PROP_EXTRACT_UINT64 ("volume.disc.capacity",      vol->disc_capacity);

		LIBHAL_PROP_EXTRACT_BOOL   ("volume.policy.should_mount",        vol->should_mount);
		LIBHAL_PROP_EXTRACT_STRING ("volume.policy.desired_mount_point", vol->desired_mount_point);
		LIBHAL_PROP_EXTRACT_STRING ("volume.policy.mount_filesystem",    vol->mount_filesystem);

		LIBHAL_PROP_EXTRACT_END;
	}

	if (disc_type_textual != NULL) {
		if (strcmp (disc_type_textual, "cd_rom") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_CDROM;
		} else if (strcmp (disc_type_textual, "cd_r") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_CDR;
		} else if (strcmp (disc_type_textual, "cd_rw") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_CDRW;
		} else if (strcmp (disc_type_textual, "dvd_rom") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_DVDROM;
		} else if (strcmp (disc_type_textual, "dvd_ram") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_DVDRAM;
		} else if (strcmp (disc_type_textual, "dvd_r") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_DVDR;
		} else if (strcmp (disc_type_textual, "dvd_rw") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_DVDRW;
		} else if (strcmp (disc_type_textual, "dvd_plus_r") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_DVDPLUSR;
		} else if (strcmp (disc_type_textual, "dvd_plus_rw") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_DVDPLUSRW;
		} else if (strcmp (disc_type_textual, "dvd_plus_r_dl") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_DVDPLUSR_DL;
		} else if (strcmp (disc_type_textual, "bd_rom") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_BDROM;
		} else if (strcmp (disc_type_textual, "bd_r") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_BDR;
		} else if (strcmp (disc_type_textual, "bd_re") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_BDRE;
		} else if (strcmp (disc_type_textual, "hddvd_rom") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_HDDVDROM;
		} else if (strcmp (disc_type_textual, "hddvd_r") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_HDDVDR;
		} else if (strcmp (disc_type_textual, "hddvd_rw") == 0) {
			vol->disc_type = LIBHAL_VOLUME_DISC_TYPE_HDDVDRW;
		}
	}

	vol->fsusage = LIBHAL_VOLUME_USAGE_UNKNOWN;
	if (vol_fsusage_textual != NULL) {
		if (strcmp (vol_fsusage_textual, "filesystem") == 0) {
			vol->fsusage = LIBHAL_VOLUME_USAGE_MOUNTABLE_FILESYSTEM;
		} else if (strcmp (vol_fsusage_textual, "partitiontable") == 0) {
			vol->fsusage = LIBHAL_VOLUME_USAGE_PARTITION_TABLE;
		} else if (strcmp (vol_fsusage_textual, "raid") == 0) {
			vol->fsusage = LIBHAL_VOLUME_USAGE_RAID_MEMBER;
		} else if (strcmp (vol_fsusage_textual, "crypto") == 0) {
			vol->fsusage = LIBHAL_VOLUME_USAGE_CRYPTO;
		} else if (strcmp (vol_fsusage_textual, "other") == 0) {
			vol->fsusage = LIBHAL_VOLUME_USAGE_OTHER;
		} else {
			vol->fsusage = LIBHAL_VOLUME_USAGE_UNKNOWN;
		} 
	}

	libhal_free_string (vol_fsusage_textual);
	libhal_free_string (disc_type_textual);
	libhal_free_property_set (properties);
	return vol;
error:
	if (dbus_error_is_set (&error)) {
		dbus_error_free (&error);
	}
	libhal_free_string (vol_fsusage_textual);
	libhal_free_string (disc_type_textual);
	libhal_free_property_set (properties);
	libhal_volume_free (vol);
	return NULL;
}


/** If the volume is on a drive with a MSDOS style partition table, return
 *  the partition table id.
 *
 *  @param  volume              Volume object
 *  @return                     The partition type or -1 if volume is not
 *                              a partition or the media the volume stems from
 *                              isn't partition with a MS DOS style table
 */
int
libhal_volume_get_msdos_part_table_type (LibHalVolume *volume)
{
	return volume->msdos_part_table_type;
}

/** If the volume is on a drive with a MSDOS style partition table, return
 *  the partition start offset according to the partition table.
 *
 *  @param  volume              Volume object
 *  @return                     The partition start offset or -1 if volume isnt
 *                              a partition or the media the volume stems from
 *                              isn't partition with a MS DOS style table
 */
dbus_uint64_t
libhal_volume_get_msdos_part_table_start (LibHalVolume *volume)
{
	return volume->msdos_part_table_start;
}

/** If the volume is on a drive with a MSDOS style partition table, return
 *  the partition size according to the partition table.
 *
 *  @param  volume              Volume object
 *  @return                     The partition size or -1 if volume is not
 *                              a partition or the media the volume stems from
 *                              isn't partition with a MS DOS style table
 */
dbus_uint64_t
libhal_volume_get_msdos_part_table_size (LibHalVolume *volume)
{
	return volume->msdos_part_table_size;
}

/***********************************************************************/

/** Get the drive object that either is (when given e.g. /dev/sdb) or contains
 *  (when given e.g. /dev/sdb1) the given device file.
 *
 *  @param  hal_ctx             libhal context to use
 *  @param  device_file         Name of special device file, e.g. '/dev/hdc'
 *  @return                     LibHalDrive object or NULL if it doesn't exist
 */
LibHalDrive *
libhal_drive_from_device_file (LibHalContext *hal_ctx, const char *device_file)
{
	int i;
	char **hal_udis;
	int num_hal_udis;
	LibHalDrive *result;
	char *found_udi;
	DBusError error;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, NULL);

	result = NULL;
	found_udi = NULL;

	dbus_error_init (&error);
	if ((hal_udis = libhal_manager_find_device_string_match (hal_ctx, "block.device", 
								 device_file, &num_hal_udis, &error)) == NULL) {
		LIBHAL_FREE_DBUS_ERROR(&error);
		goto out;
	}

	for (i = 0; i < num_hal_udis; i++) {
		char *udi;
		char *storage_udi;
		DBusError err1;
		DBusError err2;
		udi = hal_udis[i];

		dbus_error_init (&err1);
		dbus_error_init (&err2);
		if (libhal_device_query_capability (hal_ctx, udi, "volume", &err1)) {

			storage_udi = libhal_device_get_property_string (hal_ctx, udi, "block.storage_device", &err1);
			if (storage_udi == NULL)
				continue;
			found_udi = strdup (storage_udi);
			libhal_free_string (storage_udi);
			break;
		} else if (libhal_device_query_capability (hal_ctx, udi, "storage", &err2)) {
			found_udi = strdup (udi);
		}
		LIBHAL_FREE_DBUS_ERROR(&err1);
		LIBHAL_FREE_DBUS_ERROR(&err2);
	}

	libhal_free_string_array (hal_udis);

	if (found_udi != NULL)
		result = libhal_drive_from_udi (hal_ctx, found_udi);

	free (found_udi);
out:
	return result;
}


/** Get the volume object for a given device file.
 *
 *  @param  hal_ctx             libhal context to use
 *  @param  device_file         Name of special device file, e.g. '/dev/hda5'
 *  @return                     LibHalVolume object or NULL if it doesn't exist
 */
LibHalVolume *
libhal_volume_from_device_file (LibHalContext *hal_ctx, const char *device_file)
{
	int i;
	char **hal_udis;
	int num_hal_udis;
	LibHalVolume *result;
	char *found_udi;
	DBusError error;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, NULL);

	result = NULL;
	found_udi = NULL;

	dbus_error_init (&error);
	if ((hal_udis = libhal_manager_find_device_string_match (hal_ctx, "block.device", 
								 device_file, &num_hal_udis, &error)) == NULL)
		goto out;

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
	LIBHAL_FREE_DBUS_ERROR(&error);
	return result;
}

dbus_uint64_t
libhal_volume_get_size (LibHalVolume *volume)
{
	if (volume->volume_size > 0)
		return volume->volume_size;
	else
		return ((dbus_uint64_t)volume->block_size) * ((dbus_uint64_t)volume->num_blocks);
}

dbus_uint64_t
libhal_volume_get_disc_capacity (LibHalVolume *volume)
{
	return volume->disc_capacity;
}


dbus_bool_t
libhal_drive_is_hotpluggable (LibHalDrive *drive)
{
	return drive->is_hotpluggable;
}

dbus_bool_t
libhal_drive_uses_removable_media (LibHalDrive *drive)
{
	return drive->is_removable;
}

dbus_bool_t
libhal_drive_is_media_detected (LibHalDrive *drive)
{
	return drive->is_media_detected;
}

dbus_uint64_t
libhal_drive_get_size (LibHalDrive *drive)
{
	return drive->drive_size;
}

dbus_uint64_t
libhal_drive_get_media_size (LibHalDrive *drive)
{
	return drive->drive_media_size;
}

const char *
libhal_drive_get_partition_scheme (LibHalDrive *drive)
{
	return drive->partition_scheme;
}


LibHalDriveType
libhal_drive_get_type (LibHalDrive *drive)
{
	return drive->type;
}

LibHalDriveBus
libhal_drive_get_bus (LibHalDrive *drive)
{
	return drive->bus;
}

LibHalDriveCdromCaps
libhal_drive_get_cdrom_caps (LibHalDrive *drive)
{
	return drive->cdrom_caps;
}

unsigned int
libhal_drive_get_device_major (LibHalDrive *drive)
{
	return drive->device_major;
}

unsigned int
libhal_drive_get_device_minor (LibHalDrive *drive)
{
	return drive->device_minor;
}

const char *
libhal_drive_get_type_textual (LibHalDrive *drive)
{
	return drive->type_textual;
}

const char *
libhal_drive_get_device_file (LibHalDrive *drive)
{
	return drive->device_file;
}

const char *
libhal_drive_get_udi (LibHalDrive *drive)
{
	return drive->udi;
}

const char *
libhal_drive_get_serial (LibHalDrive *drive)
{
	return drive->serial;
}

const char *
libhal_drive_get_firmware_version (LibHalDrive *drive)
{
	return drive->firmware_version;
}

const char *
libhal_drive_get_model (LibHalDrive *drive)
{
	return drive->model;
}

const char *
libhal_drive_get_vendor (LibHalDrive *drive)
{
	return drive->vendor;
}

/*****************************************************************************/

const char *
libhal_volume_get_udi (LibHalVolume *volume)
{
	return volume->udi;
}

const char *
libhal_volume_get_device_file (LibHalVolume *volume)
{
	return volume->device_file;
}

unsigned int libhal_volume_get_device_major (LibHalVolume *volume)
{
	return volume->device_major;
}

unsigned int libhal_volume_get_device_minor (LibHalVolume *volume)
{
	return volume->device_minor;
}

const char *
libhal_volume_get_fstype (LibHalVolume *volume)
{
	return volume->fstype;
}

const char *
libhal_volume_get_fsversion (LibHalVolume *volume)
{
	return volume->fsversion;
}

LibHalVolumeUsage 
libhal_volume_get_fsusage (LibHalVolume *volume)
{
	return volume->fsusage;
}

dbus_bool_t 
libhal_volume_is_mounted (LibHalVolume *volume)
{
	return volume->is_mounted;
}

dbus_bool_t 
libhal_volume_is_mounted_read_only (LibHalVolume *volume)
{
	return volume->is_mounted_read_only;
}

dbus_bool_t 
libhal_volume_is_partition (LibHalVolume *volume)
{
	return volume->is_partition;
}

dbus_bool_t
libhal_volume_is_disc (LibHalVolume *volume)
{
	return volume->is_disc;
}

unsigned int
libhal_volume_get_partition_number (LibHalVolume *volume)
{
	return volume->partition_number;
}

const char *
libhal_volume_get_partition_scheme (LibHalVolume *volume)
{
	return volume->partition_scheme;
}

const char *
libhal_volume_get_partition_type (LibHalVolume *volume)
{
	return volume->partition_type;
}

const char *
libhal_volume_get_partition_label (LibHalVolume *volume)
{
	return volume->partition_label;
}

const char *
libhal_volume_get_partition_uuid (LibHalVolume *volume)
{
	return volume->partition_uuid;
}

const char **
libhal_volume_get_partition_flags (LibHalVolume *volume)
{
	return (const char **) volume->partition_flags;
}


dbus_uint64_t 
libhal_volume_get_partition_start_offset (LibHalVolume *volume)
{
	return volume->partition_start_offset;
}

dbus_uint64_t
libhal_volume_get_partition_media_size (LibHalVolume *volume)
{
	return volume->partition_media_size;
}

const char *
libhal_volume_get_label (LibHalVolume *volume)
{
	return volume->volume_label;
}

const char *
libhal_volume_get_mount_point (LibHalVolume *volume)
{
	return volume->mount_point;
}

const char *
libhal_volume_get_uuid (LibHalVolume *volume)
{
	return volume->uuid;
}

dbus_bool_t
libhal_volume_disc_has_audio (LibHalVolume *volume)
{
	return volume->disc_has_audio;
}

dbus_bool_t
libhal_volume_disc_has_data (LibHalVolume *volume)
{
	return volume->disc_has_data;
}

dbus_bool_t
libhal_volume_disc_is_blank (LibHalVolume *volume)
{
	return volume->disc_is_blank;
}

dbus_bool_t
libhal_volume_disc_is_rewritable (LibHalVolume *volume)
{
	return volume->disc_is_rewritable;
}

dbus_bool_t
libhal_volume_disc_is_appendable (LibHalVolume *volume)
{
	return volume->disc_is_appendable;
}

LibHalVolumeDiscType
libhal_volume_get_disc_type (LibHalVolume *volume)
{
	return volume->disc_type;
}

dbus_bool_t
libhal_volume_should_ignore (LibHalVolume     *volume)
{
	return volume->ignore_volume;
}

char ** 
libhal_drive_find_all_volumes (LibHalContext *hal_ctx, LibHalDrive *drive, int *num_volumes)
{
	int i;
	char **udis;
	int num_udis;
	const char *drive_udi;
	char **result;
	DBusError error;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, NULL);

	udis = NULL;
	result = NULL;
	*num_volumes = 0;

	drive_udi = libhal_drive_get_udi (drive);
	if (drive_udi == NULL)
		goto out;

	/* get initial list... */
	dbus_error_init (&error);
	if ((udis = libhal_manager_find_device_string_match (hal_ctx, "block.storage_device", 
							     drive_udi, &num_udis, &error)) == NULL) {
		LIBHAL_FREE_DBUS_ERROR(&error);
		goto out;
	}

	result = malloc (sizeof (char *) * (num_udis + 1));
	if (result == NULL)
		goto out;

	/* ...and filter out the single UDI that is the drive itself */
	for (i = 0; i < num_udis; i++) {
		if (strcmp (udis[i], drive_udi) == 0)
			continue;
		result[*num_volumes] = strdup (udis[i]);
		*num_volumes = (*num_volumes) + 1;
	}
	/* set last element (above removed UDI) to NULL for libhal_free_string_array()*/
	result[*num_volumes] = NULL;

out:
	libhal_free_string_array (udis);
	return result;
}

const char *
libhal_volume_crypto_get_backing_volume_udi (LibHalVolume *volume)
{
	return volume->crypto_backing_volume;
}

char *
libhal_volume_crypto_get_clear_volume_udi (LibHalContext *hal_ctx, LibHalVolume *volume)
{
	DBusError error;
	char **clear_devices;
	int num_clear_devices;
	char *result;

	result = NULL;

	LIBHAL_CHECK_LIBHALCONTEXT (hal_ctx, NULL);

	dbus_error_init (&error);
	clear_devices = libhal_manager_find_device_string_match (hal_ctx,
								 "volume.crypto_luks.clear.backing_volume",
								 volume->udi,
								 &num_clear_devices,
								 &error);
	if (clear_devices != NULL) {

		if (num_clear_devices >= 1) {
			result = strdup (clear_devices[0]);
		}
		libhal_free_string_array (clear_devices);
	}

	return result;
}


/*************************************************************************/

char *
libhal_drive_policy_default_get_mount_root (LibHalContext *hal_ctx)
{
	char *result;
	DBusError error;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, NULL);

	dbus_error_init (&error);
	if ((result = libhal_device_get_property_string (hal_ctx, "/org/freedesktop/Hal/devices/computer",
						    "storage.policy.default.mount_root", &error)) == NULL) 
		LIBHAL_FREE_DBUS_ERROR(&error);

	return result;
}

dbus_bool_t
libhal_drive_policy_default_use_managed_keyword (LibHalContext *hal_ctx)
{
	dbus_bool_t result;
	DBusError error;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, FALSE);

	dbus_error_init (&error);
	if ((result = libhal_device_get_property_bool (hal_ctx, "/org/freedesktop/Hal/devices/computer",
						  "storage.policy.default.use_managed_keyword", &error)) == FALSE)
		LIBHAL_FREE_DBUS_ERROR(&error);

	return result;
}

char *
libhal_drive_policy_default_get_managed_keyword_primary (LibHalContext *hal_ctx)
{
	char *result;
	DBusError error;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, NULL);

	dbus_error_init (&error);
	if ((result = libhal_device_get_property_string (hal_ctx, "/org/freedesktop/Hal/devices/computer",
						    "storage.policy.default.managed_keyword.primary", &error)) == NULL)
		LIBHAL_FREE_DBUS_ERROR(&error);

	return result;
}

char *
libhal_drive_policy_default_get_managed_keyword_secondary (LibHalContext *hal_ctx)
{
	char *result;
	DBusError error;

	LIBHAL_CHECK_LIBHALCONTEXT(hal_ctx, NULL);

	dbus_error_init (&error);
	if ((result = libhal_device_get_property_string (hal_ctx, "/org/freedesktop/Hal/devices/computer",
						    "storage.policy.default.managed_keyword.secondary", &error)) == NULL)
		LIBHAL_FREE_DBUS_ERROR(&error);

	return result;
}

/*************************************************************************/

dbus_bool_t
libhal_drive_policy_is_mountable (LibHalDrive *drive, LibHalStoragePolicy *policy)
{
	printf ("should_mount=%d, no_partitions_hint=%d\n", drive->should_mount, drive->no_partitions_hint);

	return drive->should_mount && drive->no_partitions_hint;
}

const char *
libhal_drive_policy_get_desired_mount_point (LibHalDrive *drive, LibHalStoragePolicy *policy)
{
	return drive->desired_mount_point;
}

/* safely strcat() at most the remaining space in 'dst' */
#define strcat_len(dst, src, dstmaxlen) do {    \
	dst[dstmaxlen - 1] = '\0'; \
	strncat (dst, src, dstmaxlen - strlen (dst) - 1); \
} while(0)


static void
mopts_collect (LibHalContext *hal_ctx, const char *namespace, int namespace_len, 
	       const char *udi, char *options_string, size_t options_max_len, dbus_bool_t only_collect_imply_opts)
{
	LibHalPropertySet *properties;
	LibHalPropertySetIterator it;
	DBusError error;

	if(hal_ctx == 0) {
		fprintf (stderr,"%s %d : LibHalContext *ctx is NULL\n",__FILE__, __LINE__);
		return;
	}

	dbus_error_init (&error);

	/* first collect from root computer device */
	properties = libhal_device_get_all_properties (hal_ctx, udi, &error);
	if (properties == NULL ) {
		LIBHAL_FREE_DBUS_ERROR(&error);
		return;
	}

	for (libhal_psi_init (&it, properties); libhal_psi_has_more (&it); libhal_psi_next (&it)) {
		int type;
		char *key;
		
		type = libhal_psi_get_type (&it);
		key = libhal_psi_get_key (&it);
		if (type == LIBHAL_PROPERTY_TYPE_BOOLEAN &&
		    strncmp (key, namespace, namespace_len - 1) == 0) {
			const char *option = key + namespace_len - 1;
			char *location;
			dbus_bool_t is_imply_opt;

			is_imply_opt = FALSE;
			if (strcmp (option, "user") == 0 ||
			    strcmp (option, "users") == 0 ||
			    strcmp (option, "defaults") == 0 ||
			    strcmp (option, "pamconsole") == 0)
				is_imply_opt = TRUE;

			
			if (only_collect_imply_opts) {
				if (!is_imply_opt)
					continue;
			} else {
				if (is_imply_opt)
					continue;
			}

			if (libhal_psi_get_bool (&it)) {
				/* see if option is already there */
				location = strstr (options_string, option);
				if (location == NULL) {
					if (strlen (options_string) > 0)
						strcat_len (options_string, ",", options_max_len);
					strcat_len (options_string, option, options_max_len);
				}
			} else {
				/* remove option if already there */
				location = strstr (options_string, option);
				if (location != NULL) {
					char *end;

					end = strchr (location, ',');
					if (end == NULL) {
						location[0] = '\0';
					} else {
						strcpy (location, end + 1); /* skip the extra comma */
					}
				}

			}
		}
	}
	
	libhal_free_property_set (properties);
}


const char *
libhal_drive_policy_get_mount_options (LibHalDrive *drive, LibHalStoragePolicy *policy)
{
	const char *result;
	char stor_mount_option_default_begin[] = "storage.policy.default.mount_option.";
	char stor_mount_option_begin[] = "storage.policy.mount_option.";

	result = NULL;
	drive->mount_options[0] = '\0';

	/* collect options != ('pamconsole', 'user', 'users', 'defaults' options that imply other options)  */
	mopts_collect (drive->hal_ctx, stor_mount_option_default_begin, sizeof (stor_mount_option_default_begin),
		       "/org/freedesktop/Hal/devices/computer", drive->mount_options, MOUNT_OPTIONS_SIZE, TRUE);
	mopts_collect (drive->hal_ctx, stor_mount_option_begin, sizeof (stor_mount_option_begin),
		       drive->udi, drive->mount_options, MOUNT_OPTIONS_SIZE, TRUE);
	/* ensure ('pamconsole', 'user', 'users', 'defaults' options that imply other options), are first */
	mopts_collect (drive->hal_ctx, stor_mount_option_default_begin, sizeof (stor_mount_option_default_begin),
		       "/org/freedesktop/Hal/devices/computer", drive->mount_options, MOUNT_OPTIONS_SIZE, FALSE);
	mopts_collect (drive->hal_ctx, stor_mount_option_begin, sizeof (stor_mount_option_begin),
		       drive->udi, drive->mount_options, MOUNT_OPTIONS_SIZE, FALSE);

	result = drive->mount_options;

	return result;
}

const char *
libhal_drive_policy_get_mount_fs (LibHalDrive *drive, LibHalStoragePolicy *policy)
{
	return drive->mount_filesystem;
}


dbus_bool_t
libhal_volume_policy_is_mountable (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy)
{
	return drive->should_mount && volume->should_mount;
}

const char *libhal_volume_policy_get_desired_mount_point (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy)
{
	return volume->desired_mount_point;
}

const char *libhal_volume_policy_get_mount_options (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy)
{
	const char *result;
	char stor_mount_option_default_begin[] = "storage.policy.default.mount_option.";
	char vol_mount_option_begin[] = "volume.policy.mount_option.";

	result = NULL;
	volume->mount_options[0] = '\0';

	/* ensure ('pamconsole', 'user', 'users', 'defaults' options that imply other options), are first */
	mopts_collect (drive->hal_ctx, stor_mount_option_default_begin, sizeof (stor_mount_option_default_begin),
		       "/org/freedesktop/Hal/devices/computer", volume->mount_options, MOUNT_OPTIONS_SIZE, TRUE);
	mopts_collect (drive->hal_ctx, vol_mount_option_begin, sizeof (vol_mount_option_begin),
		       volume->udi, volume->mount_options, MOUNT_OPTIONS_SIZE, TRUE);
	/* collect options != ('pamconsole', 'user', 'users', 'defaults' options that imply other options)  */
	mopts_collect (drive->hal_ctx, stor_mount_option_default_begin, sizeof (stor_mount_option_default_begin),
		       "/org/freedesktop/Hal/devices/computer", volume->mount_options, MOUNT_OPTIONS_SIZE, FALSE);
	mopts_collect (drive->hal_ctx, vol_mount_option_begin, sizeof (vol_mount_option_begin),
		       volume->udi, volume->mount_options, MOUNT_OPTIONS_SIZE, FALSE);

	result = volume->mount_options;

	return result;
}

const char *libhal_volume_policy_get_mount_fs (LibHalDrive *drive, LibHalVolume *volume, LibHalStoragePolicy *policy)
{
	return volume->mount_filesystem;
}

dbus_bool_t       
libhal_drive_no_partitions_hint (LibHalDrive *drive)
{
	return drive->no_partitions_hint;
}

/** @} */
