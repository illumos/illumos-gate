/***************************************************************************
 * CVSID: $Id$
 *
 * libhal-storage.h : HAL convenience library for storage devices and volumes
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef LIBHAL_STORAGE_H
#define LIBHAL_STORAGE_H

#include <libhal.h>

#if defined(__cplusplus)
extern "C" {
#if 0
} /* shut up emacs indenting */
#endif
#endif

struct LibHalDrive_s;
typedef struct LibHalDrive_s LibHalDrive;
struct LibHalVolume_s;
typedef struct LibHalVolume_s LibHalVolume;
struct LibHalStoragePolicy_s;
typedef struct LibHalStoragePolicy_s LibHalStoragePolicy;


typedef enum {
	LIBHAL_STORAGE_ICON_DRIVE_REMOVABLE_DISK           = 0x10000,
	LIBHAL_STORAGE_ICON_DRIVE_REMOVABLE_DISK_IDE       = 0x10001,
	LIBHAL_STORAGE_ICON_DRIVE_REMOVABLE_DISK_SCSI      = 0x10002,
	LIBHAL_STORAGE_ICON_DRIVE_REMOVABLE_DISK_USB       = 0x10003,
	LIBHAL_STORAGE_ICON_DRIVE_REMOVABLE_DISK_IEEE1394  = 0x10004,
	LIBHAL_STORAGE_ICON_DRIVE_DISK                     = 0x10100,
	LIBHAL_STORAGE_ICON_DRIVE_DISK_IDE                 = 0x10101,
	LIBHAL_STORAGE_ICON_DRIVE_DISK_SCSI                = 0x10102,
	LIBHAL_STORAGE_ICON_DRIVE_DISK_USB                 = 0x10103,
	LIBHAL_STORAGE_ICON_DRIVE_DISK_IEEE1394            = 0x10104,
	LIBHAL_STORAGE_ICON_DRIVE_CDROM                    = 0x10200,
	LIBHAL_STORAGE_ICON_DRIVE_CDROM_IDE                = 0x10201,
	LIBHAL_STORAGE_ICON_DRIVE_CDROM_SCSI               = 0x10202,
	LIBHAL_STORAGE_ICON_DRIVE_CDROM_USB                = 0x10203,
	LIBHAL_STORAGE_ICON_DRIVE_CDROM_IEEE1394           = 0x10204,
	LIBHAL_STORAGE_ICON_DRIVE_FLOPPY                   = 0x10300,
	LIBHAL_STORAGE_ICON_DRIVE_FLOPPY_IDE               = 0x10301,
	LIBHAL_STORAGE_ICON_DRIVE_FLOPPY_SCSI              = 0x10302,
	LIBHAL_STORAGE_ICON_DRIVE_FLOPPY_USB               = 0x10303,
	LIBHAL_STORAGE_ICON_DRIVE_FLOPPY_IEEE1394          = 0x10304,
	LIBHAL_STORAGE_ICON_DRIVE_TAPE                     = 0x10400,
	LIBHAL_STORAGE_ICON_DRIVE_COMPACT_FLASH            = 0x10500,
	LIBHAL_STORAGE_ICON_DRIVE_MEMORY_STICK             = 0x10600,
	LIBHAL_STORAGE_ICON_DRIVE_SMART_MEDIA              = 0x10700,
	LIBHAL_STORAGE_ICON_DRIVE_SD_MMC                   = 0x10800,
	LIBHAL_STORAGE_ICON_DRIVE_CAMERA                   = 0x10900,
	LIBHAL_STORAGE_ICON_DRIVE_PORTABLE_AUDIO_PLAYER    = 0x10a00,
	LIBHAL_STORAGE_ICON_DRIVE_ZIP                      = 0x10b00,
        LIBHAL_STORAGE_ICON_DRIVE_JAZ                      = 0x10c00,
        LIBHAL_STORAGE_ICON_DRIVE_FLASH_KEY                = 0x10d00,

	LIBHAL_STORAGE_ICON_VOLUME_REMOVABLE_DISK          = 0x20000,
	LIBHAL_STORAGE_ICON_VOLUME_REMOVABLE_DISK_IDE      = 0x20001,
	LIBHAL_STORAGE_ICON_VOLUME_REMOVABLE_DISK_SCSI     = 0x20002,
	LIBHAL_STORAGE_ICON_VOLUME_REMOVABLE_DISK_USB      = 0x20003,
	LIBHAL_STORAGE_ICON_VOLUME_REMOVABLE_DISK_IEEE1394 = 0x20004,
	LIBHAL_STORAGE_ICON_VOLUME_DISK                    = 0x20100,
	LIBHAL_STORAGE_ICON_VOLUME_DISK_IDE                = 0x20101,
	LIBHAL_STORAGE_ICON_VOLUME_DISK_SCSI               = 0x20102,
	LIBHAL_STORAGE_ICON_VOLUME_DISK_USB                = 0x20103,
	LIBHAL_STORAGE_ICON_VOLUME_DISK_IEEE1394           = 0x20104,
	LIBHAL_STORAGE_ICON_VOLUME_CDROM                   = 0x20200,
	LIBHAL_STORAGE_ICON_VOLUME_CDROM_IDE               = 0x20201,
	LIBHAL_STORAGE_ICON_VOLUME_CDROM_SCSI              = 0x20202,
	LIBHAL_STORAGE_ICON_VOLUME_CDROM_USB               = 0x20203,
	LIBHAL_STORAGE_ICON_VOLUME_CDROM_IEEE1394          = 0x20204,
	LIBHAL_STORAGE_ICON_VOLUME_FLOPPY                  = 0x20300,
	LIBHAL_STORAGE_ICON_VOLUME_FLOPPY_IDE              = 0x20301,
	LIBHAL_STORAGE_ICON_VOLUME_FLOPPY_SCSI             = 0x20302,
	LIBHAL_STORAGE_ICON_VOLUME_FLOPPY_USB              = 0x20303,
	LIBHAL_STORAGE_ICON_VOLUME_FLOPPY_IEEE1394         = 0x20304,
	LIBHAL_STORAGE_ICON_VOLUME_TAPE                    = 0x20400,
	LIBHAL_STORAGE_ICON_VOLUME_COMPACT_FLASH           = 0x20500,
	LIBHAL_STORAGE_ICON_VOLUME_MEMORY_STICK            = 0x20600,
	LIBHAL_STORAGE_ICON_VOLUME_SMART_MEDIA             = 0x20700,
	LIBHAL_STORAGE_ICON_VOLUME_SD_MMC                  = 0x20800,
	LIBHAL_STORAGE_ICON_VOLUME_CAMERA                  = 0x20900,
	LIBHAL_STORAGE_ICON_VOLUME_PORTABLE_AUDIO_PLAYER   = 0x20a00,
	LIBHAL_STORAGE_ICON_VOLUME_ZIP                     = 0x20b00,
        LIBHAL_STORAGE_ICON_VOLUME_JAZ                     = 0x20c00,
        LIBHAL_STORAGE_ICON_VOLUME_FLASH_KEY               = 0x20d00,

	LIBHAL_STORAGE_ICON_DISC_CDROM                     = 0x30000,
	LIBHAL_STORAGE_ICON_DISC_CDR                       = 0x30001,
	LIBHAL_STORAGE_ICON_DISC_CDRW                      = 0x30002,
	LIBHAL_STORAGE_ICON_DISC_DVDROM                    = 0x30003,
	LIBHAL_STORAGE_ICON_DISC_DVDRAM                    = 0x30004,
	LIBHAL_STORAGE_ICON_DISC_DVDR                      = 0x30005,
	LIBHAL_STORAGE_ICON_DISC_DVDRW                     = 0x30006,
	LIBHAL_STORAGE_ICON_DISC_DVDPLUSR                  = 0x30007,
	LIBHAL_STORAGE_ICON_DISC_DVDPLUSRW                 = 0x30008,
	LIBHAL_STORAGE_ICON_DISC_DVDPLUSRWDL               = 0x30009,
	LIBHAL_STORAGE_ICON_DISC_BDROM                     = 0x3000a,
	LIBHAL_STORAGE_ICON_DISC_BDR                       = 0x3000b,
	LIBHAL_STORAGE_ICON_DISC_BDRE                      = 0x3000c,
	LIBHAL_STORAGE_ICON_DISC_HDDVDROM                  = 0x3000d,
	LIBHAL_STORAGE_ICON_DISC_HDDVDR                    = 0x3000e,
	LIBHAL_STORAGE_ICON_DISC_HDDVDRW                   = 0x3000f
} LibHalStoragePolicyIcon;

typedef struct {
	LibHalStoragePolicyIcon icon;
	const char *icon_path;
} LibHalStoragePolicyIconPair;

LibHalStoragePolicy *libhal_storage_policy_new		    (void) LIBHAL_DEPRECATED;
void                 libhal_storage_policy_free		    (LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;

void                 libhal_storage_policy_set_icon_path    (LibHalStoragePolicy *policy,
		   					     LibHalStoragePolicyIcon icon,
							     const char *path) LIBHAL_DEPRECATED;

void                 libhal_storage_policy_set_icon_mapping (LibHalStoragePolicy *policy,
							     LibHalStoragePolicyIconPair *pairs) LIBHAL_DEPRECATED;
const char  	    *libhal_storage_policy_lookup_icon	    (LibHalStoragePolicy *policy,
						  	     LibHalStoragePolicyIcon icon) LIBHAL_DEPRECATED;

typedef enum {
	LIBHAL_DRIVE_BUS_UNKNOWN     = 0x00,
	LIBHAL_DRIVE_BUS_IDE         = 0x01,
	LIBHAL_DRIVE_BUS_SCSI        = 0x02,
	LIBHAL_DRIVE_BUS_USB         = 0x03,
	LIBHAL_DRIVE_BUS_IEEE1394    = 0x04,
	LIBHAL_DRIVE_BUS_CCW         = 0x05
} LibHalDriveBus;

typedef enum {
	LIBHAL_DRIVE_TYPE_REMOVABLE_DISK        = 0x00,
	LIBHAL_DRIVE_TYPE_DISK                  = 0x01,
	LIBHAL_DRIVE_TYPE_CDROM                 = 0x02,
	LIBHAL_DRIVE_TYPE_FLOPPY                = 0x03,
	LIBHAL_DRIVE_TYPE_TAPE                  = 0x04,
	LIBHAL_DRIVE_TYPE_COMPACT_FLASH         = 0x05,
	LIBHAL_DRIVE_TYPE_MEMORY_STICK          = 0x06,
	LIBHAL_DRIVE_TYPE_SMART_MEDIA           = 0x07,
	LIBHAL_DRIVE_TYPE_SD_MMC                = 0x08,
	LIBHAL_DRIVE_TYPE_CAMERA                = 0x09,
	LIBHAL_DRIVE_TYPE_PORTABLE_AUDIO_PLAYER = 0x0a,
	LIBHAL_DRIVE_TYPE_ZIP                   = 0x0b,
	LIBHAL_DRIVE_TYPE_JAZ                   = 0x0c,
	LIBHAL_DRIVE_TYPE_FLASHKEY              = 0x0d
} LibHalDriveType;

typedef enum {
	LIBHAL_DRIVE_CDROM_CAPS_CDROM       = 0x00001,
	LIBHAL_DRIVE_CDROM_CAPS_CDR         = 0x00002,
	LIBHAL_DRIVE_CDROM_CAPS_CDRW        = 0x00004,
	LIBHAL_DRIVE_CDROM_CAPS_DVDRAM      = 0x00008,
	LIBHAL_DRIVE_CDROM_CAPS_DVDROM      = 0x00010,
	LIBHAL_DRIVE_CDROM_CAPS_DVDR        = 0x00020,
	LIBHAL_DRIVE_CDROM_CAPS_DVDRW       = 0x00040,
	LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSR    = 0x00080,
	LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRW   = 0x00100,
	LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRDL  = 0x00200,
	LIBHAL_DRIVE_CDROM_CAPS_DVDPLUSRWDL = 0x00400,
	LIBHAL_DRIVE_CDROM_CAPS_BDROM       = 0x00800,
	LIBHAL_DRIVE_CDROM_CAPS_BDR         = 0x01000,
	LIBHAL_DRIVE_CDROM_CAPS_BDRE        = 0x02000,
	LIBHAL_DRIVE_CDROM_CAPS_HDDVDROM    = 0x04000,
	LIBHAL_DRIVE_CDROM_CAPS_HDDVDR      = 0x08000,
	LIBHAL_DRIVE_CDROM_CAPS_HDDVDRW     = 0x10000
} LibHalDriveCdromCaps;

LibHalDrive         *libhal_drive_from_udi                    (LibHalContext *hal_ctx,
							       const char *udi);
LibHalDrive         *libhal_drive_from_device_file            (LibHalContext *hal_ctx,
							       const char *device_file);
void                 libhal_drive_free                        (LibHalDrive *drive);

dbus_bool_t          libhal_drive_is_hotpluggable          (LibHalDrive      *drive);
dbus_bool_t          libhal_drive_uses_removable_media     (LibHalDrive      *drive);
dbus_bool_t          libhal_drive_is_media_detected        (LibHalDrive      *drive);
dbus_uint64_t        libhal_drive_get_size                 (LibHalDrive      *drive);
dbus_uint64_t        libhal_drive_get_media_size           (LibHalDrive      *drive);
const char          *libhal_drive_get_partition_scheme     (LibHalDrive      *drive);
dbus_bool_t          libhal_drive_no_partitions_hint       (LibHalDrive      *drive);
dbus_bool_t          libhal_drive_requires_eject           (LibHalDrive      *drive);
LibHalDriveType      libhal_drive_get_type                 (LibHalDrive      *drive);
LibHalDriveBus       libhal_drive_get_bus                  (LibHalDrive      *drive);
LibHalDriveCdromCaps libhal_drive_get_cdrom_caps           (LibHalDrive      *drive);
unsigned int         libhal_drive_get_device_major         (LibHalDrive      *drive);
unsigned int         libhal_drive_get_device_minor         (LibHalDrive      *drive);
const char          *libhal_drive_get_type_textual         (LibHalDrive      *drive);
const char          *libhal_drive_get_device_file          (LibHalDrive      *drive);
const char          *libhal_drive_get_udi                  (LibHalDrive      *drive);
const char          *libhal_drive_get_serial               (LibHalDrive      *drive);
const char          *libhal_drive_get_firmware_version     (LibHalDrive      *drive);
const char          *libhal_drive_get_model                (LibHalDrive      *drive);
const char          *libhal_drive_get_vendor               (LibHalDrive      *drive);
const char          *libhal_drive_get_physical_device_udi  (LibHalDrive      *drive);

const char          *libhal_drive_get_dedicated_icon_drive    (LibHalDrive      *drive);
const char          *libhal_drive_get_dedicated_icon_volume   (LibHalDrive      *drive);

char                *libhal_drive_policy_compute_display_name (LibHalDrive        *drive,
							       LibHalVolume        *volume,
							       LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;
char                *libhal_drive_policy_compute_icon_name    (LibHalDrive         *drive,
							       LibHalVolume        *volume,
							       LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;

dbus_bool_t          libhal_drive_policy_is_mountable            (LibHalDrive         *drive,
								  LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;
const char          *libhal_drive_policy_get_desired_mount_point (LibHalDrive         *drive,
								  LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;
const char          *libhal_drive_policy_get_mount_options       (LibHalDrive         *drive,
							          LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;
const char          *libhal_drive_policy_get_mount_fs            (LibHalDrive      *drive,
								  LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;

char               **libhal_drive_find_all_volumes (LibHalContext *hal_ctx,
						    LibHalDrive   *drive,
						    int 	  *num_volumes);


char        *libhal_drive_policy_default_get_mount_root                (LibHalContext *hal_ctx) LIBHAL_DEPRECATED;
dbus_bool_t  libhal_drive_policy_default_use_managed_keyword           (LibHalContext *hal_ctx) LIBHAL_DEPRECATED;
char        *libhal_drive_policy_default_get_managed_keyword_primary   (LibHalContext *hal_ctx) LIBHAL_DEPRECATED;
char        *libhal_drive_policy_default_get_managed_keyword_secondary (LibHalContext *hal_ctx) LIBHAL_DEPRECATED;


typedef enum {
	LIBHAL_VOLUME_USAGE_MOUNTABLE_FILESYSTEM,
	LIBHAL_VOLUME_USAGE_PARTITION_TABLE,
	LIBHAL_VOLUME_USAGE_RAID_MEMBER,
	LIBHAL_VOLUME_USAGE_CRYPTO,
	LIBHAL_VOLUME_USAGE_UNKNOWN,
	LIBHAL_VOLUME_USAGE_OTHER
} LibHalVolumeUsage;

typedef enum {
	LIBHAL_VOLUME_DISC_TYPE_CDROM       = 0x00,
	LIBHAL_VOLUME_DISC_TYPE_CDR         = 0x01,
	LIBHAL_VOLUME_DISC_TYPE_CDRW        = 0x02,
	LIBHAL_VOLUME_DISC_TYPE_DVDROM      = 0x03,
	LIBHAL_VOLUME_DISC_TYPE_DVDRAM      = 0x04,
	LIBHAL_VOLUME_DISC_TYPE_DVDR        = 0x05,
	LIBHAL_VOLUME_DISC_TYPE_DVDRW       = 0x06,
	LIBHAL_VOLUME_DISC_TYPE_DVDPLUSR    = 0x07,
	LIBHAL_VOLUME_DISC_TYPE_DVDPLUSRW   = 0x08,
	LIBHAL_VOLUME_DISC_TYPE_DVDPLUSR_DL = 0x09,
	LIBHAL_VOLUME_DISC_TYPE_BDROM       = 0x0a,
	LIBHAL_VOLUME_DISC_TYPE_BDR         = 0x0b,
	LIBHAL_VOLUME_DISC_TYPE_BDRE        = 0x0c,
	LIBHAL_VOLUME_DISC_TYPE_HDDVDROM    = 0x0d,
	LIBHAL_VOLUME_DISC_TYPE_HDDVDR      = 0x0e,
	LIBHAL_VOLUME_DISC_TYPE_HDDVDRW     = 0x0f
} LibHalVolumeDiscType;

LibHalVolume     *libhal_volume_from_udi                      (LibHalContext *hal_ctx,
							       const char *udi);
LibHalVolume     *libhal_volume_from_device_file              (LibHalContext *hal_ctx,
							       const char *device_file);
void              libhal_volume_free                          (LibHalVolume     *volume);
dbus_uint64_t     libhal_volume_get_size                      (LibHalVolume     *volume);
dbus_uint64_t     libhal_volume_get_disc_capacity             (LibHalVolume     *volume);

const char          *libhal_volume_get_udi                       (LibHalVolume     *volume);
const char          *libhal_volume_get_device_file               (LibHalVolume     *volume);
unsigned int         libhal_volume_get_device_major              (LibHalVolume     *volume);
unsigned int         libhal_volume_get_device_minor              (LibHalVolume     *volume);
const char          *libhal_volume_get_fstype                    (LibHalVolume     *volume);
const char          *libhal_volume_get_fsversion                 (LibHalVolume     *volume);
LibHalVolumeUsage    libhal_volume_get_fsusage                   (LibHalVolume     *volume);
dbus_bool_t          libhal_volume_is_mounted                    (LibHalVolume     *volume);
dbus_bool_t          libhal_volume_is_mounted_read_only          (LibHalVolume     *volume);
dbus_bool_t          libhal_volume_is_partition                  (LibHalVolume     *volume);
dbus_bool_t          libhal_volume_is_disc                       (LibHalVolume     *volume);

const char          *libhal_volume_get_partition_scheme          (LibHalVolume     *volume);
const char          *libhal_volume_get_partition_type            (LibHalVolume     *volume);
const char          *libhal_volume_get_partition_label           (LibHalVolume     *volume);
const char          *libhal_volume_get_partition_uuid            (LibHalVolume     *volume);
const char         **libhal_volume_get_partition_flags           (LibHalVolume     *volume);
unsigned int         libhal_volume_get_partition_number          (LibHalVolume     *volume);
dbus_uint64_t        libhal_volume_get_partition_start_offset    (LibHalVolume     *volume);
dbus_uint64_t        libhal_volume_get_partition_media_size      (LibHalVolume     *volume);

const char          *libhal_volume_get_label                     (LibHalVolume     *volume);
const char          *libhal_volume_get_mount_point               (LibHalVolume     *volume);
const char          *libhal_volume_get_uuid                      (LibHalVolume     *volume);
const char          *libhal_volume_get_storage_device_udi        (LibHalVolume     *volume);

const char          *libhal_volume_crypto_get_backing_volume_udi (LibHalVolume     *volume);
char                *libhal_volume_crypto_get_clear_volume_udi   (LibHalContext    *hal_ctx, LibHalVolume *volume);


dbus_bool_t          libhal_volume_disc_has_audio             (LibHalVolume     *volume);
dbus_bool_t          libhal_volume_disc_has_data              (LibHalVolume     *volume);
dbus_bool_t          libhal_volume_disc_is_blank              (LibHalVolume     *volume);
dbus_bool_t          libhal_volume_disc_is_rewritable         (LibHalVolume     *volume);
dbus_bool_t          libhal_volume_disc_is_appendable         (LibHalVolume     *volume);
LibHalVolumeDiscType libhal_volume_get_disc_type              (LibHalVolume     *volume);

int               libhal_volume_get_msdos_part_table_type     (LibHalVolume     *volume)  LIBHAL_DEPRECATED;
dbus_uint64_t     libhal_volume_get_msdos_part_table_start    (LibHalVolume     *volume)  LIBHAL_DEPRECATED;
dbus_uint64_t     libhal_volume_get_msdos_part_table_size     (LibHalVolume     *volume)  LIBHAL_DEPRECATED;


dbus_bool_t       libhal_volume_should_ignore 	              (LibHalVolume     *volume);

char             *libhal_volume_policy_compute_size_as_string (LibHalVolume     *volume) LIBHAL_DEPRECATED;

char             *libhal_volume_policy_compute_display_name   (LibHalDrive         *drive,
							       LibHalVolume        *volume,
							       LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;
char             *libhal_volume_policy_compute_icon_name      (LibHalDrive         *drive,
							       LibHalVolume        *volume,
							       LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;

dbus_bool_t       libhal_volume_policy_should_be_visible      (LibHalDrive         *drive,
							       LibHalVolume        *volume,
							       LibHalStoragePolicy *policy,
							       const char          *target_mount_point) LIBHAL_DEPRECATED;

dbus_bool_t       libhal_volume_policy_is_mountable		(LibHalDrive         *drive,
								 LibHalVolume        *volume,
								 LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;
const char       *libhal_volume_policy_get_desired_mount_point  (LibHalDrive         *drive,
								 LibHalVolume        *volume,
								 LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;
const char       *libhal_volume_policy_get_mount_options   	(LibHalDrive         *drive,
							    	 LibHalVolume        *volume,
							    	 LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;
const char       *libhal_volume_policy_get_mount_fs        	(LibHalDrive         *drive,
							    	 LibHalVolume        *volume,
							    	 LibHalStoragePolicy *policy) LIBHAL_DEPRECATED;


#if defined(__cplusplus)
}
#endif

#endif /* LIBHAL_STORAGE_H */
