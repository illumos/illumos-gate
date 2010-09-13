/*
    libparted - a library for manipulating disk partitions
    Copyright (C) 1998 - 2001, 2005, 2007 Free Software Foundation, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * \addtogroup PedDevice
 * @{
 */

/** \file device.h */

#ifndef PED_DEVICE_H_INCLUDED
#define PED_DEVICE_H_INCLUDED

#include <parted/timer.h>

/** We can address 2^63 sectors */
typedef long long PedSector;

/** \deprecated Removal from API planned */
typedef enum {
        PED_DEVICE_UNKNOWN      = 0,
        PED_DEVICE_SCSI         = 1,
        PED_DEVICE_IDE          = 2,
        PED_DEVICE_DAC960       = 3,
        PED_DEVICE_CPQARRAY     = 4,
        PED_DEVICE_FILE         = 5,
        PED_DEVICE_ATARAID      = 6,
        PED_DEVICE_I2O          = 7,
        PED_DEVICE_UBD          = 8,
        PED_DEVICE_DASD         = 9,
        PED_DEVICE_VIODASD      = 10,
        PED_DEVICE_SX8          = 11,
#ifdef ENABLE_DEVICE_MAPPER
        PED_DEVICE_DM           = 12,
#endif
        PED_DEVICE_XVD          = 13
} PedDeviceType;

typedef struct _PedDevice PedDevice;
typedef struct _PedDeviceArchOps PedDeviceArchOps;
typedef struct _PedCHSGeometry PedCHSGeometry;

/**
 * A cylinder-head-sector "old-style" geometry.
 * 
 * A device addressed in this way has C*H*S sectors.
 */
struct _PedCHSGeometry {
        int             cylinders;
        int             heads;
        int             sectors;
};

/** A block device - for example, /dev/hda, not /dev/hda3 */
struct _PedDevice {
        PedDevice*      next;

        char*           model;          /**< \brief description of hardware
                                             (manufacturer, model) */
        char*           path;           /**< device /dev entry */

        PedDeviceType   type;           /**< SCSI, IDE, etc.
                                             \deprecated \sa PedDeviceType */
        long long       sector_size;            /**< logical sector size */
        long long       phys_sector_size;       /**< physical sector size */
        PedSector       length;                 /**< device length (LBA) */

        int             open_count; /**< the number of times this device has
                                         been opened with ped_device_open(). */
        int             read_only;
        int             external_mode;
        int             dirty;
        int             boot_dirty;

        PedCHSGeometry  hw_geom;
        PedCHSGeometry  bios_geom;
        short           host, did;

        void*           arch_specific;
};

/**
 * List of functions implementing architecture-specific operations.
 */
struct _PedDeviceArchOps {
        PedDevice* (*_new) (const char* path);
        void (*destroy) (PedDevice* dev);
        int (*is_busy) (PedDevice* dev);
        int (*open) (PedDevice* dev);
        int (*refresh_open) (PedDevice* dev);
        int (*close) (PedDevice* dev);
        int (*refresh_close) (PedDevice* dev);
        int (*read) (const PedDevice* dev, void* buffer,
                     PedSector start, PedSector count);
        int (*write) (PedDevice* dev, const void* buffer,
                      PedSector start, PedSector count);
        int (*sync) (PedDevice* dev);
        int (*sync_fast) (PedDevice* dev);
        PedSector (*check) (PedDevice* dev, void* buffer,
                            PedSector start, PedSector count);
        void (*probe_all) ();
};

extern void ped_device_probe_all ();
extern void ped_device_free_all ();

extern PedDevice* ped_device_get (const char* name);
extern PedDevice* ped_device_get_next (const PedDevice* dev);
extern int ped_device_is_busy (PedDevice* dev);
extern int ped_device_open (PedDevice* dev);
extern int ped_device_close (PedDevice* dev);
extern void ped_device_destroy (PedDevice* dev);
extern void ped_device_cache_remove (PedDevice* dev);

extern int ped_device_begin_external_access (PedDevice* dev);
extern int ped_device_end_external_access (PedDevice* dev);

extern int ped_device_read (const PedDevice* dev, void* buffer,
                            PedSector start, PedSector count);
extern int ped_device_write (PedDevice* dev, const void* buffer,
                             PedSector start, PedSector count);
extern int ped_device_sync (PedDevice* dev);
extern int ped_device_sync_fast (PedDevice* dev);
extern PedSector ped_device_check (PedDevice* dev, void* buffer,
                                   PedSector start, PedSector count);
extern PedConstraint* ped_device_get_constraint (PedDevice* dev);

/* private stuff ;-) */

extern void _ped_device_probe (const char* path);

#endif /* PED_DEVICE_H_INCLUDED */

/** @} */

