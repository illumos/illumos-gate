/* device.h - Define macros and declare prototypes for device.c */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2004  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef DEVICE_MAP_HEADER
#define DEVICE_MAP_HEADER	1

/* The maximum number of BIOS disks.  */
#define NUM_DISKS	256

/* Simulated disk sizes. */
#define DEFAULT_FD_CYLINDERS	80
#define DEFAULT_FD_HEADS	2
#define DEFAULT_FD_SECTORS	18
#define DEFAULT_HD_CYLINDERS	620
#define DEFAULT_HD_HEADS	128
#define DEFAULT_HD_SECTORS	63

/* Function prototypes.  */
extern void get_drive_geometry (struct geometry *geom, char **map, int drive);
extern int check_device (const char *device);
extern int init_device_map (char ***map, const char *map_file,
			    int no_floppies);
extern void restore_device_map (char **map);

#ifdef __linux__
extern int is_disk_device (char **map, int drive);
extern int write_to_partition (char **map, int drive, int partition,
			       int offset, int size, const char *buf);
#endif /* __linux__ */
			       
#endif /* DEVICE_MAP_HEADER */
