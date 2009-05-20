/*
    libparted - a library for manipulating disk partitions
    Copyright (C) 1998-2001, 2005, 2006, 2007 Free Software Foundation, Inc.

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
 * \addtogroup PedGeometry
 * @{
 */

/** \file geom.h */

#ifndef PED_GEOM_H_INCLUDED
#define PED_GEOM_H_INCLUDED

#include <parted/device.h>
#include <parted/timer.h>

typedef struct _PedGeometry	PedGeometry;

/**
 * Geometry of the partition
 */
struct _PedGeometry {
	PedDevice*		dev;
	PedSector		start;
	PedSector		length;
	PedSector		end;
};

extern int ped_geometry_init (PedGeometry* geom, const PedDevice* dev,
			      PedSector start, PedSector length);
extern PedGeometry* ped_geometry_new (const PedDevice* dev, PedSector start,
				      PedSector length);
extern PedGeometry* ped_geometry_duplicate (const PedGeometry* geom);
extern PedGeometry* ped_geometry_intersect (const PedGeometry* a,
	       				    const PedGeometry* b);
extern void ped_geometry_destroy (PedGeometry* geom);
extern int ped_geometry_set (PedGeometry* geom, PedSector start,
			     PedSector length);
extern int ped_geometry_set_start (PedGeometry* geom, PedSector start);
extern int ped_geometry_set_end (PedGeometry* geom, PedSector end);
extern int ped_geometry_test_overlap (const PedGeometry* a,
	       			      const PedGeometry* b);
extern int ped_geometry_test_inside (const PedGeometry* a,
				     const PedGeometry* b);
extern int ped_geometry_test_equal (const PedGeometry* a, const PedGeometry* b);
extern int ped_geometry_test_sector_inside (const PedGeometry* geom,
	       				    PedSector sect);

extern int ped_geometry_read (const PedGeometry* geom, void* buffer,
			      PedSector offset, PedSector count);
extern int ped_geometry_write (PedGeometry* geom, const void* buffer,
			       PedSector offset, PedSector count);
extern PedSector ped_geometry_check (PedGeometry* geom, void* buffer,
				     PedSector buffer_size, PedSector offset,
				     PedSector granularity, PedSector count,
				     PedTimer* timer);
extern int ped_geometry_sync (PedGeometry* geom);
extern int ped_geometry_sync_fast (PedGeometry* geom);

/* returns -1 if "sector" is not within dest's space. */
extern PedSector ped_geometry_map (const PedGeometry* dst,
				   const PedGeometry* src,
				   PedSector sector);

#endif /* PED_GEOM_H_INCLUDED */

/** @} */

