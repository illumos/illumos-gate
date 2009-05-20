/*
    libparted - a library for manipulating disk partitions
    Copyright (C) 2001, 2007 Free Software Foundation, Inc.

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

#ifndef PED_GNU_H_INCLUDED
#define PED_GNU_H_INCLUDED

#include <parted/parted.h>

#include <hurd/store.h>

#define GNU_SPECIFIC(dev)	((GNUSpecific*) (dev)->arch_specific)

typedef	struct _GNUSpecific	GNUSpecific;

struct _GNUSpecific {
	struct store*	store;
	int consume;
};

extern PedArchitecture ped_gnu_arch;

/* Initialize a PedDevice using SOURCE.  The SOURCE will NOT be destroyed;
   the caller created it, it is the caller's responsilbility to free it
   after it calls ped_device_destory.  SOURCE is not registered in Parted's
   list of devices.  */
PedDevice* ped_device_new_from_store (struct store *source);

#endif /* PED_GNU_H_INCLUDED */

