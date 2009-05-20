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

#ifndef PED_LINUX_H_INCLUDED
#define PED_LINUX_H_INCLUDED

#include <parted/parted.h>
#include <parted/device.h>

#if defined __s390__ || defined __s390x__
#  include <parted/fdasd.h>
#endif

#define LINUX_SPECIFIC(dev)	((LinuxSpecific*) (dev)->arch_specific)

typedef	struct _LinuxSpecific	LinuxSpecific;

struct _LinuxSpecific {
	int	fd;
#if defined(__s390__) || defined(__s390x__)
	unsigned int real_sector_size;
	/* IBM internal dasd structure (i guess ;), required. */
	struct fdasd_anchor *anchor;
#endif
};

extern PedArchitecture ped_linux_arch;

#endif /* PED_LINUX_H_INCLUDED */

