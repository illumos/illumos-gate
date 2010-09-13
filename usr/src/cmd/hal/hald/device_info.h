/***************************************************************************
 * CVSID: $Id$
 *
 * device_store.c : Search for .fdi files and merge on match
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
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

#ifndef DEVICE_INFO_H
#define DEVICE_INFO_H

#include <stdarg.h>
#include <stdint.h>
#include <dbus/dbus.h>

#include "device_store.h"

typedef enum {
	DEVICE_INFO_TYPE_PREPROBE,
	DEVICE_INFO_TYPE_INFORMATION,
	DEVICE_INFO_TYPE_POLICY
} DeviceInfoType;

dbus_bool_t di_search_and_merge (HalDevice *d, DeviceInfoType type);

#endif				/* DEVICE_INFO_H */
