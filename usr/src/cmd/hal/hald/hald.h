/***************************************************************************
 * CVSID: $Id$
 *
 * device_store.h : device store interface
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

#ifndef HALD_H
#define HALD_H

#include <stdarg.h>
#include <stdint.h>
#include <dbus/dbus.h>

#include "device_store.h"

/**
 *  @addtogroup HalDaemon
 *
 *  @{
 */

HalDeviceStore *hald_get_gdl (void);
HalDeviceStore *hald_get_tdl (void);

void property_atomic_update_begin ();
void property_atomic_update_end ();

extern dbus_bool_t hald_is_verbose;
extern dbus_bool_t hald_use_syslog;
extern dbus_bool_t hald_is_initialising;
extern dbus_bool_t hald_is_shutting_down;

/* If this is defined, the amount of time, in seconds, before hald
 * does an exit where resources are freed - useful for valgrinding
 * and finding memory leaks; e.g. plug in a device, do something
 * with the hal daemon and then look at the report
 *
 * Use hald/valgrind-hald.sh for this
 */
/*#define HALD_MEMLEAK_DBG 60*/

/**
 *  @}
 */

#endif				/* HALD_H */
