/***************************************************************************
 * CVSID: $Id$
 *
 * osspec.h : OS Specific interface
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

#ifndef OSSPEC_H
#define OSSPEC_H

#include <stdarg.h>
#include <stdint.h>
#include <dbus/dbus.h>

#include "device.h"

/** Initialize the kernel specific parts of the daemon */
void osspec_init (void);

/** Probe all devices present in the system and build the device list */
void osspec_probe (void);

/* Called by kernel specific parts when probing is done */
void osspec_probe_done (void);

gboolean osspec_device_rescan (HalDevice *d);

gboolean osspec_device_reprobe (HalDevice *d);

/* Called to refresh mount state for a device object of capability volume */
void osspec_refresh_mount_state_for_block_device (HalDevice *d);

/** Called when the org.freedesktop.Hal service receives a messaged that the generic daemon
 *  doesn't handle. Can be used for intercepting messages from kernel or core OS components.
 *
 *  @param  connection          D-BUS connection
 *  @param  message             Message
 *  @param  user_data           User data
 *  @return                     What to do with the message
 */
DBusHandlerResult osspec_filter_function (DBusConnection *connection, DBusMessage *message, void *user_data);

#endif /* OSSPEC_H */
