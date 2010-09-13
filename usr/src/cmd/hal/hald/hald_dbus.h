/***************************************************************************
 * CVSID: $Id$
 *
 * hal_dbus.h : D-BUS interface of HAL daemon
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

#ifndef HAL_DBUS_H
#define HAL_DBUS_H

#include <dbus/dbus.h>

#include "device.h"

DBusHandlerResult manager_get_all_devices           (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult manager_find_device_string_match  (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult manager_find_device_by_capability (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult manager_device_exists             (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult device_get_all_properties         (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult device_get_property               (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult device_get_property_type          (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult device_set_property               (DBusConnection *conn,
						     DBusMessage    *msg, dbus_bool_t local_interface);
DBusHandlerResult device_add_capability             (DBusConnection *conn,
						     DBusMessage    *msg, dbus_bool_t local_interface);
DBusHandlerResult device_remove_capability          (DBusConnection *conn,
						     DBusMessage    *msg, dbus_bool_t local_interface);
DBusHandlerResult device_remove_property            (DBusConnection *conn,
						     DBusMessage    *msg, dbus_bool_t local_interface);
DBusHandlerResult device_property_exists            (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult device_query_capability           (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult device_lock                       (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult device_unlock                     (DBusConnection *conn,
						     DBusMessage    *msg);
DBusHandlerResult manager_new_device          (DBusConnection *conn,
					       DBusMessage    *msg, dbus_bool_t local_interface);
DBusHandlerResult manager_commit_to_gdl       (DBusConnection *conn,
					       DBusMessage    *msg, dbus_bool_t local_interface);
DBusHandlerResult manager_remove              (DBusConnection *conn,
					       DBusMessage    *msg, dbus_bool_t local_interface);
DBusHandlerResult merge_properties            (DBusConnection *conn,
					       DBusMessage    *msg);
DBusHandlerResult device_matches              (DBusConnection *conn,
					       DBusMessage    *msg);

void manager_send_signal_device_added   (HalDevice *device);
void manager_send_signal_device_removed (HalDevice *device);
void manager_send_signal_new_capability (HalDevice *device,
					 const char *capability);

void device_send_signal_property_modified (HalDevice *device,
					   const char *key,
					   dbus_bool_t removed,
					   dbus_bool_t added);
void device_send_signal_condition (HalDevice *device,
				   const char *condition_name,
				   const char *condition_details);

void device_property_atomic_update_begin (void);
void device_property_atomic_update_end   (void);

gboolean hald_dbus_init (void);

gboolean hald_dbus_local_server_init (void);

DBusHandlerResult hald_dbus_filter_function (DBusConnection * connection, DBusMessage * message, void *user_data);

char *hald_dbus_local_server_addr (void);

gboolean device_is_executing_method (HalDevice *d, const char *interface_name, const char *method_name);

#endif /* HAL_DBUS_H */
