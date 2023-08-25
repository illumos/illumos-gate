/***************************************************************************
 * CVSID: $Id$
 *
 * device.c : HalDevice methods
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
 * Copyright (C) 2004 Novell, Inc.
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

#ifndef DEVICE_H
#define DEVICE_H

#include <glib-object.h>
#include <dbus/dbus.h>

#include "property.h"

typedef struct _HalDevice      HalDevice;
typedef struct _HalDeviceClass HalDeviceClass;

struct _HalDevice {
	GObject parent;

	char *udi;

	GSList *properties;

	int num_addons;
	int num_addons_ready;
};

struct _HalDeviceClass {
	GObjectClass parent_class;

	/* signals */
	void (*property_changed) (HalDevice *device,
				  const char *key,
				  gboolean removed,
				  gboolean added);

	void (*capability_added) (HalDevice *device,
				  const char *capability);

	void (*callouts_finished) (HalDevice *device);

	void (*cancelled) (HalDevice *device);
};

#define HAL_TYPE_DEVICE             (hal_device_get_type ())
#define HAL_DEVICE(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), \
                                     HAL_TYPE_DEVICE, HalDevice))
#define HAL_DEVICE_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), \
                                     HAL_TYPE_DEVICE, HalDeviceClass))
#define HAL_IS_DEVICE(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), \
                                     HAL_TYPE_DEVICE))
#define HAL_IS_DEVICE_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), \
                                     HAL_TYPE_DEVICE))

typedef void     (*HalDeviceAsyncCallback) (HalDevice *device,
					    gpointer user_data,
					    gboolean prop_exists);

/* Return value of FALSE means that the foreach should be short-circuited */
typedef gboolean (*HalDevicePropertyForeachFn) (HalDevice *device,
						HalProperty *property,
						gpointer user_data);

GType         hal_device_get_type            (void);

HalDevice   *hal_device_new                  (void);

void          hal_device_merge               (HalDevice    *target,
					      HalDevice    *source);

void          hal_device_merge_with_rewrite  (HalDevice    *target,
					      HalDevice    *source,
					      const char   *target_namespace,
					      const char   *source_namespace);

gboolean      hal_device_matches             (HalDevice    *device1,
					      HalDevice    *device2,
					      const char   *namespace);

const char   *hal_device_get_udi             (HalDevice    *device);
void          hal_device_set_udi             (HalDevice    *device,
					      const char   *udi);

void          hal_device_add_capability      (HalDevice    *device,
					      const char   *capability);
gboolean      hal_device_has_capability      (HalDevice    *device,
					      const char   *capability);

gboolean      hal_device_has_property        (HalDevice    *device,
					      const char   *key);
HalProperty  *hal_device_property_find       (HalDevice    *device,
					      const char   *key);
int           hal_device_num_properties      (HalDevice    *device);
char *        hal_device_property_to_string  (HalDevice    *device,
					      const char   *key);
void          hal_device_property_foreach    (HalDevice    *device,
					      HalDevicePropertyForeachFn callback,
					      gpointer      user_data);

int           hal_device_property_get_type   (HalDevice    *device,
					      const char   *key);
const char   *hal_device_property_get_as_string (HalDevice    *device,
						 const char   *key,
						 char *buf,
						 size_t bufsize);


const char   *hal_device_property_get_string (HalDevice    *device,
					      const char   *key);
dbus_int32_t  hal_device_property_get_int    (HalDevice    *device,
					      const char   *key);
dbus_uint64_t hal_device_property_get_uint64 (HalDevice    *device,
						  const char   *key);
dbus_bool_t   hal_device_property_get_bool   (HalDevice    *device,
					      const char   *key);
double        hal_device_property_get_double (HalDevice    *device,
					      const char   *key);
GSList       *hal_device_property_get_strlist (HalDevice    *device,
					       const char   *key);
const char   *hal_device_property_get_strlist_elem (HalDevice    *device,
						    const char   *key,
						    guint index);



gboolean      hal_device_property_set_string (HalDevice    *device,
					      const char   *key,
					      const char   *value);
gboolean      hal_device_property_set_int    (HalDevice    *device,
					      const char   *key,
					      dbus_int32_t  value);
gboolean      hal_device_property_set_uint64 (HalDevice    *device,
					      const char   *key,
					      dbus_uint64_t value);
gboolean      hal_device_property_set_bool   (HalDevice    *device,
					      const char   *key,
					      dbus_bool_t   value);
gboolean      hal_device_property_set_double (HalDevice    *device,
					      const char   *key,
					      double        value);
gboolean      hal_device_property_strlist_append (HalDevice    *device,
						  const char   *key,
						  const char *value);
gboolean      hal_device_property_strlist_prepend (HalDevice    *device,
						  const char   *key,
						  const char *value);
gboolean      hal_device_property_strlist_remove_elem (HalDevice    *device,
						       const char   *key,
						       guint index);
gboolean      hal_device_property_strlist_clear (HalDevice    *device,
						 const char   *key);
gboolean      hal_device_property_strlist_add (HalDevice    *device,
					       const char   *key,
					       const char *value);
gboolean      hal_device_property_strlist_remove (HalDevice    *device,
						  const char   *key,
						  const char *value);
gboolean      hal_device_property_strlist_is_empty (HalDevice    *device,
                                                    const char   *key);

gboolean      hal_device_property_remove     (HalDevice    *device,
					      const char   *key);

gboolean      hal_device_copy_property       (HalDevice *from_device,
					      const char *from,
					      HalDevice *to_device,
					      const char *to);


void          hal_device_print               (HalDevice    *device);

void          hal_device_async_wait_property (HalDevice    *device,
					      const char   *key,
					      HalDeviceAsyncCallback callback,
					      gpointer      user_data,
					      int           timeout);

void          hal_device_callouts_finished    (HalDevice    *device);

void          hal_device_cancel               (HalDevice    *device);

gboolean      hal_device_property_set_attribute (HalDevice *device,
						 const char *key,
						 enum PropertyAttribute attr,
						 gboolean persistence);

void          hal_device_inc_num_addons (HalDevice *device);

gboolean      hal_device_inc_num_ready_addons (HalDevice *device);

gboolean      hal_device_are_all_addons_ready (HalDevice *device);


#endif /* DEVICE_H */
