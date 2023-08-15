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

#ifndef DEVICE_STORE_H
#define DEVICE_STORE_H

#include <glib-object.h>

#include "device.h"

typedef struct _HalDeviceStore      HalDeviceStore;
typedef struct _HalDeviceStoreClass HalDeviceStoreClass;

struct _HalDeviceStore {
	GObject parent;

	GSList *devices;
};

struct _HalDeviceStoreClass {
	GObjectClass parent_class;

	/* signals */
	void (*store_changed) (HalDeviceStore *store,
			       HalDevice *device,
			       gboolean added);

	void (*device_property_changed) (HalDeviceStore *store,
					 HalDevice *device,
					 const char *key,
					 gboolean removed,
					 gboolean added);

	void (*device_capability_added) (HalDeviceStore *store,
					 HalDevice *device,
					 const char *capability);

};

#define HAL_TYPE_DEVICE_STORE              (hal_device_store_get_type ())
#define HAL_DEVICE_STORE(obj)              (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
                                            HAL_TYPE_DEVICE_STORE, \
                                            HalDeviceStore))
#define HAL_DEVICE_STORE_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST ((klass), \
                                            HAL_TYPE_DEVICE_STORE, \
					    HalDeviceStoreClass))
#define HAL_IS_DEVICE_STORE(obj)           (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
                                            HAL_TYPE_DEVICE_STORE))
#define HAL_IS_DEVICE_STORE_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass), \
                                            HAL_TYPE_DEVICE_STORE))

typedef void     (*HalDeviceStoreAsyncCallback) (HalDeviceStore *store,
						 HalDevice      *device,
						 gpointer        user_data);

/* Return value of FALSE means that the foreach should be short-circuited */
typedef gboolean (*HalDeviceStoreForeachFn) (HalDeviceStore *store,
					     HalDevice      *device,
					     gpointer        user_data);

GType           hal_device_store_get_type   (void);

HalDeviceStore *hal_device_store_new        (void);

void            hal_device_store_add        (HalDeviceStore *store,
					     HalDevice      *device);
gboolean        hal_device_store_remove     (HalDeviceStore *store,
					     HalDevice      *device);

HalDevice      *hal_device_store_find       (HalDeviceStore *store,
					     const char     *udi);

void            hal_device_store_foreach    (HalDeviceStore *store,
					     HalDeviceStoreForeachFn callback,
					     gpointer user_data);

HalDevice      *hal_device_store_match_key_value_string (HalDeviceStore *store,
							 const char *key,
							 const char *value);

HalDevice      *hal_device_store_match_key_value_int (HalDeviceStore *store,
						      const char *key,
						      int value);

GSList         *hal_device_store_match_multiple_key_value_string (HalDeviceStore *store,
								  const char *key,
								  const char *value);

void           hal_device_store_match_key_value_string_async (HalDeviceStore *store,
							      const char *key,
							      const char *value,
							      HalDeviceStoreAsyncCallback callback,
							      gpointer user_data,
							      int timeout);

void hal_device_store_print (HalDeviceStore *store);


#endif /* DEVICE_STORE_H */
