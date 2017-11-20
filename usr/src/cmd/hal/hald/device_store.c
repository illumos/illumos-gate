/***************************************************************************
 * CVSID: $Id$
 *
 * device_store.c : HalDeviceStore methods
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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "device_store.h"
#include "hald_marshal.h"
#include "logger.h"

static GObjectClass *parent_class;

enum {
	STORE_CHANGED,
	DEVICE_PROPERTY_CHANGED,
	DEVICE_CAPABILITY_ADDED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
hal_device_store_finalize (GObject *obj)
{
	HalDeviceStore *store = HAL_DEVICE_STORE (obj);

	g_slist_foreach (store->devices, (GFunc) g_object_unref, NULL);

	if (parent_class->finalize)
		parent_class->finalize (obj);
}

static void
hal_device_store_class_init (HalDeviceStoreClass *klass)
{
	GObjectClass *obj_class = (GObjectClass *) klass;

	parent_class = g_type_class_peek_parent (klass);

	obj_class->finalize = hal_device_store_finalize;

	signals[STORE_CHANGED] =
		g_signal_new ("store_changed",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (HalDeviceStoreClass,
					       store_changed),
			      NULL, NULL,
			      hald_marshal_VOID__OBJECT_BOOLEAN,
			      G_TYPE_NONE, 2,
			      G_TYPE_OBJECT,
			      G_TYPE_BOOLEAN);

	signals[DEVICE_PROPERTY_CHANGED] =
		g_signal_new ("device_property_changed",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (HalDeviceStoreClass,
					       device_property_changed),
			      NULL, NULL,
			      hald_marshal_VOID__OBJECT_STRING_BOOLEAN_BOOLEAN,
			      G_TYPE_NONE, 4,
			      G_TYPE_OBJECT,
			      G_TYPE_STRING,
			      G_TYPE_BOOLEAN,
			      G_TYPE_BOOLEAN);

	signals[DEVICE_CAPABILITY_ADDED] =
		g_signal_new ("device_capability_added",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (HalDeviceStoreClass,
					       device_capability_added),
			      NULL, NULL,
			      hald_marshal_VOID__OBJECT_STRING,
			      G_TYPE_NONE, 2,
			      G_TYPE_OBJECT,
			      G_TYPE_STRING);
}

static void
hal_device_store_init (HalDeviceStore *device)
{
}

GType
hal_device_store_get_type (void)
{
	static GType type = 0;
	
	if (!type) {
		static GTypeInfo type_info = {
			sizeof (HalDeviceStoreClass),
			NULL, NULL,
			(GClassInitFunc) hal_device_store_class_init,
			NULL, NULL,
			sizeof (HalDeviceStore),
			0,
			(GInstanceInitFunc) hal_device_store_init
		};

		type = g_type_register_static (G_TYPE_OBJECT,
					       "HalDeviceStore",
					       &type_info,
					       0);
	}

	return type;
}

HalDeviceStore *
hal_device_store_new (void)
{
	HalDeviceStore *store;

	store = g_object_new (HAL_TYPE_DEVICE_STORE, NULL, NULL);

	return store;
}

static void
emit_device_property_changed (HalDevice *device,
			      const char *key,
			      gboolean added,
			      gboolean removed,
			      gpointer data)
{
	HalDeviceStore *store = HAL_DEVICE_STORE (data);

	g_signal_emit (store, signals[DEVICE_PROPERTY_CHANGED], 0,
		       device, key, added, removed);
}

static void
emit_device_capability_added (HalDevice *device,
			      const char *capability,
			      gpointer data)
{
	HalDeviceStore *store = HAL_DEVICE_STORE (data);

	g_signal_emit (store, signals[DEVICE_CAPABILITY_ADDED], 0,
		       device, capability);
}

void
hal_device_store_add (HalDeviceStore *store, HalDevice *device)
{
	const char buf[] = "/org/freedesktop/Hal/devices/";

	if (strncmp(device->udi, buf, sizeof (buf) - 1) != 0) {
		
		HAL_ERROR(("Can't add HalDevice with incorrect UDI. Valid "
			   "UDI must start with '/org/freedesktop/Hal/devices/'"));
		goto out;
	}
	store->devices = g_slist_prepend (store->devices,
					  g_object_ref (device));

	g_signal_connect (device, "property_changed",
			  G_CALLBACK (emit_device_property_changed), store);
	g_signal_connect (device, "capability_added",
			  G_CALLBACK (emit_device_capability_added), store);

	g_signal_emit (store, signals[STORE_CHANGED], 0, device, TRUE);

out:
	;
}

gboolean
hal_device_store_remove (HalDeviceStore *store, HalDevice *device)
{
	if (!g_slist_find (store->devices, device))
		return FALSE;

	store->devices = g_slist_remove (store->devices, device);

	g_signal_handlers_disconnect_by_func (device,
					      (gpointer)emit_device_property_changed,
					      store);
	g_signal_handlers_disconnect_by_func (device,
					      (gpointer)emit_device_capability_added,
					      store);

	g_signal_emit (store, signals[STORE_CHANGED], 0, device, FALSE);

	g_object_unref (device);

	return TRUE;
}

HalDevice *
hal_device_store_find (HalDeviceStore *store, const char *udi)
{
	GSList *iter;

	for (iter = store->devices; iter != NULL; iter = iter->next) {
		HalDevice *d = iter->data;

		if (strcmp (hal_device_get_udi (d), udi) == 0)
			return d;
	}

	return NULL;
}

void
hal_device_store_foreach (HalDeviceStore *store,
			  HalDeviceStoreForeachFn callback,
			  gpointer user_data)
{
	GSList *iter;

	g_return_if_fail (store != NULL);
	g_return_if_fail (callback != NULL);

	for (iter = store->devices; iter != NULL; iter = iter->next) {
		HalDevice *d = HAL_DEVICE (iter->data);
		gboolean cont;

		cont = callback (store, d, user_data);

		if (cont == FALSE)
			return;
	}
}

static gboolean
hal_device_store_print_foreach_fn (HalDeviceStore *store,
				   HalDevice *device,
				   gpointer user_data)
{
	fprintf (stderr, "----\n");
	hal_device_print (device);
	fprintf (stderr, "----\n");
	return TRUE;
}

void 
hal_device_store_print (HalDeviceStore *store)
{
	fprintf (stderr, "===============================================\n");
        fprintf (stderr, "Dumping %d devices\n", 
		 g_slist_length (store->devices));
	fprintf (stderr, "===============================================\n");
	hal_device_store_foreach (store, 
				  hal_device_store_print_foreach_fn, 
				  NULL);
	fprintf (stderr, "===============================================\n");
}

HalDevice *
hal_device_store_match_key_value_string (HalDeviceStore *store,
					 const char *key,
					 const char *value)
{
	GSList *iter;

	g_return_val_if_fail (store != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);
	g_return_val_if_fail (value != NULL, NULL);

	for (iter = store->devices; iter != NULL; iter = iter->next) {
		HalDevice *d = HAL_DEVICE (iter->data);
		int type;

		if (!hal_device_has_property (d, key))
			continue;

		type = hal_device_property_get_type (d, key);
		if (type != HAL_PROPERTY_TYPE_STRING)
			continue;

		if (strcmp (hal_device_property_get_string (d, key),
			    value) == 0)
			return d;
	}

	return NULL;
}

HalDevice *
hal_device_store_match_key_value_int (HalDeviceStore *store,
				      const char *key,
				      int value)
{
	GSList *iter;

	g_return_val_if_fail (store != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	for (iter = store->devices; iter != NULL; iter = iter->next) {
		HalDevice *d = HAL_DEVICE (iter->data);
		int type;

		if (!hal_device_has_property (d, key))
			continue;

		type = hal_device_property_get_type (d, key);
		if (type != HAL_PROPERTY_TYPE_INT32)
			continue;

		if (hal_device_property_get_int (d, key) == value)
			return d;
	}

	return NULL;
}

GSList *
hal_device_store_match_multiple_key_value_string (HalDeviceStore *store,
						  const char *key,
						  const char *value)
{
	GSList *iter;
	GSList *matches = NULL;

	g_return_val_if_fail (store != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);
	g_return_val_if_fail (value != NULL, NULL);

	for (iter = store->devices; iter != NULL; iter = iter->next) {
		HalDevice *d = HAL_DEVICE (iter->data);
		int type;

		if (!hal_device_has_property (d, key))
			continue;

		type = hal_device_property_get_type (d, key);
		if (type != HAL_PROPERTY_TYPE_STRING)
			continue;

		if (strcmp (hal_device_property_get_string (d, key),
			    value) == 0)
			matches = g_slist_prepend (matches, d);
	}

	return matches;
}

typedef struct {
	HalDeviceStore *store;
	char *key;
	char *value;
	HalDeviceStoreAsyncCallback callback;
	gpointer user_data;

	guint prop_signal_id;
	guint store_signal_id;
	guint timeout_id;
} AsyncMatchInfo;

static void
destroy_async_match_info (AsyncMatchInfo *info)
{
	g_object_unref (info->store);

	g_free (info->key);
	g_free (info->value);

	g_signal_handler_disconnect (info->store, info->prop_signal_id);
	g_signal_handler_disconnect (info->store, info->store_signal_id);
	g_source_remove (info->timeout_id);

	g_free (info);
}

static void
match_device_async (HalDeviceStore *store, HalDevice *device,
		    const char *key, gboolean removed, gboolean added,
		    gpointer user_data)
{
	AsyncMatchInfo *info = (AsyncMatchInfo *) user_data;

	/* Only want to do it for added or changed properties */
	if (removed)
		return;

	/* Keys have to match */
	if (strcmp (info->key, key) != 0)
		return;

	/* Values have to match */
	if (strcmp (hal_device_property_get_string (device, key),
		    info->value) != 0)
		return;

	info->callback (store, device, info->user_data);

	destroy_async_match_info (info);
}

static void
store_changed (HalDeviceStore *store, HalDevice *device,
	       gboolean added, gpointer user_data)
{
	AsyncMatchInfo *info = (AsyncMatchInfo *) user_data;

	if (!added)
		return;

	if (!hal_device_has_property (device, info->key))
		return;

	if (strcmp (hal_device_property_get_string (device, info->key),
		    info->value) != 0)
		return;

	info->callback (store, device, info->user_data);

	destroy_async_match_info (info);
}

static gboolean
match_device_async_timeout (gpointer user_data)
{
	AsyncMatchInfo *info = (AsyncMatchInfo *) user_data;

	info->callback (info->store, NULL, info->user_data);

	destroy_async_match_info (info);

	return FALSE;
}

void
hal_device_store_match_key_value_string_async (HalDeviceStore *store,
					       const char *key,
					       const char *value,
					       HalDeviceStoreAsyncCallback callback,
					       gpointer user_data,
					       int timeout)
{
	HalDevice *device;
	AsyncMatchInfo *info;

	/* First check to see if it's already there */
	device = hal_device_store_match_key_value_string (store, key, value);

	if (device != NULL || timeout == 0) {
		callback (store, device, user_data);

		return;
	}

	info = g_new0 (AsyncMatchInfo, 1);

	info->store = g_object_ref (store);
	info->key = g_strdup (key);
	info->value = g_strdup (value);
	info->callback = callback;
	info->user_data = user_data;

	info->prop_signal_id = g_signal_connect (store,
						 "device_property_changed",
						 G_CALLBACK (match_device_async),
						 info);
	info->store_signal_id = g_signal_connect (store,
						  "store_changed",
						  G_CALLBACK (store_changed),
						  info);

	info->timeout_id = g_timeout_add (timeout,
					  match_device_async_timeout,
					  info);
}
