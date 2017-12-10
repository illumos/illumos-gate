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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>

#include "hald.h"
#include "device.h"
#include "hald_marshal.h"
#include "logger.h"
#include "hald_runner.h"

static GObjectClass *parent_class;

enum {
	PROPERTY_CHANGED,
	CAPABILITY_ADDED,
	CALLOUTS_FINISHED,
	CANCELLED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

#ifdef HALD_MEMLEAK_DBG
int dbg_hal_device_object_delta = 0;
#endif

static void
hal_device_finalize (GObject *obj)
{
	HalDevice *device = HAL_DEVICE (obj);

	runner_device_finalized (device);

#ifdef HALD_MEMLEAK_DBG
	dbg_hal_device_object_delta--;
	printf ("************* in finalize for udi=%s\n", device->udi);
#endif


	g_slist_foreach (device->properties, (GFunc) hal_property_free, NULL);

	g_slist_free (device->properties);

	g_free (device->udi);

	if (parent_class->finalize)
		parent_class->finalize (obj);

}

static void
hal_device_class_init (HalDeviceClass *klass)
{
	GObjectClass *obj_class = (GObjectClass *) klass;

	parent_class = g_type_class_peek_parent (klass);

	obj_class->finalize = hal_device_finalize;

	signals[PROPERTY_CHANGED] =
		g_signal_new ("property_changed",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (HalDeviceClass,
					       property_changed),
			      NULL, NULL,
			      hald_marshal_VOID__STRING_BOOLEAN_BOOLEAN,
			      G_TYPE_NONE, 3,
			      G_TYPE_STRING,
			      G_TYPE_BOOLEAN,
			      G_TYPE_BOOLEAN);

	signals[CAPABILITY_ADDED] =
		g_signal_new ("capability_added",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (HalDeviceClass,
					       capability_added),
			      NULL, NULL,
			      hald_marshal_VOID__STRING,
			      G_TYPE_NONE, 1,
			      G_TYPE_STRING);

	signals[CALLOUTS_FINISHED] =
		g_signal_new ("callouts_finished",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (HalDeviceClass,
					       callouts_finished),
			      NULL, NULL,
			      hald_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);

	signals[CANCELLED] =
		g_signal_new ("cancelled",
			      G_TYPE_FROM_CLASS (klass),
			      G_SIGNAL_RUN_LAST,
			      G_STRUCT_OFFSET (HalDeviceClass,
					       cancelled),
			      NULL, NULL,
			      hald_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);
}

static void
hal_device_init (HalDevice *device)
{
	static int temp_device_counter = 0;

	device->udi = g_strdup_printf ("/org/freedesktop/Hal/devices/temp/%d",
				       temp_device_counter++);
	device->num_addons = 0;
	device->num_addons_ready = 0;
}

GType
hal_device_get_type (void)
{
	static GType type = 0;
	
	if (!type) {
		static GTypeInfo type_info = {
			sizeof (HalDeviceClass),
			NULL, NULL,
			(GClassInitFunc) hal_device_class_init,
			NULL, NULL,
			sizeof (HalDevice),
			0,
			(GInstanceInitFunc) hal_device_init,
			NULL
		};

		type = g_type_register_static (G_TYPE_OBJECT,
					       "HalDevice",
					       &type_info,
					       0);
	}

	return type;
}


HalDevice *
hal_device_new (void)
{
	HalDevice *device;

	device = g_object_new (HAL_TYPE_DEVICE, NULL, NULL);

#ifdef HALD_MEMLEAK_DBG
	dbg_hal_device_object_delta++;
#endif
	return device;
}

/** Merge all properties from source where the key starts with 
 *  source_namespace and put them onto target replacing source_namespace
 *  with target_namespace
 *
 *  @param  target              Device to put properties onto
 *  @param  source              Device to retrieve properties from
 *  @param  target_namespace    Replace source namespace with this namespace
 *  @param  source_namespace    Source namespace that property keys must match
 */
void
hal_device_merge_with_rewrite  (HalDevice    *target,
				HalDevice    *source,
				const char   *target_namespace,
				const char   *source_namespace)
{
	GSList *iter;
	size_t source_ns_len;

	source_ns_len = strlen (source_namespace);

	/* doesn't handle info.capabilities */

	/* device_property_atomic_update_begin (); */

	for (iter = source->properties; iter != NULL; iter = iter->next) {
		HalProperty *p = iter->data;
		int type;
		const char *key;
		int target_type;
		gchar *target_key;

		key = hal_property_get_key (p);

		/* only care about properties that match source namespace */
		if (strncmp(key, source_namespace, source_ns_len) != 0)
			continue;

		target_key = g_strdup_printf("%s%s", target_namespace,
					     key+source_ns_len);

		type = hal_property_get_type (p);

		/* only remove target if it exists with a different type */
		target_type = hal_device_property_get_type (target, key);
		if (target_type != HAL_PROPERTY_TYPE_INVALID && target_type != type)
			hal_device_property_remove (target, key);

		switch (type) {

		case HAL_PROPERTY_TYPE_STRING:
			hal_device_property_set_string (
				target, target_key,
				hal_property_get_string (p));
			break;

		case HAL_PROPERTY_TYPE_INT32:
			hal_device_property_set_int (
				target, target_key,
				hal_property_get_int (p));
			break;

		case HAL_PROPERTY_TYPE_UINT64:
			hal_device_property_set_uint64 (
				target, target_key,
				hal_property_get_uint64 (p));
			break;

		case HAL_PROPERTY_TYPE_BOOLEAN:
			hal_device_property_set_bool (
				target, target_key,
				hal_property_get_bool (p));
			break;

		case HAL_PROPERTY_TYPE_DOUBLE:
			hal_device_property_set_double (
				target, target_key,
				hal_property_get_double (p));
			break;

		default:
			HAL_WARNING (("Unknown property type %d", type));
			break;
		}

		g_free (target_key);
	}

	/* device_property_atomic_update_end (); */

}

void
hal_device_merge (HalDevice *target, HalDevice *source)
{
	GSList *iter;
	GSList *caps;

	/* device_property_atomic_update_begin (); */

	for (iter = source->properties; iter != NULL; iter = iter->next) {
		HalProperty *p = iter->data;
		int type;
		const char *key;
		int target_type;

		key = hal_property_get_key (p);
		type = hal_property_get_type (p);

		/* handle info.capabilities in a special way */
		if (strcmp (key, "info.capabilities") == 0)
			continue;

		/* only remove target if it exists with a different type */
		target_type = hal_device_property_get_type (target, key);
		if (target_type != HAL_PROPERTY_TYPE_INVALID && target_type != type)
			hal_device_property_remove (target, key);

		switch (type) {

		case HAL_PROPERTY_TYPE_STRING:
			hal_device_property_set_string (
				target, key,
				hal_property_get_string (p));
			break;

		case HAL_PROPERTY_TYPE_INT32:
			hal_device_property_set_int (
				target, key,
				hal_property_get_int (p));
			break;

		case HAL_PROPERTY_TYPE_UINT64:
			hal_device_property_set_uint64 (
				target, key,
				hal_property_get_uint64 (p));
			break;

		case HAL_PROPERTY_TYPE_BOOLEAN:
			hal_device_property_set_bool (
				target, key,
				hal_property_get_bool (p));
			break;

		case HAL_PROPERTY_TYPE_DOUBLE:
			hal_device_property_set_double (
				target, key,
				hal_property_get_double (p));
			break;

		default:
			HAL_WARNING (("Unknown property type %d", type));
			break;
		}
	}

	/* device_property_atomic_update_end (); */

	caps = hal_device_property_get_strlist (source, "info.capabilities");
	for (iter = caps; iter != NULL; iter = iter->next) {
		if (!hal_device_has_capability (target, iter->data))
			hal_device_add_capability (target, iter->data);
	}
}

gboolean
hal_device_matches (HalDevice *device1, HalDevice *device2,
		    const char *namespace)
{
	int len;
	GSList *iter;

	len = strlen (namespace);

	for (iter = device1->properties; iter != NULL; iter = iter->next) {
		HalProperty *p;
		const char *key;
		int type;

		p = (HalProperty *) iter->data;
		key = hal_property_get_key (p);
		type = hal_property_get_type (p);

		if (strncmp (key, namespace, len) != 0)
			continue;

		if (!hal_device_has_property (device2, key))
			return FALSE;

		switch (type) {

		case HAL_PROPERTY_TYPE_STRING:
			if (strcmp (hal_property_get_string (p),
				    hal_device_property_get_string (device2,
								    key)) != 0)
				return FALSE;
			break;

		case HAL_PROPERTY_TYPE_INT32:
			if (hal_property_get_int (p) !=
			    hal_device_property_get_int (device2, key))
				return FALSE;
			break;

		case HAL_PROPERTY_TYPE_UINT64:
			if (hal_property_get_uint64 (p) !=
				hal_device_property_get_uint64 (device2, key))
				return FALSE;
			break;

		case HAL_PROPERTY_TYPE_BOOLEAN:
			if (hal_property_get_bool (p) !=
			    hal_device_property_get_bool (device2, key))
				return FALSE;
			break;

		case HAL_PROPERTY_TYPE_DOUBLE:
			if (hal_property_get_double (p) !=
			    hal_device_property_get_double (device2, key))
				return FALSE;
			break;

		default:
			HAL_WARNING (("Unknown property type %d", type));
			break;
		}
	}

	return TRUE;
}

const char *
hal_device_get_udi (HalDevice *device)
{
	return device->udi;
}

void
hal_device_set_udi (HalDevice *device, const char *udi)
{
	if (device->udi != NULL)
		g_free (device->udi);
	device->udi = g_strdup (udi);
}

void
hal_device_add_capability (HalDevice *device, const char *capability)
{
	if (hal_device_property_strlist_add (device, "info.capabilities", capability))
		g_signal_emit (device, signals[CAPABILITY_ADDED], 0, capability);
}

gboolean
hal_device_has_capability (HalDevice *device, const char *capability)
{
	GSList *caps;
	GSList *iter;
	gboolean matched = FALSE;

	caps = hal_device_property_get_strlist (device, "info.capabilities");

	if (caps == NULL)
		return FALSE;

	for (iter = caps; iter != NULL; iter = iter->next) {
		if (strcmp (iter->data, capability) == 0) {
			matched = TRUE;
			break;
		}
	}

	return matched;
}

gboolean
hal_device_has_property (HalDevice *device, const char *key)
{
	g_return_val_if_fail (device != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);

	return hal_device_property_find (device, key) != NULL;
}

int
hal_device_num_properties (HalDevice *device)
{
	g_return_val_if_fail (device != NULL, -1);

	return g_slist_length (device->properties);
}

HalProperty *
hal_device_property_find (HalDevice *device, const char *key)
{
	GSList *iter;

	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	for (iter = device->properties; iter != NULL; iter = iter->next) {
		HalProperty *p = iter->data;

		if (strcmp (hal_property_get_key (p), key) == 0)
			return p;
	}

	return NULL;
}

char *
hal_device_property_to_string (HalDevice *device, const char *key)
{
	HalProperty *prop;

	prop = hal_device_property_find (device, key);
	if (!prop)
		return NULL;

	return hal_property_to_string (prop);
}

void
hal_device_property_foreach (HalDevice *device,
			     HalDevicePropertyForeachFn callback,
			     gpointer user_data)
{
	GSList *iter;

	g_return_if_fail (device != NULL);
	g_return_if_fail (callback != NULL);

	for (iter = device->properties; iter != NULL; iter = iter->next) {
		HalProperty *p = iter->data;
		gboolean cont;

		cont = callback (device, p, user_data);

		if (cont == FALSE)
			return;
	}
}

int
hal_device_property_get_type (HalDevice *device, const char *key)
{
	HalProperty *prop;

	g_return_val_if_fail (device != NULL, HAL_PROPERTY_TYPE_INVALID);
	g_return_val_if_fail (key != NULL, HAL_PROPERTY_TYPE_INVALID);

	prop = hal_device_property_find (device, key);

	if (prop != NULL)
		return hal_property_get_type (prop);
	else
		return HAL_PROPERTY_TYPE_INVALID;
}

const char *
hal_device_property_get_string (HalDevice *device, const char *key)
{
	HalProperty *prop;

	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	prop = hal_device_property_find (device, key);

	if (prop != NULL)
		return hal_property_get_string (prop);
	else
		return NULL;
}

const char *
hal_device_property_get_as_string (HalDevice *device, const char *key, char *buf, size_t bufsize)
{
	HalProperty *prop;

	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);
	g_return_val_if_fail (buf != NULL, NULL);

	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		switch (hal_property_get_type (prop)) {
		case HAL_PROPERTY_TYPE_STRING:
			strncpy (buf, hal_property_get_string (prop), bufsize);
			break;
		case HAL_PROPERTY_TYPE_INT32:
			snprintf (buf, bufsize, "%d", hal_property_get_int (prop));
			break;
		case HAL_PROPERTY_TYPE_UINT64:
			snprintf (buf, bufsize, "%llu", (long long unsigned int) hal_property_get_uint64 (prop));
			break;
		case HAL_PROPERTY_TYPE_DOUBLE:
			snprintf (buf, bufsize, "%f", hal_property_get_double (prop));
			break;
		case HAL_PROPERTY_TYPE_BOOLEAN:
			strncpy (buf, hal_property_get_bool (prop) ? "true" : "false", bufsize);
			break;

		case HAL_PROPERTY_TYPE_STRLIST:
			/* print out as "\tval1\tval2\val3\t" */
		        {
				GSList *iter;
				guint i;

				if (bufsize > 0)
					buf[0] = '\t';
				i = 1;
				for (iter = hal_property_get_strlist (prop); 
				     iter != NULL && i < bufsize; 
				     iter = g_slist_next (iter)) {
					guint len;
					const char *str;
					
					str = (const char *) iter->data;
					len = strlen (str);
					strncpy (buf + i, str, bufsize - i);
					i += len;

					if (i < bufsize) {
						buf[i] = '\t';
						i++;
					}
				}
			}
			break;
		}
		return buf;
	} else {
		buf[0] = '\0';
		return NULL;
	}
}

dbus_int32_t
hal_device_property_get_int (HalDevice *device, const char *key)
{
	HalProperty *prop;

	g_return_val_if_fail (device != NULL, -1);
	g_return_val_if_fail (key != NULL, -1);

	prop = hal_device_property_find (device, key);

	if (prop != NULL)
		return hal_property_get_int (prop);
	else
		return -1;
}

dbus_uint64_t
hal_device_property_get_uint64 (HalDevice *device, const char *key)
{
	HalProperty *prop;

	g_return_val_if_fail (device != NULL, -1);
	g_return_val_if_fail (key != NULL, -1);

	prop = hal_device_property_find (device, key);

	if (prop != NULL)
		return hal_property_get_uint64 (prop);
	else
		return -1;
}

dbus_bool_t
hal_device_property_get_bool (HalDevice *device, const char *key)
{
	HalProperty *prop;

	g_return_val_if_fail (device != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);

	prop = hal_device_property_find (device, key);

	if (prop != NULL)
		return hal_property_get_bool (prop);
	else
		return FALSE;
}

double
hal_device_property_get_double (HalDevice *device, const char *key)
{
	HalProperty *prop;

	g_return_val_if_fail (device != NULL, -1.0);
	g_return_val_if_fail (key != NULL, -1.0);

	prop = hal_device_property_find (device, key);

	if (prop != NULL)
		return hal_property_get_double (prop);
	else
		return -1.0;
}

gboolean
hal_device_property_set_string (HalDevice *device, const char *key,
				const char *value)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_STRING)
			return FALSE;

		/* don't bother setting the same value */
		if (value != NULL &&
		    strcmp (hal_property_get_string (prop), value) == 0)
			return TRUE;

		hal_property_set_string (prop, value);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);

	} else {

		prop = hal_property_new_string (key, value);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);
	}

	return TRUE;
}

gboolean
hal_device_property_set_int (HalDevice *device, const char *key,
			     dbus_int32_t value)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_INT32)
			return FALSE;

		/* don't bother setting the same value */
		if (hal_property_get_int (prop) == value)
			return TRUE;

		hal_property_set_int (prop, value);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);

	} else {
		prop = hal_property_new_int (key, value);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);
	}

	return TRUE;
}

gboolean
hal_device_property_set_uint64 (HalDevice *device, const char *key,
			     dbus_uint64_t value)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_UINT64)
			return FALSE;

		/* don't bother setting the same value */
		if (hal_property_get_uint64 (prop) == value)
			return TRUE;

		hal_property_set_uint64 (prop, value);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);

	} else {
		prop = hal_property_new_uint64 (key, value);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);
	}

	return TRUE;
}

gboolean
hal_device_property_set_bool (HalDevice *device, const char *key,
			     dbus_bool_t value)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_BOOLEAN)
			return FALSE;

		/* don't bother setting the same value */
		if (hal_property_get_bool (prop) == value)
			return TRUE;

		hal_property_set_bool (prop, value);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);

	} else {
		prop = hal_property_new_bool (key, value);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);
	}

	return TRUE;
}

gboolean
hal_device_property_set_double (HalDevice *device, const char *key,
				double value)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_DOUBLE)
			return FALSE;

		/* don't bother setting the same value */
		if (hal_property_get_double (prop) == value)
			return TRUE;

		hal_property_set_double (prop, value);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);

	} else {
		prop = hal_property_new_double (key, value);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);
	}

	return TRUE;
}

gboolean
hal_device_copy_property (HalDevice *from_device, const char *from, HalDevice *to_device, const char *to)
{
	gboolean rc;

	rc = FALSE;

	if (hal_device_has_property (from_device, from)) {
		switch (hal_device_property_get_type (from_device, from)) {
		case HAL_PROPERTY_TYPE_STRING:
			rc = hal_device_property_set_string (
				to_device, to, hal_device_property_get_string (from_device, from));
			break;
		case HAL_PROPERTY_TYPE_INT32:
			rc = hal_device_property_set_int (
				to_device, to, hal_device_property_get_int (from_device, from));
			break;
		case HAL_PROPERTY_TYPE_UINT64:
			rc = hal_device_property_set_uint64 (
				to_device, to, hal_device_property_get_uint64 (from_device, from));
			break;
		case HAL_PROPERTY_TYPE_BOOLEAN:
			rc = hal_device_property_set_bool (
				to_device, to, hal_device_property_get_bool (from_device, from));
			break;
		case HAL_PROPERTY_TYPE_DOUBLE:
			rc = hal_device_property_set_double (
				to_device, to, hal_device_property_get_double (from_device, from));
			break;
		}
	}

	return rc;
}

gboolean
hal_device_property_remove (HalDevice *device, const char *key)
{
	HalProperty *prop;

	prop = hal_device_property_find (device, key);

	if (prop == NULL)
		return FALSE;

	device->properties = g_slist_remove (device->properties, prop);

	hal_property_free (prop);

	g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
		       key, TRUE, FALSE);

	return TRUE;
}

gboolean
hal_device_property_set_attribute (HalDevice *device,
				   const char *key,
				   enum PropertyAttribute attr,
				   gboolean val)
{
	HalProperty *prop;

	prop = hal_device_property_find (device, key);

	if (prop == NULL)
		return FALSE;

	return TRUE;
}

void
hal_device_print (HalDevice *device)
{
	GSList *iter;

        fprintf (stderr, "device udi = %s\n", hal_device_get_udi (device));

	for (iter = device->properties; iter != NULL; iter = iter->next) {
		HalProperty *p = iter->data;
                int type;
                const char *key;

                key = hal_property_get_key (p);
                type = hal_property_get_type (p);

                switch (type) {
                case HAL_PROPERTY_TYPE_STRING:
                        fprintf (stderr, "  %s = '%s'  (string)\n", key,
                                hal_property_get_string (p));
                        break;
 
                case HAL_PROPERTY_TYPE_INT32:
                        fprintf (stderr, "  %s = %d  0x%x  (int)\n", key,
                                hal_property_get_int (p),
                                hal_property_get_int (p));
                        break;
 
                case HAL_PROPERTY_TYPE_UINT64:
                        fprintf (stderr, "  %s = %llu  0x%llx  (uint64)\n", key,
                                (long long unsigned int) hal_property_get_uint64 (p),
                                (long long unsigned int) hal_property_get_uint64 (p));
                        break;
 
                case HAL_PROPERTY_TYPE_DOUBLE:
                        fprintf (stderr, "  %s = %g  (double)\n", key,
                                hal_property_get_double (p));
                        break;
 
                case HAL_PROPERTY_TYPE_BOOLEAN:
                        fprintf (stderr, "  %s = %s  (bool)\n", key,
                                (hal_property_get_bool (p) ? "true" :
                                 "false"));
                        break;
 
                default:
                        HAL_WARNING (("Unknown property type %d", type));
                        break;
                }
        }
        fprintf (stderr, "\n");
}


typedef struct {
	char *key;
	HalDevice *device;
	HalDeviceAsyncCallback callback;
	gpointer user_data;

	guint prop_signal_id;
	guint timeout_id;
} AsyncMatchInfo;

static void
destroy_async_match_info (AsyncMatchInfo *ai)
{
	g_free (ai->key);
	g_signal_handler_disconnect (ai->device, ai->prop_signal_id);
	g_source_remove (ai->timeout_id);
	g_object_unref (ai->device);
	g_free (ai);
}

static void
prop_changed_cb (HalDevice *device, const char *key,
		 gboolean removed, gboolean added, gpointer user_data)
{
	AsyncMatchInfo *ai = user_data;

	if (strcmp (key, ai->key) != 0)
		return;

	/* the property is no longer there */
	if (removed)
		goto cleanup;


	ai->callback (ai->device, ai->user_data, TRUE);

cleanup:
	destroy_async_match_info (ai);
}


static gboolean
async_wait_timeout (gpointer user_data)
{
	AsyncMatchInfo *ai = (AsyncMatchInfo *) user_data;

	ai->callback (ai->device, ai->user_data, FALSE);

	destroy_async_match_info (ai);

	return FALSE;
}

void
hal_device_async_wait_property (HalDevice    *device,
				const char   *key,
				HalDeviceAsyncCallback callback,
				gpointer     user_data,
				int          timeout)
{
	HalProperty *prop;
	AsyncMatchInfo *ai;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL || timeout==0) {
		callback (device, user_data, prop != NULL);
		return;
	}

	ai = g_new0 (AsyncMatchInfo, 1);

	ai->device = g_object_ref (device);
	ai->key = g_strdup (key);
	ai->callback = callback;
	ai->user_data = user_data;

	ai->prop_signal_id = g_signal_connect (device, "property_changed",
					       G_CALLBACK (prop_changed_cb),
					       ai);

	ai->timeout_id = g_timeout_add (timeout, async_wait_timeout, ai);
}

void
hal_device_callouts_finished (HalDevice *device)
{
	g_signal_emit (device, signals[CALLOUTS_FINISHED], 0);
}

/** Used when giving up on a device, e.g. if no device file appeared
 */
void
hal_device_cancel (HalDevice *device)
{
	HAL_INFO (("udi=%s", device->udi));
	g_signal_emit (device, signals[CANCELLED], 0);
}




GSList *
hal_device_property_get_strlist (HalDevice    *device, 
				 const char   *key)
{
	HalProperty *prop;

	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (key != NULL, NULL);

	prop = hal_device_property_find (device, key);

	if (prop != NULL)
		return hal_property_get_strlist (prop);
	else
		return NULL;
}

const char *
hal_device_property_get_strlist_elem (HalDevice    *device,
				      const char   *key,
				      guint index)
{
	GSList *strlist;
	GSList *i;

	strlist = hal_device_property_get_strlist (device, key);
	if (strlist == NULL)
		return NULL;

	i = g_slist_nth (strlist, index);
	if (i == NULL)
		return NULL;

	return (const char *) i->data;
}

gboolean
hal_device_property_strlist_append (HalDevice    *device,
				    const char   *key,
				    const char *value)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_STRLIST)
			return FALSE;

		hal_property_strlist_append (prop, value);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);

	} else {
		prop = hal_property_new_strlist (key);
		hal_property_strlist_append (prop, value);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);
	}

	return TRUE;
}

gboolean 
hal_device_property_strlist_prepend (HalDevice    *device,
				     const char   *key,
				     const char *value)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_STRLIST)
			return FALSE;

		hal_property_strlist_prepend (prop, value);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);

	} else {
		prop = hal_property_new_strlist (key);
		hal_property_strlist_prepend (prop, value);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);
	}

	return TRUE;
}

gboolean
hal_device_property_strlist_remove_elem (HalDevice    *device,
					 const char   *key,
					 guint index)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop == NULL)
		return FALSE;

	if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_STRLIST)
		return FALSE;
	
	if (hal_property_strlist_remove_elem (prop, index)) {
		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);
		return TRUE;
	}
	
	return FALSE;
}

gboolean
hal_device_property_strlist_clear (HalDevice    *device,
				   const char   *key)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop == NULL) {
		prop = hal_property_new_strlist (key);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);

		return TRUE;
	}

	if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_STRLIST)
		return FALSE;
	
	if (hal_property_strlist_clear (prop)) {
		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);
		return TRUE;
	}
	
	return FALSE;
}


gboolean
hal_device_property_strlist_add (HalDevice *device,
				 const char *key,
				 const char *value)
{
	HalProperty *prop;
	gboolean res;

	res = FALSE;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop != NULL) {
		if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_STRLIST)
			goto out;

		res = hal_property_strlist_add (prop, value);
		if (res) {
			g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
				       key, FALSE, FALSE);
		}

	} else {
		prop = hal_property_new_strlist (key);
		hal_property_strlist_prepend (prop, value);

		device->properties = g_slist_prepend (device->properties, prop);

		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, TRUE);

		res = TRUE;
	}

out:
	return res;
}

gboolean
hal_device_property_strlist_remove (HalDevice *device,
				    const char *key,
				    const char *value)
{
	HalProperty *prop;

	/* check if property already exists */
	prop = hal_device_property_find (device, key);

	if (prop == NULL)
		return FALSE;

	if (hal_property_get_type (prop) != HAL_PROPERTY_TYPE_STRLIST)
		return FALSE;
	
	if (hal_property_strlist_remove (prop, value)) {
		g_signal_emit (device, signals[PROPERTY_CHANGED], 0,
			       key, FALSE, FALSE);
	}
	
	return TRUE;
}

gboolean
hal_device_property_strlist_is_empty (HalDevice    *device,
				      const char   *key)
{
	GSList *strlist;

	if ( hal_device_has_property (device, key)) {
		strlist = hal_device_property_get_strlist (device, key);
		if (strlist == NULL ) 
			return TRUE;

		if (g_slist_length (strlist) > 0) 
			return FALSE;
		else 
			return TRUE;
	}
	return FALSE;
}

void
hal_device_inc_num_addons (HalDevice *device)
{
	device->num_addons++;
}

gboolean
hal_device_inc_num_ready_addons (HalDevice *device)
{
	if (hal_device_are_all_addons_ready (device)) {
		HAL_ERROR (("In hal_device_inc_num_ready_addons for udi=%s but all addons are already ready!", 
			    device->udi));
		return FALSE;
	}

	device->num_addons_ready++;
	return TRUE;
}

gboolean
hal_device_are_all_addons_ready (HalDevice *device)
{
	if (device->num_addons_ready == device->num_addons) {
		return TRUE;
	} else {
		return FALSE;
	}
}
