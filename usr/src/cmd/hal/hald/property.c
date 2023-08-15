/***************************************************************************
 * CVSID: $Id$
 *
 * property.c : HalProperty methods
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

#include <string.h>
#include <glib.h>

#include "logger.h"
#include "property.h"

struct _HalProperty {
	char *key;

	int type;
	union {
		char *str_value;
		dbus_int32_t int_value;
 		dbus_uint64_t uint64_value;
		dbus_bool_t bool_value;
		double double_value;
		GSList *strlist_value;
	} v;
	gboolean readonly;
	gboolean persistence;
	gboolean callout;
};

void
hal_property_free (HalProperty *prop)
{

	g_free (prop->key);

	if (prop->type == HAL_PROPERTY_TYPE_STRING) {
		g_free (prop->v.str_value);
	} else if (prop->type == HAL_PROPERTY_TYPE_STRLIST) {
		GSList *i;
		for (i = prop->v.strlist_value; i != NULL; i = g_slist_next (i)) {
			g_free (i->data);
		}
		g_slist_free (prop->v.strlist_value);
	}

	g_free (prop);
}

HalProperty *
hal_property_new_string (const char *key, const char *value)
{
	HalProperty *prop;
	char *endchar;
	gboolean validated = TRUE;

	prop = g_new0 (HalProperty, 1);

	prop->type = HAL_PROPERTY_TYPE_STRING;
	prop->key = g_strdup (key);
	prop->v.str_value = g_strdup (value != NULL ? value : "");

	while (!g_utf8_validate (prop->v.str_value, -1,
				 (const char **) &endchar)) {
		validated = FALSE;
		*endchar = '?';
	}

	if (!validated) {
		HAL_WARNING (("Key '%s' has invalid UTF-8 string '%s'",
			      key, prop->v.str_value));
	}

	return prop;
}

HalProperty *
hal_property_new_int (const char *key, dbus_int32_t value)
{
	HalProperty *prop;

	prop = g_new0 (HalProperty, 1);

	prop->type = HAL_PROPERTY_TYPE_INT32;
	prop->key = g_strdup (key);
	prop->v.int_value = value;

	return prop;
}

HalProperty *
hal_property_new_uint64 (const char *key, dbus_uint64_t value)
{
	HalProperty *prop;

	prop = g_new0 (HalProperty, 1);

	prop->type = HAL_PROPERTY_TYPE_UINT64;
	prop->key = g_strdup (key);
	prop->v.uint64_value = value;

	return prop;
}

HalProperty *
hal_property_new_bool (const char *key, dbus_bool_t value)
{
	HalProperty *prop;

	prop = g_new0 (HalProperty, 1);

	prop->type = HAL_PROPERTY_TYPE_BOOLEAN;
	prop->key = g_strdup (key);
	prop->v.bool_value = value;

	return prop;
}

HalProperty *
hal_property_new_double (const char *key, double value)
{
	HalProperty *prop;

	prop = g_new0 (HalProperty, 1);

	prop->type = HAL_PROPERTY_TYPE_DOUBLE;
	prop->key = g_strdup (key);
	prop->v.double_value = value;

	return prop;
}

const char *
hal_property_get_key (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, NULL);

	return prop->key;
}

int
hal_property_get_type (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, HAL_PROPERTY_TYPE_INVALID);

	return prop->type;
}

const char *
hal_property_get_string (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, NULL);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_STRING, NULL);

	return prop->v.str_value;
}

dbus_int32_t
hal_property_get_int (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, -1);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_INT32, -1);

	return prop->v.int_value;
}

dbus_uint64_t
hal_property_get_uint64 (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, -1);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_UINT64, -1);

	return prop->v.uint64_value;
}

dbus_bool_t
hal_property_get_bool (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, FALSE);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_BOOLEAN, FALSE);

	return prop->v.bool_value;
}

char *
hal_property_to_string (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, NULL);

	switch (prop->type) {
	case HAL_PROPERTY_TYPE_STRING:
		return g_strdup (prop->v.str_value);
	case HAL_PROPERTY_TYPE_INT32:
		return g_strdup_printf ("%d", prop->v.int_value);
	case HAL_PROPERTY_TYPE_UINT64:
		return g_strdup_printf ("%llu", (long long unsigned int) prop->v.uint64_value);
	case HAL_PROPERTY_TYPE_BOOLEAN:
		/* FIXME: Maybe use 1 and 0 here instead? */
		return g_strdup (prop->v.bool_value ? "true" : "false");
	case HAL_PROPERTY_TYPE_DOUBLE:
		return g_strdup_printf ("%f", prop->v.double_value);
	case HAL_PROPERTY_TYPE_STRLIST:
	{
		GSList *iter;
		guint i;
		char buf[256];

		i = 0;
		buf[0] = '\0';
		for (iter = hal_property_get_strlist (prop);
		     iter != NULL && i < sizeof(buf);
		     iter = g_slist_next (iter)) {
			guint len;
			const char *str;

			str = (const char *) iter->data;
			len = strlen (str);
			strncpy (buf + i, str, sizeof(buf) - i);
			i += len;

			if (g_slist_next (iter) != NULL && i < sizeof(buf)) {
				buf[i] = '\t';
				i++;
			}
		}
		return g_strdup (buf);
	}

	default:
		return NULL;
	}
}

double
hal_property_get_double (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, -1.0);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_DOUBLE, -1.0);

	return prop->v.double_value;
}

void
hal_property_set_string (HalProperty *prop, const char *value)
{
	char *endchar;
	gboolean validated = TRUE;

	g_return_if_fail (prop != NULL);
	g_return_if_fail (prop->type == HAL_PROPERTY_TYPE_STRING ||
			  prop->type == HAL_PROPERTY_TYPE_INVALID);

	prop->type = HAL_PROPERTY_TYPE_STRING;
	if (prop->v.str_value != NULL)
		g_free (prop->v.str_value);
	prop->v.str_value = g_strdup (value);

	while (!g_utf8_validate (prop->v.str_value, -1,
				 (const char **) &endchar)) {
		validated = FALSE;
		*endchar = '?';
	}

	if (!validated) {
		HAL_WARNING (("Key '%s' has invalid UTF-8 string '%s'",
			      prop->key, value));
	}
}

void
hal_property_set_int (HalProperty *prop, dbus_int32_t value)
{
	g_return_if_fail (prop != NULL);
	g_return_if_fail (prop->type == HAL_PROPERTY_TYPE_INT32 ||
			  prop->type == HAL_PROPERTY_TYPE_INVALID);

	prop->type = HAL_PROPERTY_TYPE_INT32;
	prop->v.int_value = value;
}

void
hal_property_set_uint64 (HalProperty *prop, dbus_uint64_t value)
{
	g_return_if_fail (prop != NULL);
	g_return_if_fail (prop->type == HAL_PROPERTY_TYPE_UINT64 ||
			  prop->type == HAL_PROPERTY_TYPE_INVALID);

	prop->type = HAL_PROPERTY_TYPE_UINT64;
	prop->v.uint64_value = value;
}

void
hal_property_set_bool (HalProperty *prop, dbus_bool_t value)
{
	g_return_if_fail (prop != NULL);
	g_return_if_fail (prop->type == HAL_PROPERTY_TYPE_BOOLEAN ||
			  prop->type == HAL_PROPERTY_TYPE_INVALID);

	prop->type = HAL_PROPERTY_TYPE_BOOLEAN;
	prop->v.bool_value = value;
}

void
hal_property_set_double (HalProperty *prop, double value)
{
	g_return_if_fail (prop != NULL);
	g_return_if_fail (prop->type == HAL_PROPERTY_TYPE_DOUBLE ||
			  prop->type == HAL_PROPERTY_TYPE_INVALID);

	prop->type = HAL_PROPERTY_TYPE_DOUBLE;
	prop->v.double_value = value;
}

void
hal_property_set_attribute (HalProperty *prop,
			    enum PropertyAttribute attr,
			    gboolean val)
{
	g_return_if_fail (prop != NULL);

	switch (attr) {
	case READONLY:
		prop->readonly = val;
		break;
	case PERSISTENCE:
		prop->persistence = val;
		break;
	case CALLOUT:
		prop->callout = val;
		break;
	}
}

gboolean
hal_property_get_attribute (HalProperty *prop,
			    enum PropertyAttribute attr)
{
	g_return_val_if_fail (prop != NULL, -1);

	switch (attr) {
	case READONLY:
		return prop->readonly;
	case PERSISTENCE:
		return prop->persistence;
	case CALLOUT:
		return prop->callout;
	default:
		return -1;
	}
}

HalProperty *
hal_property_new_strlist (const char *key)
{
	HalProperty *prop;

	prop = g_new0 (HalProperty, 1);

	prop->type = HAL_PROPERTY_TYPE_STRLIST;
	prop->key = g_strdup (key);
	prop->v.strlist_value = NULL;

	return prop;
}

GSList *
hal_property_get_strlist (HalProperty *prop)
{
	g_return_val_if_fail (prop != NULL, NULL);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_STRLIST, NULL);

	return prop->v.strlist_value;
}

gboolean
hal_property_strlist_append (HalProperty *prop, const char *value)
{
	g_return_val_if_fail (prop != NULL, FALSE);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_STRLIST, FALSE);

	prop->v.strlist_value = g_slist_append (prop->v.strlist_value, g_strdup (value));

	return TRUE;
}

gboolean
hal_property_strlist_prepend (HalProperty *prop, const char *value)
{
	g_return_val_if_fail (prop != NULL, FALSE);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_STRLIST, FALSE);

	prop->v.strlist_value = g_slist_prepend (prop->v.strlist_value, g_strdup (value));

	return TRUE;
}

gboolean
hal_property_strlist_remove_elem (HalProperty *prop, guint index)
{
	GSList *elem;

	g_return_val_if_fail (prop != NULL, FALSE);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_STRLIST, FALSE);

	if (prop->v.strlist_value == NULL)
		return FALSE;

	elem = g_slist_nth (prop->v.strlist_value, index);
	if (elem == NULL)
		return FALSE;

	g_free (elem->data);
	prop->v.strlist_value = g_slist_delete_link (prop->v.strlist_value, elem);
	return TRUE;
}


gboolean
hal_property_strlist_add (HalProperty  *prop, const char *value)
{
	GSList *elem;

	g_return_val_if_fail (prop != NULL, FALSE);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_STRLIST, FALSE);

	for (elem = prop->v.strlist_value; elem != NULL; elem = g_slist_next (elem)) {
		if (strcmp (elem->data, value) == 0) {
			return FALSE;
		}
	}

	return hal_property_strlist_append (prop, value);
}

gboolean
hal_property_strlist_remove (HalProperty *prop, const char *value)
{
	guint i;
	GSList *elem;

	g_return_val_if_fail (prop != NULL, FALSE);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_STRLIST, FALSE);

	for (elem = prop->v.strlist_value, i = 0; elem != NULL; elem = g_slist_next (elem), i++) {
		if (strcmp (elem->data, value) == 0) {
			return hal_property_strlist_remove_elem (prop, i);
		}
	}

	return FALSE;
}

gboolean
hal_property_strlist_clear (HalProperty *prop)
{
	GSList *elem;

	g_return_val_if_fail (prop != NULL, FALSE);
	g_return_val_if_fail (prop->type == HAL_PROPERTY_TYPE_STRLIST, FALSE);

	for (elem = prop->v.strlist_value; elem != NULL; elem = g_slist_next (elem)) {
		g_free (elem->data);
	}
	g_slist_free (prop->v.strlist_value);

	return FALSE;
}
