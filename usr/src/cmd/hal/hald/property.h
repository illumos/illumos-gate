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

#ifndef PROPERTY_H
#define PROPERTY_H

#include <dbus/dbus.h>

typedef struct _HalProperty HalProperty;

#define HAL_PROPERTY_TYPE_INVALID         DBUS_TYPE_INVALID
#define HAL_PROPERTY_TYPE_INT32       DBUS_TYPE_INT32
#define HAL_PROPERTY_TYPE_UINT64      DBUS_TYPE_UINT64
#define HAL_PROPERTY_TYPE_DOUBLE      DBUS_TYPE_DOUBLE
#define HAL_PROPERTY_TYPE_BOOLEAN     DBUS_TYPE_BOOLEAN
#define HAL_PROPERTY_TYPE_STRING      DBUS_TYPE_STRING
#define HAL_PROPERTY_TYPE_STRLIST     ((int) (DBUS_TYPE_STRING<<8)+('l'))

enum PropertyAttribute {
	READONLY,
	PERSISTENCE,
	CALLOUT
};

void          hal_property_free               (HalProperty  *prop);

HalProperty *hal_property_new_string          (const char   *key,
					       const char   *value);
HalProperty *hal_property_new_int             (const char   *key,
					       dbus_int32_t  value);
HalProperty *hal_property_new_uint64          (const char   *key,
					       dbus_uint64_t value);
HalProperty *hal_property_new_bool            (const char   *key,
					       dbus_bool_t   value);
HalProperty *hal_property_new_double          (const char   *key,
					       double        value);
HalProperty *hal_property_new_strlist         (const char   *key);

const char   *hal_property_get_key            (HalProperty  *prop);
int           hal_property_get_type           (HalProperty  *prop);
char         *hal_property_to_string          (HalProperty  *prop);

const char   *hal_property_get_string         (HalProperty  *prop);
dbus_int32_t  hal_property_get_int            (HalProperty  *prop);
dbus_uint64_t hal_property_get_uint64         (HalProperty  *prop);
dbus_bool_t   hal_property_get_bool           (HalProperty  *prop);
double        hal_property_get_double         (HalProperty  *prop);
GSList       *hal_property_get_strlist        (HalProperty  *prop);

void          hal_property_set_string         (HalProperty  *prop,
					       const char   *value);
void          hal_property_set_int            (HalProperty  *prop,
					       dbus_int32_t  value);
void          hal_property_set_uint64         (HalProperty  *prop,
					       dbus_uint64_t value);
void          hal_property_set_bool           (HalProperty  *prop,
					       dbus_bool_t   value);
void          hal_property_set_double         (HalProperty  *prop,
					       double        value);
gboolean      hal_property_strlist_append     (HalProperty  *prop,
					       const char   *value);
gboolean      hal_property_strlist_prepend    (HalProperty  *prop,
					       const char   *value);
gboolean      hal_property_strlist_remove_elem (HalProperty  *prop,
					        guint index);

gboolean      hal_property_strlist_add        (HalProperty  *prop,
					       const char *value);
gboolean      hal_property_strlist_remove     (HalProperty  *prop,
					       const char *value);
gboolean      hal_property_strlist_clear      (HalProperty  *prop);


void          hal_property_set_attribute      (HalProperty *prop,
					       enum PropertyAttribute attr,
					       gboolean val);
gboolean      hal_property_get_attribute      (HalProperty *prop,
					       enum PropertyAttribute attr);

#endif /* PROPERTY_H */
