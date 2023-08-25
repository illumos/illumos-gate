/***************************************************************************
 * CVSID: $Id$
 *
 * libhal.c : HAL daemon C convenience library
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
 * Copyright (C) 2006 Sjoerd Simons, <sjoerd@luon.net>
 * Copyright (C) 2007 Codethink Ltd. Author Rob Taylor <rob.taylor@codethink.co.uk>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307	 USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dbus/dbus.h>

#include "libhal.h"

#ifdef ENABLE_NLS
# include <libintl.h>
# define _(String) dgettext (GETTEXT_PACKAGE, String)
# ifdef gettext_noop
#   define N_(String) gettext_noop (String)
# else
#   define N_(String) (String)
# endif
#else
/* Stubs that do something close enough.  */
# define textdomain(String) (String)
# define gettext(String) (String)
# define dgettext(Domain,Message) (Message)
# define dcgettext(Domain,Message,Type) (Message)
# define bindtextdomain(Domain,Directory) (Domain)
# define _(String)
# define N_(String) (String)
#endif

/**
 * LIBHAL_CHECK_PARAM_VALID:
 * @_param_: the prameter to check for
 * @_name_:  the name of the prameter (for debug output)
 * @_ret_:   what to use for return value if the prameter is NULL
 *
 * Handy macro for checking whether a parameter is valid and not NULL.
 */
#define LIBHAL_CHECK_PARAM_VALID(_param_,_name_,_ret_)				\
	do {									\
		if (_param_ == NULL) {						\
			fprintf (stderr,					\
				 "%s %d : invalid paramater. %s is NULL.\n",  	\
				 __FILE__, __LINE__, _name_);	 		\
			return _ret_;						\
		}								\
	} while(0)

/**
 * LIBHAL_CHECK_UDI_VALID:
 * @_udi_: the UID to check for
 * @_ret_:   what to use for return value if udi is invalid
 *
 * Handy macro for checking whether a UID is valid and not NULL.
 */
#define LIBHAL_CHECK_UDI_VALID(_udi_,_ret_)						\
	do {										\
		if (_udi_ == NULL) {							\
			fprintf (stderr,						\
				 "%s %d : invalid udi %s. udi is NULL.\n",  		\
				 __FILE__, __LINE__, _udi_);	 			\
			return _ret_;							\
		} else {								\
			if(strncmp(_udi_, "/org/freedesktop/Hal/devices/", 29) != 0) {	\
				fprintf (stderr,					\
                                 	 "%s %d : invalid udi: %s doesn't start"	\
					 "with '/org/freedesktop/Hal/devices/'. \n",    \
	                                 __FILE__, __LINE__, _udi_);			\
				return _ret_;						\
			}								\
		}									\
	} while(0)

static char **libhal_get_string_array_from_iter (DBusMessageIter *iter, int *num_elements);

static dbus_bool_t libhal_property_fill_value_from_variant (LibHalProperty *p, DBusMessageIter *var_iter);


/**
 * libhal_free_string_array:
 * @str_array: the array to be freed
 *
 * Frees a NULL-terminated array of strings. If passed NULL, does nothing.
 */
void
libhal_free_string_array (char **str_array)
{
	if (str_array != NULL) {
		int i;

		for (i = 0; str_array[i] != NULL; i++) {
			free (str_array[i]);
			str_array[i] = NULL;
		}
		free (str_array);
		str_array = NULL;
	}
}


/**
 * libhal_get_string_array_from_iter:
 * @iter: the message iterator to extract the strings from
 * @num_elements: pointer to an integer where to store number of elements (can be NULL)
 *
 * Creates a NULL terminated array of strings from a dbus message iterator.
 *
 * Returns: pointer to the string array
 */
static char **
libhal_get_string_array_from_iter (DBusMessageIter *iter, int *num_elements)
{
	int count;
	char **buffer;
	char **t;

	count = 0;
	buffer = (char **)malloc (sizeof (char *) * 8);

	if (buffer == NULL)
		goto oom;

	buffer[0] = NULL;
	while (dbus_message_iter_get_arg_type (iter) == DBUS_TYPE_STRING) {
		const char *value;
		char *str;

		if ((count % 8) == 0 && count != 0) {
			t = realloc (buffer, sizeof (char *) * (count + 8));
			if (t == NULL)
				goto oom;
			else
				buffer = t;
		}

		dbus_message_iter_get_basic (iter, &value);
		str = strdup (value);
		if (str == NULL)
			goto oom;

		buffer[count] = str;

		dbus_message_iter_next(iter);
		count++;
	}

	if ((count % 8) == 0) {
		t = realloc (buffer, sizeof (char *) * (count + 1));
		if (t == NULL)
			goto oom;
		else
			buffer = t;
	}

	buffer[count] = NULL;
	if (num_elements != NULL)
		*num_elements = count;
	return buffer;

oom:
	if (buffer != NULL)
		free (buffer);
	fprintf (stderr, "%s %d : error allocating memory\n", __FILE__, __LINE__);
	return NULL;

}

/**
 * libhal_free_string:
 * @str: the nul-terminated sting to free
 *
 * Used to free strings returned by libhal.
 */
void
libhal_free_string (char *str)
{
	if (str != NULL) {
		free (str);
		str = NULL;
	}
}


/**
 * LibHalPropertySet:
 *
 * Represents a set of properties. Opaque; use the
 * libhal_property_set_*() family of functions to access it.
 */
struct LibHalPropertySet_s {
	unsigned int num_properties; /**< Number of properties in set */
	LibHalProperty *properties_head;
				     /**< Pointer to first property or NULL
				      *	  if there are no properties */
};

/**
 * LibHalProperty:
 *
 * Represents a property. Opaque.
 */
struct LibHalProperty_s {
	LibHalPropertyType type;	     	/**< Type of property */
	char *key;		     		/**< ASCII string */

	/** Possible values of the property */
	union {
		char *str_value;     /**< UTF-8 zero-terminated string */
		dbus_int32_t int_value;
				     /**< 32-bit signed integer */
		dbus_uint64_t uint64_value;
				     /**< 64-bit unsigned integer */
		double double_value; /**< IEEE754 double precision float */
		dbus_bool_t bool_value;
				     /**< Truth value */

		char **strlist_value; /**< List of UTF-8 zero-terminated strings */
	} v;

	LibHalProperty *next;	     /**< Next property or NULL if this is
				      *	  the last */
};

/**
 * LibHalContext:
 *
 * Context for connection to the HAL daemon. Opaque, use the
 * libhal_ctx_*() family of functions to access it.
 */
struct LibHalContext_s {
	DBusConnection *connection;           /**< D-BUS connection */
	dbus_bool_t is_initialized;           /**< Are we initialised */
	dbus_bool_t is_shutdown;              /**< Have we been shutdown */
	dbus_bool_t cache_enabled;            /**< Is the cache enabled */
	dbus_bool_t is_direct;                /**< Whether the connection to hald is direct */

	/** Device added */
	LibHalDeviceAdded device_added;

	/** Device removed */
	LibHalDeviceRemoved device_removed;

	/** Device got a new capability */
	LibHalDeviceNewCapability device_new_capability;

	/** Device got a new capability */
	LibHalDeviceLostCapability device_lost_capability;

	/** A property of a device changed  */
	LibHalDevicePropertyModified device_property_modified;

	/** A non-continous event on the device occured  */
	LibHalDeviceCondition device_condition;

	void *user_data;                      /**< User data */
};

/**
 * libhal_ctx_set_user_data:
 * @ctx: the context for the connection to hald
 * @user_data: user data
 *
 * Set user data for the context.
 *
 * Returns: TRUE if user data was successfully set, FALSE if otherwise
 */
dbus_bool_t
libhal_ctx_set_user_data(LibHalContext *ctx, void *user_data)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	ctx->user_data = user_data;
	return TRUE;
}

/**
 * libhal_ctx_get_user_data:
 * @ctx: the context for the connection to hald
 *
 * Get user data for the context.
 *
 * Returns: opaque pointer stored through libhal_ctx_set_user_data() or NULL if not set.
 */
void*
libhal_ctx_get_user_data(LibHalContext *ctx)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);
	return ctx->user_data;
}


/**
 * libhal_property_fill_value_from_variant:
 * @p: the property to fill in
 * @var_iter: variant iterator to extract the value from
 *
 * Fills in the value for the LibHalProperty given a variant iterator.
 *
 * Returns: Whether the value was put in.
 */
static dbus_bool_t
libhal_property_fill_value_from_variant (LibHalProperty *p, DBusMessageIter *var_iter)
{
	DBusMessageIter iter_array;

	LIBHAL_CHECK_PARAM_VALID(p, "LibHalProperty *p", FALSE);
	LIBHAL_CHECK_PARAM_VALID(var_iter, "DBusMessageIter *var_iter", FALSE);

	switch (p->type) {
	case DBUS_TYPE_ARRAY:
		if (dbus_message_iter_get_element_type (var_iter) != DBUS_TYPE_STRING)
			return FALSE;

		dbus_message_iter_recurse (var_iter, &iter_array);
		p->v.strlist_value = libhal_get_string_array_from_iter (&iter_array, NULL);

		p->type = LIBHAL_PROPERTY_TYPE_STRLIST;

		break;
	case DBUS_TYPE_STRING:
	{
		const char *v;

		dbus_message_iter_get_basic (var_iter, &v);

		p->v.str_value = strdup (v);
		if (p->v.str_value == NULL)
			return FALSE;
		p->type = LIBHAL_PROPERTY_TYPE_STRING;

		break;
	}
	case DBUS_TYPE_INT32:
	{
		dbus_int32_t v;

		dbus_message_iter_get_basic (var_iter, &v);

		p->v.int_value = v;
		p->type = LIBHAL_PROPERTY_TYPE_INT32;

		break;
	}
	case DBUS_TYPE_UINT64:
	{
		dbus_uint64_t v;

		dbus_message_iter_get_basic (var_iter, &v);

		p->v.uint64_value = v;
		p->type = LIBHAL_PROPERTY_TYPE_UINT64;

		break;
	}
	case DBUS_TYPE_DOUBLE:
	{
		double v;

		dbus_message_iter_get_basic (var_iter, &v);

		p->v.double_value = v;
		p->type = LIBHAL_PROPERTY_TYPE_DOUBLE;

		break;
	}
	case DBUS_TYPE_BOOLEAN:
	{
		double v;

		dbus_message_iter_get_basic (var_iter, &v);

		p->v.double_value = v;
		p->type = LIBHAL_PROPERTY_TYPE_BOOLEAN;

		break;
	}
	default:
		/** @todo  report error */
		break;
	}

	return TRUE;
}

/**
 * libhal_device_get_all_properties:
 * @ctx: the context for the connection to hald
 * @udi: the Unique id of device
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Retrieve all the properties on a device.
 *
 * Returns: An object represent all properties. Must be freed with libhal_free_property_set().
 */
LibHalPropertySet *
libhal_device_get_all_properties (LibHalContext *ctx, const char *udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	DBusMessageIter dict_iter;
	LibHalPropertySet *result;
	LibHalProperty *p_last;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);
	LIBHAL_CHECK_UDI_VALID(udi, NULL);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"GetAllProperties");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return NULL;
	}

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		fprintf (stderr,
			 "%s %d : %s\n",
			 __FILE__, __LINE__, error->message);

		dbus_message_unref (message);
		return NULL;
	}

	if (reply == NULL) {
		dbus_message_unref (message);
		return NULL;
	}

	dbus_message_iter_init (reply, &reply_iter);

	result = malloc (sizeof (LibHalPropertySet));
	if (result == NULL)
		goto oom;

/*
    result->properties = malloc(sizeof(LibHalProperty)*result->num_properties);
    if( result->properties==NULL )
    {
    /// @todo  cleanup
	return NULL;
    }
*/

	result->properties_head = NULL;
	result->num_properties = 0;

	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_ARRAY  &&
	    dbus_message_iter_get_element_type (&reply_iter) != DBUS_TYPE_DICT_ENTRY) {
		fprintf (stderr, "%s %d : error, expecting an array of dict entries\n",
			 __FILE__, __LINE__);
		dbus_message_unref (message);
		dbus_message_unref (reply);
		return NULL;
	}

	dbus_message_iter_recurse (&reply_iter, &dict_iter);

	p_last = NULL;

	while (dbus_message_iter_get_arg_type (&dict_iter) == DBUS_TYPE_DICT_ENTRY)
	{
		DBusMessageIter dict_entry_iter, var_iter;
		const char *key;
		LibHalProperty *p;

		dbus_message_iter_recurse (&dict_iter, &dict_entry_iter);

		dbus_message_iter_get_basic (&dict_entry_iter, &key);

		p = malloc (sizeof (LibHalProperty));
		if (p == NULL)
			goto oom;

		p->next = NULL;

		if (result->num_properties == 0)
			result->properties_head = p;

		if (p_last != NULL)
			p_last->next = p;

		p_last = p;

		p->key = strdup (key);
		if (p->key == NULL)
			goto oom;

		dbus_message_iter_next (&dict_entry_iter);

		dbus_message_iter_recurse (&dict_entry_iter, &var_iter);


		p->type = dbus_message_iter_get_arg_type (&var_iter);

		result->num_properties++;

		if(!libhal_property_fill_value_from_variant (p, &var_iter))
			goto oom;

		dbus_message_iter_next (&dict_iter);
	}

	dbus_message_unref (message);
	dbus_message_unref (reply);

	return result;

oom:
	fprintf (stderr,
		"%s %d : error allocating memory\n",
		 __FILE__, __LINE__);
		/** @todo FIXME cleanup */
	return NULL;
}

/**
 * libhal_free_property_set:
 * @set: property-set to free
 *
 * Free a property set earlier obtained with libhal_device_get_all_properties().
 */
void
libhal_free_property_set (LibHalPropertySet * set)
{
	LibHalProperty *p;
	LibHalProperty *q;

	if (set == NULL)
		return;

	for (p = set->properties_head; p != NULL; p = q) {
		free (p->key);
		if (p->type == DBUS_TYPE_STRING)
			free (p->v.str_value);
		if (p->type == LIBHAL_PROPERTY_TYPE_STRLIST)
			libhal_free_string_array (p->v.strlist_value);
		q = p->next;
		free (p);
	}
	free (set);
}

/**
 * libhal_property_set_get_num_elems:
 * @set: property set to consider
 *
 * Get the number of properties in a property set.
 *
 * Returns: number of properties in given property set
 */
unsigned int
libhal_property_set_get_num_elems (LibHalPropertySet *set)
{
	unsigned int num_elems;
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", 0);

	num_elems = 0;
	for (p = set->properties_head; p != NULL; p = p->next)
		num_elems++;

	return num_elems;
}

static LibHalProperty *
property_set_lookup (const LibHalPropertySet *set, const char *key)
{
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", NULL);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", NULL);

	for (p = set->properties_head; p != NULL; p = p->next)
		if (strcmp (key, p->key) == 0)
			return p;

	return NULL;
}

/**
 * libhal_ps_get_type:
 * @set: property set
 * @key: name of property to inspect
 *
 * Get the type of a given property.
 *
 * Returns: the #LibHalPropertyType of the given property,
 * LIBHAL_PROPERTY_TYPE_INVALID if property is not in the set
 */
LibHalPropertyType
libhal_ps_get_type (const LibHalPropertySet *set, const char *key)
{
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", LIBHAL_PROPERTY_TYPE_INVALID);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", LIBHAL_PROPERTY_TYPE_INVALID);

	p = property_set_lookup (set, key);
	if (p) return p->type;
	else return LIBHAL_PROPERTY_TYPE_INVALID;
}

/**
 * libhal_ps_get_string:
 * @set: property set
 * @key: name of property to inspect
 *
 * Get the value of a property of type string.
 *
 * Returns: UTF8 nul-terminated string. This pointer is only valid
 * until libhal_free_property_set() is invoked on the property set
 * this property belongs to. NULL if property is not in the set or not a string
 */
const char *
libhal_ps_get_string  (const LibHalPropertySet *set, const char *key)
{
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", NULL);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", NULL);

	p = property_set_lookup (set, key);
	if (p && p->type == LIBHAL_PROPERTY_TYPE_STRING)
		return p->v.str_value;
	else return NULL;
}

/**
 * libhal_ps_get_int:
 * @set: property set
 * @key: name of property to inspect
 *
 * Get the value of a property of type signed integer.
 *
 * Returns: property value (32-bit signed integer)
 */
dbus_int32_t
libhal_ps_get_int32 (const LibHalPropertySet *set, const char *key)
{
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", 0);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", 0);

	p = property_set_lookup (set, key);
	if (p && p->type == LIBHAL_PROPERTY_TYPE_INT32)
		return p->v.int_value;
	else return 0;
}

/**
 * libhal_ps_get_uint64:
 * @set: property set
 * @key: name of property to inspect
 *
 * Get the value of a property of type unsigned integer.
 *
 * Returns: property value (64-bit unsigned integer)
 */
dbus_uint64_t
libhal_ps_get_uint64 (const LibHalPropertySet *set, const char *key)
{
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", 0);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", 0);

	p = property_set_lookup (set, key);
	if (p && p->type == LIBHAL_PROPERTY_TYPE_UINT64)
		return p->v.uint64_value;
	else return 0;
}

/**
 * libhal_ps_get_double:
 * @set: property set
 * @key: name of property to inspect
 *
 * Get the value of a property of type double.
 *
 * Returns: property value (IEEE754 double precision float)
 */
double
libhal_ps_get_double (const LibHalPropertySet *set, const char *key)
{
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", 0.0);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", 0.0);

	p = property_set_lookup (set, key);
	if (p && p->type == LIBHAL_PROPERTY_TYPE_DOUBLE)
		return p->v.double_value;
	else return 0.0;
}

/**
 * libhal_ps_get_bool:
 * @set: property set
 * @key: name of property to inspect
 *
 * Get the value of a property of type bool.
 *
 * Returns: property value (bool)
 */
dbus_bool_t
libhal_ps_get_bool (const LibHalPropertySet *set, const char *key)
{
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	p = property_set_lookup (set, key);
	if (p && p->type == LIBHAL_PROPERTY_TYPE_BOOLEAN)
		return p->v.bool_value;
	else return FALSE;
}

/**
 * libhal_ps_get_strlist:
 * @set: property set
 * @key: name of property to inspect
 *
 * Get the value of a property of type string list.
 *
 * Returns: pointer to array of strings, this is owned by the property set
 */
const char *const *
libhal_ps_get_strlist (const LibHalPropertySet *set, const char *key)
{
	LibHalProperty *p;

	LIBHAL_CHECK_PARAM_VALID(set, "*set", NULL);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", NULL);

	p = property_set_lookup (set, key);
	if (p && p->type == LIBHAL_PROPERTY_TYPE_STRLIST)
		return (const char *const *) p->v.strlist_value;
	else return NULL;
}


/**
 * libhal_psi_init:
 * @iter: iterator object
 * @set: property set to iterate over
 *
 * Initialize a property set iterator.
 *
 */
void
libhal_psi_init (LibHalPropertySetIterator * iter, LibHalPropertySet * set)
{
	if (set == NULL)
		return;

	iter->set = set;
	iter->idx = 0;
	iter->cur_prop = set->properties_head;
}


/**
 * libhal_psi_has_more:
 * @iter: iterator object
 *
 * Determine whether there are more properties to iterate over.
 *
 * Returns: TRUE if there are more properties, FALSE otherwise.
 */
dbus_bool_t
libhal_psi_has_more (LibHalPropertySetIterator * iter)
{
	return iter->idx < iter->set->num_properties;
}

/**
 * libhal_psi_next:
 * @iter: iterator object
 *
 * Advance iterator to next property.
 */
void
libhal_psi_next (LibHalPropertySetIterator * iter)
{
	iter->idx++;
	iter->cur_prop = iter->cur_prop->next;
}

/**
 * libhal_psi_get_type:
 * @iter: iterator object
 *
 * Get type of property.
 *
 * Returns: the property type at the iterator's position
 */
LibHalPropertyType
libhal_psi_get_type (LibHalPropertySetIterator * iter)
{
	return iter->cur_prop->type;
}

/**
 * libhal_psi_get_key:
 * @iter: iterator object
 *
 * Get the key of a property.
 *
 * Returns: ASCII nul-terminated string. This pointer is only valid
 * until libhal_free_property_set() is invoked on the property set
 * this property belongs to.
 */
char *
libhal_psi_get_key (LibHalPropertySetIterator * iter)
{
	return iter->cur_prop->key;
}

/**
 * libhal_psi_get_string:
 * @iter: iterator object
 *
 * Get the value of a property of type string.
 *
 * Returns: UTF8 nul-terminated string. This pointer is only valid
 * until libhal_free_property_set() is invoked on the property set
 * this property belongs to.
 */
char *
libhal_psi_get_string (LibHalPropertySetIterator * iter)
{
	return iter->cur_prop->v.str_value;
}

/**
 * libhal_psi_get_int:
 * @iter: iterator object
 *
 * Get the value of a property of type signed integer.
 *
 * Returns: property value (32-bit signed integer)
 */
dbus_int32_t
libhal_psi_get_int (LibHalPropertySetIterator * iter)
{
	return iter->cur_prop->v.int_value;
}

/**
 * libhal_psi_get_uint64:
 * @iter: iterator object
 *
 * Get the value of a property of type unsigned integer.
 *
 * Returns: property value (64-bit unsigned integer)
 */
dbus_uint64_t
libhal_psi_get_uint64 (LibHalPropertySetIterator * iter)
{
	return iter->cur_prop->v.uint64_value;
}

/**
 * libhal_psi_get_double:
 * @iter: iterator object
 *
 * Get the value of a property of type double.
 *
 * Returns: property value (IEEE754 double precision float)
 */
double
libhal_psi_get_double (LibHalPropertySetIterator * iter)
{
	return iter->cur_prop->v.double_value;
}

/**
 * libhal_psi_get_bool:
 * @iter: iterator object
 *
 * Get the value of a property of type bool.
 *
 * Returns: property value (bool)
 */
dbus_bool_t
libhal_psi_get_bool (LibHalPropertySetIterator * iter)
{
	return iter->cur_prop->v.bool_value;
}

/**
 * libhal_psi_get_strlist:
 * @iter: iterator object
 *
 * Get the value of a property of type string list.
 *
 * Returns: pointer to array of strings
 */
char **
libhal_psi_get_strlist (LibHalPropertySetIterator * iter)
{
	return iter->cur_prop->v.strlist_value;
}


static DBusHandlerResult
filter_func (DBusConnection * connection,
	     DBusMessage * message, void *user_data)
{
	const char *object_path;
	DBusError error;
	LibHalContext *ctx = (LibHalContext *) user_data;

	if (ctx->is_shutdown)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_error_init (&error);

	object_path = dbus_message_get_path (message);

	/*fprintf (stderr, "*** libhal filer_func: connection=%p obj_path=%s interface=%s method=%s\n",
		   connection,
		   dbus_message_get_path (message),
		   dbus_message_get_interface (message),
		   dbus_message_get_member (message));
        */

	if (dbus_message_is_signal (message, "org.freedesktop.Hal.Manager",
				    "DeviceAdded")) {
		char *udi;
		if (dbus_message_get_args (message, &error,
					   DBUS_TYPE_STRING, &udi,
					   DBUS_TYPE_INVALID)) {
			if (ctx->device_added != NULL) {
				ctx->device_added (ctx, udi);
			}
		} else {
			LIBHAL_FREE_DBUS_ERROR(&error);
		}
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else if (dbus_message_is_signal (message, "org.freedesktop.Hal.Manager", "DeviceRemoved")) {
		char *udi;
		if (dbus_message_get_args (message, &error,
					   DBUS_TYPE_STRING, &udi,
					   DBUS_TYPE_INVALID)) {
			if (ctx->device_removed != NULL) {
				ctx->device_removed (ctx, udi);
			}
		} else {
			LIBHAL_FREE_DBUS_ERROR(&error);
		}
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else if (dbus_message_is_signal (message, "org.freedesktop.Hal.Manager","NewCapability")) {
		char *udi;
		char *capability;
		if (dbus_message_get_args (message, &error,
					   DBUS_TYPE_STRING, &udi,
					   DBUS_TYPE_STRING, &capability,
					   DBUS_TYPE_INVALID)) {
			if (ctx->device_new_capability != NULL) {
				ctx->device_new_capability (ctx, udi, capability);
			}
		} else {
			LIBHAL_FREE_DBUS_ERROR(&error);
		}
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else if (dbus_message_is_signal (message, "org.freedesktop.Hal.Device", "Condition")) {
		char *condition_name;
		char *condition_detail;
		if (dbus_message_get_args (message, &error,
					   DBUS_TYPE_STRING, &condition_name,
					   DBUS_TYPE_STRING, &condition_detail,
					   DBUS_TYPE_INVALID)) {
			if (ctx->device_condition != NULL) {
				ctx->device_condition (ctx, object_path, condition_name, condition_detail);
			}
		} else {
			LIBHAL_FREE_DBUS_ERROR(&error);
		}
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else if (dbus_message_is_signal (message, "org.freedesktop.Hal.Device", "PropertyModified")) {
		if (ctx->device_property_modified != NULL) {
			int i;
			char *key;
			dbus_bool_t removed;
			dbus_bool_t added;
			int num_modifications;
			DBusMessageIter iter;
			DBusMessageIter iter_array;

			dbus_message_iter_init (message, &iter);
			dbus_message_iter_get_basic (&iter, &num_modifications);
			dbus_message_iter_next (&iter);

			dbus_message_iter_recurse (&iter, &iter_array);

			for (i = 0; i < num_modifications; i++) {
				DBusMessageIter iter_struct;

				dbus_message_iter_recurse (&iter_array, &iter_struct);

				dbus_message_iter_get_basic (&iter_struct, &key);
				dbus_message_iter_next (&iter_struct);
				dbus_message_iter_get_basic (&iter_struct, &removed);
				dbus_message_iter_next (&iter_struct);
				dbus_message_iter_get_basic (&iter_struct, &added);

				ctx->device_property_modified (ctx,
							       object_path,
							       key, removed,
							       added);

				dbus_message_iter_next (&iter_array);
			}

		}
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* for i18n purposes */
static dbus_bool_t libhal_already_initialized_once = FALSE;


/**
 * libhal_get_all_devices:
 * @ctx: the context for the connection to hald
 * @num_devices: the number of devices will be stored here
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Get all devices in the Global Device List (GDL).
 *
 * Returns: An array of device identifiers terminated with NULL. It is
 * the responsibility of the caller to free with
 * libhal_free_string_array(). If an error occurs NULL is returned.
 */
char **
libhal_get_all_devices (LibHalContext *ctx, int *num_devices, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter_array, reply_iter;
	char **hal_device_names;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);

	*num_devices = 0;

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"GetAllDevices");
	if (message == NULL) {
		fprintf (stderr, "%s %d : Could not allocate D-BUS message\n", __FILE__, __LINE__);
		return NULL;
	}

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection, message, -1, &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return NULL;
	}
	if (reply == NULL) {
		return NULL;
	}

	/* now analyze reply */
	dbus_message_iter_init (reply, &reply_iter);

	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_ARRAY) {
		fprintf (stderr, "%s %d : wrong reply from hald.  Expecting an array.\n", __FILE__, __LINE__);
		dbus_message_unref (reply);
		return NULL;
	}

	dbus_message_iter_recurse (&reply_iter, &iter_array);

	hal_device_names = libhal_get_string_array_from_iter (&iter_array, num_devices);

	dbus_message_unref (reply);
	return hal_device_names;
}

/**
 * libhal_device_get_property_type:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Query a property type of a device.
 *
 * Returns: A LibHalPropertyType. LIBHAL_PROPERTY_TYPE_INVALID is
 * return if the property doesn't exist.
 */
LibHalPropertyType
libhal_device_get_property_type (LibHalContext *ctx, const char *udi, const char *key, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	LibHalPropertyType type;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, LIBHAL_PROPERTY_TYPE_INVALID); /* or return NULL? */
	LIBHAL_CHECK_UDI_VALID(udi, LIBHAL_PROPERTY_TYPE_INVALID);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", LIBHAL_PROPERTY_TYPE_INVALID);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"GetPropertyType");
	if (message == NULL) {
		fprintf (stderr, "%s %d : Couldn't allocate D-BUS message\n", __FILE__, __LINE__);
		return LIBHAL_PROPERTY_TYPE_INVALID;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return LIBHAL_PROPERTY_TYPE_INVALID;
	}
	if (reply == NULL) {
		return LIBHAL_PROPERTY_TYPE_INVALID;
	}

	dbus_message_iter_init (reply, &reply_iter);
	dbus_message_iter_get_basic (&reply_iter, &type);

	dbus_message_unref (reply);
	return type;
}

/**
 * libhal_device_get_property_strlist:
 * @ctx: the context for the connection to hald
 * @udi: unique Device Id
 * @key: name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Get the value of a property of type string list.
 *
 * Returns: Array of pointers to UTF8 nul-terminated strings
 * terminated by NULL. The caller is responsible for freeing this
 * string array with the function libhal_free_string_array(). Returns
 * NULL if the property didn't exist or we are OOM
 */
char **
libhal_device_get_property_strlist (LibHalContext *ctx, const char *udi, const char *key, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, iter_array, reply_iter;
	char **our_strings;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);
	LIBHAL_CHECK_UDI_VALID(udi, NULL);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", NULL);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"GetPropertyStringList");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return NULL;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return NULL;
	}
	if (reply == NULL) {
		return NULL;
	}
	/* now analyse reply */
	dbus_message_iter_init (reply, &reply_iter);

	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_ARRAY) {
		fprintf (stderr, "%s %d : wrong reply from hald.  Expecting an array.\n", __FILE__, __LINE__);
		dbus_message_unref (reply);
		return NULL;
	}

	dbus_message_iter_recurse (&reply_iter, &iter_array);

	our_strings = libhal_get_string_array_from_iter (&iter_array, NULL);

	dbus_message_unref (reply);
	return our_strings;
}

/**
 * libhal_device_get_property_string:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: the name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Get the value of a property of type string.
 *
 * Returns: UTF8 nul-terminated string. The caller is responsible for
 * freeing this string with the function libhal_free_string(). Returns
 * NULL if the property didn't exist or we are OOM.
 */
char *
libhal_device_get_property_string (LibHalContext *ctx,
				   const char *udi, const char *key, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	char *value;
	char *dbus_str;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);
	LIBHAL_CHECK_UDI_VALID(udi, NULL);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", NULL);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"GetPropertyString");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return NULL;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return NULL;
	}
	if (reply == NULL) {
		return NULL;
	}

	dbus_message_iter_init (reply, &reply_iter);

	/* now analyze reply */
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_STRING) {
		dbus_message_unref (reply);
		return NULL;
	}

	dbus_message_iter_get_basic (&reply_iter, &dbus_str);
	value = (char *) ((dbus_str != NULL) ? strdup (dbus_str) : NULL);
	if (value == NULL) {
		fprintf (stderr, "%s %d : error allocating memory\n",
			 __FILE__, __LINE__);
	}

	dbus_message_unref (reply);
	return value;
}

/**
 * libhal_device_get_property_int:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Get the value of a property of type integer.
 *
 * Returns: Property value (32-bit signed integer)
 */
dbus_int32_t
libhal_device_get_property_int (LibHalContext *ctx,
				const char *udi, const char *key, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	dbus_int32_t value;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, -1);
	LIBHAL_CHECK_UDI_VALID(udi, -1);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", -1);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"GetPropertyInteger");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return -1;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return -1;
	}
	if (reply == NULL) {
		return -1;
	}

	dbus_message_iter_init (reply, &reply_iter);

	/* now analyze reply */
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_INT32) {
		fprintf (stderr,
			 "%s %d : property '%s' for device '%s' is not "
			 "of type integer\n", __FILE__, __LINE__, key,
			 udi);
		dbus_message_unref (reply);
		return -1;
	}
	dbus_message_iter_get_basic (&reply_iter, &value);

	dbus_message_unref (reply);
	return value;
}

/**
 * libhal_device_get_property_uint64:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Get the value of a property of type signed integer.
 *
 * Returns: Property value (64-bit unsigned integer)
 */
dbus_uint64_t
libhal_device_get_property_uint64 (LibHalContext *ctx,
				   const char *udi, const char *key, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	dbus_uint64_t value;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, -1);
	LIBHAL_CHECK_UDI_VALID(udi, -1);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", -1);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"GetPropertyInteger");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return -1;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return -1;
	}
	if (reply == NULL) {
		return -1;
	}

	dbus_message_iter_init (reply, &reply_iter);
	/* now analyze reply */
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_UINT64) {
		fprintf (stderr,
			 "%s %d : property '%s' for device '%s' is not "
			 "of type integer\n", __FILE__, __LINE__, key,
			 udi);
		dbus_message_unref (reply);
		return -1;
	}
	dbus_message_iter_get_basic (&reply_iter, &value);

	dbus_message_unref (reply);
	return value;
}

/**
 * libhal_device_get_property_double:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Get the value of a property of type double.
 *
 * Returns: Property value (IEEE754 double precision float)
 */
double
libhal_device_get_property_double (LibHalContext *ctx,
				   const char *udi, const char *key, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	double value;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, -1.0);
	LIBHAL_CHECK_UDI_VALID(udi, -1.0);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", -1.0);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"GetPropertyDouble");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return -1.0f;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return -1.0f;
	}
	if (reply == NULL) {
		return -1.0f;
	}

	dbus_message_iter_init (reply, &reply_iter);

	/* now analyze reply */
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_DOUBLE) {
		fprintf (stderr,
			 "%s %d : property '%s' for device '%s' is not "
			 "of type double\n", __FILE__, __LINE__, key, udi);
		dbus_message_unref (reply);
		return -1.0f;
	}
	dbus_message_iter_get_basic (&reply_iter, &value);

	dbus_message_unref (reply);
	return (double) value;
}

/**
 * libhal_device_get_property_bool:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Get the value of a property of type bool.
 *
 * Returns: Property value (boolean)
 */
dbus_bool_t
libhal_device_get_property_bool (LibHalContext *ctx,
				 const char *udi, const char *key, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	dbus_bool_t value;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"GetPropertyBoolean");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_iter_init (reply, &reply_iter);

	/* now analyze reply */
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_BOOLEAN) {
		fprintf (stderr,
			 "%s %d : property '%s' for device '%s' is not "
			 "of type bool\n", __FILE__, __LINE__, key, udi);
		dbus_message_unref (reply);
		return FALSE;
	}
	dbus_message_iter_get_basic (&reply_iter, &value);

	dbus_message_unref (reply);
	return value;
}


/* generic helper */
static dbus_bool_t
libhal_device_set_property_helper (LibHalContext *ctx,
				   const char *udi,
				   const char *key,
				   int type,
				   const char *str_value,
				   dbus_int32_t int_value,
				   dbus_uint64_t uint64_value,
				   double double_value,
				   dbus_bool_t bool_value,
				   DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;
	char *method_name = NULL;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	/** @todo  sanity check incoming params */
	switch (type) {
	case DBUS_TYPE_INVALID:
		method_name = "RemoveProperty";
		break;
	case DBUS_TYPE_STRING:
		method_name = "SetPropertyString";
		break;
	case DBUS_TYPE_INT32:
	case DBUS_TYPE_UINT64:
		method_name = "SetPropertyInteger";
		break;
	case DBUS_TYPE_DOUBLE:
		method_name = "SetPropertyDouble";
		break;
	case DBUS_TYPE_BOOLEAN:
		method_name = "SetPropertyBoolean";
		break;

	default:
		/* cannot happen; is not callable from outside this file */
		break;
	}

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						method_name);
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);
	switch (type) {
	case DBUS_TYPE_STRING:
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &str_value);
		break;
	case DBUS_TYPE_INT32:
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &int_value);
		break;
	case DBUS_TYPE_UINT64:
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_UINT64, &uint64_value);
		break;
	case DBUS_TYPE_DOUBLE:
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_DOUBLE, &double_value);
		break;
	case DBUS_TYPE_BOOLEAN:
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_BOOLEAN, &bool_value);
		break;
	}


	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);

	return TRUE;
}

/**
 * libhal_device_set_property_string:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @value: value of the property; a UTF8 string
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Set a property of type string.
 *
 * Returns: TRUE if the property was set, FALSE if the device didn't
 * exist or the property had a different type.
 */
dbus_bool_t
libhal_device_set_property_string (LibHalContext *ctx,
				   const char *udi,
				   const char *key,
				   const char *value,
				   DBusError *error)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);
	LIBHAL_CHECK_PARAM_VALID(value, "*value", FALSE);

	return libhal_device_set_property_helper (ctx, udi, key,
						  DBUS_TYPE_STRING,
						  value, 0, 0, 0.0f, FALSE, error);
}

/**
 * libhal_device_set_property_int:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @value: value of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Set a property of type signed integer.
 *
 * Returns: TRUE if the property was set, FALSE if the device didn't
 * exist or the property had a different type.
 */
dbus_bool_t
libhal_device_set_property_int (LibHalContext *ctx, const char *udi,
				const char *key, dbus_int32_t value, DBusError *error)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	return libhal_device_set_property_helper (ctx, udi, key,
						  DBUS_TYPE_INT32,
						  NULL, value, 0, 0.0f, FALSE, error);
}

/**
 * libhal_device_set_property_uint64:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @value: value of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Set a property of type unsigned integer.
 *
 * Returns: TRUE if the property was set, FALSE if the device didn't
 * exist or the property had a different type.
 */
dbus_bool_t
libhal_device_set_property_uint64 (LibHalContext *ctx, const char *udi,
				   const char *key, dbus_uint64_t value, DBusError *error)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	return libhal_device_set_property_helper (ctx, udi, key,
						  DBUS_TYPE_UINT64,
						  NULL, 0, value, 0.0f, FALSE, error);
}

/**
 * libhal_device_set_property_double:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @value: value of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Set a property of type double.
 *
 * Returns: TRUE if the property was set, FALSE if the device didn't
 * exist or the property had a different type.
 */
dbus_bool_t
libhal_device_set_property_double (LibHalContext *ctx, const char *udi,
				   const char *key, double value, DBusError *error)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	return libhal_device_set_property_helper (ctx, udi, key,
						  DBUS_TYPE_DOUBLE,
						  NULL, 0, 0, value, FALSE, error);
}

/**
 * libhal_device_set_property_bool:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @value: value of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Set a property of type bool.
 *
 * Returns: TRUE if the property was set, FALSE if the device didn't
 * exist or the property had a different type.
 */
dbus_bool_t
libhal_device_set_property_bool (LibHalContext *ctx, const char *udi,
				 const char *key, dbus_bool_t value, DBusError *error)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	return libhal_device_set_property_helper (ctx, udi, key,
						  DBUS_TYPE_BOOLEAN,
						  NULL, 0, 0, 0.0f, value, error);
}


/**
 * libhal_device_remove_property:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Remove a property.
 *
 * Returns: TRUE if the property was set, FALSE if the device didn't
 * exist
 */
dbus_bool_t
libhal_device_remove_property (LibHalContext *ctx,
			       const char *udi, const char *key, DBusError *error)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	return libhal_device_set_property_helper (ctx, udi, key, DBUS_TYPE_INVALID,
						  /* DBUS_TYPE_INVALID means remove */
						  NULL, 0, 0, 0.0f, FALSE, error);
}

/**
 * libhal_device_property_strlist_append:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @value: value to append to property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Append to a property of type strlist.
 *
 * Returns: TRUE if the value was appended, FALSE if the device didn't
 * exist or the property had a different type.
 */
dbus_bool_t
libhal_device_property_strlist_append (LibHalContext *ctx,
				       const char *udi,
				       const char *key,
				       const char *value,
				       DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);
	LIBHAL_CHECK_PARAM_VALID(value, "*value", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"StringListAppend");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &value);

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}

/**
 * libhal_device_property_strlist_prepend:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @value: value to prepend to property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Prepend to a property of type strlist.
 *
 * Returns: TRUE if the value was prepended, FALSE if the device
 * didn't exist or the property had a different type.
 */
dbus_bool_t
libhal_device_property_strlist_prepend (LibHalContext *ctx,
					const char *udi,
					const char *key,
					const char *value,
					DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);
	LIBHAL_CHECK_PARAM_VALID(value, "*value", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"StringListPrepend");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &value);

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}

/**
 * libhal_device_property_strlist_remove_index:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @idx: index of string to remove in the strlist
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Remove a specified string from a property of type strlist.
 *
 * Returns: TRUE if the string was removed, FALSE if the device didn't
 * exist or the property had a different type.
 */
dbus_bool_t
libhal_device_property_strlist_remove_index (LibHalContext *ctx,
					     const char *udi,
					     const char *key,
					     unsigned int idx,
					     DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"StringListRemoveIndex");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_UINT32, &idx);

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}

/**
 * libhal_device_property_strlist_remove:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property
 * @value: the string to remove
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Remove a specified string from a property of type strlist.
 *
 * Returns: TRUE if the string was removed, FALSE if the device didn't
 * exist or the property had a different type.
 */
dbus_bool_t
libhal_device_property_strlist_remove (LibHalContext *ctx,
				       const char *udi,
				       const char *key,
				       const char *value, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);
	LIBHAL_CHECK_PARAM_VALID(value, "*value", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"StringListRemove");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}
	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &value);

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}


/**
 * libhal_device_lock:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @reason_to_lock: a user-presentable reason why the device is locked.
 * @reason_why_locked: a pointer to store the reason why the device cannot be locked on failure, or NULL
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Take an advisory lock on the device.
 *
 * Returns: TRUE if the lock was obtained, FALSE otherwise
 */
dbus_bool_t
libhal_device_lock (LibHalContext *ctx,
		    const char *udi,
		    const char *reason_to_lock,
		    char **reason_why_locked, DBusError *error)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusMessage *reply;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	if (reason_why_locked != NULL)
		*reason_why_locked = NULL;

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						udi,
						"org.freedesktop.Hal.Device",
						"Lock");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &reason_to_lock);


	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		if (strcmp (error->name,
			    "org.freedesktop.Hal.DeviceAlreadyLocked") == 0) {
			if (reason_why_locked != NULL) {
				*reason_why_locked =
					dbus_malloc0 (strlen (error->message) + 1);
				if (*reason_why_locked == NULL)
					return FALSE;
				strcpy (*reason_why_locked, error->message);
			}
		}

		return FALSE;
	}
	if (reply == NULL)
		return FALSE;

	dbus_message_unref (reply);

	return TRUE;
}

/**
 * libhal_device_unlock:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Release an advisory lock on the device.
 *
 * Returns: TRUE if the device was successfully unlocked,
 *                              FALSE otherwise
 */
dbus_bool_t
libhal_device_unlock (LibHalContext *ctx,
		      const char *udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						udi,
						"org.freedesktop.Hal.Device",
						"Unlock");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}


	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL)
		return FALSE;

	dbus_message_unref (reply);

	return TRUE;
}


/**
 * libhal_new_device:
 * @ctx: the context for the connection to hald
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Create a new device object which will be hidden from applications
 * until the CommitToGdl(), ie. libhal_device_commit_to_gdl(), method
 * is called. Note that the program invoking this method needs to run
 * with super user privileges.
 *
 * Returns: Temporary device unique id or NULL if there was a
 * problem. This string must be freed by the caller.
 */
char *
libhal_new_device (LibHalContext *ctx, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter reply_iter;
	char *value;
	char *dbus_str;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"NewDevice");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return NULL;
	}


	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return NULL;
	}
	if (reply == NULL) {
		return NULL;
	}

	dbus_message_iter_init (reply, &reply_iter);

	/* now analyze reply */
	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_STRING) {
		fprintf (stderr,
			 "%s %d : expected a string in reply to NewDevice\n",
			 __FILE__, __LINE__);
		dbus_message_unref (reply);
		return NULL;
	}

	dbus_message_iter_get_basic (&reply_iter, &dbus_str);
	value = (char *) ((dbus_str != NULL) ? strdup (dbus_str) : NULL);
	if (value == NULL) {
		fprintf (stderr, "%s %d : error allocating memory\n",
			 __FILE__, __LINE__);
	}

	dbus_message_unref (reply);
	return value;
}


/**
 * libhal_device_commit_to_gdl:
 * @ctx: the context for the connection to hald
 * @temp_udi: the temporary unique device id as returned by libhal_new_device()
 * @udi: the new unique device id.
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * When a hidden device has been built using the NewDevice method,
 * ie. libhal_new_device(), and the org.freedesktop.Hal.Device
 * interface this function will commit it to the global device list.
 *
 * This means that the device object will be visible to applications
 * and the HAL daemon will possibly attempt to boot the device
 * (depending on the property RequireEnable).
 *
 * Note that the program invoking this method needs to run with super
 * user privileges.
 *
 * Returns: FALSE if the given unique device id is already in use.
 */
dbus_bool_t
libhal_device_commit_to_gdl (LibHalContext *ctx,
			     const char *temp_udi, const char *udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(temp_udi, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"CommitToGdl");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &temp_udi);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &udi);


	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}

/**
 * libhal_remove_device:
 * @ctx: the context for the connection to hald
 * @udi: the Unique device id.
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * This method can be invoked when a device is removed. The HAL daemon
 * will shut down the device. Note that the device may still be in the
 * device list if the Persistent property is set to true.
 *
 * Note that the program invoking this method needs to run with super
 * user privileges.
 *
 * Returns: TRUE if the device was removed, FALSE otherwise
 */
dbus_bool_t
libhal_remove_device (LibHalContext *ctx, const char *udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"Remove");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &udi);


	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}

/**
 * libhal_device_exists:
 * @ctx: the context for the connection to hald
 * @udi: the Unique device id.
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Determine if a device exists.
 *
 * Returns: TRUE if the device exists
 */
dbus_bool_t
libhal_device_exists (LibHalContext *ctx, const char *udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	dbus_bool_t value;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"DeviceExists");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &udi);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_iter_init (reply, &reply_iter);

	/* now analyze reply */
	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_BOOLEAN) {
		fprintf (stderr,
			 "%s %d : expected a bool in reply to DeviceExists\n",
			 __FILE__, __LINE__);
		dbus_message_unref (reply);
		return FALSE;
	}

	dbus_message_iter_get_basic (&reply_iter, &value);

	dbus_message_unref (reply);
	return value;
}

/**
 * libhal_device_property_exists:
 * @ctx: the context for the connection to hald
 * @udi: the Unique device id.
 * @key: name of the property
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Determine if a property on a device exists.
 *
 * Returns: TRUE if the device exists, FALSE otherwise
 */
dbus_bool_t
libhal_device_property_exists (LibHalContext *ctx,
			       const char *udi, const char *key, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	dbus_bool_t value;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"PropertyExists");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_iter_init (reply, &reply_iter);

	/* now analyse reply */
	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_BOOLEAN) {
		fprintf (stderr, "%s %d : expected a bool in reply to "
			 "PropertyExists\n", __FILE__, __LINE__);
		dbus_message_unref (reply);
		return FALSE;
	}

	dbus_message_iter_get_basic (&reply_iter, &value);

	dbus_message_unref (reply);
	return value;
}

/**
 * libhal_merge_properties:
 * @ctx: the context for the connection to hald
 * @target_udi: the Unique device id of target device to merge to
 * @source_udi: the Unique device id of device to merge from
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Merge properties from one device to another.
 *
 * Returns: TRUE if the properties were merged, FALSE otherwise
 */
dbus_bool_t
libhal_merge_properties (LibHalContext *ctx,
			 const char *target_udi, const char *source_udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(target_udi, FALSE);
	LIBHAL_CHECK_UDI_VALID(source_udi, FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"MergeProperties");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &target_udi);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &source_udi);


	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}

/**
 * libhal_device_matches:
 * @ctx: the context for the connection to hald
 * @udi1: the Unique Device Id for device 1
 * @udi2: the Unique Device Id for device 2
 * @property_namespace: the namespace for set of devices, e.g. "usb"
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Check a set of properties for two devices matches.
 *
 * Checks that all properties where keys, starting with a given value
 * (namespace), of the first device is in the second device and that
 * they got the same value and type.
 *
 * Note that the other inclusion isn't tested, so there could be
 * properties (from the given namespace) in the second device not
 * present in the first device.
 *
 * Returns: TRUE if all properties starting with the given namespace
 * parameter from one device is in the other and have the same value.
 */
dbus_bool_t
libhal_device_matches (LibHalContext *ctx,
		       const char *udi1, const char *udi2,
		       const char *property_namespace, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, reply_iter;
	dbus_bool_t value;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi1, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi2, FALSE);
	LIBHAL_CHECK_PARAM_VALID(property_namespace, "*property_namespace", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"DeviceMatches");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, udi1);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, udi2);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, property_namespace);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}
	/* now analyse reply */
	dbus_message_iter_init (reply, &reply_iter);

	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_BOOLEAN) {
		fprintf (stderr,
			 "%s %d : expected a bool in reply to DeviceMatches\n",
			 __FILE__, __LINE__);
		dbus_message_unref (reply);
		return FALSE;
	}

	dbus_message_iter_get_basic (&reply_iter, &value);

	dbus_message_unref (reply);
	return value;
}

/**
 * libhal_device_print:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Print a device to stdout; useful for debugging.
 *
 * Returns: TRUE if device's information could be obtained, FALSE otherwise
 */
dbus_bool_t
libhal_device_print (LibHalContext *ctx, const char *udi, DBusError *error)
{
	int type;
	char *key;
	LibHalPropertySet *pset;
	LibHalPropertySetIterator i;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	printf ("device_id = %s\n", udi);

	if ((pset = libhal_device_get_all_properties (ctx, udi, error)) == NULL)
		return FALSE;

	for (libhal_psi_init (&i, pset); libhal_psi_has_more (&i);
	     libhal_psi_next (&i)) {
		type = libhal_psi_get_type (&i);
		key = libhal_psi_get_key (&i);

		switch (type) {
		case LIBHAL_PROPERTY_TYPE_STRING:
			printf ("    %s = '%s' (string)\n", key,
				libhal_psi_get_string (&i));
			break;
		case LIBHAL_PROPERTY_TYPE_INT32:
			printf ("    %s = %d = 0x%x (int)\n", key,
				libhal_psi_get_int (&i),
				libhal_psi_get_int (&i));
			break;
		case LIBHAL_PROPERTY_TYPE_UINT64:
			printf ("    %s = %llu = 0x%llx (uint64)\n", key,
				(long long unsigned int) libhal_psi_get_uint64 (&i),
				(long long unsigned int) libhal_psi_get_uint64 (&i));
			break;
		case LIBHAL_PROPERTY_TYPE_BOOLEAN:
			printf ("    %s = %s (bool)\n", key,
				(libhal_psi_get_bool (&i) ? "true" :
				 "false"));
			break;
		case LIBHAL_PROPERTY_TYPE_DOUBLE:
			printf ("    %s = %g (double)\n", key,
				libhal_psi_get_double (&i));
			break;
		case LIBHAL_PROPERTY_TYPE_STRLIST:
		{
			unsigned int j;
			char **str_list;

			str_list = libhal_psi_get_strlist (&i);
			printf ("    %s = [", key);
			for (j = 0; str_list[j] != NULL; j++) {
				printf ("'%s'", str_list[j]);
				if (str_list[j+1] != NULL)
					printf (", ");
			}
			printf ("] (string list)\n");

			break;
		}
		default:
			printf ("    *** unknown type for key %s\n", key);
			break;
		}
	}

	libhal_free_property_set (pset);

	return TRUE;
}

/**
 * libhal_manager_find_device_string_match:
 * @ctx: the context for the connection to hald
 * @key: name of the property
 * @value: the value to match
 * @num_devices: pointer to store number of devices
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Find a device in the GDL where a single string property matches a
 * given value.
 *
 * Returns: UDI of devices; free with libhal_free_string_array()
 */
char **
libhal_manager_find_device_string_match (LibHalContext *ctx,
					 const char *key,
					 const char *value, int *num_devices, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, iter_array, reply_iter;
	char **hal_device_names;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", NULL);
	LIBHAL_CHECK_PARAM_VALID(value, "*value", NULL);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"FindDeviceStringMatch");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return NULL;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &key);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &value);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return NULL;
	}
	if (reply == NULL) {
		return NULL;
	}
	/* now analyse reply */
	dbus_message_iter_init (reply, &reply_iter);

	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_ARRAY) {
		fprintf (stderr, "%s %d : wrong reply from hald.  Expecting an array.\n", __FILE__, __LINE__);
		return NULL;
	}

	dbus_message_iter_recurse (&reply_iter, &iter_array);

	hal_device_names = libhal_get_string_array_from_iter (&iter_array, num_devices);

	dbus_message_unref (reply);
	return hal_device_names;
}


/**
 * libhal_device_add_capability:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @capability: the capability name to add
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Assign a capability to a device.
 *
 * Returns: TRUE if the capability was added, FALSE if the device didn't exist
 */
dbus_bool_t
libhal_device_add_capability (LibHalContext *ctx,
			      const char *udi, const char *capability, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(capability, "*capability", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"AddCapability");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &capability);


	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}

/**
 * libhal_device_query_capability:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @capability: the capability name
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Check if a device has a capability. The result is undefined if the
 * device doesn't exist.
 *
 * Returns: TRUE if the device has the capability, otherwise FALSE
 */
dbus_bool_t
libhal_device_query_capability (LibHalContext *ctx, const char *udi, const char *capability, DBusError *error)
{
	char **caps;
	unsigned int i;
	dbus_bool_t ret;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(capability, "*capability", FALSE);

	ret = FALSE;

	caps = libhal_device_get_property_strlist (ctx, udi, "info.capabilities", error);
	if (caps != NULL) {
		for (i = 0; caps[i] != NULL; i++) {
			if (strcmp (caps[i], capability) == 0) {
				ret = TRUE;
				break;
			}
		}
		libhal_free_string_array (caps);
	}

	return ret;
}

/**
 * libhal_find_device_by_capability:
 * @ctx: the context for the connection to hald
 * @capability: the capability name
 * @num_devices: pointer to store number of devices
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Find devices with a given capability.
 *
 * Returns: UDI of devices; free with libhal_free_string_array()
 */
char **
libhal_find_device_by_capability (LibHalContext *ctx,
				  const char *capability, int *num_devices, DBusError *error)
{
	DBusMessage *message;
	DBusMessage *reply;
	DBusMessageIter iter, iter_array, reply_iter;
	char **hal_device_names;
	DBusError _error;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);
	LIBHAL_CHECK_PARAM_VALID(capability, "*capability", NULL);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						"/org/freedesktop/Hal/Manager",
						"org.freedesktop.Hal.Manager",
						"FindDeviceByCapability");
	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return NULL;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &capability);

	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return NULL;
	}
	if (reply == NULL) {
		return NULL;
	}
	/* now analyse reply */
	dbus_message_iter_init (reply, &reply_iter);

	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_ARRAY) {
		fprintf (stderr, "%s %d : wrong reply from hald.  Expecting an array.\n", __FILE__, __LINE__);
		return NULL;
	}

	dbus_message_iter_recurse (&reply_iter, &iter_array);

	hal_device_names = libhal_get_string_array_from_iter (&iter_array, num_devices);

	dbus_message_unref (reply);
	return hal_device_names;
}

/**
 * libhal_device_property_watch_all:
 * @ctx: the context for the connection to hald
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Watch all devices, ie. the device_property_changed callback is
 * invoked when the properties on any device changes.
 *
 * Returns: TRUE only if the operation succeeded
 */
dbus_bool_t
libhal_device_property_watch_all (LibHalContext *ctx, DBusError *error)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	dbus_bus_add_match (ctx->connection,
			    "type='signal',"
			    "interface='org.freedesktop.Hal.Device',"
			    "sender='org.freedesktop.Hal'", error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	return TRUE;
}


/**
 * libhal_device_add_property_watch:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Add a watch on a device, so the device_property_changed callback is
 * invoked when the properties on the given device changes.
 *
 * The application itself is responsible for deleting the watch, using
 * libhal_device_remove_property_watch, if the device is removed.
 *
 * Returns: TRUE only if the operation succeeded
 */
dbus_bool_t
libhal_device_add_property_watch (LibHalContext *ctx, const char *udi, DBusError *error)
{
	char buf[512];

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	snprintf (buf, 512,
		  "type='signal',"
		  "interface='org.freedesktop.Hal.Device',"
		  "sender='org.freedesktop.Hal'," "path=%s", udi);

	dbus_bus_add_match (ctx->connection, buf, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	return TRUE;
}


/**
 * libhal_device_remove_property_watch:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Remove a watch on a device.
 *
 * Returns: TRUE only if the operation succeeded
 */
dbus_bool_t
libhal_device_remove_property_watch (LibHalContext *ctx, const char *udi, DBusError *error)
{
	char buf[512];

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	snprintf (buf, 512,
		  "type='signal',"
		  "interface='org.freedesktop.Hal.Device',"
		  "sender='org.freedesktop.Hal'," "path=%s", udi);

	dbus_bus_remove_match (ctx->connection, buf, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	return TRUE;
}


/**
 * libhal_ctx_new:
 *
 * Create a new LibHalContext
 *
 * Returns: a new uninitialized LibHalContext object
 */
LibHalContext *
libhal_ctx_new (void)
{
	LibHalContext *ctx;

	if (!libhal_already_initialized_once) {
		bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
		bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");

		libhal_already_initialized_once = TRUE;
	}

	ctx = calloc (1, sizeof (LibHalContext));
	if (ctx == NULL) {
		fprintf (stderr,
			 "%s %d : Failed to allocate %lu bytes\n",
			 __FILE__, __LINE__, (unsigned long) sizeof (LibHalContext));
		return NULL;
	}

	ctx->is_initialized = FALSE;
	ctx->is_shutdown = FALSE;
	ctx->connection = NULL;
	ctx->is_direct = FALSE;

	return ctx;
}

/**
 * libhal_ctx_set_cache:
 * @ctx: context to enable/disable cache for
 * @use_cache: whether or not to use cache
 *
 * Enable or disable caching. Note: Caching is not actually
 * implemented yet.
 *
 * Returns: TRUE if cache was successfully enabled/disabled, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_set_cache (LibHalContext *ctx, dbus_bool_t use_cache)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	ctx->cache_enabled = use_cache;
	return TRUE;
}

/**
 * libhal_ctx_set_dbus_connection:
 * @ctx: context to set connection for
 * @conn: DBus connection to use
 *
 * Set DBus connection to use to talk to hald.
 *
 * Returns: TRUE if connection was successfully set, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_set_dbus_connection (LibHalContext *ctx, DBusConnection *conn)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	if (conn == NULL)
		return FALSE;

	ctx->connection = conn;
	return TRUE;
}

/**
 * libhal_ctx_get_dbus_connection:
 * @ctx: context to get connection for
 *
 * Get DBus connection used for talking to hald.
 *
 * Returns: DBus connection to use or NULL
 */
DBusConnection *
libhal_ctx_get_dbus_connection (LibHalContext *ctx)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, NULL);

	return ctx->connection;
}


/**
 * libhal_ctx_init:
 * @ctx: Context for connection to hald (D-BUS connection should be set with libhal_ctx_set_dbus_connection)
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Initialize the connection to hald.
 *
 * Returns: TRUE if initialization succeeds, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_init (LibHalContext *ctx, DBusError *error)
{
	DBusError _error;
	dbus_bool_t hald_exists;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	if (ctx->connection == NULL)
		return FALSE;

	dbus_error_init (&_error);
	hald_exists = dbus_bus_name_has_owner (ctx->connection, "org.freedesktop.Hal", &_error);
	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}

	if (!hald_exists) {
		return FALSE;
	}


	if (!dbus_connection_add_filter (ctx->connection, filter_func, ctx, NULL)) {
		return FALSE;
	}

	dbus_bus_add_match (ctx->connection,
			    "type='signal',"
			    "interface='org.freedesktop.Hal.Manager',"
			    "sender='org.freedesktop.Hal',"
			    "path='/org/freedesktop/Hal/Manager'", &_error);
	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	ctx->is_initialized = TRUE;
	ctx->is_direct = FALSE;

	return TRUE;
}

/**
 * libhal_ctx_init_direct:
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Create an already initialized connection to hald. This function should only be used by HAL helpers.
 *
 * Returns: A pointer to an already initialized LibHalContext
 */
LibHalContext *
libhal_ctx_init_direct (DBusError *error)
{
	char *hald_addr;
	LibHalContext *ctx;
	DBusError _error;

	ctx = libhal_ctx_new ();
	if (ctx == NULL)
		goto out;

	if (((hald_addr = getenv ("HALD_DIRECT_ADDR"))) == NULL) {
		libhal_ctx_free (ctx);
		ctx = NULL;
		goto out;
	}

	dbus_error_init (&_error);
	ctx->connection = dbus_connection_open (hald_addr, &_error);
	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		libhal_ctx_free (ctx);
		ctx = NULL;
		goto out;
	}

	ctx->is_initialized = TRUE;
	ctx->is_direct = TRUE;

out:
	return ctx;
}

/**
 * libhal_ctx_shutdown:
 * @ctx: the context for the connection to hald
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Shut down a connection to hald.
 *
 * Returns: TRUE if connection successfully shut down, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_shutdown (LibHalContext *ctx, DBusError *error)
{
	DBusError myerror;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	if (ctx->is_direct) {
		/* for some reason dbus_connection_set_exit_on_disconnect doesn't work yet so don't unref */
		/*dbus_connection_unref (ctx->connection);*/
	} else {
		dbus_error_init (&myerror);
		dbus_bus_remove_match (ctx->connection,
				       "type='signal',"
				       "interface='org.freedesktop.Hal.Manager',"
				       "sender='org.freedesktop.Hal',"
				       "path='/org/freedesktop/Hal/Manager'", &myerror);
		dbus_move_error (&myerror, error);
		if (error != NULL && dbus_error_is_set (error)) {
			fprintf (stderr, "%s %d : Error unsubscribing to signals, error=%s\n",
				 __FILE__, __LINE__, error->message);
			/** @todo  clean up */
		}

		/* TODO: remove other matches */

		dbus_connection_remove_filter (ctx->connection, filter_func, ctx);
	}

	ctx->is_initialized = FALSE;

	return TRUE;
}

/**
 * libhal_ctx_free:
 * @ctx: pointer to a LibHalContext
 *
 * Free a LibHalContext resource.
 *
 * Returns: TRUE
 */
dbus_bool_t
libhal_ctx_free (LibHalContext *ctx)
{
	free (ctx);
	return TRUE;
}

/**
 * libhal_ctx_set_device_added:
 * @ctx: the context for the connection to hald
 * @callback: the function to call when a device is added
 *
 * Set the callback for when a device is added
 *
 * Returns: TRUE if callback was successfully set, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_set_device_added (LibHalContext *ctx, LibHalDeviceAdded callback)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	ctx->device_added = callback;
	return TRUE;
}

/**
 * libhal_ctx_set_device_removed:
 * @ctx: the context for the connection to hald
 * @callback: the function to call when a device is removed
 *
 * Set the callback for when a device is removed.
 *
 * Returns: TRUE if callback was successfully set, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_set_device_removed (LibHalContext *ctx, LibHalDeviceRemoved callback)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	ctx->device_removed = callback;
	return TRUE;
}

/**
 * libhal_ctx_set_device_new_capability:
 * @ctx: the context for the connection to hald
 * @callback: the function to call when a device gains a new capability
 *
 * Set the callback for when a device gains a new capability.
 *
 * Returns: TRUE if callback was successfully set, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_set_device_new_capability (LibHalContext *ctx, LibHalDeviceNewCapability callback)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	ctx->device_new_capability = callback;
	return TRUE;
}

/**
 * libhal_ctx_set_device_lost_capability:
 * @ctx: the context for the connection to hald
 * @callback: the function to call when a device loses a capability
 *
 * Set the callback for when a device loses a capability
 *
 * Returns: TRUE if callback was successfully set, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_set_device_lost_capability (LibHalContext *ctx, LibHalDeviceLostCapability callback)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	ctx->device_lost_capability = callback;
	return TRUE;
}

/**
 * libhal_ctx_set_device_property_modified:
 * @ctx: the context for the connection to hald
 * @callback: the function to call when a property is modified on a device
 *
 * Set the callback for when a property is modified on a device.
 *
 * Returns: TRUE if callback was successfully set, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_set_device_property_modified (LibHalContext *ctx, LibHalDevicePropertyModified callback)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	ctx->device_property_modified = callback;
	return TRUE;
}

/**
 * libhal_ctx_set_device_condition:
 * @ctx: the context for the connection to hald
 * @callback: the function to call when a device emits a condition
 *
 * Set the callback for when a device emits a condition
 *
 * Returns: TRUE if callback was successfully set, FALSE otherwise
 */
dbus_bool_t
libhal_ctx_set_device_condition (LibHalContext *ctx, LibHalDeviceCondition callback)
{
	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);

	ctx->device_condition = callback;
	return TRUE;
}

/**
 * libhal_string_array_length:
 * @str_array: array of strings to consider
 *
 * Get the length of an array of strings.
 *
 * Returns: Number of strings in array
 */
unsigned int
libhal_string_array_length (char **str_array)
{
	unsigned int i;

	if (str_array == NULL)
		return 0;

	for (i = 0; str_array[i] != NULL; i++)
		;

	return i;
}


/**
 * libhal_device_rescan:
 * @ctx: the context for the connection to hald
 * @udi: the Unique id of device
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * TODO document me.
 *
 * Returns: Whether the operation succeeded
 */
dbus_bool_t
libhal_device_rescan (LibHalContext *ctx, const char *udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessageIter reply_iter;
	DBusMessage *reply;
	dbus_bool_t result;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal", udi,
						"org.freedesktop.Hal.Device",
						"Rescan");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL)
		return FALSE;

	dbus_message_iter_init (reply, &reply_iter);
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_BOOLEAN) {
		dbus_message_unref (reply);
		return FALSE;
	}
	dbus_message_iter_get_basic (&reply_iter, &result);

	dbus_message_unref (reply);

	return result;
}

/**
 * libhal_device_reprobe:
 * @ctx: the context for the connection to hald
 * @udi: the Unique id of device
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * TODO document me.
 *
 * Returns: Whether the operation succeeded
 */
dbus_bool_t
libhal_device_reprobe (LibHalContext *ctx, const char *udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessageIter reply_iter;
	DBusMessage *reply;
	dbus_bool_t result;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						udi,
						"org.freedesktop.Hal.Device",
						"Reprobe");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL)
		return FALSE;

	dbus_message_iter_init (reply, &reply_iter);
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_BOOLEAN) {
		dbus_message_unref (reply);
		return FALSE;
	}
	dbus_message_iter_get_basic (&reply_iter, &result);

	dbus_message_unref (reply);

	return result;
}

/**
 * libhal_device_emit_condition:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @condition_name: user-readable name of condition
 * @condition_details: user-readable details of condition
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Emit a condition from a device. Can only be used from hald helpers.
 *
 * Returns: TRUE if condition successfully emitted,
 *                              FALSE otherwise
 */
dbus_bool_t libhal_device_emit_condition (LibHalContext *ctx,
					  const char *udi,
					  const char *condition_name,
					  const char *condition_details,
					  DBusError *error)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusMessageIter reply_iter;
	DBusMessage *reply;
	dbus_bool_t result;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(condition_name, "*condition_name", FALSE);
	LIBHAL_CHECK_PARAM_VALID(condition_details, "*condition_details", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						udi,
						"org.freedesktop.Hal.Device",
						"EmitCondition");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &condition_name);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &condition_details);

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		fprintf (stderr,
			 "%s %d : Failure sending D-BUS message: %s: %s\n",
			 __FILE__, __LINE__, error->name, error->message);
		return FALSE;
	}

	if (reply == NULL) {
		fprintf (stderr,
			 "%s %d : Got no reply\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init (reply, &reply_iter);
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_BOOLEAN) {
		dbus_message_unref (reply);
		fprintf (stderr,
			 "%s %d : Malformed reply\n",
			 __FILE__, __LINE__);
		return FALSE;
	}
	dbus_message_iter_get_basic (&reply_iter, &result);

	dbus_message_unref (reply);

	return result;
}

/**
 * libhal_device_addon_is_ready:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id this addon is handling
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * HAL addon's must call this method when they are done initializing the device object. The HAL
 * daemon will wait for all addon's to call this.
 *
 * Can only be used from hald helpers.
 *
 * Returns: TRUE if the HAL daemon received the message, FALSE otherwise
 */
dbus_bool_t
libhal_device_addon_is_ready (LibHalContext *ctx, const char *udi, DBusError *error)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusMessageIter reply_iter;
	DBusMessage *reply;
	dbus_bool_t result;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						udi,
						"org.freedesktop.Hal.Device",
						"AddonIsReady");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL)
		return FALSE;

	dbus_message_iter_init (reply, &reply_iter);
	if (dbus_message_iter_get_arg_type (&reply_iter) != DBUS_TYPE_BOOLEAN) {
		dbus_message_unref (reply);
		return FALSE;
	}
	dbus_message_iter_get_basic (&reply_iter, &result);

	dbus_message_unref (reply);
	return result;
}

/**
 * libhal_device_claim_interface:
 * @ctx: the context for the connection to hald
 * @udi: the Unique Device Id
 * @interface_name: Name of interface to claim, e.g. org.freedesktop.Hal.Device.FoobarKindOfThing
 * @introspection_xml: Introspection XML containing what would be inside the interface XML tag
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Claim an interface for a device. All messages to this interface
 * will be forwarded to the helper. Can only be used from hald
 * helpers.
 *
 * Returns: TRUE if interface was claimed, FALSE otherwise
 */
dbus_bool_t
libhal_device_claim_interface (LibHalContext *ctx,
			       const char *udi,
			       const char *interface_name,
			       const char *introspection_xml,
			       DBusError *error)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusMessageIter reply_iter;
	DBusMessage *reply;
	dbus_bool_t result;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(udi, FALSE);
	LIBHAL_CHECK_PARAM_VALID(interface_name, "*interface_name", FALSE);

	message = dbus_message_new_method_call ("org.freedesktop.Hal",
						udi,
						"org.freedesktop.Hal.Device",
						"ClaimInterface");

	if (message == NULL) {
		fprintf (stderr,
			 "%s %d : Couldn't allocate D-BUS message\n",
			 __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &interface_name);
	dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &introspection_xml);

	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   error);

	dbus_message_unref (message);

	if (error != NULL && dbus_error_is_set (error)) {
		return FALSE;
	}
	if (reply == NULL)
		return FALSE;

	dbus_message_iter_init (reply, &reply_iter);
	if (dbus_message_iter_get_arg_type (&reply_iter) !=
		   DBUS_TYPE_BOOLEAN) {
		dbus_message_unref (reply);
		return FALSE;
	}
	dbus_message_iter_get_basic (&reply_iter, &result);

	dbus_message_unref (reply);

	return result;
}



struct LibHalChangeSetElement_s;

typedef struct LibHalChangeSetElement_s LibHalChangeSetElement;

struct LibHalChangeSetElement_s {
	char *key;
	int change_type;
	union {
		char *val_str;
		dbus_int32_t val_int;
		dbus_uint64_t val_uint64;
		double val_double;
		dbus_bool_t val_bool;
		char **val_strlist;
	} value;
	LibHalChangeSetElement *next;
	LibHalChangeSetElement *prev;
};

struct LibHalChangeSet_s {
	char *udi;
	LibHalChangeSetElement *head;
	LibHalChangeSetElement *tail;
};

/**
 * libhal_device_new_changeset:
 * @udi: unique device identifier
 *
 * Request a new changeset object. Used for changing multiple properties at once. Useful when
 * performance is critical and also for atomically updating several properties.
 *
 * Returns: A new changeset object or NULL on error
 */
LibHalChangeSet *
libhal_device_new_changeset (const char *udi)
{
	LibHalChangeSet *changeset;

	LIBHAL_CHECK_UDI_VALID(udi, NULL);

	changeset = calloc (1, sizeof (LibHalChangeSet));
	if (changeset == NULL)
		goto out;

	changeset->udi = strdup (udi);
	if (changeset->udi == NULL) {
		free (changeset);
		changeset = NULL;
		goto out;
	}

	changeset->head = NULL;
	changeset->tail = NULL;

out:
	return changeset;
}

static void
libhal_changeset_append (LibHalChangeSet *changeset, LibHalChangeSetElement *elem)
{
	LIBHAL_CHECK_PARAM_VALID(changeset, "*changeset", );
	LIBHAL_CHECK_PARAM_VALID(elem, "*elem", );

	if (changeset->head == NULL) {
		changeset->head = elem;
		changeset->tail = elem;
		elem->next = NULL;
		elem->prev = NULL;
	} else {
		elem->prev = changeset->tail;
		elem->next = NULL;
		elem->prev->next = elem;
		changeset->tail = elem;
	}
}


/**
 * libhal_changeset_set_property_string:
 * @changeset: the changeset
 * @key: key of property
 * @value: the value to set
 *
 * Set a property.
 *
 * Returns: FALSE on OOM
 */
dbus_bool_t
libhal_changeset_set_property_string (LibHalChangeSet *changeset, const char *key, const char *value)
{
	LibHalChangeSetElement *elem;

	LIBHAL_CHECK_PARAM_VALID(changeset, "*changeset", FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);
	LIBHAL_CHECK_PARAM_VALID(value, "*value", FALSE);

	elem = calloc (1, sizeof (LibHalChangeSetElement));
	if (elem == NULL)
		goto out;
	elem->key = strdup (key);
	if (elem->key == NULL) {
		free (elem);
		elem = NULL;
		goto out;
	}

	elem->change_type = LIBHAL_PROPERTY_TYPE_STRING;
	elem->value.val_str = strdup (value);
	if (elem->value.val_str == NULL) {
		free (elem->key);
		free (elem);
		elem = NULL;
		goto out;
	}

	libhal_changeset_append (changeset, elem);
out:
	return elem != NULL;
}

/**
 * libhal_changeset_set_property_int:
 * @changeset: the changeset
 * @key: key of property
 * @value: the value to set
 *
 * Set a property.
 *
 * Returns: FALSE on OOM
 */
dbus_bool_t
libhal_changeset_set_property_int (LibHalChangeSet *changeset, const char *key, dbus_int32_t value)
{
	LibHalChangeSetElement *elem;

	LIBHAL_CHECK_PARAM_VALID(changeset, "*changeset", FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	elem = calloc (1, sizeof (LibHalChangeSetElement));
	if (elem == NULL)
		goto out;
	elem->key = strdup (key);
	if (elem->key == NULL) {
		free (elem);
		elem = NULL;
		goto out;
	}

	elem->change_type = LIBHAL_PROPERTY_TYPE_INT32;
	elem->value.val_int = value;

	libhal_changeset_append (changeset, elem);
out:
	return elem != NULL;
}

/**
 * libhal_changeset_set_property_uint64:
 * @changeset: the changeset
 * @key: key of property
 * @value: the value to set
 *
 * Set a property.
 *
 * Returns: FALSE on OOM
 */
dbus_bool_t
libhal_changeset_set_property_uint64 (LibHalChangeSet *changeset, const char *key, dbus_uint64_t value)
{
	LibHalChangeSetElement *elem;

	LIBHAL_CHECK_PARAM_VALID(changeset, "*changeset", FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	elem = calloc (1, sizeof (LibHalChangeSetElement));
	if (elem == NULL)
		goto out;
	elem->key = strdup (key);
	if (elem->key == NULL) {
		free (elem);
		elem = NULL;
		goto out;
	}

	elem->change_type = LIBHAL_PROPERTY_TYPE_UINT64;
	elem->value.val_uint64 = value;

	libhal_changeset_append (changeset, elem);
out:
	return elem != NULL;
}

/**
 * libhal_changeset_set_property_double:
 * @changeset: the changeset
 * @key: key of property
 * @value: the value to set
 *
 * Set a property.
 *
 * Returns: FALSE on OOM
 */
dbus_bool_t
libhal_changeset_set_property_double (LibHalChangeSet *changeset, const char *key, double value)
{
	LibHalChangeSetElement *elem;

	LIBHAL_CHECK_PARAM_VALID(changeset, "*changeset", FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	elem = calloc (1, sizeof (LibHalChangeSetElement));
	if (elem == NULL)
		goto out;
	elem->key = strdup (key);
	if (elem->key == NULL) {
		free (elem);
		elem = NULL;
		goto out;
	}

	elem->change_type = LIBHAL_PROPERTY_TYPE_DOUBLE;
	elem->value.val_double = value;

	libhal_changeset_append (changeset, elem);
out:
	return elem != NULL;
}

/**
 * libhal_changeset_set_property_bool:
 * @changeset: the changeset
 * @key: key of property
 * @value: the value to set
 *
 * Set a property.
 *
 * Returns: FALSE on OOM
 */
dbus_bool_t
libhal_changeset_set_property_bool (LibHalChangeSet *changeset, const char *key, dbus_bool_t value)
{
	LibHalChangeSetElement *elem;

	LIBHAL_CHECK_PARAM_VALID(changeset, "*changeset", FALSE);
	LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	elem = calloc (1, sizeof (LibHalChangeSetElement));
	if (elem == NULL)
		goto out;
	elem->key = strdup (key);
	if (elem->key == NULL) {
		free (elem);
		elem = NULL;
		goto out;
	}

	elem->change_type = LIBHAL_PROPERTY_TYPE_BOOLEAN;
	elem->value.val_bool = value;

	libhal_changeset_append (changeset, elem);
out:
	return elem != NULL;
}

/**
 * libhal_changeset_set_property_strlist:
 * @changeset: the changeset
 * @key: key of property
 * @value: the value to set - NULL terminated array of strings
 *
 * Set a property.
 *
 * Returns: FALSE on OOM
 */
dbus_bool_t
libhal_changeset_set_property_strlist (LibHalChangeSet *changeset, const char *key, const char **value)
{
	LibHalChangeSetElement *elem;
	char **value_copy;
	int len;
	int i, j;

        LIBHAL_CHECK_PARAM_VALID(changeset, "*changeset", FALSE);
        LIBHAL_CHECK_PARAM_VALID(key, "*key", FALSE);

	elem = calloc (1, sizeof (LibHalChangeSetElement));
	if (elem == NULL)
		goto out;
	elem->key = strdup (key);
	if (elem->key == NULL) {
		free (elem);
		elem = NULL;
		goto out;
	}

	for (i = 0; value[i] != NULL; i++)
		;
	len = i;

	value_copy = calloc (len + 1, sizeof (char *));
	if (value_copy == NULL) {
		free (elem->key);
		free (elem);
		elem = NULL;
		goto out;
	}

	for (i = 0; i < len; i++) {
		value_copy[i] = strdup (value[i]);
		if (value_copy[i] == NULL) {
			for (j = 0; j < i; j++) {
				free (value_copy[j]);
			}
			free (value_copy);
			free (elem->key);
			free (elem);
			elem = NULL;
			goto out;
		}
	}
	value_copy[i] = NULL;

	elem->change_type = LIBHAL_PROPERTY_TYPE_STRLIST;
	elem->value.val_strlist = value_copy;

	libhal_changeset_append (changeset, elem);
out:
	return elem != NULL;
}

/**
 * libhal_device_commit_changeset:
 * @ctx: the context for the connection to hald
 * @changeset: the changeset to commit
 * @error: pointer to an initialized dbus error object for returning errors or NULL
 *
 * Commit a changeset to the daemon.
 *
 * Returns: True if the changeset was committed on the daemon side
 */
dbus_bool_t
libhal_device_commit_changeset (LibHalContext *ctx, LibHalChangeSet *changeset, DBusError *error)
{
	LibHalChangeSetElement *elem;
	DBusMessage *message;
	DBusMessage *reply;
	DBusError _error;
	DBusMessageIter iter;
	DBusMessageIter sub;
	DBusMessageIter sub2;
	DBusMessageIter sub3;
	DBusMessageIter sub4;
	int i;

	LIBHAL_CHECK_LIBHALCONTEXT(ctx, FALSE);
	LIBHAL_CHECK_UDI_VALID(changeset->udi, FALSE);

	if (changeset->head == NULL) {
		return TRUE;
	}

	message = dbus_message_new_method_call ("org.freedesktop.Hal", changeset->udi,
						"org.freedesktop.Hal.Device",
						"SetMultipleProperties");

	if (message == NULL) {
		fprintf (stderr, "%s %d : Couldn't allocate D-BUS message\n", __FILE__, __LINE__);
		return FALSE;
	}

	dbus_message_iter_init_append (message, &iter);

	dbus_message_iter_open_container (&iter,
					  DBUS_TYPE_ARRAY,
					  DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					  DBUS_TYPE_STRING_AS_STRING
					  DBUS_TYPE_VARIANT_AS_STRING
					  DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					  &sub);

	for (elem = changeset->head; elem != NULL; elem = elem->next) {
		dbus_message_iter_open_container (&sub,
						  DBUS_TYPE_DICT_ENTRY,
						  NULL,
						  &sub2);
		dbus_message_iter_append_basic (&sub2, DBUS_TYPE_STRING, &(elem->key));

		switch (elem->change_type) {
		case LIBHAL_PROPERTY_TYPE_STRING:
			dbus_message_iter_open_container (&sub2, DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &sub3);
			dbus_message_iter_append_basic (&sub3, DBUS_TYPE_STRING, &(elem->value.val_str));
			dbus_message_iter_close_container (&sub2, &sub3);
			break;
		case LIBHAL_PROPERTY_TYPE_STRLIST:
			dbus_message_iter_open_container (&sub2, DBUS_TYPE_VARIANT,
							  DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, &sub3);
			dbus_message_iter_open_container (&sub3, DBUS_TYPE_ARRAY,
							  DBUS_TYPE_STRING_AS_STRING, &sub4);
			for (i = 0; elem->value.val_strlist[i] != NULL; i++) {
				dbus_message_iter_append_basic (&sub4, DBUS_TYPE_STRING,
								&(elem->value.val_strlist[i]));
			}
			dbus_message_iter_close_container (&sub3, &sub4);
			dbus_message_iter_close_container (&sub2, &sub3);
			break;
		case LIBHAL_PROPERTY_TYPE_INT32:
			dbus_message_iter_open_container (&sub2, DBUS_TYPE_VARIANT, DBUS_TYPE_INT32_AS_STRING, &sub3);
			dbus_message_iter_append_basic (&sub3, DBUS_TYPE_INT32, &(elem->value.val_int));
			dbus_message_iter_close_container (&sub2, &sub3);
			break;
		case LIBHAL_PROPERTY_TYPE_UINT64:
			dbus_message_iter_open_container (&sub2, DBUS_TYPE_VARIANT, DBUS_TYPE_UINT64_AS_STRING, &sub3);
			dbus_message_iter_append_basic (&sub3, DBUS_TYPE_UINT64, &(elem->value.val_uint64));
			dbus_message_iter_close_container (&sub2, &sub3);
			break;
		case LIBHAL_PROPERTY_TYPE_DOUBLE:
			dbus_message_iter_open_container (&sub2, DBUS_TYPE_VARIANT, DBUS_TYPE_DOUBLE_AS_STRING, &sub3);
			dbus_message_iter_append_basic (&sub3, DBUS_TYPE_DOUBLE, &(elem->value.val_double));
			dbus_message_iter_close_container (&sub2, &sub3);
			break;
		case LIBHAL_PROPERTY_TYPE_BOOLEAN:
			dbus_message_iter_open_container (&sub2, DBUS_TYPE_VARIANT, DBUS_TYPE_BOOLEAN_AS_STRING,&sub3);
			dbus_message_iter_append_basic (&sub3, DBUS_TYPE_BOOLEAN, &(elem->value.val_bool));
			dbus_message_iter_close_container (&sub2, &sub3);
			break;
		default:
			fprintf (stderr, "%s %d : unknown change_type %d\n", __FILE__, __LINE__, elem->change_type);
			break;
		}
		dbus_message_iter_close_container (&sub, &sub2);
	}

	dbus_message_iter_close_container (&iter, &sub);


	dbus_error_init (&_error);
	reply = dbus_connection_send_with_reply_and_block (ctx->connection,
							   message, -1,
							   &_error);

	dbus_message_unref (message);

	dbus_move_error (&_error, error);
	if (error != NULL && dbus_error_is_set (error)) {
		fprintf (stderr,
			 "%s %d : %s\n",
			 __FILE__, __LINE__, error->message);

		return FALSE;
	}
	if (reply == NULL) {
		return FALSE;
	}

	dbus_message_unref (reply);
	return TRUE;
}

/**
 * libhal_device_free_changeset:
 * @changeset: the changeset to free
 *
 * Free a changeset.
 */
void
libhal_device_free_changeset (LibHalChangeSet *changeset)
{
	LibHalChangeSetElement *elem;
	LibHalChangeSetElement *elem2;

	for (elem = changeset->head; elem != NULL; elem = elem2) {
		elem2 = elem->next;

		switch (elem->change_type) {
		case LIBHAL_PROPERTY_TYPE_STRING:
			free (elem->value.val_str);
			break;
		case LIBHAL_PROPERTY_TYPE_STRLIST:
			libhal_free_string_array (elem->value.val_strlist);
			break;
                /* explicit fallthrough */
		case LIBHAL_PROPERTY_TYPE_INT32:
		case LIBHAL_PROPERTY_TYPE_UINT64:
		case LIBHAL_PROPERTY_TYPE_DOUBLE:
		case LIBHAL_PROPERTY_TYPE_BOOLEAN:
			break;
		default:
			fprintf (stderr, "%s %d : unknown change_type %d\n", __FILE__, __LINE__, elem->change_type);
			break;
		}
		free (elem->key);
		free (elem);
	}

	free (changeset->udi);
	free (changeset);
}
