/***************************************************************************
 * CVSID: $Id$
 *
 * libhal.h : HAL daemon C convenience library headers
 *
 * Copyright (C) 2003 David Zeuthen, <david@fubar.dk>
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifndef LIBHAL_H
#define LIBHAL_H

#include <dbus/dbus.h>

#if defined(__cplusplus)
extern "C" {
#if 0
} /* shut up emacs indenting */
#endif
#endif

#if defined(__GNUC__)
#define LIBHAL_DEPRECATED __attribute__ ((deprecated))  
#else  
#define LIBHAL_DEPRECATED  
#endif 


#define LIBHAL_FREE_DBUS_ERROR(_dbus_error_)					\
	do {									\
		if (dbus_error_is_set(_dbus_error_))				\
			dbus_error_free (_dbus_error_);				\
	} while (0)


/**
 * LIBHAL_CHECK_LIBHALCONTEXT:
 * @_ctx_: the context
 * @_ret_: what to use for return value if context is invalid
 *
 * Handy macro for checking whether a context is valid.
 */
#define LIBHAL_CHECK_LIBHALCONTEXT(_ctx_, _ret_)				\
	do {									\
		if (_ctx_ == NULL) {						\
			fprintf (stderr,					\
				 "%s %d : LibHalContext *ctx is NULL\n", 	\
				 __FILE__, __LINE__);				\
			return _ret_;						\
		}								\
	} while(0)

/** 
 * LibHalPropertyType:
 *
 * Possible types for properties on hal device objects 
 */
typedef enum {
        /** Used to report error condition */
	LIBHAL_PROPERTY_TYPE_INVALID =    DBUS_TYPE_INVALID,

	/** Type for 32-bit signed integer property */
	LIBHAL_PROPERTY_TYPE_INT32   =    DBUS_TYPE_INT32,

	/** Type for 64-bit unsigned integer property */
	LIBHAL_PROPERTY_TYPE_UINT64  =    DBUS_TYPE_UINT64,

	/** Type for double precision floating point property */
	LIBHAL_PROPERTY_TYPE_DOUBLE  =    DBUS_TYPE_DOUBLE,

	/** Type for boolean property */
	LIBHAL_PROPERTY_TYPE_BOOLEAN =    DBUS_TYPE_BOOLEAN,

	/** Type code marking a D-Bus array type */
	LIBHAL_PROPERTY_TYPE_ARRAY   =    DBUS_TYPE_ARRAY,

	/** Type for UTF-8 string property */
	LIBHAL_PROPERTY_TYPE_STRING  =    DBUS_TYPE_STRING,

	/** Type for list of UTF-8 strings property */
	LIBHAL_PROPERTY_TYPE_STRLIST =    ((int) (DBUS_TYPE_STRING<<8)+('l'))
} LibHalPropertyType;


typedef struct LibHalContext_s LibHalContext;

/** 
 * LibHalIntegrateDBusIntoMainLoop:
 * @ctx: context for connection to hald
 * @dbus_connection: DBus connection to use in ctx
 *
 * Type for function in application code that integrates a
 * DBusConnection object into its own mainloop.
 */
typedef void (*LibHalIntegrateDBusIntoMainLoop) (LibHalContext *ctx,
						 DBusConnection *dbus_connection);

/** 
 * LibHalDeviceAdded:
 * @ctx: context for connection to hald
 * @udi: the Unique Device Id
 *
 * Type for callback when a device is added.
 */
typedef void (*LibHalDeviceAdded) (LibHalContext *ctx, 
				   const char *udi);

/** 
 * LibHalDeviceRemoved:
 * @ctx: context for connection to hald
 * @udi: the Unique Device Id
 *
 * Type for callback when a device is removed. 
 */
typedef void (*LibHalDeviceRemoved) (LibHalContext *ctx, 
				     const char *udi);

/** 
 * LibHalDeviceNewCapability:
 * @ctx: context for connection to hald
 * @udi: the Unique Device Id
 * @capability: capability of the device
 *
 * Type for callback when a device gains a new capability.
 *
 */
typedef void (*LibHalDeviceNewCapability) (LibHalContext *ctx, 
					   const char *udi,
					   const char *capability);

/** 
 * LibHalDeviceLostCapability:
 * @ctx: context for connection to hald
 * @udi: the Unique Device Id
 * @capability: capability of the device
 *
 * Type for callback when a device loses a capability.
 *
 */
typedef void (*LibHalDeviceLostCapability) (LibHalContext *ctx, 
					    const char *udi,
					    const char *capability);

/** 
 * LibHalDevicePropertyModified:
 * @ctx: context for connection to hald
 * @udi: the Unique Device Id
 * @key: name of the property that has changed
 * @is_removed: whether or not property was removed
 * @is_added: whether or not property was added
 *
 * Type for callback when a property of a device changes. 
 */
typedef void (*LibHalDevicePropertyModified) (LibHalContext *ctx,
					      const char *udi,
					      const char *key,
					      dbus_bool_t is_removed,
					      dbus_bool_t is_added);

/** 
 * LibHalDeviceCondition:
 * @ctx: context for connection to hald
 * @udi: the Unique Device Id
 * @condition_name: name of the condition, e.g. ProcessorOverheating. Consult the HAL spec for details
 * @condition_detail: detail of condition
 *
 * Type for callback when a non-continuous condition occurs on a device.
 */
typedef void (*LibHalDeviceCondition) (LibHalContext *ctx,
				       const char *udi,
				       const char *condition_name,
				       const char *condition_detail);


/* Create a new context for a connection with hald */
LibHalContext *libhal_ctx_new                          (void);

/* Enable or disable caching */
dbus_bool_t    libhal_ctx_set_cache                    (LibHalContext *ctx, dbus_bool_t use_cache);

/* Set DBus connection to use to talk to hald. */
dbus_bool_t    libhal_ctx_set_dbus_connection          (LibHalContext *ctx, DBusConnection *conn);

/* Get DBus connection to use to talk to hald. */
DBusConnection *libhal_ctx_get_dbus_connection          (LibHalContext *ctx);

/* Set user data for the context */
dbus_bool_t    libhal_ctx_set_user_data                (LibHalContext *ctx, void *user_data);

/* Get user data for the context */
void*          libhal_ctx_get_user_data                (LibHalContext *ctx);

/* Set the callback for when a device is added */
dbus_bool_t    libhal_ctx_set_device_added             (LibHalContext *ctx, LibHalDeviceAdded callback);

/* Set the callback for when a device is removed */
dbus_bool_t    libhal_ctx_set_device_removed           (LibHalContext *ctx, LibHalDeviceRemoved callback);

/* Set the callback for when a device gains a new capability */
dbus_bool_t    libhal_ctx_set_device_new_capability    (LibHalContext *ctx, LibHalDeviceNewCapability callback);

/* Set the callback for when a device loses a capability */
dbus_bool_t    libhal_ctx_set_device_lost_capability   (LibHalContext *ctx, LibHalDeviceLostCapability callback);

/* Set the callback for when a property is modified on a device */
dbus_bool_t    libhal_ctx_set_device_property_modified (LibHalContext *ctx, LibHalDevicePropertyModified callback);

/* Set the callback for when a device emits a condition */
dbus_bool_t    libhal_ctx_set_device_condition         (LibHalContext *ctx, LibHalDeviceCondition callback);

/* Initialize the connection to hald */
dbus_bool_t    libhal_ctx_init                         (LibHalContext *ctx, DBusError *error);

/* Shut down a connection to hald */
dbus_bool_t    libhal_ctx_shutdown                     (LibHalContext *ctx, DBusError *error);

/* Free a LibHalContext resource */
dbus_bool_t    libhal_ctx_free                         (LibHalContext *ctx);

/* Create an already initialized connection to hald */
LibHalContext *libhal_ctx_init_direct                  (DBusError *error);

/* Get all devices in the Global Device List (GDL). */
char        **libhal_get_all_devices (LibHalContext *ctx, int *num_devices, DBusError *error);

/* Determine if a device exists. */
dbus_bool_t   libhal_device_exists   (LibHalContext *ctx, const char *udi,  DBusError *error);

/* Print a device to stdout; useful for debugging. */
dbus_bool_t   libhal_device_print    (LibHalContext *ctx, const char *udi,  DBusError *error);

/* Determine if a property on a device exists. */
dbus_bool_t libhal_device_property_exists (LibHalContext *ctx, 
					   const char *udi,
					   const char *key,
					   DBusError *error);

/* Get the value of a property of type string. */
char *libhal_device_get_property_string (LibHalContext *ctx, 
					 const char *udi,
					 const char *key,
					 DBusError *error);

/* Get the value of a property of type signed integer. */
dbus_int32_t libhal_device_get_property_int (LibHalContext *ctx, 
					     const char *udi,
					     const char *key,
					     DBusError *error);

/* Get the value of a property of type unsigned integer. */
dbus_uint64_t libhal_device_get_property_uint64 (LibHalContext *ctx, 
						 const char *udi,
						 const char *key,
						 DBusError *error);

/* Get the value of a property of type double. */
double libhal_device_get_property_double (LibHalContext *ctx, 
					  const char *udi,
					  const char *key,
					  DBusError *error);

/* Get the value of a property of type bool. */
dbus_bool_t libhal_device_get_property_bool (LibHalContext *ctx, 
					     const char *udi,
					     const char *key,
					     DBusError *error);

/* Get the value of a property of type string list. */
char **libhal_device_get_property_strlist (LibHalContext *ctx, 
					   const char *udi, 
					   const char *key,
					   DBusError *error);

/* Set a property of type string. */
dbus_bool_t libhal_device_set_property_string (LibHalContext *ctx, 
					       const char *udi,
					       const char *key,
					       const char *value,
					       DBusError *error);

/* Set a property of type signed integer. */
dbus_bool_t libhal_device_set_property_int (LibHalContext *ctx, 
					    const char *udi,
					    const char *key,
					    dbus_int32_t value,
					    DBusError *error);

/* Set a property of type unsigned integer. */
dbus_bool_t libhal_device_set_property_uint64 (LibHalContext *ctx, 
					       const char *udi,
					       const char *key,
					       dbus_uint64_t value,
					       DBusError *error);

/* Set a property of type double. */
dbus_bool_t libhal_device_set_property_double (LibHalContext *ctx, 
					       const char *udi,
					       const char *key,
					       double value,
					       DBusError *error);

/* Set a property of type bool. */
dbus_bool_t libhal_device_set_property_bool (LibHalContext *ctx, 
					     const char *udi,
					     const char *key,
					     dbus_bool_t value,
					     DBusError *error);

/* Append to a property of type strlist. */
dbus_bool_t libhal_device_property_strlist_append (LibHalContext *ctx, 
						   const char *udi,
						   const char *key,
						   const char *value,
						   DBusError *error);

/* Prepend to a property of type strlist. */
dbus_bool_t libhal_device_property_strlist_prepend (LibHalContext *ctx, 
						    const char *udi,
						    const char *key,
						    const char *value,
						    DBusError *error);

/* Remove a specified string from a property of type strlist. */
dbus_bool_t libhal_device_property_strlist_remove_index (LibHalContext *ctx, 
							 const char *udi,
							 const char *key,
							 unsigned int idx,
							 DBusError *error);

/* Remove a specified string from a property of type strlist. */
dbus_bool_t libhal_device_property_strlist_remove (LibHalContext *ctx, 
						   const char *udi,
						   const char *key,
						   const char *value,
						   DBusError *error);

/* Remove a property. */
dbus_bool_t libhal_device_remove_property (LibHalContext *ctx, 
					   const char *udi,
					   const char *key,
					   DBusError *error);

/* Query a property type of a device. */
LibHalPropertyType libhal_device_get_property_type (LibHalContext *ctx, 
						    const char *udi,
						    const char *key,
						    DBusError *error);

struct LibHalChangeSet_s;
typedef struct LibHalChangeSet_s LibHalChangeSet;

LibHalChangeSet *libhal_device_new_changeset (const char *udi);

dbus_bool_t libhal_changeset_set_property_string (LibHalChangeSet *changeset,
						  const char *key,
						  const char *value);

dbus_bool_t libhal_changeset_set_property_int (LibHalChangeSet *changeset,
					       const char *key,
					       dbus_int32_t value);

dbus_bool_t libhal_changeset_set_property_uint64 (LibHalChangeSet *changeset,
						  const char *key,
						  dbus_uint64_t value);

dbus_bool_t libhal_changeset_set_property_double (LibHalChangeSet *changeset,
						  const char *key,
						  double value);

dbus_bool_t libhal_changeset_set_property_bool (LibHalChangeSet *changeset,
						const char *key,
						dbus_bool_t value);

dbus_bool_t libhal_changeset_set_property_strlist (LibHalChangeSet *changeset,
						   const char *key,
						   const char **value);

dbus_bool_t libhal_device_commit_changeset (LibHalContext *ctx,
					    LibHalChangeSet *changeset,
					    DBusError *error);

void libhal_device_free_changeset (LibHalChangeSet *changeset);


struct LibHalProperty_s;
typedef struct LibHalProperty_s LibHalProperty;

struct LibHalPropertySet_s;
typedef struct LibHalPropertySet_s LibHalPropertySet;


/* Retrieve all the properties on a device. */
LibHalPropertySet *libhal_device_get_all_properties (LibHalContext *ctx, 
						     const char *udi,
						     DBusError *error);

/* Free a property set earlier obtained with libhal_device_get_all_properties(). */
void libhal_free_property_set (LibHalPropertySet *set);

/* Get the number of properties in a property set. */
unsigned int libhal_property_set_get_num_elems (LibHalPropertySet *set);

/* Get type of property. */
LibHalPropertyType libhal_ps_get_type (const LibHalPropertySet *set, const char *key);

/* Get the value of a property of type string. */
const char *libhal_ps_get_string  (const LibHalPropertySet *set, const char *key);

/* Get the value of a property of type signed integer. */
dbus_int32_t libhal_ps_get_int32 (const LibHalPropertySet *set, const char *key);

/* Get the value of a property of type unsigned integer. */
dbus_uint64_t libhal_ps_get_uint64 (const LibHalPropertySet *set, const char *key);

/* Get the value of a property of type double. */
double libhal_ps_get_double (const LibHalPropertySet *set, const char *key);

/* Get the value of a property of type bool. */
dbus_bool_t libhal_ps_get_bool (const LibHalPropertySet *set, const char *key);

/* Get the value of a property of type string list. */
const char * const *libhal_ps_get_strlist (const LibHalPropertySet *set, const char *key);


/** 
 * LibHalPropertySetIterator: 
 * 
 * Iterator for inspecting all properties. Do not access any members;
 * use the libhal_psi_* family of functions instead.
 */
struct LibHalPropertySetIterator_s {
	LibHalPropertySet *set;    /**< Property set we are iterating over */
	unsigned int idx;          /**< Index into current element */
	LibHalProperty *cur_prop;  /**< Current property being visited */
	void *reservered0;         /**< Reserved for future use */
	void *reservered1;         /**< Reserved for future use */
};


typedef struct LibHalPropertySetIterator_s LibHalPropertySetIterator;

/* Initialize a property set iterator. */
void libhal_psi_init (LibHalPropertySetIterator *iter, LibHalPropertySet *set);

/* Determine whether there are more properties to iterate over */
dbus_bool_t libhal_psi_has_more (LibHalPropertySetIterator *iter);

/* Advance iterator to next property. */
void libhal_psi_next (LibHalPropertySetIterator *iter);

/* Get type of property. */
LibHalPropertyType libhal_psi_get_type (LibHalPropertySetIterator *iter);

/* Get the key of a property. */
char *libhal_psi_get_key (LibHalPropertySetIterator *iter);

/* Get the value of a property of type string. */
char *libhal_psi_get_string (LibHalPropertySetIterator *iter);

/* Get the value of a property of type signed integer. */
dbus_int32_t libhal_psi_get_int (LibHalPropertySetIterator *iter);

/* Get the value of a property of type unsigned integer. */
dbus_uint64_t libhal_psi_get_uint64 (LibHalPropertySetIterator *iter);

/* Get the value of a property of type double. */
double libhal_psi_get_double (LibHalPropertySetIterator *iter);

/* Get the value of a property of type bool. */
dbus_bool_t libhal_psi_get_bool (LibHalPropertySetIterator *iter);

/* Get the value of a property of type string list. */
char **libhal_psi_get_strlist (LibHalPropertySetIterator *iter);

/* Get the length of an array of strings */
unsigned int libhal_string_array_length (char **str_array);

/* Frees a NULL-terminated array of strings. If passed NULL, does nothing. */
void libhal_free_string_array (char **str_array);

/* Frees a nul-terminated string */
void libhal_free_string (char *str);

/* Create a new device object which will be hidden from applications
 * until the CommitToGdl(), ie. libhal_device_commit_to_gdl(), method is called.
 */
char *libhal_new_device (LibHalContext *ctx, DBusError *error);

/* When a hidden device has been built using the NewDevice method, ie.
 * libhal_new_device(), and the org.freedesktop.Hal.Device interface
 * this function will commit it to the global device list. 
 */
dbus_bool_t libhal_device_commit_to_gdl (LibHalContext *ctx,
					 const char *temp_udi,
					 const char *udi,
					 DBusError *error);

/* This method can be invoked when a device is removed. The HAL daemon
 * will shut down the device. Note that the device may still be in the device
 * list if the Persistent property is set to true. 
 */
dbus_bool_t libhal_remove_device (LibHalContext *ctx, 
					const char *udi,
					DBusError *error);

/* Merge properties from one device to another. */
dbus_bool_t libhal_merge_properties (LibHalContext *ctx,
					   const char *target_udi,
					   const char *source_udi,
					   DBusError *error);

/* Check a set of properties for two devices matches. */
dbus_bool_t libhal_device_matches (LibHalContext *ctx,
					 const char *udi1,
					 const char *udi2,
					 const char *property_namespace,
					 DBusError *error);

/* Find a device in the GDL where a single string property matches a
 * given value.
 */
char **libhal_manager_find_device_string_match (LibHalContext *ctx,
						const char *key,
						const char *value,
						int *num_devices,
						DBusError *error);

/* Assign a capability to a device. */
dbus_bool_t libhal_device_add_capability (LibHalContext *ctx,
					  const char *udi,
					  const char *capability,
					  DBusError *error);

/* Check if a device has a capability. The result is undefined if the
 * device doesn't exist.
 */
dbus_bool_t libhal_device_query_capability (LibHalContext *ctx,
					    const char *udi,
					    const char *capability,
					    DBusError *error);

/* Find devices with a given capability. */
char **libhal_find_device_by_capability (LibHalContext *ctx,
					 const char *capability,
					 int *num_devices,
					 DBusError *error);

/* Watch all devices, ie. the device_property_changed callback is
 * invoked when the properties on any device changes.
 */
dbus_bool_t libhal_device_property_watch_all (LibHalContext *ctx,
					      DBusError *error);

/* Add a watch on a device, so the device_property_changed callback is
 * invoked when the properties on the given device changes.
 */
dbus_bool_t libhal_device_add_property_watch (LibHalContext *ctx, 
					      const char *udi,
					      DBusError *error);

/* Remove a watch on a device */
dbus_bool_t libhal_device_remove_property_watch (LibHalContext *ctx, 
						 const char *udi,
						 DBusError *error);

/* Take an advisory lock on the device. */
dbus_bool_t libhal_device_lock (LibHalContext *ctx,
				const char *udi,
				const char *reason_to_lock,
				char **reason_why_locked,
				DBusError *error);

/* Release an advisory lock on the device. */
dbus_bool_t libhal_device_unlock (LibHalContext *ctx,
				  const char *udi,
				  DBusError *error);

dbus_bool_t libhal_device_rescan (LibHalContext *ctx,
				  const char *udi,
				  DBusError *error);

dbus_bool_t libhal_device_reprobe (LibHalContext *ctx,
				   const char *udi,
				   DBusError *error);

/* Emit a condition from a device (for hald helpers only) */
dbus_bool_t libhal_device_emit_condition (LibHalContext *ctx,
					  const char *udi,
					  const char *condition_name,
					  const char *condition_details,
					  DBusError *error);

/* Claim an interface for a device (for hald helpers only) */
dbus_bool_t libhal_device_claim_interface (LibHalContext *ctx,
					   const char *udi,
					   const char *interface_name,
					   const char *introspection_xml,
					   DBusError *error);

/* hald waits for all addons to call this function before announcing the addon (for hald helpers only) */
dbus_bool_t libhal_device_addon_is_ready (LibHalContext *ctx, const char *udi, DBusError *error);


#if defined(__cplusplus)
}
#endif

#endif /* LIBHAL_H */
