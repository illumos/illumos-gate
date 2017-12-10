/******************************************************************************
 *
 * Description
 * mpapi.c - Implements Multipath Management API Version 1.0 
 *
 * License:
 *  The contents of this file are subject to the SNIA Public License
 *  Version 1.1 (the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *
 *  http://mp-mgmt-api.sourceforge.net
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *  the License for the specific language governing rights and limitations
 *  under the License.
 *
 * The Original Code is  SNIA iSCSI Management API and Multipath Management
 *	API header files.
 *
 * The Initial Developer of the Original Code is:
 *	Benjamin F. Kuo Troika Networks, Inc. (benk@troikanetworks.com)
 *	David Dillard	VERITAS Software(david.dillard@veritas.com)
 *	Jeff Ding 	Adaptec, Inc. (jding@corp.adaptec.com)
 *      Hyon Kim        Sun Microsystems(hyon.kim@sun.com)
 *
 * Contributor(s):
 *	Paul von Behren Sun Microsystems(paul.vonbehren@sun.com)
 *
 ******************************************************************************
 *
 *   Changes:
 *  1/15/2005	Implemented SNIA MP API specification 1.0 
 *  10/11/2005
 * 		- License location was specified in the header comment.
 *  	    	- validate_object() routine was updated per the latest
 *		  specification.
 *  		- is_zero_oid() routine was added.
 *  		- MP_GetObjectType() was updated with validate_object().
 *  		- pplist argument checking added in MP_GetMultipathLus().
 *  		- Corrected typo in MP_GetTaregetPortGroupProperties()
 *  		- MP_RegisterForObjectPropertyChanges() was updated with
 *		  is_zero_oid() routine.		
 *  		- MP_DeregisterForObjectPropertyChanges() was updated with
 *		  is_zero_oid() routine.		
 *		- MP_RegisterForObjectVisibilityChanges() was updated with
 *		  is_zero_oid() routine.		
 *		- MP_DeregisterForObjectVisibilityChanges() was updated with
 *		  is_zero_oid() routine.		
 *  		- Added stat() check in MP_RegisterPlugin() to validate the
 *		  the given plugin file name.
 *  		- Made MP_DeregisterPlugin() return MP_STATUS_UNKNOWN_FN
 *		  to mach the specification description.
 ******************************************************************************
 */

#include <sys/sem.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include "mpapi.h"
#include "mpapi-sun.h"
#include "mpapi-plugin.h"

#define LIBRARY_SUPPORTED_MP_VERSION	1
#define LIBRARY_IMPLEMENTATION_VERSION	L"1.0.0"
#define LIBRARY_VENDOR			L"Sun Microsystems Inc."

#define LIBRARY_FILE_NAME               "libMPAPI.so"


MPPLUGININFO_T	plugintable[MP_MAX_NUM_PLUGINS];
pthread_mutex_t mp_lib_mutex = PTHREAD_MUTEX_INITIALIZER;

static int	number_of_plugins = -1;


void InitLibrary();
void ExitLibrary();
static int lock_register(int fd, int cmd, int type, off_t offset, int whence,
	    off_t len);
static int search_line(MP_CHAR *buf, size_t buflen, MP_CHAR *srch_id,
	    size_t id_len, int *write_offset, int *bytes_left);
static int is_zero_oid(MP_OID);

/**
 ******************************************************************************
 *
 * Validate the oid.
 *
 * - Return MP_STATUS_OBJECT_NOT_FOUND when no plugin is found or the ownerId 
 *      of input OID is not found.
 * - Return MP_STATUS_INVALID_OBJECT_TYPE when no plugin is found or
 *      the type of input OID is not one of legitimate types defined SNIA 
 *      Multipath Management spec.
 * - Return MP_STATUS_INVALID_PARAMETER when the type of input OID is
 *	legitimate but its object type doesn't match with the object type 
 *      argument.
 * - Otherwise return MP_STATUS_SUCCESS.
 *
 ******************************************************************************
 */
MP_STATUS validate_object(MP_OID obj, MP_OBJECT_TYPE objType,
    MP_UINT32 flag)
{

    if ((number_of_plugins == 0) ||
	(obj.ownerId > number_of_plugins || obj.ownerId <= 0)) {
	return (MP_STATUS_OBJECT_NOT_FOUND);
    } else if (obj.objectType < 0 || obj.objectType > MP_OBJECT_TYPE_MAX) {
	return (MP_STATUS_INVALID_OBJECT_TYPE);
    } else if (obj.objectType == MP_OBJECT_TYPE_PLUGIN) {
	if (obj.objectSequenceNumber != 0) {
	    return (MP_STATUS_OBJECT_NOT_FOUND);
	}
    }

    if (flag == MP_OBJECT_TYPE_MATCH) {
    	if (obj.objectType != objType) {
	    return (MP_STATUS_INVALID_PARAMETER);
        }
    }
    return (MP_STATUS_SUCCESS);
}

/**
 ******************************************************************************
 *
 * Check if an oid is ZERO_OID or not.
 *
 * - Return 1 if the input OID is ZERO_OID 
 *
 * - Return 0 if not.
 *
 ******************************************************************************
 */
static int is_zero_oid(MP_OID oid)
{

    if ((oid.objectType != MP_OBJECT_TYPE_UNKNOWN) || (oid.ownerId != 0) ||
	(oid.objectSequenceNumber != 0)) {
	return (0);
    }

    return (1);
}

/**
 ******************************************************************************
 *
 * Initialize by loading plugin libraries and calling Initialize routine.
 * Note: The build of libMPAPI.so should include a linker option to make this
 *	 routine executed when it is loaded.
 *
 * - This routine bypasses a plugin library if it is not found.
 * - The implementation of this routine is based on configuration file
 *   /etc/mpapi.conf that contains a list of plugin libraries.
 *
 ******************************************************************************
 */
void InitLibrary()
{
	FILE *mpconf;		
	int fd_mpconf;
	MP_WCHAR fullline[MAX_LINE_SIZE]; /* line read in from mpapi.conf */
	MP_WCHAR name[MAX_NAME_SIZE]; 	/* Read in from file mpapi.conf */
	char path[MAX_NAME_SIZE]; 	/* Read in from file mpapi.conf */
	char systemPath[MAX_NAME_SIZE], mpConfFilePath[MAX_NAME_SIZE];
	MP_WCHAR *charPtr;
	MP_WCHAR *sol;
	struct stat	stat_buf;

	MP_UINT32 i = 0;	/* index for plugin table */

	if(number_of_plugins != -1) {
		return;
	}

	(void) pthread_mutex_lock(&mp_lib_mutex);

	number_of_plugins = 0;

	/* Open configuration file from known location */
	strncpy(mpConfFilePath, "/etc/mpapi.conf", MAX_NAME_SIZE);

	if ((fd_mpconf = open(mpConfFilePath, O_RDONLY)) < 0) {
		(void) pthread_mutex_unlock(&mp_lib_mutex);
		return;
	}
	    
	if (lock_register(fd_mpconf, F_SETLKW, F_RDLCK, 0, SEEK_SET, 0) < 0) {
		close(fd_mpconf);
		(void) pthread_mutex_unlock(&mp_lib_mutex);
		return;
	}

	if ((mpconf = fdopen(fd_mpconf, "r")) == NULL) {
		lock_register(fd_mpconf, F_SETLK, F_UNLCK, 0, SEEK_SET, 0);
		close(fd_mpconf);
		(void) pthread_mutex_unlock(&mp_lib_mutex);
		return;
	}

	/* Read in each line and load library */
	while ((mpconf != NULL) &&
	    (charPtr = fgetws(fullline, MAX_LINE_SIZE, mpconf))) {
	    if ((*charPtr != L'#') && (*charPtr != L'\n')) {
		/* Take out the '\n' */
		if ((charPtr = wcschr(fullline, L'\n')) != NULL)
		    *charPtr = L'\0';

		charPtr = fullline;
		/* remove leading blank or taps. */
		while ((fullline[0] == L' ') || (fullline[0] == L'\t'))
			charPtr++;

		sol = charPtr;

		/*
		 * look for first tab or space. 
		 */
		if ((charPtr = wcschr(fullline, L'\t')) == NULL)
		    charPtr = wcschr(fullline, L' ');

		/* Set Null termination for library name if found */
		if (charPtr != NULL) {
		    *charPtr++ = L'\0';
		    wcsncpy(name, sol, MAX_NAME_SIZE);
			/* Skip space and tab until the next character found */
		    while ((*charPtr == L' ') || (*charPtr == L'\t'))
			charPtr++;
		} else {
		    continue;	/* May be invalid entry */
		}

		/* Copy library name and path */
		wcstombs(path, charPtr, MAX_NAME_SIZE);

		/*
		 * Continue to the next line if library name or path is
		 * invalid 
		 */
		if ((wcslen(name) == 0) ||
			(strlen(path) == 0))
		    continue;

		/* Load the plugin now */
		if (stat(path, &stat_buf) != -1) {
		    plugintable[i].hdlPlugin = dlopen(path, RTLD_LAZY);
		} else {
		    continue;
		}

		if (plugintable[i].hdlPlugin != NULL) {
		    InitializeFn PassFunc;

                    wcsncpy(plugintable[i].pluginName,
                        name, MAX_NAME_SIZE);
                    strncpy(plugintable[i].pluginPath,
                        path, MAX_NAME_SIZE);

		    plugintable[i].ownerId = i + 1;

		    PassFunc = (InitializeFn)
			 dlsym(plugintable[i].hdlPlugin, "Initialize");
		    if (PassFunc != NULL) {
			(void) PassFunc(plugintable[i].ownerId);
		    }

		    i++;
		}
	    }
	}

	if (lock_register(fd_mpconf, F_SETLK, F_UNLCK, 0, SEEK_SET, 0) < 0) {
	    fclose(mpconf);
	    close(fd_mpconf);
	    (void) pthread_mutex_unlock(&mp_lib_mutex);
	    return;
	}
	fclose(mpconf);
	close(fd_mpconf);

	number_of_plugins = i;
	(void) pthread_mutex_unlock(&mp_lib_mutex);
}

/**
 ******************************************************************************
 *
 * Exit by calling Terminate routine of plugin libraries.
 *
 * Note: The build of libMPAPI.so should include a linker option to make this
 *	 routine executed when it is unloaded.
 *
 ******************************************************************************
 */
void ExitLibrary()
{
    MP_UINT32 i, j;

    if(number_of_plugins == -1)
        return;

    (void) pthread_mutex_lock(&mp_lib_mutex);
    for (i = 0; i < number_of_plugins; i++) {
        if (plugintable[i].hdlPlugin != NULL) {
        TerminateFn ExitPassFunc;

        ExitPassFunc = (TerminateFn)
            dlsym(plugintable[i].hdlPlugin, "Terminate");

        if (ExitPassFunc != NULL) {
            ExitPassFunc();
        }

        /* Unload plugin from memory */
        dlclose(plugintable[i].hdlPlugin);
        }
    }

    number_of_plugins = -1;

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    (void) pthread_mutex_destroy(&mp_lib_mutex);
}

/**
 ******************************************************************************
 *
 * Gets the properties of the MP API library that is being used.
 *
 * @param pProps
 *  A pointer to an @ref MP_LIBRARY_PROPERTIES structure allocated by
 *  the caller.  On successful return this structure will contain the
 *  properties of the MP library.
 *
 * @return An MP_STATUS indicating if the operation was successful or
 *  if an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *  Returned if the library properties were successfully returned.
 *
 * @retval MP_STATUS_INVALID_PARAMETER Returned if @a pProps is NULL or
 *  specifies a memory area to which data cannot be written.
 *
 ******************************************************************************
 */
MP_STATUS MP_GetLibraryProperties(
    MP_LIBRARY_PROPERTIES *pProps)
{
    char mpPath[MAX_NAME_SIZE];

    if(pProps == NULL) {
        return MP_STATUS_INVALID_PARAMETER;
    }

    /* Fill in properties */
    if (mbstowcs(pProps->buildTime, BUILD_TIME, 256) !=
	strlen(BUILD_TIME)) {
	return (MP_STATUS_INVALID_PARAMETER);
    }
    pProps->supportedMpVersion = LIBRARY_SUPPORTED_MP_VERSION;

    wcsncpy(pProps->implementationVersion,
	LIBRARY_IMPLEMENTATION_VERSION, MAX_NAME_SIZE);
    wcsncpy(pProps->vendor, LIBRARY_VENDOR, MAX_NAME_SIZE);

    snprintf(pProps->fileName, MAX_NAME_SIZE, "%s",
	LIBRARY_FILE_NAME);

    return MP_STATUS_SUCCESS;
}


/**
 ******************************************************************************
 *
 * Gets a list of the object IDs of all currently loaded plugins.
 *
 * @param ppList A pointer to a pointer to an @ref MP_OID_LIST.  On successful
 *  return this will contain a pointer to an @ref MP_OID_LIST
 *  which contains the object IDs of all of the plugins currently loaded
 *  by the library.
 * @return An MP_STATUS indicating if the operation was successful or if
 * an error
 *              occurred.
 * @retval MP_SUCCESS Returned if the plugin ID list was successfully returned.
 * @retval MP_STATUS_INVALID_PARAMETER Returned if @a ppList is NULL or
 * specifies a memory area to which data cannot be written.
 *
 ******************************************************************************
 */
MP_STATUS MP_GetPluginOidList(
    MP_OID_LIST **ppList)
{
    MP_UINT32  i;

    if (ppList == NULL)
        return (MP_STATUS_INVALID_PARAMETER);

    (void) pthread_mutex_lock(&mp_lib_mutex);

    if (number_of_plugins == 0) {
        *ppList = (MP_OID_LIST*)calloc(1, sizeof(MP_OID_LIST));
    } else {
        *ppList = (MP_OID_LIST*)calloc(1,
        sizeof(MP_OID_LIST) + (number_of_plugins - 1)* sizeof(MP_OID) );
    }

    if ((*ppList) == NULL) {
    	(void) pthread_mutex_unlock(&mp_lib_mutex);
        return (MP_STATUS_INSUFFICIENT_MEMORY);
    }

    (*ppList)->oidCount = number_of_plugins;

    if (number_of_plugins != 0) {
        for (i = 0; i < number_of_plugins; i++) {
        (*ppList)->oids[i].objectType = MP_OBJECT_TYPE_PLUGIN;
        (*ppList)->oids[i].ownerId = plugintable[i].ownerId;
        (*ppList)->oids[i].objectSequenceNumber = 0;
        }
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return MP_STATUS_SUCCESS;
}

/**
 *******************************************************************************
 *
 * Gets the properties of the specified vendor plugin.
 *
 * @param  oid
 *         The ID of the plugin whose properties are being retrieved.
 *
 * @param  pProps
 *         A pointer to an @ref MP_PLUGIN_PROPERTIES structure allocated by
 *         the caller.  On successful return this will contain the properties
 *         of the plugin specified by pluginOid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if an
 *         error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned if the plugin properties were successfully returned.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *         Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *         Returned if oid has an owner that is not currently known to
 *     the system.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *         Returned if 'pProps' is NULL or specifies a memory area to
 *         which data cannot be written.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetPluginProperties(
    MP_OID pluginOid,
    MP_PLUGIN_PROPERTIES *pProps)
{
    MP_GetPluginPropertiesPluginFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if(pProps == NULL)
        return (MP_STATUS_INVALID_PARAMETER);

    if ((status = validate_object(pluginOid, MP_OBJECT_TYPE_PLUGIN,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = pluginOid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetPluginPropertiesPluginFn)
        dlsym(plugintable[index].hdlPlugin, "MP_GetPluginPropertiesPlugin");

        if (PassFunc != NULL) {
            status = PassFunc(pProps);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return status;
}

/**
 *******************************************************************************
 *
 * Gets the object ID for the plugin associated with the specified object ID.
 *
 * @param  oid
 *         The object ID of an object that has been received from a previous
 *         library call.
 *
 * @param  pPluginOid
 *         A pointer to an MP_OID structure allocated by the caller.  On
 *         successful return this will contain the object ID of the plugin
 *         associated with the object specified by @a objectId.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *          Returned if the associated plugin ID was successfully returned.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid does not specify a plugin that is currently known to
 *     the system.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *          Returned if 'oid' specifies an object not owned by a plugin or
 *     if pPluginOid is NULL or specifies a memory area to which data
 *     cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *         Returned if 'oid' specifies an object with an invalid type.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetAssociatedPluginOid(
    MP_OID objectId,
    MP_OID *pPluginId)
{
    MP_UINT32 i;
    MP_STATUS status;

    if (pPluginId == NULL)
        return (MP_STATUS_INVALID_PARAMETER);

    if ((status = validate_object(objectId, 0, MP_OBJECT_TYPE_ANY)) !=
            MP_STATUS_SUCCESS) {
        return (status);
    }

    pPluginId->objectType = MP_OBJECT_TYPE_PLUGIN;
    pPluginId->ownerId = objectId.ownerId;
    pPluginId->objectSequenceNumber = 0;

    return (MP_STATUS_SUCCESS);
}

/**
 *******************************************************************************
 *
 * Gets the object type of an initialized object ID.
 *
 * @param  oid
 *         The object ID of an object that has been received from a previous
 *         library call.
 *
 * @param  pObjectType
 *         A pointer to an MP_OBJECT_TYPE variable allocated by the caller.
 *         On successful return this will contain the object type of oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or
 *         if an error occurred.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned if oid has an owner that is not currently known to
 *      the system.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetObjectType(
    MP_OID oid,
    MP_OBJECT_TYPE *pObjectType)
{
    MP_STATUS status;

    if (pObjectType == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, 0, MP_OBJECT_TYPE_ANY))
	!= MP_STATUS_SUCCESS) {
        return (status);
    }

    *pObjectType = oid.objectType;
    return MP_STATUS_SUCCESS;
}

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the device product properties
 *       associated with this plugin.
 *
 * @param  oid
 *         The object ID of plugin.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the device
 *      product descriptors associated with the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the device product list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *         Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *         Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetDeviceProductOidList(
    MP_OID oid,
    MP_OID_LIST **ppList)
{
    MP_GetDeviceProductOidListPluginFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (ppList == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetDeviceProductOidListPluginFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetDeviceProductOidListPlugin");
        if (PassFunc != NULL) {
	    status = PassFunc(ppList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return status;
}

/**
 *******************************************************************************
 *
 * Gets the device product properties of the specified plugin oid.
 *
 * @param  oid
 *         The object ID of the plugin.
 *
 * @param  ppProps
 *      A pointer to a pointer to an MP_DEVICE_PRODUCT_PROPERTIES structure
 *      allocated by the caller. On successful return it will contain
 *      a pointer to an MP_DEVICE_PRODUCT_PROPERTIES structure allocated
 *      by the library.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppProps pointer passed as placeholder for holding
 *      the device product properties is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *         Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *         Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetDeviceProductProperties(
        MP_OID oid,
        MP_DEVICE_PRODUCT_PROPERTIES *pProps)
{
    MP_GetDeviceProductPropertiesFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (pProps == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_DEVICE_PRODUCT,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetDeviceProductPropertiesFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetDeviceProductProperties");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, pProps);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return status;
}

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the initiator ports associated
 * with this plugin.
 *
 * @param  oid
 *         The object ID of plugin.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the initiator
 *      ports associated with the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the initiator port list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetInitiatorPortOidList(
        MP_OID oid,
        MP_OID_LIST **ppList)
{
    MP_GetInitiatorPortOidListPluginFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (ppList == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetDeviceProductOidListPluginFn)
        dlsym(plugintable[index].hdlPlugin, "MP_GetInitiatorPortOidListPlugin");

        if (PassFunc != NULL) {
	    status = PassFunc(ppList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets the properties of the specified initiator port.
 *
 * @param  oid
 *         The object ID of the initiator port.
 *
 * @param  pProps
 *      A pointer to an MP_INITIATOR_PORT_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetInitiatorPortProperties(
        MP_OID oid,
        MP_INITIATOR_PORT_PROPERTIES *pProps)
{
    MP_GetInitiatorPortPropertiesFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (pProps == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_INITIATOR_PORT,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetInitiatorPortPropertiesFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetInitiatorPortProperties");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, pProps);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return status;
}

/**
 *******************************************************************************
 *
 * Gets a list of multipath logical units associated to a plugin.
 *
 * @param  oid
 *         The object ID of plugin.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the multipath
 *      logical units associated with the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the multipath logical unit list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetMultipathLus(
        MP_OID oid,
        MP_OID_LIST **ppList)
{
    MP_UINT32 index;
    MP_STATUS status;

    if (ppList == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
	MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_DEVICE_PRODUCT,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
	if (oid.objectType == MP_OBJECT_TYPE_PLUGIN) {
	    MP_GetMultipathLusPluginFn PassFunc;
	    PassFunc = (MP_GetMultipathLusPluginFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_GetMultipathLusPlugin");

	    if (PassFunc != NULL) {
		status = PassFunc(ppList);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else if (oid.objectType == MP_OBJECT_TYPE_DEVICE_PRODUCT) {
	    MP_GetMultipathLusDevProdFn PassFunc;
	    PassFunc = (MP_GetMultipathLusDevProdFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_GetMultipathLusDevProd");

	    if (PassFunc != NULL) {
		status = PassFunc(oid, ppList);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else {
	    status = MP_STATUS_INVALID_PARAMETER;
	}
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}


/**
 *******************************************************************************
 *
 * Gets the properties of the specified logical unit.
 *
 * @param  oid
 *         The object ID of the multipath logical unit.
 *
 * @param  pProps
 *      A pointer to an MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetMPLogicalUnitProperties(
        MP_OID oid,
        MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES *pProps)
{
    MP_GetMPLogicalUnitPropertiesFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (pProps == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetMPLogicalUnitPropertiesFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetMPLogicalUnitProperties");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, pProps);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the path logical units associated
 * with the specified multipath logical unit, initiator port, or target port.
 *
 * @param  oid
 *         The object ID of multipath logical unit, initiator port, or
 *     target port.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the mp path
 *      logical units associated with the specified OID.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the device product list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetAssociatedPathOidList(
        MP_OID oid,
        MP_OID_LIST **ppList)
{
    MP_GetAssociatedPathOidListFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (ppList == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_INITIATOR_PORT,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_TARGET_PORT,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetAssociatedPathOidListFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetAssociatedPathOidList");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, ppList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets the properties of the specified path logical unit.
 *
 * @param  oid
 *         The object ID of the path logical unit.
 *
 * @param  pProps
 *      A pointer to an MP_PATH_LOGICAL_UNIT_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetPathLogicalUnitProperties(
        MP_OID oid,
        MP_PATH_LOGICAL_UNIT_PROPERTIES *pProps)
{
    MP_GetPathLogicalUnitPropertiesFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (pProps == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_PATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetPathLogicalUnitPropertiesFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetPathLogicalUnitProperties");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, pProps);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the target port group associated
 * with the specified multipath logical unit.
 *
 * @param  oid
 *         The object ID of the multiple logical unit.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the target
 *      port group associated with the specified multipath logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the target port group list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 *
 *******************************************************************************
 */
MP_STATUS MP_GetAssociatedTPGOidList(
        MP_OID oid,
        MP_OID_LIST **ppList)
{
    MP_GetAssociatedTPGOidListFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (ppList == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetAssociatedTPGOidListFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetAssociatedTPGOidList");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, ppList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets the properties of the specified target port group.
 *
 * @param  oid
 *         The object ID of the target port group.
 *
 * @param  pProps
 *      A pointer to an MP_TARGET_PORT_GROUP_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetTargetPortGroupProperties(
        MP_OID oid,
        MP_TARGET_PORT_GROUP_PROPERTIES *pProps)
{
    MP_GetTargetPortGroupPropertiesFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (pProps == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_TARGET_PORT_GROUP,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetTargetPortGroupPropertiesFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetTargetPortGroupProperties");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, pProps);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets a list of multipath logical units associated with the specific target
 *  port group.
 *
 * @param  oid
 *         The object ID of the target port group.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the multipath
 *      logical units associated with the specified target port group.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the multipath logical unit list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 *******************************************************************************
 */
MP_STATUS MP_GetMPLuOidListFromTPG(
        MP_OID oid,
        MP_OID_LIST **ppList)
{
    MP_GetMPLuOidListFromTPGFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (ppList == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_TARGET_PORT_GROUP,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetMPLuOidListFromTPGFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetMPLuOidListFromTPG");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, ppList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of all the proprietary load balance
 * algorithms associated with this plugin.
 *
 * @param  oid
 *         The object ID of the plugin.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the proprietary
 *      load balance algorithms associated with the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the proprietary load balance oid list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the API is not supported.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetProprietaryLoadBalanceOidList(
        MP_OID oid,
        MP_OID_LIST **ppList)
{
    MP_GetProprietaryLoadBalanceOidListPluginFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (ppList == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetProprietaryLoadBalanceOidListPluginFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetProprietaryLoadBalanceOidListPlugin");

        if (PassFunc != NULL) {
	    status = PassFunc(ppList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets the properties of the specified load balance properties structure.
 *
 * @param  oid
 *         The object ID of the load balance properties structure.
 *
 * @param  pProps
 *      A pointer to an MP_LOAD_BALANCE_PROPRIETARY_TYPE structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the proprietary load balance algorithm
 *	specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetProprietaryLoadBalanceProperties (
        MP_OID oid,
        MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES *pProps)
{
    MP_GetProprietaryLoadBalancePropertiesFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (pProps == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_PROPRIETARY_LOAD_BALANCE,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetProprietaryLoadBalancePropertiesFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetProprietaryLoadBalanceProperties");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, pProps);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets a list of the object IDs of the target ports in the specified target
 * port group.
 *
 * @param  oid
 *         The object ID of the target port group.
 *
 * @param  ppList
 *      A pointer to a pointer to an MP_OID_LIST structure.
 *      On a successful return, this will contain a pointer to
 *      an MP_OID_LIST that contains the object IDs of all the target ports
 *      associated with the specified target port group.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if ppList pointer passed as placeholder for holding
 *      the multipath logical unit list is found to be invalid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the plugin for the specified oid is not found.
 *
 * @retval MP_STATUS_INSUFFICIENT_MEMORY
 *      Returned when memory allocation failure occurs
 *
 *******************************************************************************
 */
MP_STATUS MP_GetTargetPortOidList(
        MP_OID oid,
        MP_OID_LIST **ppList)
{
    MP_GetTargetPortOidListFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (ppList == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_TARGET_PORT_GROUP,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetTargetPortOidListFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetTargetPortOidList");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, ppList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Gets the properties of the specified target port.
 *
 * @param  oid
 *         The object ID of the target port.
 *
 * @param  pProps
 *      A pointer to an MP_TARGET_PORT_PROPERTIES structure
 *      allocated by the caller. On successful return, this structure
 *      will contain the properties of the port specified by oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pProps is NULL or specifies a memory area to
 *      which data cannot be written.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_GetTargetPortProperties(
        MP_OID oid,
        MP_TARGET_PORT_PROPERTIES *pProps)
{
    MP_GetTargetPortPropertiesFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (pProps == NULL)
        return MP_STATUS_INVALID_PARAMETER;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_TARGET_PORT,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_GetTargetPortPropertiesFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_GetTargetPortProperties");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, pProps);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}


/**
 *******************************************************************************
 *
 * Assign a multipath logical unit to a target port group.
 *
 * @param  tpgOid
 *      An MP_TARGET_PORT_GROUP oid. The target port group currently in
 *      active access state that the administrator would like the LU
 *      assigned to.
 *
 * @param  luOid
 *      An MP_MULTIPATH_LOGICAL_UNIT oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned when luOid is not associated with tpgOid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_AssignLogicalUnitToTPG(
        MP_OID tpgOid,
        MP_OID luOid)
{
    MP_AssignLogicalUnitToTPGFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (luOid.ownerId != tpgOid.ownerId) {
        return (MP_STATUS_INVALID_PARAMETER);
    }

    if ((status = validate_object(tpgOid, MP_OBJECT_TYPE_TARGET_PORT_GROUP,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    if ((status = validate_object(luOid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = tpgOid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_AssignLogicalUnitToTPGFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_AssignLogicalUnitToTPG");

        if (PassFunc != NULL) {
            status = PassFunc(tpgOid, luOid);
        } else {
            status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Manually override the path for a logical unit. The path exclusively used to
 * access the logical unit until cleared.
 *
 * @param  logicalUnitOid
 *      The object ID of the multipath logical unit.
 *
 * @param  pathOid
 *      The object ID of the path logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if the oid of the object is not valid
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_PATH_NONOPERATIONAL
 *          Returned when the driver cannot communicate through selected path.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetOverridePath(
    MP_OID logicalUnitOid,
    MP_OID pathOid)
{
    MP_SetOverridePathFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if ((status = validate_object(logicalUnitOid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }
    if ((status = validate_object(pathOid, MP_OBJECT_TYPE_PATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = pathOid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_SetOverridePathFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_SetOverridePath");

        if (PassFunc != NULL) {
	    status = PassFunc(logicalUnitOid, pathOid);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Cancel a path override and re-enable load balancing.
 *
 * @param  luOid
 *         An MP_MULTIPATH_LOGICAL_UNIT oid.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if MP_MULTIPATH_LOGICAL_UNIT with the luOid is not found.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *          Returned if oid has an owner that is not currently known to
 *      the system.
 *
 *******************************************************************************
 */
MP_STATUS MP_CancelOverridePath(
        MP_OID luOid)
{
    MP_CancelOverridePathFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if ((status = validate_object(luOid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = luOid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_CancelOverridePathFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_CancelOverridePath");

        if (PassFunc != NULL) {
	    status = PassFunc(luOid);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Enables Auto-failback.
 *
 * @param  oid
 *      The oid of the plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *	a valid plugin oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_EnableAutoFailback(
    MP_OID oid)
{
    MP_UINT32 index;
    MP_STATUS status;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
	MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
	if (oid.objectType == MP_OBJECT_TYPE_PLUGIN) {
	    MP_EnableAutoFailbackPluginFn PassFunc;
	    PassFunc = (MP_EnableAutoFailbackPluginFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_EnableAutoFailbackPlugin");

	    if (PassFunc != NULL) {
		status = PassFunc();
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else if (oid.objectType == MP_OBJECT_TYPE_MULTIPATH_LU) {
	    MP_EnableAutoFailbackLuFn PassFunc;
	    PassFunc = (MP_EnableAutoFailbackLuFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_EnableAutoFailbackLu");

	    if (PassFunc != NULL) {
		status = PassFunc(oid);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else {
	    status = MP_STATUS_INVALID_PARAMETER;
	}
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Enables Auto-probing.
 *
 * @param  oid
 *      The oid of the plugin or the multipath logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid plugin oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_EnableAutoProbing(
    MP_OID oid)
{
    MP_UINT32 index;
    MP_STATUS status;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
	MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
	if (oid.objectType == MP_OBJECT_TYPE_PLUGIN) {
	    MP_EnableAutoProbingPluginFn PassFunc;
	    PassFunc = (MP_EnableAutoProbingPluginFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_EnableAutoProbingPlugin");

	    if (PassFunc != NULL) {
		status = PassFunc();
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else if (oid.objectType == MP_OBJECT_TYPE_MULTIPATH_LU) {
	    MP_EnableAutoProbingLuFn PassFunc;
	    PassFunc = (MP_EnableAutoProbingLuFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_EnableAutoProbingLu");

	    if (PassFunc != NULL) {
		status = PassFunc(oid);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else {
	    status = MP_STATUS_INVALID_PARAMETER;
	}
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Disables Auto-failback.
 *
 * @param  oid
 *      The oid of the plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid plugin oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_DisableAutoFailback(
    MP_OID oid)
{
    MP_UINT32 index;
    MP_STATUS status;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
	MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
	if (oid.objectType == MP_OBJECT_TYPE_PLUGIN) {
	    MP_DisableAutoFailbackPluginFn PassFunc;
	    PassFunc = (MP_DisableAutoFailbackPluginFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_DisableAutoFailbackPlugin");

	    if (PassFunc != NULL) {
		status = PassFunc();
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else if (oid.objectType == MP_OBJECT_TYPE_MULTIPATH_LU) {
	    MP_DisableAutoFailbackLuFn PassFunc;
	    PassFunc = (MP_DisableAutoFailbackLuFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_DisableAutoFailbackLu");

	    if (PassFunc != NULL) {
		status = PassFunc(oid);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else {
	    status = MP_STATUS_INVALID_PARAMETER;
	}
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Disables Auto-probing.
 *
 * @param  oid
 *      The oid of the plugin or the multipath logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid plugin oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_DisableAutoProbing(
    MP_OID oid)
{
    MP_UINT32 index;
    MP_STATUS status;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
	MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
	if (oid.objectType == MP_OBJECT_TYPE_PLUGIN) {
	    MP_DisableAutoProbingPluginFn PassFunc;
	    PassFunc = (MP_DisableAutoProbingPluginFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_DisableAutoProbingPlugin");

	    if (PassFunc != NULL) {
		status = PassFunc();
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else if (oid.objectType == MP_OBJECT_TYPE_MULTIPATH_LU) {
	    MP_DisableAutoFailbackLuFn PassFunc;
	    PassFunc = (MP_DisableAutoProbingLuFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_DisableAutoProbingLu");

	    if (PassFunc != NULL) {
		status = PassFunc(oid);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else {
	    status = MP_STATUS_INVALID_PARAMETER;
	}
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Enables a path. This API may cause failover in a logical unit with
 * asymmetric access.
 *
 * @param  oid
 *      The oid of the path.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid path oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_EnablePath(
    MP_OID oid)
{
    MP_EnablePathFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_PATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_EnablePathFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_EnablePath");

        if (PassFunc != NULL) {
	    status = PassFunc(oid);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Disables a path. This API may cause failover in a logical unit with
 * asymmetric access. This API may cause a logical unit to become unavailable.
 *
 * @param  oid
 *      The oid of the path.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if oid is NULL or specifies a memory area that is not
 *      a valid path oid.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_DisablePath(
    MP_OID oid)
{
    MP_DisablePathFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_PATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_DisablePathFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_DisablePath");

        if (PassFunc != NULL) {
	    status = PassFunc(oid);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Set the multipath logical unit s load balancing policy.
 *
 * @param  logicalUnitoid
 *      The object ID of the multipath logical unit.
 *
 * @param  loadBanlance
 *      The desired load balance policy for the specified logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if no MP_MULTIPATH_LOGICAL_UNIT associated with
 *      @ref ligicalUnitrOid is found or invalid MP_LOAD_BALANCE_TYPE is
 *      specified.
 *
 * @retval MP_STATUS_FAILED
 *      Returned when the specified loadBalance type cannot be handled
 *      by the plugin.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetLogicalUnitLoadBalanceType(
    MP_OID logicalUnitOid,
    MP_LOAD_BALANCE_TYPE loadBalance)
{
    MP_SetLogicalUnitLoadBalanceTypeFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if ((status = validate_object(logicalUnitOid,
        MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = logicalUnitOid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_SetLogicalUnitLoadBalanceTypeFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_SetLogicalUnitLoadBalanceType");

        if (PassFunc != NULL) {
	    status = PassFunc(logicalUnitOid, loadBalance);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Set the weight to be assigned to a particular path.
 *
 * @param  pathOid
 *      The object ID of the path logical unit.
 *
 * @param  weight
 *      weight that will be assigned to the path logical unit.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the MP Path specified by the PathOid could not be
 *      found.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the operation failed.
 *
 * @retval MP_STATUS_PATH_NONOPERATIONAL
 *          Returned when the driver cannot communicate through selected path.
 *
 * @retval MP_STATUS_INVALID_WEIGHT
 *          Returned when the weight parameter is greater than the plugin's
 *      maxWeight property.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetPathWeight(
    MP_OID pathOid,
    MP_UINT32 weight)
{
    MP_SetPathWeightFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if ((status = validate_object(pathOid, MP_OBJECT_TYPE_PATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = pathOid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_SetPathWeightFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_SetPathWeight");

        if (PassFunc != NULL) {
	    status = PassFunc(pathOid, weight);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Set the default load balance policy for the plugin.
 *
 * @param  oid
 *      The object ID of the plugin
 *
 * @param  loadBalance
 *      The desired default load balance policy for the specified plugin.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the the plugin specified by @ref oid could not be
 *      found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if the oid of the object is not valid.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned when the specified loadBalance type cannot be handled
 *      by the plugin.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetPluginLoadBalanceType(
    MP_OID oid,
    MP_LOAD_BALANCE_TYPE loadBalance)
{
    MP_SetPluginLoadBalanceTypePluginFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if ((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_SetPluginLoadBalanceTypePluginFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_SetPluginLoadBalanceTypePlugin");

        if (PassFunc != NULL) {
	    status = PassFunc(loadBalance);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Set the failback polling rates. Setting both rates to zero disables polling.
 *
 * @param  pluginOid
 *      The object ID of the plugin or multipath lu.
 *
 * @param  pollingRate
 *      The value to be set in MP_PLUGIN_PROPERTIES currentPollingRate.or
 *	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES pollingRate.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the the plugin specified by @ref oid could not be
 *      found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if one of the polling values is outside the range
 *      supported by the driver.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetFailbackPollingRate(
    MP_OID oid,
    MP_UINT32 pollingRate)
{
    MP_UINT32 index;
    MP_STATUS status;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
	MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
	if (oid.objectType == MP_OBJECT_TYPE_PLUGIN) {
	    MP_SetFailbackPollingRatePluginFn PassFunc;
	    PassFunc = (MP_SetFailbackPollingRatePluginFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_SetFailbackPollingRatePlugin");

	    if (PassFunc != NULL) {
		status = PassFunc(pollingRate);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else if (oid.objectType == MP_OBJECT_TYPE_MULTIPATH_LU) {
	    MP_SetFailbackPollingRateLuFn PassFunc;
	    PassFunc = (MP_SetFailbackPollingRateLuFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_SetFailbackPollingRateLu");

	    if (PassFunc != NULL) {
		status = PassFunc(oid, pollingRate);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else {
	    status = MP_STATUS_INVALID_PARAMETER;
	}
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Set the probing polling rates. Setting both rates to zero disables polling.
 *
 * @param  pluginOid
 *      The object ID of either the plugin or a multipath logical unit.
 *
 * @param  pollingRate
 *      The value to be set in MP_PLUGIN_PROPERTIES current pollingRate or
 *	MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES pollingRate.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the the plugin specified by @ref oid could not be
 *      found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if one of the polling values is outside the range
 *      supported by the driver.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetProbingPollingRate(
    MP_OID    oid,
    MP_UINT32 pollingRate)
{
    MP_UINT32 index;
    MP_STATUS status;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
	MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
	if (oid.objectType == MP_OBJECT_TYPE_PLUGIN) {
	    MP_SetProbingPollingRatePluginFn PassFunc;
	    PassFunc = (MP_SetProbingPollingRatePluginFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_SetProbingPollingRatePlugin");

	    if (PassFunc != NULL) {
		status = PassFunc(pollingRate);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else if (oid.objectType == MP_OBJECT_TYPE_MULTIPATH_LU) {
	    MP_SetProbingPollingRateLuFn PassFunc;
	    PassFunc = (MP_SetProbingPollingRateLuFn)
	    dlsym(plugintable[index].hdlPlugin,
        	"MP_SetProbingPollingRateLu");

	    if (PassFunc != NULL) {
		status = PassFunc(oid, pollingRate);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else {
	    status = MP_STATUS_INVALID_PARAMETER;
	}
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Set proprietary properties in supported object instances.
 *
 * @param  pluginOid
 *      The object ID of MP_LOAD_BALANCE_PROPRIETARY_TYPE, MP_PLUGIN_PROPERTIES
 *	or MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES.
 *
 * @param  count
 *	   The number of valid items in pPropertyList.
 *
 * @param  pPropertyList
 *	   A pointer to an array of property name/value pairs. This array must
 *	   contain the same number of elements as count.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the the plugin specified by @ref oid could not be
 *      found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if one of the polling values is outside the range
 *      supported by the driver.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_SetProprietaryProperties(
    MP_OID    oid,
    MP_UINT32 count,
    MP_PROPRIETARY_PROPERTY *pPropertyList)
{
    MP_SetProprietaryPropertiesFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if (((status = validate_object(oid, MP_OBJECT_TYPE_PLUGIN,
	MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) &&
	((status = validate_object(oid, MP_OBJECT_TYPE_PROPRIETARY_LOAD_BALANCE,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS)) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = oid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_SetProprietaryPropertiesFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_SetProprietaryProperties");

        if (PassFunc != NULL) {
	    status = PassFunc(oid, count, pPropertyList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Set the access state for a list of target port groups. This allows
 * a client to force a failover or failback to a desired set of target port
 * groups.
 *
 * @param  luOid
 *      The object ID of the logical unit where the command is sent.
 *
 * @param  count
 *      The number of valid items in the pTpgStateList.
 *
 * @param  pTpgStateList
 *      A pointer to an array of TPG/access-state values. This array must
 *      contain the same number of elements as @ref count.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_OBJECT_NOT_FOUND
 *      Returned when the MP_MULTIPATH_LOGICAL_UNIT associated with @ref
 *      oid could not be found.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pTpgStateList is null or if one of the TPGs referenced
 *      in the list is not associated with the specified MP logical unit.
 *
 * @retval MP_STATUS_UNSUPPORTED
 *      Returned when the implementation does not support the API
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_ACCESS_STATE_INVALID
 *         Returned if the target device returns a status indicating the caller
 *     is attempting to establish an illegal combination of access states.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if the underlying interface failed the commend for some
 *      reason other than MP_STATUS_ACCESS_STATE_INVALID
 *
 *******************************************************************************
 */
MP_STATUS MP_SetTPGAccess(
    MP_OID luOid,
    MP_UINT32 count,
    MP_TPG_STATE_PAIR *pTpgStateList)
{
    MP_SetTPGAccessFn PassFunc;
    MP_UINT32 index;
    MP_STATUS status;

    if ((status = validate_object(luOid, MP_OBJECT_TYPE_MULTIPATH_LU,
        MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
        return (status);
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    index = luOid.ownerId - 1;
    if (plugintable[index].hdlPlugin != NULL) {
        PassFunc = (MP_SetTPGAccessFn)
        dlsym(plugintable[index].hdlPlugin,
        "MP_SetTPGAccess");

        if (PassFunc != NULL) {
	    status = PassFunc(luOid, count, pTpgStateList);
        } else {
	    status = MP_STATUS_UNSUPPORTED;
        }
    } else {
        status = MP_STATUS_FAILED;
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Registers a client function that is to be called
 * whenever the property of an an object changes.
 *
 * @param  pClientFn,
 *      A pointer to an MP_OBJECT_PROPERTY_FN function defined by the
 *      client. On successful return this function will be called to
 *      inform the client of objects that have had one or more properties
 *      change.
 *
 * @param  objectType
 *      The type of object the client wishes to deregister for
 *      property change callbacks. If null, then all objects types are
 *      deregistered.
 *
 * @param  pCallerData
 *      A pointer that is passed to the callback routine with each event.
 *      This may be used by the caller to correlate the event to source of
 *      the registration.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pClientFn is NULL or specifies a memory area
 *      that is not executable.
 *
 * @retval MP_STATUS_FN_REPLACED
 *      Returned when an existing client function is replaced with the one
 *      specified in pClientFn.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_RegisterForObjectPropertyChanges(
    MP_OBJECT_PROPERTY_FN pClientFn,
    MP_OBJECT_TYPE objectType,
    void *pCallerData,
    MP_OID pluginOid)
{
    MP_RegisterForObjectPropertyChangesPluginFn PassFunc;
    MP_UINT32 i;
    MP_UINT32 index;
    MP_STATUS status;

    if (pClientFn == NULL) {
        return (MP_STATUS_INVALID_PARAMETER);
    }

    if (objectType > MP_OBJECT_TYPE_MAX) {
        return (MP_STATUS_INVALID_OBJECT_TYPE);
    }

    if (!(is_zero_oid(pluginOid))) {
	if ((status = validate_object(pluginOid, MP_OBJECT_TYPE_PLUGIN,
	    MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
	    return (status);
	}
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    if (is_zero_oid(pluginOid)) {
	for (i = 0; i < number_of_plugins; i++) {
	    if (plugintable[i].hdlPlugin != NULL) {
		PassFunc = (MP_RegisterForObjectPropertyChangesPluginFn)
		dlsym(plugintable[i].hdlPlugin,
		"MP_RegisterForObjectPropertyChangesPlugin");
	    }

	    if (PassFunc != NULL) {
		status =
		     PassFunc(pClientFn, objectType, pCallerData);
		/* ignore an error and continue */
	    }
	}
    } else {
	index = pluginOid.ownerId - 1;
	if (plugintable[index].hdlPlugin != NULL) {
		PassFunc = (MP_RegisterForObjectPropertyChangesPluginFn)
		dlsym(plugintable[index].hdlPlugin,
		"MP_RegisterForObjectPropertyChangesPlugin");
	}

	if (PassFunc != NULL) {
	    status = PassFunc(pClientFn, objectType, pCallerData);
	}
    }
    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Deregisters a previously registered client function that is to be invoked
 * whenever an object's property changes.
 *
 * @param  pClientFn,
 *      A pointer to an MP_OBJECT_PROPERTY_FN function defined by the
 *      client that was previously registered using
 *      the MP_RegisterForObjectPropertyChanges API. On successful return
 *      this function will no longer be called to inform the client of
 *      object property changes.
 *
 * @param  objectType
 *      The type of object the client wishes to deregister for
 *      property change callbacks. If null, then all objects types are
 *      deregistered.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pClientFn is NULL or specifies a memory area
 *      that is not executable.
 *
 * @retval MP_STATUS_UNKNOWN_FN
 *      Returned if pClientFn is not the same as the previously registered
 *      function.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if oid does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if pClientFn deregistration is not possible at this time.
 *
 *******************************************************************************
 */
MP_STATUS MP_DeregisterForObjectPropertyChanges(
    MP_OBJECT_PROPERTY_FN pClientFn,
    MP_OBJECT_TYPE objectType,
    MP_OID pluginOid)
{
    MP_DeregisterForObjectPropertyChangesPluginFn PassFunc;
    MP_UINT32 i;
    MP_UINT32 index;
    MP_STATUS status;

    if (pClientFn == NULL) {
        return (MP_STATUS_INVALID_PARAMETER);
    }

    if (objectType > MP_OBJECT_TYPE_MAX) {
        return (MP_STATUS_INVALID_OBJECT_TYPE);
    }

    if (!(is_zero_oid(pluginOid))) {
	if ((status = validate_object(pluginOid, MP_OBJECT_TYPE_PLUGIN,
	    MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
	    return (status);
	}
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    if (is_zero_oid(pluginOid)) {
	for (i = 0; i < number_of_plugins; i++) {
	    if (plugintable[i].hdlPlugin != NULL) {
		PassFunc = (MP_DeregisterForObjectPropertyChangesPluginFn)
		dlsym(plugintable[i].hdlPlugin,
		"MP_DeregisterForObjectPropertyChangesPlugin");
	    }

	    if (PassFunc != NULL) {
		status = PassFunc(pClientFn, objectType);
	    }
	}
    } else {
	index = pluginOid.ownerId - 1;
	if (plugintable[index].hdlPlugin != NULL) {
		PassFunc = (MP_DeregisterForObjectPropertyChangesPluginFn)
		dlsym(plugintable[index].hdlPlugin,
		"MP_DeregisterForObjectPropertyChangesPlugin");
	}

	if (PassFunc != NULL) {
	    status = PassFunc(pClientFn, objectType);
	}
    }
    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Registers a client function that is to be called
 * whenever a high level object appears or disappears.
 *
 * @param  pClientFn,
 *      A pointer to an MP_OBJECT_VISIBILITY_FN function defined by the
 *      client. On successful return this function will be called to
 *      inform the client of objects whose visibility has changed.
 *
 * @param  objectType
 *      The type of object the client wishes to deregister for
 *      property change callbacks. If null, then all objects types are
 *      deregistered.
 *
 * @param  pCallerData
 *      A pointer that is passed to the callback routine with each event.
 *      This may be used by the caller to correlate the event to source of
 *      the registration.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pClientFn is NULL or specifies a memory area
 *      that is not executable.
 *
 * @retval MP_STATUS_FN_REPLACED
 *      Returned when an existing client function is replaced with the one
 *      specified in pClientFn.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if objectType does not specify any valid object type.
 *
 *******************************************************************************
 */
MP_STATUS MP_RegisterForObjectVisibilityChanges(
    MP_OBJECT_VISIBILITY_FN pClientFn,
    MP_OBJECT_TYPE objectType,
    void *pCallerData,
    MP_OID pluginOid)
{
    MP_RegisterForObjectVisibilityChangesPluginFn PassFunc;
    MP_UINT32 i;
    MP_UINT32 index;
    MP_STATUS status;

    if (pClientFn == NULL) {
        return (MP_STATUS_INVALID_PARAMETER);
    }

    if (objectType > MP_OBJECT_TYPE_MAX) {
        return (MP_STATUS_INVALID_OBJECT_TYPE);
    }

    if (!(is_zero_oid(pluginOid))) {
	if ((status = validate_object(pluginOid, MP_OBJECT_TYPE_PLUGIN,
	    MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
	    return (status);
	}
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    if (is_zero_oid(pluginOid)) {
	for (i = 0; i < number_of_plugins; i++) {
	    if (plugintable[i].hdlPlugin != NULL) {
	    PassFunc = (MP_RegisterForObjectVisibilityChangesPluginFn)
		dlsym(plugintable[i].hdlPlugin,
		"MP_RegisterForObjectVisibilityChangesPlugin");
	    }

	    if (PassFunc != NULL) {
		status = PassFunc(pClientFn, objectType, pCallerData);
		/* ignore an error and continue. */
	    }
	}
    } else {
	    index = pluginOid.ownerId - 1;
	    if (plugintable[index].hdlPlugin != NULL) {
	    PassFunc = (MP_RegisterForObjectVisibilityChangesPluginFn)
		dlsym(plugintable[index].hdlPlugin,
		"MP_RegisterForObjectVisibilityChangesPlugin");
	    }

	    if (PassFunc != NULL) {
		status = PassFunc(pClientFn, objectType, pCallerData);
	    }
    }
    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);

}

/**
 *******************************************************************************
 *
 * Deregisters a previously registered client function that is to be invoked
 * whenever a high level object appears or disappears.
 *
 * @param  pClientFn,
 *      A pointer to an MP_OBJECT_VISIBILITY_FN function defined by the
 *      client that was previously registered using
 *      the MP_RegisterForObjectVisibilityChanges API. On successful return
 *      this function will no longer be called to inform the client of
 *      object property changes.
 *
 * @param  objectType
 *      The type of object the client wishes to deregister for visibility
 *      change callbacks. If null, then all objects types are
 *      deregistered.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the operation is successful.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pClientFn is NULL or specifies a memory area
 *      that is not executable.
 *
 * @retval MP_STATUS_UNKNOWN_FN
 *      Returned if pClientFn is not the same as the previously registered
 *      function.
 *
 * @retval MP_STATUS_INVALID_OBJECT_TYPE
 *          Returned if objectType does not specify any valid object type.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if pClientFn deregistration is not possible at this time.
 *
 *******************************************************************************
 */
MP_STATUS MP_DeregisterForObjectVisibilityChanges(
    MP_OBJECT_VISIBILITY_FN pClientFn,
    MP_OBJECT_TYPE objectType,
    MP_OID pluginOid)
{
    MP_DeregisterForObjectVisibilityChangesPluginFn PassFunc;
    MP_UINT32 i;
    MP_UINT32 index;
    MP_STATUS status;

    if (pClientFn == NULL) {
        return (MP_STATUS_INVALID_PARAMETER);
    }

    if (objectType > MP_OBJECT_TYPE_MAX) {
        return (MP_STATUS_INVALID_OBJECT_TYPE);
    }

    if (!(is_zero_oid(pluginOid))) {
	if ((status = validate_object(pluginOid, MP_OBJECT_TYPE_PLUGIN,
	    MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
	    return (status);
	}
    }

    (void) pthread_mutex_lock(&mp_lib_mutex);

    if (is_zero_oid(pluginOid)) {
	for (i = 0; i < number_of_plugins; i++) {
	    if (plugintable[i].hdlPlugin != NULL) {
		PassFunc = (MP_DeregisterForObjectVisibilityChangesPluginFn)
		    dlsym(plugintable[i].hdlPlugin,
		    "MP_DeregisterForObjectVisibilityChangesPlugin");
		if (PassFunc != NULL) {
		    status = PassFunc(pClientFn, objectType);
		}
	    }
	}
    } else  {
	    index = pluginOid.ownerId - 1;
	    if (plugintable[index].hdlPlugin != NULL) {
		PassFunc = (MP_DeregisterForObjectVisibilityChangesPluginFn)
		    dlsym(plugintable[index].hdlPlugin,
		    "MP_DeregisterForObjectVisibilityChangesPlugin");
		if (PassFunc != NULL) {
		    status = PassFunc(pClientFn, objectType);
		}
	    }
    }

    (void) pthread_mutex_unlock(&mp_lib_mutex);
    return (status);
}

/**
 *******************************************************************************
 *
 * Compare two Oids for equality to see whether they refer to the same object.
 *
 * @param  oid1
 *          Oid to compare.
 *
 * @param  oid2
 *          Oid to compare.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when the two Oids do refer to the same object.
 *
 * @retval MP_STATUS_FAILED
 *      Returned if the Oids don't compare.
 *
 *******************************************************************************
 */
MP_STATUS MP_CompareOIDs(
        MP_OID oid1,
    MP_OID oid2)
{
    if ((oid1.objectType == oid2.objectType) && (oid1.ownerId == oid2.ownerId)
    	&& (oid1.objectSequenceNumber == oid2.objectSequenceNumber)) {
    	return (MP_STATUS_SUCCESS);
    } else {
    	return (MP_STATUS_FAILED);
    }
}

/**
 *******************************************************************************
 *
 * Frees memory returned by an MP API.
 *
 * @param  pOidList
 *      A pointer to the memory returned by an MP API. On successful
        return, the allocated memory is freed.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when pPluginId is deregistered successfully.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pMemory is NULL or specifies a memory area to which
 *      data cannot be written.
 *
 *******************************************************************************
 */
MP_STATUS MP_FreeOidList(MP_OID_LIST *pOidList)
{
	if (pOidList == NULL) {
	    return (MP_STATUS_INVALID_PARAMETER);
	}
	
	free(pOidList);

	return (MP_STATUS_SUCCESS);
}

static MP_CHAR *HDR =
"#\n" 
"# This file contains names and references to MP API plugin libraries\n"
"#\n"
"#  Do NOT manually edit this file\n" 
"#\n"
"# Format:\n"
"#\n"
"# <library ID>  <library pathname>\n"
"#\n";

#define CLEANUP_N_RET(fd, ret)  \
	if (lock_register(fd, F_SETLK, F_UNLCK, 0, SEEK_SET, 0) < 0) { \
		close(fd); \
		return (MP_STATUS_FAILED); \
	} \
	close(fd); \
	return (ret)
	
/*
 * This function sets an advisory lock on the file pointed to by the argument
 * fd, which is a file descriptor. The lock is set using fcntl() which uses
 * flock structure.
 */
static int
lock_register(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock lock;

    lock.l_type = type;
    lock.l_start = offset;
    lock.l_whence = whence;
    lock.l_len = len;

    return (fcntl(fd, cmd, &lock));
}

/*
 * This function searches for "srch_str" (of length "slen") in "buf" (of length
 * "buflen"). If it is not found, "write_offset" has the offset in "buf" where
 * "srch_str" would have to be added in "buf". If "srch_str" is found in "buf",
 * "write_offset" has its offset in "buf"
 *
 * ARGUMENTS :
 * buf		- buffer to search in
 * buflen	- length of buffer
 * srch_id	- id to search
 * id_len	- length of srch_id
 * write_offset	- Set in function on exit
 *		- It is the offset in buf where srch_str is or should be
 * bytes_left	- Set in function on exit
 *		- It is the # of bytes left beyond write_offset in buf
 * RETURN VALUES :
 * Zero - "srch_id" found in "buf"... "write_offset" has offset in "buf"
 * != 0 - "srch_str" NOT found in "buf" ... "write_offset" points to the end of
 *	    "buf".
 */
static int
search_line(MP_CHAR *buf, size_t buflen, MP_CHAR *srch_id, size_t id_len,
		int *write_offset, int *bytes_left)
{
	int	retval, sizeof_conf_hdr = strlen(HDR);
	MP_CHAR	*sol;		/* Pointer to Start-Of-Line */
	MP_CHAR	*cur_pos;	/* current position */

	*bytes_left = buflen;
	*write_offset = 0;

	if (buf == NULL || buflen <= 0)
		return (-1);	

	if (srch_id == NULL || id_len <= 0)
		return (0);	

	sol = cur_pos = buf;

	/*
	 * mp conf file should not be edited but takes care of 
	 * any extra white space when parsing the line.
	 *
	 * The line should have id + delimiter + name + newline.
	 */
	while (*bytes_left >= (id_len + 3)) {
	    /* skip leading blank or space. */
	    while ((*cur_pos == ' ') || (*cur_pos == '\t')) {
		cur_pos++;
	    }

	    if (strncmp(cur_pos, srch_id, id_len) == 0) {
		/* id matched. */
		cur_pos += id_len;

		while (*cur_pos != '\n') {
		    cur_pos++;
		}
		*write_offset = (sol - buf);
		*bytes_left = buflen - ((cur_pos + 1) - buf);
		return (0);
	    } else {
		/* move to the next line */
		while (*cur_pos != '\n') {
		    cur_pos++;
		}
		*bytes_left = buflen - ((cur_pos + 1) - buf);
	    }
	    sol = cur_pos = cur_pos + 1;
	} 	

	/* Given strings are not found. */
	*write_offset = buflen;
	return (-1);
}

/**
 *******************************************************************************
 *
 * Registers a plugin with common library.  The implementation of this routine
 * is based on configuration file /etc/mpapi.conf that contains a list of 
 * plugin libraries.
 *
 * @param  pPluginId
 *	    A pointer to the key name shall be the reversed domain name of
 *	    the vendor followed by followed by the vendor specific name for
 *	    the plugin that uniquely identifies the plugin.  Should be NULL
 *	    terminated.
 *
 * @param  pFileName
 *	    The full path to the plugin library.
 *	    Should be NULL terminated.
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when pPluginId is deregistered successfully.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pPluginId is NULL or specifies a memory area that
 *      is not executable.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if pClientFn deregistration is not possible at this time.
 *
 *******************************************************************************
 */
MP_STATUS MP_RegisterPlugin(
	MP_WCHAR *pPluginId,
	char *pFileName)
{
	int mpconf, bytes_left, write_offset;
	MP_CHAR fullline[MAX_LINE_SIZE]; /* Full line to add to mpapi.conf */
	MP_CHAR *mpconf_buf;
	MP_CHAR pluginid[MAX_NAME_SIZE];
	char systemPath[MAX_NAME_SIZE], mpConfFilePath[MAX_NAME_SIZE];
	MP_UINT32   new_file_flag = 0;
	MP_UINT32   sizeof_conf_hdr = strlen(HDR);
	struct stat	stbuf;
	
	if ((pPluginId == NULL) || (pFileName == NULL)) {
	    return (MP_STATUS_INVALID_PARAMETER);
	}

	if (stat(pFileName, &stbuf) != 0) {
	    return (MP_STATUS_INVALID_PARAMETER);
	}

	if (wcstombs(pluginid, pPluginId, MAX_NAME_SIZE) != wcslen(pPluginId)) {
	    return (MP_STATUS_INVALID_PARAMETER);
	}

	*fullline = '\0';
	strncpy(fullline, pluginid, MAX_NAME_SIZE);
	/* add tab */
	strncat(fullline, "\t", MAX_LINE_SIZE - strlen(pluginid));
	strncat(fullline, pFileName, MAX_LINE_SIZE - strlen(pluginid) - 1);
	/* add a new line. */
	strncat(fullline, "\n",
	    MAX_LINE_SIZE - strlen(pluginid) - strlen(pFileName) -1);
	
	/* Open configuration file from known location */
	strncpy(mpConfFilePath, "/etc/mpapi.conf", MAX_NAME_SIZE);

	if ((chmod(mpConfFilePath, S_IRUSR|S_IRGRP|S_IROTH) == -1) &&
		(errno == ENOENT))  {
	    new_file_flag = 1;
	}
    
	if ((mpconf = open(mpConfFilePath, O_RDWR | O_CREAT)) == -1) {
		return (MP_STATUS_FAILED);
	}

	if (fchmod(mpconf, S_IRUSR | S_IRGRP | S_IROTH) < 0) {
	    close(mpconf);
	    return (MP_STATUS_FAILED);
	}

	if (lock_register(mpconf, F_SETLKW, F_WRLCK, 0, SEEK_SET, 0) < 0) {
	    close(mpconf);
	    return (MP_STATUS_FAILED);
	}

	if (fstat(mpconf, &stbuf) == -1) {
	    CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	}

	if ((new_file_flag) || (stbuf.st_size == 0)) {
	    if (write(mpconf, HDR, sizeof_conf_hdr) !=
		sizeof_conf_hdr) {
		CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	    }

	    if (pwrite(mpconf, fullline, strlen(fullline),
		sizeof_conf_hdr) !=
		strlen(fullline)) {
		CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	    }
	    CLEANUP_N_RET(mpconf, MP_STATUS_SUCCESS);
	}

	if ((mpconf_buf = (MP_CHAR *)mmap(0, stbuf.st_size,
		PROT_READ | PROT_WRITE,
		MAP_SHARED, mpconf, 0)) == MAP_FAILED) {
	    CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	}

	if (search_line(mpconf_buf, stbuf.st_size,
	    pluginid, strlen(pluginid), &write_offset, &bytes_left) == 0) {
	    /* found a match. */
	    munmap((void *)mpconf_buf, stbuf.st_size);
	    CLEANUP_N_RET(mpconf, MP_STATUS_SUCCESS);
	} else {
	    munmap((void *)mpconf_buf, stbuf.st_size);
	    /* append the fullline to the mpconf. */
	    if (pwrite(mpconf, fullline, strlen(fullline),
		write_offset) !=
		strlen(fullline)) {
		CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	    } else {
		CLEANUP_N_RET(mpconf, MP_STATUS_SUCCESS);
	    }
	}
}

/**
 *******************************************************************************
 *
 * Deregisters a plugin from the common library.  This routine is based on
 * configuration file /etc/mpapi.conf that contains a list of plugin libraries.
 *
 * @param  pPluginId
 *      A pointer to a Plugin ID previously registered using
 *      the MP_RegisterPlugin API..
 *
 * @return An MP_STATUS indicating if the operation was successful or if
 *         an error occurred.
 *
 * @retval MP_STATUS_SUCCESS
 *         Returned when pPluginId is deregistered successfully.
 *
 * @retval MP_STATUS_INVALID_PARAMETER
 *      Returned if pPluginId is NULL or specifies a memory area that
 *      is not executable.
 *
 * @retval MP_STATUS_FAILED
 *          Returned if pClientFn deregistration is not possible at this time.
 *
 *******************************************************************************
 */
MP_STATUS MP_DeregisterPlugin(
    MP_WCHAR *pPluginId)
{
	int mpconf, tmp_mpconf, bytes_left, write_offset;
	char systemPath[MAX_NAME_SIZE], mpConfFilePath[MAX_NAME_SIZE],
	    tmp_mpConfFilePath[MAX_NAME_SIZE + sizeof(pid_t)];
	MP_CHAR    pluginid[MAX_NAME_SIZE];
	MP_CHAR    *mpconf_buf;
	MP_UINT32   sizeof_conf_hdr = strlen(HDR);
	struct stat	stbuf;

	if (pPluginId == NULL) {
	    return (MP_STATUS_INVALID_PARAMETER);
	}

	if (wcstombs(pluginid, pPluginId, MAX_NAME_SIZE) != wcslen(pPluginId)) {
	    return (MP_STATUS_INVALID_PARAMETER);
	}

	/* Open configuration file from known location */
	strncpy(mpConfFilePath, "/etc/mpapi.conf", MAX_NAME_SIZE);

	if ((chmod(mpConfFilePath, S_IRUSR|S_IRGRP|S_IROTH) == -1) &&
		(errno == ENOENT))  {
	    /* no file found */
	    return (MP_STATUS_UNKNOWN_FN);
	}
    
	if ((mpconf = open(mpConfFilePath, O_RDWR)) == -1) {
		return (MP_STATUS_FAILED);
	}

	if (fchmod(mpconf, S_IRUSR | S_IRGRP | S_IROTH) < 0) {
	    close(mpconf);
	    return (MP_STATUS_FAILED);
	}

	if (lock_register(mpconf, F_SETLKW, F_WRLCK, 0, SEEK_SET, 0) < 0) {
	    close(mpconf);
	    return (MP_STATUS_FAILED);
	}

	if (fstat(mpconf, &stbuf) == -1) {
	    CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	}

	if (stbuf.st_size == 0) {
	    CLEANUP_N_RET(mpconf, MP_STATUS_SUCCESS);
	}

	if ((mpconf_buf = (MP_CHAR *)mmap(0, stbuf.st_size,
		PROT_READ | PROT_WRITE,
		MAP_SHARED, mpconf, 0)) == MAP_FAILED) {
	    CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	}

	if (search_line(mpconf_buf, stbuf.st_size, pluginid, strlen(pluginid),
		&write_offset, &bytes_left) != 0) {
	    munmap((void *)mpconf_buf, stbuf.st_size);
	    CLEANUP_N_RET(mpconf, MP_STATUS_UNKNOWN_FN);
	} else {
	    /*
	     * found a match.
	     * construct temp file name using pid.
	     */
	    (void) snprintf(tmp_mpConfFilePath, MAX_NAME_SIZE,
		"%s%ld", "/etc/mpapi.conf", getpid());

	    if ((tmp_mpconf = open(tmp_mpConfFilePath,
		O_RDWR|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR)) < 0) {
		CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	    }

	    if (write(tmp_mpconf, mpconf_buf, write_offset) != write_offset) {
		close(tmp_mpconf);
		CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	    }

	    if (pwrite(tmp_mpconf, mpconf_buf + (stbuf.st_size - bytes_left),
		bytes_left, write_offset) != bytes_left) {
		close(tmp_mpconf);
		CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	    }

	    close(tmp_mpconf);
	    munmap((void *)mpconf_buf, stbuf.st_size);

	    /* rename temp file to mpConfFile before unlock and close. */
	    if (rename(tmp_mpConfFilePath, mpConfFilePath) != 0) {
		CLEANUP_N_RET(mpconf, MP_STATUS_FAILED);
	    } else {
		CLEANUP_N_RET(mpconf, MP_STATUS_SUCCESS);
	    }
	}
}
