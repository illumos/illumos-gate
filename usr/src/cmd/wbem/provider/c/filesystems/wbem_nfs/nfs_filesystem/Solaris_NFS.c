/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "Solaris_NFS.h"
#include "util.h" /* Error handling */
#include "nfs_provider_names.h"
#include "nfs_providers_msgstrings.h"
#include "messageStrings.h"
#include "libfsmgt.h"
#include "nfsprov_methods.h"
#include "createprop_methods.h"
#include <errno.h>
#include <sys/types.h>
#include <string.h>

#define	GET_DEF_SECMODE_METHOD "getDefaultNfsSecMode"
#define	GET_NET_CFG_LIST_METHOD "getNetCfgList"
#define	GET_NFS_SEC_LIST_METHOD "getNfsSecList"
#define	UNKNOWN		"Unknown"
/*
 * Private method declarations
 */
static CCIMInstanceList* enumerate_nfs_mounts();
static CCIMPropertyList* populate_property_list(nfs_mntlist_t *nfs_mount);
static CIMBool		populate_property_values(nfs_mntlist_t *nfs_mount,
				cimchar **propValues);
/*
 * Instance provider methods
 */

/*
 * Method: cp_createInstance_Solaris_NFS
 *
 * Description: This method is not supported.  A Solaris_NFS instance is only
 * created upon the creation of a corresponding NFS mount.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsOP - An object path containing the name of
 *	the class of which to enumerate the instances of.
 *
 * Returns:
 *	- Always returns NULL because the method is not supported.
 */
/* ARGSUSED */
CCIMObjectPath *
cp_createInstance_Solaris_NFS(CCIMObjectPath *nfsOP,
	CCIMInstance *nfsInst) {

	int err = 0;

	util_handleError("SOLARIS_NFS::CREATE_INSTANCE", CIM_ERR_NOT_SUPPORTED,
		NULL, NULL, &err);

	return ((CCIMObjectPath *)NULL);
} /* cp_createInstance_Solaris_NFS */

/*
 * Method: cp_deleteInstance_Solaris_NFS
 *
 * Description: This method is not supported.  A Solaris_NFS instance is
 * only deleted upon the deletion of the corresponding NFS mount.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the
 *	information about the class of which to delete the instance of.
 *
 * Returns:
 *	- Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_NFS(CCIMObjectPath *nfsOP) {

	int err = 0;

	util_handleError("SOLARIS_NFS::DELETE_INSTANCE", CIM_ERR_NOT_SUPPORTED,
		NULL, NULL, &err);

	return (cim_false);
} /* cp_deleteInstance_Solaris_NFS */

/*
 * Method: cp_enumInstances_Solaris_NFS
 *
 * Description: Enumerates the instances of Solaris_NFS mount on the host.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsOP - An object path containing the name of
 *	the class of which to enumerate the instances of.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFS instances.
 *	- NULL if an error occurred or if there aren't any instances of
 *	Solaris_NFS on the host.  In the case of an error, the error will be
 *	logged.
 */
CCIMInstanceList *
cp_enumInstances_Solaris_NFS(CCIMObjectPath *nfsOP) {
	CCIMInstanceList	*instList;
	int			err = 0;

	/*
	 * First check if the CCIMObjectPath passed in is NULL.
	 */
	if (nfsOP == NULL) {
		util_handleError("SOLARIS_NFS::ENUM_INSTANCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);

		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * An nfs file system instance is equivalent to a nfs mount on the
	 * host.
	 */
	instList = enumerate_nfs_mounts();

	return (instList);
} /* cp_enumInstances_Solaris_NFS */

/*
 * Method: cp_enumInstanceNames_Solaris_NFS
 *
 * Description: Enumerates the object paths of the instances of Solaris_NFS
 * on the host.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsOP - An object path containing the name of
 *	the class of which to enumerate the instance names of.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFS object paths.
 *	- NULL if an error occurred or if there aren't any instances of
 *	Solaris_NFS on the host.  In the case of an error, the error will be
 *	logged.
 */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_NFS(CCIMObjectPath *nfsOP) {
	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	int			err = 0;

	/*
	 * First check if the object path is null.
	 */
	if (nfsOP == NULL) {
		util_handleError("SOLARIS_NFS::ENUM_INSTANCENAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);

		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFS(nfsOP);
	if (instList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	objPathList = cim_createObjectPathList(instList);

	cim_freeInstanceList(instList);
	/*
	 * If an error occurred in cim_createObjectPathList it will be handled
	 * there.
	 */
	return (objPathList);
} /* cp_enumInstanceNames_Solaris_NFS */

/*
 * Method: cp_execQuery_Solaris_NFS
 *
 * Description: Queries the nfs instances on the host to find those that meet
 * the search criteria.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsOP - An object path containing the name of
 *	the class of which to query.
 *	- char *selectClause - Not used.
 *	- char *nonJoinExp - Not used.
 *	- char *queryExp - Not used.
 *	- char *queryLang - Not used.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFS instances that match the criteria.
 *	- NULL if an error occurred or if there are no Solaris_NFS instances
 *	that match the criteria.  In the case of an error, the error will be
 *	logged.
 *
 * NOTE: Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_execQuery_Solaris_NFS(CCIMObjectPath *nfsOP, char *selectClause,
	char *nonJoinExp, char *queryExp, char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*nfsInstList;
	CCIMException		*ex;
	int			err = 0;

	if (nfsOP == NULL) {
		util_handleError("SOLARIS_NFS::EXEC_QUERY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsInstList = cp_enumInstances_Solaris_NFS(nfsOP);
	if (nfsInstList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFS::EXEC_QUERY",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(nfsInstList);
		return ((CCIMInstanceList *)NULL);
	}

	nfsInstList = cim_prependInstance(nfsInstList, emptyInst);
	if (nfsInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFS::EXEC_QUERY",
			CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (nfsInstList);
} /* cp_execQuery_Solaris_NFS */

/*
 * Method: cp_getInstance_Solaris_NFS
 *
 * Description: Gets the Solaris_NFS instance that corresponds to the object
 * path passed in.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsOP - The object path containing all the
 *	keys of the instance that is supposed to be returned.
 *
 * Returns:
 *	- A pointer to an instance of Solaris_NFS which corresponds to the
 *	object path passed in.
 *	- NULL if an error occurred or if there is no Solaris_NFS instance
 *	corresponding to the object path passed in.  In the case of an error,
 *	the error will be logged.
 */
CCIMInstance *
cp_getInstance_Solaris_NFS(CCIMObjectPath *nfsOP) {
	CCIMInstanceList	*instList;
	CCIMInstance		*inst;
	CCIMException		*ex;
	int			err = 0;

	/*
	 * First check to see if the object path is null.
	 */
	if (nfsOP == NULL || nfsOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFS::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFS(nfsOP);
	if (instList == NULL) {
		/*
		 * Either an error occurred or we simply don't have any
		 * instances of Solaris_NFS on the system.  In the case that
		 * an error occurred, it will be handled in
		 * cp_enumInstances_Solaris_NFS.
		 */
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, nfsOP);
	if (inst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFS::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, GET_INSTANCE_FAILURE,
			ex, &err);
		cim_freeInstanceList(instList);
		return ((CCIMInstance *)NULL);
	}

	cim_freeInstanceList(instList);
	return (inst);
} /* cp_getInstance_Solaris_NFS */

/*
 * Method: cp_setInstance_Solaris_NFS
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties of a Solaris_NFS instance underlying file
 * system or file system mount would have to be modified.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of the class
 *	of which to set the instance.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- Always returns cim_false since the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_NFS(CCIMObjectPath *nfsOP, CCIMInstance *nfsInst) {

	int	err = 0;

	util_handleError("SOLARIS_NFS::SET_INSTANCE", CIM_ERR_NOT_SUPPORTED,
		NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_NFS */

/*
 * Method: cp_setInstanceWithList_Solaris_NFS
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties of a Solaris_NFS instance underlying file
 * system or file system mount would have to be modified.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsOP - The object path containing the name
 *	of the class of which to set the instance.
 *	- CCIMInstance *nfsInst - Not used.
 *	- char **props - Not used.
 *	- int num_props - Not used.
 *
 * Returns:
 *	- Always returns cim_false since the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_NFS(CCIMObjectPath *nfsOP, CCIMInstance *nfsInst,
	char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_NFS::SET_INSTANCE", CIM_ERR_NOT_SUPPORTED,
		NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstanceWithList_Solaris_NFS */


/*
 * Property provider methods
 */

/*
 * Method: cp_getProperty_Solaris_NFS
 *
 * Description: Retrieves the property with the name matching the passed in
 * parameter, pPropName, along with the value and descriptive other information.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsOP - The object path containing all the
 *	information needed to find the instance in which the property is to
 *	be returned.
 *	- cimchar *pPropName - The name of the property to be found.
 *
 * Returns:
 *	- A pointer to a the property corresponding to the property name passed
 *	in with pPropName.
 *	- NULL if an error occurred or if there is no property corresponding to
 *	pPropName.  In the case of an error, the error will be logged.
 */
CCIMProperty *
cp_getProperty_Solaris_NFS(CCIMObjectPath *nfsOP, cimchar *pPropName) {
	CCIMInstance	*nfsInst;
	CCIMProperty	*nfsProp;
	int		err = 0;

	if (nfsOP == NULL || pPropName == NULL) {
		util_handleError("SOLARIS_NFS::GET_PROPERTY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	nfsInst = cp_getInstance_Solaris_NFS(nfsOP);
	if (nfsInst == NULL) {
		return ((CCIMProperty *)NULL);
	}

	nfsProp = cim_getProperty(nfsInst, pPropName);

	cim_freeInstance(nfsInst);
	/*
	 * If an error occurred in cim_getProperty it will be handled there.
	 */
	return (nfsProp);
} /* cp_getProperty_Solaris_NFS */

/*
 * Method: cp_setProperty_Solaris_NFS
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties of a Solaris_NFS instance underlying file
 * system or file system mount would have to be modified.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsOP - Not used.
 *	- CCIMProperty *pProp - Not used.
 *
 * Returns:
 *	- Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_NFS(CCIMObjectPath *nfsOP, CCIMProperty *pProp) {
	int	err = 0;

	util_handleError("SOLARIS_NFS::SET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_NFS */

/*
 * Method provider methods
 */

/*
 * Method: cp_invokeMethod_Solaris_NFS
 *
 * Description: Routes the cp_invokeMethod_Solaris_NFS calls to the correct
 * Solaris_NFS methods.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - The object path containing needed information
 *	about the class that is to getting methods invoked.
 *	- cimchar *functionName - The name of the function to be invoked.
 *	- CCIMPropertyList *inParams - The input parameters to the function.
 *	- CCIMPropertyList *outParams - The output parameters from the function.
 *
 * Returns:
 *	- A property having a value which indicates success or failure of the
 *	function.  1 for success, 0 for failure.
 *	- Upon error, NULL is returned and the error is logged.
 *
 * NOTE: All methods of Solaris_NFS are deprecated, but are still to be
 * supported until they are EOL'd.  EOL date is to be determined.
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_NFS(CCIMObjectPath *pOP, cimchar *functionName,
	CCIMPropertyList *inParams, CCIMPropertyList *outParams) {

	int		err = 0;
	CCIMProperty    *retVal;

	if (pOP == NULL || functionName == NULL) {
		util_handleError("SOLARIS_NFS::INVOKE_METHOD",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}
	/*
	 * Determine what method is being called.
	 */
	if (strcasecmp(functionName, GET_NET_CFG_LIST_METHOD) == 0) {
		retVal = get_netconfig_list(outParams);
	} else if (strcasecmp(functionName, GET_NFS_SEC_LIST_METHOD) == 0) {
		retVal = get_nfssec_list(outParams);
	} else if (strcasecmp(functionName, GET_DEF_SECMODE_METHOD) == 0) {
		retVal = get_default_secmode(outParams);
	} else {
		/*
		 * No such method name.
		 */
		util_handleError("SOLARIS_NFS::INVOKE_METHOD",
			CIM_ERR_FAILED, NO_SUCH_METHOD, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	return (retVal);
} /* cp_invokeMethod_Solaris_NFS */

/*
 * Private methods
 */

/*
 * Method: enumerate_nfs_mounts
 *
 * Description: Enumerates all the NFS file systems on the host.
 *
 * Parameters:
 *	- NONE
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFS instances on the host.
 *	- NULL if an error occurred or if there aren't any Solaris_NFS
 *	instances on the host.  In the case of an error, the error will be
 *	logged.
 */
static CCIMInstanceList *
enumerate_nfs_mounts() {
	int		err = 0;
	nfs_mntlist_t	*nfs_mount_list, *currentMnt;
	CCIMException	*ex;

	nfs_mount_list = nfs_get_mount_list(&err);
	if (nfs_mount_list == NULL) {
		/*
		 * Check whether an error was returned or if we simply don't
		 * have any nfs file systems on the system.  If err is not
		 * equal to 0, an error was encountered.
		 */
		if (err != 0) {
			/*
			 * Determine the error and log it.
			 */
			if (err == ENOMEM || err == EAGAIN) {
				util_handleError("SOLARIS_NFS::ENUM_MOUNTS",
					CIM_ERR_LOW_ON_MEMORY,
					NFS_GET_MNTLIST_FAILURE,
					NULL, &err);

				return ((CCIMInstanceList *)NULL);
			} else {
				/*
				 * If any other errors were encountered it
				 * can be handled as a general error.  We may
				 * not know exactly what the error is.
				 */
				util_handleError("SOLARIS_NFS::ENUM_MOUNTS",
					CIM_ERR_FAILED, NFS_GET_MNTLIST_FAILURE,
					NULL, &err);

				return ((CCIMInstanceList *)NULL);
			}
		}
		/*
		 * There are simply no nfs mounts on the host.
		 */
		return ((CCIMInstanceList *)NULL);
	} else {
		/*
		 * At this point, one or more nfs mounts were found on the
		 * system, create the instance list from the nfs_mount_list.
		 */
		CCIMInstanceList	*nfsInstList;

		nfsInstList = cim_createInstanceList();
		if (nfsInstList == NULL) {
			ex = cim_getLastError();
			util_handleError("SOLARIS_NFS::ENUM_MOUNTS",
				CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE,
				ex, &err);
			nfs_free_mntinfo_list(nfs_mount_list);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Loop through the nfs mounts to retrieve their properties
		 * and create an instance list containing all the nfs file
		 * systems and their properties.
		 */
		for (currentMnt = nfs_mount_list; currentMnt != NULL;
			currentMnt = currentMnt->next) {

			CCIMInstance		*solarisNFSInstance;
			CCIMPropertyList	*solarisNFSPropList;

			/*
			 * Create the Solaris_NFS CCIMInstance
			 */
			solarisNFSInstance =
				cim_createInstance(SOLARIS_NFS);
			if (solarisNFSInstance == NULL) {
				ex = cim_getLastError();
				util_handleError("SOLARIS_NFS::ENUM_MOUNTS",
					CIM_ERR_FAILED,
					CREATE_INSTANCE_FAILURE, ex, &err);

				cim_freeInstanceList(nfsInstList);
				nfs_free_mntinfo_list(nfs_mount_list);
				return ((CCIMInstanceList *)NULL);
			}

			solarisNFSPropList =
				populate_property_list(currentMnt);
			if (solarisNFSPropList == NULL) {
				/*
				 * An error occurred in populate_property_list
				 * and was logged there.
				 */
				cim_freeInstanceList(nfsInstList);
				cim_freeInstance(solarisNFSInstance);
				return ((CCIMInstanceList *)NULL);
			}

			solarisNFSInstance = cim_addPropertyListToInstance(
				solarisNFSInstance, solarisNFSPropList);
			if (solarisNFSInstance == NULL) {
				ex = cim_getLastError();
				util_handleError("SOLARIS_NFS::ENUM_MOUNTS",
					CIM_ERR_FAILED,
					PROPLIST_TO_INSTANCE_FAILURE, ex,
					&err);
				cim_freeInstanceList(nfsInstList);
				cim_freePropertyList(solarisNFSPropList);
				nfs_free_mntinfo_list(nfs_mount_list);
				return ((CCIMInstanceList *)NULL);
			}

			nfsInstList = cim_addInstance(nfsInstList,
				solarisNFSInstance);
			if (nfsInstList == NULL) {
				ex = cim_getLastError();
				util_handleError("SOLARIS_NFS::ENUM_MOUNTS",
					CIM_ERR_FAILED, ADD_INSTANCE_FAILURE,
					ex, &err);
				/*
				 * Freeing the instance will also free the
				 * property list added to the instance.
				 */
				cim_freeInstance(solarisNFSInstance);
				nfs_free_mntinfo_list(nfs_mount_list);
				return ((CCIMInstanceList *)NULL);
			}
		} /* end for */

		nfs_free_mntinfo_list(nfs_mount_list);
		return (nfsInstList);
	}

} /* enumerate_nfs_mounts */

/*
 * Method:populate_property_list
 *
 * Description: Populates a property list with the properties of the nfs mounted
 * file system that is passed in with the nfs_mount parameter.
 *
 * Parameters:
 *	- The nfs mount from which to extract the properties from.
 *
 * Returns:
 *	- A pointer to a list of properties corresponding to the NFS mounted
 *	file system passed in with the nfs_mount parameter.
 *	- Upon error, NULL is returned and an error is logged.
 */
static CCIMPropertyList *
populate_property_list(nfs_mntlist_t *nfs_mount) {
	CCIMPropertyList	*nfsPropList;
	CCIMException		*ex;
	cimchar			**propValues;
	int			err = 0, i = 0;

	nfsPropList = cim_createPropertyList();
	if (nfsPropList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFS::POPULATE_PROPLIST",
			CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE, ex, &err);
		return ((CCIMPropertyList *)NULL);
	}

	propValues = calloc((size_t)PROPCOUNT, (size_t)sizeof (cimchar *));
	if (propValues == NULL) {
		util_handleError("SOLARIS_NFS::POPULATE_PROPLIST",
			CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, &err);
		return ((CCIMPropertyList *)NULL);
	}

	if (populate_property_values(nfs_mount, propValues) == cim_false) {
		cim_freePropertyList(nfsPropList);
		fileutil_free_string_array(propValues, PROPCOUNT);
		return ((CCIMPropertyList *)NULL);
	}

	for (i = 0; i < PROPCOUNT; i++) {
		nfsPropList = add_property_to_list(nfsProps[i].name,
			nfsProps[i].type, propValues[i], NULL,
			nfsProps[i].isKey, nfsPropList);
		if (nfsPropList == NULL) {
			fileutil_free_string_array(propValues, PROPCOUNT);
			return ((CCIMPropertyList *)NULL);
		}
	}

	fileutil_free_string_array(propValues, PROPCOUNT);
	return (nfsPropList);
} /* populate_property_list */

static CIMBool
populate_property_values(nfs_mntlist_t *nfs_mount,
	cimchar **propValues) {

	unsigned long long	availablesize;
	unsigned long long	blocksize;
	unsigned long long	totalsize;
	unsigned long long	usedsize;
	unsigned long		maxfilenamelen;
	unsigned long		fragsize;
	unsigned int		codeSet[1] = { 0 };
	boolean_t		readonly;
	boolean_t		optHasEquals;
	cimchar			*codeSetValue;
	cimchar			propValue[MAXSIZE];
	char			*hostname;
	char			*devid;
	char			*resourceStr = "resource:=";
	char			*devidStr = "devid:=";
	char			*noSuid, *posix, *public, *quota, *port;
	int			err = 0, defaultValue = 0, nameLen = 0;

	/*
	 * AttributeCaching
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", (!nfs_mount->nml_noac));
	propValues[ATTRCACHE] = strdup(propValue);
	if (propValues[ATTRCACHE] == NULL) {
		return (cim_false);
	}

	/*
	 * AttributeCachingForDirectoriesMax
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_acdirmax);
	propValues[ATTRCACHEDIRMAX] = strdup(propValue);
	if (propValues[ATTRCACHEDIRMAX] == NULL) {
		return (cim_false);
	}

	/*
	 * AttributeCachingForDirectoriesMin
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_acdirmin);
	propValues[ATTRCACHEDIRMIN] = strdup(propValue);
	if (propValues[ATTRCACHEDIRMIN] == NULL) {
		return (cim_false);
	}

	/*
	 * AttributeCachingForRegularFilesMax
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_acregmax);
	propValues[ATTRCACHEFILESMAX] = strdup(propValue);
	if (propValues[ATTRCACHEFILESMAX] == NULL) {
		return (cim_false);
	}

	/*
	 * AttributeCachingForRegularFilesMin
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_acregmin);
	propValues[ATTRCACHEFILESMIN] = strdup(propValue);
	if (propValues[ATTRCACHEFILESMIN] == NULL) {
		return (cim_false);
	}

	/*
	 * AvailableSpace
	 */
	availablesize = fs_get_availablesize(nfs_mount->nml_mountp, &err);
	if (err != 0) {
		return (cim_false);
	}
	(void) snprintf(propValue, MAXSIZE, "%lld", availablesize);
	propValues[AVAILSPACE] = strdup(propValue);
	if (propValues[AVAILSPACE] == NULL) {
		return (cim_false);
	}

	/*
	 * BlockSize
	 */
	blocksize = fs_get_blocksize(nfs_mount->nml_mountp, &err);
	if (err != 0) {
		return (cim_false);
	}
	(void) snprintf(propValue, MAXSIZE, "%lld", blocksize);
	propValues[BLKSIZE] = strdup(propValue);
	if (propValues[BLKSIZE] == NULL) {
		return (cim_false);
	}

	/*
	 * Caption - Nothing top populate here.
	 */

	/*
	 * CasePreserved - True
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", B_TRUE);
	propValues[CASEPRES] = strdup(propValue);
	if (propValues[CASEPRES] == NULL) {
		return (cim_false);
	}

	/*
	 * CaseSensitive - True
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", B_TRUE);
	propValues[CASESENS] = strdup(propValue);
	if (propValues[CASESENS] == NULL) {
		return (cim_false);
	}

	/*
	 * ClusterSize - As defined in CIM_FileSystem:
	 * The minimum file allocation size (an integral number of
	 * blocks), imposed by the FileSystem. (The size of a block is
	 * specified in the BlockSize property for the FileSystem.)
	 * Minimum allocation size is the smallest amount of storage
	 * allocated to a LogicalFile by the FileSystem. This is not a
	 * mandatory minimum allocation for all FileSystems. Under
	 * stress conditions, some FileSystems may allocate storage
	 * in amounts smaller than the ClusterSize.
	 */
	fragsize = fs_get_fragsize(nfs_mount->nml_mountp, &err);
	if (err != 0) {
		return (cim_false);
	}
	(void) snprintf(propValue, MAXSIZE, "%ld", fragsize);
	propValues[CLUSTERSZ] = strdup(propValue);
	if (propValues[CLUSTERSZ] == NULL) {
		return (cim_false);
	}

	/*
	 * CodeSet
	 */
	codeSetValue = cim_encodeUint16Array(codeSet, 1);
	if (codeSetValue == NULL) {
		return (cim_false);
	}
	propValues[CODESET] = strdup(codeSetValue);
	if (propValues[CODESET] == NULL) {
		return (cim_false);
	}
	free(codeSetValue);

	/*
	 * CompressionMethod
	 */
	(void) snprintf(propValue, MAXSIZE, "%s", UNKNOWN);
	propValues[COMPRESSMETH] = strdup(propValue);
	if (propValues[COMPRESSMETH] == NULL) {
		return (cim_false);
	}

	/*
	 * CSCreationClassName -- KEY
	 */
	propValues[CSCREATCLASSNM] = strdup(SOLARIS_CS);
	if (propValues[CSCREATCLASSNM] == NULL) {
		return (cim_false);
	}

	/*
	 * CSName -- KEY
	 */
	hostname = sys_get_hostname(&err);
	if (hostname == NULL) {
		util_handleError("SOLARIS_NFS::POPULATE_PROPVALUES",
			CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL, &err);
		return (cim_false);
	}
	propValues[CSNAME] = strdup(hostname);
	if (propValues[CSNAME] == NULL) {
		return (cim_false);
	}
	free(hostname);

	/*
	 * CreationClassName -- KEY
	 */
	propValues[CREATCLASSNM] = strdup(SOLARIS_NFS);
	if (propValues[CREATCLASSNM] == NULL) {
		return (cim_false);
	}

	/*
	 * Description - Nothing to populate here.
	 */

	/*
	 * EncryptionMethod
	 */
	propValues[ENCRYPTMETH] = strdup(UNKNOWN);
	if (propValues[ENCRYPTMETH] == NULL) {
		return (cim_false);
	}

	/*
	 * FileSystemSize
	 */
	totalsize = fs_get_totalsize(nfs_mount->nml_mountp, &err);
	if (err != 0) {
		return (cim_false);
	}
	(void) snprintf(propValue, MAXSIZE, "%lld", totalsize);
	propValues[FSSIZE] = strdup(propValue);
	if (propValues[FSSIZE] == NULL) {
		return (cim_false);
	}

	/*
	 * FileSystemType
	 */
	propValues[FSTYPE] = strdup(nfs_mount->nml_fstype);
	if (propValues[FSTYPE] == NULL) {
		return (cim_false);
	}

	/*
	 * ForegroundMount - This property is not populated because it is only
	 * valid upon creation of a nfs mounted file system.  This is actually
	 * a mount process option and not a mount option.
	 */

	/*
	 * Global - this doesn't really make sense for a nfs file system.
	 * An nfs file system can't be mounted globally on all nodes of a
	 * cluster so this will always be false.
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", B_FALSE);
	propValues[GLOBAL] = strdup(propValue);
	if (propValues[GLOBAL] == NULL) {
		return (cim_false);
	}

	/*
	 * GrpId
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_grpid);
	propValues[GRPID] = strdup(propValue);
	if (propValues[GRPID] == NULL) {
		return (cim_false);
	}

	/*
	 * HardMount
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_hard);
	propValues[HARDMNT] = strdup(propValue);
	if (propValues[HARDMNT] == NULL) {
		return (cim_false);
	}

	/*
	 * InstallDate - Nothing to populate here.
	 */

	/*
	 * Interrupt
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_intr);
	propValues[INTR] = strdup(propValue);
	if (propValues[INTR] == NULL) {
		return (cim_false);
	}

	/*
	 * MaxFileNameLength
	 */
	maxfilenamelen = fs_get_maxfilenamelen(nfs_mount->nml_mountp, &err);
	if (err != 0) {
		util_handleError("SOLARIS_NFS::POPULATE_PROPVALUES",
			CIM_ERR_FAILED, FS_GET_MAXFILENMLEN_FAILURE, NULL,
			&err);
		return (cim_false);
	}
	(void) snprintf(propValue, MAXSIZE, "%ld", maxfilenamelen);
	propValues[MAXFILENMLN] = strdup(propValue);
	if (propValues[MAXFILENMLN] == NULL) {
		return (cim_false);
	}

	/*
	 * MountFailureRetries - This value is only valid upon creation of a
	 * nfs mount.  This is actually a mount process option and not a mount
	 * option.
	 */

	/*
	 * Name -- KEY, Populated with the string:
	 * "resource:=<resource> devid:=<devid>" in order to create a unique
	 * yet readable key.
	 */
	devid = fs_parse_optlist_for_option(nfs_mount->nml_mntopts,
		"dev=", &err);
	if (devid == NULL) {
		util_handleError("SOLARIS_NFS::POPULATE_PROPVALUES",
			CIM_ERR_FAILED, FS_PARSE_OPTLIST_FAILURE, NULL, &err);
		return (cim_false);
	}
	/*
	 * + 2 is for space and null terminating character.
	 */
	nameLen = strlen(resourceStr) + strlen(nfs_mount->nml_resource) +
		strlen(devidStr) + strlen(devid) + 2;

	propValues[NAME] = calloc((size_t)nameLen, (size_t)sizeof (cimchar));
	if (propValues[NAME] == NULL) {
		return (cim_false);
	}

	(void) snprintf(propValues[NAME], nameLen, "%s%s%s%s%s", resourceStr,
		nfs_mount->nml_resource, " ", devidStr, devid);
	free(devid);

	/*
	 * NoMnttabEntry - This will always be false for every file system
	 * that is shown in the CIM/WBEM interface because there is no way
	 * to programatically determine a file system that is mounted if it
	 * is not in /etc/mnttab.  If it is not in /etc/mnttab, it is like
	 * that for a reason and is also an argument for not showing the
	 * existence of those file systems.
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", B_FALSE);
	propValues[NOMNTTABENT] = strdup(propValue);
	if (propValues[NOMNTTABENT] == NULL) {
		return (cim_false);
	}

	/*
	 * NoSuid
	 */
	optHasEquals = B_FALSE;
	noSuid = get_property_from_opt_string(nfs_mount->nml_mntopts,
		"nosuid", optHasEquals, defaultValue);
	if (noSuid == NULL) {
		return (cim_false);
	}
	propValues[NOSUID] = strdup(noSuid);
	if (propValues[NOSUID] == NULL) {
		return (cim_false);
	}
	free(noSuid);

	/*
	 * Overlay - This is a property which is only valid upon creation of a
	 * nfs mount.  It specifies that the file system is to be mounted on
	 * top of another existing mounted file system.
	 */

	/*
	 * Posix
	 */
	optHasEquals = B_FALSE;
	posix = get_property_from_opt_string(nfs_mount->nml_mntopts,
		"posix", optHasEquals, defaultValue);
	if (posix == NULL) {
		return (cim_false);
	}
	propValues[POSIX] = strdup(posix);
	if (propValues[POSIX] == NULL) {
		return (cim_false);
	}
	free(posix);

	/*
	 * Proto
	 */
	propValues[PROTO] = strdup(nfs_mount->nml_proto);
	if (propValues[PROTO] == NULL) {
		return (cim_false);
	}

	/*
	 * Public
	 */
	optHasEquals = B_FALSE;
	public = get_property_from_opt_string(nfs_mount->nml_mntopts,
		"public", optHasEquals, defaultValue);
	if (public == NULL) {
		return (cim_false);
	}
	propValues[PUBLIC] = strdup(public);
	if (propValues[PUBLIC] == NULL) {
		return (cim_false);
	}
	free(public);

	/*
	 * Quota
	 */
	optHasEquals = B_FALSE;
	quota = get_property_from_opt_string(nfs_mount->nml_mntopts,
		"quota", optHasEquals, defaultValue);
	if (quota == NULL) {
		return (cim_false);
	}
	propValues[QUOTA] = strdup(quota);
	if (propValues[QUOTA] == NULL) {
		return (cim_false);
	}
	free(quota);

	/*
	 * ReadBufferSize
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_curread);
	propValues[READBUFFSIZE] = strdup(propValue);
	if (propValues[READBUFFSIZE] == NULL) {
		return (cim_false);
	}

	/*
	 * ReadOnly
	 */
	readonly = fs_is_readonly(nfs_mount->nml_mountp, &err);
	if (err != 0) {
		return (cim_false);
	}
	(void) snprintf(propValue, MAXSIZE, "%d", readonly);
	propValues[READONLY] = strdup(propValue);
	if (propValues[READONLY] == NULL) {
		return (cim_false);
	}

	/*
	 * Remount - This is a property that is only valid upon creation of a
	 * nfs file system mount.  This should not be populated upon the
	 * enumeration of the Solaris_NFS class instances or instanceNames.
	 */

	/*
	 * RetransmissionAttempts
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_retrans);
	propValues[RETRANSATTEMPTS] = strdup(propValue);
	if (propValues[RETRANSATTEMPTS] == NULL) {
		return (cim_false);
	}

	/*
	 * RetransmissionTimeout
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_timeo);
	propValues[RETRANSTIMEO] = strdup(propValue);
	if (propValues[RETRANSTIMEO] == NULL) {
		return (cim_false);
	}

	/*
	 * Root
	 */
	propValues[ROOT] = strdup(nfs_mount->nml_mountp);
	if (propValues[ROOT] == NULL) {
		return (cim_false);
	}

	/*
	 * SecurityMode
	 */
	if (nfs_mount->nml_securitymode != NULL) {
		propValues[SECMODE] = strdup(nfs_mount->nml_securitymode);
		if (propValues[SECMODE] == NULL) {
			return (cim_false);
		}
	}

	/*
	 * ServerCommunicationPort
	 */
	optHasEquals = B_TRUE,
	defaultValue = NFS_PORT;
	port = get_property_from_opt_string(nfs_mount->nml_mntopts,
		"port=", optHasEquals, defaultValue);
	if (port == NULL) {
		return (cim_false);
	}
	propValues[SERVERCOMMPORT] = strdup(port);
	if (propValues[SERVERCOMMPORT] == NULL) {
		return (cim_false);
	}
	free(port);

	/*
	 * Status - Nothing to populate here.
	 */

	/*
	 * UsedSpace
	 */
	usedsize = fs_get_usedsize(nfs_mount->nml_mountp, &err);
	if (err != 0) {
		return (cim_false);
	}
	(void) snprintf(propValue, MAXSIZE, "%lld", usedsize);
	propValues[USEDSPACE] = strdup(propValue);
	if (propValues[USEDSPACE] == NULL) {
		return (cim_false);
	}

	/*
	 * Version
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_vers);
	propValues[VERS] = strdup(propValue);
	if (propValues[VERS] == NULL) {
		return (cim_false);
	}

	/*
	 * WriteBufferSize
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_curwrite);
	propValues[WRITEBUFFSIZE] = strdup(propValue);
	if (propValues[WRITEBUFFSIZE] == NULL) {
		return (cim_false);
	}

	return (cim_true);
} /* populate_property_values */
