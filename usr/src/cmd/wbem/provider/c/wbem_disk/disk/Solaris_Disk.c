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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include "util.h"
#include "cimKeys.h"
#include "methods.h"
#include "disk_descriptors.h"
#include "providerNames.h"
#include "messageStrings.h"

#define	DISK_GETINSTANCE	"DISK,GET_INSTANCE"
#define	DISK_ENUMINSTANCES	"DISK,ENUM_INSTANCES"
#define	DISK_ENUMINSTANCENAMES	"DISK,ENUM_INSTANCENAMES"
#define	DISK_CREATEINSTANCE	"DISK,CREATE_INSTANCE"
#define	DISK_DELETEINSTANCE	"DISK,DELETE_INSTANCE"
#define	DISK_SETINSTANCE	"DISK,SET_INSTANCE"
#define	DISK_GETPROPERTY	"DISK,GET_PROPERTY"
#define	DISK_SETPROPERTY	"DISK,SET_PROPERTY"
#define	DISK_INVOKEMETHOD	"DISK,INVOKE_METHOD"
#define	DISK_EXECQUERY		"DISK,EXEC_QUERY"

/*
 * Solaris_Disk provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the CIMOM as the caller.
 */


/*
 * Name: cp_getInstance_Solaris_Disk
 *
 * Description: Returns an instance which matches the passed in object path
 * if found.
 *
 * Parameters:
 *      pOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstance * if matched instance is found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMInstance*
cp_getInstance_Solaris_Disk(CCIMObjectPath* pOP)
{
	CCIMInstance		*inst = NULL;
	CCIMPropertyList	*pCurPropList;
	dm_descriptor_t		disk_descriptor;
	char			*name;
	int			error;

	if (pOP == NULL || pOP->mKeyProperties == NULL) {
	    util_handleError(DISK_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	pCurPropList = pOP->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string, TAG, &error);

	if (error != 0 || name == NULL) {
	    util_handleError(DISK_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	disk_descriptor = dm_get_descriptor_by_name(DM_MEDIA, name, &error);

	/*
	 * Not found. Return a null instance.
	 */
	if (error == ENODEV) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(DISK_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/* Turn this descriptor in to a disk drive instance */

	inst = disk_descriptor_toCCIMInstance(
	    hostName, disk_descriptor, DISK, &error);
	dm_free_descriptor(disk_descriptor);

	if (error != 0) {
	    util_handleError(DISK_GETINSTANCE, CIM_ERR_FAILED,
		DISK_DESC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_Disk
 *
 * Description: Returns a list of instances if found.
 *
 * Parameters:
 *      pOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstanceList * if matched instance is found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_Disk(CCIMObjectPath* pOP)
{
	CCIMInstanceList* 	instList = NULL;
	dm_descriptor_t		*disk_descriptorp;
	int			error;

	disk_descriptorp = dm_get_descriptors(DM_MEDIA, NULL, &error);

	if (disk_descriptorp == NULL ||
	    disk_descriptorp[0] == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}
	if (error != 0) {
	    util_handleError(DISK_ENUMINSTANCENAMES, CIM_ERR_FAILED,
		DM_GET_DESCRIPTORS, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/* convert drive descriptors to CCIMInstanceList */
	instList = disk_descriptors_toCCIMInstanceList(DISK,
	    disk_descriptorp, &error);
	dm_free_descriptors(disk_descriptorp);

	if (error != 0) {
	    util_handleError(DISK_ENUMINSTANCES, CIM_ERR_FAILED,
		DISK_DESC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_Disk
 *
 * Description: Returns a list of instances if found.
 *
 * Parameters:
 *      pOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMObjectPathList * if matched instance is found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMObjectPathList*
cp_enumInstanceNames_Solaris_Disk(CCIMObjectPath * pOP) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pOP == NULL) {
	    util_handleError(DISK_ENUMINSTANCENAMES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call in to enumInstances and then convert the instance list in
	 * to an object list.
	 */

	instList = cp_enumInstances_Solaris_Disk(pOP);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_Disk is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_Disk(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(DISK_CREATEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return ((CCIMObjectPath *)NULL);
}

/*
 * Deleting an instance of a Solaris_Disk is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_Disk(CCIMObjectPath* pInst)
{

	int	error;

	util_handleError(DISK_DELETEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_Disk
 *
 * Description: Returns the property requested, if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMProperty * if found.
 */

/* ARGSUSED */
CCIMProperty	*
cp_getProperty_Solaris_Disk(CCIMObjectPath *pOP, char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error;

	if (pOP == NULL) {
	    util_handleError(DISK_GETPROPERTY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_Disk(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}

/* This provider cannot set an instance of a Solaris_Disk object. */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_Disk(CCIMObjectPath* pOP, CCIMInstance* pInst)
{

	int	error;

	util_handleError(DISK_SETINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL, NULL,
	    &error);
	return (cim_false);
}

/* This provider cannot set an instance of a Solaris_Disk object. */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_Disk(CCIMObjectPath* pOP, CCIMProperty* pProp)
{

	int	error;

	util_handleError(DISK_SETPROPERTY, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return (cim_false);
}

/* invokeMethod function dispatches to the various method implementations */
CCIMProperty*
cp_invokeMethod_Solaris_Disk(CCIMObjectPath* op, cimchar* methodName,
    CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty	*retVal = (CCIMProperty *)NULL;
	int		error;

	/* dispatch code for various methods */
	if (strcasecmp("createFDiskPartitions", methodName) == 0) {
		retVal = create_fdisk_partitions(inParams, op);
		return (retVal);
	} else if (strcasecmp("createPartitions", methodName) == 0) {
		retVal = create_partitions(inParams, op);
		return (retVal);
	} else if (strcasecmp("labelDisk", methodName) == 0) {
		retVal = label_disk(inParams, op);
		return (retVal);
	} else if (strcasecmp("getDiskGeometry", methodName) == 0) {
		retVal = get_disk_geometry(outParams, op);
		return (retVal);
	}

	/*
	 * We fell through the dispatch logic.  There is no function
	 * that matches 'methodName'.
	 */

	util_handleError(DISK_INVOKEMETHOD, CIM_ERR_FAILED,
	    NO_SUCH_METHOD, NULL, &error);
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_Disk
 *
 * Description:
 * Returns an instance list which matches the query if any are found.
 *
 * Parameters:
 *      CCIMObjectPath *op - An CCIMObjectPath * which contains the
 *      information on the class for which to find the instances.
 *
 *      selectList - Not used
 *      nonJoinExp - Not used
 *
 * Returns:
 *      CCIMInstance * if matched instance is found. Otherwise, NULL.
 */

/*
 * Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_execQuery_Solaris_Disk(CCIMObjectPath *op, cimchar *selectList,
    cimchar *nonJoinExp, cimchar *queryExp, int queryType)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstanceList	*result;
	CCIMInstance		*emptyInst;
	CCIMException		*ex;
	int			error;

	if (op == NULL) {
	    util_handleError(DISK_EXECQUERY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cp_enumInstances_Solaris_Disk(op);

	if (instList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}
	/*
	 * Create a null instance and add it to the beginning
	 * of the list to indicate to the CIMOM that no filtering
	 * was done.
	 */

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISK_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, &error);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_createInstanceList();
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISK_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_addInstance(result, emptyInst);
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISK_EXECQUERY, CIM_ERR_FAILED,
		ADD_INSTANCE_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Since copying the original list to the new list will
	 * leave no way to free the original list, manually
	 * concatenate the original list to the new one.
	 */

	result->mNext = instList;
	return (result);
}
