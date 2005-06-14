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

#include <errno.h>
#include <sys/wait.h>
#include "cimKeys.h"
#include "util.h"
#include "Solaris_DiskPartition.h"
#include "partition_descriptors.h"
#include "methods.h"
#include "providerNames.h"
#include "messageStrings.h"

#define	DISK_GETINSTANCE	"DISK_PARTITION,GET_INSTANCE"
#define	DISK_ENUMINSTANCES	"DISK_PARTITION,ENUM_INSTANCES"
#define	DISK_ENUMINSTANCENAMES	"DISK_PARTITION,ENUM_INSTANCENAMES"
#define	DISK_CREATEINSTANCE	"DISK_PARTITION,CREATE_INSTANCE"
#define	DISK_DELETEINSTANCE	"DISK_PARTITION,DELETE_INSTANCE"
#define	DISK_SETINSTANCE	"DISK_PARTITION,SET_INSTANCE"
#define	DISK_GETPROPERTY	"DISK_PARTITION,GET_PROPERTY"
#define	DISK_SETPROPERTY	"DISK_PARTITION,SET_PROPERTY"
#define	DISK_INVOKEMETHOD	"DISK_PARTITION,INVOKE_METHOD"
#define	DISK_EXECQUERY		"DISK_PARTITION,EXEC_QUERY"

/*
 * Name: cp_getInstance_Solaris_DiskPartition
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
CCIMInstance *
cp_getInstance_Solaris_DiskPartition(CCIMObjectPath *pOP)
{

	CCIMInstance*		inst = NULL;
	CCIMPropertyList*	pCurPropList;
	CCIMException*		ex;
	dm_descriptor_t		dp_descriptor;
	char			*name;
	int			error;

	if (pOP == NULL ||
	    pOP->mKeyProperties == NULL) {
	    util_handleError(DISK_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	pCurPropList = pOP->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);

	if (error != 0 || name == NULL) {
	    util_handleError(DISK_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	dp_descriptor = dm_get_descriptor_by_name(DM_SLICE, name, &error);

	/*
	 * If not found, could be an fdisk partition.
	 */

	if (error == ENODEV) {
	    dp_descriptor = dm_get_descriptor_by_name(DM_PARTITION, name,
		&error);
	    if (error == ENODEV) {
		return ((CCIMInstance *)NULL);
	    } else if (error != 0) {
		util_handleError(DISK_GETINSTANCE, CIM_ERR_FAILED,
		    DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
		return ((CCIMInstance*)NULL);
	    }
	} else if (error != 0) {
	    util_handleError(DISK_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	/* Turn this descriptor in to a disk partition instance */

	inst = partition_descriptor_toCCIMInstance(
	    hostName, dp_descriptor, DISK_PARTITION, &error);
	dm_free_descriptor(dp_descriptor);

	if (error != 0) {
	    ex = cim_getLastError();
	    util_handleError(DISK_GETINSTANCE, CIM_ERR_FAILED,
		PART_DESC_TO_INSTANCE_FAILURE, ex, &error);
	    return ((CCIMInstance*)NULL);
	}

	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_DiskPartition
 *
 * Description: Returns a list of instances if found.
 *
 * Parameters:
 *      pOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstance * if matched instance is found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_DiskPartition(CCIMObjectPath* pOP)
{

	CCIMInstanceList*	instList = NULL;
	dm_descriptor_t		*dsolpart_descriptorp = NULL;
	dm_descriptor_t		*dfdiskpart_descriptorp = NULL;
	int			error;
	int			filter[2];

	filter[0] = DM_MT_FIXED;
	filter[1] = DM_FILTER_END;

	dsolpart_descriptorp = dm_get_descriptors(DM_SLICE, filter, &error);

	if (error != 0) {
	    util_handleError(DISK_ENUMINSTANCES, CIM_ERR_FAILED,
		DM_GET_DESCRIPTORS, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	dfdiskpart_descriptorp =
	    dm_get_descriptors(DM_PARTITION, filter, &error);

	if (error != 0) {
	    if (dsolpart_descriptorp != NULL) {
		dm_free_descriptors(dsolpart_descriptorp);
	    }
	    util_handleError(DISK_ENUMINSTANCES, CIM_ERR_FAILED,
		DM_GET_DESCRIPTORS, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}


	/*
	 * If both descriptor lists are null, then there is nothing to return.
	 * otherwise, call the conversion function and return what is found.
	 */

	if (dsolpart_descriptorp == NULL && dfdiskpart_descriptorp == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/* Convert the slice descriptors to a CCIMInstanceList */

	instList = partition_descriptors_toCCIMInstanceList(DISK_PARTITION,
	    dsolpart_descriptorp, dfdiskpart_descriptorp, &error);

	if (dsolpart_descriptorp != NULL) {
	    dm_free_descriptors(dsolpart_descriptorp);
	}

	if (dfdiskpart_descriptorp != NULL) {
	    dm_free_descriptors(dfdiskpart_descriptorp);
	}

	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_DiskPartition
 *
 * Description: Returns a list of instances if found.
 *
 * Parameters:
 *      pOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMObjectPathList * if found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_DiskPartition(CCIMObjectPath *pOP) {

	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*objList = NULL;
	int			error = 0;

	if (pOP == NULL) {
	    util_handleError(DISK_ENUMINSTANCENAMES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call to enumInstances and then convert instance list to a list
	 * of object list.
	 */

	instList = cp_enumInstances_Solaris_DiskPartition(pOP);
	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_DiskPartition is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_DiskPartition(CCIMObjectPath* pOP,
    CCIMInstance* pInst)
{
	int	error;

	util_handleError(DISK_CREATEINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return ((CCIMObjectPath*)NULL);
}

/*
 * Deleting an instance of a Solaris_DiskPartition is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_DiskPartition(CCIMObjectPath* pInst)
{
	int	error;

	util_handleError(DISK_DELETEINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_DiskPartition
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
cp_getProperty_Solaris_DiskPartition(CCIMObjectPath *pOP,
    char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error = 0;

	if (pOP == NULL) {
	    util_handleError(DISK_GETPROPERTY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_DiskPartition(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}
/*
 * Deleting an instance of a Solaris_DiskPartition is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_DiskPartition(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int		error;

	util_handleError(DISK_DELETEINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * Setting a property on an instance of a Solaris_DiskPartition is not
 * supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_DiskPartition(CCIMObjectPath* pOP, CCIMProperty* pProp)
{
	int error;

	util_handleError(DISK_SETPROPERTY, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/* invokeMethod function dispatches to the various method implementations */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_DiskPartition(CCIMObjectPath* op, cimchar* methodName,
    CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty	*retVal = (CCIMProperty*)NULL;
	int		error = 0;


	/* dispatch code for various methods */
	if (strcasecmp("CreatePartitions", methodName) == 0) {
	    retVal = create_partitions(inParams, op);
	    return (retVal);
	} else if (strcasecmp("CreateFileSystem", methodName) == 0) {
	    retVal = create_filesystem(op);
	    return (retVal);
	}

	/*
	 * We fell through the dispatch logic.  There is no function
	 * that matches 'methodName'.
	 */

	util_handleError(DISK_INVOKEMETHOD, CIM_ERR_FAILED,
	    NO_SUCH_METHOD, NULL, &error);
	return ((CCIMProperty*)NULL);
}

/*
 * Name: cp_execQuery_Solaris_DiskPartition
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
cp_execQuery_Solaris_DiskPartition(CCIMObjectPath *op, cimchar *selectList,
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

	/* Enumerate all instances */
	instList = cp_enumInstances_Solaris_DiskPartition(op);

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
