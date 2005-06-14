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
#include "providerNames.h"
#include "messageStrings.h"
#include "disk_descriptors.h"
#include "logicaldisk_descriptors.h"
#include "realizesextent_descriptors.h"
#include "Solaris_RealizesExtent.h"

#define	REALIZES_GETINSTANCE		"REALIZES_EXTENT,GET_INSTANCE"
#define	REALIZES_ENUMINSTANCES		"REALIZES_EXTENT,ENUM_INSTANCES"
#define	REALIZES_ENUMINSTANCENAMES \
	"REALIZES_EXTENT,ENUM_INSTANCENAMES"
#define	REALIZES_CREATEINSTANCE		"REALIZES_EXTENT,CREATE_INSTANCE"
#define	REALIZES_DELETEINSTANCE		"REALIZES_EXTENT,DELETE_INSTANCE"
#define	REALIZES_SETINSTANCE		"REALIZES_EXTENT,SET_INSTANCE"
#define	REALIZES_SETPROPERTY		"REALIZES_EXTENT,SET_PROPERTY"
#define	REALIZES_GETPROPERTY		"REALIZES_EXTENT,GET_PROPERTY"
#define	REALIZES_INVOKEMETHOD		"REALIZES_EXTENT,INVOKE_METHOD"
#define	REALIZES_EXECQUERY		"REALIZES_EXTENT,EXEC_QUERY"
#define	REALIZES_ASSOCIATORS		"REALIZES_EXTENT,ASSOCIATORS"
#define	REALIZES_ASSOCIATORNAMES	"REALIZES_EXTENT,ASSOCIATOR_NAMES"
#define	REALIZES_REFERENCES		"REALIZES_EXTENT,REFERENCES"
#define	REALIZES_REFERENCENAMES		"REALIZES_EXTENT,REFERENCE_NAMES"

static
CCIMInstanceList  *
createRealizesExtentList(CCIMObjectPath *pObjectName,
    cimchar *pObjectNameRole,
	CCIMObjectPathList *objList, cimchar *objRole, int *error);
/*
 * Solaris_RealizesExtent provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the door process prior to
 * sending a copy of the data to the CIMOM.
 */

/*
 * Name: cp_getInstance_Solaris_RealizesExtent
 *
 * Description: Returns an instance of Solaris_RealizesExtent if one
 *  is found that matches the object path passed in .
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instance.
 * Returns: CCIMInstance * if match is found, or NULL if not.
 *
 */

CCIMInstance*
cp_getInstance_Solaris_RealizesExtent(CCIMObjectPath* pOP)
{

	CCIMInstance 		*inst = NULL;
	CCIMPropertyList	*pCurPropList;
	CCIMObjectPath		*antOp = NULL;
	CCIMObjectPath		*depOp = NULL;
	dm_descriptor_t		d_descriptor;
	char			*name;
	int			error;


	if (pOP == NULL || pOP->mKeyProperties == NULL) {
	    util_handleError(REALIZES_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	}

	pCurPropList = pOP->mKeyProperties;
	antOp = (CCIMObjectPath *)util_getKeyValue(pCurPropList, reference,
	    ANTECEDENT, &error);

	if (error == 0) {
	    depOp = (CCIMObjectPath *)util_getKeyValue(pCurPropList, reference,
		DEPENDENT, &error);
	}

	/*
	 * Make sure we have both keys. If not, this is an error.
	 */

	if (error != 0) {
	    util_handleError(REALIZES_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Now get the name of the antecedent from the object path.
	 */

	if (antOp->mKeyProperties == NULL ||
	    depOp->mKeyProperties == NULL) {
	    util_handleError(REALIZES_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	pCurPropList = antOp->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string, TAG, &error);

	if (error != 0 || name == NULL) {
	    util_handleError(REALIZES_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	d_descriptor = dm_get_descriptor_by_name(DM_MEDIA, name, &error);

	/*
	 * Not found. Return a null instance.
	 */

	if (error == ENODEV || d_descriptor == NULL) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(REALIZES_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Turn this in to a realizes extent instance.
	 */

	inst = realizesextent_descriptor_toCCIMInstance(hostName, d_descriptor,
	    REALIZES_EXTENT, &error);
	dm_free_descriptor(d_descriptor);

	if (error != 0) {
	    util_handleError(REALIZES_GETINSTANCE, CIM_ERR_FAILED,
		REALIZESEXT_DESC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_RealizesExtent
 *
 * Description: Returns a linked list of instances of this association.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMInstanceList * if istances are found. NULL otherwise.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_RealizesExtent(CCIMObjectPath* pOP)
{
	CCIMInstanceList* 	instList = NULL;
	CCIMInstance*		inst;
	CCIMException*		ex;
	dm_descriptor_t		*disk_descriptorp = NULL;
	int			error = 0;
	int			filter[2];
	int			i = 0;

	filter[0] = DM_MT_FIXED;
	filter[1] = DM_FILTER_END;


	disk_descriptorp = dm_get_descriptors(DM_MEDIA, filter, &error);
	if (disk_descriptorp == NULL ||
	    disk_descriptorp[0] == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}
	if (error != 0) {
	    util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		DM_GET_DESCRIPTORS, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * For each one of the disks found, generate the physical and
	 * logical views and create an association instance.
	 */

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    dm_free_descriptors(disk_descriptorp);
	    return ((CCIMInstanceList *)NULL);
	}

	for (i = 0; disk_descriptorp[i] != NULL; i ++) {
	    inst = realizesextent_descriptor_toCCIMInstance(hostName,
		disk_descriptorp[i], REALIZES_EXTENT, &error);
	    if (error != 0) {
		util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		    REALIZESEXT_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		dm_free_descriptors(disk_descriptorp);
		return ((CCIMInstanceList *)NULL);
	    }
	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, NULL, &error);
		dm_free_descriptors(disk_descriptorp);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	}

	dm_free_descriptors(disk_descriptorp);
	if (instList->mDataObject == NULL) {
	    cim_freeInstanceList(instList);
	    instList = NULL;
	}
	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_RealizesExtent
 *
 * Description: Returns a linked list of CCIMObjectPath *
 *      of Solaris_RealizesExtent objects if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMObjectPathList * if objects are found. NULL otherwise.
 */

/* ARGSUSED */
CCIMObjectPathList*
cp_enumInstanceNames_Solaris_RealizesExtent(CCIMObjectPath * pOP) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pOP == NULL) {
	    util_handleError(REALIZES_ENUMINSTANCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call in to enumInstances and then convert the instance list in
	 * to an object list.
	 */

	instList = cp_enumInstances_Solaris_RealizesExtent(pOP);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_RealizesExtent is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_RealizesExtent(
    CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(REALIZES_CREATEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return ((CCIMObjectPath *)NULL);
}


/*
 * Deleting an instance of a Solaris_RealizesExtent is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_RealizesExtent(CCIMObjectPath* pInst)
{
	int	error;

	util_handleError(REALIZES_DELETEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_RealizesExtent
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
cp_getProperty_Solaris_RealizesExtent(CCIMObjectPath *pOP,
    char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error = 0;

	if (pOP == NULL) {
	    util_handleError(REALIZES_GETPROPERTY,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_RealizesExtent(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}

/*
 * Setting an instance of a Solaris_RealizesExtent is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_RealizesExtent(
    CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(REALIZES_SETINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return (cim_false);
}


/*
 * Setting a property on a Solaris_RealizesExtent is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_RealizesExtent(
    CCIMObjectPath* pOP, CCIMProperty* pProp)
{
	int	error;

	util_handleError(REALIZES_SETPROPERTY, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return (cim_false);
}

/*
 * No Methods for Solaris_RealizesExtent.
 */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_RealizesExtent(
    CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty	*retVal = (CCIMProperty *)NULL;
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_RealizesExtent
 *
 * Description:
 * Returns an instance list which matches the query if any are found.
 *
 * Parameters:
 *	CCIMObjectPath *op - An CCIMObjectPath * which contains the
 *	information on the class for which to find the instances.
 *
 * 	selectList - Not used
 *	nonJoinExp - Not used
 *
 * Returns:
 *	CCIMInstance * if matched instance is found. Otherwise, NULL.
 */
/*
 * Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_execQuery_Solaris_RealizesExtent(
    CCIMObjectPath *op, cimchar *selectList, cimchar *nonJoinExp,
	cimchar *queryExp, int queryType)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstanceList	*result;
	CCIMInstance		*emptyInst;
	CCIMException		*ex;
	int			error;

	if (op == NULL) {
	    util_handleError(REALIZES_EXECQUERY,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cp_enumInstances_Solaris_RealizesExtent(op);

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
	    util_handleError(REALIZES_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_createInstanceList();
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(REALIZES_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_addInstance(result, emptyInst);
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(REALIZES_EXECQUERY, CIM_ERR_FAILED,
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

/*
 * Name: cp_associators_Solaris_RealizesExtent
 *
 * Description:
 * Returns a instances of objects associated with the passed in
 * object if there are any.
 *
 * Parameters:
 *
 *	CCIMObjectPath *pAssocName - The name of the association that
 *	the client wants information about.
 *
 *	CCIMObjectPath *pObjectName - An CCIMObjectPath * which contains the
 *	information on the class for which to find the associated instances.
 *
 *	cimchar *pResultClass - If specified, only return instances that
 *	are of this class type.
 *
 *      cimchar *pRole - If specified, must be valid for the object path
 *	passed in requesting the associated instances.
 *
 *	cimchar *pResultRole - If specified, only return instances that
 *	are playing this role in the association.
 *
 *
 * Returns:
 *	CCIMInstanceList * if associated objects are found. NULL otherwise.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_RealizesExtent(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{
	CCIMPropertyList	*pCurPropList;
	CCIMInstanceList	*instList = NULL;
	CCIMInstance		*inst;
	CCIMException		*ex;
	dm_descriptor_t		obj_desc;
	char			*name;
	int			error = 0;
	int			isAntecedent = 0;


	if (pObjectName == NULL ||
	    pObjectName->mName == NULL ||
		pObjectName->mKeyProperties == NULL) {
	    util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	}

	if (strcasecmp(pObjectName->mName, DISK) == 0) {
	    isAntecedent = 1;
	}

	if (pRole != NULL) {
	    if (strcasecmp(pRole, ANTECEDENT) == 0) {
		if (isAntecedent != 1) {
		    util_handleError(REALIZES_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    }
	}

	pCurPropList = pObjectName->mKeyProperties;

	/*
	 * Get the key. It will either be deviceid or tag. These are
	 * mutually exclusive.
	 */

	if (isAntecedent) {
	    name = (cimchar *)util_getKeyValue(pCurPropList, string, TAG,
		&error);
	} else {
	    name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
		&error);
	}

	/*
	 * We went through the whole list and didn't find the necessary
	 * key value.
	 */

	if (error != 0 || name == NULL) {
	    util_handleError(REALIZES_ASSOCIATORS,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	obj_desc = dm_get_descriptor_by_name(DM_MEDIA, name, &error);
	/*
	 * No device found.
	 */
	if (error == ENODEV || obj_desc == NULL) {
	    return (instList);
	}

	if (error != 0) {
	    util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent == 1) {
		/*
		 * Physical disk calling this method, return instances of the
		 * logical disk associated with this disk.
		 */

	    inst = logicaldisk_descriptor_toCCIMInstance(hostName,
		    obj_desc, LOGICAL_DISK, &error);
	    dm_free_descriptor(obj_desc);

	    if (error != 0) {
		util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		    LOGICALDISK_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_createInstanceList();
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		    CREATE_INSTANCE_FAILURE, ex, &error);
		return ((CCIMInstanceList *)NULL);
	    }
	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, &error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	} else {
		/*
		 * This is the logical disk calling this function. Return the
		 * disk that this belongs to.
		 */

	    inst = disk_descriptor_toCCIMInstance(hostName, obj_desc,
		DISK, &error);
	    dm_free_descriptor(obj_desc);

	    if (error != 0) {
		util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		    DISK_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_createInstanceList();
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		    CREATE_INSTANCE_FAILURE, ex, &error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, &error);
		return ((CCIMInstanceList *)NULL);
	    }
	}

	return (instList);
}

/*
 * Name: cp_associatorNames_Solaris_RealizesExtent
 *
 * Description:
 * Returns a list of objects associated with the passed in
 * object if there are any via the object CCIMObjectPath.
 *
 * Parameters:
 *
 *	CCIMObjectPath *pAssocName - The name of the association that
 *	the client wants information about.
 *
 *	CCIMObjectPath *pObjectName - An CCIMObjectPath * which contains the
 *	information on the class for which to find the associated instances.
 *
 *	cimchar *pResultClass - If specified, only return instances that
 *	are of this class type.
 *
 *      cimchar *pRole - If specified, must be valid for the object path
 *	passed in requesting the associated instances.
 *
 *	cimchar *pResultRole - If specified, only return instances that
 *	are playing this role in the association.
 *
 *
 * Returns:
 *	CCIMObjectPathList * if associated objects are found. NULL otherwise.
 */

/* ARGSUSED */
CCIMObjectPathList *
cp_associatorNames_Solaris_RealizesExtent(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;


	if (pObjectName == NULL) {
	    util_handleError(REALIZES_ASSOCIATORNAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_associators_Solaris_RealizesExtent(
		pAssocName, pObjectName, pResultClass, pRole, pResultRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Name: cp_references_Solaris_RealizesExtent
 *
 * Description:
 * Returns a instances of objects that have references to the passed in
 * object if there are any.
 *
 * Parameters:
 *
 *	CCIMObjectPath *pAssocName - The name of the association that
 *	the client wants information about.
 *
 *	CCIMObjectPath *pObjectName - An CCIMObjectPath * which contains the
 *	information on the class for which to find the associated instances.
 *
 *      cimchar *pRole - If specified, must be valid for the object path
 *	passed in requesting the associated instances.
 *
 * Returns:
 *	CCIMObjectPathList * if associated objects are found. NULL otherwise.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_references_Solaris_RealizesExtent(CCIMObjectPath *pAssocName,
CCIMObjectPath *pObjectName, char *pRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;


	if (pObjectName == NULL) {
	    util_handleError(REALIZES_REFERENCES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	/*
	 * Get the list of those objects that are referred to by
	 * the calling object.
	 */

	objList =
	    cp_associatorNames_Solaris_RealizesExtent(
		pAssocName, pObjectName, NULL, NULL, NULL);

	if (objList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Now generate the list of instances to return.
	 */

	if (strcasecmp(pObjectName->mName, DISK) == 0) {
	    instList = createRealizesExtentList(pObjectName,
		ANTECEDENT, objList, DEPENDENT, &error);
	} else {
	    instList = createRealizesExtentList(pObjectName,
		DEPENDENT, objList, ANTECEDENT, &error);
	}

	cim_freeObjectPathList(objList);
	return (instList);
}

/*
 * Name: cp_referenceNames_Solaris_RealizesExtent
 *
 * Description:
 * Returns a instances of objects that have references to the passed in
 * object if there are any.
 *
 * Parameters:
 *
 *	CCIMObjectPath *pAssocName - The name of the association that
 *	the client wants information about.
 *
 *	CCIMObjectPath *pObjectName - An CCIMObjectPath * which contains the
 *	information on the class for which to find the associated instances.
 *
 *      cimchar *pRole - If specified, must be valid for the object path
 *	passed in requesting the associated instances.
 *
 *
 * Returns:
 *	CCIMObjectPathList * if associated objects are found. NULL otherwise.
 *
 */

/* ARGSUSED */
CCIMObjectPathList *
cp_referenceNames_Solaris_RealizesExtent(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pRole)
{

	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(REALIZES_REFERENCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_references_Solaris_RealizesExtent(pAssocName,
		pObjectName, pRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Create the association class with the passed in attributes.
 */
static
CCIMInstanceList  *
createRealizesExtentList(CCIMObjectPath *pObjectName,
    cimchar *pObjectNameRole,
	CCIMObjectPathList *objList, cimchar *objRole, int *error)
{

	CCIMObjectPathList	*tmpList;
	CCIMInstanceList	*instList = NULL;
	CCIMInstance		*inst;
	CCIMObjectPath		*obj1;
	CCIMObjectPath		*obj2;
	CCIMException		*ex;

	*error = 0;

	/*
	 * If no objects associated with this one, return NULL.
	 */
	if (objList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(REALIZES_EXTENT, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstanceList *)NULL);
	}

	tmpList = objList;
	while (tmpList != NULL) {
	    obj1 = tmpList->mDataObject;
	    obj2 = cim_copyObjectPath(pObjectName);
	    if (obj2 == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_EXTENT, CIM_ERR_FAILED,
		    COPY_OBJPATH_FAILURE, ex, error);
		return ((CCIMInstanceList *)NULL);
	    }

	    inst = cim_createInstance(REALIZES_EXTENT);
	    if (inst == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_EXTENT, CIM_ERR_FAILED,
		    CREATE_INSTANCE_FAILURE, ex, error);
		return ((CCIMInstanceList *)NULL);
	    }

	    util_doReferenceProperty(pObjectNameRole, obj2, cim_true, inst,
		error);
	    cim_freeObjectPath(obj2);

	    if (*error != 0) {
		ex = cim_getLastError();
		util_handleError(REALIZES_EXTENT, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }

	    util_doReferenceProperty(objRole, obj1, cim_true, inst, error);

	    if (*error != 0) {
		ex = cim_getLastError();
		util_handleError(REALIZES_EXTENT, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_EXTENT, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }

	    tmpList = tmpList->mNext;
	}
	return (instList);
}
