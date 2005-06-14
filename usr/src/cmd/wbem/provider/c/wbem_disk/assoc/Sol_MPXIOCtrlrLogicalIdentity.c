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
#include "ctrl_descriptors.h"
#include "mpxiogroup_descriptors.h"
#include "Sol_MPXIOCtrlrLogicalIdentity.h"


#define	LOGID_GETINSTANCE		"MPXIO_LOGICALIDENTITY,GET_INSTANCE"
#define	LOGID_ENUMINSTANCES		"MPXIO_LOGICALIDENTITY,ENUM_INSTANCES"
#define	LOGID_ENUMINSTANCENAMES \
	"MPXIO_LOGICALIDENTITY,ENUM_INSTANCENAMES"
#define	LOGID_CREATEINSTANCE		"MPXIO_LOGICALIDENTITY,CREATE_INSTANCE"
#define	LOGID_DELETEINSTANCE		"MPXIO_LOGICALIDENTITY,DELETE_INSTANCE"
#define	LOGID_SETINSTANCE		"MPXIO_LOGICALIDENTITY,SET_INSTANCE"
#define	LOGID_SETPROPERTY		"MPXIO_LOGICALIDENTITY,SET_PROPERTY"
#define	LOGID_GETPROPERTY		"MPXIO_LOGICALIDENTITY,GET_PROPERTY"
#define	LOGID_INVOKEMETHOD		"MPXIO_LOGICALIDENTITY,INVOKE_METHOD"
#define	LOGID_EXECQUERY			"MPXIO_LOGICALIDENTITY,EXEC_QUERY"
#define	LOGID_ASSOCIATORS		"MPXIO_LOGICALIDENTITY,ASSOCIATORS"
#define	LOGID_ASSOCIATORNAMES		"MPXIO_LOGICALIDENTITY,ASSOCIATOR_NAMES"
#define	LOGID_REFERENCES		"MPXIO_LOGICALIDENTITY,REFERENCES"
#define	LOGID_REFERENCENAMES		"MPXIO_LOGICALIDENTITY,REFERENCE_NAMES"

static
CCIMInstanceList *
mpxioLogIdentAssocToInstList(CCIMObjectPath *pObjectName,
    cimchar *pObjectNameRole, CCIMObjectPathList *objList,
	cimchar *objRole, int *error);

static
CCIMInstance  *
mpxioLogIdentAssocToInst(CCIMObjectPath *obj1, cimchar *obj1Role,
	CCIMObjectPath *obj2, cimchar *obj2Role, int *error);

/*
 * Solaris_MPXIOCtrlrLogicalIdentity provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the door process prior to
 * sending a copy of the data to the CIMOM.
 */

/*
 * Name: cp_getInstance_Solaris_MPXIOCtrlrLogicalIdentity
 *
 * Description: Returns an instance which matches the passed in object path
 * if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instance.
 * Returns:
 *	CCIMInstance * if matched instance is found. Otherwise, NULL.
 */

CCIMInstance*
cp_getInstance_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath* pOP)
{
	CCIMInstance		*inst = NULL;
	CCIMPropertyList	*pCurPropList;
	CCIMObjectPath		*antOp = NULL;
	CCIMObjectPath		*depOp = NULL;
	dm_descriptor_t		c_descriptor;
	char			*name;
	int			error;

	if (pOP == NULL ||
		((pCurPropList = pOP->mKeyProperties) == NULL)) {
	    util_handleError(LOGID_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	antOp = (CCIMObjectPath *)util_getKeyValue(pCurPropList, reference,
	    SYSTEM_ELEMENT, &error);

	if (error == 0) {
	    depOp = (CCIMObjectPath *)util_getKeyValue(pCurPropList, reference,
	    SAME_ELEMENT, &error);
	}

	if (error != 0) {
	    util_handleError(LOGID_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Now, get the name of the antecedent from the object path.
	 */

	if ((pCurPropList = antOp->mKeyProperties) == NULL) {
	    util_handleError(LOGID_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);

	if (error != 0) {
	    util_handleError(LOGID_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * The only reason it is needed to get the descriptor for these
	 * two devices is to verify that they still exist and are valid.
	 * If they are not found, then getting the instance for this
	 * association as passed in by the client is not possible.
	 */
	c_descriptor = dm_get_descriptor_by_name(DM_CONTROLLER, name,
	    &error);
	/*
	 * Not found. Return a null instance.
	 */

	if (error == ENODEV) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(LOGID_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	dm_free_descriptor(c_descriptor);

	/*
	 * At this point I have verified I have the controller device that
	 * are part of this association. Use the object paths I got
	 * earlier to create the mpxiologicalident instance.
	 */
	inst = mpxioLogIdentAssocToInst(antOp, SYSTEM_ELEMENT, depOp,
	    SAME_ELEMENT, &error);

	if (error != 0) {
	    util_handleError(LOGID_GETINSTANCE, CIM_ERR_FAILED,
		MPXIOINT_ASSOC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_MPXIOCtrlrLogicalIdentity
 *
 * Description: Returns a linked list of instances of
 *      Solaris_MPXIOCtrlrLogicalIdentity if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMInstanceList * if istances are found.
 *	Otherwise, NULL is returned.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath* pOP)
{
	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*cObjList = NULL;
	CCIMObjectPathList	*tmpObjList;
	CCIMObjectPath		*objPath;
	CCIMException		*ex;
	int			error = 0;

	/*
	 * Get the list of MPXIO Controllers. Then generate the list
	 * of mpxio groups from these controllers.
	 */

	objPath = cim_createEmptyObjectPath(MPXIO_CONTROLLER);
	if (objPath == NULL) {
	    ex = cim_getLastError();
	    util_handleError(LOGID_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_OBJECT_PATH, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	cObjList = cimom_enumerateInstanceNames(objPath, cim_false);
	cim_freeObjectPath(objPath);

	/*
	 * NULL is error.
	 */
	if (cObjList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(LOGID_ENUMINSTANCES, CIM_ERR_FAILED,
		ENUM_INSTANCENAMES_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (cObjList->mDataObject == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Loop through all of these controller objects and get the associated
	 * disks.
	 */

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(LOGID_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * For each of the object paths found above, generate the group
	 * object path that is associated with it. If, there is an MPXIO
	 * controller, there will automatically be an MPXIOGroup object
	 * because of the nature of this controllers identity.
	 */

	for (tmpObjList = cObjList; tmpObjList != NULL;
	    tmpObjList = tmpObjList->mNext) {

	    CCIMObjectPath 	*cOp;
	    CCIMInstance	*tmpInst;
	    CCIMInstance	*tmpInst1;
	    CCIMPropertyList	*pCurPropList;
	    CCIMObjectPath	*dObjPath;
	    dm_descriptor_t	c_descriptor;
	    char 		*name = NULL;

	    cOp = tmpObjList->mDataObject;
	    if ((pCurPropList = cOp->mKeyProperties) == NULL) {
		util_handleError(LOGID_ENUMINSTANCES,
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    name = (cimchar *)util_getKeyValue(pCurPropList, string,
		DEVICEID, &error);
	    if (error != 0) {
		util_handleError(LOGID_ENUMINSTANCES,
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }
	    c_descriptor = dm_get_descriptor_by_name(DM_CONTROLLER, name,
		&error);
	    if (error == ENODEV) {
		continue;
	    }
	    if (error != 0) {
		util_handleError(LOGID_ENUMINSTANCES, CIM_ERR_FAILED,
		    DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }
	    tmpInst = mpxiogroup_descriptor_toCCIMInstance(
		c_descriptor, MPXIO_GROUP, &error);
	    dm_free_descriptor(c_descriptor);

	    if (error != 0) {
		util_handleError(LOGID_ENUMINSTANCES, CIM_ERR_FAILED,
		    MPXIOGRP_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    dObjPath = cim_createObjectPath(tmpInst);
	    cim_freeInstance(tmpInst);

	    if (dObjPath == NULL) {
		util_handleError(LOGID_ENUMINSTANCES, CIM_ERR_FAILED,
		    CREATE_OBJECT_PATH_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    tmpInst1 = mpxioLogIdentAssocToInst(
		cOp, SYSTEM_ELEMENT, dObjPath, SAME_ELEMENT, &error);
	    cim_freeObjectPath(dObjPath);

	    if (error != 0) {
		util_handleError(LOGID_ENUMINSTANCES, CIM_ERR_FAILED,
		    DRIVE_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_addInstance(instList, tmpInst1);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(LOGID_ENUMINSTANCES, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, &error);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }
	} /* end for */

	cim_freeObjectPathList(cObjList);

	/*
	 * It is possible I will have an empty instance list at
	 * this point. So, I must check and NULL this out if
	 * there are no entries.
	 */

	if (instList->mDataObject == NULL) {
	    cim_freeInstanceList(instList);
	    instList = NULL;
	}
	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_MPXIOCtrlrLogicalIdentity
 *
 * Description: Returns a linked list of CCIMObjectPath *
 *      of Solaris_MPXIOCtrlrLogicalIdentity if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMObjectPathList * if objects are found. NULL otherwise.
 */

CCIMObjectPathList*
cp_enumInstanceNames_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath * pOP) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pOP == NULL) {
	    util_handleError(LOGID_ENUMINSTANCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call in to enumInstances and then convert the instance list in
	 * to an object list.
	 */

	instList = cp_enumInstances_Solaris_MPXIOCtrlrLogicalIdentity(pOP);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_MPXIOCtrlrLogicalIdentity is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath* pOP,
    CCIMInstance* pInst)
{
	int	error;

	util_handleError(LOGID_CREATEINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return ((CCIMObjectPath *)NULL);
}


/*
 * Deleting an instance of a Solaris_MPXIOCtrlrLogicalIdentity is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath* pInst)
{
	int	error;

	util_handleError(LOGID_DELETEINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_MPXIOCtrlrLogicalIdentity
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
cp_getProperty_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath *pOP,
    char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error = 0;

	if (pOP == NULL) {
	    util_handleError(LOGID_GETPROPERTY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_MPXIOCtrlrLogicalIdentity(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}

/*
 * Setting an instance of a Solaris_MPXIOCtrlrLogicalIdentity is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath* pOP,
    CCIMInstance* pInst)
{
	int	error;

	util_handleError(LOGID_SETINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * Setting a property on a Solaris_MPXIOCtrlrLogicalIdentity is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath* pOP,
    CCIMProperty* pProp)
{
	int	error;

	util_handleError(LOGID_SETPROPERTY, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * No Methods for Solaris_MPXIOCtrlrLogicalIdentity.
 */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_MPXIOCtrlrLogicalIdentity(
    CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty	*retVal = (CCIMProperty	*)NULL;
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_MPXIOCtrlrLogicalIdentity
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
cp_execQuery_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath *op,
    cimchar *selectList, cimchar *nonJoinExp, cimchar *queryExp, int queryType)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstanceList	*result;
	CCIMInstance		*emptyInst;
	CCIMException		*ex;
	int			error;

	if (op == NULL) {
	    util_handleError(LOGID_EXECQUERY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cp_enumInstances_Solaris_MPXIOCtrlrLogicalIdentity(op);

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
	    util_handleError(LOGID_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, &error);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_createInstanceList();
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(LOGID_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_addInstance(result, emptyInst);
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(LOGID_EXECQUERY, CIM_ERR_FAILED,
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
 * Name: cp_associators_Solaris_MPXIOCtrlrLogicalIdentity
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
cp_associators_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{
	CCIMPropertyList	*pCurPropList;
	CCIMInstance		*inst;
	CCIMInstanceList	*instList = NULL;
	CCIMException		*ex;
	dm_descriptor_t		obj_desc;
	char			*name;
	int			error = 0;
	int			isSystem = 0;


	if (pObjectName == NULL ||
	    ((pCurPropList = pObjectName->mKeyProperties) == NULL)) {
	    util_handleError(LOGID_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (strcasecmp(pObjectName->mName, MPXIO_CONTROLLER) == 0) {
	    isSystem = 1;
	}

	if (pRole != NULL) {
	    if (strcasecmp(pRole, SYSTEM_ELEMENT) == 0) {
		if (isSystem != 1) {
		    util_handleError(LOGID_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    } else if (strcasecmp(pRole, SAME_ELEMENT) == 0) {
		if (isSystem == 1) {
		    util_handleError(LOGID_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    }
	}

	if (isSystem) {
	    name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
		&error);
	} else {
	    name = (cimchar *)util_getKeyValue(pCurPropList, string, "Name",
		&error);
	}

	if (error != 0) {
	    util_handleError(LOGID_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * In this case, it does not matter which object called it for
	 * getting the descriptor. This is an association which represents
	 * another identity of the controller, so the only device we
	 * really have is the controller.
	 */
	obj_desc = dm_get_descriptor_by_name(DM_CONTROLLER, name, &error);

	if (error == ENODEV) {
	    return ((CCIMInstanceList *)NULL);
	}
	if (error != 0) {
	    util_handleError(LOGID_ASSOCIATORS, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isSystem == 1) {
		/*
		 * Generate associated mpxio group.
		 */

	    inst = mpxiogroup_descriptor_toCCIMInstance(obj_desc,
		MPXIO_GROUP, &error);
	    dm_free_descriptor(obj_desc);

	    if (error != 0) {
		util_handleError(LOGID_ASSOCIATORS,  CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	} else {
		/*
		 * This is the mpxio group calling this function. Return the
		 * controllers that are associated with this group.
		 */
	    inst = ctrl_descriptor_toCCIMInstance(hostName,
		obj_desc, MPXIO_CONTROLLER, &error);
	    dm_free_descriptor(obj_desc);

	    if (error != 0) {
		util_handleError(LOGID_ASSOCIATORS, CIM_ERR_FAILED,
		    MPXIOCTRL_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	}

	/*
	 * Now generate the instance list for return. This is a strange
	 * association since it is always only possible to have one
	 * associated object no matter what is the calling object.
	 */

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    cim_getLastError();
	    util_handleError(LOGID_ASSOCIATORS, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, NULL, &error);
	    cim_freeInstance(inst);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cim_addInstance(instList, inst);
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(LOGID_ASSOCIATORS, CIM_ERR_FAILED,
		ADD_INSTANCE_FAILURE, ex, &error);
	    cim_freeInstance(inst);
	    return ((CCIMInstanceList *)NULL);
	}
	return (instList);
}

/*
 * Name: cp_associatorNames_Solaris_MPXIOCtrlrLogicalIdentity
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
 *	CCIMObjectPathList * if associated objects are found. Otherwise NULL.
 */

/* ARGSUSED */
CCIMObjectPathList *
cp_associatorNames_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(LOGID_ASSOCIATORNAMES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_associators_Solaris_MPXIOCtrlrLogicalIdentity(
		pAssocName, pObjectName, pResultClass, pRole, pResultRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}
	return (objList);
}

/*
 * Name: cp_references_Solaris_MPXIOCtrlrLogicalIdentity
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
 *	CCIMObjectPathList * if associated objects are found. Otherwise NULL.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_references_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath *pAssocName,
CCIMObjectPath *pObjectName, char *pRole)
{

	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*objList;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(LOGID_REFERENCES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Get the list of those objects that are referred to by
	 * the calling object.
	 */

	objList =
	    cp_associatorNames_Solaris_MPXIOCtrlrLogicalIdentity(
		pAssocName, pObjectName, NULL, NULL, NULL);

	if (objList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Now generate the list of instances to return.
	 */

	if ((strcasecmp(pObjectName->mName, MPXIO_CONTROLLER)) == 0) {
	    instList = mpxioLogIdentAssocToInstList(pObjectName,
		SYSTEM_ELEMENT, objList, SAME_ELEMENT, &error);
	} else {
	    instList = mpxioLogIdentAssocToInstList(pObjectName,
		SYSTEM_ELEMENT, objList, SAME_ELEMENT, &error);
	}

	cim_freeObjectPathList(objList);
	return (instList);
}

/*
 * Name: cp_referenceNames_Solaris_MPXIOCtrlrLogicalIdentity
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
 *	CCIMObjectPathList * if associated objects are found. Otherwise NULL.
 *
 */

/* ARGSUSED */
CCIMObjectPathList *
cp_referenceNames_Solaris_MPXIOCtrlrLogicalIdentity(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(LOGID_REFERENCENAMES, CIM_ERR_INVALID_PARAMETER,
		NULL, CIM_ERR_FAILED, &error);
	    return ((CCIMObjectPathList *)NULL);
	}
	instList =
	    cp_references_Solaris_MPXIOCtrlrLogicalIdentity(pAssocName,
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
mpxioLogIdentAssocToInstList(CCIMObjectPath *pObjectName,
    cimchar *pObjectNameRole, CCIMObjectPathList *objList, cimchar *objRole,
	int *error)
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
	    util_handleError(MPXIO_LOGICALIDENTITY, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, error);
	    return ((CCIMInstanceList *)NULL);
	}
	tmpList = objList;
	while (tmpList != NULL) {
	    obj1 = tmpList->mDataObject;
	    obj2 = cim_copyObjectPath(pObjectName);
	    if (obj2 == NULL) {
		ex = cim_getLastError();
		util_handleError(MPXIO_LOGICALIDENTITY, CIM_ERR_FAILED,
		    COPY_OBJPATH_FAILURE, ex, error);
		return ((CCIMInstanceList *)NULL);
	    }

	    inst = mpxioLogIdentAssocToInst(obj1, objRole, obj2,
		pObjectNameRole, error);
	    cim_freeObjectPath(obj2);
	    if (*error != 0) {
		util_handleError(MPXIO_LOGICALIDENTITY, CIM_ERR_FAILED,
		    MPXIOINT_ASSOC_TO_INSTANCE_FAILURE, NULL, error);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(MPXIO_LOGICALIDENTITY, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, NULL, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	    tmpList = tmpList->mNext;
	}
	return (instList);
}

static
CCIMInstance  *
mpxioLogIdentAssocToInst(CCIMObjectPath *obj1, cimchar *obj1Role,
	CCIMObjectPath *obj2, cimchar *obj2Role, int *error)
{

	CCIMInstance	*inst = NULL;
	CCIMException	*ex;

	*error = 0;
	inst = cim_createInstance(MPXIO_LOGICALIDENTITY);
	if (inst == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_LOGICALIDENTITY, CIM_ERR_FAILED,
		MPXIOINT_ASSOC_TO_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstance *)NULL);
	}

	util_doReferenceProperty(obj2Role, obj2, cim_true, inst,
	    error);
	if (*error != 0) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_LOGICALIDENTITY, CIM_ERR_FAILED,
		CREATE_REFPROP_FAILURE, ex, error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doReferenceProperty(obj1Role, obj1, cim_true, inst, error);
	if (*error != 0) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_LOGICALIDENTITY, CIM_ERR_FAILED,
		CREATE_REFPROP_FAILURE, ex, error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}
