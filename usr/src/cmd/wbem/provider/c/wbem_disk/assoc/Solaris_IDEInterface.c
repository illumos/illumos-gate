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
#include <errno.h>

#include "util.h"
#include "cimKeys.h"
#include "providerNames.h"
#include "messageStrings.h"
#include "drive_descriptors.h"
#include "ctrl_descriptors.h"
#include "Solaris_IDEInterface.h"

#define	IDE_GETINSTANCE		"IDE_INTERFACE,GET_INSTANCE"
#define	IDE_ENUMINSTANCES	"IDE_INTERFACE,ENUM_INSTANCES"
#define	IDE_ENUMINSTANCENAMES	"IDE_INTERFACE,ENUM_INSTANCENAMES"
#define	IDE_CREATEINSTANCE	"IDE_INTERFACE,CREATE_INSTANCE"
#define	IDE_DELETEINSTANCE	"IDE_INTERFACE,DELETE_INSTANCE"
#define	IDE_SETINSTANCE		"IDE_INTERFACE,SET_INSTANCE"
#define	IDE_GETPROPERTY		"IDE_INTERFACE,GET_PROPERTY"
#define	IDE_SETPROPERTY		"IDE_INTERFACE,SET_PROPERTY"
#define	IDE_INVOKEMETHOD	"IDE_INTERFACE,INVOKE_METHOD"
#define	IDE_EXECQUERY		"IDE_INTERFACE,EXEC_QUERY"
#define	IDE_ASSOCIATORS		"IDE_INTERFACE,ASSOCIATORS"
#define	IDE_ASSOCIATORNAMES	"IDE_INTERFACE,ASSOCIATOR_NAMES"
#define	IDE_REFERENCES		"IDE_INTERFACE,REFERENCES"
#define	IDE_REFERENCENAMES	"IDE_INTERFACE,REFERENCE_NAMES"


static
CCIMInstanceList *
ideIntAssocToInstList(CCIMObjectPath *pObjectName, cimchar *pObjectNameRole,
	CCIMObjectPathList *objList, cimchar *objRole, int *error);

static
CCIMInstance  *
ideIntAssocToInst(CCIMObjectPath *obj1, cimchar *obj1Role,
	CCIMObjectPath *obj2, cimchar *obj2Role, int *error);

/*
 * Solaris_IDEInterface provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the door process prior to
 * sending a copy of the data to the CIMOM.
 */

/*
 * Name: cp_getInstance_Solaris_IDEInterface
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

/* ARGSUSED */
CCIMInstance*
cp_getInstance_Solaris_IDEInterface(CCIMObjectPath* pOP)
{
	CCIMInstance* 		inst = NULL;
	CCIMPropertyList* 	pCurPropList;
	dm_descriptor_t		d_descriptor;
	dm_descriptor_t		c_descriptor;
	CCIMObjectPath		*antOp = NULL;
	CCIMObjectPath		*depOp = NULL;
	int			error;
	char			*name;

	if (pOP == NULL) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	if ((pCurPropList = pOP->mKeyProperties) == NULL) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	antOp = (CCIMObjectPath *)util_getKeyValue(pCurPropList, reference,
	    ANTECEDENT, &error);

	if (error == 0) {
	    depOp = (CCIMObjectPath *)util_getKeyValue(pCurPropList, reference,
		DEPENDENT, &error);
	}

	if (error != 0) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Now, get the name of the antecedent from the object path.
	 */

	if ((pCurPropList = antOp->mKeyProperties) == NULL) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);

	if (error != 0) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
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

	if (c_descriptor == NULL || error == ENODEV) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}
	dm_free_descriptor(c_descriptor);

	/*
	 * Now, get the name of the dependent from the object path.
	 */

	if ((pCurPropList = depOp->mKeyProperties) == NULL) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);

	if (error != 0) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	d_descriptor = dm_get_descriptor_by_name(DM_DRIVE, name,
	    &error);
	/*
	 * Not found. Return a null instance.
	 */

	if (d_descriptor == NULL || error == ENODEV) {
	    d_descriptor = dm_get_descriptor_by_name(DM_ALIAS, name,
		&error);
	    if (d_descriptor == NULL || error == ENODEV) {
		util_handleError(IDE_GETINSTANCE, CIM_ERR_NOT_FOUND,
		    NULL, NULL, &error);
		return ((CCIMInstance *)NULL);
	    }
	}

	if (error != 0) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	dm_free_descriptor(d_descriptor);

	/*
	 * At this point I have verified I have the two devices that
	 * are part of this association. Use the object paths I got
	 * earlier to create the ideinterface instance.
	 */
	inst = ideIntAssocToInst(antOp, ANTECEDENT, depOp, DEPENDENT, &error);

	if (error != 0) {
	    util_handleError(IDE_GETINSTANCE, CIM_ERR_FAILED,
		IDEINT_ASSOC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_IDEInterface
 *
 * Description: Returns a linked list of instances of
 *      Solaris_IDEInterface if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMInstanceList * if istances are found. If no instances,
 *	NULL is returned. On error, NULL is returned.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_IDEInterface(CCIMObjectPath* pOP)
{
	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*cObjList = NULL;
	CCIMObjectPathList	*tmpObjList;
	CCIMObjectPath		*objPath;
	CCIMInstance		*inst;
	CCIMException		*ex;
	dm_descriptor_t		*d_descriptorp = NULL;
	int			error = 0;

	/*
	 * Get the list of IDE Controllers. Then get the associated drives
	 * via the device api.
	 */

	objPath = cim_createEmptyObjectPath(IDE_CONTROLLER);
	if (objPath == NULL) {
	    ex = cim_getLastError();
	    util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_OBJECT_PATH, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	cObjList = cimom_enumerateInstanceNames(objPath, cim_false);
	cim_freeObjectPath(objPath);

	/*
	 * NULL means error.
	 */
	if (cObjList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
		ENUM_INSTANCENAMES_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (cObjList->mDataObject == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	/*
	 * Loop through all of these controller objects and get the associated
	 * disks.
	 */

	for (tmpObjList = cObjList;
	    tmpObjList != NULL && tmpObjList->mDataObject != NULL;
		tmpObjList = tmpObjList->mNext) {

	    char 		*name = NULL;
	    CCIMObjectPath 	*cOp;
	    CCIMInstanceList	*tmpList = NULL;
	    CCIMInstanceList	*tmpList1;
	    CCIMPropertyList	*pCurPropList;
	    CCIMObjectPathList	*dObjList;
	    CCIMInstanceList	*tL;
	    dm_descriptor_t	c_descriptor = NULL;
	    error = 0;

	    cOp = tmpObjList->mDataObject;
	    if ((pCurPropList = cOp->mKeyProperties) == NULL) {
		util_handleError(IDE_ENUMINSTANCES,
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		cim_freeObjectPathList(cObjList);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
		&error);

	    if (error != 0) {
		util_handleError(IDE_ENUMINSTANCES,
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		cim_freeObjectPathList(cObjList);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    c_descriptor = dm_get_descriptor_by_name(DM_CONTROLLER, name,
		&error);
	    if (c_descriptor == NULL || error == ENODEV) {
		continue;
	    }
	    if (error != 0) {
		util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
		    DM_GET_DESC_BYNAME_FAILURE, NULL,
			&error);
		cim_freeObjectPathList(cObjList);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    d_descriptorp = dm_get_associated_descriptors(c_descriptor,
		DM_DRIVE, &error);
	    dm_free_descriptor(c_descriptor);

		/*
		 * If there are no drives associated with this controller,
		 * continue on to the next controller.
		 */

	    if (d_descriptorp == NULL) {
		continue;
	    }

	    if (d_descriptorp[0] == NULL) {
		dm_free_descriptors(d_descriptorp);
		continue;
	    }

	    if (error == ENODEV) {
		continue;
	    }

	    if (error != 0) {
		util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    tmpList = drive_descriptors_toCCIMObjPathInstList(
		DISK_DRIVE, d_descriptorp, &error);
	    dm_free_descriptors(d_descriptorp);
	    d_descriptorp = NULL;

	    if (error != 0) {
		util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
		    DRIVE_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

		/*
		 * It is possible that the controller does not have a drive
		 * associated with it. If this is true, the list will be
		 * NULL.
		 */

	    if (tmpList == NULL) {
		continue;
	    }

	    dObjList = cim_createObjectPathList(tmpList);
	    cim_freeInstanceList(tmpList);

	    if (dObjList == NULL) {
		util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
		    DRIVE_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }
	    tmpList1 = ideIntAssocToInstList(
		cOp, ANTECEDENT, dObjList, DEPENDENT, &error);
	    cim_freeObjectPathList(dObjList);

	    if (error != 0) {
		util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
		    IDECTRL_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    tL = tmpList1;
	    do {
		inst = cim_copyInstance(tL->mDataObject);
		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
		    util_handleError(IDE_ENUMINSTANCES, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, NULL, &error);
		    cim_freeObjectPathList(cObjList);
		    cim_freeObjectPathList(tmpList1);
		    return ((CCIMInstanceList *)NULL);
		}
		tL = tL->mNext;
	    } while (tL && tL->mDataObject != NULL);

	    cim_freeInstanceList(tmpList1);
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
 * Name: cp_enumInstanceNames_Solaris_IDEInterface
 *
 * Description: Returns a linked list of CCIMObjectPath *
 *      of Solaris_IDEInterface if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMObjectPathList * if objects are found. If no objects,
 *	an empty list is returned. On error, NULL is returned.
 */

CCIMObjectPathList*
cp_enumInstanceNames_Solaris_IDEInterface(CCIMObjectPath * pOP) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pOP == NULL) {
	    util_handleError(IDE_ENUMINSTANCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call in to enumInstances and then convert the instance list in
	 * to an object list.
	 */

	instList = cp_enumInstances_Solaris_IDEInterface(pOP);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_IDEInterface is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_IDEInterface(CCIMObjectPath* pOP,
    CCIMInstance* pInst)
{
	int	error;

	util_handleError(IDE_CREATEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return ((CCIMObjectPath *)NULL);
}

/*
 * Deleting an instance of a Solaris_IDEInterface is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_IDEInterface(CCIMObjectPath* pInst)
{
	int	error;

	util_handleError(
	    IDE_DELETEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}
/*
 * Name: cp_getProperty_Solaris_IIDEInterface
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
cp_getProperty_Solaris_IDEInterface(CCIMObjectPath *pOP,
    char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error = 0;

	if (pOP == NULL) {
	    util_handleError(IDE_GETPROPERTY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_IDEInterface(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}

/*
 * Setting an instance of a Solaris_IDEInterface is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_IDEInterface(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(
	    IDE_SETINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}


/*
 * Setting a property on a Solaris_IDEInterface is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_IDEInterface(CCIMObjectPath* pOP, CCIMProperty* pProp)
{
	int	error;

	util_handleError(
	    IDE_SETPROPERTY, CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}

/*
 * No Methods for Solaris_IDEInterface.
 */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_IDEInterface(
    CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty 	*retVal = (CCIMProperty *)NULL;
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_IDEInterface
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
 *	CCIMInstanceList * if matched instance is found. Otherwise, NULL.
 */
/*
 * Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_execQuery_Solaris_IDEInterface(CCIMObjectPath *op,
    cimchar *selectList, cimchar *nonJoinExp, cimchar *queryExp, int queryType)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstanceList	*result;
	CCIMInstance		*emptyInst;
	CCIMException		*ex;
	int			error;

	if (op == NULL) {
	    util_handleError(IDE_EXECQUERY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cimom_enumerateInstances(op, cim_false, cim_false, cim_false,
	    cim_false, cim_false, NULL, 0);

		/*
		 * NULL means error.
		 */
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(IDE_EXECQUERY, CIM_ERR_FAILED,
		ENUM_INSTANCES_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (instList->mDataObject ==  NULL) {
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
	    util_handleError(IDE_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_createInstanceList();
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(IDE_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_addInstance(result, emptyInst);
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(IDE_EXECQUERY, CIM_ERR_FAILED,
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
 * Name: cp_associators_Solaris_IDEInterface
 *
 * Description:
 * Returns instances of objects associated with the passed in
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
 *	CCIMInstanceList * if associated objects are found. Thist list
 *	may be empty. NULL is returned on error.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_IDEInterface(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{
	CCIMPropertyList	*pCurPropList;
	CCIMInstanceList	*instList = NULL;
	dm_descriptor_t		*assoc_descriptors = NULL;
	dm_descriptor_t		*tmpList = NULL;
	dm_descriptor_t		obj_desc = NULL;
	char			*name;
	int			error = 0;
	int			isAntecedent = 0;
	int			isAlias = 0;

	if ((pObjectName == NULL ||
	    (pCurPropList = pObjectName->mKeyProperties) == NULL)) {
	    util_handleError(IDE_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (strcasecmp(pObjectName->mName, IDE_CONTROLLER) == 0) {
	    isAntecedent = 1;
	}

	if (pRole != NULL) {
	    if (strcasecmp(pRole, ANTECEDENT) == 0) {
		if (isAntecedent != 1) {
		    util_handleError(IDE_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    } else if (strcasecmp(pRole, DEPENDENT) == 0) {
		if (isAntecedent == 1) {
		    util_handleError(IDE_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    }
	}

	/*
	 * Both ide controller and disk drive have deviceid as the
	 * key.
	 */

	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);
	if (error != 0) {
	    util_handleError(IDE_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent) {
	    obj_desc = dm_get_descriptor_by_name(DM_CONTROLLER, name,
		&error);
	} else {
	    obj_desc = dm_get_descriptor_by_name(DM_DRIVE, name,
		&error);
	    if (obj_desc == NULL || error == ENODEV) {
		isAlias = 1;
		obj_desc = dm_get_descriptor_by_name(DM_ALIAS, name, &error);
	    }
	}

	if (obj_desc == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	if (error != 0) {
	    util_handleError(IDE_ASSOCIATORS, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAlias) {
	    tmpList = dm_get_associated_descriptors(obj_desc, DM_DRIVE,
		&error);
	    if (tmpList == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (tmpList[0] == NULL) {
		dm_free_descriptors(tmpList);
		return ((CCIMInstanceList *)NULL);
	    }
	}


	if (isAntecedent) {
		/*
		 * Get associated descriptors.
		 */

	    assoc_descriptors = dm_get_associated_descriptors(obj_desc,
		DM_DRIVE, &error);
	    dm_free_descriptor(obj_desc);

	    if (assoc_descriptors == NULL) {
		return (instList);
	    }

	    if (assoc_descriptors[0] == NULL) {
		dm_free_descriptors(assoc_descriptors);
		return (instList);
	    }

	    if (error != 0) {
		util_handleError(IDE_ASSOCIATORS,  CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

		/*
		 * Generate the inst list of the associated disk drives.
		 */

	    instList = drive_descriptors_toCCIMObjPathInstList(DISK_DRIVE,
		assoc_descriptors, &error);
	    dm_free_descriptors(assoc_descriptors);

	    if (error != 0) {
		util_handleError(IDE_ASSOCIATORS, CIM_ERR_FAILED,
		    DRIVE_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }
	} else {
		/*
		 * This is the disk drive calling this function. Return the
		 * controllers that are associated with this disk.
		 */

	    if (tmpList == NULL && obj_desc == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (tmpList != NULL) {
		assoc_descriptors = dm_get_associated_descriptors(tmpList[0],
		    DM_CONTROLLER, &error);
		dm_free_descriptors(tmpList);
	    } else {
		assoc_descriptors = dm_get_associated_descriptors(obj_desc,
		    DM_CONTROLLER, &error);
		dm_free_descriptor(obj_desc);
	    }

	    if (assoc_descriptors == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (assoc_descriptors[0] == NULL) {
		dm_free_descriptors(assoc_descriptors);
		return ((CCIMInstanceList *)NULL);
	    }

	    if (error != 0) {
		util_handleError(IDE_ASSOCIATORS,  CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = ctrl_descriptors_toCCIMInstanceList(IDE_CONTROLLER,
		assoc_descriptors, &error, 2, "ata", "pcata");
	    dm_free_descriptors(assoc_descriptors);

	    if (error != 0) {
		util_handleError(IDE_ASSOCIATORS, CIM_ERR_FAILED,
		    IDECTRL_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }
	}

	return (instList);
}

/*
 * Name: cp_associatorNames_Solaris_IDEInterface
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
 *	CCIMObjectPathList * if associated objects are found. Thist list
 *	may be empty. NULL is returned on error.
 */
/* ARGSUSED */
CCIMObjectPathList *
cp_associatorNames_Solaris_IDEInterface(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(IDE_ASSOCIATORNAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_associators_Solaris_IDEInterface(
		pAssocName, pObjectName, pResultClass, pRole, pResultRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Name: cp_references_Solaris_IDEInterface
 *
 * Description:
 * Returns instances of objects that have references to the passed in
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
 *	CCIMInstanceList * if associated objects are found. Thist list
 *	may be empty. NULL is returned on error.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_references_Solaris_IDEInterface(CCIMObjectPath *pAssocName,
CCIMObjectPath *pObjectName, char *pRole)
{

	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*objList;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(IDE_REFERENCES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Get the list of those objects that are referred to by
	 * the calling object.
	 */

	objList =
	    cp_associatorNames_Solaris_IDEInterface(
		pAssocName, pObjectName, NULL, NULL, NULL);

	if (objList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Now generate the list of instances to return.
	 */

	if ((strcasecmp(pObjectName->mName, IDE_CONTROLLER)) == 0) {
	    instList = ideIntAssocToInstList(pObjectName,
		ANTECEDENT, objList, DEPENDENT, &error);
	} else {
	    instList = ideIntAssocToInstList(pObjectName,
		DEPENDENT, objList, ANTECEDENT, &error);
	}

	cim_freeObjectPathList(objList);
	return (instList);
}

/*
 * Name: cp_referenceNames_Solaris_IDEInterface
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
 *	CCIMInstanceList * if associated objects are found. Thist list
 *	may be empty. NULL is returned on error.
 *
 */
/* ARGSUSED */
CCIMObjectPathList *
cp_referenceNames_Solaris_IDEInterface(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(IDE_REFERENCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_references_Solaris_IDEInterface(pAssocName, pObjectName, pRole);

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
ideIntAssocToInstList(CCIMObjectPath *pObjectName, cimchar *pObjectNameRole,
	CCIMObjectPathList *objList, cimchar *objRole, int *error)
{

	CCIMObjectPathList	*tmpList;
	CCIMInstanceList	*instList = NULL;
	CCIMInstance		*inst;
	CCIMObjectPath		*obj1;
	CCIMObjectPath		*obj2;
	CCIMException		*ex;

	*error = 0;

	if (objList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(IDE_INTERFACE, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstanceList *)NULL);
	}

	tmpList = objList;
	while (tmpList != NULL) {
	    obj1 = tmpList->mDataObject;
	    obj2 = cim_copyObjectPath(pObjectName);
	    if (obj2 == NULL) {
		ex = cim_getLastError();
		util_handleError(IDE_INTERFACE, CIM_ERR_FAILED,
		    COPY_OBJPATH_FAILURE, ex, error);
		return ((CCIMInstanceList *)NULL);
	    }

	    inst = ideIntAssocToInst(obj1, objRole, obj2, pObjectNameRole,
			error);
	    cim_freeObjectPath(obj2);

	    if (*error != 0) {
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(IDE_INTERFACE, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	    tmpList = tmpList->mNext;
	}
	return (instList);
}

/*
 * Create an instance of the class with the passed in attributes.
 */
static
CCIMInstance  *
ideIntAssocToInst(CCIMObjectPath *obj1, cimchar *obj1Role,
	CCIMObjectPath *obj2, cimchar *obj2Role, int *error)
{

	CCIMInstance	*inst = NULL;
	CCIMException	*ex;

	*error = 0;

	inst = cim_createInstance(IDE_INTERFACE);
	if (inst == NULL) {
	    ex = cim_getLastError();
	    util_handleError(IDE_INTERFACE, CIM_ERR_FAILED,
		IDEINT_ASSOC_TO_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstance *)NULL);
	}

	util_doReferenceProperty(obj2Role, obj2, cim_true, inst, error);
	util_doReferenceProperty(obj1Role, obj1, cim_true, inst, error);
	if (*error != 0) {
	    ex = cim_getLastError();
	    util_handleError(IDE_INTERFACE, CIM_ERR_FAILED,
		CREATE_REFPROP_FAILURE, ex, error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}
