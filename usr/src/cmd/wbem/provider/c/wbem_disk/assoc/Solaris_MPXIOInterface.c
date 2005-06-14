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
#include "drive_descriptors.h"
#include "ctrl_descriptors.h"
#include "Solaris_MPXIOInterface.h"


#define	MPXIO_GETINSTANCE		"MPXIO_INTERFACE,GET_INSTANCE"
#define	MPXIO_ENUMINSTANCES		"MPXIO_INTERFACE,ENUM_INSTANCES"
#define	MPXIO_ENUMINSTANCENAMES		"MPXIO_INTERFACE,ENUM_INSTANCENAMES"
#define	MPXIO_CREATEINSTANCE		"MPXIO_INTERFACE,CREATE_INSTANCE"
#define	MPXIO_DELETEINSTANCE		"MPXIO_INTERFACE,DELETE_INSTANCE"
#define	MPXIO_SETINSTANCE		"MPXIO_INTERFACE,SET_INSTANCE"
#define	MPXIO_GETPROPERTY		"MPXIO_INTERFACE,GET_PROPERTY"
#define	MPXIO_SETPROPERTY		"MPXIO_INTERFACE,SET_PROPERTY"
#define	MPXIO_INVOKEMETHOD		"MPXIO_INTERFACE,INVOKE_METHOD"
#define	MPXIO_EXECQUERY			"MPXIO_INTERFACE,EXEC_QUERY"
#define	MPXIO_ASSOCIATORS		"MPXIO_INTERFACE,ASSOCIATORS"
#define	MPXIO_ASSOCIATORNAMES		"MPXIO_INTERFACE,ASSOCIATOR_NAMES"
#define	MPXIO_REFERENCES		"MPXIO_INTERFACE,REFERENCES"
#define	MPXIO_REFERENCENAMES		"MPXIO_INTERFACE,REFERENCE_NAMES"

static
CCIMInstanceList *
mpxioIntAssocToInstList(CCIMObjectPath *pObjectName, cimchar *pObjectNameRole,
	CCIMObjectPathList *objList, cimchar *objRole, int *error);

static
CCIMInstance  *
mpxioIntAssocToInst(CCIMObjectPath *obj1, cimchar *obj1Role,
	CCIMObjectPath *obj2, cimchar *obj2Role, int *error);

/*
 * Solaris_MPXIOInterface provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the door process prior to
 * sending a copy of the data to the CIMOM.
 */

/*
 * Name: cp_getInstance_Solaris_MPXIOInterface
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
cp_getInstance_Solaris_MPXIOInterface(CCIMObjectPath* pOP)
{
	CCIMInstance* 		inst = NULL;
	CCIMPropertyList* 	pCurPropList;
	CCIMObjectPath		*antOp = NULL;
	CCIMObjectPath		*depOp = NULL;
	dm_descriptor_t		d_descriptor;
	dm_descriptor_t		c_descriptor;
	char			*name;
	int			error;

	if (pOP == NULL ||
		((pCurPropList = pOP->mKeyProperties) == NULL)) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	antOp = (CCIMObjectPath *)util_getKeyValue(
		pCurPropList, reference, ANTECEDENT, &error);

	if (error == 0) {
	    depOp = (CCIMObjectPath *)util_getKeyValue(
		pCurPropList, reference, DEPENDENT, &error);
	}

	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	/*
	 * Now, get the name of the antecedent from the object path.
	 */

	if (((pCurPropList = antOp->mKeyProperties) == NULL) ||
	    ((pCurPropList = depOp->mKeyProperties) == NULL)) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	pCurPropList = antOp->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string,
	    DEVICEID, &error);
	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
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
	if (error == ENODEV || c_descriptor == NULL) {
	    return ((CCIMInstance *)NULL);
	}
	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	dm_free_descriptor(c_descriptor);

	pCurPropList = depOp->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string,
	    DEVICEID, &error);
	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	d_descriptor = dm_get_descriptor_by_name(DM_DRIVE, name, &error);

	/*
	 * Not found. Return a null instance.
	 */

	if (error == ENODEV || d_descriptor == NULL) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}
	dm_free_descriptor(d_descriptor);

	/*
	 * At this point I have verified I have the two devices that
	 * are part of this association. Use the object paths I got
	 * earlier to create the mpxiointerface instance.
	 */
	inst = mpxioIntAssocToInst(antOp, ANTECEDENT, depOp, DEPENDENT, &error);

	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_FAILED,
		MPXIOINT_ASSOC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_MPXIOInterface
 *
 * Description: Returns a linked list of instances of
 *      Solaris_MPXIOInterface if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMInstanceList * if istances are found. NULL otherwise.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_MPXIOInterface(CCIMObjectPath* pOP)
{
	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*cObjList;
	CCIMObjectPathList	*tmpObjList;
	CCIMObjectPath		*objPath;
	CCIMInstance		*inst;
	CCIMException		*ex;
	dm_descriptor_t		*d_descriptorp = NULL;
	int			error = 0;


	objPath = cim_createEmptyObjectPath(MPXIO_CONTROLLER);
	if (objPath == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_OBJECT_PATH, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	cObjList = cimom_enumerateInstanceNames(objPath, cim_false);
	cim_freeObjectPath(objPath);

	/*
	 * NULL is an error. Empty list is not.
	 */
	if (cObjList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
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
	    util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	for (tmpObjList = cObjList; tmpObjList != NULL &&
	    tmpObjList->mDataObject != NULL;
		tmpObjList = tmpObjList->mNext) {

	    CCIMObjectPath 	*cOp;
	    CCIMInstanceList	*tmpList;
	    CCIMInstanceList	*tmpList1 = NULL;
	    CCIMPropertyList	*pCurPropList;
	    CCIMObjectPathList	*dObjList;
	    CCIMInstanceList	*tL;
	    dm_descriptor_t	c_descriptor;
	    char 		*name = NULL;

	    cOp = tmpObjList->mDataObject;
	    if ((pCurPropList = cOp->mKeyProperties) == NULL) {
		util_handleError(MPXIO_ENUMINSTANCES,
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    name = (cimchar *)util_getKeyValue(pCurPropList, string,
		DEVICEID, &error);
	    if (error != 0 || name == NULL) {
		util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_INVALID_PARAMETER,
		    NULL, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    c_descriptor = dm_get_descriptor_by_name(DM_CONTROLLER, name,
		&error);
	    if (error == ENODEV || c_descriptor == NULL) {
		continue;
	    }
	    if (error != 0) {
		util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
		    DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    d_descriptorp = dm_get_associated_descriptors(c_descriptor,
		DM_DRIVE, &error);
	    dm_free_descriptor(c_descriptor);
		/*
		 * If there are no drives associated with this controller,
		 * continue on to the next controller.
		 */
	    if (d_descriptorp == NULL ||
		d_descriptorp[0] == NULL) {
		continue;
	    }
	    if (error != 0) {
		util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    tmpList = drive_descriptors_toCCIMObjPathInstList(
		DISK_DRIVE, d_descriptorp, &error);
	    dm_free_descriptors(d_descriptorp);

	    if (error != 0) {
		util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
		    DRIVE_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }

	    if (tmpList == NULL) {
		continue;
	    }

	    dObjList = cim_createObjectPathList(tmpList);
	    cim_freeInstanceList(tmpList);

	    if (dObjList == NULL) {
		util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
		    DRIVE_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }
	    tmpList1 = mpxioIntAssocToInstList(
		cOp, ANTECEDENT, dObjList, DEPENDENT, &error);
	    cim_freeObjectPathList(dObjList);

	    if (error != 0) {
		util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
		    DRIVE_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(cObjList);
		return ((CCIMInstanceList *)NULL);
	    }
		/*
		 * Assign a pointer to the tmplist. Traverse the list with
		 * this pointer so as not to disturb the original value of
		 * the instance list. This is needed for freeing the list
		 * later.
		 */
	    tL = tmpList1;
	    do {
		inst = cim_copyInstance(tL->mDataObject);
		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
			/*
			 * In this case we do not free the indivual instance
			 * added to the instance list. On error, the original
			 * instance list is freed.
			 */
		    util_handleError(MPXIO_ENUMINSTANCENAMES, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, NULL, &error);
		    cim_freeInstance(inst);
		    cim_freeObjectPathList(cObjList);
		    cim_freeInstanceList(tmpList1);
		    return ((CCIMInstanceList *)NULL);
		}
		tL = tL->mNext;
	    } while (tL);

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
 * Name: cp_enumInstanceNames_Solaris_MPXIOInterface
 *
 * Description: Returns a linked list of CCIMObjectPath *
 *      of Solaris_MPXIOInterface if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMObjectPathList * if objects are found. NULL otherwise.
 */

CCIMObjectPathList*
cp_enumInstanceNames_Solaris_MPXIOInterface(CCIMObjectPath * pOP) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;


	if (pOP == NULL) {
	    util_handleError(MPXIO_ENUMINSTANCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call in to enumInstances and then convert the instance list in
	 * to an object list.
	 */

	instList = cp_enumInstances_Solaris_MPXIOInterface(pOP);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_MPXIOInterface is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_MPXIOInterface(CCIMObjectPath* pOP,
    CCIMInstance* pInst)
{
	int	error;

	util_handleError(MPXIO_CREATEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return ((CCIMObjectPath *)NULL);
}


/*
 * Deleting an instance of a Solaris_MPXIOInterface is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_MPXIOInterface(CCIMObjectPath* pInst)
{
	int	error;

	util_handleError(MPXIO_DELETEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_MPXIOInterface
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
cp_getProperty_Solaris_MPXIOInterface(CCIMObjectPath *pOP,
    char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error = 0;

	if (pOP == NULL) {
	    util_handleError(MPXIO_GETPROPERTY,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_MPXIOInterface(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}
	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}

/*
 * Setting an instance of a Solaris_MPXIOInterface is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_MPXIOInterface(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(MPXIO_SETINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return (cim_false);
}

/*
 * Setting a property on a Solaris_MPXIOInterface is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_MPXIOInterface(CCIMObjectPath* pOP, CCIMProperty* pProp)
{
	int	error;

	util_handleError(MPXIO_SETPROPERTY, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return (cim_false);
}

/*
 * No Methods for Solaris_MPXIOInterface.
 */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_MPXIOInterface(
    CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{

	CCIMProperty	*retVal = (CCIMProperty	*)NULL;
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_MPXIOInterface
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
cp_execQuery_Solaris_MPXIOInterface(CCIMObjectPath *op,
    cimchar *selectList, cimchar *nonJoinExp, cimchar *queryExp, int queryType)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstanceList	*result;
	CCIMInstance		*emptyInst;
	CCIMException		*ex;
	int			error;

	if (op == NULL) {
	    util_handleError(MPXIO_EXECQUERY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cp_enumInstances_Solaris_MPXIOInterface(op);

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
	    util_handleError(MPXIO_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_createInstanceList();
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_addInstance(result, emptyInst);
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_EXECQUERY, CIM_ERR_FAILED,
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
 * Name: cp_associators_Solaris_MPXIOInterface
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
cp_associators_Solaris_MPXIOInterface(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{
	CCIMPropertyList	*pCurPropList;
	CCIMInstanceList	*instList = NULL;
	dm_descriptor_t		*assoc_descriptors;
	dm_descriptor_t		obj_desc;
	char			*name;
	int			error = 0;
	int			isAntecedent = 0;

	if (pObjectName == NULL ||
	    pObjectName->mName == NULL ||
		((pCurPropList = pObjectName->mKeyProperties) == NULL)) {
		util_handleError(MPXIO_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER,
		    NULL, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	}

	if (strcasecmp(pObjectName->mName, MPXIO_CONTROLLER) == 0) {
	    isAntecedent = 1;
	}

	if (pRole != NULL) {
	    if (strcasecmp(pRole, ANTECEDENT) == 0) {
		if (isAntecedent != 1) {
		    util_handleError(MPXIO_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    } else if (strcasecmp(pRole, DEPENDENT) == 0) {
		if (isAntecedent == 1) {
		    util_handleError(MPXIO_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    }
	}

	/*
	 * Both mpxio controller and disk drive have deviceid as the
	 * key.
	 */

	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);
	if (error != 0) {
	    util_handleError(MPXIO_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent) {
	    obj_desc = dm_get_descriptor_by_name(DM_CONTROLLER, name,
		&error);
	} else {
	    obj_desc = dm_get_descriptor_by_name(DM_DRIVE, name,
		&error);
	}
	/*
	 * No device found.
	 */
	if (error == ENODEV || obj_desc == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}
	if (error != 0) {
	    util_handleError(MPXIO_ASSOCIATORS, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent) {
		/*
		 * Controller calling this method, return instances of the
		 * disk drives associatied with this controller.
		 */

	    assoc_descriptors = dm_get_associated_descriptors(obj_desc,
		DM_DRIVE, &error);
	    dm_free_descriptor(obj_desc);

	    if (assoc_descriptors == NULL ||
		assoc_descriptors[0] == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (error != 0) {
		util_handleError(MPXIO_ASSOCIATORS,  CIM_ERR_FAILED,
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
		util_handleError(MPXIO_ASSOCIATORS, CIM_ERR_FAILED,
		    DRIVE_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }
	} else {
		/*
		 * This is the disk drive calling this function. Return the
		 * controllers that are associated with this disk.
		 */
	    assoc_descriptors = dm_get_associated_descriptors(obj_desc,
		DM_CONTROLLER, &error);
	    dm_free_descriptor(obj_desc);

	    if (assoc_descriptors == NULL ||
		assoc_descriptors[0] == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (error != 0) {
		util_handleError(MPXIO_ASSOCIATORS,  CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = ctrl_descriptors_toCCIMInstanceList(MPXIO_CONTROLLER,
		assoc_descriptors, &error, 1, "scsi_vhci");
	    dm_free_descriptors(assoc_descriptors);

	    if (error != 0) {
		util_handleError(MPXIO_ASSOCIATORS, CIM_ERR_FAILED,
		    MPXIOCTRL_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }
	}

	return (instList);
}

/*
 * Name: cp_associatorNames_Solaris_MPXIOInterface
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
 *	CCIMObjectPathList * if associated objects are found. Otherwise, NULL.
 */
/* ARGSUSED */
CCIMObjectPathList *
cp_associatorNames_Solaris_MPXIOInterface(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(MPXIO_ASSOCIATORNAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_associators_Solaris_MPXIOInterface(
		pAssocName, pObjectName, pResultClass, pRole, pResultRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}
	return (objList);
}

/*
 * Name: cp_references_Solaris_MPXIOInterface
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
 *	CCIMInstanceList * if associated objects are found. NULL otherwise.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_references_Solaris_MPXIOInterface(CCIMObjectPath *pAssocName,
CCIMObjectPath *pObjectName, char *pRole)
{

	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*objList;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(MPXIO_REFERENCES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	/*
	 * Get the list of those objects that are referred to by
	 * the calling object.
	 */

	objList =
	    cp_associatorNames_Solaris_MPXIOInterface(
		pAssocName, pObjectName, NULL, NULL, NULL);

	if (objList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Now generate the list of instances to return.
	 */

	if ((strcasecmp(pObjectName->mName, MPXIO_CONTROLLER)) == 0) {
	    instList = mpxioIntAssocToInstList(pObjectName,
		ANTECEDENT, objList, DEPENDENT, &error);
	} else {
	    instList = mpxioIntAssocToInstList(pObjectName,
		DEPENDENT, objList, ANTECEDENT, &error);
	}

	cim_freeObjectPathList(objList);
	return (instList);
}

/*
 * Name: cp_referenceNames_Solaris_MPXIOInterface
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
cp_referenceNames_Solaris_MPXIOInterface(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(MPXIO_REFERENCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_references_Solaris_MPXIOInterface(pAssocName,
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
mpxioIntAssocToInstList(CCIMObjectPath *pObjectName, cimchar *pObjectNameRole,
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
	    util_handleError(MPXIO_INTERFACE, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstanceList *)NULL);
	}

	tmpList = objList;
	while (tmpList != NULL) {
	    obj1 = tmpList->mDataObject;
	    obj2 = cim_copyObjectPath(pObjectName);
	    if (obj2 == NULL) {
		ex = cim_getLastError();
		util_handleError(MPXIO_INTERFACE, CIM_ERR_FAILED,
		    COPY_OBJPATH_FAILURE, ex, error);
		return ((CCIMInstanceList *)NULL);
	    }

	    inst = mpxioIntAssocToInst(obj1, objRole, obj2, pObjectNameRole,
		error);
	    cim_freeObjectPath(obj2);
	    if (*error != 0) {
		util_handleError(MPXIO_INTERFACE, CIM_ERR_FAILED,
		    MPXIOINT_ASSOC_TO_INSTANCE_FAILURE, NULL, error);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(MPXIO_INTERFACE, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	    tmpList = tmpList->mNext;
	}
	return (instList);
}

static
CCIMInstance  *
mpxioIntAssocToInst(CCIMObjectPath *obj1, cimchar *obj1Role,
	CCIMObjectPath *obj2, cimchar *obj2Role, int *error)
{

	CCIMInstance	*inst = NULL;
	CCIMException	*ex;

	*error	= 0;

	inst = cim_createInstance(MPXIO_INTERFACE);
	if (inst == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_INTERFACE, CIM_ERR_FAILED,
		MPXIOINT_ASSOC_TO_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstance *)NULL);
	}

	util_doReferenceProperty(obj2Role, obj2, cim_true, inst, error);
	if (*error != 0) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_INTERFACE, CIM_ERR_FAILED,
		CREATE_REFPROP_FAILURE, ex, error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doReferenceProperty(obj1Role, obj1, cim_true, inst,
	    error);
	if (*error != 0) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_INTERFACE, CIM_ERR_FAILED,
		CREATE_REFPROP_FAILURE, ex, error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}
