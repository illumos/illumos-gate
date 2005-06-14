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
#include "realizesdiskdrive_descriptors.h"
#include "Solaris_RealizesDiskDrive.h"

#define	REALIZES_GETINSTANCE		"REALIZES_DISKDRIVE,GET_INSTANCE"
#define	REALIZES_ENUMINSTANCES		"REALIZES_DISKDRIVE,ENUM_INSTANCES"
#define	REALIZES_ENUMINSTANCENAMES \
	"REALIZES_BASEDONDISK,ENUM_INSTANCENAMES"
#define	REALIZES_CREATEINSTANCE		"REALIZES_DISKDRIVE,CREATE_INSTANCE"
#define	REALIZES_DELETEINSTANCE		"REALIZES_DISKDRIVE,DELETE_INSTANCE"
#define	REALIZES_SETINSTANCE		"REALIZES_DISKDRIVE,SET_INSTANCE"
#define	REALIZES_SETPROPERTY		"REALIZES_DISKDRIVE,SET_PROPERTY"
#define	REALIZES_GETPROPERTY		"REALIZES_DISKDRIVE,GET_PROPERTY"
#define	REALIZES_INVOKEMETHOD		"REALIZES_DISKDRIVE,INVOKE_METHOD"
#define	REALIZES_EXECQUERY		"REALIZES_DISKDRIVE,EXEC_QUERY"
#define	REALIZES_ASSOCIATORS		"REALIZES_DISKDRIVE,ASSOCIATORS"
#define	REALIZES_ASSOCIATORNAMES	"REALIZES_DISKDRIVE,ASSOCIATOR_NAMES"
#define	REALIZES_REFERENCES		"REALIZES_DISKDRIVE,REFERENCES"
#define	REALIZES_REFERENCENAMES		"REALIZES_DISKDRIVE,REFERENCE_NAMES"


static
CCIMInstanceList  *
createRealizesDiskDriveList(CCIMObjectPath *pObjectName,
    cimchar *pObjectNameRole, CCIMObjectPathList *objList,
	cimchar *objRole, int *error);
/*
 * Solaris_RealizesDiskDrive provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the door process prior to
 * sending a copy of the data to the CIMOM.
 */

/*
 * Name: cp_getInstance_Solaris_RealizesDiskDrive
 *
 * Description: Returns an instance of Solaris_RealizesDiskDrive if one
 *  is found that matches the object path passed in .
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instance.
 * Returns: CCIMInstance * if match is found, or NULL if not.
 *
 */

/* ARGSUSED */
CCIMInstance*
cp_getInstance_Solaris_RealizesDiskDrive(CCIMObjectPath* pOP)
{

	CCIMInstance 		*inst = NULL;
	CCIMPropertyList	*pCurPropList;
	CCIMObjectPath		*antOp = NULL;
	CCIMObjectPath		*depOp = NULL;
	dm_descriptor_t		d_descriptor;
	char			*name;
	int			error;

	if (pOP == NULL ||
	    (pCurPropList = pOP->mKeyProperties) == NULL) {
	    util_handleError(REALIZES_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	antOp = (CCIMObjectPath *)util_getKeyValue(pCurPropList, reference,
	    ANTECEDENT, &error);

	if (error == 0) {
	    depOp = (CCIMObjectPath *)util_getKeyValue(pCurPropList, reference,
		DEPENDENT, &error);
	}

	if (error != 0) {
	    util_handleError(REALIZES_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * In this provider, the antecedent has no provider, therefore
	 * we check the validity of this request based on a match
	 * from the device api to the dependent name. The dependent in
	 * this case is a disk drive.
	 */

	if ((pCurPropList = depOp->mKeyProperties) == NULL) {
	    util_handleError(REALIZES_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);
	if (error != 0) {
	    util_handleError(REALIZES_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	d_descriptor = dm_get_descriptor_by_name(DM_DRIVE, name,
	    &error);
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
	 * Turn this in to a realizes diskdrive instance.
	 */

	inst = realizesdiskdrive_descriptor_toCCIMInstance(
	    hostName, antOp, d_descriptor, REALIZES_DISKDRIVE, &error);
	dm_free_descriptor(d_descriptor);

	if (error != 0) {
	    util_handleError(REALIZES_GETINSTANCE, CIM_ERR_FAILED,
		REALIZESDD_DESC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_RealizesDiskDrive
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
cp_enumInstances_Solaris_RealizesDiskDrive(CCIMObjectPath* pOP)
{
	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*objList;
	CCIMObjectPathList	*tmpObjList;
	CCIMPropertyList	*pCurPropList;
	CCIMObjectPath		*objPath;
	CCIMInstance		*inst;
	CCIMException		*ex;
	dm_descriptor_t		d_descriptor;
	int			error = 0;
	int			filter[2];

	filter[0] = DM_MT_FIXED;
	filter[1] = DM_FILTER_END;

	/*
	 * First see if there are any physical package instances on this
	 * system. If none found, then we cannot enumerate instances of
	 * this association. We will return an empty list.
	 */

	inst = cim_createInstance(PHYSICAL_PACKAGE);
	if (inst == NULL) {
	    ex = cim_getLastError();
	    util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_INSTANCE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	objPath = cim_createObjectPath(inst);
	cim_freeInstance(inst);

	if (objPath == NULL) {
	    ex = cim_getLastError();
	    util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_OBJECT_PATH_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	objList = cimom_enumerateInstanceNames(objPath, cim_false);
	cim_freeObjectPath(objPath);

	/*
	 * NULL means error. Empty list does not.
	 */
	if (objList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		ENUM_INSTANCENAMES_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	if (objList->mDataObject == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_INSTANCE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	for (tmpObjList = objList; tmpObjList->mDataObject != NULL;
	    tmpObjList = tmpObjList->mNext) {
		/*
		 * Make sure there is a device associated with the instance of
		 * the physical package.
		 */

	    char *name = NULL;

	    if ((pCurPropList =
		((CCIMObjectPath *)tmpObjList->mDataObject)->mKeyProperties)
		    == NULL) {
		util_handleError(REALIZES_ENUMINSTANCES,
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    name = (cimchar *)util_getKeyValue(pCurPropList, string, TAG,
		&error);
	    if (error != 0 || name == NULL) {
		util_handleError(REALIZES_ENUMINSTANCES,
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(objList);
		return ((CCIMInstanceList *)NULL);
	    }

	    d_descriptor = dm_get_descriptor_by_name(DM_DRIVE, name, &error);
	    if (error == ENODEV || d_descriptor == NULL) {
		continue;
	    }

	    if (error != 0) {
		util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		    DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(objList);
		return ((CCIMInstanceList *)NULL);
	    }
	    inst = realizesdiskdrive_descriptor_toCCIMInstance(hostName,
		tmpObjList->mDataObject, d_descriptor,
		    REALIZES_DISKDRIVE, &error);
	    dm_free_descriptor(d_descriptor);

	    if (error != 0) {
		util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		    REALIZESDD_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		cim_freeInstanceList(instList);
		cim_freeObjectPathList(objList);
		return ((CCIMInstanceList *)NULL);
	    }
	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		util_handleError(REALIZES_ENUMINSTANCES, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, NULL, &error);
		cim_freeObjectPathList(objList);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	}

	cim_freeObjectPathList(objList);
	if (instList->mDataObject == NULL) {
	    cim_freeInstanceList(instList);
	    instList = NULL;
	}
	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_RealizesDiskDrive
 *
 * Description: Returns a linked list of CCIMObjectPath *
 *      of Solaris_RealizesDiskDrive objects if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMObjectPathList * if objects are found. NULL Otherwise.
 */

/* ARGSUSED */
CCIMObjectPathList*
cp_enumInstanceNames_Solaris_RealizesDiskDrive(CCIMObjectPath * pOP) {

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

	instList = cp_enumInstances_Solaris_RealizesDiskDrive(pOP);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_RealizesDiskDrive is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_RealizesDiskDrive(
    CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(REALIZES_CREATEINSTANCE,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return ((CCIMObjectPath *)NULL);
}


/*
 * Deleting an instance of a Solaris_RealizesDiskDrive is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_RealizesDiskDrive(CCIMObjectPath* pInst)
{
	int	error;

	util_handleError(REALIZES_DELETEINSTANCE,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_RealizesDiskDrive
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
cp_getProperty_Solaris_RealizesDiskDrive(CCIMObjectPath *pOP,
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

	inst = cp_getInstance_Solaris_RealizesDiskDrive(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}
/*
 * Setting an instance of a Solaris_RealizesDiskDrive is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_RealizesDiskDrive(
    CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(REALIZES_SETINSTANCE,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}


/*
 * Setting a property on a Solaris_RealizesDiskDrive is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_RealizesDiskDrive(
    CCIMObjectPath* pOP, CCIMProperty* pProp)
{
	int	error;

	util_handleError(REALIZES_SETPROPERTY,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}

/*
 * No Methods for Solaris_RealizesDiskDrive.
 */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_RealizesDiskDrive(
    CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty	*retVal = (CCIMProperty	*)NULL;
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_RealizesDiskDrive
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
cp_execQuery_Solaris_RealizesDiskDrive(
    CCIMObjectPath *op, cimchar *selectList, cimchar *nonJoinExp,
	cimchar *queryExp, int queryType)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstanceList	*result;
	CCIMInstance		*emptyInst;
	CCIMException		*ex;
	int			error;

	if (op == NULL) {
	    util_handleError(REALIZES_EXECQUERY, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cp_enumInstances_Solaris_RealizesDiskDrive(op);

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
 * Name: cp_associators_Solaris_RealizesDiskDrive
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
 *	CCIMInstanceList * if associated objects are found. NULL Otherwise.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_RealizesDiskDrive(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{
	CCIMPropertyList	*pCurPropList;
	CCIMInstanceList	*instList = NULL;
	CCIMInstance		*inst = NULL;
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
	    return ((CCIMInstanceList *)NULL);
	}

	if (strcasecmp(pObjectName->mName, PHYSICAL_PACKAGE) == 0) {
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

	if (error != 0) {
	    util_handleError(REALIZES_ASSOCIATORS,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	obj_desc = dm_get_descriptor_by_name(DM_DRIVE, name, &error);
	/*
	 * No device found.
	 */
	if (error == ENODEV || obj_desc == NULL) {
	    return ((CCIMInstanceList *)NULL);

	}
	if (error != 0) {
	    util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent == 1) {
		/*
		 * Physical package calling this method, return instances of the
		 * disk drive associated with this physical package.
		 */

	    inst = disk_descriptor_toCCIMInstance(hostName, obj_desc, DISK,
		&error);
	    dm_free_descriptor(obj_desc);

	    if (error != 0) {
		ex = cim_getLastError();
		util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		    DISK_DESC_TO_INSTANCE_FAILURE, ex, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_createInstanceList();
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
		    CREATE_INSTANCE_LIST_FAILURE, ex, &error);
		cim_freeInstance(inst);
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
		 * This is the disk calling this function. Return the physical
		 * package instances, if any, that are found on this system.
		 * Turn the object descriptor in to a CCIMObjectPath. Then, ask
		 * the CIMOM for any instances of this.
		 */

		CCIMObjectPath	*ob;
		CCIMInstance	*in =
		    cim_createInstance(PHYSICAL_PACKAGE);

		if (in == NULL) {
		    ex = cim_getLastError();
		    util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
			CREATE_INSTANCE_FAILURE, ex, &error);
		    return ((CCIMInstanceList *)NULL);
		}

		util_doProperty(
		    DEVICEID, string, name, cim_true, inst, &error);

		ob = cim_createObjectPath(in);
		cim_freeInstance(in);

		if (ob == NULL) {
		    ex = cim_getLastError();
		    util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
			CREATE_OBJECT_PATH_FAILURE, ex, &error);
		    return ((CCIMInstanceList *)NULL);
		}

		inst = cimom_getInstance(ob, cim_false, cim_false,
		    cim_false, cim_false, NULL, 0);
		cim_freeObjectPath(ob);

		/*
		 * NULL indicates error. Empty object does not.
		 */
		if (inst == NULL) {
		    ex = cim_getLastError();
		    util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
			GET_INSTANCE_FAILURE, ex, &error);
		    return ((CCIMInstanceList *)NULL);
		}

		if (inst->mProperties == NULL) {
		    return ((CCIMInstanceList *)NULL);
		}

		instList = cim_createInstanceList();
		if (instList == NULL) {
		    ex = cim_getLastError();
		    util_handleError(REALIZES_ASSOCIATORS, CIM_ERR_FAILED,
			CREATE_INSTANCE_LIST_FAILURE, ex, &error);
		    cim_freeInstance(inst);
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
	}

	return (instList);
}

/*
 * Name: cp_associatorNames_Solaris_RealizesDiskDrive
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
cp_associatorNames_Solaris_RealizesDiskDrive(CCIMObjectPath *pAssocName,
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
	    cp_associators_Solaris_RealizesDiskDrive(
		pAssocName, pObjectName, pResultClass, pRole, pResultRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Name: cp_references_Solaris_RealizesDiskDrive
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
cp_references_Solaris_RealizesDiskDrive(CCIMObjectPath *pAssocName,
CCIMObjectPath *pObjectName, char *pRole)
{

	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*objList;
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
	    cp_associatorNames_Solaris_RealizesDiskDrive(
		pAssocName, pObjectName, NULL, NULL, NULL);

	if (objList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Now generate the list of instances to return.
	 */

	if ((strcasecmp(pObjectName->mName, PHYSICAL_PACKAGE)) == 0) {
	    instList = createRealizesDiskDriveList(pObjectName, ANTECEDENT,
		objList, DEPENDENT, &error);
	} else {
	    instList = createRealizesDiskDriveList(pObjectName, DEPENDENT,
		objList, ANTECEDENT, &error);
	}

	cim_freeObjectPathList(objList);
	return (instList);
}

/*
 * Name: cp_referenceNames_Solaris_RealizesDiskDrive
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
 *	CCIMInstanceList * if associated objects are found. NULL otherwise.
 *
 */
/* ARGSUSED */
CCIMObjectPathList *
cp_referenceNames_Solaris_RealizesDiskDrive(CCIMObjectPath *pAssocName,
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
	    cp_references_Solaris_RealizesDiskDrive(pAssocName,
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
createRealizesDiskDriveList(CCIMObjectPath *pObjectName,
    cimchar *pObjectNameRole, CCIMObjectPathList *objList,
	cimchar *objRole, int *error)
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
	    util_handleError(REALIZES_DISKDRIVE,
		CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstanceList *)NULL);
	}

	tmpList = objList;
	while (tmpList != NULL) {
	    obj1 = tmpList->mDataObject;
	    obj2 = cim_copyObjectPath(pObjectName);
	    if (obj2 == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_DISKDRIVE, CIM_ERR_FAILED,
		    COPY_OBJPATH_FAILURE, ex, error);
		return ((CCIMInstanceList *)NULL);
	    }

	    inst = cim_createInstance(REALIZES_DISKDRIVE);
	    if (inst == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_DISKDRIVE,
		    CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, error);
		return ((CCIMInstanceList *)NULL);
	    }

	    util_doReferenceProperty(pObjectNameRole, obj2, cim_true,
		inst, error);
	    cim_freeObjectPath(obj2);

	    if (*error != 0) {
		ex = cim_getLastError();
		util_handleError(REALIZES_DISKDRIVE,
		    CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }

	    util_doReferenceProperty(objRole, obj1, cim_true, inst, error);

	    if (*error != 0) {
		ex = cim_getLastError();
		util_handleError(REALIZES_DISKDRIVE, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(REALIZES_DISKDRIVE, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }

	    tmpList = tmpList->mNext;
	}
	return (instList);
}
