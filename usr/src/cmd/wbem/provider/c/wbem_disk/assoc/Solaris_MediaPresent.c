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
#include "mediapresent_descriptors.h"
#include "drive_descriptors.h"
#include "logicaldisk_descriptors.h"
#include "Solaris_MediaPresent.h"

#define	MEDIA_GETINSTANCE		"MEDIA_PRESENT,GET_INSTANCE"
#define	MEDIA_ENUMINSTANCES		"MEDIA_PRESENT,ENUM_INSTANCES"
#define	MEDIA_ENUMINSTANCENAMES		"MEDIA_PRESENT,ENUM_INSTANCENAMES"
#define	MEDIA_CREATEINSTANCE		"MEDIA_PRESENT,CREATE_INSTANCE"
#define	MEDIA_DELETEINSTANCE		"MEDIA_PRESENT,DELETE_INSTANCE"
#define	MEDIA_SETINSTANCE		"MEDIA_PRESENT,SET_INSTANCE"
#define	MEDIA_GETPROPERTY		"MEDIA_PRESENT,GET_PROPERTY"
#define	MEDIA_SETPROPERTY		"MEDIA_PRESENT,SET_PROPERTY"
#define	MEDIA_INVOKEMETHOD		"MEDIA_PRESENT,INVOKE_METHOD"
#define	MEDIA_EXECQUERY			"MEDIA_PRESENT,EXEC_QUERY"
#define	MEDIA_ASSOCIATORS		"MEDIA_PRESENT,ASSOCIATORS"
#define	MEDIA_ASSOCIATORNAMES		"MEDIA_PRESENT,ASSOCIATOR_NAMES"
#define	MEDIA_REFERENCES		"MEDIA_PRESENT,REFERENCES"
#define	MEDIA_REFERENCENAMES		"MEDIA_PRESENT,REFERENCE_NAMES"


static CCIMInstanceList  *createMediaPresRefList(
    CCIMObjectPath *pObjectName, cimchar *pObjectNameRole,
	CCIMObjectPathList *objList, cimchar *objRole, int *error);

static CCIMInstance  *createMediaPresRefInst(
    CCIMObjectPath *pObjectName, cimchar *pObjectNameRole,
	CCIMObjectPath *objName, cimchar *objRole, int *error);
/*
 * Solaris_MediaPresent provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the door process prior to
 * sending a copy of the data to the CIMOM.
 */

/*
 * Name: cp_getInstance_Solaris_MediaPresent
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
cp_getInstance_Solaris_MediaPresent(CCIMObjectPath* pOP)
{
	CCIMInstance* 		inst = NULL;
	CCIMPropertyList* 	pCurPropList;
	CCIMObjectPath		*antOp = NULL;
	CCIMObjectPath		*depOp = NULL;
	dm_descriptor_t		dd_descriptor;
	dm_descriptor_t		ld_descriptor;
	char			*name;
	int			error;

	if (pOP == NULL ||
	    (pCurPropList = pOP->mKeyProperties) == NULL) {
	    util_handleError(MEDIA_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

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
	    util_handleError(MEDIA_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	/*
	 * Now, get the name of the antecedent from the object path.
	 */

	if ((pCurPropList = antOp->mKeyProperties) == NULL ||
	    (pCurPropList = depOp->mKeyProperties) == NULL) {
	    util_handleError(MEDIA_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * both of the objects have the deviceid as the key value.
	 */
	pCurPropList = antOp->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);
	if (error != 0) {
	    util_handleError(MEDIA_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	dd_descriptor = dm_get_descriptor_by_name(DM_DRIVE, name, &error);
	/*
	 * Not found. Return a null instance.
	 */
	if (error == ENODEV || dd_descriptor) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(MEDIA_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	/*
	 * Only need the descriptor to verify the device still exists.
	 */
	dm_free_descriptor(dd_descriptor);

	/*
	 * Now, get the name of the dependent from the object path.
	 */

	pCurPropList = depOp->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);
	if (error != 0) {
	    util_handleError(MEDIA_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	ld_descriptor = dm_get_descriptor_by_name(DM_MEDIA, name, &error);
	/*
	 * Not found. Return a null instance.
	 */

	if (error == ENODEV || ld_descriptor == NULL) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(MEDIA_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	dm_free_descriptor(ld_descriptor);

	/* Turn these descriptors in to a media present instance */
	inst = createMediaPresRefInst(antOp, ANTECEDENT, depOp, DEPENDENT,
	    &error);
	if (error != 0) {
	    util_handleError(MEDIA_GETINSTANCE, CIM_ERR_FAILED,
		MEDIAPRES_ASSOC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_MediaPresent
 *
 * Description: Returns a linked list of instances of associated objects
 * if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMInstanceList * if istances are found. Otherwise NULL,
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_MediaPresent(CCIMObjectPath* pOP)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstance		*inst;
	CCIMException*		ex;
	dm_descriptor_t		*dd_descriptorp = NULL;
	dm_descriptor_t		*ld_descriptorp = NULL;
	int			error = 0;
	int			filter[2];
	int			i = 0;
	int			j = 0;

	filter[0] = DM_DT_FIXED;
	filter[1] = DM_FILTER_END;

	if (pOP == NULL) {
	    util_handleError(MEDIA_ENUMINSTANCES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	dd_descriptorp = dm_get_descriptors(DM_DRIVE, filter, &error);
	if (dd_descriptorp == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	if (dd_descriptorp[0] == NULL) {
	    dm_free_descriptors(dd_descriptorp);
	    return ((CCIMInstanceList *)NULL);
	}

	if (error != 0) {
	    util_handleError(MEDIA_ENUMINSTANCES, CIM_ERR_FAILED,
		DM_GET_DESCRIPTORS, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * For each one of the drives found, get the associated media, if
	 * any.
	 */

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MEDIA_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    dm_free_descriptors(dd_descriptorp);
	    return ((CCIMInstanceList *)NULL);
	}

	for (i = 0; dd_descriptorp[i] != NULL; i ++) {
	    ld_descriptorp = dm_get_associated_descriptors(
		dd_descriptorp[i], DM_MEDIA, &error);

	    /* If no media associated with this disk, continue */

	    if (ld_descriptorp == NULL) {
		continue;
	    }

	    if (error != 0) {
		util_handleError(MEDIA_ENUMINSTANCES, CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		dm_free_descriptors(dd_descriptorp);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    for (j = 0; ld_descriptorp[j] != NULL; j ++) {
		inst = mediapresent_descriptor_toCCIMInstance(hostName,
		    dd_descriptorp[i], ld_descriptorp[j],
			MEDIA_PRESENT, &error);
		if (error != 0) {
		    util_handleError(MEDIA_ENUMINSTANCES, CIM_ERR_FAILED,
			MEDIAPRES_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		    dm_free_descriptors(dd_descriptorp);
		    dm_free_descriptors(ld_descriptorp);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}

		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
		    ex = cim_getLastError();
		    util_handleError(MEDIA_ENUMINSTANCES, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, ex, NULL);
		    dm_free_descriptors(dd_descriptorp);
		    dm_free_descriptors(ld_descriptorp);
		    return ((CCIMInstanceList *)NULL);
		}
	    }

	    dm_free_descriptors(ld_descriptorp);
	}
	dm_free_descriptors(dd_descriptorp);

	if (instList->mDataObject == NULL) {
	    cim_freeInstanceList(instList);
	    instList = NULL;
	}

	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_MediaPresent
 *
 * Description: Returns a linked list of CCIMObjectPath *
 *      of Solaris_MediaPresent if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMObjectPathList * if objects are found. Otherwise NULL.
 */

CCIMObjectPathList*
cp_enumInstanceNames_Solaris_MediaPresent(CCIMObjectPath * pOP) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pOP == NULL) {
	    util_handleError(MEDIA_ENUMINSTANCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call in to enumInstances and then convert the instance list in
	 * to an object list.
	 */

	instList = cp_enumInstances_Solaris_MediaPresent(pOP);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}
	return (objList);
}

/*
 * Creating an instance of a Solaris_MediaPresent is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_MediaPresent(
    CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(MEDIA_CREATEINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return ((CCIMObjectPath *)NULL);
}

/*
 * Deleting an instance of a Solaris_MediaPresent is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_MediaPresent(CCIMObjectPath* pInst)
{
	int	error;

	util_handleError(MEDIA_DELETEINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_MediaPresent
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
cp_getProperty_Solaris_MediaPresent(CCIMObjectPath *pOP,
    char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error = 0;

	if (pOP == NULL) {
	    util_handleError(MEDIA_GETPROPERTY, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_MediaPresent(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}

/*
 * Setting an instance of a Solaris_MediaPresent is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_MediaPresent(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(MEDIA_SETINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * Setting a property on a Solaris_MediaPresent is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_MediaPresent(CCIMObjectPath* pOP, CCIMProperty* pProp)
{
	int	error;

	util_handleError(MEDIA_SETPROPERTY, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * No Methods for Solaris_MediaPresent.
 */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_MediaPresent(CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty	*retVal = (CCIMProperty	*)NULL;
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_MediaPresent
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
cp_execQuery_Solaris_MediaPresent(CCIMObjectPath *op, cimchar *selectList,
    cimchar *nonJoinExp, cimchar *queryExp, int queryType)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstanceList	*result;
	CCIMInstance		*emptyInst;
	CCIMException		*ex;
	int			error;

	if (op == NULL) {
	    util_handleError(MEDIA_EXECQUERY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cp_enumInstances_Solaris_MediaPresent(op);

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
	    util_handleError(MEDIA_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_createInstanceList();
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MEDIA_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_addInstance(result, emptyInst);
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MEDIA_EXECQUERY, CIM_ERR_FAILED,
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
 * Name: cp_associators_Solaris_MediaPresent
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
 *	CCIMInstanceList * if associated objects are found.
 *	NULL is returned on error and for an empty list.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_MediaPresent(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{
	CCIMPropertyList	*pCurPropList;
	CCIMInstanceList	*instList = NULL;
	CCIMInstance		*inst;
	CCIMException		*ex;
	dm_descriptor_t		*assoc_descriptors;
	dm_descriptor_t		obj_desc;
	char			*name;
	int			error = 0;
	int			isAntecedent = 0;
	int			i;


	if (pObjectName == NULL || pObjectName->mName == NULL ||
		pObjectName->mKeyProperties == NULL) {
	    util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	if (strcasecmp(pObjectName->mName, DISK_DRIVE) == 0) {
	    isAntecedent = 1;
	}

	if (pRole != NULL) {
	    if (strcasecmp(pRole, ANTECEDENT) == 0) {
		if (isAntecedent != 1) {
		    util_handleError(MEDIA_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    } else if (strcasecmp(pRole, DEPENDENT) == 0) {
		if (isAntecedent == 1) {
		    util_handleError(MEDIA_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    }
	}

	/*
	 * Both logical disk and disk drive have deviceid as the
	 * key.
	 */

	pCurPropList = pObjectName->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);
	if (error != 0) {
	    util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent) {
	    obj_desc = dm_get_descriptor_by_name(DM_DRIVE, name, &error);
	} else {
	    obj_desc = dm_get_descriptor_by_name(DM_MEDIA, name, &error);
	}
	if (error == ENODEV || obj_desc == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}
	if (error != 0) {
	    util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_FAILED,
		    DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent) {

	    /* Get associated descriptors. */

	    assoc_descriptors = dm_get_associated_descriptors(obj_desc,
		DM_MEDIA, &error);
	    dm_free_descriptor(obj_desc);

	    if (assoc_descriptors == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (assoc_descriptors[0] == NULL) {
		dm_free_descriptors(assoc_descriptors);
		return ((CCIMInstanceList *)NULL);
	    }

	    if (error != 0) {
		util_handleError(MEDIA_ASSOCIATORS,  CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_createInstanceList();
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_FAILED,
		    CREATE_INSTANCE_LIST_FAILURE, ex, &error);
		dm_free_descriptors(assoc_descriptors);
		return ((CCIMInstanceList *)NULL);
	    }
	    /* Traverse the list and create instances of associated objects. */

	    for (i = 0; assoc_descriptors[i] != NULL; i ++) {
		inst = logicaldisk_descriptor_toCCIMInstance(hostName,
		    assoc_descriptors[i], LOGICAL_DISK, &error);

		if (error != 0) {
		    ex = cim_getLastError();
		    util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_FAILED,
			LOGICALDISK_DESC_TO_INSTANCE_FAILURE, ex, &error);
		    dm_free_descriptors(assoc_descriptors);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}
		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
		    ex = cim_getLastError();
		    util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, ex, &error);
		    dm_free_descriptors(assoc_descriptors);
		    cim_freeInstance(inst);
		    return ((CCIMInstanceList *)NULL);
		}
	    } /* End for */
	} else {
		/*
		 * This is the logical disk calling this function. Return the
		 * logical disk that this belongs to.
		 */

	    assoc_descriptors = dm_get_associated_descriptors(obj_desc,
		DM_DRIVE, &error);
	    dm_free_descriptor(obj_desc);

	    if (assoc_descriptors == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (assoc_descriptors[0] == NULL) {
		dm_free_descriptors(assoc_descriptors);
		return ((CCIMInstanceList *)NULL);
	    }

	    if (error != 0) {
		util_handleError(MEDIA_ASSOCIATORS,  CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_createInstanceList();
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_FAILED,
		    CREATE_INSTANCE_LIST_FAILURE, ex, &error);
		dm_free_descriptors(assoc_descriptors);
		return ((CCIMInstanceList *)NULL);
	    }
	    for (i = 0; assoc_descriptors[i] != NULL; i ++) {
		inst = drive_descriptor_toCCIMInstance(hostName,
		    assoc_descriptors[i], DISK_DRIVE, &error);

		if (error != 0) {
		    ex = cim_getLastError();
		    util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_FAILED,
			DRIVE_DESC_TO_INSTANCE_FAILURE, ex, &error);
		    dm_free_descriptors(assoc_descriptors);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}

		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
		    ex = cim_getLastError();
		    util_handleError(MEDIA_ASSOCIATORS, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, ex, &error);
		    dm_free_descriptors(assoc_descriptors);
		    cim_freeInstance(inst);
		    return ((CCIMInstanceList *)NULL);
		}
	    } /* End for */
	}
	dm_free_descriptors(assoc_descriptors);
	return (instList);
}

/*
 * Name: cp_associatorNames_Solaris_MediaPresent
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
cp_associatorNames_Solaris_MediaPresent(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(MEDIA_ASSOCIATORNAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_associators_Solaris_MediaPresent(
		pAssocName, pObjectName, pResultClass, pRole, pResultRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Name: cp_references_Solaris_MediaPresent
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
cp_references_Solaris_MediaPresent(CCIMObjectPath *pAssocName,
CCIMObjectPath *pObjectName, char *pRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(MEDIA_REFERENCES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	/*
	 * Get the list of those objects that are referred to by
	 * the calling object.
	 */

	objList =
	    cp_associatorNames_Solaris_MediaPresent(
		pAssocName, pObjectName, NULL, NULL, NULL);
	/*
	 * Now generate the list of instances to return.
	 */

	if (strcasecmp(pObjectName->mName, DISK_DRIVE) == 0) {
	    instList = createMediaPresRefList(pObjectName,
		ANTECEDENT, objList, DEPENDENT, &error);
	} else {
	    instList = createMediaPresRefList(pObjectName,
		DEPENDENT, objList, ANTECEDENT, &error);
	}

	cim_freeObjectPathList(objList);
	return (instList);
}

/*
 * Name: cp_referenceNames_Solaris_MediaPresent
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
cp_referenceNames_Solaris_MediaPresent(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(MEDIA_REFERENCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_references_Solaris_MediaPresent(pAssocName, pObjectName, pRole);

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
createMediaPresRefList(CCIMObjectPath *pObjectName, cimchar *pObjectNameRole,
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
	    util_handleError(MEDIA_PRESENT, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstanceList *)NULL);
	}

	tmpList = objList;
	while (tmpList != NULL) {
	    obj1 = tmpList->mDataObject;
	    obj2 = cim_copyObjectPath(pObjectName);
	    if (obj2 == NULL) {
		ex = cim_getLastError();
		util_handleError(MEDIA_PRESENT, CIM_ERR_FAILED,
		    COPY_OBJPATH_FAILURE, ex, error);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    inst = createMediaPresRefInst(obj2, pObjectNameRole, obj1,
		objRole, error);
	    cim_freeObjectPath(obj2);

	    if (*error != 0) {
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(MEDIA_PRESENT, CIM_ERR_FAILED,
		    CREATE_INSTANCE_FAILURE, ex, NULL);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }

	    tmpList = tmpList->mNext;
	}
	return (instList);
}
static
CCIMInstance  *
createMediaPresRefInst(CCIMObjectPath *obj2,
    cimchar *pObjectNameRole, CCIMObjectPath *obj1, cimchar *objRole,
	int *error)
{

	CCIMInstance	*inst = NULL;
	CCIMException	*ex;

	*error	= 0;

	inst  = cim_createInstance(MEDIA_PRESENT);
	if (inst == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MEDIA_PRESENT, CIM_ERR_FAILED, NULL, NULL, error);
	    return ((CCIMInstance *)NULL);
	}
	util_doReferenceProperty(pObjectNameRole, obj2, cim_true, inst, error);
	if (*error != 0) {
	    ex = cim_getLastError();
	    util_handleError(MEDIA_PRESENT, CIM_ERR_FAILED,
		CREATE_REFPROP_FAILURE, ex, error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doReferenceProperty(objRole, obj1, cim_true, inst, error);
	if (*error != 0) {
	    ex = cim_getLastError();
	    util_handleError(MEDIA_PRESENT, CIM_ERR_FAILED,
		CREATE_REFPROP_FAILURE, ex, error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("FixedMedia", boolean, "1", cim_false, inst, error);
	if (*error != 0) {
	    ex = cim_getLastError();
	    util_handleError(MEDIA_PRESENT, CIM_ERR_FAILED,
		CREATE_REFPROP_FAILURE, ex, error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	return (inst);
}
