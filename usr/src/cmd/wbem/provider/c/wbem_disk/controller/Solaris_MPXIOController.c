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
#include "ctrl_descriptors.h"
#include "providerNames.h"
#include "messageStrings.h"
#include "Solaris_MPXIOController.h"

#define	MPXIO_GETINSTANCE	"MPXIO_CONTROLLER,GET_INSTANCE"
#define	MPXIO_ENUMINSTANCES	"MPXIO_CONTROLLER,ENUM_INSTANCES"
#define	MPXIO_ENUMINSTANCENAMES	"MPXIO_CONTROLLER,ENUM_INSTANCENAMES"
#define	MPXIO_CREATEINSTANCE	"MPXIO_CONTROLLER,CREATE_INSTANCE"
#define	MPXIO_DELETEINSTANCE	"MPXIO_CONTROLLER,DELETE_INSTANCE"
#define	MPXIO_SETINSTANCE	"MPXIO_CONTROLLER,SET_INSTANCE"
#define	MPXIO_GETPROPERTY	"MPXIO_CONTROLLER,GET_PROPERTY"
#define	MPXIO_SETPROPERTY	"MPXIO_CONTROLLER,SET_PROPERTY"
#define	MPXIO_INVOKEMETHOD	"MPXIO_CONTROLLER,INVOKE_METHOD"
#define	MPXIO_EXECQUERY		"MPXIO_CONTROLLER,EXEC_QUERY"

/*
 * Solaris_MPXIOController provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the CIMOM as the caller.
 */

/*
 * Name: cp_getInstance_Solaris_MPXIOController
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
cp_getInstance_Solaris_MPXIOController(CCIMObjectPath* pOP)
{
	CCIMInstance		*inst = NULL;
	CCIMPropertyList	*pCurPropList;
	dm_descriptor_t		mpxioctrl_descriptor;
	char			*name;
	int			error;

	if (pOP == NULL ||
	    pOP->mKeyProperties == NULL) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	pCurPropList = pOP->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);

	if (error != 0 || name == NULL) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	mpxioctrl_descriptor =
	    dm_get_descriptor_by_name(DM_CONTROLLER, name, &error);

	/*
	 * Not found. Return a null instance.
	 */
	if (error == ENODEV) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	/* Turn this descriptor in to a mpxio controller instance */

	inst = ctrl_descriptor_toCCIMInstance(
	    hostName, mpxioctrl_descriptor, MPXIO_CONTROLLER, &error);
	dm_free_descriptor(mpxioctrl_descriptor);

	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_FAILED,
		MPXIOCTRL_DESC_TO_INSTANCE_FAILURE, NULL,
		&error);
	    return ((CCIMInstance*)NULL);
	}

	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_MPXIOController
 *
 * Description: Returns an instancelist of MPXIO controllers, if found.
 *
 * Parameters:
 *      pOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstanceList * if matched instance is found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_MPXIOController(CCIMObjectPath* pOP)
{
	CCIMInstanceList	*instList = NULL;
	dm_descriptor_t		*mpxioctrl_descriptorp;
	int			error;
	int			filter[1];

	filter[0] = DM_FILTER_END;

	mpxioctrl_descriptorp = dm_get_descriptors(DM_CONTROLLER, filter,
	    &error);

	/*
	 * If no devices, return NULL. CIMOM expects NULL. Do not set
	 * last error. If set, the CIMOM will assume an error and
	 * throw an exception.
	 */

	if (mpxioctrl_descriptorp == NULL ||
	    mpxioctrl_descriptorp[0] == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}
	if (error != 0) {
	    util_handleError(MPXIO_ENUMINSTANCES, CIM_ERR_FAILED,
		DM_GET_DESCRIPTORS, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/* convert controllers to CCIMInstanceList */
	instList = ctrl_descriptors_toCCIMInstanceList(MPXIO_CONTROLLER,
	    mpxioctrl_descriptorp, &error, 1, "scsi_vhci");
	dm_free_descriptors(mpxioctrl_descriptorp);

	if (error != 0) {
	    util_handleError(MPXIO_GETINSTANCE, CIM_ERR_FAILED,
		MPXIOCTRL_DESC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_MPXIOController
 *
 * Description: Returns an object pathlist of MPXIO controllers, if found.
 *
 * Parameters:
 *      pOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMObjectPathList * if matched instance is found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMObjectPathList*
cp_enumInstanceNames_Solaris_MPXIOController(CCIMObjectPath * pOP) {

	CCIMInstanceList	*instList = NULL;
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

	instList = cp_enumInstances_Solaris_MPXIOController(pOP);
	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_MPXIOController is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_MPXIOController(CCIMObjectPath* pOP,
    CCIMInstance* pInst)
{
	int	error;

	util_handleError(MPXIO_CREATEINSTANCE, CIM_ERR_NOT_SUPPORTED, NULL,
	    NULL, &error);
	return ((CCIMObjectPath*)NULL);
}

/*
 * Deleting an instance of a Solaris_MPXIOController is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_MPXIOController(CCIMObjectPath* pInst)
{

	int	error;

	util_handleError(MPXIO_DELETEINSTANCE,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_MPXIOController
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
cp_getProperty_Solaris_MPXIOController(CCIMObjectPath *pOP,
    char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error = 0;

	if (pOP == NULL) {
	    util_handleError(MPXIO_GETPROPERTY, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_MPXIOController(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}

/*
 * Setting an instance of a Solaris_MPXIOController is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_MPXIOController(CCIMObjectPath* pOP, CCIMInstance* pInst)
{

	int	error;

	util_handleError(MPXIO_SETINSTANCE, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 * Setting properties on an instance of a Solaris_MPXIOController is not
 * supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_MPXIOController(CCIMObjectPath* pOP, CCIMProperty* pProp)
{

	int	error;

	util_handleError(MPXIO_SETPROPERTY, CIM_ERR_NOT_SUPPORTED,
	    NULL, NULL, &error);
	return (cim_false);
}

/*
 *  No methods available on an instance of a Solaris_MPXIOController.
 */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_MPXIOController(CCIMObjectPath* op, cimchar* methodName,
    CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty	*retVal = (CCIMProperty*)NULL;
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_MPXIOController
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
 *      CCIMInstanceList * if matched instance is found. Otherwise, NULL.
 */
/*
 * Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_execQuery_Solaris_MPXIOController(CCIMObjectPath *op, cimchar *selectList,
    cimchar *nonJoinExp, cimchar *queryExp, int queryType)
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

	instList = cp_enumInstances_Solaris_MPXIOController(op);

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
	    cim_freeInstanceList(instList);
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
	    cim_freeInstanceList(instList);
	    cim_freeInstance(emptyInst);
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
