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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "util.h"
#include "nfs_providers_msgstrings.h"
#include "messageStrings.h"
#include "nfs_provider_names.h"
#include "nfsprov_methods.h"
#include <cimapi.h>
#include <cp_method.h>


/*
 * Constants
 */
#define	MOUNTALL "mountall"
#define	UMOUNTALL "unmountall"

/*
 * Instance provider methods
 */

/* ARGSUSED */
CCIMObjectPath *
cp_createInstance_Solaris_MountService(CCIMObjectPath *pOP,
	CCIMInstance *pInst) {

	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::CREATE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMObjectPath *)NULL);
} /* cp_createInstance_Solaris_MountService */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_MountService(CCIMObjectPath *pOP) {
	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::DELETE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_deleteInstance_Solaris_MountService */

/* ARGSUSED */
CCIMInstanceList *
cp_enumInstances_Solaris_MountService(CCIMObjectPath *pOP) {
	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::ENUM_INSTANCES",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMInstanceList *)NULL);
} /* cp_enumInstances_Solaris_MountService */

/* ARGSUSED */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_MountService(CCIMObjectPath *pOP) {
	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::ENUM_INSTANCENAMES",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMObjectPathList *)NULL);
} /* cp_enumInstanceNames_Solaris_MountService */

/* ARGSUSED */
CCIMInstanceList *
cp_execQuery_Solaris_MountService(CCIMObjectPath *pOP, char *selectClause,
	char *nonJoinExp, char *queryExp, char *queryLang) {

	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::EXEC_QUERY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMInstanceList *)NULL);
} /* cp_execQuery_Solaris_MountService */

/* ARGSUSED */
CCIMInstance *
cp_getInstance_Solaris_MountService(CCIMObjectPath *pOP) {
	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::GET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMInstance *)NULL);
} /* cp_getInstance_Solaris_MountService */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_MountService(CCIMObjectPath *pOP, CCIMInstance *pInst) {
	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_MountService */

/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_MountService(CCIMObjectPath *pOP,
	CCIMInstance *pInst, char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstanceWithList_Solaris_MountService */

/*
 * Property provider methods
 */
/* ARGSUSED */
CCIMProperty *
cp_getProperty_Solaris_MountService(CCIMObjectPath *pOP, cimchar *pPropName) {
	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::GET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMProperty *)NULL);
} /* cp_getProperty_Solaris_MountService */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_MountService(CCIMObjectPath *pOP, CCIMProperty *pProp) {
	int	err = 0;

	util_handleError("SOLARIS_MNTSERV::SET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_MountService */


/*
 * Method provider methods
 */
/*
 * Method: cp_invokeMethod_Solaris_MountService
 *
 * Description: Routes the cp_invokeMethod_Solaris_MountService calls to the
 * correct Solaris_MountService methods.
 *
 * Parameters:
 *      - CCIMObjectPath *pOP - The object path containing needed information
 *      about the class that is to getting methods invoked.
 *      - cimchar *functionName - The name of the function to be invoked.
 *      - CCIMPropertyList *inParams - The input parameters to the function.
 *      - CCIMPropertyList *outParams - The output parameters from the function.
 *
 * Returns:
 *      - A pointer to a property which indicates success or failure of the
 *      function.  1 for success, 0 for failure.
 *      - Upon error, NULL is returned and the error is logged.
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_MountService(CCIMObjectPath *pOP, cimchar *functionName,
	CCIMPropertyList *inParams, CCIMPropertyList *outParams) {

	CCIMProperty	*retVal;
	int		err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_MNTSERV::INVOKE_METHOD",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	/*
	 * Determine what method is being called.
	 */
	if (strcasecmp(functionName, MOUNTALL) == 0) {
		retVal = mountall(inParams);
	} else if (strcasecmp(functionName, UMOUNTALL) == 0) {
		retVal = unmountall(inParams);
	} else {
		/*
		 * No such method name.
		 */
		util_handleError("SOLARIS_MNTSERV::INVOKE_METHOD",
			CIM_ERR_FAILED, NO_SUCH_METHOD, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	return (retVal);
} /* cp_invokeMethod_Solaris_MountService */
