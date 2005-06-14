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

#include "common_functions.h"
#include "util.h"

/*
 * Public methods
 */

/*
 * Method: create_association_instList
 *
 * Description: Creates an instance list for the association class as named in
 * the pClassName parameter.
 *
 * Parameters:
 *	- cimchar *pClassName - The name of the association class to create
 *	the instances of.
 *	- CCIMObjectPath *pObjectName - One of the references for the
 *	association.
 *	- char *pObjectNameRole - The role that the pObjectName parameter plays
 *	in the association.
 *	- CCIMObjectPathList *pObjPathList - The other reference for the
 *	association
 *	- char *pRole - The role that the object paths in the
 *	CCIMObjectPathList play in the association.
 *
 * Returns:
 *	- CCIMInstanceList * - The instance list created from the parameters.
 *	- NULL if an error occurred.
 */
CCIMInstanceList *
create_association_instList(cimchar *pClassName, CCIMObjectPath *pObjectName,
	char *pObjectNameRole, CCIMObjectPathList *pObjPathList, char *pRole,
	int *errp) {

	CCIMObjectPathList	*currentObjPath;
	CCIMProperty		*objectNameProp;
	CCIMInstanceList	*instList;
	CCIMException		*ex;

	instList = cim_createInstanceList();
	if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError("CREATE_ASSOC_INSTLIST", CIM_ERR_FAILED,
			CREATE_INSTANCE_LIST_FAILURE, ex, errp);
		return ((CCIMInstanceList *)NULL);
	}

	objectNameProp = cim_createReferenceProperty(pObjectNameRole,
		pObjectName, cim_true);
	if (objectNameProp == NULL) {
		ex = cim_getLastError();
		util_handleError("CREATE_ASSOC_INSTLIST", CIM_ERR_FAILED,
			CREATE_REFPROP_FAILURE, ex, errp);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	}

	currentObjPath = pObjPathList;

	while (currentObjPath != NULL) {
		CCIMInstance	*inst;
		CCIMProperty	*objPathListProp;
		CIMBool		returned_val;

		/*
		 * Create the property from the current object path in the list.
		 */
		objPathListProp = cim_createReferenceProperty(pRole,
			currentObjPath->mDataObject, cim_true);
		if (objPathListProp == NULL) {
			ex = cim_getLastError();
			util_handleError("CREATE_ASSOC_INSTLIST",
				CIM_ERR_FAILED, CREATE_REFPROP_FAILURE, ex,
				errp);
			cim_freeInstanceList(instList);
			cim_freeProperty(objectNameProp);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Create the instance of the class name as passed in with
		 * pClassName and add the properties to the instance.
		 */
		inst = cim_createInstance(pClassName);
		if (inst == NULL) {
			ex = cim_getLastError();
			util_handleError("CREATE_ASSOC_INSTLIST",
				CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex,
				errp);
			cim_freeInstanceList(instList);
			cim_freeProperty(objectNameProp);
			cim_freeProperty(objPathListProp);
			return ((CCIMInstanceList *)NULL);
		}

		returned_val = cim_addProperty(inst, objectNameProp);
		if (returned_val == cim_false) {
			ex = cim_getLastError();
			util_handleError("CREATE_ASSOC_INSTLIST",
				CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
			cim_freeInstance(inst);
			cim_freeInstanceList(instList);
			cim_freeProperty(objectNameProp);
			cim_freeProperty(objPathListProp);
			return ((CCIMInstanceList *)NULL);
		}

		returned_val = cim_addProperty(inst, objPathListProp);
		if (returned_val == cim_false) {
			ex = cim_getLastError();
			util_handleError("CREATE_ASSOC_INSTLIST",
				CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
			cim_freeInstance(inst);
			cim_freeInstanceList(instList);
			cim_freeProperty(objPathListProp);
			return ((CCIMInstanceList *)NULL);
		}

		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
			ex = cim_getLastError();
			util_handleError("CREATE_ASSOC_INSTLIST",
				CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, errp);
			cim_freeInstance(inst);
			return ((CCIMInstanceList *)NULL);
		}

		currentObjPath = currentObjPath->mNext;
	}

	return (instList);
} /* create_association_instList */
