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

#include "Solaris_SharedFileSystem.h"
#include "nfs_keys.h"
#include "nfs_providers_msgstrings.h"
#include "messageStrings.h"
#include "nfs_provider_names.h"
#include "util.h"
#include "common_functions.h"
#include "createprop_methods.h"
#include <sys/types.h>

typedef void* inst_or_objPath;

/*
 * Private method declaration
 */
static inst_or_objPath	get_associated_directory(CCIMObjectPath *nfsShareOP,
				boolean_t returnInst);
static CCIMInstanceList* get_associated_instances(CCIMObjectPath *pOP,
				boolean_t isSystemElement);
static CCIMInstance*	get_associated_share(CCIMObjectPath *dirOP);

/*
 * Public methods
 */

/*
 * Instance provider methods
 */

/*
 * Method: cp_createInstance_Solaris_SharedFileSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order for a Solaris_SharedFileSystem association to exist a corresponding
 * Solaris_NFSShare and Solaris_Directory must exist.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of
 *	the class of which to create an instance of.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- Always returns NULL because the method is not supported.
 */
/* ARGSUSED */
CCIMObjectPath *
cp_createInstance_Solaris_SharedFileSystem(CCIMObjectPath *pOP,
	CCIMInstance *pInst) {

	int	err = 0;

	util_handleError("SOLARIS_SHAREDFS::CREATE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMObjectPath *)NULL);
} /* cp_createInstance_Solaris_SharedFileSystem */

/*
 * Method: cp_deleteInstance_Solaris_SharedFileSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order for it to be actually deleted the corresponding Solaris_NFSShare or
 * Solaris_Directory would need to be deleted.  That action is not appropriate
 * for this provider.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the
 *	information about the class of which to delete the instance of.
 *
 * Returns:
 *	- Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_SharedFileSystem(CCIMObjectPath pOP) {
	int	err = 0;

	util_handleError("SOLARIS_SHAREDFS::DELETE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_deleteInstance_Solaris_SharedFileSystem */

/*
 * Method: cp_enumInstances_Solaris_SharedFileSystem
 *
 * Description: Enumerates the instances of Solaris_SharedFileSystem on a host.
 * An instance of Solaris_SharedFileSystem is an association that links a share
 * object to the directory that is shared.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of
 *	the class of which to enumerate the instances of.
 *
 * Returns:
 *	- A pointer to a list of Solaris_SharedFileSystem instances.
 *	- NULL if an error occurred or if there are no instances of
 *	Solaris_SharedFileSystem on the host.  In the case of an error, the
 *	error will be logged.
 */
CCIMInstanceList *
cp_enumInstances_Solaris_SharedFileSystem(CCIMObjectPath *pOP) {
	CCIMObjectPathList	*nfsShareOPList;
	CCIMObjectPathList	*currentShareOP;
	CCIMInstanceList	*sharedFSInstList;
	CCIMObjectPath		*nfsShareOP;
	CCIMException		*ex;
	cimchar			*pValue;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_SHAREDFS::ENUM_INSTANCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOP = cim_createEmptyObjectPath(SOLARIS_NFSSHARE);
	if (nfsShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOPList = cimom_enumerateInstanceNames(nfsShareOP, cim_false);
	/*
	 * A NULL return value means error, an empty list does not.
	 */
	if (nfsShareOPList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::ENUM_INSTANCES",
			CIM_ERR_FAILED, CIMOM_ENUM_INSTNAMES_FAILURE, ex, &err);
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMInstanceList *)NULL);
	}

	cim_freeObjectPath(nfsShareOP);

	if (nfsShareOPList->mDataObject == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	sharedFSInstList = cim_createInstanceList();
	if (sharedFSInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		cim_freeObjectPathList(nfsShareOPList);
		return ((CCIMInstanceList *)NULL);
	}

	for (currentShareOP = nfsShareOPList; currentShareOP != NULL;
		currentShareOP = currentShareOP->mNext) {

		CCIMObjectPath	*sysElementOP;
		CCIMInstance	*sharedFSInst;

		sharedFSInst = cim_createInstance(SOLARIS_SHAREDFS);
		if (sharedFSInst == NULL) {
			ex = cim_getLastError();
			util_handleError("SOLARIS_SHAREDFS::ENUM_INSTANCES",
				CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex,
				&err);
			cim_freeObjectPathList(nfsShareOPList);
			cim_freeInstanceList(sharedFSInstList);
			return ((CCIMInstanceList *) NULL);
		}

		/*
		 * Retrieve the Solaris_Directory instance associated with
		 * the current Solaris_NFSShare object path.
		 */
		sysElementOP = get_associated_directory(
			currentShareOP->mDataObject, B_FALSE);
		if (sysElementOP == NULL) {
			cim_freeObjectPathList(nfsShareOPList);
			cim_freeInstanceList(sharedFSInstList);
			cim_freeInstance(sharedFSInst);
			return ((CCIMInstanceList *)NULL);
		}

		pValue = NULL;
		if (add_property_to_instance(sharedFSProps[SYS].name,
			sharedFSProps[SYS].type, pValue, sysElementOP,
			sharedFSProps[SYS].isKey, sharedFSInst) == cim_false) {

			cim_freeObjectPathList(nfsShareOPList);
			cim_freeObjectPath(sysElementOP);
			cim_freeInstanceList(sharedFSInstList);
			cim_freeInstance(sharedFSInst);
			return ((CCIMInstanceList *)NULL);
		}

		cim_freeObjectPath(sysElementOP);

		pValue = NULL;
		if (add_property_to_instance(sharedFSProps[SAME].name,
			sharedFSProps[SAME].type, pValue,
			currentShareOP->mDataObject, sharedFSProps[SAME].isKey,
			sharedFSInst) == cim_false) {

			cim_freeObjectPathList(nfsShareOPList);
			cim_freeInstanceList(sharedFSInstList);
			cim_freeInstance(sharedFSInst);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Add the instance to the instance list.
		 */
		sharedFSInstList = cim_addInstance(sharedFSInstList,
			sharedFSInst);
		if (sharedFSInstList == NULL) {
			ex = cim_getLastError();
			util_handleError("SOLARIS_SHAREDFS::ENUM_INSTANCES",
				CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, &err);
			cim_freeObjectPathList(nfsShareOPList);
			cim_freeInstance(sharedFSInst);
			return ((CCIMInstanceList *)NULL);
		}

	} /* end for */

	cim_freeObjectPathList(nfsShareOPList);
	return (sharedFSInstList);
} /* cp_enumInstances_Solaris_SharedFileSystem */

/*
 * Method: cp_enumInstanceNames_Solaris_SharedFileSystem
 *
 * Description: Enumerates the instances of Solaris_SharedFileSystem on a host.
 * An instance of Solaris_SharedFileSystem is an association that links a share
 * object to the directory that is shared.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of
 *	the class of which to enumerate the instances of.
 *
 * Returns:
 *	- A pointer to a list of object paths corresponding to the
 *	Solaris_SharedFileSystem instances on the host.
 *	- NULL if an error occurred or if there are no instances of
 *	Solaris_SharedFileSystem on the host.  In the case of an error, the
 *	error will be logged.
 */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_SharedFileSystem(CCIMObjectPath *pOP) {
	CCIMInstanceList	*sharedFSInstList;
	CCIMObjectPathList	*sharedFSOPList;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_SHAREDFS::ENUM_INSTANCENAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	sharedFSInstList = cp_enumInstances_Solaris_SharedFileSystem(pOP);
	if (sharedFSInstList == NULL) {
		/*
		 * Either an error occurred or there are no instances of
		 * Solaris_SharedFileSystem on the system.  In the case of an
		 * error, the error would have been handled in
		 * cp_enumInstances_Solaris_SharedFileSystem.
		 */
		return ((CCIMObjectPathList *)NULL);
	}

	sharedFSOPList = cim_createObjectPathList(sharedFSInstList);

	cim_freeInstanceList(sharedFSInstList);
	return (sharedFSOPList);
} /* cp_enumInstanceNames_Solaris_SharedFileSystem */

/*
 * Method: cp_execQuery_Solaris_SharedFileSystem
 *
 * Description: Queries the host to find those Solaris_SharedFileSystem
 * instances that meet the search criteria.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of
 *	the class of which to query.
 *	- char *selectClause - Not used.
 *	- char *nonJoinExp - Not used.
 *	- char *queryExp - Not used.
 *	- char *queryLang - Not used.
 *
 * Returns:
 *	- A pointer to a list of Solaris_SharedFileSystem instances that match
 *	the criteria.
 *	- NULL if an error occurred or if there are no Solaris_SharedFileSystem
 *	instances that match the criteria.  In the case of an error, the error
 *	will be logged.
 *
 * NOTE: Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_execQuery_Solaris_SharedFileSystem(CCIMObjectPath *pOP,
	char *selectClause, char *nonJoinExp, char *queryExp, char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*sharedElemInstList;
	CCIMException		*ex;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_SHAREDFS::EXEC_QUERY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	sharedElemInstList = cp_enumInstances_Solaris_SharedFileSystem(pOP);
	if (sharedElemInstList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::EXEC_QUERY",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(sharedElemInstList);
		return ((CCIMInstanceList *)NULL);
	}

	sharedElemInstList = cim_prependInstance(sharedElemInstList, emptyInst);
	if (sharedElemInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::EXEC_QUERY",
			CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (sharedElemInstList);
} /* cp_execQuery_Solaris_SharedFileSystem */

/*
 * Method: cp_getInstance_Solaris_SharedFileSystem
 *
 * Description: Gets the instance corresponding to the passed in object path.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - The object path containing all the
 *	keys of the instance that is supposed to be returned.
 *
 * Returns:
 *	- A pointer to the instance of Solaris_SharedFileSystem corresponding
 *	to pOP.
 *	- NULL if an error occurred or if the instance doesn't exist on the
 *	host.  In the case of an error, the error will be logged.
 */
CCIMInstance *
cp_getInstance_Solaris_SharedFileSystem(CCIMObjectPath *pOP) {
	CCIMInstanceList	*instList;
	CCIMInstance		*inst;
	CCIMObjectPath		*sameOP;
	CCIMObjectPath		*sysOP;
	CCIMPropertyList	*sharedFSPropList;
	int			err = 0;

	if (pOP == NULL || pOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SHAREDFS::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	/*
	 * Check if we have the SameElement and SystemElement properties.
	 */
	sharedFSPropList = pOP->mKeyProperties;
	sameOP = util_getKeyValue(sharedFSPropList, sharedFSProps[SAME].type,
		sharedFSProps[SAME].name, &err);
	sysOP = util_getKeyValue(sharedFSPropList, sharedFSProps[SYS].type,
		sharedFSProps[SYS].name, &err);

	if (sameOP == NULL || sysOP == NULL) {
		util_handleError("SOLARIS_SHAREDFS::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	if (sameOP->mKeyProperties == NULL || sysOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SHAREDFS::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_SharedFileSystem(pOP);
	if (instList == NULL) {
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, pOP);

	cim_freeInstanceList(instList);
	return (inst);
} /* cp_getInstances_Solaris_SharedFileSystem */

/*
 * Method: cp_setInstance_Solaris_SharedFileSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change a Solaris_SharedFileSystem instance the underlying share and
 * directory must be modified.  Those actions must be done on the appropriate
 * share and directory objects, not here.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of the class
 *	of which to set the instance.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- Always returns cim_false, because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_SharedFileSystem(CCIMObjectPath *pOP,
	CCIMInstance *pInst) {

	int	err = 0;

	util_handleError("SOLARIS_SHAREDFS::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_SharedFileSystem */

/*
 * Method: cp_setInstanceWithList_Solaris_SharedFileSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change a Solaris_SharedFileSystem instance the underlying share and
 * directory must be modified.  Those actions must be done on the appropriate
 * share and directory objects, not here.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of the class
 *	of which to set the instance.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- Always returns cim_false, because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_SharedFileSystem(CCIMObjectPath *pOP,
	CCIMInstance *pInst, char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_SHAREDFS::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstanceWithList_Solaris_SharedFileSystem */

/*
 * Association provider methods
 */

/*
 * Method: cp_associators_Solaris_SharedFileSystem
 *
 * Description: Returns the instances associated, via the
 * Solaris_SharedFileSystem association, to the pObjectName parameter.
 *
 * Parameters:
 *	- CCIMObjectPath *pAssocName - An object path containing the name of
 *	the association that the caller is trying to reach.
 *	- CCIMObjectPath *pObjectName - The object path containing information
 *	(Class Name, Key Properties) about the object whose associated objects
 *	are to be returned.
 *	- char *pResultClass - If specified, only return instances that are of
 *	this class type.
 *	- char *pRole - If specified, this is the role of the pObjectName
 *	object path passed in.  If this is not valid, NULL is returned.
 *	- char *pResultRole - If specified, only return instances that are
 *	playing this role in the association.
 *
 * Returns:
 *	- A list of Solaris_NFSShare (if pRole == SystemElement && pObjectName
 *	is a Solaris_Directory object path) or Solaris_Directory (if
 *	pRole == SameElement && pObjectName is a Solaris_NFSShare object path)
 *	instances which are associated to the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_SharedFileSystem(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*returnInstList = NULL;
	boolean_t		isSystemElement = B_FALSE;
	int			err = 0;

	/*
	 * Check if the needed parameters are null.
	 */
	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SHAREDFS::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	if ((strcasecmp(pObjectName->mName, SOLARIS_DIR) == 0)) {
		isSystemElement = B_TRUE;
		/*
		 * If a value was passed in with pRole and it does not match
		 * the role that pObjectName actually is then log an invalid
		 * param error.
		 */
		if (pRole != NULL && (strcasecmp(pRole, SYSTEM_ELEMENT) != 0)) {
			util_handleError("SOLARIS_SHAREDFS::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}
	} else if ((strcasecmp(pObjectName->mName, SOLARIS_NFSSHARE) == 0)) {
		isSystemElement = B_FALSE;
		if (pRole != NULL && (strcasecmp(pRole, SAME_ELEMENT) != 0)) {
			util_handleError("SOLARIS_SHAREDFS::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}
	} else {
		util_handleError("SOLARIS_SHAREDFS::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	returnInstList = get_associated_instances(pObjectName, isSystemElement);

	return (returnInstList);
} /* cp_associators_Solaris_SharedFileSystem */

/*
 * Method: cp_associatorNames_Solaris_SharedFileSystem
 *
 * Description: Returns the object paths of the instances on the other side of
 * the association which are associated via the Solaris_SharedFileSystem
 * association and having the passed in parameter, pObjectName, as the opposite
 * key.
 *
 * Parameters:
 *	- CCIMObjectPath *pAssocName - An object path containing information
 *	about the association that the caller is trying to reach.
 *	- CCIMObjectPath *pObjectName - The object path which contains the
 *	information on whose associated objects are to be returned.
 *	- char *pResultClass - If specified, only return instances that are of
 *	this class type.
 *	- char *pRole - If specified, this is the role of the pObjectName
 *	object path passed in.  If this is not valid, NULL is returned.
 *	- char *pResultRole - If specified, only return instances that are
 *	playing this role in the association.
 *
 * Returns:
 *	- A list of Solaris_NFSShare (if pRole == SystemElement && pObjectName
 *	is a Solaris_Directory object path) or Solaris_Directory (if
 *	pRole == SameElement && pObjectName is a Solaris_NFSShare object path)
 *	object paths which are associated to the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
CCIMObjectPathList *
cp_associatorNames_Solaris_SharedFileSystem(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	CCIMException		*ex;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SHAREDFS::ASSOCIATOR_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_associators_Solaris_SharedFileSystem(pAssocName,
		pObjectName, pResultClass, pRole, pResultRole);
	if (instList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	objPathList = cim_createObjectPathList(instList);
	if (objPathList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::ASSOCIATOR_NAMES",
			CIM_ERR_FAILED, CREATE_OBJECT_LIST_FAILURE, ex, &err);
		cim_freeInstanceList(instList);
		return ((CCIMObjectPathList *)NULL);
	}

	cim_freeInstanceList(instList);
	return (objPathList);
} /* cp_associatorNames_Solaris_SharedFileSystem */

/*
 * Method: cp_references_Solaris_SharedFileSystem
 *
 * Description: Returns the Solaris_ShareSharedFileSystem instances that have
 * the passed in parameter, pObjectName, as one of it's keys.
 *
 * Parameters:
 *	- CCIMObjectPath *pAssocName - An object path containing information
 *	about the association that the caller is trying to reach.
 *	- CCIMObjectPath *pObjectName - The object path which contains the
 *	information on whose associated objects are to be returned.
 *	- char *pRole - If specified, this is the role of the pObjectName
 *	object path passed in.  If this is not valid, NULL is returned.
 *
 * Returns:
 *	- A pointer to a list of Solaris_SharedFileSystem instances.
 *	- NULL if an error occurred or if there are no Solaris_SharedFileSystem
 *	instances having pObjectName as one of it's keys.
 */
CCIMInstanceList *
cp_references_Solaris_SharedFileSystem(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SHAREDFS::REFERENCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Get everything that is related to the pObjectName passed in.
	 */
	objPathList = cp_associatorNames_Solaris_SharedFileSystem(pAssocName,
		pObjectName, NULL, pRole, NULL);
	if (objPathList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Now use the object paths in the object path list and the pObjectName
	 * variable to create the association instances.
	 */
	if ((strcasecmp(pObjectName->mName, SOLARIS_DIR) == 0)) {
		/*
		 * pObjectName is the SystemElement
		 */
		instList = create_association_instList(SOLARIS_SHAREDFS,
			pObjectName,  SYS_ELEMENT, objPathList, SAME_ELEMENT,
			&err);
	} else {
		/*
		 * pObjectName is the SameElement
		 */
		instList = create_association_instList(SOLARIS_SHAREDFS,
			pObjectName, SAME_ELEMENT, objPathList, SYS_ELEMENT,
			&err);
	}

	cim_freeObjectPathList(objPathList);

	return (instList);
} /* cp_references_Solaris_SharedFileSystem */

/*
 * Method: cp_referenceNames_Solaris_SharedFileSystem
 *
 * Description: Returns the object paths of the Solaris_ShareSharedFileSystem
 * instances that have the passed in parameter, pObjectName, as one of it's
 * keys.
 *
 * Parameters:
 *	- CCIMObjectPath *pAssocName - An object path containing information
 *	about the association that the caller is trying to reach.
 *	- CCIMObjectPath *pObjectName - The object path which contains the
 *	information on whose associated objects are to be returned.
 *	- char *pRole - If specified, this is the role of the pObjectName
 *	object path passed in.  If this is not valid, NULL is returned.
 *
 * Returns:
 *	- A pointer to a list of Solaris_SharedFileSystem object paths.
 *	- NULL if an error occurred or if there are no Solaris_SharedFileSystem
 *	instances having pObjectName as one of it's keys.
 */
CCIMObjectPathList *
cp_referenceNames_Solaris_SharedFileSystem(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*sharedElemInstList;
	CCIMObjectPathList	*sharedElemOPList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SHAREDFS::REFERENCE_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	sharedElemInstList = cp_references_Solaris_SharedFileSystem(pAssocName,
		pObjectName, pRole);
	if (sharedElemInstList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	sharedElemOPList = cim_createObjectPathList(sharedElemInstList);

	cim_freeInstanceList(sharedElemInstList);

	return (sharedElemOPList);
} /* cp_referenceNames_Solaris_SharedFileSystem */

/*
 * Property provider methods
 */

/*
 * Method: cp_getProperty_Solaris_SharedFileSystem
 *
 * Description: Retrieves a certain property from the instance of
 * Solaris_SharedFileSystem on the host that is described by the parameter
 * pOP.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - The object path containing all the
 *	information needed to find the instance in which the property is to
 *	be returned.
 *	- cimchar *pPropName - The name of the property to be found.
 *
 * Returns:
 *	- A pointer to the property corresponding to the name passed in with
 *	pPropName.
 *	- NULL if an error occurred or if the property doesn't exist.  In the
 *	case of an error, the error will be logged.
 */
CCIMProperty *
cp_getProperty_Solaris_SharedFileSystem(CCIMObjectPath *pOP, cimchar *pPropName)
{
	CCIMInstance	*sharedElemInst;
	CCIMProperty	*sharedElemProp;
	int		err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_SHAREDFS::GET_PROPERTY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	sharedElemInst = cp_getInstance_Solaris_SharedFileSystem(pOP);
	if (sharedElemInst == NULL) {
		return ((CCIMProperty *)NULL);
	}

	sharedElemProp = cim_getProperty(sharedElemInst, pPropName);
	cim_freeInstance(sharedElemInst);

	return (sharedElemProp);
} /* cp_getProperty_Solaris_SharedFileSystem */

/*
 * Method: cp_setProperty_Solaris_SharedFileSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change a Solaris_SharedFileSystem instance the underlying share and
 * directory must be modified.  Those actions must be done on the appropriate
 * share and directory objects, not here.
 *
 * Parameters:
 *      - CCIMObjectPath *pOP - Not used.
 *      - CCIMProperty *pProp - Not used.
 *
 * Returns:
 *      - Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_SharedFileSystem(CCIMObjectPath *pOP,
	CCIMProperty *pProp) {

	int	err = 0;

	util_handleError("SOLARIS_SHAREDFS::SET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_SharedFileSystem */

/*
 * Method provider methods
 */

/*
 * Method: cp_invokeMethod_Solaris_SharedFileSystem
 *
 * Description: This method is not supported because the provider doesn't have
 * any methods.
 *
 * Parameters:
 *      - CCIMObjectPath* op - Not used.
 *      - cimchar* methodName - Not used.
 *      - CCIMPropertyList* inParams - Not used.
 *      - CCIMPropertyList* outParams - Not used.
 *
 * Returns:
 *      - Always returns null because the method is not supported.
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_SharedFileSystem(CCIMObjectPath* op,
	cimchar* methodName, CCIMPropertyList* inParams,
	CCIMPropertyList* outParams) {

	return ((CCIMProperty *)NULL);
} /* cp_invokeMethod_Solaris_SharedFileSystem */

/*
 * Private methods
 */

/*
 * Method: get_associated_directory
 *
 * Description:
 * This method will return the Solaris_Directory instance or object path
 * associated with the Solaris_NFSShare object path passed in.  The returnInst
 * parameter determines whether an CCIMInstance* or a CCIMObjectPath* is
 * returned.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsShareOP - Solaris_NFSShare object path which to
 *	find the associated Solaris_Directory instance.
 *	- boolean_t returnInst - The value which determines whether to return
 *	a Solaris_Directory instance or an object path.
 *
 * Returns:
 *	- If returnInst == B_TRUE, a pointer to a Solaris_Directory instance.
 *	If returnInst == B_FALSE, a pointer to a Solaris_Directory object path.
 *	- NULL is returned if an error occurred or if there are no
 *	Solaris_Directory instances associated to the Solaris_NFSShare object
 *	path passed in.
 */
static inst_or_objPath
get_associated_directory(CCIMObjectPath *nfsShareOP, boolean_t returnInst) {
	CCIMObjectPath	*dirOP;
	CCIMInstance	*dirInst;
	CCIMException	*ex;
	CCIMObjectPath	*propOP;
	CIMType		propType;
	CIMBool		propIsKey;
	cimchar		*propName;
	cimchar		*propValue;
	char		*name;
	int		err = 0;

	/*
	 * Retrieve the Name key property value from the Solaris_NFSShare
	 * object path passed in with nfsShareOP.
	 */
	name = util_getKeyValue(nfsShareOP->mKeyProperties, string, NAME, &err);
	if (name == NULL || err != 0) {
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_DIR",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return (NULL);
	}

	dirInst = cim_createInstance(SOLARIS_DIR);
	if (dirInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_DIR",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return (NULL);
	}

	/*
	 * Create Name property and add it to the Solaris_Directory instance
	 */
	propName = NAME;
	propType = string;
	propValue = name;
	propOP = NULL;
	propIsKey = cim_true;
	if (add_property_to_instance(propName, propType, propValue,
		propOP, propIsKey, dirInst) == cim_false) {

		cim_freeInstance(dirInst);
		return (NULL);
	}

	/*
	 * Create the Solaris_Directory object path.
	 */
	dirOP = cim_createObjectPath(dirInst);
	cim_freeInstance(dirInst);
	if (dirOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_DIR",
			CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE, ex, &err);
		return (NULL);
	}

	/*
	 * Must use cimom_getInstance to determine if the directory exists.
	 */
	dirInst = cimom_getInstance(dirOP, cim_false, cim_false, cim_false,
		cim_false, NULL, 0);
	cim_freeObjectPath(dirOP);
	/*
	 * A NULL return value means error, an empty list does not.
	 */
	if (dirInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_DIR",
			CIM_ERR_FAILED, CIMOM_GET_INST_FAILURE, ex, &err);
		return (NULL);
	}

	if (dirInst->mProperties == NULL) {
		cim_freeInstance(dirInst);
		return (NULL);
	}

	/*
	 * Work around for cimom bug 4649100.
	 */
	if (!set_dir_keyProperties_to_true(dirInst)) {
		cim_freeInstance(dirInst);
		return (NULL);
	}

	if (returnInst == B_TRUE)
		return (dirInst);

	/*
	 * Create the correct Solaris_Directory object path.
	 */
	dirOP = cim_createObjectPath(dirInst);
	if (dirOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_DIR",
			CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE, ex, &err);
		cim_freeInstance(dirInst);
		return (NULL);
	}

	cim_freeInstance(dirInst);
	return (dirOP);
} /* get_associated_directory */

/*
 * Method: get_associated_instances
 *
 * Description:
 * This method will get the instances associated to the object passed in.
 * The result role is the role the Instances to be returned in the instance
 * list are to play regarding the Solaris_SharedFileSystem association.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - The object path of which to get the associated
 *	instances.
 *	- boolean_t isSystemElement - Whether or not the pObjectName is the
 *	SystemElement.  If isSystemElement == B_FALSE, pObjectName is the
 *	SameElement.
 * Returns:
 *	- A pointer to a list of Solaris_NFSShare or Solaris_Directory
 *	instances depending on the parameters passed in.
 *	- NULL if an error occurred or if there are no instances associated
 *	with the object path passed in.
 */

static CCIMInstanceList *
get_associated_instances(CCIMObjectPath *pOP, boolean_t isSystemElement) {
	CCIMInstanceList	*returnInstList;
	CCIMInstance		*assocInst;
	CCIMException		*ex;
	int			err = 0;

	returnInstList = cim_createInstanceList();
	if (returnInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_INST",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Determine if we are supposed to return the SameElement or
	 * SystemElement instances by checking isSystemElement.
	 */
	if (isSystemElement == B_TRUE) {
		/*
		 * pOP is a Solaris_Directory object path so find the associated
		 * Solaris_NFSShare instances.  There should only be one.
		 */
		assocInst = get_associated_share(pOP);
	} else {
		/*
		 * pOP is a Solaris_NFSShare object path so find the associated
		 * Solaris_Directory instances.  There should only be one.
		 */
		assocInst = get_associated_directory(pOP, B_TRUE);
	}

	if (assocInst == NULL) {
		cim_freeInstanceList(returnInstList);
		return ((CCIMInstanceList *)NULL);
	}
	/*
	 * Add the instance to the instance list.
	 */
	returnInstList = cim_addInstance(returnInstList, assocInst);
	if (returnInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_INST",
			CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(assocInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (returnInstList);
} /* get_associated_instances */

/*
 * Method: get_associated_share
 *
 * Description:
 * This method will return the Solaris_NFSShare instance or reference property
 * associated with the Solaris_Directory object path passed in.  The returnInst
 * parameter determines whether an CCIMInstance or a CCIMProperty is returned.
 *
 * Parameters:
 *      - CCIMObjectPath *nfsShareOP - Solaris_Directory object path which to
 *      find the associated Solaris_NFSShare instance.
 *      - boolean_t returnInst - The value which determines whether to return
 *      a Solaris_NFSShare instance or a reference property.
 *
 * Returns:
 *      - If returnInst == B_TRUE, a pointer to a Solaris_NFSShare instance.
 *      If returnInst == B_FALSE, a pointer to a Solaris_NFSShare reference
 *      property.
 *      - NULL is returned if an error occurred or if there are no
 *      Solaris_NFSShare instances associated to the Solaris_Directory object
 *      path passed in.
 */
static CCIMInstance *
get_associated_share(CCIMObjectPath *dirOP) {
	CCIMObjectPath	*nfsShareOP;
	CCIMInstance	*nfsShareInst;
	CCIMException	*ex;
	CCIMObjectPath	*propOP;
	CIMType		propType;
	CIMBool		propIsKey;
	cimchar		*propName;
	cimchar		*propValue;
	char		*name;
	int		err = 0;

	/*
	 * Retrieve the Name key property value from the Solaris_Directory
	 * object path passed in with dirOP.
	 */
	name = util_getKeyValue(dirOP->mKeyProperties, string, NAME, &err);
	if (name == NULL || err != 0) {
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_SHARE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	nfsShareInst = cim_createInstance(SOLARIS_NFSSHARE);
	if (nfsShareInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_SHARE",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return ((CCIMInstance *)NULL);
	}

	propName = NAME;
	propType = string;
	propValue = name;
	propOP = NULL;
	propIsKey = cim_true;
	if (add_property_to_instance(propName, propType, propValue,
		propOP, propIsKey, nfsShareInst) == cim_false) {

		cim_freeInstance(nfsShareInst);
		return ((CCIMInstance *)NULL);
	}

	nfsShareOP = cim_createObjectPath(nfsShareInst);
	if (nfsShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_SHARE",
			CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE, ex, &err);
		cim_freeInstance(nfsShareInst);
		return ((CCIMInstance *)NULL);
	}

	cim_freeInstance(nfsShareInst);

	/*
	 * Use cimom_getInstance to determine if the share exists.
	 */
	nfsShareInst = cimom_getInstance(nfsShareOP, cim_false, cim_false,
		cim_false, cim_false, NULL, 0);

	/*
	 * A NULL return value indicates an error, an empty list does not.
	 */
	if (nfsShareInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SHAREDFS::GET_ASSOC_SHARE",
			CIM_ERR_FAILED, CIMOM_GET_INST_FAILURE, ex, &err);
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMInstance *)NULL);
	}

	cim_freeObjectPath(nfsShareOP);

	if (nfsShareInst->mProperties == NULL) {
		return ((CCIMInstance *)NULL);
	}

	return (nfsShareInst);

} /* get_associated_share */
