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

#include "Solaris_PersistentShareForSystem.h"
#include "nfs_keys.h"
#include "nfs_providers_msgstrings.h"
#include "messageStrings.h"
#include "nfs_provider_names.h"
#include "util.h"
#include "common_functions.h"
#include "createprop_methods.h"
#include "libfsmgt.h"

/*
 * Private methods
 */
static CIMBool		does_persistent_share_exist(CCIMObjectPath *pShareOP);
static CCIMProperty	*get_Antecedent();

/*
 * Public methods
 */

/*
 * Instance provider methods
 */

/*
 * Method: cp_createInstance_Solaris_PersistentShareForSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order for a Solaris_PersistentShareForSystem association to exist a
 * corresponding Solaris_PersistentShare and Solaris_ComputerSystem must exist.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of
 *	the class for which to create an instance.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- Always returns NULL because the method is not supported.
 */
/* ARGSUSED */
CCIMObjectPath *
cp_createInstance_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP,
	CCIMInstance *pInst) {
	int	err = 0;

	util_handleError("SOLARIS_SYSPERSISTSHARE::CREATE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMObjectPath *)NULL);

} /* cp_createInstance_Solaris_PersistentShareForSystem */

/*
 * Method: cp_deleteInstance_Solaris_PersistentShareForSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order for it to be actually deleted the corresponding
 * Solaris_PersistentShare would need to be deleted.  That action is not
 * appropriate for this provider.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the
 *	information about the class for which to delete the instance.
 *
 * Returns:
 *	- Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP) {
	int	err = 0;

	util_handleError("SOLARIS_SYSPERSISTSHARE::DELETE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);

} /* cp_deleteInstance_Solaris_PersistentShareForSystem */

/*
 * Method: cp_enumInstances_Solaris_PersistentShareForSystem
 *
 * Description: Enumerates the instances of Solaris_PersistentShareForSystem on
 * a host.
 * An instance of Solaris_PersistentShareForSystem is an association that links
 * a persistent share to the hosting machine.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of
 *	the class for which to enumerate the instances.
 *
 * Returns:
 *	- A pointer to a list of Solaris_PersistentShareForSystem instances.
 *	- NULL if an error occurred or if there are no instances of
 *	Solaris_PersistentShareForSystem on the host.  In the case of an error,
 *	the error will be logged.
 */
CCIMInstanceList *
cp_enumInstances_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP) {
	CCIMObjectPathList	*persistShareOPList;
	CCIMObjectPathList	*tmpOPList;
	CCIMObjectPath		*persistShareOP;
	CCIMInstanceList	*persistShareForSysInstList;
	CCIMProperty		*antProp;
	CIMBool			returned_val;
	CCIMException		*ex;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::ENUM_INSTANCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	persistShareOP = cim_createEmptyObjectPath(SOLARIS_PERSISTSHARE);
	if (persistShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	persistShareOPList = cimom_enumerateInstanceNames(persistShareOP,
		cim_false);

	/*
	 * A NULL return value indicates an error, an empty list does not.
	 */
	if (persistShareOPList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE::ENUM_INSTANCES",
			CIM_ERR_FAILED, CIMOM_ENUM_INSTNAMES_FAILURE, ex, &err);
		cim_freeObjectPath(persistShareOP);
		return ((CCIMInstanceList *)NULL);
	}

	cim_freeObjectPath(persistShareOP);

	if (persistShareOPList->mDataObject == NULL) {
		cim_freeObjectPathList(persistShareOPList);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Retrieve the Antecedent property.  The Antecedent property is the
	 * same for every instance of Solaris_PersistentShareForSystem because
	 * it is the Solaris_ComputerSystem upon which the
	 * Solaris_PersistentShare resides.
	 */
	antProp = get_Antecedent();
	if (antProp == NULL) {
		/*
		 * An error was encountered and it was handled in
		 * get_Antecedent.
		 */
		cim_freeObjectPathList(persistShareOPList);
		return ((CCIMInstanceList *)NULL);
	}

	persistShareForSysInstList = cim_createInstanceList();
	if (persistShareForSysInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		cim_freeObjectPathList(persistShareOPList);
		cim_freeProperty(antProp);
		return ((CCIMInstanceList *)NULL);
	}

	for (tmpOPList = persistShareOPList; tmpOPList != NULL;
		tmpOPList = tmpOPList->mNext) {

		CCIMInstance	*persistShareForSysInst;

		persistShareForSysInst = cim_createInstance(
			SOLARIS_SYSPERSISTSHARE);
		if (persistShareForSysInst == NULL) {
			ex = cim_getLastError();
			util_handleError(
				"SOLARIS_SYSPERSISTSHARE::ENUM_INSTANCES",
				CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex,
				&err);
			cim_freeObjectPathList(persistShareOPList);
			cim_freeProperty(antProp);
			cim_freeInstanceList(persistShareForSysInstList);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Create a reference property out of the current
		 * Solaris_PersistentShare object path.
		 */
		if (add_property_to_instance(sysPersShareProps[DEP].name,
			sysPersShareProps[DEP].type, NULL,
			tmpOPList->mDataObject, sysPersShareProps[DEP].isKey,
			persistShareForSysInst) == cim_false) {

			cim_freeObjectPathList(persistShareOPList);
			cim_freeProperty(antProp);
			cim_freeInstance(persistShareForSysInst);
			cim_freeInstanceList(persistShareForSysInstList);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Add the Antecedent (Solaris_ComputerSystem) property to the
		 * instance.
		 */
		returned_val = cim_addProperty(persistShareForSysInst, antProp);
		if (returned_val == cim_false) {
			ex = cim_getLastError();
			util_handleError(
				"SOLARIS_SYSPERSISTSHARE::ENUM_INSTANCES",
				CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, &err);
			cim_freeObjectPathList(persistShareOPList);
			cim_freeProperty(antProp);
			cim_freeInstanceList(persistShareForSysInstList);
			cim_freeInstance(persistShareForSysInst);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Add the Solaris_PersistentShareForSystem instance to the
		 * instance list.
		 */
		persistShareForSysInstList = cim_addInstance(
			persistShareForSysInstList,
			persistShareForSysInst);
		if (persistShareForSysInstList == NULL) {
			ex = cim_getLastError();
			util_handleError(
				"SOLARIS_SYSPERSISTSHARE::ENUM_INSTANCES",
				CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, &err);
			cim_freeObjectPathList(persistShareOPList);
			cim_freeInstance(persistShareForSysInst);
			return ((CCIMInstanceList *)NULL);
		}
	}

	cim_freeObjectPathList(persistShareOPList);
	return (persistShareForSysInstList);

} /* cp_enumInstances_Solaris_PersistentShareForSystem */

/*
 * Method: cp_enumInstanceNames_Solaris_PersistentShareForSystem
 *
 * Description: Enumerates the object paths corresponding to the instances of
 * Solaris_PersistentShareForSystem on a host.
 * An instance of Solaris_PersistentShareForSystem is an association that links
 * a persistent share to the hosting machine.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of
 *	the class for which to enumerate the instances.
 *
 * Returns:
 *	- A pointer to a list of Solaris_PersistentShareForSystem object paths.
 *	- NULL if an error occurred or if there are no instances of
 *	Solaris_PersistentShareForSystem on the host.  In the case of an error,
 *	the error will be logged.
 */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP) {
	CCIMInstanceList	*persistShareForSysInstList;
	CCIMObjectPathList	*persistShareForSysOPList;
	int			err = 0;

	/*
	 * First check if the CCIMObjectPath parameter is null.
	 */
	if (pOP == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::ENUM_INSTANCE_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	persistShareForSysInstList =
		cp_enumInstances_Solaris_PersistentShareForSystem(pOP);
	if (persistShareForSysInstList == NULL) {
		/*
		 * An error occurred in enumInstances or there are simply no
		 * Solaris_PersistentShareForSystem instances to enumerate.  In
		 * the case of an error, the error would have been handled in
		 * the cp_enumInstances_Solaris_PersistentShareForSystem
		 * function.
		 */
		return ((CCIMObjectPathList *)NULL);
	}

	persistShareForSysOPList = cim_createObjectPathList(
		persistShareForSysInstList);

	cim_freeInstanceList(persistShareForSysInstList);
	return (persistShareForSysOPList);

} /* cp_enumInstanceNames_Solaris_PersistentShareForSystem */

/*
 * Method: cp_execQuery_Solaris_PersistentShareForSystem
 *
 * Description: Queries the host to find those Solaris_PersistentShareForSystem
 * instances that meet the search criteria.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of
 *	the class to query.
 *	- char *selectClause - Not used.
 *	- char *nonJoinExp - Not used.
 *	- char *queryExp - Not used.
 *	- char *queryLang - Not used.
 *
 * Returns:
 *	- A pointer to a list of Solaris_PersistentShareForSystem instances
 *	that match the criteria.
 *	- NULL if an error occurred or if there are no
 *	Solaris_PersistentShareForSystem instances that match the criteria.
 *	In the case of an error, the error will be logged.
 *
 * NOTE: Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_execQuery_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP,
	char *selectClause, char *nonJoinExp, char *queryExp, char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*persistShareForSysInstList;
	CCIMException		*ex;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::EXEC_QUERY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	persistShareForSysInstList =
		cp_enumInstances_Solaris_PersistentShareForSystem(pOP);
	if (persistShareForSysInstList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE::EXEC_QUERY",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	persistShareForSysInstList = cim_prependInstance(
		persistShareForSysInstList, emptyInst);
	if (persistShareForSysInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE::EXEC_QUERY",
			CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (persistShareForSysInstList);
} /* cp_execQuery_Solaris_PersistentShareForSystem */

/*
 * Method: cp_getInstance_Solaris_PersistentShareForSystem
 *
 * Description: Gets the instance corresponding to the passed in object path.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - The object path containing all the
 *	keys of the instance that is to be returned.
 *
 * Returns:
 *	- A pointer to the instance of Solaris_PersistentShareForSystem
 *	corresponding to pOP.
 *	- NULL if an error occurred or if the instance doesn't exist on the
 *	host.  In the case of an error, the error will be logged.
 */
CCIMInstance *
cp_getInstance_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP) {
	CCIMInstance		*persistShareForSysInst;
	CCIMPropertyList	*persistShareForSysPropList;
	CCIMInstanceList	*instList;
	CCIMObjectPath		*antOP;
	CCIMObjectPath		*depOP;
	int			err = 0;

	if (pOP == NULL || pOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	/*
	 * Get the Dependent and Antecedent properties.
	 */
	persistShareForSysPropList = pOP->mKeyProperties;
	antOP = util_getKeyValue(persistShareForSysPropList,
		sysPersShareProps[ANT].type, sysPersShareProps[ANT].name, &err);
	depOP = util_getKeyValue(persistShareForSysPropList,
		sysPersShareProps[DEP].type, sysPersShareProps[DEP].name, &err);

	/*
	 * Check if we have the Antecedent and Dependent properties.
	 */
	if (antOP == NULL || depOP == NULL ||
		antOP->mKeyProperties == NULL ||
		depOP->mKeyProperties == NULL) {

		util_handleError("SOLARIS_SYSPERSISTSHARE::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_PersistentShareForSystem(pOP);
	if (instList == NULL) {
		return ((CCIMInstance *)NULL);
	}

	persistShareForSysInst = cim_getInstance(instList, pOP);

	cim_freeInstanceList(instList);
	return (persistShareForSysInst);

} /* cp_getInstance_Solaris_PersistentShareForSystem */

/*
 * Method: cp_setInstance_Solaris_PersistentShareForSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change a Solaris_PersistentShareForSystem instance the underlying
 * persistent share and computer system must be modified.  Those actions must
 * done on the appropriate persistent share and computer system objects, not
 * here.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of the class
 *	for which to set the instance.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- Always returns cim_false, because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP,
	CCIMInstance *pInst) {

	int	err = 0;

	util_handleError("SOLARIS_SYSPERSISTSHARE::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_PersistentShareForSystem */

/*
 * Method: cp_setInstanceWithList_Solaris_PersistentShareForSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change a Solaris_PersistentShareForSystem instance the underlying
 * persistent share and computer system must be modified.  Those actions must
 * done on the appropriate persistent share and computer system objects, not
 * here.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of the class
 *	for which to set the instance.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- Always returns cim_false, because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP,
	CCIMInstance *pInst, char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_SYSPERSISTSHARE::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstanceWithList_Solaris_PersistentShareForSystem */

/*
 * Associator provider methods
 */

/*
 * Method: cp_associators_Solaris_PersistentShareForSystem
 *
 * Description:  Returns the instances associated, via the
 * Solaris_PersistentShareForSystem association, to the pObjectName parameter.
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
 *	- A list of Solaris_PersistentShare (if pRole == Antecedent &&
 *	pObjectName is a Solaris_ComputerSystem object path) or
 *	Solaris_ComputerSystem (if pRole == Dependent && pObjectName is a
 *	Solaris_PersistentShare object path) instances which are associated
 *	to the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_PersistentShareForSystem(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*returnInstList = NULL;
	CCIMObjectPath		*resultOP;
	CCIMException		*ex;
	cimchar			*resultClassName;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Determine whether the pObjectName is the Antecedent or the Dependent
	 * of the association.  Antecedent == Solaris_ComputerSystem,
	 * Dependent = Solaris_PersistentShare
	 */
	if ((strcasecmp(pObjectName->mName, COMPUTER_SYSTEM) == 0)) {
		CCIMPropertyList	*propList;
		char			*name;
		char			*hostname;

		resultClassName = SOLARIS_PERSISTSHARE;

		/*
		 * If a value was passed in with pRole and it does not match
		 * the role that the pObjectName actually is then log an
		 * invalid param error.
		 */
		if (pRole != NULL && (strcasecmp(pRole,
			sysPersShareProps[ANT].name) != 0)) {
			util_handleError("SOLARIS_SYSPERSISTSHARE::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Retrieve the Name key property from the pObjectName object
		 * path.  This is expected to be populated with the host name.
		 * If the Name key value is not the same as that of the current
		 * host, return null.
		 */
		propList = pObjectName->mKeyProperties;
		name = (cimchar *)util_getKeyValue(propList, string, NAME,
			&err);

		if (name == NULL || err != 0) {
			/*
			 * We don't have the appropriate information.
			 */
			util_handleError("SOLARIS_SYSPERSISTSHARE::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}

		err = 0;
		hostname = sys_get_hostname(&err);
		if (hostname == NULL || err != 0) {
			util_handleError("SOLARIS_SYSPERSISTSHARE::ASSOCIATORS",
				CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL,
				&err);
			return ((CCIMInstanceList *)NULL);
		}

		if ((strcmp(name, hostname) != 0)) {
			/*
			 * We can only determine shares on the current host.
			 * The providers are not distributed.
			 */
			util_handleError("SOLARIS_SYSPERSISTSHARE::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			free(hostname);
			return ((CCIMInstanceList *)NULL);
		}
		free(hostname);

	} else if (strcasecmp(pObjectName->mName, SOLARIS_PERSISTSHARE) == 0) {
		CIMBool	persistShareExists;

		resultClassName = COMPUTER_SYSTEM;
		if (pRole != NULL && (strcasecmp(pRole,
			sysPersShareProps[DEP].name) != 0)) {
			util_handleError("SOLARIS_SYSPERSISTSHARE::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}

		persistShareExists = does_persistent_share_exist(pObjectName);

		if (persistShareExists == cim_false) {
			cim_logDebug("cp_associators",
				"persistShareExists == cim_false");
			util_handleError("SOLARIS_SYSPERSISTSHARE:ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}
	} else {
		util_handleError("SOLARIS_SYSPERSISTSHARE:ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	resultOP = cim_createEmptyObjectPath(resultClassName);
	if (resultOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE:ASSOCIATORS",
			CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	returnInstList = cimom_enumerateInstances(resultOP, cim_false,
		cim_false, cim_false, cim_false, cim_false, NULL, 0);

	/*
	 * A NULL return value indicates error, an empty list does not.
	 */
	if (returnInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE:ASSOCIATORS",
			CIM_ERR_FAILED, CIMOM_ENUM_INST_FAILURE, ex, &err);
		cim_freeObjectPath(resultOP);
		return ((CCIMInstanceList *)NULL);
	}

	cim_freeObjectPath(resultOP);

	if (returnInstList->mDataObject == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	return (returnInstList);
} /* cp_associators_Solaris_PersistentShareForSystem */

/*
 * Method: cp_associatorNames_Solaris_PersistentShareForSystem
 *
 * Description: Returns the object paths corresponding to the instances on the
 * other side of the association which are associated via the
 * Solaris_PersistentShareForSystem association and having the passed in
 * parameter, pObjectName, as the opposite key.
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
 *	- A list of Solaris_PersistentShare (if pRole == Antecedent &&
 *	pObjectName is a Solaris_ComputerSystem object path) or
 *	Solaris_ComputerSystem (if pRole == Dependent && pObjectName is a
 *	Solaris_PersistentShare object path) object paths which are associated
 *	to the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
CCIMObjectPathList *
cp_associatorNames_Solaris_PersistentShareForSystem(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::ASSOCIATOR_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_associators_Solaris_PersistentShareForSystem(pAssocName,
		pObjectName, pResultClass, pRole, pResultRole);
	if (instList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	objPathList = cim_createObjectPathList(instList);

	cim_freeInstanceList(instList);
	return (objPathList);
} /* cp_associatorNames_Solaris_PersistentShareForSystem */

/*
 * Method: cp_references_Solaris_PersistentShareForSystem
 *
 * Description: Returns the Solaris_PersistentShareForSystem instances that
 * have the passed in parameter, pObjectName, as one of it's keys.
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
 *	- A pointer to a list of Solaris_PersistentShareForSystem instances.
 *	- NULL if an error occurred or if there are no
 *	Solaris_PersistentShareForSystem instances having pObjectName as one of
 *	it's keys.
 */
CCIMInstanceList *
cp_references_Solaris_PersistentShareForSystem(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::REFERENCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Get everything that is related to the pObjectName passed in.
	 */
	objPathList = cp_associatorNames_Solaris_PersistentShareForSystem(
		pAssocName, pObjectName, NULL, pRole, NULL);
	if (objPathList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Now use the object paths in the object path list and the pObjectName
	 * variable to create the association instances.
	 */

	if ((strcasecmp(pObjectName->mName, SOLARIS_PERSISTSHARE) == 0)) {
		/*
		 * pObjectName is the Dependent
		 */
		instList = create_association_instList(SOLARIS_SYSPERSISTSHARE,
			pObjectName, DEPENDENT, objPathList, ANTECEDENT, &err);
	} else {
		/*
		 * pObjectName is the Antecedent
		 */
		instList = create_association_instList(SOLARIS_SYSPERSISTSHARE,
			pObjectName, ANTECEDENT, objPathList, DEPENDENT, &err);
	}
	cim_freeObjectPathList(objPathList);

	return (instList);
} /* cp_references_Solaris_PersistentShareForSystem */

/*
 * Method: cp_referenceNames_Solaris_PersistentShareForSystem
 *
 * Description: Returns the object paths corresponding to the
 * Solaris_PersistentShareForSystem instances that have the passed in parameter,
 * pObjectName, as one of it's keys.
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
 *	- A pointer to a list of Solaris_PersistentShareForSystem object paths.
 *	- NULL if an error occurred or if there are no
 *	Solaris_PersistentShareForSystem instances having pObjectName as one of
 *	it's keys.
 */
CCIMObjectPathList *
cp_referenceNames_Solaris_PersistentShareForSystem(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*persistShareForSysInstList;
	CCIMObjectPathList	*persistShareForSysOPList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::REFERENCE_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	persistShareForSysInstList =
		cp_references_Solaris_PersistentShareForSystem(pAssocName,
			pObjectName, pRole);
	if (persistShareForSysInstList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	persistShareForSysOPList = cim_createObjectPathList(
		persistShareForSysInstList);

	cim_freeInstanceList(persistShareForSysInstList);
	return (persistShareForSysOPList);
} /* cp_referenceNames_Solaris_PersistentShareForSystem */

/*
 * Property provider methods
 */

/*
 * Method: cp_getProperty_Solaris_PersistentShareForSystem
 *
 * Description: Retrieves a certain property from the instance of
 * Solaris_PersistentShareForSystem on the host that is described by the
 * parameter pOP.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - The object path containing all the
 *	information needed to find the instance for which the property is to
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
cp_getProperty_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP,
	cimchar *pPropName) {

	CCIMInstance	*persistShareForSysInst;
	CCIMProperty	*persistShareForSysProp;
	int		err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::GET_PROPERTY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	persistShareForSysInst =
		cp_getInstance_Solaris_PersistentShareForSystem(pOP);
	if (persistShareForSysInst == NULL) {
		return ((CCIMProperty *)NULL);
	}

	persistShareForSysProp = cim_getProperty(persistShareForSysInst,
		pPropName);
	cim_freeInstance(persistShareForSysInst);

	return (persistShareForSysProp);

} /* cp_getProperty_Solaris_PersistentShareForSystem */

/*
 * Method: cp_setProperty_Solaris_PersistentShareForSystem
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change a Solaris_PersistentShareForSystem instance the underlying
 * persistent share and computer system must be modified.  Those actions must
 * done on the appropriate persistent share and computer system objects, not
 * here.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - Not used.
 *	- CCIMProperty *pProp - Not used.
 *
 * Returns:
 *	- Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP,
	CCIMProperty *pProp) {

	int	err = 0;

	util_handleError("SOLARIS_SYSPERSISTSHARE::SET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_PersistentShareForSystem */

/*
 * Method provider methods
 */

/*
 * Method: cp_invokeMethod_Solaris_PersistentShareForSystem
 *
 * Description: This method is not supported because the provider doesn't have
 * any methods.
 *
 * Parameters:
 *	- CCIMObjectPath* op - Not used.
 *	- cimchar* methodName - Not used.
 *	- CCIMPropertyList* inParams - Not used.
 *	- CCIMPropertyList* outParams - Not used.
 *
 * Returns:
 *	- Always returns null because the method is not supported.
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_PersistentShareForSystem(CCIMObjectPath *pOP,
	cimchar *methodName, CCIMPropertyList *inParams,
	CCIMPropertyList *outParams) {

	return ((CCIMProperty *)NULL);
} /* cp_invokeMethod_Solaris_PersistentShareForSystem */

/*
 * Private Methods
 */

/*
 * Method: does_persistent_share_exist
 *
 * Description: Determines from the Solaris_PersistentShare object path whether
 * or not the dfstab entry actually exists.
 *
 * Parameters:
 *	- CCIMObjectPath *persShareOP - The object path used (by retrieving
 *	the SettingId property) to determine whether or not the dfstab entry
 *	exists.
 *
 * Returns:
 *	- cim_true or cim_false representing whether or not the entry was
 *	found.
 */
static CIMBool
does_persistent_share_exist(CCIMObjectPath *persShareOP) {
	CCIMPropertyList	*propList;
	CIMBool			foundEntry = cim_false;
	fs_dfstab_entry_t	dfstabEnts, currentDfstabEnt;
	char			*settingId;
	int			err = 0;

	propList = persShareOP->mKeyProperties;

	settingId = util_getKeyValue(propList, string, SETTING_ID, &err);
	if (settingId == NULL || err != 0) {
		return (cim_false);
	}

	cim_logDebug("does_persistent_share_exist", "SettingId =%s", settingId);
	dfstabEnts = fs_get_DFStab_ents(&err);

	currentDfstabEnt = dfstabEnts;
	while (currentDfstabEnt != NULL && foundEntry == cim_false) {
		char	*path;

		path = fs_get_DFStab_ent_Path(currentDfstabEnt);

		if (strcasecmp(path, settingId) == 0) {
			foundEntry = cim_true;
		}
		currentDfstabEnt = fs_get_DFStab_ent_Next(currentDfstabEnt);
	}

	fs_free_DFStab_ents(dfstabEnts);
	return (foundEntry);
} /* does_persistent_share_exist */

/*
 * Method: get_Antecedent
 *
 * Description: Retrieves the antecedent, Solaris_ComputerSystem, reference
 * property for the association.
 *
 * Parameters:
 *	- NONE
 *
 * Returns:
 *	- A pointer to a Solaris_ComputerSystem reference property.
 *	- Upon error, NULL is returned and the error is logged.
 */
static CCIMProperty *
get_Antecedent() {
	CCIMInstance    *compSysInst;
	CCIMObjectPath	*compSysOP;
	CCIMProperty	*compSysRefProp;
	CCIMException	*ex;
	char		*hostname;
	int		err = 0;

	compSysInst = cim_createInstance(COMPUTER_SYSTEM);
	if (compSysInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE::GET_ANT",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return ((CCIMProperty *)NULL);
	}

	/*
	 * Create the key properties on the Solaris_ComputerSystem instance.
	 *
	 * The Solaris_ComputerSystem keys are as follows:
	 * CreationClassName = "Solaris_ComputerSystem"
	 * Name = < host name >
	 */

	if (add_property_to_instance(CREATION_CLASS, string,
		COMPUTER_SYSTEM, NULL, cim_true, compSysInst) == cim_false) {

		cim_freeInstance(compSysInst);
		return ((CCIMProperty *)NULL);
	}

	err = 0;
	hostname = sys_get_hostname(&err);
	if (hostname == NULL) {
		util_handleError("SOLARIS_SYSPERSISTSHARE::GET_ANT",
			CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL, &err);
		cim_freeInstance(compSysInst);
		return ((CCIMProperty *)NULL);
	}

	if (add_property_to_instance(NAME, string, hostname, NULL,
		cim_true, compSysInst) == cim_false) {

		free(hostname);
		cim_freeInstance(compSysInst);
		return ((CCIMProperty *)NULL);
	}
	free(hostname);

	compSysOP = cim_createObjectPath(compSysInst);
	if (compSysOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE::GET_ANT",
			CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE,
			ex, &err);
		cim_freeInstance(compSysInst);
		return ((CCIMProperty *)NULL);
	}

	cim_freeInstance(compSysInst);

	compSysRefProp = cim_createReferenceProperty(
		sysPersShareProps[ANT].name, compSysOP,
		sysPersShareProps[ANT].isKey);
	if (compSysRefProp == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_SYSPERSISTSHARE::GET_ANT",
			CIM_ERR_FAILED, CREATE_REFPROP_FAILURE, ex, &err);
		cim_freeObjectPath(compSysOP);
		return ((CCIMProperty *)NULL);
	}

	cim_freeObjectPath(compSysOP);

	return (compSysRefProp);
} /* get_Antecedent */
