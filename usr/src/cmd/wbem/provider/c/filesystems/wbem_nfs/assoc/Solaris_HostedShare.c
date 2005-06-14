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

#include "Solaris_HostedShare.h"
#include "nfs_keys.h"
#include "nfs_providers_msgstrings.h"
#include "messageStrings.h"
#include "nfs_provider_names.h"
#include "util.h"
#include "libfsmgt.h"
#include "common_functions.h"
#include "createprop_methods.h"

/*
 * Private method declarations
 */
static CIMBool		does_share_exist(char *dir);
static CCIMObjectPath*	get_Antecedent();

/*
 * Public methods
 */

/*
 * Instance provider methods
 */

/*
 * Method: cp_createInstance_Solaris_HostedShare
 *
 * Description: This method is not supported.  It is not supported because in
 * order for a Solaris_HostedShare association to exist a corresponding
 * Solaris_NFSShare and Solaris_ComputerSystem must exist.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - An object path containing the name of
 *	the class of which to create an instance of.
 *	- CCIMInstance *hostedShareInst - Not used.
 *
 * Returns:
 *	- Always returns NULL because the method is not supported.
 */
/* ARGSUSED */
CCIMObjectPath *
cp_createInstance_Solaris_HostedShare(CCIMObjectPath *hostedShareOP,
	CCIMInstance *hostedShareInst) {

	int	err = 0;

	util_handleError("SOLARIS_HOSTEDSHARE::CREATE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMObjectPath *)NULL);
} /* cp_createInstance_Solaris_HostedShare */

/*
 * Method: cp_deleteInstance_Solaris_HostedShare
 *
 * Description: This method is not supported.  It is not supported because in
 * order for it to be actually deleted the corresponding Solaris_NFSShare would
 * need to be deleted.  That action is not appropriate for this provider.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - An object path containing the
 *	information about the class of which to delete the instance of.
 *
 * Returns:
 *	- Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_HostedShare(CCIMObjectPath *hostedShareOP) {
	int	err = 0;

	util_handleError("SOLARIS_HOSTEDSHARE::DELETE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_deleteInstance_Solaris_HostedShare */

/*
 * Method: cp_enumInstances_Solaris_HostedShare
 *
 * Description: Enumerates the instances of Solaris_HostedShare on a host.
 * An instance of Solaris_HostedShare is an association that links a share to
 * the hosting machine.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - An object path containing the name of
 *	the class of which to enumerate the instances of.
 *
 * Returns:
 *	- A pointer to a list of Solaris_HostedShare instances.
 *	- NULL if an error occurred or if there are no instances of
 *	Solaris_HostedShare on the host.  In the case of an error, the error
 *	will be logged.
 */
CCIMInstanceList *
cp_enumInstances_Solaris_HostedShare(CCIMObjectPath* hostedShareOP) {
	CCIMInstanceList	*hostedShareInstList;
	CCIMObjectPath		*nfsShareOP;
	CCIMObjectPathList	*nfsShareOPList, *currentShareOP;
	CCIMObjectPath		*antOP;
	CCIMException		*ex;
	int			err = 0;

	/*
	 * The Antecedent property is a Solaris_ComputerSystem reference.
	 * The Dependent property is a Solaris_NFSShare reference.
	 */
	if (hostedShareOP == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::ENUM_INSTANCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOP = cim_createEmptyObjectPath(SOLARIS_NFSSHARE);
	if (nfsShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Enumerate all of the Solaris_NFSShare object paths on the system.
	 */
	nfsShareOPList = cimom_enumerateInstanceNames(nfsShareOP, cim_false);

	/*
	 * A NULL return value indicates an error, an empty list does not.
	 */
	if (nfsShareOPList == NULL) {
		cim_logDebug("cp_enumInstances_Solaris_HostedShare",
			"nfsShareOPList = NULL");
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::ENUM_INSTANCES",
			CIM_ERR_FAILED, CIMOM_ENUM_INSTNAMES_FAILURE, ex, &err);
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMInstanceList *)NULL);

	}

	cim_freeObjectPath(nfsShareOP);

	if (nfsShareOPList->mDataObject == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	antOP = get_Antecedent();
	if (antOP == NULL) {
		/*
		 * The error was logged in get_Antecedent.
		 */
		cim_freeObjectPathList(nfsShareOPList);
		return ((CCIMInstanceList *)NULL);
	}

	hostedShareInstList = cim_createInstanceList();
	if (hostedShareInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		cim_freeObjectPathList(nfsShareOPList);
		cim_freeObjectPath(antOP);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Each share on the system will be associated with the same
	 * Solaris_ComputerSystem object path.
	 */
	for (currentShareOP = nfsShareOPList; currentShareOP != NULL;
		currentShareOP = currentShareOP->mNext) {

		CCIMInstance	*hostedShareInst;
		cimchar		*propValue;

		hostedShareInst = cim_createInstance(SOLARIS_HOSTEDSHARE);
		if (hostedShareInst == NULL) {
			ex = cim_getLastError();
			util_handleError("SOLARIS_HOSTEDSHARE::ENUM_INSTANCES",
				CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex,
				&err);
			cim_freeInstanceList(hostedShareInstList);
			cim_freeObjectPath(antOP);
			cim_freeObjectPathList(nfsShareOPList);
			return ((CCIMInstanceList *)NULL);
		}

		propValue = NULL;
		if (add_property_to_instance(
			hostedShareProps[ANT].name, hostedShareProps[ANT].type,
			propValue, antOP, hostedShareProps[ANT].isKey,
			hostedShareInst) == cim_false) {

			cim_freeInstance(hostedShareInst);
			cim_freeInstanceList(hostedShareInstList);
			cim_freeObjectPathList(nfsShareOPList);
			cim_freeObjectPath(antOP);
			return ((CCIMInstanceList *)NULL);
		}

		if (add_property_to_instance(hostedShareProps[DEP].name,
			hostedShareProps[DEP].type, propValue,
			currentShareOP->mDataObject,
			hostedShareProps[DEP].isKey, hostedShareInst)
			== cim_false) {

			cim_freeInstance(hostedShareInst);
			cim_freeInstanceList(hostedShareInstList);
			cim_freeObjectPathList(nfsShareOPList);
			cim_freeObjectPath(antOP);
			return ((CCIMInstanceList *)NULL);
		}

		hostedShareInstList = cim_addInstance(hostedShareInstList,
			hostedShareInst);
		if (hostedShareInstList == NULL) {
			ex = cim_getLastError();
			util_handleError("SOLARIS_HOSTEDSHARE::ENUM_INSTANCES",
				CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, &err);
			cim_freeInstance(hostedShareInst);
			cim_freeObjectPathList(nfsShareOPList);
			cim_freeObjectPath(antOP);
			return ((CCIMInstanceList *)NULL);
		}
	}

	cim_freeObjectPath(antOP);
	cim_freeObjectPathList(nfsShareOPList);

	return (hostedShareInstList);
} /* cp_enumInstances_Solaris_HostedShare */

/*
 * Method: cp_enumInstanceNames_Solaris_HostedShare
 *
 * Description: Enumerates the instances of Solaris_HostedShare on the host.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - An object path containing the name of
 *	the class of which to enumerate the instance names of.
 *
 * Returns:
 *	- A list of object paths corresponding to the instances of
 *	Solaris_HostedShare on the host.
 *	- NULL if an error occurred or if there are no instances of
 *	Solaris_HostedShare on the host.  In the case of an error, the error
 *	will be logged.
 */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_HostedShare(CCIMObjectPath *hostedShareOP) {
	CCIMInstanceList	*hostedShareInstList;
	CCIMObjectPathList	*hostedShareOPList;
	int			err = 0;

	if (hostedShareOP == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::ENUM_INSTANCENAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	hostedShareInstList =
		cp_enumInstances_Solaris_HostedShare(hostedShareOP);
	if (hostedShareInstList == NULL) {
		/*
		 * An error occurred in enumInstances or there are simply
		 * no Solaris_HostedShare instances to enumerate.  In the case,
		 * of an error, the error would have been handled in the
		 * cp_enumInstances_Solaris_HostedShare function.
		 */
		return ((CCIMObjectPathList *)NULL);
	}

	hostedShareOPList = cim_createObjectPathList(hostedShareInstList);

	cim_freeInstanceList(hostedShareInstList);
	/*
	 * If an error occurred it will be handled in cim_createObjectPathList.
	 */
	return (hostedShareOPList);
} /* cp_enumInstanceNames_Solaris_HostedShare */

/*
 * Method: cp_execQuery_Solaris_HostedShare
 *
 * Description: Queries the host to find those Solaris_HostedShare instances
 * that meet the search criteria.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - An object path containing the name of
 *	the class of which to query.
 *	- char *selectClause - Not used.
 *	- char *nonJoinExp - Not used.
 *	- char *queryExp - Not used.
 *	- char *queryLang - Not used.
 *
 * Returns:
 *      - A pointer to a list of Solaris_HostedShare instances that match the
 *      criteria.
 *      - NULL if an error occurred or if there are no Solaris_HostedShare
 *      instances that match the criteria.  In the case of an error, the error
 *      will be logged.
 *
 * NOTE: Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_execQuery_Solaris_HostedShare(CCIMObjectPath *hostedShareOP,
	char *selectClause, char *nonJoinExp, char *queryExp, char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*hostedShareInstList;
	CCIMException		*ex;
	int			err = 0;

	if (hostedShareOP == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::EXEC_QUERY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	hostedShareInstList = cp_enumInstances_Solaris_HostedShare(
		hostedShareOP);
	if (hostedShareInstList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::EXEC_QUERY",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(hostedShareInstList);
		return ((CCIMInstanceList *)NULL);
	}

	hostedShareInstList = cim_prependInstance(hostedShareInstList,
		emptyInst);

	if (hostedShareInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::EXEC_QUERY",
			CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (hostedShareInstList);
} /* cp_execQuery_Solaris_HostedShare */

/*
 * Method: cp_getInstance_Solaris_HostedShare
 *
 * Description: Gets the instance corresponding to the passed in object path.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - The object path containing all the
 *	keys of the instance that is supposed to be returned.
 *
 * Returns:
 *	- A pointer to the instance of Solaris_HostedShare corresponding to
 *	hostedShareOP.
 *	- NULL if an error occurred or if the instance doesn't exist on the
 *	host.  In the case of an error, the error will be logged.
 */
CCIMInstance *
cp_getInstance_Solaris_HostedShare(CCIMObjectPath *hostedShareOP) {
	CCIMInstance		*inst;
	CCIMInstanceList	*instList;
	CCIMPropertyList	*hsPropList;
	CCIMObjectPath		*depOP;
	CCIMObjectPath		*antOP;
	int			err = 0;

	if (hostedShareOP == NULL || hostedShareOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	/*
	 * Get the Dependent and Antecedent properties.
	 */
	hsPropList = hostedShareOP->mKeyProperties;
	depOP = util_getKeyValue(hsPropList, hostedShareProps[DEP].type,
		hostedShareProps[DEP].name, &err);
	antOP = util_getKeyValue(hsPropList, hostedShareProps[ANT].type,
		hostedShareProps[ANT].name, &err);

	/*
	 * Check if we have the Antecedent and Dependent properties.
	 */
	if (depOP == NULL || antOP == NULL ||
		depOP->mKeyProperties == NULL ||
		antOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_HostedShare(hostedShareOP);
	if (instList == NULL) {
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, hostedShareOP);

	cim_freeInstanceList(instList);
	return (inst);
} /* cp_getInstance_Solaris_HostedShare */

/*
 * Method: cp_setInstance_Solaris_HostedShare
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change a Solaris_HostedShare instance the underlying share and
 * computer system must be modified.  Those actions must be done on the
 * appropriate share and computer system objects, not here.
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
cp_setInstance_Solaris_HostedShare(CCIMObjectPath *pOP, CCIMInstance *pInst) {

	int	err = 0;

	util_handleError("SOLARIS_HOSTEDSHARE::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_HostedShare */

/*
 * Method: cp_setInstanceWithList_Solaris_HostedShare
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change a Solaris_HostedShare instance the underlying share and
 * computer system must be modified.  Those actions must be done on the
 * appropriate share and computer system objects, not here.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - The object path containing the name
 *	of the class of which to set the instance.
 *	- CCIMInstance *hostedShareInst - Not used.
 *	- char **props - Not used.
 *	- int num_props - Not used.
 *
 * Returns:
 *      - Always returns cim_false, because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_HostedShare(CCIMObjectPath *hostedShareOP,
	CCIMInstance *hostedShareInst, char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_HOSTEDSHARE::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstanceWithList_Solaris_HostedShare */

/*
 * Association provider methods
 */

/*
 * Method: cp_associators_Solaris_HostedShare
 *
 * Description: Returns the instances associated, via the Solaris_HostedShare
 * association, to the pObjectName parameter.
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
 *	- A list of Solaris_NFSShare (if pRole == Antecedent && pObjectName is
 *	a Solaris_ComputerSystem object path) or Solaris_ComputerSystem (if
 *	pRole == Dependent && pObjectName is a Solaris_NFSShare object path)
 *	instances which are associated to the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_HostedShare(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*returnInstList = NULL;
	CCIMPropertyList	*propList;
	CCIMObjectPath		*resultOP;
	CCIMException		*ex;
	CIMBool			pDeep, pLocalOnly, pIncludeQualifiers,
				pIncludeClassOrigin, pUseInternal;
	cimchar			*resultClassName;
	char			*name;
	char			**pPropertyList;
	unsigned int		pNumProps;
	int			err = 0;
	/*
	 * Check if the needed parameters are NULL.
	 */
	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * The Name key property is the defining property for each the
	 * Antecedent (Solaris_ComputerSystem) and the Dependent
	 * (Solaris_NFSShare) so retrieve that property.
	 */
	propList = pObjectName->mKeyProperties;
	name = (cimchar *)util_getKeyValue(propList, string, NAME, &err);

	if (name == NULL || err != 0) {
		/*
		 * We don't have the appropriate information.
		 */
		util_handleError("SOLARIS_HOSTEDSHARE::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Determine whether the pObjectName is the Antecedent or the Dependent
	 * of the association.  Antecedent == Solaris_ComputerSystem,
	 * Dependent == Solaris_NFSShare
	 */
	if ((strcasecmp(pObjectName->mName, COMPUTER_SYSTEM) == 0)) {
		char	*hostname;

		resultClassName = SOLARIS_NFSSHARE;

		/*
		 * If a value was passed in with pRole and it does not match
		 * the role that pObjectName actually is then log an invalid
		 * param error.
		 */
		if (pRole != NULL && (strcasecmp(pRole, ANTECEDENT) != 0)) {
			util_handleError("SOLARIS_NFSMOUNT::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Get the current host name and compare it to the name
		 * property of the passed in pObjectName.
		 */
		hostname = sys_get_hostname(&err);
		if (hostname == NULL) {
			util_handleError("SOLARIS_HOSTEDSHARE::ASSOCIATORS",
				CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL,
				&err);
			return ((CCIMInstanceList *)NULL);
		}

		if ((strcmp(name, hostname) != 0)) {
			/*
			 * We can only determine shares on the current host.
			 * The providers are not distributed.
			 */
			util_handleError("SOLARIS_HOSTEDSHARE::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			free(hostname);
			return ((CCIMInstanceList *)NULL);
		}
		free(hostname);
	} else if ((strcasecmp(pObjectName->mName, SOLARIS_NFSSHARE) == 0)) {
		CIMBool	shareExists;

		resultClassName = COMPUTER_SYSTEM;

		/*
		 * pObjectName is the Dependent (Solaris_NFSShare) so determine
		 * if the share actually exists by comparing the Name property
		 * of pObjectName, which is populated with the shared directory,
		 * to existing nfs shares on the system.
		 */
		shareExists = does_share_exist(name);
		if (shareExists == cim_false) {
			return ((CCIMInstanceList *)NULL);
		}
	} else {
		util_handleError("SOLARIS_HOSTEDSHARE::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	resultOP = cim_createEmptyObjectPath(resultClassName);
	if (resultOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::ASSOCIATORS",
			CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE,
			ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	pDeep = cim_false;
	pLocalOnly = cim_false;
	pIncludeQualifiers = cim_false;
	pIncludeClassOrigin = cim_false;
	pUseInternal = cim_false;
	pPropertyList = NULL;
	pNumProps = 0;
	returnInstList = cimom_enumerateInstances(resultOP, pDeep,
		pLocalOnly, pIncludeQualifiers, pIncludeClassOrigin,
		pUseInternal, pPropertyList, pNumProps);
	/*
	 * A NULL return value indicates an error, an empty list
	 * doesn't.
	 */
	if (returnInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::ASSOCIATORS",
			CIM_ERR_FAILED, CIMOM_ENUM_INST_FAILURE, ex,
			&err);
		cim_freeObjectPath(resultOP);
		return ((CCIMInstanceList *)NULL);
	}

	cim_freeObjectPath(resultOP);

	if (returnInstList->mDataObject == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	return (returnInstList);
} /* cp_associators_Solaris_HostedShare */

/*
 * Method: cp_associatorNames_Solaris_HostedShare
 *
 * Description: Returns the object paths of the instances on the other side of
 * the association which are associated via the Solaris_HostedShare association
 * and having the passed in parameter, pObjectName, as the opposite key.
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
 *	- A list of Solaris_NFSShare (if pRole == Antecedent && pObjectName is
 *      a Solaris_ComputerSystem object path) or Solaris_ComputerSystem (if
 *      pRole == Dependent && pObjectName is a Solaris_NFSShare object path)
 *      object paths which are associated to the pObjectName parameter.
 *      - NULL if an error occurred or if there are no instances associated to
 *      the pObjectName passed in.  In the case of an error, the error will be
 *      logged.
 */
CCIMObjectPathList *
cp_associatorNames_Solaris_HostedShare(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList = NULL;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::ASSOCIATOR_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_associators_Solaris_HostedShare(pAssocName, pObjectName,
		pResultClass, pRole, pResultRole);
	if (instList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	objPathList = cim_createObjectPathList(instList);
	cim_freeInstanceList(instList);

	return (objPathList);
} /* cp_associatorNames_Solaris_HostedShare */

/*
 * Method: cp_references_Solaris_HostedShare
 *
 * Description: Returns the Solaris_HostedShare instances that have the passed
 * in parameter, pObjectName, as one of it's keys.
 *
 * Parameters:
 *	- CCIMObjectPath *pAssocName - An object path containing information
 *      about the association that the caller is trying to reach.
 *	- CCIMObjectPath *pObjectName - The object path which contains the
 *	information on whose associated objects are to be returned.
 *	- char *pRole - If specified, this is the role of the pObjectName
 *	object path passed in.  If this is not valid, NULL is returned.
 *
 * Returns:
 *	- A pointer to a list of Solaris_HostedShare instances.
 *	- NULL if an error occurred or if there are no Solaris_HostedShare
 *	instances having pObjectName as one of it's keys.
 */
CCIMInstanceList *
cp_references_Solaris_HostedShare(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	char			*pObjectNameRole;
	char			*objPathListRole;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::REFERENCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Get everything that is related to the pObjectName passed in.
	 */
	objPathList = cp_associatorNames_Solaris_HostedShare(pAssocName,
		pObjectName, NULL, pRole, NULL);
	if (objPathList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Now use the object paths in the object path list and the pObjectName
	 * variable to create the association instances.
	 */
	if ((strcasecmp(pObjectName->mName, SOLARIS_NFSSHARE) == 0)) {
		/*
		 * pObjectName is the Dependent.
		 */
		pObjectNameRole = DEPENDENT;
		objPathListRole = ANTECEDENT;
		instList = create_association_instList(SOLARIS_HOSTEDSHARE,
			pObjectName, pObjectNameRole, objPathList,
			objPathListRole, &err);
	} else {
		/*
		 * pObjectName is the Antecedent.
		 */
		pObjectNameRole = ANTECEDENT;
		objPathListRole = DEPENDENT;
		instList = create_association_instList(SOLARIS_HOSTEDSHARE,
			pObjectName, pObjectNameRole, objPathList,
			objPathListRole, &err);
	}
	cim_freeObjectPathList(objPathList);

	return (instList);
} /* cp_references_Solaris_HostedShare */

/*
 * Method: cp_referenceNames_Solaris_HostedShare
 *
 * Description: Returns the Solaris_HostedShare object paths of the instances
 * that have the passed in parameter, pObjectName, as one of it's keys.
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
 *	- A pointer to a list of Solaris_HostedShare object paths.
 *	- NULL if an error occurred or if there are no Solaris_HostedShare
 *	instances having pObjectName as one of it's keys.
 */
CCIMObjectPathList *
cp_referenceNames_Solaris_HostedShare(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*hostedShareInstList;
	CCIMObjectPathList	*hostedShareOPList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::REFERENCE_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	hostedShareInstList = cp_references_Solaris_HostedShare(pAssocName,
		pObjectName, pRole);

	if (hostedShareInstList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	hostedShareOPList = cim_createObjectPathList(hostedShareInstList);

	cim_freeInstanceList(hostedShareInstList);
	/*
	 * If an error occurred it will be handled in cim_createObjectPathList.
	 */
	return (hostedShareOPList);
} /* cp_referenceNames_Solaris_HostedShare */

/*
 * Property provider methods
 */

/*
 * Method: cp_getProperty_Solaris_HostedShare
 *
 * Description: Retrieves a certain property from the instance of
 * Solaris_HostedShare on the host that is described by the parameter
 * hostedShareOP.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - The object path containing all the
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
cp_getProperty_Solaris_HostedShare(CCIMObjectPath *hostedShareOP,
	cimchar *pPropName) {

	CCIMInstance	*hostedShareInst;
	CCIMProperty	*hostedShareProp;
	int		err = 0;

	if (hostedShareOP == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::GET_PROPERTY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	hostedShareInst = cp_getInstance_Solaris_HostedShare(hostedShareOP);
	if (hostedShareInst == NULL) {
		return ((CCIMProperty *)NULL);
	}

	hostedShareProp = cim_getProperty(hostedShareInst, pPropName);
	cim_freeInstance(hostedShareInst);

	return (hostedShareProp);

} /* cp_getProperty_Solaris_HostedShare */

/*
 * Method: cp_setProperty_Solaris_HostedShare
 *
 * Description: This method is not supported.  It is not supported because in
 * order to change the properties of a Solaris_HostedShare instance, the
 * underlying classes being associated must be changed.  This provider isn't
 * the appropriate place to be changing other things on the host.
 *
 * Parameters:
 *      - CCIMObjectPath *hostedShareOP - Not used.
 *      - CCIMProperty *pProp - Not used.
 *
 * Returns:
 *	- Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_HostedShare(CCIMObjectPath *hostedShareOP,
	CCIMProperty *pProp) {

	int	err = 0;

	util_handleError("SOLARIS_HOSTEDSHARE::SET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_HostedShare */

/*
 * Method provider methods
 */

/*
 * Method: cp_invokeMethod_Solaris_HostedShare
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
cp_invokeMethod_Solaris_HostedShare(CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams) {

	return ((CCIMProperty *)NULL);
} /* cp_invokeMethod_Solaris_HostedShare */

/*
 * Private methods
 */

/*
 * Method: does_share_exist
 *
 * Description: Determines if a given share exists on the host.
 *
 * Parameters:
 *	- char *dir - The name of the directory to see if it is shared.
 *
 * Returns:
 *	- An integer corresponding to the existence of the share on the system.
 *	1 is returned if the share exists, 0 is returned if the share does not
 *	exist.
 */
static CIMBool
does_share_exist(char *dir) {
	fs_sharelist_t	*share_list;
	fs_sharelist_t	*currentShare;
	CIMBool		return_val = cim_false;
	int		err = 0;

	share_list = fs_get_share_list(&err);
	if (share_list == NULL) {
		/*
		 * Either there was an error or there are no shares on the
		 * system.  If there was an error err should be a non-zero
		 * value.
		 */
		if (err != 0) {
			util_handleError("SOLARIS_HOSTEDSHARE::SHARE_EXISTS",
				CIM_ERR_FAILED, FS_GET_SHARE_FAILURE, NULL,
				&err);
		}

		return (return_val);
	}

	currentShare = share_list;
	while (currentShare != NULL && return_val == cim_false) {
		if ((strcmp(currentShare->path, dir) == 0)) {
			return_val = cim_true;
		}

		currentShare = currentShare->next;
	}

	fs_free_share_list(share_list);
	return (return_val);

} /* does_share_exist */

/*
 * Method: get_Antecedent
 *
 * Description: Retrieves a reference property of the host's
 * Solaris_ComputerSystem class.
 *
 * Parameters:
 *	- NONE
 * Returns:
 *	- A pointer to a property which is a reference property of the host's
 *	Solaris_ComputerSystem instance.
 *	- Upon error, NULL is returned and the error is logged.
 */
static CCIMObjectPath *
get_Antecedent() {
	CCIMInstance	*compSysInst;
	CCIMObjectPath	*compSysOP;
	CCIMException	*ex;
	char		*hostname;
	int		err = 0;

	compSysInst = cim_createInstance(COMPUTER_SYSTEM);
	if (compSysInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::GET_ANT",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return ((CCIMObjectPath *)NULL);
	}

	/*
	 * Create the key properties on the Solaris_ComputerSystem instance.
	 *
	 * The Solaris_ComputerSystem keys are as follows:
	 * CreationClassName = "Solaris_ComputerSystem"
	 * Name = < host name >
	 */
	if (add_property_to_instance(CREATION_CLASS, string, COMPUTER_SYSTEM,
		NULL, cim_true, compSysInst) == cim_false) {

		cim_freeInstance(compSysInst);
		return ((CCIMObjectPath *)NULL);
	}

	hostname = sys_get_hostname(&err);
	if (hostname == NULL) {
		util_handleError("SOLARIS_HOSTEDSHARE::GET_ANT",
			CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL, &err);
		return ((CCIMObjectPath *)NULL);
	}

	if (add_property_to_instance(NAME, string, hostname, NULL,
		cim_true, compSysInst) == cim_false) {

		free(hostname);
		cim_freeInstance(compSysInst);
		return ((CCIMObjectPath *)NULL);
	}
	free(hostname);

	compSysOP = cim_createObjectPath(compSysInst);
	if (compSysOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_HOSTEDSHARE::GET_ANT",
			CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE,
			ex, &err);
		cim_freeInstance(compSysInst);
		return ((CCIMObjectPath *)NULL);
	}

	return (compSysOP);
} /* get_Antecedent */
