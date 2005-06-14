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

#include "Solaris_NFSShareEntry.h"
#include "nfs_keys.h"
#include "nfs_providers_msgstrings.h"
#include "nfs_provider_names.h"
#include "messageStrings.h"
#include "util.h"
#include "common_functions.h"
#include "createprop_methods.h"
#include "libfsmgt.h"

#define	COMMAND "Command"
/*
 * Private method declarations
 */
static CCIMInstanceList* create_shareEntry_inst_and_update_list(
	CCIMObjectPath *nfsShare, CCIMInstanceList *shareEntInstList);
static CCIMInstanceList* get_associated_nfsShare_instList(
				CCIMObjectPath *sharePersistOP);
static CCIMInstanceList* get_associated_sharePersist_instList(
				CCIMObjectPath *nfsShareOP);
static CCIMObjectPathList* get_associated_sharePersist_OPList(
				CCIMObjectPath *nfsShareOP, int *errp);
static CCIMObjectPath* get_Solaris_NFSShare_OP(char *nameKey);
static CCIMInstance* get_Solaris_PersistentShare_Inst(char *path,
				char *command);

/*
 * Public methods
 */

/*
 * Instance provider methods
 */

/*
 * Method: cp_createInstance_Solaris_NFSShareEntry
 *
 * Description: This method is not supported.  It is not supported because in
 * order for a Solaris_NFSShareEntry association to exist a corresponding
 * Solaris_NFSShare and Solaris_PersistentShare must exist.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - An object path containing the name of
 *	the class of which to create an instance of.
 *      - CCIMInstance *pInst - Not used.
 *
 * Return Value:
 *	- Always returns NULL because the method is not supported.
 */
/* ARGSUSED */
CCIMObjectPath *
cp_createInstance_Solaris_NFSShareEntry(CCIMObjectPath *pOP,
	CCIMInstance *pInst) {

	int	err = 0;

	util_handleError("SOLARIS_NFSSHAREENT::CREATE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMObjectPath *)NULL);
} /* cp_createInstance_Solaris_NFSShareEntry */

/*
 * Method: cp_deleteInstance_Solaris_NFSShareEntry
 *
 * Description: This method is not supported.  It is not supported because in
 * order for it to be actually deleted the corresponding Solaris_NFSShare or
 * Solaris_PersistentShare would need to be deleted. That action is not
 * for this provider.
 *
 * Parameters:
 *      - CCIMObjectPath *pOP - An object path containing the
 *      information about the class of which to delete the instance of.
 *
 * Return Value:
 *      - Always returns cim_false because the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_NFSShareEntry(CCIMObjectPath *pOP) {
	int	err = 0;

	util_handleError("SOLARIS_NFSSHAREENT::DELETE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_deleteInstance_Solaris_NFSShareEntry */

/*
 * Method: cp_enumInstances_Solaris_NFSShareEntry
 *
 * Description: Enumerates the instances of Solaris_NFSShareEntry on a host.
 * An instance of Solaris_NFSShareEntry is an association that links a share to
 * it's persistent share entry.
 *
 * Parameters:
 *      - CCIMObjectPath *pOP - An object path containing the name of
 *      the class of which to enumerate the instances of.
 *
 * Return Value:
 *      - A pointer to a list of Solaris_NFSShareEntry instances.
 *      - NULL if an error occurred or if there are no instances of
 *      Solaris_NFSShareEntry on the host.  In the case of an error, the error
 *      will be logged.
 */

CCIMInstanceList *
cp_enumInstances_Solaris_NFSShareEntry(CCIMObjectPath *pOP) {
	CCIMInstanceList	*shareEntryInstList;
	CCIMObjectPathList	*nfsShareOPList;
	CCIMObjectPathList	*currentShareOP;
	CCIMObjectPath		*nfsShareOP;
	CCIMException		*ex;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::ENUM_INSTANCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOP = cim_createEmptyObjectPath(SOLARIS_NFSSHARE);
	if (nfsShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex,
			&err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOPList = cimom_enumerateInstanceNames(nfsShareOP, cim_false);

	/*
	 * A NULL return value means error, an empty list does not.
	 */
	if (nfsShareOPList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::ENUM_INSTANCES",
			CIM_ERR_FAILED, CIMOM_ENUM_INSTNAMES_FAILURE, ex, &err);
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMInstanceList *)NULL);
	}

	cim_freeObjectPath(nfsShareOP);

	if (nfsShareOPList->mDataObject == NULL) {
		cim_freeObjectPathList(nfsShareOPList);
		return ((CCIMInstanceList *)NULL);
	}

	shareEntryInstList = cim_createInstanceList();
	if (shareEntryInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		cim_freeObjectPathList(nfsShareOPList);
		return ((CCIMInstanceList *)NULL);
	}

	for (currentShareOP = nfsShareOPList; currentShareOP != NULL;
		currentShareOP = currentShareOP->mNext) {

		shareEntryInstList = create_shareEntry_inst_and_update_list(
			currentShareOP->mDataObject, shareEntryInstList);
		if (shareEntryInstList == NULL) {
			cim_freeObjectPathList(nfsShareOPList);
			return ((CCIMInstanceList *)NULL);
		}
	}

	cim_freeObjectPathList(nfsShareOPList);
	return (shareEntryInstList);
} /* cp_enumInstances_Solaris_NFSShareEntry */

/*
 * Method: cp_enumInstanceNames_Solaris_NFSShareEntry
 *
 * Description: Enumerates all of the instances of Solaris_NFSShareEntry on the
 * host.
 *
 * Parameters:
 *	- CCIMObjectPath* pOP - An object path containing the name of the
 *	class of which to enumerate instances of.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFSShareEntry object paths.
 *	- NULL if an error occurred or if there are no NFS mounts on the host.
 *	In the case of an error, the error will be logged.
 */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_NFSShareEntry(CCIMObjectPath *pOP) {
	CCIMInstanceList	*instList;
	CCIMObjectPathList	*OPList;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::ENUM_INSTANCENAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFSShareEntry(pOP);
	if (instList == NULL) {
		/*
		 * Either an error occurred or we don't have any
		 * Solaris_NFSShareEntry instances on the host.
		 */
		return ((CCIMObjectPathList *)NULL);
	}

	OPList = cim_createObjectPathList(instList);

	cim_freeInstanceList(instList);
	return (OPList);
} /* cp_enumInstanceNames_Solaris_NFSShareEntry */

/*
 * Method: cp_execQuery_Solaris_NFSShareEntry
 *
 * Description: Queries the Solaris_NFSShareEntry instances on the host to find
 * those that meet the search criteria.
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
 *	- A pointer to a list of Solaris_NFSShareEntry instances that match the
 *	criteria.
 *	- NULL if an error occurred or if there are no Solaris_NFSShareEntry
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
cp_execQuery_Solaris_NFSShareEntry(CCIMObjectPath *pOP, char *selectClause,
	char *nonJoinExp, char *queryExp, char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*shareEntryInstList;
	CCIMException		*ex;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::EXEC_QUERY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	shareEntryInstList = cp_enumInstances_Solaris_NFSShareEntry(pOP);
	if (shareEntryInstList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::EXEC_QUERY",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(shareEntryInstList);
		return ((CCIMInstanceList *)NULL);
	}

	shareEntryInstList = cim_prependInstance(shareEntryInstList,
		emptyInst);
	if (shareEntryInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::EXEC_QUERY",
			CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (shareEntryInstList);
} /* cp_execQuery_Solaris_NFSShareEntry */

/*
 * Method: cp_getInstance_Solaris_NFSShareEntry
 *
 * Description: Gets the instance corresponding to the Solaris_NFSShareEntry
 * object path passed in.
 *
 * Parameters:
 *      - CCIMObjectPath* pOP - An object path containing all the keys of
 *      the instance that is supposed to be returned.
 *
 * Returns:
 *	- A pointer to the Solaris_NFSShareEntry instance corresponding to the
 *	object path parameter.
 *	- NULL if an error occurred or if the instance doesn't exist.  In the
 *	case of an error, the error will be logged.
 */
CCIMInstance *
cp_getInstance_Solaris_NFSShareEntry(CCIMObjectPath *pOP) {
	CCIMInstanceList	*instList;
	CCIMInstance		*inst;
	CCIMObjectPath		*setOP;
	CCIMObjectPath		*elemOP;
	CCIMPropertyList	*shareEntPropList;
	int			err = 0;

	if (pOP == NULL || pOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	/*
	 * Determine if the key values are populated.
	 */
	shareEntPropList = pOP->mKeyProperties;
	setOP = util_getKeyValue(shareEntPropList, shareEntProps[SETTING].type,
		shareEntProps[SETTING].name, &err);
	elemOP = util_getKeyValue(shareEntPropList, shareEntProps[ELEMENT].type,
		shareEntProps[ELEMENT].name, &err);

	if (setOP == NULL || elemOP == NULL ||
		setOP->mKeyProperties == NULL ||
		elemOP->mKeyProperties == NULL) {

		util_handleError("SOLARIS_NFSSHAREENT::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFSShareEntry(pOP);
	if (instList == NULL) {
		/*
		 * Either an error occurred or we simply don't have any
		 * instances of Solaris_NFSShareEntry on the system.  In the
		 * case that an error occurred, it will be handled in
		 * cp_enumInstances_Solaris_NFSShareEntry.
		 */
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, pOP);

	cim_freeInstanceList(instList);
	return (inst);
} /* cp_getInstance_Solaris_NFSShareEntry */

/*
 * Method: cp_setInstance_Solaris_NFSShareEntry
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties a Solaris_NFSShareEntry on the host, the
 * Solaris_NFSShare and Solaris_PersistentShare must most likely be changed.
 * In order to change the associated objects, they need to be changed in those
 * providers and not this one.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of the class
 *	of which to set the instance.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- cim_false is returned every time since the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_NFSShareEntry(CCIMObjectPath *pOP, CCIMInstance *pInst) {
	int	err = 0;

	util_handleError("SOLARIS_NFSSHAREENT::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_NFSShareEntry */

/*
 * Method: cp_setInstanceWithList_Solaris_NFSShareEntry
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties a Solaris_NFSShareEntry on the host, the
 * Solaris_NFSShare and Solaris_PersistentShare must most likely be changed.
 * In order to change the associated objects, they need to be changed in those
 * providers and not this one.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - An object path containing the name of the class
 *	of which to set the instance.
 *	- CCIMInstance *pInst - Not used.
 *
 * Returns:
 *	- cim_false is returned every time since the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_NFSShareEntry(CCIMObjectPath *pOP,
	CCIMInstance *pInst, char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_NFSSHAREENT::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstanceWithList_Solaris_NFSShareEntry */

/*
 * Association provider methods
 */

/*
 * Method: cp_associators_Solaris_NFSShareEntry
 *
 * Description: Returns the instances associated, via the Solaris_NFSShareEntry
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
 *	- A pointer to a list of Solaris_PersistentShare (if pRole ==
 *	Element && pObjectName is a Solaris_NFSShare object path) or
 *	Solaris_NFSShare (if pRole == Setting && pObjectName is a
 *	Solaris_PersistentShare object path) instances which are associated to
 *	the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_NFSShareEntry(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*returnInstList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Determine whether pObjectname is the Element or the Setting of the
	 * association.  Element = Solaris_NFSShare,
	 * Setting = Solaris_PersistentShare.
	 */
	if (strcasecmp(pObjectName->mName, SOLARIS_NFSSHARE) == 0) {
		if (pRole != NULL && (strcasecmp(pRole,
			shareEntProps[ELEMENT].name) != 0)) {

			util_handleError("SOLARIS_NFSSHAREENT::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}

		returnInstList = get_associated_sharePersist_instList(
			pObjectName);
	} else if (strcasecmp(pObjectName->mName, SOLARIS_PERSISTSHARE) == 0) {
		if (pRole != NULL && (strcasecmp(pRole,
			shareEntProps[SETTING].name) != 0)) {

			util_handleError("SOLARIS_NFSSHAREENT::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}

		returnInstList = get_associated_nfsShare_instList(pObjectName);
	} else {
		util_handleError("SOLARIS_NFSSHAREENT::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	return (returnInstList);
} /* cp_associators_Solaris_NFSShareEntry */

/*
 * Method: cp_associatorNames_Solaris_NFSShareEntry
 *
 * Description: Returns the object paths of the instances on the other side of
 * the association which are associated via the Solaris_NFSShareEntry
 * association and having the passed in parameter, pObjectName, as the
 * opposite key.
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
 *	- A pointer to a list of Solaris_PersistentShare (if pRole ==
 *	Element && pObjectName is a Solaris_NFSShare object path) or
 *	Solaris_NFSShare (if pRole == Setting && pObjectName is a
 *	Solaris_PersistentShare object path) object paths which are associated
 *	to the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
CCIMObjectPathList *
cp_associatorNames_Solaris_NFSShareEntry(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::ASSOCIATOR_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_associators_Solaris_NFSShareEntry(pAssocName, pObjectName,
		pResultClass, pRole, pResultRole);
	if (instList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	objPathList = cim_createObjectPathList(instList);

	cim_freeInstanceList(instList);

	return (objPathList);
} /* cp_associatorNames_Solaris_NFSShareEntry */

/*
 * Method: cp_references_Solaris_NFSShareEntry
 *
 * Description: Returns the Solaris_NFSShareEntry instances that have the
 * passed in parameter, pObjectName, as one of it's keys.
 *
 * Parameters:
 *      - CCIMObjectPath *pAssocName - An object path containing information
 *      about the association that the caller is trying to reach.
 *      - CCIMObjectPath *pObjectName - The object path which contains the
 *      information on whose associated objects are to be returned.
 *      - char *pRole - If specified, this is the role of the pObjectName
 *      object path passed in.  If this is not valid, NULL is returned.
 *
 * Returns:
 *      - A pointer to a list of Solaris_NFSShareEntry instances.
 *      - NULL if an error occurred or if there are no Solaris_NFSShareEntry
 *      instances having pObjectName as one of it's keys.
 */
CCIMInstanceList *
cp_references_Solaris_NFSShareEntry(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::REFERENCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Get everything that is related to the pObjectName passed in.
	 */
	objPathList = cp_associatorNames_Solaris_NFSShareEntry(
		pAssocName, pObjectName, NULL, pRole, NULL);
	if (objPathList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Determine whether pObjectname is the Element or the Setting of the
	 * association.  Element = Solaris_NFSShare,
	 * Setting = Solaris_PersistentShare.
	 */

	if (strcasecmp(pObjectName->mName, SOLARIS_NFSSHARE) == 0) {
		instList = create_association_instList(SOLARIS_NFSSHAREENT,
			pObjectName, shareEntProps[ELEMENT].name, objPathList,
			shareEntProps[SETTING].name, &err);
	} else {
		instList = create_association_instList(SOLARIS_NFSSHAREENT,
			pObjectName, shareEntProps[SETTING].name, objPathList,
			shareEntProps[ELEMENT].name, &err);
	}
	cim_freeObjectPathList(objPathList);

	return (instList);
} /* cp_references_Solaris_NFSShareEntry */

/*
 * Method: cp_referenceNames_Solaris_NFSShareEntry
 *
 * Description: Returns the Solaris_NFSShareEntry object paths of the instances
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
 *	- A pointer to a list of Solaris_NFSShareEntry object paths.
 *	- NULL if an error occurred or if there are no Solaris_NFSShareEntry
 *	instances having pObjectName as one of it's keys.
 */
CCIMObjectPathList *
cp_referenceNames_Solaris_NFSShareEntry(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*shareEntryInstList;
	CCIMObjectPathList	*shareEntryOPList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::REFERENCE_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	shareEntryInstList = cp_references_Solaris_NFSShareEntry(pAssocName,
		pObjectName, pRole);

	if (shareEntryInstList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	shareEntryOPList = cim_createObjectPathList(shareEntryInstList);

	cim_freeInstanceList(shareEntryInstList);

	return (shareEntryOPList);
} /* cp_referenceNames_Solaris_NFSShareEntry */

/*
 * Property provider methods
 */

/*
 * Method: cp_getProperty_Solaris_NFSShareEntry
 *
 * Description: Retrieves a certain property from the instance of
 * Solaris_NFSShareEntry on the host that is described by the parameter pOP.
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
cp_getProperty_Solaris_NFSShareEntry(CCIMObjectPath *pOP, cimchar *pPropName) {
	CCIMInstance	*shareEntryInst;
	CCIMProperty	*shareEntryProp;
	int		err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::GET_PROPERTY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	shareEntryInst = cp_getInstance_Solaris_NFSShareEntry(pOP);
	if (shareEntryInst == NULL) {
		return ((CCIMProperty *)NULL);
	}

	shareEntryProp = cim_getProperty(shareEntryInst, pPropName);
	cim_freeInstance(shareEntryInst);

	return (shareEntryProp);
} /* cp_getProperty_Solaris_NFSShareEntry */

/*
 * Method: cp_setProperty_Solaris_NFSShareEntry
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties a Solaris_NFSShareEntry on the host, the
 * Solaris_NFSShare and Solaris_PersistentShare must most likely be changed.
 * In order to change the associated objects, they need to be changed in those
 * providers and not this one.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - Not used.
 *	- CCIMProperty *pProp - Not used.
 *
 * Returns:
 *	- cim_false is returned every time since the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_NFSShareEntry(CCIMObjectPath *pOP, CCIMProperty *pProp) {
	int	err = 0;

	util_handleError("SOLARIS_NFSSHAREENT::SET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_NFSShareEntry */

/*
 * Method provider methods
 */

/*
 * Method: cp_invokeMethod_Solaris_NFSShareEntry
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
 * Return Value:
 *	- Always returns null because the method is not supported.
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_NFSShareEntry(CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams) {

	return ((CCIMProperty *)NULL);
} /* cp_invokeMethod_Solaris_NFSShareEntry */

/*
 * Private methods
 */

/*
 * Method: create_shareEntry_inst_and_update_list
 *
 */
static CCIMInstanceList *
create_shareEntry_inst_and_update_list(CCIMObjectPath *nfsShareOP,
	CCIMInstanceList *shareEntInstList) {

	CCIMObjectPathList	*sharePersistOPList;
	CCIMObjectPathList	*currentPersistShareOP;
	CCIMInstance		*shareEntryInst;
	CCIMException		*ex;
	int			err = 0;

	shareEntryInst = cim_createInstance(SOLARIS_NFSSHAREENT);
	if (shareEntryInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex,
			&err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Retrieve all of the Solaris_PersistentShare object paths
	 * associated with the current Solaris_NFSShare object path.
	 *
	 * NOTE: Although it is wrong, and we can't control it since
	 * /etc/dfs/dfstab is a editable file, there may be multiple
	 * dfstab entries for one nfs share.
	 */
	sharePersistOPList = get_associated_sharePersist_OPList(nfsShareOP,
		&err);
	if (sharePersistOPList == NULL) {
		if (err != 0) {
			cim_freeInstance(shareEntryInst);
			return ((CCIMInstanceList *)NULL);
		}
		cim_freeInstance(shareEntryInst);
		return (shareEntInstList);
	}

	for (currentPersistShareOP = sharePersistOPList;
		currentPersistShareOP != NULL;
		currentPersistShareOP = currentPersistShareOP->mNext) {
		/*
		 * Add the properties to the Solaris_NFSShareEntry
		 * instance.
		 */
		if (add_property_to_instance(shareEntProps[SETTING].name,
			shareEntProps[SETTING].type, NULL,
			currentPersistShareOP->mDataObject,
			shareEntProps[SETTING].isKey, shareEntryInst)
			== cim_false) {

			cim_freeObjectPathList(sharePersistOPList);
			return ((CCIMInstanceList *)NULL);
		}

		if (add_property_to_instance(shareEntProps[ELEMENT].name,
			shareEntProps[ELEMENT].type, NULL, nfsShareOP,
			shareEntProps[ELEMENT].isKey, shareEntryInst)
			== cim_false) {

			cim_freeObjectPathList(sharePersistOPList);
			return ((CCIMInstanceList *)NULL);
		}

		shareEntInstList = cim_addInstance(shareEntInstList,
			shareEntryInst);
		if (shareEntInstList == NULL) {
			ex = cim_getLastError();
			util_handleError("SOLARIS_NFSSHAREENT::ENUM_INSTANCES",
				CIM_ERR_FAILED, ADD_INSTANCE_FAILURE,
				ex, &err);
			cim_freeInstance(shareEntryInst);
			return ((CCIMInstanceList *)NULL);
		}
	}

	return (shareEntInstList);
} /* create_shareEntry_inst_and_update_list */

/*
 * Method: get_associated_nfsShare_instList
 *
 * Description: Finds the Solaris_NFSShare instances that are associated to
 * the passed in Solaris_PersistentShare object path.
 *
 * Parameters:
 *	- CCIMObjectPath *sharePersistOP - The Solaris_PersistentShare object
 *	path that is to be used to find the associated Solaris_NFSShare
 *	instances.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFSShare instances that are associated
 *	to the Solaris_PersistentShare object path, sharePersistOP, passed in.
 *	- NULL if an error occurred or if there are no Solaris_NFSShare
 *	instances associated to the Solaris_PersistentShare object path.  In
 *	the case of an error, the error will be logged.
 */
static CCIMInstanceList *
get_associated_nfsShare_instList(CCIMObjectPath *sharePersistOP) {
	CCIMInstanceList	*nfsShareInstList;
	CCIMInstance		*nfsShareInst;
	CCIMObjectPath		*nfsShareOP;
	CCIMException		*ex;
	char			*settingId;
	int			err = 0;

	settingId = util_getKeyValue(sharePersistOP->mKeyProperties, string,
		SETTING_ID, &err);
	if (settingId == NULL || err != 0) {
		util_handleError(
			"SOLARIS_NFSSHAREENT::GET_ASSOC_SHARE_INSTLIST",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareInstList = cim_createInstanceList();
	if (nfsShareInstList == NULL) {
		ex = cim_getLastError();
		util_handleError(
			"SOLARIS_NFSSHAREENT::GET_ASSOC_SHARE_INSTLIST",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOP = get_Solaris_NFSShare_OP(settingId);
	if (nfsShareOP == NULL) {
		/*
		 * An error occurred in get_Solaris_NFSShare_OP and was
		 * handled there.
		 */
		cim_freeInstanceList(nfsShareInstList);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareInst = cimom_getInstance(nfsShareOP, cim_false, cim_false,
		cim_false, cim_false, NULL, 0);

	cim_freeObjectPath(nfsShareOP);
	/*
	 * A NULL return value indicates an error, an empty instance does not.
	 */
	if (nfsShareInst == NULL) {
		ex = cim_getLastError();
		util_handleError(
			"SOLARIS_NFSSHAREENT::GET_ASSOC_SHARE_INSTLIST",
			CIM_ERR_FAILED, CIMOM_GET_INST_FAILURE, ex, &err);
		cim_freeInstanceList(nfsShareInstList);
		return ((CCIMInstanceList *)NULL);
	}

	if (nfsShareInst->mProperties == NULL) {
		cim_freeInstanceList(nfsShareInstList);
		cim_freeInstance(nfsShareInst);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Work around for cimom bug 4649100.
	 */
	if (!set_share_keyProperties_to_true(nfsShareInst)) {
		/*
		 * Key values not found
		 */
		cim_logDebug(
			"get_associated_nfsShareSec_instList",
			"No keyProprties found, should return error here");
		cim_freeInstance(nfsShareInst);
		cim_freeInstanceList(nfsShareInstList);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareInstList = cim_addInstance(nfsShareInstList, nfsShareInst);
	if (nfsShareInstList == NULL) {
		ex = cim_getLastError();
		util_handleError(
			"SOLARIS_NFSSHAREENT::GET_ASSOC_SHARE_INSTLIST",
			CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(nfsShareInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (nfsShareInstList);
} /* get_associated_nfsShare_instList */

/*
 * Method: get_associated_sharePersist_instList
 *
 * Description:  Finds the Solaris_PersistentShare instances that are
 * associated to the passed in Solaris_NFSShare object path.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsShareOP - The Solaris_NFSShare object path that is
 *	to be used to find the associated Solaris_PersistentShare instances.
 *
 * Returns:
 *	- A pointer to a list of Solaris_PersistentShare instances that are
 *	associated to the Solaris_NFSShare object path, nfsShareOP, passed in.
 *	NOTE: An instance list is returned rather than a single instance
 *	because it is possible (although unlikely) to have multiple
 *	/etc/dfs/dfstab entries per share.
 *	- NULL if an error occurred or if there are no Solaris_PersistentShare
 *	instances associated to the Solaris_NFSShare object path.
 */
static CCIMInstanceList *
get_associated_sharePersist_instList(CCIMObjectPath *nfsShareOP) {
	CCIMInstanceList	*sharePersistInstList = NULL;
	CCIMException		*ex;
	fs_dfstab_entry_t	dfstabEnt;
	fs_dfstab_entry_t	tmpDfstabEnt;
	char			*name;
	int			err = 0;

	name = util_getKeyValue(nfsShareOP->mKeyProperties, string, NAME, &err);
	if (name == NULL || err != 0) {
		util_handleError("SOLARIS_NFSSHAREENT::GET_ASSOC_SP_INSTLIST",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	sharePersistInstList = cim_createInstanceList();
	if (sharePersistInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::GET_ASSOC_SP_INSTLIST",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	dfstabEnt = fs_get_DFStab_ents(&err);
	if (dfstabEnt == NULL) {
		/*
		 * Check if an error occurred or if there just weren't any
		 * /etc/dfs/dfstab entries.
		 */
		if (err != 0) {
			util_handleError(
				"SOLARIS_NFSSHAREENT::GET_ASSOC_SP_INSTLIST",
				CIM_ERR_FAILED, FS_GET_DFSTAB_ENT_FAILURE,
				NULL, &err);
			cim_freeInstanceList(sharePersistInstList);
			return ((CCIMInstanceList *)NULL);
		}

		return ((CCIMInstanceList *)NULL);
	}

	for (tmpDfstabEnt = dfstabEnt; tmpDfstabEnt != NULL;
		tmpDfstabEnt = fs_get_DFStab_ent_Next(tmpDfstabEnt)) {
		char    *path;
		char	*fstype;
		char	*command;

		err = 0;
		path = fs_get_DFStab_ent_Path(tmpDfstabEnt);
		fstype = fs_get_DFStab_ent_Fstype(tmpDfstabEnt);
		command = fs_get_Dfstab_share_cmd(tmpDfstabEnt, &err);

		/*
		 * Compare the dfstab entry to the nfs share.  Do this by first
		 * checking if the fstype is "nfs" and second by checking
		 * if the path is the same.
		 */
		if ((strcasecmp(fstype, NFS) == 0) &&
			(strcmp(path, name) == 0)) {

			CCIMInstance	*sharePersistInst;

			/*
			 * We can't just call Solaris_PersistentShare's
			 * cp_getInstance method because there is a chance that
			 * multiple dfstab entries having the same path.  If
			 * this is the case, that method will return null and
			 * some sort of "key not unique" error.
			 */
			sharePersistInst = get_Solaris_PersistentShare_Inst(
				path, command);
			if (sharePersistInst == NULL) {
				/*
				 * An error occurred and it was handled in
				 * get_sharePersist_Inst.
				 */
				fs_free_DFStab_ents(dfstabEnt);
				return ((CCIMInstanceList *)NULL);
			}

			sharePersistInstList = cim_addInstance(
				sharePersistInstList, sharePersistInst);
			if (sharePersistInstList == NULL) {
			    ex = cim_getLastError();
			    util_handleError(
				"SOLARIS_NFSSHAREENT::GET_ASSOC_SP_INSTLIST",
				CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, &err);
			    cim_freeInstance(sharePersistInst);
			    fs_free_DFStab_ents(dfstabEnt);
			    return ((CCIMInstanceList *)NULL);
			}
		}
	}

	fs_free_DFStab_ents(dfstabEnt);
	return (sharePersistInstList);
} /* get_associated_sharePersist_instList */

/*
 * Method: get_associated_sharePersist_OPList
 *
 * Description:  Finds the Solaris_PersistentShare object paths that are
 * associated to the passed in Solaris_NFSShare object path.
 *
 * Parameters:
 *	- CCIMObjectPath *nfsShareOP - The Solaris_NFSShare object path of
 *	of which to retrieve the associated Solaris_PersistentShare object
 *	paths.
 *
 * Returns:
 *	- A pointer to a list of Solaris_PersistentShare object paths that are
 *	associated to the passed in Solaris_NFSShare object path.
 *      - Upon error, NULL is returned and the error is logged.
 *
 * Returns:
 */
static CCIMObjectPathList *
get_associated_sharePersist_OPList(CCIMObjectPath *nfsShareOP, int *errp) {
	CCIMInstanceList	*sharePersistInstList;
	CCIMObjectPathList	*sharePersistOPList;
	CCIMException		*ex;
	int			err = 0;

	sharePersistInstList = get_associated_sharePersist_instList(nfsShareOP);
	if (sharePersistInstList == NULL) {
		/*
		 * An error occurred in get_associated_sharePersist_InstList
		 * and was handled in that function.
		 */
		*errp = -1;
		return ((CCIMObjectPathList *)NULL);
	}

	sharePersistOPList = cim_createObjectPathList(sharePersistInstList);
	if (sharePersistOPList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::GET_ASSOC_SP_OPLIST",
			CIM_ERR_FAILED, CREATE_OBJECT_LIST_FAILURE, ex, &err);
		cim_freeInstanceList(sharePersistInstList);
		*errp = -1;
		return ((CCIMObjectPathList *)NULL);
	}

	cim_freeInstanceList(sharePersistInstList);
	return (sharePersistOPList);
} /* get_associated_sharePersist_OPList */

/*
 * Method: get_Solaris_NFSShare_OP
 *
 * Description:
 *
 * Parameters:
 *
 * Returns:
 */
static CCIMObjectPath *
get_Solaris_NFSShare_OP(char *nameKey) {
	CCIMObjectPath		*nfsShareOP;
	CCIMPropertyList	*nfsShareKeyPropList;
	CCIMException		*ex;
	char			*sysName;
	int			err = 0;

	nfsShareOP = cim_createEmptyObjectPath(SOLARIS_NFSSHARE);
	if (nfsShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::GET_NFSSHARE_OP",
			CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex,
			&err);
		return ((CCIMObjectPath *)NULL);
	}

	sysName = (cimchar *)sys_get_hostname(&err);
	if (sysName == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::GET_NFSSHARE_OP",
			CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL, &err);
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMObjectPath *)NULL);
	}

	/*
	 * Create the property list which to add all the key properties to and
	 * which will be added to the object path.
	 */
	nfsShareKeyPropList = cim_createPropertyList();
	if (nfsShareKeyPropList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::GET_NFSSHARE_OP",
			CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE, ex, &err);
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMObjectPath *)NULL);
	}

	/*
	 * add_property_to_list parameters are as follows:
	 * 1.) property name (cimchar *),
	 * 2.) property type (CIMType),
	 * 3.) property value (cimchar *),
	 * 4.) property object path for reference properties (CCIMObjectPath *),
	 * 5.) is property a key? (CIMBool),
	 * 6.) property list to add the property to (CCIMPropertyList *).
	 */
	nfsShareKeyPropList = add_property_to_list(NAME, string, nameKey,
		NULL, cim_true, nfsShareKeyPropList);
	if (nfsShareKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareKeyPropList = add_property_to_list(CREATION_CLASS, string,
		SOLARIS_NFSSHARE, NULL, cim_true, nfsShareKeyPropList);
	if (nfsShareKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareKeyPropList = add_property_to_list(SYS_CREATION_CLASS, string,
		COMPUTER_SYSTEM, NULL, cim_true, nfsShareKeyPropList);
	if (nfsShareKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareKeyPropList = add_property_to_list(SYSTEM, string, sysName,
		NULL, cim_true, nfsShareKeyPropList);
	if (nfsShareKeyPropList == NULL) {
		free(sysName);
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMObjectPath *)NULL);
	}
	free(sysName);

	nfsShareOP = cim_addPropertyListToObjectPath(nfsShareOP,
		nfsShareKeyPropList);
	if (nfsShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::GET_NFSSHARE_OP",
			CIM_ERR_FAILED, ADD_PROP_TO_OBJPATH_FAILURE, ex, &err);
		cim_freePropertyList(nfsShareKeyPropList);
		return ((CCIMObjectPath *)NULL);
	}

	return (nfsShareOP);
} /* get_Solaris_NFSShare_OP */

/*
 * Method: get_Solaris_PersistentShare_Inst
 *
 * Description: Creates an instance of the Solaris_PersistentShare class.
 *
 * Parameters:
 *	- char *path - The value to be used for the SettingID property.
 *	- char *command - The value to be used for the Command property.
 *
 * Returns:
 *	- A pointer to a Solaris_PersistentShare instance.
 *	- Upon error, NULL is returned and the error is logged.
 */
static CCIMInstance *
get_Solaris_PersistentShare_Inst(char *path, char *command) {
	CCIMInstance	*sharePersistInst;
	CCIMException	*ex;
	cimchar		*sysName;
	int		err = 0;

	sysName = (cimchar *)sys_get_hostname(&err);
	if (sysName == NULL) {
		util_handleError("SOLARIS_NFSSHAREENT::GET_SHAREPERSIST_INST",
			CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	sharePersistInst = cim_createInstance(SOLARIS_PERSISTSHARE);
	if (sharePersistInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHAREENT::GET_SHAREPERSIST_INST",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return ((CCIMInstance *)NULL);
	}

	/*
	 * add_property_to_instance parameters are as follows:
	 * 1.) property name (cimchar *),
	 * 2.) property type (CIMType),
	 * 3.) property value (cimchar *),
	 * 4.) property object path for reference properties (CCIMObjectPath *),
	 * 5.) is property a key? (CIMBool),
	 * 6.) instance to add the property to (CCIMInstance *).
	 */
	if (add_property_to_instance(CREATION_CLASS, string,
		SOLARIS_PERSISTSHARE, NULL, cim_true, sharePersistInst)
		== cim_false) {

		cim_freeInstance(sharePersistInst);
		return ((CCIMInstance *)NULL);
	}

	if (add_property_to_instance(SYS_CREATION_CLASS, string,
		COMPUTER_SYSTEM, NULL, cim_true, sharePersistInst)
		== cim_false) {

		cim_freeInstance(sharePersistInst);
		return ((CCIMInstance *)NULL);
	}

	if (add_property_to_instance(SETTING_ID, string, path,
		NULL, cim_true, sharePersistInst) == cim_false) {

		cim_freeInstance(sharePersistInst);
		return ((CCIMInstance *)NULL);
	}

	if (add_property_to_instance(SYSTEM, string, sysName,
		NULL, cim_true, sharePersistInst) == cim_false) {

		free(sysName);
		cim_freeInstance(sharePersistInst);
		return ((CCIMInstance *)NULL);
	}
	free(sysName);

	if (add_property_to_instance(COMMAND, string, command,
		NULL, cim_false, sharePersistInst) == cim_false) {

		cim_freeInstance(sharePersistInst);
		return ((CCIMInstance *)NULL);
	}

	return (sharePersistInst);
} /* get_Solaris_PersistentShare_Inst */
