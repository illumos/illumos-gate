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

#include <errno.h>
#include "Solaris_NFSShareSecurityModes.h"
#include "nfs_keys.h"
#include "nfs_providers_msgstrings.h"
#include "nfs_provider_names.h"
#include "messageStrings.h"
#include "util.h"
#include "common_functions.h"
#include "createprop_methods.h"
#include "libfsmgt.h"


/*
 * Private method declarations
 */

static CCIMInstanceList		*get_associated_nfsShare_instList(
				    CCIMObjectPath *nfsShareOP);
static CCIMInstanceList		*get_associated_nfsShareSec_instList(
				    CCIMObjectPath *nfsShareSecOP);
static CCIMObjectPathList	*get_associated_nfsShareSec_OPList(
				    CCIMObjectPath *nfsShareSecOP, int *err);
static CCIMObjectPath		*get_Solaris_NFSShare_OP(char *nameKey);
static CCIMObjectPath		*get_Solaris_NFSShareSec_OP(char *, char *);
static CCIMInstanceList		*update_list_with_secMode_inst(
				    CCIMObjectPath *nfsShareOP,
				    CCIMInstanceList *shareSecModeInstList);

/*
 * Public methods
 */
/*
 * Instance provider methods
 */

/*
 * Method: cp_createInstance_Solaris_NFSShareSecurityModes
 *
 * This method is not supported. In order for a Solaris_NFSShareSecurityModes
 * association to exist a corresponding Solaris_NFSShare and
 * Solaris_NFSShareSecurity must already exist.
 */
/* ARGSUSED */
CCIMObjectPath *
cp_createInstance_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP,
	CCIMInstance *pInst) {

	int	err = 0;

	util_handleError("SOLARIS_NFSSHARESECMODES::CREATE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return ((CCIMObjectPath *)NULL);
} /* cp_createInstance_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_deleteInstance_Solaris_NFSShareSecurityModes
 *
 * This method is not supported. In order for a Solaris_NFSShareSecurityModes
 * association to be deleted a corresponding Solaris_NFSShare and
 * Solaris_NFSShareSecurity must be deleted. The Solaris_NFSShare and
 * Solaris_NFSShareSecurity should only be deleted through those providers.
 */
/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP) {
	int	err = 0;

	util_handleError("SOLARIS_NFSSHARESECMODES::DELETE_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_deleteInstance_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_enumInstances_Solaris_NFSShareSecurityModes
 *
 * Description: Enumerates the instances of Solaris_NFSShareSecurityModes
 * on a host. An instance of Solaris_NFSShareSecurityModes is an
 * association that links a share to it's share security entry.
 *
 * Parameters:
 *      - CCIMObjectPath *pOP - An object path containing the name of
 *      the class of which to enumerate the instances of.
 *
 * Return Value:
 *      - A pointer to a list of Solaris_NFSShareSecurityModes instances.
 *      - NULL if an error occurred or if there are no instances of
 *      Solaris_NFSShareSecurityModes on the host.  In the case of an
 *      error, the error will be logged.
 */

CCIMInstanceList *
cp_enumInstances_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP) {
	CCIMInstanceList	*shareSecModeInstList;
	CCIMObjectPathList	*nfsShareOPList;
	CCIMObjectPathList	*tmpOPList;
	CCIMObjectPath		*nfsShareOP;
	CCIMException		*ex;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::ENUM_INSTANCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOP = cim_createEmptyObjectPath(SOLARIS_NFSSHARE);
	if (nfsShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECMODES::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex,
			&err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOPList = cimom_enumerateInstanceNames(nfsShareOP, cim_false);
	if (nfsShareOPList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECMODES::ENUM_INSTANCES",
			CIM_ERR_FAILED, CIMOM_ENUM_INSTNAMES_FAILURE, ex, &err);
		cim_freeObjectPath(nfsShareOP);
		return ((CCIMInstanceList *)NULL);
	}

	cim_freeObjectPath(nfsShareOP);


	if (nfsShareOPList->mDataObject == NULL) {
		cim_freeObjectPathList(nfsShareOPList);
		return ((CCIMInstanceList *)NULL);
	}

	shareSecModeInstList = cim_createInstanceList();
	if (shareSecModeInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECMODES::ENUM_INSTANCES",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		cim_freeObjectPathList(nfsShareOPList);
		return ((CCIMInstanceList *)NULL);
	}


	for (tmpOPList = nfsShareOPList; tmpOPList != NULL;
	    tmpOPList = tmpOPList->mNext) {
		shareSecModeInstList = update_list_with_secMode_inst(
		    tmpOPList->mDataObject, shareSecModeInstList);
		if (shareSecModeInstList == NULL) {
			cim_freeObjectPathList(nfsShareOPList);
			return ((CCIMInstanceList *)NULL);
		}
	}
	cim_freeObjectPathList(nfsShareOPList);
	return (shareSecModeInstList);
} /* cp_enumInstances_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_enumInstanceNames_Solaris_NFSShareSecurityModes
 *
 * Description: Enumerates all of the instances of
 * Solaris_NFSShareSecurityModes on the host.
 *
 * Parameters:
 *      - CCIMObjectPath* pOP - An object path containing the name of the
 *      class of which to enumerate instances of.
 *
 * Returns:
 *      - A pointer to a list of Solaris_NFSShareSecurityModes object paths.
 *      - NULL if an error occurred or if there are no NFS mounts on the host.
 *      In the case of an error, the error will be logged.
 */

CCIMObjectPathList *
cp_enumInstanceNames_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP) {
	CCIMInstanceList	*instList;
	CCIMObjectPathList	*OPList;
	CCIMException		*ex;
	int			err = 0;

	/*
	 * First check if pOP is null.
	 */
	if (pOP == NULL) {
		util_handleError(
		    "SOLARIS_NFSSHARESECMODES::ENUM_INSTANCENAMES",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFSShareSecurityModes(pOP);
	if (instList == NULL) {
		/*
		 * Either an error occurred or we don't have any
		 * Solaris_NFSShareSecurityModes instances on the host.
		 */
		return ((CCIMObjectPathList *)NULL);
	}

	OPList = cim_createObjectPathList(instList);
	if (OPList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHARESECMODES::ENUM_INSTANCENAMES",
		    CIM_ERR_FAILED, CREATE_OBJECT_LIST_FAILURE, ex, &err);
	}

	cim_freeInstanceList(instList);
	return (OPList);
} /* cp_enumInstanceNames_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_execQuery_Solaris_NFSShareSecurityModes
 *
 * Description: Queries the Solaris_NFSShareSecurityModes instances on the
 * host to find those that meet the search criteria.
 *
 * Parameters:
 *      - CCIMObjectPath *pOP - An object path containing the name of
 *      the class of which to query.
 *      - char *selectClause - Not used.
 *      - char *nonJoinExp - Not used.
 *      - char *queryExp - Not used.
 *      - char *queryLang - Not used.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFSShareSecurityModes instances
 *	that match the search criteria.
 *	- NULL if an error occurred or if there are no
 *      Solaris_NFSShareSecurityModes instances matching the search criteria.
 *	in case of an error, the error will be logged.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_execQuery_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP,
    char *selectClause, char *nonJoinExp, char *queryExp,
    char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*shareSecModeInstList;
	CCIMException		*ex;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::EXEC_QUERY",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	shareSecModeInstList =
	    cp_enumInstances_Solaris_NFSShareSecurityModes(pOP);
	if (shareSecModeInstList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECMODES::EXEC_QUERY",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(shareSecModeInstList);
		return ((CCIMInstanceList *)NULL);
	}

	shareSecModeInstList = cim_prependInstance(shareSecModeInstList,
		emptyInst);
	if (shareSecModeInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECMODES::EXEC_QUERY",
			CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (shareSecModeInstList);
} /* cp_execQuery_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_getInstance_Solaris_NFSShareSecurityModes
 *
 * Description: Gets the instance corresponding to the
 * Solaris_NFSShareSecurityModes object path passed in.
 *
 * Parameters:
 *      - CCIMObjectPath* pOP - An object path containing all the keys of
 *      the instance that is supposed to be returned.
 *
 * Returns:
 *	- A pointer to the Solaris_NFSShareSecurityModes instance corresponding
 *	to the object path parameter.
 *	- NULL if an error occurred or if the instance doesn't exist. In the
 *	case of an error the error is logged.
 */
CCIMInstance *
cp_getInstance_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP) {
	CCIMInstanceList	*instList;
	CCIMInstance		*inst;
	CCIMObjectPath		*settingOP;
	CCIMObjectPath		*elementOP;
	CCIMPropertyList	*shareSecModesPropList;
	int			err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	/*
	 * Make sure the key values passed in are populated.
	 */
	shareSecModesPropList = pOP->mKeyProperties;
	settingOP = util_getKeyValue(shareSecModesPropList,
	    shareSecModeProps[SETTING].type, shareSecModeProps[SETTING].name,
	    &err);
	elementOP = util_getKeyValue(shareSecModesPropList,
	    shareSecModeProps[ELEMENT].type, shareSecModeProps[ELEMENT].name,
	    &err);

	if (settingOP == NULL || elementOP == NULL ||
	    settingOP->mKeyProperties == NULL ||
	    elementOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::GET_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFSShareSecurityModes(pOP);
	if (instList == NULL) {
		/*
		 * Either an error occurred or we simply don't have any
		 * instances of Solaris_NFSShareSecurityModes on the system.
		 * In the case that an error occurred, it will be handled in
		 * cp_enumInstances_Solaris_NFSShareSecurityModes.
		 */
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, pOP);

	cim_freeInstanceList(instList);
	return (inst);
} /* cp_getInstance_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_setInstance_Solaris_NFSShareSecurityModes
 *
 * Not Supported: Inorder to change the properties of a
 * Solaris_NFSShareSecurityModes instance on the host the Solaris_NFSShare and
 * Solaris_NFSShareSecurity instances would have to be changed. These changes
 * must be done in the providers for Solaris_NFSShare and
 * Solaris_NFSShareSecurity.
 */
/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP,
    CCIMInstance *pInst, char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_NFSSHAREDEFSECMODES::SET_INSTANCE",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_NFSShareDefSecurityModes */

/*
 * Method: cp_setInstanceWithList_Solaris_NFSShareSecurityModes
 *
 * Not Supported: Inorder to change the properties of a
 * Solaris_NFSShareSecurityModes instance on the host the Solaris_NFSShare and
 * Solaris_NFSShareSecurity instances would have to be changed. These changes
 * must be done in the providers for Solaris_NFSShare and
 * Solaris_NFSShareSecurity.
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP,
	CCIMInstance *pInst, char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_NFSSHARESECMODES::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstanceWithList_Solaris_NFSShareSecurityModes */

/*
 * Association provider methods
 */
/*
 * Method: cp_associators_Solaris_NFSShareSecurityModes
 *
 * Description: Returns the instances associated with the pObjectName
 * parameter via the Solaris_NFSShareSecurityModes association.
 *
 * Parameters:
 *      - CCIMObjectPath *pAssocName - An object path containing the name of
 *      the association that the caller is trying to reach.
 *      - CCIMObjectPath *pObjectName - The object path containing information
 *      (Class Name, Key Properties) about the object whose associated objects
 *      are to be returned.
 *      - char *pResultClass - If specified, only return instances that are of
 *      this class type.
 *      - char *pRole - If specified, this is the role of the pObjectName
 *      object path passed in.  If this is not valid, NULL is returned.
 *      - char *pResultRole - If specified, only return instances that are
 *      playing this role in the association.
 *
 * Returns:
 *      - A pointer to a list of Solaris_NFSShareSecurity (if pRole ==
 *      Element && pObjectName is a Solaris_NFSShare object path) or
 *      Solaris_NFSShare (if pRole == Setting && pObjectName is a
 *      Solaris_NFSShareSecurity object path) instances which are associated to
 *      the pObjectName parameter.
 *      - NULL if an error occurred or if there are no instances associated to
 *      the pObjectName passed in.  In the case of an error, the error will be
 *      logged.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_NFSShareSecurityModes(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*returnInstList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Determine whether pObjectname is the Element or the Setting of the
	 * association.  Element = Solaris_NFSShare,
	 * Setting = Solaris_NFSShareSecurity.
	 */
	if ((strcasecmp(pObjectName->mName, SOLARIS_NFSSHARE) == 0)) {
		if (pRole != NULL && (strcasecmp(pRole,
		    shareSecModeProps[ELEMENT].name) != 0)) {
			util_handleError(
			    "SOLARIS_NFSSHARESECMODES::ASSOCIATORS",
			    CIM_ERR_INVALID_PARAMETER, NULL, NULL,
			    &err);
			return ((CCIMInstanceList *)NULL);
		}
		returnInstList = get_associated_nfsShareSec_instList(
			pObjectName);
	} else if (strcasecmp(pObjectName->mName,
	    SOLARIS_NFSSHARESECURITY) == 0) {
		if (pRole != NULL && (strcasecmp(pRole,
		    shareSecModeProps[SETTING].name) != 0)) {
			util_handleError(
			    "SOLARIS_NFSSHARESECMODES::ASSOCIATORS",
			    CIM_ERR_INVALID_PARAMETER, NULL, NULL,
			    &err);
			return ((CCIMInstanceList *)NULL);
		}
		returnInstList = get_associated_nfsShare_instList(pObjectName);
	} else {
		util_handleError("SOLARIS_NFSSHARESECMODES::ASSOCIATORS",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	return (returnInstList);
} /* cp_associators_Solaris_NFSShareSecurityModes */

/*
 * Method:cp_associatorNames_Solaris_NFSShareSecurityModes
 *
 * Description: Returns the object paths of the instances on the other side
 * of the association. These are associated via the
 * Solaris_NFSShareSecurityModes association and have the opposite key
 * passed in as the parameter(pObjectName).
 *
 * Parameters:
 *      - CCIMObjectPath *pAssocName - An object path containing information
 *      about the association that the caller is trying to reach.
 *      - CCIMObjectPath *pObjectName - The object path which contains the
 *      information on whose associated objects are to be returned.
 *      - char *pResultClass - If specified, only return instances that are of
 *      this class type.
 *      - char *pRole - If specified, this is the role of the pObjectName
 *      object path passed in.  If this is not valid, NULL is returned.
 *      - char *pResultRole - If specified, only return instances that are
 *      playing this role in the association.
 *
 * Returns:
 *      - A pointer to a list of Solaris_NFSShareSecurity (if Role ==
 *      Element and pObjectName is a Solaris_NFSShare object path) or
 *      Solaris_NFSShare (if Role == Setting and pObjectName is a
 *      Solaris_NFSShareSecurity object path) object paths which are
 *      associated to the pObjectName parameter.
 *      - NULL  if an error occurred or if there are no instances associated to
 *      the pObjectName passed in.  In the case of an error, the error will be
 *      logged.
 */
CCIMObjectPathList *
cp_associatorNames_Solaris_NFSShareSecurityModes(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList = NULL;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::ASSOCIATOR_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
	} else {
		instList =
		    cp_associators_Solaris_NFSShareSecurityModes(pAssocName,
		    pObjectName, pResultClass, pRole, pResultRole);
		if (instList != NULL) {
			objPathList = cim_createObjectPathList(instList);
			cim_freeInstanceList(instList);
		}
	}
	return (objPathList);
} /* cp_associatorNames_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_references_Solaris_NFSShareSecurityModes
 *
 * Description: Returns the Solaris_NFSShareSecurityModes instances that have
 * the passed in parameter, pObjectName, as one of it's keys.
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
 *      - A pointer to a list of Solaris_NFSShareSecurityModes instances.
 *      - NULL if an error occurred or if there are no
 *      Solaris_NFSShareSecurityModes instances having pObjectName as one of
 *      it's keys.
 */
CCIMInstanceList *
cp_references_Solaris_NFSShareSecurityModes(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::REFERENCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}


	/*
	 * Get everything that is related to the pObjectName passed in.
	 */
	objPathList = cp_associatorNames_Solaris_NFSShareSecurityModes(
		pAssocName, pObjectName, NULL, pRole, NULL);
	if (objPathList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Determine whether pObjectname is the Element or the Setting of the
	 * association.  Element = Solaris_NFSShare,
	 * Setting = Solaris_NFSShareSecurity.
	 */
	if ((strcasecmp(pObjectName->mName, SOLARIS_NFSSHARE) == 0)) {
		instList = create_association_instList(
		    SOLARIS_NFSSHARESECMODES, pObjectName,
		    shareSecModeProps[ELEMENT].name, objPathList,
		    shareSecModeProps[SETTING].name, &err);
	} else {
		instList =
		    create_association_instList(SOLARIS_NFSSHARESECMODES,
		    pObjectName, shareSecModeProps[SETTING].name,
		    objPathList, shareSecModeProps[ELEMENT].name, &err);
	}
	cim_freeObjectPathList(objPathList);

	return (instList);
} /* cp_references_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_referenceNames_Solaris_NFSShareSecurityModes
 *
 * Description: Returns the Solaris_NFSShareSecurityModes object paths for
 * the instances that have the passed in parameter (pObjectName, as one of
 * it's keys.
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
 *      - A pointer to a list of Solaris_NFSShareSecurityModes object paths.
 *      - NULL if there was an error or if there are no
 *      Solaris_NFSShareSecurityModes instances having pObjectName as one of
 *      it's keys.
 */
CCIMObjectPathList *
cp_referenceNames_Solaris_NFSShareSecurityModes(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*shareSecModeInstList;
	CCIMObjectPathList	*shareSecModeOPList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::REFERENCE_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	shareSecModeInstList =
	    cp_references_Solaris_NFSShareSecurityModes(pAssocName,
	    pObjectName, pRole);

	if (shareSecModeInstList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	shareSecModeOPList = cim_createObjectPathList(shareSecModeInstList);

	cim_freeInstanceList(shareSecModeInstList);

	return (shareSecModeOPList);
} /* cp_referenceNames_Solaris_NFSShareSecurityModes */

/*
 * Property provider methods
 */

/*
 * Method: cp_getProperty_Solaris_NFSShareSecurityModes
 *
 * Description: Retrieves the property, described by the parameter pOP, from
 * the instance of Solaris_NFSShareSecurityModes on the host.
 *
 * Parameters:
 *      - CCIMObjectPath *pOP - The object path containing all the
 *      information needed to find the instance in which the property is to
 *      be returned.
 *      - cimchar *pPropName - The name of the property to be found.
 *
 * Returns:
 *      - A pointer to the property corresponding to the name passed in with
 *      pPropName.
 *      - NULL if an error occurred or if the property doesn't exist.  In the
 *      case of an error, the error will be logged.
 */
CCIMProperty *
cp_getProperty_Solaris_NFSShareSecurityModes(CCIMObjectPath *pOP,
	cimchar *pPropName) {

	CCIMInstance	*shareSecModeInst;
	CCIMProperty	*shareSecModeProp;
	int		err = 0;

	if (pOP == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::GET_PROPERTY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	shareSecModeInst = cp_getInstance_Solaris_NFSShareSecurityModes(pOP);
	if (shareSecModeInst == NULL) {
		return ((CCIMProperty *)NULL);
	}

	shareSecModeProp = cim_getProperty(shareSecModeInst, pPropName);
	cim_freeInstance(shareSecModeInst);

	return (shareSecModeProp);
} /* cp_getProperty_Solaris_NFSShareSecurityModes */

/*
 * Method: cp_setProperty_Solaris_NFSShareSecurityModes
 *
 * This method is not supported.  This is not allowed because in
 * order to change the properties a Solaris_NFSShareSecurityModes on
 * the host, the Solaris_NFSShare and Solaris_NFSShareSecurity must
 * be changed. Any changes to Solaris_NFSShare and Solaris_NFSShareSecurity
 * need to be done in those providers.
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_NFSShareSecurityModes(
    CCIMObjectPath *pOP,
    CCIMProperty *pProp) {

	int	err = 0;

	util_handleError("SOLARIS_NFSSHARESECMODES::SET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_NFSShareSecurityModes */

/*
 * Method provider methods
 */

/*
 * Method: cp_invokeMethod_Solaris_NFSShareSecurityModes
 *
 * Description: This method is not supported because the provider doesn't have
 * any methods.
 *
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_NFSShareSecurityModes(
    CCIMObjectPath *pOP,
    cimchar *functionName,
    CCIMPropertyList *inParams,
    CCIMPropertyList *outParams) {
	int	err = 0;

	util_handleError("SOLARIS_NFSSHARESECMODES::INVOKE_METHOD",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return ((CCIMProperty *)NULL);
} /* cp_invokeMethod_Solaris_NFSShareSecurityModes */


/*
 * Private methods
 */

/*
 * Method: get_associated_nfsShare_instList
 *
 * Finds the Solaris_NFSShare instances that are associated to the
 * Solaris_NFSShareSecurity object path that was passed in.
 */
static CCIMInstanceList *
get_associated_nfsShare_instList(CCIMObjectPath *nfsShareSecOP) {
	CCIMInstanceList	*nfsShareInstList;
	CCIMInstance		*nfsShareInst;
	CCIMObjectPath		*nfsShareOP;
	CCIMException		*ex;
	char			*settingID;
	int			err = 0;

	settingID = util_getKeyValue(nfsShareSecOP->mKeyProperties, string,
		SETTING_ID, &err);
	if (settingID == NULL || err != 0) {
		util_handleError(
			"SOLARIS_NFSSHARESECMODES::GET_ASSOC_SHARE_INSTLIST",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareInstList = cim_createInstanceList();
	if (nfsShareInstList == NULL) {
		ex = cim_getLastError();
		util_handleError(
			"SOLARIS_NFSSHARESECMODES::GET_ASSOC_SHARE_INSTLIST",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareOP = get_Solaris_NFSShare_OP(settingID);
	if (nfsShareOP == NULL) {
		/*
		 * An error occurred in get_Solaris_NFSShare_OP and was
		 * handled there.
		 */
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareInst = cimom_getInstance(nfsShareOP, cim_false, cim_false,
	    cim_false, cim_false, NULL, 0);

	cim_freeObjectPath(nfsShareOP);

	if (nfsShareInst == NULL) {
		/*
		 * No instances exist which are associated with the passed in
		 * Solaris_NFSShareSecurity object.
		 */
		cim_freeInstanceList(nfsShareInstList);
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

	if (nfsShareInst->mProperties == NULL) {
		cim_freeInstanceList(nfsShareInstList);
		cim_freeInstance(nfsShareInst);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareInstList = cim_addInstance(nfsShareInstList, nfsShareInst);
	if (nfsShareInstList == NULL) {
		ex = cim_getLastError();
		util_handleError(
			"SOLARIS_NFSSHARESECMODES::GET_ASSOC_SHARE_INSTLIST",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		cim_freeInstance(nfsShareInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (nfsShareInstList);
} /* get_associated_nfsShare_instList */

/*
 * Method: get_associated_nfsShareSec_instList
 *
 * Finds the Solaris_NFSShareSecurity instances that are associated to the
 * Solaris_NFSShare object path that was passed in.
 */
static CCIMInstanceList *
get_associated_nfsShareSec_instList(CCIMObjectPath *nfsShareOP) {
	CCIMObjectPath		*nfsShareSecOP;
	CCIMInstanceList	*nfsShareSecInstList = NULL;
	CCIMException		*ex;
	char			*name;
	int			err = 0;
	fs_sharelist_t  *nfs_sharesec_list, *tmp_sharesec_list;


	name = util_getKeyValue(nfsShareOP->mKeyProperties, string,
	    NAME, &err);
	if (name == NULL || err != 0) {
		util_handleError(
		    "SOLARIS_NFSSHARESECMODES::GET_ASSOC_SP_INSTLIST",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsShareSecInstList = cim_createInstanceList();
	if (nfsShareSecInstList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHARESECMODES::GET_ASSOC_SP_INSTLIST",
		    CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfs_sharesec_list = fs_get_share_list(&err);
	if (nfs_sharesec_list == NULL) {
		/*
		 * Check whether an error was returned or if we simply don't
		 * have any nfs shares on the system. If err is not
		 * equal to 0, an error was encountered.
		 */

		if (err != 0) {
			/*
			 * Determine the error and log it.
			 */
			if (err == ENOMEM || err == EAGAIN) {
				util_handleError(
				    "SOLARIS_NFSSHARESECMODES:" \
				    ":GET_ASSOC_SEC_INSTLIST",
				    CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY,
				    NULL, &err);
				cim_freeInstanceList(nfsShareSecInstList);
				return ((CCIMInstanceList *)NULL);
			} else {

				/*
				 * If any other errors were encountered it
				 * can be handled as a general error.  We may
				 * not know exactly what the error is.
				 */
				util_handleError(
				    "SOLARIS_NFSSHARESECMODES:" \
				    ":GET_ASSOC_SEC_INSTLIST",
				    CIM_ERR_FAILED, strerror(err),
				    NULL, &err);
				cim_freeInstanceList(nfsShareSecInstList);
				return ((CCIMInstanceList *)NULL);
			}
		}
	}


	for (tmp_sharesec_list = nfs_sharesec_list; tmp_sharesec_list != NULL;
	    tmp_sharesec_list = tmp_sharesec_list->next) {
		char	**sec_modes;
		char	*optionValue = NULL;
		int	count = 0;

		err = 0;


		sec_modes = fs_parse_opts_for_sec_modes(
		    tmp_sharesec_list->options, &count, &err);


		if (sec_modes == NULL || count == 0) {
			util_handleError(
			    "SOLARIS_NFSSHARESECMODES::GET_ASSOC_SEC_INSTLIST",
			    CIM_ERR_FAILED,
			    FS_PARSE_OPTS_FOR_SEC_MODES_FAILURE, ex, &err);
			fs_free_share_list(nfs_sharesec_list);
			cim_freeInstanceList(nfsShareSecInstList);
			return ((CCIMInstanceList *)NULL);
		}


		if ((strcasecmp(tmp_sharesec_list->fstype, "nfs") == 0) &&
		    (strcmp(tmp_sharesec_list->path, name) == 0)) {

			CCIMInstance	*nfsShareSecInst;
			int i;

			for (i = 0; i < count; i++) {
				char	tmpString[MAXSIZE];
				(void) strcpy(tmpString, sec_modes[i]);
				optionValue = get_property_from_opt_string(
				    sec_modes[i], "sec=", B_TRUE, B_FALSE);

				if (strcmp(optionValue, "0") == 0) {
					free(optionValue);
					optionValue = strdup("sys");
				}

				nfsShareSecOP =
				    get_Solaris_NFSShareSec_OP(name,
				    optionValue);

				free(optionValue);
				if (nfsShareSecOP == NULL) {
					/*
					 * An error occurred and it was
					 * handled in get_NFSShareSec_OP.
					 */
					fs_free_share_list(nfs_sharesec_list);
					fileutil_free_string_array(sec_modes,
					    count);
					cim_freeInstanceList(
					    nfsShareSecInstList);
					return ((CCIMInstanceList *)NULL);
				}

				nfsShareSecInst =
				    cimom_getInstance(nfsShareSecOP, cim_false,
				    cim_false, cim_false, cim_false, NULL, 0);
				if (nfsShareSecInst == NULL) {
					/*
					 * An error occurred and it was
					 * handled in cimom_getInstance.
					 */
					fs_free_share_list(nfs_sharesec_list);
					fileutil_free_string_array(sec_modes,
					    count);
					cim_freeInstanceList(
					    nfsShareSecInstList);
					return ((CCIMInstanceList *)NULL);
				}

				/*
				 * Work around for cimom bug 4649100.
				 */
				if (!set_shareSec_keyProperties_to_true(
				    nfsShareSecInst)) {
					/*
					 * Key values not found
					 */
					cim_logDebug(
					    "get_associated_nfsShareSec_" \
					    "instList", "No keyProprties " \
					    "found, should return error here");
					cim_freeInstance(nfsShareSecInst);
					cim_freeInstanceList(
					    nfsShareSecInstList);
					return ((CCIMInstanceList *)NULL);
				}

				/*
				 * Add the instance to the instance list.
				 */
				nfsShareSecInstList = cim_addInstance(
					nfsShareSecInstList, nfsShareSecInst);
				if (nfsShareSecInstList == NULL) {
					ex = cim_getLastError();
					util_handleError(
					    "SOLARIS_NFSSHARESECMODES:" \
					    ":GET_ASSOC_SEC_INSTLIST",
					    CIM_ERR_FAILED,
					    ADD_INSTANCE_FAILURE, ex, &err);
					cim_freeInstance(nfsShareSecInst);
					fs_free_share_list(nfs_sharesec_list);
					fileutil_free_string_array(sec_modes,
					    count);
					return ((CCIMInstanceList *)NULL);
				}
			}
		}
		fileutil_free_string_array(sec_modes, count);
	}
	fs_free_share_list(nfs_sharesec_list);
	return (nfsShareSecInstList);
} /* get_associated_nfsShareSec_instList */

/*
 * Method: get_associated_nfsShareSec_OPList
 *
 * Finds the Solaris_NFSShareSecurity object paths that are associated
 * to the Solaris_NFSShare object path that was passed in.
 */
static CCIMObjectPathList *
get_associated_nfsShareSec_OPList(CCIMObjectPath *nfsShareOP, int *errp) {
	CCIMInstanceList	*nfsShareSecInstList;
	CCIMObjectPathList	*nfsShareSecOPList;
	CCIMException		*ex;
	int			err = 0;


	nfsShareSecInstList =
	    get_associated_nfsShareSec_instList(nfsShareOP);
	if (nfsShareSecInstList == NULL) {
		/*
		 * An error occurred in get_associated_nfsShareSec_InstList
		 * and was handled in that function.
		 */
		*errp = -1;
		return ((CCIMObjectPathList *)NULL);
	}

	nfsShareSecOPList = cim_createObjectPathList(nfsShareSecInstList);
	if (nfsShareSecOPList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHARESECMODES::GET_ASSOC_SP_OPLIST",
		    CIM_ERR_FAILED, CREATE_OBJECT_LIST_FAILURE,
		    ex, &err);
		*errp = -1;
	}

	cim_freeInstanceList(nfsShareSecInstList);
	return (nfsShareSecOPList);
} /* get_associated_nfsShareSec_OPList */

/*
 * Method: get_Solaris_NFSShare_OP
 *
 * Gets the Solaris_NFSShare object path based on the passed in name key.
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
		util_handleError("SOLARIS_NFSSHARESECMODES::GET_NFSSHARE_OP",
		    CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex,
		    &err);
		return ((CCIMObjectPath *)NULL);
	}

	sysName = (cimchar *)sys_get_hostname(&err);
	if (sysName == NULL) {
		util_handleError("SOLARIS_NFSSHARESECMODES::GET_NFSSHARE_OP",
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
		util_handleError("SOLARIS_NFSSHARESECMODES::GET_NFSSHARE_OP",
			CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE, ex, &err);
		cim_freeObjectPath(nfsShareOP);
		free(sysName);
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

	nfsShareKeyPropList = add_property_to_list(CREATION_CLASS, string,
	    SOLARIS_NFSSHARE, NULL, cim_true, nfsShareKeyPropList);
	if (nfsShareKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareOP);
		free(sysName);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareKeyPropList = add_property_to_list(NAME, string, nameKey,
	    NULL, cim_true, nfsShareKeyPropList);
	if (nfsShareKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareOP);
		free(sysName);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareKeyPropList = add_property_to_list(SYS_CREATION_CLASS, string,
	    SOLARIS_CS, NULL, cim_true, nfsShareKeyPropList);
	if (nfsShareKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareOP);
		free(sysName);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareKeyPropList = add_property_to_list(SYSTEM, string, sysName,
	    NULL, cim_true, nfsShareKeyPropList);
	if (nfsShareKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareOP);
		free(sysName);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareOP = cim_addPropertyListToObjectPath(nfsShareOP,
		nfsShareKeyPropList);
	if (nfsShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECMODES::GET_NFSSHARE_OP",
			CIM_ERR_FAILED, ADD_PROP_TO_OBJPATH_FAILURE, ex, &err);
		cim_freePropertyList(nfsShareKeyPropList);
		free(sysName);
		return ((CCIMObjectPath *)NULL);
	}

	free(sysName);
	return (nfsShareOP);
} /* get_Solaris_NFSShare_OP */

/*
 * Method: get_Solaris_NFSShareSec_OP
 *
 * Gets the Solaris_NFSShareSecurity object path based on the passed in
 * path and mode keys.
 */
static CCIMObjectPath *
get_Solaris_NFSShareSec_OP(char *path, char *mode) {
	CCIMObjectPath		*nfsShareSecOP;
	CCIMPropertyList	*nfsShareSecKeyPropList;
	CCIMException		*ex;
	int			err = 0;

	cim_logDebug("get_Solaris_NFSShareSec_OP",
	    "Just entering");

	nfsShareSecOP =
		cim_createEmptyObjectPath(SOLARIS_NFSSHARESEC);
	if (nfsShareSecOP == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHAREDEFSECMODES::GET_NFSSHARESEC_OP",
		    CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex, &err);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareSecKeyPropList =
	    cim_createPropertyList();
	if (nfsShareSecKeyPropList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHAREDEFSECMODES::GET_NFSSHARESEC_OP",
		    CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE, ex, &err);
		cim_freeObjectPath(nfsShareSecOP);
		return ((CCIMObjectPath *)NULL);
	}

	/*
	 * add_property_to_list parameters are as follows:
	 * 1.) property settingID (cimchar *),
	 * 2.) property mode (cimchar *)
	 */
	nfsShareSecKeyPropList = add_property_to_list(SETTING_ID, string,
	    path, NULL, cim_true, nfsShareSecKeyPropList);
	if (nfsShareSecKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareSecOP);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareSecKeyPropList = add_property_to_list(MODE, string, mode,
	    NULL, cim_true, nfsShareSecKeyPropList);
	if (nfsShareSecKeyPropList == NULL) {
		cim_freeObjectPath(nfsShareSecOP);
		return ((CCIMObjectPath *)NULL);
	}

	nfsShareSecOP = cim_addPropertyListToObjectPath(
	    nfsShareSecOP, nfsShareSecKeyPropList);
	if (nfsShareSecOP == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHAREDEFSECMODES::GET_NFSSHARESEC_OP",
		    CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, &err);
		cim_freePropertyList(nfsShareSecKeyPropList);
		return ((CCIMObjectPath *)NULL);
	}

	return (nfsShareSecOP);
} /* get_Solaris_NFSShareSec_OP */

/*
 * Method: update_list_with_secMode_inst
 *
 * Adds the Solaris_NFSShareSecurityModes instance described by the passed
 *  in object path to the shareSecModeInstList instance list.
 */
static CCIMInstanceList *
update_list_with_secMode_inst(CCIMObjectPath *nfsShareOP,
    CCIMInstanceList *shareSecModeInstList) {

	CCIMObjectPathList	*nfsShareSecOPList;
	CCIMObjectPathList	*tmpOPList;
	CCIMInstance		*shareSecModeInst;
	CCIMException		*ex;
	int			err = 0;

	/*
	 * Retrieve all of the Solaris_NFSShareSecurity instances
	 * associated with the current Solaris_NFSShare object path.
	 * The get_associate_nfsShareSec_propList function will return
	 * the appropriate reference properties to be used in creating
	 * a Solaris_NFSShareSecurityModes instance.
	 */
	nfsShareSecOPList = get_associated_nfsShareSec_OPList(
		nfsShareOP, &err);
	if (nfsShareSecOPList == NULL) {
		if (err != 0) {
			return ((CCIMInstanceList *)NULL);
		}
		return (shareSecModeInstList);
	}

	for (tmpOPList = nfsShareSecOPList; tmpOPList != NULL;
	    tmpOPList = tmpOPList->mNext) {
		shareSecModeInst = cim_createInstance(SOLARIS_NFSSHARESECMODES);
		if (shareSecModeInst == NULL) {
			ex = cim_getLastError();
			util_handleError(
			    "SOLARIS_NFSSHARESECMODES::ENUM_INSTANCES",
			    CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
			return ((CCIMInstanceList *)NULL);
		}
		/*
		 * Add the properties to the
		 * Solaris_NFSSHareSecurityModes instance.
		 */

		if (add_property_to_instance(shareSecModeProps[SETTING].name,
		    shareSecModeProps[SETTING].type, NULL,
		    tmpOPList->mDataObject, shareSecModeProps[SETTING].isKey,
		    shareSecModeInst) == cim_false) {
			cim_freeObjectPathList(nfsShareSecOPList);
			return ((CCIMInstanceList *)NULL);
		}

		if (add_property_to_instance(shareSecModeProps[ELEMENT].name,
		    shareSecModeProps[ELEMENT].type, NULL,
		    nfsShareOP, shareSecModeProps[ELEMENT].isKey,
		    shareSecModeInst) == cim_false) {
			cim_freeObjectPathList(nfsShareSecOPList);
			return ((CCIMInstanceList *)NULL);
		}

		shareSecModeInstList =
		    cim_addInstance(shareSecModeInstList,
		    shareSecModeInst);
		if (shareSecModeInstList == NULL) {
			ex = cim_getLastError();
			util_handleError(
			    "SOLARIS_NFSSHARESECMODES::ENUM_INSTANCES",
			    CIM_ERR_FAILED, ADD_INSTANCE_FAILURE,
			    ex, &err);
			cim_freeInstance(shareSecModeInst);
			cim_freeObjectPathList(nfsShareSecOPList);
			return ((CCIMInstanceList *)NULL);
		}
	}

	return (shareSecModeInstList);
} /* update_list_with_secMode_inst */
