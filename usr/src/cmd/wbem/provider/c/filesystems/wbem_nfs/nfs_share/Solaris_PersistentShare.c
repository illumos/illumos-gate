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

#include "Solaris_PersistentShare.h"
#include "nfs_keys.h"
#include "nfs_provider_names.h"
#include "nfs_providers_msgstrings.h"
#include "nfsprov_methods.h"
#include "messageStrings.h"
#include "util.h"
#include "libfsmgt.h"
#include "createprop_methods.h"
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>

/*
 * Constants
 */
const char *DEL_ALL_WITH_DUPLICATE_PATH = "deleteAllWithDuplicatePath";

/*
 * Private method declarations
 */

static CCIMInstanceList *create_persistentShare_InstList(
	fs_dfstab_entry_t fs_dfstab_ent,
	int *err);
static CCIMInstanceList *enumerate_dfstab();
static CCIMPropertyList *populate_Solaris_PersistentShare_property_list(
	char *hostname,
	fs_dfstab_entry_t fs_dfstab_ents);
static void populate_Solaris_PersistentShare_property_values(
	char *hostname,
	fs_dfstab_entry_t fs_dfstab_ents,
	cimchar propValues[PROPCOUNT][MAXSIZE],
	int *err);

/*
 * Name: cp_enumInstances_Solaris_PersistentShare
 *
 * Description: Creates a list of instances and returns that list.
 *
 * Parameters:
 *      dfstabOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstanceList * if matched instance is found. Otherwise, NULL.
 */
CCIMInstanceList *
cp_enumInstances_Solaris_PersistentShare(CCIMObjectPath* dfstabOP) {
	CCIMInstanceList *instList;
	int err = 0;

	cim_logDebug("cp_enumInstances_Solaris_PersistentShare",
	    "Just entering...");
	/*
	 * First check if the CCIMObjectPath passed in is null.
	 */
	if (dfstabOP == NULL) {
		util_handleError(
		    "SOLARIS_PERSISTSHARE::ENUM_INSTANCES",
		    CIM_ERR_INVALID_PARAMETER, NULL,
		    NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	instList = enumerate_dfstab();
	if (instList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}
	cim_logDebug("cp_enumInstances_Solaris_PersistentShare",
	    "Returning non NULL instance list.");
	return (instList);
} /* cp_enumInstances_Solaris_PersistentShare */

/*
 * Name: cp_enumInstanceNames_Solaris_PersistentShare
 *
 * Description: Returns a list of instances if found.
 *
 * Parameters:
 *      dfstabOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMObjectPathList * if matched instance is found. Otherwise, NULL.
 */
CCIMInstanceList *
cp_enumInstanceNames_Solaris_PersistentShare(CCIMObjectPath *dfstabOP) {
	CCIMInstanceList	*instList;
	CCIMObjectPathList	*OPList;
	CCIMException		*ex;
	int			err;

	/*
	 * First check if the CCIMObjectPath parameter is null.
	 */
	if (dfstabOP == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::ENUM_INSTANCENAMES",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}
	instList = cp_enumInstances_Solaris_PersistentShare(dfstabOP);
	if (instList == NULL) {
		/*
		 * Failure...or there are no dfstab instances.
		 */
		return ((CCIMObjectPathList *)NULL);
	}

	OPList = cim_createObjectPathList(instList);
	if (OPList == NULL) {
		/*
		 * Error encountered
		 */
		ex = cim_getLastError();
		util_handleError(
			"SOLARIS_DFSTABEMTRY::ENUM_INSTANCENAMES",
			CIM_ERR_FAILED, CREATE_OBJECT_LIST_FAILURE, ex, &err);
			cim_freeInstanceList(instList);
		return (NULL);
	}

	cim_freeInstanceList(instList);
	return (OPList);
} /* cp_enumInstanceNames_Solaris_PersistentShare */


/*
 * Name: cp_getInstance_Solaris_PersistentShare
 *
 * Description: Returns an instance which matches the passed in object path
 * if found.
 *
 * Parameters:
 *      dfstabOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstance * if matched instance is found. Otherwise, NULL.
 */
CCIMInstance *
cp_getInstance_Solaris_PersistentShare(CCIMObjectPath *dfstabOP) {
	CCIMInstanceList	*instList;
	CCIMInstance		*inst;
	CCIMException		*ex;
	int			err = 0;

	/*
	 * First check to see if the object path is null
	 */
	if (dfstabOP == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::GET_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		    return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_PersistentShare(dfstabOP);
	if (instList == NULL) {
		/*
		 * Either an error occurred or we simply don't have any
		 * instances of Solaris_PersistentShare on the system.  In the
		 * case, that an error occurred, it will be handled in
		 * cp_enumInstances_Solaris_PersistentShare.
		 */
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, dfstabOP);
	if (inst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_PERSISTSHARE::GET_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, GET_INSTANCE_FAILURE,
		    ex, &err);
		cim_freeInstanceList(instList);
		return ((CCIMInstance *)NULL);
	}
	cim_freeInstanceList(instList);
	return (inst);
} /* cp_getInstance_Solaris_PersistentShare */

/*
 * cp_setInstance not supported
 */
/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_PersistentShare(CCIMObjectPath *pOP,
    CCIMInstance *pInst, char **props, int num_props) {

	int	err = 0;

	util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_PersistentShare */

/*
 * cp_setProperty not supported
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_PersistentShare(CCIMObjectPath *pOP,
    CCIMInstance *pInst, char **props, int num_props) {
	int	err = 0;

	util_handleError("SOLARIS_PERSISTSHARE::SET_PROPERTY",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_PersistentShare */

/*
 * Method: cp_setInstanceWithList_Solaris_PersistentShare
 *
 * Description: This method is used to edit or change a dfstab entry.
 *
 * Parameters:
 *      - CCIMObjectPath *dfstabOP - The object path containing the name
 *      of the class of which to set the instance.
 *      - CCIMInstance *dfstabInst - The instance containg the information
 *	of the dfstab entry that will be changed.
 *      - char **props - Not used.
 *      - int num_props - Not used.
 *
 * Returns:
 *	- cim_true if successful. If an error accures cim_false is returned.
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_PersistentShare(CCIMObjectPath *dfstabOP,
	CCIMInstance *dfstabInst, char **props, int num_props) {

	int err = 0;
	CCIMProperty *dfstab_prop;
	CCIMInstance *fsDfstab_inst; /* XXXX original instance */
	CCIMObjectPath *fsDfstab_OP;
	char *new_cmd_value;


	if (dfstabOP == NULL || dfstabInst == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return (cim_false);
	}

	fsDfstab_OP = cim_createObjectPath(dfstabInst);
	if (fsDfstab_OP == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return (cim_false);
	}
	fsDfstab_inst =
	    cp_getInstance_Solaris_PersistentShare(fsDfstab_OP);
	if (fsDfstab_inst == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
		    CIM_ERR_FAILED, CIMOM_GET_INST_FAILURE, NULL, &err);
		return (cim_false);
	}

	dfstab_prop = cim_getProperty(fsDfstab_inst,
	    nfsPersistProps[SETTINGID].name);
	if (dfstab_prop == NULL) {
		return (cim_false);
	} else {
		int path_count =
		    fs_check_for_duplicate_DFStab_paths(
		    dfstab_prop->mValue, &err);
		if (path_count > 1 || path_count == -1) {
			util_handleError(
			    "SOLARIS_PERSISTSHARE::SET_INSTANCE",
			    CIM_ERR_FAILED, FS_CHECK_DUP_PATHS,
			    NULL, &err);
			return (cim_false);
		}
	}

	dfstab_prop = cim_getProperty(fsDfstab_inst,
	    nfsPersistProps[COMMAND].name);
	if (dfstab_prop == NULL) {
		return (cim_false);
	}

	new_cmd_value = strdup(dfstab_prop->mValue);
	if (new_cmd_value == NULL) {
		err = ENOMEM;
		util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
		    CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, &err);
		return (cim_false);
	}

	dfstab_prop = cim_getProperty(dfstabInst,
	    nfsPersistProps[COMMAND].name);
	if (dfstab_prop == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
		    CIM_ERR_FAILED, GET_PROPERTY_FAILURE, NULL, &err);
		cim_freeInstance(fsDfstab_inst);
		free(new_cmd_value);
		return (cim_false);
	} else {
		fs_dfstab_entry_t dfstab_ent_list;
		char *cmd_value = NULL;
		cmd_value = strdup(dfstab_prop->mValue);
		if (cmd_value == NULL) {
			/*
			 * Out of memory
			 */
			err = ENOMEM;
			util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
			    CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, &err);
			return (cim_false);
		}

		if ((dfstab_ent_list = fs_edit_DFStab_ent(cmd_value,
		    new_cmd_value, &err)) == NULL) {
			util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
			    CIM_ERR_FAILED, FS_EDIT_DFSTAB_ENT_FAILURE,
			    NULL, &err);
			return (cim_false);
		}

		fs_free_DFStab_ents(dfstab_ent_list);
		free(cmd_value);
		free(new_cmd_value);
		cim_freeInstance(fsDfstab_inst);
	}
	return (cim_true);
} /* cp_setInstanceWithList_Solaris_PersistentShare */

/*
 * Name: cp_createInstance_Solaris_PersistentShare
 * Description: A create instance will actually add an entry to
 *              /etc/dfs/dfstab in the current host by calling
 *              the fs_dfstab interface's fs_set_DFStab_ent
 *              function.
 * Parameters:
 *      dfstabOP - An CCIMObjectPath * which contains the information on
 *                the class for which to find the instance.
 *      dfstabInst - an instance that contains the properties for the share
 *                  to be created.
 * Returns:
 *      CCIMObjectPath * - Object path containing the new instance. On
 *                         failure NULL is returned.
 */
CCIMObjectPath *
cp_createInstance_Solaris_PersistentShare(CCIMObjectPath *dfstabOP,
	CCIMInstance *dfstabInst) {

	char	*cmd = NULL;
	int	err = 0;
	CCIMProperty *dfstab_prop;
	CCIMInstance *fsDfstab_inst;
	CCIMObjectPath *fsDfstab_OP;
	CCIMException   *ex;
	fs_dfstab_entry_t dfstab_ent_list;

	if (dfstabOP == NULL || dfstabInst == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPath *)NULL);
	}

	dfstab_prop = cim_getProperty(dfstabInst,
	    nfsPersistProps[COMMAND].name);
	if (dfstab_prop != NULL) {
		CCIMProperty *dfsProp;

		cmd = strdup(dfstab_prop->mValue);
		if (cmd == NULL) {
			/*
			 * Out of memory
			 */
			err = ENOMEM;
			util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
			    CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, &err);
			cim_freeProperty(dfstab_prop);
			return ((CCIMObjectPath *)NULL);
		} else if (strlen(cmd) == NULL) {
			util_handleError(
				"SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			cim_freeProperty(dfstab_prop);
			return ((CCIMObjectPath *)NULL);
		}

		dfsProp = cim_getProperty(dfstabInst,
		    nfsPersistProps[SETTINGID].name);
		if (dfsProp == NULL) {
			util_handleError("SOLARIS_PERSISTSHARE::SET_INSTANCE",
			    CIM_ERR_FAILED, GET_PROPERTY_FAILURE, NULL, &err);
			free(cmd);
			return ((CCIMObjectPath *)NULL);
		}
		if (fs_check_for_duplicate_DFStab_paths(dfsProp->mValue,
		    &err) == 0) {

			dfstab_ent_list = fs_add_DFStab_ent(cmd, &err);
			if (dfstab_ent_list == NULL) {
				util_handleError(
				    "SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
				    CIM_ERR_FAILED, FS_ADD_DFSTAB_ENT_FAILURE,
				    NULL, &err);
				free(cmd);
				return ((CCIMObjectPath *)NULL);
			}
			fs_free_DFStab_ents(dfstab_ent_list);
		} else {
			util_handleError(
			    "SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
			    CIM_ERR_FAILED, FS_CHECK_DUP_PATHS, NULL, &err);
			free(cmd);
			return ((CCIMObjectPath *)NULL);
		}
	}
	free(cmd);

	fsDfstab_inst = cp_getInstance_Solaris_PersistentShare(dfstabOP);
	if (fsDfstab_inst == NULL) {
		/*
		 * The dfstab instance was not found there for the create
		 * instance failed.
		 */
		return ((CCIMObjectPath *)NULL);
	}
	fsDfstab_OP = cim_createObjectPath(fsDfstab_inst);
	if (fsDfstab_OP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
		    CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE, ex, &err);
		cim_freeInstance(fsDfstab_inst);
		return ((CCIMObjectPath *)NULL);
	}

	cim_freeInstance(fsDfstab_inst);
	return (fsDfstab_OP);
} /* cp_createInstance_Solaris_PersistentShare */

/*
 * Name: cp_deleteInstance_Solaris_NFSShare
 *
 * Description: The delete instance will remove the specified line from dfstab
 *              on the current host by calling
 *              cmd_execute_command_and_retrieve_string() from the cmd
 *              interface.
 *
 * Parameters:
 *      dfstabOP - An CCIMObjectPath * - The object path corresponding to the
 *                instance to be removed.
 * Returns:
 *      CIMBool - Returns cim_true on successful completion. On failure
 *                cim_false is returned.
 */
CIMBool
cp_deleteInstance_Solaris_PersistentShare(CCIMObjectPath *dfstabOP) {
	char	*cmd = NULL;
	int	err = 0;
	int	len;
	CCIMProperty *dfstab_prop;
	CCIMInstance *fsDfstab_inst;
	CCIMException   *ex;
	fs_dfstab_entry_t dfstab_ent_list;

	if (dfstabOP == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return (cim_false);
	}

	fsDfstab_inst = cp_getInstance_Solaris_PersistentShare(dfstabOP);
	if (fsDfstab_inst == NULL) {
		/*
		 * The dfstab instance was not found therefore it can't
		 * be deleted.
		 */
		return (cim_false);
	}

	dfstab_prop = cim_getProperty(fsDfstab_inst,
	    nfsPersistProps[COMMAND].name);
	if (dfstab_prop != NULL) {
		cmd = strdup(dfstab_prop->mValue);
		if (cmd == NULL) {
			/*
			 * Out of memory
			 */
			err = ENOMEM;
			util_handleError(
			    "SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
			    CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, &err);
			return (cim_false);
		} else {
			int path_count = 0;
			cim_freeProperty(dfstab_prop);
			dfstab_prop = cim_getProperty(fsDfstab_inst,
			    nfsPersistProps[SETTINGID].name);
			if (dfstab_prop == NULL) {
				ex = cim_getLastError();
				util_handleError(
				    "SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
				    CIM_ERR_FAILED, GET_PROPERTY_FAILURE,
				    ex, &err);
				return (cim_false);
			}
			path_count =
			    fs_check_for_duplicate_DFStab_paths(
			    dfstab_prop->mValue, &err);
			if (path_count > 1 || path_count == -1) {
				util_handleError(
				    "SOLARIS_PERSISTSHARE::SET_INSTANCE",
				    CIM_ERR_INVALID_PARAMETER,
				    FS_CHECK_DUP_PATHS, NULL, &err);
				free(cmd);
				cim_freeProperty(dfstab_prop);
				return (cim_false);
			}
		}
		cim_freeProperty(dfstab_prop);

		/*
		 * We're stripping the return char off the end of cmd.
		 * fs_del_DFStab_ent expects to have no \n at the end
		 * of the line. The call to cim_getProperty() for the cmd
		 * will always return the command string with a \n.
		 */
		len = strlen(cmd);
		cmd[len - 1] = '\0';
		dfstab_ent_list = fs_del_DFStab_ent(cmd, &err);
		if (dfstab_ent_list == NULL && err != 0) {
			util_handleError(
			    "SOLARIS_PERSISTSHARE::CREATE_INSTANCE",
			    CIM_ERR_FAILED, FS_DEL_DFSTAB_ENT_FAILURE,
			    NULL, &err);
			free(cmd);
			return (cim_false);
		}
		fs_free_DFStab_ents(dfstab_ent_list);
		free(cmd);
	}
	cim_freeInstance(fsDfstab_inst);
	return (cim_true);
} /* cp_deleteInstance_Solaris_PersistentShare */

/*
 * Name: cp_execQuery_Solaris_PersistentShare
 *
 * Description: Builds a list of all instances, prepends the list with an
 *              empty instance, and returns the instance list. The CIMOM
 *              interprets the initial empty instance to mean that it has
 *              to do the filtering. The caller is responsible for freeing
 *              the memory allocated for the returned object.
 *
 * Parameters:
 * CCIMObjectPath *dfstabOP - An objectpath which represents the class to
 *                           work on
 * char *electClause - The select clause
 * char *nonJoinExp - The non join expression
 * char *queryExp - The query Expression
 * char *queryLang - The Query Language used (s/b "WQL")
 *
 * Returns:
 * Returns the prepended instance list. On error NULL is returned.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_execQuery_Solaris_PersistentShare(CCIMObjectPath *dfstabOP,
	char *selectClause, char *nonJoinExp, char *queryExp, char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*fsDfstabInstList;
	CCIMInstanceList	*result;
	CCIMException		*ex;
	int			err = 0;

	if (dfstabOP == NULL) {
		util_handleError("SOLARIS_PERSISTSHARE::EXEC_QUERY",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	fsDfstabInstList = cp_enumInstances_Solaris_PersistentShare(dfstabOP);
	if (fsDfstabInstList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_PERSISTSHARE::EXEC_QUERY",
		    CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	result = cim_prependInstance(fsDfstabInstList, emptyInst);
	if (result == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_PERSISTSHARE::EXEC_QUERY",
		    CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		cim_freeInstanceList(fsDfstabInstList);
		return ((CCIMInstanceList *)NULL);
	}

	return (result);
} /* cp_execQuery_Solaris_PersistentShare */

/*
 * Provider methods
 */
/*
 * Method: cp_invokeMethod_Solaris_PersistentShare
 *
 * Description: cp_invokeMethod_Solaris_PersistentShare calls to the
 * correct Solaris_PersistentShare method. In this case the only method
 * available is del_all_with_duplicate_path(). Thsi method checks the
 * dfstab file for entries with the same path any found are removed.
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
cp_invokeMethod_Solaris_PersistentShare(CCIMObjectPath *pOP,
    cimchar *functionName, CCIMPropertyList *inParams,
    CCIMPropertyList *outParams) {

	int		err = 0;
	CCIMProperty	*retVal;

	/*
	 * Make sure the proper method is being called.
	 */
	if (strcasecmp(functionName, DEL_ALL_WITH_DUPLICATE_PATH) == 0) {
		retVal = del_all_with_duplicate_path(inParams);
	} else {
		/*
		 * No such method name.
		 */
		util_handleError("SOLARIS_PERSISTSHARE::INVOKE_METHOD",
		    CIM_ERR_FAILED, NO_SUCH_METHOD, NULL, &err);
		return (cim_createProperty("Status", sint32, "0", NULL,
		    cim_false));
	}

	return (retVal);
} /* cp_invokeMethod_Solaris_PersistentShare */


/*
 * Private Methods
 */
/*
 * create_persistentShare_InstList
 *
 * Creates the Solaris_NFSShareSecurity instance list from information
 * gathered from the shares on the system. The instance list is returned.
 */
static CCIMInstanceList *
create_persistentShare_InstList(
    fs_dfstab_entry_t persistentShareList,
    int *err) {

	fs_dfstab_entry_t fs_dfstab_ent;
	CCIMInstanceList *fsDfstabInstList;
	CCIMException *ex;
	struct utsname	hostname;


	cim_logDebug("create_persistentShare_InstList",
	    "Entering function");

	/*
	 * retrieve system name
	 */
	(void) uname(&hostname);
	*err = errno;
	if (*err != 0) {
		util_handleError(
		    "SOLARIS_PERSISTSHARE::CREATE_INSTLIST",
		    CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL, err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * At this point, one or more dfstab entries were found on the
	 * system, create the instance list from the fs_dfstab_ent.
	 */
	fsDfstabInstList = cim_createInstanceList();
	if (fsDfstabInstList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_PERSISTSHARE::CREATE_INSTLIST",
		    CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE,
		    ex, err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Loop through the dfstab entries to retrieve their properties
	 * and create an instance list containing all these entries and
	 * their properties.
	 */
	fs_dfstab_ent = persistentShareList;
	while (fs_dfstab_ent != NULL) {
		CCIMInstance 	*solaris_Dfstab_instance;
		CCIMPropertyList	*solaris_Dfstab_prop_list;

		/*
		 * Create the Solaris_PersistentShare CCIMInstance
		 */
		solaris_Dfstab_instance =
			cim_createInstance(SOLARIS_PERSISTSHARE);
		if (solaris_Dfstab_instance == NULL) {
			ex = cim_getLastError();
			util_handleError(
			    "SOLARIS_PERSISTSHARE::CREATE_INSTLIST",
			    CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE,
			    ex, err);
			return ((CCIMInstanceList *)NULL);
		}

		solaris_Dfstab_prop_list =
		    populate_Solaris_PersistentShare_property_list(
		    hostname.nodename, fs_dfstab_ent);
		if (solaris_Dfstab_prop_list == NULL) {
			/*
			 * populatePropertyList already logged this
			 * error so there is no need to log it here.
			 */
			cim_freeInstance(solaris_Dfstab_instance);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Add the property list to the instance
		 */
		solaris_Dfstab_instance =
		    cim_addPropertyListToInstance(
			solaris_Dfstab_instance,
			solaris_Dfstab_prop_list);
		if (solaris_Dfstab_instance == NULL) {
			ex = cim_getLastError();
			util_handleError(
			    "SOLARIS_PERSISTSHARE::CREATE_INSTLIST",
			    CIM_ERR_FAILED, PROPLIST_TO_INSTANCE_FAILURE,
			    ex, err);
			cim_freePropertyList(solaris_Dfstab_prop_list);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Add the instance to the instance list
		 */
		fsDfstabInstList = cim_addInstance(fsDfstabInstList,
		    solaris_Dfstab_instance);
		if (fsDfstabInstList == NULL) {
			ex = cim_getLastError();
			util_handleError(
			    "SOLARIS_PERSISTSHARE::CREATE_INSTLIST",
			    CIM_ERR_FAILED, ADD_INSTANCE_FAILURE,
			    ex, err);
			cim_freeInstance(solaris_Dfstab_instance);
			return ((CCIMInstanceList *)NULL);
		}
		fs_dfstab_ent = fs_get_DFStab_ent_Next(fs_dfstab_ent);
	} /* while (fs_dfstab_ent != NULL) */

	cim_logDebug("create_persistentShare_InstList",
	    "returning instance list");
	return (fsDfstabInstList);
} /* create_persistentShare_InstList */


/*
 * Enumerate the nfs shares by using the fs_shares fs_get_share_list
 * method
 */
static CCIMInstanceList *
enumerate_dfstab() {

	int err = 0;
	fs_dfstab_entry_t fs_dfstab_ent;

	cim_logDebug("enumerate_dfstab", "Just entering...");

	fs_dfstab_ent = fs_get_DFStab_ents(&err);
	if (fs_dfstab_ent == NULL) {
		/*
		 * Check whether an error was returned or if we simply don't
		 * have any dfstab entries on the system. If err is not
		 * equal to 0, an error was encountered.
		 */
		if (err != 0) {
			cim_logDebug("enumerate_dfstab", "An error occurred " \
			    "while getting the dfstab entries");
			/*
			 * Determine the error and log it.
			 */
			if (err == ENOMEM || err == EAGAIN) {
				util_handleError(
				    "SOLARIS_PERSISTSHARE::ENUM_INSTANCES",
				    CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY,
				    NULL, &err);
				return ((CCIMInstanceList *)NULL);
			} else {

				/*
				 * If any other errors were encountered it
				 * can be handled as a general error. We may
				 * not know exactly what the error is.
				 */
				util_handleError(
				    "SOLARIS_PERSISTSHARE::ENUM_INSTANCES",
				    CIM_ERR_FAILED, FS_GET_DFSTAB_ENT_FAILURE,
				    NULL, &err);
				return ((CCIMInstanceList *)NULL);
			}
		}
		/*
		 * There are no nfs shares on the host.
		 */
		cim_logDebug("enumerate_dfstab",
		    "There are no dfstab entries on the host. Returning NULL");
		return ((CCIMInstanceList *)NULL);

	} else {

		CCIMInstanceList	*fsDfstabInstList;

		fsDfstabInstList =
		    create_persistentShare_InstList(fs_dfstab_ent, &err);

		fs_free_DFStab_ents(fs_dfstab_ent);

		cim_logDebug("enumerate_dfstab", "Returning the instance list");
		return (fsDfstabInstList);
	}
} /* enumerate_dfstab */

/*
 * populate_Solaris_PersistentShare_property_list
 * Populates the property list with the share information for each
 * instance in the instance list. Returns the instance list.
 */
static CCIMPropertyList *
populate_Solaris_PersistentShare_property_list(
    char *hostname,
    fs_dfstab_entry_t fs_dfstab_ents) {

	CCIMException *ex;
	CCIMPropertyList *fsDfstabPropList;
	char propValues[PROPCOUNT][MAXSIZE];
	int i, err = 0;

	cim_logDebug("populate_Solaris_PersistentShare_property_list",
	    "Just entring...");

	fsDfstabPropList = cim_createPropertyList();
	if (fsDfstabPropList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_PERSISTSHARE::POPULATE_PROPLIST",
		    CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE,
		    ex, &err);
		return ((CCIMPropertyList *)NULL);
	}

	/*
	 * Create the CCIMProperties for this instance
	 */

	populate_Solaris_PersistentShare_property_values(hostname,
	    fs_dfstab_ents, propValues, &err);
	if (err != 0) {
		cim_freePropertyList(fsDfstabPropList);
		fsDfstabPropList = NULL;
	} else {
		for (i = 0; i < PROPCOUNT; i++) {
			fsDfstabPropList = add_property_to_list(
			    nfsPersistProps[i].name, nfsPersistProps[i].type,
			    propValues[i], NULL, nfsPersistProps[i].isKey,
			    fsDfstabPropList);
			if (fsDfstabPropList == NULL) {
				break;
			}
		}
	}
	cim_logDebug("populate_Solaris_NFSShareSecurity_property_list",
	    "Returning property list");
	return (fsDfstabPropList);
} /* populate_Solaris_PersistentShare_property_list */

/*
 * populate_Solaris_NFSShare_property_Values
 * Populates the property array for use in the populate_property_list function
 */
static void
populate_Solaris_PersistentShare_property_values(
    char *hostname,
    fs_dfstab_entry_t fs_dfstab_ents,
    cimchar propValues[PROPCOUNT][MAXSIZE],
    int *err) {

	char		*optValue;

	cim_logDebug("populate_Solaris_PersistentShare_property_values",
	    "Just entring...");

	/*
	 * Key - System name
	 */
	(void) snprintf(propValues[SYSTEMNAME], MAXSIZE, "%s",
	    hostname);

	/*
	 * Get the dfstab entry string
	 */
	optValue = fs_get_Dfstab_share_cmd(fs_dfstab_ents, err);

	if (*err == 0) {
		(void) snprintf(propValues[COMMAND], MAXSIZE, "%s", optValue);
		free(optValue);
	} else {
		*err = EINVAL;
		return;
	}

	/*
	 * Key - creation class name
	 */
	(void) snprintf(propValues[CREATIONCLASSNAME], MAXSIZE, "%s",
	    SOLARIS_PERSISTSHARE);

	/*
	 * Key - Shared Path
	 */
	optValue = fs_get_DFStab_ent_Path(fs_dfstab_ents);
	if (optValue != NULL) {
		(void) snprintf(propValues[SETTINGID], MAXSIZE, "%s", optValue);
	} else {
		*err = EINVAL;
		return;
	}

	/*
	 * Key - System Creation class name
	 */
	(void) snprintf(propValues[SYSTEMCREATIONCLASSNAME], MAXSIZE, "%s",
	    SOLARIS_CS);

	cim_logDebug("populate_Solaris_PersistentShare_property_values",
	    "Returning");

} /* populate_Solaris_PersistentShare_property_values */
