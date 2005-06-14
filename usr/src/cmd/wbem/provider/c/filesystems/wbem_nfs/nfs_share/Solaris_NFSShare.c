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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "Solaris_NFSShare.h"
#include "nfs_keys.h"
#include "nfs_provider_names.h"
#include "nfs_providers_msgstrings.h"
#include "messageStrings.h"
#include "cmdgen.h"
#include "util.h"
#include "libfsmgt.h"
#include "createprop_methods.h"
#include <string.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * Constants
 */
/* #define	SOLARIS_NFSSHARE "Solaris_NFSShare" */
#define	NFSD 0
#define	MOUNTD 1


/*
 * Private method declarations
 */

static CIMBool		check_for_PersistentShareEnt(
			    fs_sharelist_t *nfs_sharelist, int *err);
static CCIMInstanceList	*enumerate_shares();
static CCIMPropertyList	*populate_Solaris_NFSShare_property_list(
			    char *hostname,
			    fs_sharelist_t *nfs_share);
static CIMBool		populate_Solaris_NFSShare_property_Values(
			    char *hostname,
			    fs_sharelist_t *nfs_sharelist,
			    cimchar propValues[PROPCOUNT][MAXSIZE],
			    int *err);
static char		*start_daemons(int which_daemon, int *err);

/*
 * Public methods
 */

/*
 * Instance provider methods
 */

/*
 * Solaris_NFSShare provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the CIMOM as the caller.
 */

/*
 * Name: cp_enumInstances_Solaris_NFSShare
 *
 * Description: Creates a list of instances and returns that list.
 *
 * Parameters:
 *      shareOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstanceList * if matched instance is found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_enumInstances_Solaris_NFSShare(CCIMObjectPath* shareOP)
{
	CCIMInstanceList	*instList;
	int			err = 0;

	cim_logDebug("cp_enumInstances_Solaris_NFSShare", "just entering...");
	/*
	 * Check object path for NULL value
	 */
	if (shareOP == NULL) {
		util_handleError(
		    "SOLARIS_NFSSHARE::ENUM_INSTANCES",
		    CIM_ERR_INVALID_PARAMETER, NULL,
		    NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	cim_logDebug("cp_enumInstances_Solaris_NFSShare",
	    "Calling enumerate_shares");
	instList = enumerate_shares();
	if (instList == NULL) {
		cim_logDebug("cp_enumInstances_Solaris_NFSShare",
		    "Call from enumerate_sharesreturned NULL");
	}
	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_NFSShare
 *
 * Description: Returns a list of instances if found.
 *
 * Parameters:
 *      shareOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMObjectPathList * if matched instance is found. Otherwise, NULL.
 */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_NFSShare(CCIMObjectPath* shareOP)
{
	CCIMInstanceList	*instList;
	CCIMObjectPathList	*ObjPathList;
	int			err = 0;

	/*
	 * Check object path for NULL value
	 */
	if (shareOP == NULL) {
		util_handleError("SOLARIS_NFSSHARE::ENUM_INSTANCENAMES",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFSShare(shareOP);
	if (instList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	ObjPathList = cim_createObjectPathList(instList);

	cim_freeInstanceList(instList);
	return (ObjPathList);
}

/*
 * Name: cp_getInstance_Solaris_NFSShare
 *
 * Description: Returns an instance which matches the passed in object path
 * if found.
 *
 * Parameters:
 *      shareOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstance * if matched instance is found. Otherwise, NULL.
 */
/* ARGSUSED */
CCIMInstance *
cp_getInstance_Solaris_NFSShare(CCIMObjectPath* shareOP)
{
	CCIMInstanceList *instList;
	CCIMInstance *inst;
	CCIMException *ex;
	int err = 0;

	/*
	 * Check object path for NULL value
	 */
	if (shareOP == NULL) {
		util_handleError("SOLARIS_NFSSHARE::ENUM_INSTANCENAMES",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFSShare(shareOP);
	if (instList == NULL) {
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, shareOP);
	if (inst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARE::ENUM_INSTANCE",
			CIM_ERR_INVALID_CLASS, GET_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(instList);
		return ((CCIMInstance *)NULL);
	}

	cim_freeInstanceList(instList);
	return (inst);
}

/*
 * cp_setInstanceWithList not supported
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_NFSShare(CCIMObjectPath *shareOP,
    CCIMInstance *shareInst, char **props, int num_props)
{
	int	err = 0;
	util_handleError("SOLARIS_NFSSHARE::SET_INSTANCEWITHLIST",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return (cim_false);
}

/*
 * cp_setInstance not supported
 */
/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_NFSShare(CCIMObjectPath *shareOP,
    CCIMInstance *shareInst, char **props, int num_props)
{
	int	err = 0;
	util_handleError("SOLARIS_NFSSHARE::SET_INSTANCE",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return (cim_false);
}

/*
 * cp_invokeMethod not supported
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_NFSShare(
    CCIMObjectPath* shareOP,
    cimchar *functionName,
    CCIMPropertyList *inParams,
    CCIMPropertyList *outParams)
{
	int	err = 0;
	util_handleError("SOLARIS_NFSSHARE::INVOKE_METHOD",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return ((CCIMProperty *)NULL);
}

/*
 * cp_setProperty not supported
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_NFSShare(CCIMObjectPath *pOP, CCIMProperty *pProp)
{
	int	err = 0;
	util_handleError("SOLARIS_NFSSHARE::SET_PROPERTY",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return (cim_false);
}

/*
 * Name: cp_createInstance_Solaris_NFSShare
 *
 * Description: Returns the instance created based on the instance
 *              inforamtion passed in. A create instance will actually
 *              share a file system on the current host by calling
 *              cmd_execute_command_and_retrieve_string() from the cmd
 *              interface.
 *
 * Parameters:
 *      shareOP - An CCIMObjectPath * which contains the information on
 *                the class for which to find the instance.
 *      shareInst - an instance that contains the properties for the share
 *                  to be created.
 * Returns:
 *      CCIMObjectPath * - Object path containing the new instance. On
 *                         failure NULL is returned.
 */
CCIMObjectPath *
cp_createInstance_Solaris_NFSShare(CCIMObjectPath* shareOP,
	CCIMInstance *shareInst)
{

	char *cmd_return, *cmd;
	int err = 0;

	CCIMInstance *nfsShareInstance;
	CCIMObjectPath *nfsShareObjectPath;
	CCIMProperty *share_Prop;
	CCIMException *ex;

	cim_logDebug("cp_createInstance_Solaris_NFSShare",
	    "Entering create instance...");

	if (shareOP == NULL || shareInst == NULL) {
		err = EINVAL;
		util_handleError(
		    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPath *)NULL);
	}

	cmd = cmdgen_generate_command(CMDGEN_NFS_SHARE, shareInst, NULL, NULL,
		&err);

	if (err != 0 || cmd == NULL) {
		util_handleError(
		    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
		    CIM_ERR_FAILED, CMDGEN_GEN_CMD_FAILURE, NULL, &err);
		return ((CCIMObjectPath *)NULL);
	}

	cmd_return = cmd_execute_command_and_retrieve_string(cmd, &err);

	free(cmd);

	if (err != 0) {
		/*
		 * An error occured while executing the command.
		 */
		if (cmd_return != NULL) {
			util_handleError(
			    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
			    CIM_ERR_FAILED, cmd_return, NULL, &err);
			free(cmd_return);
			return ((CCIMObjectPath *)NULL);
		} else {
			util_handleError(
			    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
			    CIM_ERR_FAILED, CMD_EXEC_RETR_STR_FAILURE,
			    NULL, &err);
			return ((CCIMObjectPath *)NULL);
		}
	}

	free(cmd_return);

	nfsShareInstance = cp_getInstance_Solaris_NFSShare(shareOP);

	if (nfsShareInstance == NULL) {
		/*
		 * The share instance was not found. The create
		 * instance failed.
		 */
		util_handleError(
		    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
		    CIM_ERR_FAILED, CIMOM_GET_INST_FAILURE, NULL, &err);
		return ((CCIMObjectPath *)NULL);
	}
	if ((nfsShareObjectPath =
	    cim_createObjectPath(nfsShareInstance)) == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARE::CREATE_INSTANCE",
		    CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE, ex, &err);
		cim_freeInstance(nfsShareInstance);
		return ((CCIMObjectPath *)NULL);
	}

	share_Prop = cim_getProperty(nfsShareInstance,
	    nfsShareProps[STARTDAEMONS].name);
	if ((share_Prop != NULL) &&
	    (strcmp(share_Prop->mValue, "true") != 0)) {
		cmd_return = start_daemons(NFSD, &err);
		if (err != 0 && err != EEXIST) {
			char error_string[MAXSIZE];
			(void) strlcpy(error_string, NFSD_START_FAILURE,
			    MAXSIZE);
			if (cmd_return == NULL) {
				util_handleError(
				    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
				    NULL, error_string, NULL, &err);
			} else {
				char return_string[MAXSIZE];
				(void) strlcat(error_string, cmd_return,
				    MAXSIZE);
				(void) strlcpy(return_string, error_string,
				    MAXSIZE);
				util_handleError(
				    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
				    NULL, return_string, NULL, &err);
			}
		}
		free(cmd_return);
		err = 0;
		cmd_return = start_daemons(MOUNTD, &err);
		if (err != 0 && err != EEXIST) {
			char error_string[MAXSIZE];
			(void) strlcpy(error_string, MOUNTD_START_FAILURE,
			    MAXSIZE);
			if (cmd_return == NULL) {
				util_handleError(
				    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
				    NULL, error_string, NULL, &err);
			} else {
				char return_string[MAXSIZE];
				(void) strlcat(error_string, cmd_return,
				    MAXSIZE);
				(void) strlcpy(return_string, error_string,
				    MAXSIZE);
				util_handleError(
				    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
				    NULL, return_string, NULL, &err);
			}
		}

		free(cmd_return);
	}

	cim_freeInstance(nfsShareInstance);
	return (nfsShareObjectPath);
} /* cp_createInstance_Solaris_NFSShare */


/*
 * Name: cp_deleteInstance_Solaris_NFSShare
 *
 * Description: The delete instance will unshare a file system on the
 *              current host by calling
 *              cmd_execute_command_and_retrieve_string() from the cmd
 *              interface.
 *
 * Parameters:
 *      shareOP - An CCIMObjectPath * - The object path coresponding to the
 *                instance to be removed.
 * Returns:
 *      CIMBool - Returns cim_true on successful completion. On failure
 *                cim_false is returned.
 */
CIMBool
cp_deleteInstance_Solaris_NFSShare(CCIMObjectPath *shareOP)
{
	char *cmd, *cmd_return;
	int err = 0;

	cim_logDebug("cp_deleteInstance_Solaris_NFSShare", "Just entering...");
	if (shareOP == NULL) {
		util_handleError("SOLARIS_NFSSHARE::DELETE_INSTANCE",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return (cim_false);
	}

	/*
	 * Get the share that is to be deleted and generatel the
	 * unshare command.
	 */
	cmd = cmdgen_generate_command(CMDGEN_NFS_UNSHARE, NULL, shareOP, NULL,
		&err);
	if (err != 0 || cmd == NULL) {
		util_handleError(
		    "SOLARIS_NFSSHARE::CREATE_INSTANCE",
		    CIM_ERR_FAILED, CMDGEN_GEN_CMD_FAILURE, NULL, &err);
		if (cmd == NULL) {
			free(cmd);
		}
		return (cim_false);
	}

	/*
	 * Execute the unshare command.
	 */
	cmd_return = cmd_execute_command_and_retrieve_string(cmd, &err);
	free(cmd);
	if (err != 0) {
		/*
		 * The unshare command execution failed.
		 */
		if (cmd_return != NULL) {
			util_handleError("SOLARIS_NFSSHARE::DELETE_INSTANCE",
			    CIM_ERR_FAILED, CMD_EXEC_RETR_STR_FAILURE,
			    NULL, &err);
			free(cmd_return);
			return (cim_false);
		} else {
			util_handleError("SOLARIS_NFSSHARE::DELETE_INSTANCE",
			    CIM_ERR_FAILED, CMD_EXEC_RETR_STR_FAILURE,
			    NULL, &err);
			return (cim_false);
		}
	}
	free(cmd_return);
	return (cim_true);
}

/*
 * Name: cp_execQuery_Solaris_NFSShare
 *
 * Description: Builds a list of all instances, prepends the list with an
 *              empty instance, and returns the instance list. The CIMOM
 *              interprets the initial empty instance to mean that it has
 *              to do the filtering. The caller is responsible for freeing
 *              the memory allocated for the returned object.
 *
 * Parameters:
 * CCIMObjectPath *shareOP - An objectpath which represents the class to
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
cp_execQuery_Solaris_NFSShare(CCIMObjectPath *shareOP, char *electClause,
    char *nonJoinExp, char *queryExp, char *queryLang)
{

	CCIMInstance *emptyInst;
	CCIMInstanceList *nfsShareInstList;
	CCIMException *ex;
	int err = 0;

	if (shareOP == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	if ((nfsShareInstList =
	    cp_enumInstances_Solaris_NFSShare(shareOP)) == NULL) {
		util_handleError("SOLARIS_NFSSHARE::EXEC_QUERY",
		    CIM_ERR_FAILED, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	if ((emptyInst = cim_createInstance("")) == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARE::EXEC_QUERY",
		    CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(nfsShareInstList);
		return ((CCIMInstanceList *)NULL);
	}

	if ((nfsShareInstList =
	    cim_prependInstance(nfsShareInstList, emptyInst)) == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARE::EXEC_QUERY",
		    CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		cim_freeInstanceList(nfsShareInstList);
		return ((CCIMInstanceList *)NULL);
	}
	return (nfsShareInstList);
} /* cp_execQuery_Solaris_NFSShare */

/*
 * Property provider methods
 */
CCIMProperty *
cp_getProperty_Solaris_NFSShare(CCIMObjectPath *pOP, cimchar *pPropName)
{
	CCIMInstance *nfsShareInst;
	CCIMProperty *nfsShareProp;
	int err = 0;

	if (pOP == NULL || pPropName == NULL) {
		util_handleError("SOLARIS_NFSSHARE::GET_PROPERTY",
		    CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	if ((nfsShareInst = cp_getInstance_Solaris_NFSShare(pOP)) == NULL) {
		return ((CCIMProperty *)NULL);
	}

	nfsShareProp = cim_getProperty(nfsShareInst, pPropName);
	cim_freeInstance(nfsShareInst);
	return (nfsShareProp);
} /* cp_getProperty_Solaris_NFSShare */

/*
 * Not supported
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_NFShare(CCIMObjectPath *pOP, CCIMProperty *pProp)
{
	int err = 0;

	util_handleError("SOLARIS_NFSSHARE::SET_PROPERTY",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return (cim_false);
} /* cp_setProperty_Solaris_NFShare */

/*
 * Private Methods
 */

/*
 * Checks for a persistent share entry for the current share.
 */
CIMBool
check_for_PersistentShareEnt(fs_sharelist_t *nfs_sharelist, int *err)
{
	CCIMException		*ex;
	CCIMObjectPath 		*nfsPersistentShareOP;
	CCIMObjectPathList	*nfsPersistShareOPList;
	CCIMObjectPathList	*tmpOPList;
	CIMBool			nfsPersistValue = cim_false;

	nfsPersistentShareOP = cim_createEmptyObjectPath(SOLARIS_PERSISTSHARE);
	if (nfsPersistentShareOP == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHARE::POPULATE_PROPLIST",
		    CIM_ERR_FAILED, CREATE_EMPTY_OBJPATH_FAILURE, ex, err);
	} else {
		nfsPersistShareOPList = cimom_enumerateInstanceNames(
		    nfsPersistentShareOP, cim_false);
		if (nfsPersistShareOPList != NULL) {
			CCIMProperty	*nfsPersistShareProp;
			tmpOPList = nfsPersistShareOPList;
			while (tmpOPList != NULL) {
				nfsPersistentShareOP = tmpOPList->mDataObject;
				tmpOPList = tmpOPList->mNext;
				nfsPersistShareProp = cp_getProperty(
				    nfsPersistentShareOP, SETTING_ID);
				if (nfsPersistShareProp == NULL) {
					cim_freeObjectPath(
					    nfsPersistentShareOP);
					cim_freeProperty(nfsPersistShareProp);
					continue;
				}
				if (strcmp(nfs_sharelist->path,
				    nfsPersistShareProp->mValue) == 0) {
					nfsPersistValue = cim_true;
					cim_freeObjectPath(
					    nfsPersistentShareOP);
					cim_freeProperty(nfsPersistShareProp);
					break;
				}
				cim_freeObjectPath(nfsPersistentShareOP);
				cim_freeProperty(nfsPersistShareProp);
			}
		} else {
			ex = cim_getLastError();
			util_handleError(
			    "SOLARIS_NFSSHARE::",
			    CIM_ERR_FAILED, CIMOM_ENUM_INSTNAMES_FAILURE,
			    ex, err);
		}
	}
	return (nfsPersistValue);
} /* check_for_PersistentShareEnt */

/*
 * Enumerate the nfs shares by using the fs_shares fs_get_share_list
 * method
 */
static CCIMInstanceList *
enumerate_shares()
{

	CCIMException		*ex;
	CCIMInstanceList	*nfsShareInstList;
	int			err = 0;
	fs_sharelist_t		*nfs_share_list;
	fs_sharelist_t		*tmp_nfs_share_list;
	char			*hostname;

	/*
	 * retrieve system name
	 */
	hostname = sys_get_hostname(&err);
	if (err != 0 || hostname == NULL || strcmp(hostname, "unknown") == 0) {
		util_handleError(
		    "SOLARIS_NFSSHARE::POPULATE_PROPVALUES",
		    CIM_ERR_FAILED, GET_HOSTNAME_FAILURE, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfs_share_list = fs_get_share_list(&err);
	if (nfs_share_list == NULL) {
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
				    "SOLARIS_NFSSHARE::ENUMERATE_SHARES",
				    CIM_ERR_LOW_ON_MEMORY,
				    FS_GET_SHARE_FAILURE, NULL, &err);
				free(hostname);
				return ((CCIMInstanceList *)NULL);
			} else if (err == ENOENT) {
				util_handleError(
				    "SOLARIS_NFSSHARE::ENUMERATE_SHARES",
				    CIM_ERR_FAILED, NO_SHARES_ON_SYSTEM, NULL,
				    &err);
				free(hostname);
				/*
				 * We don't have any nfs shares
				 */
				cim_logDebug("enumerate_shares",
				    "There are no shares on the host.");
				return ((CCIMInstanceList *)NULL);
			} else {
				/*
				 * If any other errors were encountered it
				 * can be handled as a general error. We may
				 * not know exactly what the error is.
				 */
				util_handleError(
				    "SOLARIS_NFSSHARE::enumerate_shares",
				    CIM_ERR_FAILED, FS_GET_SHARE_FAILURE,
				    NULL, &err);
				free(hostname);
				return ((CCIMInstanceList *)NULL);
			}
		}
		return ((CCIMInstanceList *)NULL);
	} else {
		/*
		 * At this point, one or more nfs shares were found on the
		 * system, create the instance list from the nfs_share_list.
		 */

		cim_logDebug("enumerate_shares",
		    "There were shares found on the system.");
		nfsShareInstList = cim_createInstanceList();
		if (nfsShareInstList == NULL) {
			ex = cim_getLastError();
			util_handleError("SOLARIS_NFSSHARE::enumerate_shares",
			    CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE,
			    ex, &err);
			fs_free_share_list(nfs_share_list);
			free(hostname);
			return ((CCIMInstanceList *)NULL);
		}

		tmp_nfs_share_list = nfs_share_list;

		/*
		 * Loop through the nfs shares to retrieve their properties
		 * and create an instance list containing all the shares and
		 * their properties.
		 */
		while (nfs_share_list != NULL) {
			CCIMInstance 	*solaris_NFSShare_instance;
			CCIMPropertyList	*solaris_NFSShare_prop_list;

			/*
			 * Create the Solaris_NFSShare CCIMInstance
			 */
			solaris_NFSShare_instance =
				cim_createInstance(SOLARIS_NFSSHARE);
			if (solaris_NFSShare_instance == NULL) {
				ex = cim_getLastError();
				util_handleError(
				    "SOLARIS_NFSSHARE::enumerate_shares",
				    CIM_ERR_FAILED, GET_INSTANCE_FAILURE,
				    ex, &err);
				cim_freeInstanceList(nfsShareInstList);
				fs_free_share_list(tmp_nfs_share_list);
				free(hostname);
				return ((CCIMInstanceList *)NULL);
			}

			solaris_NFSShare_prop_list =
			    populate_Solaris_NFSShare_property_list(
			    hostname, nfs_share_list);
			if (solaris_NFSShare_prop_list == NULL) {
				/*
				 * populatePropertyList already logged this
				 * error so there is no need to log it here.
				 */
				cim_freeInstanceList(nfsShareInstList);
				cim_freeInstance(solaris_NFSShare_instance);
				fs_free_share_list(tmp_nfs_share_list);
				free(hostname);
				return ((CCIMInstanceList *)NULL);
			}

			/*
			 * Add the property list to the instance
			 */
			solaris_NFSShare_instance =
			    cim_addPropertyListToInstance(
				solaris_NFSShare_instance,
				solaris_NFSShare_prop_list);
			if (solaris_NFSShare_instance == NULL) {
				ex = cim_getLastError();
				util_handleError(
				    "SOLARIS_NFSSHARE::enumerate_shares",
				    CIM_ERR_FAILED,
				    PROPLIST_TO_INSTANCE_FAILURE, ex, &err);
				fs_free_share_list(tmp_nfs_share_list);
				cim_freeInstanceList(nfsShareInstList);
				cim_freePropertyList(
				    solaris_NFSShare_prop_list);
				free(hostname);
				return ((CCIMInstanceList *)NULL);
			}


			/*
			 * Add the instance to the instance list
			 */
			nfsShareInstList = cim_addInstance(nfsShareInstList,
			    solaris_NFSShare_instance);
			if (nfsShareInstList == NULL) {
				ex = cim_getLastError();
				util_handleError(
				    "SOLARIS_NFSSHARE::enumerate_shares",
				    CIM_ERR_FAILED, ADD_INSTANCE_FAILURE,
				    ex, &err);
				fs_free_share_list(tmp_nfs_share_list);
				cim_freeInstanceList(nfsShareInstList);
				free(hostname);
				return ((CCIMInstanceList *)NULL);
			}
			nfs_share_list = nfs_share_list->next;
		} /* while (nfs_share_list != NULL) */

		fs_free_share_list(tmp_nfs_share_list);
	} /* if (nfs_share_list == NULL) */

	free(hostname);
	return (nfsShareInstList);
} /* enumerate_shares() */

/*
 * Populates the property list with that share information for each
 * instance in the instance list.
 */
/* ARGSUSED */
static CCIMPropertyList *
populate_Solaris_NFSShare_property_list(
    char *hostname, fs_sharelist_t *nfs_sharelist)
{

	CCIMException		*ex;
	CCIMPropertyList	*nfsSharePropList;
	char			propValues[PROPCOUNT][MAXSIZE];
	int			i, err = 0;

	cim_logDebug("populate_Solaris_NFSShare_property_list",
	    "Just entering...");

	nfsSharePropList = cim_createPropertyList();
	if (nfsSharePropList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHARE::POPULATE_PROPLIST",
		    CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE, ex, &err);
		return ((CCIMPropertyList *)NULL);
	}

	/*
	 * Create the CCIMProperties for this instance
	 */
	if (!populate_Solaris_NFSShare_property_Values(hostname,
	    nfs_sharelist, propValues, &err)) {
		util_handleError(
		    "SOLARIS_NFSSHARE::POPULATE_PROPLIST",
		    CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE, NULL, &err);
		return ((CCIMPropertyList *)NULL);
	}
	for (i = 0; i < PROPCOUNT; i++) {
		cim_logDebug("populate_Solaris_NFSShare_property_list",
		    "propValues[%d] = %s", i, propValues[i]);
		nfsSharePropList = add_property_to_list(nfsShareProps[i].name,
		    nfsShareProps[i].type, propValues[i], NULL,
		    nfsShareProps[i].isKey, nfsSharePropList);
		if (nfsSharePropList == NULL) {
			break;
		}
	}
	return (nfsSharePropList);

} /* populate_Solaris_NFSShare_property_list */

/*
 * populate_Solaris_NFSShare_property_Values
 * Populates the property array for use in the populate_property_list function
 */
static CIMBool
populate_Solaris_NFSShare_property_Values(
    char *hostname,
    fs_sharelist_t *nfs_sharelist,
    cimchar propValues[PROPCOUNT][MAXSIZE],
    int *err)
{

	CIMBool			nfsPersistValue = cim_false;
	boolean_t		hasEquals;
	int			defaultValue = 0;
	char			*optValue;


	cim_logDebug("populate_Solaris_NFSShare_property_Values",
	    "Just entering...");
	/*
	 * Allow access control
	 */
	hasEquals = B_FALSE;
	optValue = get_property_from_opt_string(nfs_sharelist->options,
	    "aclok", hasEquals, defaultValue);
	if (optValue != NULL) {
		(void) snprintf(propValues[ALLOWACCESSCONTROL], MAXSIZE, "%s",
		    optValue);
		free(optValue);
	} else {
		return (cim_false);
	}
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[ALLOWACCESSCONTROL].name,
	    propValues[ALLOWACCESSCONTROL]);

	/*
	 * Key - creation class name
	 */
	(void) snprintf(propValues[CREATIONCLASSNAME], MAXSIZE, "%s",
	    SOLARIS_NFSSHARE);
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[CREATIONCLASSNAME].name,
	    propValues[CREATIONCLASSNAME]);

	/*
	 * Description
	 */
	if (nfs_sharelist->description != NULL) {
		(void) snprintf(propValues[DESCRIPTION], MAXSIZE, "%s",
		    nfs_sharelist->description);
	} else {
		(void) snprintf(propValues[DESCRIPTION], MAXSIZE, "\0");
	}

	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[DESCRIPTION].name,
	    propValues[DESCRIPTION]);
	/*
	 * Effective user ID "anon"
	 */
	hasEquals = B_TRUE;
	defaultValue = UID_NOBODY;
	optValue = get_property_from_opt_string(nfs_sharelist->options,
	    "anon=", hasEquals, defaultValue);
	if (optValue != NULL) {
		(void) snprintf(propValues[EFFECTIVEUID], MAXSIZE, "%s",
		    optValue);
		free(optValue);
	} else {
		return (cim_false);
	}
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[EFFECTIVEUID].name,
	    propValues[EFFECTIVEUID]);

	/*
	 * Ignore setuid "nosuid"
	 */
	hasEquals = B_FALSE;
	defaultValue = B_FALSE;
	optValue = get_property_from_opt_string(nfs_sharelist->options,
	    "nosuid", hasEquals, defaultValue);
	if (optValue != NULL) {
		(void) snprintf(propValues[IGNORESETID], MAXSIZE, "%s",
		    optValue);
		free(optValue);
	} else {
		return (cim_false);
	}
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[IGNORESETID].name,
	    propValues[IGNORESETID]);

	/*
	 * Enable logging, use log file tag "log"
	 */
	hasEquals = B_FALSE;
	defaultValue = B_FALSE;
	optValue = get_property_from_opt_string(nfs_sharelist->options,
	    "log", hasEquals, defaultValue);
	if (optValue != NULL) {
		if (strcmp(optValue, "1") == 0) {
			(void) strlcpy(propValues[LOGFILETAG], "global",
			    MAXSIZE);
			free(optValue);
		} else {
			free(optValue);
			hasEquals = B_TRUE;
			optValue = get_property_from_opt_string(
			    nfs_sharelist->options,
			    "log=", hasEquals, defaultValue);
			if (strcmp(optValue, "0") == 0) {
				/*
				 * Logging not enabled
				 */
				(void) snprintf(propValues[LOGFILETAG],
				    MAXSIZE, "%s", "\0");
				cim_logDebug(
				    "populate_Solaris_NFSShare_property_Values",
				    "No log property for this share");
			} else {
				(void) snprintf(propValues[LOGFILETAG],
				    MAXSIZE, "%s", optValue);
			}
			free(optValue);
		}
	} else {
		return (cim_false);
	}
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[LOGFILETAG].name,
	    propValues[LOGFILETAG]);

	/*
	 * Key - Shared Path
	 */
	(void) snprintf(propValues[SHAREDNAME], MAXSIZE, "%s",
	    nfs_sharelist->path);
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[SHAREDNAME].name,
	    propValues[SHAREDNAME]);

	/*
	 * Persistent share entry
	 */
	nfsPersistValue = check_for_PersistentShareEnt(nfs_sharelist, err);
	(void) snprintf(propValues[PERSISTENT], MAXSIZE, "%d", nfsPersistValue);
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[PERSISTENT].name, propValues[PERSISTENT]);

	/*
	 * No subdirectory mounts "nosub"
	 */
	hasEquals = B_FALSE;
	defaultValue = B_FALSE;
	optValue = get_property_from_opt_string(nfs_sharelist->options,
	    "nosub", hasEquals, defaultValue);
	if (optValue != NULL) {
		(void) snprintf(propValues[PREVENTSUBDIRMOUNT], MAXSIZE, "%s",
		    optValue);
		free(optValue);
	} else {
		return (cim_false);
	}
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[PREVENTSUBDIRMOUNT].name,
	    propValues[PREVENTSUBDIRMOUNT]);

	/*
	 * Public filehandle "public"
	 */
	hasEquals = B_FALSE;
	defaultValue = B_FALSE;
	optValue = get_property_from_opt_string(nfs_sharelist->options,
	    "public", hasEquals, defaultValue);
	if (optValue != NULL) {
	(void) snprintf(propValues[PUBLIC], MAXSIZE, "%s", optValue);
	free(optValue);
	} else {
		return (cim_false);
	}
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[PUBLIC].name, propValues[PUBLIC]);

	/*
	 * Share option string
	 */
	(void) snprintf(propValues[SHAREOPTS], MAXSIZE, "%s",
	    nfs_sharelist->options);
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[SHAREOPTS].name, propValues[SHAREOPTS]);

	/*
	 * Key - System Creation class name
	 */
	(void) snprintf(propValues[SYSTEMCREATIONCLASSNAME], MAXSIZE, "%s",
	    SOLARIS_CS);
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[SYSTEMCREATIONCLASSNAME].name,
	    propValues[SYSTEMCREATIONCLASSNAME]);

	/*
	 * Key - System name
	 */
	(void) snprintf(propValues[SYSTEMNAME], MAXSIZE, "%s",
	    hostname);
	cim_logDebug("populate_Solaris_NFSShare_property_Values", "%s= %s",
	    nfsShareProps[SYSTEMNAME].name, propValues[SYSTEMNAME]);

	return (cim_true);

} /* populate_Solaris_NFSShare_property_Values */

/*
 * start_daemons
 *
 * Starts the nfsd and mountd daemons based on which daemon is requested
 * in which_daemon. The string returned from the execution of the damon
 * command is returned.
 */
static char *
start_daemons(int which_daemon, int *err)
{
	FILE *fd;
	pid_t pid;
	char *pidfile;
	char *cmd_return = NULL;
	char *cmd = NULL;
	char pid_str[MAXSIZE];
	int pid_kill = 0;

	switch (which_daemon) {
		case NFSD:
			pidfile = "/etc/svc/volatile/nfs-server.lock";
			cmd = "/usr/lib/nfs/nfsd";
			break;

		case MOUNTD:
			pidfile = "/etc/svc/volatile/nfs-mountd.lock";
			cmd = "/usr/lib/nfs/mountd";
			break;

		default:
			cim_logDebug("start_daemons", "Invalid command");
			*err = EINVAL;
			return (NULL);
	}

	if ((fd = fopen(pidfile, "r")) == NULL) {
		*err = errno;
		if (*err == ENOENT) {
			*err = 0;
			cmd_return =
			    cmd_execute_command_and_retrieve_string(cmd,
			    err);
			return (cmd_return);
		} else {
			return (cmd_return);
		}
	}
	if (fgets(pid_str, MAXSIZE, fd) == NULL) {
		*err = errno;
		(void) fclose(fd);
		cim_logDebug("start_daemons",
		    "Can not read from file %s - %s\n",
		    pidfile, strerror(*err));
		return (NULL);
	}

	(void) fclose(fd);
	pid = (pid_t)strtoll(pid_str, NULL, 0);
	pid_kill = kill(pid, 0);
	*err = errno;
	if (pid_kill == 0) {
		/*
		 * Setting error to EEXIST so that the error returned
		 * tells the caller that the daemon already exists.
		 */
		*err = EEXIST;
		cim_logDebug("start_daemon",
		    "Terminated - nfsd(%ld) already running.\n", pid);
	} else if (*err == ESRCH) {
		/*
		 * ESRCH indicates that there is no such process and
		 * the daemon needs to be started.
		 */
		*err = 0;
		cmd_return =
		    cmd_execute_command_and_retrieve_string(cmd, err);
	} else {
		cim_logDebug("start_daemon",
		    "Unknown error starting %s (%ld)", cmd, pid);
	}
	return (cmd_return);
} /* start_daemons */
