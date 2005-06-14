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

#include "nfsprov_methods.h"
#include "util.h"
#include "libfsmgt.h"
#include "util.h"
#include "cmdgen.h"
#include "nfs_providers_msgstrings.h"
#include "messageStrings.h"
#include "nfs_provider_names.h"
#include <sys/types.h>

CCIMProperty *exec_command(char *cmd);

/*
 * Public methods
 */

/*
 * Method: create_outParams_list
 *
 * Description: Creates a string or a string array property to be added to the
 * passed in CCIMPropertyList*, outParams.
 *
 * Parameters:
 *	- CCIMPropertyList *outParams - The property list to add the string
 *	array property to.
 *	- char **list - The string array to add to outParams.
 *	- int num_elements - The number of elements in list.
 *	- char *single_value - The string to add to outParams.
 *
 * Returns:
 *	- Nothing
 */
void
create_outParams_list(CCIMPropertyList *outParams, char **list,
	int num_elements, char *single_value) {

	CCIMProperty		*prop = NULL;
	CCIMException		*ex;
	cimchar			*outParamValues;
	int			err = 0;

	if (list != NULL) {
		/*
		 * cim_encodeStringArray converts an array or strings into a
		 * regular string for placement into the CCIMProperty.
		 */
		outParamValues = cim_encodeStringArray(list, num_elements);
		if (outParamValues == NULL) {
			ex = cim_getLastError();
			util_handleError(CREATE_OUT_PARAMS, CIM_ERR_FAILED,
				ENCODE_STRING_ARRAY_FAILURE, ex, &err);
			outParams = NULL;
			return;
		}
		prop = cim_createProperty("outParams", string_array,
			outParamValues, NULL, cim_false);
	} else if (single_value != NULL) {
		prop = cim_createProperty("outParams", string, single_value,
			NULL, cim_false);
	}

	if (prop == NULL) {
		ex = cim_getLastError();
		util_handleError(CREATE_OUT_PARAMS, CIM_ERR_FAILED,
			CREATE_PROPERTY_FAILURE, ex, &err);
		outParams = NULL;
		free(outParamValues);
		return;
	}

	outParams = cim_addPropertyToPropertyList(outParams, prop);
	if (outParams == NULL) {
		ex = cim_getLastError();
		util_handleError(CREATE_OUT_PARAMS, CIM_ERR_FAILED,
			ADD_PROP_TO_PROPLIST_FAILURE, ex, &err);
		return;
	}

} /* create_outParams_list */

/*
 * Method: del_all_with_duplicate_path
 *
 * Description: Deletes all /etc/dfs/dfstab entries having the same path as
 * defined with the passed in parameter list.
 *
 * Parameters:
 *	- CCIMPropertyList *inParams - The input parameter list containing
 *	the path of the /etc/dfs/dfstab entries to delete.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 */
CCIMProperty *
del_all_with_duplicate_path(CCIMPropertyList *inParams) {
	int		err = 0;
	CCIMProperty	*pathProp;
	char		*path;

	if (inParams == NULL) {
		util_handleError(DELETE_DUP_PATHS, CIM_ERR_INVALID_PARAMETER,
			NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	pathProp = inParams->mDataObject;
	if (pathProp == NULL) {
		util_handleError(DELETE_DUP_PATHS, CIM_ERR_INVALID_PARAMETER,
			DEL_DUPLICATE_PATHS_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	path = pathProp->mValue;

	if (fs_del_All_DFStab_ents_with_Path(path, &err) == NULL) {
		if (err != 0) {
			util_handleError(DELETE_DUP_PATHS, CIM_ERR_FAILED,
				DEL_DUPLICATE_PATHS_FAILURE, NULL, &err);
			return ((CCIMProperty *)NULL);
		}
	}
	return (cim_createProperty("Status", sint32, "0", NULL, cim_false));
}

/*
 * Method: get_default_secmode
 *
 * Description: Retrieves the default security mode for the system and places
 * it in the passed in outParams property list.
 *
 * Parameters:
 *	- CCIMPropertyList *outParams - The property list for which to add the
 *	security mode property.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 */
CCIMProperty *
get_default_secmode(CCIMPropertyList *outParams) {
	char    *defmode;
	int	err = 0;

	defmode = nfssec_get_default_secmode(&err);
	if (defmode == NULL) {
		util_handleError(GET_DEF_SECMODE, CIM_ERR_FAILED,
			GET_DEFAULT_SECMODE_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	create_outParams_list(outParams, NULL, NULL, defmode);
	if (outParams == NULL) {
		/*
		 * An error occurred in create_outParams_list.
		 */
		free(defmode);
		return ((CCIMProperty *)NULL);
	}

	free(defmode);
	return (cim_createProperty("Status", sint32, "0", NULL, cim_false));
} /* get_default_secmode */

/*
 * Method: get_netconfig_list
 *
 * Description: Retrieves the network id list from /etc/netconfig and places
 * it in the passed in outParams property list.
 *
 * Parameters:
 *	- CCIMPropertyList *outParams - The property list for which to add the
 *	network id list.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 */
CCIMProperty *
get_netconfig_list(CCIMPropertyList *outParams) {
	char    **netid_list;
	int	num_elements = 0;
	int	err = 0;

	netid_list = netcfg_get_networkid_list(&num_elements, &err);
	if (netid_list == NULL) {
		util_handleError(GET_NETCFG_LIST, CIM_ERR_FAILED,
			GET_NETID_LIST_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	create_outParams_list(outParams, netid_list, num_elements, NULL);
	netcfg_free_networkid_list(netid_list, num_elements);
	if (outParams == NULL) {
		/*
		 * An error occurred in create_outParams_list.  It was
		 * handled in that function so just return NULL.
		 */
		return ((CCIMProperty *)NULL);
	}

	return (cim_createProperty("Status", sint32, "0", NULL,
		cim_false));
} /* get_netconfig_list */

/*
 * Method: get_nfssec_list
 *
 * Description: Retrieves the list of nfs security modes from /etc/nfssec.conf
 * and places it in the passed in outParams property list.
 *
 * Parameters:
 *	- CCIMPropertyList *outParams - The property list for which to add the
 *	nfs security modes list.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 */
CCIMProperty *
get_nfssec_list(CCIMPropertyList *outParams) {
	char    **secmode_list;
	int	num_elements = 0;
	int	err = 0;

	secmode_list = nfssec_get_nfs_secmode_list(&num_elements, &err);
	if (secmode_list == NULL) {
		util_handleError(GET_NFSSEC_LIST, CIM_ERR_FAILED,
			GET_SECMODE_LIST_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	create_outParams_list(outParams, secmode_list, num_elements, NULL);
	if (outParams == NULL) {
		/*
		 * An error occurred in create_outParams_list.
		 */
		nfssec_free_secmode_list(secmode_list, num_elements);
		return ((CCIMProperty *)NULL);
	}

	nfssec_free_secmode_list(secmode_list, num_elements);

	return (cim_createProperty("Status", sint32, "0", NULL, cim_false));

} /* get_nfssec_list */

/*
 * Method: mountall
 *
 * Description: Executes the mountall command with the options given in the
 * inParams property list.
 *
 * Parameters:
 *	- CCIMPropertyList *inParams - The property list containing the options
 *	to be used when executing the mountall command.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 */
CCIMProperty *
mountall(CCIMPropertyList *inParams) {
	CCIMProperty	*retVal;
	char		*cmd = NULL;
	int		err = 0;

	cmd = cmdgen_generate_command(CMDGEN_MOUNTALL, NULL, NULL, inParams,
		&err);
	if (cmd == NULL || err != 0) {
		cim_logDebug("mountall", "cmdgen_generate_command failed.");
		util_handleError(MOUNTALL_INVOKE_METH, CIM_ERR_FAILED,
			CMDGEN_GEN_CMD_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	cim_logDebug("mountall", "Command generated is: %s", cmd);

	retVal = exec_command(cmd);
	free(cmd);
	return (retVal);
} /* mountall */

/*
 * Method: shareall
 *
 * Description: Executes the shareall command with the options given in the
 * inParams property list.
 *
 * Parameters:
 *	- CCIMPropertyList *inParams - The property list containing the options
 *	to be used when executing the shareall command.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 */
CCIMProperty *
shareall(CCIMPropertyList *inParams) {
	CCIMProperty	*retVal;
	char		*cmd = NULL;
	int		err = 0;

	cmd = cmdgen_generate_command(CMDGEN_SHAREALL, NULL, NULL, inParams,
		&err);
	if (cmd == NULL || err != 0) {
		util_handleError(SHAREALL_INVOKE_METH, CIM_ERR_FAILED,
			CMDGEN_GEN_CMD_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	cim_logDebug("shareall", "Command returned: %s", cmd);

	retVal = exec_command(cmd);
	free(cmd);
	return (retVal);
} /* shareall */

/*
 * Method: unmountall
 *
 * Description: Executes the umountall command with the options given in the
 * inParams property list.
 *
 * Parameters:
 *	- CCIMPropertyList *inParams - The property list containing the options
 *	to be used when executing the umountall command.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 */
CCIMProperty *
unmountall(CCIMPropertyList *inParams) {
	CCIMProperty	*retVal;
	char		*cmd = NULL;
	int		err = 0;

	cmd = cmdgen_generate_command(CMDGEN_UMOUNTALL, NULL, NULL, inParams,
		&err);
	if (cmd == NULL || err != 0) {
		util_handleError(UNMOUNTALL_INVOKE_METH, CIM_ERR_FAILED,
			CMDGEN_GEN_CMD_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	cim_logDebug("unmountall", "Command returned: %s", cmd);

	retVal = exec_command(cmd);
	free(cmd);
	return (retVal);
} /* unmountall */

/*
 * Method: unshareall
 *
 * Description: Executes the unshareall command with the options given in the
 * inParams property list.
 *
 * Parameters:
 *	- CCIMPropertyList *inParams - The property list containing the options
 *	to be used when executing the unshareall command.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 */
CCIMProperty *
unshareall(CCIMPropertyList *inParams) {
	CCIMProperty	*retVal;
	char		*cmd = NULL;
	int		err = 0;

	cmd = cmdgen_generate_command(CMDGEN_UNSHAREALL, NULL, NULL, inParams,
		&err);
	if (cmd == NULL || err != 0) {
		util_handleError(UNSHAREALL_INVOKE_METH, CIM_ERR_FAILED,
			CMDGEN_GEN_CMD_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	cim_logDebug("unshareall", "Command returned: %s", cmd);

	retVal = exec_command(cmd);
	free(cmd);
	return (retVal);
} /* unshareall */

/*
 * Private Methods
 */

/*
 * Method: exec_command
 *
 * Description: Executes the given command, returns a success/failure property
 * and handles errors from the execution of the command if needed.
 *
 * Parameters:
 *	- char *cmd - The command to execute.
 *
 * Returns:
 *	- CCIMProperty * - A property defining the success or failure of the
 *	method.
 *	- NULL if an error occurred.
 */
CCIMProperty *
exec_command(char *cmd) {
	char	*cmd_return = NULL;
	int	err = 0;

	cmd_return = cmd_execute_command_and_retrieve_string(cmd, &err);
	if (err != 0) {
		if (cmd_return != NULL) {
			util_handleError(EXEC_CMD, CIM_ERR_FAILED,
				cmd_return, NULL, &err);
			free(cmd_return);
			return ((CCIMProperty *)NULL);
		} else {
			util_handleError(EXEC_CMD, CIM_ERR_FAILED,
				CMD_EXEC_RETR_STR_FAILURE, NULL, &err);
			return ((CCIMProperty *)NULL);
		}
	}

	if (cmd_return != NULL) {
		cim_logDebug("exec_command", "Exec command return =%s",
			cmd_return);
		free(cmd_return);
	}

	return (cim_createProperty("Status", sint32, "0", NULL, cim_false));
} /* exec_command */
