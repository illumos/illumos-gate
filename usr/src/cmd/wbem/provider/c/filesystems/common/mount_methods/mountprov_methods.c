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

#include "mountprov_methods.h"
#include "nfsprov_methods.h"
#include "util.h"
#include "libfsmgt.h"
#include "nfs_providers_msgstrings.h"
#include "nfs_provider_names.h"
#include <errno.h>

#define	SHOWEXPORTS "/usr/sbin/showmount -e "

/*
 * Private methods
 */
static char **create_export_array(char *exportList_in_string_form,
	int *num_elements, int *errp);

/*
 * Public methods
 */
/*
 * Method: delete_vfstab_entry
 *
 * Description: Deletes the /etc/vfstab entry with the corresponding resource
 * and mount point as passed in with inParams.
 *
 * Parameters:
 *	- CCIMPropertyList *inParams - The input parameters to the method.
 *	The property list is expected to contain two elements in the following
 *	order:
 *	1.) string resource - the resource that is listed in the device to
 *	mount column of /etc/vfstab.  Example: /dev/dsk/c0t0d0s5
 *	2.) string mount point
 *
 * Returns:
 *	- CCIMProperty * - A value telling the success or failure of the method.
 */
CCIMProperty *
delete_vfstab_entry(CCIMPropertyList *inParams) {
	fs_mntdefaults_t	*vfstabEnts, *vfstabEntToDelete;
	CCIMPropertyList	*currentParam;
	CCIMProperty		*resourceProp;
	CCIMProperty		*mountPointProp;
	char			*resource;
	char			*mountPoint;
	int			err = 0;

	if (inParams == NULL) {
		util_handleError(DELETE_VFSTAB_ENT, CIM_ERR_INVALID_PARAMETER,
			NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	/*
	 * The inParams are expected to contain two elements in this order:
	 * 1.) string resource
	 * 2.) string mountPoint
	 */
	currentParam = inParams;

	resourceProp = currentParam->mDataObject;
	if (resourceProp == NULL || resourceProp->mValue == NULL) {
		util_handleError(DELETE_VFSTAB_ENT, CIM_ERR_INVALID_PARAMETER,
			NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	resource = resourceProp->mValue;

	currentParam = currentParam->mNext;

	mountPointProp = currentParam->mDataObject;
	if (mountPointProp == NULL || mountPointProp->mValue == NULL) {
		util_handleError(DELETE_VFSTAB_ENT, CIM_ERR_INVALID_PARAMETER,
			NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	mountPoint = mountPointProp->mValue;

	vfstabEntToDelete = calloc(1, sizeof (fs_mntdefaults_t));

	vfstabEntToDelete->resource = strdup(resource);
	vfstabEntToDelete->mountp = strdup(mountPoint);

	vfstabEnts = fs_del_mount_default_ent(vfstabEntToDelete, &err);
	if (vfstabEnts == NULL) {
		util_handleError(DELETE_VFSTAB_ENT, CIM_ERR_FAILED,
			FS_DEL_MNT_DEFAULT_FAILURE, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	cim_logDebug("delete_vfstab_entry", "After fs_del_mount_default_ent");
	fs_free_mntdefaults_list(vfstabEnts);
	fs_free_mntdefaults_list(vfstabEntToDelete);
	return (cim_createProperty("Status", sint32, "0", NULL, cim_false));
} /* delete_vfstab_entry */

/*
 * Method: show_exports
 *
 * Description: Shows the list of shared file systems on a certain host by
 * executing the showmount command.
 *
 * Parameters:
 *	- CCIMPropertyList *inParams - The input parameters to the method.
 *	The property list is expected to contain one element, a string value
 *	representing the host to show exports on.
 *	- CCIMPropertyList *outParams - The output of the showmount command.
 *
 * Returns:
 *	- CCIMProperty * - A value telling the success or failure of the method.
 *
 * NOTE: This is a deprecated method, but is supported until the EOL process
 * is done.  That date is TBD.
 */
CCIMProperty *
show_exports(CCIMPropertyList *inParams, CCIMPropertyList *outParams) {
	CCIMProperty	*hostProp;
	char		*showExportsCommand;
	char		*cmd_return;
	char		*host;
	int		commandLen;
	int		err = 0;

	if (inParams == NULL) {
		util_handleError(SHOW_EXPORTS, CIM_ERR_INVALID_PARAMETER,
			NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	/*
	 * The inParams are expected to contain one element being:
	 * 1.) string host
	 */
	hostProp = inParams->mDataObject;
	if (hostProp == NULL || hostProp->mValue == NULL) {
		util_handleError(SHOW_EXPORTS, CIM_ERR_INVALID_PARAMETER,
			NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	host = hostProp->mValue;

	commandLen = strlen(SHOWEXPORTS) + strlen(host) + 1;

	showExportsCommand = calloc(commandLen, sizeof (char));
	if (showExportsCommand == NULL) {
		util_handleError(SHOW_EXPORTS, CIM_ERR_LOW_ON_MEMORY,
			NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	(void) snprintf(showExportsCommand, commandLen, "%s%s", SHOWEXPORTS,
	    host);
	cmd_return = cmd_execute_command_and_retrieve_string(showExportsCommand,
		&err);
	if (err != 0) {
		cim_logDebug(SHOW_EXPORTS, "err =%d", err);
		outParams = NULL;
		if (cmd_return != NULL) {
			cim_logDebug(SHOW_EXPORTS, "Command return =%s",
				cmd_return);
			util_handleError(SHOW_EXPORTS, CIM_ERR_FAILED,
				cmd_return, NULL, &err);
			free(cmd_return);
		} else {
			util_handleError(SHOW_EXPORTS, CIM_ERR_FAILED,
				CMD_EXEC_RETR_STR_FAILURE, NULL, &err);
		}

		free(showExportsCommand);
		return ((CCIMProperty *)NULL);
	}

	if (cmd_return != NULL) {
		char	**export_array;
		int	num_elements = 0;

		cim_logDebug("show_exports", "Output =%s", cmd_return);

		export_array = create_export_array(cmd_return, &num_elements,
			&err);
		if (export_array == NULL) {
			cim_logDebug("show_exports", "export_array == NULL");
			if (err != 0) {
				util_handleError(SHOW_EXPORTS,
					CIM_ERR_LOW_ON_MEMORY, NULL, NULL,
					&err);
			}
			return ((CCIMProperty *)NULL);
		}

		create_outParams_list(outParams, export_array, num_elements,
			NULL);
		fileutil_free_string_array(export_array, num_elements);
	}

	free(showExportsCommand);
	return (cim_createProperty("Status", sint32, "0", NULL, cim_false));
} /* show_exports */


/*
 * Private methods
 */

/*
 * Method: create_export_array
 *
 * Description: Creates an array from the export list given in string form.
 *
 * Parameters:
 *	- char *exportList_in_string_form - The export list from the showmount
 *	command.
 *	- int *num_elements - The element counter which keeps track of the
 *	number of elements returned in the string array.
 *	- int *errp - The error pointer which gets set upon error.
 *
 * Returns:
 *	- char ** - The string array containing the individual elements from
 *	the showmount export list.
 *	- NULL if an error occurred.
 */
static char **
create_export_array(char *exportList_in_string_form, int *num_elements,
	int *errp) {

	char	*endOfLine = "\n";
	char	*export;
	char	*listCopy;
	char	**export_array = NULL;
	int	i = 0;


	listCopy = strdup(exportList_in_string_form);
	if (listCopy == NULL) {
		*errp = errno;
		*num_elements = 0;
		return (NULL);
	}

	/*
	 * Ignore the first line.  It is a header that is always printed out
	 * when using showmounts -e.
	 */
	export = strtok(listCopy, endOfLine);

	/*
	 * Count the number of elements to be in the array.
	 */
	*num_elements = 0;
	for (export = strtok(NULL, endOfLine); export != NULL;
		export = strtok(NULL, endOfLine)) {
		*num_elements = *num_elements + 1;
	}

	export_array = calloc((size_t)*num_elements, (size_t)sizeof (char *));
	if (export_array == NULL) {
		*errp = errno;
		*num_elements = 0;
		free(listCopy);
		return (NULL);
	}

	free(listCopy);
	listCopy = strdup(exportList_in_string_form);
	if (listCopy == NULL) {
		*errp = errno;
		*num_elements = 0;
		fileutil_free_string_array(export_array, *num_elements);
		return (NULL);
	}

	export = strtok(listCopy, endOfLine);

	for (i = 0; i < *num_elements; i++) {

		export = strtok(NULL, endOfLine);

		if (export != NULL) {
			export_array[i] = strdup(export);
			if (export_array[i] == NULL) {
				*errp = errno;
				free(listCopy);
				fileutil_free_string_array(export_array,
					*num_elements);
				*num_elements = 0;
				return (NULL);
			}
		}
	}

	free(listCopy);
	return (export_array);
} /* create_export_array */
