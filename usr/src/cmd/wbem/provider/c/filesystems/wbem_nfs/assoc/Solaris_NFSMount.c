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

#include "Solaris_NFSMount.h"
#include "nfs_keys.h"
#include "nfs_providers_msgstrings.h"
#include "messageStrings.h"
#include "nfs_provider_names.h"
#include "libfsmgt.h"
#include "cmdgen.h"
#include "util.h"
#include "nfsprov_methods.h"
#include "mountprov_methods.h"
#include "createprop_methods.h"
#include <sys/types.h>
#include <string.h>
#include <errno.h>

/*
 * Constants
 */
#define	DELETE_VFSTAB_ENT_METHOD "deleteVfstabEntry"
#define	GET_DEF_SECMODE_METHOD "getDefaultNfsSecMode"
#define	GET_NET_CFG_LIST_METHOD "getNetCfgList"
#define	GET_NFS_SEC_LIST_METHOD "getNfsSecList"
#define	SHOW_EXPORTS_METHOD "showExports"
/*
 * Private method declarations
 */

static CCIMInstanceList * create_nfsMount_associations(nfs_mntlist_t *mountList,
				int *errp);
static CCIMInstanceList * enumerate_mounts();
static CCIMObjectPath * get_Antecedent(cimchar *mount_point);
static CCIMInstanceList * get_associated_instances(nfs_mntlist_t *mountList,
				boolean_t resultIsAnt);
static nfs_mntlist_t *get_associated_nfs_mntlist(boolean_t isAntecedent,
			char *nameKeyValue);
static CCIMObjectPath * get_Dependent(nfs_mntlist_t *nfs_mount);
static char *get_devid(char *keyValue, int *errp);
static char *get_resource(char *keyValue, int *errp);
static CCIMPropertyList * populate_property_list(nfs_mntlist_t *nfs_mount);
static CIMBool populate_property_values(nfs_mntlist_t *nfs_mount,
		cimchar **propValues);

/*
 * Public methods
 */

/*
 * Instance provider methods
 */

/*
 * Method: cp_enumInstances_Solaris_NFSMount
 *
 * Description: Enumerates all of the nfs mounts on the host.  NFS mounts with
 * "ignore" in the option string are ignored.
 *
 * Parameters:
 *	- CCIMObjectPath* mountOP - The object path containing the name of the
 *	class to which the instance to be enumerated belongs.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFSMount instances.
 *	- NULL if an error occurred or if there are no NFS mounts on the host.
 *	In the case of an error, the error will be logged.
 */
CCIMInstanceList *
cp_enumInstances_Solaris_NFSMount(CCIMObjectPath* mountOP) {
	CCIMInstanceList *instList;
	int	err = 0;

	/*
	 * First check if the CCIMObjectPath passed in is null.
	 */
	if (mountOP == NULL) {
		util_handleError(
			"SOLARIS_NFSMOUNT::ENUM_INSTANCES",
			CIM_ERR_INVALID_PARAMETER, NULL,
			NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	instList = enumerate_mounts();
	if (instList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	return (instList);
} /* cp_enumInstances_Solaris_NFSMount */

/*
 * Method: cp_getInstance_Solaris_NFSMount
 *
 * Description: Gets the instance corresponding to the Solaris_NFSMount
 * object path passed in.
 *
 * Parameters:
 *	- CCIMObjectPath* mountOP - An object path containing all the keys of
 *	the instance that is supposed to be returned.
 *
 * Returns:
 *	- A pointer to the Solaris_NFSMount instance corresponding to the object
 *	path parameter.
 *	- NULL if an error occurred or if the instance doesn't exist.  In the
 *	case of an error, the error will be logged.
 */
CCIMInstance *
cp_getInstance_Solaris_NFSMount(CCIMObjectPath* mountOP) {
	CCIMInstanceList	*instList;
	CCIMInstance		*inst;
	CCIMPropertyList	*mountPropList;
	CCIMObjectPath		*antOP, *depOP;
	int			err;

	if (mountOP == NULL || mountOP->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	mountPropList = mountOP->mKeyProperties;
	depOP = util_getKeyValue(mountPropList, nfsMountProps[DEP].type,
		nfsMountProps[DEP].name, &err);
	antOP = util_getKeyValue(mountPropList, nfsMountProps[ANT].type,
		nfsMountProps[ANT].name, &err);

	if (depOP == NULL || antOP == NULL ||
		depOP->mKeyProperties == NULL ||
		antOP->mKeyProperties == NULL) {

		util_handleError("SOLARIS_NFSMOUNT::GET_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFSMount(mountOP);
	if (instList == NULL) {
		/*
		 * Either an error occurred or we simply don't have any
		 * instances of Solaris_NFSMount on the system.  In the case,
		 * that an error occurred, it will be handled in
		 * cp_enumInstances_Solaris_NFSMount.
		 */
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, mountOP);

	cim_freeInstanceList(instList);
	return (inst);
} /* cp_getInstance_Solaris_NFSMount */

/*
 * Method: cp_createInstance_Solaris_NFSMount
 *
 * Description:
 * Creates an instance of the Solaris_NFSMount class.
 * A create instance will actually mount a file system on the current host by
 * calling the cmd interface's cmd_execute_command_and_retrieve_string function.
 *
 * Parameters:
 *	- CCIMObjectPath* nfsOP - An object path containing the information
 *	needed about the class of which to have an instance created.
 *	- CCIMInstance* nfsInst - The instance to be created.
 *
 * Returns:
 *	- A pointer to a Solaris_NFSMount CCIMObjectPath which corresponds to
 *	the mount that was created.
 *	- Upon error, NULL is returned and the error will be logged.
 */
CCIMObjectPath *
cp_createInstance_Solaris_NFSMount(CCIMObjectPath* nfsOP,
	CCIMInstance* nfsInst) {

	char			*cmd_return = NULL;
	char			*cmd;
	char			*resource;
	char			*mountp;
	char			*mntoptsParam, *timeParam;
	boolean_t		findOverlayParam;
	int			err = 0;
	nfs_mntlist_t		*mount;
	CCIMObjectPath		*nfsMountOP = NULL;
	CCIMObjectPath		*opParam;
	CCIMPropertyList	*propListParam;
	CCIMInstanceList	*nfsMountInstList;
	CCIMInstanceList	*currentInst;
	CCIMProperty		*mnt_prop;
	CCIMException		*ex;

	/*
	 * First check if the CCIMInstance or CCIMObjectPath is null.
	 */
	if (nfsOP == NULL || nfsInst == NULL) {
		util_handleError(
			"SOLARIS_NFSMOUNT::CREATE_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPath *)NULL);
	}

	/*
	 * Get the properties from the instance parameter in order to create
	 * an instance as defined. The properties will be used to create a
	 * mount command to execute.
	 */

	/*
	 * The only properties required are resource and mount point.
	 * All other properties are not needed.  The defaults will be used.
	 */
	err = 0;
	opParam = NULL;
	propListParam = NULL;
	cmd = cmdgen_generate_command(CMDGEN_NFS_MOUNT, nfsInst, opParam,
		propListParam, &err);
	if (cmd == NULL || err != 0) {
		util_handleError("SOLARIS_NFSMOUNT::CREATE_INSTANCE",
			CIM_ERR_FAILED, CMDGEN_GEN_CMD_FAILURE, NULL, &err);
		return ((CCIMObjectPath *)NULL);
	}

	cim_logDebug("cp_createInstance_Solaris_NFSMount",
		"cmd =%s", cmd);
	err = 0;
	cmd_return = cmd_execute_command_and_retrieve_string(cmd, &err);
	if (err != 0) {
		cim_logDebug("cp_createInstance_Solaris_NFSMount",
			"cmd_return =%s", cmd_return);
		/*
		 * An error occurred in executing the command.
		 */
		if (cmd_return != NULL) {
			util_handleError("SOLARIS_NFSMOUNT::CREATE_INSTANCE",
				CIM_ERR_FAILED, CMD_EXEC_RETR_STR_FAILURE,
				NULL, &err);
			free(cmd);
			free(cmd_return);
			return ((CCIMObjectPath *)NULL);
		} else {
			util_handleError("SOLARIS_NFSMOUNT::CREATE_INSTANCE",
				CIM_ERR_FAILED, CMD_EXEC_RETR_STR_FAILURE,
				NULL, &err);
			free(cmd);
			return ((CCIMObjectPath *)NULL);
		}
	}

	free(cmd);
	if (cmd_return != NULL) {
		free(cmd_return);
	}

	/*
	 * It should be certain that the mount got created if the
	 * cmd_execute_command_and_retrieve_string function succeded, but we
	 * will do a second check to make sure it did and to get the devid.
	 * We can determine if the mount exists by checking for a mount having
	 * the same resource/mount point as the instance passed in.
	 */
	mnt_prop = cim_getProperty(nfsInst, nfsMountProps[ANT].name);
	if (mnt_prop != NULL) {
		CCIMPropertyList	*antPropList;

		antPropList = mnt_prop->mObjPathValue->mKeyProperties;

		mountp = util_getKeyValue(antPropList, string, NAME, &err);
		if (mountp == NULL || err != 0) {
			util_handleError("SOLARIS_NFSMOUNT::CREATE_INSTANCE",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMObjectPath *)NULL);
		}

		cim_freeProperty(mnt_prop);

	}

	mnt_prop = cim_getProperty(nfsInst, nfsMountProps[DEP].name);
	if (mnt_prop != NULL) {
		CCIMPropertyList	*depPropList;

		depPropList = mnt_prop->mObjPathValue->mKeyProperties;

		resource = util_getKeyValue(depPropList, string, NAME, &err);
		if (resource == NULL || err != 0) {
			util_handleError("SOLARIS_NFSMOUNT::CREATE_INSTANCE",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMObjectPath *)NULL);
		}

		cim_freeProperty(mnt_prop);
	}

	err = 0;
	mntoptsParam = NULL;
	timeParam = NULL;
	findOverlayParam = B_TRUE;
	mount = nfs_get_filtered_mount_list(resource, mountp, mntoptsParam,
		timeParam, findOverlayParam, &err);
	if (mount == NULL) {
		if (err != 0) {
			util_handleError("SOLARIS_NFSMOUNT::CREATE_INSTANCE",
				CIM_ERR_FAILED, NFS_GET_FILTERED_MOUNTS_FAILURE,
				NULL, &err);
		}
		cim_logDebug("cp_createInstance_Solaris_NFSMount",
			"Mount was not found w/ resource/mount point combo");
		/*
		 * There were no mounts found with the resource and mount point.
		 * We can assume that the mount wasn't created so return NULL.
		 */
		return ((CCIMObjectPath *)NULL);
	}

	nfsMountInstList = create_nfsMount_associations(mount, &err);
	if (nfsMountInstList == NULL) {
		if (err != 0) {
			nfs_free_mntinfo_list(mount);
			util_handleError("SOLARIS_NFSMOUNT::CREATE_INSTANCE",
				CIM_ERR_FAILED, CREATE_NFSMOUNT_ASSOC_FAILURE,
				NULL, &err);
		}
		return ((CCIMObjectPath *)NULL);
	}

	nfs_free_mntinfo_list(mount);

	for (currentInst = nfsMountInstList; currentInst != NULL;
		currentInst = currentInst->mNext) {

		/*
		 * Ideally there is only one instance, but with being able to
		 * overlay file systems there is a possibility that there may
		 * be multiple file systems with the same resource/mount point.
		 * If there are multiple instances in this list the last one
		 * returned will be used to create the return object path.
		 * That should be the most recently created mount.
		 */
		if (nfsMountOP != NULL) {
			cim_logDebug("cp_createInstance_Solaris_NFSMount",
				"More than one mount found.");
			cim_freeObjectPath(nfsMountOP);
		}
		nfsMountOP = cim_createObjectPath(currentInst->mDataObject);
		if (nfsMountOP == NULL) {
			ex = cim_getLastError();
			util_handleError("SOLARIS_NFSMOUNT::CREATE_INSTANCE",
				CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE,
				ex, &err);
			cim_freeInstanceList(nfsMountInstList);
			return ((CCIMObjectPath *)NULL);
		}
	}

	cim_freeInstanceList(nfsMountInstList);
	return (nfsMountOP);
} /* cp_createInstance_Solaris_NFSMount */

/*
 * Method: cp_deleteInstance_Solaris_NFSMount
 *
 * Description: Deletes a Solaris_NFSMount instance.
 * A delete instance will actually unmount a file system on the current host by
 * calling the cmd interface's cmd_execute_command_and_retrieve_string function.
 *
 * Parameters:
 *	- CCIMObjectPath* nfsOP - The object path containing all information
 *	needed to delete the appropriate instance.
 *
 * Returns:
 *	- A CIMBool value corresponding to whether or not the instance was
 *	deleted.  cim_true will be returned if the delete was successful,
 *	cim_false will be returned if the delete failed.
 */
CIMBool
cp_deleteInstance_Solaris_NFSMount(CCIMObjectPath* nfsOP) {

	CCIMInstance		*instParam;
	CCIMPropertyList	*propListParam;
	char			*cmd;
	char			*cmd_return = NULL;
	int			err = 0;

	if (nfsOP == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::DELETE_INSTANCE",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return (cim_false);
	}

	/*
	 * Get the mount that is to be deleted and generate the command.
	 */
	instParam = NULL;
	propListParam = NULL;
	cmd = cmdgen_generate_command(CMDGEN_NFS_UMOUNT, instParam, nfsOP,
		propListParam, &err);
	if (cmd == NULL || err != 0) {
		util_handleError("SOLARIS_NFSMOUNT::DELETE_INSTANCE",
			CIM_ERR_FAILED, CMDGEN_GEN_CMD_FAILURE, NULL, &err);
		return (cim_false);
	}

	/*
	 * Execute the umount command
	 */
	err = 0;
	cmd_return = cmd_execute_command_and_retrieve_string(cmd, &err);
	if (err != 0) {
		/*
		 * The command execution failed.
		 */
		if (cmd_return != NULL) {
			util_handleError("SOLARIS_NFSMOUNT::DELETE_INSTANCE",
				CIM_ERR_FAILED, CMD_EXEC_RETR_STR_FAILURE,
				NULL, &err);
			free(cmd);
			free(cmd_return);
			return (cim_false);
		} else {
			util_handleError("SOLARIS_NFSMOUNT::DELETE_INSTANCE",
				CIM_ERR_FAILED, CMD_EXEC_RETR_STR_FAILURE,
				NULL, &err);
			free(cmd);
			return (cim_false);
		}
	}

	free(cmd);
	if (cmd_return != NULL)
		free(cmd_return);

	return (cim_true);
} /* cp_deleteInstance_Solaris_NFSMount */

/*
 * Method: cp_enumInstanceNames_Solaris_NFSMount
 *
 * Description: Enumerates all of the nfs mounts on the host.  NFS mounts with
 * "ignore" in the option string are ignored.
 *
 * Parameters:
 *	- CCIMObjectPath* mountOP - An object path containing the name of the
 *	class of which to enumerate instances of.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFSMount object paths.
 *	- NULL if an error occurred or if there are no NFS mounts on the host.
 *	In the case of an error, the error will be logged.
 */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_NFSMount(CCIMObjectPath* mountOP) {
	CCIMInstanceList	*instList;
	CCIMObjectPathList	*OPList;
	int			err = 0;
	/*
	 * First check if the CCIMObjectPath parameter is null.
	 */
	if (mountOP == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::ENUM_INSTANCENAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_enumInstances_Solaris_NFSMount(mountOP);
	if (instList == NULL)
	{
		/*
		 * Failure...or there are no NFS mount instances.
		 */
		return ((CCIMObjectPathList *)NULL);
	}

	OPList = cim_createObjectPathList(instList);

	cim_freeInstanceList(instList);
	/*
	 * If an error occurred in cim_createObjectPathList it will be handled
	 * there.
	 */
	return (OPList);
} /* cp_enumInstanceNames_Solaris_NFSMount */

/*
 * Method: cp_execQuery_Solaris_NFSMount
 *
 * Description: Queries the nfs mounts on the host to find those that meet the
 * search criteria.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - An object path containing the name of
 *	the class to query.
 *	- char *selectClause - Not used.
 *	- char *nonJoinExp - Not used.
 *	- char *queryExp - Not used.
 *	- char *queryLang - Not used.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFSMount instances that match the
 *	criteria.
 *	- NULL if an error occurred or if there are no Solaris_NFSMount
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
cp_execQuery_Solaris_NFSMount(CCIMObjectPath *mountOP, char *selectClause,
	char *nonJoinExp, char *queryExp, char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*nfsMountInstList;
	CCIMException		*ex;
	int			err = 0;

	if (mountOP == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::EXEC_QUERY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsMountInstList = cp_enumInstances_Solaris_NFSMount(mountOP);

	if (nfsMountInstList == NULL) {
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::EXEC_QUERY",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	nfsMountInstList = cim_prependInstance(nfsMountInstList, emptyInst);
	if (nfsMountInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::EXEC_QUERY",
			CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstance(emptyInst);
		return ((CCIMInstanceList *)NULL);
	}

	return (nfsMountInstList);
} /* cp_execQuery_Solaris_NFSMount */

/*
 * Method: cp_setInstance_Solaris_NFSMount
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties of a mount on the host, the mount must be
 * unmounted and mounted with the new properties.  This behavior is not
 * appropriate for the set instance.  If the client wants to change the
 * properties of a mount they must delete the old instance and create a
 * new one with the desired properties.
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
cp_setInstance_Solaris_NFSMount(CCIMObjectPath* pOP, CCIMInstance* pInst) {
	int	err = 0;

	util_handleError("SOLARIS_NFSMOUNT::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setInstance_Solaris_NFSMount */

/*
 * Method: cp_setInstanceWithList_Solaris_NFSMount
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties of a mount on the host, the mount must be
 * unmounted and mounted with the new properties.  This behavior is not
 * appropriate for the set instance.  If the client wants to change the
 * properties of a mount they must delete the old instance and create a
 * new one with the desired properties.
 *
 * Parameters:
 *	- CCIMObjectPath *hostedShareOP - The object path containing the name
 *	of the class of which to set the instance.
 *	- CCIMInstance *hostedShareInst - Not used.
 *	- char **props - Not used.
 *	- int num_props - Not used.
 *
 * Returns:
 *	- cim_false is returned every time since the method is not supported.
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_NFSMount(CCIMObjectPath* mountOP,
					CCIMInstance* mountInst,
					char **props, int num_props) {
	int	err = 0;

	util_handleError("SOLARIS_NFSMOUNT::SET_INSTANCE",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);

} /* cp_setInstanceWithList_Solaris_NFSMount */

/*
 * Associator provider methods
 */

/*
 * Method: cp_associators_Solaris_NFSMount
 *
 * Description: Returns the instances associated, via the Solaris_NFSMount
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
 *	- A pointer to a list of Solaris_NFS (if pRole == Antecedent &&
 *	pObjectName is a Solaris_Directory object path) or Solaris_Directory
 *	(if pRole == DEPENDENT && pObjectName is a Solaris_NFS object path)
 *	instances which are associated to the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_NFSMount(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*returnInstList;
	CCIMPropertyList	*propList;
	nfs_mntlist_t		*mountList;
	cimchar			*name;
	boolean_t		isAntecedent = B_FALSE;
	int			err = 0;

	/*
	 * Check if the needed parameters are null.
	 */
	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * The Name key property is the defining property for each the
	 * Antecedent (Solaris_Directory) and the Dependent (Solaris_NFS)
	 * so retrieve that property.
	 */
	propList = pObjectName->mKeyProperties;
	name = (cimchar *)util_getKeyValue(propList, string, NAME, &err);

	if (name == NULL || err != 0) {
		util_handleError("SOLARIS_NFSMOUNT::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Determine whether pObjectName is the Antecedent or the Dependent
	 * of the association.  Antecedent = Solaris_Directory,
	 * Dependent = Solaris_NFS
	 */
	if ((strcasecmp(pObjectName->mName, SOLARIS_DIR) == 0)) {
		isAntecedent = B_TRUE;
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
	} else {
		isAntecedent = B_FALSE;
		if (pRole != NULL && (strcasecmp(pRole, DEPENDENT) != 0)) {
			util_handleError("SOLARIS_NFSMOUNT::ASSOCIATORS",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}
	}

	mountList = get_associated_nfs_mntlist(isAntecedent, name);
	if (mountList == NULL)
		return ((CCIMInstanceList *)NULL);
	returnInstList = get_associated_instances(mountList, (!isAntecedent));
	nfs_free_mntinfo_list(mountList);

	return (returnInstList);
} /* cp_associators_Solaris_NFSMount */

/*
 * Method: cp_associatorNames_Solaris_NFSMount
 *
 * Description: Returns the object paths of the instances on the other side of
 * the association which are associated via the Solaris_NFSMount association
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
 *	- A pointer to a list of Solaris_NFS (if pRole == Antecedent &&
 *	pObjectName is a Solaris_Directory object path) or Solaris_Directory
 *	(if pRole == DEPENDENT && pObjectName is a Solaris_NFS object path)
 *	object paths which are associated to the pObjectName parameter.
 *	- NULL if an error occurred or if there are no instances associated to
 *	the pObjectName passed in.  In the case of an error, the error will be
 *	logged.
 */
CCIMObjectPathList *
cp_associatorNames_Solaris_NFSMount(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objPathList;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::ASSOCIATOR_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	instList = cp_associators_Solaris_NFSMount(pAssocName, pObjectName,
		pResultClass, pRole, pResultRole);

	if (instList != NULL) {
		objPathList = cim_createObjectPathList(instList);
		cim_freeInstanceList(instList);
	}

	return (objPathList);
} /* cp_associatorNames_Solaris_NFSMount */

/*
 * Method: cp_references_Solaris_NFSMount
 *
 * Description: Returns the Solaris_NFSMount instances that have the passed in
 * parameter, pObjectName, as one of it's keys.
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
 *	- A pointer to a list of Solaris_NFSMount instances.
 *	- NULL if an error occurred or if there are no Solaris_NFSMount
 *	instances having pObjectName as one of it's keys.
 */
/* ARGSUSED */
CCIMInstanceList *
cp_references_Solaris_NFSMount(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*instList;
	CCIMPropertyList	*propList;
	nfs_mntlist_t		*mountList;
	char			*name;
	boolean_t		isAntecedent = B_FALSE;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::REFERENCES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * The Name key property is the defining property for each the
	 * Antecedent (Solaris_Directory) and the Dependent (Solaris_NFS)
	 * so retrieve that property.
	 */
	propList = pObjectName->mKeyProperties;
	name = (cimchar *)util_getKeyValue(propList, string, NAME, &err);

	if (name == NULL || err != 0) {
		/*
		 * The object path passed in does not have the appropriate
		 * information.
		 */
		util_handleError("SOLARIS_NFSMOUNT::ASSOCIATORS",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	if ((strcasecmp(pObjectName->mName, SOLARIS_DIR) == 0)) {
		isAntecedent = B_TRUE;
		/*
		 * If a value was passed in with pRole and it does not match
		 * the role that pObjectName actually is then log an invalid
		 * param error.
		 */
		if (pRole != NULL && (strcasecmp(pRole, ANTECEDENT) != 0)) {
			util_handleError("SOLARIS_NFSMOUNT::REFERENCES",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}
	} else {
		isAntecedent = B_FALSE;
		if (pRole != NULL && (strcasecmp(pRole, DEPENDENT) != 0)) {
			util_handleError("SOLARIS_NFSMOUNT::REFERENCES",
				CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
			return ((CCIMInstanceList *)NULL);
		}
	}

	mountList = get_associated_nfs_mntlist(isAntecedent, name);
	if (mountList == NULL)
		return ((CCIMInstanceList *)NULL);
	instList = create_nfsMount_associations(mountList, &err);

	nfs_free_mntinfo_list(mountList);

	return (instList);
} /* cp_references_Solaris_NFSMount */

/*
 * Method: cp_referenceNames_Solaris_NFSMount
 *
 * Description: Returns the Solaris_NFSMount object paths of the instances
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
 *	- A pointer to a list of Solaris_NFSMount object paths.
 *	- NULL if an error occurred or if there are no Solaris_NFSMount
 *	instances having pObjectName as one of it's keys.
 */
CCIMObjectPathList *
cp_referenceNames_Solaris_NFSMount(CCIMObjectPath *pAssocName,
	CCIMObjectPath *pObjectName, char *pRole) {

	CCIMInstanceList	*nfsMountInstList;
	CCIMObjectPathList	*nfsMountOPList;
	CCIMException		*ex;
	int			err = 0;

	if (pObjectName == NULL || pObjectName->mKeyProperties == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::REFERENCES_NAMES",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	nfsMountInstList = cp_references_Solaris_NFSMount(pAssocName,
		pObjectName, pRole);

	if (nfsMountInstList == NULL) {
		return ((CCIMObjectPathList *)NULL);
	}

	nfsMountOPList = cim_createObjectPathList(nfsMountInstList);
	if (nfsMountOPList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::REFERENCE_NAMES",
			CIM_ERR_FAILED, CREATE_OBJECT_LIST_FAILURE, ex, &err);
		cim_freeInstanceList(nfsMountInstList);
		return ((CCIMObjectPathList *)NULL);
	}

	cim_freeInstanceList(nfsMountInstList);

	return (nfsMountOPList);
} /* cp_referenceNames_Solaris_NFSMount */

/*
 * Property provider methods
 */

/*
 * Method: cp_getProperty_Solaris_NFSMount
 *
 * Description: Retrieves a certain property from the instance of
 * Solaris_NFSMount on the host that is described by the parameter pOP.
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
cp_getProperty_Solaris_NFSMount(CCIMObjectPath *pOP, cimchar *pPropName) {
	CCIMInstance	*nfsMountInst;
	CCIMProperty	*nfsMountProp;
	int		err = 0;

	if (pOP == NULL || pPropName == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::GET_PROPERTY",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	nfsMountInst = cp_getInstance_Solaris_NFSMount(pOP);
	if (nfsMountInst == NULL) {
		return ((CCIMProperty *)NULL);
	}

	nfsMountProp = cim_getProperty(nfsMountInst, pPropName);

	cim_freeInstance(nfsMountInst);
	/*
	 * If an error occurred in cim_getProperty it will be handled there.
	 */
	return (nfsMountProp);
} /* cp_getProperty_Solaris_NFSMount */

/*
 * Method: cp_setProperty_Solaris_NFSMount
 *
 * Description: This method is not supported.  This is not allowed because in
 * order to change the properties of a mount on the host, the mount must be
 * unmounted and mounted with the new properties.  This behavior is not
 * appropriate for the set property.  If the client wants to change the
 * properties of a mount they must delete the old instance and create a
 * new one with the desired properties.
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
cp_setProperty_Solaris_NFSMount(CCIMObjectPath *pOP, CCIMProperty *pProp) {
	int	err = 0;

	util_handleError("SOLARIS_NFSMOUNT::SET_PROPERTY",
		CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);

	return (cim_false);
} /* cp_setProperty_Solaris_NFSMount */

/*
 * Method provider methods
 */

/*
 * Method: cp_invokeMethod_Solaris_NFSMount
 *
 * Description: Routes the cp_invokeMethod_Solaris_NFSMount calls to the
 * correct Solaris_NFSMount methods.
 *
 * Parameters:
 *	- CCIMObjectPath *pOP - The object path containing needed information
 *	about the class that is to getting methods invoked.
 *	- cimchar *functionName - The name of the function to be invoked.
 *	- CCIMPropertyList *inParams - The input parameters to the function.
 *	- CCIMPropertyList *outParams - The output parameters from the function.
 *
 * Returns:
 *	- A pointer to a property which indicates success or failure of the
 *	function.  1 for success, 0 for failure.
 *	- Upon error, NULL is returned and the error is logged.
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_NFSMount(CCIMObjectPath *pOP, cimchar *functionName,
	CCIMPropertyList *inParams, CCIMPropertyList *outParams) {

	int		err = 0;
	CCIMProperty	*retVal;

	if (pOP == NULL || functionName == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::INVOKE_METHOD",
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &err);
		return ((CCIMProperty *)NULL);
	}
	cim_logDebug("cp_invokeMethod_Solaris_NFSMount",
		"Invoking %s", functionName);
	/*
	 * Determine what method is being called.
	 */
	if (strcasecmp(functionName, GET_NET_CFG_LIST_METHOD) == 0) {
		retVal = get_netconfig_list(outParams);
	} else if (strcasecmp(functionName, GET_NFS_SEC_LIST_METHOD) == 0) {
		retVal = get_nfssec_list(outParams);
	} else if (strcasecmp(functionName, GET_DEF_SECMODE_METHOD) == 0) {
		retVal = get_default_secmode(outParams);
	} else if (strcasecmp(functionName, SHOW_EXPORTS_METHOD) == 0) {
		retVal = show_exports(inParams, outParams);
	} else if (strcasecmp(functionName, DELETE_VFSTAB_ENT_METHOD) == 0) {
		retVal = delete_vfstab_entry(inParams);
	} else {
		/*
		 * No such method name.
		 */
		util_handleError("SOLARIS_NFSMOUNT::INVOKE_METHOD",
			CIM_ERR_FAILED, NO_SUCH_METHOD, NULL, &err);
		return ((CCIMProperty *)NULL);
	}

	return (retVal);
} /* cp_invokeMethod_Solaris_NFSMount */

/*
 * Private Methods
 */

/*
 * Method: create_nfsMount_associations
 *
 * Description: Creates Solaris_NFSMount associations out of the information
 * gathered from all the NFS mounts on the host.
 *
 * Parameters:
 *	- nfs_mntlist_t *mountList - The list of nfs mounts on the host.
 *	- int *errp - The error pointer.  If an error occurs, this will be a
 * 	non-zero number.
 *
 * Returns:
 *	- A pointer to a list of all the Solaris_NFSMount instances on the host.
 *	- NULL if an error occurred or if there aren't any NFS mounts on the
 *	host.  In the case of an error, the error will be logged.
 */
static CCIMInstanceList *
create_nfsMount_associations(nfs_mntlist_t *mountList, int *errp) {
	nfs_mntlist_t		*currentMnt;
	CCIMInstanceList	*nfsMountInstList;
	CCIMException		*ex;

	nfsMountInstList = cim_createInstanceList();
	if (nfsMountInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::CREATE_NFSMOUNT_ASSOC",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex,
			errp);
		return ((CCIMInstanceList *)NULL);
	}

	for (currentMnt = mountList; currentMnt != NULL;
		currentMnt = currentMnt->next) {

		CCIMInstance		*nfsMountInst;
		CCIMPropertyList	*nfsMountPropList;

		/*
		 * Create the Solaris_NFSMount instance and add the properties
		 * to the instance.
		 */
		nfsMountInst = cim_createInstance(SOLARIS_NFSMOUNT);
		if (nfsMountInst == NULL) {
			ex = cim_getLastError();
			util_handleError(
				"SOLARIS_NFSMOUNT::CREATE_NFSMOUNT_ASSOC",
				CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE,
				ex, errp);
			cim_freeInstanceList(nfsMountInstList);
			return ((CCIMInstanceList *)NULL);
		}

		nfsMountPropList = populate_property_list(currentMnt);
		if (nfsMountPropList == NULL) {
			/*
			 * An error was encountered, but it was logged in
			 * populate_property_list so just return null.
			 */
			cim_freeInstanceList(nfsMountInstList);
			cim_freeInstance(nfsMountInst);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Add the returned property list to the instance.
		 */
		nfsMountInst = cim_addPropertyListToInstance(nfsMountInst,
			nfsMountPropList);
		if (nfsMountInst == NULL) {
			ex = cim_getLastError();
			util_handleError(
				"SOLARIS_NFSMOUNT::CREATE_NFSMOUNT_ASSOC",
				CIM_ERR_FAILED, PROPLIST_TO_INSTANCE_FAILURE,
				ex, errp);
			cim_freeInstanceList(nfsMountInstList);
			cim_freePropertyList(nfsMountPropList);
			return ((CCIMInstanceList *)NULL);
		}

		/*
		 * Add the instance to the instance list.
		 */
		nfsMountInstList = cim_addInstance(nfsMountInstList,
			nfsMountInst);
		if (nfsMountInstList == NULL) {
			ex = cim_getLastError();
			util_handleError(
				"SOLARIS_NFSMOUNT::CREATE_NFSMOUNT_ASSOC",
				CIM_ERR_FAILED, ADD_INSTANCE_FAILURE,
				ex, errp);
			/*
			 * Freeing the instance will free the property list
			 * that was added to it.  There is no need to free
			 * the property list separately.
			 */
			cim_freeInstance(nfsMountInst);
			return ((CCIMInstanceList *)NULL);
		}
	}

	return (nfsMountInstList);
} /* create_nfsMount_associations */

/*
 * Method: enumerate_mounts
 *
 * Description: Enumerates the NFS mounts on the host by using the
 * nfs_mntinfo nfs_get_mount_list method.
 *
 * Parameters:
 *	- NONE
 *
 * Returns:
 *	- A pointer to a list of all the Solaris_NFSMount instances on the host.
 *	- NULL if an error occurred or if there are no NFS mounts on the system.
 *	In the case of an error, the error will be logged.
 */
static CCIMInstanceList *
enumerate_mounts() {
	int get_mntlist_err = 0;
	int err = 0;
	nfs_mntlist_t 	*nfs_mount_list;

	nfs_mount_list = nfs_get_mount_list(&get_mntlist_err);
	if (nfs_mount_list == NULL) {
		/*
		 * Check whether an error was returned or if we simply don't
		 * have any nfs file systems on the system. If
		 * get_mntlist_err is not equal to 0, an error was encountered.
		 */
		if (get_mntlist_err != 0) {
			/*
			 * Determine the error and log it.
			 */
			if (get_mntlist_err == ENOMEM ||
				get_mntlist_err == EAGAIN) {
				util_handleError(
					"SOLARIS_NFSMOUNT::ENUM_MOUNTS",
					CIM_ERR_LOW_ON_MEMORY,
					NFS_GET_MNTLIST_FAILURE,
					NULL, &err);

				return ((CCIMInstanceList *)NULL);
			} else {
				/*
				 * If any other errors were encountered it
				 * can be handled as a general error.  We may
				 * not know exactly what the error is.
				 */
				util_handleError(
					"SOLARIS_NFSMOUNT::ENUM_MOUNTS",
					CIM_ERR_FAILED,
					NFS_GET_MNTLIST_FAILURE,
					NULL, &err);

				return ((CCIMInstanceList *)NULL);
			}
		}
		/*
		 * We simply don't have any nfs mounts on the host.
		 */
		return ((CCIMInstanceList *)NULL);

	} else {
		/*
		 * At this point, one or more nfs mounts were found on the
		 * system, create the instance list from the nfs_mount_list.
		 */
		CCIMInstanceList	*nfsMountInstList;

		nfsMountInstList = create_nfsMount_associations(nfs_mount_list,
			&err);

		nfs_free_mntinfo_list(nfs_mount_list);
		return (nfsMountInstList);
	} /* if (nfs_mount_list == NULL) */

} /* enumerate_mounts */

/*
 * Method: get_Antecedent
 *
 * Description: Creates the Antecedent object path of the Solaris_NFSMount
 * class.
 *
 * Parameters:
 *	- cimchar *mount_point - the mount point of the nfs mount which is
 *	used as the Name Key property of the Antecedent, Solaris_Directory.
 *
 * Returns:
 *	- The corresponding Solaris_Directory CCIMObjectPath* is returned.
 *	- Upon error NULL is returned.
 *	The returned CCIMObjectPath* must be freed by the calling function.
 */
static CCIMObjectPath *
get_Antecedent(cimchar *mount_point) {
	CCIMInstance	*solarisDirInst;
	CCIMObjectPath	*solarisDirOP;
	CCIMException	*ex;
	int		err;
	char		*hostname;

	solarisDirInst = cim_createInstance(SOLARIS_DIR);
	if (solarisDirInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::GET_ANT",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return ((CCIMObjectPath *)NULL);
	}

	/*
	 * Create the key properties on the Solaris_Directory instance.
	 *
	 * The Solaris_Directory keys are as follows:
	 * CSCreationClassName = "Solaris_ComputerSystem"
	 * CSName = < hostname >
	 * FSCreationClassName = "Solaris_NFS"
	 * FSName = "NFS"
	 * CreationClassName = "Solaris_Directory"
	 * Name = < full pathname of mount point >
	 */
	if (add_property_to_instance(CS_CREATION_CLASS, string,
		SOLARIS_CS, NULL, cim_true, solarisDirInst) == cim_false) {

		cim_freeInstance(solarisDirInst);
		return ((CCIMObjectPath *)NULL);
	}

	hostname = sys_get_hostname(&err);
	if (hostname == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::GET_ANT)", CIM_ERR_FAILED,
			GET_HOSTNAME_FAILURE, NULL, &err);
		return ((CCIMObjectPath *)NULL);
	}

	if (add_property_to_instance(CSNAME, string, hostname,
		NULL, cim_true, solarisDirInst) == cim_false) {

		free(hostname);
		cim_freeInstance(solarisDirInst);
		return ((CCIMObjectPath *)NULL);
	}
	free(hostname);

	if (add_property_to_instance(FS_CREATION_CLASS, string,
		SOLARIS_NFS, NULL, cim_true, solarisDirInst) == cim_false) {

		cim_freeInstance(solarisDirInst);
		return ((CCIMObjectPath *)NULL);
	}

	if (add_property_to_instance(FSNAME, string,
		NFS, NULL, cim_true, solarisDirInst) == cim_false) {

		cim_freeInstance(solarisDirInst);
		return ((CCIMObjectPath *)NULL);
	}

	if (add_property_to_instance(CREATION_CLASS, string,
		SOLARIS_DIR, NULL, cim_true, solarisDirInst) == cim_false) {

		cim_freeInstance(solarisDirInst);
		return ((CCIMObjectPath *)NULL);
	}

	if (add_property_to_instance(NAME, string, mount_point,
		NULL, cim_true, solarisDirInst) == cim_false) {

		cim_freeInstance(solarisDirInst);
		return ((CCIMObjectPath *)NULL);
	}

	solarisDirOP = cim_createObjectPath(solarisDirInst);
	if (solarisDirOP == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::GET_ANT",
			CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE,
			ex, &err);
		cim_freeInstance(solarisDirInst);
		return ((CCIMObjectPath *)NULL);
	}

	cim_freeInstance(solarisDirInst);
	return (solarisDirOP);
} /* get_Antecedent */

/*
 * Method: get_associated_instances
 *
 * Description: Gets instances associated to the mounts passed in with
 * mountList.
 *
 * Parameters:
 *	- nfs_mntlist_t *mountList - The nfs mount list from which to get the
 *	associated instances.
 *	- boolean_t resultIsAnt - Whether or not the role that the instance
 *	returned plays in the association is the Antecedent.
 *
 * Returns:
 *	- A pointer to a list of Solaris_NFS or Solaris_Directory instances that
 *	are associated to the mount passed in with mountList.
 *	- NULL if an error occurred or if there are no instances that are
 *	associated to mountList.
 */
static CCIMInstanceList *
get_associated_instances(nfs_mntlist_t *mountList, boolean_t resultIsAnt) {
	CCIMInstanceList	*returnInstList;
	CCIMException		*ex;
	nfs_mntlist_t		*currentMnt;
	int			err = 0;

	returnInstList = cim_createInstanceList();
	if (returnInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::GET_ASSOC_INST",
			CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	for (currentMnt = mountList; currentMnt != NULL;
		currentMnt = currentMnt->next) {
		/*
		 * Determine if we are supposed to form the Antecedent or
		 * Dependent instances by checking the value of resultIsAnt.
		 */
		if (resultIsAnt == B_FALSE) {
			CCIMObjectPath	*nfsOP;
			CCIMInstance	*nfsInst;

			nfsOP = get_Dependent(currentMnt);
			if (nfsOP == NULL) {
				/*
				 * An error occurred in get_Dependent and was
				 * handled there so just return NULL.
				 */
				cim_freeInstanceList(returnInstList);
				return ((CCIMInstanceList *)NULL);
			}

			nfsInst = cimom_getInstance(nfsOP, cim_false,
				cim_false, cim_false, cim_false, NULL, 0);

			/*
			 * A NULL return value indicates an error, an empty
			 * list does not.
			 */
			if (nfsInst == NULL) {
				ex = cim_getLastError();
				util_handleError(
					"SOLARIS_NFSMOUNT::GET_ASSOC_INST",
					CIM_ERR_FAILED, CIMOM_GET_INST_FAILURE,
					ex, &err);
				cim_freeObjectPath(nfsOP);
				cim_freeInstanceList(returnInstList);
				return ((CCIMInstanceList *)NULL);
			}

			cim_freeObjectPath(nfsOP);

			if (nfsInst->mProperties == NULL) {
				cim_freeInstanceList(returnInstList);
				return ((CCIMInstanceList *)NULL);
			}

			/*
			 * Add the Solaris_NFS instance to the instance
			 * list to be returned.
			 */
			returnInstList = cim_addInstance(returnInstList,
				nfsInst);
			if (returnInstList == NULL) {
				ex = cim_getLastError();
				util_handleError(
					"SOLARIS_NFSMOUNT::GET_ASSOC_INST",
					CIM_ERR_FAILED, ADD_INSTANCE_FAILURE,
					ex, &err);
				cim_freeInstance(nfsInst);
				return ((CCIMInstanceList *)NULL);
			}
		} else {
			CCIMObjectPath	*dirOP;
			CCIMInstance	*dirInst;

			dirOP = (CCIMObjectPath *)get_Antecedent(
				currentMnt->nml_mountp);

			if (dirOP == NULL) {
				/*
				 * An error occurred in get_Antecedent and was
				 * handled there so just return NULL.
				 */
				cim_freeInstanceList(returnInstList);
				return ((CCIMInstanceList *)NULL);
			}
			cim_logDebug("get_associated_instances",
				"dirOP =%s", dirOP->mName);

			dirInst = cimom_getInstance(dirOP, cim_false,
				cim_false, cim_false, cim_false, NULL, 0);

			/*
			 * A NULL return value means error, an empty list
			 * does not.
			 */
			if (dirInst == NULL) {
				ex = cim_getLastError();
				util_handleError(
					"SOLARIS_NFSMOUNT::GET_ASSOC_INST",
					CIM_ERR_FAILED, CIMOM_GET_INST_FAILURE,
					ex, &err);
				cim_freeObjectPath(dirOP);
				cim_freeInstanceList(returnInstList);
				return ((CCIMInstanceList *)NULL);
			}

			cim_freeObjectPath(dirOP);

			if (dirInst->mProperties == NULL) {
				cim_freeInstance(dirInst);
				cim_freeInstanceList(returnInstList);
				return ((CCIMInstanceList *)NULL);
			}

			/*
			 * Work around for cimom bug 4649100.
			 */
			if (!set_dir_keyProperties_to_true(dirInst)) {
				cim_freeInstance(dirInst);
				cim_freeInstanceList(returnInstList);
				return ((CCIMInstanceList *)NULL);
			}

			/*
			 * Add the Solaris_Directory instance to the
			 * instance list to be returned.
			 */
			returnInstList = cim_addInstance(returnInstList,
				dirInst);
			if (returnInstList == NULL) {
				ex = cim_getLastError();
				util_handleError(
					"SOLARIS_NFSMOUNT::GET_ASSOC_INST",
					CIM_ERR_FAILED, ADD_INSTANCE_FAILURE,
					ex, &err);
				cim_freeInstance(dirInst);
				return ((CCIMInstanceList *)NULL);
			}
		}
	}

	return (returnInstList);
} /* get_associated_instances */

/*
 * Method: get_associated_nfs_mntlist
 *
 * Description: Gets a list of mounts, including their information, that have
 * the same value as nameKeyValue for the Name property.
 *
 * Parameters:
 *	- boolean_t isAntecedent - A boolean value representing whether the
 *	key value passed in with nameKeyVal is the Antecedent or not.
 *	- char *nameKeyVal - The value of the Name key.
 *
 * Returns:
 *	- A pointer to a list of nfs mounts.
 *	- NULL if an error occurred or if there are no mounts having the same
 *	information as passed in with nameKeyVal.
 */
static nfs_mntlist_t *
get_associated_nfs_mntlist(boolean_t isAntecedent, char *nameKeyVal) {
	nfs_mntlist_t	*mountList;
	int		err = 0;

	if (isAntecedent) {
		/*
		 * The nameKeyValue is that of the Antecedent,
		 * Solaris_Directory.
		 */
		/*
		 * The Name property is populated with the mount point of the
		 * nfs file system so we need to determine if the mount point
		 * exists.
		 */
		mountList = nfs_get_filtered_mount_list(NULL, nameKeyVal, NULL,
			NULL, B_TRUE, &err);
		if (mountList == NULL) {
			/*
			 * Check if an error occurred and if it did handle it.
			 */
			if (err != 0) {
				util_handleError(
					"SOLARIS_NFSMOUNT::GET_ASSOC_NFSMNTS",
					CIM_ERR_FAILED,
					NFS_GET_FILTERED_MOUNTS_FAILURE,
					NULL, &err);
				return (NULL);
			}
			/*
			 * If no error occurred then we know that the mount
			 * point doesn't exist so return NULL.
			 */
			return (NULL);
		}
	} else {
		char	*resource;
		char	*devid;
		char	*devMntOpt = "dev=";
		char	*searchOpt;
		int	searchOptLen;

		/*
		 * The nameKeyValue is that of the Dependent, Solaris_NFS.
		 */
		/*
		 * Get the resource and devid from the Name key property
		 * which should be in the form:
		 * "resource:=< resource > devid:=< devid >"
		 */
		err = 0;
		devid = get_devid(nameKeyVal, &err);
		if (devid == NULL) {
			util_handleError(
				"SOLARIS_NFSMOUNT::GET_ASSOC_NFSMNTS",
				CIM_ERR_FAILED, GET_DEVID_FAILURE, NULL, &err);
			return (NULL);
		}

		cim_logDebug("get_associated_nfs_mntlist",
			"isDependent: devid =%s", devid);
		err = 0;
		resource = get_resource(nameKeyVal, &err);
		if (resource == NULL) {
			util_handleError(
				"SOLARIS_NFSMOUNT::GET_ASSOC_NFSMNTS",
				CIM_ERR_FAILED, GET_RESOURCE_FAILURE, NULL,
				&err);
			free(devid);
			return (NULL);
		}

		cim_logDebug("get_associated_nfs_mntlist",
			"isDependent: resource =%s", resource);
		/*
		 * The devid is unique per file system so we will search for
		 * the mount that has the corresponding devid.  Obviously,
		 * we only expect to get one file system.
		 */
		searchOptLen = (strlen(devMntOpt) + strlen(devid) + 1);

		searchOpt = (char *)calloc((size_t)searchOptLen,
			(size_t)sizeof (char));

		if (searchOpt == NULL) {
			/*
			 * Out of memory
			 */
			free(devid);
			free(resource);
			return (NULL);
		}

		(void) snprintf(searchOpt, (size_t)searchOptLen, "%s%s",
			devMntOpt, devid);
		cim_logDebug("get_associated_nfs_mntlist",
			"isDependent: searchOpt =%s", searchOpt);

		free(devid);

		mountList = nfs_get_mounts_by_mntopt(searchOpt, B_FALSE, &err);
		if (mountList == NULL) {
			free(resource);
			free(searchOpt);
			if (err != 0) {
				util_handleError(
					"SOLARIS_NFSMOUNT::GET_ASSOC_NFSMNTS",
					CIM_ERR_FAILED,
					NFS_GET_MNTS_BY_MNTOPT_FAILURE,
					NULL, &err);
				return (NULL);
			}
			return (NULL);
		}

		free(searchOpt);

		/*
		 * Check that the resource from the pObjectName is the same as
		 * the one in the mountList.  If it is not, return null.
		 */
		if ((strcmp(resource, mountList->nml_resource) != 0)) {
			free(resource);
			return (NULL);
		}
		free(resource);
	}

	return (mountList);
} /* get_associated_nfs_mntlist */

/*
 * Method: get_Dependent
 *
 * Description: Creates the Dependent object path of the Solaris_NFSMount class
 *
 * Parameters:
 *	- nfs_mntlist_t *nfs_mount - The nfs mount to be used for filling in
 *	the properties of the Dependent, Solaris_NFS.
 *
 * Returns:
 *	- A Solaris_NFS CCIMObjectPath* is returned.
 *	- Upon error, NULL is returned.
 */
static CCIMObjectPath *
get_Dependent(nfs_mntlist_t *nfs_mount) {
	CCIMInstance	*solarisNFSInst;
	CCIMObjectPath	*solarisNFSOp;
	CCIMException	*ex;
	char		*name_val;
	char		*devid;
	char		*resourceStr = "resource:=";
	char		*devidStr = "devid:=";
	char		*hostname;
	int		err = 0;
	int		name_val_len;

	solarisNFSInst = cim_createInstance(SOLARIS_NFS);
	if (solarisNFSInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::GET_DEP",
			CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		return (NULL);
	}

	/*
	 * Create the key properties on the Solaris_NFS instance.
	 *
	 * The Solaris_Directory keys are as follows:
	 * CSCreationClassName = "Solaris_ComputerSystem"
	 * CSName = < hostname >
	 * CreationClassName = "Solaris_NFS"
	 * Name = resource:=< resource > devid:= < devid >
	 */
	if (add_property_to_instance(CS_CREATION_CLASS, string,
		SOLARIS_CS, NULL, cim_true, solarisNFSInst) == cim_false) {

		cim_freeInstance(solarisNFSInst);
		return ((CCIMObjectPath *)NULL);
	}

	hostname = sys_get_hostname(&err);
	if (hostname == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::GET_DEP", CIM_ERR_FAILED,
			GET_HOSTNAME_FAILURE, NULL, &err);
		cim_freeInstance(solarisNFSInst);
		return ((CCIMObjectPath *)NULL);
	}

	if (add_property_to_instance(CSNAME, string, hostname, NULL, cim_true,
		solarisNFSInst) == cim_false) {

		free(hostname);
		cim_freeInstance(solarisNFSInst);
		return ((CCIMObjectPath *)NULL);
	}
	free(hostname);

	if (add_property_to_instance(CREATION_CLASS, string,
		SOLARIS_NFS, NULL, cim_true, solarisNFSInst) == cim_false) {

		cim_freeInstance(solarisNFSInst);
		return ((CCIMObjectPath *)NULL);
	}

	if (nfs_mount != NULL) {
		err = 0;
		devid = fs_parse_optlist_for_option(
			nfs_mount->nml_mntopts, "dev=", &err);
		if (devid == NULL) {
			util_handleError("SOLARIS_NFSMOUNT::GET_DEP",
				CIM_ERR_FAILED, FS_PARSE_OPTLIST_FAILURE,
				NULL, &err);
			cim_freeInstance(solarisNFSInst);
			return ((CCIMObjectPath *)NULL);
		}

		name_val_len = strlen(resourceStr) +
			strlen(nfs_mount->nml_resource) + strlen(devidStr) +
			strlen(devid) + 2;

		name_val = (char *)calloc((size_t)name_val_len,
			(size_t)(sizeof (char)));
		if (name_val == NULL) {
			util_handleError("SOLARIS_NFSMOUNT::GET_DEP",
				CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, NULL);
			cim_freeInstance(solarisNFSInst);
			return ((CCIMObjectPath *)NULL);
		}

		(void) snprintf(name_val, (size_t)name_val_len,
			"%s%s%s%s%s", resourceStr, nfs_mount->nml_resource, " ",
			devidStr, devid);
	}

	free(devid);

	if (add_property_to_instance(NAME, string, name_val, NULL,
		cim_true, solarisNFSInst) == cim_false) {

		cim_freeInstance(solarisNFSInst);
		return ((CCIMObjectPath *)NULL);
	}

	free(name_val);

	solarisNFSOp = cim_createObjectPath(solarisNFSInst);

	if (solarisNFSOp == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::GET_DEP",
			CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE,
			ex, &err);
		cim_freeInstance(solarisNFSInst);
		return (NULL);
	}

	cim_freeInstance(solarisNFSInst);

	return (solarisNFSOp);
} /* get_Dependent */

/*
 * Method: get_devid
 *
 * Description:
 * Parses the Solaris_NFS.Name key property, which is in the
 * "resource:=<resource> devid:=<devid>" format, for the devid.
 *
 * Parameters:
 *	- char *keyValue - The string which is in the
 *	"resource:=<resource> devid:=<devid>" format to parse the devid from.
 *	- int *errp - The error pointer.  This will be set to a non-zero number
 *	if an error is encountered.
 *
 * Returns:
 *	- A pointer to a string which is the value of the devid.
 *	- NULL if the devid is not found or if an error occurred.  In the case
 *	of an error, errp will be set to a non-zero number.
 *
 * NOTE:
 * The caller must free the memory allocated for the return string.
 */
char *
get_devid(char *keyValue, int *errp) {
	char	*devidMarker = "devid:=";
	char	*devidMarkerStart;
	char	*devidStart;
	char	*devid;

	devidMarkerStart = strstr(keyValue, devidMarker);
	if (devidMarkerStart == NULL) {
		return (NULL);
	}

	devidStart = devidMarkerStart + strlen(devidMarker);
	devid = strdup(devidStart);
	if (devid == NULL) {
		*errp = errno;
		return (NULL);
	}

	return (devid);
} /* get_devid */

/*
 * Method: get_resource
 *
 * Description:
 * Parses the Solaris_NFS.Name key property, which is in the
 * "resource:=<resource> devid:=<devid>" format, for the resource.
 *
 * Parameters:
 *	- char *keyValue - The string which is in the
 *      "resource:=<resource> devid:=<devid>" format to parse the resource from.
 *	- int *errp - The error pointer.  This will be set to a non-zero number
 *	if an error is encountered.
 *
 * Returns:
 *	- A pointer to a string which is the value of the resource.
 *	- NULL if the resource is not for or if an error occurred.  In the case
 *	of an error, errp will be set to a non-zero number.
 * NOTE:
 * The caller must free the memory allocated for the return string.
 */
static char *
get_resource(char *keyValue, int *errp) {
	char	*devid;
	char	*devidStr = "devid:=";
	char	*resource;
	char	*resourceStr = "resource:=";
	int	totalDevidLen = 0, keyValueLen = 0, resourceLen = 0,
		resourceStrLen = 0, i = 0;
	int	err = 0;

	/*
	 * First we need to get the devid string portion of the Solaris_NFS.Name
	 * key value in order to figure out how long that portion is.
	 */
	devid = get_devid(keyValue, &err);
	if (devid == NULL) {
		*errp = err;
		return (NULL);
	}

	totalDevidLen = strlen(devidStr) + strlen(devid);

	keyValueLen = strlen(keyValue);
	resourceStrLen = strlen(resourceStr);

	/*
	 * The length of the space character between the resource and devid
	 * is not taken out here for the fact that we will use that space in
	 * order to allocate enough space for the null terminating character.
	 */
	resourceLen = keyValueLen - totalDevidLen - resourceStrLen;
	resourceLen = strlen(keyValue) - (strlen(devidStr) + strlen(devid)) -
		strlen(resourceStr);

	resource = (char *)calloc((size_t)resourceLen, (size_t)sizeof (char));
	if (resource == NULL) {
		*errp = errno;
		return (NULL);
	}

	for (i = 0; i < (resourceLen - 1); i++) {
		resource[i] = keyValue[resourceStrLen+i];
	}

	/*
	 * Make sure to put the null terminating character at the end.
	 */
	resource[resourceLen-1] = '\0';

	free(devid);
	return (resource);
} /* get_resource */

/*
 * Method: populate_property_list
 *
 * Description: Populates all the properties of the passed in mount into a
 * property list.
 *
 * Parameters:
 *	- nfs_mntlist_t *nfs_mount - The nfs mount to retrieve the properties
 *	from.
 *
 * Returns:
 *	- A pointer to a list of properties that correspond to the properties of
 *	nfs_mount.
 *	- Upon error, NULL is returned and the error is logged.
 */
static CCIMPropertyList *
populate_property_list(nfs_mntlist_t *nfs_mount) {
	CCIMException		*ex;
	CCIMPropertyList	*nfsMountPropList;
	CCIMObjectPath		*antOP;
	CCIMObjectPath		*depOP;
	cimchar			**propValues;
	int			i = 0;
	int			err = 0;

	nfsMountPropList = cim_createPropertyList();
	if (nfsMountPropList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSMOUNT::POPULATE_PROPLIST",
			CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE, ex, &err);
		return ((CCIMPropertyList *)NULL);
	}

	/*
	 * Create the CCIMProperties for this instance
	 */

	/*
	 * Antecedent
	 */
	antOP = get_Antecedent(nfs_mount->nml_mountp);
	if (antOP == NULL) {
		cim_freePropertyList(nfsMountPropList);
		return ((CCIMPropertyList *)NULL);
	}
	nfsMountPropList = add_property_to_list(nfsMountProps[ANT].name,
		nfsMountProps[ANT].type, NULL, antOP, nfsMountProps[ANT].isKey,
		nfsMountPropList);

	/*
	 * Dependent
	 */
	depOP = get_Dependent(nfs_mount);
	if (depOP == NULL) {
		cim_freePropertyList(nfsMountPropList);
		return ((CCIMPropertyList *)NULL);
	}
	nfsMountPropList = add_property_to_list(nfsMountProps[DEP].name,
		nfsMountProps[DEP].type, NULL, depOP, nfsMountProps[DEP].isKey,
		nfsMountPropList);

	propValues = calloc((size_t)PROPCOUNT, (size_t)sizeof (cimchar *));
	if (propValues == NULL) {
		util_handleError("SOLARIS_NFSMOUNT::POPULATE_PROPLIST",
			CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, &err);
		return ((CCIMPropertyList *)NULL);
	}

	if (populate_property_values(nfs_mount, propValues) == cim_false) {
		fileutil_free_string_array(propValues, PROPCOUNT);
		cim_freePropertyList(nfsMountPropList);
		return ((CCIMPropertyList *)NULL);
	}

	for (i = 0; i < PROPCOUNT; i++) {
		if (i == ANT || i == DEP) {
			continue;
		}
		nfsMountPropList = add_property_to_list(nfsMountProps[i].name,
			nfsMountProps[i].type, propValues[i], NULL,
			nfsMountProps[i].isKey, nfsMountPropList);
		if (nfsMountPropList == NULL) {
			fileutil_free_string_array(propValues, PROPCOUNT);
			return ((CCIMPropertyList *)NULL);
		}
	}

	fileutil_free_string_array(propValues, PROPCOUNT);
	return (nfsMountPropList);
} /* populate_property_list */

static CIMBool
populate_property_values(nfs_mntlist_t *nfs_mount,
	cimchar **propValues) {

	fs_mntdefaults_t	vfstab_filter;
	fs_mntdefaults_t	*vfstab_entry;
	boolean_t		readonly;
	boolean_t		optHasEquals;
	char			*enableQuota, *failoverList, *noSuid,
				*posix, *public, *port;
	cimchar			propValue[MAXSIZE];
	int			defaultValue = 0;
	int			err = 0;

	/*
	 * AttributeCaching
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", !(nfs_mount->nml_noac));
	propValues[ATTRCACHE] = strdup(propValue);
	if (propValues[ATTRCACHE] == NULL) {
		return (cim_false);
	}

	/*
	 * AttributeCachingForDirectoriesMax
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_acdirmax);
	propValues[ATTRCACHEDIRMAX] = strdup(propValue);
	if (propValues[ATTRCACHEDIRMAX] == NULL) {
		return (cim_false);
	}

	/*
	 * AttributeCachingForDirectoriesMin
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_acdirmin);
	propValues[ATTRCACHEDIRMIN] = strdup(propValue);
	if (propValues[ATTRCACHEDIRMIN] == NULL) {
		return (cim_false);
	}

	/*
	 * AttributeCachingForRegularFilesMax
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_acregmax);
	propValues[ATTRCACHEFILESMAX] = strdup(propValue);
	if (propValues[ATTRCACHEFILESMAX] == NULL) {
		return (cim_false);
	}

	/*
	 * AttributeCachingForRegularFilesMin
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_acregmin);
	propValues[ATTRCACHEFILESMIN] = strdup(propValue);
	if (propValues[ATTRCACHEFILESMIN] == NULL) {
		return (cim_false);
	}

	/*
	 * EnableQuotaChecking
	 */
	optHasEquals = B_FALSE;
	enableQuota = get_property_from_opt_string(nfs_mount->nml_mntopts,
		"quota", optHasEquals, defaultValue);
	if (enableQuota == NULL) {
		return (cim_false);
	}
	propValues[ENABLEQUOTA] = strdup(enableQuota);
	if (propValues[ENABLEQUOTA] == NULL) {
		return (cim_false);
	}
	free(enableQuota);

	/*
	 * FailoverList
	 */
	failoverList = cim_encodeStringArray(nfs_mount->nml_failoverlist,
		nfs_mount->nml_failovercount);
	if (failoverList == NULL) {
		cim_logDebug("populate_property_values", "encoding FAILED");
		return (cim_false);
	}
	propValues[FAILOVER] = strdup(failoverList);
	if (propValues[FAILOVER] == NULL) {
		return (cim_false);
	}

	/*
	 * ForceDirectIO
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_directio);
	propValues[FORCEDIRECTIO] = strdup(propValue);
	if (propValues[FORCEDIRECTIO] == NULL) {
		return (cim_false);
	}

	/*
	 * FsType
	 */
	propValues[FSTYPE] = strdup(nfs_mount->nml_fstype);
	if (propValues[FSTYPE] == NULL) {
		return (cim_false);
	}

	/*
	 * GroupId
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_grpid);
	propValues[GRPID] = strdup(propValue);
	if (propValues[GRPID] == NULL) {
		return (cim_false);
	}

	/*
	 * HardMount
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_hard);
	propValues[HARDMNT] = strdup(propValue);
	if (propValues[HARDMNT] == NULL) {
		return (cim_false);
	}

	/*
	 * Interrupt
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_intr);
	propValues[INTR] = strdup(propValue);
	if (propValues[INTR] == NULL) {
		return (cim_false);
	}

	/*
	 * MaxRetransmissionAttempts
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_retrans);
	propValues[MAXRETRANSATTEMPTS] = strdup(propValue);
	if (propValues[MAXRETRANSATTEMPTS] == NULL) {
		return (cim_false);
	}

	/*
	 * MountAtBootEntry - Deprecated
	 */
	vfstab_filter.resource = nfs_mount->nml_resource;
	vfstab_filter.fsckdevice = NULL;
	vfstab_filter.mountp = nfs_mount->nml_mountp;
	vfstab_filter.fstype = nfs_mount->nml_fstype;
	vfstab_filter.fsckpass = NULL;
	vfstab_filter.mountatboot = NULL;
	vfstab_filter.mntopts = NULL;

	err = 0;
	/*
	 * The space allocated for the value returned by
	 * fs_get_filtered_mount_defaults is freed later in this function
	 * because it is needed to set the value of the VfstabEntry property.
	 */
	vfstab_entry = fs_get_filtered_mount_defaults(&vfstab_filter, &err);
	if (vfstab_entry == NULL) {
		if (err != 0) {
			util_handleError("SOLARIS_NFSMOUNT::POPULATE_PROPLIST",
				CIM_ERR_FAILED,
				FS_GET_FILTERED_MNTDEFAULTS_FAILURE, NULL,
				&err);
			return (cim_false);
		}
		(void) snprintf(propValue, (size_t)MAXSIZE, "%d", B_FALSE);
	} else {
		/*
		 * The possible values in the mount at boot field are "yes",
		 * "no" and "-".  The "-" character, although it is not likely
		 * to be used, will be interpretted as the mount is to not be
		 * mounted at boot.  "-" is used when a field does not apply to
		 * the resource being mounted.
		 */
		if (strcasecmp(vfstab_entry->mountatboot, "yes") == 0) {
			(void) snprintf(propValue, (size_t)MAXSIZE, "%d",
			    B_TRUE);
		} else {
			(void) snprintf(propValue, (size_t)MAXSIZE, "%d",
			    B_FALSE);
		}
	}
	propValues[MNTATBOOTENTRY] = strdup(propValue);
	if (propValues[MNTATBOOTENTRY] == NULL) {
		return (cim_false);
	}

	/*
	 * MountOptions
	 */
	propValues[MNTOPTS] = strdup(nfs_mount->nml_mntopts);
	if (propValues[MNTOPTS] == NULL) {
		return (cim_false);
	}

	/*
	 * MountFailureRetries - This value is only valid upon creation of an
	 * instance of Solaris_NFSMount.  This is actually a mount _process_
	 * option and not a mount option.
	 */

	/*
	 * NoCloseToOpenConsistency
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_nocto);
	propValues[NOCTO] = strdup(propValue);
	if (propValues[NOCTO] == NULL) {
		return (cim_false);
	}

	/*
	 * NoMnttabEntry - This will always be false for every nfs mount that
	 * is shown in the CIM/WBEM interface because there is no way to
	 * programatically determine a file system that is mounted if it is not
	 * in /etc/mnttab.  If it is not in /etc/mnttab, it is like that for a
	 * reason and is also an argument for not showing the existense of
	 * those file systems.
	 */
	(void) snprintf(propValue, (size_t)MAXSIZE, "%d", B_FALSE);
	propValues[NOMNTTABENT] = strdup(propValue);
	if (propValues[NOMNTTABENT] == NULL) {
		return (cim_false);
	}

	/*
	 * NoSuid
	 */
	optHasEquals = B_FALSE;
	noSuid = get_property_from_opt_string(nfs_mount->nml_mntopts,
		"nosuid", optHasEquals, defaultValue);
	if (noSuid == NULL) {
		return (cim_false);
	}
	propValues[NOSUID] = strdup(noSuid);
	if (propValues[NOSUID] == NULL) {
		return (cim_false);
	}
	free(noSuid);

	/*
	 * Overlay - This is a property which is only valid upon creation of a
	 * Solaris_NFSMount instance.  It specifies that the file system to be
	 * mounted should be mounted on top of another existing mounted file
	 * system.
	 */

	/*
	 * Overlayed
	 */
	/*
	 * We must do some magic here with determining an overlayed file system.
	 * We must check for mounts with the same mount point and determine
	 * which is further down in the mnttab list to determine the top most
	 * file system.  This is all done in the fs_mounts interface.
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_overlayed);
	propValues[OVERLAYED] = strdup(propValue);
	if (propValues[OVERLAYED] == NULL) {
		return (cim_false);
	}

	/*
	 * Posix
	 */
	optHasEquals = B_FALSE;
	posix = get_property_from_opt_string(nfs_mount->nml_mntopts, "posix",
		optHasEquals, defaultValue);
	if (posix == NULL) {
		return (cim_false);
	}
	propValues[POSIX] = strdup(posix);
	if (propValues[POSIX] == NULL) {
		return (cim_false);
	}
	free(posix);

	/*
	 * Protocol
	 */
	propValues[PROTO] = strdup(nfs_mount->nml_proto);
	if (propValues[PROTO] == NULL) {
		return (cim_false);
	}

	/*
	 * Public
	 */
	optHasEquals = B_FALSE;
	public = get_property_from_opt_string(nfs_mount->nml_mntopts,
		"public", optHasEquals, defaultValue);
	if (public == NULL) {
		return (cim_false);
	}
	propValues[PUBLIC] = strdup(public);
	if (propValues[PUBLIC] == NULL) {
		return (cim_false);
	}
	free(public);

	/*
	 * ReadBufferSize
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_curread);
	propValues[READBUFFSIZE] = strdup(propValue);
	if (propValues[READBUFFSIZE] == NULL) {
		return (cim_false);
	}

	/*
	 * ReadOnly
	 */
	readonly = fs_is_readonly(nfs_mount->nml_mountp, &err);
	if (err != 0) {
		return (cim_false);
	}
	(void) snprintf(propValue, (size_t)MAXSIZE, "%d", readonly);
	propValues[READONLY] = strdup(propValue);
	if (propValues[READONLY] == NULL) {
		return (cim_false);
	}

	/*
	 * ReplicatedResources - Deprecated.
	 */
	/*
	 * This is the same as the FailoverList so we can use the value used
	 * to create that property (failoverList).
	 */
	propValues[REPLRESOURCES] = strdup(failoverList);
	if (propValues[REPLRESOURCES] == NULL) {
		free(failoverList);
		return (cim_false);
	}
	free(failoverList);

	/*
	 * RetransmissionTimeout
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_timeo);
	propValues[RETRANSTIMEO] = strdup(propValue);
	if (propValues[RETRANSTIMEO] == NULL) {
		return (cim_false);
	}

	/*
	 * RetryInForeground - This value is only valid upon creation of an
	 * instance of Solaris_NFSMount.  This is actually a mount _process_
	 * option and not a mount option.
	 */

	/*
	 * SecurityMode
	 */
	if (nfs_mount->nml_securitymode == NULL) {
		cim_logDebug("populate_property_value", "secmode == NULL");
	} else {
		cim_logDebug("populate_property_value", "secmode =%s",
			nfs_mount->nml_securitymode);
	}

	if (nfs_mount->nml_securitymode != NULL) {
		propValues[SECMODE] = strdup(nfs_mount->nml_securitymode);
		if (propValues[SECMODE] == NULL) {
			return (cim_false);
		}
	}

	/*
	 * ServerCommunicationPort
	 */
	optHasEquals = B_TRUE;
	defaultValue = NFS_PORT;
	port = get_property_from_opt_string(nfs_mount->nml_mntopts, "port=",
		optHasEquals, defaultValue);
	if (port == NULL) {
		return (cim_false);
	}
	propValues[SERVERCOMMPORT] = strdup(port);
	if (propValues[SERVERCOMMPORT] == NULL) {
		return (cim_false);
	}
	free(port);

	/*
	 * ServerName
	 */
	propValues[SERVERNAME] = strdup(nfs_mount->nml_curserver);
	if (propValues[SERVERNAME] == NULL) {
		return (cim_false);
	}

	/*
	 * ServerPath
	 */
	propValues[SERVERPATH] = strdup(nfs_mount->nml_curpath);
	if (propValues[SERVERPATH] == NULL) {
		return (cim_false);
	}

	/*
	 * Version
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_vers);
	propValues[VERS] = strdup(propValue);
	if (propValues[VERS] == NULL) {
		return (cim_false);
	}

	/*
	 * VfstabEntry
	 */
	/*
	 * The vfstab_entry variable is retrieved from the
	 * fs_get_filtered_mount_defaults call when populating the
	 * MountAtBootEntry property.
	 */
	if (vfstab_entry == NULL) {
		(void) snprintf(propValue, MAXSIZE, "%d", B_FALSE);
	} else {
		(void) snprintf(propValue, MAXSIZE, "%d", B_TRUE);
		fs_free_mntdefaults_list(vfstab_entry);
	}
	propValues[VFSTABENTRY] = strdup(propValue);
	if (propValues[VFSTABENTRY] == NULL) {
		return (cim_false);
	}

	/*
	 * WriteBufferSize
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_curwrite);
	propValues[WRITEBUFFSIZE] = strdup(propValue);
	if (propValues[WRITEBUFFSIZE] == NULL) {
		return (cim_false);
	}

	/*
	 * Xattr
	 */
	(void) snprintf(propValue, MAXSIZE, "%d", nfs_mount->nml_xattr);
	propValues[XATTR] = strdup(propValue);
	if (propValues[XATTR] == NULL) {
		return (cim_false);
	}

	cim_logDebug("populate_property_values", "returning cim_true");
	return (cim_true);
} /* populate_property_values */
