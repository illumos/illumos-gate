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

#include "Solaris_NFSShareSecurity.h"
#include "nfs_keys.h"
#include "nfs_provider_names.h"
#include "nfs_providers_msgstrings.h"
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
#define	SECMODES 5
#define	DEFAULT_MAXLIFE 30000
#define	MAXSIZE 256


/*
 * Private variables
 */

/*
 * Private method declarations
 */

static CCIMInstanceList *create_nfsShareSec_InstList(
			    fs_sharelist_t *nfs_sharesec_list, int *err);
static CCIMInstanceList	*enumerate_sharesecurity();
static CCIMPropertyList	*populate_Solaris_NFSShareSecurity_property_list(
			    fs_sharelist_t *nfs_share, char *secmode_opts);
static void		populate_Solaris_NFSShareSecurity_property_Values(
			    char *path,
			    cimchar propValues[PROPCOUNT][MAXSIZE],
			    char *secmode_opts, int *err);

/*
 * Public methods
 */

/*
 * Instance provider methods
 */

/*
 * Solaris_NFSShareSecurity provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the CIMOM as the caller.
 */

/*
 * Name: cp_enumInstances_Solaris_NFSShareSecurity
 *
 * Description: Returns a list of instances if found.
 *
 * Parameters:
 *      shareOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMInstanceList * if matched instance is found. Otherwise, NULL.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_enumInstances_Solaris_NFSShareSecurity(CCIMObjectPath* shareOP) {
	CCIMInstanceList *instList;
	int err = 0;

	cim_logDebug("cp_enumInstances_Solaris_NFSShareSecurity",
	    "Just entering...");
	/*
	 * Check object path for NULL value
	 */
	if (shareOP == NULL) {
		util_handleError(
		    "SOLARIS_NFSSHARESECURITY::ENUM_INSTANCES",
		    CIM_ERR_INVALID_PARAMETER, NULL,
		    NULL, &err);
		return ((CCIMInstanceList *)NULL);
	}

	instList = enumerate_sharesecurity();
	if (instList == NULL) {
		cim_logDebug("cp_enumInstances_Solaris_NFSShareSecurity",
		    "Call to enumerate_sharesecurity returned NULL");
		util_handleError(
		    "SOLARIS_NFSSHARESECURITY::ENUM_INSTANCES",
		    CIM_ERR_FAILED, CIMOM_ENUM_INST_FAILURE,
		    NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	cim_logDebug("cp_enumInstances_Solaris_NFSShareSecurity",
	    "Returning Solaris_NFSShareSecurity instance");
	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_NFSShareSecurity
 *
 * Description:  Enumerates all of the security modes and options for all
 * of the nfs shares on the host.
 *
 * Parameters:
 *      shareOP - An CCIMObjectPath * which contains the information on
 *      the class for which to find the instance.
 * Returns:
 *      CCIMObjectPathList * if matched instance is found. Otherwise, NULL.
 */

/* ARGUSED */
CCIMObjectPathList *
cp_enumInstanceNames_Solaris_NFSShareSecurity(CCIMObjectPath* shareOP) {
	CCIMInstanceList *instList;
	CCIMObjectPathList *OPList;
	CCIMException *ex;
	int err = 0;

	instList = cp_enumInstances_Solaris_NFSShareSecurity(shareOP);
	if (instList == NULL) {
		util_handleError(
		    "SOLARIS_NFSSHARESECURITY::ENUM_INSTANCES",
		    CIM_ERR_FAILED, CIMOM_ENUM_INSTNAMES_FAILURE,
		    NULL, &err);
		return ((CCIMObjectPathList *)NULL);
	}

	OPList = cim_createObjectPathList(instList);
	if (OPList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHARESECURITY::ENUM_INSTANCENAMES",
		    CIM_ERR_FAILED, CREATE_OBJECT_LIST_FAILURE, ex, &err);
		cim_freeCIMException(ex);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	}
	cim_freeInstanceList(instList);
	return (OPList);
}

/*
 * Name: cp_getInstance_Solaris_NFSShareSecurity
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

CCIMInstance *
cp_getInstance_Solaris_NFSShareSecurity(CCIMObjectPath* shareOP) {
	CCIMInstanceList *instList;
	CCIMInstance *inst;
	CCIMException *ex;
	int err = 0;

	instList = cp_enumInstances_Solaris_NFSShareSecurity(shareOP);
	if (instList == NULL) {
		util_handleError(
		    "SOLARIS_NFSSHARESECURITY::GET_INSTANCE",
		    CIM_ERR_FAILED, CIMOM_ENUM_INST_FAILURE,
		    NULL, &err);
		return ((CCIMInstance *)NULL);
	}

	inst = cim_getInstance(instList, shareOP);
	if (inst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECURITY::GET_INSTANCE",
			CIM_ERR_INVALID_CLASS, GET_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(instList);
		return ((CCIMInstance *)NULL);
	}

	cim_freeInstanceList(instList);
	cim_logDebug("cp_getInstance_Solaris_NFSShareSecurity",
	    "Returning instance");

	return (inst);
}

/*
 * cp_setInstance not supported
 */
/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_NFSShareSecurity(CCIMObjectPath *shareOP,
			CCIMInstance *shareInst,
			char **props, int num_props) {
	int err = 0;

	util_handleError("SOLARIS_NFSSHARESECURITY::SET_INSTANCE",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return (cim_false);
} /* cp_setInstance_Solaris_NFSShareSecurity */

/*
 * cp_setInstanceWithList not supported
 */
/* ARGSUSED */
CIMBool
cp_setInstanceWithList_Solaris_NFSShareSecurity(CCIMObjectPath *shareOP,
			CCIMInstance *shareInst,
			char **props, int num_props) {
	int err = 0;

	util_handleError("SOLARIS_NFSSHARESECURITY::SET_INSTANCEWITHLIST",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return (cim_false);
}

/*
 * cp_invokeMethod not supported
 */
/* ARGSUSED */
CCIMProperty *
cp_invokeMethod_Solaris_NFSShareSecurity(
    CCIMObjectPath *pOP,
    cimchar *functionName,
    CCIMPropertyList *inParams,
    CCIMPropertyList *outParams) {

	int 	err = 0;
	util_handleError("SOLARIS_NFSSHARESECURITY::INVOKE_METHOD",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return ((CCIMProperty *)NULL);
} /* cp_invokeMethod_Solaris_NFSShareSecurity */


/*
 * cp_setProperty not supported
 */
/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_NFSShareSecurity(CCIMObjectPath *pOP,
    CCIMProperty *pProp) {
	int	err = 0;
	util_handleError("SOLARIS_NFSSHARESECURITY::SET_PROPERTY",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return (cim_false);
}

/*
 * cp_createInstance not supported
 */
/* ARGSUSED */
CCIMObjectPath *
cp_createInstance_Solaris_NFSShareSecurity(CCIMObjectPath *shareOP,
	CCIMInstance *shareInst) {

	int err = 0;

	util_handleError("SOLARIS_NFSSHARESECURITY::CREATE_INSTANCE",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return ((CCIMObjectPath *)NULL);
}

/*
 * cp_deleteInstance not supported
 */
/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_NFSShareSecurity(CCIMObjectPath *shareOP) {

	int err = 0;

	util_handleError("SOLARIS_NFSSHARESECURITY::DELETE_INSTANCE",
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &err);
	return (cim_false);
}

/*
 * Name: cp_execQuery_Solaris_NFSShareSecurity
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
CCIMInstanceList*
cp_execQuery_Solaris_NFSShareSecurity(CCIMObjectPath *shareOP,
    char *selectClause, char *nonJoinExp, char *queryExp, char *queryLang) {

	CCIMInstance		*emptyInst;
	CCIMInstanceList	*shareSecInstList;
	CCIMInstanceList	*resultInstList;
	CCIMException		*ex;
	int			err = 0;

	shareSecInstList = cp_enumInstances_Solaris_NFSShareSecurity(shareOP);
	if (shareSecInstList == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECURITY::EXEC_QUERY",
		    CIM_ERR_FAILED, CIMOM_ENUM_INST_FAILURE, ex, &err);
		return ((CCIMInstanceList *)NULL);
	}

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
		ex = cim_getLastError();
		util_handleError("SOLARIS_NFSSHARESECURITY::EXEC_QUERY",
		    CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, &err);
		cim_freeCIMException(ex);
		cim_freeInstanceList(shareSecInstList);
		return ((CCIMInstanceList *)NULL);
	}

	resultInstList = cim_prependInstance(shareSecInstList, emptyInst);
	if (resultInstList == NULL) {
		util_handleError("SOLARIS_NFSSHARESECURITY::EXEC_QUERY",
		    CIM_ERR_FAILED, PREPEND_INSTANCE_FAILURE, ex, &err);
		cim_freeInstanceList(shareSecInstList);
		cim_freeInstance(emptyInst);
	}
	return (resultInstList);

} /* cp_execQuery_Solaris_NFSShareSecurity */


/*
 * Private Methods
 */

/*
 * create_nfsShareSec_InstList
 *
 * Creates the Solaris_NFSShareSecurity instance list from information
 * gathered from the shares on the system. The instance list is returned.
 */
static CCIMInstanceList *
create_nfsShareSec_InstList(fs_sharelist_t *nfs_sharesec_list, int *err) {
	fs_sharelist_t		*currentShare;
	CCIMInstanceList	*nfsShareSecInstList;
	CCIMException		*ex;
	char			**sec_modes;
	int			count;

	cim_logDebug("create_nfsShareSec_InstList", "Just entering...");
	/*
	 * At this point, one or more nfs shares were found on the
	 * system, create the instance list from the nfs_sharesec_list.
	 */
	nfsShareSecInstList = cim_createInstanceList();
	if (nfsShareSecInstList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHARESECURITY::CREATE_INST_LIST ",
		    CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE,
		    ex, err);
		return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Loop through the security modes for the nfs shares to
	 * retrieve their security properties and create an
	 * instance list containing all the security modes and
	 * their properties for each share.
	 */
	for (currentShare = nfs_sharesec_list; currentShare != NULL;
	    currentShare = currentShare->next) {
		int i;
		CCIMInstance 		*solaris_NFSShareSec_instance;
		CCIMPropertyList	*solaris_NFSShareSec_prop_list;

		/*
		 * Parse the the share options list for multiple
		 * security modes. An array of strings is returned
		 * that will be used to create the instances for each
		 * share.
		 */
		sec_modes = fs_parse_opts_for_sec_modes(
		    currentShare->options, &count, err);
		if (sec_modes == NULL) {
			util_handleError(
			    "SOLARIS_NFSSHARESECURITY::CREATE_INST_LIST ",
			    CIM_ERR_INVALID_PARAMETER, NULL, NULL, err);
			return ((CCIMInstanceList *)NULL);
		}
		for (i = 0; i < count; i++) {
			/*
			 * Create the Solaris_NFSShareSecurity
			 * CCIMInstance
			 */
			solaris_NFSShareSec_instance =
			    cim_createInstance(SOLARIS_NFSSHARESECURITY);
			if (solaris_NFSShareSec_instance == NULL) {
				ex = cim_getLastError();
				util_handleError("SOLARIS_NFSSHARESECURITY:" \
				    ":CREATE_INST_LIST", CIM_ERR_FAILED,
				    CREATE_INSTANCE_FAILURE, ex, err);
				cim_freeInstanceList(nfsShareSecInstList);
				fileutil_free_string_array(sec_modes, count);
				return ((CCIMInstanceList *)NULL);
			}

			solaris_NFSShareSec_prop_list =
			    populate_Solaris_NFSShareSecurity_property_list(
			    currentShare, sec_modes[i]);
			if (solaris_NFSShareSec_prop_list == NULL) {
				/*
				 * populatePropertyList already logged
				 * this error so there is no need to
				 * log it here.
				 */
				cim_freeInstance(solaris_NFSShareSec_instance);
				cim_freeInstanceList(nfsShareSecInstList);
				fileutil_free_string_array(sec_modes, count);
				return ((CCIMInstanceList *)NULL);
			}

			/*
			 * Add the property list to the instance
			 */
			solaris_NFSShareSec_instance =
			    cim_addPropertyListToInstance(
				solaris_NFSShareSec_instance,
				solaris_NFSShareSec_prop_list);
			if (solaris_NFSShareSec_instance == NULL) {
				ex = cim_getLastError();
				util_handleError("SOLARIS_NFSSHARESECURITY:" \
				    ":CREATE_INST_LIST", CIM_ERR_FAILED,
				    PROPLIST_TO_INSTANCE_FAILURE, ex, err);
				cim_freePropertyList(
				    solaris_NFSShareSec_prop_list);
				cim_freeInstanceList(nfsShareSecInstList);
				fileutil_free_string_array(sec_modes, count);
				return ((CCIMInstanceList *)NULL);
			}

			/*
			 * Add the instance to the instance list
			 */
			nfsShareSecInstList =
			    cim_addInstance(nfsShareSecInstList,
			    solaris_NFSShareSec_instance);
			if (nfsShareSecInstList == NULL) {
				ex = cim_getLastError();
				util_handleError("SOLARIS_NFSSHARESECURITY:" \
				    ":CREATE_INST_LIST", CIM_ERR_FAILED,
				    ADD_INSTANCE_FAILURE, ex, err);
				cim_freeInstance(solaris_NFSShareSec_instance);
				fileutil_free_string_array(sec_modes, count);
				return ((CCIMInstanceList *)NULL);
			}
		} /* for (int i; i < count; i++) */

	} /* for (currentShare = nfs_sharesec_list; ...) */

	fileutil_free_string_array(sec_modes, count);

	cim_logDebug("create_nfsShareSec_InstList", "Returning instance list");
	return (nfsShareSecInstList);

} /* create_nfsShareSec_InstList */

/*
 * enumerate_sharesecurity
 * Enumerate the nfs sharesecurity modes for each share by using the
 * fs_shares fs_get_share_list method to get the security modes from
 * the option string.
 */
static CCIMInstanceList *
enumerate_sharesecurity() {

	int		err;
	fs_sharelist_t 	*nfs_sharesec_list;

	cim_logDebug("enumerate_sharesecurity", "Just entering...");
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
				    "SOLARIS_NFSSHARESECURITY:" \
				    ":ENUM_SHARESECURITY ",
				    CIM_ERR_LOW_ON_MEMORY,
				    NULL, NULL, &err);
				return ((CCIMInstanceList *)NULL);
			} else {

				/*
				 * If any other errors were encountered it
				 * can be handled as a general error.  We may
				 * not know exactly what the error is.
				 */
				util_handleError(
				    "SOLARIS_NFSSHARESECURITY:" \
				    ":ENUM_SHARESECURITY ",
				    CIM_ERR_FAILED,
				    strerror(err), NULL, &err);
				return ((CCIMInstanceList *)NULL);
			}
		}
		/*
		 * There are no nfs shares on the host.
		 */
		cim_logDebug("enumerate_sharesecurity", "No shares on system");
		return ((CCIMInstanceList *)NULL);

	} else {

		CCIMInstanceList	*nfsShareSecInstList;

		nfsShareSecInstList =
		    create_nfsShareSec_InstList(nfs_sharesec_list, &err);

		fs_free_share_list(nfs_sharesec_list);

		return (nfsShareSecInstList);
	}
} /* enumerate_sharesecurity */

/*
 * populate_Solaris_NFSShareSecurity_property_list
 * Populates the property list with that share information for each
 * instance in the instance list.
 */
static CCIMPropertyList *
populate_Solaris_NFSShareSecurity_property_list(
    fs_sharelist_t *nfs_share, char *secmode_opts) {

	CCIMException		*ex;
	CCIMPropertyList	*nfsShareSecPropList;
	char			propValues[PROPCOUNT][MAXSIZE];
	int			i, err = 0;

	cim_logDebug("populate_Solaris_NFSShareSecurity_property_list",
	    "Just entering...");

	nfsShareSecPropList = cim_createPropertyList();
	if (nfsShareSecPropList == NULL) {
		ex = cim_getLastError();
		util_handleError(
		    "SOLARIS_NFSSHARESECURITY::POPULATE_PROPLIST",
		    CIM_ERR_FAILED, CREATE_PROPLIST_FAILURE, ex, &err);
		cim_freeCIMException(ex);
		goto out;
	}

	/*
	 * Create the CCIMProperties for this instance
	 */
	populate_Solaris_NFSShareSecurity_property_Values(
	    nfs_share->path, propValues, secmode_opts, &err);
	if (err != 0) {
		cim_freePropertyList(nfsShareSecPropList);
		nfsShareSecPropList = NULL;
	} else {
		for (i = 0; i < PROPCOUNT; i++) {
			cim_logDebug(
			    "populate_Solaris_NFSShareSecurity_property_list",
			    "propValues[%d] = %s", i, propValues[i]);
			nfsShareSecPropList =
			    add_property_to_list(nfsShareSecProps[i].name,
			    nfsShareSecProps[i].type, propValues[i], NULL,
			    nfsShareSecProps[i].isKey, nfsShareSecPropList);
			if (nfsShareSecPropList == NULL) {
				goto out;
			}
		}
	}
out:
	cim_logDebug("populate_Solaris_NFSShareSecurity_property_list",
	    "Returning property list");
	return (nfsShareSecPropList);

} /* populate_Solaris_NFSShareSecurity_property_list */

/*
 * populate_Solaris_NFSShareSecurity_property_Values
 * Populates the property array for use in the populate_property_list function
 */
static void
populate_Solaris_NFSShareSecurity_property_Values(char *path,
    cimchar propValues[PROPCOUNT][MAXSIZE], char *secmode_opts, int *err) {

	boolean_t	hasEquals;
	int		defaultValue = B_FALSE;
	int		count = 0;
	char		**access_list;
	char		*optValue;
	cimchar		*propString;


	cim_logDebug("populate_Solaris_NFSShareSecurity_property_Values",
	    "Just entering...");
	/*
	 * Check for security mode option in option string.
	 * Key - Mode
	 */
	hasEquals = B_TRUE;
	defaultValue = B_FALSE;

	optValue = get_property_from_opt_string(secmode_opts,
	    "sec=", hasEquals, defaultValue);
	if (strcmp(optValue, "0") != 0) {
		(void) snprintf(propValues[SEC_MODE], MAXSIZE, "%s", optValue);
	} else {
		/*
		 * The default security mode is set only if no security
		 * mode is set in the option string.
		 */
		(void) snprintf(propValues[SEC_MODE], MAXSIZE, "%s", "sys");
	}
	cim_logDebug("populate_Solaris_NFSShareSecurity_property_Values",
	    "%s = %s", nfsShareSecProps[SEC_MODE].name, propValues[SEC_MODE]);
	free(optValue);

	/*
	 * MaxLife
	 * only used with sec mode of "dh"
	 */
	if (strcmp(propValues[SEC_MODE], "dh") == 0) {
		hasEquals = B_TRUE;
		defaultValue = DEFAULT_MAXLIFE;
		optValue =
		    get_property_from_opt_string(secmode_opts,
		    "window=", hasEquals, defaultValue);
		(void) snprintf(propValues[MAXLIFE], MAXSIZE, "%s", optValue);
		cim_logDebug(
		    "populate_Solaris_NFSShareSecurity_property_Values",
		    "%s = %s", nfsShareSecProps[MAXLIFE].name,
		    propValues[MAXLIFE]);
	} else {
		(void) snprintf(propValues[MAXLIFE], MAXSIZE, "\0");
	}
	free(optValue);

	/*
	 * Path
	 */
	if (path != NULL) {
		(void) snprintf(propValues[PATH], MAXSIZE, "%s",
		    path);
		cim_logDebug(
		    "populate_Solaris_NFSShareSecurity_property_Values",
		    "%s = %s", nfsShareSecProps[PATH].name, propValues[PATH]);
	} else {
		(void) snprintf(propValues[PATH], MAXSIZE, "\0");
		cim_logDebug(
		    "populate_Solaris_NFSShareSecurity_property_Values",
		    "%s = %s", nfsShareSecProps[PATH].name, "null");
	}

	/*
	 * ReadOnly
	 */
	hasEquals = B_FALSE;
	defaultValue = B_FALSE;
	optValue = get_property_from_opt_string(secmode_opts,
	    "ro", hasEquals, defaultValue);
	(void) snprintf(propValues[READONLY], MAXSIZE, "%s", optValue);
	cim_logDebug(
	    "populate_Solaris_NFSShareSecurity_property_Values",
	    "%s = %s", nfsShareSecProps[READONLY].name, propValues[READONLY]);
	free(optValue);

	/*
	 * Read Write List
	 */
	hasEquals = B_TRUE;
	defaultValue = B_FALSE;
	optValue = get_property_from_opt_string(secmode_opts, "rw=",
	    hasEquals, defaultValue);
	if (strcmp(optValue, "0") != 0) {
		access_list =
		    fs_create_array_from_accesslist(optValue,
		    &count, err);
		propString = cim_encodeStringArray(access_list, count);
		if (propString == NULL) {
			*err = ENOMEM;
			return;
		}
		free(optValue);
		optValue = strdup(propString);
		if (optValue == NULL) {
			*err = ENOMEM;
			return;
		}
		free(propString);
		fileutil_free_string_array(access_list, count);
	} else {
		optValue = strdup("\0");
	}
	(void) snprintf(propValues[READWRITELIST], MAXSIZE, "%s", optValue);
	cim_logDebug("populate_Solaris_NFSShareSecurity_property_Values",
	    "%s = %s", nfsShareSecProps[READWRITELIST].name,
	    propValues[READWRITELIST]);
	free(optValue);
	count = 0;

	/*
	 * Read Only List
	 */
	hasEquals = B_TRUE;
	defaultValue = B_FALSE;
	optValue = get_property_from_opt_string(secmode_opts, "ro=",
	    hasEquals, defaultValue);

	if (strcmp(optValue, "0") != 0) {
		access_list =
		    fs_create_array_from_accesslist(optValue,
		    &count, err);
		propString = cim_encodeStringArray(access_list, count);
		if (propString == NULL) {
			*err = ENOMEM;
			return;
		}
		free(optValue);
		optValue = strdup(propString);
		if (optValue == NULL) {
			*err = ENOMEM;
			return;
		}
		free(propString);
		fileutil_free_string_array(access_list, count);
	} else {
		optValue = strdup("\0");
	}
	(void) snprintf(propValues[READONLYLIST], MAXSIZE, "%s", optValue);
	cim_logDebug("populate_Solaris_NFSShareSecurity_property_Values",
	    "%s = %s", nfsShareSecProps[READONLYLIST].name,
	    propValues[READONLYLIST]);
	free(optValue);
	count = 0;

	/*
	 * root server list
	 */
	hasEquals = B_TRUE;
	defaultValue = B_FALSE;
	optValue = get_property_from_opt_string(secmode_opts,
	    "root=", hasEquals, defaultValue);
	if (strcmp(optValue, "0") != 0) {
		access_list =
		    fs_create_array_from_accesslist(optValue,
		    &count, err);
		propString = cim_encodeStringArray(access_list, count);
		if (propString == NULL) {
			*err = ENOMEM;
			return;
		}
		free(optValue);
		optValue = strdup(propString);
		if (optValue == NULL) {
			*err = ENOMEM;
			return;
		}
		free(propString);
		fileutil_free_string_array(access_list, count);
	} else {
		optValue = strdup("\0");
	}
	(void) snprintf(propValues[ROOTSERVERS], MAXSIZE, "%s", optValue);
	cim_logDebug("populate_Solaris_NFSShareSecurity_property_Values",
	    "%s = %s", nfsShareSecProps[ROOTSERVERS].name,
	    propValues[ROOTSERVERS]);
	free(optValue);

	cim_logDebug("populate_Solaris_NFSShareSecurity_property_Values",
	    "Returning");

} /* populate_Solaris_NFSShareSecurity_property_Values */
