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

#include <sys/types.h>
#include <string.h>
#include "createprop_methods.h"
#include "messageStrings.h"
#include "nfs_providers_msgstrings.h"
#include "nfs_provider_names.h"
#include "nfs_keys.h"
#include "libfsmgt.h"
#include "util.h"

#define	MAXSIZE	256

/*
 * Method: add_property_to_instance
 *
 * Description: Creates a property corresponding to the input parameters and
 * adds it to the instance passed in.
 *
 * Parameters:
 *	- cimchar *pName - The name of the property to be created.
 *	- CIMType pType - The type of the property.
 *	- cimchar *pValue - The value of the property if it is NOT to be a
 *	reference property.
 *	- CCIMObjectPath *pOP - The value of the property if it is to be a
 *	reference property.
 *	- CIMBool pIsKey - A boolean value representing whether or not the
 *	property is a key.
 *	- CCIMInstance *pInst - The instance that the property is added to.
 *
 * Returns:
 *	- A CIMBool which is true if the property was added to the instance and
 * 	false if it was not.
 */
CIMBool
add_property_to_instance(cimchar *pName, CIMType pType, cimchar *pValue,
	CCIMObjectPath *pOP, CIMBool pIsKey, CCIMInstance *pInst) {

	CCIMProperty	*prop;
	CCIMException	*ex;
	int		err = 0;

	if (pOP == NULL) {
		prop = cim_createProperty(pName, pType, pValue, NULL, pIsKey);
	} else {
		prop = cim_createReferenceProperty(pName, pOP, pIsKey);
	}

	if (prop == NULL) {
		ex = cim_getLastError();
		util_handleError(ADD_PROP_TO_INST, CIM_ERR_FAILED,
			CREATE_PROPERTY_FAILURE, ex, &err);
		return (cim_false);
	}

	if (cim_addProperty(pInst, prop) == cim_false) {
		ex = cim_getLastError();
		util_handleError(ADD_PROP_TO_INST, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, &err);
		cim_freeProperty(prop);
		return (cim_false);
	}

	return (cim_true);
} /* add_property_to_instance */

/*
 * Method: add_property_to_list
 *
 * Description: Creates a property corresponding to the input parameters and
 * adds it to the property list passed in.
 *
 * Parameters:
 *      - cimchar *pName - The name of the property to be created.
 *      - CIMType pType - The type of the property.
 *      - cimchar *pValue - The value of the property if it is NOT to be a
 *      reference property.
 *      - CCIMObjectPath *pOP - The value of the property if it is to be a
 *      reference property.
 *      - CIMBool pIsKey - A boolean value representing whether or not the
 *      property is a key.
 *      - CCIMPropertyList *pPropList - The property list that the property is
 *	added to.
 *
 * Returns:
 *	- A pointer to the property list that the property was added to.
 *	- NULL if an error occurred.
 *
 * NOTE: Upon error, the passed in CCIMPropertyList*, pPropList, is freed.
 * Since this is a wrapper for the cim_addPropertyToPropertyList function
 * this is done to be consistent with the way that the CIM C API works.
 * Upon error, the CCIMPropertyList passed into cim_addPropertyToPropertyList
 * is freed.
 */
CCIMPropertyList *
add_property_to_list(cimchar *pName, CIMType pType, cimchar *pValue,
	CCIMObjectPath *pOP, CIMBool pIsKey, CCIMPropertyList *pPropList) {

	CCIMProperty	*prop;
	CCIMException	*ex;
	int		err = 0;

	if (pOP == NULL) {
		prop = cim_createProperty(pName, pType, pValue, NULL, pIsKey);
	} else {
		prop = cim_createReferenceProperty(pName, pOP, pIsKey);
	}

	/*
	 * If NULL, an error was encountered.
	 */
	if (prop == NULL) {
		ex = cim_getLastError();
		util_handleError(ADD_PROP_TO_LIST, CIM_ERR_FAILED,
			CREATE_PROPERTY_FAILURE, ex, &err);
		cim_freePropertyList(pPropList);
		return ((CCIMPropertyList *)NULL);
	}

	pPropList = cim_addPropertyToPropertyList(pPropList, prop);
	if (pPropList == NULL) {
		ex = cim_getLastError();
		util_handleError(ADD_PROP_TO_LIST, CIM_ERR_FAILED,
			ADD_PROP_TO_PROPLIST_FAILURE, ex, &err);
		cim_freeProperty(prop);
		return ((CCIMPropertyList *)NULL);
	}

	/*
	 * Debugging...
	 */
	if (pValue != NULL) {
		cim_logDebug("add_property_to_list", "Adding %s, value %s",
			pName, pValue);
	}

	return (pPropList);
} /* add_property_to_list */

/*
 * Method: get_property_from_opt_string
 *
 * Description: Determines if a property exists in the mount option string and
 * returns a value of the property to be used in creating a CCIMProperty.
 *
 * Parameters:
 *	- char *mntopts - The mount option string to search.
 *	- char *option - The option to search for.
 *	- boolean_t optHasEquals - A boolean telling the method whether or not
 *	the option being searched for contains the "=" character.
 *	- int defaultValue - The value of the property if it is not found in
 *	the option string.
 *
 * Returns:
 *      - The string value of the property found.
 *	- NULL if an error occurred.
 *
 * NOTE: The caller must free space allocated for return value.
 */
cimchar *
get_property_from_opt_string(char *mntopts, char *option,
	boolean_t optHasEquals, int defaultValue) {

	cimchar	propValue[MAXSIZE];
	cimchar *retVal;
	char	*optionString = NULL;
	char	*optionFound;
	int	err = 0;

	optionString = strdup(mntopts);
	if (optionString == NULL) {
		util_handleError(GET_PROP_FROM_OPTS,
			CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, &err);
		return (NULL);
	} else {
		optionFound = fs_parse_optlist_for_option(optionString,
			option, &err);
		/*
		 * Was the option found in the option string?
		 * If it was, propValue = true or propValue = optionFound.
		 */
		if (optionFound != NULL) {
			if (optHasEquals) {
				(void) snprintf(propValue, MAXSIZE, "%s",
				    optionFound);
				free(optionFound);
			} else {
				(void) snprintf(propValue, MAXSIZE, "%d",
				    B_TRUE);
				free(optionFound);
			}
		} else {
			/*
			 * Since the option was not found we know that
			 * propValue = false or the default value.
			 */
			if (optHasEquals)  {
				(void) snprintf(propValue, MAXSIZE, "%d",
				    defaultValue);
			} else {
				(void) snprintf(propValue, MAXSIZE, "%d",
				    B_FALSE);
			}
		}
	}

	retVal = strdup(propValue);
	if (retVal == NULL) {
		util_handleError(GET_PROP_FROM_OPTS,
			CIM_ERR_LOW_ON_MEMORY, LOW_MEMORY, NULL, &err);
		return (NULL);
	}

	free(optionString);
	return (retVal);
} /* get_property_from_opt_string */

/*
 * Method set_dir_keyProperties_to_true
 *
 * Helper function to work around cimom bug 4649100 which causes
 * cimom_getInstance to return the instance with the value of
 * keyProperty set to cim_false instead of cim_true.
 */
CIMBool
set_dir_keyProperties_to_true(CCIMInstance *dirInst) {
	CCIMProperty		*tempProp;
	CCIMPropertyList	*tempPList;
	CIMBool			return_value = cim_false;

	for (tempPList = dirInst->mProperties; tempPList != NULL;
		tempPList = tempPList->mNext) {

		tempProp = tempPList->mDataObject;
		if (strcmp(tempProp->mName, CREATION_CLASS) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, NAME) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, CS_CREATION_CLASS)
			== 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, CSNAME) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, FS_CREATION_CLASS) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, FSNAME) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		}
	}
	return (return_value);
} /* set_dir_keyProperties_to_true */

/*
 * Method set_share_keyProperties_to_true
 *
 * Helper function to work around cimom bug 4649100 which causes
 * cimom_getInstance to return the instance with the value of
 * keyProperty set to cim_false instead of cim_true.
 */
CIMBool
set_share_keyProperties_to_true(CCIMInstance *nfsShareInst) {
	CCIMProperty		*tempProp;
	CCIMPropertyList	*tempPList;
	CIMBool			return_value = cim_false;

	for (tempPList = nfsShareInst->mProperties; tempPList != NULL;
		tempPList = tempPList->mNext) {

		tempProp = tempPList->mDataObject;
		if (strcmp(tempProp->mName, CREATION_CLASS) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, NAME) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, SYS_CREATION_CLASS)
			== 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, SYSTEM) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		}
	}
	return (return_value);
} /* set_share_keyProperties_to_true */

/*
 * Method set_shareSec_keyProperties_to_true
 *
 * Helper function to work around cimom bug 4649100 which causes
 * cimom_getInstance to return the instance with the value of
 * keyProperty set to cim_false instead of cim_true.
 */
CIMBool
set_shareSec_keyProperties_to_true(CCIMInstance *nfsShareSecInst) {
	CCIMProperty		*tempProp;
	CCIMPropertyList	*tempPList;
	CIMBool			return_value = cim_false;

	for (tempPList = nfsShareSecInst->mProperties; tempPList != NULL;
		tempPList = tempPList->mNext) {

		tempProp = tempPList->mDataObject;
		if (strcmp(tempProp->mName, MODE) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		} else if (strcmp(tempProp->mName, SETTING_ID_LOWCASE) == 0) {
			tempProp->mKeyProperty = cim_true;
			return_value = cim_true;
		}
	}
	return (return_value);
} /* set_shareSec_keyProperties_to_true */
