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

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <cimapi.h>
#include <libnvpair.h>
#include <md5.h>

#include "libdiskmgt.h"
#include "providerNames.h"
#include "messageStrings.h"
#include "cimKeys.h"
#include "util.h"

/*
 * Convert a single descriptor in to a Solaris_XXXController instance
 */

CCIMInstance *
ctrl_descriptor_toCCIMInstance(char *hostname, dm_descriptor_t  desc,
    char *provider, int *errp)
{

	CCIMInstance		*inst = NULL;
	CCIMException		*ex;
	nvlist_t		*nvlp;
	nvpair_t		*nvp;
	char			*str;
	int			error;

	*errp = 0;

	/* Create instance of controller */

	if ((inst = cim_createInstance(provider)) == NULL) {
	    ex = cim_getLastError();
	    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, errp);
	    return ((CCIMInstance *)NULL);
	}

	/* First, assign the deviceID */

	str = dm_get_name(desc, &error);

	if (error != 0) {
	    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	if (str == NULL) {
	    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty(DEVICEID, string, str, cim_true, inst, errp);
	dm_free_name(str);

	if (*errp == 0) {
	    util_doProperty(CREATION_CLASS, string, provider, cim_true, inst,
		errp);
	}

	if (*errp == 0) {
	    util_doProperty(SYS_CREATION_CLASS, string, COMPUTER_SYSTEM,
		cim_true, inst, errp);
	}

	if (*errp == 0) {
	    util_doProperty(SYSTEM, string, hostname, cim_true, inst, errp);
	}

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	/* Now get the controller attributes */
	nvlp = dm_get_attributes(desc, &error);
	if (error != 0) {
	    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ATTR_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	/* No attributes, no more to process */
	if (nvlp == NULL) {
	    return (inst);
	}

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char 	*attrname;
	    char	*str;
	    char	*protocol;
	    char	*avail;
	    char	*status;

	    attrname = nvpair_name(nvp);
	    if (attrname == NULL) {
		continue;
	    }

	    /* Loop through nvpair list and assign attrs to the CIMInstance. */

	    if (strcasecmp(attrname, DM_CTYPE) == 0) {
		error = nvpair_value_string(nvp, &str);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		if (strcasecmp(str, "scsi") == 0) {
		    protocol = "11";
		} else if (strcasecmp(str, "usb") == 0) {
		    protocol = "16";
		} else if (strcasecmp(str, "ata") == 0) {
		    protocol = "42";
		} else if (strcasecmp(str, "fibre channel") == 0) {
		    protocol = "10";
		} else if (strcasecmp(str, "scsi_vhci") == 0) {
		    protocol = "1";
		} else {
		    protocol = "2";
		}

		util_doProperty("ProtocolSupported", string, protocol,
		    cim_false, inst, errp);
		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    } else if (strcasecmp(attrname, DM_PATH_STATE) == 0) {
		error = nvpair_value_string(nvp, &str);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		if (strcasecmp(str, "online") == 0) {
		    avail = "3";
		    status = "3";
		} else if (strcasecmp(str, "standby") == 0) {
		    avail = "11";
		    status = "1";
		} else if (strcasecmp(str, "offline") == 0) {
		    avail = "8";
		    status = "4";
		} else if (strcasecmp(str, "faulted") == 0) {
		    avail = "9";
		    status = "4";
		} else {
		    avail = "2";
		    status = "2";
		}
		util_doProperty("Availability", string, avail,
		    cim_false, inst, errp);
		util_doProperty("StatusInfo", string, status,
		    cim_false, inst, errp);
		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    nvlist_free(nvlp);
		    cim_freeInstance(inst);
		    return ((CCIMInstance *)NULL);
		}
	    }
	} /* End for */

	nvlist_free(nvlp);
	return (inst);
}

/* Convert the descriptor list to a CIMInstance List */

CCIMInstanceList*
ctrl_descriptors_toCCIMInstanceList(char *providerName, dm_descriptor_t *dp,
	int *errp, int number, ...)
{
	CCIMInstance 		*inst;
	CCIMInstanceList 	*instList = NULL;
	CCIMException		*ex;
	va_list			args;
	dm_descriptor_t 	desc;
	nvlist_t		*nvlp;
	int			i;
	int			k;
	int			error;
	char			*type;
	char			*arg_type;

	*errp = 0;

	/* If not descriptor list, return an empty instance list. */
	if (dp == NULL) {
	    return (instList);
	}

	/*
	 * Create the instance list which will store the instances
	 * Only create this list when we know we have a valid
	 * instance to create
	 */
	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, errp);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Loop through all of the controller types specified.
	 */


	for (k = 0; dp[k] != NULL; k ++) {
	    desc = dp[k];
	    nvlp = dm_get_attributes(desc, &error);
	    if (error != 0) {
		util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    DM_GET_ATTR_FAILURE, NULL, errp);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    error = nvlist_lookup_string(nvlp, "ctype", &type);
	    if (error != 0) {
		util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    NVLIST_FAILURE, NULL, errp);
		nvlist_free(nvlp);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    va_start(args, number);
	    for (i = 0; i < number; i ++) {
		arg_type = va_arg(args, char *);
		if (strcasecmp(arg_type, "scsi_vhci") == 0) {
		    error = nvlist_lookup_boolean(nvlp, "multiplex");
		    if (error != 0) {
			continue;
		    }
		} else if (strcasecmp(type, arg_type) != 0) {
		    continue;
		}

		inst = ctrl_descriptor_toCCIMInstance(hostName, desc,
		    providerName, &error);
		if (error != 0) {
		    /* Error handling is done in the subfunction. */
		    nvlist_free(nvlp);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}

		/* add the instance to the instance list */
		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
		    ex = cim_getLastError();
		    util_handleError(CTRL_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstanceList *)NULL);
		}
	    }
	}
	va_end(args);
	nvlist_free(nvlp);

	/*
	 * If no matches were found, then we need to free the instance list
	 * and return NULL.
	 */
	if (instList->mDataObject == NULL) {
	    cim_freeInstanceList(instList);
	    instList = NULL;
	}
	return (instList);
}
