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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
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
 * Convert a single descriptor in to a Solaris_LogicalDisk instance
 */

CCIMInstance *
logicaldisk_descriptor_toCCIMInstance(char *hostname, dm_descriptor_t  desc,
    char *provider, int *errp)
{

	nvlist_t		*nvlp;
	nvpair_t		*nvp;
	CCIMInstance		*inst = NULL;
	CCIMException		*ex;
	dm_descriptor_t		*dlist;
	dm_descriptor_t		*alist;
	char			*str;
	char			*drive;
	int			error;
	char			buf[100];

	*errp = 0;

	/* Create instance of disk. */

	if ((inst = cim_createInstance(provider)) == NULL) {
	    ex = cim_getLastError();
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, errp);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Get the alias name to display as the common name as well as
	 * the deviceid if for some reason this media does not have
	 * a name.
	 */
	dlist = dm_get_associated_descriptors(desc, DM_DRIVE, &error);

	if (error != 0) {
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ASSOC_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	alist = dm_get_associated_descriptors(dlist[0], DM_ALIAS, &error);
	dm_free_descriptors(dlist);

	if (error != 0) {
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ASSOC_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	drive = dm_get_name(alist[0], &error);
	dm_free_descriptors(alist);

	if (error != 0) {
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("Name", string, drive, cim_true, inst, errp);
	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    dm_free_name(drive);
	    return ((CCIMInstance *)NULL);
	}

	/* Now, assign the deviceID */
	str = dm_get_name(desc, &error);

	if (error != 0) {
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_name(drive);
	    return ((CCIMInstance *)NULL);
	}

	if (str != NULL) {
	    util_doProperty(DEVICEID, string, str, cim_true, inst, errp);
	    dm_free_name(str);

	    if (*errp != 0) {
		ex = cim_getLastError();
		util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, errp);
		cim_freeInstance(inst);
		dm_free_name(drive);
		return ((CCIMInstance *)NULL);
	    }

	} else {

	    util_doProperty(DEVICEID, string, drive, cim_true, inst, errp);

	    if (*errp != 0) {
		ex = cim_getLastError();
		util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, errp);
		cim_freeInstance(inst);
		dm_free_name(drive);
		return ((CCIMInstance *)NULL);
	    }
	}
	dm_free_name(drive);


	/* add keys */

	util_doProperty(CREATION_CLASS, string, LOGICAL_DISK, cim_true,
	    inst, errp);

	if (*errp == 0) {
	    util_doProperty(SYS_CREATION_CLASS, string, COMPUTER_SYSTEM,
		cim_true, inst, errp);
	}

	if (*errp == 0) {
	    util_doProperty(SYSTEM, string, hostname, cim_true, inst, errp);
	}

	if (!errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	nvlp = dm_get_attributes(desc, &error);
	if (error != 0) {
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ATTR_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	if (nvlp == NULL) {
	    return (inst);
	}

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char 	*attrname;
	    uint32_t    ui32;
	    uint64_t	ui64;

	    attrname = nvpair_name(nvp);

	    /* If the attrname for this nvp is null, try the next one. */

	    if (attrname == NULL) {
		continue;
	    }

	    /* Loop through nvpair list and assign attrs to the CIMInstace. */

	    if (strcasecmp(attrname, DM_BLOCKSIZE) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		error = snprintf(buf, sizeof (buf), "%u", ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		util_doProperty("BlockSize", uint64, buf, cim_false, inst,
		    errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    } else if (strcasecmp(attrname, DM_SIZE) == 0) {
		error = nvpair_value_uint64(nvp, &ui64);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		error = snprintf(buf, sizeof (buf), "%llu", ui64);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		util_doProperty("NumberOfBlocks", uint64, buf, cim_false,
		    inst, errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    }
	} /* End for */
	nvlist_free(nvlp);

	/*
	 * Get the associated drive descriptor to get the status information.
	 * about this media.
	 */

	dlist = dm_get_associated_descriptors(desc, DM_DRIVE, &error);
	if (error != 0) {
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ASSOC_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}


	nvlp = dm_get_attributes(dlist[0], &error);
	dm_free_descriptors(dlist);
	if (error != 0) {
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ATTR_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	if (nvlp == NULL) {
	    return (inst);
	}

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char 	*attrname;
	    uint32_t    ui32;
	    char	*status;
	    char	*statusinfo;

	    attrname = nvpair_name(nvp);
	    /* If the attrname for this nvp is null, try the next one. */

	    if (attrname == NULL) {
		continue;
	    }

	    if (strcasecmp(attrname, DM_STATUS) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		if (ui32 == 0) {
		    status = "Error";
		    statusinfo = "4";
		} else {
		    status = "OK";
		    statusinfo = "3";
		}
		util_doProperty("Status", string, status, cim_false,
		    inst, errp);
		util_doProperty("StatusInfo", uint16, statusinfo, cim_false,
		    inst, errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DISK_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    } /* End ifelse */
	} /* end for */
	nvlist_free(nvlp);
	return (inst);
}

/* Convert the descriptor list to a CIMInstance List */

CCIMInstanceList*
logicaldisk_descriptors_toCCIMInstanceList(char *providerName,
	dm_descriptor_t *dp, int *errp)
{
	CCIMInstance 		*inst;
	CCIMInstanceList 	*instList = NULL;
	CCIMException		*ex;
	dm_descriptor_t 	desc;
	int			error;
	int			i;

	*errp = 0;


	/* If not descriptpr list, return an empty instance list. */
	if (dp == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/* Create the instance list which will store the instances */
	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, errp);
	    return ((CCIMInstanceList *)NULL);
	}
	for (i = 0; dp[i] != NULL; i ++) {
	    desc = dp[i];
	    inst = logicaldisk_descriptor_toCCIMInstance(hostName, desc,
		providerName, &error);
	    if (error != 0) {
		/* Error handling is done in the subfunction. */
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    if (inst == NULL) {
		continue;
	    }

	    /* add the instance to the instance list */
	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(LOGICALDISK_DESCRIPTOR_FUNC,
		    CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, errp);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	}
	return (instList);
}
