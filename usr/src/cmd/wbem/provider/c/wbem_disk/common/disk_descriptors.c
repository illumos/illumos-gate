/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
 * Convert a single descriptor in to a Solaris_Disk instance
 */

/* ARGSUSED */
CCIMInstance *
disk_descriptor_toCCIMInstance(char *hostname, dm_descriptor_t  desc,
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
	char			*vid;
	char			*prodid;
	char			buf[100];
	uint32_t		status;
	int			error = 0;

	*errp = 0;

	if ((inst = cim_createInstance(provider)) == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, errp);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * First, assign the common name from the alias value of the
	 * drive.
	 */
	dlist = dm_get_associated_descriptors(desc, DM_DRIVE, &error);

	if (error != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ASSOC_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	alist = dm_get_associated_descriptors(dlist[0], DM_ALIAS, &error);

	if (error != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_descriptors(dlist);
	    return ((CCIMInstance *)NULL);
	}

	drive = dm_get_name(alist[0], &error);
	dm_free_descriptors(alist);
	if (error != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_descriptors(dlist);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("Name", string, drive, cim_false, inst, errp);
	if (error != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_name(drive);
	    dm_free_descriptors(dlist);
	    return ((CCIMInstance *)NULL);
	}
	/*
	 * From the drive, assign the manufacturer and model.
	 */

	nvlp = dm_get_attributes(dlist[0], &error);
	dm_free_descriptors(dlist);
	if (error != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ATTR_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_name(drive);
	    return ((CCIMInstance *)NULL);
	}

	error = nvlist_lookup_string(nvlp, "product_id", &prodid);
	if (error == 0) {
	    util_doProperty("Model", string, prodid, cim_false, inst, errp);
	}
	if (*errp != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_name(drive);
	    nvlist_free(nvlp);
	    return ((CCIMInstance *)NULL);
	}

	error = nvlist_lookup_string(nvlp, "vendor_id", &vid);
	if (error == 0) {
	    util_doProperty("Manufacturer", string, vid, cim_false, inst, errp);
	}

	if (*errp != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_name(drive);
	    nvlist_free(nvlp);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Now get the status from the drive.
	 */
	error = nvlist_lookup_uint32(nvlp, "status", &status);
	if (error == 0) {
	    if (status == 0) {
		util_doProperty("Status", string, "Lost Comm", cim_false,
		    inst, errp);
	    } else {
		util_doProperty("Status", string, "OK", cim_false, inst,
		    errp);
	    }
	    if (*errp != 0) {
		ex = cim_getLastError();
		util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, errp);
		cim_freeInstance(inst);
		nvlist_free(nvlp);
		dm_free_name(drive);
		return ((CCIMInstance *)NULL);
	    }
	}
	nvlist_free(nvlp);

	/* Now, assign the TAG value */

	str = dm_get_name(desc, &error);

	if (error != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_name(drive);
	    return ((CCIMInstance *)NULL);
	}

	if (str != NULL) {
	    util_doProperty(TAG, string, str, cim_true, inst, errp);
	    dm_free_name(str);

	    if (*errp != 0) {
		ex = cim_getLastError();
		util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, errp);
		cim_freeInstance(inst);
		dm_free_name(drive);
		return ((CCIMInstance *)NULL);
	    }

	} else {

	    util_doProperty(TAG, string, drive, cim_true, inst, errp);

	    if (*errp != 0) {
		ex = cim_getLastError();
		util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, errp);
		cim_freeInstance(inst);
		dm_free_name(drive);
		return ((CCIMInstance *)NULL);
	    }
	}
	dm_free_name(drive);

	/* add keys */

	util_doProperty(CREATION_CLASS, string, DISK, cim_true, inst, errp);
	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	/* Now fill in the other attributes */

	nvlp = dm_get_attributes(desc, &error);

	/*
	 * If the underlying api cannot access the media, it will return
	 * an ENODEV. Set the status for this media appropriately and return
	 * the instance.
	 */
	if (error == ENODEV) {
	    util_doProperty("Status", string, "Lost Comm", cim_false,
		inst, errp);
	    return (inst);
	}
	if (error != 0) {
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ATTR_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	/* If there are no other attriubtes, we are done. */
	if (nvlp == NULL) {
	    return (inst);
	}

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char 	*attrname;
	    uint32_t    ui32;
	    uint64_t	ui64;

	    attrname = nvpair_name(nvp);
	    if (attrname == NULL) {
		continue;
	    }

	    /* Loop through nvpair list and assign attrs to the CIMInstace. */

	    if (strcasecmp(attrname, DM_SIZE) == 0) {
		uint32_t	blocksize = 512;

		error = nvpair_value_uint64(nvp, &ui64);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		(void) nvlist_lookup_uint32(nvlp, DM_BLOCKSIZE, &blocksize);

		error = snprintf(buf, sizeof (buf), "%llu", ui64 * blocksize);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		util_doProperty("Capacity", uint64, buf, cim_false, inst,
		    errp);
		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    } else if (strcasecmp(attrname, DM_MTYPE) == 0) {
		char	*mtype = "0";

		error = nvpair_value_uint32(nvp, &ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		/*
		 * The values for MediaType are hardcoded as the enumeration
		 * values from the CIM_PhysicalMedia MOF definition.
		 */
		switch (ui32) {
		case DM_MT_FIXED:	mtype = "29";
					break;
		case DM_MT_FLOPPY:	mtype = "28";
					break;
		case DM_MT_CDROM:	mtype = "16";
					break;
		case DM_MT_ZIP:		mtype = "13";
					break;
		case DM_MT_JAZ:		mtype = "12";
					break;
		case DM_MT_CDR:		mtype = "19";
					break;
		case DM_MT_CDRW:	mtype = "33";
					break;
		case DM_MT_DVDROM:	mtype = "25";
					break;
		case DM_MT_DVDR:	mtype = "22";
					break;
		case DM_MT_DVDRAM:	mtype = "24";
					break;
		case DM_MT_MO_ERASABLE:	mtype = "43";
					break;
		case DM_MT_MO_WRITEONCE: mtype = "44";
					break;
		case DM_MT_AS_MO:	mtype = "21";
					break;
		}

		util_doProperty("MediaType", uint16, mtype, cim_false, inst,
		    errp);
		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}

	    } else if (strcasecmp(attrname, DM_REMOVABLE) == 0) {
		util_doProperty("Removable", boolean, "1", cim_false, inst,
		    errp);
		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    }
	} /* End for */

	nvlist_free(nvlp);
	return (inst);
}

/* Convert the descriptor list to a CIMInstance List */

CCIMInstanceList*
disk_descriptors_toCCIMInstanceList(char *providerName, dm_descriptor_t *dp,
	int *errp)
{
	CCIMInstance 		*inst;
	CCIMInstanceList 	*instList = NULL;
	CCIMException		*ex;
	dm_descriptor_t 	desc;
	int			i;
	int			error;

	*errp = 0;


	/* If not descriptpr list, return an empty instance list. */
	if (dp == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/* Create the instance list which will store the instances */

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, errp);
	    return ((CCIMInstanceList *)NULL);
	}

	for (i = 0; dp[i] != NULL; i ++) {
	    desc = dp[i];
	    inst = disk_descriptor_toCCIMInstance(hostName, desc,
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
		util_handleError(DISK_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, errp);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	}
	return (instList);
}
