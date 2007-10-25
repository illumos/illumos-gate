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
 * Convert a single descriptor in to a Solaris_DiskDrive instance
 */

CCIMInstance *
drive_descriptor_toCCIMInstance(char *hostname, dm_descriptor_t  desc,
    char *provider, int *errp)
{

	nvlist_t		*nvlp;
	nvpair_t		*nvp;
	CCIMInstance		*inst = NULL;
	CCIMException		*ex;
	dm_descriptor_t		*dlist;
	dm_descriptor_t		*mlist;
	char			*str = NULL;
	char			*alias;
	char			buf[100];
	uint32_t		nheads = 0;
	uint32_t		nsecs = 0;
	uint64_t		bytes_per_cylinder = 0;
	uint32_t		blocksize = 0;
	int			error = 0;
	int			fdisk = 0;

	*errp = 0;

	if (desc == NULL) {
	    return ((CCIMInstance *)NULL);
	}

	/* Create instance of disk drive. */

	if ((inst = cim_createInstance(provider)) == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, errp);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Get the common name from the alias descriptor associated with
	 * this drive. This is used for the 'name' attribute as well as the
	 * deviceid if the standard deviceid is not found.
	 */
	dlist = dm_get_associated_descriptors(desc, DM_ALIAS,
	    &error);
	if (error != 0) {
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	alias = dm_get_name(dlist[0], &error);
	dm_free_descriptors(dlist);

	if (error != 0) {
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}
	util_doProperty("Name", string, alias, cim_false, inst, errp);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    dm_free_name(alias);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	/* Now, assign the deviceID */

	str = dm_get_name(desc, &error);

	if (error != 0) {
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    dm_free_name(alias);
	    return ((CCIMInstance *)NULL);
	}

	if (str != NULL) {
	    util_doProperty(DEVICEID, string, str, cim_true, inst, errp);
	    dm_free_name(str);

	    if (*errp != 0) {
		ex = cim_getLastError();
		util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, errp);
		cim_freeInstance(inst);
		dm_free_name(alias);
		return ((CCIMInstance *)NULL);
	    }

	} else {

	    util_doProperty(DEVICEID, string, alias, cim_true, inst, errp);

	    if (*errp != 0) {
		ex = cim_getLastError();
		util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, errp);
		cim_freeInstance(inst);
		dm_free_name(alias);
		return ((CCIMInstance *)NULL);
	    }
	}
	dm_free_name(alias);

	/* add keys */

	util_doProperty(CREATION_CLASS, string, DISK_DRIVE, cim_true,
	    inst, errp);

	if (*errp == 0) {
	    util_doProperty(SYS_CREATION_CLASS, string, COMPUTER_SYSTEM,
		cim_true, inst, errp);
	}

	if (*errp == 0) {
	    util_doProperty(SYSTEM, string, hostname, cim_true, inst, errp);
	}

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	nvlp = dm_get_attributes(desc, &error);
	if (error != 0) {
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ATTR_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	if (nvlp == NULL) {
	    return (inst);
	}

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char 		*attrname;
	    uint32_t		ui32;
	    char		*status;

	    attrname = nvpair_name(nvp);
	    if (attrname == NULL) {
		continue;
	    }

		/*
		 * loop through the nvpair list and assign attributes to the
		 * CIMInstace.
		 */

	    if (strcasecmp(attrname, DM_DRVTYPE) == 0) {
		char	*type = "Unknown";

		error = nvpair_value_uint32(nvp, &ui32);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		switch (ui32) {
		case DM_DT_FIXED:
		    type = "Fixed";
		    break;
		case DM_DT_ZIP:
		    type = "Zip";
		    break;
		case DM_DT_JAZ:
		    type = "Jaz";
		    break;
		default:
		    if (nvlist_lookup_boolean(nvlp, DM_REMOVABLE) == 0) {
			type = "Removable";
		    }
		    break;
		}

		util_doProperty("DiskType", string, type, cim_false, inst,
		    errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    return ((CCIMInstance *)NULL);
		}

	    } else if (strcasecmp(attrname, DM_STATUS) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		if (ui32 == 0) {
		    error = snprintf(buf, sizeof (buf), "%u", 4);
		    status = "Error";
		} else {
		    error = snprintf(buf, sizeof (buf), "%u", 3);
		    status = "OK";
		}

		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		util_doProperty("StatusInfo", uint32, buf, cim_false,
		    inst, errp);

		if (*errp == 0) {
		    util_doProperty("Status", string, status, cim_false,
			inst, errp);
		}

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    }
	}

	nvlist_free(nvlp);

	/*
	 * Now get the associated media, and get some of the other attributes.
	 */

	mlist = dm_get_associated_descriptors(desc, DM_MEDIA, errp);

	if (mlist == NULL) {
	    return (inst);
	}

	if (mlist[0] == NULL) {
	    dm_free_descriptors(mlist);
	    return (inst);
	}

	if (*errp != 0) {
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	nvlp = dm_get_attributes(mlist[0], errp);
	dm_free_descriptors(mlist);

	/*
	 * It is possible that we cannot read the media for this drive.
	 * So, do not error out, but return what we have so far for the
	 * drive instance.
	 */
	if (*errp == ENODEV || nvlp == NULL) {
	    *errp = 0;
	    return (inst);
	}

	if (*errp != 0) {
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char 		*attrname;
	    uint32_t		ui32;

	    attrname = nvpair_name(nvp);
	    if (attrname == NULL) {
		continue;
	    }

	    if (strcasecmp(attrname, DM_BLOCKSIZE) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		blocksize = ui32;
		error = snprintf(buf, sizeof (buf), "%u", ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		util_doProperty("DefaultBlockSize", uint64, buf,
		    cim_false, inst, errp);
		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}

	    } else if (strcasecmp(DM_FDISK, attrname) == 0) {
		fdisk = 1;
		util_doProperty("FdiskPresent", boolean, "1", cim_false,
		    inst, errp);
		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    } else if (strcasecmp(DM_LABEL, attrname) == 0) {
		error = nvpair_value_string(nvp, &str);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		util_doProperty("DiskLabel", string, str, cim_false, inst,
		    errp);
		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    } else if (strcasecmp(DM_NHEADS, attrname) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		nheads = ui32;
	    } else if (strcasecmp(DM_NSECTORS, attrname) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		nsecs = ui32;
	    } else if (strcasecmp(DM_NPHYSCYLINDERS, attrname) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		error = snprintf(buf, sizeof (buf), "%u", ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		util_doProperty("PhysicalCylinders", uint32, buf, cim_false,
		    inst, errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    nvlist_free(nvlp);
		    cim_freeInstance(inst);
		    return ((CCIMInstance *)NULL);
		}
	    } else if (strcasecmp(DM_NCYLINDERS, attrname) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		error = snprintf(buf, sizeof (buf), "%u", ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		util_doProperty("DataCylinders", uint32, buf, cim_false,
		    inst, errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    nvlist_free(nvlp);
		    cim_freeInstance(inst);
		    return ((CCIMInstance *)NULL);
		}
	    } else if (strcasecmp(DM_NACTUALCYLINDERS, attrname) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		error = snprintf(buf, sizeof (buf), "%u", ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		util_doProperty("ActualCylinders", uint32, buf, cim_false,
		    inst, errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(DRIVE_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    nvlist_free(nvlp);
		    cim_freeInstance(inst);
		    return ((CCIMInstance *)NULL);
		}
	    }

	} /* end for */

	nvlist_free(nvlp);

	/*
	 * Now fill in the geometry data
	 */

	error = snprintf(buf, sizeof (buf), "%u", nheads);

	if (error < 0) {
	    cim_freeInstance(inst);
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("HeadsPerCylinder", uint32, buf, cim_false, inst,
	    errp);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	error = snprintf(buf, sizeof (buf), "%u", nsecs);

	if (error < 0) {
	    cim_freeInstance(inst);
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("SectorsPerTrack", uint32, buf, cim_false, inst,
	    errp);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	error = snprintf(buf, sizeof (buf), "%u", nsecs * nheads);

	if (error < 0) {
	    cim_freeInstance(inst);
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("SectorsPerCylinder", uint32, buf, cim_false, inst,
	    errp);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	bytes_per_cylinder = (nheads * nsecs) * blocksize;
	error = snprintf(buf, sizeof (buf), "%llu", bytes_per_cylinder);

	if (error < 0) {
	    cim_freeInstance(inst);
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("BytesPerCylinder", uint32, buf, cim_false,
	    inst, errp);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(DRIVE_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Now check to see if there is an fdisk or not.
	 */

	if (fdisk != 1) {
	    util_doProperty("FdiskPresent", boolean, "0", cim_false,
		inst, errp);
	    if (*errp != 0) {
		ex = cim_getLastError();
		util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, ex, errp);
		cim_freeInstance(inst);
		return ((CCIMInstance *)NULL);
	    }
	}

	return (inst);
}

/* Convert the descriptor list to a CIMInstance List */

CCIMInstanceList*
drive_descriptors_toCCIMInstanceList(char *providerName, dm_descriptor_t *dp,
	int *errp)
{
	CCIMInstance 		*inst;
	CCIMInstanceList 	*instList = NULL;
	CCIMException		*ex;
	dm_descriptor_t 	desc;
	int			i;
	int			error = 0;

	*errp = 0;


	/* If not descriptor list, return an empty instance list. */
	if (dp == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/* Create the instance list which will store the instances */
	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, errp);
	    return ((CCIMInstanceList *)NULL);
	}
	for (i = 0; dp[i] != NULL; i ++) {
	    desc = dp[i];
	    inst = drive_descriptor_toCCIMInstance(hostName, desc,
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
		util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, errp);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	}

	return (instList);
}

/*
 * Convert the descriptor list to a CIMInstance List that will be used
 * only for object paths and thus does not need to be fully populated.
 * We do the filtering in this function to be sure that we are only
 * returning drives that are modeled with this class in CIM.
 */
CCIMInstanceList*
drive_descriptors_toCCIMObjPathInstList(char *providerName, dm_descriptor_t *dp,
	int *errp)
{
	CCIMInstanceList 	*instList = NULL;
	int			i;
	int			error = 0;
	int			have_instances = 0;

	*errp = 0;

	if (dp == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/* Create the instance list which will store the instances */
	instList = cim_createInstanceList();
	if (instList == NULL) {
	    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, cim_getLastError(), errp);
	    return ((CCIMInstanceList *)NULL);
	}

	for (i = 0; dp[i] != NULL; i ++) {
	    dm_descriptor_t 	desc;
	    nvlist_t		*attrs;
	    uint32_t		drvtype;
	    char		*str;
	    CCIMInstance	*inst;

	    desc = dp[i];

	    attrs = dm_get_attributes(desc, &error);
	    if (error != 0 || attrs == NULL) {
		continue;
	    }

	    drvtype = DM_DT_UNKNOWN;
	    (void) nvlist_lookup_uint32(attrs, DM_DRVTYPE, &drvtype);
	    nvlist_free(attrs);

	    switch (drvtype) {
	    case DM_DT_UNKNOWN:
		break;
	    case DM_DT_FIXED:
		break;
	    case DM_DT_ZIP:
		break;
	    case DM_DT_JAZ:
		break;
	    default:
		/*
		 * This is not one of the drives that are modeled as a
		 * Solaris_DiskDrive, so we should skip over it.
		 */
		continue;
	    }

	    str = dm_get_name(desc, &error);
	    if (error != 0) {
		util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    DM_GET_NAME_FAILURE, NULL, errp);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    if (str == NULL) {
		dm_descriptor_t *aliases;

		aliases = dm_get_associated_descriptors(desc, DM_ALIAS, &error);
		if (error != 0) {
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_ASSOC_FAILURE, NULL, errp);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}

		str = dm_get_name(aliases[0], &error);
		dm_free_descriptors(aliases);

		if (error != 0) {
		    util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
			DM_GET_NAME_FAILURE, NULL, errp);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}
	    }

	    /* Create instance of disk drive. */
	    if ((inst = cim_createInstance(providerName)) == NULL) {
		util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    CREATE_INSTANCE_FAILURE, cim_getLastError(), errp);
		dm_free_name(str);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    /* add keys */
	    util_doProperty(DEVICEID, string, str, cim_true, inst, errp);
	    dm_free_name(str);

	    if (*errp == 0) {
		util_doProperty(CREATION_CLASS, string, DISK_DRIVE, cim_true,
		    inst, errp);
	    }

	    if (*errp == 0) {
		util_doProperty(SYS_CREATION_CLASS, string, COMPUTER_SYSTEM,
		    cim_true, inst, errp);
	    }

	    if (*errp == 0) {
		util_doProperty(SYSTEM, string, hostName, cim_true, inst, errp);
	    }

	    if (*errp != 0) {
		util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_PROPERTY_FAILURE, cim_getLastError(), errp);
		cim_freeInstance(inst);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    /* add the instance to the instance list */
	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		util_handleError(DRIVE_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, cim_getLastError(), errp);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }

	    have_instances = 1;
	}

	if (!have_instances) {
	    cim_freeInstanceList(instList);
	    instList = (CCIMInstanceList *)NULL;
	}

	return (instList);
}
