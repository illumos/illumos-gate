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

static void	do_alias_desc(CCIMInstance *inst, dm_descriptor_t desc,
		    int *errp);
static void	do_drive_desc(CCIMInstance *inst, dm_descriptor_t desc,
		    int *errp);
static void	do_media_desc(CCIMInstance *inst, dm_descriptor_t desc,
		    uint32_t *blocksize, uint64_t *blocks_per_cyl, int *errp);
static void	do_misc_attrs(CCIMInstance *inst, int *errp, uint64_t size,
		    uint32_t starting_cylinder, uint32_t end_cylinder,
		    uint32_t ncylinders);
static void	do_slice_desc(CCIMInstance *inst, char *hostname,
		    dm_descriptor_t desc, uint64_t *numblocks, uint32_t *bcyl,
		    uint32_t *ecyl, uint64_t *start, int *errp);
static void	do_prop64(CCIMInstance *inst, char *name, uint64_t val,
		    int *errp);
static void	do_prop32(CCIMInstance *inst, char *name, uint32_t val,
		    int *errp);
static dm_descriptor_t get_first_assoc(dm_descriptor_t desc,
		    dm_desc_type_t type, int *errp);
static CCIMInstance *fatal(CCIMInstance *inst, dm_descriptor_t desc, int *errp);

/*
 * Convert a single descriptor in to a Solaris_DiskPartition instance
 */

CCIMInstance *
partition_descriptor_toCCIMInstance(char *hostname, dm_descriptor_t  desc,
    char *provider, int *errp)
{

	CCIMInstance		*inst = NULL;
	dm_descriptor_t		media_desc;
	dm_descriptor_t		drive_desc;
	dm_descriptor_t		alias_desc;
	uint32_t		ncylinders = 0;
	uint32_t		bcyl = 0;
	uint32_t		ecyl = 0;
	uint32_t		starting_cylinder = 0;
	uint32_t		end_cylinder = 0;
	uint64_t		start = 0;
	uint64_t		numblocks = 0;
	uint32_t		blocksize = 0;
	uint64_t		blocks_per_cyl = 0;
	uint64_t		size = 0;
	int			isFdisk = 0;

	*errp = 0;

	/* Create instance of disk drive. */
	if ((inst = cim_createInstance(provider)) == NULL)
	    return (fatal(inst, NULL, errp));

	do_slice_desc(inst, hostname, desc, &numblocks, &bcyl, &ecyl, &start,
	    errp);
	if (*errp != 0)
	    return (fatal(inst, NULL, errp));

	media_desc = get_first_assoc(desc, DM_MEDIA, errp);
	if (*errp != 0)
	    return (fatal(inst, NULL, errp));

	if (media_desc == NULL) {
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	do_media_desc(inst, media_desc, &blocksize, &blocks_per_cyl, errp);
	if (*errp != 0)
	    return (fatal(inst, media_desc, errp));

	drive_desc = get_first_assoc(media_desc, DM_DRIVE, errp);
	if (*errp != 0)
	    return (fatal(inst, media_desc, errp));
	dm_free_descriptor(media_desc);

	if (drive_desc == NULL) {
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	do_drive_desc(inst, drive_desc, errp);
	if (*errp != 0)
	    return (fatal(inst, drive_desc, errp));

	alias_desc = get_first_assoc(drive_desc, DM_ALIAS, errp);
	if (*errp != 0)
	    return (fatal(inst, drive_desc, errp));
	dm_free_descriptor(drive_desc);

	if (alias_desc == NULL) {
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	do_alias_desc(inst, alias_desc, errp);
	if (*errp != 0)
	    return (fatal(inst, alias_desc, errp));
	dm_free_descriptor(alias_desc);

	if (dm_get_type(desc) == DM_PARTITION) {
	    isFdisk = 1;
	}

	/* Partition size in bytes */
	size = (uint64_t)(numblocks * blocksize);

	/* Starting cylinder */
	if (isFdisk) {
	    starting_cylinder = bcyl;
	} else if (blocks_per_cyl != 0) {
	    starting_cylinder = (uint32_t)(start / blocks_per_cyl);
	}

	/* Total cylinders */
	if (isFdisk) {
	    ncylinders = (ecyl - bcyl) + 1;
	} else if (blocks_per_cyl != 0) {
	    ncylinders = (uint32_t)(numblocks / blocks_per_cyl);
	}

	/* ending cylinder */

	if (isFdisk) {
	    end_cylinder = ecyl;
	} else {
	    if (ncylinders == 0) {
		end_cylinder = 0;
	    } else {
		end_cylinder = (uint32_t)((ncylinders + starting_cylinder) - 1);
	    }
	}

	do_misc_attrs(inst, errp, size, starting_cylinder, end_cylinder,
	    ncylinders);
	if (*errp != 0)
	    return (fatal(inst, NULL, errp));

	return (inst);
}

/* Convert the descriptor list to a CIMInstance List */

CCIMInstanceList*
partition_descriptors_toCCIMInstanceList(char *providerName,
    dm_descriptor_t *dp, dm_descriptor_t *fdp, int *errp)
{
	CCIMInstance 		*inst;
	CCIMInstanceList 	*instList = NULL;
	CCIMException		*ex;
	dm_descriptor_t 	desc;
	int			i;
	int			error;

	*errp = 0;


	/* If not descriptpr list, return a NULL instance list. */
	if (dp == NULL && fdp == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/* Create the instance list which will store the instances */
	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(PARTITION_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, errp);
	    return ((CCIMInstanceList *)NULL);
	}


	for (i = 0; dp != NULL && dp[i] != NULL; i ++) {
	    desc = dp[i];
	    inst = partition_descriptor_toCCIMInstance(hostName, desc,
		providerName, &error);
	    if (error != 0) {
		/* Error logging and exception handling done in sub function */
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
		util_handleError(PARTITION_DESCRIPTOR_FUNC,
		    CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, errp);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	}
	for (i = 0; fdp != NULL && fdp[i] != NULL; i ++) {
	    desc = fdp[i];
	    inst = partition_descriptor_toCCIMInstance(hostName, desc,
		providerName, &error);
	    if (error != 0) {
		/* Error logging and exception handling done in sub function */
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
		util_handleError(PARTITION_DESCRIPTOR_FUNC,
		    CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, errp);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }
	}
	return (instList);
}

static void
do_slice_desc(CCIMInstance *inst, char *hostname, dm_descriptor_t desc,
	uint64_t *numblocks, uint32_t *bcyl, uint32_t *ecyl, uint64_t *start,
	int *errp)
{
	nvlist_t	*nvlp;
	nvpair_t	*nvp;
	char		*str;
	char		*ptype = "2";	/* default is vtoc */
	char		*type = "3";	/* default is vtoc */
	char		*validFS = "0";
	uint32_t    	ui32;

	*errp = 0;
	*numblocks = 0;
	*bcyl = 0;
	*ecyl = 0;
	*start = 0;

	str = dm_get_name(desc, errp);
	if (*errp != 0)
	    return;

	if (str == NULL) {
	    *errp = ENOENT;
	    return;
	}

	util_doProperty(DEVICEID, string, str, cim_true, inst, errp);
	dm_free_name(str);
	if (*errp != 0)
	    return;

	if (dm_get_type(desc) == DM_PARTITION) {
	    ptype = "3";
	}

	/* add keys */

	util_doProperty(CREATION_CLASS, string, DISK_PARTITION, cim_true,
	    inst, errp);
	if (*errp != 0)
	    return;

	util_doProperty(SYS_CREATION_CLASS, string, COMPUTER_SYSTEM, cim_true,
	    inst, errp);
	if (*errp != 0)
	    return;

	util_doProperty(SYSTEM, string, hostname, cim_true, inst, errp);
	if (*errp != 0)
	    return;

	nvlp = dm_get_attributes(desc, errp);
	if (*errp == ENODEV || nvlp == NULL) {
	    /* not a failure, just a sparse slice */
	    *errp = 0;
	    return;
	}

	if (*errp != 0)
	    return;

	/*
	 * Now get the other attributes we are interested in.
	 */
	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char 	*attrname;

	    attrname = nvpair_name(nvp);
	    if (attrname == NULL) {
		continue;
	    }

	    /* loop through the list and assign attrs to the CIMInstance. */

	    if (strcasecmp(attrname, DM_MTYPE) == 0) {
		continue;
	    }

	    if (strcasecmp(DM_SIZE, attrname) == 0) {
		/* vtoc */
		*errp = nvpair_value_uint64(nvp, numblocks);
		if (*errp != 0)
		    break;

		do_prop64(inst, "NumberOfBlocks", *numblocks, errp);
		if (*errp != 0)
		    break;


	    } else if (strcasecmp(DM_NSECTORS, attrname) == 0) {
		/* fdisk */
		*errp = nvpair_value_uint32(nvp, &ui32);
		if (*errp != 0)
		    break;

		*numblocks = ui32;
		do_prop64(inst, "NumberOfBlocks", *numblocks, errp);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(DM_BOOTID, attrname) == 0) {
		/* fdisk */
		char *primary = "0";
		char *bootable = "0";

		*errp = nvpair_value_uint32(nvp, &ui32);
		if (*errp != 0)
		    break;

		if (ui32 == 128) {
		    primary = "1";
		    bootable = "1";
		    type = "2";
		} else {
		    type = "1";
		}

		util_doProperty("PrimaryPartition", boolean, primary, cim_false,
		    inst, errp);
		if (*errp != 0)
		    break;

		util_doProperty("Bootable", boolean, bootable, cim_false, inst,
		    errp);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(DM_START, attrname) == 0) {
		*errp = nvpair_value_uint64(nvp, start);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(DM_TAG, attrname) == 0) {
		int	error;
		char	buf[100];

		*errp = nvpair_value_uint32(nvp, &ui32);
		if (*errp != 0)
		    break;

		error = snprintf(buf, sizeof (buf), "%u", ui32);
		if (error < 0) {
		    *errp = error;
		    break;
		}

		util_doProperty("Tag", uint8, buf, cim_false, inst, errp);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(DM_FLAG, attrname) == 0) {
		int	error;
		char	buf[100];

		*errp = nvpair_value_uint32(nvp, &ui32);
		if (*errp != 0)
		    break;

		error = snprintf(buf, sizeof (buf), "%u", ui32);
		if (error < 0) {
		    *errp = error;
		    break;
		}

		util_doProperty("Flag", uint8, buf, cim_false, inst, errp);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(DM_MOUNTPOINT, attrname) == 0) {
		validFS = "1";

	    } else if (strcasecmp(attrname, DM_BCYL) == 0) {
		*errp = nvpair_value_uint32(nvp, bcyl);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(attrname, DM_ECYL) == 0) {
		*errp = nvpair_value_uint32(nvp, ecyl);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(attrname, DM_PTYPE) == 0) {
		int	error;
		char	buf[100];

		*errp = nvpair_value_uint32(nvp, &ui32);
		if (*errp != 0)
		    break;

		error = snprintf(buf, sizeof (buf), "%u", ui32);
		if (error < 0) {
		    *errp = error;
		    break;
		}

		util_doProperty("PartitionSubtype", uint16, buf, cim_false,
		    inst, errp);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(DM_EFI, attrname) == 0) {
		ptype = "4";
	    }

	} /* end for */

	if (*errp == 0) {
	    util_doProperty("ValidFileSystem", boolean, validFS, cim_false,
		inst, errp);
	}

	if (*errp == 0) {
	    util_doProperty("SolarisPartitionType", uint16, ptype, cim_false,
		inst, errp);
	}

	if (*errp == 0) {
	    util_doProperty("PartitionType", uint16, type, cim_false, inst,
		errp);
	}

	nvlist_free(nvlp);
}

static void
do_media_desc(CCIMInstance *inst, dm_descriptor_t desc, uint32_t *blocksize,
	uint64_t *blocks_per_cyl, int *errp)
{
	nvlist_t		*nvlp;
	nvpair_t		*nvp;
	uint32_t		nheads = 0;
	uint32_t		nsecs = 0;

	*errp = 0;
	*blocksize = 0;

	nvlp = dm_get_attributes(desc, errp);
	if (*errp == ENODEV || nvlp == NULL) {
	    *errp = 0;
	    return;
	}

	if (*errp != 0)
	    return;

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char 	*attrname;

	    attrname = nvpair_name(nvp);
	    if (attrname == NULL) {
		continue;
	    }

	    if (strcasecmp(attrname, DM_BLOCKSIZE) == 0) {
		*errp = nvpair_value_uint32(nvp, blocksize);
		if (*errp != 0)
		    break;

		do_prop64(inst, "BlockSize", (uint64_t)*blocksize, errp);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(DM_NHEADS, attrname) == 0) {
		*errp = nvpair_value_uint32(nvp, &nheads);
		if (*errp != 0)
		    break;

	    } else if (strcasecmp(DM_NSECTORS, attrname) == 0) {
		*errp = nvpair_value_uint32(nvp, &nsecs);
		if (*errp != 0)
		    break;
	    }

	} /* end for */

	nvlist_free(nvlp);

	*blocks_per_cyl = nheads * nsecs;
}

static void
do_drive_desc(CCIMInstance *inst, dm_descriptor_t desc, int *errp)
{
	nvlist_t	*nvlp;
	uint32_t    	ui32;
	char		*status;
	char		*statusinfo;

	*errp = 0;

	nvlp = dm_get_attributes(desc, errp);
	if (*errp != 0)
	    return;

	*errp = nvlist_lookup_uint32(nvlp, "status", &ui32);
	if (*errp != 0) {
	    nvlist_free(nvlp);
	    return;
	}

	if (ui32 == 0) {
	    statusinfo = "4";
	    status = "Error";
	} else {
	    statusinfo = "3";
	    status = "OK";
	}

	util_doProperty("StatusInfo", uint16, statusinfo, cim_false, inst,
	    errp);
	if (*errp != 0) {
	    nvlist_free(nvlp);
	    return;
	}

	util_doProperty("Status", string, status, cim_false, inst, errp);
	if (*errp != 0) {
	    nvlist_free(nvlp);
	    return;
	}

	nvlist_free(nvlp);
}

static void
do_alias_desc(CCIMInstance *inst, dm_descriptor_t desc, int *errp)
{
	char *str;

	*errp = 0;

	str = dm_get_name(desc, errp);

	if (*errp != 0)
	    return;

	if (str != NULL) {
	    util_doProperty("DiskID", string, str, cim_false, inst, errp);
	    dm_free_name(str);
	}
}

static void
do_misc_attrs(CCIMInstance *inst, int *errp, uint64_t size,
	uint32_t starting_cylinder, uint32_t end_cylinder, uint32_t ncylinders)
{
	do_prop64(inst, "PartitionSize", size, errp);
	if (*errp != 0)
	    return;

	do_prop32(inst, "StartCylinder", starting_cylinder, errp);
	if (*errp != 0)
	    return;

	do_prop32(inst, "TotalCylinders", ncylinders, errp);
	if (*errp != 0)
	    return;

	do_prop32(inst, "EndCylinder", end_cylinder, errp);
}

static void
do_prop64(CCIMInstance *inst, char *name, uint64_t val, int *errp)
{
	char	buf[100];
	int	error;

	error = snprintf(buf, sizeof (buf), "%llu", val);
	if (error < 0) {
	    *errp = error;
	    return;
	}

	util_doProperty(name, uint64, buf, cim_false, inst, errp);
}

static void
do_prop32(CCIMInstance *inst, char *name, uint32_t val, int *errp)
{
	char	buf[100];
	int	error;

	error = snprintf(buf, sizeof (buf), "%u", val);
	if (error < 0) {
	    *errp = error;
	    return;
	}

	util_doProperty(name, uint32, buf, cim_false, inst, errp);
}

static dm_descriptor_t
get_first_assoc(dm_descriptor_t desc, dm_desc_type_t type, int *errp)
{
	dm_descriptor_t		*da;
	dm_descriptor_t		d;
	int			i;

	da = dm_get_associated_descriptors(desc, type, errp);

	if (*errp == ENODEV || da == NULL || da[0] == NULL) {
	    *errp = 0;
	    return (NULL);
	}

	if (*errp != 0) {
	    return (NULL);
	}

	d = da[0];

	/* there shouldn't be any more, but just in case */
	for (i = 1; da[i]; i++) {
	    dm_free_descriptor(da[i]);
	}
	free(da);

	return (d);
}

static CCIMInstance *
fatal(CCIMInstance *inst, dm_descriptor_t desc, int *errp)
{
	CCIMException		*ex;

	ex = cim_getLastError();
	util_handleError(PARTITION_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
	    ADD_PROPERTY_FAILURE, ex, errp);
	if (inst != NULL) {
	    cim_freeInstance(inst);
	}
	if (desc != NULL) {
	    dm_free_descriptor(desc);
	}
	return ((CCIMInstance *)NULL);
}
