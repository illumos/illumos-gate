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
#include "logicaldisk_descriptors.h"
#include "partition_descriptors.h"

/*
 * Convert a the antecedent and dependent descriptors to a
 * Solaris_DiskPartitionBasedOn & Solaris_DiskPartitionBasedOnFdisk
 * association instance
 */

CCIMInstance *
partbasedon_descriptor_toCCIMInstance(char *hostname, dm_descriptor_t  ant,
    dm_descriptor_t dep, char *provider, int *errp)
{
	nvlist_t		*nvlp;
	nvpair_t		*nvp;
	CCIMInstance		*inst = NULL;
	CCIMInstance		*ant_inst;
	CCIMInstance		*dep_inst;
	CCIMObjectPath		*ant_op;
	CCIMObjectPath		*dep_op;
	CCIMException		*ex;
	int			error;
	uint64_t		size;  /* need these to calculate ending addr */
	uint64_t		startaddr;
	uint64_t		endaddr;
	char			attrval[100];
	int			isFdisk = 0;

	*errp = 0;

	/* Create instance of partition based on assoc. */

	if ((inst = cim_createInstance(provider)) == NULL) {
	    ex = cim_getLastError();
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, errp);
	    return ((CCIMInstance *)NULL);
	}

	if ((strcasecmp(provider, DISKPART_BASEDONFDISK)) == 0) {
	    isFdisk = 1;
	}

	/*
	 * Now get the object path for the REF pointers.
	 */


	if (isFdisk) {
	    ant_inst = partition_descriptor_toCCIMInstance(hostname, ant,
		DISK_PARTITION, &error);
	} else {
	    ant_inst = logicaldisk_descriptor_toCCIMInstance(hostname, ant,
		LOGICAL_DISK, &error);
	}

	if (error != 0) {
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, PARTBASEDON_DESC_TO_INSTANCE_FAILURE,
		    NULL, &error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	dep_inst = partition_descriptor_toCCIMInstance(hostname, dep,
	    DISK_PARTITION, &error);

	if (error != 0) {
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, PARTBASEDON_DESC_TO_INSTANCE_FAILURE,
		    NULL, &error);
	    cim_freeInstance(inst);
	    cim_freeInstance(ant_inst);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Get the object paths that are represented by these instances.
	 * Add these properties to the association instance.
	 */

	ant_op = cim_createObjectPath(ant_inst);
	dep_op = cim_createObjectPath(dep_inst);
	cim_freeInstance(ant_inst);
	cim_freeInstance(dep_inst);

	if (ant_op == NULL || dep_op == NULL) {
	    ex = cim_getLastError();
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE, ex, &error);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doReferenceProperty(ANTECEDENT, ant_op, cim_true, inst, errp);
	util_doReferenceProperty(DEPENDENT, dep_op, cim_true, inst, errp);
	cim_freeObjectPath(ant_op);
	cim_freeObjectPath(dep_op);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Now get the other attributes we are interested in
	 */

	nvlp = dm_get_attributes(dep, &error);
	if (error != 0) {
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_ATTR_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	if (nvlp == NULL) {
	    return (inst);
	}

	for (nvp = nvlist_next_nvpair(nvlp, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvlp, nvp)) {

	    char	*attrname;
	    uint64_t	ui64;
	    uint32_t	ui32;

	    attrname = nvpair_name(nvp);
	    if (attrname == NULL) {
		continue;
	    }

	    if (strcasecmp(attrname, DM_SIZE) == 0) {
		error = nvpair_value_uint64(nvp, &ui64);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}
		size = ui64;
	    } else if (strcasecmp(attrname, DM_START) == 0) {
		error = nvpair_value_uint64(nvp, &ui64);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		startaddr = ui64;
		error = snprintf(attrval, sizeof (attrval), "%llu", ui64);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		util_doProperty("StartingAddress", uint64, attrval, cim_false,
		    inst, errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    } else if (strcasecmp(attrname, DM_INDEX) == 0) {
		error = nvpair_value_uint32(nvp, &ui32);
		if (error != 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		error = snprintf(attrval, sizeof (attrval), "%u", ui32);
		if (error < 0) {
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		    return ((CCIMInstance *)NULL);
		}

		util_doProperty("OrderIndex", uint32, attrval, cim_false,
		    inst, errp);

		if (*errp != 0) {
		    ex = cim_getLastError();
		    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
			CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
		    cim_freeInstance(inst);
		    nvlist_free(nvlp);
		    return ((CCIMInstance *)NULL);
		}
	    }
	}

	nvlist_free(nvlp);
	/*
	 * Now add the ending address attribute. Do this here because
	 * there is no guarantee about the order for how these name/value
	 * pairs are given and without the starting address we cannot
	 * calculate the ending address.
	 */

	endaddr = startaddr + size;
	error = snprintf(attrval, sizeof (attrval), "%llu", endaddr);
	if (error < 0) {
	    cim_freeInstance(inst);
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("EndingAddress", uint64, attrval, cim_false, inst,
	    errp);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}
