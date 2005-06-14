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
 * Convert a single descriptor in to a Solaris_MPXIOGroup instance
 */

CCIMInstance *
mpxiogroup_descriptor_toCCIMInstance(dm_descriptor_t  desc, char *provider,
    int *errp)
{

	CCIMInstance		*inst = NULL;
	CCIMException		*ex;
	char			*str;
	int			error;

	*errp = 0;

	/* Create instance of MPXIO Group */

	if ((inst = cim_createInstance(provider)) == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, errp);
	    return ((CCIMInstance *)NULL);
	}

	/* First, assign the deviceID */

	str = dm_get_name(desc, &error);

	if (error != 0) {
	    util_handleError(MPXIO_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	if (str == NULL) {
	    util_handleError(MPXIO_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		DM_GET_NAME_FAILURE, NULL, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty(NAME, string, str, cim_true, inst, errp);
	dm_free_name(str);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	/* add keys */

	util_doProperty(CREATION_CLASS, string, provider, cim_true,
	    inst, errp);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("RedundancyStatus", string, "2", cim_false,
	    inst, errp);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}

/* Convert the descriptor list to a CIMInstance List */

CCIMInstanceList*
mpxiogroup_descriptors_toCCIMInstanceList(char *providerName,
    dm_descriptor_t *dp, int *errp)
{
	CCIMInstance 		*inst;
	CCIMInstanceList 	*instList = NULL;
	CCIMException		*ex;
	nvlist_t		*nvlp;
	char			*type = NULL;
	int			i;
	int			error = 0;

	*errp = 0;

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(MPXIO_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, CREATE_INSTANCE_LIST_FAILURE, ex, errp);
	    return ((CCIMInstanceList *)NULL);
	}

	for (i = 0; dp[i] != NULL; i ++) {

	    nvlp = dm_get_attributes(dp[i], errp);
	    if (*errp != 0) {
		util_handleError(MPXIO_DESCRIPTOR_FUNC,
		    CIM_ERR_FAILED, DM_GET_ATTR_FAILURE, NULL, errp);
		return ((CCIMInstanceList *)NULL);
	    }
		/*
		 * Create the instance list which will store the instances
		 * Only create this list when we know we have a valid
		 * instance to create
		 */

	    *errp = nvlist_lookup_string(nvlp, "ctype", &type);
	    if (*errp != 0) {
		util_handleError(MPXIO_DESCRIPTOR_FUNC, CIM_ERR_FAILED,
		    NVLIST_FAILURE, NULL, errp);
		nvlist_free(nvlp);
		return ((CCIMInstanceList *)NULL);
	    }

	    error = nvlist_lookup_boolean(nvlp, "multiplex");

		/*
		 * Only interested in mpxio controller types since they are
		 * the only ones that can be in an mpxiogroup relationship.
		 */

	    if (strcasecmp(type, "scsi") == 0) {
		if (error != 0) {
		    continue;
		}
	    } else {
		continue;
	    }

	    inst = mpxiogroup_descriptor_toCCIMInstance(dp[i], providerName,
		errp);
	    if (*errp != 0) {
		/* Error handling is done in the subfunction. */
		cim_freeInstanceList(instList);
		nvlist_free(nvlp);
		return ((CCIMInstanceList *)NULL);
	    }

	    /* add the instance to the instance list */
	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(MPXIO_DESCRIPTOR_FUNC,
		    CIM_ERR_FAILED, ADD_INSTANCE_FAILURE, ex, errp);
		cim_freeInstance(inst);
		nvlist_free(nvlp);
		return ((CCIMInstanceList *)NULL);
	    }
	}
	nvlist_free(nvlp);

	if (instList->mDataObject == NULL) {
	    cim_freeInstanceList(instList);
	    instList = NULL;
	}
	return (instList);
}
