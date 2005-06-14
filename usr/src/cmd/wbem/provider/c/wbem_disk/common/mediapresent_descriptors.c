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
#include "drive_descriptors.h"

/*
 * Convert a the antecedent and dependent descriptors to a
 * Solaris_MediaPresent association instance
 */

CCIMInstance *
mediapresent_descriptor_toCCIMInstance(char *hostname, dm_descriptor_t  ant,
    dm_descriptor_t dep, char *provider, int *errp)
{
	CCIMInstance		*inst = NULL;
	CCIMInstance		*ant_inst;
	CCIMInstance		*dep_inst;
	CCIMObjectPath		*ant_op;
	CCIMObjectPath		*dep_op;
	CCIMException		*ex;

	*errp = 0;

	/* Create instance of media present assoc. */

	if ((inst = cim_createInstance(provider)) == NULL) {
	    ex = cim_getLastError();
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, CREATE_INSTANCE_FAILURE, ex, errp);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Now get the object path for the REF pointers.
	 */

	ant_inst = drive_descriptor_toCCIMInstance(hostname, ant,
		DISK_DRIVE, errp);

	if (*errp != 0) {
	    util_handleError(MEDIAPRES_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, MEDIAPRES_DESC_TO_INSTANCE_FAILURE, NULL,
		    errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	dep_inst = logicaldisk_descriptor_toCCIMInstance(hostname, dep,
	    LOGICAL_DISK, errp);

	if (*errp != 0) {
	    util_handleError(MEDIAPRES_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, MEDIAPRES_DESC_TO_INSTANCE_FAILURE,
		    NULL, errp);
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
		CIM_ERR_FAILED, CREATE_OBJECT_PATH_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}


	util_doReferenceProperty(ANTECEDENT, ant_op, cim_true, inst, errp);
	cim_freeObjectPath(ant_op);

	util_doReferenceProperty(DEPENDENT, dep_op, cim_true, inst, errp);
	cim_freeObjectPath(dep_op);

	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(PARTBASEDON_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}

	util_doProperty("FixedMedia", boolean, "1", cim_false, inst, errp);
	if (*errp != 0) {
	    ex = cim_getLastError();
	    util_handleError(MEDIAPRES_DESCRIPTOR_FUNC,
		CIM_ERR_FAILED, ADD_PROPERTY_FAILURE, ex, errp);
	    cim_freeInstance(inst);
	    return ((CCIMInstance *)NULL);
	}
	return (inst);
}
