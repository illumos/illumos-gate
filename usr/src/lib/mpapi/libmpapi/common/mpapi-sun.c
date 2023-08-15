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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Description
 * mpapi-sun.c - Implements the Sun Extension to the Multipath Management
 * API Version 1.0
 */

#include <dlfcn.h>
#include <pthread.h>
#include "mpapi.h"
#include "mpapi-sun.h"
#include "mpapi-plugin.h"

extern MPPLUGININFO_T plugintable[MP_MAX_NUM_PLUGINS];

extern pthread_mutex_t mp_lib_mutex;
extern MP_STATUS validate_object(MP_OID obj, MP_OBJECT_TYPE objType,
		MP_UINT32 flag);

MP_STATUS Sun_MP_SendScsiCmd(
	MP_OID pathOid, struct uscsi_cmd *cmd)
{
	Sun_MP_SendScsiCmdFn PassFunc;
	MP_UINT32 index;
	MP_STATUS status;

	if ((status = validate_object(pathOid, MP_OBJECT_TYPE_PATH_LU,
	    MP_OBJECT_TYPE_MATCH)) != MP_STATUS_SUCCESS) {
	    return (status);
	}

	(void) pthread_mutex_lock(&mp_lib_mutex);

	index = pathOid.ownerId - 1;
	if (plugintable[index].hdlPlugin != NULL) {
	    PassFunc = (Sun_MP_SendScsiCmdFn)
	    dlsym(plugintable[index].hdlPlugin,
	    "Sun_MP_SendScsiCmd");

	    if (PassFunc != NULL) {
		status = PassFunc(pathOid, cmd);
	    } else {
		status = MP_STATUS_UNSUPPORTED;
	    }
	} else {
	    status = MP_STATUS_FAILED;
	}

	(void) pthread_mutex_unlock(&mp_lib_mutex);
	return (status);
}
