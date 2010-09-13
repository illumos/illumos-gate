/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 *  You may not use this file except in compliance with the License.
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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "mp_utils.h"


/*
 *	Global Variables
 */

MP_UINT32	g_pluginOwnerID = 0;
int		g_scsi_vhci_fd  = -1;

PROPERTY_CALLBACK_NODE   g_Property_Callback_List[MP_OBJECT_TYPE_MAX + 1];
VISIBILITY_CALLBACK_NODE g_Visibility_Callback_List[MP_OBJECT_TYPE_MAX + 1];

sysevent_handle_t *g_SysEventHandle = NULL;

pthread_mutex_t g_visa_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_prop_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 *	Called by the common layer to request the plugin to initialize
 *	itself.
 */

MP_STATUS
Initialize(MP_UINT32 pluginOwnerID)
{
	log(LOG_INFO, "Initialize()", " - enter");


	(void) memset(&g_Property_Callback_List, 0,
	    sizeof (PROPERTY_CALLBACK_NODE) * (MP_OBJECT_TYPE_MAX + 1));

	(void) memset(&g_Visibility_Callback_List, 0,
	    sizeof (VISIBILITY_CALLBACK_NODE) * (MP_OBJECT_TYPE_MAX + 1));

	/* Attempt to open the driver that this plugin will make request of. */
	g_scsi_vhci_fd = open("/devices/scsi_vhci:devctl",
	    O_NDELAY | O_RDONLY);

	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "Initialize()",
		    " - failed to open driver.  error is : %s",
		    strerror(errno));
		log(LOG_INFO, "Initialize()", " - error exit");
		return (MP_STATUS_FAILED);
	}

	g_pluginOwnerID = pluginOwnerID;

	log(LOG_INFO, "Initialize()", " - exit");

	return (MP_STATUS_SUCCESS);
}
