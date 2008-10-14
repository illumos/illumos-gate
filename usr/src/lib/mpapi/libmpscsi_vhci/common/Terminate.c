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

#include <syslog.h>
#include <unistd.h>

#include "mp_utils.h"


MP_STATUS
Terminate(void)
{
	log(LOG_INFO, "Terminate()", " - enter");


	if (g_scsi_vhci_fd > -1) {
		(void) close(g_scsi_vhci_fd);
	}

	if (NULL != g_SysEventHandle) {

		sysevent_unbind_handle(g_SysEventHandle);
	}

	(void) pthread_mutex_destroy(&g_visa_mutex);
	(void) pthread_mutex_destroy(&g_prop_mutex);

	log(LOG_INFO, "Terminate()", " - exit");

	return (MP_STATUS_SUCCESS);
}
