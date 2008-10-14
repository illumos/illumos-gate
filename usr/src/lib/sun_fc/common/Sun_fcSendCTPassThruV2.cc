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



#include "Trace.h"
#include "Handle.h"
#include "HBA.h"
#include "HBAPort.h"
#include "Exceptions.h"
#include "sun_fc.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mkdev.h>
#include <errno.h>
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Send a CT passthrough frame to the fabric
 * @return	    HBA_STATUS_OK or other error code
 * @param	    handle The HBA to operate on
 * @param	    portWWN Identifies the HBA port to use
 * @param	    requestBuffer Contains the user requested CT command
 * @param	    requestSize The size of the request
 * @param	    responseBuffer Contains the user-allocated response buf
 * @param	    responseSize The size of the response buf
 */
HBA_STATUS Sun_fcSendCTPassThruV2(HBA_HANDLE handle, HBA_WWN portWWN,
	    void *requestBuffer, HBA_UINT32 requestSize,
	    void *responseBuffer, HBA_UINT32 *responseSize) {
	Trace log("Sun_fcSendCTPassThruV2");

	/* Validate the arguments */
	if (requestBuffer == NULL ||
		responseBuffer == NULL ||
		responseSize == NULL) {
	    log.userError("NULL argument");
	    return (HBA_STATUS_ERROR_ARG);
	}

	try {
	    Handle *myHandle = Handle::findHandle(handle);
	    HBA *hba = myHandle->getHBA();
	    HBAPort *port = hba->getPort(wwnConversion(portWWN.wwn));

	    port->sendCTPassThru(requestBuffer, requestSize,
		    responseBuffer, responseSize);
	    return (HBA_STATUS_OK);
	} catch (HBAException &e) {
	    return (e.getErrorCode());
	} catch (...) {
	    log.internalError(
		"Uncaught exception");
	    return (HBA_STATUS_ERROR);
	}
}
#ifdef	__cplusplus
}
#endif
