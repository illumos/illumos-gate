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
#include "Exceptions.h"
#include "Handle.h"
#include "HBA.h"
#include "HBAPort.h"
#include "sun_fc.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <errno.h>
#ifdef	__cplusplus
extern "C" {
#endif



/**
 * @memo	    Returns the RNID from port 0 on the HBA
 * @return	    HBA_STATUS_OK if value is fetched
 * @param	    handle The HBA to operate on
 * @param	    info Pointer to user-allocated buffer for results
 */
HBA_STATUS Sun_fcGetRNIDMgmtInfo(HBA_HANDLE handle,
	    PHBA_MGMTINFO info) {
	Trace log("Sun_fcGetRNIDMgmtInfo");

	try {
	    Handle *myHandle = Handle::findHandle(handle);
	    HBA *hba = myHandle->getHBA();
	    HBAPort *port = hba->getPortByIndex(0); // Always use port zero
	    port->getRNIDMgmtInfo(info);
	    return (HBA_STATUS_OK);
	} catch (HBAException &e) {
	    return (e.getErrorCode());
	} catch (...) {
	    log.internalError("Uncaught exception");
	    return (HBA_STATUS_ERROR);
	}
}
#ifdef	__cplusplus
}
#endif
