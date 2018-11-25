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
#include "HBA.h"
#include "HBAPort.h"
#include "Exceptions.h"
#include "sun_fc.h"
#include <unistd.h>

#define	    BUSY_SLEEP		1000 /* 1/100 second */
#define	    BUSY_RETRY_TIMER	5000000000ULL /* Retry for 5 seconds */
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Send a read capacity to a remote WWN
 * @return	    HBA_STATUS_OK or other error code
 *		    scsiStatus should be checked to ensure SCSI command
 *		    was a success.
 * @param	    handle The HBA to operate on
 * @param	    portWWN Indicates the HBA port to send command through
 * @param	    targetPortWWN Indicates the target to send command to
 * @param	    fcLun Indicates the target unit to send command to
 * @param	    responseBuffer User-allocated response buffer
 * @param	    responseSize Size of User-allocated response buffer
 * @param	    scsiStatus User-allocated scsi status byte
 *
 * @doc		    This routine will attempt a limited number of retries
 *		    When busy or again errors are encountered.
 */
HBA_STATUS
Sun_fcScsiReadCapacityV2(HBA_HANDLE handle, HBA_WWN portWWN,
	    HBA_WWN targetPortWWN, HBA_UINT64 fcLun,
	    void *responseBuffer, HBA_UINT32 *responseSize,
	    HBA_UINT8 *scsiStatus,
	    void *senseBuffer, HBA_UINT32 *senseSize) {
	Trace log("Sun_fcScsiReadCapacityV2");

	hrtime_t start = gethrtime();
	hrtime_t end = start + BUSY_RETRY_TIMER;
	for (hrtime_t cur = start; cur < end; cur = gethrtime()) {
	    try {
		Handle *myHandle = Handle::findHandle(handle);
		HBA *hba = myHandle->getHBA();
		HBAPort *port = hba->getPort(wwnConversion(portWWN.wwn));
		port->sendReadCapacity(wwnConversion(targetPortWWN.wwn),
			fcLun, responseBuffer, responseSize, scsiStatus,
			senseBuffer, senseSize);
		return (HBA_STATUS_OK);
	    } catch (BusyException &e) {
		usleep(BUSY_SLEEP);
		continue;
	    } catch (TryAgainException &e) {
		usleep(BUSY_SLEEP);
		continue;
	    } catch (HBAException &e) {
		return (e.getErrorCode());
	    } catch (...) {
		log.internalError(
		    "Uncaught exception");
		return (HBA_STATUS_ERROR);
	    }
	}
	return (HBA_STATUS_ERROR_TRY_AGAIN);
}
#ifdef	__cplusplus
}
#endif
