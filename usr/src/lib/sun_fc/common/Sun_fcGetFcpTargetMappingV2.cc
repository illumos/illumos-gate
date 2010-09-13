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



#include "Handle.h"
#include "HBA.h"
#include "HBAPort.h"
#include "Trace.h"
#include "Exceptions.h"
#include "sun_fc.h"
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Retrieves the mapping between FCP targets and OS
 *		    SCSI information
 * @return	    HBA_STATUS_OK if userMappings contains valid response data
 * @return	    HBA_STATUS_ERROR if an error was encountered.  The
 *		    contents of userMappings is undefined 
 * @param	    handle The HBA to fetch mappings on
 * @param	    portWWN The HBA Port to fetch mappings on
 * @param	    userMappings a pre-allocated user structure to store
 *		    the mappings within.  NumberOfEntries must be set
 *		    to indicate the size of the allocated buffer.
 * 
 */
HBA_STATUS Sun_fcGetFcpTargetMappingV2(HBA_HANDLE handle, HBA_WWN portWWN,
	    PHBA_FCPTARGETMAPPINGV2 userMappings) {
	Trace log("Sun_fcGetFcpTargetMappingV2");

	try {
	    Handle *myHandle = Handle::findHandle(handle);
	    HBA *hba = myHandle->getHBA();
	    HBAPort *port = hba->getPort(wwnConversion(portWWN.wwn));
	    port->getTargetMappings(userMappings);
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
