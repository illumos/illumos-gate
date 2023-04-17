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
#include "sun_fc.h"
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Send ELS RPL command out on the wire
 * @return	    HBA_STATUS_OK or error code
 * @param	    handle The HBA to operate on
 * @param	    hbaPortWWN Identifies the HBA port to use
 * @param	    agent_wwn ???
 * @param	    agent_domain ???
 * @param	    portindex ???
 * @param	    pRspBuffer The user-allocated response buffer
 * @param	    pRspBufferSize The size of user-allocated response buffer
 */
HBA_STATUS Sun_fcSendRPL(HBA_HANDLE		handle,
	    HBA_WWN		hbaPortWWN,
	    HBA_WWN		agent_wwn,
	    HBA_UINT32		agent_domain,
	    HBA_UINT32		portindex,
	    void		*pRspBuffer,
	    HBA_UINT32		*pRspBufferSize) {
	Trace log("Sun_fcSendRPL");

	try {
	    Handle *myHandle = Handle::findHandle(handle);
	    HBA *hba = myHandle->getHBA();
	    HBAPort *port = hba->getPort(wwnConversion(hbaPortWWN.wwn));
	    port->sendRPL(wwnConversion(agent_wwn.wwn), agent_domain,
		portindex, pRspBuffer, pRspBufferSize);
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
