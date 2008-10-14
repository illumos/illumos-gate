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
#include "AdapterPortEventListener.h"
#include "sun_fc.h"
#include "EventBridgeFactory.h"
#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Register for Adapter Port Event callbacks
 * @return	    HBA_STATUS_OK if callback is registered
 * @param	    callback The routine to call when the event occurs
 * @param	    userData Opaque data to pass to the callback when the event
 *		    occurs.
 * @param	    callbackHandle Output argument used for later removal of
 *		    subscription.
 * @param	    PortWWN Identifies the HBA port of interest
 */
HBA_STATUS Sun_fcRegisterForAdapterPortEvents(
	    void		(*callback)(
		void		*data,
		HBA_WWN		PortWWN,
		HBA_UINT32	eventType,
		HBA_UINT32	fabricPortID),
	    void		*userData,
	    HBA_HANDLE		handle,
	    HBA_WWN		PortWWN,
	    HBA_CALLBACKHANDLE *callbackHandle) {
	Trace log("Sun_fcRegisterForAdapterPortEvents");
	try {
	    if (callback == NULL) throw BadArgumentException();
	    if (callbackHandle == NULL) throw BadArgumentException();
	    Handle *myHandle = Handle::findHandle(handle);
	    HBA *hba = myHandle->getHBA();
	    HBAPort *port = hba->getPort(wwnConversion(PortWWN.wwn));
	    AdapterPortEventListener *listener = new AdapterPortEventListener(
		    port, (AdapterPortCallback)callback, userData);
	    AdapterPortEventBridge *bridge =
		    EventBridgeFactory::fetchAdapterPortEventBridge();
	    bridge->addListener(listener, port);
	    *callbackHandle = (void *)listener;
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
