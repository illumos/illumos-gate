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




#include "TargetEventListener.h"
#include "TargetEvent.h"
#include "Exceptions.h"
#include "Trace.h"
#include "sun_fc.h"

/**
 * @memo	    Create a new TargetEvent listener
 * @postcondition   Listener ready to receive callbacks
 * @exception	    BadArgumentException
 * @param	    myCallback	The listeners callback routine
 * @param	    data	Opaque data that will be passed to the
 *				callback routine when and event comes in.
 */
TargetEventListener::TargetEventListener(HBAPort *myPort,
	TargetCallback myCallback, void *data, uint64_t wwn, bool myFilter) :
	port(myPort), Listener(data), callback(myCallback), targetPortWWN(wwn),
	filter(myFilter) {

	Trace log("TargetEventListener::TargetEventListener");
	if (callback == NULL) {
	    throw BadArgumentException();
	}
}

/**
 * @memo	    Send the event to this listener
 * @param	    event   The event to send to the listener
 *
 * @doc		    The callback registered in the constructor will
 *		    be called.
 */
void TargetEventListener::dispatch(Event &event) {
	Trace log("TargetEventListener::dispatch");
	TargetEvent *e = static_cast<TargetEvent*> (&event);
	if (e != NULL) {
	    HBA_WWN hbawwn;
	    uint64_t hbalwwn = e->getHBAPortWWN();
	    // Filter out unwanted events
	    if (port->getPortWWN() != hbalwwn) {
		return;
	    }
	    if (filter) {
		if (targetPortWWN != e->getTargetPortWWN()) {
		    return;
		}
	    }
	    hbalwwn = htonll(hbalwwn);
	    memcpy(&hbawwn, &hbalwwn, sizeof (hbawwn));
	    HBA_WWN tgtwwn;
	    uint64_t tgtlwwn = htonll(e->getTargetPortWWN());
	    memcpy(&tgtwwn, &tgtlwwn, sizeof (tgtwwn));
	    callback(getData(), hbawwn, tgtwwn, e->getType());
	} else {
	    log.internalError("Unexpected event type.");
	}
}
