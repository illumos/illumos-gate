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



#include "LinkEventListener.h"
#include "LinkEvent.h"
#include "Exceptions.h"
#include "Trace.h"
#include "sun_fc.h"

/**
 * @memo	    Create a new LinkEvent listener
 * @postcondition   Listener ready to receive callbacks
 * @exception	    BadArgumentException
 * @param	    myCallback	The listeners callback routine
 * @param	    data	Opaque data that will be passed to the
 *				callback routine when and event comes in.
 *
 */
LinkEventListener::LinkEventListener(LinkCallback myCallback,
	void *data, void *myBuf, uint32_t mySize) :
	Listener(data), callback(myCallback), buf(myBuf), size(mySize) {
	Trace log("LinkEventListener::LinkEventListener");
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
void LinkEventListener::dispatch(Event &event) {
	Trace log("LinkEventListener::dispatch");
	LinkEvent *e = static_cast<LinkEvent*> (&event);
	if (e != NULL) {
	    HBA_WWN wwn;
	    uint64_t lwwn = htonll(e->getPortWWN());
	    memcpy(&wwn, &lwwn, sizeof (wwn));
	    callback(getData(), wwn, e->getType(), e->getBuf(), e->getSize());
	} else {
	    log.internalError("Unexpected event type.");
	}
}
