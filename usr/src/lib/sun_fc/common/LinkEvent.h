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

#ifndef _LINKEVENT_H
#define _LINKEVENT_H

#include "Event.h"
#include <hbaapi.h>

/**
 * @memo	    Represents a Link Event
 *
 * @doc		    When link events occur on the HBA, an
 *		    event of this type will be sent to registered
 *		    listeners
 */
class LinkEvent : public Event {
public:
    enum EVENT_TYPE {
		UNKNOWN = HBA_EVENT_LINK_UNKNOWN,
		INCIDENT = HBA_EVENT_LINK_INCIDENT
	    };
    LinkEvent(uint64_t myWwn, void *myBuf, uint32_t mySize, EVENT_TYPE myType) :
		    wwn(myWwn), buf(myBuf), size(mySize), type(myType) { }
    uint64_t getPortWWN() { return (wwn); }
    void* getBuf() { return (buf); }
    uint32_t getSize() { return (size); }
    EVENT_TYPE getType() { return (type); }

private:
    uint64_t wwn;
    void    *buf;
    uint32_t size;
    EVENT_TYPE type;
};

#endif /* _LINKEVENT_H */
