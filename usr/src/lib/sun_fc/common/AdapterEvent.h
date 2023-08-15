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

#ifndef	_ADAPTEREVENT_H
#define	_ADAPTEREVENT_H



#include "Event.h"

#include <hbaapi.h>

/**
 * @memo	    Represents an Adapter Event
 *
 * @doc		    When adapter events occur on the HBA, an
 *		    event of this type will be sent to registered
 *		    listeners
 */
class AdapterEvent : public Event {
public:
    enum EVENT_TYPE {
		UNKNOWN = HBA_EVENT_ADAPTER_UNKNOWN,
		ADD = HBA_EVENT_ADAPTER_ADD,
		REMOVE = HBA_EVENT_ADAPTER_REMOVE,
		CHANGE = HBA_EVENT_ADAPTER_CHANGE
	    };
    AdapterEvent(uint64_t myWwn, EVENT_TYPE myType) :
		    wwn(myWwn), type(myType) { }
    uint64_t getPortWWN() { return (wwn); }
    EVENT_TYPE getType() { return (type); }

private:
    uint64_t wwn;
    EVENT_TYPE type;
};

#endif /* _ADAPTEREVENT_H */
