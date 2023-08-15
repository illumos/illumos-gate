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

#ifndef	_TARGETEVENT_H
#define	_TARGETEVENT_H



#include "Event.h"
#include <hbaapi.h>


/**
 * @memo	    Represents a target Event
 *
 * @doc		    When target events occur on the HBA, an
 *		    event of this type will be sent to registered
 *		    listeners
 */
class TargetEvent : public Event {
public:
    enum EVENT_TYPE {
		UNKNOWN = HBA_EVENT_TARGET_UNKNOWN,
		OFFLINE = HBA_EVENT_TARGET_OFFLINE,
		ONLINE = HBA_EVENT_TARGET_ONLINE,
		REMOVED = HBA_EVENT_TARGET_REMOVED
	    };
    TargetEvent(uint64_t myHBAPortWWN, uint64_t myTargetPortWWN,
		EVENT_TYPE myType) :
		hbaWWN(myHBAPortWWN), targetWWN(myTargetPortWWN), type(myType) { }
    uint64_t getHBAPortWWN() { return (hbaWWN); }
    uint64_t getTargetPortWWN() { return (targetWWN); }
    EVENT_TYPE getType() { return (type); }

private:
    uint64_t hbaWWN;
    uint64_t targetWWN;
    EVENT_TYPE type;
};

#endif /* _TARGETEVENT_H */
