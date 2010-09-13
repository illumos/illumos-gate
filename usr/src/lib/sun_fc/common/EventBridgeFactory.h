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

#ifndef	_EVENTBRIDGEFACTORY_H
#define	_EVENTBRIDGEFACTORY_H



#include "AdapterAddEventBridge.h"
#include "AdapterEventBridge.h"
#include "AdapterPortEventBridge.h"
#include "AdapterDeviceEventBridge.h"
#include "AdapterPortStatEventBridge.h"
#include "LinkEventBridge.h"
#include "TargetEventBridge.h"

/*
 * @memo	    Static routines to build the proper event bridge
 *		    for the current version of the library.
 *
 * @doc		    To keep client code isolated from the underlying
 *		    event infrastructure (eg: sysevent, IOCTLs, etc.)
 *		    Bridge classes are used for registration.  This
 *		    factory interface allows client code to be compiled
 *		    once without knowledge of the underlying details.
 *		    The concrete implementation of this class will
 *		    define which concrete bridge instance(s)
 *		    are returned.
 */
class EventBridgeFactory {
public:
    static AdapterAddEventBridge* fetchAdapterAddEventBridge();
    static AdapterEventBridge* fetchAdapterEventBridge();
    static AdapterPortEventBridge* fetchAdapterPortEventBridge();
    static AdapterDeviceEventBridge* fetchAdapterDeviceEventBridge();
    static AdapterPortStatEventBridge* fetchAdapterPortStatEventBridge();
    static TargetEventBridge* fetchTargetEventBridge();
    static LinkEventBridge* fetchLinkEventBridge();
};

#endif /* _EVENTBRIDGEFACTORY_H */
