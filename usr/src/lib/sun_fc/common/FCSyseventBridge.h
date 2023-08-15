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

#ifndef	_FCSYSEVENTBRIDGE_H
#define	_FCSYSEVENTBRIDGE_H



#include "AdapterAddEventBridge.h"
#include "AdapterEventBridge.h"
#include "AdapterPortEventBridge.h"
#include "AdapterDeviceEventBridge.h"
#include "TargetEventBridge.h"
#include "Lockable.h"
#include <vector>
#include <libsysevent.h>

/**
 * Note: Even though we take various arguments in within the API,
 * we don't actually filter anything, since sys-even is either on
 * or off.  The idea is that the actual Listener themselves will perform
 * a final filter pass, so why do the work twice.  If we were going to
 * use proprietary IOCTLs or some other event plumbing that allowed filtering,
 * we could use the passed in arguments to do useful work.  In short,
 * once turned on, we send events of a given type and rely on
 * someone downstream to filter.
 */
class FCSyseventBridge :
	public AdapterAddEventBridge,
	public AdapterEventBridge,
	public AdapterPortEventBridge,
	public AdapterDeviceEventBridge,
	public TargetEventBridge,
	public Lockable {
public:
    static FCSyseventBridge* getInstance();
    virtual int32_t getMaxListener();
    virtual void addListener(AdapterAddEventListener *listener);
    virtual void addListener(AdapterEventListener *listener, HBA *hba);
    virtual void addListener(AdapterPortEventListener *listener, HBAPort *port);
    virtual void addListener(AdapterDeviceEventListener *listener,
	     HBAPort *port);
    virtual void addListener(TargetEventListener *listener,
	    HBAPort *port, uint64_t targetWWN, bool filter);
    virtual void removeListener(AdapterAddEventListener *listener);
    virtual void removeListener(AdapterEventListener *listener);
    virtual void removeListener(AdapterPortEventListener *listener);
    virtual void removeListener(AdapterDeviceEventListener *listener);
    virtual void removeListener(TargetEventListener *listener);

    /* Private function, called by handler.  Friend maybe? */
    void dispatch(sysevent_t *ev);

private:
    FCSyseventBridge() :handle(NULL) { }
    /**
     * Subscribe if we need to, or unsubscribe if nobody is left
     * Instance lock must already be held!
     */
    void validateRegistration();
    sysevent_handle_t *handle;
    static FCSyseventBridge*	_instance;


    std::vector<AdapterAddEventListener*>	adapterAddEventListeners;
    std::vector<AdapterEventListener*>		adapterEventListeners;
    std::vector<AdapterPortEventListener*>	adapterPortEventListeners;
    std::vector<AdapterDeviceEventListener*>	adapterDeviceEventListeners;
    std::vector<TargetEventListener*>		targetEventListeners;
};

#endif /* _FCSYSEVENTBRIDGE_H */
