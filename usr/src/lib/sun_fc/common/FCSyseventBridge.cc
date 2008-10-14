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



#include "FCSyseventBridge.h"
#include "Exceptions.h"
#include "Trace.h"
#include "AdapterAddEvent.h"
#include "AdapterEvent.h"
#include "AdapterPortEvent.h"
#include "AdapterDeviceEvent.h"
#include "TargetEvent.h"
#include "sun_fc.h"
#include <libnvpair.h>
#include <iostream>

using namespace std;

FCSyseventBridge* FCSyseventBridge::_instance = NULL;

FCSyseventBridge* FCSyseventBridge::getInstance() {
    Trace log("FCSyseventBridge::getInstance");
    if (_instance == NULL) {
	_instance = new FCSyseventBridge();
    }
    return (_instance);

}


void FCSyseventBridge::addListener(AdapterAddEventListener *listener) {
    lock();
    try {
	adapterAddEventListeners.insert(adapterAddEventListeners.begin(),
		listener);
	validateRegistration();
	unlock();
    } catch (...) {
	unlock();
	throw;
    }
}
void FCSyseventBridge::addListener(AdapterEventListener *listener, HBA *hba) {
    lock();
    try {
	adapterEventListeners.insert(adapterEventListeners.begin(), listener);
	validateRegistration();
	unlock();
    } catch (...) {
	unlock();
	throw;
    }
}
void FCSyseventBridge::addListener(AdapterPortEventListener *listener,
	    HBAPort *port) {
    lock();
    try {
	adapterPortEventListeners.insert(adapterPortEventListeners.begin(),
		listener);
	validateRegistration();
	unlock();
    } catch (...) {
	unlock();
	throw;
    }
}
void FCSyseventBridge::addListener(AdapterDeviceEventListener *listener,
    HBAPort *port) {
	lock();
	try {
		adapterDeviceEventListeners.insert(adapterDeviceEventListeners.begin(),
		    listener);
		validateRegistration();
		unlock();
	} catch (...) {
		unlock();
		throw;
	}
}
void FCSyseventBridge::addListener(TargetEventListener *listener,
	    HBAPort *port, uint64_t targetWWN, bool filter) {
    lock();
    try {
	targetEventListeners.insert(targetEventListeners.begin(), listener);
	validateRegistration();
	unlock();
    } catch (...) {
	unlock();
	throw;
    }
}

void FCSyseventBridge::removeListener(AdapterAddEventListener *listener) {
    lock();
    try {
	typedef vector<AdapterAddEventListener *>::iterator Iter;
	for (Iter tmp = adapterAddEventListeners.begin();
		tmp != adapterAddEventListeners.end(); tmp++) {
	    if (*tmp == listener) {
		adapterAddEventListeners.erase(tmp);
		unlock();
		return;
	    }
	}
	throw InvalidHandleException();
    } catch (...) {
	unlock();
	throw;
    }
}

void FCSyseventBridge::removeListener(AdapterEventListener *listener) {
    lock();
    try {
	typedef vector<AdapterEventListener *>::iterator Iter;
	for (Iter tmp = adapterEventListeners.begin();
		tmp != adapterEventListeners.end(); tmp++) {
	    if (*tmp == listener) {
		adapterEventListeners.erase(tmp);
		unlock();
		return;
	    }
	}
	throw InvalidHandleException();
    } catch (...) {
	unlock();
	throw;
    }
}

void FCSyseventBridge::removeListener(AdapterPortEventListener *listener) {
    lock();
    try {
	typedef vector<AdapterPortEventListener *>::iterator Iter;
	for (Iter tmp = adapterPortEventListeners.begin();
		tmp != adapterPortEventListeners.end(); tmp++) {
	    if (*tmp == listener) {
		adapterPortEventListeners.erase(tmp);
		unlock();
		return;
	    }
	}
	throw InvalidHandleException();
    } catch (...) {
	unlock();
	throw;
    }
}

void FCSyseventBridge::removeListener(AdapterDeviceEventListener *listener) {
	lock();
	try {
		typedef vector<AdapterDeviceEventListener *>::iterator Iter;
		for (Iter tmp = adapterDeviceEventListeners.begin();
		    tmp != adapterDeviceEventListeners.end(); tmp++) {
			if (*tmp == listener) {
				adapterDeviceEventListeners.erase(tmp);
				unlock();
				return;
			}
		}
		throw InvalidHandleException();
	} catch (...) {
		unlock();
		throw;
	}
}
 
void FCSyseventBridge::removeListener(TargetEventListener *listener) {
    lock();
    try {
	typedef vector<TargetEventListener *>::iterator Iter;
	for (Iter tmp = targetEventListeners.begin();
		tmp != targetEventListeners.end(); tmp++) {
	    if (*tmp == listener) {
		targetEventListeners.erase(tmp);
		unlock();
		return;
	    }
	}
	throw InvalidHandleException();
    } catch (...) {
	unlock();
	throw;
    }
}

extern "C" void static_dispatch(sysevent_t *ev) {
    Trace log("static_dispatch");
    FCSyseventBridge::getInstance()->dispatch(ev);
}

void FCSyseventBridge::dispatch(sysevent_t *ev) {
    Trace log("FCSyseventBridge::dispatch");
    nvlist_t		    *list = NULL;
    hrtime_t			when;

    if (ev == NULL) {
	log.debug("Null event.");
	return;
    }

    if (sysevent_get_attr_list(ev, &list) || list == NULL) {
	log.debug("Empty event.");
	return;
    }

    string eventVendor = sysevent_get_vendor_name(ev);
    string eventPublisher = sysevent_get_pub_name(ev);
    string eventClass = sysevent_get_class_name(ev);
    string eventSubClass = sysevent_get_subclass_name(ev);

    sysevent_get_time(ev, &when);

    // Now that we know what type of event it is, handle it accordingly
    if (eventClass == "EC_sunfc") {

	// All events of this class type have instance and port-wwn for
	// the HBA port.
	uint32_t	instance;
	if (nvlist_lookup_uint32(list, (char *)"instance",
		&instance)) {
	    log.genericIOError(
		"Improperly formed event: no instance field.");
	    nvlist_free(list);
	    return;
	}
	uchar_t		*rawPortWWN;
	uint32_t	rawPortWWNLength;

	if (nvlist_lookup_byte_array(list, (char *)"port-wwn",
		&rawPortWWN, &rawPortWWNLength)) {
	    log.genericIOError(
		"Improperly formed event: no port-wwn field.");
	    nvlist_free(list);
	    return;
	}

	// Now deal with the specific details of each subclass type
	if (eventSubClass == "ESC_sunfc_port_offline") {

	    // Create event instance
	    AdapterPortEvent event(
		wwnConversion(rawPortWWN),
		AdapterPortEvent::OFFLINE,
		0);

	    // Dispatch to interested parties.
	    lock();
	    try {
		typedef vector<AdapterPortEventListener *>::iterator Iter;
		for (Iter tmp = adapterPortEventListeners.begin();
			tmp != adapterPortEventListeners.end(); tmp++) {
		    (*tmp)->dispatch(event);
		}
	    } catch (...) {
		unlock();
		nvlist_free(list);
		throw;
	    }
	    unlock();

	} else if (eventSubClass == "ESC_sunfc_port_online") {

	    // Create event instance
	    AdapterPortEvent event(
		wwnConversion(rawPortWWN),
		AdapterPortEvent::ONLINE,
		0);

	    // Dispatch to interested parties.
	    lock();
	    try {
		typedef vector<AdapterPortEventListener *>::iterator Iter;
		for (Iter tmp = adapterPortEventListeners.begin();
			tmp != adapterPortEventListeners.end(); tmp++) {
		    (*tmp)->dispatch(event);
		}
	    } catch (...) {
		unlock();
		nvlist_free(list);
		throw;
	    }
	    unlock();

	} else if (eventSubClass == "ESC_sunfc_device_online") {
		AdapterDeviceEvent event(
		    wwnConversion(rawPortWWN),
		    AdapterDeviceEvent::ONLINE,
		    0);
		lock();
		try {
			typedef vector<AdapterDeviceEventListener *>::iterator Iter;
			for (Iter tmp = adapterDeviceEventListeners.begin();
			    tmp != adapterDeviceEventListeners.end(); tmp++) {
				(*tmp)->dispatch(event);
			}
		} catch (...) {
			unlock();
			nvlist_free(list);
			throw;
		}
		unlock();

	} else if (eventSubClass == "ESC_sunfc_device_offline") {
		AdapterDeviceEvent event(
		    wwnConversion(rawPortWWN),
		    AdapterDeviceEvent::OFFLINE,
		    0);
		lock();
		try {
			typedef vector<AdapterDeviceEventListener *>::iterator Iter;
			for (Iter tmp = adapterDeviceEventListeners.begin();
			    tmp != adapterDeviceEventListeners.end(); tmp++) {
				(*tmp)->dispatch(event);
			}
		} catch (...) {
			unlock();
			nvlist_free(list);
			throw;
		}
		unlock();

	} else if (eventSubClass == "ESC_sunfc_port_rscn") {
	    /*
	     * RSCNs are a little tricky.  There can be multiple
	     * affected page properties, each numbered.  To make sure
	     * we get them all, we loop through all properties
	     * in the nvlist and if their name begins with "affected_page_"
	     * then we send an event for them.
	     */
	    uint32_t	affected_page;
	    nvpair_t    *attr = NULL;
	    for (attr = nvlist_next_nvpair(list, NULL);
		    attr != NULL;
		    attr = nvlist_next_nvpair(list, attr)) {
		string name = nvpair_name(attr);
		if (name.find("affected_page_") != name.npos) {

		    if (nvpair_value_uint32(attr, &affected_page)) {
			log.genericIOError(
			    "Improperly formed event: "
			    "corrupt affected_page field");
			continue;
		    }
		    // Create event instance
		    AdapterPortEvent event(
			wwnConversion(rawPortWWN),
			AdapterPortEvent::FABRIC,
			affected_page);

		    // Dispatch to interested parties.
		    lock();
		    typedef vector<AdapterPortEventListener *>::iterator Iter;
		    try {
			for (Iter tmp = adapterPortEventListeners.begin();
				tmp != adapterPortEventListeners.end(); tmp++) {
			    (*tmp)->dispatch(event);
			}
		    } catch (...) {
			unlock();
			nvlist_free(list);
			throw;
		    }
		    unlock();
		}
	    }
	} else if (eventSubClass == "ESC_sunfc_target_add") {
	    uchar_t	*rawTargetPortWWN;
	    uint32_t	rawTargetPortWWNLength;

	    if (nvlist_lookup_byte_array(list, (char *)"target-port-wwn",
		    &rawTargetPortWWN, &rawTargetPortWWNLength)) {
		log.genericIOError(
		    "Improperly formed event: no target-port-wwn field.");
		nvlist_free(list);
		return;
	    }

	    // Create event instance
	    AdapterPortEvent event(
		wwnConversion(rawPortWWN),
		AdapterPortEvent::NEW_TARGETS,
		0);

	    // Dispatch to interested parties.
	    lock();
	    try {
		typedef vector<AdapterPortEventListener *>::iterator Iter;
		for (Iter tmp = adapterPortEventListeners.begin();
			tmp != adapterPortEventListeners.end(); tmp++) {
		    (*tmp)->dispatch(event);
		}
	    } catch (...) {
		unlock();
		nvlist_free(list);
		throw;
	    }
	    unlock();
	} else if (eventSubClass == "ESC_sunfc_target_remove") {
	    uchar_t	*rawTargetPortWWN;
	    uint32_t	rawTargetPortWWNLength;

	    if (nvlist_lookup_byte_array(list, (char *)"target-port-wwn",
		    &rawTargetPortWWN, &rawTargetPortWWNLength)) {
		log.genericIOError(
		    "Improperly formed event: no target-port-wwn field.");
		nvlist_free(list);
		return;
	    }
	    // Create event instance
	    TargetEvent event(
		wwnConversion(rawPortWWN),
		wwnConversion(rawTargetPortWWN),
		TargetEvent::REMOVED);

	    // Dispatch to interested parties.
	    lock();
	    try {
		typedef vector<TargetEventListener *>::iterator Iter;
		for (Iter tmp = targetEventListeners.begin();
			tmp != targetEventListeners.end(); tmp++) {
		    (*tmp)->dispatch(event);
		}
	    } catch (...) {
		unlock();
		nvlist_free(list);
		throw;
	    }
	    unlock();
	} else if (eventSubClass == "ESC_sunfc_port_attach") {
	    // Create event instance
	    AdapterAddEvent event(wwnConversion(rawPortWWN));
	    // Dispatch to interested parties.
	    lock();
	    try {
		typedef vector<AdapterAddEventListener *>::iterator Iter;
		for (Iter tmp = adapterAddEventListeners.begin();
			tmp != adapterAddEventListeners.end(); tmp++) {
		    (*tmp)->dispatch(event);
		}
	    } catch (...) {
		unlock();
		nvlist_free(list);
		throw;
	    }
	    unlock();
	} else if (eventSubClass == "ESC_sunfc_port_detach") {
	    // Technically, we should probably try to coalesce
	    // all detach events for the same multi-ported adapter
	    // and only send one event to the client, but for now,
	    // we'll just blindly send duplicates.

	    // Create event instance
	    AdapterEvent event(
		wwnConversion(rawPortWWN),
		AdapterEvent::REMOVE);

	    // Dispatch to interested parties.
	    lock();
	    try {
		typedef vector<AdapterEventListener *>::iterator Iter;
		for (Iter tmp = adapterEventListeners.begin();
			tmp != adapterEventListeners.end(); tmp++) {
		    (*tmp)->dispatch(event);
		}
	    } catch (...) {
		unlock();
		nvlist_free(list);
		throw;
	    }
	    unlock();

	} else {
	    log.genericIOError(
		    "Unrecognized subclass \"%s\": Ignoring event",
		    eventSubClass.c_str());
	}
    } else {
	// This should not happen, as we only asked for specific classes.
	log.genericIOError(
		"Unrecognized class \"%s\": Ignoring event",
		eventClass.c_str());
    }
    nvlist_free(list);
}

void FCSyseventBridge::validateRegistration() {
    Trace log("FCSyseventBridge::validateRegistration");
    uint64_t count = 0;
    count = adapterAddEventListeners.size() +
	    adapterEventListeners.size() +
	    adapterPortEventListeners.size() +
	    targetEventListeners.size();
    if (count == 1) {
	handle = sysevent_bind_handle(static_dispatch);
	if (handle == NULL) {
	    log.genericIOError(
		"Unable to bind sysevent handle.");
	    return;
	}
	const char *subclass_list[9] = {
		"ESC_sunfc_port_attach",
		"ESC_sunfc_port_detach",
		"ESC_sunfc_port_offline",
		"ESC_sunfc_port_online",
		"ESC_sunfc_port_rscn",
		"ESC_sunfc_target_add",
		"ESC_sunfc_target_remove",
		"ESC_sunfc_device_online",
		"ESC_sunfc_device_offline"
	    };
	if (sysevent_subscribe_event(handle,
		"EC_sunfc", (const char **)subclass_list, 9)) {
	    log.genericIOError(
		"Unable to subscribe to sun_fc events.");
	    sysevent_unbind_handle(handle);
	    handle = NULL;
	}
    } else if (count == 0 && handle != NULL) {
	// Remove subscription
	sysevent_unbind_handle(handle);
	handle == NULL;
    } // Else do nothing
}

int32_t FCSyseventBridge::getMaxListener() {
    return (INT_MAX);
}
