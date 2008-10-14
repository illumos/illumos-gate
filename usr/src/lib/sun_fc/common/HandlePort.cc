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



#include "HandlePort.h"
#include "Exceptions.h"
#include "Trace.h"
#include <iostream>
#include <iomanip>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>


using namespace std;

/**
 * @memo	    Construct a new HandlePort for state tracking
 * @precondition    Handle must be open
 * @param	    myHandle The open handle for this HBA
 * @param	    myHBA The HBA for this port
 * @param	    myPort The HBA Port to open
 */
HandlePort::HandlePort(Handle *myHandle, HBA *myHBA, HBAPort *myPort) :
	handle(myHandle), hba(myHBA), port(myPort), active(false) {
	Trace log("HandlePort::HandlePort");
}

/**
 * @memo	    Reset the state tracking values for stale index detection
 * @postcondition   The first subsequent call to any index based routine
 *		    will always succed. 
 */
void HandlePort::refresh() {
	Trace log("HandlePort::refresh");
	lock();
	active = false;
	unlock();
}

/**
 * @memo	    Validate the current state of the handle port
 * @exception	    StaleDataException Thrown if the state has changed
 * @param	    newState The new state of the port
 * 
 * @doc		    After opening a port or refreshing, no state is tracked.
 *		    The first time validate is called, the state is recorded.
 *		    Subsequent calls will verify that the state is the same.
 *		    If the state has changed, the exception will be thrown.
 */
void HandlePort::validate(uint64_t newState) {
	Trace log("HandlePort::validate");
	log.debug("Port %016llx state %016llx", port->getPortWWN(), newState);
	lock();
	if (active) {
	    if (lastState != newState) {
		unlock();
		throw StaleDataException();
	    }
	} else {
	    active = true;
	    lastState = newState;
	}
	unlock();
}

/**
 * @memo	    Verify this port has the stated port wwn
 * @return	    TRUE if the argument matches this port
 * @return	    FALSE if the argument does not match this port
 * @param	    portWWN The Port WWN to compare against this port
 */
bool HandlePort::match(uint64_t portWWN) {
	Trace log("HandlePort::match(wwn)");
	bool ret = false;
	ret = (portWWN == port->getPortWWN());
	return (ret);
}

/**
 * @memo	    Verify this port is the stated index
 * @return	    TRUE if the argument matches this port
 * @return	    FALSE if the argument does not match this port
 * @param	    index The index value to compare against this port
 */
bool HandlePort::match(int index) {
	Trace log("HandlePort::match(index)");
	return (*port == *(hba->getPortByIndex(index)));
}

/**
 * @memo	    Get attributes from a discovered port.
 * @exception	    ... underlying exceptions will be thrown
 * @return	    The discovered port attributes
 * @param	    wwn The node or port wwn of the discovered port
 * 
 * @doc		    This routine will not perform any state validation
 */
HBA_PORTATTRIBUTES HandlePort::getDiscoveredAttributes(uint64_t wwn) {
	Trace log("HandlePort::getDiscoveredAttributes(wwn)");
	uint64_t newState;
	HBA_PORTATTRIBUTES attributes = port->getDiscoveredAttributes(
		wwn, newState);
	// We don't validate when a WWN was used
	return (attributes);
}

/**
 * @memo	    Get attributes from this port.
 * @exception	    ... underlying exceptions will be thrown
 * @return	    The port attributes
 * @see		    HandlePort::validate
 * 
 * @doc		    This routine will perform state validation
 */
HBA_PORTATTRIBUTES HandlePort::getPortAttributes() {
	Trace log("HandlePort::getPortAttributes");
	uint64_t newState;
	HBA_PORTATTRIBUTES attributes = port->getPortAttributes(newState);
	validate(newState);
	return (attributes);
}

/**
 * @memo	    Get attributes from a discovered port.
 * @exception	    ... underlying exceptions will be thrown
 * @return	    The discovered port attributes
 * @param	    discoveredport The index of the discovered port
 * @see		    HandlePort::validate
 * 
 * @doc		    This routine will perform state validation
 */
HBA_PORTATTRIBUTES
HandlePort::getDiscoveredAttributes(HBA_UINT32 discoveredport) {
	Trace log("HandlePort::getDiscoveredAttributes(index)");
	uint64_t newState;
	HBA_PORTATTRIBUTES attributes = port->getDiscoveredAttributes(
		discoveredport, newState);
	validate(newState);
	return (attributes);
}

HBA_PORTNPIVATTRIBUTES HandlePort::getPortNPIVAttributes() {
	Trace log("HandlePort::getPortNPIVAttributes");
	uint64_t newState;
	HBA_PORTNPIVATTRIBUTES attributes = port->getPortNPIVAttributes(newState);
	validate(newState);
	return (attributes);
}

uint32_t HandlePort::deleteNPIVPort(uint64_t vportwwn) {
	Trace log("HandlePort::deleteNPIVPort");
	uint32_t ret = port->deleteNPIVPort(vportwwn);

	return (ret);
}

uint32_t HandlePort::createNPIVPort(uint64_t vnodewwn,
    uint64_t vportwwn, uint32_t vindex) {
	Trace log("HandlePort::createNPIVPort");
	uint32_t vportindex;

	vportindex = port->createNPIVPort(vnodewwn, vportwwn, vindex);
	return (vportindex);
}

HandleNPIVPort* HandlePort::getHandleNPIVPortByIndex(int index) {
	Trace log("HandlePort::getHandleNPIVPortByIndex(int index)");

	HBANPIVPort* vport = port->getPortByIndex(index);
	return (getHandleNPIVPort(vport->getPortWWN()));
}

HandleNPIVPort* HandlePort::getHandleNPIVPort(uint64_t wwn) {
	Trace log("HandlePort::getHandleNPIVPort");
	lock();
	try {
		// Check to see if the wwn is in the map
		if (npivportHandles.find(wwn) == npivportHandles.end()) {
			// Not found, add a new one
			HBANPIVPort* vport = port->getPort(wwn);
			npivportHandles[wwn] = new HandleNPIVPort(handle, this, hba, port, vport);
		}
		HandleNPIVPort *npivportHandle = npivportHandles[wwn];
		unlock();
		return (npivportHandle);
	} catch (...) {
		unlock();
		throw;
	}
}

