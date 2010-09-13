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



#include "HandleNPIVPort.h"
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
 * @memo            Construct a new HandleNPIVPort for state tracking
 * @precondition    Handle must be open
 * @param           myHandle The open handle for this HBA
 * @param           myHandlePort The open handle for this HBA Port
 * @param           myHBA The HBA for this port
 * @param           myPort The HBA Port for this npiv port
 * @param           myvPort The NPIV port to open
 * @version         1.2
 */
HandleNPIVPort::HandleNPIVPort(Handle *myHandle, HandlePort *myHandlePort,
    HBA *myHBA, HBAPort *myPort, HBANPIVPort *myvPort) :
    handle(myHandle), handleport(myHandlePort), hba(myHBA),
    port(myPort), active(false), vport(myvPort) {
	Trace log("HandleNPIVPort::HandleNPIVPort");
}

/**
 * @memo            Reset the state tracking values for stale index detection
 * @postcondition   The first subsequent call to any index based routine
 *                  will always succed.
 * @version         1.2
 */
void HandleNPIVPort::refresh() {
	Trace log("HandleNPIVPort::refresh");
	lock();
	active = false;
	unlock();
}

/**
 * @memo            Validate the current state of the handle port
 * @exception       StaleDataException Thrown if the state has changed
 * @param           newState The new state of the port
 * @version         1.2
 *
 * @doc             After opening a port or refreshing, no state is tracked.
 *                  The first time validate is called, the state is recorded.
 *                  Subsequent calls will verify that the state is the same.
 *                  If the state has changed, the exception will be thrown.
 */
void HandleNPIVPort::validate(uint64_t newState) {
	Trace log("HandleNPIVPort::validate");
	log.debug("Port %016llx state %016llx",
	    vport->getPortWWN(), newState);
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
 * @memo            Verify this port has the stated port wwn
 * @return          TRUE if the argument matches this port
 * @return          FALSE if the argument does not match this port
 * @param           portWWN The Port WWN to compare against this port
 * @version         1.2
 */
bool HandleNPIVPort::match(uint64_t portWWN) {
	Trace log("HandleNPIVPort::match(wwn)");
	bool ret = false;
	ret = (portWWN == vport->getPortWWN());
	return (ret);
}

/**
 * @memo            Verify this port is the stated index
 * @return          TRUE if the argument matches this port
 * @return          FALSE if the argument does not match this port
 * @param           index The index value to compare against this port
 * @version         1.2
 */
bool HandleNPIVPort::match(int index) {
	Trace log("HandleNPIVPort::match(index)");
	return (*vport == *(port->getPortByIndex(index)));
}

/**
 * @memo            Get attributes from this port.
 * @exception       ... underlying exceptions will be thrown
 * @return          The port attributes
 * @version         1.2
 * @see             HandlePort::validate
 *
 * @doc             This routine will perform state validation
 */
HBA_NPIVATTRIBUTES HandleNPIVPort::getPortAttributes() {
	Trace log("HandleNPIVPort::getPortAttributes");
	uint64_t newState;
	HBA_NPIVATTRIBUTES attributes = vport->getPortAttributes(newState);
	validate(newState);
	return (attributes);
}

