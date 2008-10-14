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



#include "Handle.h"
#include "Exceptions.h"
#include "Trace.h"
#include <libdevinfo.h>
#include <iostream>
#include <iomanip>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>

#define	MAX_INIT_HANDLE_ID	0x7fff
#define	MAX_TGT_HANDLE_ID	0xffff

using namespace std;

/**
 * Global lock for list of Handles
 */
pthread_mutex_t Handle::staticLock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Tracking for the previous handle we have opened
 */
HBA_HANDLE Handle::prevOpen = 0;

/**
 * Tracking for the previous target HBA handle we have opened
 */
HBA_HANDLE Handle::prevTgtOpen = 0x8000;

/**
 * Global map from HBA_HANDLE to Handle pointers (our global list)
 */
map<HBA_HANDLE, Handle*> Handle::openHandles;

/**
 * @memo	    Create a new open handle for a specified HBA
 * @precondition    HBA port(s) must be loaded
 * @postcondition   An open handle will be present in the global tracking list
 *		    and must be closed at some point to prevent leakage. If no
 *		    handle could be assigned (the track list is full), an
 *		    exception will be thrown. Scope for valid ids in the track
 *		    list is [1, MAX_INIT_HANDLE_ID].
 * @param	    myhba The HBA to open a handle for
 */
Handle::Handle(HBA *myhba) {
	map<HBA_HANDLE, Handle*>::iterator mapend;
	Trace log("Handle::Handle");
	modeVal = INITIATOR;
	lock(&staticLock);
	mapend = openHandles.end();
	/* Start the search for a free id from the previously assigned one */
	id = prevOpen + 1;
	while (id != prevOpen) {
		/* Exceeds the max valid value, continue the search from 1 */
		if (id > MAX_INIT_HANDLE_ID)
			id = 1;

		if (openHandles.find(id) == mapend) {
			/* the id is not in use */
			break;
		}
		id ++;
	}
	if (id == prevOpen) {
		/* no usable id for now */
		unlock(&staticLock);
		throw TryAgainException();
	}
	prevOpen = id;
	hba = myhba;
	openHandles[id] = this;
	unlock(&staticLock);
}

/**
 * @memo	    Create a new open handle for a specified HBA
 * @precondition    HBA port(s) must be loaded
 * @postcondition   An open handle will be present in the global tracking list
 *		    and must be closed at some point to prevent leakage. If no
 *		    handle could be assigned (the track list is full), an
 *		    exception will be thrown. Scope for valid ids in the track
 *		    list is [0x8000, MAX_TGT_HANDLE_ID].
 * @param	    myhba The HBA to open a handle for
 *		    m The mode of HBA to open handle for
 */
#if 0
// appears unused
Handle::Handle(HBA *myhba, MODE m) {
	map<HBA_HANDLE, Handle*>::iterator mapend;
	Trace log("Handle::Handle");
	lock(&staticLock);
	modeVal = m;


	// if initiator mode call constructor for initiator.
	if (m == INITIATOR) { 
		Handle(myhba, TARGET);
	}

	mapend = openHandles.end();
	/* Start the search for a free id from the previously assigned one */
	id = prevTgtOpen + 1;
	while (id != prevTgtOpen) {
		/*
		 * Exceeds the max valid target id value,
		 * continue the search from 1.
		 */
		if (id > MAX_TGT_HANDLE_ID)
			id = 0x8001;

		if (openHandles.find(id) == mapend) {
			/* the id is not in use */
			break;
		}
		id ++;
	}
	if (id == prevTgtOpen) {
		/* no usable id for now */
		unlock(&staticLock);
		throw TryAgainException();
	}
	prevTgtOpen = id;
	hba = myhba;
	openHandles[id] = this;
	unlock(&staticLock);
}
#endif
/**
 * @memo	    Free up the handle (aka, close it)
 * @postcondition   This handle will be removed from the global list
 * @exception	    ... underlying exceptions will be thrown
 */
Handle::~Handle() {
	Trace log("Handle::~Handle");
	// Remove this handle from the global list
	lock(&staticLock);
	try {
	    openHandles.erase(openHandles.find(getHandle()));
	    unlock(&staticLock);
	} catch (...) {
	    unlock(&staticLock);
	    throw;
	}

	// Now nuke all internal dynamic allocations
	typedef map<uint64_t, HandlePort *>::const_iterator CI;
	lock();
	try {
	    for (CI port = portHandles.begin(); port != portHandles.end();
		    port++) {
		delete port->second;
	    }
	    portHandles.clear();
	    unlock();
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Locate a handle in the global list of open handles
 * @precondition    The requested handle must already be open
 * @exception	    InvalidHandleException Thrown if the id does not match
 *		    an open handle
 * @return	    The open Handle
 * @param	    id The id of the handle to fetch
 *
 * @doc		    The HBA API uses a simple integer type to represent
 *		    an open Handle, but we use an instance of the Handle
 *		    class.  This interface allows a caller to quickly convert
 *		    from the API integer value to related the Handle instance.
 */
Handle* Handle::findHandle(HBA_HANDLE id) {
	Trace log("Handle::findHandle(id)");
	Handle *tmp = NULL;
	lock(&staticLock);
	try {
	    if (openHandles.find(id) == openHandles.end()) {
		throw InvalidHandleException();
	    }
	    tmp = openHandles[id];
	    unlock(&staticLock);
	    return (tmp);
	} catch (...) {
	    unlock(&staticLock);
	    throw;
	}
}

/**
 * @memo	    Find an open handle based on Node or Port WWN
 * @precondition    The given HBA must already be open
 * @exception	    IllegalWWNException Thrown if no matching open Handle found
 * @return	    The open handle matching the wwn argument
 * @param	    wwn The Node or Port WWN of the HBA whos open handle
 *		    is requested.
 *
 */
Handle* Handle::findHandle(uint64_t wwn) {
	Trace log("Handle::findHandle(wwn)");
	Handle *tmp = NULL;
	lock(&staticLock);
	try {
	    for (int i = 0; i < openHandles.size(); i++) {
		tmp = openHandles[i];
		if (tmp->getHBA()->containsWWN(wwn)) {
		    unlock(&staticLock);
		    return (tmp);
		}
	    }
	    tmp = NULL;
	} catch (...) { tmp = NULL; }
	unlock(&staticLock);
	if (tmp == NULL) {
	    throw IllegalWWNException();
	}
	return (tmp);
}

/**
 * @memo	    Refresh underlying index values
 * @postcondition   All HandlePorts will be reset and prior index values
 *		    will be undefined.
 * @exception	    ... underlying exceptions will be thrown
 *
 * @doc		    A number of APIs in the standard interface require
 *		    the use of index values for identifying what "thing"
 *		    to operate on.  When dynamic reconfiguration occurs
 *		    these indexes may become inconsistent.  This routine
 *		    is called to reset the indexes and signify that the caller
 *		    no longer holds or will refer to any old indexes.
 */
void Handle::refresh() {
	Trace log("Handle::refresh");
	lock();
	try {
	    typedef map<uint64_t, HandlePort *>::const_iterator CI;
	    for (CI port = portHandles.begin(); port != portHandles.end();
		    port++) {
		port->second->refresh();
	    }
	    unlock();
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Close the specified handle
 * @precondition    The handle must be open
 * @postcondition   The handle will be closed and should be discarded.
 * @param	    id The handle to close
 */
void Handle::closeHandle(HBA_HANDLE id) {
	Trace log("Handle::closeHandle");
	Handle *myHandle = findHandle(id);
	delete myHandle;
}

/**
 * @memo	    Get the integer value for return to the API
 * @exception	    ... underlying exceptions will be thrown
 * @return	    The integer value representing the handle
 *
 * @doc		    The HBA API uses integer values to represent handles.
 *		    Call this routine to convert a Handle instance into
 *		    its representative integer value.
 */
HBA_HANDLE Handle::getHandle() {
	Trace log("Handle::getHandle");
	HBA_HANDLE tmp;
	lock();
	try {
	    tmp = (HBA_HANDLE) id;
	    unlock();
	    return (tmp);
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Compare two handles for equality
 * @return	    TRUE if the handles are the same
 * @return	    FALSE if the handles are different
 */
bool Handle::operator==(Handle comp) {
	Trace log("Handle::operator==");
	return (this->id == comp.id);
}

/**
 * @memo	    Get the underlying Handle port based on index
 * @return	    The Handle port for the given port index
 * @param	    index The index of the desired port
 */
HandlePort* Handle::getHandlePortByIndex(int index) {
	Trace log("Handle::getHandlePortByIndex");
	HBAPort* port = hba->getPortByIndex(index);
	return (getHandlePort(port->getPortWWN()));
}

/**
 * @memo	    Get the underlying Handle port based on Port wwn
 * @exception	    IllegalWWNException thrown if the wwn is not found
 * @return	    The handle port for the specified WWN
 * @param	    wwn The Port WWN of the HBA port
 *
 */
HandlePort* Handle::getHandlePort(uint64_t wwn) {
	Trace log("Handle::getHandlePort");
	lock();
	try {
	    // Check to see if the wwn is in the map
	    if (portHandles.find(wwn) == portHandles.end()) {
		// Not found, add a new one
		HBAPort* port = hba->getPort(wwn);
		portHandles[wwn] = new HandlePort(this, hba, port);
	    }
	    HandlePort *portHandle = portHandles[wwn];
	    unlock();
	    return (portHandle);
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Get the HBA attributes from the underlying HBA
 *
 * @see		    HBA::getHBAAttributes
 */
HBA_ADAPTERATTRIBUTES Handle::getHBAAttributes() {
	Trace log("Handle::getHBAAttributes");
	lock();
	try {
	    HBA_ADAPTERATTRIBUTES attributes = hba->getHBAAttributes();
	    unlock();
	    return (attributes);
	} catch (...) {
	    unlock();
	    throw;
	}
}

HBA_ADAPTERATTRIBUTES Handle::npivGetHBAAttributes() {
	Trace log("Handle::npivGetHBAAttributes");
	lock();
	try {
		HBA_ADAPTERATTRIBUTES attributes = hba->npivGetHBAAttributes();
		unlock();
		return (attributes);
	} catch (...) {
		unlock();
		throw;
	}
}


/**
 * @memo	    Get the HBA port attributes from the HBA
 * @see		    HBAPort::getPortAttributes
 * @see		    HBAPort::getDisoveredAttributes
 *
 * @doc		    This routine will return either HBA port
 *		    attributes, or discovered port attributes
 *
 */
HBA_PORTATTRIBUTES Handle::getPortAttributes(uint64_t wwn) {
	Trace log("Handle::getPortAttributes");
	uint64_t tmp;
	HBA_PORTATTRIBUTES attributes;

	lock();
	try {
	    // Is this a WWN for one of the adapter ports?
	    if (hba->containsWWN(wwn)) {
		attributes = hba->getPort(wwn)->getPortAttributes(tmp);
		unlock();
		return (attributes);
	    } else { // Is this a target we know about?
		// Loop through all ports and look for the first match

		for (int i = 0; i < hba->getNumberOfPorts(); i++) {
		    try {
			attributes =
			    hba->getPortByIndex(i)->getDiscoveredAttributes(
			    wwn, tmp);
			unlock();
			return (attributes);
		    } catch (HBAException &e) {
			continue;
		    }
		}

		// If we get to here, then we don't see this WWN on this HBA
		throw IllegalWWNException();
	    }
	} catch (...) {
	    unlock();
	    throw;
	}
}
