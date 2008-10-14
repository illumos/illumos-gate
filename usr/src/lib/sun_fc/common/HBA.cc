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



#include "HBA.h"
#include "Exceptions.h"
#include "Trace.h"
#include <iostream>
#include <iomanip>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <errno.h>

#define	    NSECS_PER_SEC	1000000000l
#define	    BUSY_SLEEP		NSECS_PER_SEC/10 /* 1/10 second */
#define	    BUSY_RETRY_TIMER	3000000000UL /* Retry for 3 seconds */

using namespace std;

/**
 * Max number of Adatper ports per HBA that VSL supports.
 *
 */
const uint8_t HBA::HBA_PORT_MAX = UCHAR_MAX;

/**
 * @memo	    Add a new port to this HBA
 * @precondition    Port must be a valid port on this HBA
 * @postcondition   Port will be exposed as one of the ports on this HBA
 * @exception	    Throws InternalError when the HBA port count exceeds
 *		    max number of ports and throws any underlying exception
 * @param	    port The Port to add to this HBA
 *
 * @doc		    When discovering HBAs and their ports, use this
 *		    routine to add a port to its existing HBA instance.
 */
void HBA::addPort(HBAPort* port) {
	Trace log("HBA::addPort");
	lock();
	// support hba with up to UCHAR_MAX number of ports.
	if (portsByIndex.size() + 1 > HBA_PORT_MAX) {
	    unlock();
	    throw InternalError("HBA Port count exceeds max number of ports");
	}

	try {
	    portsByWWN[port->getPortWWN()] = port;
	    portsByIndex.insert(portsByIndex.end(), port);
	    unlock();
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Return number of ports to this HBA
 * @exception	    No exception for this method.
 *
 * @doc		    Returns the number of ports on this HBA. The max
 *		    number of ports that VSL support is up to max uint8_t
 *		    size.
 */
uint8_t HBA::getNumberOfPorts() {
	Trace log("HBA::getNumberOfPorts");
	return (uint8_t)portsByIndex.size();
}

/**
 * @memo	    Retrieve an HBA port based on a Port WWN
 * @exception	    IllegalWWNException Thrown if WWN does not match any
 *		    known HBA port.
 * @return	    HBAPort* to the port with a matching Port WWN
 * @param	    wwn The wwn of the desired HBA port
 *
 * @doc		    Fetch an HBA port based on WWN.  If the port is not
 *		    found, an exception will be thrown.  NULL will never
 *		    be returned.
 */
HBAPort* HBA::getPort(uint64_t wwn) {
	Trace log("HBA::getPort");
	HBAPort *port = NULL;
	lock();

	log.debug("getPort(wwn): WWN %016llx", wwn);

	try {
	    // Make sure it is in the map
	    if (portsByWWN.find(wwn) == portsByWWN.end()) {
		throw IllegalWWNException();
	    }
	    port = portsByWWN[wwn];
	    unlock();
	    return (port);
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * Iterator for WWN to HBAPort map type
 */
typedef map<uint64_t, HBAPort *>::const_iterator CI;

/**
 * @memo	    Return true if this HBA contains the stated WWN
 *		    (node or port)
 * @exception	    ... underlying exceptions will be thrown
 * @return	    TRUE if the wwn is found
 * @return	    FALSE if the wwn is not found
 * @param	    wwn The wwn to look for
 *
 */
bool HBA::containsWWN(uint64_t wwn) {
	Trace log("HBA::containsWWN");
	lock();

	try {
	    for (CI port = portsByWWN.begin(); port != portsByWWN.end();
		    port++) {
		if (port->second->getPortWWN() == wwn) {
		    unlock();
		    return (true);
		}
		if (port->second->getNodeWWN() == wwn) {
		    unlock();
		    return (true);
		}
	    }
	    unlock();
	    return (false);
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Fetch the port based on index.
 * @exception	    IllegalIndexException Thrown if the index is not valid
 * @return	    HBAPort* the port matching the index
 * @param	    index - the zero based index of the port to retrieve
 *
 */
HBAPort* HBA::getPortByIndex(int index) {
	Trace log("HBA::getPortByIndex");
	lock();
	try {
	    log.debug("Port index size %d index %d ", portsByIndex.size(),
		    index);

	    if (index >= portsByIndex.size() || index < 0) {
		throw IllegalIndexException();
	    }

	    HBAPort *tmp = portsByIndex[index];
	    unlock();
	    return (tmp);
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Compare two HBAs for equality
 * @precondition    Both HBAs should be fully discovered (all ports added)
 * @exception	    ... underlying exceptions will be thrown
 * @return	    TRUE The two HBA instances represent the same HBA
 * @return	    FALSE The two HBA instances are different
 *
 * @doc		    This routine will compare each port within both
 *		    HBAs and verify they are the same.  The ports must
 *		    have been added in the same order.
 */
bool HBA::operator==(HBA &comp) {
	Trace log("HBA::operator==");
	lock();

	try {
	    bool ret = false;
	    if (portsByIndex.size() == comp.portsByIndex.size()) {
		if (portsByIndex.size() > 0) {
		    ret = (*portsByIndex[0] == *comp.portsByIndex[0]);
		}
	    }
	    unlock();
	    return (ret);
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Set the RNID data for all the ports in this HBA
 * @precondition    All ports must be added
 * @postcondition   Each port will have the same RNID value set
 * @exception	    ... underlying exceptions will be thrown.  Partial failure
 *		    is possible and will not be cleaned up.
 * @param	    info The RNID information to program for each HBA port
 * @see		    HBAPort::setRNID
 *
 */
void HBA::setRNID(HBA_MGMTINFO info) {
	Trace log("HBA::setRNID");
	lock();

	try {
	    for (CI port = portsByWWN.begin(); port != portsByWWN.end();
		    port++) {
		port->second->setRNID(info);
	    }
	    unlock();
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * @memo	    Verify that this HBA is present on the system
 * @exception	    UnavailableException Thrown when HBA not present
 * @see		    HBAPort::validatePresent
 *
 * @doc		    This routine is used to verify that a given HBA
 *		    has not been removed through dynamic reconfiguration.
 *		    If the HBA is present, the routine will return.
 *		    If the HBA is not present (if any port is not present)
 *		    an exception will be thrown
 */
void HBA::validatePresent() {
	Trace log("HBA::validatePresent");
	lock();
	try {
	    for (CI port = portsByWWN.begin(); port != portsByWWN.end();
		    port++) {
		port->second->validatePresent();
	    }
	    unlock();
	} catch (...) {
	    unlock();
	    throw;
	}
}

/**
 * Opens a file, throwing exceptions on error.
 */
int HBA::_open(std::string path, int flag) {
	Trace log("HBA::open");
	int fd;
	errno = 0;
	if ((fd = open(path.c_str(), flag)) < 0) {
	    log.debug("Unable to open \"%s\" - reason (%d) %s",
		path.c_str(), errno, strerror(errno));
	    if (errno == EBUSY) {
		throw BusyException();
	    } else if (errno == EAGAIN) {
		throw TryAgainException();
	    } else if (errno == ENOTSUP) {
		throw NotSupportedException();
	    } else if (errno == ENOENT) {
		throw UnavailableException();
	    } else {
		string msg = "Unable to open ";
		msg += path;
		throw IOError(msg);
	    }
	}
	return (fd);
}

/**
 * Issues IOCTL, throwing exceptions on error.
 * Note, if the IOCTL succeeds, but some IOCTL specific
 * error is recorded in the response, this routine
 * will not throw an exception.
 */
void HBA::_ioctl(int fd, int type, uchar_t *arg) {
	Trace log("HBA::ioctl");
	hrtime_t	    cur;
	int		    saved_errno = 0;
	struct timespec	    ts;

	errno = 0;
	hrtime_t start = gethrtime();
	hrtime_t end = start + BUSY_RETRY_TIMER;
	ts.tv_sec = 0;
	ts.tv_nsec = BUSY_SLEEP;
	for (cur = start; cur < end; cur = gethrtime()) {
		if (ioctl(fd, type, arg) != 0) {
			if (errno == EAGAIN) {
				saved_errno = errno;
				nanosleep(&ts, NULL);
				continue;
			} else if (errno == EBUSY) {
				saved_errno = errno;
				nanosleep(&ts, NULL);
				continue;
			} else if (errno == ENOTSUP) {
				throw NotSupportedException();
			} else if (errno == ENOENT) {
				throw UnavailableException();
			} else {
				throw IOError("IOCTL failed");
			}
		} else {
			break;
		}
	}
	if (cur >= end) {
		if (saved_errno == EAGAIN) {
			throw TryAgainException();
		} else if (saved_errno == EBUSY) {
			throw BusyException();
		} else {
			throw IOError("IOCTL failed");
		}
	}
}

HBA::~HBA() {
	Trace log("HBA::~HBA");
	for (int i = 0; i < getNumberOfPorts(); i++) {
	    delete (getPortByIndex(i));
	}
}

