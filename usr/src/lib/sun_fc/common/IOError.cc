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



#include "Exceptions.h"
#include "Trace.h"
#include "sun_fc.h"
#include <iostream>
#include <iomanip>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <cstring>
#include <cerrno>
using namespace std;

/**
 * @memo	    Log a simple I/O error message
 * @param	    message The message to log
 */
IOError::IOError(string message) : HBAException(HBA_STATUS_ERROR) {
	Trace log("IOError::IOError(string)");
	log.genericIOError("%s (%s)", message.c_str(), strerror(errno));
}

/**
 * @memo	    Log a handle I/O error message
 * @param	    handle The handle where the I/O error took place
 */
IOError::IOError(Handle *handle) : HBAException(HBA_STATUS_ERROR) {
	Trace log("IOError::IOError(Handle)");
	log.genericIOError(
		"On handle %08lx (%s)", handle->getHandle(), strerror(errno));
}

/**
 * @memo	    Log an HBAPort I/O error message
 * @param	    port The port where the I/O error took place
 */
IOError::IOError(HBAPort *port) : HBAException(HBA_STATUS_ERROR) {
	Trace log("IOError::IOError(HBAPort)");
	log.genericIOError(
		"On HBA port %016llx (%s)", port->getPortWWN(),
		strerror(errno));
}

/**
 * @memo	    Log a target I/O error message
 * @param	    port The port where the I/O error took place
 * @param	    target The target wwn which failed
 */
IOError::IOError(HBAPort *port, uint64_t target) :
	    HBAException(HBA_STATUS_ERROR) {
	Trace log("IOError::IOError(HBAPort, wwn)");
	log.genericIOError(
		"On HBA port %016llx target %016llx (%s)", port->getPortWWN(),
		target, strerror(errno));
}

/**
 * @memo	    Log a LUN I/O error message
 * @param	    port The port where the I/O error took place
 * @param	    target The target wwn which failed
 * @param	    lun The unit number which failed
 */
IOError::IOError(HBAPort *port, uint64_t target, uint64_t lun) :
	HBAException(HBA_STATUS_ERROR) {
	Trace log("IOError::IOError(HBAPort, wwn, lun)");
	log.genericIOError(
		"On HBA port %016llx target %016llx lun %016llx (%s)",
		port->getPortWWN(),
		target,
		lun, strerror(errno));
}
