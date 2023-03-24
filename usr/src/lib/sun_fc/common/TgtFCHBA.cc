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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <unistd.h>

#include <TgtFCHBA.h>
#include <Exceptions.h>
#include <Trace.h>
#include <iostream>
#include <iomanip>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/fctio.h>
#include <sys/fibre-channel/impl/fc_error.h>
#include <TgtFCHBAPort.h>
#include <HBAList.h>
#include <sun_fc.h>
#include <cstdlib>

using namespace std;
const string TgtFCHBA::FCT_DRIVER_PATH = "/devices/pseudo/fct@0:admin";
const string TgtFCHBA::FCT_ADAPTER_NAME_PREFIX = "/devices/pseudo/fct@0";
const string TgtFCHBA::FCT_DRIVER_PKG	= "SUNWfct";
const int TgtFCHBA::MAX_FCTIO_MSG_LEN = 256;

TgtFCHBA::TgtFCHBA(string path) : HBA()
{
    Trace log("TgtFCHBA::TgtFCHBA");
    log.debug("Constructing new Target mode HBA (%s)", path.c_str());

    // Add a target FCHBA port. With fct driver architecuture, all target mode
    // FCHBA will have a single port regardless of the multiport support on
    // FCA layer.
    addPort(new TgtFCHBAPort(path));
    name = "INTERNAL-FAILURE"; // Just in case things go wrong
    try {
	    HBA_ADAPTERATTRIBUTES attrs = getHBAAttributes();
	    name = attrs.Manufacturer;
	    name += "-";
	    name += attrs.Model;
	    name += "-Tgt";

    } catch (HBAException &e) {
	    log.debug(
		"Failed to get HBA attribute for %s", path.c_str());
	    throw e;
    }
}

std::string TgtFCHBA::getName()
{
    Trace log("TgtFCHBA::getName");
    return (name);
}

HBA_ADAPTERATTRIBUTES TgtFCHBA::getHBAAttributes()
{
    Trace log("TgtFCHBA::getHBAAttributes");
    int fd;

    errno = 0;
    HBAPort *port = getPortByIndex(0);

    HBA_ADAPTERATTRIBUTES attributes;
    fctio_t			    fctio;
    fc_tgt_hba_adapter_attributes_t	    attrs;
    uint64_t	portwwn;

    if ((fd = open(FCT_DRIVER_PATH.c_str(), O_NDELAY | O_RDONLY)) == -1) {
	// Why did we fail?
	if (errno == EBUSY) {
	    throw BusyException();
	} else if (errno == EAGAIN) {
	    throw TryAgainException();
	} else if (errno == ENOTSUP) {
	    throw NotSupportedException();
	} else {
	    throw IOError(port);
	}
    }

    try {
	    std::string path = port->getPath();
	    string::size_type offset = path.find_last_of(".");
	    if (offset >= 0) {
		string portwwnString = path.substr(offset+1);
		portwwn = strtoull(portwwnString.c_str(), NULL, 16);
	    }
    } catch (...) {
	    throw BadArgumentException();
    }

    uint64_t en_wwn = htonll(portwwn);

    memset(&fctio, 0, sizeof (fctio));
    fctio.fctio_cmd = FCTIO_GET_ADAPTER_ATTRIBUTES;
    fctio.fctio_olen = (uint32_t)(sizeof (attrs));
    fctio.fctio_xfer = FCTIO_XFER_READ;
    fctio.fctio_obuf = (uint64_t)(uintptr_t)&attrs;
    fctio.fctio_ilen = 8;
    fctio.fctio_ibuf = (uint64_t)(uintptr_t)&en_wwn;

    errno = 0;
    if (ioctl(fd, FCTIO_CMD, &fctio) != 0) {
	close(fd);
	if (errno == EBUSY) {
	    throw BusyException();
	} else if (errno == EAGAIN) {
	    throw TryAgainException();
	} else if (errno == ENOTSUP) {
	    throw NotSupportedException();
	} else {
	    throw IOError("Unable to fetch adapter attributes");
	}
    }
    close(fd);

    /* Now copy over the payload */
    attributes.NumberOfPorts = attrs.NumberOfPorts;
    attributes.VendorSpecificID = attrs.VendorSpecificID;
    memcpy(attributes.Manufacturer, attrs.Manufacturer, 64);
    memcpy(attributes.SerialNumber, attrs.SerialNumber, 64);
    memcpy(attributes.Model, attrs.Model, 256);
    memcpy(attributes.ModelDescription, attrs.ModelDescription, 256);
    memcpy(attributes.NodeSymbolicName, attrs.NodeSymbolicName, 256);
    memcpy(attributes.HardwareVersion, attrs.HardwareVersion, 256);
    memcpy(attributes.DriverVersion, attrs.DriverVersion, 256);
    memcpy(attributes.OptionROMVersion, attrs.OptionROMVersion, 256);
    memcpy(attributes.FirmwareVersion, attrs.FirmwareVersion, 256);
    memcpy(attributes.DriverName, attrs.DriverName, 256);
    memcpy(&attributes.NodeWWN, &attrs.NodeWWN, 8);

    return (attributes);
}

int TgtFCHBA::doForceLip()
{
    Trace	 log("TgtFCHBA::doForceLip");
    int		 fd;
    HBAPort	*port = getPortByIndex(0);
    fctio_t	 fctio;
    uint64_t	 portwwn;

    errno = 0;
    if ((fd = open(FCT_DRIVER_PATH.c_str(), O_NDELAY | O_RDONLY)) == -1) {
	if (errno == EBUSY) {
	    throw BusyException();
	} else if (errno == EAGAIN) {
	    throw TryAgainException();
	} else if (errno == ENOTSUP) {
	    throw NotSupportedException();
	} else {
	    throw IOError(port);
	}
    }

    try {
	    std::string path = port->getPath();
	    string::size_type offset = path.find_last_of(".");
	    if (offset >= 0) {
		string portwwnString = path.substr(offset+1);
		portwwn = strtoull(portwwnString.c_str(), NULL, 16);
	    }
    } catch (...) {
	    throw BadArgumentException();
    }

    uint64_t en_wwn = htonll(portwwn);
    memset(&fctio, 0, sizeof (fctio));
    fctio.fctio_cmd = FCTIO_FORCE_LIP;
    fctio.fctio_xfer = FCTIO_XFER_READ;
    fctio.fctio_ilen = 8;
    fctio.fctio_ibuf = (uint64_t)(uintptr_t)&en_wwn;

    errno = 0;
    if (ioctl(fd, FCTIO_CMD, &fctio) != 0) {
	close(fd);
	if (errno == EBUSY) {
	    throw BusyException();
	} else if (errno == EAGAIN) {
	    throw TryAgainException();
	} else if (errno == ENOTSUP) {
	    throw NotSupportedException();
	} else {
	    throw IOError("Unable to reinitialize the link");
	}
    } else {
	close(fd);
	return ((int)fctio.fctio_errno);
    }
}

void TgtFCHBA::loadAdapters(vector<HBA*> &list)
{
    Trace log("TgtFCHBA::loadAdapters");
    fctio_t			fctio;
    fc_tgt_hba_list_t		*tgthbaList;
    int			fd;
    int			size = 64; // default first attempt
    bool		retry = false;
    struct stat		sb;
    int bufSize;
    char wwnStr[17];

    /* Before we do anything, let's see if FCT is on the system */
    errno = 0;
    if (stat(FCT_DRIVER_PATH.c_str(), &sb) != 0) {
	if (errno == ENOENT) {
	    log.genericIOError(
		"The %s driver is not present."
                " Please install the %s package.",
		FCT_DRIVER_PATH.c_str(), FCT_DRIVER_PKG.c_str());
	    throw NotSupportedException();
	} else {
	    log.genericIOError(
		"Can not stat the %s driver for reason \"%s\" "
		"Unable to get target mode FC adapters.",
		FCT_DRIVER_PATH.c_str(), strerror(errno));
	    throw IOError("Unable to stat FCSM driver");
	}
    }


    /* construct fcio struct */
    memset(&fctio, 0, sizeof (fctio_t));
    fctio.fctio_cmd	= FCTIO_ADAPTER_LIST;
    fctio.fctio_xfer	= FCTIO_XFER_RW;

    /* open the fcsm node so we can send the ioctl to */
    errno = 0;
    if ((fd = open(FCT_DRIVER_PATH.c_str(), O_RDONLY)) < 0) {
	if (errno == EBUSY) {
	    throw BusyException();
	} else if (errno == EAGAIN) {
	    throw TryAgainException();
	} else if (errno == ENOTSUP) {
	    throw NotSupportedException();
	} else if (errno == ENOENT) {
	    throw UnavailableException();
	} else {
	    throw IOError("Unable to open FCT driver");
	}
    }

    do {
	retry = false;
	errno = 0;
	bufSize = 8 * (size - 1) + (int) sizeof (fc_tgt_hba_list_t);
	tgthbaList = (fc_tgt_hba_list_t *)new uchar_t[bufSize];
	tgthbaList->numPorts = size;
	fctio.fctio_olen	= bufSize;
	fctio.fctio_obuf	= (uint64_t)(uintptr_t)tgthbaList;
	if (ioctl(fd, FCTIO_CMD, &fctio) != 0) {
	    /* Interpret the fcio error code */
	    char fcioErrorString[MAX_FCTIO_MSG_LEN] = "";

	    log.genericIOError(
		"TGT_ADAPTER_LIST failed: "
		"Errno: \"%s\"",
		strerror(errno));
	    delete[] (tgthbaList);
	    close(fd);
	    if (errno == EBUSY) {
		throw BusyException();
	    } else if (errno == EAGAIN) {
		throw TryAgainException();
	    } else if (errno == ENOTSUP) {
		throw NotSupportedException();
	    } else if (errno == ENOENT) {
		throw UnavailableException();
	    } else {
		throw IOError("Unable to build HBA list");
	    }
	}
	if (tgthbaList->numPorts > size) {
	    log.debug(
		"Buffer too small for number of target mode HBAs. Retrying.");
	    size = tgthbaList->numPorts;
	    retry = true;
	    delete[] (tgthbaList);
	}
    } while (retry);

    close(fd);
    log.debug("Detected %d target mode adapters", tgthbaList->numPorts);
    for (int i = 0; i < tgthbaList->numPorts; i++) {
	try {
	    std::string hbapath = FCT_ADAPTER_NAME_PREFIX.c_str();
	    hbapath += ".";
	    // move the row with two dimentional uint8 array for WWN
	    uint64_t tmp = ntohll(*((uint64_t *)&tgthbaList->port_wwn[i][0]));
	    sprintf(wwnStr, "%llx", tmp);
	    hbapath += wwnStr;

	    HBA *hba = new TgtFCHBA(hbapath);
	    list.insert(list.begin(), hba);
	} catch (...) {
	    log.debug(
		"Ignoring partial failure while loading an HBA");
	}
    }
    if (tgthbaList->numPorts > HBAList::HBA_MAX_PER_LIST) {
	delete[](tgthbaList);
	throw InternalError(
	    "Exceeds max number of adapters that VSL supports.");
    }
    delete[] (tgthbaList);
}
