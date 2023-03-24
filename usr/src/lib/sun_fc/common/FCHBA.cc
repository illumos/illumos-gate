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

#include <FCHBA.h>
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
#include <sys/fibre-channel/fcio.h>
#include <sys/fibre-channel/ulp/fcsm.h>
#include <FCHBAPort.h>
#include <HBAList.h>

#define EXCPT_RETRY_COUNT    10

using namespace std;
const string FCHBA::FCSM_DRIVER_PATH = "/devices/pseudo/fcsm@0:fcsm";
const string FCHBA::FCSM_DRIVER_PKG	= "SUNWfcsm";
const int FCHBA::MAX_FCIO_MSG_LEN = 256;

FCHBA::FCHBA(string path) : HBA() {
    Trace log("FCHBA::FCHBA");
    log.debug("Constructing new HBA (%s)", path.c_str());

    // Add first port
    addPort(new FCHBAPort(path));

    name = "INTERNAL-FAILURE"; // Just in case things go wrong
    try {
	HBA_ADAPTERATTRIBUTES attrs = getHBAAttributes();
	name = attrs.Manufacturer;
	name += "-";
	name += attrs.Model;

	// Grab any other ports on this adapter
	for (int i = 1; i < attrs.NumberOfPorts; i++) {
	    fcio_t			fcio;
	    int			fd;
	    char		nextPath[MAXPATHLEN];

	    log.debug("Fetching other port %d", i);

	    // construct fcio struct
	    memset(&fcio, 0, sizeof (fcio_t));
	    memset(nextPath, 0, sizeof (nextPath));
	    fcio.fcio_cmd	= FCIO_GET_OTHER_ADAPTER_PORTS;
	    fcio.fcio_xfer	= FCIO_XFER_RW;

	    fcio.fcio_olen	= MAXPATHLEN;
	    fcio.fcio_obuf	= (char *)nextPath;
	    fcio.fcio_ilen	= sizeof (i);
	    fcio.fcio_ibuf	= (char *)&i;

	    // open the fcsm node so we can send the ioctl to
	    errno = 0;
	    HBAPort *port = getPortByIndex(0);
	    if ((fd = open(port->getPath().c_str(), O_NDELAY | O_RDONLY)) ==
		    -1) {
		log.debug("Unable to open %d opened (%s)", i,
		port->getPath().c_str());
		if (errno == EBUSY) {
		    throw BusyException();
		} else if (errno == EAGAIN) {
		    throw TryAgainException();
		} else if (errno == ENOTSUP) {
		    throw NotSupportedException();
		} else if (errno == ENOENT) {
		    throw UnavailableException();
		} else {
		    throw IOError("Unable to open FCSM driver");
		}
	    }
	    log.debug("Other port %d opened", i);

	    errno = 0;
	    if (ioctl(fd, FCIO_CMD, &fcio) != 0) {
		// Interpret the fcio error code
		char fcioErrorString[MAX_FCIO_MSG_LEN] = "";

		log.genericIOError(
		    "ADAPTER_LIST failed: "
		    "Errno: \"%s\"",
		    strerror(errno));
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
	    close(fd);
	    log.debug("About to add port %d (%s)", i, nextPath);
	    addPort(new FCHBAPort(nextPath));
	}
    } catch (BusyException &e) {
        throw e;
    } catch (TryAgainException &e) {
	throw e;
    } catch (UnavailableException &e) {
	throw e;
    } catch (HBAException &e) {
	log.internalError(
		"Unable to construct HBA.");
	throw e;
    }
}

std::string FCHBA::getName() {
    Trace log("FCHBA::getName");
    return (name);
}

HBA_ADAPTERATTRIBUTES FCHBA::getHBAAttributes() {
    Trace log("FCHBA::getHBAAttributes");
    int fd;

    errno = 0;
    HBAPort *port = getPortByIndex(0);
    if ((fd = open(port->getPath().c_str(), O_NDELAY | O_RDONLY)) == -1) {
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

    HBA_ADAPTERATTRIBUTES attributes;
    fcio_t			    fcio;
    fc_hba_adapter_attributes_t	    attrs;

    memset(&fcio, 0, sizeof (fcio));

    fcio.fcio_cmd = FCIO_GET_ADAPTER_ATTRIBUTES;
    fcio.fcio_olen = sizeof (attrs);
    fcio.fcio_xfer = FCIO_XFER_READ;
    fcio.fcio_obuf = (caddr_t)&attrs;


    errno = 0;
    if (ioctl(fd, FCIO_CMD, &fcio) != 0) {
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

int FCHBA::doForceLip() {
    Trace	 log("FCHBA::doForceLip");
    int		 fd;
    fcio_t	 fcio;
    uint64_t	 wwn  = 0;
    HBAPort	*port = getPortByIndex(0);

    errno = 0;
    if ((fd = open(port->getPath().c_str(), O_RDONLY | O_EXCL)) == -1) {
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

    memset(&fcio, 0, sizeof (fcio));
    fcio.fcio_cmd = FCIO_RESET_LINK;
    fcio.fcio_xfer = FCIO_XFER_WRITE;
    fcio.fcio_ilen = sizeof (wwn);
    fcio.fcio_ibuf = (caddr_t)&wwn;

    errno = 0;
    if (ioctl(fd, FCIO_CMD, &fcio) != 0) {
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
	return (fcio.fcio_errno);
    }
}

HBA_ADAPTERATTRIBUTES FCHBA::npivGetHBAAttributes() {
	Trace log("FCHBA::npivGetHBAAttributes");
	int fd;

	errno = 0;
	HBAPort *port = getPortByIndex(0);
	if ((fd = open(port->getPath().c_str(), O_NDELAY | O_RDONLY)) == -1) {
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

	HBA_ADAPTERATTRIBUTES attributes;
	fcio_t fcio;
	fc_hba_adapter_attributes_t attrs;

	memset(&fcio, 0, sizeof (fcio));
	fcio.fcio_cmd = FCIO_NPIV_GET_ADAPTER_ATTRIBUTES;
	fcio.fcio_olen = sizeof (attrs);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)&attrs;
	errno = 0;

	if (ioctl(fd, FCIO_CMD, &fcio) != 0) {
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

void FCHBA::loadAdapters(vector<HBA*> &list) {
    Trace log("FCHBA::loadAdapters");
    fcio_t			fcio;
    fc_hba_list_t		*pathList;
    int			fd;
    int			size = 64; // default first attempt
    bool		retry = false;
    struct stat		sb;
    int bufSize;

    /* Before we do anything, let's see if FCSM is on the system */
    errno = 0;
    if (stat(FCSM_DRIVER_PATH.c_str(), &sb) != 0) {
	if (errno == ENOENT) {
	    log.genericIOError(
		"The %s driver is not present. Unable to issue "
		"CT commands. Please install the %s package.",
		FCSM_DRIVER_PATH.c_str(), FCSM_DRIVER_PKG.c_str());
	    throw NotSupportedException();
	} else {
	    log.genericIOError(
		"Can not stat the %s driver for reason \"%s\" "
		"Unable to issue CT commands.",
		FCSM_DRIVER_PATH.c_str(), strerror(errno));
	    throw IOError("Unable to stat FCSM driver");
	}
    }


    /* construct fcio struct */
    memset(&fcio, 0, sizeof (fcio_t));
    fcio.fcio_cmd	= FCSMIO_ADAPTER_LIST;
    fcio.fcio_xfer	= FCIO_XFER_RW;


    /* open the fcsm node so we can send the ioctl to */
    errno = 0;
    if ((fd = open(FCSM_DRIVER_PATH.c_str(), O_RDONLY)) < 0) {
	if (errno == EBUSY) {
	    throw BusyException();
	} else if (errno == EAGAIN) {
	    throw TryAgainException();
	} else if (errno == ENOTSUP) {
	    throw NotSupportedException();
	} else if (errno == ENOENT) {
	    throw UnavailableException();
	} else {
	    throw IOError("Unable to open FCSM driver");
	}
    }

    do {
	retry = false;
	errno = 0;
	bufSize = MAXPATHLEN * size + (int) sizeof (fc_hba_list_t) - 1;
	pathList = (fc_hba_list_t *)new uchar_t[bufSize];
	pathList->numAdapters = size;
	fcio.fcio_olen	= bufSize;
	fcio.fcio_obuf	= (char *)pathList;
	if (ioctl(fd, FCSMIO_CMD, &fcio) != 0) {
	    /* Interpret the fcio error code */
	    char fcioErrorString[MAX_FCIO_MSG_LEN] = "";

	    log.genericIOError(
		"ADAPTER_LIST failed: "
		"Errno: \"%s\"",
		strerror(errno));
	    delete[] (pathList);
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
	if (pathList->numAdapters > size) {
	    log.debug(
		"Buffer too small for number of HBAs. Retrying.");
	    size = pathList->numAdapters;
	    retry = true;
	    delete[] (pathList);
	}
    } while (retry);

    close(fd);
    log.debug("Detected %d adapters", pathList->numAdapters);
    for (int i = 0, times =0; i < pathList->numAdapters;) {
	try {
	    HBA *hba = new FCHBA(pathList->hbaPaths[i]);
	    list.insert(list.begin(), hba);
	    i++;
	} catch (BusyException &e) {
            sleep(1);
            if (times++ > EXCPT_RETRY_COUNT) {
                i++;
                times = 0;
            }
	    continue;
	} catch (TryAgainException &e) {
	    sleep(1);
	    if (times++ > EXCPT_RETRY_COUNT) {
		i++;
		times = 0;
	    }
	    continue;
	} catch (UnavailableException &e) {
	    sleep(1);
	    if (times++ > EXCPT_RETRY_COUNT) {
		i++;
		times = 0;
	    }
	    continue;
	} catch (HBAException &e) {
	    i++;
	    times = 0;
	    log.debug(
		"Ignoring partial failure while loading an HBA");
	}
    }
    if (pathList->numAdapters > HBAList::HBA_MAX_PER_LIST) {
	delete[](pathList);
	throw InternalError(
	    "Exceeds max number of adapters that VSL supports.");
    }
    delete[] (pathList);
}
