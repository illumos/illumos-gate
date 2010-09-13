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


#include "FCHBANPIVPort.h"
#include <Exceptions.h>
#include <Trace.h>
#include <sun_fc.h>
#include <iostream>
#include <iomanip>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <dirent.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/fcio.h>
#include <sys/fibre-channel/ulp/fcp_util.h>
#include <sys/fibre-channel/ulp/fcsm.h>
#include <sys/fibre-channel/impl/fc_error.h>
#include <sys/fibre-channel/fc_appif.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>
#include <sys/scsi/impl/sense.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/generic/status.h>
#include <errno.h>

using namespace std;

const int FCHBANPIVPort::MAX_FCIO_MSG_LEN = 256;

FCHBANPIVPort::FCHBANPIVPort(string thePath) : HBANPIVPort() {
	Trace log("FCHBANPIVPort::FCHBANPIVPort");
	log.debug("Initializing HBA NPIV port %s", thePath.c_str());

	try {
		path = lookupControllerPath(thePath);
	} catch (...) {
		log.debug("Unable to lookup controller path and number for %s",
		    thePath.c_str());
		path = "/devices";
		path += thePath;
		path += ":fc";
	}

	uint64_t tmp;
	HBA_NPIVATTRIBUTES attrs = getPortAttributes(tmp);
	memcpy(&tmp, &attrs.PortWWN, 8);
	portWWN = ntohll(tmp);
	memcpy(&tmp, &attrs.NodeWWN, 8);
	nodeWWN = ntohll(tmp);
}


HBA_NPIVATTRIBUTES FCHBANPIVPort::getPortAttributes(uint64_t &stateChange) {
	Trace log("FCHBANPIVPort::getPortAttributes");

	HBA_NPIVATTRIBUTES attributes;
	fcio_t fcio;
	fc_hba_npiv_attributes_t attrs;

	memset(&fcio, 0, sizeof (fcio));
	memset(&attributes, 0, sizeof (attributes));
	fcio.fcio_cmd = FCIO_GET_NPIV_ATTRIBUTES;
	fcio.fcio_olen = sizeof (attrs);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)&attrs;
	fp_ioctl(getPath(), FCIO_CMD, &fcio);

	stateChange = attrs.lastChange;
	memcpy(&attributes.NodeWWN, &attrs.NodeWWN, 8);
	memcpy(&attributes.PortWWN, &attrs.PortWWN, 8);

	return (attributes);
}


void FCHBANPIVPort::fp_ioctl(string path, int cmd, fcio_t *fcio) {
	Trace log("FCHBANPIVPort::fp_ioctl");

	char fcioErrorString[MAX_FCIO_MSG_LEN] = "";
	int fd = HBA::_open(path, O_NDELAY | O_RDONLY);

	try {
		int times = 0;
		HBA::_ioctl(fd, cmd, (uchar_t *)fcio);
		while (fcio->fcio_errno == FC_STATEC_BUSY) {
			(void) sleep(2);
			HBA::_ioctl(fd, cmd, (uchar_t *)fcio);
			if (times++ > 20) {
				break;
			}
		}
		close(fd);
		if (fcio->fcio_errno) {
			throw IOError("IOCTL transport failure");
		}
	} catch (...) {
		close(fd);
		transportError(fcio->fcio_errno, fcioErrorString);
		log.genericIOError("NPIV Port ioctl (0x%x) failed. Transport: \"%s\"", cmd,
		    fcioErrorString);
		switch (fcio->fcio_errno) {
		case FC_BADWWN:
			throw IllegalWWNException();
		case FC_BADPORT:
			throw IllegalWWNException();
		case FC_OUTOFBOUNDS:
			throw IllegalIndexException();
		case FC_PBUSY:
		case FC_FBUSY:
		case FC_TRAN_BUSY:
		case FC_STATEC_BUSY:
		case FC_DEVICE_BUSY:
			throw BusyException();
		case FC_SUCCESS:
		default:
			throw;
		}
	}
}


/*
 * Interpret the error code in the fcio_t structure
 *
 * message must be at least MAX_FCIO_MSG_LEN in length.
 */
void
FCHBANPIVPort::transportError(uint32_t fcio_errno, char *message) {
	Trace log("transportError");

	string fcioErrorString;
	if (message == NULL) {
		log.internalError("NULL routine argument");
		return;
	}
	switch (fcio_errno) {
	case (uint32_t)FC_FAILURE:
		fcioErrorString = "general failure";
		break;
	case (uint32_t)FC_FAILURE_SILENT:
		fcioErrorString = "general failure but fail silently";
		break;
	case FC_SUCCESS:
		fcioErrorString = "successful completion";
		break;
	case FC_CAP_ERROR:
		fcioErrorString = "FCA capability error";
		break;
	case FC_CAP_FOUND:
		fcioErrorString = "FCA capability unsettable";
		break;
	case FC_CAP_SETTABLE:
		fcioErrorString = "FCA capability settable";
		break;
	case FC_UNBOUND:
		fcioErrorString = "unbound stuff";
		break;
	case FC_NOMEM:
		fcioErrorString = "allocation error";
		break;
	case FC_BADPACKET:
		fcioErrorString = "invalid packet specified/supplied";
		break;
	case FC_OFFLINE:
		fcioErrorString = "I/O resource unavailable";
		break;
	case FC_OLDPORT:
		fcioErrorString = "operation on non-loop port";
		break;
	case FC_NO_MAP:
		fcioErrorString = "requested map unavailable";
		break;
	case FC_TRANSPORT_ERROR:
		fcioErrorString = "unable to transport I/O";
		break;
	case FC_ELS_FREJECT:
		fcioErrorString = "ELS rejected by a Fabric";
		break;
	case FC_ELS_PREJECT:
		fcioErrorString = "ELS rejected by an N_port";
		break;
	case FC_ELS_BAD:
		fcioErrorString = "ELS rejected by FCA/fctl";
		break;
	case FC_ELS_MALFORMED:
		fcioErrorString = "poorly formed ELS request";
		break;
	case FC_TOOMANY:
		fcioErrorString = "resource request too large";
		break;
	case FC_UB_BADTOKEN:
		fcioErrorString = "invalid unsolicited buffer token";
		break;
	case FC_UB_ERROR:
		fcioErrorString = "invalid unsol buf request";
		break;
	case FC_UB_BUSY:
		fcioErrorString = "buffer already in use";
		break;
	case FC_BADULP:
		fcioErrorString = "Unknown ulp";
		break;
	case FC_BADTYPE:
		fcioErrorString = "ULP not registered to handle this FC4 type";
		break;
	case FC_UNCLAIMED:
		fcioErrorString = "request or data not claimed";
		break;
	case FC_ULP_SAMEMODULE:
		fcioErrorString = "module already in use";
		break;
	case FC_ULP_SAMETYPE:
		fcioErrorString = "FC4 module already in use";
		break;
	case FC_ABORTED:
		fcioErrorString = "request aborted";
		break;
	case FC_ABORT_FAILED:
		fcioErrorString = "abort request failed";
		break;
	case FC_BADEXCHANGE:
		fcioErrorString = "exchange doesn\325t exist";
		break;
	case FC_BADWWN:
		fcioErrorString = "WWN not recognized";
		break;
	case FC_BADDEV:
		fcioErrorString = "device unrecognized";
		break;
	case FC_BADCMD:
		fcioErrorString = "invalid command issued";
		break;
	case FC_BADOBJECT:
		fcioErrorString = "invalid object requested";
		break;
	case FC_BADPORT:
		fcioErrorString = "invalid port specified";
		break;
	case FC_NOTTHISPORT:
		fcioErrorString = "resource not at this port";
		break;
	case FC_PREJECT:
		fcioErrorString = "reject at remote N_Port";
		break;
	case FC_FREJECT:
		fcioErrorString = "reject at remote Fabric";
		break;
	case FC_PBUSY:
		fcioErrorString = "remote N_Port busy";
		break;
	case FC_FBUSY:
		fcioErrorString = "remote Fabric busy";
		break;
	case FC_ALREADY:
		fcioErrorString = "already logged in";
		break;
	case FC_LOGINREQ:
		fcioErrorString = "login required";
		break;
	case FC_RESETFAIL:
		fcioErrorString = "reset failed";
		break;
	case FC_INVALID_REQUEST:
		fcioErrorString = "request is invalid";
		break;
	case FC_OUTOFBOUNDS:
		fcioErrorString = "port number is out of bounds";
		break;
	case FC_TRAN_BUSY:
		fcioErrorString = "command transport busy";
		break;
	case FC_STATEC_BUSY:
		fcioErrorString = "port driver currently busy";
		break;
	case FC_DEVICE_BUSY:
                fcioErrorString = "transport working on this device";
                break;
        case FC_DEVICE_NOT_TGT:
		fcioErrorString = "device is not a SCSI target";
		break;
	default:
		snprintf(message, MAX_FCIO_MSG_LEN, "Unknown error code 0x%x",
		    fcio_errno);
		return;
	}
	snprintf(message, MAX_FCIO_MSG_LEN, "%s", fcioErrorString.c_str());
}

