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



#include <TgtFCHBAPort.h>
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
#include <sys/fctio.h>
#include <sys/fibre-channel/impl/fc_error.h>
#include <sys/fibre-channel/fc_appif.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>
#include <sys/scsi/impl/sense.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/generic/status.h>
#include <errno.h>
#include <cstdlib>


using namespace std;

const int TgtFCHBAPort::MAX_FCTIO_MSG_LEN = 256;
const string TgtFCHBAPort::FCT_DRIVER_PATH = "/devices/pseudo/fct@0:admin";

/*
 * Interpret the error code in the fctio_t structure
 *
 * message must be at least MAX_FCTIO_MSG_LEN in length.
 */
void
TgtFCHBAPort::transportError(uint32_t fctio_errno, char *message) {
	Trace log("transportError");
	string fcioErrorString;
	if (message == NULL) {
	    log.internalError("NULL routine argument");
	    return;
	}
	switch (fctio_errno) {
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
	    fcioErrorString = "exchange doesn’t exist";
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
	    snprintf(message, MAX_FCTIO_MSG_LEN, "Unknown error code 0x%x",
		fctio_errno);
	    return;
	}
	snprintf(message, MAX_FCTIO_MSG_LEN, "%s", fcioErrorString.c_str());
}

TgtFCHBAPort::TgtFCHBAPort(string thePath) : HBAPort() {
	Trace log("TgtFCHBAPort::TgtFCHBAPort");
	log.debug("Initializing HBA port %s", path.c_str());
	path = thePath;

	// This routine is not index based, so we can discard stateChange
	uint64_t tmp;
	HBA_PORTATTRIBUTES attrs = getPortAttributes(tmp);
	memcpy(&tmp, &attrs.PortWWN, 8);
	portWWN = ntohll(tmp);
	memcpy(&tmp, &attrs.NodeWWN, 8);
	nodeWWN = ntohll(tmp);

	// For reference, here's how to dump WWN's through C++ streams.
	// cout << "\tPort WWN: " << hex << setfill('0') << setw(16) << portWWN
	// << endl;
	// cout << "\tNode WWN: " << hex << setfill('0') << setw(16) << nodeWWN
	// << endl;
}

HBA_PORTATTRIBUTES TgtFCHBAPort::getPortAttributes(uint64_t &stateChange) {
	Trace log("TgtFCHBAPort::getPortAttributes");

	HBA_PORTATTRIBUTES	attributes;
	fctio_t			fctio;
	fc_tgt_hba_port_attributes_t    attrs;

	memset(&fctio, 0, sizeof (fctio));
	memset(&attributes, 0, sizeof (attributes));

	uint64_t portwwn = 0;
	try {
	    string::size_type offset = path.find_last_of(".");
	    if (offset >= 0) {
		string portwwnString = path.substr(offset+1);
		portwwn = strtoull(portwwnString.c_str(), NULL, 16);
	    }
	} catch (...) {
	    throw BadArgumentException();
	}

	uint64_t en_wwn = htonll(portwwn);

	fctio.fctio_cmd = FCTIO_GET_ADAPTER_PORT_ATTRIBUTES;
	fctio.fctio_ilen = 8;
	fctio.fctio_ibuf = (uint64_t)(uintptr_t)&en_wwn;
	fctio.fctio_xfer = FCTIO_XFER_READ;
	fctio.fctio_olen = (uint32_t)(sizeof (attrs));
	fctio.fctio_obuf = (uint64_t)(uintptr_t)&attrs;

	fct_ioctl(FCTIO_CMD, &fctio);

	stateChange = attrs.lastChange;

	attributes.PortFcId = attrs.PortFcId;
	attributes.PortType = attrs.PortType;
	attributes.PortState = attrs.PortState;
	attributes.PortSupportedClassofService = attrs.PortSupportedClassofService;
	attributes.PortSupportedSpeed = attrs.PortSupportedSpeed;
	attributes.PortSpeed = attrs.PortSpeed;
	attributes.PortMaxFrameSize = attrs.PortMaxFrameSize;
	attributes.NumberofDiscoveredPorts = attrs.NumberofDiscoveredPorts;
	memcpy(&attributes.NodeWWN, &attrs.NodeWWN, 8);
	memcpy(&attributes.PortWWN, &attrs.PortWWN, 8);
	memcpy(&attributes.FabricName, &attrs.FabricName, 8);
	memcpy(&attributes.PortSupportedFc4Types, &attrs.PortSupportedFc4Types, 32);
	memcpy(&attributes.PortActiveFc4Types, &attrs.PortActiveFc4Types, 32);
	memcpy(&attributes.PortSymbolicName, &attrs.PortSymbolicName, 256);

	strncpy((char *)attributes.OSDeviceName, "Not Applicable", 15);
	return (attributes);
}

HBA_PORTATTRIBUTES TgtFCHBAPort::getDiscoveredAttributes(
	    HBA_UINT32 discoveredport, uint64_t &stateChange) {
	Trace log("TgtFCHBAPort::getDiscoverdAttributes(i)");

	HBA_PORTATTRIBUTES		attributes;
	fctio_t			fctio;
	fc_tgt_hba_port_attributes_t    attrs;

	memset(&fctio, 0, sizeof (fctio));
	memset(&attributes, 0, sizeof (attributes));

	uint64_t portwwn = 0;
	try {
	    string::size_type offset = path.find_last_of(".");
	    if (offset >= 0) {
		string portwwnString = path.substr(offset+1);
		portwwn = strtoull(portwwnString.c_str(), NULL, 16);
	    }
	} catch (...) {
	    throw BadArgumentException();
	}

	uint64_t en_wwn = htonll(portwwn);

	fctio.fctio_cmd = FCTIO_GET_DISCOVERED_PORT_ATTRIBUTES;
	fctio.fctio_ilen = 8;
	fctio.fctio_ibuf = (uint64_t)(uintptr_t)&en_wwn;
	fctio.fctio_xfer = FCTIO_XFER_READ;
	fctio.fctio_olen = (uint32_t)(sizeof (attrs));
	fctio.fctio_obuf = (uint64_t)(uintptr_t)&attrs;
	fctio.fctio_alen = (uint32_t)(sizeof (discoveredport));
	fctio.fctio_abuf = (uint64_t)(uintptr_t)&discoveredport;

	fct_ioctl(FCTIO_CMD, &fctio);

	stateChange = attrs.lastChange;

	attributes.PortFcId = attrs.PortFcId;
	attributes.PortType = attrs.PortType;
	attributes.PortState = attrs.PortState;
	attributes.PortSupportedClassofService = attrs.PortSupportedClassofService;
	attributes.PortSupportedSpeed = attrs.PortSupportedSpeed;
	attributes.PortSpeed = attrs.PortSpeed;
	attributes.PortMaxFrameSize = attrs.PortMaxFrameSize;
	attributes.NumberofDiscoveredPorts = attrs.NumberofDiscoveredPorts;
	memcpy(&attributes.NodeWWN, &attrs.NodeWWN, 8);
	memcpy(&attributes.PortWWN, &attrs.PortWWN, 8);
	memcpy(&attributes.FabricName, &attrs.FabricName, 8);
	memcpy(&attributes.PortSupportedFc4Types, &attrs.PortSupportedFc4Types, 32);
	memcpy(&attributes.PortActiveFc4Types, &attrs.PortActiveFc4Types, 32);
	memcpy(&attributes.PortSymbolicName, &attrs.PortSymbolicName, 256);


	return (attributes);
}

HBA_PORTATTRIBUTES TgtFCHBAPort::getDiscoveredAttributes(
	    uint64_t wwn, uint64_t &stateChange) {
	Trace log("TgtFCHBAPort::getDiscoverdAttributes(p)");

	HBA_PORTATTRIBUTES attributes;
	fctio_t			fctio;
	fc_tgt_hba_port_attributes_t    attrs;

	memset(&fctio, 0, sizeof (fctio));
	memset(&attributes, 0, sizeof (attributes));

	uint64_t en_wwn = htonll(wwn);

	fctio.fctio_cmd = FCTIO_GET_PORT_ATTRIBUTES;
	fctio.fctio_olen = (uint32_t)(sizeof (attrs));
	fctio.fctio_xfer = FCTIO_XFER_READ;
	fctio.fctio_obuf = (uint64_t)(uintptr_t)&attrs;
	fctio.fctio_ilen = (uint32_t)(sizeof (wwn));
	fctio.fctio_ibuf = (uint64_t)(uintptr_t)&en_wwn;

	fct_ioctl(FCTIO_CMD, &fctio);

	stateChange = attrs.lastChange;

	attributes.PortFcId = attrs.PortFcId;
	attributes.PortType = attrs.PortType;
	attributes.PortState = attrs.PortState;
	attributes.PortSupportedClassofService = attrs.PortSupportedClassofService;
	attributes.PortSupportedSpeed = attrs.PortSupportedSpeed;
	attributes.PortSpeed = attrs.PortSpeed;
	attributes.PortMaxFrameSize = attrs.PortMaxFrameSize;
	attributes.NumberofDiscoveredPorts = attrs.NumberofDiscoveredPorts;
	memcpy(&attributes.NodeWWN, &attrs.NodeWWN, 8);
	memcpy(&attributes.PortWWN, &attrs.PortWWN, 8);
	memcpy(&attributes.FabricName, &attrs.FabricName, 8);
	memcpy(&attributes.PortSupportedFc4Types, &attrs.PortSupportedFc4Types, 32);
	memcpy(&attributes.PortActiveFc4Types, &attrs.PortActiveFc4Types, 32);
	memcpy(&attributes.PortSymbolicName, &attrs.PortSymbolicName, 256);


	return (attributes);
}

void TgtFCHBAPort::sendRLS(uint64_t destWWN,
	    void		*pRspBuffer,
	    HBA_UINT32		*pRspBufferSize) {
	Trace log("FCHBAPort::sendRLS");

	fctio_t		fctio;
	// fc_hba_adapter_port_stats_t	fc_port_stat;
	uint64_t	en_portWWN;
	uint64_t	DestPortID;

	// Validate the arguments
	if (pRspBuffer == NULL ||
		pRspBufferSize == NULL) {
	    log.userError("NULL hba");
	    throw BadArgumentException();
	}

	// check to see if we are sending RLS to the HBA
	HBA_PORTATTRIBUTES attrs;
	uint64_t tmp;
	portWWN = getPortWWN();
	en_portWWN = htonll(portWWN);

	/* The destWWN is either the adapter port or a discovered port. */
	memset(&fctio, 0, sizeof (fctio));
	fctio.fctio_cmd = FCTIO_GET_LINK_STATUS;
	fctio.fctio_ibuf = (uint64_t)(uintptr_t)&en_portWWN;
	fctio.fctio_ilen = (uint32_t)(sizeof (en_portWWN));
	if (portWWN != destWWN) {
	    attrs = getDiscoveredAttributes(destWWN, tmp);
	    DestPortID = (uint64_t)attrs.PortFcId;
	    fctio.fctio_abuf = (uint64_t)(uintptr_t)&DestPortID;
	    fctio.fctio_alen = (uint32_t)(sizeof (DestPortID));
	}
	fctio.fctio_xfer = FCTIO_XFER_READ;
	fctio.fctio_flags = 0;
	fctio.fctio_obuf = (uint64_t)(uintptr_t)new uchar_t[*pRspBufferSize];
	fctio.fctio_olen = *pRspBufferSize;

	if (fctio.fctio_obuf == 0) {
	    log.noMemory();
	    throw InternalError();
	}

	fct_ioctl(FCTIO_CMD, &fctio);
	memcpy(pRspBuffer, (uchar_t *)(uintptr_t)fctio.fctio_obuf, 
	       *pRspBufferSize);
	if (fctio.fctio_obuf != 0) {
	    delete((uchar_t *)(uintptr_t)fctio.fctio_obuf);
	}
}

/**
 * @memo	    Validate that the port is still present in the system
 * @exception	    UnavailableException if the port is not present
 * @version	    1.7
 * 
 * @doc		    If the port is still present on the system, the routine
 *		    will return normally.  If the port is not present
 *		    an exception will be thrown.
 */
void TgtFCHBAPort::validatePresent() {
	Trace log("TgtFCHBAPort::validatePresent");
	// We already got the adapter list through the ioctl
	// so calling it again to validate it is too expensive.
}

void TgtFCHBAPort::fct_ioctl(int cmd, fctio_t *fctio) {
	Trace log("TgtFCHBAPort::fct_ioctl");
	char fcioErrorString[MAX_FCTIO_MSG_LEN] = "";
	int fd = HBA::_open(FCT_DRIVER_PATH, O_NDELAY | O_RDONLY);
	try {
	    HBA::_ioctl(fd, cmd, (uchar_t *)fctio);
	    close(fd);
	    if (fctio->fctio_errno) {
		throw IOError("IOCTL transport failure");
	    }
	} catch (...) {
	    close(fd);
	    transportError(fctio->fctio_errno, fcioErrorString);
	    log.genericIOError("ioctl (0x%x) failed. Transport: \"%s\"", cmd,
		    fcioErrorString);
	    switch (fctio->fctio_errno) {
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
