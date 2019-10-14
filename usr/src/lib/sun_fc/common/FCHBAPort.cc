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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2019 RackTop Systems.
 */



#include <FCHBAPort.h>
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
#include <FCHBANPIVPort.h>


using namespace std;

const int FCHBAPort::MAX_FCIO_MSG_LEN = 256;
const string FCHBAPort::FCSM_DRIVER_PATH = "/devices/pseudo/fcsm@0:fcsm";
const string FCHBAPort::FCP_DRIVER_PATH	= "/devices/pseudo/fcp@0:fcp";

/*
 * Interpret the error code in the fcio_t structure
 *
 * message must be at least MAX_FCIO_MSG_LEN in length.
 */
void
FCHBAPort::transportError(uint32_t fcio_errno, char *message) {
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
	    fcioErrorString = "exchange doesnÕt exist";
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

static void
reportSense(struct scsi_extended_sense *sense, const char *routine) {
	Trace log("reportSense");
	string msg;
	if (!sense) {
	    log.internalError("NULL sense argument passed.");
	    return;
	}
	if (!routine) {
	    log.internalError("NULL routine argument passed.");
	    return;
	}
	log.genericIOError("SCSI FAILURE");
	switch (sense->es_key) {
	case KEY_NO_SENSE:
	    msg = "No sense";
	    break;
	case KEY_RECOVERABLE_ERROR:
	    msg = "Recoverable error";
	    break;
	case KEY_NOT_READY:
	    msg = "Not ready";
	    break;
	case KEY_MEDIUM_ERROR:
	    msg = "Medium error";
	    break;
	case KEY_HARDWARE_ERROR:
	    msg = "Hardware error";
	    break;
	case KEY_ILLEGAL_REQUEST:
	    msg = "Illegal request";
	    break;
	case KEY_UNIT_ATTENTION:
	    msg = "Unit attention";
	    break;
	case KEY_DATA_PROTECT:
	    msg = "Data protect";
	    break;
	case KEY_BLANK_CHECK:
	    msg = "Blank check";
	    break;
	case KEY_VENDOR_UNIQUE:
	    msg = "Vendor Unique";
	    break;
	case KEY_COPY_ABORTED:
	    msg = "Copy aborted";
	    break;
	case KEY_ABORTED_COMMAND:
	    msg = "Aborted command";
	    break;
	case KEY_EQUAL:
	    msg = "Equal";
	    break;
	case KEY_VOLUME_OVERFLOW:
	    msg = "Volume overflow";
	    break;
	case KEY_MISCOMPARE:
	    msg = "Miscompare";
	    break;
	case KEY_RESERVED:
	    msg = "Reserved";
	    break;
	default:
	    msg = "unknown sense key";
	}
	log.genericIOError("\tSense key: %s", msg.c_str());
	log.genericIOError("\tASC  = 0x%x", sense->es_add_code);
	log.genericIOError("\tASCQ = 0x%x", sense->es_qual_code);
}

/*
 * Issue a SCSI pass thru command.
 * Returns a scsi status value.
 */
void FCHBAPort::sendSCSIPassThru(struct fcp_scsi_cmd *fscsi,
	    HBA_UINT32 *responseSize, HBA_UINT32 *senseSize,
	    HBA_UINT8 *scsiStatus) {
	Trace log("FCHBAPort::sendSCSIPassThru");
	int		    fd;
	HBA_STATUS	    ret;
	char		    fcioErrorString[MAX_FCIO_MSG_LEN] = "";
	hrtime_t	    start;
	hrtime_t	    end;
	int		    ioctl_errno;
	double		    duration;
	la_wwn_t	    wwn;

	if (fscsi == NULL ||
		responseSize == NULL ||
		senseSize == NULL ||
		scsiStatus == NULL) {
	    throw BadArgumentException();
	}

	memcpy(&wwn, fscsi->scsi_fc_pwwn.raw_wwn, sizeof (la_wwn_t));
	start = gethrtime();
	fscsi->scsi_fc_port_num	= instanceNumber;

	fd = HBA::_open(FCP_DRIVER_PATH, O_RDONLY | O_NDELAY);
	ioctl_errno = 0;

	if (ioctl(fd, FCP_TGT_SEND_SCSI, fscsi) != 0) {
	    /* save off errno */
	    ioctl_errno = errno;
	    close(fd);
	    /*
	     * collect SCSI status first regrardless of the value.
	     * 0 is a good status so this should be okay
	     */
	    *scsiStatus = fscsi->scsi_bufstatus & STATUS_MASK;
	    transportError(fscsi->scsi_fc_status, fcioErrorString);

	    /* Did we get a check condition? */
	    if ((fscsi->scsi_bufstatus & STATUS_MASK) == STATUS_CHECK) {
		*senseSize = fscsi->scsi_rqlen;
		throw CheckConditionException();
	    } else if (fscsi->scsi_fc_status == FC_DEVICE_NOT_TGT) {
		/*
		 * fcp driver returns FC_DEVICE_NOT_TGT when the node is not
		 * scsi-capable like remote hba nodes.
		 */
		throw NotATargetException();
	    } else if (fscsi->scsi_fc_status == FC_INVALID_LUN) {
		throw InvalidLUNException();
	    } else if (ioctl_errno == EBUSY) {
		throw BusyException();
	    } else if (ioctl_errno == EAGAIN) {
		throw TryAgainException();
	    } else if (ioctl_errno == ENOTSUP) {
		throw NotSupportedException();
	    } else if (ioctl_errno == ENOENT) {
		throw UnavailableException();
	    } else {
		throw IOError(this, wwnConversion(wwn.raw_wwn),
			fscsi->scsi_lun);
	    }
	} else {
		close(fd);
	    /* Just in case, check for a check-condition state */
	    if ((fscsi->scsi_bufstatus & STATUS_MASK) == STATUS_CHECK) {
		*scsiStatus = fscsi->scsi_bufstatus & STATUS_MASK;
		*senseSize = fscsi->scsi_rqlen;
		throw CheckConditionException();
	    }
	}

	/* Record the response data */
	*scsiStatus = fscsi->scsi_bufstatus & STATUS_MASK;
	*responseSize = fscsi->scsi_buflen;
	*senseSize = fscsi->scsi_rqlen;

	/* Do some quick duration calcuations */
	end = gethrtime();
	duration = end - start;
	duration /= HR_SECOND;
	log.debug("Total SCSI IO time for HBA %s "
	    "target %016llx was %.4f seconds", getPath().c_str(),
	    wwnConversion(wwn.raw_wwn), duration);

#ifdef DEBUG
	/* Did we have any failure */
	if (ret != HBA_STATUS_OK) {
	    log.genericIOError(
		"Ioctl failed for device \"%s\" target %016llx."
		"  Errno: \"%s\"(%d), "
		"Transport: \"%s\", SCSI Status: 0x%x"
		"responseSize = %d, senseSize = %d",
		getPath().c_str(), wwnConversion(fscsi->scsi_fc_pwwn.raw_wwn),
		strerror(ioctl_errno), ioctl_errno, fcioErrorString,
		*scsiStatus, *responseSize, *senseSize);
	    /* We may or may not have sense data */
	    reportSense((struct scsi_extended_sense *)fscsi->scsi_rqbufaddr,
		ROUTINE);
	}
#endif

}

/*
 * constructs the fcp_scsi_cmd struct for SCSI_Inquiry, SendReadCapacity, or
 * SendReportLUNs
 */
/*#include <fcio.h>
#include <fcp_util.h>*/
inline void
scsi_cmd_init(struct fcp_scsi_cmd *fscsi, const char *portname, void *reqbuf,
	    size_t req_len, void *responseBuffer, size_t resp_len,
	    void *senseBuffer, size_t sense_len) {
	Trace log("scsi_cmd_init");
	fscsi->scsi_fc_rspcode	= 0;
	fscsi->scsi_flags	= FCP_SCSI_READ;
	fscsi->scsi_timeout	= 10 /* sec */;
	fscsi->scsi_cdbbufaddr	= (char *)reqbuf;
	fscsi->scsi_cdblen	= (uint32_t) req_len;
	fscsi->scsi_bufaddr	= (char *)responseBuffer;
	fscsi->scsi_buflen	= (uint32_t) resp_len;
	fscsi->scsi_bufresid	= 0;
	fscsi->scsi_bufstatus	= 0;
	fscsi->scsi_rqbufaddr	= (char *)senseBuffer;
	fscsi->scsi_rqlen	= (uint32_t) sense_len;
	fscsi->scsi_rqresid	= 0;
}


FCHBAPort::FCHBAPort(string thePath) : HBAPort() {
	Trace log("FCHBAPort::FCHBAPort");
	log.debug("Initializing HBA port %s", thePath.c_str());
	fcio_t		fcio;
	int		size = 200;
	fc_hba_npiv_port_list_t	*pathList;
	bool		retry = false;
	int		bufSize;

	try {
	    path = lookupControllerPath(thePath);
	    sscanf(path.c_str(), "/dev/cfg/c%d", &controllerNumber);
	} catch (...) {
	    log.debug("Unable to lookup controller path and number for %s",
		    thePath.c_str());
	    path = "/devices";
	    path += thePath;
	    path += ":fc";
	    controllerNumber = -1;
	}

	// Fetch the minor number for later use
	struct stat sbuf;
	if (stat(path.c_str(), &sbuf) == -1) {
	    throw IOError("Unable to stat device path: " + path);
	}
	instanceNumber = minor(sbuf.st_rdev);

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

	// we should add code here to build NPIVPORT instance
	// Get Port's NPIV port list ( include nwwn and pwwn and path)
	memset((caddr_t)&fcio, 0, sizeof (fcio));
	fcio.fcio_cmd = FCIO_GET_NPIV_PORT_LIST;
	fcio.fcio_xfer = FCIO_XFER_READ;
	do {
		retry = false;
		bufSize = MAXPATHLEN * (size - 1) + (int) sizeof (fc_hba_npiv_port_list_t);
		pathList = (fc_hba_npiv_port_list_t *) new uchar_t[bufSize];
		pathList->numAdapters = size;
		fcio.fcio_olen = bufSize;
		fcio.fcio_obuf = (char *)pathList;
		fp_ioctl(getPath(), FCIO_CMD, &fcio);
		if (pathList->numAdapters > size) {
			log.debug("Buffer too small for number of NPIV Port.Retry.");
			size = pathList->numAdapters;
			retry = true;
			delete (pathList);
		}
	} while (retry);
	log.debug("Get %d npiv ports", pathList->numAdapters);
	// Make instance for each NPIV Port
	for ( int i = 0; i < pathList->numAdapters; i++) {
		try {
			addPort(new FCHBANPIVPort(pathList->hbaPaths[i]));
		} catch (...) {
			log.debug("Ignoring partial failure");
		}
	}
	delete (pathList);
}

uint32_t FCHBAPort::deleteNPIVPort(uint64_t vportwwn) {
	Trace log("FCHBAPort::deleteNPIVPort");
	fcio_t  fcio;
	la_wwn_t        lawwn[1];
	int ret = 0;

	memset(&fcio, 0, sizeof(fcio));
	uint64_t en_wwn = htonll(vportwwn);
	memcpy(&lawwn[0], &en_wwn, sizeof (en_wwn));

	fcio.fcio_cmd = FCIO_DELETE_NPIV_PORT;
	fcio.fcio_xfer = FCIO_XFER_WRITE;
	fcio.fcio_ilen = sizeof (la_wwn_t) * 2;
	fcio.fcio_ibuf = (caddr_t)&lawwn;

	fp_ioctl(getPath(), FCIO_CMD, &fcio);

	return (ret);
}

uint32_t FCHBAPort::createNPIVPort(uint64_t vnodewwn, uint64_t vportwwn, uint32_t vindex) {
	Trace log("FCHBAPort::createNPIVPort");
	fcio_t  fcio;
	la_wwn_t        lawwn[2];
	uint32_t vportindex = 0;
	HBA_NPIVCREATEENTRY	entrybuf;

	memset(&fcio, 0, sizeof(fcio));
	uint64_t en_wwn = htonll(vnodewwn);
	memcpy(&entrybuf.VNodeWWN, &en_wwn, sizeof (en_wwn));
	en_wwn = htonll(vportwwn);
	memcpy(&entrybuf.VPortWWN, &en_wwn, sizeof (en_wwn));
	entrybuf.vindex = vindex;

	fcio.fcio_cmd = FCIO_CREATE_NPIV_PORT;
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_olen = sizeof (uint32_t);
	fcio.fcio_obuf = (caddr_t)&vportindex;
	fcio.fcio_ilen = sizeof (HBA_NPIVCREATEENTRY);
	fcio.fcio_ibuf = (caddr_t)&entrybuf;

	fp_ioctl(getPath(), FCIO_CMD, &fcio);

	return (vportindex);
}

HBA_PORTNPIVATTRIBUTES FCHBAPort::getPortNPIVAttributes(uint64_t &stateChange) {
	Trace log("FCHBAPort::getPortNPIVAttributes");

	HBA_PORTNPIVATTRIBUTES  attributes;
	fc_hba_port_npiv_attributes_t   attrs;
	fcio_t  fcio;

	memset(&fcio, 0, sizeof(fcio));
	memset(&attributes, 0, sizeof(attributes));

	fcio.fcio_cmd = FCIO_GET_ADAPTER_PORT_NPIV_ATTRIBUTES;
	fcio.fcio_olen = sizeof(attrs);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)&attrs;

	fp_ioctl(getPath(), FCIO_CMD, &fcio);

	stateChange = attrs.lastChange;
	attributes.npivflag = attrs.npivflag;
	memcpy(&attributes.NodeWWN, &attrs.NodeWWN, 8);
	memcpy(&attributes.PortWWN, &attrs.PortWWN, 8);
	attributes.MaxNumberOfNPIVPorts = attrs.MaxNumberOfNPIVPorts;
	attributes.NumberOfNPIVPorts = attrs.NumberOfNPIVPorts;

	return (attributes);
}

HBA_PORTATTRIBUTES FCHBAPort::getPortAttributes(uint64_t &stateChange) {
	Trace log("FCHBAPort::getPortAttributes");

	HBA_PORTATTRIBUTES		attributes;
	fcio_t			fcio;
	fc_hba_port_attributes_t    attrs;

	memset(&fcio, 0, sizeof (fcio));
	memset(&attributes, 0, sizeof (attributes));

	fcio.fcio_cmd = FCIO_GET_ADAPTER_PORT_ATTRIBUTES;
	fcio.fcio_olen = sizeof (attrs);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)&attrs;

	fp_ioctl(getPath(), FCIO_CMD, &fcio);

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

	strncpy((char *)attributes.OSDeviceName, getPath().c_str(), 256);
	return (attributes);
}

HBA_PORTATTRIBUTES FCHBAPort::getDiscoveredAttributes(
	    HBA_UINT32 discoveredport, uint64_t &stateChange) {
	Trace log("FCHBAPort::getDiscoverdAttributes(i)");

	HBA_PORTATTRIBUTES		attributes;
	fcio_t			fcio;
	fc_hba_port_attributes_t    attrs;

	memset(&fcio, 0, sizeof (fcio));
	memset(&attributes, 0, sizeof (attributes));

	fcio.fcio_cmd = FCIO_GET_DISCOVERED_PORT_ATTRIBUTES;
	fcio.fcio_olen = sizeof (attrs);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)&attrs;
	fcio.fcio_ilen = sizeof (discoveredport);
	fcio.fcio_ibuf = (caddr_t)&discoveredport;

	fp_ioctl(getPath(), FCIO_CMD, &fcio);

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

HBA_PORTATTRIBUTES FCHBAPort::getDiscoveredAttributes(
	    uint64_t wwn, uint64_t &stateChange) {
	Trace log("FCHBAPort::getDiscoverdAttributes(p)");

	HBA_PORTATTRIBUTES attributes;
	fcio_t			fcio;
	fc_hba_port_attributes_t    attrs;
	la_wwn_t	lawwn;

	memset(&fcio, 0, sizeof (fcio));
	memset(&attributes, 0, sizeof (attributes));

	uint64_t en_wwn = htonll(wwn);
	memcpy(&lawwn, &en_wwn, sizeof (en_wwn));

	fcio.fcio_cmd = FCIO_GET_PORT_ATTRIBUTES;
	fcio.fcio_olen = sizeof (attrs);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)&attrs;
	fcio.fcio_ilen = sizeof (wwn);
	fcio.fcio_ibuf = (caddr_t)&lawwn;

	fp_ioctl(getPath(), FCIO_CMD, &fcio);

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


void FCHBAPort::getTargetMappings(PHBA_FCPTARGETMAPPINGV2 userMappings) {
	Trace log("FCHBAPort::getTargetMappings");
	int				i, index;
	uint_t			total_entries = 0;

	struct fcp_ioctl		fioctl;
	fc_hba_target_mappings_t    *mappings;
	int				fd;
	bool			zeroLength = false;


	if (userMappings == NULL) {
	    log.userError("Null mapping argument ");
	    throw BadArgumentException();
	}

	/* It's possible they didn't give any space */
	if (userMappings->NumberOfEntries == 0) {
	    zeroLength = true;
	    userMappings->NumberOfEntries = 1;
		/* We have to give the driver at least one space */
	}

	mappings = (fc_hba_target_mappings_t *)new uchar_t[
		(sizeof (fc_hba_mapping_entry_t)) *
		(userMappings->NumberOfEntries - 1) +
		sizeof (fc_hba_target_mappings_t)];
	if (mappings == NULL) {
	    log.noMemory();
	    throw InternalError();
	}


	fioctl.fp_minor = instanceNumber;
	fioctl.listlen = ((uint32_t) (sizeof (fc_hba_mapping_entry_t))) *
		(userMappings->NumberOfEntries - 1) +
		(uint32_t) sizeof (fc_hba_target_mappings_t);
	fioctl.list = (caddr_t)mappings;

	fd = HBA::_open(FCP_DRIVER_PATH, O_RDONLY | O_NDELAY);

	log.debug("Performing IOCTL to fetch mappings");

	if (ioctl(fd, FCP_GET_TARGET_MAPPINGS, &fioctl) != 0) {
	    delete (mappings);
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
		throw IOError("Unable to fetch target mappings");
	    }
	}

	close(fd);
	// Quickly iterate through and copy the data over to the client
	for (i = 0; i < userMappings->NumberOfEntries && !zeroLength &&
		    i < mappings->numLuns; i++) {
	    string raw = mappings->entries[i].targetDriver;


	    if (raw.length() <= 0) {
		log.internalError("Bad target mapping without path, truncating.");
		break;
	    }
	    /*
	     * Ideally, we'd like to ask some standard Solaris interface
	     * "What is the prefered minor node for this target?"
	     * but no such interface exists today.  So, for now,
	     * we just hard-code ":n" for tapes, ":c,raw" for disks,
	     * and ":0" for enclosures.
	     * Devices with other generic names will be presented through
	     * first matching /dev path.
	     */
	    if ((raw.find("/st@") != raw.npos) ||
		(raw.find("/tape@") != raw.npos)) {
		raw += ":n";
	    } else if ((raw.find("/ssd@") != raw.npos) ||
	    	(raw.find("/sd@") != raw.npos) ||
	   	(raw.find("/disk@") != raw.npos)) { 
		raw += ":c,raw";
	    } else if ((raw.find("/ses@") != raw.npos) ||
	   	(raw.find("/enclosure@") != raw.npos)) { 
		raw += ":0";
	    } else {
		log.debug(
	    "Unrecognized target driver (%s), using first matching /dev path",
		    raw.c_str());
	    }
	    snprintf(userMappings->entry[i].ScsiId.OSDeviceName,
		sizeof (userMappings->entry[i].ScsiId.OSDeviceName),
		"/devices%s", raw.c_str());
	    userMappings->entry[i].ScsiId.ScsiBusNumber =
		    controllerNumber;
	    userMappings->entry[i].ScsiId.ScsiTargetNumber =
		    mappings->entries[i].targetNumber;
	    userMappings->entry[i].ScsiId.ScsiOSLun =
		    mappings->entries[i].osLUN;
	    userMappings->entry[i].FcpId.FcId =
		    mappings->entries[i].d_id;
	    memcpy(userMappings->entry[i].FcpId.NodeWWN.wwn,
		    mappings->entries[i].NodeWWN.raw_wwn,
		    sizeof (la_wwn_t));
	    memcpy(userMappings->entry[i].FcpId.PortWWN.wwn,
		    mappings->entries[i].PortWWN.raw_wwn,
		    sizeof (la_wwn_t));

	    userMappings->entry[i].FcpId.FcpLun = 
		mappings->entries[i].samLUN;
		
	    memcpy(userMappings->entry[i].LUID.buffer,
		    mappings->entries[i].guid,
		    sizeof (userMappings->entry[i].LUID.buffer));
	}

	log.debug("Total mappings: %d %08x %08x",
	    mappings->numLuns, mappings->entries[i].osLUN, mappings->entries[i].samLUN);

	// If everything is good, convert paths to sym-links
	if (mappings->numLuns > 0 && !zeroLength) {
	    if (userMappings->NumberOfEntries >= mappings->numLuns) {
		// User buffer is larger than needed. (All is good)
		userMappings->NumberOfEntries = mappings->numLuns;
		convertToShortNames(userMappings);
	    } else {
		// User buffer is non zero, but too small.  Don't bother with links
		userMappings->NumberOfEntries = mappings->numLuns;
		delete (mappings);
		throw MoreDataException();
	    }
	} else if (mappings->numLuns > 0) {
	    // Zero length buffer, but we've got mappings
	    userMappings->NumberOfEntries = mappings->numLuns;
	    delete (mappings);
	    throw MoreDataException();
	} else {
	    // No mappings, no worries
	    userMappings->NumberOfEntries = 0;
	    delete (mappings);
	    return;
	}
	delete (mappings);
}

void FCHBAPort::getRNIDMgmtInfo(PHBA_MGMTINFO info) {
	Trace log("FCHBAPort::getRNIDMgmtInfo");
	HBA_STATUS		status = HBA_STATUS_OK;
	fc_rnid_t		rnid;
	fcio_t			fcio;


	if (info == NULL) {
	    log.userError("NULL port management info");
	    throw BadArgumentException();
	}

	// Get the RNID information from the first port
	memset(&rnid, 0, sizeof (fc_rnid_t));
	memset((caddr_t)&fcio, 0, sizeof (fcio));

	fcio.fcio_cmd =	FCIO_GET_NODE_ID;
	fcio.fcio_olen = sizeof (fc_rnid_t);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)&rnid;
	fp_ioctl(getPath(), FCIO_CMD, &fcio);

	// Copy out the struct members of rnid into PHBA_MGMTINFO struct
	memcpy(&info->wwn, &(rnid.global_id), sizeof (info->wwn));
	memcpy(&info->unittype, &(rnid.unit_type), sizeof (info->unittype));
	memcpy(&info->PortId, &(rnid.port_id), sizeof (info->PortId));
	memcpy(&info->NumberOfAttachedNodes, &(rnid.num_attached),
		sizeof (info->NumberOfAttachedNodes));
	memcpy(&info->IPVersion, &(rnid.ip_version), sizeof (info->IPVersion));
	memcpy(&info->UDPPort, &(rnid.udp_port), sizeof (info->UDPPort));
	memcpy(&info->IPAddress, &(rnid.ip_addr), sizeof (info->IPAddress));
	memcpy(&info->TopologyDiscoveryFlags, &(rnid.topo_flags),
		sizeof (info->TopologyDiscoveryFlags));
}

void FCHBAPort::sendCTPassThru(void *requestBuffer, HBA_UINT32 requestSize,
	    void *responseBuffer, HBA_UINT32 *responseSize) {
	Trace log("FCHBAPort::sendCTPassThru");
	fcio_t			fcio;
	struct stat		sbuf;
	minor_t			minor_node;
	hrtime_t		start, end;
	double			duration;

	// Validate the arguments
	if (requestBuffer == NULL) {
	    log.userError("NULL request buffer");
	    throw BadArgumentException();
	}
	if (responseBuffer == NULL) {
	    log.userError("NULL response buffer");
	    throw BadArgumentException();
	}

	minor_node = instanceNumber;

	// construct fcio struct
	memset(&fcio, 0, sizeof (fcio_t));
	fcio.fcio_cmd	= FCSMIO_CT_CMD;
	fcio.fcio_xfer	= FCIO_XFER_RW;

	fcio.fcio_ilen	= requestSize;
	fcio.fcio_ibuf	= (char *)requestBuffer;
	fcio.fcio_olen	= *responseSize;
	fcio.fcio_obuf	= (char *)responseBuffer;

	fcio.fcio_alen	= sizeof (minor_t);
	fcio.fcio_abuf	= (char *)&minor_node;


	start = gethrtime();
	fcsm_ioctl(FCSMIO_CMD, &fcio);

	// Do some calculations on the duration of the ioctl.
	end = gethrtime();
	duration = end - start;
	duration /= HR_SECOND;
	log.debug(
	    "Total CTPASS ioctl call for HBA %s was %.4f seconds",
	    getPath().c_str(), duration);
}

void FCHBAPort::sendRLS(uint64_t destWWN,
	    void		*pRspBuffer,
	    HBA_UINT32		*pRspBufferSize) {
	Trace log("FCHBAPort::sendRLS");

	fcio_t		fcio;
	fc_portid_t		rls_req;


	// Validate the arguments
	if (pRspBuffer == NULL ||
		pRspBufferSize == NULL) {
	    log.userError("NULL hba");
	    throw BadArgumentException();
	}

	// check to see if we are sending RLS to the HBA
	HBA_PORTATTRIBUTES attrs;
	uint64_t tmp;
	if (getPortWWN() == destWWN) {
	    attrs = getPortAttributes(tmp);
	} else {
	    attrs = getDiscoveredAttributes(destWWN, tmp);
	}

	memcpy(&rls_req, &attrs.PortFcId,
	    sizeof (attrs.PortFcId));

	memset((caddr_t)&fcio, 0, sizeof (fcio));
	fcio.fcio_cmd = FCIO_LINK_STATUS;
	fcio.fcio_ibuf = (caddr_t)&rls_req;
	fcio.fcio_ilen = sizeof (rls_req);
	fcio.fcio_xfer = FCIO_XFER_RW;
	fcio.fcio_flags = 0;
	fcio.fcio_cmd_flags = FCIO_CFLAGS_RLS_DEST_NPORT;
	fcio.fcio_obuf = (char *)new uchar_t[*pRspBufferSize];
	fcio.fcio_olen = *pRspBufferSize;

	if (fcio.fcio_obuf == NULL) {
	    log.noMemory();
	    throw InternalError();
	}

	fp_ioctl(getPath(), FCIO_CMD, &fcio);
	memcpy(pRspBuffer, fcio.fcio_obuf, *pRspBufferSize);
	if (fcio.fcio_obuf != NULL) {
	    delete(fcio.fcio_obuf);
	}
}

void FCHBAPort::sendReportLUNs(uint64_t wwn,
	    void *responseBuffer, HBA_UINT32 *responseSize,
	    HBA_UINT8 *scsiStatus,
	    void *senseBuffer, HBA_UINT32 *senseSize) {
	Trace log("FCHBAPort::sendReportLUNs");
	struct	fcp_scsi_cmd	    fscsi;
	union	scsi_cdb	    scsi_rl_req;
	uint64_t		    targetWwn = htonll(wwn);

	// Validate the arguments
	if (responseBuffer == NULL ||
		senseBuffer == NULL ||
		responseSize == NULL ||
		senseSize == NULL) {
	    throw BadArgumentException();
	}

	memset(&fscsi, 0, sizeof (fscsi));
	memset(&scsi_rl_req, 0, sizeof (scsi_rl_req));
	memcpy(fscsi.scsi_fc_pwwn.raw_wwn, &targetWwn, sizeof (la_wwn_t));

	scsi_cmd_init(&fscsi, getPath().c_str(), &scsi_rl_req,
		    sizeof (scsi_rl_req), responseBuffer, *responseSize,
		    senseBuffer, *senseSize);

	fscsi.scsi_lun = 0;
	scsi_rl_req.scc_cmd = SCMD_REPORT_LUNS;
	FORMG5COUNT(&scsi_rl_req, *responseSize);
	sendSCSIPassThru(&fscsi, responseSize, senseSize, scsiStatus);
}

/*
 * arguments:
 *	wwn - remote target WWN where the SCSI Inquiry shall be sent
 *	fcLun - the SCSI LUN to which the SCSI Inquiry shall be sent
 *	cdb1 - the second byte of the CDB for the SCSI Inquiry
 *	cdb2 - the third byte of teh CDB for the SCSI Inquiry
 *	responseBuffer - shall be a pointer to a buffer to receive the SCSI
 *		Inquiry command response
 *	responseSize - a pointer to the size of the buffer to receive
 *		the SCSI Inquiry.
 *	scsiStatus - a pointer to a buffer to receive SCSI status
 *	senseBuffer - pointer to a buffer to receive SCSI sense data
 *	seneseSize - pointer to the size of the buffer to receive SCSI sense
 *		data
 */
void FCHBAPort::sendScsiInquiry(uint64_t wwn, HBA_UINT64 fcLun,
	    HBA_UINT8 cdb1, HBA_UINT8 cdb2, void *responseBuffer,
	    HBA_UINT32 *responseSize, HBA_UINT8 *scsiStatus, void *senseBuffer,
	    HBA_UINT32 *senseSize) {
	Trace log("FCHBAPort::sendScsiInquiry");

	struct	fcp_scsi_cmd	    fscsi;
	union	scsi_cdb	    scsi_inq_req;
	uint64_t		    targetWwn = htonll(wwn);

	// Validate the arguments
	if (responseBuffer == NULL ||
		senseBuffer == NULL ||
		responseSize == NULL ||
		senseSize == NULL) {
	    throw BadArgumentException();
	}

	memset(&fscsi, 0, sizeof (fscsi));
	memset(&scsi_inq_req, 0, sizeof (scsi_inq_req));
	memcpy(fscsi.scsi_fc_pwwn.raw_wwn, &targetWwn, sizeof (la_wwn_t));


	scsi_cmd_init(&fscsi, getPath().c_str(), &scsi_inq_req,
	    sizeof (scsi_inq_req), responseBuffer, *responseSize,
	    senseBuffer, *senseSize);
	fscsi.scsi_lun = fcLun;

	scsi_inq_req.scc_cmd = SCMD_INQUIRY;
	scsi_inq_req.g0_addr1 = cdb2;
	scsi_inq_req.g0_addr2 = cdb1;
	scsi_inq_req.g0_count0 = *responseSize;


	sendSCSIPassThru(&fscsi, responseSize, senseSize, scsiStatus);
}


void FCHBAPort::sendReadCapacity(uint64_t pwwn,
		HBA_UINT64 fcLun, void *responseBuffer,
		HBA_UINT32 *responseSize, HBA_UINT8 *scsiStatus,
		void *senseBuffer, HBA_UINT32 *senseSize) {
	Trace log("FCHBAPort::sendReadCapacity");

	struct fcp_scsi_cmd	    fscsi;
	union scsi_cdb	    scsi_rc_req;
	uint64_t		    targetWwn = htonll(pwwn);

	// Validate the arguments
	if (responseBuffer == NULL ||
		senseBuffer == NULL ||
		responseSize == NULL ||
		senseSize == NULL ||
		scsiStatus == NULL) {
	    throw BadArgumentException();
	}

	memset(&fscsi, 0, sizeof (fscsi));
	memset(&scsi_rc_req, 0, sizeof (scsi_rc_req));

	scsi_cmd_init(&fscsi, getPath().c_str(), &scsi_rc_req,
	    sizeof (scsi_rc_req), responseBuffer, *responseSize,
	    senseBuffer, *senseSize);

	memcpy(fscsi.scsi_fc_pwwn.raw_wwn, &targetWwn, sizeof (la_wwn_t));
	fscsi.scsi_lun = fcLun;

	scsi_rc_req.scc_cmd = SCMD_READ_CAPACITY;
	scsi_rc_req.g1_reladdr = 0;

	scsi_rc_req.g1_addr3 = 0;
	scsi_rc_req.g1_count0	= 0;

	sendSCSIPassThru(&fscsi, responseSize, senseSize, scsiStatus);
}

void FCHBAPort::sendRNID(uint64_t destwwn, HBA_UINT32 destfcid,
			    HBA_UINT32 nodeIdDataFormat, void *pRspBuffer,
			    HBA_UINT32 *RspBufferSize) {
	Trace log("FCHBAPort::sendRNID");
	int 			localportfound, remoteportfound, send;
	fcio_t			fcio;

	// Validate the arguments
	if (pRspBuffer == NULL ||
		RspBufferSize == NULL) {
	    throw BadArgumentException();
	}
	// NodeIdDataFormat must be within the range of 0x00 and 0xff
	if (nodeIdDataFormat > 0xff) {
	    log.userError(
		    "NodeIdDataFormat must be within the range of 0x00 "
		    "and 0xFF");
	    throw BadArgumentException();
	}


	remoteportfound = 0;
	if (destfcid != 0) {
	    try {
		uint64_t tmp;
		HBA_PORTATTRIBUTES attrs = getDiscoveredAttributes(destwwn,
			tmp);
		if (attrs.PortFcId == destfcid) {
		    send = 1;
		    remoteportfound = 1;
		} else {
		    send = 0;
		    remoteportfound = 1;
		}
	    } catch (HBAException &e) {
		/*
		 * Send RNID if destination port not
		 * present in the discovered ports table
		 */
	    }
	    if (remoteportfound == 0) {
		send = 1;
	    }
	} else {
	    send = 1;
	}

	if (!send) {
	    // Can we log something so we can figure out why?
	    throw BadArgumentException();
	}

	memset((caddr_t)&fcio, 0, sizeof (fcio));
	uint64_t netdestwwn = htonll(destwwn);
	fcio.fcio_cmd = FCIO_SEND_NODE_ID;
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_cmd_flags = nodeIdDataFormat;
	fcio.fcio_ilen = sizeof (la_wwn_t);
	fcio.fcio_ibuf = (caddr_t)&netdestwwn;
	fcio.fcio_olen  = *RspBufferSize;
	fcio.fcio_obuf  = (char *)new uchar_t[*RspBufferSize];


	if (fcio.fcio_obuf == NULL) {
	    log.noMemory();
	    throw InternalError();
	}

	fp_ioctl(getPath(), FCIO_CMD, &fcio);

	memcpy(pRspBuffer, fcio.fcio_obuf, *RspBufferSize);

	if (fcio.fcio_obuf != NULL) {
	    delete(fcio.fcio_obuf);
	}
}

void FCHBAPort::setRNID(HBA_MGMTINFO info) {
	Trace log("FCHBAPort::setRNID");
	fc_rnid_t		rnid;
	fcio_t			fcio;

	memset(&rnid, 0, sizeof (fc_rnid_t));
	memset((caddr_t)&fcio, 0, sizeof (fcio));


	fcio.fcio_cmd = FCIO_SET_NODE_ID;
	fcio.fcio_ilen = sizeof (fc_rnid_t);
	fcio.fcio_xfer = FCIO_XFER_WRITE;
	fcio.fcio_ibuf = (caddr_t)&rnid;


	// Copy the HBA_MGMTINFO into fc_rnid_t struct
	memcpy(&(rnid.unit_type), &(info.unittype), sizeof (rnid.unit_type));
	memcpy(&(rnid.port_id), &(info.PortId), sizeof (rnid.port_id));
	memcpy(&(rnid.global_id), &(info.wwn), sizeof (info.wwn));
	memcpy(&(rnid.num_attached), &(info.NumberOfAttachedNodes),
		sizeof (rnid.num_attached));
	memcpy(&(rnid.ip_version), &(info.IPVersion), sizeof (rnid.ip_version));
	memcpy(&(rnid.udp_port), &(info.UDPPort), sizeof (rnid.udp_port));
	memcpy(&(rnid.ip_addr), &info.IPAddress, sizeof (rnid.ip_addr));
	memcpy(&(rnid.topo_flags), &(info.TopologyDiscoveryFlags),
		sizeof (rnid.topo_flags));

	fp_ioctl(getPath(), FCIO_CMD, &fcio, O_NDELAY | O_RDONLY | O_EXCL);
}

void FCHBAPort::fp_ioctl(string path, int cmd, fcio_t *fcio, int openflag) {
	Trace log("FCHBAPort::fp_ioctl with openflag");
	char fcioErrorString[MAX_FCIO_MSG_LEN] = "";
	int fd = HBA::_open(path, openflag);
	try {
	    int times = 0;
	    HBA::_ioctl(fd, cmd, (uchar_t *)fcio);
	    while (fcio->fcio_errno == FC_STATEC_BUSY) {
		sleep(1);
		HBA::_ioctl(fd, cmd, (uchar_t *)fcio);
		if (times++ > 10) {
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
	    log.genericIOError("ioctl (0x%x) failed. Transport: \"%s\"", cmd,
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

void FCHBAPort::fp_ioctl(string path, int cmd, fcio_t *fcio) {
	Trace log("FCHBAPort::fp_ioctl");
	fp_ioctl(path, cmd, fcio, O_NDELAY | O_RDONLY);
}

void FCHBAPort::fcsm_ioctl(int cmd, fcio_t *fcio) {
	// We use the same error handling as fp, so just re-use
	fp_ioctl(FCSM_DRIVER_PATH, cmd, fcio);
}
