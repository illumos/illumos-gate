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
 * Copyright 2020 RackTop Systems, Inc.
 */



#include <stdio.h>
#include <hbaapi.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <ctype.h>
#include "fcinfo.h"

#ifdef _BIG_ENDIAN
#define	htonll(x)   (x)
#define	ntohll(x)   (x)
#else
#define	htonll(x)   ((((unsigned long long)htonl(x)) << 32) + htonl(x >> 32))
#define	ntohll(x)   ((((unsigned long long)ntohl(x)) << 32) + ntohl(x >> 32))
#endif

/* Fc4 Types Format */
#define	FC4_TYPE_WORD_POS(x)	    ((uint_t)((uint_t)(x) >> 5))
#define	FC4_TYPE_BIT_POS(x)	    ((uchar_t)(x) & 0x1F)

#define	TYPE_IP_FC		    0x05
#define	TYPE_SCSI_FCP		    0x08

static int fc4_map_is_set(uint32_t *map, uchar_t ulp_type);
static char *getPortType(HBA_PORTTYPE portType);
static char *getPortState(HBA_PORTSTATE portState);
static void printPortSpeed(HBA_PORTSPEED portSpeed);
static char *getDTypeString(uchar_t dType);

uint64_t wwnConversion(uchar_t *wwn) {
	uint64_t tmp;
	memcpy(&tmp, wwn, sizeof (uint64_t));
	return (ntohll(tmp));
}

static char *
getPortType(HBA_PORTTYPE portType) {
	switch (portType) {
	case HBA_PORTTYPE_UNKNOWN:
	    return ("unknown");
	case HBA_PORTTYPE_OTHER:
	    return ("other");
	case HBA_PORTTYPE_NOTPRESENT:
	    return ("not present");
	case HBA_PORTTYPE_NPORT:
	    return ("N-port");
	case HBA_PORTTYPE_NLPORT:
	    return ("NL-port");
	case HBA_PORTTYPE_FLPORT:
	    return ("FL-port");
	case HBA_PORTTYPE_FPORT:
	    return ("F-port");
	case HBA_PORTTYPE_LPORT:
	    return ("L-port");
	case HBA_PORTTYPE_PTP:
	    return ("point-to-point");
	default:
	    return ("unrecognized type");
	}
}

static char *
getPortState(HBA_PORTSTATE portState) {
	switch (portState) {
	case HBA_PORTSTATE_UNKNOWN:
	    return ("unknown");
	case HBA_PORTSTATE_ONLINE:
	    return ("online");
	case HBA_PORTSTATE_OFFLINE:
	    return ("offline");
	case HBA_PORTSTATE_BYPASSED:
	    return ("bypassed");
	case HBA_PORTSTATE_DIAGNOSTICS:
	    return ("diagnostics");
	case HBA_PORTSTATE_LINKDOWN:
	    return ("link down");
	case HBA_PORTSTATE_ERROR:
	    return ("error");
	case HBA_PORTSTATE_LOOPBACK:
	    return ("loopback");
	default:
	    return ("unrecognized state");
	}
}

static void
printPortSpeed(HBA_PORTSPEED portSpeed) {
	int foundSpeed = 0;

	if ((portSpeed & HBA_PORTSPEED_1GBIT) == HBA_PORTSPEED_1GBIT) {
		fprintf(stdout, "1Gb ");
		foundSpeed = 1;
	}
	if ((portSpeed & HBA_PORTSPEED_2GBIT) == HBA_PORTSPEED_2GBIT) {
		fprintf(stdout, "2Gb ");
		foundSpeed = 1;
	}
	if ((portSpeed & HBA_PORTSPEED_4GBIT) == HBA_PORTSPEED_4GBIT) {
		fprintf(stdout, "4Gb ");
		foundSpeed = 1;
	}
	if ((portSpeed & HBA_PORTSPEED_8GBIT) == HBA_PORTSPEED_8GBIT) {
		fprintf(stdout, "8Gb ");
		foundSpeed = 1;
	}
	if ((portSpeed & HBA_PORTSPEED_10GBIT) == HBA_PORTSPEED_10GBIT) {
		fprintf(stdout, "10Gb ");
		foundSpeed = 1;
	}
	if ((portSpeed & HBA_PORTSPEED_16GBIT) == HBA_PORTSPEED_16GBIT) {
		fprintf(stdout, "16Gb ");
		foundSpeed = 1;
	}
	if ((portSpeed & HBA_PORTSPEED_32GBIT) == HBA_PORTSPEED_32GBIT) {
		fprintf(stdout, "32Gb ");
		foundSpeed = 1;
	}
	if ((portSpeed & HBA_PORTSPEED_NOT_NEGOTIATED)
	    == HBA_PORTSPEED_NOT_NEGOTIATED) {
		fprintf(stdout, "not established ");
		foundSpeed = 1;
	}
	if (foundSpeed == 0) {
		fprintf(stdout, "not established ");
	}
}

void
printDiscoPortInfo(HBA_PORTATTRIBUTES *discoPort, int scsiTargetType) {
	int fc4_types = 0;

	fprintf(stdout, gettext("Remote Port WWN: %016llx\n"),
	    wwnConversion(discoPort->PortWWN.wwn));
	fprintf(stdout, gettext("\tActive FC4 Types: "));
	if (fc4_map_is_set(
		    (uint32_t *)discoPort->PortActiveFc4Types.bits,
		    TYPE_SCSI_FCP)) {
		fprintf(stdout, gettext("SCSI"));
		fc4_types++;
	}
	if (fc4_map_is_set(
		    (uint32_t *)discoPort->PortActiveFc4Types.bits,
		    TYPE_IP_FC)) {
		if (fc4_types != 0) {
			fprintf(stdout, ",");
		}
		fprintf(stdout, gettext("IP"));
		fc4_types++;
	}
	fprintf(stdout, "\n");

	/* print out scsi target type information */
	fprintf(stdout, gettext("\tSCSI Target: "));
	if (scsiTargetType == SCSI_TARGET_TYPE_YES) {
		fprintf(stdout, gettext("yes\n"));
	} else if (scsiTargetType == SCSI_TARGET_TYPE_NO) {
		fprintf(stdout, gettext("no\n"));
	} else {
		fprintf(stdout, gettext("unknown\n"));
	}
	fprintf(stdout, gettext("\tPort Symbolic Name: %s\n"),
	    discoPort->PortSymbolicName);
	fprintf(stdout, gettext("\tNode WWN: %016llx\n"),
	    wwnConversion(discoPort->NodeWWN.wwn));
}

/*
 * scan the bitmap array for the specifed ULP type. The bit map array
 * is 32 bytes long
 */
static int
fc4_map_is_set(uint32_t *map, uchar_t ulp_type)
{

	map += FC4_TYPE_WORD_POS(ulp_type) * 4;

	if (ntohl((*(uint32_t *)map)) & (1 << FC4_TYPE_BIT_POS(ulp_type))) {
		return (1);
	}

	return (0);
}

/*
 * prints out all the HBA port information
 */
void
printHBAPortInfo(HBA_PORTATTRIBUTES *port,
    HBA_ADAPTERATTRIBUTES *attrs, int mode) {
	if (attrs == NULL || port == NULL) {
		return;
	}
	fprintf(stdout, gettext("HBA Port WWN: %016llx\n"),
		wwnConversion(port->PortWWN.wwn));
	fprintf(stdout, gettext("\tPort Mode: %s\n"),
	    (mode == INITIATOR_MODE) ? "Initiator" : "Target");
	fprintf(stdout, gettext("\tPort ID: %x\n"),
	    port->PortFcId);
	fprintf(stdout, gettext("\tOS Device Name: %s\n"), port->OSDeviceName);

	fprintf(stdout, gettext("\tManufacturer: %s\n"),
	    attrs->Manufacturer);
	fprintf(stdout, gettext("\tModel: %s\n"), attrs->Model);
	fprintf(stdout, gettext("\tFirmware Version: %s\n"),
	    attrs->FirmwareVersion);
	fprintf(stdout, gettext("\tFCode/BIOS Version: %s\n"),
	    attrs->OptionROMVersion);
	fprintf(stdout, gettext("\tSerial Number: %s\n"),
	    attrs->SerialNumber[0] == 0? "not available":attrs->SerialNumber);

	fprintf(stdout, gettext("\tDriver Name: %s\n"),
	    attrs->DriverName[0] == 0? "not available":attrs->DriverName);
	fprintf(stdout, gettext("\tDriver Version: %s\n"),
	    attrs->DriverVersion[0] == 0? "not available":attrs->DriverVersion);

	fprintf(stdout, gettext("\tType: %s\n"),
	    getPortType(port->PortType));
	fprintf(stdout, gettext("\tState: %s\n"),
	    getPortState(port->PortState));

	fprintf(stdout, gettext("\tSupported Speeds: "));
	printPortSpeed(port->PortSupportedSpeed);
	fprintf(stdout, "\n");

	fprintf(stdout, gettext("\tCurrent Speed: "));
	printPortSpeed(port->PortSpeed);
	fprintf(stdout, "\n");

	fprintf(stdout, gettext("\tNode WWN: %016llx\n"),
	    wwnConversion(port->NodeWWN.wwn));
}

void
printStatus(HBA_STATUS status) {
	switch (status) {
		case HBA_STATUS_OK:
			fprintf(stderr, gettext("OK"));
			return;
		case HBA_STATUS_ERROR:
			fprintf(stderr, gettext("ERROR"));
			return;
		case HBA_STATUS_ERROR_NOT_SUPPORTED:
			fprintf(stderr, gettext("NOT SUPPORTED"));
			return;
		case HBA_STATUS_ERROR_INVALID_HANDLE:
			fprintf(stderr, gettext("INVALID HANDLE"));
			return;
		case HBA_STATUS_ERROR_ARG:
			fprintf(stderr, gettext("ERROR ARG"));
			return;
		case HBA_STATUS_ERROR_ILLEGAL_WWN:
			fprintf(stderr, gettext("ILLEGAL WWN"));
			return;
		case HBA_STATUS_ERROR_ILLEGAL_INDEX:
			fprintf(stderr, gettext("ILLEGAL INDEX"));
			return;
		case HBA_STATUS_ERROR_MORE_DATA:
			fprintf(stderr, gettext("MORE DATA"));
			return;
		case HBA_STATUS_ERROR_STALE_DATA:
			fprintf(stderr, gettext("STALE DATA"));
			return;
		case HBA_STATUS_SCSI_CHECK_CONDITION:
			fprintf(stderr, gettext("SCSI CHECK CONDITION"));
			return;
		case HBA_STATUS_ERROR_BUSY:
			fprintf(stderr, gettext("BUSY"));
			return;
		case HBA_STATUS_ERROR_TRY_AGAIN:
			fprintf(stderr, gettext("TRY AGAIN"));
			return;
		case HBA_STATUS_ERROR_UNAVAILABLE:
			fprintf(stderr, gettext("UNAVAILABLE"));
			return;
		default:
			fprintf(stderr, "%s %d",
			    gettext("Undefined error code "), status);
			return;
	}
}

void
printLUNInfo(struct scsi_inquiry *inq, HBA_UINT32 scsiLUN, char *devpath) {
	fprintf(stdout, "\tLUN: %d\n", scsiLUN);
	fprintf(stdout, "\t  Vendor: %c%c%c%c%c%c%c%c\n",
	    inq->inq_vid[0],
	    inq->inq_vid[1],
	    inq->inq_vid[2],
	    inq->inq_vid[3],
	    inq->inq_vid[4],
	    inq->inq_vid[5],
	    inq->inq_vid[6],
	    inq->inq_vid[7]);
	fprintf(stdout, "\t  Product: %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
		    inq->inq_pid[0],
		    inq->inq_pid[1],
		    inq->inq_pid[2],
		    inq->inq_pid[3],
		    inq->inq_pid[4],
		    inq->inq_pid[5],
		    inq->inq_pid[6],
		    inq->inq_pid[7],
		    inq->inq_pid[8],
		    inq->inq_pid[9],
		    inq->inq_pid[10],
		    inq->inq_pid[11],
		    inq->inq_pid[12],
		    inq->inq_pid[13],
		    inq->inq_pid[14],
		    inq->inq_pid[15]);
	fprintf(stdout, gettext("\t  OS Device Name: %s\n"), devpath);
}

void
printPortStat(fc_rls_acc_t *rls_payload) {
	fprintf(stdout, gettext("\tLink Error Statistics:\n"));
	fprintf(stdout, gettext("\t\tLink Failure Count: %u\n"),
	    rls_payload->rls_link_fail);
	fprintf(stdout, gettext("\t\tLoss of Sync Count: %u\n"),
	    rls_payload->rls_sync_loss);
	fprintf(stdout, gettext("\t\tLoss of Signal Count: %u\n"),
	    rls_payload->rls_sig_loss);
	fprintf(stdout, gettext("\t\tPrimitive Seq Protocol Error Count: %u\n"),
	    rls_payload->rls_prim_seq_err);
	fprintf(stdout, gettext("\t\tInvalid Tx Word Count: %u\n"),
	    rls_payload->rls_invalid_word);
	fprintf(stdout, gettext("\t\tInvalid CRC Count: %u\n"),
	    rls_payload->rls_invalid_crc);
}

/*
 * return device type description
 *
 * Arguments:
 *	dType - Device type returned from Standard INQUIRY
 * Returns:
 *	char string description for device type
 */
static char *
getDTypeString(uchar_t dType)
{
	switch (dType & DTYPE_MASK) {
		case DTYPE_DIRECT:
			return ("Disk Device");
		case DTYPE_SEQUENTIAL:
			return ("Tape Device");
		case DTYPE_PRINTER:
			return ("Printer Device");
		case DTYPE_PROCESSOR:
			return ("Processor Device");
		case DTYPE_WORM:
			return ("WORM Device");
		case DTYPE_RODIRECT:
			return ("CD/DVD Device");
		case DTYPE_SCANNER:
			return ("Scanner Device");
		case DTYPE_OPTICAL:
			return ("Optical Memory Device");
		case DTYPE_CHANGER:
			return ("Medium Changer Device");
		case DTYPE_COMM:
			return ("Communications Device");
		case DTYPE_ARRAY_CTRL:
			return ("Storage Array Controller Device");
		case DTYPE_ESI:
			return ("Enclosure Services Device");
		case DTYPE_RBC:
			return ("Simplified Direct-access Device");
		case DTYPE_OCRW:
			return ("Optical Card Reader/Writer Device");
		case DTYPE_BCC:
			return ("Bridge Controller Commands");
		case DTYPE_OSD:
			return ("Object-based Storage Device");
		case DTYPE_ADC:
			return ("Automation/Drive Interface");
		case DTYPE_WELLKNOWN:
			return ("Well Known Logical Unit");
		case DTYPE_UNKNOWN:
			return ("Unknown Device");
		default:
			return ("Undefined");
	}
}

/*
 * print the OS device name for the logical-unit object
 *
 * Arguments:
 *	devListWalk - OS device path info
 *	verbose - boolean indicating whether to display additional info
 *
 * returns:
 *	none
 */
void
printOSDeviceNameInfo(discoveredDevice *devListWalk, boolean_t verbose)
{
	portWWNList		*WWNList;
	tgtPortWWNList		*tgtWWNList;
	int			i, count;

	fprintf(stdout, "OS Device Name: %s\n", devListWalk->OSDeviceName);
	if (verbose == B_TRUE) {
		for (WWNList = devListWalk->HBAPortWWN;
		    WWNList != NULL; WWNList = WWNList->next) {
			fprintf(stdout, "\tHBA Port WWN: ");
			fprintf(stdout, "%016llx",
			    wwnConversion(WWNList->portWWN.wwn));
			for (tgtWWNList = WWNList->tgtPortWWN;
			    tgtWWNList != NULL; tgtWWNList = tgtWWNList->next) {
				fprintf(stdout, "\n\t\tRemote Port WWN: ");
				fprintf(stdout, "%016llx",
				    wwnConversion(tgtWWNList->portWWN.wwn));
				fprintf(stdout, "\n\t\t\tLUN: %d",
				    tgtWWNList->scsiOSLun);
			}
			fprintf(stdout, "\n");
		}

		fprintf(stdout, "\tVendor: ");
		for (count = sizeof (devListWalk->VID), i = 0; i < count; i++) {
			if (isprint(devListWalk->VID[i]))
				fprintf(stdout, "%c", devListWalk->VID[i]);
		}

		fprintf(stdout, "\n\tProduct: ");
		for (count = sizeof (devListWalk->PID), i = 0; i < count; i++) {
			if (isprint(devListWalk->PID[i]))
				fprintf(stdout, "%c", devListWalk->PID[i]);
		}

		fprintf(stdout, "\n\tDevice Type: %s\n",
		    getDTypeString(devListWalk->dType));
	}
}
