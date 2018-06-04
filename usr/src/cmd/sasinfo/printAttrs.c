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

#include <ctype.h>
#include <printAttrs.h>

static SAS_STATE hbastatus_string[] = {
	HBA_STATUS_OK,				"Okay",
	HBA_STATUS_ERROR,			"Error",
	HBA_STATUS_ERROR_NOT_SUPPORTED,		"Not Supported",
	HBA_STATUS_ERROR_INVALID_HANDLE,	"Invalid Handle",
	HBA_STATUS_ERROR_ARG,			"Argument Error",
	HBA_STATUS_ERROR_ILLEGAL_WWN,		"Illegal WWN",
	HBA_STATUS_ERROR_ILLEGAL_INDEX,		"Illegal Index",
	HBA_STATUS_ERROR_MORE_DATA,		"Not Enough Buffer for Data",
	HBA_STATUS_ERROR_STALE_DATA,		"Stale Data",
	HBA_STATUS_SCSI_CHECK_CONDITION,	"SCSI Check Condition",
	HBA_STATUS_ERROR_BUSY,			"Busy",
	HBA_STATUS_ERROR_TRY_AGAIN,		"Try Again",
	HBA_STATUS_ERROR_UNAVAILABLE,		"Unavailable",
	HBA_STATUS_ERROR_ELS_REJECT,		"ELS Reject",
	HBA_STATUS_ERROR_INVALID_LUN,		"Invalid LUN",
	HBA_STATUS_ERROR_INCOMPATIBLE,		"Request Incompatible",
	HBA_STATUS_ERROR_AMBIGUOUS_WWN,		"Ambiguous WWN",
	HBA_STATUS_ERROR_LOCAL_BUS,		"Local Bus Error",
	HBA_STATUS_ERROR_LOCAL_TARGET,		"Local Target Error",
	HBA_STATUS_ERROR_LOCAL_LUN,		"Local LUN Error",
	HBA_STATUS_ERROR_LOCAL_SCSIID_BOUND,	"Local SCSIID Bound",
	HBA_STATUS_ERROR_TARGET_FCID,		"Target FCID Error",
	HBA_STATUS_ERROR_TARGET_NODE_WWN,	"Target Node WWN Error",
	HBA_STATUS_ERROR_TARGET_PORT_WWN,	"Target Port WWN Error",
	HBA_STATUS_ERROR_TARGET_LUN,		"Target LUN Error",
	HBA_STATUS_ERROR_TARGET_LUID,		"Target LUID Error",
	HBA_STATUS_ERROR_NO_SUCH_BINDING,	"No Such Binding",
	HBA_STATUS_ERROR_NOT_A_TARGET,		"Not a Target",
	HBA_STATUS_ERROR_UNSUPPORTED_FC4,	"Unsupported FC4",
	HBA_STATUS_ERROR_INCAPABLE,		"Incapable",
	HBA_STATUS_ERROR_TARGET_BUSY,		"Target Busy",
	HBA_STATUS_ERROR_NOT_LOADED,		"Not Loaded",
	HBA_STATUS_ERROR_ALREADY_LOADED,	"Alreday Loaded",
	HBA_STATUS_ERROR_ILLEGAL_FCID,		"Illegal FCID",
	HBA_STATUS_ERROR_NOT_ASCSIDEVICE,	"Not a SCSI Device",
	HBA_STATUS_ERROR_INVALID_PROTOCOL_TYPE,	"Invalid Protocol Type",
	HBA_STATUS_ERROR_BAD_EVENT_TYPE,	"Bad Event Type",
	-1,					NULL
};

SAS_STATE porttype_string[] = {
	HBA_PORTTYPE_UNKNOWN,		"UNKNOWN",
	HBA_PORTTYPE_OTHER,		"OTHER",
	HBA_PORTTYPE_NOTPRESENT,	"NOT Present",
	HBA_PORTTYPE_SASDEVICE,		"SAS Device",
	HBA_PORTTYPE_SATADEVICE,	"SATA Device",
	HBA_PORTTYPE_SASEXPANDER, 	"SAS Expander",
	-1,				NULL,
};

SAS_STATE portstate_string[] = {
	HBA_PORTSTATE_UNKNOWN,		"unknown",
	HBA_PORTSTATE_ONLINE,		"online",
	HBA_PORTSTATE_OFFLINE,		"offline",
	HBA_PORTSTATE_BYPASSED,		"bypassed",
	HBA_PORTSTATE_DIAGNOSTICS,	"diagnostics",
	HBA_PORTSTATE_LINKDOWN,		"link Down",
	HBA_PORTSTATE_ERROR,		"port Error",
	HBA_PORTSTATE_LOOPBACK,		"loopback",
	HBA_PORTSTATE_DEGRADED,		"degraded",
	-1,				NULL,
};

static SAS_STATE phystate_string[] = {
	HBA_SASSTATE_UNKNOWN,		"unknown",
	HBA_SASSTATE_DISABLED,		"disabled",
	HBA_SASSTATE_FAILED,		"failed",
	HBA_SASSTATE_SATASPINUP,	"sata-spinup",
	HBA_SASSTATE_SATAPORTSEL,	"sata-portselector",
	HBA_SASSPEED_1_5GBIT,		"1.5Gbit",
	HBA_SASSPEED_3GBIT,		"3Gbit",
	HBA_SASSPEED_6GBIT,		"6Gbit",
	HBA_SASSPEED_12GBIT,		"12Gbit",
	-1,				NULL,
};

static SAS_STATE dtype_string[] = {
	DTYPE_DIRECT,			"Disk Device",
	DTYPE_SEQUENTIAL,		"Tape Device",
	DTYPE_PRINTER,			"Printer Device",
	DTYPE_PROCESSOR,		"Processor Device",
	DTYPE_WORM,			"WORM Device",
	DTYPE_RODIRECT,			"CD/DVD Device",
	DTYPE_SCANNER,			"Scanner Device",
	DTYPE_OPTICAL,			"Optical Memory Device",
	DTYPE_CHANGER,			"Medium Changer Device",
	DTYPE_COMM,			"Communications Device",
	DTYPE_ARRAY_CTRL,		"Storage Array Controller Device",
	DTYPE_ESI,			"Enclosure Services Device",
	DTYPE_RBC,			"Simplified Direct-access Device",
	DTYPE_OCRW,			"Optical Card Reader/Writer Device",
	DTYPE_BCC,			"Bridge Controller Commands",
	DTYPE_OSD,			"Object-based Storage Device",
	DTYPE_ADC,			"Automation/Drive Interface",
	DTYPE_WELLKNOWN,		"Well Known Logical Unit",
	DTYPE_UNKNOWN,			"Unknown Device",
	-1,				NULL
};

static char *getPhyStateString(HBA_UINT32 key, phystat_type phyt);

char *
getIndentSpaces(int number)
{
	int 		i = 0;
	/* the maximum indent with terminator '\0' */
	static char	ret[MAXINDENT+1];

	if (number > MAXINDENT)
		number = MAXINDENT;

	for (i = 0; i < number; i++) {
		ret[i] = ' ';
	}
	ret[i] = '\0';
	return (ret);
}

char *
getStateString(HBA_UINT32 key, SAS_STATE *stat_string)
{
	static char ret[64];
	while (stat_string->key != -1) {
		if (stat_string->key == key) {
			return ((char *)stat_string->value);
		}
		stat_string++;
	}
	(void *) sprintf(ret, "Undefined value (%d)", key);
	return (ret);
}

static char *
getPhyStateString(HBA_UINT32 key, phystat_type phyt)
{
	int i = 0, len = 0, match = 0;
	HBA_UINT32 physpeed[] = {
		HBA_SASSPEED_1_5GBIT,
		HBA_SASSPEED_3GBIT,
		HBA_SASSPEED_6GBIT,
		HBA_SASSPEED_12GBIT
	};

	len = sizeof (physpeed) / sizeof (HBA_UINT32);
	for (i = 0; i < len; i++) {
		if (key == physpeed[i]) {
			match = 1;
			break;
		}
	}

	if (match == 1) {
		if (phyt == PHY_STATE)
			return ("enabled");
		else
			return (getStateString(key, phystate_string));
	} else {
		if (phyt == PHY_STATE)
			return (getStateString(key, phystate_string));
		else
			return ("not available");
	}
}

char *
getHBAStatus(HBA_STATUS key)
{
	return (getStateString(key, hbastatus_string));
}

/*
 * return device type description
 *
 * Arguments:
 *	dType - Device type returned from Standard INQUIRY
 * Returns:
 *	char string description for device type
 */
char *
getDTypeString(uchar_t dType)
{
	return (getStateString((dType & DTYPE_MASK), dtype_string));
}

uint64_t
wwnConversion(uchar_t *wwn)
{
	uint64_t tmp;
	(void *) memcpy(&tmp, wwn, sizeof (uint64_t));
	return (ntohll(tmp));
}

/*
 * prints out HBA information
 */
void
printHBAInfo(SMHBA_ADAPTERATTRIBUTES *attrs, int pflag, int numberOfPorts,
    const char *adapterName)
{

	(void *) fprintf(stdout, "%s %s\n", "HBA Name:", adapterName);

	if (pflag & PRINT_VERBOSE) {
		(void *) fprintf(stdout, "%s%s %s\n",
		    getIndentSpaces(4), "Manufacturer:",
		    attrs->Manufacturer[0] == 0?
		    "not available":attrs->Manufacturer);
		(void *) fprintf(stdout, "%s%s %s\n",
		    getIndentSpaces(4), "Model: ",
		    attrs->Model[0] == 0? "not available":attrs->Model);
		(void *) fprintf(stdout, "%s%s %s\n",
		    getIndentSpaces(4),
		    "Firmware Version:",
		    attrs->FirmwareVersion[0] == 0? "not available":
		    attrs->FirmwareVersion);
		(void *) fprintf(stdout, "%s%s %s\n",
		    getIndentSpaces(4),
		    "FCode/BIOS Version:",
		    attrs->OptionROMVersion[0] == 0? "not available":
		    attrs->OptionROMVersion);
		(void *) fprintf(stdout, "%s%s %s\n",
		    getIndentSpaces(4),
		    "Serial Number:",
		    attrs->SerialNumber[0] == 0? "not available":
		    attrs->SerialNumber);
		(void *) fprintf(stdout, "%s%s %s\n",
		    getIndentSpaces(4),
		    "Driver Name:",
		    attrs->DriverName[0] == 0? "not available":
		    attrs->DriverName);
		(void *) fprintf(stdout, "%s%s %s\n",
		    getIndentSpaces(4),
		    "Driver Version:",
		    attrs->DriverVersion[0] == 0? "not available":
		    attrs->DriverVersion);
		(void *) fprintf(stdout, "%s%s %d\n",
		    getIndentSpaces(4),
		    "Number of HBA Ports:",
		    numberOfPorts);
	}
}

/*
 * prints out all the HBA port information
 */
void
printHBAPortInfo(SMHBA_PORTATTRIBUTES *port,
    SMHBA_ADAPTERATTRIBUTES *attrs, int pflag) {

	if ((port == NULL) || (attrs == NULL)) {
		return;
	}

	(void *) fprintf(stdout, "%s%s %s\n",
	    getIndentSpaces(2),
	    "HBA Port Name:",
	    port->OSDeviceName);

	if (!(pflag & PRINT_VERBOSE)) {
		return;
	}

	if (port->PortType != HBA_PORTTYPE_SASDEVICE)
		return;

	(void *) fprintf(stdout, "%s%s %s\n",
	    getIndentSpaces(4),
	    "Type:",
	    getStateString(port->PortType, porttype_string));
	(void *) fprintf(stdout, "%s%s %s\n",
	    getIndentSpaces(4),
	    "State:",
	    getStateString(port->PortState, portstate_string));

	(void *) fprintf(stdout, "%s%s %016llx\n",
	    getIndentSpaces(4),
	    "Local SAS Address:",
	    wwnConversion(port->PortSpecificAttribute.SASPort->\
	    LocalSASAddress.wwn));

	(void *) fprintf(stdout, "%s%s %016llx\n",
	    getIndentSpaces(4),
	    "Attached SAS Address:",
	    wwnConversion(port->PortSpecificAttribute.SASPort->\
	    AttachedSASAddress.wwn));

	(void *) fprintf(stdout, "%s%s %d\n",
	    getIndentSpaces(4),
	    "Number of Phys:",
	    port->PortSpecificAttribute.SASPort->NumberofPhys);
}

void
printHBAPortPhyInfo(SMHBA_SAS_PHY *phyinfo)
{
	if (phyinfo == NULL)
		return;

	(void *) fprintf(stdout, "%s%s %u\n",
	    getIndentSpaces(6),
	    "Identifier:",
	    phyinfo->PhyIdentifier);

	(void *) fprintf(stdout, "%s%s %s\n",
	    getIndentSpaces(8),
	    "State: ",
	    getPhyStateString(phyinfo->NegotiatedLinkRate, PHY_STATE));
	(void *) fprintf(stdout, "%s%s %s/%s\n",
	    getIndentSpaces(8),
	    "HardwareLinkRate(Min/Max):",
	    getPhyStateString(phyinfo->HardwareMinLinkRate, PHY_SPEED),
	    getPhyStateString(phyinfo->HardwareMaxLinkRate, PHY_SPEED));
	(void *) fprintf(stdout, "%s%s %s/%s\n",
	    getIndentSpaces(8),
	    "ProgrammedLinkRate(Min/Max):",
	    getPhyStateString(phyinfo->ProgrammedMinLinkRate, PHY_SPEED),
	    getPhyStateString(phyinfo->ProgrammedMaxLinkRate, PHY_SPEED));
	(void *) fprintf(stdout, "%s%s %s\n",
	    getIndentSpaces(8),
	    "NegotiatedLinkRate:",
	    getPhyStateString(phyinfo->NegotiatedLinkRate, PHY_SPEED));
}

void
printHBAPortPhyStatistics(SMHBA_SASPHYSTATISTICS *phystat)
{
	if (phystat == NULL)
		return;

	(void *) fprintf(stdout, "%s%s\n",
	    getIndentSpaces(8),
	    "Link Error Statistics:");
	(void *) fprintf(stdout, "%s%s %llu\n",
	    getIndentSpaces(12),
	    "Invalid Dword:",
	    phystat->InvalidDwordCount);
	(void *) fprintf(stdout, "%s%s %llu\n",
	    getIndentSpaces(12),
	    "Running Disparity Error:",
	    phystat->RunningDisparityErrorCount);
	(void *) fprintf(stdout, "%s%s %llu\n",
	    getIndentSpaces(12),
	    "Loss of Dword Sync:",
	    phystat->LossofDwordSyncCount);
	(void *) fprintf(stdout, "%s%s %llu\n",
	    getIndentSpaces(12),
	    "Reset Problem:",
	    phystat->PhyResetProblemCount);
}

/*
 * print the OS device name for the logical-unit object
 *
 * Arguments:
 *	devListWalk - OS device path info
 *	verbose - boolean indicating whether to display additional info
 *
 * returns:
 * 	0 - we're good.
 * 	>0 - we met issues.
 */
int
printTargetPortInfo(targetPortList_t *TPListWalk, int pflag)
{
	targetPortConfig_t	*configList;
	targetPortMappingData_t	*mapList;
	int			count, i;
	int			ret = 0;

	(void *) fprintf(stdout, "Target Port SAS Address: %016llx\n",
	    wwnConversion(TPListWalk->sasattr.LocalSASAddress.wwn));
	if ((pflag & PRINT_VERBOSE) || (pflag & PRINT_TARGET_SCSI)) {
		(void *) fprintf(stdout, "%sType: %s\n", getIndentSpaces(4),
		    getStateString(TPListWalk->targetattr.PortType,
		    porttype_string));
		for (configList = TPListWalk->configEntry;
		    configList != NULL; configList = configList->next) {
			(void *) fprintf(stdout, "%sHBA Port Name: %s\n",
			    getIndentSpaces(4), configList->hbaPortName);
			if (wwnConversion(configList->expanderSASAddr.wwn) !=
			    0) {
				if (configList->expanderValid) {
					(void *) fprintf(stdout,
					    "%sExpander Device SAS Address:"
					    " %016llx",
					    getIndentSpaces(8),
					    wwnConversion(configList->
					    expanderSASAddr.wwn));
				} else {
					(void *) fprintf(stdout,
					    "%sExpander Device SAS Address:"
					    " %016llx (Failed to Validate"
					    " Attached Port.)",
					    getIndentSpaces(8),
					    wwnConversion(configList->
					    expanderSASAddr.wwn));
					ret++;
				}
			} else {
				if (configList->expanderValid) {
					(void *) fprintf(stdout,
					    "%sExpander Device SAS Address: %s",
					    getIndentSpaces(8),
					    "None (direct attached)");
				} else {
					(void *) fprintf(stdout,
					    "%sExpander Device SAS Address: %s",
					    getIndentSpaces(8),
					    "None (Failed to Get"
					    " Attached Port)");
				}
			}
			(void *) fprintf(stdout, "\n");
			if (pflag & PRINT_TARGET_SCSI) {

				if (configList->reportLUNsFailed) {
					(void *) fprintf(stdout,
					    "%s %016llx\n",
					    gettext("Error: Failed to get "
					    "ReportLun Data on"),
					    wwnConversion(TPListWalk->
					    sasattr.LocalSASAddress.wwn));
					ret++;
					continue;
				}

				for (mapList = configList->map;
				    mapList != NULL; mapList = mapList->next) {
					(void *) fprintf(stdout, "%sLUN : %d\n",
					    getIndentSpaces(12),
					    mapList->osLUN);
					if (mapList->mappingExist) {
						(void *) fprintf(stdout,
						    "%sOS Device Name : %s\n",
						    getIndentSpaces(14),
						    (mapList->osDeviceName[0] ==
						    '\0') ?  "Not avaialble" :
						    mapList->osDeviceName);
					} else {
						(void *) fprintf(stdout,
						    "%sOS Device Name : %s\n",
						    getIndentSpaces(14), "No "
						    "matching OS Device "
						    "found.");
						ret++;
					}
		/* indentation changed here */
		if (mapList->inquiryFailed) {
			(void *) fprintf(stdout, "%s %s LUN %d\n",
			    gettext("Error: Failed to get Inquiry Data on"),
			    mapList->osDeviceName, mapList->osLUN);
			ret++;
		} else {
			(void *) fprintf(stdout, "%sVendor: ",
			    getIndentSpaces(14));
			for (count = sizeof (mapList->inq_vid), i = 0;
			    i < count; i++) {
				if (isprint(mapList->inq_vid[i]))
					(void *) fprintf(stdout, "%c",
					    mapList->inq_vid[i]);
			}

			(void *) fprintf(stdout, "\n%sProduct: ",
			    getIndentSpaces(14));
			for (count = sizeof (mapList->inq_pid), i = 0;
			    i < count; i++) {
				if (isprint(mapList->inq_pid[i]))
					(void *) fprintf(stdout, "%c",
					    mapList->inq_pid[i]);
			}

			(void *) fprintf(stdout, "\n%sDevice Type: %s\n",
			    getIndentSpaces(14),
			    getDTypeString(mapList->inq_dtype));
		}
		/* indentation changed back */
				}
			}
		}
	}
	return (ret);
}

/*
 * print the OS device name for the logical-unit object
 *
 * Arguments:
 *	devListWalk - OS device path info
 *	verbose - boolean indicating whether to display additional info
 *
 * returns:
 * 	0 - we're good.
 * 	>0 - we met issues.
 */
int
printOSDeviceNameInfo(discoveredDevice *devListWalk, boolean_t verbose)
{
	portList		*portElem;
	tgtPortWWNList		*tgtWWNList;
	int			i, count;
	int			ret = 0;

	(void *) fprintf(stdout, "OS Device Name: %s\n",
	    devListWalk->OSDeviceName);
	if (verbose == B_TRUE) {
		for (portElem = devListWalk->HBAPortList;
		    portElem != NULL; portElem = portElem->next) {
			(void *) fprintf(stdout, "%sHBA Port Name: ",
			    getIndentSpaces(4));
			(void *) fprintf(stdout, "%s", portElem->portName);
			for (tgtWWNList = portElem->tgtPortWWN;
			    tgtWWNList != NULL; tgtWWNList = tgtWWNList->next) {
				(void *) fprintf(stdout,
				    "\n%sTarget Port SAS Address: ",
				    getIndentSpaces(8));
				(void *) fprintf(stdout, "%016llx",
				    wwnConversion(tgtWWNList->portWWN.wwn));
				(void *) fprintf(stdout, "\n%sLUN: %u",
				    getIndentSpaces(12),
				    tgtWWNList->scsiOSLun);
			}
			(void *) fprintf(stdout, "\n");
		}

		if (devListWalk->inquiryFailed) {
			(void *) fprintf(stdout, "%s %s\n",
			    gettext("Error: Failed to get Inquiry data "
			    "on device"), devListWalk->OSDeviceName);
			ret++;
		} else {
			(void *) fprintf(stdout, "%sVendor: ",
			    getIndentSpaces(4));
			for (count = sizeof (devListWalk->VID), i = 0;
			    i < count; i++) {
				if (isprint(devListWalk->VID[i]))
					(void *) fprintf(stdout, "%c",
					    devListWalk->VID[i]);
			}

			(void *) fprintf(stdout, "\n%sProduct: ",
			    getIndentSpaces(4));
			for (count = sizeof (devListWalk->PID), i = 0;
			    i < count; i++) {
				if (isprint(devListWalk->PID[i]))
					(void *) fprintf(stdout, "%c",
					    devListWalk->PID[i]);
			}

			(void *) fprintf(stdout, "\n%sDevice Type: %s\n",
			    getIndentSpaces(4),
			    getDTypeString(devListWalk->dType));
		}
	}
	return (ret);
}
