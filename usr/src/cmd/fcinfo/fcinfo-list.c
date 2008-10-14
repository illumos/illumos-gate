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


#include "fcinfo.h"
#include <libintl.h>

struct lun {
	uchar_t val[8];
};

typedef enum {
    HBA_PORT,
    REMOTE_PORT,
    LOGICAL_UNIT
} resource_type;

typedef struct rep_luns_rsp {
	uint32_t    length;
	uint32_t    rsrvd;
	struct lun  lun[1];
} rep_luns_rsp_t;

static int getTargetMapping(HBA_HANDLE, HBA_WWN myhbaPortWWN,
    HBA_FCPTARGETMAPPINGV2 **mapping);
static int processHBA(HBA_HANDLE handle, HBA_ADAPTERATTRIBUTES attrs,
    int portIndex, HBA_PORTATTRIBUTES port, HBA_FCPTARGETMAPPINGV2 *map,
    int resourceType, int flags, int mode);
static void processRemotePort(HBA_HANDLE handle, HBA_WWN portWWN,
    HBA_FCPTARGETMAPPINGV2 *map, int wwnCount, char **wwn_argv, int flags);
static void handleRemotePort(HBA_HANDLE handle, HBA_WWN portWWN,
    HBA_WWN myRemotePortWWN, HBA_PORTATTRIBUTES *discPort);
static void printLinkStat(HBA_HANDLE handle, HBA_WWN hbaportWWN,
    HBA_WWN destWWN);
static void handleScsiTarget(HBA_HANDLE handle, HBA_WWN hbaPortWWN,
    HBA_WWN scsiTargetWWN, HBA_FCPTARGETMAPPINGV2 *map);
static int retrieveAttrs(HBA_HANDLE handle, HBA_WWN hbaPortWWN,
    HBA_ADAPTERATTRIBUTES *attrs, HBA_PORTATTRIBUTES *port, int *portIndex);
static void searchDevice(discoveredDevice **devList, HBA_FCPSCSIENTRYV2 entry,
    HBA_WWN initiatorPortWWN, HBA_HANDLE handle, boolean_t verbose);

/*
 * This function retrieve the adapater attributes, port attributes, and
 * portIndex for the given handle and hba port WWN.
 *
 * Arguments:
 *	handle	    an HBA_HANDLE to a adapter
 *	hbaPortWWN  WWN of the port on the adapter to which to retrieve
 *			HBA_PORTATTRIBUTES from
 *	attrs	    pointer to a HBA_ADAPTERATTRIBUTES structure.  Upon
 *			successful completion, this structure will be filled in
 *	port	    pointer to a HBA_PORTATTRIBUTES structure.  Upon successful
 *			completion, this structure will be fill in
 *	portIndex   the Index count of the port on the adapter that is
 *			associated with the WWN.
 *
 * Returns
 *	0	    successfully retrieve all information
 *	>0	    otherwise
 */
static int
retrieveAttrs(HBA_HANDLE handle, HBA_WWN hbaPortWWN,
    HBA_ADAPTERATTRIBUTES *attrs, HBA_PORTATTRIBUTES *port, int *portIndex)
{
	HBA_STATUS		status;
	int			portCtr;
	int			times;

	/* argument checking */
	if (attrs == NULL || port == NULL || portIndex == NULL) {
		fprintf(stderr, gettext("Error: Invalid arguments to "
			    "retreiveAttrs\n"));
		return (1);
	}

	/* retrieve Adapter attributes */
	memset(attrs, 0, sizeof (HBA_ADAPTERATTRIBUTES));
	status = HBA_GetAdapterAttributes(handle, attrs);
	times = 0;
	while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) &&
	    times++ < HBA_MAX_RETRIES) {
		(void) sleep(1);
		status = HBA_GetAdapterAttributes(handle, attrs);
		if (status == HBA_STATUS_OK) {
			break;
		}
	}
	if (status != HBA_STATUS_OK) {
		fprintf(stderr, gettext("Failed to get adapter "
		    "attributes handle(%d) Reason: "), handle);
		printStatus(status);
		fprintf(stderr, "\n");
		return (1);
	}

	/*
	 * find the corresponding port on the adapter and retrieve
	 * port attributes as well as the port index
	 */
	memset(port,  0, sizeof (HBA_PORTATTRIBUTES));
	for (portCtr = 0; portCtr < attrs->NumberOfPorts; portCtr++) {
		if ((status = HBA_GetAdapterPortAttributes(handle,
				    portCtr, port)) != HBA_STATUS_OK) {
			fprintf(stderr,
			    gettext("Error: Failed to get port (%d) "
				    "attributes reason: "), portCtr);
			printStatus(status);
			fprintf(stderr, "\n");
			return (1);
		}
		if (memcmp(hbaPortWWN.wwn, port->PortWWN.wwn,
			    sizeof (port->PortWWN.wwn)) == 0) {
			break;
		}
	}
	if (portCtr >= attrs->NumberOfPorts) {
		/*
		 * not able to find corresponding port WWN
		 * returning an error
		 */
		*portIndex = 0;
		return (1);
	}
	*portIndex = portCtr;
	return (0);
}

/*
 * This function retrieves target mapping information for the HBA port WWN.
 * This function will allocate space for the mapping structure which the caller
 * must free when they are finished
 *
 * Arguments:
 *	handle - a handle to a HBA that we will be processing
 *	hbaPortWWN - the port WWN for the HBA port to retrieve the mappings for
 *	mapping - a pointer to a pointer for the target mapping structure
 *	    Upon successful completion of this function, *mapping will contain
 *	    the target mapping information
 *
 * returns:
 *	0	if successful
 *	1	otherwise
 */
static int
getTargetMapping(HBA_HANDLE handle, HBA_WWN hbaPortWWN,
    HBA_FCPTARGETMAPPINGV2 **mapping)
{
	HBA_FCPTARGETMAPPINGV2	*map;
	HBA_STATUS		status;
	int			count;

	/* argument sanity checking */
	if (mapping == NULL) {
		fprintf(stderr, gettext("Internal Error: mapping is NULL"));
		return (1);
	}
	*mapping = NULL;
	if ((map = calloc(1, sizeof (HBA_FCPTARGETMAPPINGV2))) == NULL) {
		fprintf(stderr,
		    gettext("Internal Error: Unable to calloc map"));
		return (1);
	}
	status = HBA_GetFcpTargetMappingV2(handle, hbaPortWWN, map);
	count = map->NumberOfEntries;
	if (status == HBA_STATUS_ERROR_MORE_DATA) {
		free(map);
		if ((map = calloc(1, (sizeof (HBA_FCPSCSIENTRYV2)*(count-1)) +
				    sizeof (HBA_FCPTARGETMAPPINGV2))) == NULL) {
			fprintf(stderr,
			    gettext("Unable to calloc map of size: %d"), count);
			return (1);
		}
		map->NumberOfEntries = count;
		status = HBA_GetFcpTargetMappingV2(handle, hbaPortWWN, map);
	}
	if (status != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Error: Unable to get Target Mapping\n"));
		printStatus(status);
		fprintf(stderr, "\n");
		free(map);
		return (1);
	}
	*mapping = map;
	return (0);
}

/*
 * This function handles the remoteport object.  It will issue a report lun
 * to determine whether it is a scsi-target and then print the information.
 *
 * Arguments:
 *	handle - a handle to a HBA that we will be processing
 *	portWWN - the port WWN for the HBA port we will be issuing the SCSI
 *	    ReportLUNS through
 *	remotePortWWN - the port WWN we will be issuing the report lun call to
 *	discPort - PORTATTRIBUTES structure for the remotePortWWN
 */
static void
handleRemotePort(HBA_HANDLE handle, HBA_WWN portWWN, HBA_WWN remotePortWWN,
    HBA_PORTATTRIBUTES *discPort)
{
	HBA_STATUS		status;
	int			scsiTargetType;
	uchar_t			raw_luns[LUN_LENGTH];
	HBA_UINT32		responseSize = LUN_LENGTH;
	struct scsi_extended_sense  sense;
	HBA_UINT32		senseSize = sizeof (struct scsi_extended_sense);
	HBA_UINT8		rep_luns_status;

	/* argument checking */
	if (discPort == NULL) {
		return;
	}

	memset(raw_luns, 0, sizeof (raw_luns));
	/* going to issue a report lun to check if this is a scsi-target */
	status = HBA_ScsiReportLUNsV2(handle, portWWN, remotePortWWN,
	    (void *)raw_luns, &responseSize, &rep_luns_status,
	    (void *)&sense, &senseSize);
	if (status == HBA_STATUS_OK) {
		scsiTargetType = SCSI_TARGET_TYPE_YES;
	} else if (status == HBA_STATUS_ERROR_NOT_A_TARGET) {
		scsiTargetType = SCSI_TARGET_TYPE_NO;
	} else {
		scsiTargetType = SCSI_TARGET_TYPE_UNKNOWN;
	}
	printDiscoPortInfo(discPort, scsiTargetType);
}

/*
 * This function will issue the RLS and print out the port statistics for
 * the given destWWN
 *
 * Arguments
 *	handle - a handle to a HBA that we will be processing
 *	hbaPortWWN - the hba port WWN through which the RLS will be sent
 *	destWWN - the remote port to which the RLS will be sent
 */
static void
printLinkStat(HBA_HANDLE handle, HBA_WWN hbaPortWWN, HBA_WWN destWWN)
{
	HBA_STATUS		status;
	fc_rls_acc_t		rls_payload;
	uint32_t		rls_payload_size;

	memset(&rls_payload, 0, sizeof (rls_payload));
	rls_payload_size = sizeof (rls_payload);
	status = HBA_SendRLS(handle, hbaPortWWN, destWWN,
	    &rls_payload, &rls_payload_size);
	if (status != HBA_STATUS_OK) {
		fprintf(stderr, gettext("Error: SendRLS failed for %016llx\n"),
		    wwnConversion(destWWN.wwn));
	} else {
		printPortStat(&rls_payload);
	}
}

int
printHBANPIVPortInfo(HBA_HANDLE handle, int portindex)
{
	HBA_PORTNPIVATTRIBUTES	portattrs;
	HBA_NPIVATTRIBUTES	npivattrs;
	HBA_STATUS		status;
	int			index;
	int			times = 0;

	status = Sun_HBA_GetPortNPIVAttributes(handle, portindex, &portattrs);
	while (status == HBA_STATUS_ERROR_TRY_AGAIN ||
	    status == HBA_STATUS_ERROR_BUSY) {
		(void) sleep(1);
		status = Sun_HBA_GetPortNPIVAttributes(
		    handle, portindex, &portattrs);
		if (times++ > HBA_MAX_RETRIES) {
			break;
		}
	}

	if (status == HBA_STATUS_ERROR_NOT_SUPPORTED) {
		fprintf(stdout, gettext("\tNPIV Not Supported\n"));
		return (0);
	}

	if (status != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Error: Failed to get port (%d) "
		    "npiv attributes reason: "), portindex);
		printStatus(status);
		fprintf(stderr, "\n");
		return (1);
	}
	if (portattrs.MaxNumberOfNPIVPorts) {
		fprintf(stdout, gettext("\tMax NPIV Ports: %d\n"),
		    portattrs.MaxNumberOfNPIVPorts);
	} else {
		fprintf(stdout, gettext("\tNPIV Not Supported\n"));
		return (0);
	}
	fprintf(stdout, gettext("\tNPIV port list:\n"));
	for (index = 0; index < portattrs.NumberOfNPIVPorts; index++) {
		int times = 0;
		status = Sun_HBA_GetNPIVPortInfo(handle,
		    portindex, index, &npivattrs);
		while (status == HBA_STATUS_ERROR_TRY_AGAIN ||
		    status == HBA_STATUS_ERROR_BUSY) {
			(void) sleep(1);
			status = Sun_HBA_GetNPIVPortInfo(handle,
			    portindex, index, &npivattrs);
			if (times++ > HBA_MAX_RETRIES) {
				break;
			}
		}

		if (status != HBA_STATUS_OK) {
			fprintf(stderr,
			    gettext("Error: Failed to get npiv port (%d) "
			    "attributes reason: "), index);
			printStatus(status);
			fprintf(stderr, "\n");
			return (1);
		} else {
			fprintf(stdout,
			    gettext("\t  Virtual Port%d:\n"), index+1);
			fprintf(stdout, gettext("\t\tNode WWN: %016llx\n"),
			    wwnConversion(npivattrs.NodeWWN.wwn));
			fprintf(stdout, gettext("\t\tPort WWN: %016llx\n"),
			    wwnConversion(npivattrs.PortWWN.wwn));
		}
	}
	return (0);
}

/*
 * This function will process hba port, remote port and scsi-target information
 * for the given handle.
 *
 * Arguments:
 *	handle - a handle to a HBA that we will be processing
 *	resourceType - resourceType flag
 *		possible values include: HBA_PORT, REMOTE_PORT
 *	flags - represents options passed in by the user
 *
 *  Return Value:
 *	    0		sucessfully processed handle
 *	    1		error has occured
 */
static int
processHBA(HBA_HANDLE handle, HBA_ADAPTERATTRIBUTES attrs, int portIndex,
    HBA_PORTATTRIBUTES port, HBA_FCPTARGETMAPPINGV2 *map,
    int resourceType, int flags, int mode)
{
	HBA_PORTATTRIBUTES	discPort;
	HBA_STATUS		status;
	int			discPortCount;

	if (resourceType == HBA_PORT) {
		printHBAPortInfo(&port, &attrs, mode);
		if ((flags & PRINT_LINKSTAT) == PRINT_LINKSTAT) {
			printLinkStat(handle, port.PortWWN, port.PortWWN);
		}
		return (0);
	}
	/*
	 * process each of the remote targets from this hba port
	 */
	for (discPortCount = 0;
	    discPortCount < port.NumberofDiscoveredPorts;
	    discPortCount++) {
		status = HBA_GetDiscoveredPortAttributes(handle,
		    portIndex, discPortCount, &discPort);
		if (status != HBA_STATUS_OK) {
			fprintf(stderr,
			    gettext("Failed to get discovered port (%d)"
				    " attributes reason :"), discPortCount);
			printStatus(status);
			fprintf(stderr, "\n");
			continue;
		}
		if (resourceType == REMOTE_PORT) {
			handleRemotePort(handle, port.PortWWN, discPort.PortWWN,
			    &discPort);
			if ((flags & PRINT_LINKSTAT) == PRINT_LINKSTAT) {
			    printLinkStat(handle, port.PortWWN,
				discPort.PortWWN);
			}
			if ((flags & PRINT_SCSI_TARGET) == PRINT_SCSI_TARGET) {
				handleScsiTarget(handle, port.PortWWN,
				    discPort.PortWWN, map);
			}
		}
	}
	return (0);
}

/*
 * This function will process remote port information for the given handle.
 *
 * Arguments:
 *	handle - a handle to a HBA that we will be processing
 *	portWWN - the port WWN for the HBA port we will be issuing the SCSI
 *	    ReportLUNS through
 *	wwnCount - the number of wwns in wwn_argv
 *	wwn_argv - argument vector of WWNs
 */
static void
processRemotePort(HBA_HANDLE handle, HBA_WWN portWWN,
    HBA_FCPTARGETMAPPINGV2 *map, int wwnCount, char **wwn_argv, int flags)
{
	int			remote_wwn_counter;
	uint64_t		remotePortWWN;
	HBA_WWN			myremotePortWWN;
	HBA_PORTATTRIBUTES	discPort;
	HBA_STATUS		status;

	for (remote_wwn_counter = 0;
	    remote_wwn_counter < wwnCount;
	    remote_wwn_counter++) {
		int times = 0;
		sscanf(wwn_argv[remote_wwn_counter], "%016llx",
		    &remotePortWWN);
		remotePortWWN = htonll(remotePortWWN);
		memcpy(myremotePortWWN.wwn, &remotePortWWN,
		    sizeof (remotePortWWN));
		memset(&discPort, 0, sizeof (discPort));
		status = HBA_GetPortAttributesByWWN(handle, myremotePortWWN,
		    &discPort);
		while (status == HBA_STATUS_ERROR_TRY_AGAIN ||
		    status == HBA_STATUS_ERROR_BUSY) {
			(void) sleep(1);
			status = HBA_GetPortAttributesByWWN(handle,
			    myremotePortWWN, &discPort);
			if (times++ > HBA_MAX_RETRIES) {
				break;
			}
		}
		if (status != HBA_STATUS_OK) {
			fprintf(stderr, gettext("HBA_GetPortAttributesByWWN "
				    "failed: reason: "));
			printStatus(status);
			fprintf(stderr, "\n");
			continue;
		}
		handleRemotePort(handle, portWWN, myremotePortWWN, &discPort);
		if ((flags & PRINT_LINKSTAT) == PRINT_LINKSTAT) {
			printLinkStat(handle, portWWN, myremotePortWWN);
		}
		if ((flags & PRINT_SCSI_TARGET) == PRINT_SCSI_TARGET) {
			handleScsiTarget(handle, portWWN,
			    myremotePortWWN, map);
		}
	}
}

/*
 * This function handles printing Scsi target information for remote ports
 *
 * Arguments:
 *	handle - a handle to a HBA that we will be processing
 *	hbaPortWWN - the port WWN for the HBA port through which the SCSI call
 *	    is being sent
 *	scsiTargetWWN - target port WWN of the remote target the SCSI call is
 *	    being sent to
 *	map - a pointer to the target mapping structure for the given HBA port
 */
static void
handleScsiTarget(HBA_HANDLE handle, HBA_WWN hbaPortWWN, HBA_WWN scsiTargetWWN,
    HBA_FCPTARGETMAPPINGV2 *map)
{
	HBA_STATUS		    status;
	struct scsi_inquiry	    inq;
	struct scsi_extended_sense  sense;
	HBA_UINT32		    responseSize, senseSize = 0;
	HBA_UINT8		    inq_status;
	uchar_t			    raw_luns[DEFAULT_LUN_LENGTH], *lun_string;
	HBA_UINT8		    rep_luns_status;
	rep_luns_rsp_t		    *lun_resp;
	uint64_t		    fcLUN;
	int			    lunNum, numberOfLun, lunCount, count;
	uint32_t		    lunlength, tmp_lunlength;

	responseSize = DEFAULT_LUN_LENGTH;
	senseSize = sizeof (struct scsi_extended_sense);
	memset(&sense, 0, sizeof (sense));
	status = HBA_ScsiReportLUNsV2(handle, hbaPortWWN,
	    scsiTargetWWN, (void *)raw_luns, &responseSize,
	    &rep_luns_status, (void *)&sense, &senseSize);
	/*
	 * if HBA_STATUS_ERROR_NOT_A_TARGET is return, we can assume this is
	 * a remote HBA and move on
	 */
	if (status == HBA_STATUS_ERROR_NOT_A_TARGET) {
		return;
	} else if (status != HBA_STATUS_OK) {
		fprintf(stderr, gettext("Error has occured. "
			    "HBA_ScsiReportLUNsV2 failed.  reason "));
		printStatus(status);
		fprintf(stderr, "\n");
		return;
	}
	lun_resp = (rep_luns_rsp_t *)raw_luns;
	memcpy(&tmp_lunlength, &(lun_resp->length), sizeof (tmp_lunlength));
	lunlength = htonl(tmp_lunlength);
	memcpy(&numberOfLun, &lunlength, sizeof (numberOfLun));
	for (lunCount = 0; lunCount < (numberOfLun / 8); lunCount++) {
		/*
		 * now issue standard inquiry to get Vendor
		 * and product information
		 */
		responseSize = sizeof (struct scsi_inquiry);
		senseSize = sizeof (struct scsi_extended_sense);
		memset(&inq, 0, sizeof (struct scsi_inquiry));
		memset(&sense, 0, sizeof (sense));
		fcLUN = ntohll(wwnConversion(lun_resp->lun[lunCount].val));
		status = HBA_ScsiInquiryV2(
			handle,
			hbaPortWWN,
			scsiTargetWWN,
			fcLUN,
			0, /* EVPD */
			0,
			&inq, &responseSize,
			&inq_status,
			&sense, &senseSize);
		if (status != HBA_STATUS_OK) {
		    fprintf(stderr, gettext("Not able to issue Inquiry.\n"));
		    printStatus(status);
		    fprintf(stderr, "\n");
		    strcpy(inq.inq_vid, "Unknown");
		    strcpy(inq.inq_pid, "Unknown");
		}
		if (map != NULL) {
			for (count = 0; count < map->NumberOfEntries; count++) {
			    if ((memcmp(map->entry[count].FcpId.PortWWN.wwn,
						    scsiTargetWWN.wwn,
						    sizeof (scsiTargetWWN.wwn))
					    == 0) &&
				    (memcmp(&(map->entry[count].FcpId.FcpLun),
					    &fcLUN, sizeof (fcLUN)) == 0)) {
				printLUNInfo(&inq,
				    map->entry[count].ScsiId.ScsiOSLun,
				    map->entry[count].ScsiId.OSDeviceName);
				    break;
			    }
			}
			if (count == map->NumberOfEntries) {
				lun_string = lun_resp->lun[lunCount].val;
				lunNum = ((lun_string[0] & 0x3F) << 8) |
				    lun_string[1];
				printLUNInfo(&inq, lunNum, "Unknown");
			}
		} else {
			/* Not able to get any target mapping information */
			lun_string = lun_resp->lun[lunCount].val;
			lunNum = ((lun_string[0] & 0x3F) << 8) |
			    lun_string[1];
			printLUNInfo(&inq, lunNum, "Unknown");
		}
	}
}

/*
 * function to handle the list remoteport command
 *
 * Arguments:
 *	wwnCount - the number of wwns in wwn_argv
 *	    if wwnCount == 0, then print information on all
 *		remote ports.  wwn_argv will not be used in this case
 *	    if wwnCount > 0, then print information for the WWNs
 *		given in wwn_argv
 *	wwn_argv - argument vector of WWNs
 *	options - any options specified by the caller
 *
 * returns:
 *	0	if successful
 *	1	otherwise
 */
int
fc_util_list_remoteport(int wwnCount, char **wwn_argv, cmdOptions_t *options)
{
	HBA_STATUS		status;
	HBA_FCPTARGETMAPPINGV2	*map = NULL;
	HBA_PORTATTRIBUTES	port;
	HBA_ADAPTERATTRIBUTES	attrs;
	HBA_HANDLE		handle;
	uint64_t		hbaPortWWN;
	HBA_WWN			myhbaPortWWN;
	int			processHBA_flags = 0, portCount = 0;
	int			mode;

	/* grab the hba port wwn from the -p option */
	for (; options->optval; options++) {
		if (options->optval == 'p') {
			sscanf(options->optarg, "%016llx",
			    &hbaPortWWN);
		} else if (options->optval == 's') {
			processHBA_flags |= PRINT_SCSI_TARGET;
		} else if (options->optval == 'l') {
			processHBA_flags |= PRINT_LINKSTAT;
		} else {
			fprintf(stderr, gettext("Error: Illegal option: %c.\n"),
			    options->optval);
			return (1);
		}
	}
	/*
	 * -h option was not specified, this should not happen either.
	 * cmdparse should catch this problem, but checking anyways
	 */
	if (hbaPortWWN == 0) {
		fprintf(stderr,
		    gettext("Error: -p option was not specified.\n"));
		return (1);
	}
	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Failed to load FC-HBA common library\n"));
		printStatus(status);
		fprintf(stderr, "\n");
		return (1);
	}
	hbaPortWWN = htonll(hbaPortWWN);
	memcpy(myhbaPortWWN.wwn, &hbaPortWWN, sizeof (hbaPortWWN));
	if ((status = HBA_OpenAdapterByWWN(&handle, myhbaPortWWN))
	    != HBA_STATUS_OK) {
		status = Sun_HBA_OpenTgtAdapterByWWN(&handle, myhbaPortWWN);
		if (status != HBA_STATUS_OK) {
		    fprintf(stderr,
			gettext("Error: Failed to open adapter port. Reason "));
			printStatus(status);
		    fprintf(stderr, "\n");
		    HBA_FreeLibrary();
		    return (1);
		} else {
		    if ((processHBA_flags & PRINT_SCSI_TARGET) ==
			PRINT_SCSI_TARGET) {
			fprintf(stderr, gettext(
			    "Error: Unsupported option for target mode: %c.\n"),
			    's');
			HBA_FreeLibrary();
			return (1);
		    }
		    mode = TARGET_MODE;
		}
	} else {
	    mode = INITIATOR_MODE;
	}

	if ((processHBA_flags & PRINT_SCSI_TARGET) == PRINT_SCSI_TARGET) {
		getTargetMapping(handle, myhbaPortWWN, &map);
	}
	if (wwnCount == 0) {
		/* get adapater attributes for the given handle */
		memset(&attrs, 0, sizeof (attrs));
		memset(&port, 0, sizeof (port));
		if (retrieveAttrs(handle, myhbaPortWWN, &attrs, &port,
			    &portCount) != 0) {
			if (map != NULL) {
				free(map);
			}
			HBA_CloseAdapter(handle);
			HBA_FreeLibrary();
			return (1);
		}
		processHBA(handle, attrs, portCount, port, map, REMOTE_PORT,
		    processHBA_flags, mode);
	} else {
		processRemotePort(handle, myhbaPortWWN, map, wwnCount,
		    wwn_argv, processHBA_flags);
	}
	if (map != NULL) {
		free(map);
	}
	HBA_CloseAdapter(handle);
	HBA_FreeLibrary();
	return (0);
}

/*
 * process the hbaport object
 *
 * Arguments:
 *	wwnCount - count of the number of WWNs in wwn_argv
 *	    if wwnCount > 0, then we will only print information for
 *		the hba ports listed in wwn_argv
 *	    if wwnCount == 0, then we will print information on all hba ports
 *	wwn_argv - argument array of hba port WWNs
 *	options - any options specified by the caller
 *
 * returns:
 *	0	if successful
 *	1	otherwise
 */
int
fc_util_list_hbaport(int wwnCount, char **wwn_argv, cmdOptions_t *options)
{
	int	port_wwn_counter, numAdapters = 0, numTgtAdapters = 0, i;
	HBA_STATUS		status;
	char			adapterName[256];
	HBA_HANDLE		handle;
	uint64_t		hbaWWN;
	HBA_WWN			myWWN;
	int			processHBA_flags = 0;
	HBA_PORTATTRIBUTES	port;
	HBA_ADAPTERATTRIBUTES	attrs;
	int			portIndex = 0, err_cnt = 0;
	int			mode;

	/* process each of the options */
	for (; options->optval; options++) {
		if (options->optval == 'l') {
			processHBA_flags |= PRINT_LINKSTAT;
		} else if (options->optval == 'i') {
			processHBA_flags |= PRINT_INITIATOR;
		} else if (options->optval == 't') {
			processHBA_flags |= PRINT_TARGET;
		}
	}

	/*
	 * Print both initiator and target if no initiator/target flag
	 * specified.
	 */
	if (((processHBA_flags & PRINT_INITIATOR) == 0) &&
	    ((processHBA_flags & PRINT_TARGET) == 0)) {
	    processHBA_flags |= PRINT_INITIATOR | PRINT_TARGET;
	}

	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Failed to load FC-HBA common library\n"));
		printStatus(status);
		fprintf(stderr, "\n");
		return (1);
	}
	if (wwnCount > 0) {
		/* list only ports given in wwn_argv */
		for (port_wwn_counter = 0;
		    port_wwn_counter < wwnCount;
		    port_wwn_counter++) {
			sscanf(wwn_argv[port_wwn_counter], "%016llx", &hbaWWN);
			hbaWWN = htonll(hbaWWN);
			memcpy(myWWN.wwn, &hbaWWN, sizeof (hbaWWN));
			/* first check to see if it is an initiator port. */
			if ((processHBA_flags & PRINT_INITIATOR) ==
			    PRINT_INITIATOR) {
			    int times = 0;
			    status = HBA_OpenAdapterByWWN(&handle, myWWN);
			    while (status == HBA_STATUS_ERROR_TRY_AGAIN ||
				status == HBA_STATUS_ERROR_BUSY) {
				(void) sleep(1);
				status = HBA_OpenAdapterByWWN(&handle, myWWN);
				if (times++ > HBA_MAX_RETRIES) {
					break;
				}
			    }
			    if (status != HBA_STATUS_OK) {
				/* now see if it is a target mode FC port */
				if ((processHBA_flags & PRINT_TARGET) ==
				    PRINT_TARGET) {
				    status =
				    Sun_HBA_OpenTgtAdapterByWWN(&handle, myWWN);
				    if (status != HBA_STATUS_OK) {
					fprintf(stderr,
					    gettext(
					    "Error: HBA port %s: not found\n"),
					    wwn_argv[port_wwn_counter]);
					    err_cnt++;
					continue;
				    } else {
					/* set the port mode. */
					mode = TARGET_MODE;
				    }
				} else {
				    fprintf(stderr,
					gettext(
					    "Error: HBA port %s: not found\n"),
					    wwn_argv[port_wwn_counter]);
					    err_cnt++;
					continue;
				}
			    } else {
				/* set the port mode. */
				mode = INITIATOR_MODE;
			    }
			/* try target mode discovery if print target is set. */
			} else if ((processHBA_flags & PRINT_TARGET) ==
				PRINT_TARGET) {
			    status =
				Sun_HBA_OpenTgtAdapterByWWN(&handle, myWWN);
			    if (status != HBA_STATUS_OK) {
				fprintf(stderr, gettext(
				    "Error: HBA port %s: not found\n"),
				    wwn_argv[port_wwn_counter]);
				    err_cnt++;
				continue;
			    } else {
				/* set the port mode. */
				mode = TARGET_MODE;
			    }
			} else {
			    /* should not get here. */
			    fprintf(stderr, gettext(
				"Error: HBA port %s: not found\n"),
				wwn_argv[port_wwn_counter]);
			    err_cnt++;
			    continue;
			}
			memset(&attrs, 0, sizeof (attrs));
			memset(&port, 0, sizeof (port));
			if (retrieveAttrs(handle, myWWN, &attrs, &port,
				    &portIndex) != 0) {
				HBA_CloseAdapter(handle);
				continue;
			}
			processHBA(handle, attrs, portIndex, port, NULL,
			    HBA_PORT, processHBA_flags, mode);
			if (printHBANPIVPortInfo(handle, portIndex)
			    != 0) {
				err_cnt++;
			}
			HBA_CloseAdapter(handle);
		}
	} else {
		/*
		 * if PRINT_INITIATOR is specified, get the list of initiator
		 * mod port.
		 */
		if ((processHBA_flags & PRINT_INITIATOR) == PRINT_INITIATOR) {
		    numAdapters = HBA_GetNumberOfAdapters();
		    if ((numAdapters == 0) &&
			((processHBA_flags & ~PRINT_INITIATOR) == 0)) {
			fprintf(stdout, gettext("No Adapters Found.\n"));
		    }
		    for (i = 0; i < numAdapters; i++) {
			int times = 0;
			status = HBA_GetAdapterName(i, adapterName);
			if (status != HBA_STATUS_OK) {
				fprintf(stderr, gettext(
				    "failed to get adapter %d. Reason: "), i);
				printStatus(status);
				fprintf(stderr, "\n");
				continue;
			}
			if ((handle = HBA_OpenAdapter(adapterName)) == 0) {
				fprintf(stderr, gettext(
					    "Failed to open adapter %s.\n"),
				    adapterName);
				continue;
			}
			/* get adapater attributes for the given handle */
			memset(&attrs, 0, sizeof (attrs));
			status =
			    Sun_HBA_NPIVGetAdapterAttributes(handle,
			    &attrs);
			while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
			    status == HBA_STATUS_ERROR_BUSY) &&
			    times++ < HBA_MAX_RETRIES) {
				(void) sleep(1);
				status =
				    Sun_HBA_NPIVGetAdapterAttributes(handle,
				    &attrs);
				if (status == HBA_STATUS_OK) {
					break;
				}
			}
			if (status != HBA_STATUS_OK) {
				fprintf(stderr,
				    gettext("Failed to get adapter attributes "
					    "handle(%d) Reason: "), handle);
				printStatus(status);
				fprintf(stderr, "\n");
				continue;
			}

			/* process each port on the given adatpter */
			for (portIndex = 0;
			    portIndex < attrs.NumberOfPorts;
			    portIndex++) {
				memset(&port, 0, sizeof (port));
				if ((status = HBA_GetAdapterPortAttributes(
						    handle, portIndex, &port))
				    != HBA_STATUS_OK) {
					/*
					 * not able to get port attributes.
					 * print out error * message and move
					 * on to the next port
					 */
					fprintf(stderr,
					    gettext("Error: Failed to get port "
						    "(%d) attributes reason: "),
					    portIndex);
					printStatus(status);
					fprintf(stderr, "\n");
					continue;
				}
				processHBA(handle, attrs, portIndex, port,
				    NULL, HBA_PORT, processHBA_flags,
				    INITIATOR_MODE);
				if (printHBANPIVPortInfo(handle, portIndex)
				    != 0) {
					err_cnt++;
				}
			}
			HBA_CloseAdapter(handle);
		    }
		}

		/*
		 * Get the info on the target mode FC port if PRINT_TARGET
		 * is specified.
		 */
		if ((processHBA_flags & PRINT_TARGET) == PRINT_TARGET) {
		    numTgtAdapters = Sun_HBA_GetNumberOfTgtAdapters();
		    if (numTgtAdapters == 0 && numAdapters == 0) {
			fprintf(stdout,
			    gettext("No Adapters Found.\n"));
		    }
		    for (i = 0; i < numTgtAdapters; i++) {
			status = Sun_HBA_GetTgtAdapterName(i, adapterName);
			if (status != HBA_STATUS_OK) {
			    fprintf(stderr, gettext(
				"failed to get adapter %d. Reason: "), i);
			    printStatus(status);
			    fprintf(stderr, "\n");
			    continue;
			}
			if ((handle = Sun_HBA_OpenTgtAdapter(adapterName))
			    == 0) {
			    fprintf(stderr, gettext(
				"Failed to open adapter %s.\n"), adapterName);
			    continue;
			}
			/* get adapater attributes for the given handle */
			memset(&attrs, 0, sizeof (attrs));
			if ((status = HBA_GetAdapterAttributes(handle, &attrs))
			    != HBA_STATUS_OK) {
				fprintf(stderr,
				    gettext("Failed to get target mode adapter"
					"attributes handle(%d) Reason: "),
					handle);
				printStatus(status);
				fprintf(stderr, "\n");
				continue;
			}

			/* process each port on the given adatpter */
			for (portIndex = 0;
			    portIndex < attrs.NumberOfPorts;
			    portIndex++) {
				memset(&port, 0, sizeof (port));
				if ((status = HBA_GetAdapterPortAttributes(
						    handle, portIndex, &port))
				    != HBA_STATUS_OK) {
					/*
					 * not able to get port attributes.
					 * print out error * message and move
					 * on to the next port
					 */
					fprintf(stderr,
					    gettext("Error: Failed to get port "
						    "(%d) attributes reason: "),
					    portIndex);
					printStatus(status);
					fprintf(stderr, "\n");
					continue;
				}
				processHBA(handle, attrs, portIndex, port,
				    NULL, HBA_PORT, processHBA_flags,
				    TARGET_MODE);
			}
		    HBA_CloseAdapter(handle);
		}
	    }
	}

	HBA_FreeLibrary();

	/*
	 * print additional error msg for partial failure when more than
	 * one wwn is specified.
	 */
	if (err_cnt != 0) {
	    if (wwnCount > 1) {
		if (err_cnt == wwnCount) {
		    fprintf(stderr, gettext(
		    "Error: All specified HBA ports are not found\n"));
		} else {
		    fprintf(stderr, gettext(
		    "Error: Some of specified HBA ports are not found\n"));
		}
	    }
	    return (1);
	}

	return (0);
}

/*
 * Search the existing device list
 *
 * Take one of two actions:
 *
 * Add an entry if an entry doesn't exist
 * Add WWN data to it if an entry does exist
 *
 * Arguments:
 *	devList - OS device path list
 *	map - target mapping data
 *	index - index into target mapping data
 *	initiatorPortWWN - HBA port WWN
 *	verbose - boolean indicating whether to get additional data
 *
 * returns:
 *	none
 */
static void
searchDevice(discoveredDevice **devList, HBA_FCPSCSIENTRYV2 entry,
HBA_WWN initiatorPortWWN, HBA_HANDLE handle, boolean_t verbose)
{
	discoveredDevice *discoveredDevList, *newDevice;
	portWWNList *WWNList, *newWWN;
	tgtPortWWNList *newTgtWWN;
	boolean_t foundDevice = B_FALSE, foundWWN;
	struct scsi_inquiry	    inq;
	struct scsi_extended_sense  sense;
	HBA_UINT32		    responseSize, senseSize = 0;
	HBA_UINT8		    inq_status;
	HBA_STATUS		status;

	for (discoveredDevList = *devList; discoveredDevList != NULL;
	    discoveredDevList = discoveredDevList->next) {
		if (strcmp(entry.ScsiId.OSDeviceName,
		    discoveredDevList->OSDeviceName) == 0) {
			/*
			 * if only device names are requested,
			 * no reason to go any further
			 */
			if (verbose == B_FALSE) {
				return;
			}
			foundDevice = B_TRUE;
			break;
		}
	}
	if (foundDevice == B_TRUE) {
		/* add initiator Port WWN if it doesn't exist */
		for (WWNList = discoveredDevList->HBAPortWWN,
		    foundWWN = B_FALSE; WWNList != NULL;
		    WWNList = WWNList->next) {
			if (memcmp((void *)&(WWNList->portWWN),
			    (void *)&initiatorPortWWN,
			    sizeof (HBA_WWN)) == 0) {
				foundWWN = B_TRUE;
				break;
			}
		}
		if (discoveredDevList->inqSuccess == B_FALSE) {
			responseSize = sizeof (struct scsi_inquiry);
			senseSize = sizeof (struct scsi_extended_sense);
			memset(&inq, 0, sizeof (struct scsi_inquiry));
			memset(&sense, 0, sizeof (sense));
			status = HBA_ScsiInquiryV2(
			    handle,
			    initiatorPortWWN,
			    entry.FcpId.PortWWN,
			    entry.FcpId.FcpLun,
			    0, /* CDB Byte 1 */
			    0, /* CDB Byte 2 */
			    &inq, &responseSize,
			    &inq_status,
			    &sense, &senseSize);
			if (status == HBA_STATUS_OK) {
				memcpy(discoveredDevList->VID, inq.inq_vid,
				    sizeof (discoveredDevList->VID));
				memcpy(discoveredDevList->PID, inq.inq_pid,
				    sizeof (discoveredDevList->PID));
				discoveredDevList->dType = inq.inq_dtype;
				discoveredDevList->inqSuccess = B_TRUE;
			}
		}

		if (foundWWN == B_FALSE) {
			newWWN = (portWWNList *)calloc(1, sizeof (portWWNList));
			if (newWWN == NULL) {
				perror("Out of memory");
				exit(1);
			}

			/* insert at head */
			newWWN->next = discoveredDevList->HBAPortWWN;
			discoveredDevList->HBAPortWWN = newWWN;
			memcpy((void *)&(newWWN->portWWN),
			    (void *)&initiatorPortWWN,
			    sizeof (newWWN->portWWN));
			/* add Target Port */
			newWWN->tgtPortWWN = (tgtPortWWNList *)calloc(1,
			    sizeof (tgtPortWWNList));
			if (newWWN->tgtPortWWN == NULL) {
				perror("Out of memory");
				exit(1);
			}

			memcpy((void *)&(newWWN->tgtPortWWN->portWWN),
			    (void *)&(entry.FcpId.PortWWN),
			    sizeof (newWWN->tgtPortWWN->portWWN));
			/* Set LUN data */
			newWWN->tgtPortWWN->scsiOSLun = entry.ScsiId.ScsiOSLun;
		} else { /* add it to existing */
			newTgtWWN = (tgtPortWWNList *)calloc(1,
			    sizeof (tgtPortWWNList));
			if (newTgtWWN == NULL) {
				perror("Out of memory");
				exit(1);
			}
			/* insert at head */
			newTgtWWN->next = WWNList->tgtPortWWN;
			WWNList->tgtPortWWN = newTgtWWN;
			memcpy((void *)&(newTgtWWN->portWWN),
			    (void *)&(entry.FcpId.PortWWN),
			    sizeof (newTgtWWN->portWWN));
			/* Set LUN data */
			newTgtWWN->scsiOSLun = entry.ScsiId.ScsiOSLun;
		}
	} else { /* add new entry */
		newDevice = (discoveredDevice *)calloc(1,
		    sizeof (discoveredDevice));
		if (newDevice == NULL) {
			perror("Out of memory");
			exit(1);
		}
		newDevice->next = *devList; /* insert at head */
		*devList = newDevice; /* set new head */

		/* Copy device name */
		strncpy(newDevice->OSDeviceName, entry.ScsiId.OSDeviceName,
		    sizeof (newDevice->OSDeviceName) - 1);

		/*
		 * if only device names are requested,
		 * no reason to go any further
		 */
		if (verbose == B_FALSE) {
			return;
		}

		/*
		 * copy WWN data
		 */
		newDevice->HBAPortWWN = (portWWNList *)calloc(1,
		    sizeof (portWWNList));
		if (newDevice->HBAPortWWN == NULL) {
			perror("Out of memory");
			exit(1);
		}
		memcpy((void *)&(newDevice->HBAPortWWN->portWWN),
		    (void *)&initiatorPortWWN, sizeof (newWWN->portWWN));

		newDevice->HBAPortWWN->tgtPortWWN =
		    (tgtPortWWNList *)calloc(1, sizeof (tgtPortWWNList));
		if (newDevice->HBAPortWWN->tgtPortWWN == NULL) {
			perror("Out of memory");
			exit(1);
		}

		memcpy((void *)&(newDevice->HBAPortWWN->tgtPortWWN->portWWN),
		    (void *)&(entry.FcpId.PortWWN),
		    sizeof (newDevice->HBAPortWWN->tgtPortWWN->portWWN));

		/* Set LUN data */
		newDevice->HBAPortWWN->tgtPortWWN->scsiOSLun =
		    entry.ScsiId.ScsiOSLun;

		responseSize = sizeof (struct scsi_inquiry);
		senseSize = sizeof (struct scsi_extended_sense);
		memset(&inq, 0, sizeof (struct scsi_inquiry));
		memset(&sense, 0, sizeof (sense));
		status = HBA_ScsiInquiryV2(
		    handle,
		    initiatorPortWWN,
		    entry.FcpId.PortWWN,
		    entry.FcpId.FcpLun,
		    0, /* CDB Byte 1 */
		    0, /* CDB Byte 2 */
		    &inq, &responseSize,
		    &inq_status,
		    &sense, &senseSize);
		if (status != HBA_STATUS_OK) {
			/* initialize VID/PID/dType as "Unknown" */
			strcpy(newDevice->VID, "Unknown");
			strcpy(newDevice->PID, "Unknown");
			newDevice->dType = DTYPE_UNKNOWN;
			/* initialize inq status */
			newDevice->inqSuccess = B_FALSE;
		} else {
			memcpy(newDevice->VID, inq.inq_vid,
			    sizeof (newDevice->VID));
			memcpy(newDevice->PID, inq.inq_pid,
			    sizeof (newDevice->PID));
			newDevice->dType = inq.inq_dtype;
			/* initialize inq status */
			newDevice->inqSuccess = B_TRUE;
		}
	}
}


/*
 * process the logical-unit object
 *
 * Arguments:
 *	luCount - count of the number of device paths in paths_argv
 *	    if pathCount > 0, then we will only print information for
 *		the device paths listed in paths_argv
 *	    if pathCount == 0, then we will print information on all device
 *	        paths
 *	luArgv - argument array of device paths
 *	options - any options specified by the caller
 *
 * returns:
 *	0	if successful
 *	> 0	otherwise
 */
int
fc_util_list_logicalunit(int luCount, char **luArgv, cmdOptions_t *options)
{
	int			pathCtr, numAdapters, i, count;
	HBA_STATUS		status;
	char			adapterName[256];
	HBA_HANDLE		handle;
	HBA_PORTATTRIBUTES	port;
	HBA_ADAPTERATTRIBUTES	attrs;
	int			portIndex = 0;
	int			ret = 0;
	boolean_t		verbose = B_FALSE;
	HBA_FCPTARGETMAPPINGV2	*map = NULL;
	discoveredDevice	*devListWalk, *devList = NULL;
	boolean_t		pathFound;

	/* process each of the options */
	for (; options->optval; options++) {
		if (options->optval == 'v') {
			verbose = B_TRUE;
		}
	}

	if ((status = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		fprintf(stderr,
		    gettext("Failed to load FC-HBA common library\n"));
		printStatus(status);
		fprintf(stderr, "\n");
		return (1);
	}
	/*
	 * Retrieve all device paths. We'll need to traverse the list
	 * until we find the input paths or all paths if none were given. We
	 * cannot print as we go since there can be duplicate paths returned
	 */
	numAdapters = HBA_GetNumberOfAdapters();
	if (numAdapters == 0) {
		return (0);
	}
	for (i = 0; i < numAdapters; i++) {
		int times;
		status = HBA_GetAdapterName(i, adapterName);
		if (status != HBA_STATUS_OK) {
			fprintf(stderr, gettext(
			    "Failed to get adapter %d. Reason: "), i);
			printStatus(status);
			fprintf(stderr, "\n");
			ret++;
			continue;
		}
		if ((handle = HBA_OpenAdapter(adapterName)) == 0) {
			fprintf(stderr, gettext("Failed to open adapter %s\n"),
			    adapterName);
			ret++;
			continue;
		}
		/* get adapter attributes for the given handle */
		memset(&attrs, 0, sizeof (attrs));
		times = 0;
		status = HBA_GetAdapterAttributes(handle, &attrs);
		while ((status == HBA_STATUS_ERROR_TRY_AGAIN ||
		    status == HBA_STATUS_ERROR_BUSY) &&
		    times++ < HBA_MAX_RETRIES) {
			(void) sleep(1);
			status = HBA_GetAdapterAttributes(handle, &attrs);
			if (status == HBA_STATUS_OK) {
				break;
			}
		}
		if (status != HBA_STATUS_OK) {
			fprintf(stderr,
			    gettext("Failed to get adapter attributes "
			    "handle(%d) Reason: "), handle);
			printStatus(status);
			fprintf(stderr, "\n");
			ret++;
			continue;
		}

		/* process each port on adapter */
		for (portIndex = 0; portIndex < attrs.NumberOfPorts;
		    portIndex++) {
			memset(&port, 0, sizeof (port));
			if ((status = HBA_GetAdapterPortAttributes(handle,
			    portIndex, &port)) != HBA_STATUS_OK) {
				/*
				 * not able to get port attributes.
				 * print out error message and move
				 * on to the next port
				 */
				fprintf(stderr, gettext("Failed to get port "
				    "(%d) attributes reason: "),
				    portIndex);
				printStatus(status);
				fprintf(stderr, "\n");
				ret++;
				continue;
			}

			/* get OS Device Paths */
			getTargetMapping(handle, port.PortWWN, &map);
			if (map != NULL) {
				for (count = 0; count < map->NumberOfEntries;
				    count++) {
					searchDevice(&devList,
					    map->entry[count], port.PortWWN,
					    handle, verbose);
				}
			}
		}
		HBA_CloseAdapter(handle);
	}
	HBA_FreeLibrary();

	if (luCount == 0) {
		/* list all paths */
		for (devListWalk = devList; devListWalk != NULL;
		    devListWalk = devListWalk->next) {
			printOSDeviceNameInfo(devListWalk, verbose);
		}
	} else {
		/*
		 * list any paths not found first
		 * this gives the user cleaner output
		 */
		for (pathCtr = 0; pathCtr < luCount; pathCtr++) {
			for (devListWalk = devList, pathFound = B_FALSE;
			    devListWalk != NULL;
			    devListWalk = devListWalk->next) {
				if (strcmp(devListWalk->OSDeviceName,
				    luArgv[pathCtr]) == 0) {
					pathFound = B_TRUE;
				}
			}
			if (pathFound == B_FALSE) {
				fprintf(stderr, "%s: no such path\n",
				    luArgv[pathCtr]);
				ret++;
			}
		}
		/* list all paths requested in order requested */
		for (pathCtr = 0; pathCtr < luCount; pathCtr++) {
			for (devListWalk = devList; devListWalk != NULL;
			    devListWalk = devListWalk->next) {
				if (strcmp(devListWalk->OSDeviceName,
				    luArgv[pathCtr]) == 0) {
					printOSDeviceNameInfo(devListWalk,
					    verbose);
				}
			}
		}
	}
	return (ret);
}
