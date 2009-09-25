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

#include <sun_sas.h>

/*
 * Pass scsi request buffer into uscsi command and sent it out via ioctl
 */
static HBA_STATUS
SendScsiReportLUNs(const char *devpath, void *responseBuffer,
    HBA_UINT32 *responseSize, HBA_UINT8 *scsiStatus,
    void *senseBuffer, HBA_UINT32 *senseSize)
{
	HBA_UINT32		status;
	struct uscsi_cmd	ucmd_buf;
	union scsi_cdb		cdb;

	bzero(&cdb, sizeof (cdb));
	bzero(&ucmd_buf, sizeof (ucmd_buf));
	bzero(senseBuffer, *senseSize);

	cdb.scc_cmd = SCMD_REPORT_LUNS;
	FORMG5COUNT(&cdb, *responseSize);

	ucmd_buf.uscsi_cdb = (char *)&cdb;
	ucmd_buf.uscsi_cdblen = CDB_GROUP5;
	ucmd_buf.uscsi_bufaddr = (caddr_t)responseBuffer;
	ucmd_buf.uscsi_buflen = *responseSize;
	ucmd_buf.uscsi_rqbuf = (caddr_t)senseBuffer;
	ucmd_buf.uscsi_rqlen = *senseSize;
	ucmd_buf.uscsi_flags = USCSI_READ | USCSI_SILENT | USCSI_RQENABLE;
	ucmd_buf.uscsi_timeout = 60;

	status = send_uscsi_cmd(devpath, &ucmd_buf);
	*scsiStatus = ucmd_buf.uscsi_status;
	return (status);

}

/*
 * Send a SCSI report luns command to a remote WWN
 */
HBA_STATUS
Sun_sasScsiReportLUNs(HBA_HANDLE handle, HBA_WWN portWWN, HBA_WWN targetPortWWN,
    HBA_WWN domainPortWWN, void *responseBuffer, HBA_UINT32 *responseSize,
    HBA_UINT8 *scsiStatus, void *senseBuffer, HBA_UINT32 *senseSize)
{
	const char		ROUTINE[] = "Sun_sasScsiReportLUNs";
	HBA_STATUS		status;
	int			index = 0, domainPortFound = 0;
	int			chkDomainPort = 0;
	int			hbaPortFound = 0;
	struct sun_sas_hba	*hba_ptr = NULL;
	struct sun_sas_port	*hba_port_ptr, *hba_disco_port;
	struct ScsiEntryList	*mapping_ptr;
	hrtime_t		start, end;
	double			duration;

	start = gethrtime();

	/* Validate the arguments */
	if (responseBuffer == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL response buffer");
		return (HBA_STATUS_ERROR_ARG);
	}
	if (senseBuffer == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL sense buffer");
		return (HBA_STATUS_ERROR_ARG);
	}
	if (responseSize == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL response size");
		return (HBA_STATUS_ERROR_ARG);
	}
	if (senseSize == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL sense size");
		return (HBA_STATUS_ERROR_ARG);
	}
	if (scsiStatus == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL scsi status");
		return (HBA_STATUS_ERROR_ARG);
	}

	lock(&all_hbas_lock);
	index = RetrieveIndex(handle);
	lock(&open_handles_lock);
	if ((hba_ptr = RetrieveHandle(index)) == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid handle %08lx", handle);
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_INVALID_HANDLE);
	}

	/* Check for stale data */
	status = verifyAdapter(hba_ptr);
	if (status != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE, "Verify adapter failed");
		unlock(&open_handles_lock);
		unlock(&all_hbas_lock);
		return (status);
	}

	if (wwnConversion(domainPortWWN.wwn))
		chkDomainPort = 1;
	/* Determine which port to use */
	for (hba_port_ptr = hba_ptr->first_port;
	    hba_port_ptr != NULL;
	    hba_port_ptr = hba_port_ptr->next) {

		if (hbaPortFound == 0) {
			if (wwnConversion(hba_port_ptr->port_attributes.
			    PortSpecificAttribute.SASPort->LocalSASAddress.wwn)
			    != wwnConversion(portWWN.wwn)) {
				/*
				 * Since all the ports under the same HBA have
				 * the same LocalSASAddress, we should break
				 * the loop once we find it dosn't match.
				 */
				break;
			} else {
				hbaPortFound = 1;
			}
		}

		if (chkDomainPort != 0) {
			if (hba_port_ptr->first_phy != NULL &&
			    wwnConversion(hba_port_ptr->first_phy->
			    phy.domainPortWWN.wwn) ==
			    wwnConversion(domainPortWWN.wwn)) {
				domainPortFound = 1;
			}
			if (!(domainPortFound)) {
				continue;
			}
		}

		for (hba_disco_port = hba_port_ptr->first_attached_port;
		    hba_disco_port != NULL;
		    hba_disco_port = hba_disco_port->next) {

			/*
			 * If discoveredPort is not given targetPort, skip
			 */
			if (wwnConversion(hba_disco_port->port_attributes.\
			    PortSpecificAttribute.SASPort->LocalSASAddress.wwn)
			    != wwnConversion(targetPortWWN.wwn)) {
				/* Does not match */
				continue;
			}

			/*
			 * If discoveredPort is not a SAS/SATA port, it is not a
			 * target port
			 */
			if ((hba_disco_port->port_attributes.PortType !=
			    HBA_PORTTYPE_SATADEVICE) &&
			    (hba_disco_port->port_attributes.PortType !=
			    HBA_PORTTYPE_SASDEVICE)) {
				unlock(&open_handles_lock);
				unlock(&all_hbas_lock);
				log(LOG_DEBUG, ROUTINE, "Target Port WWN "
				    "%016llx on handle %08lx is not a Target",
				    wwnConversion(targetPortWWN.wwn), handle);
				return (HBA_STATUS_ERROR_NOT_A_TARGET);
			}

			if ((mapping_ptr = hba_disco_port->scsiInfo) != NULL) {

				status = SendScsiReportLUNs(
				    mapping_ptr->entry.ScsiId.OSDeviceName,
				    responseBuffer, responseSize,
				    scsiStatus, senseBuffer, senseSize);

				unlock(&open_handles_lock);
				unlock(&all_hbas_lock);
				end = gethrtime();
				duration = end - start;
				duration /= HR_SECOND;
				log(LOG_DEBUG, ROUTINE, "Took total\
				    of %.4f seconds", duration);
				return (status);
			}
		}

		if (chkDomainPort) {
			unlock(&open_handles_lock);
			unlock(&all_hbas_lock);
			log(LOG_DEBUG, ROUTINE, "Unable to located requested "
			    "Port %016llx on handle %08lx",
			    wwnConversion(targetPortWWN.wwn), handle);
			return (HBA_STATUS_ERROR_ILLEGAL_WWN);
		}
	}

	unlock(&open_handles_lock);
	unlock(&all_hbas_lock);
	if (hbaPortFound == 0) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to locate requested Port WWN %016llx on "
		    "handle %08lx", wwnConversion(portWWN.wwn), handle);
	} else if (chkDomainPort && !domainPortFound) {
		log(LOG_DEBUG, ROUTINE, "Unable to locate requested"
		    " domainPortWWN %016llx on handle %08lx",
		    wwnConversion(domainPortWWN.wwn), handle);
	} else {
		log(LOG_DEBUG, ROUTINE, "Unable to locate requested "
		    "Port WWN %016llx on handle %08lx",
		    wwnConversion(targetPortWWN.wwn), handle);
	}
	return (HBA_STATUS_ERROR_ILLEGAL_WWN);
}
