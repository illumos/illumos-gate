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
/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sun_sas.h>
#include <sys/scsi/impl/usmp.h>

/*
 * Pass usmp_cmd into ioctl
 */
static HBA_STATUS
SendSMPPassThru(const char *devpath, void *reqframe, HBA_UINT32 *reqsize,
    void *rspframe, HBA_UINT32 *rspsize)
{
	const char		ROUTINE[] = "SendSMPPassThru";
	int			fd;
	usmp_cmd_t		ucmd_buf;
	HBA_STATUS		ret;

	bzero(&ucmd_buf, sizeof (ucmd_buf));

	ucmd_buf.usmp_req = (caddr_t)reqframe;
	ucmd_buf.usmp_rsp = (caddr_t)rspframe;
	ucmd_buf.usmp_reqsize = (size_t)(*reqsize);
	ucmd_buf.usmp_rspsize = (size_t)(*rspsize);
	ucmd_buf.usmp_timeout = SMP_DEFAULT_TIMEOUT;

	/*
	 * open smp device
	 */

	if ((fd = open(devpath, O_RDONLY | O_NONBLOCK)) == -1) {
		log(LOG_DEBUG, ROUTINE,
		    "open devpath %s failed due to %s",
		    devpath, strerror(errno));
		return (HBA_STATUS_ERROR);
	}

	/*
	 * send usmp command
	 */
	if (ioctl(fd, USMPFUNC, &ucmd_buf) == -1) {
		if ((errno == ETIME) || (errno == ETIMEDOUT) ||
		    (errno == EAGAIN)) {
			ret = HBA_STATUS_ERROR_TRY_AGAIN;
		} else if (errno == EBUSY) {
			ret = HBA_STATUS_ERROR_BUSY;
		} else {
			ret = HBA_STATUS_ERROR;
		}
		log(LOG_DEBUG, ROUTINE, "ioctl:USMPFUNC failed due to %s",
		    strerror(errno));
		(void) close(fd);
		return (ret);
	}

	(void) close(fd);
	return (HBA_STATUS_OK);
}

/*
 * Send a USMP command to a remote SMP node
 */
HBA_STATUS
Sun_sasSendSMPPassThru(HBA_HANDLE handle, HBA_WWN hbaPortWWN,
    HBA_WWN destPortWWN, HBA_WWN domainPortWWN, void *pReqBuffer,
    HBA_UINT32 ReqBufferSize, void *pRspBuffer, HBA_UINT32 *pRspBufferSize)
{
	const char		ROUTINE[] = "Sun_sasSendSMPPassThru";
	HBA_STATUS		status;
	struct sun_sas_hba	*hba_ptr;
	int			domainPortFound = 0;
	int			chkDomainPort = 0;
	int			hbaPortFound = 0;
	struct sun_sas_port	*hba_port_ptr, *hba_disco_port;
	hrtime_t		start, end;
	double			duration;

	start = gethrtime();
	/* Validate the arguments */
	if (pRspBuffer == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL response buffer");
		return (HBA_STATUS_ERROR_ARG);
	}
	if (pReqBuffer == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL sense buffer");
		return (HBA_STATUS_ERROR_ARG);
	}
	if (pRspBufferSize == NULL) {
		log(LOG_DEBUG, ROUTINE, "NULL response size");
		return (HBA_STATUS_ERROR_ARG);
	}

	lock(&all_hbas_lock);
	if ((hba_ptr = Retrieve_Sun_sasHandle(handle)) == NULL) {
		log(LOG_DEBUG, ROUTINE, "Invalid handle %08lx", handle);
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR_INVALID_HANDLE);
	}

	/* Check for stale data */
	status = verifyAdapter(hba_ptr);
	if (status != HBA_STATUS_OK) {
		log(LOG_DEBUG, ROUTINE, "Verify adapter failed");
		unlock(&all_hbas_lock);
		return (status);
	}

	/*
	 * We are not checking to see if our data is stale.
	 * By verifying this information here, we will take a big performance
	 * hit.  This check will be done later only if the Inquiry ioctl fails
	 */

	if (hba_ptr->device_path[0] == '\0') {
		log(LOG_DEBUG, ROUTINE,
		    "HBA handle had empty device path.\
		    Unable to send SCSI cmd");
		unlock(&all_hbas_lock);
		return (HBA_STATUS_ERROR);
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
			    != wwnConversion(hbaPortWWN.wwn)) {
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
			 * If discoveredPort is not given targetPort, just skip
			 */
			if (wwnConversion(hba_disco_port->port_attributes.\
			    PortSpecificAttribute.SASPort->LocalSASAddress.wwn)
			    != wwnConversion(destPortWWN.wwn)) {
				/* Does not match */
				continue;
			}

			/*
			 * If matching targetPort does not support SMP protocal
			 * return error.
			 * comment it out for testing only
			 */
			if ((hba_disco_port->port_attributes.\
			    PortSpecificAttribute.SASPort->PortProtocol &
			    HBA_SASPORTPROTOCOL_SMP) == 0) {
				log(LOG_DEBUG, ROUTINE, "Input WWN %01611x\
				    does not support SMP protocol",
				    wwnConversion(hbaPortWWN.wwn));
				unlock(&all_hbas_lock);
				return (HBA_STATUS_ERROR_INVALID_PROTOCOL_TYPE);
			}

			/*
			 * SMP target port doesn't have any scsi info.
			 *   - like /dev/rdsk/cxtxdxsx
			 * So we use OSDeviceName from port attributes.
			 *   - like /dev/smp/expd[0-9]
			 */
			status = SendSMPPassThru(
			    hba_disco_port->port_attributes.OSDeviceName,
			    pReqBuffer, &ReqBufferSize,
			    pRspBuffer, pRspBufferSize);

			unlock(&all_hbas_lock);
			end = gethrtime();
			duration = end - start;
			duration /= HR_SECOND;
			log(LOG_DEBUG, ROUTINE, "Took total\
			    of %.4f seconds", duration);
			return (status);
		}
		if (chkDomainPort) {
			unlock(&all_hbas_lock);
			log(LOG_DEBUG, ROUTINE, "Unable to locate"
			    "requested SMP target port %16llx",
			    wwnConversion(destPortWWN.wwn));
			return (HBA_STATUS_ERROR_ILLEGAL_WWN);
		}
	}
	unlock(&all_hbas_lock);
	if (hbaPortFound == 0) {
		log(LOG_DEBUG, ROUTINE,
		    "Unable to locate requested Port WWN %016llx on "
		    "handle %08lx", wwnConversion(hbaPortWWN.wwn), handle);
	} else if (chkDomainPort && !domainPortFound) {
		log(LOG_DEBUG, ROUTINE, "Unable to locate requested"
		    " domainPortWWN %016llx on handle %08lx",
		    wwnConversion(domainPortWWN.wwn), handle);
	} else {
		log(LOG_DEBUG, ROUTINE, "Unable to locate"
		    "requested SMP target port %16llx",
		    wwnConversion(destPortWWN.wwn));
	}
	return (HBA_STATUS_ERROR_ILLEGAL_WWN);
}
