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

#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>

#include "mp_utils.h"



MP_STATUS
MP_GetTargetPortProperties(MP_OID oid,
	MP_TARGET_PORT_PROPERTIES *pProps)
{
	mp_iocdata_t		mp_ioctl;
	mp_target_port_prop_t	tpInfo;

	int ioctlStatus = 0;

	MP_STATUS mpStatus = MP_STATUS_SUCCESS;



	log(LOG_INFO, "MP_GetTargetPortProperties()", " - enter");


	log(LOG_INFO, "MP_GetTargetPortProperties()",
		"oid.objectSequenceNumber = %llx",
		oid.objectSequenceNumber);

	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_GetTargetPortProperties()",
		    "invalid driver file handle");
		log(LOG_INFO, "MP_GetTargetPortProperties()", " - error exit");
		return (MP_STATUS_FAILED);
	}

	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
	(void) memset(&tpInfo,   0, sizeof (mp_target_port_prop_t));

	mp_ioctl.mp_cmd  = MP_GET_TARGET_PORT_PROP;
	mp_ioctl.mp_ibuf = (caddr_t)&oid.objectSequenceNumber;
	mp_ioctl.mp_ilen = sizeof (oid.objectSequenceNumber);
	mp_ioctl.mp_obuf = (caddr_t)&tpInfo;
	mp_ioctl.mp_olen = sizeof (mp_target_port_prop_t);
	mp_ioctl.mp_xfer = MP_XFER_READ;

	log(LOG_INFO, "MP_GetTargetPortProperties()",
		"mp_ioctl.mp_cmd (MP_GET_TARGET_PORT_PROP) : %d",
		mp_ioctl.mp_cmd);

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

	log(LOG_INFO, "MP_GetTargetPortProperties()",
		" IOCTL call returned: %d", ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if (ioctlStatus != 0) {
		log(LOG_INFO, "MP_GetTargetPortProperties()",
		    "IOCTL call failed.  IOCTL error is: %d",
			ioctlStatus);
		log(LOG_INFO, "MP_GetTargetPortProperties()",
		    "IOCTL call failed.  IOCTL error is: %s",
			strerror(ioctlStatus));
		log(LOG_INFO, "MP_GetTargetPortProperties()",
		    "IOCTL call failed.  mp_ioctl.mp_errno: %x",
			mp_ioctl.mp_errno);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus = getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "MP_GetTargetPortProperties()",
			" - error exit");

		return (mpStatus);
	}

	(void) memset(pProps, 0, sizeof (MP_TARGET_PORT_PROPERTIES));

	(void) strncpy(pProps->portID, tpInfo.portName,
	    sizeof (pProps->portID));
	pProps->relativePortID = tpInfo.relativePortID;


	log(LOG_INFO, "MP_GetTargetPortProperties()", " - exit");

	return (MP_STATUS_SUCCESS);
}
