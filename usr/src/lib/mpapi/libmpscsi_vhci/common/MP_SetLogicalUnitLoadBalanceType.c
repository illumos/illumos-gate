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
/*
 * Copyright 2025 Hans Rosenfeld
 */

#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>

#include "mp_utils.h"


MP_STATUS
MP_SetLogicalUnitLoadBalanceType(MP_OID logicalUnitOid,
    MP_LOAD_BALANCE_TYPE loadBalance)
{
	mp_iocdata_t mp_ioctl;
	mp_set_lu_lb_type_req_t setLuLoadBalanceType;

	int ioctlStatus = 0;

	MP_STATUS mpStatus = MP_STATUS_SUCCESS;


	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()", " - enter");


	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    " - logicalUnitOid.objectSequenceNumber: %llx",
	    logicalUnitOid.objectSequenceNumber);

	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
		    "invalid driver file handle");
		log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
		    " - error exit");
		return (MP_STATUS_FAILED);
	}

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    " - loadBalance: %d", loadBalance);

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    "logicalUnitOid.ownerId = %d", logicalUnitOid.ownerId);

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    "logicalUnitOid.objectType = %d", logicalUnitOid.objectType);

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    "logicalUnitOid.objectSequenceNumber = %llx",
	    logicalUnitOid.objectSequenceNumber);

	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
	(void) memset(&setLuLoadBalanceType, 0,
	    sizeof (mp_set_lu_lb_type_req_t));

	setLuLoadBalanceType.desiredType = loadBalance;
	setLuLoadBalanceType.luId = logicalUnitOid.objectSequenceNumber;

	mp_ioctl.mp_cmd  = MP_SET_LU_LOADBALANCE_TYPE;
	mp_ioctl.mp_ibuf = (caddr_t)&setLuLoadBalanceType;
	mp_ioctl.mp_ilen = sizeof (mp_set_lu_lb_type_req_t);
	mp_ioctl.mp_xfer =  MP_XFER_WRITE;

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    "mp_ioctl.mp_cmd (MP_SET_LU_LOADBALANCE_TYPE) : %d",
	    mp_ioctl.mp_cmd);

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    "setLuLoadBalanceType.luId = %llx",
	    setLuLoadBalanceType.luId);

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    "setLuLoadBalanceType.desiredType = %u",
	    setLuLoadBalanceType.desiredType);

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
	    " IOCTL call returned: %d", ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if (ioctlStatus != 0) {
		log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
		    "IOCTL call failed.  IOCTL error is: %d", ioctlStatus);
		log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
		    "IOCTL call failed.  IOCTL error is: %s",
		    strerror(ioctlStatus));
		log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
		    "IOCTL call failed.  mp_ioctl.mp_errno: %x",
		    mp_ioctl.mp_errno);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus =
			    getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()",
		    " - error exit");

		return (mpStatus);
	}

	log(LOG_INFO, "MP_SetLogicalUnitLoadBalanceType()", " - exit");

	return (MP_STATUS_SUCCESS);
}
