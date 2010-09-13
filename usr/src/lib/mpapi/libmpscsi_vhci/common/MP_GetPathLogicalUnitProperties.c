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
MP_GetPathLogicalUnitProperties(MP_OID oid,
	MP_PATH_LOGICAL_UNIT_PROPERTIES *pProps)
{
	mp_iocdata_t   	mp_ioctl;
	mp_path_prop_t	pathInfo;

	int ioctlStatus = 0;

	MP_OID initPortOID;
	MP_OID targetPortOID;
	MP_OID luOID;

	MP_STATUS mpStatus = MP_STATUS_SUCCESS;



	log(LOG_INFO, "MP_GetPathLogicalUnitProperties()", " - enter");


	log(LOG_INFO, "MP_GetPathLogicalUnitProperties()",
		"oid.objectSequenceNumber = %llx",
		oid.objectSequenceNumber);


	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_GetPathLogicalUnitProperties()",
		    "invalid driver file handle");
		log(LOG_INFO, "MP_GetPathLogicalUnitProperties()",
			" - error exit");
		return (MP_STATUS_FAILED);
	}

	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
	(void) memset(&pathInfo, 0, sizeof (mp_path_prop_t));

	mp_ioctl.mp_cmd  = MP_GET_PATH_PROP;
	mp_ioctl.mp_ibuf = (caddr_t)&oid.objectSequenceNumber;
	mp_ioctl.mp_ilen = sizeof (oid.objectSequenceNumber);
	mp_ioctl.mp_obuf = (caddr_t)&pathInfo;
	mp_ioctl.mp_olen = sizeof (mp_path_prop_t);
	mp_ioctl.mp_xfer = MP_XFER_READ;

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

	log(LOG_INFO, "MP_GetPathLogicalUnitProperties()",
		" IOCTL call returned: %d", ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if (ioctlStatus != 0) {
		log(LOG_INFO, "MP_GetPathLogicalUnitProperties()",
		    "IOCTL call failed.  IOCTL error is: %d",
			ioctlStatus);
		log(LOG_INFO, "MP_GetPathLogicalUnitProperties()",
		    "IOCTL call failed.  IOCTL error is: %s",
			strerror(ioctlStatus));
		log(LOG_INFO, "MP_GetPathLogicalUnitProperties()",
		    "IOCTL call failed.  mp_ioctl.mp_errno: %x",
			mp_ioctl.mp_errno);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus = getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "MP_GetPathLogicalUnitProperties()",
			" - error exit");

		return (mpStatus);
	}

	(void) memset(pProps, 0, sizeof (MP_PATH_LOGICAL_UNIT_PROPERTIES));

	pProps->disabled = pathInfo.disabled;

	initPortOID.objectSequenceNumber = pathInfo.initPort.id;
	initPortOID.objectType = MP_OBJECT_TYPE_INITIATOR_PORT;
	initPortOID.ownerId = g_pluginOwnerID;

	(void) memcpy(&pProps->initiatorPortOid, &initPortOID, sizeof (MP_OID));

	targetPortOID.objectSequenceNumber = pathInfo.targetPort.id;
	targetPortOID.objectType = MP_OBJECT_TYPE_TARGET_PORT;
	targetPortOID.ownerId = g_pluginOwnerID;

	(void) memcpy(&pProps->targetPortOid, &targetPortOID, sizeof (MP_OID));

	luOID.objectSequenceNumber = pathInfo.logicalUnit.id;
	luOID.objectType = MP_OBJECT_TYPE_MULTIPATH_LU;
	luOID.ownerId = g_pluginOwnerID;

	(void) memcpy(&pProps->logicalUnitOid, &luOID, sizeof (MP_OID));

	pProps->logicalUnitNumber = pathInfo.logicalUnit.id;

	switch (pathInfo.pathState) {

		case MP_DRVR_PATH_STATE_ACTIVE:
		case MP_DRVR_PATH_STATE_PASSIVE:
			pProps->pathState = MP_PATH_STATE_OKAY;
			break;

		case MP_DRVR_PATH_STATE_PATH_ERR:
			pProps->pathState = MP_PATH_STATE_PATH_ERR;
			break;

		case MP_DRVR_PATH_STATE_LU_ERR:
			pProps->pathState = MP_PATH_STATE_LU_ERR;
			break;

		case MP_DRVR_PATH_STATE_RESERVED:
			pProps->pathState = MP_PATH_STATE_RESERVED;
			break;

		case MP_DRVR_PATH_STATE_REMOVED:
			pProps->pathState = MP_PATH_STATE_REMOVED;
			break;

		case MP_DRVR_PATH_STATE_TRANSITIONING:
			pProps->pathState = MP_PATH_STATE_TRANSITIONING;
			break;

		default:
			pProps->pathState = MP_PATH_STATE_UNKNOWN;

	}

	pProps->weight = pathInfo.weight;


	log(LOG_INFO, "MP_GetPathLogicalUnitProperties()", " - exit");

	return (MP_STATUS_SUCCESS);
}
