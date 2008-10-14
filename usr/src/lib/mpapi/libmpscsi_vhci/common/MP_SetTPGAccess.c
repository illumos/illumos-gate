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


/*
 *	Called by the common layer to request the plugin to set the
 *	access state for a list of target port groups.
 */

MP_STATUS
MP_SetTPGAccess(MP_OID oid, MP_UINT32 count,
	MP_TPG_STATE_PAIR *pTpgStateList)
{

	MP_TPG_STATE_PAIR *head = pTpgStateList;

	mp_iocdata_t		mp_ioctl;
	mp_set_tpg_state_req_t	setTpgStateRequest;

	int r = 0;

	int ioctlStatus = 0;

	MP_STATUS mpStatus = MP_STATUS_SUCCESS;



	log(LOG_INFO, "MP_SetTPGAccess()", " - enter");


	if (NULL == pTpgStateList) {

		log(LOG_INFO, "MP_SetTPGAccess()",
			"pTpgStateList is NULL");

		return (MP_STATUS_INVALID_PARAMETER);
	}


	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_SetTPGAccess()",
		    "invalid driver file handle");
		log(LOG_INFO, "MP_SetTPGAccess()", " - error exit");
		return (MP_STATUS_FAILED);
	}


	log(LOG_INFO, "MP_SetTPGAccess()",
		"oid.ownerId = %d",
		oid.ownerId);

	log(LOG_INFO, "MP_SetTPGAccess()",
		"oid.objectType = %d",
		oid.objectType);

	log(LOG_INFO, "MP_SetTPGAccess()",
		"oid.objectSequenceNumber = %llx",
		oid.objectSequenceNumber);


	log(LOG_INFO, "MP_SetTPGAccess()",
		"count = %d",
		count);


	for (r = 0; r < count; r++) {

		if (head->tpgOid.ownerId != g_pluginOwnerID) {

			log(LOG_INFO, "MP_SetTPGAccess()",
				"pTpgStateList->tpgOid.ownerId is not for"
				" this plugin");

			log(LOG_INFO, "MP_SetTPGAccess()",
				"error exit");

			return (MP_STATUS_INVALID_PARAMETER);
		}

		if (head->tpgOid.objectType !=
		    MP_OBJECT_TYPE_TARGET_PORT_GROUP) {

			log(LOG_INFO, "MP_SetTPGAccess()",
				"pTpgStateList->tpgOid.objectType is not"
				" MP_OBJECT_TYPE_TARGET_PORT_GROUP");

			log(LOG_INFO, "MP_SetTPGAccess()",
				"error exit");

			return (MP_STATUS_INVALID_PARAMETER);
		}


		head++;
	}


	head = pTpgStateList;

	for (r = 0; r < count; r++) {

		(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
		(void) memset(&setTpgStateRequest, 0,
		    sizeof (mp_set_tpg_state_req_t));

		setTpgStateRequest.desiredState
			= head->desiredState;
		setTpgStateRequest.luTpgPair.luId
			= oid.objectSequenceNumber;
		setTpgStateRequest.luTpgPair.tpgId
			= head->tpgOid.objectSequenceNumber;

		mp_ioctl.mp_cmd  = MP_SET_TPG_ACCESS_STATE;
		mp_ioctl.mp_ibuf = (caddr_t)&setTpgStateRequest;
		mp_ioctl.mp_ilen = sizeof (mp_set_tpg_state_req_t);
		mp_ioctl.mp_xfer  = MP_XFER_WRITE;

		log(LOG_INFO, "MP_SetTPGAccess()",
			"mp_ioctl.mp_cmd (MP_SET_TPG_ACCESS_STATE) : %d",
			mp_ioctl.mp_cmd);

		log(LOG_INFO, "MP_SetTPGAccess()",
			"setTpgStateRequest.luTpgPair.luId  = %llx",
			setTpgStateRequest.luTpgPair.luId);

		log(LOG_INFO, "MP_SetTPGAccess()",
			"setTpgStateRequest.luTpgPair.tpgId = %llx",
			setTpgStateRequest.luTpgPair.tpgId);

		log(LOG_INFO, "MP_SetTPGAccess()",
			"setTpgStateRequest.desiredState    = %d",
			setTpgStateRequest.desiredState);

		ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

		log(LOG_INFO, "MP_SetTPGAccess()",
			" IOCTL call returned: %d", ioctlStatus);

		if (ioctlStatus < 0) {
			ioctlStatus = errno;
		}

		if (ioctlStatus != 0) {
			log(LOG_INFO, "MP_SetTPGAccess()",
				"IOCTL call failed.  IOCTL error is: %d",
				ioctlStatus);
			log(LOG_INFO, "MP_SetTPGAccess()",
				"IOCTL call failed.  IOCTL error is: %s",
				strerror(ioctlStatus));
			log(LOG_INFO, "MP_SetTPGAccess()",
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

			log(LOG_INFO, "MP_SetTPGAccess()",
				" - error exit");

			return (mpStatus);
		}

		head++;
	}


	log(LOG_INFO, "MP_SetTPGAccess()", " - exit");

	return (MP_STATUS_SUCCESS);
}
