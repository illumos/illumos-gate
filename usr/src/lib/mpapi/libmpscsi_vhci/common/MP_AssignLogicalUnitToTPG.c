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

#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>

#include "mp_utils.h"


/*
 *	Called by the common layer to request the plugin to assign
 *	a logical unit to a TPG.  luOid is the logical unit to assign
 *	to the TPG, tpgOid.
 */

MP_STATUS
MP_AssignLogicalUnitToTPG(MP_OID tpgOid, MP_OID luOid)
{
	mp_lu_tpg_pair_t	tpgPair;
	mp_iocdata_t		mp_ioctl;

	int ioctlStatus = 0;

	MP_STATUS mpStatus = MP_STATUS_SUCCESS;



	log(LOG_INFO, "MP_AssignLogicalUnitToTPG()", " - enter");


	log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
		"tpgOid.objectSequenceNumber = %llx",
		tpgOid.objectSequenceNumber);

	log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
		"luOid.objectSequenceNumber  = %llx",
		luOid.objectSequenceNumber);


	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
		    "invalid driver file handle");
		log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
			" - error exit");
		return (MP_STATUS_FAILED);
	}

	(void) memset(&tpgPair, 0, sizeof (mp_lu_tpg_pair_t));
	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));

	tpgPair.tpgId = tpgOid.objectSequenceNumber;
	tpgPair.luId = luOid.objectSequenceNumber;

	mp_ioctl.mp_cmd  = MP_ASSIGN_LU_TO_TPG;
	mp_ioctl.mp_ibuf = (caddr_t)&tpgPair;
	mp_ioctl.mp_ilen = sizeof (mp_lu_tpg_pair_t);
	mp_ioctl.mp_xfer =  MP_XFER_WRITE;

	log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
		"mp_ioctl.mp_cmd (MP_ASSIGN_LU_TO_TPG) : %d",
		mp_ioctl.mp_cmd);

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

	log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
		" IOCTL call returned: %d", ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if (ioctlStatus != 0) {
		log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
		    "IOCTL call failed.  IOCTL error is: %d",
			ioctlStatus);
		log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
		    "IOCTL call failed.  IOCTL error is: %s",
			strerror(ioctlStatus));
		log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
		    "IOCTL call failed.  mp_ioctl.mp_errno: %x",
			mp_ioctl.mp_errno);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus = getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "MP_AssignLogicalUnitToTPG()",
			" - error exit, returning %d to caller.", mpStatus);

		return (mpStatus);
	}


	log(LOG_INFO, "MP_AssignLogicalUnitToTPG()", " - exit");

	return (MP_STATUS_SUCCESS);
}
