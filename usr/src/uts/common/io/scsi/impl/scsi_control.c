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
 * Generic Abort, Reset and Misc Routines
 */

#include <sys/scsi/scsi.h>


#define	A_TO_TRAN(ap)	(ap->a_hba_tran)

int
scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	return (*A_TO_TRAN(ap)->tran_abort)(ap, pkt);
}

int
scsi_reset(struct scsi_address *ap, int level)
{
	ASSERT((level == RESET_LUN) || (level == RESET_TARGET) ||
	    (level == RESET_ALL));
	if ((level == RESET_LUN) &&
	    ((*A_TO_TRAN(ap)->tran_getcap)(ap, "lun-reset", 1) != 1)) {
		return (0);
	}
	if ((A_TO_TRAN(ap)->tran_reset) == NULL) {
		return (0);
	}
	return (*A_TO_TRAN(ap)->tran_reset)(ap, level);
}

int
scsi_reset_notify(struct scsi_address *ap, int flag,
	void (*callback)(caddr_t), caddr_t arg)
{
	if ((A_TO_TRAN(ap)->tran_reset_notify) == NULL) {
		return (DDI_FAILURE);
	}
	return (*A_TO_TRAN(ap)->tran_reset_notify)(ap, flag, callback, arg);
}

int
scsi_clear_task_set(struct scsi_address *ap)
{
	if ((A_TO_TRAN(ap)->tran_clear_task_set) == NULL) {
		return (-1);
	}
	return (*A_TO_TRAN(ap)->tran_clear_task_set)(ap);
}

int
scsi_terminate_task(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	if ((A_TO_TRAN(ap)->tran_terminate_task) == NULL) {
		return (-1);
	}
	return (*A_TO_TRAN(ap)->tran_terminate_task)(ap, pkt);
}

/*
 * Other Misc Routines
 */

int
scsi_clear_aca(struct scsi_address *ap)
{
	if ((A_TO_TRAN(ap)->tran_clear_aca) == NULL) {
		return (-1);
	}
	return (*A_TO_TRAN(ap)->tran_clear_aca)(ap);
}
