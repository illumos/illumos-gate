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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * Generic Capabilities Routines
 *
 */

#include <sys/scsi/scsi.h>

#define	A_TO_TRAN(ap)	(ap->a_hba_tran)

int
scsi_ifgetcap(struct scsi_address *ap, char *cap, int whom)
{
	return (*A_TO_TRAN(ap)->tran_getcap)(ap, cap, whom);
}

int
scsi_ifsetcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int rval;
	int cidx;

	rval = (*A_TO_TRAN(ap)->tran_setcap)(ap, cap, value, whom);
	if (rval == 1) {
		cidx = scsi_hba_lookup_capstr(cap);
		if (cidx == SCSI_CAP_SECTOR_SIZE) {
			/*
			 * if we have successfully changed the
			 * granularity update SCSA's copy
			 */
			A_TO_TRAN(ap)->tran_dma_attr.dma_attr_granular =
				value;
		}
	}
	return (rval);
}
