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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * Generic Capabilities Routines
 *
 */

#include <sys/scsi/scsi.h>
#ifdef	__x86
#include <sys/ddi_isa.h>
#endif

#define	A_TO_TRAN(ap)	(ap->a_hba_tran)


int
scsi_ifgetcap(struct scsi_address *ap, char *cap, int whom)
{
	int capability;
#ifdef	__x86
	ddi_dma_attr_t *dmaattr;
	int ckey;
#endif


	capability = (*A_TO_TRAN(ap)->tran_getcap)(ap, cap, whom);

#ifdef	__x86
	if (cap != NULL) {
		ckey = scsi_hba_lookup_capstr(cap);
		dmaattr = &ap->a_hba_tran->tran_dma_attr;
		switch (ckey) {
		case SCSI_CAP_DMA_MAX:
			/*
			 * If the HBA is unable to reach all the memory in
			 * the system, the maximum copy buffer size may limit
			 * the size of the max DMA.
			 */
			if (i_ddi_copybuf_required(dmaattr)) {
				capability = MIN(capability,
				    i_ddi_copybuf_size());
			}

			/*
			 * make sure the value we return is a whole multiple of
			 * the granlarity.
			 */
			if (dmaattr->dma_attr_granular > 1) {
				capability = capability -
				    (capability % dmaattr->dma_attr_granular);
			}

			break;

		case SCSI_CAP_DMA_MAX_ARCH:
			capability = i_ddi_dma_max(ap->a_hba_tran->tran_hba_dip,
			    dmaattr);

			break;

		/*FALLTHROUGH*/
		}
	}
#endif

	return (capability);
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
