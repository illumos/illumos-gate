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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ghd.h"

void
ghd_dmafree_attr(gcmd_t *gcmdp)
{
	GDBG_DMA(("ghd_dma_attr_free: gcmdp 0x%p\n", (void *)gcmdp));

	if (gcmdp->cmd_dma_handle != NULL) {
		if (ddi_dma_unbind_handle(gcmdp->cmd_dma_handle) !=
		    DDI_SUCCESS)
			cmn_err(CE_WARN, "ghd dma free attr: "
			    "unbind handle failed");
		ddi_dma_free_handle(&gcmdp->cmd_dma_handle);
		GDBG_DMA(("ghd_dma_attr_free: ddi_dma_free 0x%p\n",
		    (void *)gcmdp));
		gcmdp->cmd_dma_handle = NULL;
		gcmdp->cmd_ccount = 0;
		gcmdp->cmd_totxfer = 0;
	}
}


int
ghd_dma_buf_bind_attr(ccc_t		*cccp,
			gcmd_t		*gcmdp,
			struct buf	*bp,
			int		 dma_flags,
			int		(*callback)(),
			caddr_t		 arg,
			ddi_dma_attr_t	*sg_attrp)
{
	int	 status;

	GDBG_DMA(("ghd_dma_attr_get: start: gcmdp 0x%p sg_attrp 0x%p\n",
	    (void *)gcmdp, (void *)sg_attrp));


	/*
	 * First time, need to establish the handle.
	 */

	ASSERT(gcmdp->cmd_dma_handle == NULL);

	status = ddi_dma_alloc_handle(cccp->ccc_hba_dip, sg_attrp, callback,
	    arg, &gcmdp->cmd_dma_handle);

	if (status != DDI_SUCCESS) {
		bp->b_error = 0;
		return (FALSE);
	}

	status = ddi_dma_buf_bind_handle(gcmdp->cmd_dma_handle, bp, dma_flags,
	    callback, arg, &gcmdp->cmd_first_cookie, &gcmdp->cmd_ccount);

	GDBG_DMA(("ghd_dma_attr_get: setup: gcmdp 0x%p status %d h 0x%p "
	    "c 0x%d\n", (void *)gcmdp, status, (void *)gcmdp->cmd_dma_handle,
	    gcmdp->cmd_ccount));

	switch (status) {
	case DDI_DMA_MAPPED:
		/* enable first (and only) call to ddi_dma_getwin */
		gcmdp->cmd_wcount = 1;
		break;

	case DDI_DMA_PARTIAL_MAP:
		/* enable first call to ddi_dma_getwin */
		if (ddi_dma_numwin(gcmdp->cmd_dma_handle, &gcmdp->cmd_wcount) !=
		    DDI_SUCCESS) {
			bp->b_error = 0;
			ddi_dma_free_handle(&gcmdp->cmd_dma_handle);
			gcmdp->cmd_dma_handle = NULL;
			return (FALSE);
		}
		break;

	case DDI_DMA_NORESOURCES:
		bp->b_error = 0;
		ddi_dma_free_handle(&gcmdp->cmd_dma_handle);
		gcmdp->cmd_dma_handle = NULL;
		return (FALSE);

	case DDI_DMA_TOOBIG:
		bioerror(bp, EINVAL);
		ddi_dma_free_handle(&gcmdp->cmd_dma_handle);
		gcmdp->cmd_dma_handle = NULL;
		return (FALSE);

	case DDI_DMA_NOMAPPING:
	case DDI_DMA_INUSE:
	default:
		bioerror(bp, EFAULT);
		ddi_dma_free_handle(&gcmdp->cmd_dma_handle);
		gcmdp->cmd_dma_handle = NULL;
		return (FALSE);
	}

	/* initialize the loop controls for ghd_dmaget_next_attr() */
	gcmdp->cmd_windex = 0;
	gcmdp->cmd_cindex = 0;
	gcmdp->cmd_totxfer = 0;
	gcmdp->cmd_dma_flags = dma_flags;
	gcmdp->use_first = 1;
	return (TRUE);
}


uint_t
ghd_dmaget_next_attr(ccc_t *cccp, gcmd_t *gcmdp, long max_transfer_cnt,
    int sg_size, ddi_dma_cookie_t cookie)
{
	ulong_t	toxfer = 0;
	int	num_segs = 0;
	int	single_seg;

	GDBG_DMA(("ghd_dma_attr_get: start: gcmdp 0x%p h 0x%p c 0x%x\n",
	    (void *)gcmdp, (void *)gcmdp->cmd_dma_handle, gcmdp->cmd_ccount));

	/*
	 * Disable single-segment Scatter/Gather option
	 * if can't do this transfer in a single segment,
	 */
	if (gcmdp->cmd_cindex + 1 < gcmdp->cmd_ccount) {
		single_seg = FALSE;
	} else {
		single_seg = TRUE;
	}


	for (;;) {
		/*
		 * call the controller specific S/G function
		 */
		(*cccp->ccc_sg_func)(gcmdp, &cookie, single_seg, num_segs);

		/* take care of the loop-bookkeeping */
		toxfer += cookie.dmac_size;
		num_segs++;
		gcmdp->cmd_cindex++;

		/*
		 * if this was the last cookie in the current window
		 * set the loop controls start the next window and
		 * exit so the HBA can do this partial transfer
		 */
		if (gcmdp->cmd_cindex >= gcmdp->cmd_ccount) {
			gcmdp->cmd_windex++;
			gcmdp->cmd_cindex = 0;
			break;
		}
		ASSERT(single_seg == FALSE);

		if (toxfer >= max_transfer_cnt)
			break;

		if (num_segs >= sg_size)
			break;

		ddi_dma_nextcookie(gcmdp->cmd_dma_handle, &cookie);
	}

	gcmdp->cmd_totxfer += toxfer;

	return (toxfer);
}



int
ghd_dmaget_attr(ccc_t		*cccp,
		gcmd_t		*gcmdp,
		long		count,
		int		sg_size,
		uint_t		*xfer)
{
	int	status;
	ddi_dma_cookie_t cookie;

	*xfer = 0;


	if (gcmdp->use_first == 1) {
		cookie = gcmdp->cmd_first_cookie;
		gcmdp->use_first = 0;
	} else if (gcmdp->cmd_windex >= gcmdp->cmd_wcount) {
		/*
		 * reached the end of buffer. This should not happen.
		 */
		ASSERT(gcmdp->cmd_windex < gcmdp->cmd_wcount);
		return (FALSE);

	} else if (gcmdp->cmd_cindex == 0) {
		off_t	offset;
		size_t	length;

		/*
		 * start the next window, and get its first cookie
		 */
		status = ddi_dma_getwin(gcmdp->cmd_dma_handle,
		    gcmdp->cmd_windex, &offset, &length,
		    &cookie, &gcmdp->cmd_ccount);
		if (status != DDI_SUCCESS)
			return (FALSE);

	} else {
		/*
		 * get the next cookie in the current window
		 */
		ddi_dma_nextcookie(gcmdp->cmd_dma_handle, &cookie);
	}

	/*
	 * start the Scatter/Gather loop passing in the first
	 * cookie obtained above
	 */
	*xfer = ghd_dmaget_next_attr(cccp, gcmdp, count, sg_size, cookie);
	return (TRUE);
}
