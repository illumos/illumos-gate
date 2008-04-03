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

#include	<hxge_impl.h>
#include	<hpi_vmac.h>
#include	<hpi_rxdma.h>

/*
 * System interrupt registers that are under function zero management.
 */
hxge_status_t
hxge_fzc_intr_init(p_hxge_t hxgep)
{
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_fzc_intr_init"));

	/* Configure the initial timer resolution */
	if ((status = hxge_fzc_intr_tmres_set(hxgep)) != HXGE_OK) {
		return (status);
	}

	/*
	 * Set up the logical device group's logical devices that
	 * the group owns.
	 */
	if ((status = hxge_fzc_intr_ldg_num_set(hxgep)) != HXGE_OK) {
		return (status);
	}

	/* Configure the system interrupt data */
	if ((status = hxge_fzc_intr_sid_set(hxgep)) != HXGE_OK) {
		return (status);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_fzc_intr_init"));

	return (status);
}

hxge_status_t
hxge_fzc_intr_ldg_num_set(p_hxge_t hxgep)
{
	p_hxge_ldg_t	ldgp;
	p_hxge_ldv_t	ldvp;
	hpi_handle_t	handle;
	int		i, j;
	hpi_status_t	rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_fzc_intr_ldg_num_set"));

	if (hxgep->ldgvp == NULL) {
		return (HXGE_ERROR);
	}

	ldgp = hxgep->ldgvp->ldgp;
	ldvp = hxgep->ldgvp->ldvp;
	if (ldgp == NULL || ldvp == NULL) {
		return (HXGE_ERROR);
	}

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	for (i = 0; i < hxgep->ldgvp->ldg_intrs; i++, ldgp++) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_fzc_intr_ldg_num_set "
		    "<== hxge_f(Hydra): # ldv %d in group %d", ldgp->nldvs,
		    ldgp->ldg));

		for (j = 0; j < ldgp->nldvs; j++, ldvp++) {
			rs = hpi_fzc_ldg_num_set(handle, ldvp->ldv,
			    ldvp->ldg_assigned);
			if (rs != HPI_SUCCESS) {
				HXGE_DEBUG_MSG((hxgep, INT_CTL,
				    "<== hxge_fzc_intr_ldg_num_set failed "
				    " rs 0x%x ldv %d ldg %d",
				    rs, ldvp->ldv, ldvp->ldg_assigned));
				return (HXGE_ERROR | rs);
			}
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "<== hxge_fzc_intr_ldg_num_set OK ldv %d ldg %d",
			    ldvp->ldv, ldvp->ldg_assigned));
		}
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_fzc_intr_ldg_num_set"));
	return (HXGE_OK);
}

hxge_status_t
hxge_fzc_intr_tmres_set(p_hxge_t hxgep)
{
	hpi_handle_t	handle;
	hpi_status_t	rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_fzc_intr_tmrese_set"));
	if (hxgep->ldgvp == NULL) {
		return (HXGE_ERROR);
	}

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	if ((rs = hpi_fzc_ldg_timer_res_set(handle, hxgep->ldgvp->tmres))) {
		return (HXGE_ERROR | rs);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_fzc_intr_tmrese_set"));
	return (HXGE_OK);
}

hxge_status_t
hxge_fzc_intr_sid_set(p_hxge_t hxgep)
{
	hpi_handle_t	handle;
	p_hxge_ldg_t	ldgp;
	fzc_sid_t	sid;
	int		i;
	hpi_status_t	rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_fzc_intr_sid_set"));
	if (hxgep->ldgvp == NULL) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "<== hxge_fzc_intr_sid_set: no ldg"));
		return (HXGE_ERROR);
	}

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	ldgp = hxgep->ldgvp->ldgp;
	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_fzc_intr_sid_set: #int %d", hxgep->ldgvp->ldg_intrs));
	for (i = 0; i < hxgep->ldgvp->ldg_intrs; i++, ldgp++) {
		sid.ldg = ldgp->ldg;
		sid.vector = ldgp->vector;
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_fzc_intr_sid_set(%d): group %d vector %d",
		    i, sid.ldg, sid.vector));
		rs = hpi_fzc_sid_set(handle, sid);
		if (rs != HPI_SUCCESS) {
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "<== hxge_fzc_intr_sid_set:failed 0x%x", rs));
			return (HXGE_ERROR | rs);
		}
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_fzc_intr_sid_set"));
	return (HXGE_OK);
}

/*
 * Receive DMA registers that are under function zero management.
 */
/*ARGSUSED*/
hxge_status_t
hxge_init_fzc_rxdma_channel(p_hxge_t hxgep, uint16_t channel,
	p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t mbox_p)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "==> hxge_init_fzc_rxdma_channel"));

	/* Initialize the RXDMA logical pages */
	status = hxge_init_fzc_rxdma_channel_pages(hxgep, channel, rbr_p);
	if (status != HXGE_OK)
		return (status);

	HXGE_DEBUG_MSG((hxgep, RX_CTL, "<== hxge_init_fzc_rxdma_channel"));
	return (status);
}

/*ARGSUSED*/
hxge_status_t
hxge_init_fzc_rxdma_channel_pages(p_hxge_t hxgep,
	uint16_t channel, p_rx_rbr_ring_t rbrp)
{
	hpi_handle_t handle;
	hpi_status_t rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_init_fzc_rxdma_channel_pages"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/* Initialize the page handle */
	rs = hpi_rxdma_cfg_logical_page_handle(handle, channel,
	    rbrp->page_hdl.bits.handle);
	if (rs != HPI_SUCCESS)
		return (HXGE_ERROR | rs);

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_init_fzc_rxdma_channel_pages"));
	return (HXGE_OK);
}

/*ARGSUSED*/
hxge_status_t
hxge_init_fzc_txdma_channel(p_hxge_t hxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p, p_tx_mbox_t mbox_p)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_init_fzc_txdma_channel"));

	/* Initialize the TXDMA logical pages */
	(void) hxge_init_fzc_txdma_channel_pages(hxgep, channel, tx_ring_p);

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "<== hxge_init_fzc_txdma_channel"));
	return (status);
}

hxge_status_t
hxge_init_fzc_rx_common(p_hxge_t hxgep)
{
	hpi_handle_t	handle;
	hpi_status_t	rs = HPI_SUCCESS;
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL, "==> hxge_init_fzc_rx_common"));
	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/*
	 * Configure the rxdma clock divider
	 * This is the granularity counter based on
	 * the hardware system clock (i.e. 300 Mhz) and
	 * it is running around 3 nanoseconds.
	 * So, set the clock divider counter to 1000 to get
	 * microsecond granularity.
	 * For example, for a 3 microsecond timeout, the timeout
	 * will be set to 1.
	 */
	rs = hpi_rxdma_cfg_clock_div_set(handle, RXDMA_CK_DIV_DEFAULT);
	if (rs != HPI_SUCCESS)
		return (HXGE_ERROR | rs);

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "<== hxge_init_fzc_rx_common:status 0x%08x", status));
	return (status);
}

hxge_status_t
hxge_init_fzc_txdma_channel_pages(p_hxge_t hxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p)
{
	hpi_handle_t		handle;
	hpi_status_t		rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, DMA_CTL,
	    "==> hxge_init_fzc_txdma_channel_pages"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	/* Initialize the page handle */
	rs = hpi_txdma_log_page_handle_set(handle, channel,
	    &tx_ring_p->page_hdl);

	if (rs == HPI_SUCCESS)
		return (HXGE_OK);
	else
		return (HXGE_ERROR | rs);
}

hxge_status_t
hxge_fzc_sys_err_mask_set(p_hxge_t hxgep, boolean_t mask)
{
	hpi_status_t	rs = HPI_SUCCESS;
	hpi_handle_t	handle;

	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	rs = hpi_fzc_sys_err_mask_set(handle, mask);
	if (rs == HPI_SUCCESS)
		return (HXGE_OK);
	else
		return (HXGE_ERROR | rs);
}
