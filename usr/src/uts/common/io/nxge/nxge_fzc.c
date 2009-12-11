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

#include	<nxge_impl.h>
#include	<npi_mac.h>
#include	<npi_rxdma.h>
#include	<nxge_hio.h>

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
static int	nxge_herr2kerr(uint64_t);
static uint64_t nxge_init_hv_fzc_lp_op(p_nxge_t, uint64_t,
    uint64_t, uint64_t, uint64_t, uint64_t);
#endif

static nxge_status_t nxge_init_fzc_rdc_pages(p_nxge_t,
    uint16_t, dma_log_page_t *, dma_log_page_t *);

static nxge_status_t nxge_init_fzc_tdc_pages(p_nxge_t,
    uint16_t, dma_log_page_t *, dma_log_page_t *);

/*
 * The following interfaces are controlled by the
 * function control registers. Some global registers
 * are to be initialized by only byt one of the 2/4 functions.
 * Use the test and set register.
 */
/*ARGSUSED*/
nxge_status_t
nxge_test_and_set(p_nxge_t nxgep, uint8_t tas)
{
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	if ((rs = npi_dev_func_sr_sr_get_set_clear(handle, tas))
	    != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	return (NXGE_OK);
}

nxge_status_t
nxge_set_fzc_multi_part_ctl(p_nxge_t nxgep, boolean_t mpc)
{
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_set_fzc_multi_part_ctl"));

	/*
	 * In multi-partitioning, the partition manager
	 * who owns function zero should set this multi-partition
	 * control bit.
	 */
	if (nxgep->use_partition && nxgep->function_num) {
		return (NXGE_ERROR);
	}

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	if ((rs = npi_fzc_mpc_set(handle, mpc)) != NPI_SUCCESS) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "<== nxge_set_fzc_multi_part_ctl"));
		return (NXGE_ERROR | rs);
	}

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_set_fzc_multi_part_ctl"));

	return (NXGE_OK);
}

nxge_status_t
nxge_get_fzc_multi_part_ctl(p_nxge_t nxgep, boolean_t *mpc_p)
{
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_get_fzc_multi_part_ctl"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	if ((rs = npi_fzc_mpc_get(handle, mpc_p)) != NPI_SUCCESS) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "<== nxge_set_fzc_multi_part_ctl"));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_get_fzc_multi_part_ctl"));

	return (NXGE_OK);
}

/*
 * System interrupt registers that are under function zero
 * management.
 */
nxge_status_t
nxge_fzc_intr_init(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_fzc_intr_init"));

	/* Configure the initial timer resolution */
	if ((status = nxge_fzc_intr_tmres_set(nxgep)) != NXGE_OK) {
		return (status);
	}

	if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		/*
		 * Set up the logical device group's logical devices that
		 * the group owns.
		 */
		if ((status = nxge_fzc_intr_ldg_num_set(nxgep)) != NXGE_OK)
			goto fzc_intr_init_exit;

		/* Configure the system interrupt data */
		if ((status = nxge_fzc_intr_sid_set(nxgep)) != NXGE_OK)
			goto fzc_intr_init_exit;
	}

fzc_intr_init_exit:

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_fzc_intr_init"));

	return (status);
}

nxge_status_t
nxge_fzc_intr_ldg_num_set(p_nxge_t nxgep)
{
	p_nxge_ldg_t	ldgp;
	p_nxge_ldv_t	ldvp;
	npi_handle_t	handle;
	int		i, j;
	npi_status_t	rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_fzc_intr_ldg_num_set"));

	if (nxgep->ldgvp == NULL) {
		return (NXGE_ERROR);
	}

	ldgp = nxgep->ldgvp->ldgp;
	ldvp = nxgep->ldgvp->ldvp;
	if (ldgp == NULL || ldvp == NULL) {
		return (NXGE_ERROR);
	}

	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	for (i = 0; i < nxgep->ldgvp->ldg_intrs; i++, ldgp++) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
		    "==> nxge_fzc_intr_ldg_num_set "
		    "<== nxge_f(Neptune): # ldv %d "
		    "in group %d", ldgp->nldvs, ldgp->ldg));

		for (j = 0; j < ldgp->nldvs; j++, ldvp++) {
			rs = npi_fzc_ldg_num_set(handle, ldvp->ldv,
			    ldvp->ldg_assigned);
			if (rs != NPI_SUCCESS) {
				NXGE_DEBUG_MSG((nxgep, INT_CTL,
				    "<== nxge_fzc_intr_ldg_num_set failed "
				    " rs 0x%x ldv %d ldg %d",
				    rs, ldvp->ldv, ldvp->ldg_assigned));
				return (NXGE_ERROR | rs);
			}
			NXGE_DEBUG_MSG((nxgep, INT_CTL,
			    "<== nxge_fzc_intr_ldg_num_set OK "
			    " ldv %d ldg %d",
			    ldvp->ldv, ldvp->ldg_assigned));
		}
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_fzc_intr_ldg_num_set"));

	return (NXGE_OK);
}

nxge_status_t
nxge_fzc_intr_tmres_set(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_fzc_intr_tmrese_set"));
	if (nxgep->ldgvp == NULL) {
		return (NXGE_ERROR);
	}
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	if ((rs = npi_fzc_ldg_timer_res_set(handle, nxgep->ldgvp->tmres))) {
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_fzc_intr_tmrese_set"));

	return (NXGE_OK);
}

nxge_status_t
nxge_fzc_intr_sid_set(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	p_nxge_ldg_t	ldgp;
	fzc_sid_t	sid;
	int		i;
	npi_status_t	rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_fzc_intr_sid_set"));
	if (nxgep->ldgvp == NULL) {
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
		    "<== nxge_fzc_intr_sid_set: no ldg"));
		return (NXGE_ERROR);
	}
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	ldgp = nxgep->ldgvp->ldgp;
	NXGE_DEBUG_MSG((nxgep, INT_CTL,
	    "==> nxge_fzc_intr_sid_set: #int %d", nxgep->ldgvp->ldg_intrs));
	for (i = 0; i < nxgep->ldgvp->ldg_intrs; i++, ldgp++) {
		sid.ldg = ldgp->ldg;
		sid.niu = B_FALSE;
		sid.func = ldgp->func;
		sid.vector = ldgp->vector;
		NXGE_DEBUG_MSG((nxgep, INT_CTL,
		    "==> nxge_fzc_intr_sid_set(%d): func %d group %d "
		    "vector %d",
		    i, sid.func, sid.ldg, sid.vector));
		rs = npi_fzc_sid_set(handle, sid);
		if (rs != NPI_SUCCESS) {
			NXGE_DEBUG_MSG((nxgep, INT_CTL,
			    "<== nxge_fzc_intr_sid_set:failed 0x%x",
			    rs));
			return (NXGE_ERROR | rs);
		}
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_fzc_intr_sid_set"));

	return (NXGE_OK);

}

/*
 * nxge_init_fzc_rdc
 *
 *	Initialize all of a RDC's FZC_DMC registers.
 *	This is executed by the service domain, on behalf of a
 *	guest domain, who cannot access these registers.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to initialize.
 *
 * NPI_NXGE function calls:
 *	nxge_init_fzc_rdc_pages()
 *
 * Context:
 *	Service Domain
 */
/*ARGSUSED*/
nxge_status_t
nxge_init_fzc_rdc(p_nxge_t nxgep, uint16_t channel)
{
	nxge_status_t	status = NXGE_OK;

	dma_log_page_t	page1, page2;
	npi_handle_t	handle;
	rdc_red_para_t	red;

	/*
	 * Initialize the RxDMA channel-specific FZC control
	 * registers.
	 */

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_init_fzc_tdc"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	/* Reset RXDMA channel */
	status = npi_rxdma_cfg_rdc_reset(handle, channel);
	if (status != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_init_fzc_rdc: npi_rxdma_cfg_rdc_reset(%d) "
		    "returned 0x%08x", channel, status));
		return (NXGE_ERROR | status);
	}

	/*
	 * These values have been copied from
	 * nxge_txdma.c:nxge_map_txdma_channel_cfg_ring().
	 */
	page1.page_num = 0;
	page1.valid = 1;
	page1.func_num = nxgep->function_num;
	page1.mask = 0;
	page1.value = 0;
	page1.reloc = 0;

	page2.page_num = 1;
	page2.valid = 1;
	page2.func_num = nxgep->function_num;
	page2.mask = 0;
	page2.value = 0;
	page2.reloc = 0;

	if (nxgep->niu_type == N2_NIU) {
#if !defined(NIU_HV_WORKAROUND)
		status = NXGE_OK;
#else
		NXGE_DEBUG_MSG((nxgep, RX_CTL,
		    "==> nxge_init_fzc_rxdma_channel: N2_NIU - NEED to "
		    "set up logical pages"));
		/* Initialize the RXDMA logical pages */
		status = nxge_init_fzc_rdc_pages(nxgep, channel,
		    &page1, &page2);
		if (status != NXGE_OK) {
			return (status);
		}
#endif
	} else if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		/* Initialize the RXDMA logical pages */
		status = nxge_init_fzc_rdc_pages(nxgep, channel,
		    &page1, &page2);
		if (status != NXGE_OK) {
			return (status);
		}
	} else {
		return (NXGE_ERROR);
	}

	/*
	 * Configure RED parameters
	 */
	red.value = 0;
	red.bits.ldw.win = RXDMA_RED_WINDOW_DEFAULT;
	red.bits.ldw.thre =
	    (nxgep->nxge_port_rcr_size - RXDMA_RED_LESS_ENTRIES);
	red.bits.ldw.win_syn = RXDMA_RED_WINDOW_DEFAULT;
	red.bits.ldw.thre_sync =
	    (nxgep->nxge_port_rcr_size - RXDMA_RED_LESS_ENTRIES);

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "==> nxge_init_fzc_rxdma_channel_red(thre_sync %d(%x))",
	    red.bits.ldw.thre_sync,
	    red.bits.ldw.thre_sync));

	status |= npi_rxdma_cfg_wred_param(handle, channel, &red);

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_init_fzc_rdc"));

	return (status);
}

/*
 * nxge_init_fzc_rxdma_channel
 *
 *	Initialize all per-channel FZC_DMC registers.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to start
 *
 * NPI_NXGE function calls:
 *	nxge_init_hv_fzc_rxdma_channel_pages()
 *	nxge_init_fzc_rxdma_channel_pages()
 *	nxge_init_fzc_rxdma_channel_red()
 *
 * Context:
 *	Service Domain
 */
/*ARGSUSED*/
nxge_status_t
nxge_init_fzc_rxdma_channel(p_nxge_t nxgep, uint16_t channel)
{
	rx_rbr_ring_t		*rbr_ring;
	rx_rcr_ring_t		*rcr_ring;

	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "==> nxge_init_fzc_rxdma_channel"));

	rbr_ring = nxgep->rx_rbr_rings->rbr_rings[channel];
	rcr_ring = nxgep->rx_rcr_rings->rcr_rings[channel];

	if (nxgep->niu_type == N2_NIU) {
#ifndef	NIU_HV_WORKAROUND
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
		NXGE_DEBUG_MSG((nxgep, RX_CTL,
		    "==> nxge_init_fzc_rxdma_channel: N2_NIU - call HV "
		    "set up logical pages"));
		/* Initialize the RXDMA logical pages */
		status = nxge_init_hv_fzc_rxdma_channel_pages(nxgep, channel,
		    rbr_ring);
		if (status != NXGE_OK) {
			return (status);
		}
#endif
		status = NXGE_OK;
#else
		NXGE_DEBUG_MSG((nxgep, RX_CTL,
		    "==> nxge_init_fzc_rxdma_channel: N2_NIU - NEED to "
		    "set up logical pages"));
		/* Initialize the RXDMA logical pages */
		status = nxge_init_fzc_rxdma_channel_pages(nxgep, channel,
		    rbr_ring);
		if (status != NXGE_OK) {
			return (status);
		}
#endif
	} else if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		/* Initialize the RXDMA logical pages */
		status = nxge_init_fzc_rxdma_channel_pages(nxgep,
		    channel, rbr_ring);
		if (status != NXGE_OK) {
			return (status);
		}
	} else {
		return (NXGE_ERROR);
	}

	/* Configure RED parameters */
	status = nxge_init_fzc_rxdma_channel_red(nxgep, channel, rcr_ring);

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "<== nxge_init_fzc_rxdma_channel"));
	return (status);
}

/*
 * nxge_init_fzc_rdc_pages
 *
 *	Configure a TDC's logical pages.
 *
 *	This function is executed by the service domain, on behalf of
 *	a guest domain, to whom this RDC has been loaned.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to initialize.
 * 	page0		Logical page 0 definition.
 * 	page1		Logical page 1 definition.
 *
 * Notes:
 *	I think that this function can be called from any
 *	domain, but I need to check.
 *
 * NPI/NXGE function calls:
 *	hv_niu_tx_logical_page_conf()
 *	hv_niu_tx_logical_page_info()
 *
 * Context:
 *	Any domain
 */
nxge_status_t
nxge_init_fzc_rdc_pages(
	p_nxge_t nxgep,
	uint16_t channel,
	dma_log_page_t *page0,
	dma_log_page_t *page1)
{
	npi_handle_t handle;
	npi_status_t rs;

	uint64_t page_handle;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "==> nxge_init_fzc_txdma_channel_pages"));

#ifndef	NIU_HV_WORKAROUND
	if (nxgep->niu_type == N2_NIU) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "<== nxge_init_fzc_rdc_pages: "
		    "N2_NIU: no need to set rxdma logical pages"));
		return (NXGE_OK);
	}
#else
	if (nxgep->niu_type == N2_NIU) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "<== nxge_init_fzc_rdc_pages: "
		    "N2_NIU: NEED to set rxdma logical pages"));
	}
#endif

	/*
	 * Initialize logical page 1.
	 */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	if ((rs = npi_rxdma_cfg_logical_page(handle, channel, page0))
	    != NPI_SUCCESS)
		return (NXGE_ERROR | rs);

	/*
	 * Initialize logical page 2.
	 */
	if ((rs = npi_rxdma_cfg_logical_page(handle, channel, page1))
	    != NPI_SUCCESS)
		return (NXGE_ERROR | rs);

	/*
	 * Initialize the page handle.
	 * (In the current driver, this is always set to 0.)
	 */
	page_handle = 0;
	rs = npi_rxdma_cfg_logical_page_handle(handle, channel, page_handle);
	if (rs == NPI_SUCCESS) {
		return (NXGE_OK);
	} else {
		return (NXGE_ERROR | rs);
	}
}

/*ARGSUSED*/
nxge_status_t
nxge_init_fzc_rxdma_channel_pages(p_nxge_t nxgep,
		uint16_t channel, p_rx_rbr_ring_t rbrp)
{
	npi_handle_t		handle;
	dma_log_page_t		cfg;
	npi_status_t		rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "==> nxge_init_fzc_rxdma_channel_pages"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	/*
	 * Initialize logical page 1.
	 */
	cfg.func_num = nxgep->function_num;
	cfg.page_num = 0;
	cfg.valid = rbrp->page_valid.bits.ldw.page0;
	cfg.value = rbrp->page_value_1.value;
	cfg.mask = rbrp->page_mask_1.value;
	cfg.reloc = rbrp->page_reloc_1.value;
	rs = npi_rxdma_cfg_logical_page(handle, channel,
	    (p_dma_log_page_t)&cfg);
	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	/*
	 * Initialize logical page 2.
	 */
	cfg.page_num = 1;
	cfg.valid = rbrp->page_valid.bits.ldw.page1;
	cfg.value = rbrp->page_value_2.value;
	cfg.mask = rbrp->page_mask_2.value;
	cfg.reloc = rbrp->page_reloc_2.value;

	rs = npi_rxdma_cfg_logical_page(handle, channel, &cfg);
	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	/* Initialize the page handle */
	rs = npi_rxdma_cfg_logical_page_handle(handle, channel,
	    rbrp->page_hdl.bits.ldw.handle);

	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "<== nxge_init_fzc_rxdma_channel_pages"));

	return (NXGE_OK);
}

/*ARGSUSED*/
nxge_status_t
nxge_init_fzc_rxdma_channel_red(p_nxge_t nxgep,
	uint16_t channel, p_rx_rcr_ring_t rcr_p)
{
	npi_handle_t		handle;
	rdc_red_para_t		red;
	npi_status_t		rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_init_fzc_rxdma_channel_red"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	red.value = 0;
	red.bits.ldw.win = RXDMA_RED_WINDOW_DEFAULT;
	red.bits.ldw.thre = (rcr_p->comp_size - RXDMA_RED_LESS_ENTRIES);
	red.bits.ldw.win_syn = RXDMA_RED_WINDOW_DEFAULT;
	red.bits.ldw.thre_sync = (rcr_p->comp_size - RXDMA_RED_LESS_ENTRIES);

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "==> nxge_init_fzc_rxdma_channel_red(thre_sync %d(%x))",
	    red.bits.ldw.thre_sync,
	    red.bits.ldw.thre_sync));

	rs = npi_rxdma_cfg_wred_param(handle, channel, &red);
	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "<== nxge_init_fzc_rxdma_channel_red"));

	return (NXGE_OK);
}

/*
 * nxge_init_fzc_tdc
 *
 *	Initialize all of a TDC's FZC_DMC registers.
 *	This is executed by the service domain, on behalf of a
 *	guest domain, who cannot access these registers.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to initialize.
 *
 * NPI_NXGE function calls:
 *	nxge_init_fzc_tdc_pages()
 *	npi_txc_dma_max_burst_set()
 *
 * Registers accessed:
 *	TXC_DMA_MAX_BURST
 *
 * Context:
 *	Service Domain
 */
/*ARGSUSED*/
nxge_status_t
nxge_init_fzc_tdc(p_nxge_t nxgep, uint16_t channel)
{
	nxge_status_t	status = NXGE_OK;

	dma_log_page_t	page1, page2;
	npi_handle_t	handle;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_init_fzc_tdc"));

	/*
	 * These values have been copied from
	 * nxge_txdma.c:nxge_map_txdma_channel_cfg_ring().
	 */
	page1.page_num = 0;
	page1.valid = 1;
	page1.func_num = nxgep->function_num;
	page1.mask = 0;
	page1.value = 0;
	page1.reloc = 0;

	page1.page_num = 1;
	page1.valid = 1;
	page1.func_num = nxgep->function_num;
	page1.mask = 0;
	page1.value = 0;
	page1.reloc = 0;

#ifdef	NIU_HV_WORKAROUND
	if (nxgep->niu_type == N2_NIU) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "==> nxge_init_fzc_txdma_channel "
		    "N2_NIU: NEED to set up txdma logical pages"));
		/* Initialize the TXDMA logical pages */
		(void) nxge_init_fzc_tdc_pages(nxgep, channel,
		    &page1, &page2);
	}
#endif
	if (nxgep->niu_type != N2_NIU) {
		if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
			/* Initialize the TXDMA logical pages */
			(void) nxge_init_fzc_tdc_pages(nxgep, channel,
			    &page1, &page2);
		} else
			return (NXGE_ERROR);
	}

	/*
	 * Configure the TXC DMA Max Burst value.
	 *
	 * PRM.13.5
	 *
	 * TXC DMA Max Burst. TXC_DMA_MAX (FZC_TXC + 0000016)
	 * 19:0		dma_max_burst		RW
	 * Max burst value associated with DMA. Used by DRR engine
	 * for computing when DMA has gone into deficit.
	 */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	(void) npi_txc_dma_max_burst_set(
	    handle, channel, TXC_DMA_MAX_BURST_DEFAULT);

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_init_fzc_tdc"));

	return (status);
}

/*ARGSUSED*/
nxge_status_t
nxge_init_fzc_txdma_channel(p_nxge_t nxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p, p_tx_mbox_t mbox_p)
{
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "==> nxge_init_fzc_txdma_channel"));

	if (nxgep->niu_type == N2_NIU) {
#ifndef	NIU_HV_WORKAROUND
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "==> nxge_init_fzc_txdma_channel "
		    "N2_NIU: call HV to set up txdma logical pages"));
		status = nxge_init_hv_fzc_txdma_channel_pages(nxgep, channel,
		    tx_ring_p);
		if (status != NXGE_OK) {
			return (status);
		}
#endif
		status = NXGE_OK;
#else
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "==> nxge_init_fzc_txdma_channel "
		    "N2_NIU: NEED to set up txdma logical pages"));
		/* Initialize the TXDMA logical pages */
		(void) nxge_init_fzc_txdma_channel_pages(nxgep, channel,
		    tx_ring_p);
#endif
	} else if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		/* Initialize the TXDMA logical pages */
		(void) nxge_init_fzc_txdma_channel_pages(nxgep,
		    channel, tx_ring_p);
	} else {
		return (NXGE_ERROR);
	}

	/*
	 * Configure Transmit DRR Weight parameters
	 * (It actually programs the TXC max burst register).
	 */
	(void) nxge_init_fzc_txdma_channel_drr(nxgep, channel, tx_ring_p);

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "<== nxge_init_fzc_txdma_channel"));
	return (status);
}


nxge_status_t
nxge_init_fzc_rx_common(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;
	nxge_status_t	status = NXGE_OK;
	nxge_rdc_grp_t	*rdc_grp_p;
	clock_t		lbolt;
	int		table;

	nxge_hw_pt_cfg_t *hardware;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_init_fzc_rx_common"));
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	if (!handle.regp) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "==> nxge_init_fzc_rx_common null ptr"));
		return (NXGE_ERROR);
	}

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
	rs = npi_rxdma_cfg_clock_div_set(handle, RXDMA_CK_DIV_DEFAULT);
	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);

#if defined(__i386)
	rs = npi_rxdma_cfg_32bitmode_enable(handle);
	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	rs = npi_txdma_mode32_set(handle, B_TRUE);
	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
#endif

	/*
	 * Enable WRED and program an initial value.
	 * Use time to set the initial random number.
	 */
	(void) drv_getparm(LBOLT, &lbolt);
	rs = npi_rxdma_cfg_red_rand_init(handle, (uint16_t)lbolt);
	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);

	hardware = &nxgep->pt_config.hw_config;
	for (table = 0; table < NXGE_MAX_RDC_GRPS; table++) {
		/* Does this table belong to <nxgep>? */
		if (hardware->grpids[table] == (nxgep->function_num + 256)) {
			rdc_grp_p = &nxgep->pt_config.rdc_grps[table];
			status = nxge_init_fzc_rdc_tbl(nxgep, rdc_grp_p, table);
		}
	}

	/* Ethernet Timeout Counter (?) */

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "<== nxge_init_fzc_rx_common:status 0x%08x", status));

	return (status);
}

nxge_status_t
nxge_init_fzc_rdc_tbl(p_nxge_t nxge, nxge_rdc_grp_t *group, int rdc_tbl)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nx_rdc_tbl_t	*table;
	npi_handle_t	handle;

	npi_status_t	rs = NPI_SUCCESS;
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxge, DMA_CTL, "==> nxge_init_fzc_rdc_tbl(%d)", table));

	/* This RDC table must have been previously bound to <nxge>. */
	MUTEX_ENTER(&nhd->lock);
	table = &nhd->rdc_tbl[rdc_tbl];
	if (table->nxge != (uintptr_t)nxge) {
		MUTEX_EXIT(&nhd->lock);
		NXGE_ERROR_MSG((nxge, DMA_CTL,
		    "nxge_init_fzc_rdc_tbl(%d): not owner", table));
		return (NXGE_ERROR);
	} else {
		table->map = group->map;
	}
	MUTEX_EXIT(&nhd->lock);

	handle = NXGE_DEV_NPI_HANDLE(nxge);

	rs = npi_rxdma_rdc_table_config(handle, rdc_tbl,
	    group->map, group->max_rdcs);

	if (rs != NPI_SUCCESS) {
		status = NXGE_ERROR | rs;
	}

	NXGE_DEBUG_MSG((nxge, DMA_CTL, "<== nxge_init_fzc_rdc_tbl(%d)", table));
	return (status);
}

static
int
rdc_tbl_bind(p_nxge_t nxge, int rdc_tbl)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nx_rdc_tbl_t *table;
	int i;

	NXGE_DEBUG_MSG((nxge, DMA_CTL, "==> nxge_fzc_rdc_tbl_bind"));

	MUTEX_ENTER(&nhd->lock);
	/* is the caller asking for a particular table? */
	if (rdc_tbl >= 0 && rdc_tbl < NXGE_MAX_RDC_GROUPS) {
		table = &nhd->rdc_tbl[rdc_tbl];
		if (table->nxge == 0) {
			table->nxge = (uintptr_t)nxge; /* It is now bound. */
			NXGE_DEBUG_MSG((nxge, DMA_CTL,
			    "<== nxge_fzc_rdc_tbl_bind(%d)", rdc_tbl));
			MUTEX_EXIT(&nhd->lock);
			return (rdc_tbl);
		}
	} else {	/* The caller will take any old RDC table. */
		for (i = 0; i < NXGE_MAX_RDC_GROUPS; i++) {
			nx_rdc_tbl_t *table = &nhd->rdc_tbl[i];
			if (table->nxge == 0) {
				table->nxge = (uintptr_t)nxge;
				/* It is now bound. */
				MUTEX_EXIT(&nhd->lock);
				NXGE_DEBUG_MSG((nxge, DMA_CTL,
				    "<== nxge_fzc_rdc_tbl_bind: %d", i));
				return (i);
			}
		}
	}
	MUTEX_EXIT(&nhd->lock);

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_fzc_rdc_tbl_bind"));

	return (-EBUSY);	/* RDC tables are bound. */
}

int
nxge_fzc_rdc_tbl_bind(
	nxge_t *nxge,
	int grp_index,
	int acceptNoSubstitutes)
{
	nxge_hw_pt_cfg_t *hardware;
	int index;

	hardware = &nxge->pt_config.hw_config;

	if ((index = rdc_tbl_bind(nxge, grp_index)) < 0) {
		if (acceptNoSubstitutes)
			return (index);
		index = rdc_tbl_bind(nxge, grp_index);
		if (index < 0) {
			NXGE_ERROR_MSG((nxge, OBP_CTL,
			    "nxge_fzc_rdc_tbl_init: "
			    "there are no free RDC tables!"));
			return (index);
		}
	}

	hardware->grpids[index] = nxge->function_num + 256;

	return (index);
}

int
nxge_fzc_rdc_tbl_unbind(p_nxge_t nxge, int rdc_tbl)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nx_rdc_tbl_t *table;

	if (nhd == NULL)
		return (0);

	NXGE_DEBUG_MSG((nxge, DMA_CTL, "==> nxge_fzc_rdc_tbl_unbind(%d)",
	    rdc_tbl));

	MUTEX_ENTER(&nhd->lock);
	table = &nhd->rdc_tbl[rdc_tbl];
	if (table->nxge != (uintptr_t)nxge) {
		NXGE_ERROR_MSG((nxge, DMA_CTL,
		    "nxge_fzc_rdc_tbl_unbind(%d): func%d not owner",
		    nxge->function_num, rdc_tbl));
		MUTEX_EXIT(&nhd->lock);
		return (EINVAL);
	} else {
		bzero(table, sizeof (*table));
	}
	MUTEX_EXIT(&nhd->lock);

	NXGE_DEBUG_MSG((nxge, DMA_CTL, "<== nxge_fzc_rdc_tbl_unbind(%d)",
	    rdc_tbl));

	return (0);
}

nxge_status_t
nxge_init_fzc_rxdma_port(p_nxge_t nxgep)
{
	npi_handle_t		handle;
	p_nxge_dma_pt_cfg_t	p_all_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	hostinfo_t 		hostinfo;
	int			i;
	npi_status_t		rs = NPI_SUCCESS;
	p_nxge_class_pt_cfg_t 	p_class_cfgp;
	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_init_fzc_rxdma_port"));

	p_all_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_all_cfgp->hw_config;
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	/*
	 * Initialize the port scheduler DRR weight.
	 * npi_rxdma_cfg_port_ddr_weight();
	 */

	if ((nxgep->mac.portmode == PORT_1G_COPPER) ||
	    (nxgep->mac.portmode == PORT_1G_FIBER) ||
	    (nxgep->mac.portmode == PORT_1G_TN1010) ||
	    (nxgep->mac.portmode == PORT_1G_SERDES)) {
		rs = npi_rxdma_cfg_port_ddr_weight(handle,
		    nxgep->function_num, NXGE_RX_DRR_WT_1G);
		if (rs != NPI_SUCCESS) {
			return (NXGE_ERROR | rs);
		}
	}

	/* Program the default RDC of a port */
	rs = npi_rxdma_cfg_default_port_rdc(handle, nxgep->function_num,
	    p_cfgp->def_rdc);
	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	/*
	 * Configure the MAC host info table with RDC tables
	 */
	hostinfo.value = 0;
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	for (i = 0; i < p_cfgp->max_macs; i++) {
		hostinfo.bits.w0.rdc_tbl_num = p_cfgp->def_mac_rxdma_grpid;
		hostinfo.bits.w0.mac_pref = p_cfgp->mac_pref;
		if (p_class_cfgp->mac_host_info[i].flag) {
			hostinfo.bits.w0.rdc_tbl_num =
			    p_class_cfgp->mac_host_info[i].rdctbl;
			hostinfo.bits.w0.mac_pref =
			    p_class_cfgp->mac_host_info[i].mpr_npr;
		}

		rs = npi_mac_hostinfo_entry(handle, OP_SET,
		    nxgep->function_num, i, &hostinfo);
		if (rs != NPI_SUCCESS)
			return (NXGE_ERROR | rs);
	}

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "<== nxge_init_fzc_rxdma_port rs 0x%08x", rs));

	return (NXGE_OK);

}

nxge_status_t
nxge_fzc_dmc_def_port_rdc(p_nxge_t nxgep, uint8_t port, uint16_t rdc)
{
	npi_status_t rs = NPI_SUCCESS;
	rs = npi_rxdma_cfg_default_port_rdc(nxgep->npi_reg_handle,
	    port, rdc);
	if (rs & NPI_FAILURE)
		return (NXGE_ERROR | rs);
	return (NXGE_OK);
}

/*
 * nxge_init_fzc_tdc_pages
 *
 *	Configure a TDC's logical pages.
 *
 *	This function is executed by the service domain, on behalf of
 *	a guest domain, to whom this TDC has been loaned.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to initialize.
 * 	page0		Logical page 0 definition.
 * 	page1		Logical page 1 definition.
 *
 * Notes:
 *	I think that this function can be called from any
 *	domain, but I need to check.
 *
 * NPI/NXGE function calls:
 *	hv_niu_tx_logical_page_conf()
 *	hv_niu_tx_logical_page_info()
 *
 * Context:
 *	Any domain
 */
nxge_status_t
nxge_init_fzc_tdc_pages(
	p_nxge_t nxgep,
	uint16_t channel,
	dma_log_page_t *page0,
	dma_log_page_t *page1)
{
	npi_handle_t handle;
	npi_status_t rs;

	log_page_hdl_t page_handle;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "==> nxge_init_fzc_txdma_channel_pages"));

#ifndef	NIU_HV_WORKAROUND
	if (nxgep->niu_type == N2_NIU) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "<== nxge_init_fzc_tdc_pages: "
		    "N2_NIU: no need to set txdma logical pages"));
		return (NXGE_OK);
	}
#else
	if (nxgep->niu_type == N2_NIU) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "<== nxge_init_fzc_tdc_pages: "
		    "N2_NIU: NEED to set txdma logical pages"));
	}
#endif

	/*
	 * Initialize logical page 1.
	 */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	if ((rs = npi_txdma_log_page_set(handle, channel, page0))
	    != NPI_SUCCESS)
		return (NXGE_ERROR | rs);

	/*
	 * Initialize logical page 2.
	 */
	if ((rs = npi_txdma_log_page_set(handle, channel, page1))
	    != NPI_SUCCESS)
		return (NXGE_ERROR | rs);

	/*
	 * Initialize the page handle.
	 * (In the current driver, this is always set to 0.)
	 */
	page_handle.value = 0;
	rs = npi_txdma_log_page_handle_set(handle, channel, &page_handle);
	if (rs == NPI_SUCCESS) {
		return (NXGE_OK);
	} else {
		return (NXGE_ERROR | rs);
	}
}

nxge_status_t
nxge_init_fzc_txdma_channel_pages(p_nxge_t nxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p)
{
	npi_handle_t		handle;
	dma_log_page_t		cfg;
	npi_status_t		rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "==> nxge_init_fzc_txdma_channel_pages"));

#ifndef	NIU_HV_WORKAROUND
	if (nxgep->niu_type == N2_NIU) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "<== nxge_init_fzc_txdma_channel_pages: "
		    "N2_NIU: no need to set txdma logical pages"));
		return (NXGE_OK);
	}
#else
	if (nxgep->niu_type == N2_NIU) {
		NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		    "<== nxge_init_fzc_txdma_channel_pages: "
		    "N2_NIU: NEED to set txdma logical pages"));
	}
#endif

	/*
	 * Initialize logical page 1.
	 */
	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	cfg.func_num = nxgep->function_num;
	cfg.page_num = 0;
	cfg.valid = tx_ring_p->page_valid.bits.ldw.page0;
	cfg.value = tx_ring_p->page_value_1.value;
	cfg.mask = tx_ring_p->page_mask_1.value;
	cfg.reloc = tx_ring_p->page_reloc_1.value;

	rs = npi_txdma_log_page_set(handle, channel,
	    (p_dma_log_page_t)&cfg);
	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	/*
	 * Initialize logical page 2.
	 */
	cfg.page_num = 1;
	cfg.valid = tx_ring_p->page_valid.bits.ldw.page1;
	cfg.value = tx_ring_p->page_value_2.value;
	cfg.mask = tx_ring_p->page_mask_2.value;
	cfg.reloc = tx_ring_p->page_reloc_2.value;

	rs = npi_txdma_log_page_set(handle, channel, &cfg);
	if (rs != NPI_SUCCESS) {
		return (NXGE_ERROR | rs);
	}

	/* Initialize the page handle */
	rs = npi_txdma_log_page_handle_set(handle, channel,
	    &tx_ring_p->page_hdl);

	if (rs == NPI_SUCCESS) {
		return (NXGE_OK);
	} else {
		return (NXGE_ERROR | rs);
	}
}


nxge_status_t
nxge_init_fzc_txdma_channel_drr(p_nxge_t nxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p)
{
	npi_status_t	rs = NPI_SUCCESS;
	npi_handle_t	handle;

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	rs = npi_txc_dma_max_burst_set(handle, channel,
	    tx_ring_p->max_burst.value);
	if (rs == NPI_SUCCESS) {
		return (NXGE_OK);
	} else {
		return (NXGE_ERROR | rs);
	}
}

nxge_status_t
nxge_fzc_sys_err_mask_set(p_nxge_t nxgep, uint64_t mask)
{
	npi_status_t	rs = NPI_SUCCESS;
	npi_handle_t	handle;

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	rs = npi_fzc_sys_err_mask_set(handle, mask);
	if (rs == NPI_SUCCESS) {
		return (NXGE_OK);
	} else {
		return (NXGE_ERROR | rs);
	}
}

/*
 * nxge_init_hv_fzc_txdma_channel_pages
 *
 *	Configure a TDC's logical pages.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to initialize.
 * 	tx_ring_p	The transmit ring.
 *
 * Notes:
 *	I think that this function can be called from any
 *	domain, but I need to check.
 *
 * NPI/NXGE function calls:
 *	hv_niu_tx_logical_page_conf()
 *	hv_niu_tx_logical_page_info()
 *
 * Context:
 *	Any domain
 */
#if defined(sun4v) && defined(NIU_LP_WORKAROUND)
nxge_status_t
nxge_init_hv_fzc_txdma_channel_pages(p_nxge_t nxgep, uint16_t channel,
	p_tx_ring_t tx_ring_p)
{
	int			err;
	uint64_t		hverr;
#ifdef	DEBUG
	uint64_t		ra, size;
#endif

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_init_hv_fzc_txdma_channel_pages"));

	if (tx_ring_p->hv_set) {
		return (NXGE_OK);
	}

	/*
	 * Initialize logical page 1 for data buffers.
	 */
	hverr = nxge_init_hv_fzc_lp_op(nxgep, (uint64_t)channel,
	    (uint64_t)0, N2NIU_TX_LP_CONF,
	    tx_ring_p->hv_tx_buf_base_ioaddr_pp,
	    tx_ring_p->hv_tx_buf_ioaddr_size);

	err = (nxge_status_t)nxge_herr2kerr(hverr);
	if (err != 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_init_hv_fzc_txdma_channel_pages: channel %d "
		    "error status 0x%x "
		    "(page 0 data buf) hverr 0x%llx "
		    "ioaddr_pp $%p "
		    "size 0x%llx ",
		    channel,
		    err,
		    hverr,
		    tx_ring_p->hv_tx_buf_base_ioaddr_pp,
		    tx_ring_p->hv_tx_buf_ioaddr_size));
		return (NXGE_ERROR | err);
	}

#ifdef	DEBUG
	ra = size = 0;
	hverr = nxge_init_hv_fzc_lp_op(nxgep, (uint64_t)channel,
	    (uint64_t)0, N2NIU_TX_LP_INFO,
	    (uint64_t)&ra, (uint64_t)&size);

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_init_hv_fzc_txdma_channel_pages: channel %d "
	    "ok status 0x%x "
	    "(page 0 data buf) hverr 0x%llx "
	    "set ioaddr_pp $%p "
	    "set size 0x%llx "
	    "get ra ioaddr_pp $%p "
	    "get size 0x%llx ",
	    channel,
	    err,
	    hverr,
	    tx_ring_p->hv_tx_buf_base_ioaddr_pp,
	    tx_ring_p->hv_tx_buf_ioaddr_size,
	    ra,
	    size));
#endif

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_init_hv_fzc_txdma_channel_pages: channel %d "
	    "(page 0 data buf) hverr 0x%llx "
	    "ioaddr_pp $%p "
	    "size 0x%llx ",
	    channel,
	    hverr,
	    tx_ring_p->hv_tx_buf_base_ioaddr_pp,
	    tx_ring_p->hv_tx_buf_ioaddr_size));

	/*
	 * Initialize logical page 2 for control buffers.
	 */
	hverr = nxge_init_hv_fzc_lp_op(nxgep, (uint64_t)channel,
	    (uint64_t)1, N2NIU_TX_LP_CONF,
	    tx_ring_p->hv_tx_cntl_base_ioaddr_pp,
	    tx_ring_p->hv_tx_cntl_ioaddr_size);

	err = (nxge_status_t)nxge_herr2kerr(hverr);

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_init_hv_fzc_txdma_channel_pages: channel %d"
	    "ok status 0x%x "
	    "(page 1 cntl buf) hverr 0x%llx "
	    "ioaddr_pp $%p "
	    "size 0x%llx ",
	    channel,
	    err,
	    hverr,
	    tx_ring_p->hv_tx_cntl_base_ioaddr_pp,
	    tx_ring_p->hv_tx_cntl_ioaddr_size));

	if (err != 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_init_hv_fzc_txdma_channel_pages: channel %d"
		    "error status 0x%x "
		    "(page 1 cntl buf) hverr 0x%llx "
		    "ioaddr_pp $%p "
		    "size 0x%llx ",
		    channel,
		    err,
		    hverr,
		    tx_ring_p->hv_tx_cntl_base_ioaddr_pp,
		    tx_ring_p->hv_tx_cntl_ioaddr_size));
		return (NXGE_ERROR | err);
	}

#ifdef	DEBUG
	ra = size = 0;
	hverr = nxge_init_hv_fzc_lp_op(nxgep, (uint64_t)channel,
	    (uint64_t)1, N2NIU_TX_LP_INFO,
	    (uint64_t)&ra, (uint64_t)&size);

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_init_hv_fzc_txdma_channel_pages: channel %d "
	    "(page 1 cntl buf) hverr 0x%llx "
	    "set ioaddr_pp $%p "
	    "set size 0x%llx "
	    "get ra ioaddr_pp $%p "
	    "get size 0x%llx ",
	    channel,
	    hverr,
	    tx_ring_p->hv_tx_cntl_base_ioaddr_pp,
	    tx_ring_p->hv_tx_cntl_ioaddr_size,
	    ra,
	    size));
#endif

	tx_ring_p->hv_set = B_TRUE;

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "<== nxge_init_hv_fzc_txdma_channel_pages"));

	return (NXGE_OK);
}

/*ARGSUSED*/
nxge_status_t
nxge_init_hv_fzc_rxdma_channel_pages(p_nxge_t nxgep,
		uint16_t channel, p_rx_rbr_ring_t rbrp)
{
	int			err;
	uint64_t		hverr;
#ifdef	DEBUG
	uint64_t		ra, size;
#endif

	NXGE_DEBUG_MSG((nxgep, RX_CTL,
	    "==> nxge_init_hv_fzc_rxdma_channel_pages"));

	if (rbrp->hv_set) {
		return (NXGE_OK);
	}

	/* Initialize data buffers for page 0 */
	hverr = nxge_init_hv_fzc_lp_op(nxgep, (uint64_t)channel,
	    (uint64_t)0, N2NIU_RX_LP_CONF,
	    rbrp->hv_rx_buf_base_ioaddr_pp,
	    rbrp->hv_rx_buf_ioaddr_size);

	err = (nxge_status_t)nxge_herr2kerr(hverr);
	if (err != 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_init_hv_fzc_rxdma_channel_pages: channel %d"
		    "error status 0x%x "
		    "(page 0 data buf) hverr 0x%llx "
		    "ioaddr_pp $%p "
		    "size 0x%llx ",
		    channel,
		    err,
		    hverr,
		    rbrp->hv_rx_buf_base_ioaddr_pp,
		    rbrp->hv_rx_buf_ioaddr_size));

		return (NXGE_ERROR | err);
	}

#ifdef	DEBUG
	ra = size = 0;
	hverr = nxge_init_hv_fzc_lp_op(nxgep, (uint64_t)channel,
	    (uint64_t)0, N2NIU_RX_LP_INFO,
	    (uint64_t)&ra, (uint64_t)&size);

	NXGE_DEBUG_MSG((nxgep, RX_CTL,
	    "==> nxge_init_hv_fzc_rxdma_channel_pages: channel %d "
	    "ok status 0x%x "
	    "(page 0 data buf) hverr 0x%llx "
	    "set databuf ioaddr_pp $%p "
	    "set databuf size 0x%llx "
	    "get databuf ra ioaddr_pp %p "
	    "get databuf size 0x%llx",
	    channel,
	    err,
	    hverr,
	    rbrp->hv_rx_buf_base_ioaddr_pp,
	    rbrp->hv_rx_buf_ioaddr_size,
	    ra,
	    size));
#endif

	/* Initialize control buffers for logical page 1.  */
	hverr = nxge_init_hv_fzc_lp_op(nxgep, (uint64_t)channel,
	    (uint64_t)1, N2NIU_RX_LP_CONF,
	    rbrp->hv_rx_cntl_base_ioaddr_pp,
	    rbrp->hv_rx_cntl_ioaddr_size);

	err = (nxge_status_t)nxge_herr2kerr(hverr);
	if (err != 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_init_hv_fzc_rxdma_channel_pages: channel %d"
		    "error status 0x%x "
		    "(page 1 cntl buf) hverr 0x%llx "
		    "ioaddr_pp $%p "
		    "size 0x%llx ",
		    channel,
		    err,
		    hverr,
		    rbrp->hv_rx_buf_base_ioaddr_pp,
		    rbrp->hv_rx_buf_ioaddr_size));

		return (NXGE_ERROR | err);
	}

#ifdef	DEBUG
	ra = size = 0;
	hverr = nxge_init_hv_fzc_lp_op(nxgep, (uint64_t)channel,
	    (uint64_t)1, N2NIU_RX_LP_INFO,
	    (uint64_t)&ra, (uint64_t)&size);

	NXGE_DEBUG_MSG((nxgep, RX_CTL,
	    "==> nxge_init_hv_fzc_rxdma_channel_pages: channel %d "
	    "error status 0x%x "
	    "(page 1 cntl buf) hverr 0x%llx "
	    "set cntl ioaddr_pp $%p "
	    "set cntl size 0x%llx "
	    "get cntl ioaddr_pp $%p "
	    "get cntl size 0x%llx ",
	    channel,
	    err,
	    hverr,
	    rbrp->hv_rx_cntl_base_ioaddr_pp,
	    rbrp->hv_rx_cntl_ioaddr_size,
	    ra,
	    size));
#endif

	rbrp->hv_set = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, RX_CTL,
	    "<== nxge_init_hv_fzc_rxdma_channel_pages"));

	return (NXGE_OK);
}

/*
 * Map hypervisor error code to errno. Only
 * H_ENORADDR, H_EBADALIGN and H_EINVAL are meaningful
 * for niu driver. Any other error codes are mapped to EINVAL.
 */
static int
nxge_herr2kerr(uint64_t hv_errcode)
{
	int	s_errcode;

	switch (hv_errcode) {
	case H_ENORADDR:
	case H_EBADALIGN:
		s_errcode = EFAULT;
		break;
	case H_EOK:
		s_errcode = 0;
		break;
	default:
		s_errcode = EINVAL;
		break;
	}
	return (s_errcode);
}

uint64_t
nxge_init_hv_fzc_lp_op(p_nxge_t nxgep, uint64_t channel,
    uint64_t page_no, uint64_t op_type,
    uint64_t ioaddr_pp, uint64_t ioaddr_size)
{
	uint64_t		hverr;
	uint64_t		major;
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxgep->nxge_hw_p->hio;
	nxhv_dc_fp_t		*io_fp;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "==> nxge_init_hv_fzc_lp_op"));

	major = nxgep->niu_hsvc.hsvc_major;
	NXGE_DEBUG_MSG((nxgep, NXGE_ERR_CTL,
	    "==> nxge_init_hv_fzc_lp_op (major %d): channel %d op_type 0x%x "
	    "page_no %d ioaddr_pp $%p ioaddr_size 0x%llx",
	    major, channel, op_type, page_no, ioaddr_pp, ioaddr_size));

	/* Call the transmit conf function. */
	switch (major) {
	case NIU_MAJOR_VER: /* 1 */
		switch (op_type) {
		case N2NIU_TX_LP_CONF:
			io_fp = &nhd->hio.tx;
			hverr = (*io_fp->lp_conf)((uint64_t)channel,
			    (uint64_t)page_no,
			    (uint64_t)ioaddr_pp,
			    (uint64_t)ioaddr_size);
			NXGE_DEBUG_MSG((nxgep, DMA_CTL,
			    "==> nxge_init_hv_fzc_lp_op(tx_conf): major %d "
			    "op 0x%x hverr 0x%x", major, op_type, hverr));
			break;

		case N2NIU_TX_LP_INFO:
			io_fp = &nhd->hio.tx;
			hverr = (*io_fp->lp_info)((uint64_t)channel,
			    (uint64_t)page_no,
			    (uint64_t *)ioaddr_pp,
			    (uint64_t *)ioaddr_size);
			break;

		case N2NIU_RX_LP_CONF:
			io_fp = &nhd->hio.rx;
			hverr = (*io_fp->lp_conf)((uint64_t)channel,
			    (uint64_t)page_no,
			    (uint64_t)ioaddr_pp,
			    (uint64_t)ioaddr_size);
			break;

		case N2NIU_RX_LP_INFO:
			io_fp = &nhd->hio.rx;
			hverr = (*io_fp->lp_info)((uint64_t)channel,
			    (uint64_t)page_no,
			    (uint64_t *)ioaddr_pp,
			    (uint64_t *)ioaddr_size);
			NXGE_DEBUG_MSG((nxgep, DMA_CTL,
			    "==> nxge_init_hv_fzc_lp_op(rx_conf): major %d "
			    "op 0x%x hverr 0x%x", major, op_type, hverr));
			break;

		default:
			hverr = EINVAL;
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "==> nxge_init_hv_fzc_lp_op(rx_conf): major %d "
			    "invalid op 0x%x hverr 0x%x", major,
			    op_type, hverr));
			break;
		}

		break;

	case NIU_MAJOR_VER_2: /* 2 */
		switch (op_type) {
		case N2NIU_TX_LP_CONF:
			io_fp = &nhd->hio.tx;
			hverr = (*io_fp->lp_cfgh_conf)(nxgep->niu_cfg_hdl,
			    (uint64_t)channel,
			    (uint64_t)page_no, ioaddr_pp, ioaddr_size);

			NXGE_DEBUG_MSG((nxgep, DMA_CTL,
			    "==> nxge_init_hv_fzc_lp_op(tx_conf): major %d "
			    "op 0x%x hverr 0x%x", major, op_type, hverr));
			break;

		case N2NIU_TX_LP_INFO:
			io_fp = &nhd->hio.tx;
			hverr = (*io_fp->lp_cfgh_info)(nxgep->niu_cfg_hdl,
			    (uint64_t)channel,
			    (uint64_t)page_no,
			    (uint64_t *)ioaddr_pp,
			    (uint64_t *)ioaddr_size);
			break;

		case N2NIU_RX_LP_CONF:
			io_fp = &nhd->hio.rx;
			hverr = (*io_fp->lp_cfgh_conf)(nxgep->niu_cfg_hdl,
			    (uint64_t)channel,
			    (uint64_t)page_no,
			    (uint64_t)ioaddr_pp,
			    (uint64_t)ioaddr_size);
			NXGE_DEBUG_MSG((nxgep, DMA_CTL,
			    "==> nxge_init_hv_fzc_lp_op(rx_conf): major %d "
			    "hverr 0x%x", major, hverr));
			break;

		case N2NIU_RX_LP_INFO:
			io_fp = &nhd->hio.rx;
			hverr = (*io_fp->lp_cfgh_info)(nxgep->niu_cfg_hdl,
			    (uint64_t)channel,
			    (uint64_t)page_no,
			    (uint64_t *)ioaddr_pp,
			    (uint64_t *)ioaddr_size);
			break;

		default:
			hverr = EINVAL;
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "==> nxge_init_hv_fzc_lp_op(rx_conf): major %d "
			    "invalid op 0x%x hverr 0x%x", major,
			    op_type, hverr));
			break;
		}

		break;

	default:
		hverr = EINVAL;
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "==> nxge_init_hv_fzc_lp_op(rx_conf): invalid major %d "
		    "op 0x%x hverr 0x%x", major, op_type, hverr));
		break;
	}

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
	    "<== nxge_init_hv_fzc_lp_op: 0x%x", hverr));

	return (hverr);
}

#endif	/* sun4v and NIU_LP_WORKAROUND */
