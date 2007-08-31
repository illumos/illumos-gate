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

#include	<nxge_impl.h>
#include	<npi_mac.h>
#include	<npi_rxdma.h>

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
static int	nxge_herr2kerr(uint64_t);
#endif

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
 * Receive DMA registers that are under function zero
 * management.
 */
/*ARGSUSED*/
nxge_status_t
nxge_init_fzc_rxdma_channel(p_nxge_t nxgep, uint16_t channel,
	p_rx_rbr_ring_t rbr_p, p_rx_rcr_ring_t rcr_p, p_rx_mbox_t mbox_p)
{
	nxge_status_t	status = NXGE_OK;
	NXGE_DEBUG_MSG((nxgep, RX_CTL, "==> nxge_init_fzc_rxdma_channel"));

	if (nxgep->niu_type == N2_NIU) {
#ifndef	NIU_HV_WORKAROUND
#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
		NXGE_DEBUG_MSG((nxgep, RX_CTL,
		    "==> nxge_init_fzc_rxdma_channel: N2_NIU - call HV "
		    "set up logical pages"));
		/* Initialize the RXDMA logical pages */
		status = nxge_init_hv_fzc_rxdma_channel_pages(nxgep, channel,
			rbr_p);
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
		    rbr_p);
		if (status != NXGE_OK) {
			return (status);
		}
#endif
	} else if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		/* Initialize the RXDMA logical pages */
		status = nxge_init_fzc_rxdma_channel_pages(nxgep,
		    channel, rbr_p);
		if (status != NXGE_OK) {
			return (status);
		}
	} else {
		return (NXGE_ERROR);
	}

	/* Configure RED parameters */
	status = nxge_init_fzc_rxdma_channel_red(nxgep, channel, rcr_p);

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "<== nxge_init_fzc_rxdma_channel"));
	return (status);
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
nxge_init_fzc_common(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;

	(void) nxge_init_fzc_rx_common(nxgep);

	return (status);
}

nxge_status_t
nxge_init_fzc_rx_common(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;
	nxge_status_t	status = NXGE_OK;
	clock_t		lbolt;

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

	/* Initialize the RDC tables for each group */
	status = nxge_init_fzc_rdc_tbl(nxgep);


	/* Ethernet Timeout Counter (?) */

	NXGE_DEBUG_MSG((nxgep, DMA_CTL,
		"<== nxge_init_fzc_rx_common:status 0x%08x", status));

	return (status);
}

nxge_status_t
nxge_init_fzc_rdc_tbl(p_nxge_t nxgep)
{
	npi_handle_t		handle;
	p_nxge_dma_pt_cfg_t	p_dma_cfgp;
	p_nxge_hw_pt_cfg_t	p_cfgp;
	p_nxge_rdc_grp_t	rdc_grp_p;
	uint8_t 		grp_tbl_id;
	int			ngrps;
	int			i;
	npi_status_t		rs = NPI_SUCCESS;
	nxge_status_t		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "==> nxge_init_fzc_rdc_tbl"));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	grp_tbl_id = p_cfgp->start_rdc_grpid;
	rdc_grp_p = &p_dma_cfgp->rdc_grps[0];
	ngrps = p_cfgp->max_rdc_grpids;
	for (i = 0; i < ngrps; i++, rdc_grp_p++) {
		rs = npi_rxdma_cfg_rdc_table(handle, grp_tbl_id++,
			rdc_grp_p->rdc);
		if (rs != NPI_SUCCESS) {
			status = NXGE_ERROR | rs;
			break;
		}
	}

	NXGE_DEBUG_MSG((nxgep, DMA_CTL, "<== nxge_init_fzc_rdc_tbl"));
	return (status);
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
		hostinfo.bits.w0.rdc_tbl_num = p_cfgp->start_rdc_grpid;
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

#if	defined(sun4v) && defined(NIU_LP_WORKAROUND)
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
	hverr = hv_niu_tx_logical_page_conf((uint64_t)channel,
			(uint64_t)0,
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
	hverr = hv_niu_tx_logical_page_info((uint64_t)channel,
			(uint64_t)0,
			&ra,
			&size);

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
	hverr = hv_niu_tx_logical_page_conf((uint64_t)channel,
			(uint64_t)1,
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
	hverr = hv_niu_tx_logical_page_info((uint64_t)channel,
			(uint64_t)1,
			&ra,
			&size);

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
	hverr = hv_niu_rx_logical_page_conf((uint64_t)channel,
			(uint64_t)0,
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
	(void) hv_niu_rx_logical_page_info((uint64_t)channel,
			(uint64_t)0,
			&ra,
			&size);

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
	hverr = hv_niu_rx_logical_page_conf((uint64_t)channel,
			(uint64_t)1,
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
	(void) hv_niu_rx_logical_page_info((uint64_t)channel,
			(uint64_t)1,
			&ra,
			&size);


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

#endif	/* sun4v and NIU_LP_WORKAROUND */
