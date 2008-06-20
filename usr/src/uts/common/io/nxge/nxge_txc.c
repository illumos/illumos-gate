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

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_txc.h>

static nxge_status_t
nxge_txc_handle_port_errors(p_nxge_t, uint32_t);
static void
nxge_txc_inject_port_err(uint8_t, txc_int_stat_dbg_t *,
			uint8_t istats);
extern nxge_status_t nxge_tx_port_fatal_err_recover(p_nxge_t);

nxge_status_t
nxge_txc_init(p_nxge_t nxgep)
{
	uint8_t			port;
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	port = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txc_init: portn %d", port));

	/*
	 * Enable the TXC controller.
	 */
	if ((rs = npi_txc_global_enable(handle)) != NPI_SUCCESS) {
		goto fail;
	}

	/* Enable this port within the TXC. */
	if ((rs = npi_txc_port_enable(handle, port)) != NPI_SUCCESS) {
		goto fail;
	}

	/* Bind DMA channels to this port. */
	if ((rs = npi_txc_port_dma_enable(handle, port,
	    TXDMA_PORT_BITMAP(nxgep))) != NPI_SUCCESS) {
		goto fail;
	}

	/* Unmask all TXC interrupts */
	npi_txc_global_imask_set(handle, port, 0);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txc_init: portn %d", port));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_txc_init: Failed to initialize txc on port %d",
	    port));

	return (NXGE_ERROR | rs);
}

nxge_status_t
nxge_txc_uninit(p_nxge_t nxgep)
{
	uint8_t			port;
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	port = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "==> nxge_txc_uninit: portn %d", port));

	/*
	 * disable the TXC controller.
	 */
	if ((rs = npi_txc_global_disable(handle)) != NPI_SUCCESS) {
		goto fail;
	}

	/* disable this port within the TXC. */
	if ((rs = npi_txc_port_disable(handle, port)) != NPI_SUCCESS) {
		goto fail;
	}

	/* unbind DMA channels to this port. */
	if ((rs = npi_txc_port_dma_enable(handle, port, 0)) != NPI_SUCCESS) {
		goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "<== nxge_txc_uninit: portn %d", port));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_txc_init: Failed to initialize txc on port %d",
	    port));

	return (NXGE_ERROR | rs);
}

/*
 * nxge_txc_tdc_bind
 *
 *	Bind a TDC to a port.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to bind.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txc_control()
 *	npi_txc_global_imask_set()
 *	npi_txc_port_dma_enable()
 *
 * Registers accessed:
 *	TXC_CONTROL
 *	TXC_PORT_DMA
 *	TXC_INT_MASK
 *
 * Context:
 *	Service domain
 */
nxge_status_t
nxge_txc_tdc_bind(
	p_nxge_t nxgep,
	int channel)
{
	uint8_t		port;
	uint64_t	bitmap;
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;
	txc_control_t	txc_control;

	port = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_txc_tdc_bind(port %d, channel %d)", port, channel));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	/* Get the current value of TXC_CONTROL. */
	(void) npi_txc_control(handle, OP_GET, &txc_control);

	/* Mask all TXC interrupts for <port>. */
	if (txc_control.value & (1 << port)) {
		npi_txc_global_imask_set(handle, port, TXC_INT_MASK_IVAL);
	}

	/* Bind <channel> to <port>. */
	/* Read in the old bitmap. */
	TXC_FZC_CNTL_REG_READ64(handle, TXC_PORT_DMA_ENABLE_REG, port,
	    &bitmap);

	if (bitmap & (1 << channel)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_txc_tdc_bind: channel %d already bound on port %d",
		    channel, port));
	} else {
		/* Bind the new channel. */
		bitmap |= (1 << channel);
		NXGE_DEBUG_MSG((nxgep, TX_CTL,
		    "==> nxge_txc_tdc_bind(): bitmap = %lx", bitmap));

		/* Write out the new bitmap. */
		if ((rs = npi_txc_port_dma_enable(handle, port,
		    (uint32_t)bitmap)) != NPI_SUCCESS) {
			goto fail;
		}
	}

	/* Enable this port, if necessary. */
	if (!(txc_control.value & (1 << port))) {
		if ((rs = npi_txc_port_enable(handle, port)) != NPI_SUCCESS) {
			goto fail;
		}
	}

	/*
	 * Enable the TXC controller, if necessary.
	 */
	if (txc_control.bits.ldw.txc_enabled == 0) {
		if ((rs = npi_txc_global_enable(handle)) != NPI_SUCCESS) {
			goto fail;
		}
	}

	/* Unmask all TXC interrupts on <port> */
	npi_txc_global_imask_set(handle, port, 0);

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "<== nxge_txc_tdc_bind(port %d, channel %d)", port, channel));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_txc_tdc_bind(port %d, channel %d) failed", port, channel));

	return (NXGE_ERROR | rs);
}

/*
 * nxge_txc_tdc_unbind
 *
 *	Unbind a TDC from a port.
 *
 * Arguments:
 * 	nxgep
 * 	channel		The channel to unbind.
 *
 * Notes:
 *
 * NPI/NXGE function calls:
 *	npi_txc_control()
 *	npi_txc_global_imask_set()
 *	npi_txc_port_dma_enable()
 *
 * Registers accessed:
 *	TXC_CONTROL
 *	TXC_PORT_DMA
 *	TXC_INT_MASK
 *
 * Context:
 *	Service domain
 */
nxge_status_t
nxge_txc_tdc_unbind(
	p_nxge_t nxgep,
	int channel)
{
	uint8_t		port;
	uint64_t	bitmap;
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	port = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "==> nxge_txc_tdc_unbind(port %d, channel %d)", port, channel));

	/* Mask all TXC interrupts for <port>. */
	npi_txc_global_imask_set(handle, port, TXC_INT_MASK_IVAL);

	/* Unbind <channel>. */
	/* Read in the old bitmap. */
	TXC_FZC_CNTL_REG_READ64(handle, TXC_PORT_DMA_ENABLE_REG, port,
	    &bitmap);

	bitmap &= (~(1 << channel));

	/* Write out the new bitmap. */
	if ((rs = npi_txc_port_dma_enable(handle, port,
	    (uint32_t)bitmap)) != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "npi_txc_port_dma_enable(%d, %d) failed: %x",
		    port, channel, rs));
	}

	/* Unmask all TXC interrupts on <port> */
	if (bitmap)
		npi_txc_global_imask_set(handle, port, 0);

	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "<== nxge_txc_tdc_unbind(port %d, channel %d)", port, channel));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_txc_tdc_unbind(port %d, channel %d) failed", port, channel));

	return (NXGE_ERROR | rs);
}

void
nxge_txc_regs_dump(p_nxge_t nxgep)
{
	uint32_t		cnt1, cnt2;
	npi_handle_t		handle;
	txc_control_t		control;
	uint32_t		bitmap = 0;

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "\nTXC dump: func # %d:\n",
	    nxgep->function_num));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	(void) npi_txc_control(handle, OP_GET, &control);
	(void) npi_txc_port_dma_list_get(handle, nxgep->function_num, &bitmap);

	NXGE_DEBUG_MSG((nxgep, TX_CTL, "\n\tTXC port control 0x%0llx",
	    (long long)control.value));
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "\n\tTXC port bitmap 0x%x", bitmap));

	(void) npi_txc_pkt_xmt_to_mac_get(handle, nxgep->function_num,
	    &cnt1, &cnt2);
	NXGE_DEBUG_MSG((nxgep, TX_CTL, "\n\tTXC bytes to MAC %d "
	    "packets to MAC %d",
	    cnt1, cnt2));

	(void) npi_txc_pkt_stuffed_get(handle, nxgep->function_num,
	    &cnt1, &cnt2);
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "\n\tTXC ass packets %d reorder packets %d",
	    cnt1 & 0xffff, cnt2 & 0xffff));

	(void) npi_txc_reorder_get(handle, nxgep->function_num, &cnt1);
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "\n\tTXC reorder resource %d", cnt1 & 0xff));
}

nxge_status_t
nxge_txc_handle_sys_errors(p_nxge_t nxgep)
{
	npi_handle_t		handle;
	txc_int_stat_t		istatus;
	uint32_t		err_status;
	uint8_t			err_portn;
	boolean_t		my_err = B_FALSE;
	nxge_status_t		status = NXGE_OK;

	handle = nxgep->npi_handle;
	npi_txc_global_istatus_get(handle, (txc_int_stat_t *)&istatus.value);
	switch (nxgep->mac.portnum) {
	case 0:
		if (istatus.bits.ldw.port0_int_status) {
			my_err = B_TRUE;
			err_portn = 0;
			err_status = istatus.bits.ldw.port0_int_status;
		}
		break;
	case 1:
		if (istatus.bits.ldw.port1_int_status) {
			my_err = B_TRUE;
			err_portn = 1;
			err_status = istatus.bits.ldw.port1_int_status;
		}
		break;
	case 2:
		if (istatus.bits.ldw.port2_int_status) {
			my_err = B_TRUE;
			err_portn = 2;
			err_status = istatus.bits.ldw.port2_int_status;
		}
		break;
	case 3:
		if (istatus.bits.ldw.port3_int_status) {
			my_err = B_TRUE;
			err_portn = 3;
			err_status = istatus.bits.ldw.port3_int_status;
		}
		break;
	default:
		return (NXGE_ERROR);
	}
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    " nxge_txc_handle_sys_errors: errored port %d",
	    err_portn));
	if (my_err) {
		status = nxge_txc_handle_port_errors(nxgep, err_status);
	}

	return (status);
}

static nxge_status_t
nxge_txc_handle_port_errors(p_nxge_t nxgep, uint32_t err_status)
{
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;
	p_nxge_txc_stats_t	statsp;
	txc_int_stat_t		istatus;
	boolean_t		txport_fatal = B_FALSE;
	uint8_t			portn;
	nxge_status_t		status = NXGE_OK;

	handle = nxgep->npi_handle;
	statsp = (p_nxge_txc_stats_t)&nxgep->statsp->txc_stats;
	portn = nxgep->mac.portnum;
	istatus.value = 0;

	if ((err_status & TXC_INT_STAT_RO_CORR_ERR) ||
	    (err_status & TXC_INT_STAT_RO_CORR_ERR) ||
	    (err_status & TXC_INT_STAT_RO_UNCORR_ERR) ||
	    (err_status & TXC_INT_STAT_REORDER_ERR)) {
		if ((rs = npi_txc_ro_states_get(handle, portn,
		    &statsp->errlog.ro_st)) != NPI_SUCCESS) {
			return (NXGE_ERROR | rs);
		}

		if (err_status & TXC_INT_STAT_RO_CORR_ERR) {
			statsp->ro_correct_err++;
			NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
			    NXGE_FM_EREPORT_TXC_RO_CORRECT_ERR);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_txc_err_evnts: "
			    "RO FIFO correctable error"));
		}
		if (err_status & TXC_INT_STAT_RO_UNCORR_ERR) {
			statsp->ro_uncorrect_err++;
			NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
			    NXGE_FM_EREPORT_TXC_RO_UNCORRECT_ERR);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_txc_err_evnts: "
			    "RO FIFO uncorrectable error"));
		}
		if (err_status & TXC_INT_STAT_REORDER_ERR) {
			statsp->reorder_err++;
			NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
			    NXGE_FM_EREPORT_TXC_REORDER_ERR);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_txc_err_evnts: "
			    "fatal error: Reorder error"));
			txport_fatal = B_TRUE;
		}

		if ((err_status & TXC_INT_STAT_RO_CORR_ERR) ||
		    (err_status & TXC_INT_STAT_RO_CORR_ERR) ||
		    (err_status & TXC_INT_STAT_RO_UNCORR_ERR)) {

			if ((rs = npi_txc_ro_ecc_state_clr(handle, portn))
			    != NPI_SUCCESS)
				return (NXGE_ERROR | rs);
			/*
			 * Making sure that error source is cleared if this is
			 * an injected error.
			 */
			TXC_FZC_CNTL_REG_WRITE64(handle, TXC_ROECC_CTL_REG,
			    portn, 0);
		}
	}

	if ((err_status & TXC_INT_STAT_SF_CORR_ERR) ||
	    (err_status & TXC_INT_STAT_SF_UNCORR_ERR)) {
		if ((rs = npi_txc_sf_states_get(handle, portn,
		    &statsp->errlog.sf_st)) != NPI_SUCCESS) {
			return (NXGE_ERROR | rs);
		}
		if (err_status & TXC_INT_STAT_SF_CORR_ERR) {
			statsp->sf_correct_err++;
			NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
			    NXGE_FM_EREPORT_TXC_SF_CORRECT_ERR);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_txc_err_evnts: "
			    "SF FIFO correctable error"));
		}
		if (err_status & TXC_INT_STAT_SF_UNCORR_ERR) {
			statsp->sf_uncorrect_err++;
			NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
			    NXGE_FM_EREPORT_TXC_SF_UNCORRECT_ERR);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_txc_err_evnts: "
			    "SF FIFO uncorrectable error"));
		}
		if ((rs = npi_txc_sf_ecc_state_clr(handle, portn))
		    != NPI_SUCCESS)
			return (NXGE_ERROR | rs);
		/*
		 * Making sure that error source is cleared if this is
		 * an injected error.
		 */
		TXC_FZC_CNTL_REG_WRITE64(handle, TXC_SFECC_CTL_REG, portn, 0);
	}

	/* Clear corresponding errors */
	switch (portn) {
	case 0:
		istatus.bits.ldw.port0_int_status = err_status;
		break;
	case 1:
		istatus.bits.ldw.port1_int_status = err_status;
		break;
	case 2:
		istatus.bits.ldw.port2_int_status = err_status;
		break;
	case 3:
		istatus.bits.ldw.port3_int_status = err_status;
		break;
	default:
		return (NXGE_ERROR);
	}

	npi_txc_global_istatus_clear(handle, istatus.value);

	if (txport_fatal) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    " nxge_txc_handle_port_errors:"
		    " fatal Error on Port#%d\n",
		    portn));
		status = nxge_tx_port_fatal_err_recover(nxgep);
		if (status == NXGE_OK) {
			FM_SERVICE_RESTORED(nxgep);
		}
	}

	return (status);
}

void
nxge_txc_inject_err(p_nxge_t nxgep, uint32_t err_id)
{
	txc_int_stat_dbg_t	txcs;
	txc_roecc_ctl_t		ro_ecc_ctl;
	txc_sfecc_ctl_t		sf_ecc_ctl;
	uint8_t			portn = nxgep->mac.portnum;

	cmn_err(CE_NOTE, "!TXC error Inject\n");
	switch (err_id) {
	case NXGE_FM_EREPORT_TXC_RO_CORRECT_ERR:
	case NXGE_FM_EREPORT_TXC_RO_UNCORRECT_ERR:
		ro_ecc_ctl.value = 0;
		ro_ecc_ctl.bits.ldw.all_pkts = 1;
		ro_ecc_ctl.bits.ldw.second_line_pkt = 1;
		if (err_id == NXGE_FM_EREPORT_TXC_RO_CORRECT_ERR)
			ro_ecc_ctl.bits.ldw.single_bit_err = 1;
		else
			ro_ecc_ctl.bits.ldw.double_bit_err = 1;
#if defined(__i386)
		cmn_err(CE_NOTE, "!Write 0x%llx to TXC_ROECC_CTL_REG\n",
		    ro_ecc_ctl.value);
#else
		cmn_err(CE_NOTE, "!Write 0x%lx to TXC_ROECC_CTL_REG\n",
		    ro_ecc_ctl.value);
#endif
		TXC_FZC_CNTL_REG_WRITE64(nxgep->npi_handle, TXC_ROECC_CTL_REG,
		    portn, ro_ecc_ctl.value);
		break;
	case NXGE_FM_EREPORT_TXC_SF_CORRECT_ERR:
	case NXGE_FM_EREPORT_TXC_SF_UNCORRECT_ERR:
		sf_ecc_ctl.value = 0;
		sf_ecc_ctl.bits.ldw.all_pkts = 1;
		sf_ecc_ctl.bits.ldw.second_line_pkt = 1;
		if (err_id == NXGE_FM_EREPORT_TXC_SF_CORRECT_ERR)
			sf_ecc_ctl.bits.ldw.single_bit_err = 1;
		else
			sf_ecc_ctl.bits.ldw.double_bit_err = 1;
#if defined(__i386)
		cmn_err(CE_NOTE, "!Write 0x%llx to TXC_SFECC_CTL_REG\n",
		    sf_ecc_ctl.value);
#else
		cmn_err(CE_NOTE, "!Write 0x%lx to TXC_SFECC_CTL_REG\n",
		    sf_ecc_ctl.value);
#endif
		TXC_FZC_CNTL_REG_WRITE64(nxgep->npi_handle, TXC_SFECC_CTL_REG,
		    portn, sf_ecc_ctl.value);
		break;
	case NXGE_FM_EREPORT_TXC_REORDER_ERR:
		NXGE_REG_RD64(nxgep->npi_handle, TXC_INT_STAT_DBG_REG,
		    &txcs.value);
		nxge_txc_inject_port_err(portn, &txcs,
		    TXC_INT_STAT_REORDER_ERR);
#if defined(__i386)
		cmn_err(CE_NOTE, "!Write 0x%llx to TXC_INT_STAT_DBG_REG\n",
		    txcs.value);
#else
		cmn_err(CE_NOTE, "!Write 0x%lx to TXC_INT_STAT_DBG_REG\n",
		    txcs.value);
#endif
		NXGE_REG_WR64(nxgep->npi_handle, TXC_INT_STAT_DBG_REG,
		    txcs.value);
		break;
	default:
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_txc_inject_err: Unknown err_id"));
	}
}

static void
nxge_txc_inject_port_err(uint8_t portn, txc_int_stat_dbg_t *txcs,
				uint8_t istats)
{
	switch (portn) {
	case 0:
		txcs->bits.ldw.port0_int_status |= istats;
		break;
	case 1:
		txcs->bits.ldw.port1_int_status |= istats;
		break;
	case 2:
		txcs->bits.ldw.port2_int_status |= istats;
		break;
	case 3:
		txcs->bits.ldw.port3_int_status |= istats;
		break;
	default:
		;
	}
}
