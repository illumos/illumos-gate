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

#include <nxge_impl.h>
#include <nxge_ipp.h>

#define	NXGE_IPP_FIFO_SYNC_TRY_COUNT 100

/* ARGSUSED */
nxge_status_t
nxge_ipp_init(p_nxge_t nxgep)
{
	uint8_t portn;
	uint32_t config;
	npi_handle_t handle;
	uint32_t pkt_size;
	ipp_status_t istatus;
	npi_status_t rs = NPI_SUCCESS;
	uint64_t val;
	uint32_t d0, d1, d2, d3, d4;
	int i;
	uint32_t dfifo_entries;

	handle = nxgep->npi_handle;
	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "==> nxge_ipp_init: port%d", portn));

	/* Initialize ECC and parity in SRAM of DFIFO and PFIFO */
	if (nxgep->niu_type == N2_NIU) {
		dfifo_entries = IPP_NIU_DFIFO_ENTRIES;
	} else if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		if (portn < 2)
			dfifo_entries = IPP_P0_P1_DFIFO_ENTRIES;
		else
			dfifo_entries = IPP_P2_P3_DFIFO_ENTRIES;
	} else {
		goto fail;
	}

	for (i = 0; i < dfifo_entries; i++) {
		if ((rs = npi_ipp_write_dfifo(handle,
		    portn, i, 0, 0, 0, 0, 0)) != NPI_SUCCESS)
			goto fail;
		if ((rs = npi_ipp_read_dfifo(handle, portn,
		    i, &d0, &d1, &d2, &d3, &d4)) != NPI_SUCCESS)
			goto fail;
	}

	/* Clear PFIFO DFIFO status bits */
	if ((rs = npi_ipp_get_status(handle, portn, &istatus)) != NPI_SUCCESS)
		goto fail;
	if ((rs = npi_ipp_get_status(handle, portn, &istatus)) != NPI_SUCCESS)
		goto fail;

	/*
	 * Soft reset to make sure we bring the FIFO pointers back to the
	 * original initial position.
	 */
	if ((rs = npi_ipp_reset(handle, portn)) != NPI_SUCCESS)
		goto fail;

	/* Clean up ECC counter */
	IPP_REG_RD(nxgep->npi_handle, portn, IPP_ECC_ERR_COUNTER_REG, &val);
	IPP_REG_RD(nxgep->npi_handle, portn, IPP_BAD_CKSUM_ERR_CNT_REG, &val);
	IPP_REG_RD(nxgep->npi_handle, portn, IPP_DISCARD_PKT_CNT_REG, &val);

	if ((rs = npi_ipp_get_status(handle, portn, &istatus)) != NPI_SUCCESS)
		goto fail;

	/* Configure IPP port */
	if ((rs = npi_ipp_iconfig(handle, INIT, portn, ICFG_IPP_ALL))
	    != NPI_SUCCESS)
		goto fail;
	nxgep->ipp.iconfig = ICFG_IPP_ALL;

	config = CFG_IPP | CFG_IPP_DFIFO_ECC_CORRECT | CFG_IPP_DROP_BAD_CRC |
	    CFG_IPP_TCP_UDP_CKSUM;
	if ((rs = npi_ipp_config(handle, INIT, portn, config)) != NPI_SUCCESS)
		goto fail;
	nxgep->ipp.config = config;

	/* Set max packet size */
	pkt_size = IPP_MAX_PKT_SIZE;
	if ((rs = npi_ipp_set_max_pktsize(handle, portn,
	    IPP_MAX_PKT_SIZE)) != NPI_SUCCESS)
		goto fail;
	nxgep->ipp.max_pkt_size = pkt_size;

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "<== nxge_ipp_init: port%d", portn));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_ipp_init: Fail to initialize IPP Port #%d\n",
	    portn));
	return (NXGE_ERROR | rs);
}

/* ARGSUSED */
nxge_status_t
nxge_ipp_disable(p_nxge_t nxgep)
{
	uint8_t portn;
	uint32_t config;
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	uint16_t wr_ptr, rd_ptr;
	uint32_t try_count;

	handle = nxgep->npi_handle;
	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "==> nxge_ipp_disable: port%d", portn));
	(void) nxge_rx_mac_disable(nxgep);

	/*
	 * Wait until ip read and write fifo pointers are equal
	 */
	(void) npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr);
	(void) npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr);
	try_count = NXGE_IPP_FIFO_SYNC_TRY_COUNT;

	while ((try_count > 0) && (rd_ptr != wr_ptr)) {
		(void) npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr);
		(void) npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr);
		try_count--;
	}

	if (try_count == 0) {
		if ((rd_ptr != 0) && (wr_ptr != 1)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    " nxge_ipp_disable: port%d failed"
			    " rd_fifo != wr_fifo", portn));
			goto fail;
		}
	}
	/* disable the IPP */
	config = nxgep->ipp.config;
	if ((rs = npi_ipp_config(handle, DISABLE,
	    portn, config)) != NPI_SUCCESS)
		goto fail;

	/* IPP soft reset */
	if ((rs = npi_ipp_reset(handle, portn)) != NPI_SUCCESS)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "<== nxge_ipp_disable: port%d", portn));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_ipp_disable: Fail to disable IPP Port #%d\n", portn));
	return (NXGE_ERROR | rs);
}

/* ARGSUSED */
nxge_status_t
nxge_ipp_reset(p_nxge_t nxgep)
{
	uint8_t portn;
	uint32_t config;
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	uint16_t wr_ptr, rd_ptr;
	uint32_t try_count;

	handle = nxgep->npi_handle;
	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "==> nxge_ipp_reset: port%d", portn));

	/* disable the IPP */
	config = nxgep->ipp.config;
	if ((rs = npi_ipp_config(handle, DISABLE,
	    portn, config)) != NPI_SUCCESS)
		goto fail;

	/*
	 * Wait until ip read and write fifo pointers are equal
	 */
	(void) npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr);
	(void) npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr);
	try_count = NXGE_IPP_FIFO_SYNC_TRY_COUNT;

	while ((try_count > 0) && (rd_ptr != wr_ptr)) {
		(void) npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr);
		(void) npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr);
		try_count--;
	}

	if (try_count == 0) {
		if ((rd_ptr != 0) && (wr_ptr != 1)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    " nxge_ipp_disable: port%d failed"
			    " rd_fifo != wr_fifo", portn));
			goto fail;
		}
	}

	/* IPP soft reset */
	if ((rs = npi_ipp_reset(handle, portn)) != NPI_SUCCESS) {
		goto fail;
	}

	/* to reset control FIFO */
	if ((rs = npi_zcp_rest_cfifo_port(handle, portn)) != NPI_SUCCESS)
		goto fail;

	/*
	 * Making sure that error source is cleared if this is an injected
	 * error.
	 */
	IPP_REG_WR(handle, portn, IPP_ECC_CTRL_REG, 0);

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "<== nxge_ipp_reset: port%d", portn));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_ipp_init: Fail to Reset IPP Port #%d\n",
	    portn));
	return (NXGE_ERROR | rs);
}

/* ARGSUSED */
nxge_status_t
nxge_ipp_enable(p_nxge_t nxgep)
{
	uint8_t portn;
	uint32_t config;
	npi_handle_t handle;
	uint32_t pkt_size;
	npi_status_t rs = NPI_SUCCESS;

	handle = nxgep->npi_handle;
	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "==> nxge_ipp_enable: port%d", portn));

	config = CFG_IPP | CFG_IPP_DFIFO_ECC_CORRECT | CFG_IPP_DROP_BAD_CRC |
	    CFG_IPP_TCP_UDP_CKSUM;
	if ((rs = npi_ipp_config(handle, INIT, portn, config)) != NPI_SUCCESS)
		goto fail;
	nxgep->ipp.config = config;

	/* Set max packet size */
	pkt_size = IPP_MAX_PKT_SIZE;
	if ((rs = npi_ipp_set_max_pktsize(handle, portn,
	    IPP_MAX_PKT_SIZE)) != NPI_SUCCESS)
		goto fail;
	nxgep->ipp.max_pkt_size = pkt_size;

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "<== nxge_ipp_enable: port%d", portn));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_ipp_init: Fail to Enable IPP Port #%d\n", portn));
	return (NXGE_ERROR | rs);
}

/* ARGSUSED */
nxge_status_t
nxge_ipp_drain(p_nxge_t nxgep)
{
	uint8_t portn;
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	uint16_t wr_ptr, rd_ptr;
	uint32_t try_count;

	handle = nxgep->npi_handle;
	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "==> nxge_ipp_drain: port%d", portn));

	/*
	 * Wait until ip read and write fifo pointers are equal
	 */
	(void) npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr);
	(void) npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr);
	try_count = NXGE_IPP_FIFO_SYNC_TRY_COUNT;

	while ((try_count > 0) && (rd_ptr != wr_ptr)) {
		(void) npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr);
		(void) npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr);
		try_count--;
	}

	if (try_count == 0) {
		if ((rd_ptr != 0) && (wr_ptr != 1)) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    " nxge_ipp_drain: port%d failed"
			    " rd_fifo != wr_fifo", portn));
			goto fail;
		}
	}

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "<== nxge_ipp_drain: port%d", portn));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_ipp_init: "
	    "Fail to Reset IPP Port #%d\n", portn));
	return (NXGE_ERROR | rs);
}

/* ARGSUSED */
nxge_status_t
nxge_ipp_handle_sys_errors(p_nxge_t nxgep)
{
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	p_nxge_ipp_stats_t statsp;
	ipp_status_t istatus;
	uint8_t portn;
	p_ipp_errlog_t errlogp;
	boolean_t rxport_fatal = B_FALSE;
	nxge_status_t status = NXGE_OK;
	uint8_t cnt8;
	uint16_t cnt16;

	handle = nxgep->npi_handle;
	statsp = (p_nxge_ipp_stats_t)&nxgep->statsp->ipp_stats;
	portn = nxgep->mac.portnum;

	errlogp = (p_ipp_errlog_t)&statsp->errlog;

	if ((rs = npi_ipp_get_status(handle, portn, &istatus)) != NPI_SUCCESS)
		return (NXGE_ERROR | rs);

	if (istatus.value == 0) {
		/*
		 * The error is not initiated from this port, so just exit.
		 */
		return (NXGE_OK);
	}

	if (istatus.bits.w0.dfifo_missed_sop) {
		statsp->sop_miss++;
		if ((rs = npi_ipp_get_dfifo_eopm_rdptr(handle, portn,
		    &errlogp->dfifo_rd_ptr)) != NPI_SUCCESS)
			return (NXGE_ERROR | rs);
		if ((rs = npi_ipp_get_state_mach(handle, portn,
		    &errlogp->state_mach)) != NPI_SUCCESS)
			return (NXGE_ERROR | rs);
		NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
		    NXGE_FM_EREPORT_IPP_SOP_MISS);
		if (statsp->sop_miss < IPP_MAX_ERR_SHOW)
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_ipp_err_evnts: fatal error: sop_miss\n"));
		rxport_fatal = B_TRUE;
	}
	if (istatus.bits.w0.dfifo_missed_eop) {
		statsp->eop_miss++;
		if ((rs = npi_ipp_get_dfifo_eopm_rdptr(handle, portn,
		    &errlogp->dfifo_rd_ptr)) != NPI_SUCCESS)
			return (NXGE_ERROR | rs);
		if ((rs = npi_ipp_get_state_mach(handle, portn,
		    &errlogp->state_mach)) != NPI_SUCCESS)
			return (NXGE_ERROR | rs);
		NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
		    NXGE_FM_EREPORT_IPP_EOP_MISS);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_ipp_err_evnts: fatal error: eop_miss\n"));
		rxport_fatal = B_TRUE;
	}
	if (istatus.bits.w0.dfifo_uncorr_ecc_err) {
		boolean_t ue_ecc_valid;

		if ((status = nxge_ipp_eccue_valid_check(nxgep,
		    &ue_ecc_valid)) != NXGE_OK)
			return (status);

		if (ue_ecc_valid) {
			statsp->dfifo_ue++;
			if ((rs = npi_ipp_get_ecc_syndrome(handle, portn,
			    &errlogp->ecc_syndrome)) != NPI_SUCCESS)
				return (NXGE_ERROR | rs);
			NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
			    NXGE_FM_EREPORT_IPP_DFIFO_UE);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_ipp_err_evnts: fatal error: dfifo_ue\n"));
			rxport_fatal = B_TRUE;
		}
	}
	if (istatus.bits.w0.pre_fifo_perr) {
		statsp->pfifo_perr++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
		    NXGE_FM_EREPORT_IPP_PFIFO_PERR);
		if (statsp->pfifo_perr < IPP_MAX_ERR_SHOW)
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_ipp_err_evnts: "
			    "fatal error: pre_pifo_perr\n"));
		rxport_fatal = B_TRUE;
	}
	if (istatus.bits.w0.pre_fifo_overrun) {
		statsp->pfifo_over++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
		    NXGE_FM_EREPORT_IPP_PFIFO_OVER);
		if (statsp->pfifo_over < IPP_MAX_ERR_SHOW)
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_ipp_err_evnts: "
			    "fatal error: pfifo_over\n"));
		rxport_fatal = B_TRUE;
	}
	if (istatus.bits.w0.pre_fifo_underrun) {
		statsp->pfifo_und++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
		    NXGE_FM_EREPORT_IPP_PFIFO_UND);
		if (statsp->pfifo_und < IPP_MAX_ERR_SHOW)
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_ipp_err_evnts: "
			    "fatal error: pfifo_und\n"));
		rxport_fatal = B_TRUE;
	}
	if (istatus.bits.w0.bad_cksum_cnt_ovfl) {
		/*
		 * Do not send FMA ereport or log error message
		 * in /var/adm/messages because this error does not
		 * indicate a HW failure.
		 *
		 * Clear bit BAD_CS_MX of register IPP_INT_STAT
		 * by reading register IPP_BAD_CS_CNT
		 */
		(void) npi_ipp_get_cs_err_count(handle, portn, &cnt16);
		statsp->bad_cs_cnt += IPP_BAD_CS_CNT_MASK;
	}
	if (istatus.bits.w0.pkt_discard_cnt_ovfl) {
		/*
		 * Do not send FMA ereport or log error message
		 * in /var/adm/messages because this error does not
		 * indicate a HW failure.
		 *
		 * Clear bit PKT_DIS_MX of register IPP_INT_STAT
		 * by reading register IPP_PKT_DIS
		 */
		(void) npi_ipp_get_pkt_dis_count(handle, portn, &cnt16);
		statsp->pkt_dis_cnt += IPP_PKT_DIS_CNT_MASK;
	}
	if (istatus.bits.w0.ecc_err_cnt_ovfl) {
		/*
		 * Clear bit ECC_ERR_MAX of register IPP_INI_STAT
		 * by reading register IPP_ECC
		 */
		(void) npi_ipp_get_ecc_err_count(handle, portn, &cnt8);
		statsp->ecc_err_cnt += IPP_ECC_CNT_MASK;
		/*
		 * A defect in Neptune port2's IPP module could generate
		 * many fake but harmless ECC errors under stress and cause
		 * the ecc-error-counter register IPP_ECC to reach its
		 * maximum value in a few seconds. To avoid false alarm, do
		 * not report the error if it is port2.
		 */
		if (portn != 2) {
			NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
			    NXGE_FM_EREPORT_IPP_ECC_ERR_MAX);
			if (statsp->ecc_err_cnt < (IPP_MAX_ERR_SHOW *
			    IPP_ECC_CNT_MASK)) {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "nxge_ipp_err_evnts: pkt_ecc_err_max\n"));
			}
		}
	}
	/*
	 * Making sure that error source is cleared if this is an injected
	 * error.
	 */
	IPP_REG_WR(handle, portn, IPP_ECC_CTRL_REG, 0);

	if (rxport_fatal) {
		NXGE_DEBUG_MSG((nxgep, IPP_CTL,
		    " nxge_ipp_handle_sys_errors:"
		    " fatal Error on  Port #%d\n", portn));
		status = nxge_ipp_fatal_err_recover(nxgep);
		if (status == NXGE_OK) {
			FM_SERVICE_RESTORED(nxgep);
		}
	}
	return (status);
}

/* ARGSUSED */
void
nxge_ipp_inject_err(p_nxge_t nxgep, uint32_t err_id)
{
	ipp_status_t ipps;
	ipp_ecc_ctrl_t ecc_ctrl;
	uint8_t portn = nxgep->mac.portnum;

	switch (err_id) {
	case NXGE_FM_EREPORT_IPP_DFIFO_UE:
		ecc_ctrl.value = 0;
		ecc_ctrl.bits.w0.cor_dbl = 1;
		ecc_ctrl.bits.w0.cor_1 = 1;
		ecc_ctrl.bits.w0.cor_lst = 1;
		cmn_err(CE_NOTE, "!Write 0x%llx to IPP_ECC_CTRL_REG\n",
		    (unsigned long long) ecc_ctrl.value);
		IPP_REG_WR(nxgep->npi_handle, portn, IPP_ECC_CTRL_REG,
		    ecc_ctrl.value);
		break;

	case NXGE_FM_EREPORT_IPP_DFIFO_CE:
		ecc_ctrl.value = 0;
		ecc_ctrl.bits.w0.cor_sng = 1;
		ecc_ctrl.bits.w0.cor_1 = 1;
		ecc_ctrl.bits.w0.cor_snd = 1;
		cmn_err(CE_NOTE, "!Write 0x%llx to IPP_ECC_CTRL_REG\n",
		    (unsigned long long) ecc_ctrl.value);
		IPP_REG_WR(nxgep->npi_handle, portn, IPP_ECC_CTRL_REG,
		    ecc_ctrl.value);
		break;

	case NXGE_FM_EREPORT_IPP_EOP_MISS:
	case NXGE_FM_EREPORT_IPP_SOP_MISS:
	case NXGE_FM_EREPORT_IPP_PFIFO_PERR:
	case NXGE_FM_EREPORT_IPP_ECC_ERR_MAX:
	case NXGE_FM_EREPORT_IPP_PFIFO_OVER:
	case NXGE_FM_EREPORT_IPP_PFIFO_UND:
	case NXGE_FM_EREPORT_IPP_BAD_CS_MX:
	case NXGE_FM_EREPORT_IPP_PKT_DIS_MX:
	case NXGE_FM_EREPORT_IPP_RESET_FAIL:
		IPP_REG_RD(nxgep->npi_handle, portn, IPP_INT_STATUS_REG,
		    &ipps.value);
		if (err_id == NXGE_FM_EREPORT_IPP_EOP_MISS)
			ipps.bits.w0.dfifo_missed_eop = 1;
		else if (err_id == NXGE_FM_EREPORT_IPP_SOP_MISS)
			ipps.bits.w0.dfifo_missed_sop = 1;
		else if (err_id == NXGE_FM_EREPORT_IPP_DFIFO_UE)
			ipps.bits.w0.dfifo_uncorr_ecc_err = 1;
		else if (err_id == NXGE_FM_EREPORT_IPP_DFIFO_CE)
			ipps.bits.w0.dfifo_corr_ecc_err = 1;
		else if (err_id == NXGE_FM_EREPORT_IPP_PFIFO_PERR)
			ipps.bits.w0.pre_fifo_perr = 1;
		else if (err_id == NXGE_FM_EREPORT_IPP_ECC_ERR_MAX) {
			/*
			 * Fill register IPP_ECC with max ECC-error-
			 * counter value (0xff) to set the ECC_ERR_MAX bit
			 * of the IPP_INT_STAT register and trigger an
			 * FMA ereport.
			 */
			IPP_REG_WR(nxgep->npi_handle, portn,
			    IPP_ECC_ERR_COUNTER_REG, IPP_ECC_CNT_MASK);
		} else if (err_id == NXGE_FM_EREPORT_IPP_PFIFO_OVER)
			ipps.bits.w0.pre_fifo_overrun = 1;
		else if (err_id == NXGE_FM_EREPORT_IPP_PFIFO_UND)
			ipps.bits.w0.pre_fifo_underrun = 1;
		else if (err_id == NXGE_FM_EREPORT_IPP_BAD_CS_MX) {
			/*
			 * Fill IPP_BAD_CS_CNT with max bad-checksum-counter
			 * value (0x3fff) to set the BAD_CS_MX bit of
			 * IPP_INT_STAT and trigger an FMA ereport.
			 */
			IPP_REG_WR(nxgep->npi_handle, portn,
			    IPP_BAD_CKSUM_ERR_CNT_REG, IPP_BAD_CS_CNT_MASK);
		} else if (err_id == NXGE_FM_EREPORT_IPP_PKT_DIS_MX) {
			/*
			 * Fill IPP_PKT_DIS with max packet-discard-counter
			 * value (0x3fff) to set the PKT_DIS_MX bit of
			 * IPP_INT_STAT and trigger an FMA ereport.
			 */
			IPP_REG_WR(nxgep->npi_handle, portn,
			    IPP_DISCARD_PKT_CNT_REG, IPP_PKT_DIS_CNT_MASK);
		}
		cmn_err(CE_NOTE, "!Write 0x%llx to IPP_INT_STATUS_REG\n",
		    (unsigned long long) ipps.value);
		IPP_REG_WR(nxgep->npi_handle, portn, IPP_INT_STATUS_REG,
		    ipps.value);
		break;
	}
}

/* ARGSUSED */
nxge_status_t
nxge_ipp_fatal_err_recover(p_nxge_t nxgep)
{
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	nxge_status_t status = NXGE_OK;
	uint8_t portn;
	uint16_t wr_ptr;
	uint16_t rd_ptr;
	uint32_t try_count;
	uint32_t dfifo_entries;
	ipp_status_t istatus;
	uint32_t d0, d1, d2, d3, d4;
	int i;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "<== nxge_ipp_fatal_err_recover"));
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "Recovering from RxPort error..."));

	handle = nxgep->npi_handle;
	portn = nxgep->mac.portnum;

	/*
	 * Making sure that error source is cleared if this is an injected
	 * error.
	 */
	IPP_REG_WR(handle, portn, IPP_ECC_CTRL_REG, 0);

	/* Disable RxMAC */
	if (nxge_rx_mac_disable(nxgep) != NXGE_OK)
		goto fail;

	/* When recovering from IPP, RxDMA channel resets are not necessary */
	/* Reset ZCP CFIFO */
	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "port%d Reset ZCP CFIFO...", portn));
	if ((rs = npi_zcp_rest_cfifo_port(handle, portn)) != NPI_SUCCESS)
		goto fail;

	/*
	 * Wait until ip read and write fifo pointers are equal
	 */
	(void) npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr);
	(void) npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr);
	try_count = 512;

	while ((try_count > 0) && (rd_ptr != wr_ptr)) {
		(void) npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr);
		(void) npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr);
		try_count--;
	}

	if (try_count == 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    " nxge_ipp_reset: port%d IPP stalled..."
		    " rd_fifo_ptr = 0x%x wr_fifo_ptr = 0x%x",
		    portn, rd_ptr, wr_ptr));
		/*
		 * This means the fatal error occurred on the first line of the
		 * fifo. In this case, just reset the IPP without draining the
		 * PFIFO.
		 */
	}

	if (nxgep->niu_type == N2_NIU) {
		dfifo_entries = IPP_NIU_DFIFO_ENTRIES;
	} else if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		if (portn < 2)
			dfifo_entries = IPP_P0_P1_DFIFO_ENTRIES;
		else
			dfifo_entries = IPP_P2_P3_DFIFO_ENTRIES;
	} else {
		goto fail;
	}

	/* Clean up DFIFO SRAM entries */
	for (i = 0; i < dfifo_entries; i++) {
		if ((rs = npi_ipp_write_dfifo(handle, portn,
		    i, 0, 0, 0, 0, 0)) != NPI_SUCCESS)
			goto fail;
		if ((rs = npi_ipp_read_dfifo(handle, portn, i,
		    &d0, &d1, &d2, &d3, &d4)) != NPI_SUCCESS)
			goto fail;
	}

	/* Clear PFIFO DFIFO status bits */
	if ((rs = npi_ipp_get_status(handle, portn, &istatus)) != NPI_SUCCESS)
		goto fail;
	if ((rs = npi_ipp_get_status(handle, portn, &istatus)) != NPI_SUCCESS)
		goto fail;

	/* Reset IPP */
	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "port%d Reset IPP...", portn));
	if ((rs = npi_ipp_reset(handle, portn)) != NPI_SUCCESS)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "port%d Reset RxMAC...", portn));
	if (nxge_rx_mac_reset(nxgep) != NXGE_OK)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "port%d Initialize RxMAC...", portn));
	if ((status = nxge_rx_mac_init(nxgep)) != NXGE_OK)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, IPP_CTL, "port%d Enable RxMAC...", portn));
	if (nxge_rx_mac_enable(nxgep) != NXGE_OK)
		goto fail;

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "Recovery successful, RxPort restored"));
	NXGE_DEBUG_MSG((nxgep, RX_CTL, "==> nxge_ipp_fatal_err_recover"));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "Recovery failed"));
	return (status | rs);
}

/* ARGSUSED */
/*
 *    A hardware bug may cause fake ECCUEs (ECC Uncorrectable Error).
 * This function checks if a ECCUE is real(valid) or not.  It is not
 * real if rd_ptr == wr_ptr.
 *    The hardware module that has the bug is used not only by the IPP
 * FIFO but also by the ZCP FIFO, therefore this function is also
 * called by nxge_zcp_handle_sys_errors for validating the ZCP FIFO
 * error.
 */
nxge_status_t
nxge_ipp_eccue_valid_check(p_nxge_t nxgep, boolean_t *valid)
{
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	uint8_t portn;
	uint16_t rd_ptr;
	uint16_t wr_ptr;
	uint16_t curr_rd_ptr;
	uint16_t curr_wr_ptr;
	uint32_t stall_cnt;
	uint32_t d0, d1, d2, d3, d4;

	handle = nxgep->npi_handle;
	portn = nxgep->mac.portnum;
	*valid = B_TRUE;

	if ((rs = npi_ipp_get_dfifo_rd_ptr(handle, portn, &rd_ptr))
	    != NPI_SUCCESS)
		goto fail;
	if ((rs = npi_ipp_get_dfifo_wr_ptr(handle, portn, &wr_ptr))
	    != NPI_SUCCESS)
		goto fail;

	if (rd_ptr == wr_ptr) {
		*valid = B_FALSE; /* FIFO not stuck, so it's not a real ECCUE */
	} else {
		stall_cnt = 0;
		/*
		 * Check if the two pointers are moving, the ECCUE is invali
		 * if either pointer is moving, which indicates that the FIFO
		 * is functional.
		 */
		while (stall_cnt < 16) {
			if ((rs = npi_ipp_get_dfifo_rd_ptr(handle,
			    portn, &curr_rd_ptr)) != NPI_SUCCESS)
				goto fail;
			if ((rs = npi_ipp_get_dfifo_wr_ptr(handle,
			    portn, &curr_wr_ptr)) != NPI_SUCCESS)
				goto fail;

			if (rd_ptr == curr_rd_ptr && wr_ptr == curr_wr_ptr) {
				stall_cnt++;
			} else {
				*valid = B_FALSE;
				break;
			}
		}

		if (valid) {
			/*
			 * Further check to see if the ECCUE is valid. The
			 * error is real if the LSB of d4 is 1, which
			 * indicates that the data that has set the ECC
			 * error flag is the 16-byte internal control word.
			 */
			if ((rs = npi_ipp_read_dfifo(handle, portn, rd_ptr,
			    &d0, &d1, &d2, &d3, &d4)) != NPI_SUCCESS)
				goto fail;
			if ((d4 & 0x1) == 0)	/* Not the 1st line */
				*valid = B_FALSE;
		}
	}
	return (NXGE_OK);
fail:
	return (NXGE_ERROR | rs);
}
