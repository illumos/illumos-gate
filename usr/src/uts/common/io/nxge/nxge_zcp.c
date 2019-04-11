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

#include <nxge_impl.h>
#include <nxge_zcp.h>
#include <nxge_ipp.h>

nxge_status_t
nxge_zcp_init(p_nxge_t nxgep)
{
	uint8_t portn;
	npi_handle_t handle;
	zcp_iconfig_t istatus;
	npi_status_t rs = NPI_SUCCESS;
	int i;
	zcp_ram_unit_t w_data;
	zcp_ram_unit_t r_data;
	uint32_t cfifo_depth;

	handle = nxgep->npi_handle;
	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	if (nxgep->niu_type == N2_NIU) {
		cfifo_depth = ZCP_NIU_CFIFO_DEPTH;
	} else if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		if (portn < 2)
			cfifo_depth = ZCP_P0_P1_CFIFO_DEPTH;
		else
			cfifo_depth = ZCP_P2_P3_CFIFO_DEPTH;
	} else {
		goto fail;
	}

	/* Clean up CFIFO */
	w_data.w0 = 0;
	w_data.w1 = 0;
	w_data.w2 = 0;
	w_data.w3 = 0;
	w_data.w4 = 0;

	for (i = 0; i < cfifo_depth; i++) {
		if (npi_zcp_tt_cfifo_entry(handle, OP_SET,
		    portn, i, &w_data) != NPI_SUCCESS)
			goto fail;
		if (npi_zcp_tt_cfifo_entry(handle, OP_GET,
		    portn, i, &r_data) != NPI_SUCCESS)
			goto fail;
	}

	if (npi_zcp_rest_cfifo_port(handle, portn) != NPI_SUCCESS)
		goto fail;

	/*
	 * Making sure that error source is cleared if this is an injected
	 * error.
	 */
	switch (portn) {
	case 0:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT0_REG, 0);
		break;
	case 1:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT1_REG, 0);
		break;
	case 2:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT2_REG, 0);
		break;
	case 3:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT3_REG, 0);
		break;
	}

	if ((rs = npi_zcp_clear_istatus(handle)) != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	if ((rs = npi_zcp_get_istatus(handle, &istatus)) != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	if ((rs = npi_zcp_iconfig(handle, INIT, ICFG_ZCP_ALL)) != NPI_SUCCESS)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "==> nxge_zcp_init: port%d", portn));
	return (NXGE_OK);

fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_zcp_init: Fail to initialize ZCP Port #%d\n", portn));
	return (NXGE_ERROR | rs);
}

nxge_status_t
nxge_zcp_handle_sys_errors(p_nxge_t nxgep)
{
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	p_nxge_zcp_stats_t statsp;
	uint8_t portn;
	zcp_iconfig_t istatus;
	boolean_t rxport_fatal = B_FALSE;
	nxge_status_t status = NXGE_OK;

	handle = nxgep->npi_handle;
	statsp = (p_nxge_zcp_stats_t)&nxgep->statsp->zcp_stats;
	portn = nxgep->mac.portnum;

	if ((rs = npi_zcp_get_istatus(handle, &istatus)) != NPI_SUCCESS)
		return (NXGE_ERROR | rs);

	if (istatus & ICFG_ZCP_RRFIFO_UNDERRUN) {
		statsp->rrfifo_underrun++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_RRFIFO_UNDERRUN);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: rrfifo_underrun"));
	}

	if (istatus & ICFG_ZCP_RRFIFO_OVERRUN) {
		statsp->rrfifo_overrun++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_RRFIFO_OVERRUN);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: buf_rrfifo_overrun"));
	}

	if (istatus & ICFG_ZCP_RSPFIFO_UNCORR_ERR) {
		statsp->rspfifo_uncorr_err++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_RSPFIFO_UNCORR_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: rspfifo_uncorr_err"));
	}

	if (istatus & ICFG_ZCP_BUFFER_OVERFLOW) {
		statsp->buffer_overflow++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_BUFFER_OVERFLOW);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: buffer_overflow"));
		rxport_fatal = B_TRUE;
	}

	if (istatus & ICFG_ZCP_STAT_TBL_PERR) {
		statsp->stat_tbl_perr++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_STAT_TBL_PERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: stat_tbl_perr"));
	}

	if (istatus & ICFG_ZCP_DYN_TBL_PERR) {
		statsp->dyn_tbl_perr++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_DYN_TBL_PERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: dyn_tbl_perr"));
	}

	if (istatus & ICFG_ZCP_BUF_TBL_PERR) {
		statsp->buf_tbl_perr++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_BUF_TBL_PERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: buf_tbl_perr"));
	}

	if (istatus & ICFG_ZCP_TT_PROGRAM_ERR) {
		statsp->tt_program_err++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_TT_PROGRAM_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: tt_program_err"));
	}

	if (istatus & ICFG_ZCP_RSP_TT_INDEX_ERR) {
		statsp->rsp_tt_index_err++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_RSP_TT_INDEX_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: rsp_tt_index_err"));
	}

	if (istatus & ICFG_ZCP_SLV_TT_INDEX_ERR) {
		statsp->slv_tt_index_err++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_SLV_TT_INDEX_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: slv_tt_index_err"));
	}

	if (istatus & ICFG_ZCP_TT_INDEX_ERR) {
		statsp->zcp_tt_index_err++;
		NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
		    NXGE_FM_EREPORT_ZCP_TT_INDEX_ERR);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_zcp_err_evnts: tt_index_err"));
	}

	if (((portn == 0) && (istatus & ICFG_ZCP_CFIFO_ECC0)) ||
	    ((portn == 1) && (istatus & ICFG_ZCP_CFIFO_ECC1)) ||
	    ((portn == 2) && (istatus & ICFG_ZCP_CFIFO_ECC2)) ||
	    ((portn == 3) && (istatus & ICFG_ZCP_CFIFO_ECC3))) {
		boolean_t ue_ecc_valid;

		if ((status = nxge_ipp_eccue_valid_check(nxgep,
		    &ue_ecc_valid)) != NXGE_OK)
			return (status);

		if (ue_ecc_valid) {
			statsp->cfifo_ecc++;
			NXGE_FM_REPORT_ERROR(nxgep, portn, 0,
			    NXGE_FM_EREPORT_ZCP_CFIFO_ECC);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_zcp_err_evnts: port%d buf_cfifo_ecc",
			    portn));
			rxport_fatal = B_TRUE;
		}
	}

	/*
	 * Making sure that error source is cleared if this is an injected
	 * error.
	 */
	switch (portn) {
	case 0:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT0_REG, 0);
		break;
	case 1:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT1_REG, 0);
		break;
	case 2:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT2_REG, 0);
		break;
	case 3:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT3_REG, 0);
		break;
	}

	(void) npi_zcp_clear_istatus(handle);

	if (rxport_fatal) {
		NXGE_DEBUG_MSG((nxgep, IPP_CTL,
		    " nxge_zcp_handle_sys_errors:"
		    " fatal Error on  Port #%d\n", portn));
		status = nxge_zcp_fatal_err_recover(nxgep);
		if (status == NXGE_OK) {
			FM_SERVICE_RESTORED(nxgep);
		}
	}
	return (status);
}

void
nxge_zcp_inject_err(p_nxge_t nxgep, uint32_t err_id)
{
	zcp_int_stat_reg_t zcps;
	uint8_t portn = nxgep->mac.portnum;
	zcp_ecc_ctrl_t ecc_ctrl;

	switch (err_id) {
	case NXGE_FM_EREPORT_ZCP_CFIFO_ECC:
		ecc_ctrl.value = 0;
		ecc_ctrl.bits.w0.cor_dbl = 1;
		ecc_ctrl.bits.w0.cor_lst = 1;
		ecc_ctrl.bits.w0.cor_all = 0;
		switch (portn) {
		case 0:
			cmn_err(CE_NOTE,
			    "!Write 0x%llx to port%d ZCP_CFIFO_ECC_PORT\n",
			    (unsigned long long) ecc_ctrl.value, portn);
			NXGE_REG_WR64(nxgep->npi_handle,
			    ZCP_CFIFO_ECC_PORT0_REG,
			    ecc_ctrl.value);
			break;
		case 1:
			cmn_err(CE_NOTE,
			    "!Write 0x%llx to port%d ZCP_CFIFO_ECC_PORT\n",
			    (unsigned long long) ecc_ctrl.value, portn);
			NXGE_REG_WR64(nxgep->npi_handle,
			    ZCP_CFIFO_ECC_PORT1_REG,
			    ecc_ctrl.value);
			break;
		case 2:
			cmn_err(CE_NOTE,
			    "!Write 0x%llx to port%d ZCP_CFIFO_ECC_PORT\n",
			    (unsigned long long) ecc_ctrl.value, portn);
			NXGE_REG_WR64(nxgep->npi_handle,
			    ZCP_CFIFO_ECC_PORT2_REG,
			    ecc_ctrl.value);
			break;
		case 3:
			cmn_err(CE_NOTE,
			    "!Write 0x%llx to port%d ZCP_CFIFO_ECC_PORT\n",
			    (unsigned long long) ecc_ctrl.value, portn);
			NXGE_REG_WR64(nxgep->npi_handle,
			    ZCP_CFIFO_ECC_PORT3_REG,
			    ecc_ctrl.value);
			break;
		}
		break;

	case NXGE_FM_EREPORT_ZCP_RRFIFO_UNDERRUN:
	case NXGE_FM_EREPORT_ZCP_RSPFIFO_UNCORR_ERR:
	case NXGE_FM_EREPORT_ZCP_STAT_TBL_PERR:
	case NXGE_FM_EREPORT_ZCP_DYN_TBL_PERR:
	case NXGE_FM_EREPORT_ZCP_BUF_TBL_PERR:
	case NXGE_FM_EREPORT_ZCP_RRFIFO_OVERRUN:
	case NXGE_FM_EREPORT_ZCP_BUFFER_OVERFLOW:
	case NXGE_FM_EREPORT_ZCP_TT_PROGRAM_ERR:
	case NXGE_FM_EREPORT_ZCP_RSP_TT_INDEX_ERR:
	case NXGE_FM_EREPORT_ZCP_SLV_TT_INDEX_ERR:
	case NXGE_FM_EREPORT_ZCP_TT_INDEX_ERR:
		NXGE_REG_RD64(nxgep->npi_handle, ZCP_INT_STAT_TEST_REG,
		    &zcps.value);
		if (err_id == NXGE_FM_EREPORT_ZCP_RRFIFO_UNDERRUN)
			zcps.bits.ldw.rrfifo_urun = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_RSPFIFO_UNCORR_ERR)
			zcps.bits.ldw.rspfifo_uc_err = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_STAT_TBL_PERR)
			zcps.bits.ldw.stat_tbl_perr = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_DYN_TBL_PERR)
			zcps.bits.ldw.dyn_tbl_perr = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_BUF_TBL_PERR)
			zcps.bits.ldw.buf_tbl_perr = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_CFIFO_ECC) {
			switch (portn) {
			case 0:
				zcps.bits.ldw.cfifo_ecc0 = 1;
				break;
			case 1:
				zcps.bits.ldw.cfifo_ecc1 = 1;
				break;
			case 2:
				zcps.bits.ldw.cfifo_ecc2 = 1;
				break;
			case 3:
				zcps.bits.ldw.cfifo_ecc3 = 1;
				break;
			}
		}
		/* FALLTHROUGH */

	default:
		if (err_id == NXGE_FM_EREPORT_ZCP_RRFIFO_OVERRUN)
			zcps.bits.ldw.rrfifo_orun = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_BUFFER_OVERFLOW)
			zcps.bits.ldw.buf_overflow = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_TT_PROGRAM_ERR)
			zcps.bits.ldw.tt_tbl_perr = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_RSP_TT_INDEX_ERR)
			zcps.bits.ldw.rsp_tt_index_err = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_SLV_TT_INDEX_ERR)
			zcps.bits.ldw.slv_tt_index_err = 1;
		if (err_id == NXGE_FM_EREPORT_ZCP_TT_INDEX_ERR)
			zcps.bits.ldw.zcp_tt_index_err = 1;
#if defined(__i386)
		cmn_err(CE_NOTE, "!Write 0x%llx to ZCP_INT_STAT_TEST_REG\n",
		    zcps.value);
#else
		cmn_err(CE_NOTE, "!Write 0x%lx to ZCP_INT_STAT_TEST_REG\n",
		    zcps.value);
#endif
		NXGE_REG_WR64(nxgep->npi_handle, ZCP_INT_STAT_TEST_REG,
		    zcps.value);
		break;
	}
}

nxge_status_t
nxge_zcp_fatal_err_recover(p_nxge_t nxgep)
{
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	nxge_status_t status = NXGE_OK;
	uint8_t portn;
	zcp_ram_unit_t w_data;
	zcp_ram_unit_t r_data;
	uint32_t cfifo_depth;
	int i;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "<== nxge_zcp_fatal_err_recover"));
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "Recovering from RxPort error..."));

	handle = nxgep->npi_handle;
	portn = nxgep->mac.portnum;

	/* Disable RxMAC */
	if (nxge_rx_mac_disable(nxgep) != NXGE_OK)
		goto fail;

	/* Make sure source is clear if this is an injected error */
	switch (portn) {
	case 0:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT0_REG, 0);
		break;
	case 1:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT1_REG, 0);
		break;
	case 2:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT2_REG, 0);
		break;
	case 3:
		NXGE_REG_WR64(handle, ZCP_CFIFO_ECC_PORT3_REG, 0);
		break;
	}

	/* Clear up CFIFO */
	if (nxgep->niu_type == N2_NIU) {
		cfifo_depth = ZCP_NIU_CFIFO_DEPTH;
	} else if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		if (portn < 2)
			cfifo_depth = ZCP_P0_P1_CFIFO_DEPTH;
		else
			cfifo_depth = ZCP_P2_P3_CFIFO_DEPTH;
	} else {
		goto fail;
	}

	w_data.w0 = 0;
	w_data.w1 = 0;
	w_data.w2 = 0;
	w_data.w3 = 0;
	w_data.w4 = 0;

	for (i = 0; i < cfifo_depth; i++) {
		if (npi_zcp_tt_cfifo_entry(handle, OP_SET,
		    portn, i, &w_data) != NPI_SUCCESS)
			goto fail;
		if (npi_zcp_tt_cfifo_entry(handle, OP_GET,
		    portn, i, &r_data) != NPI_SUCCESS)
			goto fail;
	}

	/* When recovering from ZCP, RxDMA channel resets are not necessary */
	/* Reset ZCP CFIFO */
	NXGE_DEBUG_MSG((nxgep, RX_CTL, "port%d Reset ZCP CFIFO...", portn));
	if ((rs = npi_zcp_rest_cfifo_port(handle, portn)) != NPI_SUCCESS)
		goto fail;

	/* Reset IPP */
	NXGE_DEBUG_MSG((nxgep, RX_CTL, "port%d Reset IPP...", portn));
	if ((rs = npi_ipp_reset(handle, portn)) != NPI_SUCCESS)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "port%d Reset RxMAC...", portn));
	if (nxge_rx_mac_reset(nxgep) != NXGE_OK)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "port%d Initialize RxMAC...", portn));
	if ((status = nxge_rx_mac_init(nxgep)) != NXGE_OK)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, RX_CTL, "port%d Enable RxMAC...", portn));
	if (nxge_rx_mac_enable(nxgep) != NXGE_OK)
		goto fail;

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "Recovery Sucessful, RxPort Restored"));
	NXGE_DEBUG_MSG((nxgep, RX_CTL, "==> nxge_zcp_fatal_err_recover"));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "Recovery failed"));
	return (status | rs);
}
