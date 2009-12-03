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

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_hio.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

static nxge_fm_ereport_attr_t
*nxge_fm_get_ereport_attr(nxge_fm_ereport_id_t);

static int
nxge_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data);

nxge_fm_ereport_attr_t	nxge_fm_ereport_pcs[] = {
	{NXGE_FM_EREPORT_XPCS_LINK_DOWN,	"10g_link_down",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_XPCS_TX_LINK_FAULT,	"10g_tx_link_fault",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_XPCS_RX_LINK_FAULT,	"10g_rx_link_fault",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_PCS_LINK_DOWN,		"1g_link_down",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_PCS_REMOTE_FAULT,	"1g_remote_fault",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
};

nxge_fm_ereport_attr_t	nxge_fm_ereport_mif[] = {
	{NXGE_FM_EREPORT_MIF_ACCESS_FAIL,	"transceiver_access_fail"}
};

nxge_fm_ereport_attr_t nxge_fm_ereport_fflp[] = {
	{NXGE_FM_EREPORT_FFLP_TCAM_ERR,		"classifier_tcam_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_FFLP_VLAN_PAR_ERR,	"classifier_vlan_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_FFLP_HASHT_DATA_ERR,	"classifier_hasht_data_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_FFLP_HASHT_LOOKUP_ERR,	"classifier_hasht_lookup_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_FFLP_ACCESS_FAIL,	"classifier_access_fail",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_DEGRADED}
};

nxge_fm_ereport_attr_t nxge_fm_ereport_ipp[] = {
	{NXGE_FM_EREPORT_IPP_EOP_MISS,		"rx_eop_miss",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_IPP_SOP_MISS,		"rx_sop_miss",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_IPP_DFIFO_UE,		"rx_dfifo_ucorr_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_IPP_DFIFO_CE,		"rx_dfifo_corr_err",
						DDI_FM_DEVICE_INTERN_CORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_IPP_PFIFO_PERR,	"rx_dfifo_parity_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_IPP_ECC_ERR_MAX,	"rx_ecc_err_max",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_IPP_PFIFO_OVER,	"rx_pfifo_overflow",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_IPP_PFIFO_UND,		"rx_pfifo_underrun",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_IPP_BAD_CS_MX,		"rx_bad_cksum_max",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_IPP_PKT_DIS_MX,	"rx_pkt_discard_max",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_IPP_RESET_FAIL,	"rx_reset_fail",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_LOST}
};

nxge_fm_ereport_attr_t nxge_fm_ereport_rdmc[] = {
	{NXGE_FM_EREPORT_RDMC_DCF_ERR,		"rxdma_dcf_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_RDMC_RCR_ACK_ERR,	"rxdma_rcr_ack_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_DC_FIFO_ERR,	"rxdma_dc_fifo_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_RDMC_RCR_SHA_PAR,	"rxdma_rcr_sha_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_RBR_PRE_PAR,	"rxdma_rbr_pre_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_RBR_TMOUT,	"rxdma_rbr_tmout",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_RSP_CNT_ERR,	"rxdma_rsp_cnt_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_BYTE_EN_BUS,	"rxdma_byte_en_bus",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_RSP_DAT_ERR,	"rxdma_rsp_dat_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_ID_MISMATCH,	"rxdma_id_mismatch",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_RDMC_ZCP_EOP_ERR,	"rxdma_zcp_eop_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_RDMC_IPP_EOP_ERR,	"rxdma_ipp_eop_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_RDMC_RCR_ERR,		"rxdma_completion_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_RDMC_CONFIG_ERR,	"rxdma_config_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_RCRINCON,		"rxdma_rcrincon",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_RCRFULL,		"rxdma_rcrfull",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_RBRFULL,		"rxdma_rbrfull",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_RBRLOGPAGE,	"rxdma_rbrlogpage",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_RDMC_CFIGLOGPAGE,	"rxdma_cfiglogpage",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED}
};

nxge_fm_ereport_attr_t nxge_fm_ereport_zcp[] = {
	{NXGE_FM_EREPORT_ZCP_RRFIFO_UNDERRUN,	"rxzcopy_rrfifo_underrun",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_RSPFIFO_UNCORR_ERR,
						"rxzcopy_rspfifo_uncorr_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_STAT_TBL_PERR,	"rxzcopy_stat_tbl_perr",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_DYN_TBL_PERR,	"rxzcopy_dyn_tbl_perr",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_BUF_TBL_PERR,	"rxzcopy_buf_tbl_perr",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_CFIFO_ECC,		"rxzcopy_cfifo_ecc",
						DDI_FM_DEVICE_INTERN_CORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_RRFIFO_OVERRUN,	"rxzcopy_rrfifo_overrun",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_BUFFER_OVERFLOW,	"rxzcopy_buffer_overflow",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_ZCP_TT_PROGRAM_ERR,	"rxzcopy_tt_program_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_RSP_TT_INDEX_ERR,	"rxzcopy_rsp_tt_index_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_SLV_TT_INDEX_ERR,	"rxzcopy_slv_tt_index_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_TT_INDEX_ERR,	"rxzcopy_tt_index_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_ZCP_ACCESS_FAIL,	"rxzcopy_access_fail",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_LOST},
};

nxge_fm_ereport_attr_t nxge_fm_ereport_rxmac[] = {
	{NXGE_FM_EREPORT_RXMAC_UNDERFLOW,	"rxmac_underflow",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_RXMAC_CRC_ERRCNT_EXP,	"rxmac_crc_errcnt_exp",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_RXMAC_LENGTH_ERRCNT_EXP,
						"rxmac_length_errcnt_exp",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_RXMAC_VIOL_ERRCNT_EXP,	"rxmac_viol_errcnt_exp",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_RXMAC_RXFRAG_CNT_EXP,	"rxmac_rxfrag_cnt_exp",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_RXMAC_ALIGN_ECNT_EXP,	"rxmac_align_ecnt_exp",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_RXMAC_LINKFAULT_CNT_EXP,
						"rxmac_linkfault_cnt_exp",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_RXMAC_RESET_FAIL,	"rxmac_reset_fail",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_UNAFFECTED},
};

nxge_fm_ereport_attr_t nxge_fm_ereport_tdmc[] = {
	{NXGE_FM_EREPORT_TDMC_PREF_BUF_PAR_ERR,	"txdma_pref_buf_par_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_TDMC_MBOX_ERR,		"txdma_mbox_err",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_TDMC_NACK_PREF,	"txdma_nack_pref",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_TDMC_NACK_PKT_RD,	"txdma_nack_pkt_rd",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR,	"txdma_pkt_size_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_TDMC_TX_RING_OFLOW,	"txdma_tx_ring_oflow",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_TDMC_CONF_PART_ERR,	"txdma_conf_part_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_TDMC_PKT_PRT_ERR,	"txdma_pkt_prt_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_DEGRADED},
	{NXGE_FM_EREPORT_TDMC_RESET_FAIL,	"txdma_reset_fail",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_LOST},
};

nxge_fm_ereport_attr_t nxge_fm_ereport_txc[] = {
	{NXGE_FM_EREPORT_TXC_RO_CORRECT_ERR,	"tx_ro_correct_err",
						DDI_FM_DEVICE_INTERN_CORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXC_RO_UNCORRECT_ERR,	"tx_ro_uncorrect_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXC_SF_CORRECT_ERR,	"tx_sf_correct_err",
						DDI_FM_DEVICE_INTERN_CORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXC_SF_UNCORRECT_ERR,	"tx_sf_uncorrect_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXC_ASSY_DEAD,		"tx_assembly_uncorrect_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXC_REORDER_ERR,	"tx_reorder_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
};

nxge_fm_ereport_attr_t nxge_fm_ereport_txmac[] = {
	{NXGE_FM_EREPORT_TXMAC_UNDERFLOW,	"txmac_underflow",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXMAC_OVERFLOW,	"txmac_overflow",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXMAC_TXFIFO_XFR_ERR,	"txmac_txfifo_xfr_err",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXMAC_MAX_PKT_ERR,	"txmac_max_pkt_err",
						DDI_FM_DEVICE_INTERN_UNCORR,
						DDI_SERVICE_UNAFFECTED},
	{NXGE_FM_EREPORT_TXMAC_RESET_FAIL,	"txmac_reset_fail",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_UNAFFECTED},
};

nxge_fm_ereport_attr_t nxge_fm_ereport_espc[] = {
	{NXGE_FM_EREPORT_ESPC_ACCESS_FAIL,	"eprom_access_fail",
						DDI_FM_DEVICE_NO_RESPONSE,
						DDI_SERVICE_LOST},
};

nxge_fm_ereport_attr_t nxge_fm_ereport_xaui[] = {
	{NXGE_FM_EREPORT_XAUI_ERR,		"xaui_bad_or_missing",
						NXGE_FM_DEVICE_XAUI_ERR,
						DDI_SERVICE_LOST},
};

nxge_fm_ereport_attr_t nxge_fm_ereport_xfp[] = {
	{NXGE_FM_EREPORT_XFP_ERR,		"xfp_bad_or_missing",
						NXGE_FM_DEVICE_XFP_ERR,
						DDI_SERVICE_LOST},
};

nxge_fm_ereport_attr_t nxge_fm_ereport_sw[] = {
	{NXGE_FM_EREPORT_SW_INVALID_PORT_NUM,	"invalid_port_num",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_SW_INVALID_CHAN_NUM,	"invalid_chan_num",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
	{NXGE_FM_EREPORT_SW_INVALID_PARAM,	"invalid_param",
						DDI_FM_DEVICE_INVAL_STATE,
						DDI_SERVICE_LOST},
};

void
nxge_fm_init(p_nxge_t nxgep, ddi_device_acc_attr_t *reg_attr,
	ddi_dma_attr_t *dma_attr)
{
	ddi_iblock_cookie_t iblk;

	/*
	 * fm-capable in nxge.conf can be used to set fm_capabilities.
	 * If fm-capable is not defined, then the last argument passed to
	 * ddi_prop_get_int will be returned as the capabilities.
	 */
	nxgep->fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY, nxgep->dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	NXGE_ERROR_MSG((nxgep, DDI_CTL,
	    "FM capable = %d\n", nxgep->fm_capabilities));

	if (isLDOMguest(nxgep)) {
		nxgep->fm_capabilities = DDI_FM_NOT_CAPABLE;
		return;
	}

	/*
	 * Register capabilities with IO Fault Services. The capabilities
	 * set above may not be supported by the parent nexus, in that case
	 * some capability bits may be cleared.
	 */
	if (nxgep->fm_capabilities)
		ddi_fm_init(nxgep->dip, &nxgep->fm_capabilities, &iblk);

	/*
	 * Initialize pci ereport capabilities if ereport capable
	 */
	if (DDI_FM_EREPORT_CAP(nxgep->fm_capabilities) ||
	    DDI_FM_ERRCB_CAP(nxgep->fm_capabilities)) {
		pci_ereport_setup(nxgep->dip);
	}

	/* Register error callback if error callback capable */
	if (DDI_FM_ERRCB_CAP(nxgep->fm_capabilities)) {
		ddi_fm_handler_register(nxgep->dip,
		    nxge_fm_error_cb, (void*) nxgep);
	}

	/*
	 * DDI_FLGERR_ACC indicates:
	 * o Driver will check its access handle(s) for faults on
	 *   a regular basis by calling ddi_fm_acc_err_get
	 * o Driver is able to cope with incorrect results of I/O
	 *   operations resulted from an I/O fault
	 */
	if (DDI_FM_ACC_ERR_CAP(nxgep->fm_capabilities)) {
		reg_attr->devacc_attr_access  = DDI_FLAGERR_ACC;
	} else {
		reg_attr->devacc_attr_access  = DDI_DEFAULT_ACC;
	}

	/*
	 * DDI_DMA_FLAGERR indicates:
	 * o Driver will check its DMA handle(s) for faults on a
	 *   regular basis using ddi_fm_dma_err_get
	 * o Driver is able to cope with incorrect results of DMA
	 *   operations resulted from an I/O fault
	 */
	if (DDI_FM_DMA_ERR_CAP(nxgep->fm_capabilities))
		dma_attr->dma_attr_flags |= DDI_DMA_FLAGERR;
	else
		dma_attr->dma_attr_flags &= ~DDI_DMA_FLAGERR;

}

void
nxge_fm_fini(p_nxge_t nxgep)
{
	/* Only unregister FMA capabilities if we registered some */
	if (nxgep->fm_capabilities) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(nxgep->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(nxgep->fm_capabilities))
			pci_ereport_teardown(nxgep->dip);

		/*
		 * Un-register error callback if error callback capable
		 */
		if (DDI_FM_ERRCB_CAP(nxgep->fm_capabilities))
			ddi_fm_handler_unregister(nxgep->dip);

		/* Unregister from IO Fault Services */
		ddi_fm_fini(nxgep->dip);
	}
}

/*ARGSUSED*/
/*
 * Simply call pci_ereport_post which generates ereports for errors
 * that occur in the PCI local bus configuration status registers.
 */
static int
nxge_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err,
	const void *impl_data)
{
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}


static nxge_fm_ereport_attr_t *
nxge_fm_get_ereport_attr(nxge_fm_ereport_id_t ereport_id)
{
	nxge_fm_ereport_attr_t *attr;
	uint8_t	blk_id = (ereport_id >> EREPORT_FM_ID_SHIFT) &
	    EREPORT_FM_ID_MASK;
	uint8_t index = ereport_id & EREPORT_INDEX_MASK;

	switch (blk_id) {
	case FM_SW_ID:
		attr = &nxge_fm_ereport_sw[index];
		break;
	case FM_PCS_ID:
		attr = &nxge_fm_ereport_pcs[index];
		break;
	case FM_TXMAC_ID:
		attr = &nxge_fm_ereport_txmac[index];
		break;
	case FM_RXMAC_ID:
		attr = &nxge_fm_ereport_rxmac[index];
		break;
	case FM_MIF_ID:
		attr = &nxge_fm_ereport_mif[index];
		break;
	case FM_FFLP_ID:
		attr = &nxge_fm_ereport_fflp[index];
		break;
	case FM_ZCP_ID:
		attr = &nxge_fm_ereport_zcp[index];
		break;
	case FM_RXDMA_ID:
		attr = &nxge_fm_ereport_rdmc[index];
		break;
	case FM_TXDMA_ID:
		attr = &nxge_fm_ereport_tdmc[index];
		break;
	case FM_IPP_ID:
		attr = &nxge_fm_ereport_ipp[index];
		break;
	case FM_TXC_ID:
		attr = &nxge_fm_ereport_txc[index];
		break;
	case FM_ESPC_ID:
		attr = &nxge_fm_ereport_espc[index];
		break;
	case FM_XAUI_ID:
		attr = &nxge_fm_ereport_xaui[index];
		break;
	case FM_XFP_ID:
		attr = &nxge_fm_ereport_xfp[index];
		break;
	default:
		attr = NULL;
	}

	return (attr);
}

static void
nxge_fm_ereport(p_nxge_t nxgep, uint8_t err_portn, uint8_t err_chan,
					nxge_fm_ereport_attr_t *ereport)
{
	uint64_t		ena;
	char			eclass[FM_MAX_CLASS];
	char			*err_str;
	p_nxge_stats_t		statsp;

	(void) snprintf(eclass, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE,
	    ereport->eclass);
	err_str = ereport->str;
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	statsp = nxgep->statsp;

	switch (ereport->index) {
		case NXGE_FM_EREPORT_XPCS_LINK_DOWN:
		case NXGE_FM_EREPORT_XPCS_TX_LINK_FAULT:
		case NXGE_FM_EREPORT_XPCS_RX_LINK_FAULT:
		case NXGE_FM_EREPORT_PCS_LINK_DOWN:
		case NXGE_FM_EREPORT_PCS_REMOTE_FAULT:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    NULL);
			break;
		case NXGE_FM_EREPORT_IPP_EOP_MISS:
		case NXGE_FM_EREPORT_IPP_SOP_MISS:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_DFIFO_RD_PTR, DATA_TYPE_UINT16,
			    statsp->ipp_stats.errlog.dfifo_rd_ptr,
			    ERNAME_IPP_STATE_MACH, DATA_TYPE_UINT32,
			    statsp->ipp_stats.errlog.state_mach,
			    NULL);
			break;
		case NXGE_FM_EREPORT_IPP_DFIFO_UE:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_DFIFO_ENTRY, DATA_TYPE_UINT16,
			    nxgep->ipp.status.bits.w0.dfifo_ecc_err_idx,
			    ERNAME_DFIFO_SYNDROME, DATA_TYPE_UINT16,
			    statsp->ipp_stats.errlog.ecc_syndrome,
			    NULL);
			break;
		case NXGE_FM_EREPORT_IPP_PFIFO_PERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_PFIFO_ENTRY, DATA_TYPE_UINT8,
			    nxgep->ipp.status.bits.w0.pre_fifo_perr_idx,
			    NULL);
			break;
		case NXGE_FM_EREPORT_IPP_DFIFO_CE:
		case NXGE_FM_EREPORT_IPP_ECC_ERR_MAX:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    NULL);
			break;
		case NXGE_FM_EREPORT_IPP_PFIFO_OVER:
		case NXGE_FM_EREPORT_IPP_PFIFO_UND:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_IPP_STATE_MACH, DATA_TYPE_UINT32,
			    statsp->ipp_stats.errlog.state_mach,
			    NULL);
			break;
		case NXGE_FM_EREPORT_IPP_BAD_CS_MX:
		case NXGE_FM_EREPORT_IPP_PKT_DIS_MX:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    NULL);
			break;
		case NXGE_FM_EREPORT_FFLP_TCAM_ERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_TCAM_ERR_LOG, DATA_TYPE_UINT32,
			    statsp->fflp_stats.errlog.tcam,
			    NULL);
			break;
		case NXGE_FM_EREPORT_FFLP_VLAN_PAR_ERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_VLANTAB_ERR_LOG, DATA_TYPE_UINT32,
			    statsp->fflp_stats.errlog.vlan,
			    NULL);
			break;
		case NXGE_FM_EREPORT_FFLP_HASHT_DATA_ERR:
		{
			int rdc_grp;
			hash_tbl_data_log_t hash_log;

			for (rdc_grp = 0; rdc_grp < MAX_PARTITION; rdc_grp++) {
				hash_log.value = nxgep->classifier.fflp_stats->
				    errlog.hash_pio[rdc_grp];
				if (hash_log.bits.ldw.pio_err) {
					ddi_fm_ereport_post(nxgep->dip, eclass,
					    ena, DDI_NOSLEEP,
					    FM_VERSION, DATA_TYPE_UINT8,
					    FM_EREPORT_VERS0,
					    ERNAME_DETAILED_ERR_TYPE,
					    DATA_TYPE_STRING, err_str,
					    ERNAME_HASHTAB_ERR_LOG,
					    DATA_TYPE_UINT32,
					    nxgep->classifier.fflp_stats->
					    errlog.hash_pio[rdc_grp], NULL);
				}
			}
		}
			break;
		case NXGE_FM_EREPORT_FFLP_HASHT_LOOKUP_ERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_HASHT_LOOKUP_ERR_LOG0, DATA_TYPE_UINT32,
			    statsp->fflp_stats.errlog. hash_lookup1,
			    ERNAME_HASHT_LOOKUP_ERR_LOG1, DATA_TYPE_UINT32,
			    statsp->fflp_stats.errlog.hash_lookup2,
			    NULL);
			break;
		case NXGE_FM_EREPORT_RDMC_DCF_ERR:
		case NXGE_FM_EREPORT_RDMC_RBR_TMOUT:
		case NXGE_FM_EREPORT_RDMC_RSP_CNT_ERR:
		case NXGE_FM_EREPORT_RDMC_BYTE_EN_BUS:
		case NXGE_FM_EREPORT_RDMC_RSP_DAT_ERR:
		case NXGE_FM_EREPORT_RDMC_RCR_ACK_ERR:
		case NXGE_FM_EREPORT_RDMC_DC_FIFO_ERR:
		case NXGE_FM_EREPORT_RDMC_CONFIG_ERR:
		case NXGE_FM_EREPORT_RDMC_RCRINCON:
		case NXGE_FM_EREPORT_RDMC_RCRFULL:
		case NXGE_FM_EREPORT_RDMC_RBRFULL:
		case NXGE_FM_EREPORT_RDMC_RBRLOGPAGE:
		case NXGE_FM_EREPORT_RDMC_CFIGLOGPAGE:
		case NXGE_FM_EREPORT_RDMC_ID_MISMATCH:
		case NXGE_FM_EREPORT_RDMC_ZCP_EOP_ERR:
		case NXGE_FM_EREPORT_RDMC_IPP_EOP_ERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
			    NULL);
			break;
		case NXGE_FM_EREPORT_RDMC_RBR_PRE_PAR:
		case NXGE_FM_EREPORT_RDMC_RCR_SHA_PAR:
			{
			uint32_t err_log;
			if (ereport->index == NXGE_FM_EREPORT_RDMC_RBR_PRE_PAR)
				err_log = (uint32_t)statsp->
				    rdc_stats[err_chan].errlog.pre_par.value;
			else
				err_log = (uint32_t)statsp->
				    rdc_stats[err_chan].errlog.sha_par.value;
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
			    ERNAME_RDMC_PAR_ERR_LOG, DATA_TYPE_UINT8, err_log,
			    NULL);
			}
			break;
		case NXGE_FM_EREPORT_RDMC_RCR_ERR:
			{
			uint8_t err_type;
			err_type = statsp->
			    rdc_stats[err_chan].errlog.compl_err_type;
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
			    ERNAME_RDC_ERR_TYPE, DATA_TYPE_UINT8, err_type,
			    NULL);
			}
			break;

		case NXGE_FM_EREPORT_ZCP_RRFIFO_UNDERRUN:
		case NXGE_FM_EREPORT_ZCP_RRFIFO_OVERRUN:
		case NXGE_FM_EREPORT_ZCP_BUFFER_OVERFLOW:
			{
			uint32_t sm;
			sm = statsp->
			    zcp_stats.errlog.state_mach.bits.ldw.state;
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    sm, DATA_TYPE_UINT32,
			    NULL);
			break;
			}
		case NXGE_FM_EREPORT_ZCP_CFIFO_ECC:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    NULL);
			break;
		case NXGE_FM_EREPORT_ZCP_RSPFIFO_UNCORR_ERR:
		case NXGE_FM_EREPORT_ZCP_STAT_TBL_PERR:
		case NXGE_FM_EREPORT_ZCP_DYN_TBL_PERR:
		case NXGE_FM_EREPORT_ZCP_BUF_TBL_PERR:
		case NXGE_FM_EREPORT_ZCP_TT_PROGRAM_ERR:
		case NXGE_FM_EREPORT_ZCP_RSP_TT_INDEX_ERR:
		case NXGE_FM_EREPORT_ZCP_SLV_TT_INDEX_ERR:
		case NXGE_FM_EREPORT_ZCP_TT_INDEX_ERR:
		case NXGE_FM_EREPORT_RXMAC_UNDERFLOW:
		case NXGE_FM_EREPORT_RXMAC_CRC_ERRCNT_EXP:
		case NXGE_FM_EREPORT_RXMAC_LENGTH_ERRCNT_EXP:
		case NXGE_FM_EREPORT_RXMAC_VIOL_ERRCNT_EXP:
		case NXGE_FM_EREPORT_RXMAC_RXFRAG_CNT_EXP:
		case NXGE_FM_EREPORT_RXMAC_LINKFAULT_CNT_EXP:
		case NXGE_FM_EREPORT_RXMAC_ALIGN_ECNT_EXP:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    NULL);
			break;
		case NXGE_FM_EREPORT_TDMC_MBOX_ERR:
		case NXGE_FM_EREPORT_TDMC_TX_RING_OFLOW:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
			    NULL);
			break;
		case NXGE_FM_EREPORT_TDMC_PREF_BUF_PAR_ERR:
		case NXGE_FM_EREPORT_TDMC_NACK_PREF:
		case NXGE_FM_EREPORT_TDMC_NACK_PKT_RD:
		case NXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR:
		case NXGE_FM_EREPORT_TDMC_CONF_PART_ERR:
		case NXGE_FM_EREPORT_TDMC_PKT_PRT_ERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_ERR_DCHAN, DATA_TYPE_UINT8, err_chan,
			    ERNAME_TDMC_ERR_LOG1, DATA_TYPE_UINT32,
			    statsp->tdc_stats[err_chan].errlog.logl.value,
			    ERNAME_TDMC_ERR_LOG1, DATA_TYPE_UINT32,
			    statsp->tdc_stats[err_chan].errlog.logh.value,
			    DATA_TYPE_UINT32,
			    NULL);
			break;
		case NXGE_FM_EREPORT_TXC_RO_CORRECT_ERR:
		case NXGE_FM_EREPORT_TXC_RO_UNCORRECT_ERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_TXC_ROECC_ADDR, DATA_TYPE_UINT16,
			    statsp->txc_stats.errlog.ro_st.roecc.
			    bits.ldw.ecc_address,
			    ERNAME_TXC_ROECC_DATA0, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.ro_st.d0.
			    bits.ldw.ro_ecc_data0,
			    ERNAME_TXC_ROECC_DATA1, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.ro_st.d1.
			    bits.ldw.ro_ecc_data1,
			    ERNAME_TXC_ROECC_DATA2, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.ro_st.d2.
			    bits.ldw.ro_ecc_data2,
			    ERNAME_TXC_ROECC_DATA3, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.ro_st.d3.
			    bits.ldw.ro_ecc_data3,
			    ERNAME_TXC_ROECC_DATA4, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.ro_st.d4.
			    bits.ldw.ro_ecc_data4,
			    NULL);
			break;
		case NXGE_FM_EREPORT_TXC_REORDER_ERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_TXC_RO_STATE0, DATA_TYPE_UINT32,
			    (uint32_t)statsp->txc_stats.errlog.ro_st.st0.value,
			    ERNAME_TXC_RO_STATE1, DATA_TYPE_UINT32,
			    (uint32_t)statsp->txc_stats.errlog.ro_st.st1.value,
			    ERNAME_TXC_RO_STATE2, DATA_TYPE_UINT32,
			    (uint32_t)statsp->txc_stats.errlog.ro_st.st2.value,
			    ERNAME_TXC_RO_STATE3, DATA_TYPE_UINT32,
			    (uint32_t)statsp->txc_stats.errlog.ro_st.st3.value,
			    ERNAME_TXC_RO_STATE_CTL, DATA_TYPE_UINT32,
			    (uint32_t)statsp->txc_stats.errlog.ro_st.ctl.value,
			    ERNAME_TXC_RO_TIDS, DATA_TYPE_UINT32,
			    (uint32_t)statsp->txc_stats.errlog.ro_st.tids.value,
			    NULL);
			break;
		case NXGE_FM_EREPORT_TXC_SF_CORRECT_ERR:
		case NXGE_FM_EREPORT_TXC_SF_UNCORRECT_ERR:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    ERNAME_TXC_SFECC_ADDR, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.sf_st.sfecc.
			    bits.ldw.ecc_address,
			    ERNAME_TXC_SFECC_DATA0, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.sf_st.d0.
			    bits.ldw.sf_ecc_data0,
			    ERNAME_TXC_SFECC_DATA0, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.sf_st.d1.
			    bits.ldw.sf_ecc_data1,
			    ERNAME_TXC_SFECC_DATA0, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.sf_st.d2.
			    bits.ldw.sf_ecc_data2,
			    ERNAME_TXC_SFECC_DATA0, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.sf_st.d3.
			    bits.ldw.sf_ecc_data3,
			    ERNAME_TXC_SFECC_DATA0, DATA_TYPE_UINT32,
			    statsp->txc_stats.errlog.sf_st.d4.
			    bits.ldw.sf_ecc_data4,
			    NULL);
			break;
		case NXGE_FM_EREPORT_TXMAC_UNDERFLOW:
		case NXGE_FM_EREPORT_TXMAC_OVERFLOW:
		case NXGE_FM_EREPORT_TXMAC_TXFIFO_XFR_ERR:
		case NXGE_FM_EREPORT_TXMAC_MAX_PKT_ERR:
		case NXGE_FM_EREPORT_XAUI_ERR:
		case NXGE_FM_EREPORT_XFP_ERR:
		case NXGE_FM_EREPORT_SW_INVALID_PORT_NUM:
		case NXGE_FM_EREPORT_SW_INVALID_CHAN_NUM:
		case NXGE_FM_EREPORT_SW_INVALID_PARAM:
			ddi_fm_ereport_post(nxgep->dip, eclass, ena,
			    DDI_NOSLEEP,
			    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERS0,
			    ERNAME_DETAILED_ERR_TYPE, DATA_TYPE_STRING, err_str,
			    ERNAME_ERR_PORTN, DATA_TYPE_UINT8, err_portn,
			    NULL);
			break;
	}
}

void
nxge_fm_report_error(p_nxge_t nxgep, uint8_t err_portn, uint8_t err_chan,
					nxge_fm_ereport_id_t fm_ereport_id)
{
	nxge_fm_ereport_attr_t		*fm_ereport_attr;

	fm_ereport_attr = nxge_fm_get_ereport_attr(fm_ereport_id);
	if (fm_ereport_attr != NULL &&
	    (DDI_FM_EREPORT_CAP(nxgep->fm_capabilities))) {
		nxge_fm_ereport(nxgep, err_portn, err_chan, fm_ereport_attr);
		ddi_fm_service_impact(nxgep->dip, fm_ereport_attr->impact);
	}
}

int
fm_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t err;

	ddi_fm_acc_err_get(handle, &err, DDI_FME_VERSION);
#ifndef	NXGE_FM_S10
	ddi_fm_acc_err_clear(handle, DDI_FME_VERSION);
#endif
	return (err.fme_status);
}

int
fm_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t err;

	ddi_fm_dma_err_get(handle, &err, DDI_FME_VERSION);
	return (err.fme_status);
}
