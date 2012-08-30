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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <hxge_impl.h>
#include <inet/mi.h>
#include <sys/cmn_err.h>

#define	RDC_NAME_FORMAT1 "RDC_"
#define	TDC_NAME_FORMAT1 "TDC_"
#define	CH_NAME_FORMAT "%d"

static int hxge_mmac_stat_update(kstat_t *ksp, int rw);

void
hxge_init_statsp(p_hxge_t hxgep)
{
	size_t stats_size;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_init_statsp"));

	stats_size = sizeof (hxge_stats_t);
	hxgep->statsp = KMEM_ZALLOC(stats_size, KM_SLEEP);
	hxgep->statsp->stats_size = stats_size;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, " <== hxge_init_statsp"));
}

typedef struct {
	uint8_t index;
	uint8_t type;
	char *name;
} hxge_kstat_index_t;

typedef enum {
	RDC_STAT_PACKETS = 0,
	RDC_STAT_BYTES,
	RDC_STAT_ERRORS,
	RDC_STAT_JUMBO_PKTS,
	RDC_STAT_RCR_UNKNOWN_ERR,
	RDC_STAT_RCR_SHA_PAR_ERR,
	RDC_STAT_RBR_PRE_PAR_ERR,
	RDC_STAT_RBR_PRE_EMTY,
	RDC_STAT_RCR_SHADOW_FULL,
	RDC_STAT_RBR_TMOUT,
	RDC_STAT_PEU_RESP_ERR,
	RDC_STAT_CTRL_FIFO_ECC_ERR,
	RDC_STAT_DATA_FIFO_ECC_ERR,
	RDC_STAT_RCRFULL,
	RDC_STAT_RBR_EMPTY,
	RDC_STAT_RBR_EMPTY_FAIL,
	RDC_STAT_RBR_EMPTY_RESTORE,
	RDC_STAT_RBR_FULL,
	RDC_STAT_RCR_INVALIDS,
	RDC_STAT_RCRTO,
	RDC_STAT_RCRTHRES,
	RDC_STAT_PKT_DROP,
	RDC_STAT_END
} hxge_rdc_stat_index_t;

hxge_kstat_index_t hxge_rdc_stats[] = {
	{RDC_STAT_PACKETS, KSTAT_DATA_UINT64, "rdc_packets"},
	{RDC_STAT_BYTES, KSTAT_DATA_UINT64, "rdc_bytes"},
	{RDC_STAT_ERRORS, KSTAT_DATA_ULONG, "rdc_errors"},
	{RDC_STAT_JUMBO_PKTS, KSTAT_DATA_ULONG, "rdc_jumbo_pkts"},
	{RDC_STAT_RCR_UNKNOWN_ERR, KSTAT_DATA_ULONG, "rdc_rcr_unknown_err"},
	{RDC_STAT_RCR_SHA_PAR_ERR, KSTAT_DATA_ULONG, "rdc_rcr_sha_par_err"},
	{RDC_STAT_RBR_PRE_PAR_ERR, KSTAT_DATA_ULONG, "rdc_rbr_pre_par_err"},
	{RDC_STAT_RBR_PRE_EMTY, KSTAT_DATA_ULONG, "rdc_rbr_pre_empty"},
	{RDC_STAT_RCR_SHADOW_FULL, KSTAT_DATA_ULONG, "rdc_rcr_shadow_full"},
	{RDC_STAT_RBR_TMOUT, KSTAT_DATA_ULONG, "rdc_rbr_tmout"},
	{RDC_STAT_PEU_RESP_ERR, KSTAT_DATA_ULONG, "peu_resp_err"},
	{RDC_STAT_CTRL_FIFO_ECC_ERR, KSTAT_DATA_ULONG, "ctrl_fifo_ecc_err"},
	{RDC_STAT_DATA_FIFO_ECC_ERR, KSTAT_DATA_ULONG, "data_fifo_ecc_err"},
	{RDC_STAT_RCRFULL, KSTAT_DATA_ULONG, "rdc_rcrfull"},
	{RDC_STAT_RBR_EMPTY, KSTAT_DATA_ULONG, "rdc_rbr_empty"},
	{RDC_STAT_RBR_EMPTY_FAIL, KSTAT_DATA_ULONG, "rdc_rbr_empty_fail"},
	{RDC_STAT_RBR_EMPTY_FAIL, KSTAT_DATA_ULONG, "rdc_rbr_empty_restore"},
	{RDC_STAT_RBR_FULL, KSTAT_DATA_ULONG, "rdc_rbrfull"},
	{RDC_STAT_RCR_INVALIDS, KSTAT_DATA_ULONG, "rdc_rcr_invalids"},
	{RDC_STAT_RCRTO, KSTAT_DATA_ULONG, "rdc_rcrto"},
	{RDC_STAT_RCRTHRES, KSTAT_DATA_ULONG, "rdc_rcrthres"},
	{RDC_STAT_PKT_DROP, KSTAT_DATA_ULONG, "rdc_pkt_drop"},
	{RDC_STAT_END, NULL, NULL}
};

typedef enum {
	RDC_SYS_STAT_CTRL_FIFO_SEC = 0,
	RDC_SYS_STAT_CTRL_FIFO_DED,
	RDC_SYS_STAT_DATA_FIFO_SEC,
	RDC_SYS_STAT_DATA_FIFO_DED,
	RDC_SYS_STAT_END
} hxge_rdc_sys_stat_idx_t;

hxge_kstat_index_t hxge_rdc_sys_stats[] = {
	{RDC_SYS_STAT_CTRL_FIFO_SEC, KSTAT_DATA_UINT64, "rdc_ctrl_fifo_sec"},
	{RDC_SYS_STAT_CTRL_FIFO_DED, KSTAT_DATA_UINT64, "rdc_ctrl_fifo_ded"},
	{RDC_SYS_STAT_DATA_FIFO_SEC, KSTAT_DATA_UINT64, "rdc_data_fifo_sec"},
	{RDC_SYS_STAT_DATA_FIFO_DED, KSTAT_DATA_UINT64, "tdc_data_fifo_ded"},
	{RDC_SYS_STAT_END, NULL, NULL}
};

typedef enum {
	TDC_STAT_PACKETS = 0,
	TDC_STAT_BYTES,
	TDC_STAT_BYTES_WITH_PAD,
	TDC_STAT_ERRORS,
	TDC_STAT_TX_INITS,
	TDC_STAT_TX_NO_BUF,
	TDC_STAT_PEU_RESP_ERR,
	TDC_STAT_PKT_SIZE_ERR,
	TDC_STAT_TX_RNG_OFLOW,
	TDC_STAT_PKT_SIZE_HDR_ERR,
	TDC_STAT_RUNT_PKT_DROP_ERR,
	TDC_STAT_PREF_PAR_ERR,
	TDC_STAT_TDR_PREF_CPL_TO,
	TDC_STAT_PKT_CPL_TO,
	TDC_STAT_INVALID_SOP,
	TDC_STAT_UNEXPECTED_SOP,
	TDC_STAT_COUNT_HDR_SIZE_ERR,
	TDC_STAT_COUNT_RUNT,
	TDC_STAT_COUNT_ABORT,
	TDC_STAT_TX_STARTS,
	TDC_STAT_TX_NO_DESC,
	TDC_STAT_TX_DMA_BIND_FAIL,
	TDC_STAT_TX_HDR_PKTS,
	TDC_STAT_TX_DDI_PKTS,
	TDC_STAT_TX_JUMBO_PKTS,
	TDC_STAT_TX_MAX_PEND,
	TDC_STAT_TX_MARKS,
	TDC_STAT_END
} hxge_tdc_stats_index_t;

hxge_kstat_index_t hxge_tdc_stats[] = {
	{TDC_STAT_PACKETS, KSTAT_DATA_UINT64, "tdc_packets"},
	{TDC_STAT_BYTES, KSTAT_DATA_UINT64, "tdc_bytes"},
	{TDC_STAT_BYTES_WITH_PAD, KSTAT_DATA_UINT64, "tdc_bytes_with_pad"},
	{TDC_STAT_ERRORS, KSTAT_DATA_UINT64, "tdc_errors"},
	{TDC_STAT_TX_INITS, KSTAT_DATA_ULONG, "tdc_tx_inits"},
	{TDC_STAT_TX_NO_BUF, KSTAT_DATA_ULONG, "tdc_tx_no_buf"},

	{TDC_STAT_PEU_RESP_ERR, KSTAT_DATA_ULONG, "tdc_peu_resp_err"},
	{TDC_STAT_PKT_SIZE_ERR, KSTAT_DATA_ULONG, "tdc_pkt_size_err"},
	{TDC_STAT_TX_RNG_OFLOW, KSTAT_DATA_ULONG, "tdc_tx_rng_oflow"},
	{TDC_STAT_PKT_SIZE_HDR_ERR, KSTAT_DATA_ULONG, "tdc_pkt_size_hdr_err"},
	{TDC_STAT_RUNT_PKT_DROP_ERR, KSTAT_DATA_ULONG, "tdc_runt_pkt_drop_err"},
	{TDC_STAT_PREF_PAR_ERR, KSTAT_DATA_ULONG, "tdc_pref_par_err"},
	{TDC_STAT_TDR_PREF_CPL_TO, KSTAT_DATA_ULONG, "tdc_tdr_pref_cpl_to"},
	{TDC_STAT_PKT_CPL_TO, KSTAT_DATA_ULONG, "tdc_pkt_cpl_to"},
	{TDC_STAT_INVALID_SOP, KSTAT_DATA_ULONG, "tdc_invalid_sop"},
	{TDC_STAT_UNEXPECTED_SOP, KSTAT_DATA_ULONG, "tdc_unexpected_sop"},

	{TDC_STAT_COUNT_HDR_SIZE_ERR, KSTAT_DATA_ULONG,
	    "tdc_count_hdr_size_err"},
	{TDC_STAT_COUNT_RUNT, KSTAT_DATA_ULONG, "tdc_count_runt"},
	{TDC_STAT_COUNT_ABORT, KSTAT_DATA_ULONG, "tdc_count_abort"},

	{TDC_STAT_TX_STARTS, KSTAT_DATA_ULONG, "tdc_tx_starts"},
	{TDC_STAT_TX_NO_DESC, KSTAT_DATA_ULONG, "tdc_tx_no_desc"},
	{TDC_STAT_TX_DMA_BIND_FAIL, KSTAT_DATA_ULONG, "tdc_tx_dma_bind_fail"},
	{TDC_STAT_TX_HDR_PKTS, KSTAT_DATA_ULONG, "tdc_tx_hdr_pkts"},
	{TDC_STAT_TX_DDI_PKTS, KSTAT_DATA_ULONG, "tdc_tx_ddi_pkts"},
	{TDC_STAT_TX_JUMBO_PKTS, KSTAT_DATA_ULONG, "tdc_tx_jumbo_pkts"},
	{TDC_STAT_TX_MAX_PEND, KSTAT_DATA_ULONG, "tdc_tx_max_pend"},
	{TDC_STAT_TX_MARKS, KSTAT_DATA_ULONG, "tdc_tx_marks"},
	{TDC_STAT_END, NULL, NULL}
};

typedef enum {
	REORD_TBL_PAR_ERR = 0,
	REORD_BUF_DED_ERR,
	REORD_BUF_SEC_ERR,
	TDC_SYS_STAT_END
} hxge_tdc_sys_stat_idx_t;

hxge_kstat_index_t hxge_tdc_sys_stats[] = {
	{REORD_TBL_PAR_ERR, KSTAT_DATA_UINT64, "reord_tbl_par_err"},
	{REORD_BUF_DED_ERR, KSTAT_DATA_UINT64, "reord_buf_ded_err"},
	{REORD_BUF_SEC_ERR, KSTAT_DATA_UINT64, "reord_buf_sec_err"},
	{TDC_SYS_STAT_END, NULL, NULL}
};

typedef enum {
	VMAC_STAT_TX_FRAME_CNT,		/* vmac_tx_frame_cnt_t */
	VMAC_STAT_TX_BYTE_CNT,		/* vmac_tx_byte_cnt_t */

	VMAC_STAT_RX_FRAME_CNT,		/* vmac_rx_frame_cnt_t */
	VMAC_STAT_RX_BYTE_CNT,		/* vmac_rx_byte_cnt_t */
	VMAC_STAT_RX_DROP_FRAME_CNT,	/* vmac_rx_drop_fr_cnt_t */
	VMAC_STAT_RX_DROP_BYTE_CNT,	/* vmac_rx_drop_byte_cnt_t */
	VMAC_STAT_RX_CRC_CNT,		/* vmac_rx_crc_cnt_t */
	VMAC_STAT_RX_PAUSE_CNT,		/* vmac_rx_pause_cnt_t */
	VMAC_STAT_RX_BCAST_FR_CNT,	/* vmac_rx_bcast_fr_cnt_t */
	VMAC_STAT_RX_MCAST_FR_CNT,	/* vmac_rx_mcast_fr_cnt_t */
	VMAC_STAT_END
} hxge_vmac_stat_index_t;

hxge_kstat_index_t hxge_vmac_stats[] = {
	{VMAC_STAT_TX_FRAME_CNT, KSTAT_DATA_UINT64, "vmac_tx_frame_cnt"},
	{VMAC_STAT_TX_BYTE_CNT, KSTAT_DATA_UINT64, "vmac_tx_byte_cnt"},

	{VMAC_STAT_RX_FRAME_CNT, KSTAT_DATA_UINT64, "vmac_rx_frame_cnt"},
	{VMAC_STAT_RX_BYTE_CNT, KSTAT_DATA_UINT64, "vmac_rx_byte_cnt"},
	{VMAC_STAT_RX_DROP_FRAME_CNT, KSTAT_DATA_UINT64,
		"vmac_rx_drop_frame_cnt"},
	{VMAC_STAT_RX_DROP_BYTE_CNT, KSTAT_DATA_UINT64,
		"vmac_rx_drop_byte_cnt"},
	{VMAC_STAT_RX_CRC_CNT, KSTAT_DATA_UINT64, "vmac_rx_crc_cnt"},
	{VMAC_STAT_RX_PAUSE_CNT, KSTAT_DATA_UINT64, "vmac_rx_pause_cnt"},
	{VMAC_STAT_RX_BCAST_FR_CNT, KSTAT_DATA_UINT64, "vmac_rx_bcast_fr_cnt"},
	{VMAC_STAT_RX_MCAST_FR_CNT, KSTAT_DATA_UINT64, "vmac_rx_mcast_fr_cnt"},
	{VMAC_STAT_END, NULL, NULL}
};

typedef enum {
	PFC_STAT_PKT_DROP,
	PFC_STAT_TCAM_PARITY_ERR,
	PFC_STAT_VLAN_PARITY_ERR,
	PFC_STAT_BAD_CS_COUNT,
	PFC_STAT_DROP_COUNT,
	PFC_STAT_TCP_CTRL_DROP,
	PFC_STAT_L2_ADDR_DROP,
	PFC_STAT_CLASS_CODE_DROP,
	PFC_STAT_TCAM_DROP,
	PFC_STAT_VLAN_DROP,
	PFC_STAT_END
} hxge_pfc_stat_index_t;

hxge_kstat_index_t hxge_pfc_stats[] = {
	{PFC_STAT_PKT_DROP, KSTAT_DATA_ULONG, "pfc_pkt_drop"},
	{PFC_STAT_TCAM_PARITY_ERR, KSTAT_DATA_ULONG, "pfc_tcam_parity_err"},
	{PFC_STAT_VLAN_PARITY_ERR, KSTAT_DATA_ULONG, "pfc_vlan_parity_err"},
	{PFC_STAT_BAD_CS_COUNT, KSTAT_DATA_ULONG, "pfc_bad_cs_count"},
	{PFC_STAT_DROP_COUNT, KSTAT_DATA_ULONG, "pfc_drop_count"},
	{PFC_STAT_TCP_CTRL_DROP, KSTAT_DATA_ULONG, "  pfc_pkt_drop_tcp_ctrl"},
	{PFC_STAT_L2_ADDR_DROP, KSTAT_DATA_ULONG, "  pfc_pkt_drop_l2_addr"},
	{PFC_STAT_CLASS_CODE_DROP, KSTAT_DATA_ULONG,
	    "  pfc_pkt_drop_class_code"},
	{PFC_STAT_TCAM_DROP, KSTAT_DATA_ULONG, "  pfc_pkt_drop_tcam"},
	{PFC_STAT_VLAN_DROP, KSTAT_DATA_ULONG, "  pfc_pkt_drop_vlan"},
	{PFC_STAT_END, NULL, NULL}
};

typedef enum {
	SPC_ACC_ERR = 0,
	TDC_PIOACC_ERR,
	RDC_PIOACC_ERR,
	PFC_PIOACC_ERR,
	VMAC_PIOACC_ERR,
	CPL_HDRQ_PARERR,
	CPL_DATAQ_PARERR,
	RETRYRAM_XDLH_PARERR,
	RETRYSOTRAM_XDLH_PARERR,
	P_HDRQ_PARERR,
	P_DATAQ_PARERR,
	NP_HDRQ_PARERR,
	NP_DATAQ_PARERR,
	EIC_MSIX_PARERR,
	HCR_PARERR,
	PEU_SYS_STAT_END
} hxge_peu_sys_stat_idx_t;

hxge_kstat_index_t hxge_peu_sys_stats[] = {
	{SPC_ACC_ERR, KSTAT_DATA_UINT64, "spc_acc_err"},
	{TDC_PIOACC_ERR, KSTAT_DATA_UINT64, "tdc_pioacc_err"},
	{RDC_PIOACC_ERR, KSTAT_DATA_UINT64, "rdc_pioacc_err"},
	{PFC_PIOACC_ERR, KSTAT_DATA_UINT64, "pfc_pioacc_err"},
	{VMAC_PIOACC_ERR, KSTAT_DATA_UINT64, "vmac_pioacc_err"},
	{CPL_HDRQ_PARERR, KSTAT_DATA_UINT64, "cpl_hdrq_parerr"},
	{CPL_DATAQ_PARERR, KSTAT_DATA_UINT64, "cpl_dataq_parerr"},
	{RETRYRAM_XDLH_PARERR, KSTAT_DATA_UINT64, "retryram_xdlh_parerr"},
	{RETRYSOTRAM_XDLH_PARERR, KSTAT_DATA_UINT64, "retrysotram_xdlh_parerr"},
	{P_HDRQ_PARERR, KSTAT_DATA_UINT64, "p_hdrq_parerr"},
	{P_DATAQ_PARERR, KSTAT_DATA_UINT64, "p_dataq_parerr"},
	{NP_HDRQ_PARERR, KSTAT_DATA_UINT64, "np_hdrq_parerr"},
	{NP_DATAQ_PARERR, KSTAT_DATA_UINT64, "np_dataq_parerr"},
	{EIC_MSIX_PARERR, KSTAT_DATA_UINT64, "eic_msix_parerr"},
	{HCR_PARERR, KSTAT_DATA_UINT64, "hcr_parerr"},
	{TDC_SYS_STAT_END, NULL, NULL}
};

typedef enum {
	MMAC_MAX_ADDR,
	MMAC_AVAIL_ADDR,
	MMAC_ADDR_POOL1,
	MMAC_ADDR_POOL2,
	MMAC_ADDR_POOL3,
	MMAC_ADDR_POOL4,
	MMAC_ADDR_POOL5,
	MMAC_ADDR_POOL6,
	MMAC_ADDR_POOL7,
	MMAC_ADDR_POOL8,
	MMAC_ADDR_POOL9,
	MMAC_ADDR_POOL10,
	MMAC_ADDR_POOL11,
	MMAC_ADDR_POOL12,
	MMAC_ADDR_POOL13,
	MMAC_ADDR_POOL14,
	MMAC_ADDR_POOL15,
	MMAC_ADDR_POOL16,
	MMAC_STATS_END
} hxge_mmac_stat_index_t;

hxge_kstat_index_t hxge_mmac_stats[] = {
	{MMAC_MAX_ADDR, KSTAT_DATA_UINT64, "max_mmac_addr"},
	{MMAC_AVAIL_ADDR, KSTAT_DATA_UINT64, "avail_mmac_addr"},
	{MMAC_ADDR_POOL1, KSTAT_DATA_UINT64, "mmac_addr_1"},
	{MMAC_ADDR_POOL2, KSTAT_DATA_UINT64, "mmac_addr_2"},
	{MMAC_ADDR_POOL3, KSTAT_DATA_UINT64, "mmac_addr_3"},
	{MMAC_ADDR_POOL4, KSTAT_DATA_UINT64, "mmac_addr_4"},
	{MMAC_ADDR_POOL5, KSTAT_DATA_UINT64, "mmac_addr_5"},
	{MMAC_ADDR_POOL6, KSTAT_DATA_UINT64, "mmac_addr_6"},
	{MMAC_ADDR_POOL7, KSTAT_DATA_UINT64, "mmac_addr_7"},
	{MMAC_ADDR_POOL8, KSTAT_DATA_UINT64, "mmac_addr_8"},
	{MMAC_ADDR_POOL9, KSTAT_DATA_UINT64, "mmac_addr_9"},
	{MMAC_ADDR_POOL10, KSTAT_DATA_UINT64, "mmac_addr_10"},
	{MMAC_ADDR_POOL11, KSTAT_DATA_UINT64, "mmac_addr_11"},
	{MMAC_ADDR_POOL12, KSTAT_DATA_UINT64, "mmac_addr_12"},
	{MMAC_ADDR_POOL13, KSTAT_DATA_UINT64, "mmac_addr_13"},
	{MMAC_ADDR_POOL14, KSTAT_DATA_UINT64, "mmac_addr_14"},
	{MMAC_ADDR_POOL15, KSTAT_DATA_UINT64, "mmac_addr_15"},
	{MMAC_ADDR_POOL16, KSTAT_DATA_UINT64, "mmac_addr_16"},
	{MMAC_STATS_END, NULL, NULL},
};


/* ARGSUSED */
int
hxge_tdc_stat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_tdc_kstat_t	tdc_kstatsp;
	p_hxge_tx_ring_stats_t	statsp;
	int			channel;
	char			*ch_name, *end;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);
	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_rxstat_update"));

	ch_name = ksp->ks_name;
	ch_name += strlen(TDC_NAME_FORMAT1);
	channel = mi_strtol(ch_name, &end, 10);

	tdc_kstatsp = (p_hxge_tdc_kstat_t)ksp->ks_data;
	statsp = (p_hxge_tx_ring_stats_t)&hxgep->statsp->tdc_stats[channel];

	HXGE_DEBUG_MSG((hxgep, KST_CTL,
	    "hxge_tdc_stat_update data $%p statsp $%p channel %d",
	    ksp->ks_data, statsp, channel));

	tdc_kstatsp->opackets.value.ull = statsp->opackets;
	tdc_kstatsp->obytes.value.ull = statsp->obytes;
	tdc_kstatsp->obytes_with_pad.value.ull = statsp->obytes_with_pad;
	tdc_kstatsp->oerrors.value.ull = statsp->oerrors;
	tdc_kstatsp->tx_hdr_pkts.value.ull = statsp->tx_hdr_pkts;
	tdc_kstatsp->tx_ddi_pkts.value.ull = statsp->tx_ddi_pkts;
	tdc_kstatsp->tx_jumbo_pkts.value.ull = statsp->tx_jumbo_pkts;
	tdc_kstatsp->tx_max_pend.value.ull = statsp->tx_max_pend;
	tdc_kstatsp->peu_resp_err.value.ul = statsp->peu_resp_err;
	tdc_kstatsp->pkt_size_err.value.ul = statsp->pkt_size_err;
	tdc_kstatsp->tx_rng_oflow.value.ul = statsp->tx_rng_oflow;
	tdc_kstatsp->pkt_size_hdr_err.value.ul = statsp->pkt_size_hdr_err;
	tdc_kstatsp->runt_pkt_drop_err.value.ul = statsp->runt_pkt_drop_err;
	tdc_kstatsp->pref_par_err.value.ul = statsp->pref_par_err;
	tdc_kstatsp->tdr_pref_cpl_to.value.ul = statsp->tdr_pref_cpl_to;
	tdc_kstatsp->pkt_cpl_to.value.ul = statsp->pkt_cpl_to;
	tdc_kstatsp->invalid_sop.value.ul = statsp->invalid_sop;
	tdc_kstatsp->unexpected_sop.value.ul = statsp->unexpected_sop;
	tdc_kstatsp->tx_starts.value.ul = statsp->tx_starts;
	tdc_kstatsp->tx_no_desc.value.ul = statsp->tx_no_desc;
	tdc_kstatsp->tx_dma_bind_fail.value.ul = statsp->tx_dma_bind_fail;

	tdc_kstatsp->count_hdr_size_err.value.ul =
	    statsp->count_hdr_size_err;
	tdc_kstatsp->count_runt.value.ul = statsp->count_runt;
	tdc_kstatsp->count_abort.value.ul = statsp->count_abort;
	tdc_kstatsp->tx_marks.value.ul = statsp->tx_marks;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, " <== hxge_tdc_stat_update"));
	return (0);
}

/* ARGSUSED */
int
hxge_tdc_sys_stat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_tdc_sys_kstat_t	tdc_sys_kstatsp;
	p_hxge_tdc_sys_stats_t	statsp;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);
	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_tdc_sys_stat_update"));

	tdc_sys_kstatsp = (p_hxge_tdc_sys_kstat_t)ksp->ks_data;
	statsp = (p_hxge_tdc_sys_stats_t)&hxgep->statsp->tdc_sys_stats;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "hxge_tdc_sys_stat_update %llx",
	    ksp->ks_data));

	tdc_sys_kstatsp->reord_tbl_par_err.value.ul =
	    statsp->reord_tbl_par_err;
	tdc_sys_kstatsp->reord_buf_ded_err.value.ul =
	    statsp->reord_buf_ded_err;
	tdc_sys_kstatsp->reord_buf_sec_err.value.ul =
	    statsp->reord_buf_sec_err;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, " <== hxge_tdc_sys_stat_update"));
	return (0);
}

/* ARGSUSED */
int
hxge_rdc_stat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_rdc_kstat_t	rdc_kstatsp;
	p_hxge_rx_ring_stats_t	statsp;
	int			channel;
	char			*ch_name, *end;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_rdc_stat_update"));

	ch_name = ksp->ks_name;
	ch_name += strlen(RDC_NAME_FORMAT1);
	channel = mi_strtol(ch_name, &end, 10);

	rdc_kstatsp = (p_hxge_rdc_kstat_t)ksp->ks_data;
	statsp = (p_hxge_rx_ring_stats_t)&hxgep->statsp->rdc_stats[channel];

	HXGE_DEBUG_MSG((hxgep, KST_CTL,
	    "hxge_rdc_stat_update $%p statsp $%p channel %d",
	    ksp->ks_data, statsp, channel));

	rdc_kstatsp->ipackets.value.ull = statsp->ipackets;
	rdc_kstatsp->rbytes.value.ull = statsp->ibytes;
	rdc_kstatsp->jumbo_pkts.value.ul = statsp->jumbo_pkts;
	rdc_kstatsp->rcr_unknown_err.value.ul = statsp->rcr_unknown_err;
	rdc_kstatsp->errors.value.ul = statsp->ierrors;
	rdc_kstatsp->rcr_sha_par_err.value.ul = statsp->rcr_sha_par;
	rdc_kstatsp->rbr_pre_par_err.value.ul = statsp->rbr_pre_par;
	rdc_kstatsp->rbr_pre_emty.value.ul = statsp->rbr_pre_empty;
	rdc_kstatsp->rcr_shadow_full.value.ul = statsp->rcr_shadow_full;
	rdc_kstatsp->rbr_tmout.value.ul = statsp->rbr_tmout;
	rdc_kstatsp->peu_resp_err.value.ul = statsp->peu_resp_err;
	rdc_kstatsp->ctrl_fifo_ecc_err.value.ul = statsp->ctrl_fifo_ecc_err;
	rdc_kstatsp->data_fifo_ecc_err.value.ul = statsp->data_fifo_ecc_err;
	rdc_kstatsp->rcrfull.value.ul = statsp->rcrfull;
	rdc_kstatsp->rbr_empty.value.ul = statsp->rbr_empty;
	rdc_kstatsp->rbr_empty_fail.value.ul = statsp->rbr_empty_fail;
	rdc_kstatsp->rbr_empty_restore.value.ul = statsp->rbr_empty_restore;
	rdc_kstatsp->rbrfull.value.ul = statsp->rbrfull;
	rdc_kstatsp->rcr_invalids.value.ul = statsp->rcr_invalids;
	rdc_kstatsp->rcr_to.value.ul = statsp->rcr_to;
	rdc_kstatsp->rcr_thresh.value.ul = statsp->rcr_thres;
	rdc_kstatsp->pkt_drop.value.ul = statsp->pkt_drop;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, " <== hxge_rdc_stat_update"));
	return (0);
}

/* ARGSUSED */
int
hxge_rdc_sys_stat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_rdc_sys_kstat_t	rdc_sys_kstatsp;
	p_hxge_rdc_sys_stats_t	statsp;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_rdc_sys_stat_update"));

	rdc_sys_kstatsp = (p_hxge_rdc_sys_kstat_t)ksp->ks_data;
	statsp = (p_hxge_rdc_sys_stats_t)&hxgep->statsp->rdc_sys_stats;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "hxge_rdc_sys_stat_update %llx",
	    ksp->ks_data));

	rdc_sys_kstatsp->ctrl_fifo_sec.value.ul = statsp->ctrl_fifo_sec;
	rdc_sys_kstatsp->ctrl_fifo_ded.value.ul = statsp->ctrl_fifo_ded;
	rdc_sys_kstatsp->data_fifo_sec.value.ul = statsp->data_fifo_sec;
	rdc_sys_kstatsp->data_fifo_ded.value.ul = statsp->data_fifo_ded;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, " <== hxge_rdc_sys_stat_update"));
	return (0);
}

/* ARGSUSED */
int
hxge_vmac_stat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_vmac_kstat_t	vmac_kstatsp;
	p_hxge_vmac_stats_t	statsp;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_vmac_stat_update"));

	hxge_save_cntrs(hxgep);

	vmac_kstatsp = (p_hxge_vmac_kstat_t)ksp->ks_data;
	statsp = (p_hxge_vmac_stats_t)&hxgep->statsp->vmac_stats;

	vmac_kstatsp->tx_frame_cnt.value.ul = statsp->tx_frame_cnt;
	vmac_kstatsp->tx_byte_cnt.value.ul = statsp->tx_byte_cnt;

	vmac_kstatsp->rx_frame_cnt.value.ul = statsp->rx_frame_cnt;
	vmac_kstatsp->rx_byte_cnt.value.ul = statsp->rx_byte_cnt;
	vmac_kstatsp->rx_drop_frame_cnt.value.ul = statsp->rx_drop_frame_cnt;
	vmac_kstatsp->rx_drop_byte_cnt.value.ul = statsp->rx_drop_byte_cnt;
	vmac_kstatsp->rx_crc_cnt.value.ul = statsp->rx_crc_cnt;
	vmac_kstatsp->rx_pause_cnt.value.ul = statsp->rx_pause_cnt;
	vmac_kstatsp->rx_bcast_fr_cnt.value.ul = statsp->rx_bcast_fr_cnt;
	vmac_kstatsp->rx_mcast_fr_cnt.value.ul = statsp->rx_mcast_fr_cnt;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "<== hxge_vmac_stat_update"));
	return (0);
}

/* ARGSUSED */
int
hxge_pfc_stat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_pfc_kstat_t	kstatsp;
	p_hxge_pfc_stats_t	statsp;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_pfc_stat_update"));

	kstatsp = (p_hxge_pfc_kstat_t)ksp->ks_data;
	statsp = (p_hxge_pfc_stats_t)&hxgep->statsp->pfc_stats;

	kstatsp->pfc_pkt_drop.value.ul = statsp->pkt_drop;
	kstatsp->pfc_tcam_parity_err.value.ul = statsp->tcam_parity_err;
	kstatsp->pfc_vlan_parity_err.value.ul = statsp->vlan_parity_err;
	kstatsp->pfc_bad_cs_count.value.ul = statsp->bad_cs_count;
	kstatsp->pfc_drop_count.value.ul = statsp->drop_count;
	kstatsp->pfc_tcp_ctrl_drop.value.ul = statsp->errlog.tcp_ctrl_drop;
	kstatsp->pfc_l2_addr_drop.value.ul = statsp->errlog.l2_addr_drop;
	kstatsp->pfc_class_code_drop.value.ul = statsp->errlog.class_code_drop;
	kstatsp->pfc_tcam_drop.value.ul = statsp->errlog.tcam_drop;
	kstatsp->pfc_vlan_drop.value.ul = statsp->errlog.vlan_drop;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "<== hxge_pfc_stat_update"));
	return (0);
}

/* ARGSUSED */
int
hxge_peu_sys_stat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_peu_sys_kstat_t	peu_kstatsp;
	p_hxge_peu_sys_stats_t	statsp;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_peu_sys_stat_update"));

	peu_kstatsp = (p_hxge_peu_sys_kstat_t)ksp->ks_data;
	statsp = (p_hxge_peu_sys_stats_t)&hxgep->statsp->peu_sys_stats;

	peu_kstatsp->spc_acc_err.value.ul = statsp->spc_acc_err;
	peu_kstatsp->tdc_pioacc_err.value.ul = statsp->tdc_pioacc_err;
	peu_kstatsp->rdc_pioacc_err.value.ul = statsp->rdc_pioacc_err;
	peu_kstatsp->pfc_pioacc_err.value.ul = statsp->pfc_pioacc_err;
	peu_kstatsp->vmac_pioacc_err.value.ul = statsp->vmac_pioacc_err;
	peu_kstatsp->cpl_hdrq_parerr.value.ul = statsp->cpl_hdrq_parerr;
	peu_kstatsp->cpl_dataq_parerr.value.ul = statsp->cpl_dataq_parerr;
	peu_kstatsp->retryram_xdlh_parerr.value.ul =
	    statsp->retryram_xdlh_parerr;
	peu_kstatsp->retrysotram_xdlh_parerr.value.ul =
	    statsp->retrysotram_xdlh_parerr;
	peu_kstatsp->p_hdrq_parerr.value.ul = statsp->p_hdrq_parerr;
	peu_kstatsp->p_dataq_parerr.value.ul = statsp->p_dataq_parerr;
	peu_kstatsp->np_hdrq_parerr.value.ul = statsp->np_hdrq_parerr;
	peu_kstatsp->np_dataq_parerr.value.ul = statsp->np_dataq_parerr;
	peu_kstatsp->eic_msix_parerr.value.ul = statsp->eic_msix_parerr;
	peu_kstatsp->hcr_parerr.value.ul = statsp->hcr_parerr;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "<== hxge_peu_sys_stat_update"));
	return (0);
}

static kstat_t *
hxge_setup_local_kstat(p_hxge_t hxgep, int instance, char *name,
	const hxge_kstat_index_t *ksip, size_t count,
	int (*update) (kstat_t *, int))
{
	kstat_t		*ksp;
	kstat_named_t	*knp;
	int		i;

	ksp = kstat_create(HXGE_DRIVER_NAME, instance, name, "net",
	    KSTAT_TYPE_NAMED, count, 0);
	if (ksp == NULL)
		return (NULL);

	ksp->ks_private = (void *) hxgep;
	ksp->ks_update = update;
	knp = ksp->ks_data;

	for (i = 0; ksip[i].name != NULL; i++) {
		kstat_named_init(&knp[i], ksip[i].name, ksip[i].type);
	}

	kstat_install(ksp);

	return (ksp);
}

void
hxge_setup_kstats(p_hxge_t hxgep)
{
	struct kstat		*ksp;
	p_hxge_port_kstat_t	hxgekp;
	size_t			hxge_kstat_sz;
	char			stat_name[64];
	int			i;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_setup_kstats"));

	/* Setup RDC statistics */
	for (i = 0; i < hxgep->nrdc; i++) {
		(void) sprintf(stat_name, "%s"CH_NAME_FORMAT,
		    RDC_NAME_FORMAT1, i);
		hxgep->statsp->rdc_ksp[i] = hxge_setup_local_kstat(hxgep,
		    hxgep->instance, stat_name, &hxge_rdc_stats[0],
		    RDC_STAT_END, hxge_rdc_stat_update);
		if (hxgep->statsp->rdc_ksp[i] == NULL)
			cmn_err(CE_WARN,
			    "kstat_create failed for rdc channel %d", i);
	}

	/* Setup RDC System statistics */
	hxgep->statsp->rdc_sys_ksp = hxge_setup_local_kstat(hxgep,
	    hxgep->instance, "RDC_system", &hxge_rdc_sys_stats[0],
	    RDC_SYS_STAT_END, hxge_rdc_sys_stat_update);
	if (hxgep->statsp->rdc_sys_ksp == NULL)
		cmn_err(CE_WARN, "kstat_create failed for rdc_sys_ksp");

	/* Setup TDC statistics */
	for (i = 0; i < hxgep->ntdc; i++) {
		(void) sprintf(stat_name, "%s"CH_NAME_FORMAT,
		    TDC_NAME_FORMAT1, i);
		hxgep->statsp->tdc_ksp[i] = hxge_setup_local_kstat(hxgep,
		    hxgep->instance, stat_name, &hxge_tdc_stats[0],
		    TDC_STAT_END, hxge_tdc_stat_update);
		if (hxgep->statsp->tdc_ksp[i] == NULL)
			cmn_err(CE_WARN,
			    "kstat_create failed for tdc channel %d", i);
	}

	/* Setup TDC System statistics */
	hxgep->statsp->tdc_sys_ksp = hxge_setup_local_kstat(hxgep,
	    hxgep->instance, "TDC_system", &hxge_tdc_sys_stats[0],
	    RDC_SYS_STAT_END, hxge_tdc_sys_stat_update);
	if (hxgep->statsp->tdc_sys_ksp == NULL)
		cmn_err(CE_WARN, "kstat_create failed for tdc_sys_ksp");

	/* Setup PFC statistics */
	hxgep->statsp->pfc_ksp = hxge_setup_local_kstat(hxgep,
	    hxgep->instance, "PFC", &hxge_pfc_stats[0],
	    PFC_STAT_END, hxge_pfc_stat_update);
	if (hxgep->statsp->pfc_ksp == NULL)
		cmn_err(CE_WARN, "kstat_create failed for pfc");

	/* Setup VMAC statistics */
	hxgep->statsp->vmac_ksp = hxge_setup_local_kstat(hxgep,
	    hxgep->instance, "VMAC", &hxge_vmac_stats[0],
	    VMAC_STAT_END, hxge_vmac_stat_update);
	if (hxgep->statsp->vmac_ksp == NULL)
		cmn_err(CE_WARN, "kstat_create failed for vmac");

	/* Setup MMAC Statistics. */
	hxgep->statsp->mmac_ksp = hxge_setup_local_kstat(hxgep,
	    hxgep->instance, "MMAC", &hxge_mmac_stats[0],
	    MMAC_STATS_END, hxge_mmac_stat_update);
	if (hxgep->statsp->mmac_ksp == NULL)
		cmn_err(CE_WARN, "kstat_create failed for mmac");

	/* Setup PEU System statistics */
	hxgep->statsp->peu_sys_ksp = hxge_setup_local_kstat(hxgep,
	    hxgep->instance, "PEU", &hxge_peu_sys_stats[0],
	    PEU_SYS_STAT_END, hxge_peu_sys_stat_update);
	if (hxgep->statsp->peu_sys_ksp == NULL)
		cmn_err(CE_WARN, "kstat_create failed for peu sys");

	/* Port stats */
	hxge_kstat_sz = sizeof (hxge_port_kstat_t);

	if ((ksp = kstat_create(HXGE_DRIVER_NAME, hxgep->instance,
	    "Port", "net", KSTAT_TYPE_NAMED,
	    hxge_kstat_sz / sizeof (kstat_named_t), 0)) == NULL) {
		cmn_err(CE_WARN, "kstat_create failed for port stat");
		return;
	}

	hxgekp = (p_hxge_port_kstat_t)ksp->ks_data;

	kstat_named_init(&hxgekp->cap_10gfdx, "cap_10gfdx", KSTAT_DATA_ULONG);

	/*
	 * Link partner capabilities.
	 */
	kstat_named_init(&hxgekp->lp_cap_10gfdx, "lp_cap_10gfdx",
	    KSTAT_DATA_ULONG);

	/*
	 * Shared link setup.
	 */
	kstat_named_init(&hxgekp->link_speed, "link_speed", KSTAT_DATA_ULONG);
	kstat_named_init(&hxgekp->link_duplex, "link_duplex", KSTAT_DATA_CHAR);
	kstat_named_init(&hxgekp->link_up, "link_up", KSTAT_DATA_ULONG);

	/*
	 * Loopback statistics.
	 */
	kstat_named_init(&hxgekp->lb_mode, "lb_mode", KSTAT_DATA_ULONG);

	/* General MAC statistics */

	kstat_named_init(&hxgekp->ifspeed, "ifspeed", KSTAT_DATA_UINT64);
	kstat_named_init(&hxgekp->promisc, "promisc", KSTAT_DATA_CHAR);

	ksp->ks_update = hxge_port_kstat_update;
	ksp->ks_private = (void *) hxgep;
	kstat_install(ksp);
	hxgep->statsp->port_ksp = ksp;
	HXGE_DEBUG_MSG((hxgep, KST_CTL, "<== hxge_setup_kstats"));
}

void
hxge_destroy_kstats(p_hxge_t hxgep)
{
	int			channel;
	p_hxge_dma_pt_cfg_t	p_dma_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_destroy_kstats"));
	if (hxgep->statsp == NULL)
		return;

	if (hxgep->statsp->ksp)
		kstat_delete(hxgep->statsp->ksp);

	p_dma_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	for (channel = 0; channel < p_cfgp->max_rdcs; channel++) {
		if (hxgep->statsp->rdc_ksp[channel]) {
			kstat_delete(hxgep->statsp->rdc_ksp[channel]);
		}
	}

	for (channel = 0; channel < p_cfgp->max_tdcs; channel++) {
		if (hxgep->statsp->tdc_ksp[channel]) {
			kstat_delete(hxgep->statsp->tdc_ksp[channel]);
		}
	}

	if (hxgep->statsp->rdc_sys_ksp)
		kstat_delete(hxgep->statsp->rdc_sys_ksp);

	if (hxgep->statsp->tdc_sys_ksp)
		kstat_delete(hxgep->statsp->tdc_sys_ksp);

	if (hxgep->statsp->peu_sys_ksp)
		kstat_delete(hxgep->statsp->peu_sys_ksp);

	if (hxgep->statsp->mmac_ksp)
		kstat_delete(hxgep->statsp->mmac_ksp);

	if (hxgep->statsp->pfc_ksp)
		kstat_delete(hxgep->statsp->pfc_ksp);

	if (hxgep->statsp->vmac_ksp)
		kstat_delete(hxgep->statsp->vmac_ksp);

	if (hxgep->statsp->port_ksp)
		kstat_delete(hxgep->statsp->port_ksp);

	if (hxgep->statsp)
		KMEM_FREE(hxgep->statsp, hxgep->statsp->stats_size);

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "<== hxge_destroy_kstats"));
}

/* ARGSUSED */
int
hxge_port_kstat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_stats_t		statsp;
	p_hxge_port_kstat_t	hxgekp;
	p_hxge_port_stats_t	psp;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_port_kstat_update"));
	statsp = (p_hxge_stats_t)hxgep->statsp;
	hxgekp = (p_hxge_port_kstat_t)ksp->ks_data;
	psp = &statsp->port_stats;

	if (hxgep->filter.all_phys_cnt)
		(void) strcpy(hxgekp->promisc.value.c, "phys");
	else if (hxgep->filter.all_multicast_cnt)
		(void) strcpy(hxgekp->promisc.value.c, "multi");
	else
		(void) strcpy(hxgekp->promisc.value.c, "off");
	hxgekp->ifspeed.value.ul = statsp->mac_stats.link_speed * 1000000ULL;

	/*
	 * transceiver state informations.
	 */
	hxgekp->cap_10gfdx.value.ul = statsp->mac_stats.cap_10gfdx;

	/*
	 * Link partner capabilities.
	 */
	hxgekp->lp_cap_10gfdx.value.ul = statsp->mac_stats.lp_cap_10gfdx;

	/*
	 * Physical link statistics.
	 */
	hxgekp->link_speed.value.ul = statsp->mac_stats.link_speed;
	if (statsp->mac_stats.link_duplex == 2)
		(void) strcpy(hxgekp->link_duplex.value.c, "full");
	else
		(void) strcpy(hxgekp->link_duplex.value.c, "unknown");
	hxgekp->link_up.value.ul = statsp->mac_stats.link_up;

	/*
	 * Loopback statistics.
	 */
	hxgekp->lb_mode.value.ul = psp->lb_mode;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "<== hxge_port_kstat_update"));
	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
hxge_rx_ring_stat(mac_ring_driver_t rdriver, uint_t stat, uint64_t *val)
{
	p_hxge_ring_handle_t	rhp = (p_hxge_ring_handle_t)rdriver;
	p_hxge_t		hxgep = rhp->hxgep;

	ASSERT(rhp != NULL);
	ASSERT(hxgep != NULL);
	ASSERT(hxgep->statsp != NULL);
	ASSERT((rhp->index >= 0) && (rhp->index < HXGE_MAX_RDCS));

	switch (stat) {
	case MAC_STAT_IERRORS:
		*val = hxgep->statsp->rdc_stats[rhp->index].ierrors;
		break;
	case MAC_STAT_RBYTES:
		*val = hxgep->statsp->rdc_stats[rhp->index].ibytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = hxgep->statsp->rdc_stats[rhp->index].ipackets;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular tx ring
 */
int
hxge_tx_ring_stat(mac_ring_driver_t rdriver, uint_t stat, uint64_t *val)
{
	p_hxge_ring_handle_t    rhp = (p_hxge_ring_handle_t)rdriver;
	p_hxge_t		hxgep = rhp->hxgep;

	ASSERT(rhp != NULL);
	ASSERT(hxgep != NULL);
	ASSERT(hxgep->statsp != NULL);
	ASSERT((rhp->index >= 0) && (rhp->index < HXGE_MAX_TDCS));

	switch (stat) {
	case MAC_STAT_OERRORS:
		*val = hxgep->statsp->tdc_stats[rhp->index].oerrors;
		break;
	case MAC_STAT_OBYTES:
		*val = hxgep->statsp->tdc_stats[rhp->index].obytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = hxgep->statsp->tdc_stats[rhp->index].opackets;
		break;
	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

int
hxge_m_stat(void *arg, uint_t stat, uint64_t *value)
{
	p_hxge_t		hxgep = (p_hxge_t)arg;
	p_hxge_stats_t		statsp;
	hxge_tx_ring_stats_t	*tx_stats;
	uint64_t		val = 0;
	int			channel;

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_m_stat"));
	statsp = (p_hxge_stats_t)hxgep->statsp;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		val = statsp->mac_stats.link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		val = 0;
		break;

	case MAC_STAT_BRDCSTRCV:
		val = 0;
		break;

	case MAC_STAT_MULTIXMT:
		val = 0;
		break;

	case MAC_STAT_BRDCSTXMT:
		val = 0;
		break;

	case MAC_STAT_NORCVBUF:
		val = 0;
		break;

	case MAC_STAT_IERRORS:
	case ETHER_STAT_MACRCV_ERRORS:
		val = 0;
		for (channel = 0; channel < hxgep->nrdc; channel++) {
			val += statsp->rdc_stats[channel].ierrors;
		}
		break;

	case MAC_STAT_NOXMTBUF:
		val = 0;
		break;

	case MAC_STAT_OERRORS:
		for (channel = 0; channel < hxgep->ntdc; channel++) {
			val += statsp->tdc_stats[channel].oerrors;
		}
		break;

	case MAC_STAT_COLLISIONS:
		val = 0;
		break;

	case MAC_STAT_RBYTES:
		for (channel = 0; channel < hxgep->nrdc; channel++) {
			val += statsp->rdc_stats[channel].ibytes;
		}
		break;

	case MAC_STAT_IPACKETS:
		for (channel = 0; channel < hxgep->nrdc; channel++) {
			val += statsp->rdc_stats[channel].ipackets;
		}
		break;

	case MAC_STAT_OBYTES:
		for (channel = 0; channel < hxgep->ntdc; channel++) {
			val += statsp->tdc_stats[channel].obytes;
		}
		break;

	case MAC_STAT_OPACKETS:
		for (channel = 0; channel < hxgep->ntdc; channel++) {
			val += statsp->tdc_stats[channel].opackets;
		}
		break;

	case MAC_STAT_UNKNOWNS:
		val = 0;
		break;

	case MAC_STAT_UNDERFLOWS:
		val = 0;
		break;

	case MAC_STAT_OVERFLOWS:
		val = 0;
		break;

	case MAC_STAT_LINK_STATE:
		val = statsp->mac_stats.link_duplex;
		break;
	case MAC_STAT_LINK_UP:
		val = statsp->mac_stats.link_up;
		break;
	case MAC_STAT_PROMISC:
		val = statsp->mac_stats.promisc;
		break;
	case ETHER_STAT_SQE_ERRORS:
		val = 0;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		/*
		 * No similar error in Hydra receive channels
		 */
		val = 0;
		break;

	case ETHER_STAT_FCS_ERRORS:
		/*
		 * No similar error in Hydra receive channels
		 */
		val = 0;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		val = 0;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		val = 0;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		val = 0;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		val = 0;
		break;

	case ETHER_STAT_DEFER_XMTS:
		val = 0;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		/*
		 * A count of frames for which transmission on a
		 * particular interface fails due to an internal
		 * MAC sublayer transmit error
		 */
		for (channel = 0; channel < hxgep->ntdc; channel++) {
			tx_stats = &statsp->tdc_stats[channel];
			val += tx_stats->pkt_size_hdr_err +
			    tx_stats->pkt_size_err +
			    tx_stats->tx_rng_oflow +
			    tx_stats->peu_resp_err +
			    tx_stats->runt_pkt_drop_err +
			    tx_stats->pref_par_err +
			    tx_stats->tdr_pref_cpl_to +
			    tx_stats->pkt_cpl_to +
			    tx_stats->invalid_sop +
			    tx_stats->unexpected_sop;
		}
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		/*
		 * The number of times that the carrier sense
		 * condition was lost or never asserted when
		 * attempting to transmit a frame on a particular interface
		 */
		for (channel = 0; channel < hxgep->ntdc; channel++) {
			tx_stats = &statsp->tdc_stats[channel];
			val += tx_stats->tdr_pref_cpl_to + tx_stats->pkt_cpl_to;
		}
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		/*
		 * A count of frames received on a particular
		 * interface that exceed the maximum permitted frame size
		 */
		for (channel = 0; channel < hxgep->ntdc; channel++) {
			tx_stats = &statsp->tdc_stats[channel];
			val += tx_stats->pkt_size_err;
		}
		break;

	case ETHER_STAT_XCVR_ADDR:
		val = 0;
		break;
	case ETHER_STAT_XCVR_ID:
		val = 0;
		break;

	case ETHER_STAT_XCVR_INUSE:
		val = 0;
		break;

	case ETHER_STAT_CAP_1000FDX:
		val = 0;
		break;

	case ETHER_STAT_CAP_1000HDX:
		val = 0;
		break;

	case ETHER_STAT_CAP_100FDX:
		val = 0;
		break;

	case ETHER_STAT_CAP_100HDX:
		val = 0;
		break;

	case ETHER_STAT_CAP_10FDX:
		val = 0;
		break;

	case ETHER_STAT_CAP_10HDX:
		val = 0;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		val = 0;
		break;

	case ETHER_STAT_CAP_PAUSE:
		val = 0;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		val = 0;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		val = 0;
		break;

	case ETHER_STAT_LINK_PAUSE:
		val = 0;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		val = 0;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		val = statsp->mac_stats.link_duplex;
		break;

	case ETHER_STAT_TOOSHORT_ERRORS:
		val = 0;
		break;

	case ETHER_STAT_CAP_REMFAULT:
		val = 0;
		break;

	case ETHER_STAT_ADV_REMFAULT:
		val = 0;
		break;

	case ETHER_STAT_LP_REMFAULT:
		val = 0;
		break;

	case ETHER_STAT_JABBER_ERRORS:
		val = 0;
		break;

	case ETHER_STAT_CAP_100T4:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_100T4:
		val = 0;
		break;

	case ETHER_STAT_LP_CAP_100T4:
		val = 0;
		break;

	case ETHER_STAT_ADV_CAP_10GFDX:
	case ETHER_STAT_CAP_10GFDX:
	case ETHER_STAT_LP_CAP_10GFDX:
		val = 0;
		break;

	default:
		/*
		 * Shouldn't reach here...
		 */
		cmn_err(CE_WARN,
		    "hxge_m_stat: unrecognized parameter value = 0x%x", stat);
		return (ENOTSUP);
	}
	*value = val;
	return (0);
}

static uint64_t
hxge_mac_octet_to_u64(uint8_t *addr)
{
	int		i;
	uint64_t	addr64 = 0;

	for (i = ETHERADDRL - 1; i >= 0; i--) {
		addr64 <<= 8;
		addr64 |= addr[i];
	}
	return (addr64);
}

/*ARGSUSED*/
static int
hxge_mmac_stat_update(kstat_t *ksp, int rw)
{
	p_hxge_t		hxgep;
	p_hxge_mmac_kstat_t	mmac_kstatsp;

	hxgep = (p_hxge_t)ksp->ks_private;
	if (hxgep == NULL)
		return (-1);

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "==> hxge_mmac_stat_update"));

	if (rw == KSTAT_WRITE) {
		cmn_err(CE_WARN, "Can not write mmac stats");
	} else {
		MUTEX_ENTER(hxgep->genlock);
		mmac_kstatsp = (p_hxge_mmac_kstat_t)ksp->ks_data;
		mmac_kstatsp->mmac_max_addr_cnt.value.ul = hxgep->mmac.total;
		mmac_kstatsp->mmac_avail_addr_cnt.value.ul =
		    hxgep->mmac.available;
		mmac_kstatsp->mmac_addr1.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[0].addr);
		mmac_kstatsp->mmac_addr2.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[1].addr);
		mmac_kstatsp->mmac_addr3.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[2].addr);
		mmac_kstatsp->mmac_addr4.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[3].addr);
		mmac_kstatsp->mmac_addr5.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[4].addr);
		mmac_kstatsp->mmac_addr6.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[5].addr);
		mmac_kstatsp->mmac_addr7.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[6].addr);
		mmac_kstatsp->mmac_addr8.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[7].addr);
		mmac_kstatsp->mmac_addr9.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[8].addr);
		mmac_kstatsp->mmac_addr10.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[9].addr);
		mmac_kstatsp->mmac_addr11.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[10].addr);
		mmac_kstatsp->mmac_addr12.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[11].addr);
		mmac_kstatsp->mmac_addr13.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[12].addr);
		mmac_kstatsp->mmac_addr14.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[13].addr);
		mmac_kstatsp->mmac_addr15.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[14].addr);
		mmac_kstatsp->mmac_addr16.value.ul =
		    hxge_mac_octet_to_u64(hxgep->mmac.addrs[15].addr);
		MUTEX_EXIT(hxgep->genlock);
	}

	HXGE_DEBUG_MSG((hxgep, KST_CTL, "<== hxge_mmac_stat_update"));
	return (0);
}
