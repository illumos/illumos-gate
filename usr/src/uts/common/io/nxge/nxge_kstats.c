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

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_hio.h>

#include <inet/mi.h>

#define	RDC_NAME_FORMAT1	"RDC Channel"
#define	TDC_NAME_FORMAT1	"TDC Channel"
#define	CH_NAME_FORMAT		" %d Stats"
#define	TDC_NAME_FORMAT		"TDC Channel %d Stats"
#define	RDC_NAME_FORMAT		"RDC Channel %d Stats"

void nxge_mac_init_kstats(p_nxge_t, struct kstat *);
void nxge_xmac_init_kstats(struct kstat *);
void nxge_bmac_init_kstats(struct kstat *);

/* ARGSUSED */
void
nxge_init_statsp(p_nxge_t nxgep)
{
	size_t stats_size;

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_init_statsp"));

	stats_size = sizeof (nxge_stats_t);
	nxgep->statsp = KMEM_ZALLOC(stats_size, KM_SLEEP);
	nxgep->statsp->stats_size = stats_size;

	NXGE_DEBUG_MSG((nxgep, KST_CTL, " <== nxge_init_statsp"));
}

typedef struct {
	uint8_t index;
	uint8_t type;
	char *name;
} nxge_kstat_index_t;

typedef enum {
	RDC_STAT_PACKETS = 0,
	RDC_STAT_BYTES,
	RDC_STAT_ERRORS,
	RDC_STAT_DCF_ERR,
	RDC_STAT_RCR_ACK_ERR,
	RDC_STAT_RCR_DC_FIFOFLOW_ERR,
	RDC_STAT_RCR_SHA_PAR_ERR,
	RDC_STAT_RBR_PRE_PAR_ERR,
	RDC_STAT_WRED_DROP,
	RDC_STAT_RBR_PRE_EMTY,
	RDC_STAT_RCR_SHADOW_FULL,
	RDC_STAT_RBR_TMOUT,
	RDC_STAT_RSP_CNT_ERR,
	RDC_STAT_BYTE_EN_BUS,
	RDC_STAT_RSP_DAT_ERR,
	RDC_STAT_PKT_TOO_LONG_ERR,
	RDC_STAT_COMPL_L2_ERR,
	RDC_STAT_COMPL_L4_CKSUM_ERR,
	RDC_STAT_COMPL_ZCP_SOFT_ERR,
	RDC_STAT_COMPL_FFLP_SOFT_ERR,
	RDC_STAT_CONFIG_ERR,
	RDC_STAT_RCRINCON,
	RDC_STAT_RCRFULL,
	RDC_STAT_RBR_EMPTY,
	RDC_STAT_RBR_FULL,
	RDC_STAT_RBRLOGPAGE,
	RDC_STAT_CFIGLOGPAGE,
	RDC_STAT_PORT_DROP_PKT,
	RDC_STAT_RCRTO,
	RDC_STAT_RCRTHRES,
	RDC_STAT_MEX,
	RDC_STAT_ID_MIS,
	RDC_STAT_ZCP_EOP,
	RDC_STAT_IPP_EOP,
	RDC_STAT_END
} nxge_rdc_stat_index_t;

nxge_kstat_index_t nxge_rdc_stats[] = {
	{RDC_STAT_PACKETS, KSTAT_DATA_UINT64, "rdc_packets"},
	{RDC_STAT_BYTES, KSTAT_DATA_UINT64, "rdc_bytes"},
	{RDC_STAT_ERRORS, KSTAT_DATA_ULONG, "rdc_errors"},
	{RDC_STAT_DCF_ERR, KSTAT_DATA_ULONG, "rdc_dcf_err"},
	{RDC_STAT_RCR_ACK_ERR, KSTAT_DATA_ULONG, "rdc_rcr_ack_err"},
	{RDC_STAT_RCR_DC_FIFOFLOW_ERR, KSTAT_DATA_ULONG, "rdc_dc_fifoflow_err"},
	{RDC_STAT_RCR_SHA_PAR_ERR, KSTAT_DATA_ULONG, "rdc_rcr_sha_par_err"},
	{RDC_STAT_RBR_PRE_PAR_ERR, KSTAT_DATA_ULONG, "rdc_rbr_pre_par_err"},
	{RDC_STAT_WRED_DROP, KSTAT_DATA_ULONG, "rdc_wred_drop"},
	{RDC_STAT_RBR_PRE_EMTY, KSTAT_DATA_ULONG, "rdc_rbr_pre_empty"},
	{RDC_STAT_RCR_SHADOW_FULL, KSTAT_DATA_ULONG, "rdc_rcr_shadow_full"},
	{RDC_STAT_RBR_TMOUT, KSTAT_DATA_ULONG, "rdc_rbr_tmout"},
	{RDC_STAT_RSP_CNT_ERR, KSTAT_DATA_ULONG, "rdc_rsp_cnt_err"},
	{RDC_STAT_BYTE_EN_BUS, KSTAT_DATA_ULONG, "rdc_byte_en_bus"},
	{RDC_STAT_RSP_DAT_ERR, KSTAT_DATA_ULONG, "rdc_rsp_dat_err"},
	{RDC_STAT_PKT_TOO_LONG_ERR, KSTAT_DATA_ULONG, "rdc_pkt_too_long_err"},
	{RDC_STAT_COMPL_L2_ERR, KSTAT_DATA_ULONG, "rdc_compl_l2_err"},
	{RDC_STAT_COMPL_L4_CKSUM_ERR, KSTAT_DATA_ULONG, "rdc_compl_l4_cksum"},
	{RDC_STAT_COMPL_ZCP_SOFT_ERR, KSTAT_DATA_ULONG,
		"rdc_compl_zcp_soft_err"},
	{RDC_STAT_COMPL_FFLP_SOFT_ERR, KSTAT_DATA_ULONG,
		"rdc_compl_fflp_soft_err"},
	{RDC_STAT_CONFIG_ERR, KSTAT_DATA_ULONG, "rdc_config_err"},
	{RDC_STAT_RCRINCON, KSTAT_DATA_ULONG, "rdc_rcrincon"},
	{RDC_STAT_RCRFULL, KSTAT_DATA_ULONG, "rdc_rcrfull"},
	{RDC_STAT_RBR_EMPTY, KSTAT_DATA_ULONG, "rdc_rbr_empty"},
	{RDC_STAT_RBR_FULL, KSTAT_DATA_ULONG, "rdc_rbrfull"},
	{RDC_STAT_RBRLOGPAGE, KSTAT_DATA_ULONG, "rdc_rbrlogpage"},
	{RDC_STAT_CFIGLOGPAGE, KSTAT_DATA_ULONG, "rdc_cfiglogpage"},
	{RDC_STAT_PORT_DROP_PKT, KSTAT_DATA_ULONG, "rdc_port_drop_pkt"},
	{RDC_STAT_RCRTO, KSTAT_DATA_ULONG, "rdc_rcrto"},
	{RDC_STAT_RCRTHRES, KSTAT_DATA_ULONG, "rdc_rcrthres"},
	{RDC_STAT_MEX, KSTAT_DATA_ULONG, "rdc_mex"},
	{RDC_STAT_ID_MIS, KSTAT_DATA_ULONG, "rdc_id_mismatch"},
	{RDC_STAT_ZCP_EOP, KSTAT_DATA_ULONG, "rdc_zcp_eop"},
	{RDC_STAT_IPP_EOP, KSTAT_DATA_ULONG, "rdc_ipp_eop"},
	{RDC_STAT_END, NULL, NULL}
};

typedef enum {
	RDC_SYS_STAT_PRE_PAR_ERR = 0,
	RDC_SYS_STAT_SHA_PAR_ERR,
	RDC_SYS_STAT_ID_MISMATCH,
	RDC_SYS_STAT_IPP_EOP_ERR,
	RDC_SYS_STAT_ZCP_EOP_ERR,
	RDC_SYS_STAT_END
} nxge_rdc_sys_stat_idx_t;

nxge_kstat_index_t nxge_rdc_sys_stats[] = {
	{RDC_SYS_STAT_PRE_PAR_ERR, KSTAT_DATA_UINT64, "rdc_pre_par_err"},
	{RDC_SYS_STAT_SHA_PAR_ERR, KSTAT_DATA_UINT64, "rdc_sha_par_err"},
	{RDC_SYS_STAT_ID_MISMATCH, KSTAT_DATA_UINT64, "rdc_stat_id_mismatch"},
	{RDC_SYS_STAT_IPP_EOP_ERR, KSTAT_DATA_UINT64, "rdc_ipp_eop_err"},
	{RDC_SYS_STAT_ZCP_EOP_ERR, KSTAT_DATA_UINT64, "rdc_zcp_eop_err"},
	{RDC_SYS_STAT_END, NULL, NULL}
};

typedef enum {
	TDC_STAT_PACKETS = 0,
	TDC_STAT_BYTES,
	TDC_STAT_ERRORS,
	TDC_STAT_TX_INITS,
	TDC_STAT_TX_NO_BUF,
	TDC_STAT_MBOX_ERR,
	TDC_STAT_PKT_SIZE_ERR,
	TDC_STAT_TX_RING_OFLOW,
	TDC_STAT_PREF_BUF_ECC_ERR,
	TDC_STAT_NACK_PREF,
	TDC_STAT_NACK_PKT_RD,
	TDC_STAT_CONF_PART_ERR,
	TDC_STAT_PKT_PRT_ERR,
	TDC_STAT_RESET_FAIL,
	TDC_STAT_TX_STARTS,
	TDC_STAT_TX_NOCANPUT,
	TDC_STAT_TX_MSGDUP_FAIL,
	TDC_STAT_TX_ALLOCB_FAIL,
	TDC_STAT_TX_NO_DESC,
	TDC_STAT_TX_DMA_BIND_FAIL,
	TDC_STAT_TX_UFLOW,
	TDC_STAT_TX_HDR_PKTS,
	TDC_STAT_TX_DDI_PKTS,
	TDC_STAT_TX_DVMA_PKTS,
	TDC_STAT_TX_MAX_PEND,
	TDC_STAT_END
} nxge_tdc_stats_index_t;

nxge_kstat_index_t nxge_tdc_stats[] = {
	{TDC_STAT_PACKETS, KSTAT_DATA_UINT64, "tdc_packets"},
	{TDC_STAT_BYTES, KSTAT_DATA_UINT64, "tdc_bytes"},
	{TDC_STAT_ERRORS, KSTAT_DATA_UINT64, "tdc_errors"},
	{TDC_STAT_TX_INITS, KSTAT_DATA_ULONG, "tdc_tx_inits"},
	{TDC_STAT_TX_NO_BUF, KSTAT_DATA_ULONG, "tdc_tx_no_buf"},
	{TDC_STAT_MBOX_ERR, KSTAT_DATA_ULONG, "tdc_mbox_err"},
	{TDC_STAT_PKT_SIZE_ERR, KSTAT_DATA_ULONG, "tdc_pkt_size_err"},
	{TDC_STAT_TX_RING_OFLOW,
		KSTAT_DATA_ULONG, "tdc_tx_ring_oflow"},
	{TDC_STAT_PREF_BUF_ECC_ERR,
		KSTAT_DATA_ULONG, "tdc_pref_buf_err_err"},
	{TDC_STAT_NACK_PREF, KSTAT_DATA_ULONG, "tdc_nack_pref"},
	{TDC_STAT_NACK_PKT_RD, KSTAT_DATA_ULONG, "tdc_nack_pkt_rd"},
	{TDC_STAT_CONF_PART_ERR,
		KSTAT_DATA_ULONG, "tdc_conf_part_err"},
	{TDC_STAT_PKT_PRT_ERR, KSTAT_DATA_ULONG, "tdc_pkt_prt_err"},
	{TDC_STAT_RESET_FAIL, KSTAT_DATA_ULONG, "tdc_reset_fail"},
	{TDC_STAT_TX_STARTS, KSTAT_DATA_ULONG, "tdc_tx_starts"},
	{TDC_STAT_TX_NOCANPUT, KSTAT_DATA_ULONG, "tdc_tx_nocanput"},
	{TDC_STAT_TX_MSGDUP_FAIL, KSTAT_DATA_ULONG, "tdc_tx_msgdup_fail"},
	{TDC_STAT_TX_ALLOCB_FAIL, KSTAT_DATA_ULONG, "tdc_tx_allocb_fail"},
	{TDC_STAT_TX_NO_DESC, KSTAT_DATA_ULONG, "tdc_tx_no_desc"},
	{TDC_STAT_TX_DMA_BIND_FAIL, KSTAT_DATA_ULONG, "tdc_tx_dma_bind_fail"},
	{TDC_STAT_TX_UFLOW, KSTAT_DATA_ULONG, "tdc_tx_uflow"},
	{TDC_STAT_TX_HDR_PKTS, KSTAT_DATA_ULONG, "tdc_tx_hdr_pkts"},
	{TDC_STAT_TX_DDI_PKTS, KSTAT_DATA_ULONG, "tdc_tx_ddi_pkts"},
	{TDC_STAT_TX_DVMA_PKTS, KSTAT_DATA_ULONG, "tdc_tx_dvma_pkts"},
	{TDC_STAT_TX_MAX_PEND, KSTAT_DATA_ULONG, "tdc_tx_max_pend"},
	{TDC_STAT_END, NULL, NULL}
};

/* IPP Statistics definitions */
typedef enum {
	IPP_STAT_EOP_MISS = 0,
	IPP_STAT_SOP_MISS,
	IPP_STAT_DFIFO_UE,
	IPP_STAT_ECC_ERR,
	IPP_STAT_PFIFO_PERR,
	IPP_STAT_PFIFO_OVER,
	IPP_STAT_PFIFO_UND,
	IPP_STAT_BAD_CS,
	IPP_STAT_BAD_DIS,
	IPP_STAT_END
} nxge_ipp_stat_index_t;

nxge_kstat_index_t nxge_ipp_stats[] = {
	{IPP_STAT_EOP_MISS, KSTAT_DATA_ULONG, "rxipp_eop_miss"},
	{IPP_STAT_SOP_MISS, KSTAT_DATA_ULONG, "rxipp_sop_miss"},
	{IPP_STAT_DFIFO_UE, KSTAT_DATA_ULONG, "rxipp_dfifo_ue"},
	{IPP_STAT_ECC_ERR, KSTAT_DATA_ULONG, "rxipp_ecc_err"},
	{IPP_STAT_PFIFO_PERR, KSTAT_DATA_ULONG, "rxipp_pfifo_perr"},
	{IPP_STAT_PFIFO_OVER, KSTAT_DATA_ULONG, "rxipp_pfifo_over"},
	{IPP_STAT_PFIFO_UND, KSTAT_DATA_ULONG, "rxipp_pfifo_und"},
	{IPP_STAT_BAD_CS, KSTAT_DATA_ULONG, "rxipp_bad_cs"},
	{IPP_STAT_BAD_DIS, KSTAT_DATA_ULONG, "rxipp_bad_dis"},
	{IPP_STAT_END, NULL, NULL}
};

/* TXC Statistics definitions */
typedef enum {
	TXC_STAT_PKT_STUFFED = 0,
	TXC_STAT_PKT_XMIT,
	TXC_STAT_RO_CORRECT_ERR,
	TXC_STAT_RO_UNCORRECT_ERR,
	TXC_STAT_SF_CORRECT_ERR,
	TXC_STAT_SF_UNCORRECT_ERR,
	TXC_STAT_ADDRESS_FAILED,
	TXC_STAT_DMA_FAILED,
	TXC_STAT_LENGTH_FAILED,
	TXC_STAT_PKT_ASSY_DEAD,
	TXC_STAT_REORDER_ERR,
	TXC_STAT_END
} nxge_txc_stat_index_t;

nxge_kstat_index_t nxge_txc_stats[] = {
	{TXC_STAT_PKT_STUFFED, KSTAT_DATA_ULONG, "txc_pkt_stuffed"},
	{TXC_STAT_PKT_XMIT, KSTAT_DATA_ULONG, "txc_pkt_xmit"},
	{TXC_STAT_RO_CORRECT_ERR, KSTAT_DATA_ULONG, "txc_ro_correct_err"},
	{TXC_STAT_RO_UNCORRECT_ERR, KSTAT_DATA_ULONG, "txc_ro_uncorrect_err"},
	{TXC_STAT_SF_CORRECT_ERR, KSTAT_DATA_ULONG, "txc_sf_correct_err"},
	{TXC_STAT_SF_UNCORRECT_ERR, KSTAT_DATA_ULONG, "txc_sf_uncorrect_err"},
	{TXC_STAT_ADDRESS_FAILED, KSTAT_DATA_ULONG, "txc_address_failed"},
	{TXC_STAT_DMA_FAILED, KSTAT_DATA_ULONG, "txc_dma_failed"},
	{TXC_STAT_LENGTH_FAILED, KSTAT_DATA_ULONG, "txc_length_failed"},
	{TXC_STAT_PKT_ASSY_DEAD, KSTAT_DATA_ULONG, "txc_pkt_assy_dead"},
	{TXC_STAT_REORDER_ERR, KSTAT_DATA_ULONG, "txc_reorder_err"},
	{TXC_STAT_END, NULL, NULL}
};

typedef enum {
	XMAC_STAT_TX_FRAME_CNT = 0,
	XMAC_STAT_TX_UNDERFLOW_ERR,
	XMAC_STAT_TX_MAXPKTSIZE_ERR,
	XMAC_STAT_TX_OVERFLOW_ERR,
	XMAC_STAT_TX_FIFO_XFR_ERR,
	XMAC_STAT_TX_BYTE_CNT,
	XMAC_STAT_RX_FRAME_CNT,
	XMAC_STAT_RX_UNDERFLOW_ERR,
	XMAC_STAT_RX_OVERFLOW_ERR,
	XMAC_STAT_RX_CRC_ERR_CNT,
	XMAC_STAT_RX_LEN_ERR_CNT,
	XMAC_STAT_RX_VIOL_ERR_CNT,
	XMAC_STAT_RX_BYTE_CNT,
	XMAC_STAT_RX_HIST1_CNT,
	XMAC_STAT_RX_HIST2_CNT,
	XMAC_STAT_RX_HIST3_CNT,
	XMAC_STAT_RX_HIST4_CNT,
	XMAC_STAT_RX_HIST5_CNT,
	XMAC_STAT_RX_HIST6_CNT,
	XMAC_STAT_RX_HIST7_CNT,
	XMAC_STAT_RX_BROADCAST_CNT,
	XMAC_STAT_RX_MULT_CNT,
	XMAC_STAT_RX_FRAG_CNT,
	XMAC_STAT_RX_FRAME_ALIGN_ERR_CNT,
	XMAC_STAT_RX_LINKFAULT_ERR_CNT,
	XMAC_STAT_RX_REMOTEFAULT_ERR,
	XMAC_STAT_RX_LOCALFAULT_ERR,
	XMAC_STAT_RX_PAUSE_CNT,
	XMAC_STAT_TX_PAUSE_STATE,
	XMAC_STAT_TX_NOPAUSE_STATE,
	XMAC_STAT_XPCS_DESKEW_ERR_CNT,
#ifdef	NXGE_DEBUG_SYMBOL_ERR
	XMAC_STAT_XPCS_SYMBOL_L0_ERR_CNT,
	XMAC_STAT_XPCS_SYMBOL_L1_ERR_CNT,
	XMAC_STAT_XPCS_SYMBOL_L2_ERR_CNT,
	XMAC_STAT_XPCS_SYMBOL_L3_ERR_CNT,
#endif
	XMAC_STAT_END
} nxge_xmac_stat_index_t;

nxge_kstat_index_t nxge_xmac_stats[] = {
	{XMAC_STAT_TX_FRAME_CNT, KSTAT_DATA_ULONG, "txmac_frame_cnt"},
	{XMAC_STAT_TX_UNDERFLOW_ERR, KSTAT_DATA_ULONG, "tmac_underflow_err"},
	{XMAC_STAT_TX_MAXPKTSIZE_ERR, KSTAT_DATA_ULONG, "txmac_maxpktsize_err"},
	{XMAC_STAT_TX_OVERFLOW_ERR, KSTAT_DATA_ULONG, "txmac_overflow_err"},
	{XMAC_STAT_TX_FIFO_XFR_ERR, KSTAT_DATA_ULONG, "txmac_fifo_xfr_err"},
	{XMAC_STAT_TX_BYTE_CNT, KSTAT_DATA_ULONG, "txmac_byte_cnt"},
	{XMAC_STAT_RX_FRAME_CNT, KSTAT_DATA_ULONG, "rxmac_frame_cnt"},
	{XMAC_STAT_RX_UNDERFLOW_ERR, KSTAT_DATA_ULONG, "rxmac_underflow_err"},
	{XMAC_STAT_RX_OVERFLOW_ERR, KSTAT_DATA_ULONG, "rxmac_overflow_err"},
	{XMAC_STAT_RX_CRC_ERR_CNT, KSTAT_DATA_ULONG, "rxmac_crc_err"},
	{XMAC_STAT_RX_LEN_ERR_CNT, KSTAT_DATA_ULONG, "rxmac_length_err"},
	{XMAC_STAT_RX_VIOL_ERR_CNT, KSTAT_DATA_ULONG, "rxmac_code_violations"},
	{XMAC_STAT_RX_BYTE_CNT, KSTAT_DATA_ULONG, "rxmac_byte_cnt"},
	{XMAC_STAT_RX_HIST1_CNT, KSTAT_DATA_ULONG, "rxmac_64_cnt"},
	{XMAC_STAT_RX_HIST2_CNT, KSTAT_DATA_ULONG, "rxmac_65_127_cnt"},
	{XMAC_STAT_RX_HIST3_CNT, KSTAT_DATA_ULONG, "rxmac_128_255_cnt"},
	{XMAC_STAT_RX_HIST4_CNT, KSTAT_DATA_ULONG, "rxmac_256_511_cnt"},
	{XMAC_STAT_RX_HIST5_CNT, KSTAT_DATA_ULONG, "rxmac_512_1023_cnt"},
	{XMAC_STAT_RX_HIST6_CNT, KSTAT_DATA_ULONG, "rxmac_1024_1522_cnt"},
	{XMAC_STAT_RX_HIST7_CNT, KSTAT_DATA_ULONG, "rxmac_jumbo_cnt"},
	{XMAC_STAT_RX_BROADCAST_CNT, KSTAT_DATA_ULONG, "rxmac_broadcast_cnt"},
	{XMAC_STAT_RX_MULT_CNT, KSTAT_DATA_ULONG, "rxmac_multicast_cnt"},
	{XMAC_STAT_RX_FRAG_CNT, KSTAT_DATA_ULONG, "rxmac_fragment_cnt"},
	{XMAC_STAT_RX_FRAME_ALIGN_ERR_CNT,
		KSTAT_DATA_ULONG, "rxmac_alignment_err"},
	{XMAC_STAT_RX_LINKFAULT_ERR_CNT,
		KSTAT_DATA_ULONG, "rxmac_linkfault_errs"},
	{XMAC_STAT_RX_REMOTEFAULT_ERR,
		KSTAT_DATA_ULONG, "rxmac_remote_faults"},
	{XMAC_STAT_RX_LOCALFAULT_ERR,
		KSTAT_DATA_ULONG, "rxmac_local_faults"},
	{XMAC_STAT_RX_PAUSE_CNT, KSTAT_DATA_ULONG, "rxmac_pause_cnt"},
	{XMAC_STAT_TX_PAUSE_STATE, KSTAT_DATA_ULONG, "txmac_pause_state"},
	{XMAC_STAT_TX_NOPAUSE_STATE, KSTAT_DATA_ULONG, "txmac_nopause_state"},
	{XMAC_STAT_XPCS_DESKEW_ERR_CNT,
		KSTAT_DATA_ULONG, "xpcs_deskew_err_cnt"},
#ifdef	NXGE_DEBUG_SYMBOL_ERR
	{XMAC_STAT_XPCS_SYMBOL_L0_ERR_CNT,
		KSTAT_DATA_ULONG, "xpcs_ln0_symbol_err_cnt"},
	{XMAC_STAT_XPCS_SYMBOL_L1_ERR_CNT,
		KSTAT_DATA_ULONG, "xpcs_ln1_symbol_err_cnt"},
	{XMAC_STAT_XPCS_SYMBOL_L2_ERR_CNT,
		KSTAT_DATA_ULONG, "xpcs_ln2_symbol_err_cnt"},
	{XMAC_STAT_XPCS_SYMBOL_L3_ERR_CNT,
		KSTAT_DATA_ULONG, "xpcs_ln3_symbol_err_cnt"},
#endif
	{XMAC_STAT_END, NULL, NULL}
};

typedef enum {
	BMAC_STAT_TX_FRAME_CNT = 0,
	BMAC_STAT_TX_UNDERRUN_ERR,
	BMAC_STAT_TX_MAX_PKT_ERR,
	BMAC_STAT_TX_BYTE_CNT,
	BMAC_STAT_RX_FRAME_CNT,
	BMAC_STAT_RX_BYTE_CNT,
	BMAC_STAT_RX_OVERFLOW_ERR,
	BMAC_STAT_RX_ALIGN_ERR_CNT,
	BMAC_STAT_RX_CRC_ERR_CNT,
	BMAC_STAT_RX_LEN_ERR_CNT,
	BMAC_STAT_RX_VIOL_ERR_CNT,
	BMAC_STAT_RX_PAUSE_CNT,
	BMAC_STAT_RX_PAUSE_STATE,
	BMAC_STAT_RX_NOPAUSE_STATE,
	BMAC_STAT_END
} nxge_bmac_stat_index_t;

nxge_kstat_index_t nxge_bmac_stats[] = {
	{BMAC_STAT_TX_FRAME_CNT, KSTAT_DATA_ULONG, "txmac_frame_cnt"},
	{BMAC_STAT_TX_UNDERRUN_ERR, KSTAT_DATA_ULONG, "txmac_underrun_err"},
	{BMAC_STAT_TX_MAX_PKT_ERR, KSTAT_DATA_ULONG, "txmac_max_pkt_err"},
	{BMAC_STAT_TX_BYTE_CNT, KSTAT_DATA_ULONG, "txmac_byte_cnt"},
	{BMAC_STAT_RX_FRAME_CNT, KSTAT_DATA_ULONG, "rxmac_frame_cnt"},
	{BMAC_STAT_RX_BYTE_CNT, KSTAT_DATA_ULONG, "rxmac_byte_cnt"},
	{BMAC_STAT_RX_OVERFLOW_ERR, KSTAT_DATA_ULONG, "rxmac_overflow_err"},
	{BMAC_STAT_RX_ALIGN_ERR_CNT, KSTAT_DATA_ULONG, "rxmac_align_err_cnt"},
	{BMAC_STAT_RX_CRC_ERR_CNT, KSTAT_DATA_ULONG, "rxmac_crc_err_cnt"},
	{BMAC_STAT_RX_LEN_ERR_CNT, KSTAT_DATA_ULONG, "rxmac_len_err_cnt"},
	{BMAC_STAT_RX_VIOL_ERR_CNT, KSTAT_DATA_ULONG, "rxmac_viol_err_cnt"},
	{BMAC_STAT_RX_PAUSE_CNT, KSTAT_DATA_ULONG, "rxmac_pause_cnt"},
	{BMAC_STAT_RX_PAUSE_STATE, KSTAT_DATA_ULONG, "txmac_pause_state"},
	{BMAC_STAT_RX_NOPAUSE_STATE, KSTAT_DATA_ULONG, "tx_nopause_state"},
	{BMAC_STAT_END, NULL, NULL}
};

typedef enum {
	ZCP_STAT_ERRORS,
	ZCP_STAT_INITS,
	ZCP_STAT_RRFIFO_UNDERRUN,
	ZCP_STAT_RRFIFO_OVERRUN,
	ZCP_STAT_RSPFIFO_UNCORR_ERR,
	ZCP_STAT_BUFFER_OVERFLOW,
	ZCP_STAT_STAT_TBL_PERR,
	ZCP_STAT_DYN_TBL_PERR,
	ZCP_STAT_BUF_TBL_PERR,
	ZCP_STAT_TT_PROGRAM_ERR,
	ZCP_STAT_RSP_TT_INDEX_ERR,
	ZCP_STAT_SLV_TT_INDEX_ERR,
	ZCP_STAT_ZCP_TT_INDEX_ERR,
	ZCP_STAT_ZCP_ACCESS_FAIL,
	ZCP_CFIFO_ECC,
	ZCP_STAT_END
} nxge_zcp_stat_index_t;

nxge_kstat_index_t nxge_zcp_stats[] = {
	{ZCP_STAT_ERRORS, KSTAT_DATA_ULONG, "zcp_erros"},
	{ZCP_STAT_INITS, KSTAT_DATA_ULONG, "zcp_inits"},
	{ZCP_STAT_RRFIFO_UNDERRUN, KSTAT_DATA_ULONG, "zcp_rrfifo_underrun"},
	{ZCP_STAT_RRFIFO_OVERRUN, KSTAT_DATA_ULONG, "zcp_rrfifo_overrun"},
	{ZCP_STAT_RSPFIFO_UNCORR_ERR, KSTAT_DATA_ULONG,
	"zcp_rspfifo_uncorr_err"},
	{ZCP_STAT_BUFFER_OVERFLOW, KSTAT_DATA_ULONG, "zcp_buffer_overflow"},
	{ZCP_STAT_STAT_TBL_PERR, KSTAT_DATA_ULONG, "zcp_stat_tbl_perr"},
	{ZCP_STAT_DYN_TBL_PERR, KSTAT_DATA_ULONG, "zcp_dyn_tbl_perr"},
	{ZCP_STAT_BUF_TBL_PERR, KSTAT_DATA_ULONG, "zcp_buf_tbl_perr"},
	{ZCP_STAT_TT_PROGRAM_ERR, KSTAT_DATA_ULONG, "zcp_tt_program_err"},
	{ZCP_STAT_RSP_TT_INDEX_ERR, KSTAT_DATA_ULONG, "zcp_rsp_tt_index_err"},
	{ZCP_STAT_SLV_TT_INDEX_ERR, KSTAT_DATA_ULONG, "zcp_slv_tt_index_err"},
	{ZCP_STAT_ZCP_TT_INDEX_ERR, KSTAT_DATA_ULONG, "zcp_zcp_tt_index_err"},
	{ZCP_STAT_ZCP_ACCESS_FAIL, KSTAT_DATA_ULONG, "zcp_access_fail"},
	{ZCP_STAT_ZCP_ACCESS_FAIL, KSTAT_DATA_ULONG, "zcp_cfifo_ecc"},
	{ZCP_STAT_END, NULL, NULL}
};

typedef enum {
	FFLP_STAT_TCAM_PERR,
	FFLP_STAT_TCAM_ECC_ERR,
	FFLP_STAT_VLAN_PERR,
	FFLP_STAT_HASH_LOOKUP_ERR,
	FFLP_STAT_HASH_P0_PIO_ERR,
	FFLP_STAT_HASH_P1_PIO_ERR,
	FFLP_STAT_HASH_P2_PIO_ERR,
	FFLP_STAT_HASH_P3_PIO_ERR,
	FFLP_STAT_HASH_P4_PIO_ERR,
	FFLP_STAT_HASH_P5_PIO_ERR,
	FFLP_STAT_HASH_P6_PIO_ERR,
	FFLP_STAT_HASH_P7_PIO_ERR,
	FFLP_STAT_END
} nxge_fflp_stat_index_t;

nxge_kstat_index_t nxge_fflp_stats[] = {
	{FFLP_STAT_TCAM_PERR, KSTAT_DATA_ULONG, "fflp_tcam_perr"},
	{FFLP_STAT_TCAM_ECC_ERR, KSTAT_DATA_ULONG, "fflp_tcam_ecc_err"},
	{FFLP_STAT_VLAN_PERR, KSTAT_DATA_ULONG, "fflp_vlan_perr"},
	{FFLP_STAT_HASH_LOOKUP_ERR, KSTAT_DATA_ULONG, "fflp_hash_lookup_err"},
	{FFLP_STAT_HASH_P0_PIO_ERR, KSTAT_DATA_ULONG, "fflp_hash_p0_pio_err"},
	{FFLP_STAT_HASH_P1_PIO_ERR, KSTAT_DATA_ULONG, "fflp_hash_p1_pio_err"},
	{FFLP_STAT_HASH_P2_PIO_ERR, KSTAT_DATA_ULONG, "fflp_hash_p2_pio_err"},
	{FFLP_STAT_HASH_P3_PIO_ERR, KSTAT_DATA_ULONG, "fflp_hash_p3_pio_err"},
	{FFLP_STAT_HASH_P4_PIO_ERR, KSTAT_DATA_ULONG, "fflp_hash_p4_pio_err"},
	{FFLP_STAT_HASH_P5_PIO_ERR, KSTAT_DATA_ULONG, "fflp_hash_p5_pio_err"},
	{FFLP_STAT_HASH_P6_PIO_ERR, KSTAT_DATA_ULONG, "fflp_hash_p6_pio_err"},
	{FFLP_STAT_HASH_P7_PIO_ERR, KSTAT_DATA_ULONG, "fflp_hash_p7_pio_err"},
	{FFLP_STAT_END, NULL, NULL}
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
} nxge_mmac_stat_index_t;

nxge_kstat_index_t nxge_mmac_stats[] = {
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
nxge_tdc_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_tdc_kstat_t tdc_kstatsp;
	p_nxge_tx_ring_stats_t statsp;
	int channel;
	char *ch_name, *end;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_rxstat_update"));

	ch_name = ksp->ks_name;
	ch_name += strlen(TDC_NAME_FORMAT1);
	channel = mi_strtol(ch_name, &end, 10);

	tdc_kstatsp = (p_nxge_tdc_kstat_t)ksp->ks_data;
	statsp = (p_nxge_tx_ring_stats_t)&nxgep->statsp->tdc_stats[channel];

	NXGE_DEBUG_MSG((nxgep, KST_CTL,
	    "nxge_tdc_stat_update data $%p statsp $%p channel %d",
	    ksp->ks_data, statsp, channel));

	if (rw == KSTAT_WRITE) {
		statsp->opackets = tdc_kstatsp->opackets.value.ull;
		statsp->obytes = tdc_kstatsp->obytes.value.ull;
		statsp->oerrors = tdc_kstatsp->oerrors.value.ull;
		statsp->mbox_err = tdc_kstatsp->mbox_err.value.ul;
		statsp->pkt_size_err = tdc_kstatsp->pkt_size_err.value.ul;
		statsp->tx_ring_oflow = tdc_kstatsp->tx_ring_oflow.value.ul;
		statsp->pre_buf_par_err =
		    tdc_kstatsp->pref_buf_ecc_err.value.ul;
		statsp->nack_pref = tdc_kstatsp->nack_pref.value.ul;
		statsp->nack_pkt_rd = tdc_kstatsp->nack_pkt_rd.value.ul;
		statsp->conf_part_err = tdc_kstatsp->conf_part_err.value.ul;
		statsp->pkt_part_err = tdc_kstatsp->pkt_prt_err.value.ul;
	} else {
		tdc_kstatsp->opackets.value.ull = statsp->opackets;
		tdc_kstatsp->obytes.value.ull = statsp->obytes;
		tdc_kstatsp->oerrors.value.ull = statsp->oerrors;
		tdc_kstatsp->tx_hdr_pkts.value.ull = statsp->tx_hdr_pkts;
		tdc_kstatsp->tx_ddi_pkts.value.ull = statsp->tx_ddi_pkts;
		tdc_kstatsp->tx_dvma_pkts.value.ull = statsp->tx_dvma_pkts;
		tdc_kstatsp->tx_max_pend.value.ull = statsp->tx_max_pend;
		tdc_kstatsp->mbox_err.value.ul = statsp->mbox_err;
		tdc_kstatsp->pkt_size_err.value.ul = statsp->pkt_size_err;
		tdc_kstatsp->tx_ring_oflow.value.ul = statsp->tx_ring_oflow;
		tdc_kstatsp->pref_buf_ecc_err.value.ul =
		    statsp->pre_buf_par_err;
		tdc_kstatsp->nack_pref.value.ul = statsp->nack_pref;
		tdc_kstatsp->nack_pkt_rd.value.ul = statsp->nack_pkt_rd;
		tdc_kstatsp->conf_part_err.value.ul = statsp->conf_part_err;
		tdc_kstatsp->pkt_prt_err.value.ul = statsp->pkt_part_err;
		tdc_kstatsp->tx_starts.value.ul = statsp->tx_starts;
		tdc_kstatsp->tx_nocanput.value.ul = statsp->tx_nocanput;
		tdc_kstatsp->tx_msgdup_fail.value.ul = statsp->tx_msgdup_fail;
		tdc_kstatsp->tx_allocb_fail.value.ul = statsp->tx_allocb_fail;
		tdc_kstatsp->tx_no_desc.value.ul = statsp->tx_no_desc;
		tdc_kstatsp->tx_dma_bind_fail.value.ul =
		    statsp->tx_dma_bind_fail;
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, " <== nxge_tdc_stat_update"));
	return (0);
}

/* ARGSUSED */
int
nxge_rdc_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_rdc_kstat_t rdc_kstatsp;
	p_nxge_rx_ring_stats_t statsp;
	int channel;
	char *ch_name, *end;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_rdc_stat_update"));

	ch_name = ksp->ks_name;
	ch_name += strlen(RDC_NAME_FORMAT1);
	channel = mi_strtol(ch_name, &end, 10);

	rdc_kstatsp = (p_nxge_rdc_kstat_t)ksp->ks_data;
	statsp = (p_nxge_rx_ring_stats_t)&nxgep->statsp->rdc_stats[channel];

	NXGE_DEBUG_MSG((nxgep, KST_CTL,
	    "nxge_rdc_stat_update $%p statsp $%p channel %d",
	    ksp->ks_data, statsp, channel));

	if (rw == KSTAT_WRITE) {
		statsp->dcf_err = rdc_kstatsp->dcf_err.value.ul;
		statsp->rcr_ack_err = rdc_kstatsp->rcr_ack_err.value.ul;
		statsp->dc_fifo_err = rdc_kstatsp->dc_fifoflow_err.value.ul;
		statsp->rcr_sha_par = rdc_kstatsp->rcr_sha_par_err.value.ul;
		statsp->rbr_pre_par = rdc_kstatsp->rbr_pre_par_err.value.ul;
		statsp->wred_drop = rdc_kstatsp->wred_drop.value.ul;
		statsp->rbr_pre_empty = rdc_kstatsp->rbr_pre_emty.value.ul;
		statsp->rcr_shadow_full = rdc_kstatsp->rcr_shadow_full.value.ul;
		statsp->rx_rbr_tmout = rdc_kstatsp->rbr_tmout.value.ul;
		statsp->rsp_cnt_err = rdc_kstatsp->rsp_cnt_err.value.ul;
		statsp->byte_en_bus = rdc_kstatsp->byte_en_bus.value.ul;
		statsp->rsp_dat_err = rdc_kstatsp->rsp_dat_err.value.ul;
		statsp->pkt_too_long_err =
		    rdc_kstatsp->pkt_too_long_err.value.ul;
		statsp->l2_err = rdc_kstatsp->compl_l2_err.value.ul;
		statsp->l4_cksum_err = rdc_kstatsp->compl_l4_cksum_err.value.ul;
		statsp->fflp_soft_err =
		    rdc_kstatsp->compl_fflp_soft_err.value.ul;
		statsp->zcp_soft_err = rdc_kstatsp->compl_zcp_soft_err.value.ul;
		statsp->config_err = rdc_kstatsp->config_err.value.ul;
		statsp->rcrincon = rdc_kstatsp->rcrincon.value.ul;
		statsp->rcrfull = rdc_kstatsp->rcrfull.value.ul;
		statsp->rbr_empty = rdc_kstatsp->rbr_empty.value.ul;
		statsp->rbrfull = rdc_kstatsp->rbrfull.value.ul;
		statsp->rbrlogpage = rdc_kstatsp->rbrlogpage.value.ul;
		statsp->cfiglogpage = rdc_kstatsp->cfiglogpage.value.ul;
	} else {
		rdc_kstatsp->ipackets.value.ull = statsp->ipackets;
		rdc_kstatsp->rbytes.value.ull = statsp->ibytes;
		rdc_kstatsp->errors.value.ul = statsp->ierrors;
		rdc_kstatsp->dcf_err.value.ul = statsp->dcf_err;
		rdc_kstatsp->rcr_ack_err.value.ul = statsp->rcr_ack_err;
		rdc_kstatsp->dc_fifoflow_err.value.ul = statsp->dc_fifo_err;
		rdc_kstatsp->rcr_sha_par_err.value.ul = statsp->rcr_sha_par;
		rdc_kstatsp->rbr_pre_par_err.value.ul = statsp->rbr_pre_par;
		rdc_kstatsp->wred_drop.value.ul = statsp->wred_drop;
		rdc_kstatsp->port_drop_pkt.value.ul = statsp->port_drop_pkt;
		rdc_kstatsp->rbr_pre_emty.value.ul = statsp->rbr_pre_empty;
		rdc_kstatsp->rcr_shadow_full.value.ul = statsp->rcr_shadow_full;
		rdc_kstatsp->rbr_tmout.value.ul = statsp->rx_rbr_tmout;
		rdc_kstatsp->rsp_cnt_err.value.ul = statsp->rsp_cnt_err;
		rdc_kstatsp->byte_en_bus.value.ul = statsp->byte_en_bus;
		rdc_kstatsp->rsp_dat_err.value.ul = statsp->rsp_dat_err;
		rdc_kstatsp->pkt_too_long_err.value.ul =
		    statsp->pkt_too_long_err;
		rdc_kstatsp->compl_l2_err.value.ul = statsp->l2_err;
		rdc_kstatsp->compl_l4_cksum_err.value.ul = statsp->l4_cksum_err;
		rdc_kstatsp->compl_fflp_soft_err.value.ul =
		    statsp->fflp_soft_err;
		rdc_kstatsp->compl_zcp_soft_err.value.ul = statsp->zcp_soft_err;
		rdc_kstatsp->config_err.value.ul = statsp->config_err;
		rdc_kstatsp->rcrincon.value.ul = statsp->rcrincon;
		rdc_kstatsp->rcrfull.value.ul = statsp->rcrfull;
		rdc_kstatsp->rbr_empty.value.ul = statsp->rbr_empty;
		rdc_kstatsp->rbrfull.value.ul = statsp->rbrfull;
		rdc_kstatsp->rbrlogpage.value.ul = statsp->rbrlogpage;
		rdc_kstatsp->cfiglogpage.value.ul = statsp->cfiglogpage;
	}

	NXGE_DEBUG_MSG((nxgep, KST_CTL, " <== nxge_rdc_stat_update"));
	return (0);
}

/* ARGSUSED */
int
nxge_rdc_sys_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_rdc_sys_kstat_t rdc_sys_kstatsp;
	p_nxge_rdc_sys_stats_t statsp;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_rdc_sys_stat_update"));

	rdc_sys_kstatsp = (p_nxge_rdc_sys_kstat_t)ksp->ks_data;
	statsp = (p_nxge_rdc_sys_stats_t)&nxgep->statsp->rdc_sys_stats;

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "nxge_rdc_sys_stat_update %llx",
	    ksp->ks_data));

	if (rw == KSTAT_WRITE) {
		statsp->id_mismatch = rdc_sys_kstatsp->id_mismatch.value.ul;
		statsp->ipp_eop_err = rdc_sys_kstatsp->ipp_eop_err.value.ul;
		statsp->zcp_eop_err = rdc_sys_kstatsp->zcp_eop_err.value.ul;
	} else {
		rdc_sys_kstatsp->id_mismatch.value.ul = statsp->id_mismatch;
		rdc_sys_kstatsp->ipp_eop_err.value.ul = statsp->ipp_eop_err;
		rdc_sys_kstatsp->zcp_eop_err.value.ul = statsp->zcp_eop_err;
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, " <== nxge_rdc_sys_stat_update"));
	return (0);
}

/* ARGSUSED */
static int
nxge_txc_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_txc_kstat_t txc_kstatsp;
	p_nxge_txc_stats_t statsp;

	nxgep = (p_nxge_t)ksp->ks_private;

	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_txc_stat_update"));

	txc_kstatsp = (p_nxge_txc_kstat_t)ksp->ks_data;
	statsp = (p_nxge_txc_stats_t)&nxgep->statsp->txc_stats;

	if (rw == KSTAT_WRITE) {
		statsp->pkt_stuffed = txc_kstatsp->pkt_stuffed.value.ul;
		statsp->pkt_xmit = txc_kstatsp->pkt_xmit.value.ul;
		statsp->ro_correct_err = txc_kstatsp->ro_correct_err.value.ul;
		statsp->ro_uncorrect_err =
		    txc_kstatsp->ro_uncorrect_err.value.ul;
		statsp->sf_correct_err = txc_kstatsp->sf_correct_err.value.ul;
		statsp->sf_uncorrect_err =
		    txc_kstatsp->sf_uncorrect_err.value.ul;
		statsp->address_failed = txc_kstatsp->address_failed.value.ul;
		statsp->dma_failed = txc_kstatsp->dma_failed.value.ul;
		statsp->length_failed = txc_kstatsp->length_failed.value.ul;
		statsp->pkt_assy_dead = txc_kstatsp->pkt_assy_dead.value.ul;
		statsp->reorder_err = txc_kstatsp->reorder_err.value.ul;
	} else {
		txc_kstatsp->pkt_stuffed.value.ul = statsp->pkt_stuffed;
		txc_kstatsp->pkt_xmit.value.ul = statsp->pkt_xmit;
		txc_kstatsp->ro_correct_err.value.ul = statsp->ro_correct_err;
		txc_kstatsp->ro_uncorrect_err.value.ul =
		    statsp->ro_uncorrect_err;
		txc_kstatsp->sf_correct_err.value.ul = statsp->sf_correct_err;
		txc_kstatsp->sf_uncorrect_err.value.ul =
		    statsp->sf_uncorrect_err;
		txc_kstatsp->address_failed.value.ul = statsp->address_failed;
		txc_kstatsp->dma_failed.value.ul = statsp->dma_failed;
		txc_kstatsp->length_failed.value.ul = statsp->length_failed;
		txc_kstatsp->pkt_assy_dead.value.ul = statsp->pkt_assy_dead;
		txc_kstatsp->reorder_err.value.ul = statsp->reorder_err;
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_txc_stat_update"));
	return (0);
}

/* ARGSUSED */
int
nxge_ipp_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_ipp_kstat_t ipp_kstatsp;
	p_nxge_ipp_stats_t statsp;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_ipp_stat_update"));

	ipp_kstatsp = (p_nxge_ipp_kstat_t)ksp->ks_data;
	statsp = (p_nxge_ipp_stats_t)&nxgep->statsp->ipp_stats;

	if (rw == KSTAT_WRITE) {
		statsp->eop_miss = ipp_kstatsp->eop_miss.value.ul;
		statsp->sop_miss = ipp_kstatsp->sop_miss.value.ul;
		statsp->dfifo_ue = ipp_kstatsp->dfifo_ue.value.ul;
		statsp->ecc_err_cnt = ipp_kstatsp->ecc_err_cnt.value.ul;
		statsp->pfifo_perr = ipp_kstatsp->pfifo_perr.value.ul;
		statsp->pfifo_over = ipp_kstatsp->pfifo_over.value.ul;
		statsp->pfifo_und = ipp_kstatsp->pfifo_und.value.ul;
		statsp->bad_cs_cnt = ipp_kstatsp->bad_cs_cnt.value.ul;
		statsp->pkt_dis_cnt = ipp_kstatsp->pkt_dis_cnt.value.ul;
	} else {
		ipp_kstatsp->eop_miss.value.ul = statsp->eop_miss;
		ipp_kstatsp->sop_miss.value.ul = statsp->sop_miss;
		ipp_kstatsp->dfifo_ue.value.ul = statsp->dfifo_ue;
		ipp_kstatsp->ecc_err_cnt.value.ul = statsp->ecc_err_cnt;
		ipp_kstatsp->pfifo_perr.value.ul = statsp->pfifo_perr;
		ipp_kstatsp->pfifo_over.value.ul = statsp->pfifo_over;
		ipp_kstatsp->pfifo_und.value.ul = statsp->pfifo_und;
		ipp_kstatsp->bad_cs_cnt.value.ul = statsp->bad_cs_cnt;
		ipp_kstatsp->pkt_dis_cnt.value.ul = statsp->pkt_dis_cnt;
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_ipp_stat_update"));
	return (0);
}

/* ARGSUSED */
int
nxge_xmac_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_xmac_kstat_t xmac_kstatsp;
	p_nxge_xmac_stats_t statsp;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_xmac_stat_update"));

	xmac_kstatsp = (p_nxge_xmac_kstat_t)ksp->ks_data;
	statsp = (p_nxge_xmac_stats_t)&nxgep->statsp->xmac_stats;

	if (rw == KSTAT_WRITE) {
		statsp->tx_frame_cnt = xmac_kstatsp->tx_frame_cnt.value.ul;
		statsp->tx_underflow_err =
		    xmac_kstatsp->tx_underflow_err.value.ul;
		statsp->tx_maxpktsize_err =
		    xmac_kstatsp->tx_maxpktsize_err.value.ul;
		statsp->tx_overflow_err =
		    xmac_kstatsp->tx_overflow_err.value.ul;
		statsp->tx_fifo_xfr_err =
		    xmac_kstatsp->tx_fifo_xfr_err.value.ul;
		statsp->tx_byte_cnt = xmac_kstatsp->tx_byte_cnt.value.ul;
		statsp->rx_underflow_err =
		    xmac_kstatsp->rx_underflow_err.value.ul;
		statsp->rx_overflow_err =
		    xmac_kstatsp->rx_overflow_err.value.ul;
		statsp->rx_crc_err_cnt = xmac_kstatsp->rx_crc_err_cnt.value.ul;
		statsp->rx_len_err_cnt = xmac_kstatsp->rx_len_err_cnt.value.ul;
		statsp->rx_viol_err_cnt =
		    xmac_kstatsp->rx_viol_err_cnt.value.ul;
		statsp->rx_byte_cnt = xmac_kstatsp->rx_byte_cnt.value.ul;
		statsp->rx_frame_cnt = xmac_kstatsp->rx_frame_cnt.value.ul;
		statsp->rx_hist1_cnt = xmac_kstatsp->rx_hist1_cnt.value.ul;
		statsp->rx_hist2_cnt = xmac_kstatsp->rx_hist2_cnt.value.ul;
		statsp->rx_hist3_cnt = xmac_kstatsp->rx_hist3_cnt.value.ul;
		statsp->rx_hist4_cnt = xmac_kstatsp->rx_hist4_cnt.value.ul;
		statsp->rx_hist5_cnt = xmac_kstatsp->rx_hist5_cnt.value.ul;
		statsp->rx_hist6_cnt = xmac_kstatsp->rx_hist6_cnt.value.ul;
		statsp->rx_hist7_cnt = xmac_kstatsp->rx_hist7_cnt.value.ul;
		statsp->rx_mult_cnt = xmac_kstatsp->rx_mult_cnt.value.ul;
		statsp->rx_frag_cnt = xmac_kstatsp->rx_frag_cnt.value.ul;
		statsp->rx_frame_align_err_cnt =
		    xmac_kstatsp->rx_frame_align_err_cnt.value.ul;
		statsp->rx_linkfault_err_cnt =
		    xmac_kstatsp->rx_linkfault_err_cnt.value.ul;
		statsp->rx_localfault_err =
		    xmac_kstatsp->rx_local_fault_err_cnt.value.ul;
		statsp->rx_remotefault_err =
		    xmac_kstatsp->rx_remote_fault_err_cnt.value.ul;
		statsp->xpcs_deskew_err_cnt =
		    xmac_kstatsp->xpcs_deskew_err_cnt.value.ul;
#ifdef	NXGE_DEBUG_SYMBOL_ERR
		statsp->xpcs_ln0_symbol_err_cnt =
		    xmac_kstatsp->xpcs_ln0_symbol_err_cnt.value.ul;
		statsp->xpcs_ln1_symbol_err_cnt =
		    xmac_kstatsp->xpcs_ln1_symbol_err_cnt.value.ul;
		statsp->xpcs_ln2_symbol_err_cnt =
		    xmac_kstatsp->xpcs_ln2_symbol_err_cnt.value.ul;
		statsp->xpcs_ln3_symbol_err_cnt =
		    xmac_kstatsp->xpcs_ln3_symbol_err_cnt.value.ul;
#endif
	} else {
		xmac_kstatsp->tx_frame_cnt.value.ul = statsp->tx_frame_cnt;
		xmac_kstatsp->tx_underflow_err.value.ul =
		    statsp->tx_underflow_err;
		xmac_kstatsp->tx_maxpktsize_err.value.ul =
		    statsp->tx_maxpktsize_err;
		xmac_kstatsp->tx_overflow_err.value.ul =
		    statsp->tx_overflow_err;
		xmac_kstatsp->tx_fifo_xfr_err.value.ul =
		    statsp->tx_fifo_xfr_err;
		xmac_kstatsp->tx_byte_cnt.value.ul = statsp->tx_byte_cnt;
		xmac_kstatsp->rx_underflow_err.value.ul =
		    statsp->rx_underflow_err;
		xmac_kstatsp->rx_overflow_err.value.ul =
		    statsp->rx_overflow_err;
		xmac_kstatsp->rx_crc_err_cnt.value.ul = statsp->rx_crc_err_cnt;
		xmac_kstatsp->rx_len_err_cnt.value.ul = statsp->rx_len_err_cnt;
		xmac_kstatsp->rx_viol_err_cnt.value.ul =
		    statsp->rx_viol_err_cnt;
		xmac_kstatsp->rx_byte_cnt.value.ul = statsp->rx_byte_cnt;
		xmac_kstatsp->rx_frame_cnt.value.ul = statsp->rx_frame_cnt;
		xmac_kstatsp->rx_hist1_cnt.value.ul = statsp->rx_hist1_cnt;
		xmac_kstatsp->rx_hist2_cnt.value.ul = statsp->rx_hist2_cnt;
		xmac_kstatsp->rx_hist3_cnt.value.ul = statsp->rx_hist3_cnt;
		xmac_kstatsp->rx_hist4_cnt.value.ul = statsp->rx_hist4_cnt;
		xmac_kstatsp->rx_hist5_cnt.value.ul = statsp->rx_hist5_cnt;
		xmac_kstatsp->rx_hist6_cnt.value.ul = statsp->rx_hist6_cnt;
		xmac_kstatsp->rx_hist7_cnt.value.ul = statsp->rx_hist7_cnt;
		xmac_kstatsp->rx_mult_cnt.value.ul = statsp->rx_mult_cnt;
		xmac_kstatsp->rx_frag_cnt.value.ul = statsp->rx_frag_cnt;
		xmac_kstatsp->rx_frame_align_err_cnt.value.ul =
		    statsp->rx_frame_align_err_cnt;
		xmac_kstatsp->rx_linkfault_err_cnt.value.ul =
		    statsp->rx_linkfault_err_cnt;
		xmac_kstatsp->rx_local_fault_err_cnt.value.ul =
		    statsp->rx_localfault_err;
		xmac_kstatsp->rx_remote_fault_err_cnt.value.ul =
		    statsp->rx_remotefault_err;
		xmac_kstatsp->xpcs_deskew_err_cnt.value.ul =
		    statsp->xpcs_deskew_err_cnt;
#ifdef	NXGE_DEBUG_SYMBOL_ERR
		xmac_kstatsp->xpcs_ln0_symbol_err_cnt.value.ul =
		    statsp->xpcs_ln0_symbol_err_cnt;
		xmac_kstatsp->xpcs_ln1_symbol_err_cnt.value.ul =
		    statsp->xpcs_ln1_symbol_err_cnt;
		xmac_kstatsp->xpcs_ln2_symbol_err_cnt.value.ul =
		    statsp->xpcs_ln2_symbol_err_cnt;
		xmac_kstatsp->xpcs_ln3_symbol_err_cnt.value.ul =
		    statsp->xpcs_ln3_symbol_err_cnt;
#endif
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_xmac_stat_update"));
	return (0);
}

/* ARGSUSED */
int
nxge_bmac_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_bmac_kstat_t bmac_kstatsp;
	p_nxge_bmac_stats_t statsp;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_bmac_stat_update"));

	bmac_kstatsp = (p_nxge_bmac_kstat_t)ksp->ks_data;
	statsp = (p_nxge_bmac_stats_t)&nxgep->statsp->bmac_stats;

	if (rw == KSTAT_WRITE) {
		statsp->tx_frame_cnt = bmac_kstatsp->tx_frame_cnt.value.ul;
		statsp->tx_underrun_err =
		    bmac_kstatsp->tx_underrun_err.value.ul;
		statsp->tx_max_pkt_err = bmac_kstatsp->tx_max_pkt_err.value.ul;
		statsp->tx_byte_cnt = bmac_kstatsp->tx_byte_cnt.value.ul;
		statsp->rx_frame_cnt = bmac_kstatsp->rx_frame_cnt.value.ul;
		statsp->rx_byte_cnt = bmac_kstatsp->rx_byte_cnt.value.ul;
		statsp->rx_overflow_err =
		    bmac_kstatsp->rx_overflow_err.value.ul;
		statsp->rx_align_err_cnt =
		    bmac_kstatsp->rx_align_err_cnt.value.ul;
		statsp->rx_crc_err_cnt = bmac_kstatsp->rx_crc_err_cnt.value.ul;
		statsp->rx_len_err_cnt = bmac_kstatsp->rx_len_err_cnt.value.ul;
		statsp->rx_viol_err_cnt =
		    bmac_kstatsp->rx_viol_err_cnt.value.ul;
	} else {
		bmac_kstatsp->tx_frame_cnt.value.ul = statsp->tx_frame_cnt;
		bmac_kstatsp->tx_underrun_err.value.ul =
		    statsp->tx_underrun_err;
		bmac_kstatsp->tx_max_pkt_err.value.ul = statsp->tx_max_pkt_err;
		bmac_kstatsp->tx_byte_cnt.value.ul = statsp->tx_byte_cnt;
		bmac_kstatsp->rx_frame_cnt.value.ul = statsp->rx_frame_cnt;
		bmac_kstatsp->rx_byte_cnt.value.ul = statsp->rx_byte_cnt;
		bmac_kstatsp->rx_overflow_err.value.ul =
		    statsp->rx_overflow_err;
		bmac_kstatsp->rx_align_err_cnt.value.ul =
		    statsp->rx_align_err_cnt;
		bmac_kstatsp->rx_crc_err_cnt.value.ul = statsp->rx_crc_err_cnt;
		bmac_kstatsp->rx_len_err_cnt.value.ul = statsp->rx_len_err_cnt;
		bmac_kstatsp->rx_viol_err_cnt.value.ul =
		    statsp->rx_viol_err_cnt;
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_bmac_stat_update"));
	return (0);
}

/* ARGSUSED */
int
nxge_zcp_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_zcp_kstat_t zcp_kstatsp;
	p_nxge_zcp_stats_t statsp;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_zcp_stat_update"));

	zcp_kstatsp = (p_nxge_zcp_kstat_t)ksp->ks_data;
	statsp = (p_nxge_zcp_stats_t)&nxgep->statsp->zcp_stats;

	if (rw == KSTAT_WRITE) {
		statsp->rrfifo_underrun = zcp_kstatsp->rrfifo_underrun.value.ul;
		statsp->rrfifo_overrun = zcp_kstatsp->rrfifo_overrun.value.ul;
		statsp->rspfifo_uncorr_err =
		    zcp_kstatsp->rspfifo_uncorr_err.value.ul;
		statsp->buffer_overflow = zcp_kstatsp->buffer_overflow.value.ul;
		statsp->stat_tbl_perr = zcp_kstatsp->stat_tbl_perr.value.ul;
		statsp->dyn_tbl_perr = zcp_kstatsp->dyn_tbl_perr.value.ul;
		statsp->buf_tbl_perr = zcp_kstatsp->buf_tbl_perr.value.ul;
		statsp->tt_program_err = zcp_kstatsp->tt_program_err.value.ul;
		statsp->rsp_tt_index_err =
		    zcp_kstatsp->rsp_tt_index_err.value.ul;
		statsp->slv_tt_index_err =
		    zcp_kstatsp->slv_tt_index_err.value.ul;
		statsp->zcp_tt_index_err =
		    zcp_kstatsp->zcp_tt_index_err.value.ul;
		statsp->cfifo_ecc = zcp_kstatsp->cfifo_ecc.value.ul;
	} else {
		zcp_kstatsp->rrfifo_underrun.value.ul = statsp->rrfifo_underrun;
		zcp_kstatsp->rrfifo_overrun.value.ul = statsp->rrfifo_overrun;
		zcp_kstatsp->rspfifo_uncorr_err.value.ul =
		    statsp->rspfifo_uncorr_err;
		zcp_kstatsp->buffer_overflow.value.ul =
		    statsp->buffer_overflow;
		zcp_kstatsp->stat_tbl_perr.value.ul = statsp->stat_tbl_perr;
		zcp_kstatsp->dyn_tbl_perr.value.ul = statsp->dyn_tbl_perr;
		zcp_kstatsp->buf_tbl_perr.value.ul = statsp->buf_tbl_perr;
		zcp_kstatsp->tt_program_err.value.ul = statsp->tt_program_err;
		zcp_kstatsp->rsp_tt_index_err.value.ul =
		    statsp->rsp_tt_index_err;
		zcp_kstatsp->slv_tt_index_err.value.ul =
		    statsp->slv_tt_index_err;
		zcp_kstatsp->zcp_tt_index_err.value.ul =
		    statsp->zcp_tt_index_err;
		zcp_kstatsp->cfifo_ecc.value.ul = statsp->cfifo_ecc;
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_zcp_stat_update"));
	return (0);
}

/* ARGSUSED */
int
nxge_fflp_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_fflp_kstat_t fflp_kstatsp;
	p_nxge_fflp_stats_t statsp;
	int ldc_grp;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_fflp_stat_update"));

	fflp_kstatsp = (p_nxge_fflp_kstat_t)ksp->ks_data;
	statsp = (p_nxge_fflp_stats_t)&nxgep->statsp->fflp_stats;

	if (rw == KSTAT_WRITE) {
		statsp->tcam_parity_err = fflp_kstatsp->fflp_tcam_perr.value.ul;
		statsp->tcam_ecc_err = fflp_kstatsp->fflp_tcam_ecc_err.value.ul;
		statsp->vlan_parity_err = fflp_kstatsp->fflp_vlan_perr.value.ul;
		statsp->hash_lookup_err =
		    fflp_kstatsp->fflp_hasht_lookup_err.value.ul;
		for (ldc_grp = 0; ldc_grp < MAX_PARTITION; ldc_grp++) {
			statsp->hash_pio_err[ldc_grp] =
			    fflp_kstatsp->fflp_hasht_data_err[ldc_grp].
			    value.ul;
		}
	} else {
		fflp_kstatsp->fflp_tcam_perr.value.ul =
		    fflp_kstatsp->fflp_tcam_perr.value.ul;
		fflp_kstatsp->fflp_tcam_ecc_err.value.ul = statsp->tcam_ecc_err;
		fflp_kstatsp->fflp_vlan_perr.value.ul = statsp->vlan_parity_err;
		fflp_kstatsp->fflp_hasht_lookup_err.value.ul =
		    statsp->hash_lookup_err;
		for (ldc_grp = 0; ldc_grp < MAX_PARTITION; ldc_grp++) {
			fflp_kstatsp->fflp_hasht_data_err[ldc_grp].value.ul =
			    statsp->hash_pio_err[ldc_grp];
		}
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_fflp_stat_update"));
	return (0);
}

/* ARGSUSED */
static uint64_t
nxge_mac_octet_to_u64(struct ether_addr addr)
{
	int i;
	uint64_t addr64 = 0;

	for (i = ETHERADDRL - 1; i >= 0; i--) {
		addr64 <<= 8;
		addr64 |= addr.ether_addr_octet[i];
	}
	return (addr64);
}

/* ARGSUSED */
int
nxge_mmac_stat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_mmac_kstat_t mmac_kstatsp;
	p_nxge_mmac_stats_t statsp;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_mmac_stat_update"));

	mmac_kstatsp = (p_nxge_mmac_kstat_t)ksp->ks_data;
	statsp = (p_nxge_mmac_stats_t)&nxgep->statsp->mmac_stats;

	if (rw == KSTAT_WRITE) {
		cmn_err(CE_WARN, "Can not write mmac stats");
	} else {
		mmac_kstatsp->mmac_max_addr_cnt.value.ul =
		    statsp->mmac_max_cnt;
		mmac_kstatsp->mmac_avail_addr_cnt.value.ul =
		    statsp->mmac_avail_cnt;
		mmac_kstatsp->mmac_addr1.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[0]);
		mmac_kstatsp->mmac_addr2.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[1]);
		mmac_kstatsp->mmac_addr3.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[2]);
		mmac_kstatsp->mmac_addr4.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[3]);
		mmac_kstatsp->mmac_addr5.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[4]);
		mmac_kstatsp->mmac_addr6.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[5]);
		mmac_kstatsp->mmac_addr7.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[6]);
		mmac_kstatsp->mmac_addr8.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[7]);
		mmac_kstatsp->mmac_addr9.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[8]);
		mmac_kstatsp->mmac_addr10.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[9]);
		mmac_kstatsp->mmac_addr11.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[10]);
		mmac_kstatsp->mmac_addr12.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[11]);
		mmac_kstatsp->mmac_addr13.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[12]);
		mmac_kstatsp->mmac_addr14.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[13]);
		mmac_kstatsp->mmac_addr15.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[14]);
		mmac_kstatsp->mmac_addr16.value.ul =
		    nxge_mac_octet_to_u64(statsp->mmac_avail_pool[15]);
	}
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_mmac_stat_update"));
	return (0);
}

/* ARGSUSED */
static kstat_t *
nxge_setup_local_kstat(p_nxge_t nxgep, int instance, char *name,
	const nxge_kstat_index_t *ksip, size_t count,
	int (*update) (kstat_t *, int))
{
	kstat_t *ksp;
	kstat_named_t *knp;
	int i;

	ksp = kstat_create(NXGE_DRIVER_NAME, instance, name, "net",
	    KSTAT_TYPE_NAMED, count, 0);
	if (ksp == NULL)
		return (NULL);

	ksp->ks_private = (void *)nxgep;
	ksp->ks_update = update;
	knp = ksp->ks_data;

	for (i = 0; ksip[i].name != NULL; i++) {
		kstat_named_init(&knp[i], ksip[i].name, ksip[i].type);
	}

	kstat_install(ksp);
	return (ksp);
}

/* ARGSUSED */
void
nxge_setup_rdc_kstats(p_nxge_t nxgep, int channel)
{
	char stat_name[64];

	/* Setup RDC statistics */
	(void) sprintf(stat_name, "%s" CH_NAME_FORMAT,
	    RDC_NAME_FORMAT1, channel);
	nxgep->statsp->rdc_ksp[channel] = nxge_setup_local_kstat(nxgep,
	    nxgep->instance,
	    stat_name,
	    nxge_rdc_stats,
	    RDC_STAT_END,
	    nxge_rdc_stat_update);
#ifdef	NXGE_DEBUG_ERROR
	if (nxgep->statsp->rdc_ksp[channel] == NULL)
		NXGE_DEBUG_MSG((nxgep, KST_CTL,
		    "kstat_create failed for rdc channel %d", channel));
#endif
}

void
nxge_setup_tdc_kstats(p_nxge_t nxgep, int channel)
{
	char stat_name[64];

	/* Setup TDC statistics */
	(void) sprintf(stat_name, "%s" CH_NAME_FORMAT,
	    TDC_NAME_FORMAT1, channel);
	nxgep->statsp->tdc_ksp[channel] = nxge_setup_local_kstat(nxgep,
	    nxgep->instance,
	    stat_name,
	    nxge_tdc_stats,
	    TDC_STAT_END,
	    nxge_tdc_stat_update);
#ifdef	NXGE_DEBUG_ERROR
	if (nxgep->statsp->tdc_ksp[channel] == NULL) {
		NXGE_DEBUG_MSG((nxgep, KST_CTL,
		    "kstat_create failed for tdc channel %d", channel));
	}
#endif
}

void
nxge_setup_kstats(p_nxge_t nxgep)
{
	struct kstat *ksp;
	p_nxge_port_kstat_t nxgekp;
	size_t nxge_kstat_sz;
	char mmac_name[64];

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_setup_kstats"));

	/* Setup RDC System statistics */
	nxgep->statsp->rdc_sys_ksp = nxge_setup_local_kstat(nxgep,
	    nxgep->instance,
	    "RDC System Stats",
	    &nxge_rdc_sys_stats[0],
	    RDC_SYS_STAT_END,
	    nxge_rdc_sys_stat_update);

	/* Setup IPP statistics */
	nxgep->statsp->ipp_ksp = nxge_setup_local_kstat(nxgep,
	    nxgep->instance,
	    "IPP Stats",
	    &nxge_ipp_stats[0],
	    IPP_STAT_END,
	    nxge_ipp_stat_update);
#ifdef	NXGE_DEBUG_ERROR
	if (nxgep->istatsp->pp_ksp == NULL)
		NXGE_DEBUG_MSG((nxgep, KST_CTL, "kstat_create failed for ipp"));
#endif

	/* Setup TXC statistics */
	nxgep->statsp->txc_ksp = nxge_setup_local_kstat(nxgep,
	    nxgep->instance, "TXC Stats", &nxge_txc_stats[0],
	    TXC_STAT_END, nxge_txc_stat_update);
#ifdef	NXGE_DEBUG_ERROR
	if (nxgep->statsp->txc_ksp == NULL)
		NXGE_DEBUG_MSG((nxgep, KST_CTL, "kstat_create failed for txc"));
#endif

	/* Setup ZCP statistics */
	nxgep->statsp->zcp_ksp = nxge_setup_local_kstat(nxgep,
	    nxgep->instance, "ZCP Stats", &nxge_zcp_stats[0],
	    ZCP_STAT_END, nxge_zcp_stat_update);
#ifdef	NXGE_DEBUG_ERROR
	if (nxgep->statsp->zcp_ksp == NULL)
		NXGE_DEBUG_MSG((nxgep, KST_CTL, "kstat_create failed for zcp"));
#endif

	/* Setup FFLP statistics */
	nxgep->statsp->fflp_ksp[0] = nxge_setup_local_kstat(nxgep,
	    nxgep->instance, "FFLP Stats", &nxge_fflp_stats[0],
	    FFLP_STAT_END, nxge_fflp_stat_update);

#ifdef	NXGE_DEBUG_ERROR
	if (nxgep->statsp->fflp_ksp == NULL)
		NXGE_DEBUG_MSG((nxgep, KST_CTL,
		    "kstat_create failed for fflp"));
#endif

	(void) sprintf(mmac_name, "MMAC Stats%d", nxgep->instance);
	nxgep->statsp->mmac_ksp = nxge_setup_local_kstat(nxgep,
	    nxgep->instance, "MMAC Stats", &nxge_mmac_stats[0],
	    MMAC_STATS_END, nxge_mmac_stat_update);

	nxge_kstat_sz = sizeof (nxge_port_kstat_t) +
	    sizeof (nxge_mac_kstat_t) - sizeof (kstat_named_t);

	if ((ksp = kstat_create(NXGE_DRIVER_NAME, nxgep->instance,
	    "Port Stats", "net", KSTAT_TYPE_NAMED,
	    nxge_kstat_sz / sizeof (kstat_named_t), 0)) == NULL) {
		NXGE_DEBUG_MSG((nxgep, KST_CTL, "kstat_create failed"));
		NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_setup_kstats"));
		return;
	}

	/*
	 * kstats
	 */
	nxgekp = (p_nxge_port_kstat_t)ksp->ks_data;

	/*
	 * transceiver state informations.
	 */
	kstat_named_init(&nxgekp->xcvr_inits, "xcvr_inits",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->xcvr_inuse, "xcvr_inuse",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->xcvr_addr, "xcvr_addr",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->xcvr_id, "xcvr_id",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_autoneg, "cap_autoneg",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_10gfdx, "cap_10gfdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_10ghdx, "cap_10ghdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_1000fdx, "cap_1000fdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_1000hdx, "cap_1000hdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_100T4, "cap_100T4",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_100fdx, "cap_100fdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_100hdx, "cap_100hdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_10fdx, "cap_10fdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_10hdx, "cap_10hdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_asmpause, "cap_asmpause",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->cap_pause, "cap_pause",
	    KSTAT_DATA_ULONG);

	/*
	 * Link partner capabilities.
	 */
	kstat_named_init(&nxgekp->lp_cap_autoneg, "lp_cap_autoneg",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_10gfdx, "lp_cap_10gfdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_10ghdx, "lp_cap_10ghdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_1000fdx, "lp_cap_1000fdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_1000hdx, "lp_cap_1000hdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_100T4, "lp_cap_100T4",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_100fdx, "lp_cap_100fdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_100hdx, "lp_cap_100hdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_10fdx, "lp_cap_10fdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_10hdx, "lp_cap_10hdx",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_asmpause, "lp_cap_asmpause",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->lp_cap_pause, "lp_cap_pause",
	    KSTAT_DATA_ULONG);
	/*
	 * Shared link setup.
	 */
	kstat_named_init(&nxgekp->link_T4, "link_T4",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->link_speed, "link_speed",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->link_duplex, "link_duplex",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&nxgekp->link_asmpause, "link_asmpause",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->link_pause, "link_pause",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->link_up, "link_up",
	    KSTAT_DATA_ULONG);

	/*
	 * Let the user know the MTU currently in use by the physical MAC
	 * port.
	 */
	kstat_named_init(&nxgekp->mac_mtu, "mac_mtu",
	    KSTAT_DATA_ULONG);

	/*
	 * Loopback statistics.
	 */
	kstat_named_init(&nxgekp->lb_mode, "lb_mode",
	    KSTAT_DATA_ULONG);

	/*
	 * This tells the user whether the driver is in QOS mode or not.
	 */
	kstat_named_init(&nxgekp->qos_mode, "qos_mode",
	    KSTAT_DATA_ULONG);

	/*
	 * This tells whether the instance is trunked or not
	 */
	kstat_named_init(&nxgekp->trunk_mode, "trunk_mode",
	    KSTAT_DATA_ULONG);

#if defined MULTI_DATA_TX || defined MULTI_DATA_TXV2
	kstat_named_init(&nxgekp->mdt_reqs, "mdt_reqs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->mdt_hdr_bufs, "mdt_hdr_bufs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->mdt_pld_bufs, "mdt_pld_bufs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->mdt_pkts, "mdt_pkts",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->mdt_hdrs, "mdt_hdrs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->mdt_plds, "mdt_plds",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->mdt_hdr_bind_fail, "mdt_hdr_bind_fail",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->mdt_pld_bind_fail, "mdt_pld_bind_fail",
	    KSTAT_DATA_ULONG);
#endif
#ifdef ACCEPT_JUMBO
	kstat_named_init(&nxgekp->tx_jumbo_pkts, "tx_jumbo_pkts",
	    KSTAT_DATA_ULONG);
#endif

	/*
	 * Rx Statistics.
	 */
#ifdef ACCEPT_JUMBO
	kstat_named_init(&nxgekp->rx_jumbo_pkts, "rx_jumbo_pkts",
	    KSTAT_DATA_ULONG);
#endif
	/* General MAC statistics */
	kstat_named_init(&nxgekp->ifspeed, "ifspeed",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&nxgekp->promisc, "promisc",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&nxgekp->rev_id, "rev_id",
	    KSTAT_DATA_ULONG);

	ksp->ks_update = nxge_port_kstat_update;
	ksp->ks_private = (void *) nxgep;
	if (nxgep->mac.porttype == PORT_TYPE_XMAC)
		nxge_xmac_init_kstats(ksp);
	else
		nxge_bmac_init_kstats(ksp);
	kstat_install(ksp);
	nxgep->statsp->port_ksp = ksp;
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_setup_kstats"));
}

/* ARGSUSED */
void
nxge_xmac_init_kstats(struct kstat *ksp)
{
	p_nxge_xmac_kstat_t nxgekp;

	nxgekp = (p_nxge_xmac_kstat_t)ksp->ks_data;

	/*
	 * Transmit MAC statistics.
	 */
	kstat_named_init(&nxgekp->tx_frame_cnt, "txmac_frame_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_underflow_err, "txmac_underflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_overflow_err, "txmac_overflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_maxpktsize_err, "txmac_maxpktsize_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_fifo_xfr_err, "txmac_fifo_xfr_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_byte_cnt, "txmac_byte_cnt",
	    KSTAT_DATA_ULONG);

	/* Receive MAC statistics */
	kstat_named_init(&nxgekp->rx_frame_cnt, "rxmac_frame_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_overflow_err, "rxmac_overflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_underflow_err, "rxmac_underflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_crc_err_cnt, "rxmac_crc_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_len_err_cnt, "rxmac_length_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_viol_err_cnt, "rxmac_code_violations",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_byte_cnt, "rxmac_byte_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_frame_align_err_cnt,
	    "rxmac_alignment_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_hist1_cnt, "rxmac_64_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_hist2_cnt, "rxmac_65_127_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_hist3_cnt, "rxmac_128_255_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_hist4_cnt, "rxmac_256_511_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_hist5_cnt, "rxmac_512_1023_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_hist6_cnt, "rxmac_1024_1522_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_hist7_cnt, "rxmac_jumbo_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_broadcast_cnt, "rxmac_broadcast_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_mult_cnt, "rxmac_multicast_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_frag_cnt, "rxmac_fragment_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_linkfault_err_cnt, "rxmac_linkfault_errs",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_remote_fault_err_cnt,
	    "rxmac_remote_faults",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_local_fault_err_cnt, "rxmac_local_faults",
	    KSTAT_DATA_ULONG);

	/* XPCS statistics */

	kstat_named_init(&nxgekp->xpcs_deskew_err_cnt, "xpcs_deskew_err_cnt",
	    KSTAT_DATA_ULONG);
#ifdef	NXGE_DEBUG_SYMBOL_ERR
	kstat_named_init(&nxgekp->xpcs_ln0_symbol_err_cnt,
	    "xpcs_ln0_symbol_err_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->xpcs_ln1_symbol_err_cnt,
	    "xpcs_ln1_symbol_err_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->xpcs_ln2_symbol_err_cnt,
	    "xpcs_ln2_symbol_err_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->xpcs_ln3_symbol_err_cnt,
	    "xpcs_ln3_symbol_err_cnt",
	    KSTAT_DATA_ULONG);
#endif
}

/* ARGSUSED */
void
nxge_bmac_init_kstats(struct kstat *ksp)
{
	p_nxge_bmac_kstat_t nxgekp;

	nxgekp = (p_nxge_bmac_kstat_t)ksp->ks_data;

	/*
	 * Transmit MAC statistics.
	 */
	kstat_named_init(&nxgekp->tx_frame_cnt, "txmac_frame_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_underrun_err, "txmac_underflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_max_pkt_err, "txmac_maxpktsize_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_byte_cnt, "txmac_byte_cnt",
	    KSTAT_DATA_ULONG);

	/* Receive MAC statistics */
	kstat_named_init(&nxgekp->rx_overflow_err, "rxmac_overflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_crc_err_cnt, "rxmac_crc_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_len_err_cnt, "rxmac_length_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_viol_err_cnt, "rxmac_code_violations",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_byte_cnt, "rxmac_byte_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_align_err_cnt, "rxmac_alignment_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_frame_cnt, "rxmac_frame_cnt",
	    KSTAT_DATA_ULONG);
}

/* ARGSUSED */
void
nxge_mac_init_kstats(p_nxge_t nxgep, struct kstat *ksp)
{
	p_nxge_mac_kstat_t nxgekp;

	nxgekp = (p_nxge_mac_kstat_t)ksp->ks_data;

	/*
	 * Transmit MAC statistics.
	 */
	kstat_named_init(&nxgekp->tx_frame_cnt, "txmac_frame_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_underflow_err, "txmac_underflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_overflow_err, "txmac_overflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_maxpktsize_err, "txmac_maxpktsize_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_fifo_xfr_err, "txmac_fifo_xfr_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->tx_byte_cnt, "txmac_byte_cnt",
	    KSTAT_DATA_ULONG);

	/*
	 * Receive MAC statistics
	 */
	kstat_named_init(&nxgekp->rx_overflow_err, "rxmac_overflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_underflow_err, "rxmac_underflow_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_crc_err_cnt, "rxmac_crc_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_len_err_cnt, "rxmac_length_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_viol_err_cnt, "rxmac_code_violations",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_byte_cnt, "rxmac_byte_cnt",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_frame_align_err_cnt,
	    "rxmac_alignment_err",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&nxgekp->rx_frame_cnt, "rxmac_frame_cnt",
	    KSTAT_DATA_ULONG);
	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		kstat_named_init(&nxgekp->rx_hist1_cnt, "rxmac_64_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_hist2_cnt, "rxmac_65_127_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_hist3_cnt, "rxmac_128_255_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_hist4_cnt, "rxmac_256_511_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_hist5_cnt, "rxmac_512_1023_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_hist6_cnt, "rxmac_1024_1522_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_hist7_cnt, "rxmac_jumbo_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_broadcast_cnt,
		    "rxmac_broadcast_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_mult_cnt, "rxmac_multicast_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_frag_cnt, "rxmac_fragment_cnt",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_linkfault_err_cnt,
		    "rxmac_linkfault_errs",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_remote_fault_err_cnt,
		    "rxmac_remote_faults",
		    KSTAT_DATA_ULONG);
		kstat_named_init(&nxgekp->rx_local_fault_err_cnt,
		    "rxmac_local_faults",
		    KSTAT_DATA_ULONG);
	}
}

/* ARGSUSED */
void
nxge_destroy_kstats(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_destroy_kstats"));

	if (nxgep->statsp == NULL)
		return;
	if (nxgep->statsp->ksp)
		kstat_delete(nxgep->statsp->ksp);

	if (nxgep->statsp->rdc_sys_ksp)
		kstat_delete(nxgep->statsp->rdc_sys_ksp);
	if (nxgep->statsp->fflp_ksp[0])
		kstat_delete(nxgep->statsp->fflp_ksp[0]);
	if (nxgep->statsp->ipp_ksp)
		kstat_delete(nxgep->statsp->ipp_ksp);
	if (nxgep->statsp->txc_ksp)
		kstat_delete(nxgep->statsp->txc_ksp);
	if (nxgep->statsp->mac_ksp)
		kstat_delete(nxgep->statsp->mac_ksp);
	if (nxgep->statsp->zcp_ksp)
		kstat_delete(nxgep->statsp->zcp_ksp);
	if (nxgep->statsp->port_ksp)
		kstat_delete(nxgep->statsp->port_ksp);
	if (nxgep->statsp->mmac_ksp)
		kstat_delete(nxgep->statsp->mmac_ksp);
	if (nxgep->statsp)
		KMEM_FREE(nxgep->statsp, nxgep->statsp->stats_size);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_destroy_kstats"));
}

/* ARGSUSED */
int
nxge_port_kstat_update(kstat_t *ksp, int rw)
{
	p_nxge_t nxgep;
	p_nxge_stats_t statsp;
	p_nxge_port_kstat_t nxgekp;

	nxgep = (p_nxge_t)ksp->ks_private;
	if (nxgep == NULL)
		return (-1);

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_port_kstat_update"));
	statsp = (p_nxge_stats_t)nxgep->statsp;
	nxgekp = (p_nxge_port_kstat_t)ksp->ks_data;
	nxge_save_cntrs(nxgep);

	if (rw == KSTAT_WRITE) {
		/*
		 * transceiver state informations.
		 */
		statsp->mac_stats.xcvr_inits = nxgekp->xcvr_inits.value.ul;

		/*
		 * Tx Statistics.
		 */
#if defined MULTI_DATA_TX || defined MULTI_DATA_TXV2
		statsp->port_stats.mdt_reqs = nxgekp->mdt_reqs.value.ul;
		statsp->port_stats.mdt_hdr_bufs = nxgekp->mdt_hdr_bufs.value.ul;
		statsp->port_stats.mdt_pld_bufs = nxgekp->mdt_pld_bufs.value.ul;
		statsp->port_stats.mdt_pkts = nxgekp->mdt_pkts.value.ul;
		statsp->port_stats.mdt_hdrs = nxgekp->mdt_hdrs.value.ul;
		statsp->port_stats.mdt_plds = nxgekp->mdt_plds.value.ul;
		statsp->port_stats.mdt_hdr_bind_fail =
		    nxgekp->mdt_hdr_bind_fail.value.ul;
		statsp->port_stats.mdt_pld_bind_fail =
		    nxgekp->mdt_pld_bind_fail.value.ul;
#endif
#ifdef ACCEPT_JUMBO
		statsp->port_stats.tx_jumbo_pkts =
		    nxgekp->tx_jumbo_pkts.value.ul;
#endif
		/*
		 * Rx Statistics.
		 */
#ifdef ACCEPT_JUMBO
		statsp->port_stats.rx_jumbo_pkts =
		    nxgekp->rx_jumbo_pkts.value.ul;
#endif
		if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
			(void) nxge_xmac_stat_update(ksp, KSTAT_WRITE);
		} else {
			(void) nxge_bmac_stat_update(ksp, KSTAT_WRITE);
		}
		return (0);
	} else {
		if (nxgep->filter.all_phys_cnt)
			(void) strcpy(nxgekp->promisc.value.c, "phys");
		else if (nxgep->filter.all_multicast_cnt)
			(void) strcpy(nxgekp->promisc.value.c, "multi");
		else
			(void) strcpy(nxgekp->promisc.value.c, "off");
		nxgekp->ifspeed.value.ul =
		    statsp->mac_stats.link_speed * 1000000ULL;
		nxgekp->rev_id.value.ul = statsp->mac_stats.rev_id;

		/*
		 * transceiver state informations.
		 */
		nxgekp->xcvr_inits.value.ul = statsp->mac_stats.xcvr_inits;
		nxgekp->xcvr_inuse.value.ul = statsp->mac_stats.xcvr_inuse;
		nxgekp->xcvr_addr.value.ul = statsp->mac_stats.xcvr_portn;
		nxgekp->xcvr_id.value.ul = statsp->mac_stats.xcvr_id;
		nxgekp->cap_autoneg.value.ul = statsp->mac_stats.cap_autoneg;
		nxgekp->cap_10gfdx.value.ul = statsp->mac_stats.cap_10gfdx;
		nxgekp->cap_10ghdx.value.ul = statsp->mac_stats.cap_10ghdx;
		nxgekp->cap_1000fdx.value.ul = statsp->mac_stats.cap_1000fdx;
		nxgekp->cap_1000hdx.value.ul = statsp->mac_stats.cap_1000hdx;
		nxgekp->cap_100T4.value.ul = statsp->mac_stats.cap_100T4;
		nxgekp->cap_100fdx.value.ul = statsp->mac_stats.cap_100fdx;
		nxgekp->cap_100hdx.value.ul = statsp->mac_stats.cap_100hdx;
		nxgekp->cap_10fdx.value.ul = statsp->mac_stats.cap_10fdx;
		nxgekp->cap_10hdx.value.ul = statsp->mac_stats.cap_10hdx;
		nxgekp->cap_asmpause.value.ul =
		    statsp->mac_stats.cap_asmpause;
		nxgekp->cap_pause.value.ul = statsp->mac_stats.cap_pause;

		/*
		 * Link partner capabilities.
		 */
		nxgekp->lp_cap_autoneg.value.ul =
		    statsp->mac_stats.lp_cap_autoneg;
		nxgekp->lp_cap_10gfdx.value.ul =
		    statsp->mac_stats.lp_cap_10gfdx;
		nxgekp->lp_cap_10ghdx.value.ul =
		    statsp->mac_stats.lp_cap_10ghdx;
		nxgekp->lp_cap_1000fdx.value.ul =
		    statsp->mac_stats.lp_cap_1000fdx;
		nxgekp->lp_cap_1000hdx.value.ul =
		    statsp->mac_stats.lp_cap_1000hdx;
		nxgekp->lp_cap_100T4.value.ul =
		    statsp->mac_stats.lp_cap_100T4;
		nxgekp->lp_cap_100fdx.value.ul =
		    statsp->mac_stats.lp_cap_100fdx;
		nxgekp->lp_cap_100hdx.value.ul =
		    statsp->mac_stats.lp_cap_100hdx;
		nxgekp->lp_cap_10fdx.value.ul =
		    statsp->mac_stats.lp_cap_10fdx;
		nxgekp->lp_cap_10hdx.value.ul =
		    statsp->mac_stats.lp_cap_10hdx;
		nxgekp->lp_cap_asmpause.value.ul =
		    statsp->mac_stats.lp_cap_asmpause;
		nxgekp->lp_cap_pause.value.ul =
		    statsp->mac_stats.lp_cap_pause;

		/*
		 * Physical link statistics.
		 */
		nxgekp->link_T4.value.ul = statsp->mac_stats.link_T4;
		nxgekp->link_speed.value.ul = statsp->mac_stats.link_speed;
		if (statsp->mac_stats.link_duplex == 2)
			(void) strcpy(nxgekp->link_duplex.value.c, "full");
		else if (statsp->mac_stats.link_duplex == 1)
			(void) strcpy(nxgekp->link_duplex.value.c, "half");
		else
			(void) strcpy(nxgekp->link_duplex.value.c, "unknown");
		nxgekp->link_asmpause.value.ul =
		    statsp->mac_stats.link_asmpause;
		nxgekp->link_pause.value.ul = statsp->mac_stats.link_pause;
		nxgekp->link_up.value.ul = statsp->mac_stats.link_up;

		/*
		 * Lets the user know the MTU currently in use by the physical
		 * MAC port.
		 */
		nxgekp->mac_mtu.value.ul = statsp->mac_stats.mac_mtu;

		/*
		 * Loopback statistics.
		 */
		nxgekp->lb_mode.value.ul = statsp->port_stats.lb_mode;

		/*
		 * This tells the user whether the driver is in QOS mode or
		 * not.
		 */
		nxgekp->qos_mode.value.ul = statsp->port_stats.qos_mode;

		/*
		 * This tells whether the instance is trunked or not
		 */
		nxgekp->trunk_mode.value.ul = statsp->port_stats.trunk_mode;

#if defined MULTI_DATA_TX || defined MULTI_DATA_TXV2
		nxgekp->mdt_reqs.value.ul = statsp->port_stats.mdt_reqs;
		nxgekp->mdt_hdr_bufs.value.ul =
		    statsp->port_stats.mdt_hdr_bufs;
		nxgekp->mdt_pld_bufs.value.ul =
		    statsp->port_stats.mdt_pld_bufs;
		nxgekp->mdt_pkts.value.ul = statsp->port_stats.mdt_pkts;
		nxgekp->mdt_hdrs.value.ul = statsp->port_stats.mdt_hdrs;
		nxgekp->mdt_plds.value.ul = statsp->port_stats.mdt_plds;
		nxgekp->mdt_hdr_bind_fail.value.ul =
		    statsp->port_stats.mdt_hdr_bind_fail;
		nxgekp->mdt_pld_bind_fail.value.ul =
		    statsp->port_stats.mdt_pld_bind_fail;
#endif
#ifdef ACCEPT_JUMBO
		nxgekp->tx_jumbo_pkts.value.ul =
		    statsp->port_stats.tx_jumbo_pkts;
#endif
#ifdef TX_MBLK_DEST
		nxgekp->tx_1_desc.value.ul = statsp->port_stats.tx_1_desc;
		nxgekp->tx_2_desc.value.ul = statsp->port_stats.tx_2_desc;
		nxgekp->tx_3_desc.value.ul = statsp->port_stats.tx_3_desc;
		nxgekp->tx_4_desc.value.ul = statsp->port_stats.tx_4_desc;
		nxgekp->tx_5_desc.value.ul = statsp->port_stats.tx_5_desc;
		nxgekp->tx_6_desc.value.ul = statsp->port_stats.tx_6_desc;
		nxgekp->tx_7_desc.value.ul = statsp->port_stats.tx_7_desc;
		nxgekp->tx_8_desc.value.ul = statsp->port_stats.tx_8_desc;
		nxgekp->tx_max_desc.value.ul =
		    statsp->port_stats.tx_max_desc;
#endif
		/*
		 * Rx Statistics.
		 */
#ifdef ACCEPT_JUMBO
		nxgekp->rx_jumbo_pkts.value.ul =
		    statsp->port_stats.rx_jumbo_pkts;
#endif
		if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
			(void) nxge_xmac_stat_update(ksp, KSTAT_READ);
		} else {
			(void) nxge_bmac_stat_update(ksp, KSTAT_READ);
		}
	}

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "<== nxge_port_kstat_update"));
	return (0);
}

/*
 * if this is the first init do not bother to save the
 * counters.
 */
/* ARGSUSED */
void
nxge_save_cntrs(p_nxge_t nxgep)
{
	p_nxge_stats_t statsp;
	uint64_t val;
	npi_handle_t handle;
	uint8_t portn;
	uint8_t cnt8;
	uint16_t cnt16;
	uint32_t cnt32;

	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "==> nxge_save_cntrs"));

	statsp = (p_nxge_stats_t)nxgep->statsp;
	handle = nxgep->npi_handle;
	portn = nxgep->mac.portnum;

	MUTEX_ENTER(&nxgep->ouraddr_lock);

	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		/*
		 * Transmit MAC statistics.
		 */
		XMAC_REG_RD(handle, portn, XTXMAC_FRM_CNT_REG, &val);
		statsp->xmac_stats.tx_frame_cnt += (val & XTXMAC_FRM_CNT_MASK);
		XMAC_REG_RD(handle, portn, XTXMAC_BYTE_CNT_REG, &val);
		statsp->xmac_stats.tx_byte_cnt += (val & XTXMAC_BYTE_CNT_MASK);
		/*
		 * Receive XMAC statistics.
		 */
		XMAC_REG_RD(handle, portn, XRXMAC_CRC_ER_CNT_REG, &val);
		statsp->xmac_stats.rx_crc_err_cnt +=
		    (val & XRXMAC_CRC_ER_CNT_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_MPSZER_CNT_REG, &val);
		statsp->xmac_stats.rx_len_err_cnt +=
		    (val & XRXMAC_MPSZER_CNT_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_CD_VIO_CNT_REG, &val);
		statsp->xmac_stats.rx_viol_err_cnt +=
		    (val & XRXMAC_CD_VIO_CNT_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_BT_CNT_REG, &val);
		statsp->xmac_stats.rx_byte_cnt += (val & XRXMAC_BT_CNT_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_HIST_CNT1_REG, &val);
		statsp->xmac_stats.rx_hist1_cnt +=
		    (val & XRXMAC_HIST_CNT1_MASK);
		statsp->xmac_stats.rx_frame_cnt +=
		    (val & XRXMAC_HIST_CNT1_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_HIST_CNT2_REG, &val);
		statsp->xmac_stats.rx_hist2_cnt +=
		    (val & XRXMAC_HIST_CNT2_MASK);
		statsp->xmac_stats.rx_frame_cnt +=
		    (val & XRXMAC_HIST_CNT2_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_HIST_CNT3_REG, &val);
		statsp->xmac_stats.rx_hist3_cnt +=
		    (val & XRXMAC_HIST_CNT3_MASK);
		statsp->xmac_stats.rx_frame_cnt +=
		    (val & XRXMAC_HIST_CNT3_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_HIST_CNT4_REG, &val);
		statsp->xmac_stats.rx_hist4_cnt +=
		    (val & XRXMAC_HIST_CNT4_MASK);
		statsp->xmac_stats.rx_frame_cnt +=
		    (val & XRXMAC_HIST_CNT4_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_HIST_CNT5_REG, &val);
		statsp->xmac_stats.rx_hist5_cnt +=
		    (val & XRXMAC_HIST_CNT5_MASK);
		statsp->xmac_stats.rx_frame_cnt +=
		    (val & XRXMAC_HIST_CNT5_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_HIST_CNT6_REG, &val);
		statsp->xmac_stats.rx_hist6_cnt +=
		    (val & XRXMAC_HIST_CNT6_MASK);
		statsp->xmac_stats.rx_frame_cnt +=
		    (val & XRXMAC_HIST_CNT6_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_HIST_CNT7_REG, &val);
		statsp->xmac_stats.rx_hist7_cnt +=
		    (val & XRXMAC_HIST_CNT7_MASK);
		statsp->xmac_stats.rx_frame_cnt +=
		    (val & XRXMAC_HIST_CNT7_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_BC_FRM_CNT_REG, &val);
		statsp->xmac_stats.rx_broadcast_cnt +=
		    (val & XRXMAC_BC_FRM_CNT_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_MC_FRM_CNT_REG, &val);
		statsp->xmac_stats.rx_mult_cnt +=
		    (val & XRXMAC_MC_FRM_CNT_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_FRAG_CNT_REG, &val);
		statsp->xmac_stats.rx_frag_cnt += (val & XRXMAC_FRAG_CNT_MASK);

		XMAC_REG_RD(handle, portn, XRXMAC_AL_ER_CNT_REG, &val);
		statsp->xmac_stats.rx_frame_align_err_cnt +=
		    (val & XRXMAC_AL_ER_CNT_MASK);

		XMAC_REG_RD(handle, portn, XMAC_LINK_FLT_CNT_REG, &val);
		statsp->xmac_stats.rx_linkfault_err_cnt +=
		    (val & XMAC_LINK_FLT_CNT_MASK);

		(void) npi_xmac_xpcs_read(handle, portn,
		    XPCS_REG_DESCWERR_COUNTER, &cnt32);
		statsp->xmac_stats.xpcs_deskew_err_cnt +=
		    (val & XMAC_XPCS_DESKEW_ERR_CNT_MASK);

#ifdef	NXGE_DEBUG_SYMBOL_ERR
		(void) npi_xmac_xpcs_read(handle, portn,
		    XPCS_REG_SYMBOL_ERR_L0_1_COUNTER, &cnt32);
		statsp->xmac_stats.xpcs_ln0_symbol_err_cnt +=
		    (cnt32 & XMAC_XPCS_SYM_ERR_CNT_L0_MASK);
		statsp->xmac_stats.xpcs_ln1_symbol_err_cnt +=
		    ((cnt32 & XMAC_XPCS_SYM_ERR_CNT_L1_MASK) >>
		    XMAC_XPCS_SYM_ERR_CNT_L1_SHIFT);
		(void) npi_xmac_xpcs_read(handle, portn,
		    XPCS_REG_SYMBOL_ERR_L2_3_COUNTER, &cnt32);
		statsp->xmac_stats.xpcs_ln2_symbol_err_cnt +=
		    (cnt32 & XMAC_XPCS_SYM_ERR_CNT_L2_MASK);
		statsp->xmac_stats.xpcs_ln3_symbol_err_cnt +=
		    ((cnt32 & XMAC_XPCS_SYM_ERR_CNT_L3_MASK) >>
		    XMAC_XPCS_SYM_ERR_CNT_L3_SHIFT);
#endif
	} else if (nxgep->mac.porttype == PORT_TYPE_BMAC) {
		/*
		 * Transmit MAC statistics.
		 */
		BMAC_REG_RD(handle, portn, BTXMAC_FRM_CNT_REG, &val);
		statsp->bmac_stats.tx_frame_cnt += (val & BTXMAC_FRM_CNT_MASK);
		/* Clear register as it is not auto clear on read */
		BMAC_REG_WR(handle, portn, BTXMAC_FRM_CNT_REG, 0);

		BMAC_REG_RD(handle, portn, BTXMAC_BYTE_CNT_REG, &val);
		statsp->bmac_stats.tx_byte_cnt += (val & BTXMAC_BYTE_CNT_MASK);
		/* Clear register as it is not auto clear on read */
		BMAC_REG_WR(handle, portn, BTXMAC_BYTE_CNT_REG, 0);

		/*
		 * Receive MAC statistics.
		 */
		BMAC_REG_RD(handle, portn, RXMAC_FRM_CNT_REG, &val);
		statsp->bmac_stats.rx_frame_cnt += (val & RXMAC_FRM_CNT_MASK);
		/* Clear register as it is not auto clear on read */
		BMAC_REG_WR(handle, portn, RXMAC_FRM_CNT_REG, 0);

		BMAC_REG_RD(handle, portn, BRXMAC_BYTE_CNT_REG, &val);
		statsp->bmac_stats.rx_byte_cnt += (val & BRXMAC_BYTE_CNT_MASK);
		/* Clear register as it is not auto clear on read */
		BMAC_REG_WR(handle, portn, BRXMAC_BYTE_CNT_REG, 0);

		BMAC_REG_RD(handle, portn, BMAC_AL_ER_CNT_REG, &val);
		statsp->bmac_stats.rx_align_err_cnt +=
		    (val & BMAC_AL_ER_CNT_MASK);
		/* Clear register as it is not auto clear on read */
		BMAC_REG_WR(handle, portn, BMAC_AL_ER_CNT_REG, 0);

		BMAC_REG_RD(handle, portn, MAC_LEN_ER_CNT_REG, &val);
		statsp->bmac_stats.rx_len_err_cnt +=
		    (val & MAC_LEN_ER_CNT_MASK);
		/* Clear register as it is not auto clear on read */
		BMAC_REG_WR(handle, portn, MAC_LEN_ER_CNT_REG, 0);

		BMAC_REG_RD(handle, portn, BMAC_CRC_ER_CNT_REG, &val);
		statsp->bmac_stats.rx_crc_err_cnt +=
		    (val & BMAC_CRC_ER_CNT_MASK);
		/* Clear register as it is not auto clear on read */
		BMAC_REG_WR(handle, portn, BMAC_CRC_ER_CNT_REG, 0);

		BMAC_REG_RD(handle, portn, BMAC_CD_VIO_CNT_REG, &val);
		statsp->bmac_stats.rx_viol_err_cnt +=
		    (val & BMAC_CD_VIO_CNT_MASK);
		/* Clear register as it is not auto clear on read */
		BMAC_REG_WR(handle, portn, BMAC_CD_VIO_CNT_REG, 0);
	}
	if (isLDOMguest(nxgep)) {
		MUTEX_EXIT(&nxgep->ouraddr_lock);
		goto nxge_save_cntrs_exit;
	}
	/* Update IPP counters */
	(void) npi_ipp_get_ecc_err_count(handle, portn, &cnt8);
	statsp->ipp_stats.ecc_err_cnt += cnt8;
	(void) npi_ipp_get_pkt_dis_count(handle, portn, &cnt16);
	statsp->ipp_stats.pkt_dis_cnt += cnt16;
	(void) npi_ipp_get_cs_err_count(handle, portn, &cnt16);
	statsp->ipp_stats.bad_cs_cnt += cnt16;

	MUTEX_EXIT(&nxgep->ouraddr_lock);

nxge_save_cntrs_exit:
	NXGE_DEBUG_MSG((nxgep, DDI_CTL, "<== nxge_save_cntrs"));
}

uint64_t
nxge_m_rx_stat(
	nxge_t *nxgep,
	uint_t stat)
{
	p_nxge_stats_t statsp;
	nxge_grp_set_t *rx_set;
	int8_t set[NXGE_MAX_RDCS];
	int i, cursor;

	uint64_t val = 0;

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_m_rx_stat"));
	statsp = (p_nxge_stats_t)nxgep->statsp;

	rx_set = &nxgep->rx_set;
	for (i = 0, cursor = 0; i < NXGE_MAX_RDCS; i++) {
		if ((1 << i) & rx_set->owned.map) {
			set[cursor++] = (uint8_t)i;
		}
	}

	for (i = 0; i < cursor; i++) {
		int rdc = set[i];
		switch (stat) {
		case MAC_STAT_IERRORS:
		case ETHER_STAT_MACRCV_ERRORS:
			val += statsp->rdc_stats[rdc].ierrors;
			break;

		case MAC_STAT_RBYTES:
			val += statsp->rdc_stats[rdc].ibytes;
			break;

		case MAC_STAT_IPACKETS:
			val += statsp->rdc_stats[rdc].ipackets;
			break;

		default:
			break;
		}
	}

	return (val);
}

uint64_t
nxge_m_tx_stat(
	nxge_t *nxgep,
	uint_t stat)
{
	p_nxge_stats_t statsp;
	nxge_grp_set_t *tx_set;
	int8_t set[NXGE_MAX_TDCS];
	int i, cursor;

	uint64_t val = 0;

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_m_tx_stat"));
	statsp = (p_nxge_stats_t)nxgep->statsp;

	tx_set = &nxgep->tx_set;
	for (i = 0, cursor = 0; i < NXGE_MAX_TDCS; i++) {
		if ((1 << i) & tx_set->owned.map) {
			set[cursor++] = (uint8_t)i;
		}
	}

	for (i = 0; i < cursor; i++) {
		int tdc = set[i];
		switch (stat) {
		case MAC_STAT_OERRORS:
			val += statsp->tdc_stats[tdc].oerrors;
			break;

		case MAC_STAT_OBYTES:
			val += statsp->tdc_stats[tdc].obytes;
			break;

		case MAC_STAT_OPACKETS:
			val += statsp->tdc_stats[tdc].opackets;
			break;

		default:
			break;
		}
	}

	return (val);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
nxge_rx_ring_stat(mac_ring_driver_t rdriver, uint_t stat, uint64_t *val)
{
	p_nxge_ring_handle_t    rhp = (p_nxge_ring_handle_t)rdriver;
	p_nxge_t		nxgep = rhp->nxgep;
	int			r_index;
	p_nxge_stats_t 		statsp;

	ASSERT(nxgep != NULL);
	statsp = (p_nxge_stats_t)nxgep->statsp;
	ASSERT(statsp != NULL);
	r_index = rhp->index + nxgep->pt_config.hw_config.start_rdc;

	if (statsp->rdc_ksp[r_index] == NULL)
		return (0);

	switch (stat) {
	case MAC_STAT_IERRORS:
		*val = statsp->rdc_stats[r_index].ierrors;
		break;

	case MAC_STAT_RBYTES:
		*val = statsp->rdc_stats[r_index].ibytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = statsp->rdc_stats[r_index].ipackets;
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
nxge_tx_ring_stat(mac_ring_driver_t rdriver, uint_t stat, uint64_t *val)
{
	p_nxge_ring_handle_t    rhp = (p_nxge_ring_handle_t)rdriver;
	p_nxge_t		nxgep = rhp->nxgep;
	int			r_index;
	p_nxge_stats_t 		statsp;

	ASSERT(nxgep != NULL);
	statsp = (p_nxge_stats_t)nxgep->statsp;
	ASSERT(statsp != NULL);
	r_index = nxgep->pt_config.hw_config.tdc.start + rhp->index;

	if (statsp->tdc_ksp[r_index] == NULL)
		return (0);

	switch (stat) {
	case MAC_STAT_OERRORS:
		*val = statsp->tdc_stats[r_index].oerrors;
		break;

	case MAC_STAT_OBYTES:
		*val = statsp->tdc_stats[r_index].obytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = statsp->tdc_stats[r_index].opackets;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}

/* ARGSUSED */
int
nxge_m_stat(void *arg, uint_t stat, uint64_t *value)
{
	p_nxge_t nxgep = (p_nxge_t)arg;
	p_nxge_stats_t statsp;
	uint64_t val = 0;

	NXGE_DEBUG_MSG((nxgep, KST_CTL, "==> nxge_m_stat"));
	statsp = (p_nxge_stats_t)nxgep->statsp;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		val = statsp->mac_stats.link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		val = statsp->port_stats.multircv;
		break;

	case MAC_STAT_BRDCSTRCV:
		val = statsp->port_stats.brdcstrcv;
		break;

	case MAC_STAT_MULTIXMT:
		val = statsp->port_stats.multixmt;
		break;

	case MAC_STAT_BRDCSTXMT:
		val = statsp->port_stats.brdcstxmt;
		break;

	case MAC_STAT_NORCVBUF:
		val = statsp->port_stats.norcvbuf;
		break;

	case MAC_STAT_IERRORS:
	case ETHER_STAT_MACRCV_ERRORS:
		val = nxge_m_rx_stat(nxgep, stat);
		break;

	case MAC_STAT_OERRORS:
		val = nxge_m_tx_stat(nxgep, stat);
		break;

	case MAC_STAT_NOXMTBUF:
		val = statsp->port_stats.noxmtbuf;
		break;

	case MAC_STAT_COLLISIONS:
		val = 0;
		break;

	case MAC_STAT_RBYTES:
		val = nxge_m_rx_stat(nxgep, stat);
		break;

	case MAC_STAT_IPACKETS:
		val = nxge_m_rx_stat(nxgep, stat);
		break;

	case MAC_STAT_OBYTES:
		val = nxge_m_tx_stat(nxgep, stat);
		break;

	case MAC_STAT_OPACKETS:
		val = nxge_m_tx_stat(nxgep, stat);
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
		if (nxgep->mac.porttype == PORT_TYPE_XMAC)
			val = statsp->xmac_stats.rx_frame_align_err_cnt;
		else if (nxgep->mac.porttype == PORT_TYPE_BMAC)
			val = statsp->bmac_stats.rx_align_err_cnt;
		else
			val = 0;
		break;

	case ETHER_STAT_FCS_ERRORS:
		if (nxgep->mac.porttype == PORT_TYPE_XMAC)
			val = statsp->xmac_stats.rx_crc_err_cnt;
		else if (nxgep->mac.porttype == PORT_TYPE_BMAC)
			val = statsp->bmac_stats.rx_crc_err_cnt;
		else
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
		if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
			val = statsp->xmac_stats.tx_underflow_err +
			    statsp->xmac_stats.tx_maxpktsize_err +
			    statsp->xmac_stats.tx_overflow_err +
			    statsp->xmac_stats.tx_fifo_xfr_err;
		} else {
			val = statsp->bmac_stats.tx_underrun_err +
			    statsp->bmac_stats.tx_max_pkt_err;
		}
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
			val = statsp->xmac_stats.rx_linkfault_err_cnt;
		} else {
			val = statsp->mac_stats.xcvr_inits +
			    statsp->mac_stats.serdes_inits;
		}
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
			val = statsp->xmac_stats.tx_maxpktsize_err +
			    statsp->xmac_stats.rx_len_err_cnt;

		} else {
			val = statsp->bmac_stats.rx_len_err_cnt +
			    statsp->bmac_stats.tx_max_pkt_err;
		}
		break;


	case ETHER_STAT_XCVR_ADDR:
		val = statsp->mac_stats.xcvr_portn;
		break;
	case ETHER_STAT_XCVR_ID:
		val = statsp->mac_stats.xcvr_id;
		break;

	case ETHER_STAT_XCVR_INUSE:
		val = statsp->mac_stats.xcvr_inuse;
		break;

	case ETHER_STAT_CAP_1000FDX:
		val = statsp->mac_stats.cap_1000fdx;
		break;

	case ETHER_STAT_CAP_1000HDX:
		val = statsp->mac_stats.cap_1000hdx;
		break;

	case ETHER_STAT_CAP_100FDX:
		val = statsp->mac_stats.cap_100fdx;
		break;

	case ETHER_STAT_CAP_100HDX:
		val = statsp->mac_stats.cap_100hdx;
		break;

	case ETHER_STAT_CAP_10FDX:
		val = statsp->mac_stats.cap_10fdx;
		break;

	case ETHER_STAT_CAP_10HDX:
		val = statsp->mac_stats.cap_10hdx;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		val = statsp->mac_stats.cap_asmpause;
		val = 1;
		break;

	case ETHER_STAT_CAP_PAUSE:
		val = statsp->mac_stats.cap_pause;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		val = statsp->mac_stats.cap_autoneg;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		val = statsp->mac_stats.adv_cap_1000fdx;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		val = statsp->mac_stats.adv_cap_1000hdx;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		val = statsp->mac_stats.adv_cap_100fdx;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		val = statsp->mac_stats.adv_cap_100hdx;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		val = statsp->mac_stats.adv_cap_10fdx;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		val = statsp->mac_stats.adv_cap_10hdx;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		val = statsp->mac_stats.adv_cap_asmpause;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		val = statsp->mac_stats.adv_cap_pause;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		val = statsp->mac_stats.adv_cap_autoneg;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		val = statsp->mac_stats.lp_cap_1000fdx;
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		val = statsp->mac_stats.lp_cap_1000hdx;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		val = statsp->mac_stats.lp_cap_100fdx;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		val = statsp->mac_stats.lp_cap_100hdx;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		val = statsp->mac_stats.lp_cap_10fdx;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		val = statsp->mac_stats.lp_cap_10hdx;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		val = statsp->mac_stats.lp_cap_asmpause;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		val = statsp->mac_stats.lp_cap_pause;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		val = statsp->mac_stats.lp_cap_autoneg;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		val = statsp->mac_stats.link_asmpause;
		break;

	case ETHER_STAT_LINK_PAUSE:
		val = statsp->mac_stats.link_pause;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		val = statsp->mac_stats.cap_autoneg;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		val = statsp->mac_stats.link_duplex;
		break;

	default:
		/*
		 * Shouldn't reach here...
		 */
#ifdef NXGE_DEBUG
		NXGE_ERROR_MSG((nxgep, KST_CTL,
		    "nxge_m_stat: unrecognized parameter value = 0x%x",
		    stat));
#endif

		return (ENOTSUP);
	}
	*value = val;
	return (0);
}
