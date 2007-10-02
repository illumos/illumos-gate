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

#ifndef	_SYS_NXGE_NXGE_FM_H
#define	_SYS_NXGE_NXGE_FM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi.h>

#define	ERNAME_DETAILED_ERR_TYPE	"detailed error type"
#define	ERNAME_ERR_PORTN		"port number"
#define	ERNAME_ERR_DCHAN		"dma channel number"
#define	ERNAME_TCAM_ERR_LOG		"tcam error log"
#define	ERNAME_VLANTAB_ERR_LOG		"vlan table error log"
#define	ERNAME_HASHTAB_ERR_LOG		"hash table error log"
#define	ERNAME_HASHT_LOOKUP_ERR_LOG0	"hash table lookup error log0"
#define	ERNAME_HASHT_LOOKUP_ERR_LOG1	"hash table lookup error log1"
#define	ERNAME_RDMC_PAR_ERR_LOG		"rdmc parity error log"
#define	ERNAME_DFIFO_RD_PTR		"dfifo read pointer"
#define	ERNAME_IPP_STATE_MACH		"ipp state machine"
#define	ERNAME_DFIFO_ENTRY		"dfifo entry"
#define	ERNAME_DFIFO_SYNDROME		"dfifo syndrome"
#define	ERNAME_PFIFO_ENTRY		"pfifo entry"
#define	ERNAME_ZCP_STATE_MACH		"zcp state machine"
#define	ERNAME_CFIFO_PORT_NUM		"cfifo port number"
#define	ERNAME_RDC_ERR_TYPE		"completion error type"
#define	ERNAME_TDMC_ERR_LOG0		"tdmc error log0"
#define	ERNAME_TDMC_ERR_LOG1		"tdmc error log1"
#define	ERNAME_TXC_ROECC_ADDR		"txc reorder FIFO ECC error address"
#define	ERNAME_TXC_ROECC_DATA0		"txc reorder FIFO data0"
#define	ERNAME_TXC_ROECC_DATA1		"txc reorder FIFO data1"
#define	ERNAME_TXC_ROECC_DATA2		"txc reorder FIFO data2"
#define	ERNAME_TXC_ROECC_DATA3		"txc reorder FIFO data3"
#define	ERNAME_TXC_ROECC_DATA4		"txc reorder FIFO data4"
#define	ERNAME_TXC_RO_STATE0		"txc reorder FIFO error state0" \
					"(duplicate TID)"
#define	ERNAME_TXC_RO_STATE1		"txc reorder FIFO error state1" \
					"(uninitialized TID)"
#define	ERNAME_TXC_RO_STATE2		"txc reorder FIFO error state2" \
					"(timed out TIDs)"
#define	ERNAME_TXC_RO_STATE3		"txc reorder FIFO error state3"
#define	ERNAME_TXC_RO_STATE_CTL		"txc reorder FIFO error control"
#define	ERNAME_TXC_RO_TIDS		"txc reorder tids"
#define	ERNAME_TXC_SFECC_ADDR		"txc store forward FIFO ECC error "\
					"address"
#define	ERNAME_TXC_SFECC_DATA0		"txc store forward FIFO data0"
#define	ERNAME_TXC_SFECC_DATA1		"txc store forward FIFO data1"
#define	ERNAME_TXC_SFECC_DATA2		"txc store forward FIFO data2"
#define	ERNAME_TXC_SFECC_DATA3		"txc store forward FIFO data3"
#define	ERNAME_TXC_SFECC_DATA4		"txc store forward FIFO data4"

#define	EREPORT_FM_ID_SHIFT		16
#define	EREPORT_FM_ID_MASK		0xFF
#define	EREPORT_INDEX_MASK		0xFF
#define	NXGE_FM_EREPORT_UNKNOWN		0

/* xaui and xfp ereport definitions */
#define	NXGE_FM_DEVICE_XAUI_ERR		"nxge.xaui-err"
#define	NXGE_FM_DEVICE_XFP_ERR		"nxge.xfp-err"

#define	FM_SW_ID			0xFF
#define	FM_PCS_ID			MAC_BLK_ID
#define	FM_TXMAC_ID			TXMAC_BLK_ID
#define	FM_RXMAC_ID			RXMAC_BLK_ID
#define	FM_MIF_ID			MIF_BLK_ID
#define	FM_IPP_ID			IPP_BLK_ID
#define	FM_TXC_ID			TXC_BLK_ID
#define	FM_TXDMA_ID			TXDMA_BLK_ID
#define	FM_RXDMA_ID			RXDMA_BLK_ID
#define	FM_ZCP_ID			ZCP_BLK_ID
#define	FM_ESPC_ID			ESPC_BLK_ID
#define	FM_FFLP_ID			FFLP_BLK_ID
#define	FM_PCIE_ID			PCIE_BLK_ID
#define	FM_ETHER_SERDES_ID		ETHER_SERDES_BLK_ID
#define	FM_PCIE_SERDES_ID		PCIE_SERDES_BLK_ID
#define	FM_VIR_ID			VIR_BLK_ID
#define	FM_XAUI_ID			XAUI_BLK_ID
#define	FM_XFP_ID			XFP_BLK_ID

typedef	uint32_t nxge_fm_ereport_id_t;

typedef	struct _nxge_fm_ereport_attr {
	uint32_t		index;
	char			*str;
	char			*eclass;
	ddi_fault_impact_t	impact;
} nxge_fm_ereport_attr_t;

/* General MAC ereports */
typedef	enum {
	NXGE_FM_EREPORT_XPCS_LINK_DOWN = (FM_PCS_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_XPCS_TX_LINK_FAULT,
	NXGE_FM_EREPORT_XPCS_RX_LINK_FAULT,
	NXGE_FM_EREPORT_PCS_LINK_DOWN,
	NXGE_FM_EREPORT_PCS_REMOTE_FAULT
} nxge_fm_ereport_pcs_t;

/* MIF ereports */
typedef	enum {
	NXGE_FM_EREPORT_MIF_ACCESS_FAIL = (FM_MIF_ID << EREPORT_FM_ID_SHIFT)
} nxge_fm_ereport_mif_t;

/* FFLP ereports */
typedef	enum {
	NXGE_FM_EREPORT_FFLP_TCAM_ERR = (FM_FFLP_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_FFLP_VLAN_PAR_ERR,
	NXGE_FM_EREPORT_FFLP_HASHT_DATA_ERR,
	NXGE_FM_EREPORT_FFLP_HASHT_LOOKUP_ERR,
	NXGE_FM_EREPORT_FFLP_ACCESS_FAIL
} nxge_fm_ereport_fflp_t;

/* IPP ereports */
typedef	enum {
	NXGE_FM_EREPORT_IPP_EOP_MISS = (FM_IPP_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_IPP_SOP_MISS,
	NXGE_FM_EREPORT_IPP_DFIFO_UE,
	NXGE_FM_EREPORT_IPP_DFIFO_CE,
	NXGE_FM_EREPORT_IPP_PFIFO_PERR,
	NXGE_FM_EREPORT_IPP_ECC_ERR_MAX,
	NXGE_FM_EREPORT_IPP_PFIFO_OVER,
	NXGE_FM_EREPORT_IPP_PFIFO_UND,
	NXGE_FM_EREPORT_IPP_BAD_CS_MX,
	NXGE_FM_EREPORT_IPP_PKT_DIS_MX,
	NXGE_FM_EREPORT_IPP_RESET_FAIL
} nxge_fm_ereport_ipp_t;

/* RDMC ereports */
typedef	enum {
	NXGE_FM_EREPORT_RDMC_DCF_ERR = (FM_RXDMA_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_RDMC_RCR_ACK_ERR,
	NXGE_FM_EREPORT_RDMC_DC_FIFO_ERR,
	NXGE_FM_EREPORT_RDMC_RCR_SHA_PAR,
	NXGE_FM_EREPORT_RDMC_RBR_PRE_PAR,
	NXGE_FM_EREPORT_RDMC_RBR_TMOUT,
	NXGE_FM_EREPORT_RDMC_RSP_CNT_ERR,
	NXGE_FM_EREPORT_RDMC_BYTE_EN_BUS,
	NXGE_FM_EREPORT_RDMC_RSP_DAT_ERR,
	NXGE_FM_EREPORT_RDMC_ID_MISMATCH,
	NXGE_FM_EREPORT_RDMC_ZCP_EOP_ERR,
	NXGE_FM_EREPORT_RDMC_IPP_EOP_ERR,
	NXGE_FM_EREPORT_RDMC_RCR_ERR,
	NXGE_FM_EREPORT_RDMC_CONFIG_ERR,
	NXGE_FM_EREPORT_RDMC_RCRINCON,
	NXGE_FM_EREPORT_RDMC_RCRFULL,
	NXGE_FM_EREPORT_RDMC_RBRFULL,
	NXGE_FM_EREPORT_RDMC_RBRLOGPAGE,
	NXGE_FM_EREPORT_RDMC_CFIGLOGPAGE
} nxge_fm_ereport_rdmc_t;

/* ZCP ereports */
typedef	enum {
	NXGE_FM_EREPORT_ZCP_RRFIFO_UNDERRUN =
					(FM_ZCP_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_ZCP_RSPFIFO_UNCORR_ERR,
	NXGE_FM_EREPORT_ZCP_STAT_TBL_PERR,
	NXGE_FM_EREPORT_ZCP_DYN_TBL_PERR,
	NXGE_FM_EREPORT_ZCP_BUF_TBL_PERR,
	NXGE_FM_EREPORT_ZCP_CFIFO_ECC,
	NXGE_FM_EREPORT_ZCP_RRFIFO_OVERRUN,
	NXGE_FM_EREPORT_ZCP_BUFFER_OVERFLOW,
	NXGE_FM_EREPORT_ZCP_TT_PROGRAM_ERR,
	NXGE_FM_EREPORT_ZCP_RSP_TT_INDEX_ERR,
	NXGE_FM_EREPORT_ZCP_SLV_TT_INDEX_ERR,
	NXGE_FM_EREPORT_ZCP_TT_INDEX_ERR,
	NXGE_FM_EREPORT_ZCP_ACCESS_FAIL
} nxge_fm_ereport_zcp_t;

typedef enum {
	NXGE_FM_EREPORT_RXMAC_UNDERFLOW = (FM_RXMAC_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_RXMAC_CRC_ERRCNT_EXP,
	NXGE_FM_EREPORT_RXMAC_LENGTH_ERRCNT_EXP,
	NXGE_FM_EREPORT_RXMAC_VIOL_ERRCNT_EXP,
	NXGE_FM_EREPORT_RXMAC_RXFRAG_CNT_EXP,
	NXGE_FM_EREPORT_RXMAC_ALIGN_ECNT_EXP,
	NXGE_FM_EREPORT_RXMAC_LINKFAULT_CNT_EXP,
	NXGE_FM_EREPORT_RXMAC_RESET_FAIL
} nxge_fm_ereport_rxmac_t;

typedef	enum {
	NXGE_FM_EREPORT_TDMC_PREF_BUF_PAR_ERR =
				(FM_TXDMA_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_TDMC_MBOX_ERR,
	NXGE_FM_EREPORT_TDMC_NACK_PREF,
	NXGE_FM_EREPORT_TDMC_NACK_PKT_RD,
	NXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR,
	NXGE_FM_EREPORT_TDMC_TX_RING_OFLOW,
	NXGE_FM_EREPORT_TDMC_CONF_PART_ERR,
	NXGE_FM_EREPORT_TDMC_PKT_PRT_ERR,
	NXGE_FM_EREPORT_TDMC_RESET_FAIL
} nxge_fm_ereport_attr_tdmc_t;

typedef	enum {
	NXGE_FM_EREPORT_TXC_RO_CORRECT_ERR =
				(FM_TXC_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_TXC_RO_UNCORRECT_ERR,
	NXGE_FM_EREPORT_TXC_SF_CORRECT_ERR,
	NXGE_FM_EREPORT_TXC_SF_UNCORRECT_ERR,
	NXGE_FM_EREPORT_TXC_ASSY_DEAD,
	NXGE_FM_EREPORT_TXC_REORDER_ERR
} nxge_fm_ereport_attr_txc_t;

typedef	enum {
	NXGE_FM_EREPORT_TXMAC_UNDERFLOW =
				(FM_TXMAC_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_TXMAC_OVERFLOW,
	NXGE_FM_EREPORT_TXMAC_TXFIFO_XFR_ERR,
	NXGE_FM_EREPORT_TXMAC_MAX_PKT_ERR,
	NXGE_FM_EREPORT_TXMAC_RESET_FAIL
} nxge_fm_ereport_attr_txmac_t;

typedef	enum {
	NXGE_FM_EREPORT_ESPC_ACCESS_FAIL = (FM_ESPC_ID << EREPORT_FM_ID_SHIFT)
} nxge_fm_ereport_espc_t;

typedef	enum {
	NXGE_FM_EREPORT_SW_INVALID_PORT_NUM = (FM_SW_ID << EREPORT_FM_ID_SHIFT),
	NXGE_FM_EREPORT_SW_INVALID_CHAN_NUM,
	NXGE_FM_EREPORT_SW_INVALID_PARAM
} nxge_fm_ereport_sw_t;

/* XAUI is broken or missing */
typedef	enum {
	NXGE_FM_EREPORT_XAUI_ERR = (FM_XAUI_ID << EREPORT_FM_ID_SHIFT)
} nxge_fm_ereport_xaui_t;

/* XFP optical module is broken or missing */
typedef	enum {
	NXGE_FM_EREPORT_XFP_ERR = (FM_XFP_ID << EREPORT_FM_ID_SHIFT)
} nxge_fm_ereport_xfp_t;

#define	NXGE_FM_EREPORT_UNKNOWN			0
#define	NXGE_FM_EREPORT_UNKNOWN_NAME		""

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_FM_H */
