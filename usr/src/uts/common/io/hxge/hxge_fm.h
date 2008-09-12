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

#ifndef	_SYS_HXGE_HXGE_FM_H
#define	_SYS_HXGE_HXGE_FM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi.h>

#define	ERNAME_DETAILED_ERR_TYPE	"detailed error type"
#define	ERNAME_ERR_DCHAN		"dma channel number"
#define	ERNAME_PFC_TCAM_ERR		"pfc tcam error"
#define	ERNAME_PFC_VLAN_ERR		"pfc vlan table error"
#define	ERNAME_PFC_PKT_DROP		"pfc pkt drop error"
#define	ERNAME_RDMC_PAR_ERR_LOG		"rdmc parity error log"
#define	ERNAME_RDC_ERR_TYPE		"completion error type"
#define	ERNAME_TDC_PREF_PAR_LOG		"tdc pref par log"

#define	EREPORT_FM_ID_SHIFT		16
#define	EREPORT_FM_ID_MASK		0xFF
#define	EREPORT_INDEX_MASK		0xFF
#define	HXGE_FM_EREPORT_UNKNOWN		0

#define	FM_SW_ID			0xFF
#define	FM_VMAC_ID			VMAC_BLK_ID
#define	FM_TXDMA_ID			TXDMA_BLK_ID
#define	FM_RXDMA_ID			RXDMA_BLK_ID
#define	FM_PFC_ID			PFC_BLK_ID
#define	FM_PEU_ID			PEU_BLK_ID

typedef	uint32_t hxge_fm_ereport_id_t;

typedef	struct _hxge_fm_ereport_attr {
	uint32_t		index;
	char			*str;
	char			*eclass;
	ddi_fault_impact_t	impact;
} hxge_fm_ereport_attr_t;

/* VMAC ereports */
typedef	enum {
	HXGE_FM_EREPORT_VMAC_LINK_DOWN = (FM_VMAC_ID << EREPORT_FM_ID_SHIFT)
} hxge_fm_ereport_vmac_t;

/* PFC ereports */
typedef	enum {
	HXGE_FM_EREPORT_PFC_TCAM_PAR_ERR = (FM_PFC_ID << EREPORT_FM_ID_SHIFT),
	HXGE_FM_EREPORT_PFC_VLAN_PAR_ERR,
	HXGE_FM_EREPORT_PFC_PKT_DROP
} hxge_fm_ereport_pfc_t;

/* RDMC ereports */
typedef	enum {
	HXGE_FM_EREPORT_RDMC_RBR_CPL_TO = (FM_RXDMA_ID << EREPORT_FM_ID_SHIFT),
	HXGE_FM_EREPORT_RDMC_PEU_RESP_ERR,
	HXGE_FM_EREPORT_RDMC_RCR_SHA_PAR,
	HXGE_FM_EREPORT_RDMC_RBR_PRE_PAR,
	HXGE_FM_EREPORT_RDMC_RBR_PRE_EMPTY,
	HXGE_FM_EREPORT_RDMC_RCR_SHA_FULL,
	HXGE_FM_EREPORT_RDMC_RCRFULL,
	HXGE_FM_EREPORT_RDMC_RBR_EMPTY,
	HXGE_FM_EREPORT_RDMC_RBRFULL,
	HXGE_FM_EREPORT_RDMC_RCR_ERR,
	HXGE_FM_EREPORT_RDMC_CTRL_FIFO_DED,
	HXGE_FM_EREPORT_RDMC_DATA_FIFO_DED,
	HXGE_FM_EREPORT_RDMC_CTRL_FIFO_SEC,
	HXGE_FM_EREPORT_RDMC_DATA_FIFO_SEC
} hxge_fm_ereport_rdmc_t;

typedef	enum {
	HXGE_FM_EREPORT_TDMC_PEU_RESP_ERR =
		(FM_TXDMA_ID << EREPORT_FM_ID_SHIFT),
	HXGE_FM_EREPORT_TDMC_PKT_SIZE_HDR_ERR,
	HXGE_FM_EREPORT_TDMC_RUNT_PKT_DROP_ERR,
	HXGE_FM_EREPORT_TDMC_PKT_SIZE_ERR,
	HXGE_FM_EREPORT_TDMC_TX_RNG_OFLOW,
	HXGE_FM_EREPORT_TDMC_PREF_PAR_ERR,
	HXGE_FM_EREPORT_TDMC_TDR_PREF_CPL_TO,
	HXGE_FM_EREPORT_TDMC_PKT_CPL_TO,
	HXGE_FM_EREPORT_TDMC_INVALID_SOP,
	HXGE_FM_EREPORT_TDMC_UNEXPECTED_SOP,
	HXGE_FM_EREPORT_TDMC_REORD_TBL_PAR,
	HXGE_FM_EREPORT_TDMC_REORD_BUF_DED
} hxge_fm_ereport_attr_tdmc_t;

/* PEU ereports */
typedef	enum {
	HXGE_FM_EREPORT_PEU_ERR = (FM_PEU_ID << EREPORT_FM_ID_SHIFT),
	HXGE_FM_EREPORT_PEU_VNM_PIO_ERR
} hxge_fm_ereport_peu_t;

typedef	enum {
	HXGE_FM_EREPORT_SW_INVALID_CHAN_NUM = (FM_SW_ID << EREPORT_FM_ID_SHIFT),
	HXGE_FM_EREPORT_SW_INVALID_PARAM
} hxge_fm_ereport_sw_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_FM_H */
