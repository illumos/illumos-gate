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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NPI_ZCP_H
#define	_NPI_ZCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>
#include <nxge_zcp_hw.h>

typedef	enum zcp_buf_region_e {
	BAM_4BUF			= 1,
	BAM_8BUF			= 2,
	BAM_16BUF			= 3,
	BAM_32BUF			= 4
} zcp_buf_region_t;

typedef enum zcp_config_e {
	CFG_ZCP				= 0x01,
	CFG_ZCP_ECC_CHK			= 0x02,
	CFG_ZCP_PAR_CHK			= 0x04,
	CFG_ZCP_BUF_RESP		= 0x08,
	CFG_ZCP_BUF_REQ			= 0x10,
	CFG_ZCP_ALL			= 0x1F
} zcp_config_t;

typedef enum zcp_iconfig_e {
	ICFG_ZCP_RRFIFO_UNDERRUN	= RRFIFO_UNDERRUN,
	ICFG_ZCP_RRFIFO_OVERRUN		= RRFIFO_OVERRUN,
	ICFG_ZCP_RSPFIFO_UNCORR_ERR	= RSPFIFO_UNCORR_ERR,
	ICFG_ZCP_BUFFER_OVERFLOW	= BUFFER_OVERFLOW,
	ICFG_ZCP_STAT_TBL_PERR		= STAT_TBL_PERR,
	ICFG_ZCP_DYN_TBL_PERR		= BUF_DYN_TBL_PERR,
	ICFG_ZCP_BUF_TBL_PERR		= BUF_TBL_PERR,
	ICFG_ZCP_TT_PROGRAM_ERR		= TT_PROGRAM_ERR,
	ICFG_ZCP_RSP_TT_INDEX_ERR	= RSP_TT_INDEX_ERR,
	ICFG_ZCP_SLV_TT_INDEX_ERR	= SLV_TT_INDEX_ERR,
	ICFG_ZCP_TT_INDEX_ERR		= ZCP_TT_INDEX_ERR,
	ICFG_ZCP_CFIFO_ECC3		= CFIFO_ECC3,
	ICFG_ZCP_CFIFO_ECC2		= CFIFO_ECC2,
	ICFG_ZCP_CFIFO_ECC1		= CFIFO_ECC1,
	ICFG_ZCP_CFIFO_ECC0		= CFIFO_ECC0,
	ICFG_ZCP_ALL			= (RRFIFO_UNDERRUN | RRFIFO_OVERRUN |
				RSPFIFO_UNCORR_ERR | STAT_TBL_PERR |
				BUF_DYN_TBL_PERR | BUF_TBL_PERR |
				TT_PROGRAM_ERR | RSP_TT_INDEX_ERR |
				SLV_TT_INDEX_ERR | ZCP_TT_INDEX_ERR |
				CFIFO_ECC3 | CFIFO_ECC2 |  CFIFO_ECC1 |
				CFIFO_ECC0 | BUFFER_OVERFLOW)
} zcp_iconfig_t;

typedef enum tte_sflow_attr_mask_e {
	TTE_RDC_TBL_OFF			= 0x0001,
	TTE_BUF_SIZE			= 0x0002,
	TTE_NUM_BUF			= 0x0004,
	TTE_ULP_END			= 0x0008,
	TTE_ULP_END_EN			= 0x0010,
	TTE_UNMAP_ALL_EN		= 0x0020,
	TTE_TMODE			= 0x0040,
	TTE_SKIP			= 0x0080,
	TTE_HBM_RING_BASE_ADDR		= 0x0100,
	TTE_HBM_RING_SIZE		= 0x0200,
	TTE_HBM_BUSY			= 0x0400,
	TTE_HBM_TOQ			= 0x0800,
	TTE_SFLOW_ATTR_ALL		= 0x0FFF
} tte_sflow_attr_mask_t;

typedef	enum tte_dflow_attr_mask_e {
	TTE_MAPPED_IN			= 0x0001,
	TTE_ANCHOR_SEQ			= 0x0002,
	TTE_ANCHOR_OFFSET		= 0x0004,
	TTE_ANCHOR_BUFFER		= 0x0008,
	TTE_ANCHOR_BUF_FLAG		= 0x0010,
	TTE_UNMAP_ON_LEFT		= 0x0020,
	TTE_ULP_END_REACHED		= 0x0040,
	TTE_ERR_STAT			= 0x0080,
	TTE_HBM_WR_PTR			= 0x0100,
	TTE_HBM_HOQ			= 0x0200,
	TTE_HBM_PREFETCH_ON		= 0x0400,
	TTE_DFLOW_ATTR_ALL		= 0x07FF
} tte_dflow_attr_mask_t;

#define	IS_VALID_BAM_REGION(region)\
		((region == BAM_4BUF) || (region == BAM_8BUF) ||\
		(region == BAM_16BUF) || (region == BAM_32BUF))

#define	ZCP_WAIT_RAM_READY(handle, val) {\
	uint32_t cnt = MAX_PIO_RETRIES;\
	do {\
		NXGE_REG_RD64(handle, ZCP_RAM_ACC_REG, &val);\
		cnt--;\
	} while ((ram_ctl.bits.ldw.busy != 0) && (cnt > 0));\
}

#define	ZCP_DMA_THRES_INVALID		0x10
#define	ZCP_BAM_REGION_INVALID		0x11
#define	ZCP_ROW_INDEX_INVALID		0x12
#define	ZCP_SFLOW_ATTR_INVALID		0x13
#define	ZCP_DFLOW_ATTR_INVALID		0x14
#define	ZCP_FLOW_ID_INVALID		0x15
#define	ZCP_BAM_BANK_INVALID		0x16
#define	ZCP_BAM_WORD_EN_INVALID		0x17

#define	NPI_ZCP_OPCODE_INVALID		((ZCP_BLK_ID << 8) | OPCODE_INVALID)
#define	NPI_ZCP_CONFIG_INVALID		((ZCP_BLK_ID << 8) | CONFIG_INVALID)
#define	NPI_ZCP_DMA_THRES_INVALID	((ZCP_BLK_ID << 8) |\
					ZCP_DMA_THRES_INVALID)
#define	NPI_ZCP_BAM_REGION_INVALID	((ZCP_BLK_ID << 8) |\
					ZCP_BAM_REGION_INVALID)
#define	NPI_ZCP_ROW_INDEX_INVALID	((ZCP_BLK_ID << 8) |\
					ZCP_ROW_INDEX_INVALID)
#define	NPI_ZCP_SFLOW_ATTR_INVALID	((ZCP_BLK_ID << 8) |\
					ZCP_SFLOW_ATTR_INVALID)
#define	NPI_ZCP_DFLOW_ATTR_INVALID	((ZCP_BLK_ID << 8) |\
					ZCP_DFLOW_ATTR_INVALID)
#define	NPI_ZCP_FLOW_ID_INVALID		((ZCP_BLK_ID << 8) |\
					ZCP_FLOW_ID_INVALID)
#define	NPI_ZCP_MEM_WRITE_FAILED	((ZCP_BLK_ID << 8) | WRITE_FAILED)
#define	NPI_ZCP_MEM_READ_FAILED		((ZCP_BLK_ID << 8) | READ_FAILED)
#define	NPI_ZCP_BAM_BANK_INVALID	((ZCP_BLK_ID << 8) |\
					(ZCP_BAM_BANK_INVALID))
#define	NPI_ZCP_BAM_WORD_EN_INVALID	((ZCP_BLK_ID << 8) |\
					(ZCP_BAM_WORD_EN_INVALID))
#define	NPI_ZCP_PORT_INVALID(portn)	((ZCP_BLK_ID << 8) | PORT_INVALID |\
					(portn << 12))

/* ZCP HW NPI Prototypes */
npi_status_t npi_zcp_config(npi_handle_t, config_op_t,
				zcp_config_t);
npi_status_t npi_zcp_iconfig(npi_handle_t, config_op_t,
				zcp_iconfig_t);
npi_status_t npi_zcp_get_istatus(npi_handle_t, zcp_iconfig_t *);
npi_status_t npi_zcp_clear_istatus(npi_handle_t);
npi_status_t npi_zcp_set_dma_thresh(npi_handle_t, uint16_t);
npi_status_t npi_zcp_set_bam_region(npi_handle_t,
				zcp_buf_region_t,
				zcp_bam_region_reg_t *);
npi_status_t npi_zcp_set_sdt_region(npi_handle_t,
				zcp_buf_region_t, uint16_t);
npi_status_t npi_zcp_tt_static_entry(npi_handle_t, io_op_t,
				uint16_t, tte_sflow_attr_mask_t,
				tte_sflow_attr_t *);
npi_status_t npi_zcp_tt_dynamic_entry(npi_handle_t, io_op_t,
				uint16_t, tte_dflow_attr_mask_t,
				tte_dflow_attr_t *);
npi_status_t npi_zcp_tt_bam_entry(npi_handle_t, io_op_t,
				uint16_t, uint8_t,
				uint8_t, zcp_ram_unit_t *);
npi_status_t npi_zcp_tt_cfifo_entry(npi_handle_t, io_op_t,
				uint8_t, uint16_t,
				zcp_ram_unit_t *);

npi_status_t npi_zcp_rest_cfifo_port(npi_handle_t, uint8_t);
npi_status_t npi_zcp_rest_cfifo_all(npi_handle_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_ZCP_H */
