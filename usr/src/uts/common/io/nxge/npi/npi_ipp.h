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

#ifndef _NPI_IPP_H
#define	_NPI_IPP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>
#include <nxge_ipp_hw.h>

/* IBTP IPP Configuration */

typedef enum ipp_config_e {
	CFG_IPP =			IPP_EN,
	CFG_IPP_DFIFO_ECC_CORRECT =	IPP_DFIFO_ECC_CORRECT_EN,
	CFG_IPP_DROP_BAD_CRC =		IPP_DROP_BAD_CRC_EN,
	CFG_IPP_TCP_UDP_CKSUM =		IPP_TCP_UDP_CKSUM_EN,
	CFG_IPP_DFIFO_PIO_WR =		IPP_DFIFO_PIO_WR_EN,
	CFG_IPP_PRE_FIFO_PIO_WR =	IPP_PRE_FIFO_PIO_WR_EN,
	CFG_IPP_FFLP_CKSUM_INFO_PIO_WR = IPP_FFLP_CKSUM_INFO_PIO_WR_EN,
	CFG_IPP_ALL =			(IPP_EN | IPP_DFIFO_ECC_CORRECT_EN |
			IPP_DROP_BAD_CRC_EN | IPP_TCP_UDP_CKSUM_EN |
			IPP_DFIFO_PIO_WR_EN | IPP_PRE_FIFO_PIO_WR_EN)
} ipp_config_t;

typedef enum ipp_iconfig_e {
	ICFG_IPP_PKT_DISCARD_OVFL =	IPP_PKT_DISCARD_CNT_INTR_DIS,
	ICFG_IPP_BAD_TCPIP_CKSUM_OVFL =	IPP_BAD_TCPIP_CKSUM_CNT_INTR_DIS,
	ICFG_IPP_PRE_FIFO_UNDERRUN =	IPP_PRE_FIFO_UNDERRUN_INTR_DIS,
	ICFG_IPP_PRE_FIFO_OVERRUN =	IPP_PRE_FIFO_OVERRUN_INTR_DIS,
	ICFG_IPP_PRE_FIFO_PERR =	IPP_PRE_FIFO_PERR_INTR_DIS,
	ICFG_IPP_DFIFO_ECC_UNCORR_ERR =	IPP_DFIFO_ECC_UNCORR_ERR_INTR_DIS,
	ICFG_IPP_DFIFO_MISSING_EOP_SOP = IPP_DFIFO_MISSING_EOP_SOP_INTR_DIS,
	ICFG_IPP_ECC_ERR_OVFL =		IPP_ECC_ERR_CNT_MAX_INTR_DIS,
	ICFG_IPP_ALL =			(IPP_PKT_DISCARD_CNT_INTR_DIS |
			IPP_BAD_TCPIP_CKSUM_CNT_INTR_DIS |
			IPP_PRE_FIFO_UNDERRUN_INTR_DIS |
			IPP_PRE_FIFO_OVERRUN_INTR_DIS |
			IPP_PRE_FIFO_PERR_INTR_DIS |
			IPP_DFIFO_ECC_UNCORR_ERR_INTR_DIS |
			IPP_DFIFO_MISSING_EOP_SOP_INTR_DIS |
			IPP_ECC_ERR_CNT_MAX_INTR_DIS)
} ipp_iconfig_t;

typedef enum ipp_counter_e {
	CNT_IPP_DISCARD_PKT		= 0x00000001,
	CNT_IPP_TCP_CKSUM_ERR		= 0x00000002,
	CNT_IPP_ECC_ERR			= 0x00000004,
	CNT_IPP_ALL			= 0x00000007
} ipp_counter_t;


typedef enum ipp_port_cnt_idx_e {
	HWCI_IPP_PKT_DISCARD = 0,
	HWCI_IPP_TCP_CKSUM_ERR,
	HWCI_IPP_ECC_ERR,
	CI_IPP_MISSING_EOP_SOP,
	CI_IPP_UNCORR_ERR,
	CI_IPP_PERR,
	CI_IPP_FIFO_OVERRUN,
	CI_IPP_FIFO_UNDERRUN,
	CI_IPP_PORT_CNT_ARR_SIZE
} ipp_port_cnt_idx_t;

/* IPP specific errors */

#define	IPP_MAX_PKT_BYTES_INVALID	0x50
#define	IPP_FIFO_ADDR_INVALID		0x51

/* IPP error return macros */

#define	NPI_IPP_PORT_INVALID(portn)\
		((IPP_BLK_ID << NPI_BLOCK_ID_SHIFT) | PORT_INVALID |\
				IS_PORT | (portn << NPI_PORT_CHAN_SHIFT))
#define	NPI_IPP_OPCODE_INVALID(portn)\
		((IPP_BLK_ID << NPI_BLOCK_ID_SHIFT) | OPCODE_INVALID |\
				IS_PORT | (portn << NPI_PORT_CHAN_SHIFT))
#define	NPI_IPP_CONFIG_INVALID(portn)\
		((IPP_BLK_ID << NPI_BLOCK_ID_SHIFT) | CONFIG_INVALID |\
				IS_PORT | (portn << NPI_PORT_CHAN_SHIFT))
#define	NPI_IPP_MAX_PKT_BYTES_INVALID(portn)\
		((IPP_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
		IPP_MAX_PKT_BYTES_INVALID |\
				IS_PORT | (portn << NPI_PORT_CHAN_SHIFT))
#define	NPI_IPP_COUNTER_INVALID(portn)\
		((IPP_BLK_ID << NPI_BLOCK_ID_SHIFT) | COUNTER_INVALID |\
				IS_PORT | (portn << NPI_PORT_CHAN_SHIFT))
#define	NPI_IPP_RESET_FAILED(portn)\
		((IPP_BLK_ID << NPI_BLOCK_ID_SHIFT) | RESET_FAILED |\
				IS_PORT | (portn << NPI_PORT_CHAN_SHIFT))
#define	NPI_IPP_FIFO_ADDR_INVALID(portn)\
		((IPP_BLK_ID << NPI_BLOCK_ID_SHIFT) |\
		IPP_FIFO_ADDR_INVALID |\
				IS_PORT | (portn << NPI_PORT_CHAN_SHIFT))

#define	IPP_REG_RD(handle, portn, reg, val) {\
	NXGE_REG_RD64(handle, IPP_REG_ADDR(portn, reg), val);\
}

#define	IPP_REG_WR(handle, portn, reg, val) {\
	NXGE_REG_WR64(handle, IPP_REG_ADDR(portn, reg), val);\
}

/* IPP NPI function prototypes */
npi_status_t npi_ipp_get_pfifo_rd_ptr(npi_handle_t, uint8_t,
			    uint16_t *);

npi_status_t npi_ipp_get_pfifo_wr_ptr(npi_handle_t, uint8_t,
			    uint16_t *);

npi_status_t npi_ipp_write_pfifo(npi_handle_t, uint8_t,
			uint8_t, uint32_t, uint32_t, uint32_t,
			uint32_t, uint32_t);

npi_status_t npi_ipp_read_pfifo(npi_handle_t, uint8_t,
			uint8_t, uint32_t *, uint32_t *, uint32_t *,
			uint32_t *, uint32_t *);

npi_status_t npi_ipp_write_dfifo(npi_handle_t, uint8_t,
			uint16_t, uint32_t, uint32_t, uint32_t,
			uint32_t, uint32_t);

npi_status_t npi_ipp_read_dfifo(npi_handle_t, uint8_t,
			uint16_t, uint32_t *, uint32_t *, uint32_t *,
			uint32_t *, uint32_t *);

npi_status_t npi_ipp_reset(npi_handle_t, uint8_t);
npi_status_t npi_ipp_config(npi_handle_t, config_op_t, uint8_t,
			ipp_config_t);
npi_status_t npi_ipp_set_max_pktsize(npi_handle_t, uint8_t,
			uint32_t);
npi_status_t npi_ipp_iconfig(npi_handle_t, config_op_t, uint8_t,
			ipp_iconfig_t);
npi_status_t npi_ipp_get_status(npi_handle_t, uint8_t,
			ipp_status_t *);
npi_status_t npi_ipp_counters(npi_handle_t, counter_op_t,
			ipp_counter_t, uint8_t, npi_counter_t *);
npi_status_t npi_ipp_get_ecc_syndrome(npi_handle_t, uint8_t,
			uint16_t *);
npi_status_t npi_ipp_get_dfifo_eopm_rdptr(npi_handle_t, uint8_t,
			uint16_t *);
npi_status_t npi_ipp_get_state_mach(npi_handle_t, uint8_t,
			uint32_t *);
npi_status_t npi_ipp_get_dfifo_rd_ptr(npi_handle_t, uint8_t,
			uint16_t *);
npi_status_t npi_ipp_get_dfifo_wr_ptr(npi_handle_t, uint8_t,
			uint16_t *);
npi_status_t npi_ipp_get_ecc_err_count(npi_handle_t, uint8_t,
			uint8_t *);
npi_status_t npi_ipp_get_pkt_dis_count(npi_handle_t, uint8_t,
			uint16_t *);
npi_status_t npi_ipp_get_cs_err_count(npi_handle_t, uint8_t,
			uint16_t *);
npi_status_t npi_ipp_dump_regs(npi_handle_t, uint8_t);
void npi_ipp_read_regs(npi_handle_t, uint8_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_IPP_H */
