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

#ifndef _NPI_TXC_H
#define	_NPI_TXC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>
#include <nxge_txc_hw.h>

/*
 * Transmit Controller (TXC) NPI error codes
 */
#define	TXC_ER_ST			(TXC_BLK_ID << NPI_BLOCK_ID_SHIFT)
#define	TXC_ID_SHIFT(n)			(n << NPI_PORT_CHAN_SHIFT)

#define	NPI_TXC_PORT_INVALID(n)		(TXC_ID_SHIFT(n) | IS_PORT |\
					TXC_ER_ST | PORT_INVALID)

#define	NPI_TXC_CHANNEL_INVALID(n)	(TXC_ID_SHIFT(n) | IS_PORT |\
					TXC_ER_ST | CHANNEL_INVALID)

#define	NPI_TXC_OPCODE_INVALID(n)	(TXC_ID_SHIFT(n) | IS_PORT |\
					TXC_ER_ST | OPCODE_INVALID)

/*
 * Register offset (0x1000 bytes for each channel) for TXC registers.
 */
#define	NXGE_TXC_FZC_OFFSET(x, cn)	(x + TXC_FZC_CHANNEL_OFFSET(cn))

/*
 * Register offset (0x100 bytes for each port) for TXC Function zero
 * control registers.
 */
#define	NXGE_TXC_FZC_CNTL_OFFSET(x, port) (x + \
			TXC_FZC_CNTL_PORT_OFFSET(port))
/*
 * PIO macros to read and write the transmit control registers.
 */
#define	TXC_FZC_REG_READ64(handle, reg, cn, val_p)	\
		NXGE_REG_RD64(handle, \
		(NXGE_TXC_FZC_OFFSET(reg, cn)), val_p)

#define	TXC_FZC_REG_WRITE64(handle, reg, cn, data)	\
		NXGE_REG_WR64(handle, \
		(NXGE_TXC_FZC_OFFSET(reg, cn)), data)

#define	TXC_FZC_CNTL_REG_READ64(handle, reg, port, val_p)	\
		NXGE_REG_RD64(handle, \
		(NXGE_TXC_FZC_CNTL_OFFSET(reg, port)), val_p)

#define	TXC_FZC_CNTL_REG_WRITE64(handle, reg, port, data)	\
		NXGE_REG_WR64(handle, \
		(NXGE_TXC_FZC_CNTL_OFFSET(reg, port)), data)

/*
 * TXC (Transmit Controller) prototypes.
 */
npi_status_t npi_txc_dma_max_burst(npi_handle_t, io_op_t,
		uint8_t, uint32_t *);
npi_status_t npi_txc_dma_max_burst_set(npi_handle_t, uint8_t,
		uint32_t);
npi_status_t npi_txc_dma_bytes_transmitted(npi_handle_t,
		uint8_t, uint32_t *);
npi_status_t npi_txc_control(npi_handle_t, io_op_t,
		p_txc_control_t);
npi_status_t npi_txc_global_enable(npi_handle_t);
npi_status_t npi_txc_global_disable(npi_handle_t);
npi_status_t npi_txc_control_clear(npi_handle_t, uint8_t);
npi_status_t npi_txc_training_set(npi_handle_t, uint32_t);
npi_status_t npi_txc_training_get(npi_handle_t, uint32_t *);
npi_status_t npi_txc_port_control_get(npi_handle_t, uint8_t,
		uint32_t *);
npi_status_t npi_txc_port_enable(npi_handle_t, uint8_t);
npi_status_t npi_txc_port_disable(npi_handle_t, uint8_t);
npi_status_t npi_txc_dma_max_burst(npi_handle_t, io_op_t,
		uint8_t, uint32_t *);
npi_status_t npi_txc_port_dma_enable(npi_handle_t, uint8_t,
		uint32_t);
npi_status_t npi_txc_port_dma_list_get(npi_handle_t, uint8_t,
		uint32_t *);
npi_status_t npi_txc_port_dma_channel_enable(npi_handle_t, uint8_t,
		uint8_t);
npi_status_t npi_txc_port_dma_channel_disable(npi_handle_t, uint8_t,
		uint8_t);

npi_status_t npi_txc_pkt_stuffed_get(npi_handle_t, uint8_t,
		uint32_t *, uint32_t *);
npi_status_t npi_txc_pkt_xmt_to_mac_get(npi_handle_t, uint8_t,
		uint32_t *, uint32_t *);
npi_status_t npi_txc_reorder_get(npi_handle_t, uint8_t,
		uint32_t *);
npi_status_t npi_txc_dump_tdc_fzc_regs(npi_handle_t, uint8_t);
npi_status_t npi_txc_dump_fzc_regs(npi_handle_t);
npi_status_t npi_txc_dump_port_fzc_regs(npi_handle_t, uint8_t);
npi_status_t npi_txc_ro_states_get(npi_handle_t, uint8_t,
		txc_ro_states_t *);
npi_status_t npi_txc_ro_ecc_state_clr(npi_handle_t, uint8_t);
npi_status_t npi_txc_sf_states_get(npi_handle_t, uint8_t,
		txc_sf_states_t *);
npi_status_t npi_txc_sf_ecc_state_clr(npi_handle_t, uint8_t);
void npi_txc_global_istatus_get(npi_handle_t, txc_int_stat_t *);
void npi_txc_global_istatus_clear(npi_handle_t, uint64_t);
void npi_txc_global_imask_set(npi_handle_t, uint8_t,
		uint8_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_TXC_H */
