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

#ifndef _NPI_TXDMA_H
#define	_NPI_TXDMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi.h>
#include <nxge_txdma_hw.h>

#define	DMA_LOG_PAGE_FN_VALIDATE(cn, pn, fn, status)	\
{									\
	status = NPI_SUCCESS;						\
	if (!TXDMA_CHANNEL_VALID(channel)) {				\
		status = (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(cn));	\
	} else if (!TXDMA_PAGE_VALID(pn)) {			\
		status =  (NPI_FAILURE | NPI_TXDMA_PAGE_INVALID(pn));	\
	} else if (!TXDMA_FUNC_VALID(fn)) {			\
		status =  (NPI_FAILURE | NPI_TXDMA_FUNC_INVALID(fn));	\
	} \
}

#define	DMA_LOG_PAGE_VALIDATE(cn, pn, status)	\
{									\
	status = NPI_SUCCESS;						\
	if (!TXDMA_CHANNEL_VALID(channel)) {				\
		status = (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(cn));	\
	} else if (!TXDMA_PAGE_VALID(pn)) {			\
		status =  (NPI_FAILURE | NPI_TXDMA_PAGE_INVALID(pn));	\
	} \
}

typedef	enum _txdma_cs_cntl_e {
	TXDMA_INIT_RESET	= 0x1,
	TXDMA_INIT_START	= 0x2,
	TXDMA_START		= 0x3,
	TXDMA_RESET		= 0x4,
	TXDMA_STOP		= 0x5,
	TXDMA_RESUME		= 0x6,
	TXDMA_CLEAR_MMK		= 0x7,
	TXDMA_MBOX_ENABLE	= 0x8
} txdma_cs_cntl_t;

typedef	enum _txdma_log_cfg_e {
	TXDMA_LOG_PAGE_MASK	= 0x01,
	TXDMA_LOG_PAGE_VALUE	= 0x02,
	TXDMA_LOG_PAGE_RELOC	= 0x04,
	TXDMA_LOG_PAGE_VALID	= 0x08,
	TXDMA_LOG_PAGE_ALL	= (TXDMA_LOG_PAGE_MASK | TXDMA_LOG_PAGE_VALUE |
				TXDMA_LOG_PAGE_RELOC | TXDMA_LOG_PAGE_VALID)
} txdma_log_cfg_t;

typedef	enum _txdma_ent_msk_cfg_e {
	CFG_TXDMA_PKT_PRT_MASK		= TX_ENT_MSK_PKT_PRT_ERR_MASK,
	CFG_TXDMA_CONF_PART_MASK	= TX_ENT_MSK_CONF_PART_ERR_MASK,
	CFG_TXDMA_NACK_PKT_RD_MASK	= TX_ENT_MSK_NACK_PKT_RD_MASK,
	CFG_TXDMA_NACK_PREF_MASK	= TX_ENT_MSK_NACK_PREF_MASK,
	CFG_TXDMA_PREF_BUF_ECC_ERR_MASK	= TX_ENT_MSK_PREF_BUF_ECC_ERR_MASK,
	CFG_TXDMA_TX_RING_OFLOW_MASK	= TX_ENT_MSK_TX_RING_OFLOW_MASK,
	CFG_TXDMA_PKT_SIZE_ERR_MASK	= TX_ENT_MSK_PKT_SIZE_ERR_MASK,
	CFG_TXDMA_MBOX_ERR_MASK		= TX_ENT_MSK_MBOX_ERR_MASK,
	CFG_TXDMA_MK_MASK		= TX_ENT_MSK_MK_MASK,
	CFG_TXDMA_MASK_ALL		= (TX_ENT_MSK_PKT_PRT_ERR_MASK |
					TX_ENT_MSK_CONF_PART_ERR_MASK |
					TX_ENT_MSK_NACK_PKT_RD_MASK |
					TX_ENT_MSK_NACK_PREF_MASK |
					TX_ENT_MSK_PREF_BUF_ECC_ERR_MASK |
					TX_ENT_MSK_TX_RING_OFLOW_MASK |
					TX_ENT_MSK_PKT_SIZE_ERR_MASK |
					TX_ENT_MSK_MBOX_ERR_MASK |
					TX_ENT_MSK_MK_MASK)
} txdma_ent_msk_cfg_t;


typedef	struct _txdma_ring_errlog {
	tx_rng_err_logl_t	logl;
	tx_rng_err_logh_t	logh;
} txdma_ring_errlog_t, *p_txdma_ring_errlog_t;

/*
 * Register offset (0x200 bytes for each channel) for logical pages registers.
 */
#define	NXGE_TXLOG_OFFSET(x, channel) (x + TX_LOG_DMA_OFFSET(channel))

/*
 * Register offset (0x200 bytes for each channel) for transmit ring registers.
 * (Ring configuration, kick register, event mask, control and status,
 *  mailbox, prefetch, ring errors).
 */
#define	NXGE_TXDMA_OFFSET(x, v, channel) (x + \
		(!v ? DMC_OFFSET(channel) : TDMC_PIOVADDR_OFFSET(channel)))
/*
 * Register offset (0x8 bytes for each port) for transmit mapping registers.
 */
#define	NXGE_TXDMA_MAP_OFFSET(x, port) (x + TX_DMA_MAP_PORT_OFFSET(port))

/*
 * Register offset (0x10 bytes for each channel) for transmit DRR and ring
 * usage registers.
 */
#define	NXGE_TXDMA_DRR_OFFSET(x, channel) (x + \
			TXDMA_DRR_RNG_USE_OFFSET(channel))

/*
 * PIO macros to read and write the transmit registers.
 */
#define	TX_LOG_REG_READ64(handle, reg, channel, val_p)	\
	NXGE_REG_RD64(handle, NXGE_TXLOG_OFFSET(reg, channel), val_p)

#define	TX_LOG_REG_WRITE64(handle, reg, channel, data)	\
	NXGE_REG_WR64(handle, NXGE_TXLOG_OFFSET(reg, channel), data)

/*
 * Transmit Descriptor Definitions.
 */
#define	TXDMA_DESC_SIZE			(sizeof (tx_desc_t))

#define	NPI_TXDMA_GATHER_INDEX(index)	\
	((index <= TX_MAX_GATHER_POINTERS)) ? NPI_SUCCESS : \
				(NPI_TXDMA_GATHER_INVALID)

/*
 * Transmit NPI error codes
 */
#define	TXDMA_ER_ST			(TXDMA_BLK_ID << NPI_BLOCK_ID_SHIFT)
#define	TXDMA_ID_SHIFT(n)		(n << NPI_PORT_CHAN_SHIFT)

#define	TXDMA_HW_STOP_FAILED		(NPI_BK_HW_ER_START | 0x1)
#define	TXDMA_HW_RESUME_FAILED		(NPI_BK_HW_ER_START | 0x2)

#define	TXDMA_GATHER_INVALID		(NPI_BK_ERROR_START | 0x1)
#define	TXDMA_XFER_LEN_INVALID		(NPI_BK_ERROR_START | 0x2)

#define	NPI_TXDMA_OPCODE_INVALID(n)	(TXDMA_ID_SHIFT(n) |	\
					TXDMA_ER_ST | OPCODE_INVALID)

#define	NPI_TXDMA_FUNC_INVALID(n)	(TXDMA_ID_SHIFT(n) |	\
					TXDMA_ER_ST | PORT_INVALID)
#define	NPI_TXDMA_CHANNEL_INVALID(n)	(TXDMA_ID_SHIFT(n) |	\
					TXDMA_ER_ST | CHANNEL_INVALID)

#define	NPI_TXDMA_PAGE_INVALID(n)	(TXDMA_ID_SHIFT(n) |	\
					TXDMA_ER_ST | LOGICAL_PAGE_INVALID)

#define	NPI_TXDMA_REGISTER_INVALID	(TXDMA_ER_ST | REGISTER_INVALID)
#define	NPI_TXDMA_COUNTER_INVALID	(TXDMA_ER_ST | COUNTER_INVALID)
#define	NPI_TXDMA_CONFIG_INVALID	(TXDMA_ER_ST | CONFIG_INVALID)


#define	NPI_TXDMA_GATHER_INVALID	(TXDMA_ER_ST | TXDMA_GATHER_INVALID)
#define	NPI_TXDMA_XFER_LEN_INVALID	(TXDMA_ER_ST | TXDMA_XFER_LEN_INVALID)

#define	NPI_TXDMA_RESET_FAILED		(TXDMA_ER_ST | RESET_FAILED)
#define	NPI_TXDMA_STOP_FAILED		(TXDMA_ER_ST | TXDMA_HW_STOP_FAILED)
#define	NPI_TXDMA_RESUME_FAILED		(TXDMA_ER_ST | TXDMA_HW_RESUME_FAILED)

/*
 * Transmit DMA Channel NPI Prototypes.
 */
npi_status_t npi_txdma_mode32_set(npi_handle_t, boolean_t);
npi_status_t npi_txdma_log_page_set(npi_handle_t, uint8_t,
		p_dma_log_page_t);
npi_status_t npi_txdma_log_page_get(npi_handle_t, uint8_t,
		p_dma_log_page_t);
npi_status_t npi_txdma_log_page_handle_set(npi_handle_t, uint8_t,
		p_log_page_hdl_t);
npi_status_t npi_txdma_log_page_config(npi_handle_t, io_op_t,
		txdma_log_cfg_t, uint8_t, p_dma_log_page_t);
npi_status_t npi_txdma_log_page_vld_config(npi_handle_t, io_op_t,
		uint8_t, p_log_page_vld_t);
npi_status_t npi_txdma_drr_weight_set(npi_handle_t, uint8_t,
		uint32_t);
npi_status_t npi_txdma_channel_reset(npi_handle_t, uint8_t);
npi_status_t npi_txdma_channel_init_enable(npi_handle_t,
		uint8_t);
npi_status_t npi_txdma_channel_enable(npi_handle_t, uint8_t);
npi_status_t npi_txdma_channel_disable(npi_handle_t, uint8_t);
npi_status_t npi_txdma_channel_resume(npi_handle_t, uint8_t);
npi_status_t npi_txdma_channel_mmk_clear(npi_handle_t, uint8_t);
npi_status_t npi_txdma_channel_mbox_enable(npi_handle_t, uint8_t);
npi_status_t npi_txdma_channel_control(npi_handle_t,
		txdma_cs_cntl_t, uint8_t);
npi_status_t npi_txdma_control_status(npi_handle_t, io_op_t,
		uint8_t, p_tx_cs_t);

npi_status_t npi_txdma_event_mask(npi_handle_t, io_op_t,
		uint8_t, p_tx_dma_ent_msk_t);
npi_status_t npi_txdma_event_mask_config(npi_handle_t, io_op_t,
		uint8_t, txdma_ent_msk_cfg_t *);
npi_status_t npi_txdma_event_mask_mk_out(npi_handle_t, uint8_t);
npi_status_t npi_txdma_event_mask_mk_in(npi_handle_t, uint8_t);

npi_status_t npi_txdma_ring_addr_set(npi_handle_t, uint8_t,
		uint64_t, uint32_t);
npi_status_t npi_txdma_ring_config(npi_handle_t, io_op_t,
		uint8_t, uint64_t *);
npi_status_t npi_txdma_mbox_config(npi_handle_t, io_op_t,
		uint8_t, uint64_t *);
npi_status_t npi_txdma_desc_gather_set(npi_handle_t,
		p_tx_desc_t, uint8_t,
		boolean_t, uint8_t,
		uint64_t, uint32_t);

npi_status_t npi_txdma_desc_gather_sop_set(npi_handle_t,
		p_tx_desc_t, boolean_t, uint8_t);

npi_status_t npi_txdma_desc_gather_sop_set_1(npi_handle_t,
		p_tx_desc_t, boolean_t, uint8_t,
		uint32_t);

npi_status_t npi_txdma_desc_set_xfer_len(npi_handle_t,
		p_tx_desc_t, uint32_t);

npi_status_t npi_txdma_desc_set_zero(npi_handle_t, uint16_t);
npi_status_t npi_txdma_desc_mem_get(npi_handle_t, uint16_t,
		p_tx_desc_t);
npi_status_t npi_txdma_desc_kick_reg_set(npi_handle_t, uint8_t,
		uint16_t, boolean_t);
npi_status_t npi_txdma_desc_kick_reg_get(npi_handle_t, uint8_t,
		p_tx_ring_kick_t);
npi_status_t npi_txdma_ring_head_get(npi_handle_t, uint8_t,
		p_tx_ring_hdl_t);
npi_status_t npi_txdma_channel_mbox_get(npi_handle_t, uint8_t,
		p_txdma_mailbox_t);
npi_status_t npi_txdma_channel_pre_state_get(npi_handle_t,
		uint8_t, p_tx_dma_pre_st_t);
npi_status_t npi_txdma_ring_error_get(npi_handle_t,
		uint8_t, p_txdma_ring_errlog_t);
npi_status_t npi_txdma_inj_par_error_clear(npi_handle_t);
npi_status_t npi_txdma_inj_par_error_set(npi_handle_t,
		uint32_t);
npi_status_t npi_txdma_inj_par_error_update(npi_handle_t,
		uint32_t);
npi_status_t npi_txdma_inj_par_error_get(npi_handle_t,
		uint32_t *);
npi_status_t npi_txdma_dbg_sel_set(npi_handle_t, uint8_t);
npi_status_t npi_txdma_training_vector_set(npi_handle_t,
		uint32_t);
void npi_txdma_dump_desc_one(npi_handle_t, p_tx_desc_t,
	int);
npi_status_t npi_txdma_dump_tdc_regs(npi_handle_t, uint8_t);
npi_status_t npi_txdma_dump_fzc_regs(npi_handle_t);
npi_status_t npi_txdma_inj_int_error_set(npi_handle_t, uint8_t,
	p_tdmc_intr_dbg_t);
#ifdef	__cplusplus
}
#endif

#endif	/* _NPI_TXDMA_H */
