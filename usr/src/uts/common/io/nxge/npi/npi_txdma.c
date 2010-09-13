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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <npi_txdma.h>
#include <npi_tx_rd64.h>
#include <npi_tx_wr64.h>

#define	TXDMA_WAIT_LOOP		10000
#define	TXDMA_WAIT_MSEC		5

static npi_status_t npi_txdma_control_reset_wait(npi_handle_t handle,
	uint8_t channel);
static npi_status_t npi_txdma_control_stop_wait(npi_handle_t handle,
	uint8_t channel);
static npi_status_t npi_txdma_control_resume_wait(npi_handle_t handle,
	uint8_t channel);

uint64_t tdc_dmc_offset[] = {
	TX_RNG_CFIG_REG,
	TX_RING_HDL_REG,
	TX_RING_KICK_REG,
	TX_ENT_MSK_REG,
	TX_CS_REG,
	TXDMA_MBH_REG,
	TXDMA_MBL_REG,
	TX_DMA_PRE_ST_REG,
	TX_RNG_ERR_LOGH_REG,
	TX_RNG_ERR_LOGL_REG,
	TDMC_INTR_DBG_REG,
	TX_CS_DBG_REG
};

const char *tdc_dmc_name[] = {
	"TX_RNG_CFIG_REG",
	"TX_RING_HDL_REG",
	"TX_RING_KICK_REG",
	"TX_ENT_MSK_REG",
	"TX_CS_REG",
	"TXDMA_MBH_REG",
	"TXDMA_MBL_REG",
	"TX_DMA_PRE_ST_REG",
	"TX_RNG_ERR_LOGH_REG",
	"TX_RNG_ERR_LOGL_REG",
	"TDMC_INTR_DBG_REG",
	"TX_CS_DBG_REG"
};

uint64_t tdc_fzc_offset [] = {
	TX_LOG_PAGE_VLD_REG,
	TX_LOG_PAGE_MASK1_REG,
	TX_LOG_PAGE_VAL1_REG,
	TX_LOG_PAGE_MASK2_REG,
	TX_LOG_PAGE_VAL2_REG,
	TX_LOG_PAGE_RELO1_REG,
	TX_LOG_PAGE_RELO2_REG,
	TX_LOG_PAGE_HDL_REG
};

const char *tdc_fzc_name [] = {
	"TX_LOG_PAGE_VLD_REG",
	"TX_LOG_PAGE_MASK1_REG",
	"TX_LOG_PAGE_VAL1_REG",
	"TX_LOG_PAGE_MASK2_REG",
	"TX_LOG_PAGE_VAL2_REG",
	"TX_LOG_PAGE_RELO1_REG",
	"TX_LOG_PAGE_RELO2_REG",
	"TX_LOG_PAGE_HDL_REG"
};

uint64_t tx_fzc_offset[] = {
	TX_ADDR_MD_REG,
	TDMC_INJ_PAR_ERR_REG,
	TDMC_DBG_SEL_REG,
	TDMC_TRAINING_REG,
	TXC_PORT_DMA_ENABLE_REG,
	TXC_DMA_MAX_BURST_REG
};

const char *tx_fzc_name[] = {
	"TX_ADDR_MD_REG",
	"TDMC_INJ_PAR_ERR_REG",
	"TDMC_DBG_SEL_REG",
	"TDMC_TRAINING_REG",
	"TXC_PORT_DMA_ENABLE_REG",
	"TXC_DMA_MAX_BURST_REG"
};

#define	NUM_TDC_DMC_REGS	(sizeof (tdc_dmc_offset) / sizeof (uint64_t))
#define	NUM_TX_FZC_REGS	(sizeof (tx_fzc_offset) / sizeof (uint64_t))

/*
 * npi_txdma_dump_tdc_regs
 * Dumps the contents of tdc csrs and fzc registers
 *
 * Input:
 *         tdc:      TX DMA number
 *
 * return:
 *     NPI_SUCCESS
 *     NPI_FAILURE
 *     NPI_TXDMA_CHANNEL_INVALID
 *
 */
npi_status_t
npi_txdma_dump_tdc_regs(npi_handle_t handle, uint8_t tdc)
{

	uint64_t		value, offset;
	int 			num_regs, i;

	ASSERT(TXDMA_CHANNEL_VALID(tdc));
	if (!TXDMA_CHANNEL_VALID(tdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_txdma_dump_tdc_regs"
		    " Invalid TDC number %d \n",
		    tdc));

		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(tdc));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nTXDMA DMC Register Dump for Channel %d\n",
	    tdc));

	num_regs = NUM_TDC_DMC_REGS;
	for (i = 0; i < num_regs; i++) {
		TXDMA_REG_READ64(handle, tdc_dmc_offset[i], tdc, &value);
		offset = NXGE_TXDMA_OFFSET(tdc_dmc_offset[i], handle.is_vraddr,
		    tdc);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%016llx \n",
		    offset, tdc_dmc_name[i],
		    value));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n TXDMA Register Dump for Channel %d done\n", tdc));

	return (NPI_SUCCESS);
}

/*
 * npi_txdma_dump_fzc_regs
 * Dumps the contents of tdc csrs and fzc registers
 *
 * Input:
 *         tdc:      TX DMA number
 *
 * return:
 *     NPI_SUCCESS
 *     NPI_FAILURE
 *     NPI_TXDMA_CHANNEL_INVALID
 *
 */
npi_status_t
npi_txdma_dump_fzc_regs(npi_handle_t handle)
{

	uint64_t value;
	int num_regs, i;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nFZC_DMC Common Register Dump\n"));

	num_regs = NUM_TX_FZC_REGS;
	for (i = 0; i < num_regs; i++) {
#if defined(__i386)
		NXGE_REG_RD64(handle, (uint32_t)tx_fzc_offset[i], &value);
#else
		NXGE_REG_RD64(handle, tx_fzc_offset[i], &value);
#endif
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%08llx \n",
		    tx_fzc_offset[i],
		    tx_fzc_name[i], value));
	}
	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n TXDMA FZC_DMC Register Dump Done \n"));

	return (NPI_SUCCESS);
}

npi_status_t
npi_txdma_tdc_regs_zero(npi_handle_t handle, uint8_t tdc)
{
	uint64_t		value;
	int 			num_regs, i;

	ASSERT(TXDMA_CHANNEL_VALID(tdc));
	if (!TXDMA_CHANNEL_VALID(tdc)) {
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    "npi_txdma_tdc_regs_zero"
		    " InvaliInvalid TDC number %d \n",
		    tdc));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(tdc));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nTXDMA DMC Register (zero) for Channel %d\n",
	    tdc));

	num_regs = NUM_TDC_DMC_REGS;
	value = 0;
	for (i = 0; i < num_regs; i++) {
		TXDMA_REG_WRITE64(handle, tdc_dmc_offset[i], tdc, value);
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nTXDMA FZC_DMC Register clear for Channel %d\n",
	    tdc));

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n TXDMA Register Clear to 0s for Channel %d done\n", tdc));

	return (NPI_SUCCESS);
}

/*
 * npi_txdma_address_mode32_set():
 *	This function is called to only support 32 bit addressing.
 *
 * Parameters:
 *	handle		- NPI handle
 *	mode_enable	- B_TRUE  (enable 32 bit mode)
 *			  B_FALSE (disable 32 bit mode)
 *
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NONE
 */
npi_status_t
npi_txdma_mode32_set(npi_handle_t handle, boolean_t mode_enable)
{
	tx_addr_md_t		mode32;

	mode32.value = 0;
	if (mode_enable) {
		mode32.bits.ldw.mode32 = 1;
	} else {
		mode32.bits.ldw.mode32 = 0;
	}
	NXGE_REG_WR64(handle, TX_ADDR_MD_REG, mode32.value);

	return (NPI_SUCCESS);
}

/*
 * npi_txdma_log_page_set():
 *	This function is called to configure a logical page
 *	(valid bit, mask, value, relocation).
 *
 * Parameters:
 *	handle		- NPI handle
 *	cfgp		- pointer to NPI defined data structure:
 *				- page valid
 * 				- mask
 *				- value
 *				- relocation
 *	channel		- hardware TXDMA channel from 0 to 23.
 *
 * Return:
 *	NPI_SUCCESS		- If configurations are set successfully.
 *
 *	Error:
 *	NPI_FAILURE -
 *		NPI_TXDMA_CHANNEL_INVALID	-
 *		NPI_TXDMA_FUNC_INVALID	-
 *		NPI_TXDMA_PAGE_INVALID	-
 */
npi_status_t
npi_txdma_log_page_set(npi_handle_t handle, uint8_t channel,
		p_dma_log_page_t cfgp)
{
	log_page_vld_t		vld;
	int			status;
	uint64_t		val;
	dma_log_page_t		cfg;

	DMA_LOG_PAGE_FN_VALIDATE(channel, cfgp->page_num, cfgp->func_num,
	    status);
	if (status) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_log_page_set"
		    " npi_status <0x%x>", status));
		return (status);
	}

	TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_VLD_REG, channel, 0);
	TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VLD_REG, channel, &val);

	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "\n==> npi_txdma_log_page_set: WRITE 0 and "
	    " READ back 0x%llx\n ", val));

	vld.value = 0;
	TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VLD_REG, channel, &val);

	val &= 0x3;
	vld.value |= val;

	vld.value = 0;
	vld.bits.ldw.func = cfgp->func_num;

	if (!cfgp->page_num) {
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_MASK1_REG,
		    channel, (cfgp->mask & DMA_LOG_PAGE_MASK_MASK));
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_VAL1_REG,
		    channel, (cfgp->value & DMA_LOG_PAGE_VALUE_MASK));
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_RELO1_REG,
		    channel, (cfgp->reloc & DMA_LOG_PAGE_RELO_MASK));
	} else {
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_MASK2_REG,
		    channel, (cfgp->mask & DMA_LOG_PAGE_MASK_MASK));
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_VAL2_REG,
		    channel, (cfgp->value & DMA_LOG_PAGE_VALUE_MASK));
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_RELO2_REG,
		    channel, (cfgp->reloc & DMA_LOG_PAGE_RELO_MASK));
	}

	TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_VLD_REG, channel,
	    vld.value | (cfgp->valid << cfgp->page_num));

	NPI_DEBUG_MSG((handle.function, NPI_REG_CTL,
	    "\n==> npi_txdma_log_page_set: vld value "
	    " 0x%llx function %d page_valid01 0x%x\n",
	    vld.value,
	    vld.bits.ldw.func,
	    (cfgp->valid << cfgp->page_num)));


	cfg.page_num = 0;
	cfg.func_num = 0;
	(void) npi_txdma_log_page_get(handle, channel, &cfg);
	cfg.page_num = 1;
	(void) npi_txdma_log_page_get(handle, channel, &cfg);

	return (status);
}

/*
 * npi_txdma_log_page_get():
 *	This function is called to get a logical page
 *	(valid bit, mask, value, relocation).
 *
 * Parameters:
 *	handle		- NPI handle
 *	cfgp		- Get the following values (NPI defined structure):
 *				- page valid
 * 				- mask
 *				- value
 *				- relocation
 *	channel		- hardware TXDMA channel from 0 to 23.
 *
 * Return:
 *	NPI_SUCCESS		- If configurations are read successfully.
 *
 *	Error:
 *	NPI_FAILURE -
 *		NPI_TXDMA_CHANNEL_INVALID	-
 *		NPI_TXDMA_FUNC_INVALID	-
 *		NPI_TXDMA_PAGE_INVALID	-
 */
npi_status_t
npi_txdma_log_page_get(npi_handle_t handle, uint8_t channel,
		p_dma_log_page_t cfgp)
{
	log_page_vld_t		vld;
	int			status;
	uint64_t		val;

	DMA_LOG_PAGE_VALIDATE(channel, cfgp->page_num, status);
	if (status) {
		NPI_ERROR_MSG((handle.function, NPI_REG_CTL,
		    " npi_txdma_log_page_get"
		    " npi_status <0x%x>", status));
		return (status);
	}

	vld.value = 0;
	vld.bits.ldw.func = cfgp->func_num;
	TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VLD_REG, channel, &val);

	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "\n==> npi_txdma_log_page_get: read value "
	    " function %d  value 0x%llx\n",
	    cfgp->func_num, val));

	vld.value |= val;
	cfgp->func_num = vld.bits.ldw.func;

	if (!cfgp->page_num) {
		TX_LOG_REG_READ64(handle, TX_LOG_PAGE_MASK1_REG, channel, &val);
		cfgp->mask = val & DMA_LOG_PAGE_MASK_MASK;
		TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VAL1_REG, channel, &val);
		cfgp->value = val & DMA_LOG_PAGE_VALUE_MASK;
		TX_LOG_REG_READ64(handle, TX_LOG_PAGE_RELO1_REG, channel, &val);
		cfgp->reloc = val & DMA_LOG_PAGE_RELO_MASK;
		cfgp->valid = vld.bits.ldw.page0;
	} else {
		TX_LOG_REG_READ64(handle, TX_LOG_PAGE_MASK2_REG, channel, &val);
		cfgp->mask = val & DMA_LOG_PAGE_MASK_MASK;
		TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VAL2_REG, channel, &val);
		cfgp->value = val & DMA_LOG_PAGE_VALUE_MASK;
		TX_LOG_REG_READ64(handle, TX_LOG_PAGE_RELO2_REG, channel, &val);
		cfgp->reloc = val & DMA_LOG_PAGE_RELO_MASK;
		cfgp->valid = vld.bits.ldw.page1;
	}

	return (status);
}

/*
 * npi_txdma_log_page_handle_set():
 *	This function is called to program a page handle
 *	(bits [63:44] of a 64-bit address to generate
 *	a 64 bit address)
 *
 * Parameters:
 *	handle		- NPI handle
 *	hdl_p		- pointer to a logical page handle
 *			  hardware data structure (log_page_hdl_t).
 *	channel		- hardware TXDMA channel from 0 to 23.
 *
 * Return:
 *	NPI_SUCCESS		- If configurations are set successfully.
 *
 *	Error:
 *	NPI_FAILURE -
 *		NPI_TXDMA_CHANNEL_INVALID	-
 *		NPI_TXDMA_FUNC_INVALID	-
 *		NPI_TXDMA_PAGE_INVALID	-
 */
npi_status_t
npi_txdma_log_page_handle_set(npi_handle_t handle, uint8_t channel,
		p_log_page_hdl_t hdl_p)
{
	int			status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_log_page_handle_set"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_HDL_REG,
	    channel, hdl_p->value);

	return (status);
}

/*
 * npi_txdma_log_page_config():
 *	This function is called to IO operations on
 *	 a logical page to set, get, clear
 *	valid bit, mask, value, relocation).
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET, OP_SET, OP_CLEAR
 *	type		- NPI specific config type
 *			   TXDMA_LOG_PAGE_MASK
 *			   TXDMA_LOG_PAGE_VALUE
 *			   TXDMA_LOG_PAGE_RELOC
 *			   TXDMA_LOG_PAGE_VALID
 *			   TXDMA_LOG_PAGE_ALL
 *	channel		- hardware TXDMA channel from 0 to 23.
 *	cfgp		- pointer to the NPI config structure.
 * Return:
 *	NPI_SUCCESS		- If configurations are read successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 *		NPI_TXDMA_FUNC_INVALID	-
 *		NPI_TXDMA_PAGE_INVALID	-
 */
npi_status_t
npi_txdma_log_page_config(npi_handle_t handle, io_op_t op_mode,
		txdma_log_cfg_t type, uint8_t channel,
		p_dma_log_page_t cfgp)
{
	int			status = NPI_SUCCESS;
	uint64_t		val;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_log_page_config"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		switch (type) {
		case TXDMA_LOG_PAGE_ALL:
			return (npi_txdma_log_page_get(handle, channel,
			    cfgp));
		case TXDMA_LOG_PAGE_MASK:
			if (!cfgp->page_num) {
				TX_LOG_REG_READ64(handle, TX_LOG_PAGE_MASK1_REG,
				    channel, &val);
				cfgp->mask = val & DMA_LOG_PAGE_MASK_MASK;
			} else {
				TX_LOG_REG_READ64(handle, TX_LOG_PAGE_MASK2_REG,
				    channel, &val);
				cfgp->mask = val & DMA_LOG_PAGE_MASK_MASK;
			}
			break;

		case TXDMA_LOG_PAGE_VALUE:
			if (!cfgp->page_num) {
				TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VAL1_REG,
				    channel, &val);
				cfgp->value = val & DMA_LOG_PAGE_VALUE_MASK;
			} else {
				TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VAL2_REG,
				    channel, &val);
				cfgp->value = val & DMA_LOG_PAGE_VALUE_MASK;
			}
			break;

		case TXDMA_LOG_PAGE_RELOC:
			if (!cfgp->page_num) {
				TX_LOG_REG_READ64(handle, TX_LOG_PAGE_RELO1_REG,
				    channel, &val);
				cfgp->reloc = val & DMA_LOG_PAGE_RELO_MASK;
			} else {
				TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VAL2_REG,
				    channel, &val);
				cfgp->reloc = val & DMA_LOG_PAGE_RELO_MASK;
			}
			break;

		default:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_txdma_log_page_config"
			    " Invalid Input: pageconfig <0x%x>",
			    type));
			return (NPI_FAILURE |
			    NPI_TXDMA_OPCODE_INVALID(channel));
		}

		break;

	case OP_SET:
	case OP_CLEAR:
		if (op_mode == OP_CLEAR) {
			cfgp->valid = 0;
			cfgp->mask = cfgp->func_num = 0;
			cfgp->value = cfgp->reloc = 0;
		}
		switch (type) {
		case TXDMA_LOG_PAGE_ALL:
			return (npi_txdma_log_page_set(handle, channel,
			    cfgp));
		case TXDMA_LOG_PAGE_MASK:
			if (!cfgp->page_num) {
				TX_LOG_REG_WRITE64(handle,
				    TX_LOG_PAGE_MASK1_REG, channel,
				    (cfgp->mask & DMA_LOG_PAGE_MASK_MASK));
			} else {
				TX_LOG_REG_WRITE64(handle,
				    TX_LOG_PAGE_MASK2_REG, channel,
				    (cfgp->mask & DMA_LOG_PAGE_MASK_MASK));
			}
			break;

		case TXDMA_LOG_PAGE_VALUE:
			if (!cfgp->page_num) {
				TX_LOG_REG_WRITE64(handle,
				    TX_LOG_PAGE_VAL1_REG, channel,
				    (cfgp->value & DMA_LOG_PAGE_VALUE_MASK));
			} else {
				TX_LOG_REG_WRITE64(handle,
				    TX_LOG_PAGE_VAL2_REG, channel,
				    (cfgp->value & DMA_LOG_PAGE_VALUE_MASK));
			}
			break;

		case TXDMA_LOG_PAGE_RELOC:
			if (!cfgp->page_num) {
				TX_LOG_REG_WRITE64(handle,
				    TX_LOG_PAGE_RELO1_REG, channel,
				    (cfgp->reloc & DMA_LOG_PAGE_RELO_MASK));
			} else {
				TX_LOG_REG_WRITE64(handle,
				    TX_LOG_PAGE_RELO2_REG, channel,
				    (cfgp->reloc & DMA_LOG_PAGE_RELO_MASK));
			}
			break;

		default:
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_txdma_log_page_config"
			    " Invalid Input: pageconfig <0x%x>",
			    type));
			return (NPI_FAILURE |
			    NPI_TXDMA_OPCODE_INVALID(channel));
		}

		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_log_page_config"
		    " Invalid Input: op <0x%x>",
		    op_mode));
		return (NPI_FAILURE | NPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * npi_txdma_log_page_vld_config():
 *	This function is called to configure the logical
 *	page valid register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get valid page configuration
 *			  OP_SET: set valid page configuration
 *			  OP_UPDATE: update valid page configuration
 *			  OP_CLEAR: reset both valid pages to
 *			  not defined (0).
 *	channel		- hardware TXDMA channel from 0 to 23.
 *	vld_p		- pointer to hardware defined log page valid register.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE -
 *		NPI_TXDMA_CHANNEL_INVALID -
 *		NPI_TXDMA_OPCODE_INVALID -
 */
npi_status_t
npi_txdma_log_page_vld_config(npi_handle_t handle, io_op_t op_mode,
		uint8_t channel, p_log_page_vld_t vld_p)
{
	int			status = NPI_SUCCESS;
	log_page_vld_t		vld;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_log_page_vld_config"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VLD_REG, channel,
		    &vld_p->value);
		break;

	case OP_SET:
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_VLD_REG,
		    channel, vld_p->value);
		break;

	case OP_UPDATE:
		TX_LOG_REG_READ64(handle, TX_LOG_PAGE_VLD_REG, channel,
		    &vld.value);
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_VLD_REG,
		    channel, vld.value | vld_p->value);
		break;

	case OP_CLEAR:
		TX_LOG_REG_WRITE64(handle, TX_LOG_PAGE_VLD_REG,
		    channel, 0);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_log_pag_vld_cofig"
		    " Invalid Input: pagevld <0x%x>",
		    op_mode));
		return (NPI_FAILURE | NPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * npi_txdma_channel_reset():
 *	This function is called to reset a transmit DMA channel.
 *	(This function is used to reset a channel and reinitialize
 *	 all other bits except RST_STATE).
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *
 * Return:
 *	NPI_SUCCESS		- If reset is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXDMA_CHANNEL_INVALID -
 *		NPI_TXDMA_RESET_FAILED -
 */
npi_status_t
npi_txdma_channel_reset(npi_handle_t handle, uint8_t channel)
{
	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    " npi_txdma_channel_reset"
	    " RESETTING",
	    channel));
	return (npi_txdma_channel_control(handle, TXDMA_RESET, channel));
}

/*
 * npi_txdma_channel_init_enable():
 *	This function is called to start a transmit DMA channel after reset.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS		- If DMA channel is started successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXDMA_CHANNEL_INVALID -
 */
npi_status_t
npi_txdma_channel_init_enable(npi_handle_t handle, uint8_t channel)
{
	return (npi_txdma_channel_control(handle, TXDMA_INIT_START, channel));
}

/*
 * npi_txdma_channel_enable():
 *	This function is called to start a transmit DMA channel.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS		- If DMA channel is stopped successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXDMA_CHANNEL_INVALID -
 */

npi_status_t
npi_txdma_channel_enable(npi_handle_t handle, uint8_t channel)
{
	return (npi_txdma_channel_control(handle, TXDMA_START, channel));
}

/*
 * npi_txdma_channel_disable():
 *	This function is called to stop a transmit DMA channel.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS		- If DMA channel is stopped successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXDMA_CHANNEL_INVALID -
 *		NPI_TXDMA_STOP_FAILED -
 */
npi_status_t
npi_txdma_channel_disable(npi_handle_t handle, uint8_t channel)
{
	return (npi_txdma_channel_control(handle, TXDMA_STOP, channel));
}

/*
 * npi_txdma_channel_resume():
 *	This function is called to restart a transmit DMA channel.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS		- If DMA channel is stopped successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXDMA_CHANNEL_INVALID -
 *		NPI_TXDMA_RESUME_FAILED -
 */
npi_status_t
npi_txdma_channel_resume(npi_handle_t handle, uint8_t channel)
{
	return (npi_txdma_channel_control(handle, TXDMA_RESUME, channel));
}

/*
 * npi_txdma_channel_mmk_clear():
 *	This function is called to clear MMK bit.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS		- If MMK is reset successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXDMA_CHANNEL_INVALID -
 */
npi_status_t
npi_txdma_channel_mmk_clear(npi_handle_t handle, uint8_t channel)
{
	return (npi_txdma_channel_control(handle, TXDMA_CLEAR_MMK, channel));
}

/*
 * npi_txdma_channel_mbox_enable():
 *	This function is called to enable the mailbox update.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS		- If mailbox is enabled successfully.
 *
 *	Error:
 *	NPI_HW_ERROR		-
 *	NPI_FAILURE	-
 *		NPI_TXDMA_CHANNEL_INVALID -
 */
npi_status_t
npi_txdma_channel_mbox_enable(npi_handle_t handle, uint8_t channel)
{
	return (npi_txdma_channel_control(handle, TXDMA_MBOX_ENABLE, channel));
}

/*
 * npi_txdma_channel_control():
 *	This function is called to control a transmit DMA channel
 *	for reset, start or stop.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	control		- NPI defined control type supported
 *				- TXDMA_INIT_RESET
 * 				- TXDMA_INIT_START
 *				- TXDMA_RESET
 *				- TXDMA_START
 *				- TXDMA_STOP
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *
 * Return:
 *	NPI_SUCCESS		- If reset is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 *		NPI_TXDMA_RESET_FAILED	-
 *		NPI_TXDMA_STOP_FAILED	-
 *		NPI_TXDMA_RESUME_FAILED	-
 */
npi_status_t
npi_txdma_channel_control(npi_handle_t handle, txdma_cs_cntl_t control,
		uint8_t channel)
{
	int		status = NPI_SUCCESS;
	tx_cs_t		cs;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_channel_control"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (control) {
	case TXDMA_INIT_RESET:
		cs.value = 0;
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &cs.value);
		cs.bits.ldw.rst = 1;
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs.value);
		return (npi_txdma_control_reset_wait(handle, channel));

	case TXDMA_INIT_START:
		cs.value = 0;
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs.value);
		break;

	case TXDMA_RESET:
		/*
		 * Sets reset bit only (Hardware will reset all
		 * the RW bits but leave the RO bits alone.
		 */
		cs.value = 0;
		cs.bits.ldw.rst = 1;
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs.value);
		return (npi_txdma_control_reset_wait(handle, channel));

	case TXDMA_START:
		/* Enable the DMA channel */
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &cs.value);
		cs.bits.ldw.stop_n_go = 0;
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs.value);
		break;

	case TXDMA_STOP:
		/* Disable the DMA channel */
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &cs.value);
		cs.bits.ldw.stop_n_go = 1;
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs.value);
		status = npi_txdma_control_stop_wait(handle, channel);
		if (status) {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    "Cannot stop channel %d (TXC hung!)",
			    channel));
		}
		break;

	case TXDMA_RESUME:
		/* Resume the packet transmission after stopping */
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &cs.value);
		cs.value |= ~TX_CS_STOP_N_GO_MASK;
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs.value);
		return (npi_txdma_control_resume_wait(handle, channel));

	case TXDMA_CLEAR_MMK:
		/* Write 1 to MK bit to clear the MMK bit */
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &cs.value);
		cs.bits.ldw.mk = 1;
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs.value);
		break;

	case TXDMA_MBOX_ENABLE:
		/*
		 * Write 1 to MB bit to enable mailbox update
		 * (cleared to 0 by hardware after update).
		 */
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &cs.value);
		cs.bits.ldw.mb = 1;
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs.value);
		break;

	default:
		status =  (NPI_FAILURE | NPI_TXDMA_OPCODE_INVALID(channel));
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_channel_control"
		    " Invalid Input: control <0x%x>",
		    control));
	}

	return (status);
}

/*
 * npi_txdma_control_status():
 *	This function is called to operate on the control
 *	and status register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware control and status
 *			  OP_SET: set hardware control and status
 *			  OP_UPDATE: update hardware control and status.
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware TXDMA channel from 0 to 23.
 *	cs_p		- pointer to hardware defined control and status
 *			  structure.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 *		NPI_TXDMA_FUNC_INVALID	-
 */
npi_status_t
npi_txdma_control_status(npi_handle_t handle, io_op_t op_mode,
		uint8_t channel, p_tx_cs_t cs_p)
{
	int		status = NPI_SUCCESS;
	tx_cs_t		txcs;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_control_status"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &cs_p->value);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel, cs_p->value);
		break;

	case OP_UPDATE:
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &txcs.value);
		TXDMA_REG_WRITE64(handle, TX_CS_REG, channel,
		    cs_p->value | txcs.value);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_control_status"
		    " Invalid Input: control <0x%x>",
		    op_mode));
		return (NPI_FAILURE | NPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);

}

/*
 * npi_txdma_event_mask():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts..
 *	and status register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware TXDMA channel from 0 to 23.
 *	mask_p		- pointer to hardware defined event mask
 *			  structure.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_event_mask(npi_handle_t handle, io_op_t op_mode,
		uint8_t channel, p_tx_dma_ent_msk_t mask_p)
{
	int			status = NPI_SUCCESS;
	tx_dma_ent_msk_t	mask;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_event_mask"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TX_ENT_MSK_REG, channel,
		    &mask_p->value);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TX_ENT_MSK_REG, channel,
		    mask_p->value);
		break;

	case OP_UPDATE:
		TXDMA_REG_READ64(handle, TX_ENT_MSK_REG, channel, &mask.value);
		TXDMA_REG_WRITE64(handle, TX_ENT_MSK_REG, channel,
		    mask_p->value | mask.value);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_event_mask"
		    " Invalid Input: eventmask <0x%x>",
		    op_mode));
		return (NPI_FAILURE | NPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * npi_txdma_event_mask_config():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts..
 *	and status register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware TXDMA channel from 0 to 23.
 *	cfgp		- pointer to NPI defined event mask
 *			  enum data type.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_event_mask_config(npi_handle_t handle, io_op_t op_mode,
		uint8_t channel, txdma_ent_msk_cfg_t *mask_cfgp)
{
	int		status = NPI_SUCCESS;
	uint64_t	configuration = *mask_cfgp;
	uint64_t	value;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_event_mask_config"
		    " Invalid Input: channel <0x%x>",
		    channel));

		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TX_ENT_MSK_REG, channel,
		    (uint64_t *)mask_cfgp);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TX_ENT_MSK_REG, channel,
		    configuration);
		break;

	case OP_UPDATE:
		TXDMA_REG_READ64(handle, TX_ENT_MSK_REG, channel, &value);
		TXDMA_REG_WRITE64(handle, TX_ENT_MSK_REG, channel,
		    configuration | value);
		break;

	case OP_CLEAR:
		TXDMA_REG_WRITE64(handle, TX_ENT_MSK_REG, channel,
		    CFG_TXDMA_MASK_ALL);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_event_mask_config"
		    " Invalid Input: eventmask <0x%x>",
		    op_mode));
		return (NPI_FAILURE | NPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * npi_txdma_event_mask_mk_out():
 *	This function is called to mask out the packet transmit marked event.
 *
 * Parameters:
 *	handle		- NPI handle
 *	channel		- hardware TXDMA channel from 0 to 23.
 *			  enum data type.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_event_mask_mk_out(npi_handle_t handle, uint8_t channel)
{
	uint64_t event_mask;
	int	status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_event_mask_mk_out"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TXDMA_REG_READ64(handle, TX_ENT_MSK_REG, channel, &event_mask);
	TXDMA_REG_WRITE64(handle, TX_ENT_MSK_REG, channel,
	    event_mask & (~TX_ENT_MSK_MK_MASK));

	return (status);
}

/*
 * npi_txdma_event_mask_mk_in():
 *	This function is called to set the mask for the the packet marked event.
 *
 * Parameters:
 *	handle		- NPI handle
 *	channel		- hardware TXDMA channel from 0 to 23.
 *			  enum data type.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_event_mask_mk_in(npi_handle_t handle, uint8_t channel)
{
	uint64_t event_mask;
	int	status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_event_mask_mk_in"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TXDMA_REG_READ64(handle, TX_ENT_MSK_REG, channel, &event_mask);
	TXDMA_REG_WRITE64(handle, TX_ENT_MSK_REG, channel,
	    event_mask | TX_ENT_MSK_MK_MASK);

	return (status);
}

/*
 * npi_txdma_ring_addr_set():
 *	This function is called to configure the transmit descriptor
 *	ring address and its size.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined
 *			  if its register pointer is from the virtual region).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *	start_addr	- starting address of the descriptor
 *	len		- maximum length of the descriptor
 *			  (in number of 64 bytes block).
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_ring_addr_set(npi_handle_t handle, uint8_t channel,
		uint64_t start_addr, uint32_t len)
{
	int		status = NPI_SUCCESS;
	tx_rng_cfig_t	cfg;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_ring_addr_set"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	cfg.value = ((start_addr & TX_RNG_CFIG_ADDR_MASK) |
	    (((uint64_t)len) << TX_RNG_CFIG_LEN_SHIFT));
	TXDMA_REG_WRITE64(handle, TX_RNG_CFIG_REG, channel, cfg.value);

	return (status);
}

/*
 * npi_txdma_ring_config():
 *	This function is called to config a descriptor ring
 *	by using the hardware defined data.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined
 *			  if its register pointer is from the virtual region).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *	op_mode		- OP_GET: get transmit ring configuration
 *			  OP_SET: set transmit ring configuration
 *	reg_data	- pointer to hardware defined transmit ring
 *			  configuration data structure.
 * Return:
 *	NPI_SUCCESS		- If set/get is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_ring_config(npi_handle_t handle, io_op_t op_mode,
		uint8_t channel, uint64_t *reg_data)
{
	int		status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_ring_config"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TX_RNG_CFIG_REG, channel, reg_data);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TX_RNG_CFIG_REG, channel,
		    *reg_data);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_ring_config"
		    " Invalid Input: ring_config <0x%x>",
		    op_mode));
		return (NPI_FAILURE | NPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * npi_txdma_mbox_config():
 *	This function is called to config the mailbox address
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined
 *			  if its register pointer is from the virtual region).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *	op_mode		- OP_GET: get the mailbox address
 *			  OP_SET: set the mailbox address
 *	reg_data	- pointer to the mailbox address.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_mbox_config(npi_handle_t handle, io_op_t op_mode,
		uint8_t channel, uint64_t *mbox_addr)
{
	int		status = NPI_SUCCESS;
	txdma_mbh_t	mh;
	txdma_mbl_t	ml;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_mbox_config"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	mh.value = ml.value = 0;

	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TXDMA_MBH_REG, channel, &mh.value);
		TXDMA_REG_READ64(handle, TXDMA_MBL_REG, channel, &ml.value);
		*mbox_addr = ml.value;
		*mbox_addr |= (mh.value << TXDMA_MBH_ADDR_SHIFT);

		break;

	case OP_SET:
		ml.bits.ldw.mbaddr = ((*mbox_addr & TXDMA_MBL_MASK) >>
		    TXDMA_MBL_SHIFT);
		TXDMA_REG_WRITE64(handle, TXDMA_MBL_REG, channel, ml.value);
		mh.bits.ldw.mbaddr = ((*mbox_addr >> TXDMA_MBH_ADDR_SHIFT) &
		    TXDMA_MBH_MASK);
		TXDMA_REG_WRITE64(handle, TXDMA_MBH_REG, channel, mh.value);

		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_mbox_config"
		    " Invalid Input: mbox <0x%x>",
		    op_mode));
		return (NPI_FAILURE | NPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);

}

/*
 * npi_txdma_desc_gather_set():
 *	This function is called to set up a transmit descriptor entry.
 *
 * Parameters:
 *	handle		- NPI handle (register pointer is the
 *			  descriptor address in memory).
 *	desc_p		- pointer to a descriptor
 *	gather_index	- which entry (starts from index 0 to 15)
 *	mark		- mark bit (only valid if it is the first gather).
 *	ngathers	- number of gather pointers to set to the first gather.
 *	dma_ioaddr	- starting dma address of an IO buffer to write.
 *			  (SAD)
 *	transfer_len	- transfer len.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_OPCODE_INVALID	-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 *		NPI_TXDMA_XFER_LEN_INVALID	-
 */
npi_status_t
npi_txdma_desc_gather_set(npi_handle_t handle,
		p_tx_desc_t desc_p, uint8_t gather_index,
		boolean_t mark, uint8_t ngathers,
		uint64_t dma_ioaddr, uint32_t transfer_len)
{
	int		status;

	status = NPI_TXDMA_GATHER_INDEX(gather_index);
	if (status) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_desc_gather_set"
		    " Invalid Input: gather_index <0x%x>",
		    gather_index));
		return (status);
	}

	if (transfer_len > TX_MAX_TRANSFER_LENGTH) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_desc_gather_set"
		    " Invalid Input: tr_len <0x%x>",
		    transfer_len));
		return (NPI_FAILURE | NPI_TXDMA_XFER_LEN_INVALID);
	}

	if (gather_index == 0) {
		desc_p->bits.hdw.sop = 1;
		desc_p->bits.hdw.mark = mark;
		desc_p->bits.hdw.num_ptr = ngathers;
		NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
		    "npi_txdma_gather_set: SOP len %d (%d)",
		    desc_p->bits.hdw.tr_len, transfer_len));
	}

	desc_p->bits.hdw.tr_len = transfer_len;
	desc_p->bits.hdw.sad = dma_ioaddr >> 32;
	desc_p->bits.ldw.sad = dma_ioaddr & 0xffffffff;

	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "npi_txdma_gather_set: xfer len %d to set (%d)",
	    desc_p->bits.hdw.tr_len, transfer_len));

	NXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}

/*
 * npi_txdma_desc_sop_set():
 *	This function is called to set up the first gather entry.
 *
 * Parameters:
 *	handle		- NPI handle (register pointer is the
 *			  descriptor address in memory).
 *	desc_p		- pointer to a descriptor
 *	mark		- mark bit (only valid if it is the first gather).
 *	ngathers	- number of gather pointers to set to the first gather.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 */
npi_status_t
npi_txdma_desc_gather_sop_set(npi_handle_t handle,
		p_tx_desc_t desc_p,
		boolean_t mark_mode,
		uint8_t ngathers)
{
	int		status = NPI_SUCCESS;

	desc_p->bits.hdw.sop = 1;
	desc_p->bits.hdw.mark = mark_mode;
	desc_p->bits.hdw.num_ptr = ngathers;

	NXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}
npi_status_t
npi_txdma_desc_gather_sop_set_1(npi_handle_t handle,
		p_tx_desc_t desc_p,
		boolean_t mark_mode,
		uint8_t ngathers,
		uint32_t extra)
{
	int		status = NPI_SUCCESS;

	desc_p->bits.hdw.sop = 1;
	desc_p->bits.hdw.mark = mark_mode;
	desc_p->bits.hdw.num_ptr = ngathers;
	desc_p->bits.hdw.tr_len += extra;

	NXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}

npi_status_t
npi_txdma_desc_set_xfer_len(npi_handle_t handle,
		p_tx_desc_t desc_p,
		uint32_t transfer_len)
{
	int		status = NPI_SUCCESS;

	desc_p->bits.hdw.tr_len = transfer_len;

	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "npi_set_xfer_len: len %d (%d)",
	    desc_p->bits.hdw.tr_len, transfer_len));

	NXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}

npi_status_t
npi_txdma_desc_set_zero(npi_handle_t handle, uint16_t entries)
{
	uint32_t	offset;
	int		i;

	/*
	 * Assume no wrapped around.
	 */
	offset = 0;
	for (i = 0; i < entries; i++) {
		NXGE_REG_WR64(handle, offset, 0);
		offset += (i * TXDMA_DESC_SIZE);
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_txdma_desc_mem_get(npi_handle_t handle, uint16_t index,
		p_tx_desc_t desc_p)
{
	int		status = NPI_SUCCESS;

	npi_txdma_dump_desc_one(handle, desc_p, index);

	return (status);

}

/*
 * npi_txdma_desc_kick_reg_set():
 *	This function is called to kick the transmit  to start transmission.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *	tail_index	- index into the transmit descriptor
 *	wrap		- toggle bit to indicate if the tail index is
 *			  wrapped around.
 *
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_desc_kick_reg_set(npi_handle_t handle, uint8_t channel,
		uint16_t tail_index, boolean_t wrap)
{
	int			status = NPI_SUCCESS;
	tx_ring_kick_t		kick;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_desc_kick_reg_set"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    " npi_txdma_desc_kick_reg_set: "
	    " KICKING channel %d",
	    channel));

	/* Toggle the wrap around bit */
	kick.value = 0;
	kick.bits.ldw.wrap = wrap;
	kick.bits.ldw.tail = tail_index;

	/* Kick start the Transmit kick register */
	TXDMA_REG_WRITE64(handle, TX_RING_KICK_REG, channel, kick.value);

	return (status);
}

/*
 * npi_txdma_desc_kick_reg_get():
 *	This function is called to kick the transmit  to start transmission.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *	tail_index	- index into the transmit descriptor
 *	wrap		- toggle bit to indicate if the tail index is
 *			  wrapped around.
 *
 * Return:
 *	NPI_SUCCESS		- If get is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_desc_kick_reg_get(npi_handle_t handle, uint8_t channel,
		p_tx_ring_kick_t kick_p)
{
	int		status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_desc_kick_reg_get"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TXDMA_REG_READ64(handle, TX_RING_KICK_REG, channel, &kick_p->value);

	return (status);
}

/*
 * npi_txdma_ring_head_get():
 *	This function is called to get the transmit ring head index.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical TXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *	hdl_p		- pointer to the hardware defined transmit
 *			  ring header data (head index and wrap bit).
 *
 * Return:
 *	NPI_SUCCESS		- If get is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXDMA_CHANNEL_INVALID	-
 */
npi_status_t
npi_txdma_ring_head_get(npi_handle_t handle, uint8_t channel,
		p_tx_ring_hdl_t hdl_p)
{
	int		status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_ring_head_get"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TXDMA_REG_READ64(handle, TX_RING_HDL_REG, channel, &hdl_p->value);

	return (status);
}

/*ARGSUSED*/
npi_status_t
npi_txdma_channel_mbox_get(npi_handle_t handle, uint8_t channel,
		p_txdma_mailbox_t mbox_p)
{
	int		status = NPI_SUCCESS;

	return (status);

}

npi_status_t
npi_txdma_channel_pre_state_get(npi_handle_t handle, uint8_t channel,
		p_tx_dma_pre_st_t prep)
{
	int		status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_channel_pre_state_get"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TXDMA_REG_READ64(handle, TX_DMA_PRE_ST_REG, channel, &prep->value);

	return (status);
}

npi_status_t
npi_txdma_ring_error_get(npi_handle_t handle, uint8_t channel,
		p_txdma_ring_errlog_t ring_errlog_p)
{
	tx_rng_err_logh_t	logh;
	tx_rng_err_logl_t	logl;
	int			status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_ring_error_get"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	logh.value = 0;
	TXDMA_REG_READ64(handle, TX_RNG_ERR_LOGH_REG, channel, &logh.value);
	TXDMA_REG_READ64(handle, TX_RNG_ERR_LOGL_REG, channel, &logl.value);
	ring_errlog_p->logh.bits.ldw.err = logh.bits.ldw.err;
	ring_errlog_p->logh.bits.ldw.merr = logh.bits.ldw.merr;
	ring_errlog_p->logh.bits.ldw.errcode = logh.bits.ldw.errcode;
	ring_errlog_p->logh.bits.ldw.err_addr = logh.bits.ldw.err_addr;
	ring_errlog_p->logl.bits.ldw.err_addr = logl.bits.ldw.err_addr;

	return (status);
}

npi_status_t
npi_txdma_inj_par_error_clear(npi_handle_t handle)
{
	NXGE_REG_WR64(handle, TDMC_INJ_PAR_ERR_REG, 0);

	return (NPI_SUCCESS);
}

npi_status_t
npi_txdma_inj_par_error_set(npi_handle_t handle, uint32_t err_bits)
{
	tdmc_inj_par_err_t	inj;

	inj.value = 0;
	inj.bits.ldw.inject_parity_error = (err_bits & TDMC_INJ_PAR_ERR_MASK);
	NXGE_REG_WR64(handle, TDMC_INJ_PAR_ERR_REG, inj.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_txdma_inj_par_error_update(npi_handle_t handle, uint32_t err_bits)
{
	tdmc_inj_par_err_t	inj;

	inj.value = 0;
	NXGE_REG_RD64(handle, TDMC_INJ_PAR_ERR_REG, &inj.value);
	inj.value |= (err_bits & TDMC_INJ_PAR_ERR_MASK);
	NXGE_REG_WR64(handle, TDMC_INJ_PAR_ERR_REG, inj.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_txdma_inj_par_error_get(npi_handle_t handle, uint32_t *err_bits)
{
	tdmc_inj_par_err_t	inj;

	inj.value = 0;
	NXGE_REG_RD64(handle, TDMC_INJ_PAR_ERR_REG, &inj.value);
	*err_bits = (inj.value & TDMC_INJ_PAR_ERR_MASK);

	return (NPI_SUCCESS);
}

npi_status_t
npi_txdma_dbg_sel_set(npi_handle_t handle, uint8_t dbg_sel)
{
	tdmc_dbg_sel_t		dbg;

	dbg.value = 0;
	dbg.bits.ldw.dbg_sel = (dbg_sel & TDMC_DBG_SEL_MASK);

	NXGE_REG_WR64(handle, TDMC_DBG_SEL_REG, dbg.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_txdma_training_vector_set(npi_handle_t handle, uint32_t training_vector)
{
	tdmc_training_t		vec;

	vec.value = 0;
	vec.bits.ldw.vec = training_vector;

	NXGE_REG_WR64(handle, TDMC_TRAINING_REG, vec.value);

	return (NPI_SUCCESS);
}

/*
 * npi_txdma_dump_desc_one(npi_handle_t handle, p_tx_desc_t desc_p,
 *	int desc_index)
 *
 *	Dumps the contents of transmit descriptors.
 *
 * Parameters:
 *	handle		- NPI handle (register pointer is the
 *			  descriptor address in memory).
 *	desc_p		- pointer to place the descriptor contents
 *	desc_index	- descriptor index
 *
 */
/*ARGSUSED*/
void
npi_txdma_dump_desc_one(npi_handle_t handle, p_tx_desc_t desc_p, int desc_index)
{

	tx_desc_t 		desc, *desp;
#ifdef NXGE_DEBUG
	uint64_t		sad;
	int			xfer_len;
#endif

	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "\n==> npi_txdma_dump_desc_one: dump "
	    " desc_p $%p descriptor entry %d\n",
	    desc_p, desc_index));
	desc.value = 0;
	desp = ((desc_p != NULL) ? desc_p : (p_tx_desc_t)&desc);
	desp->value = NXGE_MEM_PIO_READ64(handle);
#ifdef NXGE_DEBUG
	sad = (desp->value & TX_PKT_DESC_SAD_MASK);
	xfer_len = ((desp->value & TX_PKT_DESC_TR_LEN_MASK) >>
	    TX_PKT_DESC_TR_LEN_SHIFT);
#endif
	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL, "\n\t: value 0x%llx\n"
	    "\t\tsad $%p\ttr_len %d len %d\tnptrs %d\tmark %d sop %d\n",
	    desp->value,
	    sad,
	    desp->bits.hdw.tr_len,
	    xfer_len,
	    desp->bits.hdw.num_ptr,
	    desp->bits.hdw.mark,
	    desp->bits.hdw.sop));

	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "\n<== npi_txdma_dump_desc_one: Done \n"));

}

/*ARGSUSED*/
void
npi_txdma_dump_hdr(npi_handle_t handle, p_tx_pkt_header_t hdrp)
{
	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "\n==> npi_txdma_dump_hdr: dump\n"));
	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "\n\t: value 0x%llx\n"
	    "\t\tpkttype 0x%x\tip_ver %d\tllc %d\tvlan %d \tihl %d\n"
	    "\t\tl3start %d\tl4start %d\tl4stuff %d\n"
	    "\t\txferlen %d\tpad %d\n",
	    hdrp->value,
	    hdrp->bits.hdw.cksum_en_pkt_type,
	    hdrp->bits.hdw.ip_ver,
	    hdrp->bits.hdw.llc,
	    hdrp->bits.hdw.vlan,
	    hdrp->bits.hdw.ihl,
	    hdrp->bits.hdw.l3start,
	    hdrp->bits.hdw.l4start,
	    hdrp->bits.hdw.l4stuff,
	    hdrp->bits.ldw.tot_xfer_len,
	    hdrp->bits.ldw.pad));

	NPI_DEBUG_MSG((handle.function, NPI_TDC_CTL,
	    "\n<== npi_txdma_dump_hdr: Done \n"));
}

npi_status_t
npi_txdma_inj_int_error_set(npi_handle_t handle, uint8_t channel,
	p_tdmc_intr_dbg_t erp)
{
	int		status = NPI_SUCCESS;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txdma_inj_int_error_set"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TXDMA_REG_WRITE64(handle, TDMC_INTR_DBG_REG, channel, erp->value);

	return (status);
}

/*
 * Static functions start here.
 */
static npi_status_t
npi_txdma_control_reset_wait(npi_handle_t handle, uint8_t channel)
{

	tx_cs_t		txcs;
	int		loop = 0;

	do {
		NXGE_DELAY(TXDMA_WAIT_MSEC);
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &txcs.value);
		if (!txcs.bits.ldw.rst) {
			return (NPI_SUCCESS);
		}
		loop++;
	} while (loop < TXDMA_WAIT_LOOP);

	if (loop == TXDMA_WAIT_LOOP) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_txdma_control_reset_wait: RST bit not "
		    "cleared to 0 txcs.bits 0x%llx", txcs.value));
		return (NPI_FAILURE | NPI_TXDMA_RESET_FAILED);
	}
	return (NPI_SUCCESS);
}

static npi_status_t
npi_txdma_control_stop_wait(npi_handle_t handle, uint8_t channel)
{
	tx_cs_t		txcs;
	int		loop = 0;

	do {
		NXGE_DELAY(TXDMA_WAIT_MSEC);
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &txcs.value);
		if (txcs.bits.ldw.sng_state) {
			return (NPI_SUCCESS);
		}
		loop++;
	} while (loop < TXDMA_WAIT_LOOP);

	if (loop == TXDMA_WAIT_LOOP) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_txdma_control_stop_wait: SNG_STATE not "
		    "set to 1 txcs.bits 0x%llx", txcs.value));
		return (NPI_FAILURE | NPI_TXDMA_STOP_FAILED);
	}

	return (NPI_SUCCESS);
}

static npi_status_t
npi_txdma_control_resume_wait(npi_handle_t handle, uint8_t channel)
{
	tx_cs_t		txcs;
	int		loop = 0;

	do {
		NXGE_DELAY(TXDMA_WAIT_MSEC);
		TXDMA_REG_READ64(handle, TX_CS_REG, channel, &txcs.value);
		if (!txcs.bits.ldw.sng_state) {
			return (NPI_SUCCESS);
		}
		loop++;
	} while (loop < TXDMA_WAIT_LOOP);

	if (loop == TXDMA_WAIT_LOOP) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_txdma_control_resume_wait: sng_state not "
		    "set to 0 txcs.bits 0x%llx", txcs.value));
		return (NPI_FAILURE | NPI_TXDMA_RESUME_FAILED);
	}

	return (NPI_SUCCESS);
}
