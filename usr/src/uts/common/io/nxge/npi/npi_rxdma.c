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

#include <npi_rxdma.h>
#include <npi_rx_rd64.h>
#include <npi_rx_wr64.h>
#include <nxge_common.h>

#define	 RXDMA_RESET_TRY_COUNT	4
#define	 RXDMA_RESET_DELAY	5

#define	 RXDMA_OP_DISABLE	0
#define	 RXDMA_OP_ENABLE	1
#define	 RXDMA_OP_RESET	2

#define	 RCR_TIMEOUT_ENABLE	1
#define	 RCR_TIMEOUT_DISABLE	2
#define	 RCR_THRESHOLD	4

/* assume weight is in byte frames unit */
#define	WEIGHT_FACTOR 3/2

uint64_t rdc_dmc_offset[] = {
	RXDMA_CFIG1_REG, RXDMA_CFIG2_REG, RBR_CFIG_A_REG, RBR_CFIG_B_REG,
	RBR_KICK_REG, RBR_STAT_REG, RBR_HDH_REG, RBR_HDL_REG,
	RCRCFIG_A_REG, RCRCFIG_B_REG, RCRSTAT_A_REG, RCRSTAT_B_REG,
	RCRSTAT_C_REG, RX_DMA_ENT_MSK_REG, RX_DMA_CTL_STAT_REG, RCR_FLSH_REG,
	RXMISC_DISCARD_REG
};

const char *rdc_dmc_name[] = {
	"RXDMA_CFIG1", "RXDMA_CFIG2", "RBR_CFIG_A", "RBR_CFIG_B",
	"RBR_KICK", "RBR_STAT", "RBR_HDH", "RBR_HDL",
	"RCRCFIG_A", "RCRCFIG_B", "RCRSTAT_A", "RCRSTAT_B",
	"RCRSTAT_C", "RX_DMA_ENT_MSK", "RX_DMA_CTL_STAT", "RCR_FLSH",
	"RXMISC_DISCARD"
};

uint64_t rdc_fzc_offset [] = {
	RX_LOG_PAGE_VLD_REG, RX_LOG_PAGE_MASK1_REG, RX_LOG_PAGE_VAL1_REG,
	RX_LOG_PAGE_MASK2_REG, RX_LOG_PAGE_VAL2_REG, RX_LOG_PAGE_RELO1_REG,
	RX_LOG_PAGE_RELO2_REG, RX_LOG_PAGE_HDL_REG, RDC_RED_PARA_REG,
	RED_DIS_CNT_REG
};


const char *rdc_fzc_name [] = {
	"RX_LOG_PAGE_VLD", "RX_LOG_PAGE_MASK1", "RX_LOG_PAGE_VAL1",
	"RX_LOG_PAGE_MASK2", "RX_LOG_PAGE_VAL2", "RX_LOG_PAGE_RELO1",
	"RX_LOG_PAGE_RELO2", "RX_LOG_PAGE_HDL", "RDC_RED_PARA", "RED_DIS_CNT"
};


/*
 * Dump the MEM_ADD register first so all the data registers
 * will have valid data buffer pointers.
 */
uint64_t rx_fzc_offset[] = {
	RX_DMA_CK_DIV_REG, DEF_PT0_RDC_REG, DEF_PT1_RDC_REG, DEF_PT2_RDC_REG,
	DEF_PT3_RDC_REG, RX_ADDR_MD_REG, PT_DRR_WT0_REG, PT_DRR_WT1_REG,
	PT_DRR_WT2_REG, PT_DRR_WT3_REG, PT_USE0_REG, PT_USE1_REG,
	PT_USE2_REG, PT_USE3_REG, RED_RAN_INIT_REG, RX_ADDR_MD_REG,
	RDMC_PRE_PAR_ERR_REG, RDMC_SHA_PAR_ERR_REG,
	RDMC_MEM_DATA4_REG, RDMC_MEM_DATA3_REG, RDMC_MEM_DATA2_REG,
	RDMC_MEM_DATA1_REG, RDMC_MEM_DATA0_REG,
	RDMC_MEM_ADDR_REG,
	RX_CTL_DAT_FIFO_STAT_REG, RX_CTL_DAT_FIFO_MASK_REG,
	RX_CTL_DAT_FIFO_STAT_DBG_REG,
	RDMC_TRAINING_VECTOR_REG,
};


const char *rx_fzc_name[] = {
	"RX_DMA_CK_DIV", "DEF_PT0_RDC", "DEF_PT1_RDC", "DEF_PT2_RDC",
	"DEF_PT3_RDC", "RX_ADDR_MD", "PT_DRR_WT0", "PT_DRR_WT1",
	"PT_DRR_WT2", "PT_DRR_WT3", "PT_USE0", "PT_USE1",
	"PT_USE2", "PT_USE3", "RED_RAN_INIT", "RX_ADDR_MD",
	"RDMC_PRE_PAR_ERR", "RDMC_SHA_PAR_ERR",
	"RDMC_MEM_DATA4", "RDMC_MEM_DATA3", "RDMC_MEM_DATA2",
	"RDMC_MEM_DATA1", "RDMC_MEM_DATA0",
	"RDMC_MEM_ADDR",
	"RX_CTL_DAT_FIFO_STAT", "RX_CTL_DAT_FIFO_MASK",
	"RDMC_TRAINING_VECTOR_REG",
	"RX_CTL_DAT_FIFO_STAT_DBG_REG"
};


npi_status_t
npi_rxdma_cfg_rdc_ctl(npi_handle_t handle, uint8_t rdc, uint8_t op);
npi_status_t
npi_rxdma_cfg_rdc_rcr_ctl(npi_handle_t handle, uint8_t rdc, uint8_t op,
				uint16_t param);


/*
 * npi_rxdma_dump_rdc_regs
 * Dumps the contents of rdc csrs and fzc registers
 *
 * Input:
 *      handle:	opaque handle interpreted by the underlying OS
 *         rdc:      RX DMA number
 *
 * return:
 *     NPI_SUCCESS
 *     NPI_RXDMA_RDC_INVALID
 *
 */
npi_status_t
npi_rxdma_dump_rdc_regs(npi_handle_t handle, uint8_t rdc)
{

	uint64_t value, offset;
	int num_regs, i;
#ifdef NPI_DEBUG
	extern uint64_t npi_debug_level;
	uint64_t old_npi_debug_level = npi_debug_level;
#endif
	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_dump_rdc_regs"
		    " Illegal RDC number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}
#ifdef NPI_DEBUG
	npi_debug_level |= DUMP_ALWAYS;
#endif
	num_regs = sizeof (rdc_dmc_offset) / sizeof (uint64_t);
	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nDMC Register Dump for Channel %d\n",
	    rdc));
	for (i = 0; i < num_regs; i++) {
		RXDMA_REG_READ64(handle, rdc_dmc_offset[i], rdc, &value);
		offset = NXGE_RXDMA_OFFSET(rdc_dmc_offset[i], handle.is_vraddr,
		    rdc);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    "%08llx %s\t %08llx \n",
		    offset, rdc_dmc_name[i], value));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n Register Dump for Channel %d done\n",
	    rdc));
#ifdef NPI_DEBUG
	npi_debug_level = old_npi_debug_level;
#endif
	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_dump_fzc_regs
 * Dumps the contents of rdc csrs and fzc registers
 *
 * Input:
 *      handle:	opaque handle interpreted by the underlying OS
 *
 * return:
 *     NPI_SUCCESS
 */
npi_status_t
npi_rxdma_dump_fzc_regs(npi_handle_t handle)
{

	uint64_t value;
	int num_regs, i;


	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nFZC_DMC Common Register Dump\n"));
	num_regs = sizeof (rx_fzc_offset) / sizeof (uint64_t);

	for (i = 0; i < num_regs; i++) {
		NXGE_REG_RD64(handle, rx_fzc_offset[i], &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    "0x%08llx %s\t 0x%08llx \n",
		    rx_fzc_offset[i],
		    rx_fzc_name[i], value));
	}
	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n FZC_DMC Register Dump Done \n"));

	return (NPI_SUCCESS);
}



/*
 * per rdc config functions
 */
npi_status_t
npi_rxdma_cfg_logical_page_disable(npi_handle_t handle, uint8_t rdc,
				    uint8_t page_num)
{
	log_page_vld_t page_vld;
	uint64_t valid_offset;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_logical_page_disable"
		    " Illegal RDC number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	ASSERT(RXDMA_PAGE_VALID(page_num));
	if (!RXDMA_PAGE_VALID(page_num)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_logical_page_disable"
		    " Illegal page number %d \n",
		    page_num));
		return (NPI_RXDMA_PAGE_INVALID);
	}

	valid_offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_VLD_REG, rdc);
	NXGE_REG_RD64(handle, valid_offset, &page_vld.value);

	if (page_num == 0)
		page_vld.bits.ldw.page0 = 0;

	if (page_num == 1)
		page_vld.bits.ldw.page1 = 0;

	NXGE_REG_WR64(handle, valid_offset, page_vld.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_cfg_logical_page(npi_handle_t handle, uint8_t rdc,
			    dma_log_page_t *pg_cfg)
{
	log_page_vld_t page_vld;
	log_page_mask_t page_mask;
	log_page_value_t page_value;
	log_page_relo_t page_reloc;
	uint64_t value_offset, reloc_offset, mask_offset;
	uint64_t valid_offset;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_cfg_logical_page"
		    " Illegal RDC number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	ASSERT(RXDMA_PAGE_VALID(pg_cfg->page_num));
	if (!RXDMA_PAGE_VALID(pg_cfg->page_num)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_cfg_logical_page"
		    " Illegal page number %d \n",
		    pg_cfg->page_num));
		return (NPI_RXDMA_PAGE_INVALID);
	}

	valid_offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_VLD_REG, rdc);
	NXGE_REG_RD64(handle, valid_offset, &page_vld.value);

	if (!pg_cfg->valid) {
		if (pg_cfg->page_num == 0)
			page_vld.bits.ldw.page0 = 0;

		if (pg_cfg->page_num == 1)
			page_vld.bits.ldw.page1 = 0;
		NXGE_REG_WR64(handle, valid_offset, page_vld.value);
		return (NPI_SUCCESS);
	}

	if (pg_cfg->page_num == 0) {
		mask_offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_MASK1_REG, rdc);
		value_offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_VAL1_REG, rdc);
		reloc_offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_RELO1_REG, rdc);
		page_vld.bits.ldw.page0 = 1;
	}

	if (pg_cfg->page_num == 1) {
		mask_offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_MASK2_REG, rdc);
		value_offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_VAL2_REG, rdc);
		reloc_offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_RELO2_REG, rdc);
		page_vld.bits.ldw.page1 = 1;
	}


	page_vld.bits.ldw.func = pg_cfg->func_num;

	page_mask.value = 0;
	page_value.value = 0;
	page_reloc.value = 0;


	page_mask.bits.ldw.mask = pg_cfg->mask >> LOG_PAGE_ADDR_SHIFT;
	page_value.bits.ldw.value = pg_cfg->value >> LOG_PAGE_ADDR_SHIFT;
	page_reloc.bits.ldw.relo = pg_cfg->reloc >> LOG_PAGE_ADDR_SHIFT;


	NXGE_REG_WR64(handle, mask_offset, page_mask.value);
	NXGE_REG_WR64(handle, value_offset, page_value.value);
	NXGE_REG_WR64(handle, reloc_offset, page_reloc.value);


/* enable the logical page */
	NXGE_REG_WR64(handle, valid_offset, page_vld.value);
	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_cfg_logical_page_handle(npi_handle_t handle, uint8_t rdc,
				    uint64_t page_handle)
{
	uint64_t offset;
	log_page_hdl_t page_hdl;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_logical_page_handle"
		    " Illegal RDC number %d \n", rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	page_hdl.value = 0;

	page_hdl.bits.ldw.handle = (uint32_t)page_handle;
	offset = REG_FZC_RDC_OFFSET(RX_LOG_PAGE_HDL_REG, rdc);
	NXGE_REG_WR64(handle, offset, page_hdl.value);

	return (NPI_SUCCESS);
}

/*
 * RX DMA functions
 */
npi_status_t
npi_rxdma_cfg_rdc_ctl(npi_handle_t handle, uint8_t rdc, uint8_t op)
{

	rxdma_cfig1_t cfg;
	uint32_t count = RXDMA_RESET_TRY_COUNT;
	uint32_t delay_time = RXDMA_RESET_DELAY;
	uint32_t error = NPI_RXDMA_ERROR_ENCODE(NPI_RXDMA_RESET_ERR, rdc);

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_cfg_rdc_ctl"
		    " Illegal RDC number %d \n", rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}


	switch (op) {
		case RXDMA_OP_ENABLE:
			RXDMA_REG_READ64(handle, RXDMA_CFIG1_REG, rdc,
			    &cfg.value);
			cfg.bits.ldw.en = 1;
			RXDMA_REG_WRITE64(handle, RXDMA_CFIG1_REG,
			    rdc, cfg.value);

			NXGE_DELAY(delay_time);
			RXDMA_REG_READ64(handle, RXDMA_CFIG1_REG, rdc,
			    &cfg.value);
			while ((count--) && (cfg.bits.ldw.qst == 0)) {
				NXGE_DELAY(delay_time);
				RXDMA_REG_READ64(handle, RXDMA_CFIG1_REG, rdc,
				    &cfg.value);
			}

			if (cfg.bits.ldw.qst == 0) {
				NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " npi_rxdma_cfg_rdc_ctl"
				    " RXDMA_OP_ENABLE Failed for RDC %d \n",
				    rdc));
				return (error);
			}

			break;
		case RXDMA_OP_DISABLE:
			RXDMA_REG_READ64(handle, RXDMA_CFIG1_REG, rdc,
			    &cfg.value);
			cfg.bits.ldw.en = 0;
			RXDMA_REG_WRITE64(handle, RXDMA_CFIG1_REG,
			    rdc, cfg.value);

			NXGE_DELAY(delay_time);
			RXDMA_REG_READ64(handle, RXDMA_CFIG1_REG, rdc,
			    &cfg.value);
			while ((count--) && (cfg.bits.ldw.qst == 0)) {
				NXGE_DELAY(delay_time);
				RXDMA_REG_READ64(handle, RXDMA_CFIG1_REG, rdc,
				    &cfg.value);
			}
			if (cfg.bits.ldw.qst == 0) {
				NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " npi_rxdma_cfg_rdc_ctl"
				    " RXDMA_OP_DISABLE Failed for RDC %d \n",
				    rdc));
				return (error);
			}

			break;
		case RXDMA_OP_RESET:
			cfg.value = 0;
			cfg.bits.ldw.rst = 1;
			RXDMA_REG_WRITE64(handle,
			    RXDMA_CFIG1_REG,
			    rdc, cfg.value);
			NXGE_DELAY(delay_time);
			RXDMA_REG_READ64(handle, RXDMA_CFIG1_REG, rdc,
			    &cfg.value);
			while ((count--) && (cfg.bits.ldw.rst)) {
				NXGE_DELAY(delay_time);
				RXDMA_REG_READ64(handle, RXDMA_CFIG1_REG, rdc,
				    &cfg.value);
			}
			if (count == 0) {
				NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
				    " npi_rxdma_cfg_rdc_ctl"
				    " Reset Failed for RDC %d \n",
				    rdc));
				return (error);
			}
			break;
		default:
			return (NPI_RXDMA_SW_PARAM_ERROR);
	}

	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_cfg_rdc_enable(npi_handle_t handle, uint8_t rdc)
{
	return (npi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_ENABLE));
}

npi_status_t
npi_rxdma_cfg_rdc_disable(npi_handle_t handle, uint8_t rdc)
{
	return (npi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_DISABLE));
}

npi_status_t
npi_rxdma_cfg_rdc_reset(npi_handle_t handle, uint8_t rdc)
{
	return (npi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_RESET));
}

/*
 * npi_rxdma_cfg_defualt_port_rdc()
 * Set the default rdc for the port
 *
 * Inputs:
 *	handle:		register handle interpreted by the underlying OS
 *	portnm:		Physical Port Number
 *	rdc:	RX DMA Channel number
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 * NPI_RXDMA_PORT_INVALID
 *
 */
npi_status_t npi_rxdma_cfg_default_port_rdc(npi_handle_t handle,
				    uint8_t portnm, uint8_t rdc)
{

	uint64_t offset;
	def_pt_rdc_t cfg;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_default_port_rdc"
		    " Illegal RDC number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	ASSERT(RXDMA_PORT_VALID(portnm));
	if (!RXDMA_PORT_VALID(portnm)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_default_port_rdc"
		    " Illegal Port number %d \n",
		    portnm));
		return (NPI_RXDMA_PORT_INVALID);
	}

	offset = DEF_PT_RDC_REG(portnm);
	cfg.value = 0;
	cfg.bits.ldw.rdc = rdc;
	NXGE_REG_WR64(handle, offset, cfg.value);
	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_cfg_rdc_rcr_ctl(npi_handle_t handle, uint8_t rdc,
			    uint8_t op, uint16_t param)
{
	rcrcfig_b_t rcr_cfgb;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_rdc_rcr_ctl"
		    " Illegal RDC number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}


	RXDMA_REG_READ64(handle, RCRCFIG_B_REG, rdc, &rcr_cfgb.value);

	switch (op) {
		case RCR_TIMEOUT_ENABLE:
			rcr_cfgb.bits.ldw.timeout = (uint8_t)param;
			rcr_cfgb.bits.ldw.entout = 1;
			break;

		case RCR_THRESHOLD:
			rcr_cfgb.bits.ldw.pthres = param;
			break;

		case RCR_TIMEOUT_DISABLE:
			rcr_cfgb.bits.ldw.entout = 0;
			break;

		default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_rdc_rcr_ctl"
		    " Illegal opcode %x \n",
		    op));
		return (NPI_RXDMA_OPCODE_INVALID(rdc));
	}

	RXDMA_REG_WRITE64(handle, RCRCFIG_B_REG, rdc, rcr_cfgb.value);
	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_cfg_rdc_rcr_timeout_disable(npi_handle_t handle, uint8_t rdc)
{
	return (npi_rxdma_cfg_rdc_rcr_ctl(handle, rdc,
	    RCR_TIMEOUT_DISABLE, 0));
}

npi_status_t
npi_rxdma_cfg_rdc_rcr_threshold(npi_handle_t handle, uint8_t rdc,
				    uint16_t rcr_threshold)
{
	return (npi_rxdma_cfg_rdc_rcr_ctl(handle, rdc,
	    RCR_THRESHOLD, rcr_threshold));

}

npi_status_t
npi_rxdma_cfg_rdc_rcr_timeout(npi_handle_t handle, uint8_t rdc,
			    uint8_t rcr_timeout)
{
	return (npi_rxdma_cfg_rdc_rcr_ctl(handle, rdc,
	    RCR_TIMEOUT_ENABLE, rcr_timeout));

}

/*
 * npi_rxdma_cfg_rdc_ring()
 * Configure The RDC channel Rcv Buffer Ring
 */
npi_status_t
npi_rxdma_cfg_rdc_ring(npi_handle_t handle, uint8_t rdc,
			    rdc_desc_cfg_t *rdc_desc_cfg, boolean_t new_off)
{
	rbr_cfig_a_t cfga;
	rbr_cfig_b_t cfgb;
	rxdma_cfig1_t cfg1;
	rxdma_cfig2_t cfg2;
	rcrcfig_a_t rcr_cfga;
	rcrcfig_b_t rcr_cfgb;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_rdc_ring"
		    " Illegal RDC number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}


	cfga.value = 0;
	cfgb.value = 0;
	cfg1.value = 0;
	cfg2.value = 0;

	if (rdc_desc_cfg->mbox_enable == 1) {
		cfg1.bits.ldw.mbaddr_h =
		    (rdc_desc_cfg->mbox_addr >> 32) & 0xfff;
		cfg2.bits.ldw.mbaddr =
		    ((rdc_desc_cfg->mbox_addr &
		    RXDMA_CFIG2_MBADDR_L_MASK) >>
		    RXDMA_CFIG2_MBADDR_L_SHIFT);


		/*
		 * Only after all the configurations are set, then
		 * enable the RDC or else configuration fatal error
		 * will be returned (especially if the Hypervisor
		 * set up the logical pages with non-zero values.
		 * This NPI function only sets up the configuration.
		 */
	}


	if (rdc_desc_cfg->full_hdr == 1)
		cfg2.bits.ldw.full_hdr = 1;

	if (new_off) {
		if (RXDMA_RF_BUFF_OFFSET_VALID(rdc_desc_cfg->offset)) {
			switch (rdc_desc_cfg->offset) {
			case SW_OFFSET_NO_OFFSET:
			case SW_OFFSET_64:
			case SW_OFFSET_128:
			case SW_OFFSET_192:
				cfg2.bits.ldw.offset = rdc_desc_cfg->offset;
				cfg2.bits.ldw.offset256 = 0;
				break;
			case SW_OFFSET_256:
			case SW_OFFSET_320:
			case SW_OFFSET_384:
			case SW_OFFSET_448:
				cfg2.bits.ldw.offset =
				    rdc_desc_cfg->offset & 0x3;
				cfg2.bits.ldw.offset256 = 1;
				break;
			default:
				cfg2.bits.ldw.offset = SW_OFFSET_NO_OFFSET;
				cfg2.bits.ldw.offset256 = 0;
			}
		} else {
			cfg2.bits.ldw.offset = SW_OFFSET_NO_OFFSET;
			cfg2.bits.ldw.offset256 = 0;
		}
	} else {
		if (RXDMA_BUFF_OFFSET_VALID(rdc_desc_cfg->offset)) {
			cfg2.bits.ldw.offset = rdc_desc_cfg->offset;
		} else {
			cfg2.bits.ldw.offset = SW_OFFSET_NO_OFFSET;
		}
	}

		/* rbr config */

	cfga.value = (rdc_desc_cfg->rbr_addr & (RBR_CFIG_A_STDADDR_MASK |
	    RBR_CFIG_A_STDADDR_BASE_MASK));

	if ((rdc_desc_cfg->rbr_len < RBR_DEFAULT_MIN_LEN) ||
	    (rdc_desc_cfg->rbr_len > RBR_DEFAULT_MAX_LEN)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_cfg_rdc_ring"
		    " Illegal RBR Queue Length %d \n",
		    rdc_desc_cfg->rbr_len));
		return (NPI_RXDMA_ERROR_ENCODE(NPI_RXDMA_RBRSIZE_INVALID, rdc));
	}


	cfga.bits.hdw.len = rdc_desc_cfg->rbr_len;
	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    "npi_rxdma_cfg_rdc_ring"
	    " CFGA 0x%llx hdw.len %d (RBR LEN %d)\n",
	    cfga.value, cfga.bits.hdw.len,
	    rdc_desc_cfg->rbr_len));

	if (rdc_desc_cfg->page_size == SIZE_4KB)
		cfgb.bits.ldw.bksize = RBR_BKSIZE_4K;
	else if (rdc_desc_cfg->page_size == SIZE_8KB)
		cfgb.bits.ldw.bksize = RBR_BKSIZE_8K;
	else if (rdc_desc_cfg->page_size == SIZE_16KB)
		cfgb.bits.ldw.bksize = RBR_BKSIZE_16K;
	else if (rdc_desc_cfg->page_size == SIZE_32KB)
		cfgb.bits.ldw.bksize = RBR_BKSIZE_32K;
	else {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "rxdma_cfg_rdc_ring"
		    " blksize: Illegal buffer size %d \n",
		    rdc_desc_cfg->page_size));
		return (NPI_RXDMA_BUFSIZE_INVALID);
	}

	if (rdc_desc_cfg->valid0) {

		if (rdc_desc_cfg->size0 == SIZE_256B)
			cfgb.bits.ldw.bufsz0 = RBR_BUFSZ0_256B;
		else if (rdc_desc_cfg->size0 == SIZE_512B)
			cfgb.bits.ldw.bufsz0 = RBR_BUFSZ0_512B;
		else if (rdc_desc_cfg->size0 == SIZE_1KB)
			cfgb.bits.ldw.bufsz0 = RBR_BUFSZ0_1K;
		else if (rdc_desc_cfg->size0 == SIZE_2KB)
			cfgb.bits.ldw.bufsz0 = RBR_BUFSZ0_2K;
		else {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize0: Illegal buffer size %x \n",
			    rdc_desc_cfg->size0));
			return (NPI_RXDMA_BUFSIZE_INVALID);
		}
		cfgb.bits.ldw.vld0 = 1;
	} else {
		cfgb.bits.ldw.vld0 = 0;
	}


	if (rdc_desc_cfg->valid1) {
		if (rdc_desc_cfg->size1 == SIZE_1KB)
			cfgb.bits.ldw.bufsz1 = RBR_BUFSZ1_1K;
		else if (rdc_desc_cfg->size1 == SIZE_2KB)
			cfgb.bits.ldw.bufsz1 = RBR_BUFSZ1_2K;
		else if (rdc_desc_cfg->size1 == SIZE_4KB)
			cfgb.bits.ldw.bufsz1 = RBR_BUFSZ1_4K;
		else if (rdc_desc_cfg->size1 == SIZE_8KB)
			cfgb.bits.ldw.bufsz1 = RBR_BUFSZ1_8K;
		else {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize1: Illegal buffer size %x \n",
			    rdc_desc_cfg->size1));
			return (NPI_RXDMA_BUFSIZE_INVALID);
		}
		cfgb.bits.ldw.vld1 = 1;
	} else {
		cfgb.bits.ldw.vld1 = 0;
	}


	if (rdc_desc_cfg->valid2) {
		if (rdc_desc_cfg->size2 == SIZE_2KB)
			cfgb.bits.ldw.bufsz2 = RBR_BUFSZ2_2K;
		else if (rdc_desc_cfg->size2 == SIZE_4KB)
			cfgb.bits.ldw.bufsz2 = RBR_BUFSZ2_4K;
		else if (rdc_desc_cfg->size2 == SIZE_8KB)
			cfgb.bits.ldw.bufsz2 = RBR_BUFSZ2_8K;
		else if (rdc_desc_cfg->size2 == SIZE_16KB)
			cfgb.bits.ldw.bufsz2 = RBR_BUFSZ2_16K;
		else {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize2: Illegal buffer size %x \n",
			    rdc_desc_cfg->size2));
			return (NPI_RXDMA_BUFSIZE_INVALID);
		}
		cfgb.bits.ldw.vld2 = 1;
	} else {
		cfgb.bits.ldw.vld2 = 0;
	}


	rcr_cfga.value = (rdc_desc_cfg->rcr_addr &
	    (RCRCFIG_A_STADDR_MASK |
	    RCRCFIG_A_STADDR_BASE_MASK));


	if ((rdc_desc_cfg->rcr_len < RCR_DEFAULT_MIN_LEN) ||
	    (rdc_desc_cfg->rcr_len > NXGE_RCR_MAX)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_cfg_rdc_ring"
		    " Illegal RCR Queue Length %d \n",
		    rdc_desc_cfg->rcr_len));
		return (NPI_RXDMA_ERROR_ENCODE(NPI_RXDMA_RCRSIZE_INVALID, rdc));
	}

	rcr_cfga.bits.hdw.len = rdc_desc_cfg->rcr_len;


	rcr_cfgb.value = 0;
	if (rdc_desc_cfg->rcr_timeout_enable == 1) {
		/* check if the rcr timeout value is valid */

		if (RXDMA_RCR_TO_VALID(rdc_desc_cfg->rcr_timeout)) {
			rcr_cfgb.bits.ldw.timeout = rdc_desc_cfg->rcr_timeout;
			rcr_cfgb.bits.ldw.entout = 1;
		} else {
			NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " Illegal RCR Timeout value %d \n",
			    rdc_desc_cfg->rcr_timeout));
			rcr_cfgb.bits.ldw.entout = 0;
		}
	} else {
		rcr_cfgb.bits.ldw.entout = 0;
	}

		/* check if the rcr threshold value is valid */
	if (RXDMA_RCR_THRESH_VALID(rdc_desc_cfg->rcr_threshold)) {
		rcr_cfgb.bits.ldw.pthres = rdc_desc_cfg->rcr_threshold;
	} else {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_cfg_rdc_ring"
		    " Illegal RCR Threshold value %d \n",
		    rdc_desc_cfg->rcr_threshold));
		rcr_cfgb.bits.ldw.pthres = 1;
	}

		/* now do the actual HW configuration */
	RXDMA_REG_WRITE64(handle, RXDMA_CFIG1_REG, rdc, cfg1.value);
	RXDMA_REG_WRITE64(handle, RXDMA_CFIG2_REG, rdc, cfg2.value);


	RXDMA_REG_WRITE64(handle, RBR_CFIG_A_REG, rdc, cfga.value);
	RXDMA_REG_WRITE64(handle, RBR_CFIG_B_REG, rdc, cfgb.value);

	RXDMA_REG_WRITE64(handle, RCRCFIG_A_REG, rdc, rcr_cfga.value);
	RXDMA_REG_WRITE64(handle, RCRCFIG_B_REG, rdc, rcr_cfgb.value);

	return (NPI_SUCCESS);

}

/*
 * npi_rxdma_red_discard_stat_get
 * Gets the current discrad count due RED
 * The counter overflow bit is cleared, if it has been set.
 *
 * Inputs:
 *      handle:	opaque handle interpreted by the underlying OS
 *	rdc:		RX DMA Channel number
 *	cnt:	Ptr to structure to write current RDC discard stat
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */
npi_status_t
npi_rxdma_red_discard_stat_get(npi_handle_t handle, uint8_t rdc,
				    rx_disc_cnt_t *cnt)
{
	uint64_t offset;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_red_discard_stat_get"
		    " Illegal RDC Number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	offset = RDC_RED_RDC_DISC_REG(rdc);
	NXGE_REG_RD64(handle, offset, &cnt->value);
	if (cnt->bits.ldw.oflow) {
		NPI_DEBUG_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_red_discard_stat_get"
		    " Counter overflow for channel %d ",
		    " ..... clearing \n",
		    rdc));
		cnt->bits.ldw.oflow = 0;
		NXGE_REG_WR64(handle, offset, cnt->value);
		cnt->bits.ldw.oflow = 1;
	}

	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_red_discard_oflow_clear
 * Clear RED discard counter overflow bit
 *
 * Inputs:
 *      handle:	opaque handle interpreted by the underlying OS
 *	rdc:		RX DMA Channel number
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */
npi_status_t
npi_rxdma_red_discard_oflow_clear(npi_handle_t handle, uint8_t rdc)

{
	uint64_t offset;
	rx_disc_cnt_t cnt;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
			    " npi_rxdma_red_discard_oflow_clear"
			    " Illegal RDC Number %d \n",
			    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	offset = RDC_RED_RDC_DISC_REG(rdc);
	NXGE_REG_RD64(handle, offset, &cnt.value);
	if (cnt.bits.ldw.oflow) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
			    " npi_rxdma_red_discard_oflow_clear"
			    " Counter overflow for channel %d ",
			    " ..... clearing \n",
			    rdc));
		cnt.bits.ldw.oflow = 0;
		NXGE_REG_WR64(handle, offset, cnt.value);
	}
	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_misc_discard_stat_get
 * Gets the current discrad count for the rdc due to
 * buffer pool empty
 * The counter overflow bit is cleared, if it has been set.
 *
 * Inputs:
 *      handle:	opaque handle interpreted by the underlying OS
 *	rdc:		RX DMA Channel number
 *	cnt:	Ptr to structure to write current RDC discard stat
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */
npi_status_t
npi_rxdma_misc_discard_stat_get(npi_handle_t handle, uint8_t rdc,
				    rx_disc_cnt_t *cnt)
{
	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_misc_discard_stat_get"
		    " Illegal RDC Number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RXMISC_DISCARD_REG, rdc, &cnt->value);
	if (cnt->bits.ldw.oflow) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_misc_discard_stat_get"
		    " Counter overflow for channel %d ",
		    " ..... clearing \n",
		    rdc));
		cnt->bits.ldw.oflow = 0;
		RXDMA_REG_WRITE64(handle, RXMISC_DISCARD_REG, rdc, cnt->value);
		cnt->bits.ldw.oflow = 1;
	}

	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_red_discard_oflow_clear
 * Clear RED discard counter overflow bit
 * clear the overflow bit for  buffer pool empty discrad counter
 * for the rdc
 *
 * Inputs:
 *      handle:	opaque handle interpreted by the underlying OS
 *	rdc:		RX DMA Channel number
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 *
 */
npi_status_t
npi_rxdma_misc_discard_oflow_clear(npi_handle_t handle, uint8_t rdc)
{
	rx_disc_cnt_t cnt;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_misc_discard_oflow_clear"
		    " Illegal RDC Number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RXMISC_DISCARD_REG, rdc, &cnt.value);
	if (cnt.bits.ldw.oflow) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_misc_discard_oflow_clear"
		    " Counter overflow for channel %d ",
		    " ..... clearing \n",
		    rdc));
		cnt.bits.ldw.oflow = 0;
		RXDMA_REG_WRITE64(handle, RXMISC_DISCARD_REG, rdc, cnt.value);
	}

	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_ring_perr_stat_get
 * Gets the current RDC Memory parity error
 * The counter overflow bit is cleared, if it has been set.
 *
 * Inputs:
 * handle:	opaque handle interpreted by the underlying OS
 * pre_log:	Structure to write current RDC Prefetch memory
 *		Parity Error stat
 * sha_log:	Structure to write current RDC Shadow memory
 *		Parity Error stat
 *
 * Return:
 * NPI_SUCCESS
 *
 */
npi_status_t
npi_rxdma_ring_perr_stat_get(npi_handle_t handle,
			    rdmc_par_err_log_t *pre_log,
			    rdmc_par_err_log_t *sha_log)
{
	uint64_t pre_offset, sha_offset;
	rdmc_par_err_log_t clr;
	int clr_bits = 0;

	pre_offset = RDMC_PRE_PAR_ERR_REG;
	sha_offset = RDMC_SHA_PAR_ERR_REG;
	NXGE_REG_RD64(handle, pre_offset, &pre_log->value);
	NXGE_REG_RD64(handle, sha_offset, &sha_log->value);

	clr.value = pre_log->value;
	if (pre_log->bits.ldw.err) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_ring_perr_stat_get"
		    " PRE ERR Bit set ..... clearing \n"));
		clr.bits.ldw.err = 0;
		clr_bits++;
	}

	if (pre_log->bits.ldw.merr) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_ring_perr_stat_get"
		    " PRE MERR Bit set ..... clearing \n"));
		clr.bits.ldw.merr = 0;
		clr_bits++;
	}

	if (clr_bits) {
		NXGE_REG_WR64(handle, pre_offset, clr.value);
	}

	clr_bits = 0;
	clr.value = sha_log->value;
	if (sha_log->bits.ldw.err) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_ring_perr_stat_get"
		    " SHA ERR Bit set ..... clearing \n"));
		clr.bits.ldw.err = 0;
		clr_bits++;
	}

	if (sha_log->bits.ldw.merr) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_ring_perr_stat_get"
		    " SHA MERR Bit set ..... clearing \n"));
		clr.bits.ldw.merr = 0;
		clr_bits++;
	}

	if (clr_bits) {
		NXGE_REG_WR64(handle, sha_offset, clr.value);
	}

	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_ring_perr_stat_clear
 * Clear RDC Memory Parity Error counter overflow bits
 *
 * Inputs:
 *      handle:	opaque handle interpreted by the underlying OS
 * Return:
 * NPI_SUCCESS
 *
 */
npi_status_t
npi_rxdma_ring_perr_stat_clear(npi_handle_t handle)
{
	uint64_t pre_offset, sha_offset;
	rdmc_par_err_log_t clr;
	int clr_bits = 0;
	pre_offset = RDMC_PRE_PAR_ERR_REG;
	sha_offset = RDMC_SHA_PAR_ERR_REG;

	NXGE_REG_RD64(handle, pre_offset, &clr.value);

	if (clr.bits.ldw.err) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_ring_perr_stat_get"
		    " PRE ERR Bit set ..... clearing \n"));
		clr.bits.ldw.err = 0;
		clr_bits++;
	}

	if (clr.bits.ldw.merr) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_ring_perr_stat_get"
		    " PRE MERR Bit set ..... clearing \n"));
		clr.bits.ldw.merr = 0;
		clr_bits++;
	}

	if (clr_bits) {
		NXGE_REG_WR64(handle, pre_offset, clr.value);
	}

	clr_bits = 0;
	NXGE_REG_RD64(handle, sha_offset, &clr.value);
	if (clr.bits.ldw.err) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_ring_perr_stat_get"
		    " SHA ERR Bit set ..... clearing \n"));
		clr.bits.ldw.err = 0;
		clr_bits++;
	}

	if (clr.bits.ldw.merr) {
		NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
		    " npi_rxdma_ring_perr_stat_get"
		    " SHA MERR Bit set ..... clearing \n"));
		clr.bits.ldw.merr = 0;
		clr_bits++;
	}

	if (clr_bits) {
		NXGE_REG_WR64(handle, sha_offset, clr.value);
	}

	return (NPI_SUCCESS);
}

/*
 * Access the RDMC Memory: used for debugging
 */
npi_status_t
npi_rxdma_rdmc_memory_io(npi_handle_t handle,
			    rdmc_mem_access_t *data, uint8_t op)
{
	uint64_t d0_offset, d1_offset, d2_offset, d3_offset, d4_offset;
	uint64_t addr_offset;
	rdmc_mem_addr_t addr;
	rdmc_mem_data_t d0, d1, d2, d3, d4;
	d0.value = 0;
	d1.value = 0;
	d2.value = 0;
	d3.value = 0;
	d4.value = 0;
	addr.value = 0;


	if ((data->location != RDMC_MEM_ADDR_PREFETCH) &&
	    (data->location != RDMC_MEM_ADDR_SHADOW)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_rdmc_memory_io"
		    " Illegal memory Type %x \n",
		    data->location));
		return (NPI_RXDMA_OPCODE_INVALID(0));
	}

	addr_offset = RDMC_MEM_ADDR_REG;
	addr.bits.ldw.addr = data->addr;
	addr.bits.ldw.pre_shad = data->location;

	d0_offset = RDMC_MEM_DATA0_REG;
	d1_offset = RDMC_MEM_DATA1_REG;
	d2_offset = RDMC_MEM_DATA2_REG;
	d3_offset = RDMC_MEM_DATA3_REG;
	d4_offset = RDMC_MEM_DATA4_REG;


	if (op == RDMC_MEM_WRITE) {
		d0.bits.ldw.data = data->data[0];
		d1.bits.ldw.data = data->data[1];
		d2.bits.ldw.data = data->data[2];
		d3.bits.ldw.data = data->data[3];
		d4.bits.ldw.data = data->data[4];
		NXGE_REG_WR64(handle, addr_offset, addr.value);
		NXGE_REG_WR64(handle, d0_offset, d0.value);
		NXGE_REG_WR64(handle, d1_offset, d1.value);
		NXGE_REG_WR64(handle, d2_offset, d2.value);
		NXGE_REG_WR64(handle, d3_offset, d3.value);
		NXGE_REG_WR64(handle, d4_offset, d4.value);
	}

	if (op == RDMC_MEM_READ) {
		NXGE_REG_WR64(handle, addr_offset, addr.value);
		NXGE_REG_RD64(handle, d4_offset, &d4.value);
		NXGE_REG_RD64(handle, d3_offset, &d3.value);
		NXGE_REG_RD64(handle, d2_offset, &d2.value);
		NXGE_REG_RD64(handle, d1_offset, &d1.value);
		NXGE_REG_RD64(handle, d0_offset, &d0.value);

		data->data[0] = d0.bits.ldw.data;
		data->data[1] = d1.bits.ldw.data;
		data->data[2] = d2.bits.ldw.data;
		data->data[3] = d3.bits.ldw.data;
		data->data[4] = d4.bits.ldw.data;
	} else {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_rdmc_memory_io"
		    " Illegal opcode %x \n",
		    op));
		return (NPI_RXDMA_OPCODE_INVALID(0));

	}

	return (NPI_SUCCESS);
}

/*
 * system wide conf functions
 */
npi_status_t
npi_rxdma_cfg_clock_div_set(npi_handle_t handle, uint16_t count)
{
	uint64_t offset;
	rx_dma_ck_div_t clk_div;

	offset = RX_DMA_CK_DIV_REG;

	clk_div.value = 0;
	clk_div.bits.ldw.cnt = count;
	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    " npi_rxdma_cfg_clock_div_set: add 0x%llx "
	    "handle 0x%llx value 0x%llx",
	    handle.regp, handle.regh, clk_div.value));

	NXGE_REG_WR64(handle, offset, clk_div.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_cfg_red_rand_init(npi_handle_t handle, uint16_t init_value)
{
	uint64_t offset;
	red_ran_init_t rand_reg;

	offset = RED_RAN_INIT_REG;

	rand_reg.value = 0;
	rand_reg.bits.ldw.init = init_value;
	rand_reg.bits.ldw.enable = 1;
	NXGE_REG_WR64(handle, offset, rand_reg.value);

	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_cfg_red_rand_disable(npi_handle_t handle)
{
	uint64_t offset;
	red_ran_init_t rand_reg;

	offset = RED_RAN_INIT_REG;

	NXGE_REG_RD64(handle, offset, &rand_reg.value);
	rand_reg.bits.ldw.enable = 0;
	NXGE_REG_WR64(handle, offset, rand_reg.value);

	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_cfg_32bitmode_enable(npi_handle_t handle)
{
	uint64_t offset;
	rx_addr_md_t md_reg;
	offset = RX_ADDR_MD_REG;
	md_reg.value = 0;
	md_reg.bits.ldw.mode32 = 1;

	NXGE_REG_WR64(handle, offset, md_reg.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_cfg_32bitmode_disable(npi_handle_t handle)
{
	uint64_t offset;
	rx_addr_md_t md_reg;
	offset = RX_ADDR_MD_REG;
	md_reg.value = 0;

	NXGE_REG_WR64(handle, offset, md_reg.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_cfg_ram_access_enable(npi_handle_t handle)
{
	uint64_t offset;
	rx_addr_md_t md_reg;
	offset = RX_ADDR_MD_REG;
	NXGE_REG_RD64(handle, offset, &md_reg.value);
	md_reg.bits.ldw.ram_acc = 1;
	NXGE_REG_WR64(handle, offset, md_reg.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_cfg_ram_access_disable(npi_handle_t handle)
{
	uint64_t offset;
	rx_addr_md_t md_reg;
	offset = RX_ADDR_MD_REG;
	NXGE_REG_RD64(handle, offset, &md_reg.value);
	md_reg.bits.ldw.ram_acc = 0;
	NXGE_REG_WR64(handle, offset, md_reg.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_cfg_port_ddr_weight(npi_handle_t handle,
				    uint8_t portnm, uint32_t weight)
{

	pt_drr_wt_t wt_reg;
	uint64_t offset;

	ASSERT(RXDMA_PORT_VALID(portnm));
	if (!RXDMA_PORT_VALID(portnm)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_cfg_port_ddr_weight"
		    " Illegal Port Number %d \n",
		    portnm));
		return (NPI_RXDMA_PORT_INVALID);
	}

	offset = PT_DRR_WT_REG(portnm);
	wt_reg.value = 0;
	wt_reg.bits.ldw.wt = weight;
	NXGE_REG_WR64(handle, offset, wt_reg.value);
	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_port_usage_get(npi_handle_t handle,
				    uint8_t portnm, uint32_t *blocks)
{

	pt_use_t use_reg;
	uint64_t offset;

	ASSERT(RXDMA_PORT_VALID(portnm));
	if (!RXDMA_PORT_VALID(portnm)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_port_usage_get"
		    " Illegal Port Number %d \n",
		    portnm));
		return (NPI_RXDMA_PORT_INVALID);
	}

	offset = PT_USE_REG(portnm);
	NXGE_REG_RD64(handle, offset, &use_reg.value);
	*blocks = use_reg.bits.ldw.cnt;
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_cfg_wred_param(npi_handle_t handle, uint8_t rdc,
				    rdc_red_para_t *wred_params)
{
	rdc_red_para_t wred_reg;
	uint64_t offset;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_cfg_wred_param"
		    " Illegal RDC Number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	/*
	 * need to update RDC_RED_PARA_REG as well as bit defs in
	 * the hw header file
	 */
	offset = RDC_RED_RDC_PARA_REG(rdc);

	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    " npi_rxdma_cfg_wred_param: "
	    "set RED_PARA: passed value 0x%llx "
	    "win 0x%x thre 0x%x sync 0x%x thre_sync 0x%x",
	    wred_params->value,
	    wred_params->bits.ldw.win,
	    wred_params->bits.ldw.thre,
	    wred_params->bits.ldw.win_syn,
	    wred_params->bits.ldw.thre_sync));

	wred_reg.value = 0;
	wred_reg.bits.ldw.win = wred_params->bits.ldw.win;
	wred_reg.bits.ldw.thre = wred_params->bits.ldw.thre;
	wred_reg.bits.ldw.win_syn = wred_params->bits.ldw.win_syn;
	wred_reg.bits.ldw.thre_sync = wred_params->bits.ldw.thre_sync;
	NXGE_REG_WR64(handle, offset, wred_reg.value);

	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    "set RED_PARA: value 0x%llx "
	    "win 0x%x thre 0x%x sync 0x%x thre_sync 0x%x",
	    wred_reg.value,
	    wred_reg.bits.ldw.win,
	    wred_reg.bits.ldw.thre,
	    wred_reg.bits.ldw.win_syn,
	    wred_reg.bits.ldw.thre_sync));

	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_rdc_table_config()
 * Configure/populate the RDC table
 *
 * Inputs:
 *	handle:	register handle interpreted by the underlying OS
 *	table:	RDC Group Number
 *	map:	A bitmap of the RDCs to populate with.
 *	count:	A count of the RDCs expressed in <map>.
 *
 * Notes:
 *	This function assumes that we are not using the TCAM, but are
 *	hashing all fields of the incoming ethernet packet!
 *
 * Return:
 *	NPI_SUCCESS
 *	NPI_RXDMA_TABLE_INVALID
 *
 */
npi_status_t
npi_rxdma_rdc_table_config(
	npi_handle_t handle,
	uint8_t table,
	dc_map_t rdc_map,
	int count)
{
	int8_t set[NXGE_MAX_RDCS];
	int i, cursor;

	rdc_tbl_t rdc_tbl;
	uint64_t offset;

	ASSERT(RXDMA_TABLE_VALID(table));
	if (!RXDMA_TABLE_VALID(table)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_cfg_rdc_table"
		    " Illegal RDC Table Number %d \n",
		    table));
		return (NPI_RXDMA_TABLE_INVALID);
	}

	if (count == 0)		/* This shouldn't happen */
		return (NPI_SUCCESS);

	for (i = 0, cursor = 0; i < NXGE_MAX_RDCS; i++) {
		if ((1 << i) & rdc_map) {
			set[cursor++] = (int8_t)i;
			if (cursor == count)
				break;
		}
	}

	rdc_tbl.value = 0;
	offset = REG_RDC_TABLE_OFFSET(table);

	/* Now write ( NXGE_MAX_RDCS / count ) sets of RDC numbers. */
	for (i = 0, cursor = 0; i < NXGE_MAX_RDCS; i++) {
		rdc_tbl.bits.ldw.rdc = set[cursor++];
		NXGE_REG_WR64(handle, offset, rdc_tbl.value);
		offset += sizeof (rdc_tbl.value);
		if (cursor == count)
			cursor = 0;
	}

	/*
	 * Here is what the resulting table looks like with:
	 *
	 *  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |v |w |x |y |z |v |w |x |y |z |v |w |x |y |z |v | 5 RDCs
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |w |x |y |z |w |x |y |z |w |x |y |z |w |x |y |z | 4 RDCs
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |x |y |z |x |y |z |x |y |z |x |y |z |x |y |z |x | 3 RDCs
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |x |y |x |y |x |y |x |y |x |y |x |y |x |y |x |y | 2 RDCs
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 * |x |x |x |x |x |x |x |x |x |x |x |x |x |x |x |x | 1 RDC
	 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 */

	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_cfg_rdc_table_default_rdc(npi_handle_t handle,
			    uint8_t table, uint8_t rdc)
{
	uint64_t offset;
	rdc_tbl_t tbl_reg;
	tbl_reg.value = 0;

	ASSERT(RXDMA_TABLE_VALID(table));
	if (!RXDMA_TABLE_VALID(table)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_cfg_rdc_table"
		    " Illegal RDC table Number %d \n",
		    rdc));
		return (NPI_RXDMA_TABLE_INVALID);
	}

	offset = REG_RDC_TABLE_OFFSET(table);
	tbl_reg.bits.ldw.rdc = rdc;
	NXGE_REG_WR64(handle, offset, tbl_reg.value);
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_dump_rdc_table(npi_handle_t handle,
			    uint8_t table)
{
	uint64_t offset;
	int tbl_offset;
	uint64_t value;

	ASSERT(RXDMA_TABLE_VALID(table));
	if (!RXDMA_TABLE_VALID(table)) {
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    " npi_rxdma_dump_rdc_table"
		    " Illegal RDC Rable Number %d \n",
		    table));
		return (NPI_RXDMA_TABLE_INVALID);
	}
	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n Register Dump for RDC Table %d \n",
	    table));
	offset = REG_RDC_TABLE_OFFSET(table);
	for (tbl_offset = 0; tbl_offset < NXGE_MAX_RDCS; tbl_offset++) {
		NXGE_REG_RD64(handle, offset, &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
		    " 0x%08llx 0x%08llx \n",
		    offset, value));
		offset += 8;
	}
	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n Register Dump for RDC Table %d done\n",
	    table));
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_rdc_rbr_stat_get(npi_handle_t handle, uint8_t rdc,
			    rbr_stat_t *rbr_stat)
{

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_rdc_rbr_stat_get"
		    " Illegal RDC Number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RBR_STAT_REG, rdc, &rbr_stat->value);
	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_rdc_rbr_head_get
 * Gets the current rbr head pointer.
 *
 * Inputs:
 *      handle:	opaque handle interpreted by the underlying OS
 *	rdc:		RX DMA Channel number
 *	hdptr		ptr to write the rbr head value
 *
 * Return:
 * NPI_SUCCESS
 * NPI_RXDMA_RDC_INVALID
 */
npi_status_t
npi_rxdma_rdc_rbr_head_get(npi_handle_t handle,
			    uint8_t rdc, addr44_t *hdptr)
{
	rbr_hdh_t hh_ptr;
	rbr_hdl_t hl_ptr;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_rdc_rbr_head_get"
		    " Illegal RDC Number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}
	hh_ptr.value = 0;
	hl_ptr.value = 0;
	RXDMA_REG_READ64(handle, RBR_HDH_REG, rdc, &hh_ptr.value);
	RXDMA_REG_READ64(handle, RBR_HDL_REG, rdc, &hl_ptr.value);
	hdptr->bits.ldw = hl_ptr.bits.ldw.head_l << 2;
	hdptr->bits.hdw = hh_ptr.bits.ldw.head_h;
	return (NPI_SUCCESS);

}

npi_status_t
npi_rxdma_rdc_rcr_qlen_get(npi_handle_t handle, uint8_t rdc,
			    uint16_t *rcr_qlen)
{

	rcrstat_a_t stats;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_rdc_rcr_qlen_get"
		    " Illegal RDC Number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RCRSTAT_A_REG, rdc, &stats.value);
	*rcr_qlen =  stats.bits.ldw.qlen;
	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    " rxdma_rdc_rcr_qlen_get"
	    " RDC %d qlen %x qlen %x\n",
	    rdc, *rcr_qlen, stats.bits.ldw.qlen));
	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_rdc_rcr_tail_get(npi_handle_t handle,
			    uint8_t rdc, addr44_t *tail_addr)
{

	rcrstat_b_t th_ptr;
	rcrstat_c_t tl_ptr;

	ASSERT(RXDMA_CHANNEL_VALID(rdc));
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " rxdma_rdc_rcr_tail_get"
		    " Illegal RDC Number %d \n",
		    rdc));
		return (NPI_RXDMA_RDC_INVALID);
	}
	th_ptr.value = 0;
	tl_ptr.value = 0;
	RXDMA_REG_READ64(handle, RCRSTAT_B_REG, rdc, &th_ptr.value);
	RXDMA_REG_READ64(handle, RCRSTAT_C_REG, rdc, &tl_ptr.value);
	tail_addr->bits.ldw = tl_ptr.bits.ldw.tlptr_l << 3;
	tail_addr->bits.hdw = th_ptr.bits.ldw.tlptr_h;
	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    " rxdma_rdc_rcr_tail_get"
	    " RDC %d rcr_tail %llx tl %x\n",
	    rdc, tl_ptr.value,
	    tl_ptr.bits.ldw.tlptr_l));

	return (NPI_SUCCESS);


}

/*
 * npi_rxdma_rxctl_fifo_error_intr_set
 * Configure The RX ctrl fifo error interrupt generation
 *
 * Inputs:
 *      handle:	opaque handle interpreted by the underlying OS
 *	mask:	rx_ctl_dat_fifo_mask_t specifying the errors
 * valid fields in  rx_ctl_dat_fifo_mask_t structure are:
 * zcp_eop_err, ipp_eop_err, id_mismatch. If a field is set
 * to 1, we will enable interrupt generation for the
 * corresponding error condition. In the hardware, the bit(s)
 * have to be cleared to enable interrupt.
 *
 * Return:
 * NPI_SUCCESS
 *
 */
npi_status_t
npi_rxdma_rxctl_fifo_error_intr_set(npi_handle_t handle,
				    rx_ctl_dat_fifo_mask_t *mask)
{
	uint64_t offset;
	rx_ctl_dat_fifo_mask_t intr_mask;
	offset = RX_CTL_DAT_FIFO_MASK_REG;
	NXGE_REG_RD64(handle, offset, &intr_mask.value);

	if (mask->bits.ldw.ipp_eop_err) {
		intr_mask.bits.ldw.ipp_eop_err = 0;
	}

	if (mask->bits.ldw.zcp_eop_err) {
		intr_mask.bits.ldw.zcp_eop_err = 0;
	}

	if (mask->bits.ldw.id_mismatch) {
		intr_mask.bits.ldw.id_mismatch = 0;
	}

	NXGE_REG_WR64(handle, offset, intr_mask.value);
	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_rxctl_fifo_error_stat_get
 * Read The RX ctrl fifo error Status
 *
 * Inputs:
 *      handle:	opaque handle interpreted by the underlying OS
 *	stat:	rx_ctl_dat_fifo_stat_t to read the errors to
 * valid fields in  rx_ctl_dat_fifo_stat_t structure are:
 * zcp_eop_err, ipp_eop_err, id_mismatch.
 * Return:
 * NPI_SUCCESS
 *
 */
npi_status_t
npi_rxdma_rxctl_fifo_error_intr_get(npi_handle_t handle,
			    rx_ctl_dat_fifo_stat_t *stat)
{
	uint64_t offset = RX_CTL_DAT_FIFO_STAT_REG;
	NXGE_REG_RD64(handle, offset, &stat->value);
	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_rdc_rcr_pktread_update(npi_handle_t handle, uint8_t channel,
				    uint16_t pkts_read)
{

	rx_dma_ctl_stat_t	cs;
	uint16_t min_read = 0;

	ASSERT(RXDMA_CHANNEL_VALID(channel));
	if (!RXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_rdc_rcr_pktread_update ",
		    " channel %d", channel));
		return (NPI_FAILURE | NPI_RXDMA_CHANNEL_INVALID(channel));
	}

	if ((pkts_read < min_read) && (pkts_read > 512)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_rdc_rcr_pktread_update ",
		    " pkts %d out of bound", pkts_read));
		return (NPI_RXDMA_OPCODE_INVALID(pkts_read));
	}

	RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
	    &cs.value);
	cs.bits.ldw.pktread = pkts_read;
	RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG,
	    channel, cs.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_rdc_rcr_bufread_update(npi_handle_t handle, uint8_t channel,
					    uint16_t bufs_read)
{

	rx_dma_ctl_stat_t	cs;
	uint16_t min_read = 0;

	ASSERT(RXDMA_CHANNEL_VALID(channel));
	if (!RXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_rdc_rcr_bufread_update ",
		    " channel %d", channel));
		return (NPI_FAILURE | NPI_RXDMA_CHANNEL_INVALID(channel));
	}

	if ((bufs_read < min_read) && (bufs_read > 512)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_rdc_rcr_bufread_update ",
		    " bufs read %d out of bound", bufs_read));
		return (NPI_RXDMA_OPCODE_INVALID(bufs_read));
	}

	RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
	    &cs.value);
	cs.bits.ldw.ptrread = bufs_read;
	RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG,
	    channel, cs.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_rxdma_rdc_rcr_read_update(npi_handle_t handle, uint8_t channel,
				    uint16_t pkts_read, uint16_t bufs_read)
{

	rx_dma_ctl_stat_t	cs;

	ASSERT(RXDMA_CHANNEL_VALID(channel));
	if (!RXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_rdc_rcr_read_update ",
		    " channel %d", channel));
		return (NPI_FAILURE | NPI_RXDMA_CHANNEL_INVALID(channel));
	}

	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    " npi_rxdma_rdc_rcr_read_update "
	    " bufs read %d pkt read %d",
	    bufs_read, pkts_read));

	RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
	    &cs.value);

	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    " npi_rxdma_rdc_rcr_read_update: "
	    " value: 0x%llx bufs read %d pkt read %d",
	    cs.value,
	    cs.bits.ldw.ptrread, cs.bits.ldw.pktread));

	cs.bits.ldw.pktread = pkts_read;
	cs.bits.ldw.ptrread = bufs_read;

	RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG,
	    channel, cs.value);

	RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
	    &cs.value);

	NPI_DEBUG_MSG((handle.function, NPI_RDC_CTL,
	    " npi_rxdma_rdc_rcr_read_update: read back after update "
	    " value: 0x%llx bufs read %d pkt read %d",
	    cs.value,
	    cs.bits.ldw.ptrread, cs.bits.ldw.pktread));

	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_channel_mex_set():
 *	This function is called to arm the DMA channel with
 *	mailbox updating capability. Software needs to rearm
 *	for each update by writing to the control and status register.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 *
 * Return:
 *	NPI_SUCCESS		- If enable channel with mailbox update
 *				  is completed successfully.
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_channel_mex_set(npi_handle_t handle, uint8_t channel)
{
	return (npi_rxdma_channel_control(handle, RXDMA_MEX_SET, channel));
}

/*
 * npi_rxdma_channel_rcrto_clear():
 *	This function is called to reset RCRTO bit to 0.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_channel_rcrto_clear(npi_handle_t handle, uint8_t channel)
{
	return (npi_rxdma_channel_control(handle, RXDMA_RCRTO_CLEAR, channel));
}

/*
 * npi_rxdma_channel_pt_drop_pkt_clear():
 *	This function is called to clear the port drop packet bit (debug).
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_channel_pt_drop_pkt_clear(npi_handle_t handle, uint8_t channel)
{
	return (npi_rxdma_channel_control(handle, RXDMA_PT_DROP_PKT_CLEAR,
	    channel));
}

/*
 * npi_rxdma_channel_wred_drop_clear():
 *	This function is called to wred drop bit (debug only).
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_channel_wred_dop_clear(npi_handle_t handle, uint8_t channel)
{
	return (npi_rxdma_channel_control(handle, RXDMA_WRED_DROP_CLEAR,
	    channel));
}

/*
 * npi_rxdma_channel_rcr_shfull_clear():
 *	This function is called to clear RCR shadow full bit.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_channel_rcr_shfull_clear(npi_handle_t handle, uint8_t channel)
{
	return (npi_rxdma_channel_control(handle, RXDMA_RCR_SFULL_CLEAR,
	    channel));
}

/*
 * npi_rxdma_channel_rcrfull_clear():
 *	This function is called to clear RCR full bit.
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware
 *			   channel number).
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_channel_rcr_full_clear(npi_handle_t handle, uint8_t channel)
{
	return (npi_rxdma_channel_control(handle, RXDMA_RCR_FULL_CLEAR,
	    channel));
}

npi_status_t
npi_rxdma_channel_rbr_empty_clear(npi_handle_t handle, uint8_t channel)
{
	return (npi_rxdma_channel_control(handle,
	    RXDMA_RBR_EMPTY_CLEAR, channel));
}

npi_status_t
npi_rxdma_channel_cs_clear_all(npi_handle_t handle, uint8_t channel)
{
	return (npi_rxdma_channel_control(handle, RXDMA_CS_CLEAR_ALL, channel));
}

/*
 * npi_rxdma_channel_control():
 *	This function is called to control a receive DMA channel
 *	for arming the channel with mailbox updates, resetting
 *	various event status bits (control and status register).
 *
 * Parameters:
 *	handle		- NPI handle (virtualization flag must be defined).
 *	control		- NPI defined control type supported:
 *				- RXDMA_MEX_SET
 * 				- RXDMA_RCRTO_CLEAR
 *				- RXDMA_PT_DROP_PKT_CLEAR
 *				- RXDMA_WRED_DROP_CLEAR
 *				- RXDMA_RCR_SFULL_CLEAR
 *				- RXDMA_RCR_FULL_CLEAR
 *				- RXDMA_RBR_PRE_EMPTY_CLEAR
 *				- RXDMA_RBR_EMPTY_CLEAR
 *	channel		- logical RXDMA channel from 0 to 23.
 *			  (If virtualization flag is not set, then
 *			   logical channel is the same as the hardware.
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_channel_control(npi_handle_t handle, rxdma_cs_cntl_t control,
			uint8_t channel)
{

	rx_dma_ctl_stat_t	cs;

	ASSERT(RXDMA_CHANNEL_VALID(channel));
	if (!RXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_rxdma_channel_control",
		    " channel", channel));
		return (NPI_FAILURE | NPI_RXDMA_CHANNEL_INVALID(channel));
	}

	switch (control) {
	case RXDMA_MEX_SET:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		cs.bits.hdw.mex = 1;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG,
		    channel, cs.value);
		break;

	case RXDMA_RCRTO_CLEAR:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		cs.bits.hdw.rcrto = 0;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs.value);
		break;

	case RXDMA_PT_DROP_PKT_CLEAR:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		cs.bits.hdw.port_drop_pkt = 0;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs.value);
		break;

	case RXDMA_WRED_DROP_CLEAR:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		cs.bits.hdw.wred_drop = 0;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs.value);
		break;

	case RXDMA_RCR_SFULL_CLEAR:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		cs.bits.hdw.rcr_shadow_full = 0;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs.value);
		break;

	case RXDMA_RCR_FULL_CLEAR:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		cs.bits.hdw.rcrfull = 0;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs.value);
		break;

	case RXDMA_RBR_PRE_EMPTY_CLEAR:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		cs.bits.hdw.rbr_pre_empty = 0;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs.value);
		break;

	case RXDMA_RBR_EMPTY_CLEAR:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		cs.bits.hdw.rbr_empty = 1;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs.value);
		break;

	case RXDMA_CS_CLEAR_ALL:
		cs.value = 0;
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs.value);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_channel_control",
		    "control", control));
		return (NPI_FAILURE | NPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (NPI_SUCCESS);
}

/*
 * npi_rxdma_control_status():
 *	This function is called to operate on the control
 *	and status register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware control and status
 *			  OP_SET: set hardware control and status
 *			  OP_UPDATE: update hardware control and status.
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	cs_p		- pointer to hardware defined control and status
 *			  structure.
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_control_status(npi_handle_t handle, io_op_t op_mode,
			uint8_t channel, p_rx_dma_ctl_stat_t cs_p)
{
	int			status = NPI_SUCCESS;
	rx_dma_ctl_stat_t	cs;

	ASSERT(RXDMA_CHANNEL_VALID(channel));
	if (!RXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_control_status",
		    "channel", channel));
		return (NPI_FAILURE | NPI_RXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs_p->value);
		break;

	case OP_SET:
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs_p->value);
		break;

	case OP_UPDATE:
		RXDMA_REG_READ64(handle, RX_DMA_CTL_STAT_REG, channel,
		    &cs.value);
		RXDMA_REG_WRITE64(handle, RX_DMA_CTL_STAT_REG, channel,
		    cs_p->value | cs.value);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_control_status",
		    "control", op_mode));
		return (NPI_FAILURE | NPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * npi_rxdma_event_mask():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	mask_p		- pointer to hardware defined event mask
 *			  structure.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_event_mask(npi_handle_t handle, io_op_t op_mode,
		uint8_t channel, p_rx_dma_ent_msk_t mask_p)
{
	int			status = NPI_SUCCESS;
	rx_dma_ent_msk_t	mask;

	ASSERT(RXDMA_CHANNEL_VALID(channel));
	if (!RXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_event_mask",
		    "channel", channel));
		return (NPI_FAILURE | NPI_RXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		RXDMA_REG_READ64(handle, RX_DMA_ENT_MSK_REG, channel,
		    &mask_p->value);
		break;

	case OP_SET:
		RXDMA_REG_WRITE64(handle, RX_DMA_ENT_MSK_REG, channel,
		    mask_p->value);
		break;

	case OP_UPDATE:
		RXDMA_REG_READ64(handle, RX_DMA_ENT_MSK_REG, channel,
		    &mask.value);
		RXDMA_REG_WRITE64(handle, RX_DMA_ENT_MSK_REG, channel,
		    mask_p->value | mask.value);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_event_mask",
		    "eventmask", op_mode));
		return (NPI_FAILURE | NPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * npi_rxdma_event_mask_config():
 *	This function is called to operate on the event mask
 *	register which is used for generating interrupts
 *	and status register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get hardware event mask
 *			  OP_SET: set hardware interrupt event masks
 *			  OP_CLEAR: clear control and status register to 0s.
 *	channel		- hardware RXDMA channel from 0 to 23.
 *	mask_cfgp		- pointer to NPI defined event mask
 *			  enum data type.
 * Return:
 *	NPI_SUCCESS		- If set is complete successfully.
 *
 *	Error:
 *	NPI error status code
 */
npi_status_t
npi_rxdma_event_mask_config(npi_handle_t handle, io_op_t op_mode,
		uint8_t channel, rxdma_ent_msk_cfg_t *mask_cfgp)
{
	int		status = NPI_SUCCESS;
	uint64_t	configuration = *mask_cfgp;
	uint64_t	value;

	ASSERT(RXDMA_CHANNEL_VALID(channel));
	if (!RXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_event_mask_config",
		    "channel", channel));
		return (NPI_FAILURE | NPI_RXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		RXDMA_REG_READ64(handle, RX_DMA_ENT_MSK_REG, channel,
		    (uint64_t *)mask_cfgp);
		break;

	case OP_SET:
		RXDMA_REG_WRITE64(handle, RX_DMA_ENT_MSK_REG, channel,
		    configuration);
		break;

	case OP_UPDATE:
		RXDMA_REG_READ64(handle, RX_DMA_ENT_MSK_REG, channel, &value);
		RXDMA_REG_WRITE64(handle, RX_DMA_ENT_MSK_REG, channel,
		    configuration | value);
		break;

	case OP_CLEAR:
		RXDMA_REG_WRITE64(handle, RX_DMA_ENT_MSK_REG, channel,
		    CFG_RXDMA_MASK_ALL);
		break;
	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_rxdma_event_mask_config",
		    "eventmask", op_mode));
		return (NPI_FAILURE | NPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}
