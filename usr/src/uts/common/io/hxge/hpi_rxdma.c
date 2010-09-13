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

#include <hpi_rxdma.h>
#include <hxge_common.h>
#include <hxge_impl.h>

#define	 RXDMA_RESET_TRY_COUNT	5
#define	 RXDMA_RESET_DELAY	5

#define	 RXDMA_OP_DISABLE	0
#define	 RXDMA_OP_ENABLE	1
#define	 RXDMA_OP_RESET		2

#define	 RCR_TIMEOUT_ENABLE	1
#define	 RCR_TIMEOUT_DISABLE	2
#define	 RCR_THRESHOLD		4

hpi_status_t
hpi_rxdma_cfg_logical_page_handle(hpi_handle_t handle, uint8_t rdc,
    uint64_t page_handle)
{
	rdc_page_handle_t page_hdl;

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "rxdma_cfg_logical_page_handle"
		    " Illegal RDC number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	page_hdl.value = 0;
	page_hdl.bits.handle = (uint32_t)page_handle;

	RXDMA_REG_WRITE64(handle, RDC_PAGE_HANDLE, rdc, page_hdl.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_rxdma_cfg_rdc_wait_for_qst(hpi_handle_t handle, uint8_t rdc)
{
	rdc_rx_cfg1_t	cfg;
	uint32_t	count = RXDMA_RESET_TRY_COUNT;
	uint32_t	delay_time = RXDMA_RESET_DELAY;

	RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);

	while ((count--) && (cfg.bits.qst == 0)) {
		HXGE_DELAY(delay_time);
		RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);
	}

	if (cfg.bits.qst == 0)
		return (HPI_FAILURE);

	return (HPI_SUCCESS);
}

/* RX DMA functions */
static hpi_status_t
hpi_rxdma_cfg_rdc_ctl(hpi_handle_t handle, uint8_t rdc, uint8_t op)
{
	rdc_rx_cfg1_t cfg;
	uint32_t count = RXDMA_RESET_TRY_COUNT;
	uint32_t delay_time = RXDMA_RESET_DELAY;
	uint32_t error = HPI_RXDMA_ERROR_ENCODE(HPI_RXDMA_RESET_ERR, rdc);

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "hpi_rxdma_cfg_rdc_ctl Illegal RDC number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	switch (op) {
	case RXDMA_OP_ENABLE:
		RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);
		cfg.bits.enable = 1;
		RXDMA_REG_WRITE64(handle, RDC_RX_CFG1, rdc, cfg.value);

		HXGE_DELAY(delay_time);
		RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);

		while ((count--) && (cfg.bits.qst == 1)) {
			HXGE_DELAY(delay_time);
			RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);
		}
		if (cfg.bits.qst == 1) {
			return (HPI_FAILURE);
		}
		break;

	case RXDMA_OP_DISABLE:
		RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);
		cfg.bits.enable = 0;
		RXDMA_REG_WRITE64(handle, RDC_RX_CFG1, rdc, cfg.value);

		HXGE_DELAY(delay_time);
		if (hpi_rxdma_cfg_rdc_wait_for_qst(handle,
		    rdc) != HPI_SUCCESS) {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    " hpi_rxdma_cfg_rdc_ctl"
			    " RXDMA_OP_DISABLE Failed for RDC %d \n",
			    rdc));
			return (error);
		}
		break;

	case RXDMA_OP_RESET:
		cfg.value = 0;
		cfg.bits.reset = 1;
		RXDMA_REG_WRITE64(handle, RDC_RX_CFG1, rdc, cfg.value);
		HXGE_DELAY(delay_time);
		RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);

		while ((count--) && (cfg.bits.qst == 0)) {
			HXGE_DELAY(delay_time);
			RXDMA_REG_READ64(handle, RDC_RX_CFG1, rdc, &cfg.value);
		}
		if (count == 0) {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    " hpi_rxdma_cfg_rdc_ctl"
			    " Reset Failed for RDC %d \n", rdc));
			return (error);
		}
		break;

	default:
		return (HPI_RXDMA_SW_PARAM_ERROR);
	}

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_rxdma_cfg_rdc_enable(hpi_handle_t handle, uint8_t rdc)
{
	return (hpi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_ENABLE));
}

hpi_status_t
hpi_rxdma_cfg_rdc_disable(hpi_handle_t handle, uint8_t rdc)
{
	return (hpi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_DISABLE));
}

hpi_status_t
hpi_rxdma_cfg_rdc_reset(hpi_handle_t handle, uint8_t rdc)
{
	return (hpi_rxdma_cfg_rdc_ctl(handle, rdc, RXDMA_OP_RESET));
}

static hpi_status_t
hpi_rxdma_cfg_rdc_rcr_ctl(hpi_handle_t handle, uint8_t rdc,
    uint8_t op, uint16_t param)
{
	rdc_rcr_cfg_b_t rcr_cfgb;

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "rxdma_cfg_rdc_rcr_ctl Illegal RDC number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RDC_RCR_CFG_B, rdc, &rcr_cfgb.value);

	switch (op) {
	case RCR_TIMEOUT_ENABLE:
		rcr_cfgb.bits.timeout = (uint8_t)param;
		rcr_cfgb.bits.entout = 1;
		break;

	case RCR_THRESHOLD:
		rcr_cfgb.bits.pthres = param;
		break;

	case RCR_TIMEOUT_DISABLE:
		rcr_cfgb.bits.entout = 0;
		break;

	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "rxdma_cfg_rdc_rcr_ctl Illegal opcode %x \n", op));
		return (HPI_RXDMA_OPCODE_INVALID(rdc));
	}

	RXDMA_REG_WRITE64(handle, RDC_RCR_CFG_B, rdc, rcr_cfgb.value);
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_rxdma_cfg_rdc_rcr_threshold(hpi_handle_t handle, uint8_t rdc,
    uint16_t rcr_threshold)
{
	return (hpi_rxdma_cfg_rdc_rcr_ctl(handle, rdc,
	    RCR_THRESHOLD, rcr_threshold));
}

hpi_status_t
hpi_rxdma_cfg_rdc_rcr_timeout(hpi_handle_t handle, uint8_t rdc,
    uint8_t rcr_timeout)
{
	return (hpi_rxdma_cfg_rdc_rcr_ctl(handle, rdc,
	    RCR_TIMEOUT_ENABLE, rcr_timeout));
}

/*
 * Configure The RDC channel Rcv Buffer Ring
 */
hpi_status_t
hpi_rxdma_cfg_rdc_ring(hpi_handle_t handle, uint8_t rdc,
    rdc_desc_cfg_t *rdc_desc_cfg)
{
	rdc_rbr_cfg_a_t		cfga;
	rdc_rbr_cfg_b_t		cfgb;
	rdc_rx_cfg1_t		cfg1;
	rdc_rx_cfg2_t		cfg2;
	rdc_rcr_cfg_a_t		rcr_cfga;
	rdc_rcr_cfg_b_t		rcr_cfgb;
	rdc_page_handle_t	page_handle;

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "rxdma_cfg_rdc_ring Illegal RDC number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	cfga.value = 0;
	cfgb.value = 0;
	cfg1.value = 0;
	cfg2.value = 0;
	page_handle.value = 0;

	if (rdc_desc_cfg->mbox_enable == 1) {
		cfg1.bits.mbaddr_h = (rdc_desc_cfg->mbox_addr >> 32) & 0xfff;
		cfg2.bits.mbaddr_l = ((rdc_desc_cfg->mbox_addr &
		    RXDMA_CFIG2_MBADDR_L_MASK) >> RXDMA_CFIG2_MBADDR_L_SHIFT);

		/*
		 * Only after all the configurations are set, then
		 * enable the RDC or else configuration fatal error
		 * will be returned (especially if the Hypervisor
		 * set up the logical pages with non-zero values.
		 * This HPI function only sets up the configuration.
		 * Call the enable function to enable the RDMC!
		 */
	}

	if (rdc_desc_cfg->full_hdr == 1)
		cfg2.bits.full_hdr = 1;

	if (RXDMA_BUFF_OFFSET_VALID(rdc_desc_cfg->offset)) {
		cfg2.bits.offset = rdc_desc_cfg->offset;
	} else {
		cfg2.bits.offset = SW_OFFSET_NO_OFFSET;
	}

	/* rbr config */
	cfga.value = (rdc_desc_cfg->rbr_addr &
	    (RBR_CFIG_A_STDADDR_MASK | RBR_CFIG_A_STDADDR_BASE_MASK));

	/* The remaining 20 bits in the DMA address form the handle */
	page_handle.bits.handle = (rdc_desc_cfg->rbr_addr >> 44) && 0xfffff;

	/*
	 * The RBR ring size must be multiple of 64.
	 */
	if ((rdc_desc_cfg->rbr_len < RBR_DEFAULT_MIN_LEN) ||
	    (rdc_desc_cfg->rbr_len > RBR_DEFAULT_MAX_LEN) ||
	    (rdc_desc_cfg->rbr_len % 64)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "hpi_rxdma_cfg_rdc_ring Illegal RBR Queue Length %d \n",
		    rdc_desc_cfg->rbr_len));
		return (HPI_RXDMA_ERROR_ENCODE(HPI_RXDMA_RBRSZIE_INVALID, rdc));
	}

	/*
	 * The lower 6 bits are hardcoded to 0 and the higher 10 bits are
	 * stored in len.
	 */
	cfga.bits.len = rdc_desc_cfg->rbr_len >> 6;
	HPI_DEBUG_MSG((handle.function, HPI_RDC_CTL,
	    "hpi_rxdma_cfg_rdc_ring CFGA 0x%llx len %d (RBR LEN %d)\n",
	    cfga.value, cfga.bits.len, rdc_desc_cfg->rbr_len));

	/*
	 * bksize is 1 bit
	 * Buffer Block Size. b0 - 4K; b1 - 8K.
	 */
	if (rdc_desc_cfg->page_size == SIZE_4KB)
		cfgb.bits.bksize = RBR_BKSIZE_4K;
	else if (rdc_desc_cfg->page_size == SIZE_8KB)
		cfgb.bits.bksize = RBR_BKSIZE_8K;
	else {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "rxdma_cfg_rdc_ring blksize: Illegal buffer size %d \n",
		    rdc_desc_cfg->page_size));
		return (HPI_RXDMA_BUFSZIE_INVALID);
	}

	/*
	 * Size 0 of packet buffer. b00 - 256; b01 - 512; b10 - 1K; b11 - resvd.
	 */
	if (rdc_desc_cfg->valid0) {
		if (rdc_desc_cfg->size0 == SIZE_256B)
			cfgb.bits.bufsz0 = RBR_BUFSZ0_256B;
		else if (rdc_desc_cfg->size0 == SIZE_512B)
			cfgb.bits.bufsz0 = RBR_BUFSZ0_512B;
		else if (rdc_desc_cfg->size0 == SIZE_1KB)
			cfgb.bits.bufsz0 = RBR_BUFSZ0_1K;
		else {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize0: Illegal buffer size %x \n",
			    rdc_desc_cfg->size0));
			return (HPI_RXDMA_BUFSZIE_INVALID);
		}
		cfgb.bits.vld0 = 1;
	} else {
		cfgb.bits.vld0 = 0;
	}

	/*
	 * Size 1 of packet buffer. b0 - 1K; b1 - 2K.
	 */
	if (rdc_desc_cfg->valid1) {
		if (rdc_desc_cfg->size1 == SIZE_1KB)
			cfgb.bits.bufsz1 = RBR_BUFSZ1_1K;
		else if (rdc_desc_cfg->size1 == SIZE_2KB)
			cfgb.bits.bufsz1 = RBR_BUFSZ1_2K;
		else {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize1: Illegal buffer size %x \n",
			    rdc_desc_cfg->size1));
			return (HPI_RXDMA_BUFSZIE_INVALID);
		}
		cfgb.bits.vld1 = 1;
	} else {
		cfgb.bits.vld1 = 0;
	}

	/*
	 * Size 2 of packet buffer. b0 - 2K; b1 - 4K.
	 */
	if (rdc_desc_cfg->valid2) {
		if (rdc_desc_cfg->size2 == SIZE_2KB)
			cfgb.bits.bufsz2 = RBR_BUFSZ2_2K;
		else if (rdc_desc_cfg->size2 == SIZE_4KB)
			cfgb.bits.bufsz2 = RBR_BUFSZ2_4K;
		else {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " blksize2: Illegal buffer size %x \n",
			    rdc_desc_cfg->size2));
			return (HPI_RXDMA_BUFSZIE_INVALID);
		}
		cfgb.bits.vld2 = 1;
	} else {
		cfgb.bits.vld2 = 0;
	}

	rcr_cfga.value = (rdc_desc_cfg->rcr_addr &
	    (RCRCFIG_A_STADDR_MASK | RCRCFIG_A_STADDR_BASE_MASK));

	/*
	 * The rcr len must be multiple of 32.
	 */
	if ((rdc_desc_cfg->rcr_len < RCR_DEFAULT_MIN_LEN) ||
	    (rdc_desc_cfg->rcr_len > HXGE_RCR_MAX) ||
	    (rdc_desc_cfg->rcr_len % 32)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " rxdma_cfg_rdc_ring Illegal RCR Queue Length %d \n",
		    rdc_desc_cfg->rcr_len));
		return (HPI_RXDMA_ERROR_ENCODE(HPI_RXDMA_RCRSZIE_INVALID, rdc));
	}

	/*
	 * Bits 15:5 of the maximum number of 8B entries in RCR.  Bits 4:0 are
	 * hard-coded to zero.  The maximum size is 2^16 - 32.
	 */
	rcr_cfga.bits.len = rdc_desc_cfg->rcr_len >> 5;

	rcr_cfgb.value = 0;
	if (rdc_desc_cfg->rcr_timeout_enable == 1) {
		/* check if the rcr timeout value is valid */

		if (RXDMA_RCR_TO_VALID(rdc_desc_cfg->rcr_timeout)) {
			rcr_cfgb.bits.timeout = rdc_desc_cfg->rcr_timeout;
			rcr_cfgb.bits.entout = 1;
		} else {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    " rxdma_cfg_rdc_ring"
			    " Illegal RCR Timeout value %d \n",
			    rdc_desc_cfg->rcr_timeout));
			rcr_cfgb.bits.entout = 0;
		}
	} else {
		rcr_cfgb.bits.entout = 0;
	}

	/* check if the rcr threshold value is valid */
	if (RXDMA_RCR_THRESH_VALID(rdc_desc_cfg->rcr_threshold)) {
		rcr_cfgb.bits.pthres = rdc_desc_cfg->rcr_threshold;
	} else {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " rxdma_cfg_rdc_ring Illegal RCR Threshold value %d \n",
		    rdc_desc_cfg->rcr_threshold));
		rcr_cfgb.bits.pthres = 1;
	}

	/* now do the actual HW configuration */
	RXDMA_REG_WRITE64(handle, RDC_RX_CFG1, rdc, cfg1.value);
	RXDMA_REG_WRITE64(handle, RDC_RX_CFG2, rdc, cfg2.value);

	RXDMA_REG_WRITE64(handle, RDC_RBR_CFG_A, rdc, cfga.value);
	RXDMA_REG_WRITE64(handle, RDC_RBR_CFG_B, rdc, cfgb.value);

	RXDMA_REG_WRITE64(handle, RDC_RCR_CFG_A, rdc, rcr_cfga.value);
	RXDMA_REG_WRITE64(handle, RDC_RCR_CFG_B, rdc, rcr_cfgb.value);

	RXDMA_REG_WRITE64(handle, RDC_PAGE_HANDLE, rdc, page_handle.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_rxdma_ring_perr_stat_get(hpi_handle_t handle,
    rdc_pref_par_log_t *pre_log, rdc_pref_par_log_t *sha_log)
{
	/*
	 * Hydra doesn't have details about these errors.
	 * It only provides the addresses of the errors.
	 */
	HXGE_REG_RD64(handle, RDC_PREF_PAR_LOG, &pre_log->value);
	HXGE_REG_RD64(handle, RDC_SHADOW_PAR_LOG, &sha_log->value);

	return (HPI_SUCCESS);
}


/* system wide conf functions */

hpi_status_t
hpi_rxdma_cfg_clock_div_set(hpi_handle_t handle, uint16_t count)
{
	uint64_t	offset;
	rdc_clock_div_t	clk_div;

	offset = RDC_CLOCK_DIV;

	clk_div.value = 0;
	clk_div.bits.count = count;
	HPI_DEBUG_MSG((handle.function, HPI_RDC_CTL,
	    " hpi_rxdma_cfg_clock_div_set: add 0x%llx "
	    "handle 0x%llx value 0x%llx",
	    handle.regp, handle.regh, clk_div.value));

	HXGE_REG_WR64(handle, offset, clk_div.value);

	return (HPI_SUCCESS);
}


hpi_status_t
hpi_rxdma_rdc_rbr_stat_get(hpi_handle_t handle, uint8_t rdc,
    rdc_rbr_qlen_t *rbr_stat)
{
	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " rxdma_rdc_rbr_stat_get Illegal RDC Number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RDC_RBR_QLEN, rdc, &rbr_stat->value);
	return (HPI_SUCCESS);
}


hpi_status_t
hpi_rxdma_rdc_rcr_qlen_get(hpi_handle_t handle, uint8_t rdc,
    uint16_t *rcr_qlen)
{
	rdc_rcr_qlen_t stats;

	if (!RXDMA_CHANNEL_VALID(rdc)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " rxdma_rdc_rcr_qlen_get Illegal RDC Number %d \n", rdc));
		return (HPI_RXDMA_RDC_INVALID);
	}

	RXDMA_REG_READ64(handle, RDC_RCR_QLEN, rdc, &stats.value);
	*rcr_qlen =  stats.bits.qlen;
	HPI_DEBUG_MSG((handle.function, HPI_RDC_CTL,
	    " rxdma_rdc_rcr_qlen_get RDC %d qlen %x qlen %x\n",
	    rdc, *rcr_qlen, stats.bits.qlen));
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_rxdma_channel_rbr_empty_clear(hpi_handle_t handle, uint8_t channel)
{
	rdc_stat_t	cs;

	if (!RXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_rxdma_channel_rbr_empty_clear", " channel", channel));
		return (HPI_FAILURE | HPI_RXDMA_CHANNEL_INVALID(channel));
	}

	RXDMA_REG_READ64(handle, RDC_STAT, channel, &cs.value);
	cs.bits.rbr_empty = 1;
	RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs.value);

	return (HPI_SUCCESS);
}

/*
 * This function is called to operate on the control and status register.
 */
hpi_status_t
hpi_rxdma_control_status(hpi_handle_t handle, io_op_t op_mode, uint8_t channel,
    rdc_stat_t *cs_p)
{
	int		status = HPI_SUCCESS;
	rdc_stat_t	cs;

	if (!RXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "hpi_rxdma_control_status", "channel", channel));
		return (HPI_FAILURE | HPI_RXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		RXDMA_REG_READ64(handle, RDC_STAT, channel, &cs_p->value);
		break;

	case OP_SET:
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel, cs_p->value);
		break;

	case OP_UPDATE:
		RXDMA_REG_READ64(handle, RDC_STAT, channel, &cs.value);
		RXDMA_REG_WRITE64(handle, RDC_STAT, channel,
		    cs_p->value | cs.value);
		break;

	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "hpi_rxdma_control_status", "control", op_mode));
		return (HPI_FAILURE | HPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * This function is called to operate on the event mask
 * register which is used for generating interrupts.
 */
hpi_status_t
hpi_rxdma_event_mask(hpi_handle_t handle, io_op_t op_mode, uint8_t channel,
    rdc_int_mask_t *mask_p)
{
	int		status = HPI_SUCCESS;
	rdc_int_mask_t	mask;

	if (!RXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "hpi_rxdma_event_mask", "channel", channel));
		return (HPI_FAILURE | HPI_RXDMA_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		RXDMA_REG_READ64(handle, RDC_INT_MASK, channel, &mask_p->value);
		break;

	case OP_SET:
		RXDMA_REG_WRITE64(handle, RDC_INT_MASK, channel, mask_p->value);
		break;

	case OP_UPDATE:
		RXDMA_REG_READ64(handle, RDC_INT_MASK, channel, &mask.value);
		RXDMA_REG_WRITE64(handle, RDC_INT_MASK, channel,
		    mask_p->value | mask.value);
		break;

	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "hpi_rxdma_event_mask", "eventmask", op_mode));
		return (HPI_FAILURE | HPI_RXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}
