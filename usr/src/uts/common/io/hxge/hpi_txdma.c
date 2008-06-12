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

#include <hpi_txdma.h>
#include <hxge_impl.h>

#define	TXDMA_WAIT_LOOP		10000
#define	TXDMA_WAIT_MSEC		5

static hpi_status_t hpi_txdma_control_reset_wait(hpi_handle_t handle,
    uint8_t channel);

hpi_status_t
hpi_txdma_log_page_handle_set(hpi_handle_t handle, uint8_t channel,
    tdc_page_handle_t *hdl_p)
{
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_log_page_handle_set"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}

	TXDMA_REG_WRITE64(handle, TDC_PAGE_HANDLE, channel, hdl_p->value);

	return (status);
}

hpi_status_t
hpi_txdma_channel_reset(hpi_handle_t handle, uint8_t channel)
{
	HPI_DEBUG_MSG((handle.function, HPI_TDC_CTL,
	    " hpi_txdma_channel_reset" " RESETTING", channel));
	return (hpi_txdma_channel_control(handle, TXDMA_RESET, channel));
}

hpi_status_t
hpi_txdma_channel_init_enable(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_txdma_channel_control(handle, TXDMA_INIT_START, channel));
}

hpi_status_t
hpi_txdma_channel_enable(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_txdma_channel_control(handle, TXDMA_START, channel));
}

hpi_status_t
hpi_txdma_channel_disable(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_txdma_channel_control(handle, TXDMA_STOP, channel));
}

hpi_status_t
hpi_txdma_channel_mbox_enable(hpi_handle_t handle, uint8_t channel)
{
	return (hpi_txdma_channel_control(handle, TXDMA_MBOX_ENABLE, channel));
}

hpi_status_t
hpi_txdma_channel_control(hpi_handle_t handle, txdma_cs_cntl_t control,
    uint8_t channel)
{
	int		status = HPI_SUCCESS;
	tdc_stat_t	cs;
	tdc_tdr_cfg_t	cfg;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_channel_control"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}

	switch (control) {
	case TXDMA_INIT_RESET:
		cfg.value = 0;
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &cfg.value);
		cfg.bits.reset = 1;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		return (hpi_txdma_control_reset_wait(handle, channel));

	case TXDMA_INIT_START:
		cfg.value = 0;
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &cfg.value);
		cfg.bits.enable = 1;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		break;

	case TXDMA_RESET:
		/*
		 * Sets reset bit only (Hardware will reset all the RW bits but
		 * leave the RO bits alone.
		 */
		cfg.value = 0;
		cfg.bits.reset = 1;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		return (hpi_txdma_control_reset_wait(handle, channel));

	case TXDMA_START:
		/* Enable the DMA channel */
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &cfg.value);
		cfg.bits.enable = 1;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		break;

	case TXDMA_STOP:
		/* Disable the DMA channel */
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &cfg.value);
		cfg.bits.enable = 0;
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, cfg.value);
		status = hpi_txdma_control_stop_wait(handle, channel);
		if (status) {
			HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
			    "Cannot stop channel %d (TXC hung!)", channel));
		}
		break;

	case TXDMA_MBOX_ENABLE:
		/*
		 * Write 1 to MB bit to enable mailbox update (cleared to 0 by
		 * hardware after update).
		 */
		TXDMA_REG_READ64(handle, TDC_STAT, channel, &cs.value);
		cs.bits.mb = 1;
		TXDMA_REG_WRITE64(handle, TDC_STAT, channel, cs.value);
		break;

	default:
		status = (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_channel_control"
		    " Invalid Input: control <0x%x>", control));
	}

	return (status);
}

hpi_status_t
hpi_txdma_control_status(hpi_handle_t handle, io_op_t op_mode, uint8_t channel,
    tdc_stat_t *cs_p)
{
	int		status = HPI_SUCCESS;
	tdc_stat_t	txcs;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_control_status"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TDC_STAT, channel, &cs_p->value);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TDC_STAT, channel, cs_p->value);
		break;

	case OP_UPDATE:
		TXDMA_REG_READ64(handle, TDC_STAT, channel, &txcs.value);
		TXDMA_REG_WRITE64(handle, TDC_STAT, channel,
		    cs_p->value | txcs.value);
		break;

	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_control_status"
		    " Invalid Input: control <0x%x>", op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

hpi_status_t
hpi_txdma_event_mask(hpi_handle_t handle, io_op_t op_mode, uint8_t channel,
    tdc_int_mask_t *mask_p)
{
	int		status = HPI_SUCCESS;
	tdc_int_mask_t	mask;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_event_mask Invalid Input: channel <0x%x>",
		    channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TDC_INT_MASK, channel, &mask_p->value);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TDC_INT_MASK, channel, mask_p->value);
		break;

	case OP_UPDATE:
		TXDMA_REG_READ64(handle, TDC_INT_MASK, channel, &mask.value);
		TXDMA_REG_WRITE64(handle, TDC_INT_MASK, channel,
		    mask_p->value | mask.value);
		break;

	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_event_mask Invalid Input: eventmask <0x%x>",
		    op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

hpi_status_t
hpi_txdma_ring_config(hpi_handle_t handle, io_op_t op_mode,
    uint8_t channel, uint64_t *reg_data)
{
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_ring_config"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, reg_data);
		break;

	case OP_SET:
		TXDMA_REG_WRITE64(handle, TDC_TDR_CFG, channel, *reg_data);
		break;

	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_ring_config"
		    " Invalid Input: ring_config <0x%x>", op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

hpi_status_t
hpi_txdma_mbox_config(hpi_handle_t handle, io_op_t op_mode,
    uint8_t channel, uint64_t *mbox_addr)
{
	int		status = HPI_SUCCESS;
	tdc_mbh_t	mh;
	tdc_mbl_t	ml;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_mbox_config Invalid Input: channel <0x%x>",
		    channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}

	mh.value = ml.value = 0;

	switch (op_mode) {
	case OP_GET:
		TXDMA_REG_READ64(handle, TDC_MBH, channel, &mh.value);
		TXDMA_REG_READ64(handle, TDC_MBL, channel, &ml.value);
		*mbox_addr = ml.value;
		*mbox_addr |= (mh.value << TDC_MBH_ADDR_SHIFT);

		break;

	case OP_SET:
		ml.bits.mbaddr = ((*mbox_addr & TDC_MBL_MASK) >> TDC_MBL_SHIFT);
		TXDMA_REG_WRITE64(handle, TDC_MBL, channel, ml.value);
		mh.bits.mbaddr = ((*mbox_addr >> TDC_MBH_ADDR_SHIFT) &
		    TDC_MBH_MASK);
		TXDMA_REG_WRITE64(handle, TDC_MBH, channel, mh.value);
		break;

	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_mbox_config Invalid Input: mbox <0x%x>",
		    op_mode));
		return (HPI_FAILURE | HPI_TXDMA_OPCODE_INVALID(channel));
	}

	return (status);
}

/*
 * This function is called to set up a transmit descriptor entry.
 */
hpi_status_t
hpi_txdma_desc_gather_set(hpi_handle_t handle, p_tx_desc_t desc_p,
    uint8_t gather_index, boolean_t mark, uint8_t ngathers,
    uint64_t dma_ioaddr, uint32_t transfer_len)
{
	int status;

	status = HPI_TXDMA_GATHER_INDEX(gather_index);
	if (status) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_desc_gather_set"
		    " Invalid Input: gather_index <0x%x>", gather_index));
		return (status);
	}
	if (transfer_len > TX_MAX_TRANSFER_LENGTH) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_desc_gather_set"
		    " Invalid Input: tr_len <0x%x>", transfer_len));
		return (HPI_FAILURE | HPI_TXDMA_XFER_LEN_INVALID);
	}
	if (gather_index == 0) {
		desc_p->bits.sop = 1;
		desc_p->bits.mark = mark;
		desc_p->bits.num_ptr = ngathers;
		HPI_DEBUG_MSG((handle.function, HPI_TDC_CTL,
		    "hpi_txdma_gather_set: SOP len %d (%d)",
		    desc_p->bits.tr_len, transfer_len));
	}
	desc_p->bits.tr_len = transfer_len;
	desc_p->bits.sad = dma_ioaddr >> 32;
	desc_p->bits.sad_l = dma_ioaddr & 0xffffffff;

	HPI_DEBUG_MSG((handle.function, HPI_TDC_CTL,
	    "hpi_txdma_gather_set: xfer len %d to set (%d)",
	    desc_p->bits.tr_len, transfer_len));

	HXGE_MEM_PIO_WRITE64(handle, desc_p->value);

	return (status);
}

hpi_status_t
hpi_txdma_desc_set_zero(hpi_handle_t handle, uint16_t entries)
{
	uint32_t	offset;
	int		i;

	/*
	 * Assume no wrapped around.
	 */
	offset = 0;
	for (i = 0; i < entries; i++) {
		HXGE_REG_WR64(handle, offset, 0);
		offset += (i * (sizeof (tx_desc_t)));
	}

	return (HPI_SUCCESS);
}

/*
 * This function is called to get the transmit ring head index.
 */
hpi_status_t
hpi_txdma_ring_head_get(hpi_handle_t handle, uint8_t channel,
    tdc_tdr_head_t *hdl_p)
{
	int status = HPI_SUCCESS;

	if (!TXDMA_CHANNEL_VALID(channel)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_txdma_ring_head_get"
		    " Invalid Input: channel <0x%x>", channel));
		return (HPI_FAILURE | HPI_TXDMA_CHANNEL_INVALID(channel));
	}
	TXDMA_REG_READ64(handle, TDC_TDR_HEAD, channel, &hdl_p->value);

	return (status);
}

/*
 * Dumps the contents of transmit descriptors.
 */
/*ARGSUSED*/
void
hpi_txdma_dump_desc_one(hpi_handle_t handle, p_tx_desc_t desc_p, int desc_index)
{
	tx_desc_t desc, *desp;

#ifdef HXGE_DEBUG
	uint64_t sad;
	int xfer_len;
#endif

	HPI_DEBUG_MSG((handle.function, HPI_TDC_CTL,
	    "\n==> hpi_txdma_dump_desc_one: dump "
	    " desc_p $%p descriptor entry %d\n", desc_p, desc_index));
	desc.value = 0;
	desp = ((desc_p != NULL) ? desc_p : (p_tx_desc_t)&desc);
	HXGE_MEM_PIO_READ64(handle, &desp->value);
#ifdef HXGE_DEBUG
	sad = desp->bits.sad;
	sad = (sad << 32) | desp->bits.sad_l;
	xfer_len = desp->bits.tr_len;
#endif
	HPI_DEBUG_MSG((handle.function, HPI_TDC_CTL, "\n\t: value 0x%llx\n"
	    "\t\tsad $%p\ttr_len %d len %d\tnptrs %d\tmark %d sop %d\n",
	    desp->value, sad, desp->bits.tr_len, xfer_len,
	    desp->bits.num_ptr, desp->bits.mark, desp->bits.sop));

	HPI_DEBUG_MSG((handle.function, HPI_TDC_CTL,
	    "\n<== hpi_txdma_dump_desc_one: Done \n"));
}

/*
 * Static functions start here.
 */
static hpi_status_t
hpi_txdma_control_reset_wait(hpi_handle_t handle, uint8_t channel)
{
	tdc_tdr_cfg_t txcs;
	int loop = 0;

	txcs.value = 0;
	do {
		HXGE_DELAY(TXDMA_WAIT_MSEC);
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &txcs.value);

		/*
		 * Reset completes when this bit is set to 1 by hw
		 */
		if (txcs.bits.qst) {
			return (HPI_SUCCESS);
		}
		loop++;
	} while (loop < TXDMA_WAIT_LOOP);

	if (loop == TXDMA_WAIT_LOOP) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "hpi_txdma_control_reset_wait: RST bit not "
		    "cleared to 0 txcs.bits 0x%llx", txcs.value));
		return (HPI_FAILURE | HPI_TXDMA_RESET_FAILED);
	}
	return (HPI_SUCCESS);
}

hpi_status_t
hpi_txdma_control_stop_wait(hpi_handle_t handle, uint8_t channel)
{
	tdc_tdr_cfg_t	txcs;
	int		loop = 0;

	do {
		txcs.value = 0;
		HXGE_DELAY(TXDMA_WAIT_MSEC);
		TXDMA_REG_READ64(handle, TDC_TDR_CFG, channel, &txcs.value);
		if (txcs.bits.qst) {
			return (HPI_SUCCESS);
		}
		loop++;
	} while (loop < TXDMA_WAIT_LOOP);

	if (loop == TXDMA_WAIT_LOOP) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    "hpi_txdma_control_stop_wait: SNG_STATE not "
		    "set to 1 txcs.bits 0x%llx", txcs.value));
		return (HPI_FAILURE | HPI_TXDMA_STOP_FAILED);
	}
	return (HPI_SUCCESS);
}
