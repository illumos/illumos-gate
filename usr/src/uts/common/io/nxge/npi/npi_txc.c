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

#include <npi_txc.h>

/*
 * Transmit Controller (TXC) Functions.
 */

uint64_t txc_fzc_dmc_offset[] = {
	TXC_DMA_MAX_BURST_REG,
	TXC_DMA_MAX_LENGTH_REG
};

const char *txc_fzc_dmc_name[] = {
	"TXC_DMA_MAX_BURST_REG",
	"TXC_DMA_MAX_LENGTH_REG"
};

uint64_t txc_fzc_offset [] = {
	TXC_CONTROL_REG,
	TXC_TRAINING_REG,
	TXC_DEBUG_SELECT_REG,
	TXC_MAX_REORDER_REG,
	TXC_INT_STAT_DBG_REG,
	TXC_INT_STAT_REG,
	TXC_INT_MASK_REG
};

const char *txc_fzc_name [] = {
	"TXC_CONTROL_REG",
	"TXC_TRAINING_REG",
	"TXC_DEBUG_SELECT_REG",
	"TXC_MAX_REORDER_REG",
	"TXC_INT_STAT_DBG_REG",
	"TXC_INT_STAT_REG",
	"TXC_INT_MASK_REG"
};

uint64_t txc_fzc_port_offset[] = {
	TXC_PORT_CTL_REG,
	TXC_PORT_DMA_ENABLE_REG,
	TXC_PKT_STUFFED_REG,
	TXC_PKT_XMIT_REG,
	TXC_ROECC_CTL_REG,
	TXC_ROECC_ST_REG,
	TXC_RO_DATA0_REG,
	TXC_RO_DATA1_REG,
	TXC_RO_DATA2_REG,
	TXC_RO_DATA3_REG,
	TXC_RO_DATA4_REG,
	TXC_SFECC_CTL_REG,
	TXC_SFECC_ST_REG,
	TXC_SF_DATA0_REG,
	TXC_SF_DATA1_REG,
	TXC_SF_DATA2_REG,
	TXC_SF_DATA3_REG,
	TXC_SF_DATA4_REG,
	TXC_RO_TIDS_REG,
	TXC_RO_STATE0_REG,
	TXC_RO_STATE1_REG,
	TXC_RO_STATE2_REG,
	TXC_RO_STATE3_REG,
	TXC_RO_CTL_REG,
	TXC_RO_ST_DATA0_REG,
	TXC_RO_ST_DATA1_REG,
	TXC_RO_ST_DATA2_REG,
	TXC_RO_ST_DATA3_REG,
	TXC_PORT_PACKET_REQ_REG
};

const char *txc_fzc_port_name[] = {
	"TXC_PORT_CTL_REG",
	"TXC_PORT_DMA_ENABLE_REG",
	"TXC_PKT_STUFFED_REG",
	"TXC_PKT_XMIT_REG",
	"TXC_ROECC_CTL_REG",
	"TXC_ROECC_ST_REG",
	"TXC_RO_DATA0_REG",
	"TXC_RO_DATA1_REG",
	"TXC_RO_DATA2_REG",
	"TXC_RO_DATA3_REG",
	"TXC_RO_DATA4_REG",
	"TXC_SFECC_CTL_REG",
	"TXC_SFECC_ST_REG",
	"TXC_SF_DATA0_REG",
	"TXC_SF_DATA1_REG",
	"TXC_SF_DATA2_REG",
	"TXC_SF_DATA3_REG",
	"TXC_SF_DATA4_REG",
	"TXC_RO_TIDS_REG",
	"TXC_RO_STATE0_REG",
	"TXC_RO_STATE1_REG",
	"TXC_RO_STATE2_REG",
	"TXC_RO_STATE3_REG",
	"TXC_RO_CTL_REG",
	"TXC_RO_ST_DATA0_REG",
	"TXC_RO_ST_DATA1_REG",
	"TXC_RO_ST_DATA2_REG",
	"TXC_RO_ST_DATA3_REG",
	"TXC_PORT_PACKET_REQ_REG"
};

/*
 * npi_txc_dump_tdc_fzc_regs
 * Dumps the contents of TXC csrs and fzc registers
 *
 * Input:
 *	handle		- NPI handle
 *         tdc:      TX DMA number
 *
 * return:
 *     NPI_SUCCESS
 *     NPI_FAILURE
 *     NPI_TXC_CHANNEL_INVALID
 *
 */
npi_status_t
npi_txc_dump_tdc_fzc_regs(npi_handle_t handle, uint8_t tdc)
{
	uint64_t		value, offset;
	int 			num_regs, i;

	ASSERT(TXDMA_CHANNEL_VALID(tdc));
	if (!TXDMA_CHANNEL_VALID(tdc)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    "npi_txc_dump_tdc_fzc_regs"
		    " Invalid TDC number %d \n",
		    tdc));
		return (NPI_FAILURE | NPI_TXC_CHANNEL_INVALID(tdc));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nTXC FZC DMC Register Dump for Channel %d\n",
	    tdc));

	num_regs = sizeof (txc_fzc_dmc_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		offset = TXC_FZC_REG_CN_OFFSET(txc_fzc_dmc_offset[i], tdc);
		NXGE_REG_RD64(handle, offset, &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%08llx \n",
		    offset, txc_fzc_dmc_name[i], value));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n TXC FZC Register Dump for Channel %d done\n", tdc));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_dump_fzc_regs
 * Dumps the contents of txc csrs and fzc registers
 *
 *
 * return:
 *     NPI_SUCCESS
 *     NPI_FAILURE
 *
 */
npi_status_t
npi_txc_dump_fzc_regs(npi_handle_t handle)
{

	uint64_t value;
	int num_regs, i;

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nTXC FZC Common Register Dump\n"));

	num_regs = sizeof (txc_fzc_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		NXGE_REG_RD64(handle, txc_fzc_offset[i], &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%08llx \n",
		    txc_fzc_offset[i], txc_fzc_name[i], value));
	}
	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n TXC FZC Common Register Dump Done \n"));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_dump_port_fzc_regs
 * Dumps the contents of TXC csrs and fzc registers
 *
 * Input:
 *	handle		- NPI handle
 *         port:      port number
 *
 * return:
 *     NPI_SUCCESS
 *     NPI_FAILURE
 *
 */
npi_status_t
npi_txc_dump_port_fzc_regs(npi_handle_t handle, uint8_t port)
{
	uint64_t		value, offset;
	int 			num_regs, i;

	ASSERT(IS_PORT_NUM_VALID(port));

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\nTXC FZC PORT Register Dump for port %d\n", port));

	num_regs = sizeof (txc_fzc_port_offset) / sizeof (uint64_t);
	for (i = 0; i < num_regs; i++) {
		offset = TXC_FZC_REG_PT_OFFSET(txc_fzc_port_offset[i], port);
		NXGE_REG_RD64(handle, offset, &value);
		NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL, "0x%08llx "
		    "%s\t 0x%08llx \n",
		    offset, txc_fzc_port_name[i], value));
	}

	NPI_REG_DUMP_MSG((handle.function, NPI_REG_CTL,
	    "\n TXC FZC Register Dump for port %d done\n", port));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_dma_max_burst():
 *	This function is called to configure the max burst bytes.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get max burst value
 *			- OP_SET: set max burst value
 *	channel		- channel number (0 - 23)
 *	dma_max_burst_p - pointer to store or used for max burst value.
 * Return:
 *	NPI_SUCCESS	- If operation is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXC_OPCODE_INVALID
 *		NPI_TXC_CHANNEL_INVALID
 */
npi_status_t
npi_txc_dma_max_burst(npi_handle_t handle, io_op_t op_mode, uint8_t channel,
		uint32_t *dma_max_burst_p)
{
	uint64_t val;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txc_dma_max_burst"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXC_CHANNEL_INVALID(channel));
	}

	switch (op_mode) {
	case OP_GET:
		TXC_FZC_REG_READ64(handle, TXC_DMA_MAX_BURST_REG, channel,
		    &val);
		*dma_max_burst_p = (uint32_t)val;
		break;

	case OP_SET:
		TXC_FZC_REG_WRITE64(handle,
		    TXC_DMA_MAX_BURST_REG, channel, *dma_max_burst_p);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txc_dma_max_burst"
		    " Invalid Input: burst <0x%x>",
		    op_mode));
		return (NPI_FAILURE | NPI_TXC_OPCODE_INVALID(channel));
	}

	return (NPI_SUCCESS);
}

/*
 * npi_txc_dma_max_burst_set():
 *	This function is called to set the max burst bytes.
 *
 * Parameters:
 *	handle		- NPI handle
 *	channel		- channel number (0 - 23)
 *	max_burst 	- max burst to set
 * Return:
 *	NPI_SUCCESS	- If operation is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 */
npi_status_t
npi_txc_dma_max_burst_set(npi_handle_t handle, uint8_t channel,
		uint32_t max_burst)
{
	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txc_dma_max_burst_set"
		    " Invalid Input: channel <0x%x>",
		    channel));
		return (NPI_FAILURE | NPI_TXC_CHANNEL_INVALID(channel));
	}

	TXC_FZC_REG_WRITE64(handle, TXC_DMA_MAX_BURST_REG,
	    channel, (uint64_t)max_burst);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_dma_bytes_transmitted():
 *	This function is called to get # of bytes transmitted by
 *	DMA (hardware register is cleared on read).
 *
 * Parameters:
 *	handle		- NPI handle
 *	channel		- channel number (0 - 23)
 *	dma_bytes_p 	- pointer to store bytes transmitted.
 * Return:
 *	NPI_SUCCESS	- If get is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXC_PORT_INVALID
 */
npi_status_t
npi_txc_dma_bytes_transmitted(npi_handle_t handle, uint8_t channel,
		uint32_t *dma_bytes_p)
{
	uint64_t val;

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txc_dma_bytes_transmitted"
		    " Invalid Input: channel %d",
		    channel));
		return (NPI_FAILURE | NPI_TXC_CHANNEL_INVALID(channel));
	}

	TXC_FZC_REG_READ64(handle, TXC_DMA_MAX_LENGTH_REG, channel, &val);
	*dma_bytes_p = (uint32_t)val;

	return (NPI_SUCCESS);
}

/*
 * npi_txc_control():
 *	This function is called to get or set the control register.
 *
 * Parameters:
 *	handle		- NPI handle
 *	op_mode		- OP_GET: get control register value
 *			  OP_SET: set control register value
 *	txc_control_p	- pointer to hardware defined data structure.
 * Return:
 *	NPI_SUCCESS	- If operation is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXC_OPCODE_INVALID
 *		NPI_TXC_PORT_INVALID
 */
npi_status_t
npi_txc_control(npi_handle_t handle, io_op_t op_mode,
		p_txc_control_t txc_control_p)
{
	switch (op_mode) {
	case OP_GET:
		NXGE_REG_RD64(handle, TXC_CONTROL_REG, &txc_control_p->value);
		break;

	case OP_SET:
		NXGE_REG_WR64(handle, TXC_CONTROL_REG,
		    txc_control_p->value);
		break;

	default:
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txc_control"
		    " Invalid Input:  control 0x%x",
		    op_mode));
		return (NPI_FAILURE | NPI_TXC_OPCODE_INVALID(op_mode));
	}

	return (NPI_SUCCESS);
}

/*
 * npi_txc_global_enable():
 *	This function is called to globally enable TXC.
 *
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	- If enable is complete successfully.
 *
 *	Error:
 */
npi_status_t
npi_txc_global_enable(npi_handle_t handle)
{
	txc_control_t	cntl;
	uint64_t	val;

	cntl.value = 0;
	cntl.bits.ldw.txc_enabled = 1;

	NXGE_REG_RD64(handle, TXC_CONTROL_REG, &val);
	NXGE_REG_WR64(handle, TXC_CONTROL_REG, val | cntl.value);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_global_disable():
 *	This function is called to globally disable TXC.
 *
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	- If disable is complete successfully.
 *
 *	Error:
 */
npi_status_t
npi_txc_global_disable(npi_handle_t handle)
{
	txc_control_t	cntl;
	uint64_t	val;


	cntl.value = 0;
	cntl.bits.ldw.txc_enabled = 0;

	NXGE_REG_RD64(handle, TXC_CONTROL_REG, &val);
	NXGE_REG_WR64(handle, TXC_CONTROL_REG, val | cntl.value);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_control_clear():
 *	This function is called to clear all bits.
 *
 * Parameters:
 *	handle		- NPI handle
 * Return:
 *	NPI_SUCCESS	- If reset all bits to 0s is complete successfully.
 *
 *	Error:
 */
npi_status_t
npi_txc_control_clear(npi_handle_t handle, uint8_t port)
{
	ASSERT(IS_PORT_NUM_VALID(port));

	NXGE_REG_WR64(handle, TXC_PORT_CTL_REG, TXC_PORT_CNTL_CLEAR);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_training_set():
 *	This function is called to set the debug training vector.
 *
 * Parameters:
 *	handle			- NPI handle
 *	vector			- training vector to set.
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE		-
 */
npi_status_t
npi_txc_training_set(npi_handle_t handle, uint32_t vector)
{
	NXGE_REG_WR64(handle, TXC_TRAINING_REG, (uint64_t)vector);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_training_get():
 *	This function is called to get the debug training vector.
 *
 * Parameters:
 *	handle			- NPI handle
 *	vector_p		- pointer to store training vector.
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE		-
 */
npi_status_t
npi_txc_training_get(npi_handle_t handle, uint32_t *vector_p)
{
	uint64_t val;

	NXGE_REG_RD64(handle, (TXC_TRAINING_REG & TXC_TRAINING_VECTOR_MASK),
	    &val);
	*vector_p = (uint32_t)val;

	return (NPI_SUCCESS);
}

/*
 * npi_txc_port_enable():
 *	This function is called to enable a particular port.
 *
 * Parameters:
 *	handle		- NPI handle
 *	port		- port number (0 - 3)
 * Return:
 *	NPI_SUCCESS	- If port is enabled successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXC_PORT_INVALID
 */
npi_status_t
npi_txc_port_enable(npi_handle_t handle, uint8_t port)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(port));

	NXGE_REG_RD64(handle, TXC_CONTROL_REG, &val);
	NXGE_REG_WR64(handle, TXC_CONTROL_REG, val | (1 << port));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_port_disable():
 *	This function is called to disable a particular port.
 *
 * Parameters:
 *	handle		- NPI handle
 *	port		- port number (0 - 3)
 * Return:
 *	NPI_SUCCESS	- If port is disabled successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXC_PORT_INVALID
 */
npi_status_t
npi_txc_port_disable(npi_handle_t handle, uint8_t port)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(port));

	NXGE_REG_RD64(handle, TXC_CONTROL_REG, &val);
	NXGE_REG_WR64(handle, TXC_CONTROL_REG, (val & ~(1 << port)));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_port_dma_enable():
 *	This function is called to bind DMA channels (bitmap) to a port.
 *
 * Parameters:
 *	handle			- NPI handle
 *	port			- port number (0 - 3)
 *	port_dma_list_bitmap	- channels bitmap
 *				(1 to bind, 0 - 23 bits one bit/channel)
 * Return:
 *	NPI_SUCCESS		- If channels are bound successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXC_PORT_INVALID
 */
npi_status_t
npi_txc_port_dma_enable(npi_handle_t handle, uint8_t port,
		uint32_t port_dma_list_bitmap)
{

	ASSERT(IS_PORT_NUM_VALID(port));

	TXC_FZC_CNTL_REG_WRITE64(handle, TXC_PORT_DMA_ENABLE_REG, port,
	    port_dma_list_bitmap);
	return (NPI_SUCCESS);
}

npi_status_t
npi_txc_port_dma_list_get(npi_handle_t handle, uint8_t port,
		uint32_t *port_dma_list_bitmap)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(port));

	TXC_FZC_CNTL_REG_READ64(handle, TXC_PORT_DMA_ENABLE_REG, port, &val);
	*port_dma_list_bitmap = (uint32_t)(val & TXC_DMA_DMA_LIST_MASK);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_port_dma_channel_enable():
 *	This function is called to bind a channel to a port.
 *
 * Parameters:
 *	handle			- NPI handle
 *	port			- port number (0 - 3)
 *	channel			- channel number (0 - 23)
 * Return:
 *	NPI_SUCCESS		- If channel is bound successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXC_PORT_INVALID	-
 */
npi_status_t
npi_txc_port_dma_channel_enable(npi_handle_t handle, uint8_t port,
		uint8_t channel)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(port));

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txc_port_dma_channel_enable"
		    " Invalid Input: channel <0x%x>", channel));
		return (NPI_FAILURE | NPI_TXC_CHANNEL_INVALID(channel));
	}

	TXC_FZC_CNTL_REG_READ64(handle, TXC_PORT_DMA_ENABLE_REG, port, &val);
	TXC_FZC_CNTL_REG_WRITE64(handle, TXC_PORT_DMA_ENABLE_REG, port,
	    (val | (1 << channel)));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_port_dma_channel_disable():
 *	This function is called to unbind a channel to a port.
 *
 * Parameters:
 *	handle			- NPI handle
 *	port			- port number (0 - 3)
 *	channel			- channel number (0 - 23)
 * Return:
 *	NPI_SUCCESS		- If channel is unbound successfully.
 *
 *	Error:
 *	NPI_FAILURE		-
 *		NPI_TXC_PORT_INVALID	-
 */
npi_status_t
npi_txc_port_dma_channel_disable(npi_handle_t handle, uint8_t port,
		uint8_t channel)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(port));

	ASSERT(TXDMA_CHANNEL_VALID(channel));
	if (!TXDMA_CHANNEL_VALID(channel)) {
		NPI_ERROR_MSG((handle.function, NPI_ERR_CTL,
		    " npi_txc_port_dma_channel_disable"
		    " Invalid Input: channel <0x%x>", channel));
		return (NPI_FAILURE | NPI_TXC_CHANNEL_INVALID(channel));
	}

	TXC_FZC_CNTL_REG_READ64(handle, TXC_PORT_DMA_ENABLE_REG, port, &val)
	TXC_FZC_CNTL_REG_WRITE64(handle, TXC_PORT_DMA_ENABLE_REG, port,
	    val & ~(1 << channel));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_max_reorder_set():
 *	This function is called to set the per port reorder resources
 *
 * Parameters:
 *	handle			- NPI handle
 *	port			- port to set
 *	reorder			- reorder resources (4 bits)
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE		-
 */
npi_status_t
npi_txc_reorder_set(npi_handle_t handle, uint8_t port, uint8_t *reorder)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(port));

	NXGE_REG_RD64(handle, TXC_MAX_REORDER_REG, &val);

	val |= (*reorder << TXC_MAX_REORDER_SHIFT(port));

	NXGE_REG_WR64(handle, TXC_MAX_REORDER_REG, val);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_reorder_get():
 *	This function is called to get the txc reorder resources.
 *
 * Parameters:
 *	handle			- NPI handle
 *	port			- port to get
 *	reorder			- data to be stored at
 * Return:
 *	NPI_SUCCESS
 *
 *	Error:
 *	NPI_FAILURE		-
 */
npi_status_t
npi_txc_reorder_get(npi_handle_t handle, uint8_t port, uint32_t *reorder)
{
	uint64_t val;

	ASSERT(IS_PORT_NUM_VALID(port));

	NXGE_REG_RD64(handle, TXC_MAX_REORDER_REG, &val);

	*reorder = (uint8_t)(val >> TXC_MAX_REORDER_SHIFT(port));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_pkt_stuffed_get():
 *	This function is called to get total # of packets processed
 *	by reorder engine and packetAssy engine.
 *
 * Parameters:
 *	handle		- NPI handle
 *	port		- port number (0 - 3)
 *	pkt_assy_p 	- packets processed by Assy engine.
 *	pkt_reorder_p	- packets processed by reorder engine.
 *
 * Return:
 *	NPI_SUCCESS	- If get is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *		NPI_TXC_PORT_INVALID
 */
npi_status_t
npi_txc_pkt_stuffed_get(npi_handle_t handle, uint8_t port,
		uint32_t *pkt_assy_p, uint32_t *pkt_reorder_p)
{
	uint64_t		value;

	ASSERT(IS_PORT_NUM_VALID(port));

	TXC_FZC_CNTL_REG_READ64(handle, TXC_PKT_STUFFED_REG, port, &value);
	*pkt_assy_p = ((uint32_t)((value & TXC_PKT_STUFF_PKTASY_MASK) >>
	    TXC_PKT_STUFF_PKTASY_SHIFT));
	*pkt_reorder_p = ((uint32_t)((value & TXC_PKT_STUFF_REORDER_MASK) >>
	    TXC_PKT_STUFF_REORDER_SHIFT));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_pkt_xmt_to_mac_get():
 *	This function is called to get total # of packets transmitted
 *	to the MAC.
 *
 * Parameters:
 *	handle		- NPI handle
 *	port		- port number (0 - 3)
 *	mac_bytes_p 	- bytes transmitted to the MAC.
 *	mac_pkts_p	- packets transmitted to the MAC.
 *
 * Return:
 *	NPI_SUCCESS	- If get is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *	NPI_TXC_PORT_INVALID
 */
npi_status_t
npi_txc_pkt_xmt_to_mac_get(npi_handle_t handle, uint8_t port,
		uint32_t *mac_bytes_p, uint32_t *mac_pkts_p)
{
	uint64_t		value;

	ASSERT(IS_PORT_NUM_VALID(port));

	TXC_FZC_CNTL_REG_READ64(handle, TXC_PKT_XMIT_REG, port, &value);
	*mac_pkts_p = ((uint32_t)((value & TXC_PKTS_XMIT_MASK) >>
	    TXC_PKTS_XMIT_SHIFT));
	*mac_bytes_p = ((uint32_t)((value & TXC_BYTES_XMIT_MASK) >>
	    TXC_BYTES_XMIT_SHIFT));

	return (NPI_SUCCESS);
}

/*
 * npi_txc_get_ro_states():
 *	This function is called to get TXC's reorder state-machine states.
 *
 * Parameters:
 *	handle		- NPI handle
 *	port		- port number
 *	*states		- TXC Re-order states.
 *
 * Return:
 *	NPI_SUCCESS	- If get is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *	NPI_TXC_PORT_INVALID
 */
npi_status_t
npi_txc_ro_states_get(npi_handle_t handle, uint8_t port,
				txc_ro_states_t *states)
{
	txc_ro_ctl_t	ctl;
	txc_ro_tids_t	tids;
	txc_ro_state0_t	s0;
	txc_ro_state1_t	s1;
	txc_ro_state2_t	s2;
	txc_ro_state3_t	s3;
	txc_roecc_st_t	ecc;
	txc_ro_data0_t	d0;
	txc_ro_data1_t	d1;
	txc_ro_data2_t	d2;
	txc_ro_data3_t	d3;
	txc_ro_data4_t	d4;

	ASSERT(IS_PORT_NUM_VALID(port));

	TXC_FZC_CNTL_REG_READ64(handle, TXC_ROECC_ST_REG, port, &ecc.value);
	if ((ecc.bits.ldw.correct_error) || (ecc.bits.ldw.uncorrect_error)) {
		TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_DATA0_REG, port,
		    &d0.value);
		TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_DATA1_REG, port,
		    &d1.value);
		TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_DATA2_REG, port,
		    &d2.value);
		TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_DATA3_REG, port,
		    &d3.value);
		TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_DATA4_REG, port,
		    &d4.value);
		states->d0.value = d0.value;
		states->d1.value = d1.value;
		states->d2.value = d2.value;
		states->d3.value = d3.value;
		states->d4.value = d4.value;

		ecc.bits.ldw.ecc_address = 0;
		ecc.bits.ldw.correct_error = 0;
		ecc.bits.ldw.uncorrect_error = 0;
		ecc.bits.ldw.clr_st = 1;
		TXC_FZC_CNTL_REG_WRITE64(handle, TXC_ROECC_ST_REG, port,
		    ecc.value);
	}

	TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_CTL_REG, port, &ctl.value);
	TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_STATE0_REG, port, &s0.value);
	TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_STATE1_REG, port, &s1.value);
	TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_STATE2_REG, port, &s2.value);
	TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_STATE3_REG, port, &s3.value);
	TXC_FZC_CNTL_REG_READ64(handle, TXC_RO_TIDS_REG, port, &tids.value);

	states->roecc.value = ctl.value;
	states->st0.value = s0.value;
	states->st1.value = s1.value;
	states->st2.value = s2.value;
	states->st3.value = s3.value;
	states->ctl.value = ctl.value;
	states->tids.value = tids.value;

	ctl.bits.ldw.clr_fail_state = 1;
	TXC_FZC_CNTL_REG_WRITE64(handle, TXC_RO_CTL_REG, port, ctl.value);

	return (NPI_SUCCESS);
}

npi_status_t
npi_txc_ro_ecc_state_clr(npi_handle_t handle, uint8_t port)
{
	ASSERT(IS_PORT_NUM_VALID(port));

	TXC_FZC_CNTL_REG_WRITE64(handle, TXC_ROECC_ST_REG, port, 0);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_sf_states_get():
 *	This function is called to get TXC's store-forward state-machine states.
 *
 * Parameters:
 *	handle		- NPI handle
 *	port		- port number
 *	states		- TXC Store-forward states
 *
 * Return:
 *	NPI_SUCCESS	- If get is complete successfully.
 *
 *	Error:
 *	NPI_FAILURE	-
 *	NPI_TXC_PORT_INVALID
 */
#ifdef lint
/*ARGSUSED*/
#endif
npi_status_t
npi_txc_sf_states_get(npi_handle_t handle, uint8_t port,
				txc_sf_states_t *states)
{
	txc_sfecc_st_t	ecc;
	txc_sf_data0_t	d0;
	txc_sf_data1_t	d1;
	txc_sf_data2_t	d2;
	txc_sf_data3_t	d3;
	txc_sf_data4_t	d4;

	ASSERT(IS_PORT_NUM_VALID(port));

	TXC_FZC_CNTL_REG_READ64(handle, TXC_SFECC_ST_REG, port, &ecc.value);
	if ((ecc.bits.ldw.correct_error) || (ecc.bits.ldw.uncorrect_error)) {
		TXC_FZC_CNTL_REG_READ64(handle, TXC_SF_DATA0_REG, port,
		    &d0.value);
		TXC_FZC_CNTL_REG_READ64(handle, TXC_SF_DATA1_REG, port,
		    &d1.value);
		TXC_FZC_CNTL_REG_READ64(handle, TXC_SF_DATA2_REG, port,
		    &d2.value);
		TXC_FZC_CNTL_REG_READ64(handle, TXC_SF_DATA3_REG, port,
		    &d3.value);
		TXC_FZC_CNTL_REG_READ64(handle, TXC_SF_DATA4_REG, port,
		    &d4.value);
		ecc.bits.ldw.ecc_address = 0;
		ecc.bits.ldw.correct_error = 0;
		ecc.bits.ldw.uncorrect_error = 0;
		ecc.bits.ldw.clr_st = 1;
		TXC_FZC_CNTL_REG_WRITE64(handle, TXC_SFECC_ST_REG, port,
		    ecc.value);
	}

	states->sfecc.value = ecc.value;
	states->d0.value = d0.value;
	states->d1.value = d1.value;
	states->d2.value = d2.value;
	states->d3.value = d3.value;
	states->d4.value = d4.value;

	return (NPI_SUCCESS);
}

npi_status_t
npi_txc_sf_ecc_state_clr(npi_handle_t handle, uint8_t port)
{
	ASSERT(IS_PORT_NUM_VALID(port));

	TXC_FZC_CNTL_REG_WRITE64(handle, TXC_SFECC_ST_REG, port, 0);

	return (NPI_SUCCESS);
}

/*
 * npi_txc_global_istatus_get():
 *	This function is called to get TXC's global interrupt status.
 *
 * Parameters:
 *	handle		- NPI handle
 *	istatus		- TXC global interrupt status
 *
 * Return:
 */
void
npi_txc_global_istatus_get(npi_handle_t handle, txc_int_stat_t *istatus)
{
	txc_int_stat_t	status;

	NXGE_REG_RD64(handle, TXC_INT_STAT_REG, &status.value);

	istatus->value = status.value;
}

/*
 * npi_txc_global_istatus_clear():
 *	This function is called to clear TXC's global interrupt status.
 *
 * Parameters:
 *	handle		- NPI handle
 *	istatus		- TXC global interrupt status
 *
 * Return:
 */
void
npi_txc_global_istatus_clear(npi_handle_t handle, uint64_t istatus)
{
	NXGE_REG_WR64(handle, TXC_INT_STAT_REG, istatus);
}

void
npi_txc_global_imask_set(npi_handle_t handle, uint8_t portn, uint8_t istatus)
{
	uint64_t val;

	NXGE_REG_RD64(handle, TXC_INT_MASK_REG, &val);
	switch (portn) {
	case 0:
		val &= 0xFFFFFF00;
		val |= istatus & 0x3F;
		break;
	case 1:
		val &= 0xFFFF00FF;
		val |= (istatus << 8) & 0x3F00;
		break;
	case 2:
		val &= 0xFF00FFFF;
		val |= (istatus << 16) & 0x3F0000;
		break;
	case 3:
		val &= 0x00FFFFFF;
		val |= (istatus << 24) & 0x3F000000;
		break;
	default:
		;
	}
	NXGE_REG_WR64(handle, TXC_INT_MASK_REG, val);
}
