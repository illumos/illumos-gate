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

#include <hxge_impl.h>
#include <hpi_vmac.h>

#define	HXGE_VMAC_RX_STAT_CLEAR		0x1ffULL
#define	HXGE_VMAC_TX_STAT_CLEAR		0x7ULL
#define	HXGE_VMAC_RX_MASK_OVERFLOW	0x1fe
#define	HXGE_VMAC_RX_MASK_FRAME		0x1

hpi_status_t
hpi_tx_vmac_reset(hpi_handle_t handle)
{
	vmac_rst_t	reset;

	HXGE_REG_RD64(handle, VMAC_RST, &(reset.value));

	reset.bits.tx_reset = 1;

	HXGE_REG_WR64(handle, VMAC_RST, reset.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_rx_vmac_reset(hpi_handle_t handle)
{
	vmac_rst_t	reset;

	HXGE_REG_RD64(handle, VMAC_RST, &(reset.value));

	reset.bits.rx_reset = 1;

	HXGE_REG_WR64(handle, VMAC_RST, reset.value);

	return (HPI_SUCCESS);
}


hpi_status_t
hpi_vmac_tx_config(hpi_handle_t handle, config_op_t op, uint64_t config,
    uint16_t max_frame_length)
{
	vmac_tx_cfg_t	cfg;

	if (config == 0) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_vmac_tx_config Invalid Input: config <0x%x>",
		    config));
		return (HPI_FAILURE);
	}

	HXGE_REG_RD64(handle, VMAC_TX_CFG, &cfg.value);

	switch (op) {
	case ENABLE:
		if (config & CFG_VMAC_TX_EN)
			cfg.bits.tx_en = 1;
		if (config & CFG_VMAC_TX_CRC_INSERT)
			cfg.bits.crc_insert = 1;
		if (config & CFG_VMAC_TX_PAD)
			cfg.bits.tx_pad = 1;
		if (max_frame_length)
			cfg.bits.tx_max_frame_length = max_frame_length;
		break;
	case DISABLE:
		if (config & CFG_VMAC_TX_EN)
			cfg.bits.tx_en = 0;
		if (config & CFG_VMAC_TX_CRC_INSERT)
			cfg.bits.crc_insert = 0;
		if (config & CFG_VMAC_TX_PAD)
			cfg.bits.tx_pad = 0;
		break;
	case INIT:
		if (config & CFG_VMAC_TX_EN)
			cfg.bits.tx_en = 1;
		else
			cfg.bits.tx_en = 0;

		if (config & CFG_VMAC_TX_CRC_INSERT)
			cfg.bits.crc_insert = 1;
		else
			cfg.bits.crc_insert = 0;

		if (config & CFG_VMAC_TX_PAD)
			cfg.bits.tx_pad = 1;
		else
			cfg.bits.tx_pad = 0;

		if (max_frame_length)
			cfg.bits.tx_max_frame_length = max_frame_length;

		break;
	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_vmac_tx_config Invalid Input: op <0x%x>", op));
		return (HPI_FAILURE);
	}

	HXGE_REG_WR64(handle, VMAC_TX_CFG, cfg.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_vmac_rx_set_framesize(hpi_handle_t handle, uint16_t max_frame_length)
{
	vmac_rx_cfg_t	cfg;
	uint16_t fsize;

	HXGE_REG_RD64(handle, VMAC_RX_CFG, &cfg.value);

	/*
	 * HW team not sure setting framesize to 0 is problematic
	 * or not.
	 */
	if (max_frame_length == 0)
		fsize = 1;
	else
		fsize = max_frame_length;

	cfg.bits.rx_max_frame_length = fsize;

	HXGE_REG_WR64(handle, VMAC_RX_CFG, cfg.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_vmac_rx_config(hpi_handle_t handle, config_op_t op, uint64_t config,
    uint16_t max_frame_length)
{
	vmac_rx_cfg_t cfg;

	if (config == 0) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_vmac_rx_config Invalid Input: config <0x%x>",
		    config));
		return (HPI_FAILURE);
	}

	HXGE_REG_RD64(handle, VMAC_RX_CFG, &cfg.value);

	switch (op) {
	case ENABLE:
		if (config & CFG_VMAC_RX_EN)
			cfg.bits.rx_en = 1;
		if (config & CFG_VMAC_RX_CRC_CHECK_DISABLE)
			cfg.bits.crc_check_disable = 1;
		if (config & CFG_VMAC_RX_STRIP_CRC)
			cfg.bits.strip_crc = 1;
		if (config & CFG_VMAC_RX_PASS_FLOW_CTRL_FR)
			cfg.bits.pass_flow_ctrl_fr = 1;
		if (config & CFG_VMAC_RX_PROMIXCUOUS_GROUP)
			cfg.bits.promiscuous_group = 1;
		if (config & CFG_VMAC_RX_PROMISCUOUS_MODE)
			cfg.bits.promiscuous_mode = 1;
		if (config & CFG_VMAC_RX_LOOP_BACK)
			cfg.bits.loopback = 1;
		break;
	case DISABLE:
		if (config & CFG_VMAC_RX_EN)
			cfg.bits.rx_en = 0;
		if (config & CFG_VMAC_RX_CRC_CHECK_DISABLE)
			cfg.bits.crc_check_disable = 0;
		if (config & CFG_VMAC_RX_STRIP_CRC)
			cfg.bits.strip_crc = 0;
		if (config & CFG_VMAC_RX_PASS_FLOW_CTRL_FR)
			cfg.bits.pass_flow_ctrl_fr = 0;
		if (config & CFG_VMAC_RX_PROMIXCUOUS_GROUP)
			cfg.bits.promiscuous_group = 0;
		if (config & CFG_VMAC_RX_PROMISCUOUS_MODE)
			cfg.bits.promiscuous_mode = 0;
		if (config & CFG_VMAC_RX_LOOP_BACK)
			cfg.bits.loopback = 0;
		break;
	case INIT:
		if (config & CFG_VMAC_RX_EN)
			cfg.bits.rx_en = 1;
		else
			cfg.bits.rx_en = 0;
		if (config & CFG_VMAC_RX_CRC_CHECK_DISABLE)
			cfg.bits.crc_check_disable = 1;
		else
			cfg.bits.crc_check_disable = 0;
		if (config & CFG_VMAC_RX_STRIP_CRC)
			cfg.bits.strip_crc = 1;
		else
			cfg.bits.strip_crc = 0;
		if (config & CFG_VMAC_RX_PASS_FLOW_CTRL_FR)
			cfg.bits.pass_flow_ctrl_fr = 1;
		else
			cfg.bits.pass_flow_ctrl_fr = 0;
		if (config & CFG_VMAC_RX_PROMIXCUOUS_GROUP)
			cfg.bits.promiscuous_group = 1;
		else
			cfg.bits.promiscuous_group = 0;
		if (config & CFG_VMAC_RX_PROMISCUOUS_MODE)
			cfg.bits.promiscuous_mode = 1;
		else
			cfg.bits.promiscuous_mode = 0;
		if (config & CFG_VMAC_RX_LOOP_BACK)
			cfg.bits.loopback = 1;
		else
			cfg.bits.loopback = 0;

		break;
	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_vmac_rx_config Invalid Input: op <0x%x>", op));
		return (HPI_FAILURE);
	}

	if (max_frame_length)
		cfg.bits.rx_max_frame_length = max_frame_length;

	HXGE_REG_WR64(handle, VMAC_RX_CFG, cfg.value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_vmac_clear_rx_int_stat(hpi_handle_t handle)
{
	uint64_t offset;

	offset = VMAC_RX_STAT;
	REG_PIO_WRITE64(handle, offset, HXGE_VMAC_RX_STAT_CLEAR);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_vmac_clear_tx_int_stat(hpi_handle_t handle)
{
	uint64_t offset;

	offset = VMAC_TX_STAT;
	REG_PIO_WRITE64(handle, offset, HXGE_VMAC_TX_STAT_CLEAR);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_rx_int_stat_mask(hpi_handle_t handle, boolean_t overflow_cnt,
    boolean_t frame_cnt)
{
	uint64_t	offset;
	uint64_t	value = 0;

	if (overflow_cnt)
		value |= HXGE_VMAC_RX_MASK_OVERFLOW;

	if (frame_cnt)
		value |= HXGE_VMAC_RX_MASK_FRAME;

	offset = VMAC_RX_MSK;
	REG_PIO_WRITE64(handle, offset, value);

	return (HPI_SUCCESS);
}

hpi_status_t
hpi_pfc_set_tx_int_stat_mask(hpi_handle_t handle, boolean_t overflow_cnt,
    boolean_t frame_cnt)
{
	uint64_t	offset;
	uint64_t	value = 0;
	uint64_t	overflow_mask = 0x6;
	uint64_t	frame_mask = 0x1;

	if (overflow_cnt)
		value |= overflow_mask;

	if (frame_cnt)
		value |= frame_mask;

	offset = VMAC_TX_MSK;
	REG_PIO_WRITE64(handle, offset, value);

	return (HPI_SUCCESS);
}
