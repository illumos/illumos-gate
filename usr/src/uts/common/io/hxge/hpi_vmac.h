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

#ifndef _HPI_MAC_H
#define	_HPI_MAC_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <hpi.h>
#include <hxge_vmac_hw.h>

hpi_status_t hpi_tx_vmac_reset(hpi_handle_t handle);
hpi_status_t hpi_rx_vmac_reset(hpi_handle_t handle);
hpi_status_t hpi_vmac_tx_config(hpi_handle_t handle, config_op_t op,
    uint64_t config, uint16_t max_frame_length);
hpi_status_t hpi_vmac_rx_config(hpi_handle_t handle, config_op_t op,
    uint64_t config, uint16_t max_frame_length);
hpi_status_t hpi_vmac_clear_rx_int_stat(hpi_handle_t handle);
hpi_status_t hpi_vmac_clear_tx_int_stat(hpi_handle_t handle);
hpi_status_t hpi_pfc_set_rx_int_stat_mask(hpi_handle_t handle,
    boolean_t overflow_cnt, boolean_t frame_cnt);
hpi_status_t hpi_pfc_set_tx_int_stat_mask(hpi_handle_t handle,
    boolean_t overflow_cnt, boolean_t frame_cnt);
hpi_status_t hpi_vmac_rx_set_framesize(hpi_handle_t handle,
    uint16_t max_frame_length);

#define	CFG_VMAC_TX_EN			0x00000001
#define	CFG_VMAC_TX_CRC_INSERT		0x00000002
#define	CFG_VMAC_TX_PAD			0x00000004

#define	CFG_VMAC_RX_EN			0x00000001
#define	CFG_VMAC_RX_CRC_CHECK_DISABLE	0x00000002
#define	CFG_VMAC_RX_STRIP_CRC		0x00000004
#define	CFG_VMAC_RX_PASS_FLOW_CTRL_FR	0x00000008
#define	CFG_VMAC_RX_PROMIXCUOUS_GROUP	0x00000010
#define	CFG_VMAC_RX_PROMISCUOUS_MODE	0x00000020
#define	CFG_VMAC_RX_LOOP_BACK		0x00000040

#ifdef	__cplusplus
}
#endif

#endif	/* _HPI_MAC_H */
