/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#ifndef _IGB_API_H
#define	_IGB_API_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "igb_hw.h"

extern void e1000_init_function_pointers_82575(struct e1000_hw *hw);

s32 e1000_set_mac_type(struct e1000_hw *hw);
s32 e1000_setup_init_funcs(struct e1000_hw *hw, bool init_device);
s32 e1000_init_mac_params(struct e1000_hw *hw);
s32 e1000_init_nvm_params(struct e1000_hw *hw);
s32 e1000_init_phy_params(struct e1000_hw *hw);
void e1000_remove_device(struct e1000_hw *hw);
s32 e1000_get_bus_info(struct e1000_hw *hw);
void e1000_clear_vfta(struct e1000_hw *hw);
void e1000_write_vfta(struct e1000_hw *hw, u32 offset, u32 value);
s32 e1000_force_mac_fc(struct e1000_hw *hw);
s32 e1000_check_for_link(struct e1000_hw *hw);
s32 e1000_reset_hw(struct e1000_hw *hw);
s32 e1000_init_hw(struct e1000_hw *hw);
s32 e1000_setup_link(struct e1000_hw *hw);
s32 e1000_get_speed_and_duplex(struct e1000_hw *hw, u16 *speed, u16 *duplex);
s32 e1000_disable_pcie_master(struct e1000_hw *hw);
void e1000_config_collision_dist(struct e1000_hw *hw);
void e1000_rar_set(struct e1000_hw *hw, u8 *addr, u32 index);
void e1000_mta_set(struct e1000_hw *hw, u32 hash_value);
u32 e1000_hash_mc_addr(struct e1000_hw *hw, u8 *mc_addr);
void e1000_update_mc_addr_list(struct e1000_hw *hw,
    u8 *mc_addr_list, u32 mc_addr_count,
    u32 rar_used_count, u32 rar_count);
s32 e1000_setup_led(struct e1000_hw *hw);
s32 e1000_cleanup_led(struct e1000_hw *hw);
s32 e1000_check_reset_block(struct e1000_hw *hw);
s32 e1000_blink_led(struct e1000_hw *hw);
s32 e1000_led_on(struct e1000_hw *hw);
s32 e1000_led_off(struct e1000_hw *hw);
void e1000_reset_adaptive(struct e1000_hw *hw);
void e1000_update_adaptive(struct e1000_hw *hw);
s32 e1000_get_cable_length(struct e1000_hw *hw);
s32 e1000_validate_mdi_setting(struct e1000_hw *hw);
s32 e1000_read_phy_reg(struct e1000_hw *hw, u32 offset, u16 *data);
s32 e1000_write_phy_reg(struct e1000_hw *hw, u32 offset, u16 data);
s32 e1000_write_8bit_ctrl_reg(struct e1000_hw *hw, u32 reg,
    u32 offset, u8 data);
s32 e1000_get_phy_info(struct e1000_hw *hw);
s32 e1000_phy_hw_reset(struct e1000_hw *hw);
s32 e1000_phy_commit(struct e1000_hw *hw);
void e1000_power_up_phy(struct e1000_hw *hw);
void e1000_power_down_phy(struct e1000_hw *hw);
s32 e1000_read_mac_addr(struct e1000_hw *hw);
s32 e1000_read_pba_num(struct e1000_hw *hw, u32 *part_num);
void e1000_reload_nvm(struct e1000_hw *hw);
s32 e1000_update_nvm_checksum(struct e1000_hw *hw);
s32 e1000_validate_nvm_checksum(struct e1000_hw *hw);
s32 e1000_read_nvm(struct e1000_hw *hw, u16 offset, u16 words, u16 *data);
s32 e1000_read_kmrn_reg(struct e1000_hw *hw, u32 offset, u16 *data);
s32 e1000_write_kmrn_reg(struct e1000_hw *hw, u32 offset, u16 data);
s32 e1000_write_nvm(struct e1000_hw *hw, u16 offset, u16 words, u16 *data);
s32 e1000_wait_autoneg(struct e1000_hw *hw);
s32 e1000_set_d3_lplu_state(struct e1000_hw *hw, bool active);
s32 e1000_set_d0_lplu_state(struct e1000_hw *hw, bool active);
bool e1000_check_mng_mode(struct e1000_hw *hw);
bool e1000_enable_mng_pass_thru(struct e1000_hw *hw);
bool e1000_enable_tx_pkt_filtering(struct e1000_hw *hw);
s32 e1000_mng_enable_host_if(struct e1000_hw *hw);
s32 e1000_mng_host_if_write(struct e1000_hw *hw,
    u8 *buffer, u16 length, u16 offset, u8 *sum);
s32 e1000_mng_write_cmd_header(struct e1000_hw *hw,
    struct e1000_host_mng_command_header *hdr);
s32 e1000_mng_write_dhcp_info(struct e1000_hw *hw,
    u8 *buffer, u16 length);
#ifndef FIFO_WORKAROUND
s32 e1000_fifo_workaround_82547(struct e1000_hw *hw, u16 length);
void e1000_update_tx_fifo_head_82547(struct e1000_hw *hw, u32 length);
void e1000_set_ttl_workaround_state_82541(struct e1000_hw *hw, bool state);
bool e1000_ttl_workaround_enabled_82541(struct e1000_hw *hw);
s32 e1000_igp_ttl_workaround_82547(struct e1000_hw *hw);
#endif


/*
 * TBI_ACCEPT macro definition:
 *
 * This macro requires:
 *	adapter = a pointer to struct e1000_hw
 *	status = the 8 bit status field of the Rx descriptor with EOP set
 *	error = the 8 bit error field of the Rx descriptor with EOP set
 *	length = the sum of all the length fields of the Rx descriptors that
 *		make up the current frame
 *	last_byte = the last byte of the frame DMAed by the hardware
 *	max_frame_length = the maximum frame length we want to accept.
 *	min_frame_length = the minimum frame length we want to accept.
 *
 * This macro is a conditional that should be used in the interrupt
 * handler's Rx processing routine when RxErrors have been detected.
 *
 * Typical use:
 *  ...
 *  if (TBI_ACCEPT) {
 *	accept_frame = TRUE;
 *	e1000_tbi_adjust_stats(adapter, MacAddress);
 *	frame_length--;
 *  } else {
 *	accept_frame = FALSE;
 *  }
 *  ...
 */

/* The carrier extension symbol, as received by the NIC. */
#define	CARRIER_EXTENSION	0x0F

#define	TBI_ACCEPT(a, status, errors, length, last_byte, \
    min_frame_size, max_frame_size) \
	(e1000_tbi_sbp_enabled_82543(a) && \
	(((errors) & E1000_RXD_ERR_FRAME_ERR_MASK) == E1000_RXD_ERR_CE) && \
	((last_byte) == CARRIER_EXTENSION) && \
	(((status) & E1000_RXD_STAT_VP) ? \
	    (((length) > (min_frame_size - VLAN_TAG_SIZE)) && \
	    ((length) <= (max_frame_size + 1))) : \
	    (((length) > min_frame_size) && \
	    ((length) <= (max_frame_size + VLAN_TAG_SIZE + 1)))))

#ifdef __cplusplus
}
#endif

#endif	/* _IGB_API_H */
