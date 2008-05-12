/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
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

/* IntelVersion: 1.50 v2008-03-04 */

#ifndef _IXGBE_API_H
#define	_IXGBE_API_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ixgbe_type.h"

s32 ixgbe_init_shared_code(struct ixgbe_hw *hw);

s32 ixgbe_set_mac_type(struct ixgbe_hw *hw);
s32 ixgbe_init_hw(struct ixgbe_hw *hw);
s32 ixgbe_reset_hw(struct ixgbe_hw *hw);
s32 ixgbe_start_hw(struct ixgbe_hw *hw);
s32 ixgbe_clear_hw_cntrs(struct ixgbe_hw *hw);
enum ixgbe_media_type ixgbe_get_media_type(struct ixgbe_hw *hw);
s32 ixgbe_get_mac_addr(struct ixgbe_hw *hw, u8 *mac_addr);
s32 ixgbe_get_bus_info(struct ixgbe_hw *hw);
u32 ixgbe_get_num_of_tx_queues(struct ixgbe_hw *hw);
u32 ixgbe_get_num_of_rx_queues(struct ixgbe_hw *hw);
s32 ixgbe_stop_adapter(struct ixgbe_hw *hw);
s32 ixgbe_read_pba_num(struct ixgbe_hw *hw, u32 *pba_num);

s32 ixgbe_identify_phy(struct ixgbe_hw *hw);
s32 ixgbe_reset_phy(struct ixgbe_hw *hw);
s32 ixgbe_read_phy_reg(struct ixgbe_hw *hw, u32 reg_addr, u32 device_type,
    u16 *phy_data);
s32 ixgbe_write_phy_reg(struct ixgbe_hw *hw, u32 reg_addr, u32 device_type,
    u16 phy_data);

s32 ixgbe_setup_phy_link(struct ixgbe_hw *hw);
s32 ixgbe_check_phy_link(struct ixgbe_hw *hw,
    ixgbe_link_speed *speed, bool *link_up);
s32 ixgbe_setup_phy_link_speed(struct ixgbe_hw *hw, ixgbe_link_speed speed,
    bool autoneg, bool autoneg_wait_to_complete);
s32 ixgbe_setup_link(struct ixgbe_hw *hw);
s32 ixgbe_setup_link_speed(struct ixgbe_hw *hw, ixgbe_link_speed speed,
    bool autoneg, bool autoneg_wait_to_complete);
s32 ixgbe_check_link(struct ixgbe_hw *hw, ixgbe_link_speed *speed,
    bool *link_up);
s32 ixgbe_get_link_capabilities(struct ixgbe_hw *hw, ixgbe_link_speed *speed,
    bool *autoneg);
s32 ixgbe_led_on(struct ixgbe_hw *hw, u32 index);
s32 ixgbe_led_off(struct ixgbe_hw *hw, u32 index);
s32 ixgbe_blink_led_start(struct ixgbe_hw *hw, u32 index);
s32 ixgbe_blink_led_stop(struct ixgbe_hw *hw, u32 index);

s32 ixgbe_init_eeprom_params(struct ixgbe_hw *hw);
s32 ixgbe_write_eeprom(struct ixgbe_hw *hw, u16 offset, u16 data);
s32 ixgbe_read_eeprom(struct ixgbe_hw *hw, u16 offset, u16 *data);
s32 ixgbe_validate_eeprom_checksum(struct ixgbe_hw *hw, u16 *checksum_val);
s32 ixgbe_update_eeprom_checksum(struct ixgbe_hw *hw);

s32 ixgbe_set_rar(struct ixgbe_hw *hw, u32 index, u8 *addr, u32 vmdq,
    u32 enable_addr);
s32 ixgbe_set_vmdq(struct ixgbe_hw *hw, u32 rar, u32 vmdq);
s32 ixgbe_init_rx_addrs(struct ixgbe_hw *hw);
u32 ixgbe_get_num_rx_addrs(struct ixgbe_hw *hw);
s32 ixgbe_update_uc_addr_list(struct ixgbe_hw *hw, u8 *addr_list,
    u32 addr_count, ixgbe_mc_addr_itr func);
s32 ixgbe_update_mc_addr_list(struct ixgbe_hw *hw, u8 *mc_addr_list,
    u32 mc_addr_count, ixgbe_mc_addr_itr func);
s32 ixgbe_enable_mc(struct ixgbe_hw *hw);
s32 ixgbe_disable_mc(struct ixgbe_hw *hw);
s32 ixgbe_clear_vfta(struct ixgbe_hw *hw);
s32 ixgbe_set_vfta(struct ixgbe_hw *hw, u32 vlan, u32 vind, bool vlan_on);

s32 ixgbe_setup_fc(struct ixgbe_hw *hw, s32 packetbuf_num);

void ixgbe_set_mta(struct ixgbe_hw *hw, u8 *mc_addr);
s32 ixgbe_get_phy_firmware_version(struct ixgbe_hw *hw,
    u16 *firmware_version);
s32 ixgbe_read_analog_reg8(struct ixgbe_hw *hw, u32 reg, u8 *val);
s32 ixgbe_write_analog_reg8(struct ixgbe_hw *hw, u32 reg, u8 val);

#endif /* _IXGBE_API_H */
