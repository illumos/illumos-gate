/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2009 Intel Corporation. All rights reserved.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

/* IntelVersion: 1.18 v2008-10-7 */

#ifndef _IGB_NVM_H
#define	_IGB_NVM_H

#ifdef __cplusplus
extern "C" {
#endif

void e1000_init_nvm_ops_generic(struct e1000_hw *hw);
s32  e1000_null_read_nvm(struct e1000_hw *hw, u16 a, u16 b, u16 *c);
void e1000_null_nvm_generic(struct e1000_hw *hw);
s32  e1000_null_led_default(struct e1000_hw *hw, u16 *data);
s32  e1000_null_write_nvm(struct e1000_hw *hw, u16 a, u16 b, u16 *c);
s32 e1000_acquire_nvm_generic(struct e1000_hw *hw);

s32 e1000_poll_eerd_eewr_done(struct e1000_hw *hw, int ee_reg);
s32 e1000_read_mac_addr_generic(struct e1000_hw *hw);
s32 e1000_read_pba_num_generic(struct e1000_hw *hw, u32 *pba_num);
s32 e1000_read_nvm_microwire(struct e1000_hw *hw, u16 offset,
    u16 words, u16 *data);
s32 e1000_read_nvm_eerd(struct e1000_hw *hw, u16 offset, u16 words,
    u16 *data);
s32 e1000_valid_led_default_generic(struct e1000_hw *hw, u16 *data);
s32 e1000_validate_nvm_checksum_generic(struct e1000_hw *hw);
s32 e1000_write_nvm_eewr(struct e1000_hw *hw, u16 offset,
    u16 words, u16 *data);
s32 e1000_write_nvm_microwire(struct e1000_hw *hw, u16 offset,
    u16 words, u16 *data);
s32 e1000_write_nvm_spi(struct e1000_hw *hw, u16 offset, u16 words,
    u16 *data);
s32 e1000_update_nvm_checksum_generic(struct e1000_hw *hw);
void e1000_release_nvm_generic(struct e1000_hw *hw);

#define	E1000_STM_OPCODE	0xDB00

#ifdef __cplusplus
}
#endif

#endif	/* _IGB_NVM_H */
