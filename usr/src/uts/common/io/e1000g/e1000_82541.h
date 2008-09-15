/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2008 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

/*
 * IntelVersion: 1.8 v2008-7-17_MountAngel2
 */
#ifndef _E1000_82541_H_
#define	_E1000_82541_H_

#ifdef __cplusplus
extern "C" {
#endif

#define	NVM_WORD_SIZE_BASE_SHIFT_82541 (NVM_WORD_SIZE_BASE_SHIFT + 1)

#define	IGP01E1000_PHY_CHANNEL_NUM		4

#define	IGP01E1000_PHY_AGC_A			0x1172
#define	IGP01E1000_PHY_AGC_B			0x1272
#define	IGP01E1000_PHY_AGC_C			0x1472
#define	IGP01E1000_PHY_AGC_D			0x1872

#define	IGP01E1000_PHY_AGC_PARAM_A		0x1171
#define	IGP01E1000_PHY_AGC_PARAM_B		0x1271
#define	IGP01E1000_PHY_AGC_PARAM_C		0x1471
#define	IGP01E1000_PHY_AGC_PARAM_D		0x1871

#define	IGP01E1000_PHY_EDAC_MU_INDEX		0xC000
#define	IGP01E1000_PHY_EDAC_SIGN_EXT_9_BITS	0x8000

#define	IGP01E1000_PHY_DSP_RESET		0x1F33

#define	IGP01E1000_PHY_DSP_FFE			0x1F35
#define	IGP01E1000_PHY_DSP_FFE_CM_CP		0x0069
#define	IGP01E1000_PHY_DSP_FFE_DEFAULT		0x002A

#define	IGP01E1000_IEEE_FORCE_GIG		0x0140
#define	IGP01E1000_IEEE_RESTART_AUTONEG		0x3300

#define	IGP01E1000_AGC_LENGTH_SHIFT		7
#define	IGP01E1000_AGC_RANGE			10

#define	FFE_IDLE_ERR_COUNT_TIMEOUT_20		20
#define	FFE_IDLE_ERR_COUNT_TIMEOUT_100		100

#define	IGP01E1000_ANALOG_FUSE_STATUS		0x20D0
#define	IGP01E1000_ANALOG_SPARE_FUSE_STATUS	0x20D1
#define	IGP01E1000_ANALOG_FUSE_CONTROL		0x20DC
#define	IGP01E1000_ANALOG_FUSE_BYPASS		0x20DE

#define	IGP01E1000_ANALOG_SPARE_FUSE_ENABLED	0x0100
#define	IGP01E1000_ANALOG_FUSE_FINE_MASK	0x0F80
#define	IGP01E1000_ANALOG_FUSE_COARSE_MASK	0x0070
#define	IGP01E1000_ANALOG_FUSE_COARSE_THRESH	0x0040
#define	IGP01E1000_ANALOG_FUSE_COARSE_10	0x0010
#define	IGP01E1000_ANALOG_FUSE_FINE_1		0x0080
#define	IGP01E1000_ANALOG_FUSE_FINE_10		0x0500
#define	IGP01E1000_ANALOG_FUSE_POLY_MASK	0xF000
#define	IGP01E1000_ANALOG_FUSE_ENABLE_SW_CONTROL 0x0002

#define	IGP01E1000_MSE_CHANNEL_D		0x000F
#define	IGP01E1000_MSE_CHANNEL_C		0x00F0
#define	IGP01E1000_MSE_CHANNEL_B		0x0F00
#define	IGP01E1000_MSE_CHANNEL_A		0xF000

#define	E1000_FIFO_MULTIPLIER			0x80
#define	E1000_FIFO_HDR_SIZE			0x10
#define	E1000_FIFO_GRANULARITY			0x10
#define	E1000_FIFO_PAD_82547			0x3E0
#define	E1000_ERR_FIFO_WRAP			8

#define	DSP_RESET_ENABLE			0x0
#define	DSP_RESET_DISABLE			0x2
#define	E1000_MAX_DSP_RESETS			10

#define	E1000_ROUNDUP(size, unit)	(((size) + (unit) - 1) & ~((unit) - 1))

void e1000_init_script_state_82541(struct e1000_hw *hw, bool state);
s32 e1000_fifo_workaround_82547(struct e1000_hw *hw, u16 length);
void e1000_update_tx_fifo_head_82547(struct e1000_hw *hw, u32 length);
void e1000_set_ttl_workaround_state_82541(struct e1000_hw *hw, bool state);
bool e1000_ttl_workaround_enabled_82541(struct e1000_hw *hw);
s32 e1000_igp_ttl_workaround_82547(struct e1000_hw *hw);

#ifdef __cplusplus
}
#endif

#endif	/* _E1000_82541_H_ */
