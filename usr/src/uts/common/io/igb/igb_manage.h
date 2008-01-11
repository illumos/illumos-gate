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

/* IntelVersion: 1.15 v2007-12-10_dragonlake5 */

#ifndef _IGB_MANAGE_H
#define	_IGB_MANAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

bool e1000_check_mng_mode_generic(struct e1000_hw *hw);
bool e1000_enable_tx_pkt_filtering_generic(struct e1000_hw *hw);
s32  e1000_mng_enable_host_if_generic(struct e1000_hw *hw);
s32  e1000_mng_host_if_write_generic(struct e1000_hw *hw, u8 *buffer,
    u16 length, u16 offset, u8 *sum);
s32  e1000_mng_write_cmd_header_generic(struct e1000_hw *hw,
    struct e1000_host_mng_command_header *hdr);
s32  e1000_mng_write_dhcp_info_generic(struct e1000_hw *hw,
    u8 *buffer, u16 length);

typedef enum {
	e1000_mng_mode_none = 0,
	e1000_mng_mode_asf,
	e1000_mng_mode_pt,
	e1000_mng_mode_ipmi,
	e1000_mng_mode_host_if_only
} e1000_mng_mode;

#define	E1000_FACTPS_MNGCG    0x20000000

#define	E1000_FWSM_MODE_MASK  0xE
#define	E1000_FWSM_MODE_SHIFT 1

#define	E1000_MNG_IAMT_MODE			0x3
#define	E1000_MNG_DHCP_COOKIE_LENGTH		0x10
#define	E1000_MNG_DHCP_COOKIE_OFFSET		0x6F0
#define	E1000_MNG_DHCP_COMMAND_TIMEOUT		10
#define	E1000_MNG_DHCP_TX_PAYLOAD_CMD		64
#define	E1000_MNG_DHCP_COOKIE_STATUS_PARSING	0x1
#define	E1000_MNG_DHCP_COOKIE_STATUS_VLAN	0x2

#define	E1000_VFTA_ENTRY_SHIFT			5
#define	E1000_VFTA_ENTRY_MASK			0x7F
#define	E1000_VFTA_ENTRY_BIT_SHIFT_MASK		0x1F

#define	E1000_HI_MAX_BLOCK_BYTE_LENGTH		1792 /* Num of bytes in range */
#define	E1000_HI_MAX_BLOCK_DWORD_LENGTH		448 /* Num of dwords in range */
/* Process HI command limit */
#define	E1000_HI_COMMAND_TIMEOUT		500

#define	E1000_HICR_EN			0x01  /* Enable bit - RO */
/* Driver sets this bit when done to put command in RAM */
#define	E1000_HICR_C			0x02
#define	E1000_HICR_SV			0x04  /* Status Validity */
#define	E1000_HICR_FW_RESET_ENABLE	0x40
#define	E1000_HICR_FW_RESET		0x80

/* Intel(R) Active Management Technology signature */
#define	E1000_IAMT_SIGNATURE  0x544D4149

#ifdef __cplusplus
}
#endif

#endif	/* _IGB_MANAGE_H */
