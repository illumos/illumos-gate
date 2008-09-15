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
 * IntelVersion: 1.16 v2008-7-17_MountAngel2
 */
#ifndef _E1000_82571_H_
#define	_E1000_82571_H_

#ifdef __cplusplus
extern "C" {
#endif

#define	ID_LED_RESERVED_F746	0xF746
#define	ID_LED_DEFAULT_82573	((ID_LED_DEF1_DEF2 << 12) | \
				(ID_LED_OFF1_ON2  <<  8) | \
				(ID_LED_DEF1_DEF2 <<  4) | \
				(ID_LED_DEF1_DEF2))

#define	E1000_GCR_L1_ACT_WITHOUT_L0S_RX	0x08000000

/* Intr Throttling - RW */
#define	E1000_EITR_82574(_n)	(0x000E8 + (0x4 * (_n)))

#define	E1000_EIAC_82574	0x000DC /* Ext. Interrupt Auto Clear - RW */
#define	E1000_EIAC_MASK_82574	0x01F00000

#define	E1000_NVM_INIT_CTRL2_MNGM 0x6000 /* Manageability Operation Mode mask */

#define	E1000_RXCFGL	0x0B634 /* TimeSync Rx EtherType & Msg Type Reg - RW */

bool e1000_get_laa_state_82571(struct e1000_hw *hw);
void e1000_set_laa_state_82571(struct e1000_hw *hw, bool state);

#ifdef __cplusplus
}
#endif

#endif	/* _E1000_82571_H_ */
