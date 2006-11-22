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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_SR_HW_H
#define	_SYS_NXGE_NXGE_SR_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ESR_NEPTUNE_DEV_ADDR	0x1E
#define	ESR_NEPTUNE_BASE	0
#define	ESR_PORT_ADDR_BASE	0
#define	PCISR_DEV_ADDR		0x1E
#define	PCISR_BASE		0
#define	PCISR_PORT_ADDR_BASE	2

#define	PB	0

#define	SR_RX_TX_COMMON_CONTROL	PB + 0x000
#define	SR_RX_TX_RESET_CONTROL	PB + 0x004
#define	SR_RX_POWER_CONTROL	PB + 0x008
#define	SR_TX_POWER_CONTROL	PB + 0x00C
#define	SR_MISC_POWER_CONTROL	PB + 0x010
#define	SR_RX_TX_CONTROL_A	PB + 0x100
#define	SR_RX_TX_TUNING_A	PB + 0x104
#define	SR_RX_SYNCCHAR_A	PB + 0x108
#define	SR_RX_TX_TEST_A		PB + 0x10C
#define	SR_GLUE_CONTROL0_A	PB + 0x110
#define	SR_GLUE_CONTROL1_A	PB + 0x114
#define	SR_RX_TX_CONTROL_B	PB + 0x120
#define	SR_RX_TX_TUNING_B	PB + 0x124
#define	SR_RX_SYNCCHAR_B	PB + 0x128
#define	SR_RX_TX_TEST_B		PB + 0x12C
#define	SR_GLUE_CONTROL0_B	PB + 0x130
#define	SR_GLUE_CONTROL1_B	PB + 0x134
#define	SR_RX_TX_CONTROL_C	PB + 0x140
#define	SR_RX_TX_TUNING_C	PB + 0x144
#define	SR_RX_SYNCCHAR_C	PB + 0x148
#define	SR_RX_TX_TEST_C		PB + 0x14C
#define	SR_GLUE_CONTROL0_C	PB + 0x150
#define	SR_GLUE_CONTROL1_C	PB + 0x154
#define	SR_RX_TX_CONTROL_D	PB + 0x160
#define	SR_RX_TX_TUNING_D	PB + 0x164
#define	SR_RX_SYNCCHAR_D	PB + 0x168
#define	SR_RX_TX_TEST_D		PB + 0x16C
#define	SR_GLUE_CONTROL0_D	PB + 0x170
#define	SR_GLUE_CONTROL1_D	PB + 0x174
#define	SR_RX_TX_TUNING_1_A	PB + 0x184
#define	SR_RX_TX_TUNING_1_B	PB + 0x1A4
#define	SR_RX_TX_TUNING_1_C	PB + 0x1C4
#define	SR_RX_TX_TUNING_1_D	PB + 0x1E4
#define	SR_RX_TX_TUNING_2_A	PB + 0x204
#define	SR_RX_TX_TUNING_2_B	PB + 0x224
#define	SR_RX_TX_TUNING_2_C	PB + 0x244
#define	SR_RX_TX_TUNING_2_D	PB + 0x264
#define	SR_RX_TX_TUNING_3_A	PB + 0x284
#define	SR_RX_TX_TUNING_3_B	PB + 0x2A4
#define	SR_RX_TX_TUNING_3_C	PB + 0x2C4
#define	SR_RX_TX_TUNING_3_D	PB + 0x2E4

/*
 * Shift right by 1 because the PRM requires that all the serdes register
 * address be divided by 2
 */
#define	ESR_NEP_RX_TX_COMMON_CONTROL_L_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_RX_TX_COMMON_CONTROL >> 1))
#define	ESR_NEP_RX_TX_COMMON_CONTROL_H_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_RX_TX_COMMON_CONTROL >> 1)\
						+ 1)
#define	ESR_NEP_RX_TX_RESET_CONTROL_L_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_RX_TX_RESET_CONTROL >> 1))
#define	ESR_NEP_RX_TX_RESET_CONTROL_H_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_RX_TX_RESET_CONTROL >> 1)\
						+ 1)
#define	ESR_NEP_RX_POWER_CONTROL_L_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_RX_POWER_CONTROL >> 1))
#define	ESR_NEP_RX_POWER_CONTROL_H_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_RX_POWER_CONTROL >> 1) + 1)
#define	ESR_NEP_TX_POWER_CONTROL_L_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_TX_POWER_CONTROL >> 1))
#define	ESR_NEP_TX_POWER_CONTROL_H_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_TX_POWER_CONTROL >> 1) + 1)
#define	ESR_NEP_MISC_POWER_CONTROL_L_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_MISC_POWER_CONTROL >> 1))
#define	ESR_NEP_MISC_POWER_CONTROL_H_ADDR()	(ESR_NEPTUNE_BASE +\
						(SR_MISC_POWER_CONTROL >> 1)\
						+ 1)
#define	ESR_NEP_RX_TX_CONTROL_L_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_CONTROL_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_RX_TX_CONTROL_H_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_CONTROL_A +\
						(chan * 0x20)) >> 1) + 1
#define	ESR_NEP_RX_TX_TUNING_L_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TUNING_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_RX_TX_TUNING_H_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TUNING_A +\
						(chan * 0x20)) >> 1) + 1
#define	ESR_NEP_RX_TX_SYNCCHAR_L_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_SYNCCHAR_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_RX_TX_SYNCCHAR_H_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_SYNCCHAR_A +\
						(chan * 0x20)) >> 1) + 1
#define	ESR_NEP_RX_TX_TEST_L_ADDR(chan)		((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TEST_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_RX_TX_TEST_H_ADDR(chan)		((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TEST_A +\
						(chan * 0x20)) >> 1) + 1
#define	ESR_NEP_GLUE_CONTROL0_L_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_GLUE_CONTROL0_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_GLUE_CONTROL0_H_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_GLUE_CONTROL0_A +\
						(chan * 0x20)) >> 1) + 1
#define	ESR_NEP_GLUE_CONTROL1_L_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_GLUE_CONTROL1_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_GLUE_CONTROL1_H_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_GLUE_CONTROL1_A +\
						(chan * 0x20)) >> 1) + 1
#define	ESR_NEP_RX_TX_TUNING_1_L_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TUNING_1_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_RX_TX_TUNING_1_H_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TUNING_1_A +\
						(chan * 0x20)) >> 1) + 1
#define	ESR_NEP_RX_TX_TUNING_2_L_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TUNING_2_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_RX_TX_TUNING_2_H_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TUNING_2_A +\
						(chan * 0x20)) >> 1) + 1
#define	ESR_NEP_RX_TX_TUNING_3_L_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TUNING_3_A +\
						(chan * 0x20)) >> 1)
#define	ESR_NEP_RX_TX_TUNING_3_H_ADDR(chan)	((ESR_NEPTUNE_BASE +\
						SR_RX_TX_TUNING_3_A +\
						(chan * 0x20)) >> 1) + 1

typedef	union _sr_rx_tx_common_ctrl_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res3		: 3;
		uint16_t refclkr_freq	: 5;
		uint16_t res4		: 8;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res4		: 8;
		uint16_t refclkr_freq	: 5;
		uint16_t res3		: 3;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_common_ctrl_l;

typedef	union _sr_rx_tx_common_ctrl_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 5;
		uint16_t tdmaster	: 3;
		uint16_t tp		: 2;
		uint16_t tz		: 2;
		uint16_t res2		: 2;
		uint16_t revlbrefsel	: 2;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t revlbrefsel	: 2;
		uint16_t res2		: 2;
		uint16_t tz		: 2;
		uint16_t tp		: 2;
		uint16_t tdmaster	: 3;
		uint16_t res1		: 5;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_common_ctrl_h;


/* RX TX Common Control Register field values */

#define	TDMASTER_LANE_A		0
#define	TDMASTER_LANE_B		1
#define	TDMASTER_LANE_C		2
#define	TDMASTER_LANE_D		3

#define	REVLBREFSEL_GBT_RBC_A_O		0
#define	REVLBREFSEL_GBT_RBC_B_O		1
#define	REVLBREFSEL_GBT_RBC_C_O		2
#define	REVLBREFSEL_GBT_RBC_D_O		3

#define	REFCLKR_FREQ_SIM		0
#define	REFCLKR_FREQ_53_125		0x1
#define	REFCLKR_FREQ_62_5		0x3
#define	REFCLKR_FREQ_70_83		0x4
#define	REFCLKR_FREQ_75			0x5
#define	REFCLKR_FREQ_78_125		0x6
#define	REFCLKR_FREQ_79_6875		0x7
#define	REFCLKR_FREQ_83_33		0x8
#define	REFCLKR_FREQ_85			0x9
#define	REFCLKR_FREQ_100		0xA
#define	REFCLKR_FREQ_104_17		0xB
#define	REFCLKR_FREQ_106_25		0xC
#define	REFCLKR_FREQ_120		0xF
#define	REFCLKR_FREQ_125		0x10
#define	REFCLKR_FREQ_127_5		0x11
#define	REFCLKR_FREQ_141_67		0x13
#define	REFCLKR_FREQ_150		0x15
#define	REFCLKR_FREQ_156_25		0x16
#define	REFCLKR_FREQ_159_375		0x17
#define	REFCLKR_FREQ_170		0x19
#define	REFCLKR_FREQ_212_5		0x1E

typedef	union _sr_rx_tx_reset_ctrl_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t rxreset_0a	: 1;
		uint16_t rxreset_0b	: 1;
		uint16_t rxreset_0c	: 1;
		uint16_t rxreset_0d	: 1;
		uint16_t rxreset_1a	: 1;
		uint16_t rxreset_1b	: 1;
		uint16_t rxreset_1c	: 1;
		uint16_t rxreset_1d	: 1;
		uint16_t rxreset_2a	: 1;
		uint16_t rxreset_2b	: 1;
		uint16_t rxreset_2c	: 1;
		uint16_t rxreset_2d	: 1;
		uint16_t rxreset_3a	: 1;
		uint16_t rxreset_3b	: 1;
		uint16_t rxreset_3c	: 1;
		uint16_t rxreset_3d	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t rxreset_3d	: 1;
		uint16_t rxreset_3c	: 1;
		uint16_t rxreset_3b	: 1;
		uint16_t rxreset_3a	: 1;
		uint16_t rxreset_2d	: 1;
		uint16_t rxreset_2c	: 1;
		uint16_t rxreset_2b	: 1;
		uint16_t rxreset_2a	: 1;
		uint16_t rxreset_1d	: 1;
		uint16_t rxreset_1c	: 1;
		uint16_t rxreset_1b	: 1;
		uint16_t rxreset_1a	: 1;
		uint16_t rxreset_0d	: 1;
		uint16_t rxreset_0c	: 1;
		uint16_t rxreset_0b	: 1;
		uint16_t rxreset_0a	: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_reset_ctrl_l;


typedef	union _sr_rx_tx_reset_ctrl_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t txreset_0a	: 1;
		uint16_t txreset_0b	: 1;
		uint16_t txreset_0c	: 1;
		uint16_t txreset_0d	: 1;
		uint16_t txreset_1a	: 1;
		uint16_t txreset_1b	: 1;
		uint16_t txreset_1c	: 1;
		uint16_t txreset_1d	: 1;
		uint16_t txreset_2a	: 1;
		uint16_t txreset_2b	: 1;
		uint16_t txreset_2c	: 1;
		uint16_t txreset_2d	: 1;
		uint16_t txreset_3a	: 1;
		uint16_t txreset_3b	: 1;
		uint16_t txreset_3c	: 1;
		uint16_t txreset_3d	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t txreset_3d	: 1;
		uint16_t txreset_3c	: 1;
		uint16_t txreset_3b	: 1;
		uint16_t txreset_3a	: 1;
		uint16_t txreset_2d	: 1;
		uint16_t txreset_2c	: 1;
		uint16_t txreset_2b	: 1;
		uint16_t txreset_2a	: 1;
		uint16_t txreset_1d	: 1;
		uint16_t txreset_1c	: 1;
		uint16_t txreset_1b	: 1;
		uint16_t txreset_1a	: 1;
		uint16_t txreset_0d	: 1;
		uint16_t txreset_0c	: 1;
		uint16_t txreset_0b	: 1;
		uint16_t txreset_0a	: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_reset_ctrl_h;

typedef	union _sr_rx_power_ctrl_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t pdrxlos_0a	: 1;
		uint16_t pdrxlos_0b	: 1;
		uint16_t pdrxlos_0c	: 1;
		uint16_t pdrxlos_0d	: 1;
		uint16_t pdrxlos_1a	: 1;
		uint16_t pdrxlos_1b	: 1;
		uint16_t pdrxlos_1c	: 1;
		uint16_t pdrxlos_1d	: 1;
		uint16_t pdrxlos_2a	: 1;
		uint16_t pdrxlos_2b	: 1;
		uint16_t pdrxlos_2c	: 1;
		uint16_t pdrxlos_2d	: 1;
		uint16_t pdrxlos_3a	: 1;
		uint16_t pdrxlos_3b	: 1;
		uint16_t pdrxlos_3c	: 1;
		uint16_t pdrxlos_3d	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t pdrxlos_3d	: 1;
		uint16_t pdrxlos_3c	: 1;
		uint16_t pdrxlos_3b	: 1;
		uint16_t pdrxlos_3a	: 1;
		uint16_t pdrxlos_2d	: 1;
		uint16_t pdrxlos_2c	: 1;
		uint16_t pdrxlos_2b	: 1;
		uint16_t pdrxlos_2a	: 1;
		uint16_t pdrxlos_1d	: 1;
		uint16_t pdrxlos_1c	: 1;
		uint16_t pdrxlos_1b	: 1;
		uint16_t pdrxlos_1a	: 1;
		uint16_t pdrxlos_0d	: 1;
		uint16_t pdrxlos_0c	: 1;
		uint16_t pdrxlos_0b	: 1;
		uint16_t pdrxlos_0a	: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_power_ctrl_l_t;


typedef	union _sr_rx_power_ctrl_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t pdownr_0a	: 1;
		uint16_t pdownr_0b	: 1;
		uint16_t pdownr_0c	: 1;
		uint16_t pdownr_0d	: 1;
		uint16_t pdownr_1a	: 1;
		uint16_t pdownr_1b	: 1;
		uint16_t pdownr_1c	: 1;
		uint16_t pdownr_1d	: 1;
		uint16_t pdownr_2a	: 1;
		uint16_t pdownr_2b	: 1;
		uint16_t pdownr_2c	: 1;
		uint16_t pdownr_2d	: 1;
		uint16_t pdownr_3a	: 1;
		uint16_t pdownr_3b	: 1;
		uint16_t pdownr_3c	: 1;
		uint16_t pdownr_3d	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t pdownr_3d	: 1;
		uint16_t pdownr_3c	: 1;
		uint16_t pdownr_3b	: 1;
		uint16_t pdownr_3a	: 1;
		uint16_t pdownr_2d	: 1;
		uint16_t pdownr_2c	: 1;
		uint16_t pdownr_2b	: 1;
		uint16_t pdownr_2a	: 1;
		uint16_t pdownr_1d	: 1;
		uint16_t pdownr_1c	: 1;
		uint16_t pdownr_1b	: 1;
		uint16_t pdownr_1a	: 1;
		uint16_t pdownr_0d	: 1;
		uint16_t pdownr_0c	: 1;
		uint16_t pdownr_0b	: 1;
		uint16_t pdownr_0a	: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_power_ctrl_h_t;

typedef	union _sr_tx_power_ctrl_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 8;
		uint16_t pdownppll0	: 1;
		uint16_t pdownppll1	: 1;
		uint16_t pdownppll2	: 1;
		uint16_t pdownppll3	: 1;
		uint16_t res2		: 4;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res2		: 4;
		uint16_t pdownppll3	: 1;
		uint16_t pdownppll2	: 1;
		uint16_t pdownppll1	: 1;
		uint16_t pdownppll0	: 1;
		uint16_t res1		: 8;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_tx_power_ctrl_l_t;

typedef	union _sr_tx_power_ctrl_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t pdownt_0a	: 1;
		uint16_t pdownt_0b	: 1;
		uint16_t pdownt_0c	: 1;
		uint16_t pdownt_0d	: 1;
		uint16_t pdownt_1a	: 1;
		uint16_t pdownt_1b	: 1;
		uint16_t pdownt_1c	: 1;
		uint16_t pdownt_1d	: 1;
		uint16_t pdownt_2a	: 1;
		uint16_t pdownt_2b	: 1;
		uint16_t pdownt_2c	: 1;
		uint16_t pdownt_2d	: 1;
		uint16_t pdownt_3a	: 1;
		uint16_t pdownt_3b	: 1;
		uint16_t pdownt_3c	: 1;
		uint16_t pdownt_3d	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t pdownt_3d	: 1;
		uint16_t pdownt_3c	: 1;
		uint16_t pdownt_3b	: 1;
		uint16_t pdownt_3a	: 1;
		uint16_t pdownt_2d	: 1;
		uint16_t pdownt_2c	: 1;
		uint16_t pdownt_2b	: 1;
		uint16_t pdownt_2a	: 1;
		uint16_t pdownt_1d	: 1;
		uint16_t pdownt_1c	: 1;
		uint16_t pdownt_1b	: 1;
		uint16_t pdownt_1a	: 1;
		uint16_t pdownt_0d	: 1;
		uint16_t pdownt_0c	: 1;
		uint16_t pdownt_0b	: 1;
		uint16_t pdownt_0a	: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_tx_power_ctrl_h_t;

typedef	union _sr_misc_power_ctrl_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 3;
		uint16_t pdrtrim	: 1;
		uint16_t pdownpecl0	: 1;
		uint16_t pdownpecl1	: 1;
		uint16_t pdownpecl2	: 1;
		uint16_t pdownpecl3	: 1;
		uint16_t pdownppll0	: 1;
		uint16_t pdownppll1	: 1;
		uint16_t pdownppll2	: 1;
		uint16_t pdownppll3	: 1;
		uint16_t res2		: 4;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res2		: 4;
		uint16_t pdownppll3	: 1;
		uint16_t pdownppll2	: 1;
		uint16_t pdownppll1	: 1;
		uint16_t pdownppll0	: 1;
		uint16_t pdownpecl3	: 1;
		uint16_t pdownpecl2	: 1;
		uint16_t pdownpecl1	: 1;
		uint16_t pdownpecl0	: 1;
		uint16_t pdrtrim	: 1;
		uint16_t res1		: 3;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_misc_power_ctrl_l_t;

typedef	union _misc_power_ctrl_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t pdclkout0	: 1;
		uint16_t pdclkout1	: 1;
		uint16_t pdclkout2	: 1;
		uint16_t pdclkout3	: 1;
		uint16_t res1		: 12;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res1		: 12;
		uint16_t pdclkout3	: 1;
		uint16_t pdclkout2	: 1;
		uint16_t pdclkout1	: 1;
		uint16_t pdclkout0	: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} misc_power_ctrl_h_t;

typedef	union _sr_rx_tx_ctrl_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 2;
		uint16_t rxpreswin	: 2;
		uint16_t res2		: 1;
		uint16_t risefall	: 3;
		uint16_t res3		: 7;
		uint16_t enstretch	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t enstretch	: 1;
		uint16_t res3		: 7;
		uint16_t risefall	: 3;
		uint16_t res2		: 1;
		uint16_t rxpreswin	: 2;
		uint16_t res1		: 2;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_ctrl_l_t;

typedef	union _sr_rx_tx_ctrl_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t biascntl	: 1;
		uint16_t res1		: 5;
		uint16_t tdenfifo	: 1;
		uint16_t tdws20		: 1;
		uint16_t vmuxlo		: 2;
		uint16_t vpulselo	: 2;
		uint16_t res2		: 4;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res2		: 4;
		uint16_t vpulselo	: 2;
		uint16_t vmuxlo		: 2;
		uint16_t tdws20		: 1;
		uint16_t tdenfifo	: 1;
		uint16_t res1		: 5;
		uint16_t biascntl	: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_ctrl_h_t;

#define	RXPRESWIN_52US_300BITTIMES	0
#define	RXPRESWIN_53US_300BITTIMES	1
#define	RXPRESWIN_54US_300BITTIMES	2
#define	RXPRESWIN_55US_300BITTIMES	3

typedef	union _sr_rx_tx_tuning_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t rxeq		: 4;
		uint16_t res1		: 12;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res1		: 12;
		uint16_t rxeq		: 4;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_tuning_l_t;

typedef	union _sr_rx_tx_tuning_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 8;
		uint16_t rp		: 2;
		uint16_t rz		: 2;
		uint16_t vtxlo		: 4;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t vtxlo		: 4;
		uint16_t rz		: 2;
		uint16_t rp		: 2;
		uint16_t res1		: 8;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_tuning_h_t;

typedef	union _sr_rx_syncchar_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t syncchar_0_3	: 4;
		uint16_t res1		: 2;
		uint16_t syncmask	: 10;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t syncmask	: 10;
		uint16_t res1		: 2;
		uint16_t syncchar_0_3	: 4;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_syncchar_l_t;

typedef	union _sr_rx_syncchar_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 1;
		uint16_t syncpol	: 1;
		uint16_t res2		: 8;
		uint16_t syncchar_4_10	: 6;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t syncchar_4_10	: 6;
		uint16_t res2		: 8;
		uint16_t syncpol	: 1;
		uint16_t res1		: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_syncchar_h_t;

typedef	union _sr_rx_tx_test_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 15;
		uint16_t ref50		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t ref50		: 1;
		uint16_t res1		: 15;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_test_l_t;

typedef	union _sr_rx_tx_test_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 5;
		uint16_t selftest	: 3;
		uint16_t res2		: 8;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res2		: 8;
		uint16_t selftest	: 3;
		uint16_t res1		: 5;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_rx_tx_test_h_t;

typedef	union _sr_glue_ctrl0_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t rxlos_test	: 1;
		uint16_t res1		: 1;
		uint16_t rxlosenable	: 1;
		uint16_t fastresync	: 1;
		uint16_t samplerate	: 4;
		uint16_t thresholdcount	: 8;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t thresholdcount	: 8;
		uint16_t samplerate	: 4;
		uint16_t fastresync	: 1;
		uint16_t rxlosenable	: 1;
		uint16_t res1		: 1;
		uint16_t rxlos_test	: 1;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_glue_ctrl0_l_t;

typedef	union _sr_glue_ctrl0_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 5;
		uint16_t bitlocktime	: 3;
		uint16_t res2		: 8;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res2		: 8;
		uint16_t bitlocktime	: 3;
		uint16_t res1		: 5;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_glue_ctrl0_h_t;

#define	BITLOCKTIME_64_CYCLES		0
#define	BITLOCKTIME_128_CYCLES		1
#define	BITLOCKTIME_256_CYCLES		2
#define	BITLOCKTIME_300_CYCLES		3
#define	BITLOCKTIME_384_CYCLES		4
#define	BITLOCKTIME_512_CYCLES		5
#define	BITLOCKTIME_1024_CYCLES		6
#define	BITLOCKTIME_2048_CYCLES		7

typedef	union _sr_glue_ctrl1_l {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 14;
		uint16_t inittime	: 2;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t inittime	: 2;
		uint16_t res1		: 14;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} sr_glue_ctrl1_l_t;

typedef	union glue_ctrl1_h {
	uint16_t value;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t termr_cfg	: 2;
		uint16_t termt_cfg	: 2;
		uint16_t rtrimen	: 2;
		uint16_t res1		: 10;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t res1		: 10;
		uint16_t rtrimen	: 2;
		uint16_t termt_cfg	: 2;
		uint16_t termr_cfg	: 2;
#else
#error one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} bits;
} glue_ctrl1_h_t;

#define	TERM_CFG_67OHM		0
#define	TERM_CFG_72OHM		1
#define	TERM_CFG_80OHM		2
#define	TERM_CFG_87OHM		3
#define	TERM_CFG_46OHM		4
#define	TERM_CFG_48OHM		5
#define	TERM_CFG_52OHM		6
#define	TERM_CFG_55OHM		7

#define	INITTIME_60US		0
#define	INITTIME_120US		1
#define	INITTIME_240US		2
#define	INITTIME_480US		3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_SR_HW_H */
