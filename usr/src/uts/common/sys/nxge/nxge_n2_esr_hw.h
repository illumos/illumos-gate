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

#ifndef _SYS_NXGE_NXGE_N2_ESR_HW_H
#define	_SYS_NXGE_NXGE_N2_ESR_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ESR_N2_DEV_ADDR		0x1E
#define	ESR_N2_BASE		0x8000

/*
 * Definitions for TI WIZ6C2xxN2x0 Macro Family.
 */

/* Register Blocks base address */

#define	ESR_N2_PLL_REG_OFFSET		0
#define	ESR_N2_TEST_REG_OFFSET		0x004
#define	ESR_N2_TX_REG_OFFSET		0x100
#define	ESR_N2_TX_0_REG_OFFSET		0x100
#define	ESR_N2_TX_1_REG_OFFSET		0x104
#define	ESR_N2_TX_2_REG_OFFSET		0x108
#define	ESR_N2_TX_3_REG_OFFSET		0x10c
#define	ESR_N2_TX_4_REG_OFFSET		0x110
#define	ESR_N2_TX_5_REG_OFFSET		0x114
#define	ESR_N2_TX_6_REG_OFFSET		0x118
#define	ESR_N2_TX_7_REG_OFFSET		0x11c
#define	ESR_N2_RX_REG_OFFSET		0x120
#define	ESR_N2_RX_0_REG_OFFSET		0x120
#define	ESR_N2_RX_1_REG_OFFSET		0x124
#define	ESR_N2_RX_2_REG_OFFSET		0x128
#define	ESR_N2_RX_3_REG_OFFSET		0x12c
#define	ESR_N2_RX_4_REG_OFFSET		0x130
#define	ESR_N2_RX_5_REG_OFFSET		0x134
#define	ESR_N2_RX_6_REG_OFFSET		0x138
#define	ESR_N2_RX_7_REG_OFFSET		0x13c
#define	ESR_N2_P1_REG_OFFSET		0x400

/* Register address */

#define	ESR_N2_PLL_CFG_REG		ESR_N2_BASE + ESR_N2_PLL_REG_OFFSET
#define	ESR_N2_PLL_CFG_L_REG		ESR_N2_BASE + ESR_N2_PLL_REG_OFFSET
#define	ESR_N2_PLL_CFG_H_REG		ESR_N2_BASE + ESR_N2_PLL_REG_OFFSET + 1
#define	ESR_N2_PLL_STS_REG		ESR_N2_BASE + ESR_N2_PLL_REG_OFFSET + 2
#define	ESR_N2_PLL_STS_L_REG		ESR_N2_BASE + ESR_N2_PLL_REG_OFFSET + 2
#define	ESR_N2_PLL_STS_H_REG		ESR_N2_BASE + ESR_N2_PLL_REG_OFFSET + 3
#define	ESR_N2_TEST_CFG_REG		ESR_N2_BASE + ESR_N2_TEST_REG_OFFSET
#define	ESR_N2_TEST_CFG_L_REG		ESR_N2_BASE + ESR_N2_TEST_REG_OFFSET
#define	ESR_N2_TEST_CFG_H_REG		ESR_N2_BASE + ESR_N2_TEST_REG_OFFSET + 1

#define	ESR_N2_TX_CFG_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_TX_REG_OFFSET +\
					(chan * 4))
#define	ESR_N2_TX_CFG_L_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_TX_REG_OFFSET +\
					(chan * 4))
#define	ESR_N2_TX_CFG_H_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_TX_REG_OFFSET +\
					(chan * 4) + 1)
#define	ESR_N2_TX_STS_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_TX_REG_OFFSET +\
					(chan * 4) + 2)
#define	ESR_N2_TX_STS_L_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_TX_REG_OFFSET +\
					(chan * 4) + 2)
#define	ESR_N2_TX_STS_H_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_TX_REG_OFFSET +\
					(chan * 4) + 3)
#define	ESR_N2_RX_CFG_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_RX_REG_OFFSET +\
					(chan * 4))
#define	ESR_N2_RX_CFG_L_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_RX_REG_OFFSET +\
					(chan * 4))
#define	ESR_N2_RX_CFG_H_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_RX_REG_OFFSET +\
					(chan * 4) + 1)
#define	ESR_N2_RX_STS_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_RX_REG_OFFSET +\
					(chan * 4) + 2)
#define	ESR_N2_RX_STS_L_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_RX_REG_OFFSET +\
					(chan * 4) + 2)
#define	ESR_N2_RX_STS_H_REG_ADDR(chan)	(ESR_N2_BASE + ESR_N2_RX_REG_OFFSET +\
					(chan * 4) + 3)

/* PLL Configuration Low 16-bit word */
typedef	union _esr_ti_cfgpll_l {
	uint16_t value;

	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res2		: 6;
		uint16_t lb		: 2;
		uint16_t res1		: 3;
		uint16_t mpy		: 4;
		uint16_t enpll		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t enpll		: 1;
		uint16_t mpy		: 4;
		uint16_t res1		: 3;
		uint16_t lb		: 2;
		uint16_t res2		: 6;
#endif
	} bits;
} esr_ti_cfgpll_l_t;

/* PLL Configurations */
#define	CFGPLL_LB_FREQ_DEP_BANDWIDTH	0
#define	CFGPLL_LB_LOW_BANDWIDTH		0x2
#define	CFGPLL_LB_HIGH_BANDWIDTH	0x3
#define	CFGPLL_MPY_4X			0
#define	CFGPLL_MPY_5X			0x1
#define	CFGPLL_MPY_6X			0x2
#define	CFGPLL_MPY_8X			0x4
#define	CFGPLL_MPY_10X			0x5
#define	CFGPLL_MPY_12X			0x6
#define	CFGPLL_MPY_12P5X		0x7

/* Rx Configuration Low 16-bit word */

typedef	union _esr_ti_cfgrx_l {
	uint16_t value;

	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t los		: 2;
		uint16_t align		: 2;
		uint16_t res		: 1;
		uint16_t term		: 3;
		uint16_t invpair	: 1;
		uint16_t rate		: 2;
		uint16_t buswidth	: 3;
		uint16_t entest		: 1;
		uint16_t enrx		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t enrx		: 1;
		uint16_t entest		: 1;
		uint16_t buswidth	: 3;
		uint16_t rate		: 2;
		uint16_t invpair	: 1;
		uint16_t term		: 3;
		uint16_t res		: 1;
		uint16_t align		: 2;
		uint16_t los		: 2;
#endif
	} bits;
} esr_ti_cfgrx_l_t;

/* Rx Configuration High 16-bit word */

typedef	union _esr_ti_cfgrx_h {
	uint16_t value;

	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res2		: 6;
		uint16_t bsinrxn	: 1;
		uint16_t bsinrxp	: 1;
		uint16_t res1		: 1;
		uint16_t eq		: 4;
		uint16_t cdr		: 3;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t cdr		: 3;
		uint16_t eq		: 4;
		uint16_t res1		: 1;
		uint16_t bsinrxp	: 1;
		uint16_t bsinrxn	: 1;
		uint16_t res2		: 6;
#endif
	} bits;
} esr_ti_cfgrx_h_t;

/* Receive Configurations */
#define	CFGRX_BUSWIDTH_10BIT			0
#define	CFGRX_BUSWIDTH_8BIT			1
#define	CFGRX_RATE_FULL				0
#define	CFGRX_RATE_HALF				1
#define	CFGRX_RATE_QUAD				2
#define	CFGRX_TERM_VDDT				0
#define	CFGRX_TERM_0P8VDDT			1
#define	CFGRX_TERM_FLOAT			3
#define	CFGRX_ALIGN_DIS				0
#define	CFGRX_ALIGN_EN				1
#define	CFGRX_ALIGN_JOG				2
#define	CFGRX_LOS_DIS				0
#define	CFGRX_LOS_HITHRES			1
#define	CFGRX_LOS_LOTHRES			2
#define	CFGRX_CDR_1ST_ORDER			0
#define	CFGRX_CDR_2ND_ORDER_HP			1
#define	CFGRX_CDR_2ND_ORDER_MP			2
#define	CFGRX_CDR_2ND_ORDER_LP			3
#define	CFGRX_CDR_1ST_ORDER_FAST_LOCK		4
#define	CFGRX_CDR_2ND_ORDER_HP_FAST_LOCK	5
#define	CFGRX_CDR_2ND_ORDER_MP_FAST_LOCK	6
#define	CFGRX_CDR_2ND_ORDER_LP_FAST_LOCK	7
#define	CFGRX_EQ_MAX_LF				0
#define	CFGRX_EQ_ADAPTIVE_LP_ADAPTIVE_ZF	0x1
#define	CFGRX_EQ_ADAPTIVE_LF_1084MHZ_ZF		0x8
#define	CFGRX_EQ_ADAPTIVE_LF_805MHZ_ZF		0x9
#define	CFGRX_EQ_ADAPTIVE_LP_573MHZ_ZF		0xA
#define	CFGRX_EQ_ADAPTIVE_LP_402MHZ_ZF		0xB
#define	CFGRX_EQ_ADAPTIVE_LP_304MHZ_ZF		0xC
#define	CFGRX_EQ_ADAPTIVE_LP_216MHZ_ZF		0xD
#define	CFGRX_EQ_ADAPTIVE_LP_156MHZ_ZF		0xE
#define	CFGRX_EQ_ADAPTIVE_LP_135HZ_ZF		0xF

/* Rx Status Low 16-bit word */

typedef	union _esr_ti_stsrx_l {
	uint16_t value;

	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res		: 10;
		uint16_t bsrxn		: 1;
		uint16_t bsrxp		: 1;
		uint16_t losdtct	: 1;
		uint16_t oddcg		: 1;
		uint16_t sync		: 1;
		uint16_t testfail	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t testfail	: 1;
		uint16_t sync		: 1;
		uint16_t oddcg		: 1;
		uint16_t losdtct	: 1;
		uint16_t bsrxp		: 1;
		uint16_t bsrxn		: 1;
		uint16_t res		: 10;
#endif
	} bits;
} esr_ti_stsrx_l_t;

/* Tx Configuration Low 16-bit word */

typedef	union _esr_ti_cfgtx_l {
	uint16_t value;

	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t de		: 4;
		uint16_t swing		: 3;
		uint16_t cm		: 1;
		uint16_t invpair	: 1;
		uint16_t rate		: 2;
		uint16_t buswwidth	: 3;
		uint16_t entest		: 1;
		uint16_t entx		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t entx		: 1;
		uint16_t entest		: 1;
		uint16_t buswwidth	: 3;
		uint16_t rate		: 2;
		uint16_t invpair	: 1;
		uint16_t cm		: 1;
		uint16_t swing		: 3;
		uint16_t de		: 4;
#endif
	} bits;
} esr_ti_cfgtx_l_t;

/* Tx Configuration High 16-bit word */

typedef	union _esr_ti_cfgtx_h {
	uint16_t value;

	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res		: 14;
		uint16_t bstx		: 1;
		uint16_t enftp		: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t enftp		: 1;
		uint16_t bstx		: 1;
		uint16_t res		: 14;
#endif
	} bits;
} esr_ti_cfgtx_h_t;

/* Transmit Configurations */
#define	CFGTX_BUSWIDTH_10BIT		0
#define	CFGTX_BUSWIDTH_8BIT		1
#define	CFGTX_RATE_FULL			0
#define	CFGTX_RATE_HALF			1
#define	CFGTX_RATE_QUAD			2
#define	CFGTX_SWING_125MV		0
#define	CFGTX_SWING_250MV		1
#define	CFGTX_SWING_500MV		2
#define	CFGTX_SWING_625MV		3
#define	CFGTX_SWING_750MV		4
#define	CFGTX_SWING_1000MV		5
#define	CFGTX_SWING_1250MV		6
#define	CFGTX_SWING_1375MV		7
#define	CFGTX_DE_0			0
#define	CFGTX_DE_4P76			1
#define	CFGTX_DE_9P52			2
#define	CFGTX_DE_14P28			3
#define	CFGTX_DE_19P04			4
#define	CFGTX_DE_23P8			5
#define	CFGTX_DE_28P56			6
#define	CFGTX_DE_33P32			7

/* Test Configuration */

typedef	union _esr_ti_testcfg {
	uint16_t value;

	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint16_t res1		: 1;
		uint16_t invpat		: 1;
		uint16_t rate		: 2;
		uint16_t res		: 1;
		uint16_t enbspls	: 1;
		uint16_t enbsrx		: 1;
		uint16_t enbstx		: 1;
		uint16_t loopback	: 2;
		uint16_t clkbyp		: 2;
		uint16_t enrxpatt	: 1;
		uint16_t entxpatt	: 1;
		uint16_t testpatt	: 2;
#elif defined(_BIT_FIELDS_LTOH)
		uint16_t testpatt	: 2;
		uint16_t entxpatt	: 1;
		uint16_t enrxpatt	: 1;
		uint16_t clkbyp		: 2;
		uint16_t loopback	: 2;
		uint16_t enbstx		: 1;
		uint16_t enbsrx		: 1;
		uint16_t enbspls	: 1;
		uint16_t res		: 1;
		uint16_t rate		: 2;
		uint16_t invpat		: 1;
		uint16_t res1		: 1;
#endif
	} bits;
} esr_ti_testcfg_t;

#define	TESTCFG_PAD_LOOPBACK		0x1
#define	TESTCFG_INNER_CML_DIS_LOOPBACK	0x2
#define	TESTCFG_INNER_CML_EN_LOOOPBACK	0x3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_N2_ESR_HW_H */
