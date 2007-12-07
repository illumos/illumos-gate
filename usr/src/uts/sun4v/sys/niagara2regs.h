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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_NIAGARA2REGS_H
#define	_SYS_NIAGARA2REGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define	MB(n)	((n) * 1024 * 1024)

#define	L2CACHE_SIZE		MB(4)
#define	L2CACHE_LINESIZE	64
#define	L2CACHE_ASSOCIATIVITY	16

#define	NIAGARA2_HSVC_MAJOR	1
#define	NIAGARA2_HSVC_MINOR	0

#define	VFALLS_HSVC_MAJOR	1
#define	VFALLS_HSVC_MINOR	0

/* PIC overflow range is -16 to -1 */
#define	PIC_IN_OV_RANGE(x)	(((uint32_t)x >= 0xfffffff0) ? 1 : 0)

/*
 * Niagara2 SPARC Performance Instrumentation Counter
 */
#define	PIC0_MASK	(((uint64_t)1 << 32) - 1)	/* pic0 in bits 31:0 */
#define	PIC1_SHIFT	32				/* pic1 in bits 64:32 */

/*
 * Niagara2 SPARC Performance Control Register
 */
#define	CPC_NIAGARA2_PCR_PRIV_SHIFT	0
#define	CPC_NIAGARA2_PCR_ST_SHIFT	1
#define	CPC_NIAGARA2_PCR_UT_SHIFT	2

#define	CPC_NIAGARA2_PCR_HT_SHIFT	3
#define	CPC_NIAGARA2_PCR_HT		(1ull << CPC_NIAGARA2_PCR_HT_SHIFT)

#define	CPC_NIAGARA2_PCR_TOE0_SHIFT	4
#define	CPC_NIAGARA2_PCR_TOE1_SHIFT	5
#define	CPC_NIAGARA2_PCR_TOE0		(1ull << CPC_NIAGARA2_PCR_TOE0_SHIFT)
#define	CPC_NIAGARA2_PCR_TOE1		(1ull << CPC_NIAGARA2_PCR_TOE1_SHIFT)

#define	CPC_NIAGARA2_PCR_PIC0_SHIFT	6
#define	CPC_NIAGARA2_PCR_PIC1_SHIFT	19
#define	CPC_NIAGARA2_PCR_PIC0_MASK	UINT64_C(0xfff)
#define	CPC_NIAGARA2_PCR_PIC1_MASK	UINT64_C(0xfff)

#define	CPC_NIAGARA2_PCR_OV0_SHIFT	18
#define	CPC_NIAGARA2_PCR_OV1_SHIFT	30
#define	CPC_NIAGARA2_PCR_OV0_MASK	UINT64_C(0x40000)
#define	CPC_NIAGARA2_PCR_OV1_MASK	UINT64_C(0x80000000)

#define	CPC_NIAGARA2_PCR_HOLDOV0_SHIFT  62
#define	CPC_NIAGARA2_PCR_HOLDOV1_SHIFT  63
#define	CPC_NIAGARA2_PCR_HOLDOV0	(1ull << CPC_NIAGARA2_PCR_HOLDOV0_SHIFT)
#define	CPC_NIAGARA2_PCR_HOLDOV1	(1ull << CPC_NIAGARA2_PCR_HOLDOV1_SHIFT)

/*
 * Hypervisor FAST_TRAP API function numbers to get/set DRAM
 * performance counters for Niagara2
 */
#define	HV_NIAGARA2_GETPERF		0x104
#define	HV_NIAGARA2_SETPERF		0x105

/*
 * Hypervisor FAST_TRAP API function numbers to get/set DRAM
 * performance counters for Victoria Falls
 */
#define	HV_VFALLS_GETPERF		0x106
#define	HV_VFALLS_SETPERF		0x107

/*
 * Niagara2 DRAM performance counters
 */
#define	NIAGARA_DRAM_PIC0_SEL_SHIFT	0x4
#define	NIAGARA_DRAM_PIC1_SEL_SHIFT	0x0

#define	NIAGARA_DRAM_PIC0_SHIFT		0x20
#define	NIAGARA_DRAM_PIC0_MASK		0x7fffffff
#define	NIAGARA_DRAM_PIC1_SHIFT		0x0
#define	NIAGARA_DRAM_PIC1_MASK		0x7fffffff

#if defined(NIAGARA2_IMPL)
/*
 * SPARC/DRAM performance counter register numbers for HV_NIAGARA2_GETPERF
 * and HV_NIAGARA2_SETPERF for Niagara2
 */
#define	NIAGARA_DRAM_BANKS		0x4

#define	HV_NIAGARA_SPARC_CTL		0x0
#define	HV_NIAGARA_DRAM_CTL0		0x1
#define	HV_NIAGARA_DRAM_COUNT0		0x2
#define	HV_NIAGARA_DRAM_CTL1		0x3
#define	HV_NIAGARA_DRAM_COUNT1		0x4
#define	HV_NIAGARA_DRAM_CTL2		0x5
#define	HV_NIAGARA_DRAM_COUNT2		0x6
#define	HV_NIAGARA_DRAM_CTL3		0x7
#define	HV_NIAGARA_DRAM_COUNT3		0x8

#elif defined(VFALLS_IMPL)
/*
 * SPARC/DRAM performance counter register numbers for HV_VFALLS_GETPERF
 * and HV_VFALLS_SETPERF for Victoria Falls
 * Support for 4-node configuration
 */
#define	NIAGARA_DRAM_BANKS		0x8

#define	HV_NIAGARA_SPARC_CTL		0x0
#define	HV_NIAGARA_L2_CTL		0x1
#define	HV_NIAGARA_DRAM_CTL0		0x2
#define	HV_NIAGARA_DRAM_COUNT0		0x3
#define	HV_NIAGARA_DRAM_CTL1		0x4
#define	HV_NIAGARA_DRAM_COUNT1		0x5
#define	HV_NIAGARA_DRAM_CTL2		0x6
#define	HV_NIAGARA_DRAM_COUNT2		0x7
#define	HV_NIAGARA_DRAM_CTL3		0x8
#define	HV_NIAGARA_DRAM_COUNT3		0x9
#define	HV_NIAGARA_DRAM_CTL4		0xa
#define	HV_NIAGARA_DRAM_COUNT4		0xb
#define	HV_NIAGARA_DRAM_CTL5		0xc
#define	HV_NIAGARA_DRAM_COUNT5		0xd
#define	HV_NIAGARA_DRAM_CTL6		0xe
#define	HV_NIAGARA_DRAM_COUNT6		0xf
#define	HV_NIAGARA_DRAM_CTL7		0x10
#define	HV_NIAGARA_DRAM_COUNT7		0x11

#define	ZAMBEZI_PIC0_SEL_SHIFT		0x0
#define	ZAMBEZI_PIC1_SEL_SHIFT		0x8

#define	ZAMBEZI_LPU_COUNTERS		0x10
#define	ZAMBEZI_GPD_COUNTERS		0x4
#define	ZAMBEZI_ASU_COUNTERS		0x4

#define	HV_ZAM0_LPU_A_PCR		0x12
#define	HV_ZAM0_LPU_A_PIC0		0x13
#define	HV_ZAM0_LPU_A_PIC1		0x14
#define	HV_ZAM0_LPU_B_PCR		0x15
#define	HV_ZAM0_LPU_B_PIC0		0x16
#define	HV_ZAM0_LPU_B_PIC1		0x17
#define	HV_ZAM0_LPU_C_PCR		0x18
#define	HV_ZAM0_LPU_C_PIC0		0x19
#define	HV_ZAM0_LPU_C_PIC1		0x1a
#define	HV_ZAM0_LPU_D_PCR		0x1b
#define	HV_ZAM0_LPU_D_PIC0		0x1c
#define	HV_ZAM0_LPU_D_PIC1		0x1d
#define	HV_ZAM0_GPD_PCR			0x1e
#define	HV_ZAM0_GPD_PIC0		0x1f
#define	HV_ZAM0_GPD_PIC1		0x20
#define	HV_ZAM0_ASU_PCR			0x21
#define	HV_ZAM0_ASU_PIC0		0x22
#define	HV_ZAM0_ASU_PIC1		0x23

#define	HV_ZAM1_LPU_A_PCR		0x24
#define	HV_ZAM1_LPU_A_PIC0		0x25
#define	HV_ZAM1_LPU_A_PIC1		0x26
#define	HV_ZAM1_LPU_B_PCR		0x27
#define	HV_ZAM1_LPU_B_PIC0		0x28
#define	HV_ZAM1_LPU_B_PIC1		0x29
#define	HV_ZAM1_LPU_C_PCR		0x2a
#define	HV_ZAM1_LPU_C_PIC0		0x2b
#define	HV_ZAM1_LPU_C_PIC1		0x2c
#define	HV_ZAM1_LPU_D_PCR		0x2d
#define	HV_ZAM1_LPU_D_PIC0		0x2e
#define	HV_ZAM1_LPU_D_PIC1		0x2f
#define	HV_ZAM1_GPD_PCR			0x30
#define	HV_ZAM1_GPD_PIC0		0x31
#define	HV_ZAM1_GPD_PIC1		0x32
#define	HV_ZAM1_ASU_PCR			0x33
#define	HV_ZAM1_ASU_PIC0		0x34
#define	HV_ZAM1_ASU_PIC1		0x35

#define	HV_ZAM2_LPU_A_PCR		0x36
#define	HV_ZAM2_LPU_A_PIC0		0x37
#define	HV_ZAM2_LPU_A_PIC1		0x38
#define	HV_ZAM2_LPU_B_PCR		0x39
#define	HV_ZAM2_LPU_B_PIC0		0x3a
#define	HV_ZAM2_LPU_B_PIC1		0x3b
#define	HV_ZAM2_LPU_C_PCR		0x3c
#define	HV_ZAM2_LPU_C_PIC0		0x3d
#define	HV_ZAM2_LPU_C_PIC1		0x3e
#define	HV_ZAM2_LPU_D_PCR		0x3f
#define	HV_ZAM2_LPU_D_PIC0		0x40
#define	HV_ZAM2_LPU_D_PIC1		0x41
#define	HV_ZAM2_GPD_PCR			0x42
#define	HV_ZAM2_GPD_PIC0		0x43
#define	HV_ZAM2_GPD_PIC1		0x44
#define	HV_ZAM2_ASU_PCR			0x45
#define	HV_ZAM2_ASU_PIC0		0x46
#define	HV_ZAM2_ASU_PIC1		0x47

#define	HV_ZAM3_LPU_A_PCR		0x48
#define	HV_ZAM3_LPU_A_PIC0		0x49
#define	HV_ZAM3_LPU_A_PIC1		0x4a
#define	HV_ZAM3_LPU_B_PCR		0x4b
#define	HV_ZAM3_LPU_B_PIC0		0x4c
#define	HV_ZAM3_LPU_B_PIC1		0x4d
#define	HV_ZAM3_LPU_C_PCR		0x4e
#define	HV_ZAM3_LPU_C_PIC0		0x4f
#define	HV_ZAM3_LPU_C_PIC1		0x50
#define	HV_ZAM3_LPU_D_PCR		0x51
#define	HV_ZAM3_LPU_D_PIC0		0x52
#define	HV_ZAM3_LPU_D_PIC1		0x53
#define	HV_ZAM3_GPD_PCR			0x54
#define	HV_ZAM3_GPD_PIC0		0x55
#define	HV_ZAM3_GPD_PIC1		0x56
#define	HV_ZAM3_ASU_PCR			0x57
#define	HV_ZAM3_ASU_PIC0		0x58
#define	HV_ZAM3_ASU_PIC1		0x59

#define	VFALLS_L2_CTL_MASK		0x3
#define	VFALLS_SL3_MASK			0x300

#endif

#ifndef _ASM
/*
 * prototypes for hypervisor interface to get/set SPARC and DRAM
 * performance counters
 */
extern uint64_t hv_niagara_setperf(uint64_t regnum, uint64_t val);
extern uint64_t hv_niagara_getperf(uint64_t regnum, uint64_t *val);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NIAGARA2REGS_H */
