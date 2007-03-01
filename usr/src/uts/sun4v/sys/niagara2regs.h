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
 * performance counters
 */
#define	HV_NIAGARA2_GETPERF		0x104
#define	HV_NIAGARA2_SETPERF		0x105

/*
 * Niagara2 DRAM performance counters
 */
#define	NIAGARA_DRAM_BANKS		0x4

#define	NIAGARA_DRAM_PIC0_SEL_SHIFT	0x4
#define	NIAGARA_DRAM_PIC1_SEL_SHIFT	0x0

#define	NIAGARA_DRAM_PIC0_SHIFT		0x20
#define	NIAGARA_DRAM_PIC0_MASK		0x7fffffff
#define	NIAGARA_DRAM_PIC1_SHIFT		0x0
#define	NIAGARA_DRAM_PIC1_MASK		0x7fffffff

/*
 * SPARC/DRAM performance counter register numbers for HV_NIAGARA2_GETPERF
 * and HV_NIAGARA2_SETPERF
 */
#define	HV_NIAGARA_SPARC_CTL		0x0
#define	HV_NIAGARA_DRAM_CTL0		0x1
#define	HV_NIAGARA_DRAM_COUNT0		0x2
#define	HV_NIAGARA_DRAM_CTL1		0x3
#define	HV_NIAGARA_DRAM_COUNT1		0x4
#define	HV_NIAGARA_DRAM_CTL2		0x5
#define	HV_NIAGARA_DRAM_COUNT2		0x6
#define	HV_NIAGARA_DRAM_CTL3		0x7
#define	HV_NIAGARA_DRAM_COUNT3		0x8

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
