/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_NIAGARAREGS_H
#define	_SYS_NIAGARAREGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Niagara SPARC Performance Instrumentation Counter
 */
#define	PIC0_MASK (((uint64_t)1 << 32) - 1)	/* pic0 in bits 31:0 */
#define	PIC1_SHIFT 32				/* pic1 in bits 64:32 */

/*
 * Niagara SPARC Performance Control Register
 */

#define	CPC_NIAGARA_PCR_PRIVPIC		0
#define	CPC_NIAGARA_PCR_SYS		1
#define	CPC_NIAGARA_PCR_USR		2

#define	CPC_NIAGARA_PCR_PIC0_SHIFT	4
#define	CPC_NIAGARA_PCR_PIC1_SHIFT	0
#define	CPC_NIAGARA_PCR_PIC0_MASK	UINT64_C(0x7)
#define	CPC_NIAGARA_PCR_PIC1_MASK	UINT64_C(0)

#define	CPC_NIAGARA_PCR_OVF_MASK	UINT64_C(0x300)
#define	CPC_NIAGARA_PCR_OVF_SHIFT	8

/*
 * Niagara DRAM performance counters
 */
#define	NIAGARA_DRAM_BANKS		0x4

#define	NIAGARA_DRAM_PIC0_SEL_SHIFT	0x4
#define	NIAGARA_DRAM_PIC1_SEL_SHIFT	0x0

#define	NIAGARA_DRAM_PIC0_SHIFT		0x20
#define	NIAGARA_DRAM_PIC0_MASK		0x7fffffff
#define	NIAGARA_DRAM_PIC1_SHIFT		0x0
#define	NIAGARA_DRAM_PIC1_MASK		0x7fffffff

/*
 * Niagara JBUS performance counters
 */
#define	NIAGARA_JBUS_PIC0_SEL_SHIFT	0x4
#define	NIAGARA_JBUS_PIC1_SEL_SHIFT	0x0

#define	NIAGARA_JBUS_PIC0_SHIFT		0x20
#define	NIAGARA_JBUS_PIC0_MASK		0x7fffffff
#define	NIAGARA_JBUS_PIC1_SHIFT		0x0
#define	NIAGARA_JBUS_PIC1_MASK		0x7fffffff


/*
 * Hypervisor FAST_TRAP API function numbers to get/set DRAM and
 * JBUS performance counters
 */
#define	HV_NIAGARA_GETPERF	0x100
#define	HV_NIAGARA_SETPERF	0x101


/*
 * DRAM/JBUS performance counter register numbers for HV_NIAGARA_GETPERF
 * and HV_NIAGARA_SETPERF
 */
#define	HV_NIAGARA_JBUS_CTL		0x0
#define	HV_NIAGARA_JBUS_COUNT		0x1
#define	HV_NIAGARA_DRAM_CTL0		0x2
#define	HV_NIAGARA_DRAM_COUNT0		0x3
#define	HV_NIAGARA_DRAM_CTL1		0x4
#define	HV_NIAGARA_DRAM_COUNT1		0x5
#define	HV_NIAGARA_DRAM_CTL2		0x6
#define	HV_NIAGARA_DRAM_COUNT2		0x7
#define	HV_NIAGARA_DRAM_CTL3		0x8
#define	HV_NIAGARA_DRAM_COUNT3		0x9

/*
 * prototypes for hypervisor interface to get/set DRAM and JBUS
 * performance counters
 */
#ifndef _ASM
extern uint64_t hv_niagara_setperf(uint64_t regnum, uint64_t val);
extern uint64_t hv_niagara_getperf(uint64_t regnum, uint64_t *val);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NIAGARAREGS_H */
