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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MCA_X86_H
#define	_SYS_MCA_X86_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Constants for the Memory Check Architecture as implemented on generic x86
 * CPUs.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Intel has defined a number of MSRs as part of the IA32 architecture.  The
 * MCG registers are part of that set, as are the first four banks (0-3) as
 * implemented by the P4 processor.  Bank MSRs were laid out slightly
 * differently on the P6 family of processors, and thus have their own #defines
 * following the architecture-generic ones.
 */
#define	IA32_MSR_MCG_CAP		0x179
#define	IA32_MSR_MCG_STATUS		0x17a
#define	IA32_MSR_MCG_CTL		0x17b

#define	MCG_CAP_COUNT_MASK		0x000000ffULL
#define	MCG_CAP_CTL_P			0x00000100ULL
#define	MCG_CAP_EXT_P			0x00000200ULL
#define	MCG_CAP_EXT_CNT_MASK		0x00ff0000ULL
#define	MCG_CAP_EXT_CNT_SHIFT		16

#define	MCG_STATUS_RIPV			0x01
#define	MCG_STATUS_EIPV			0x02
#define	MCG_STATUS_MCIP			0x04

#define	IA32_MSR_MC0_CTL		0x400
#define	IA32_MSR_MC0_STATUS		0x401
#define	IA32_MSR_MC0_ADDR		0x402
#define	IA32_MSR_MC0_MISC		0x403

#define	IA32_MSR_MC1_CTL		0x404
#define	IA32_MSR_MC1_STATUS		0x405
#define	IA32_MSR_MC1_ADDR		0x406
#define	IA32_MSR_MC1_MISC		0x407

#define	IA32_MSR_MC2_CTL		0x408
#define	IA32_MSR_MC2_STATUS		0x409
#define	IA32_MSR_MC2_ADDR		0x40a
#define	IA32_MSR_MC2_MISC		0x40b

#define	IA32_MSR_MC3_CTL		0x40c
#define	IA32_MSR_MC3_STATUS		0x40d
#define	IA32_MSR_MC3_ADDR		0x40e
#define	IA32_MSR_MC3_MISC		0x40f

#define	MSR_MC_STATUS_VAL		0x8000000000000000ULL
#define	MSR_MC_STATUS_O			0x4000000000000000ULL
#define	MSR_MC_STATUS_UC		0x2000000000000000ULL
#define	MSR_MC_STATUS_EN		0x1000000000000000ULL
#define	MSR_MC_STATUS_MISCV		0x0800000000000000ULL
#define	MSR_MC_STATUS_ADDRV		0x0400000000000000ULL
#define	MSR_MC_STATUS_PCC		0x0200000000000000ULL
#define	MSR_MC_STATUS_OTHER_MASK	0x01ffffff00000000ULL
#define	MSR_MC_STATUS_OTHER_SHIFT	32
#define	MSR_MC_STATUS_MSERR_MASK	0x00000000ffff0000ULL
#define	MSR_MC_STATUS_MSERR_SHIFT	16
#define	MSR_MC_STATUS_MCAERR_MASK	0x000000000000ffffULL

/*
 * P6 MCA bank MSRs.  Note that the ordering is 0, 1, 2, *4*, 3.  Yes, really.
 */
#define	P6_MSR_MC0_CTL			0x400
#define	P6_MSR_MC0_STATUS		0x401
#define	P6_MSR_MC0_ADDR			0x402
#define	P6_MSR_MC0_MISC			0x403

#define	P6_MSR_MC1_CTL			0x404
#define	P6_MSR_MC1_STATUS		0x405
#define	P6_MSR_MC1_ADDR			0x406
#define	P6_MSR_MC1_MISC			0x407

#define	P6_MSR_MC2_CTL			0x408
#define	P6_MSR_MC2_STATUS		0x409
#define	P6_MSR_MC2_ADDR			0x40a
#define	P6_MSR_MC2_MISC			0x40b

#define	P6_MSR_MC4_CTL			0x40c
#define	P6_MSR_MC4_STATUS		0x40d
#define	P6_MSR_MC4_ADDR			0x40e
#define	P6_MSR_MC4_MISC			0x40f

#define	P6_MSR_MC3_CTL			0x410
#define	P6_MSR_MC3_STATUS		0x411
#define	P6_MSR_MC3_ADDR			0x412
#define	P6_MSR_MC3_MISC			0x413

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MCA_X86_H */
