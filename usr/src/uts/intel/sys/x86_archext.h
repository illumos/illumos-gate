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
 * Copyright (c) 1995, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 by Delphix. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2018 Joyent, Inc.
 * Copyright 2012 Jens Elkner <jel+illumos@cs.uni-magdeburg.de>
 * Copyright 2012 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 * Copyright 2014 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 * Copyright 2018 Nexenta Systems, Inc.
 */

#ifndef _SYS_X86_ARCHEXT_H
#define	_SYS_X86_ARCHEXT_H

#if !defined(_ASM)
#include <sys/regset.h>
#include <sys/processor.h>
#include <vm/seg_enum.h>
#include <vm/page.h>
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * cpuid instruction feature flags in %edx (standard function 1)
 */

#define	CPUID_INTC_EDX_FPU	0x00000001	/* x87 fpu present */
#define	CPUID_INTC_EDX_VME	0x00000002	/* virtual-8086 extension */
#define	CPUID_INTC_EDX_DE	0x00000004	/* debugging extensions */
#define	CPUID_INTC_EDX_PSE	0x00000008	/* page size extension */
#define	CPUID_INTC_EDX_TSC	0x00000010	/* time stamp counter */
#define	CPUID_INTC_EDX_MSR	0x00000020	/* rdmsr and wrmsr */
#define	CPUID_INTC_EDX_PAE	0x00000040	/* physical addr extension */
#define	CPUID_INTC_EDX_MCE	0x00000080	/* machine check exception */
#define	CPUID_INTC_EDX_CX8	0x00000100	/* cmpxchg8b instruction */
#define	CPUID_INTC_EDX_APIC	0x00000200	/* local APIC */
						/* 0x400 - reserved */
#define	CPUID_INTC_EDX_SEP	0x00000800	/* sysenter and sysexit */
#define	CPUID_INTC_EDX_MTRR	0x00001000	/* memory type range reg */
#define	CPUID_INTC_EDX_PGE	0x00002000	/* page global enable */
#define	CPUID_INTC_EDX_MCA	0x00004000	/* machine check arch */
#define	CPUID_INTC_EDX_CMOV	0x00008000	/* conditional move insns */
#define	CPUID_INTC_EDX_PAT	0x00010000	/* page attribute table */
#define	CPUID_INTC_EDX_PSE36	0x00020000	/* 36-bit pagesize extension */
#define	CPUID_INTC_EDX_PSN	0x00040000	/* processor serial number */
#define	CPUID_INTC_EDX_CLFSH	0x00080000	/* clflush instruction */
						/* 0x100000 - reserved */
#define	CPUID_INTC_EDX_DS	0x00200000	/* debug store exists */
#define	CPUID_INTC_EDX_ACPI	0x00400000	/* monitoring + clock ctrl */
#define	CPUID_INTC_EDX_MMX	0x00800000	/* MMX instructions */
#define	CPUID_INTC_EDX_FXSR	0x01000000	/* fxsave and fxrstor */
#define	CPUID_INTC_EDX_SSE	0x02000000	/* streaming SIMD extensions */
#define	CPUID_INTC_EDX_SSE2	0x04000000	/* SSE extensions */
#define	CPUID_INTC_EDX_SS	0x08000000	/* self-snoop */
#define	CPUID_INTC_EDX_HTT	0x10000000	/* Hyper Thread Technology */
#define	CPUID_INTC_EDX_TM	0x20000000	/* thermal monitoring */
#define	CPUID_INTC_EDX_IA64	0x40000000	/* Itanium emulating IA32 */
#define	CPUID_INTC_EDX_PBE	0x80000000	/* Pending Break Enable */

/*
 * cpuid instruction feature flags in %ecx (standard function 1)
 */

#define	CPUID_INTC_ECX_SSE3	0x00000001	/* Yet more SSE extensions */
#define	CPUID_INTC_ECX_PCLMULQDQ 0x00000002 	/* PCLMULQDQ insn */
#define	CPUID_INTC_ECX_DTES64	0x00000004	/* 64-bit DS area */
#define	CPUID_INTC_ECX_MON	0x00000008	/* MONITOR/MWAIT */
#define	CPUID_INTC_ECX_DSCPL	0x00000010	/* CPL-qualified debug store */
#define	CPUID_INTC_ECX_VMX	0x00000020	/* Hardware VM extensions */
#define	CPUID_INTC_ECX_SMX	0x00000040	/* Secure mode extensions */
#define	CPUID_INTC_ECX_EST	0x00000080	/* enhanced SpeedStep */
#define	CPUID_INTC_ECX_TM2	0x00000100	/* thermal monitoring */
#define	CPUID_INTC_ECX_SSSE3	0x00000200	/* Supplemental SSE3 insns */
#define	CPUID_INTC_ECX_CID	0x00000400	/* L1 context ID */
						/* 0x00000800 - reserved */
#define	CPUID_INTC_ECX_FMA	0x00001000	/* Fused Multiply Add */
#define	CPUID_INTC_ECX_CX16	0x00002000	/* cmpxchg16 */
#define	CPUID_INTC_ECX_ETPRD	0x00004000	/* extended task pri messages */
#define	CPUID_INTC_ECX_PDCM	0x00008000	/* Perf/Debug Capability MSR */
						/* 0x00010000 - reserved */
#define	CPUID_INTC_ECX_PCID	0x00020000	/* process-context ids */
#define	CPUID_INTC_ECX_DCA	0x00040000	/* direct cache access */
#define	CPUID_INTC_ECX_SSE4_1	0x00080000	/* SSE4.1 insns */
#define	CPUID_INTC_ECX_SSE4_2	0x00100000	/* SSE4.2 insns */
#define	CPUID_INTC_ECX_X2APIC	0x00200000	/* x2APIC */
#define	CPUID_INTC_ECX_MOVBE	0x00400000	/* MOVBE insn */
#define	CPUID_INTC_ECX_POPCNT	0x00800000	/* POPCNT insn */
#define	CPUID_INTC_ECX_TSCDL	0x01000000	/* Deadline TSC */
#define	CPUID_INTC_ECX_AES	0x02000000	/* AES insns */
#define	CPUID_INTC_ECX_XSAVE	0x04000000	/* XSAVE/XRESTOR insns */
#define	CPUID_INTC_ECX_OSXSAVE	0x08000000	/* OS supports XSAVE insns */
#define	CPUID_INTC_ECX_AVX	0x10000000	/* AVX supported */
#define	CPUID_INTC_ECX_F16C	0x20000000	/* F16C supported */
#define	CPUID_INTC_ECX_RDRAND	0x40000000	/* RDRAND supported */
#define	CPUID_INTC_ECX_HV	0x80000000	/* Hypervisor */

/*
 * cpuid instruction feature flags in %edx (extended function 0x80000001)
 */

#define	CPUID_AMD_EDX_FPU	0x00000001	/* x87 fpu present */
#define	CPUID_AMD_EDX_VME	0x00000002	/* virtual-8086 extension */
#define	CPUID_AMD_EDX_DE	0x00000004	/* debugging extensions */
#define	CPUID_AMD_EDX_PSE	0x00000008	/* page size extensions */
#define	CPUID_AMD_EDX_TSC	0x00000010	/* time stamp counter */
#define	CPUID_AMD_EDX_MSR	0x00000020	/* rdmsr and wrmsr */
#define	CPUID_AMD_EDX_PAE	0x00000040	/* physical addr extension */
#define	CPUID_AMD_EDX_MCE	0x00000080	/* machine check exception */
#define	CPUID_AMD_EDX_CX8	0x00000100	/* cmpxchg8b instruction */
#define	CPUID_AMD_EDX_APIC	0x00000200	/* local APIC */
						/* 0x00000400 - sysc on K6m6 */
#define	CPUID_AMD_EDX_SYSC	0x00000800	/* AMD: syscall and sysret */
#define	CPUID_AMD_EDX_MTRR	0x00001000	/* memory type and range reg */
#define	CPUID_AMD_EDX_PGE	0x00002000	/* page global enable */
#define	CPUID_AMD_EDX_MCA	0x00004000	/* machine check arch */
#define	CPUID_AMD_EDX_CMOV	0x00008000	/* conditional move insns */
#define	CPUID_AMD_EDX_PAT	0x00010000	/* K7: page attribute table */
#define	CPUID_AMD_EDX_FCMOV	0x00010000	/* FCMOVcc etc. */
#define	CPUID_AMD_EDX_PSE36	0x00020000	/* 36-bit pagesize extension */
				/* 0x00040000 - reserved */
				/* 0x00080000 - reserved */
#define	CPUID_AMD_EDX_NX	0x00100000	/* AMD: no-execute page prot */
				/* 0x00200000 - reserved */
#define	CPUID_AMD_EDX_MMXamd	0x00400000	/* AMD: MMX extensions */
#define	CPUID_AMD_EDX_MMX	0x00800000	/* MMX instructions */
#define	CPUID_AMD_EDX_FXSR	0x01000000	/* fxsave and fxrstor */
#define	CPUID_AMD_EDX_FFXSR	0x02000000	/* fast fxsave/fxrstor */
#define	CPUID_AMD_EDX_1GPG	0x04000000	/* 1GB page */
#define	CPUID_AMD_EDX_TSCP	0x08000000	/* rdtscp instruction */
				/* 0x10000000 - reserved */
#define	CPUID_AMD_EDX_LM	0x20000000	/* AMD: long mode */
#define	CPUID_AMD_EDX_3DNowx	0x40000000	/* AMD: extensions to 3DNow! */
#define	CPUID_AMD_EDX_3DNow	0x80000000	/* AMD: 3DNow! instructions */

#define	CPUID_AMD_ECX_AHF64	0x00000001	/* LAHF and SAHF in long mode */
#define	CPUID_AMD_ECX_CMP_LGCY	0x00000002	/* AMD: multicore chip */
#define	CPUID_AMD_ECX_SVM	0x00000004	/* AMD: secure VM */
#define	CPUID_AMD_ECX_EAS	0x00000008	/* extended apic space */
#define	CPUID_AMD_ECX_CR8D	0x00000010	/* AMD: 32-bit mov %cr8 */
#define	CPUID_AMD_ECX_LZCNT	0x00000020	/* AMD: LZCNT insn */
#define	CPUID_AMD_ECX_SSE4A	0x00000040	/* AMD: SSE4A insns */
#define	CPUID_AMD_ECX_MAS	0x00000080	/* AMD: MisAlignSse mnode */
#define	CPUID_AMD_ECX_3DNP	0x00000100	/* AMD: 3DNowPrefectch */
#define	CPUID_AMD_ECX_OSVW	0x00000200	/* AMD: OSVW */
#define	CPUID_AMD_ECX_IBS	0x00000400	/* AMD: IBS */
#define	CPUID_AMD_ECX_SSE5	0x00000800	/* AMD: Extended AVX */
#define	CPUID_AMD_ECX_SKINIT	0x00001000	/* AMD: SKINIT */
#define	CPUID_AMD_ECX_WDT	0x00002000	/* AMD: WDT */
				/* 0x00004000 - reserved */
#define	CPUID_AMD_ECX_LWP	0x00008000	/* AMD: Lightweight profiling */
#define	CPUID_AMD_ECX_FMA4	0x00010000	/* AMD: 4-operand FMA support */
				/* 0x00020000 - reserved */
				/* 0x00040000 - reserved */
#define	CPUID_AMD_ECX_NIDMSR	0x00080000	/* AMD: Node ID MSR */
				/* 0x00100000 - reserved */
#define	CPUID_AMD_ECX_TBM	0x00200000	/* AMD: trailing bit manips. */
#define	CPUID_AMD_ECX_TOPOEXT	0x00400000	/* AMD: Topology Extensions */

/*
 * AMD uses %ebx for some of their features (extended function 0x80000008).
 */
#define	CPUID_AMD_EBX_ERR_PTR_ZERO	0x00000004 /* AMD: FP Err. Ptr. Zero */

/*
 * Intel now seems to have claimed part of the "extended" function
 * space that we previously for non-Intel implementors to use.
 * More excitingly still, they've claimed bit 20 to mean LAHF/SAHF
 * is available in long mode i.e. what AMD indicate using bit 0.
 * On the other hand, everything else is labelled as reserved.
 */
#define	CPUID_INTC_ECX_AHF64	0x00100000	/* LAHF and SAHF in long mode */

/*
 * Intel also uses cpuid leaf 7 to have additional instructions and features.
 * Like some other leaves, but unlike the current ones we care about, it
 * requires us to specify both a leaf in %eax and a sub-leaf in %ecx. To deal
 * with the potential use of additional sub-leaves in the future, we now
 * specifically label the EBX features with their leaf and sub-leaf.
 */
#define	CPUID_INTC_EBX_7_0_BMI1		0x00000008	/* BMI1 instrs */
#define	CPUID_INTC_EBX_7_0_HLE		0x00000010	/* HLE */
#define	CPUID_INTC_EBX_7_0_AVX2		0x00000020	/* AVX2 supported */
#define	CPUID_INTC_EBX_7_0_SMEP		0x00000080	/* SMEP in CR4 */
#define	CPUID_INTC_EBX_7_0_BMI2		0x00000100	/* BMI2 instrs */
#define	CPUID_INTC_EBX_7_0_INVPCID	0x00000400	/* invpcid instr */
#define	CPUID_INTC_EBX_7_0_MPX		0x00004000	/* Mem. Prot. Ext. */
#define	CPUID_INTC_EBX_7_0_AVX512F	0x00010000	/* AVX512 foundation */
#define	CPUID_INTC_EBX_7_0_AVX512DQ	0x00020000	/* AVX512DQ */
#define	CPUID_INTC_EBX_7_0_RDSEED	0x00040000	/* RDSEED instr */
#define	CPUID_INTC_EBX_7_0_ADX		0x00080000	/* ADX instrs */
#define	CPUID_INTC_EBX_7_0_SMAP		0x00100000	/* SMAP in CR 4 */
#define	CPUID_INTC_EBX_7_0_AVX512IFMA	0x00200000	/* AVX512IFMA */
#define	CPUID_INTC_EBX_7_0_CLWB		0x01000000	/* CLWB */
#define	CPUID_INTC_EBX_7_0_AVX512PF	0x04000000	/* AVX512PF */
#define	CPUID_INTC_EBX_7_0_AVX512ER	0x08000000	/* AVX512ER */
#define	CPUID_INTC_EBX_7_0_AVX512CD	0x10000000	/* AVX512CD */
#define	CPUID_INTC_EBX_7_0_SHA		0x20000000	/* SHA extensions */
#define	CPUID_INTC_EBX_7_0_AVX512BW	0x40000000	/* AVX512BW */
#define	CPUID_INTC_EBX_7_0_AVX512VL	0x80000000	/* AVX512VL */

#define	CPUID_INTC_EBX_7_0_ALL_AVX512 \
	(CPUID_INTC_EBX_7_0_AVX512F | CPUID_INTC_EBX_7_0_AVX512DQ | \
	CPUID_INTC_EBX_7_0_AVX512IFMA | CPUID_INTC_EBX_7_0_AVX512PF | \
	CPUID_INTC_EBX_7_0_AVX512ER | CPUID_INTC_EBX_7_0_AVX512CD | \
	CPUID_INTC_EBX_7_0_AVX512BW | CPUID_INTC_EBX_7_0_AVX512VL)

#define	CPUID_INTC_ECX_7_0_AVX512VBMI	0x00000002	/* AVX512VBMI */
#define	CPUID_INTC_ECX_7_0_UMIP		0x00000004	/* UMIP */
#define	CPUID_INTC_ECX_7_0_PKU		0x00000008	/* umode prot. keys */
#define	CPUID_INTC_ECX_7_0_OSPKE	0x00000010	/* OSPKE */
#define	CPUID_INTC_ECX_7_0_AVX512VPOPCDQ 0x00004000	/* AVX512 VPOPCNTDQ */

#define	CPUID_INTC_ECX_7_0_ALL_AVX512 \
	(CPUID_INTC_ECX_7_0_AVX512VBMI | CPUID_INTC_ECX_7_0_AVX512VPOPCDQ)

#define	CPUID_INTC_EDX_7_0_AVX5124NNIW	0x00000004	/* AVX512 4NNIW */
#define	CPUID_INTC_EDX_7_0_AVX5124FMAPS	0x00000008	/* AVX512 4FMAPS */

#define	CPUID_INTC_EDX_7_0_ALL_AVX512 \
	(CPUID_INTC_EDX_7_0_AVX5124NNIW | CPUID_INTC_EDX_7_0_AVX5124FMAPS)

/*
 * Intel also uses cpuid leaf 0xd to report additional instructions and features
 * when the sub-leaf in %ecx == 1. We label these using the same convention as
 * with leaf 7.
 */
#define	CPUID_INTC_EAX_D_1_XSAVEOPT	0x00000001	/* xsaveopt inst. */
#define	CPUID_INTC_EAX_D_1_XSAVEC	0x00000002	/* xsavec inst. */
#define	CPUID_INTC_EAX_D_1_XSAVES	0x00000008	/* xsaves inst. */

#define	REG_PAT			0x277
#define	REG_TSC			0x10	/* timestamp counter */
#define	REG_APIC_BASE_MSR	0x1b
#define	REG_X2APIC_BASE_MSR	0x800	/* The MSR address offset of x2APIC */

#if !defined(__xpv)
/*
 * AMD C1E
 */
#define	MSR_AMD_INT_PENDING_CMP_HALT	0xC0010055
#define	AMD_ACTONCMPHALT_SHIFT	27
#define	AMD_ACTONCMPHALT_MASK	3
#endif

#define	MSR_DEBUGCTL		0x1d9

#define	DEBUGCTL_LBR		0x01
#define	DEBUGCTL_BTF		0x02

/* Intel P6, AMD */
#define	MSR_LBR_FROM		0x1db
#define	MSR_LBR_TO		0x1dc
#define	MSR_LEX_FROM		0x1dd
#define	MSR_LEX_TO		0x1de

/* Intel P4 (pre-Prescott, non P4 M) */
#define	MSR_P4_LBSTK_TOS	0x1da
#define	MSR_P4_LBSTK_0		0x1db
#define	MSR_P4_LBSTK_1		0x1dc
#define	MSR_P4_LBSTK_2		0x1dd
#define	MSR_P4_LBSTK_3		0x1de

/* Intel Pentium M */
#define	MSR_P6M_LBSTK_TOS	0x1c9
#define	MSR_P6M_LBSTK_0		0x040
#define	MSR_P6M_LBSTK_1		0x041
#define	MSR_P6M_LBSTK_2		0x042
#define	MSR_P6M_LBSTK_3		0x043
#define	MSR_P6M_LBSTK_4		0x044
#define	MSR_P6M_LBSTK_5		0x045
#define	MSR_P6M_LBSTK_6		0x046
#define	MSR_P6M_LBSTK_7		0x047

/* Intel P4 (Prescott) */
#define	MSR_PRP4_LBSTK_TOS	0x1da
#define	MSR_PRP4_LBSTK_FROM_0	0x680
#define	MSR_PRP4_LBSTK_FROM_1	0x681
#define	MSR_PRP4_LBSTK_FROM_2	0x682
#define	MSR_PRP4_LBSTK_FROM_3	0x683
#define	MSR_PRP4_LBSTK_FROM_4	0x684
#define	MSR_PRP4_LBSTK_FROM_5	0x685
#define	MSR_PRP4_LBSTK_FROM_6	0x686
#define	MSR_PRP4_LBSTK_FROM_7	0x687
#define	MSR_PRP4_LBSTK_FROM_8 	0x688
#define	MSR_PRP4_LBSTK_FROM_9	0x689
#define	MSR_PRP4_LBSTK_FROM_10	0x68a
#define	MSR_PRP4_LBSTK_FROM_11 	0x68b
#define	MSR_PRP4_LBSTK_FROM_12	0x68c
#define	MSR_PRP4_LBSTK_FROM_13	0x68d
#define	MSR_PRP4_LBSTK_FROM_14	0x68e
#define	MSR_PRP4_LBSTK_FROM_15	0x68f
#define	MSR_PRP4_LBSTK_TO_0	0x6c0
#define	MSR_PRP4_LBSTK_TO_1	0x6c1
#define	MSR_PRP4_LBSTK_TO_2	0x6c2
#define	MSR_PRP4_LBSTK_TO_3	0x6c3
#define	MSR_PRP4_LBSTK_TO_4	0x6c4
#define	MSR_PRP4_LBSTK_TO_5	0x6c5
#define	MSR_PRP4_LBSTK_TO_6	0x6c6
#define	MSR_PRP4_LBSTK_TO_7	0x6c7
#define	MSR_PRP4_LBSTK_TO_8	0x6c8
#define	MSR_PRP4_LBSTK_TO_9 	0x6c9
#define	MSR_PRP4_LBSTK_TO_10	0x6ca
#define	MSR_PRP4_LBSTK_TO_11	0x6cb
#define	MSR_PRP4_LBSTK_TO_12	0x6cc
#define	MSR_PRP4_LBSTK_TO_13	0x6cd
#define	MSR_PRP4_LBSTK_TO_14	0x6ce
#define	MSR_PRP4_LBSTK_TO_15	0x6cf

#define	MCI_CTL_VALUE		0xffffffff

#define	MTRR_TYPE_UC		0
#define	MTRR_TYPE_WC		1
#define	MTRR_TYPE_WT		4
#define	MTRR_TYPE_WP		5
#define	MTRR_TYPE_WB		6
#define	MTRR_TYPE_UC_		7

/*
 * For Solaris we set up the page attritubute table in the following way:
 * PAT0	Write-Back
 * PAT1	Write-Through
 * PAT2	Unchacheable-
 * PAT3	Uncacheable
 * PAT4 Write-Back
 * PAT5	Write-Through
 * PAT6	Write-Combine
 * PAT7 Uncacheable
 * The only difference from h/w default is entry 6.
 */
#define	PAT_DEFAULT_ATTRIBUTE			\
	((uint64_t)MTRR_TYPE_WB |		\
	((uint64_t)MTRR_TYPE_WT << 8) |		\
	((uint64_t)MTRR_TYPE_UC_ << 16) |	\
	((uint64_t)MTRR_TYPE_UC << 24) |	\
	((uint64_t)MTRR_TYPE_WB << 32) |	\
	((uint64_t)MTRR_TYPE_WT << 40) |	\
	((uint64_t)MTRR_TYPE_WC << 48) |	\
	((uint64_t)MTRR_TYPE_UC << 56))

#define	X86FSET_LARGEPAGE	0
#define	X86FSET_TSC		1
#define	X86FSET_MSR		2
#define	X86FSET_MTRR		3
#define	X86FSET_PGE		4
#define	X86FSET_DE		5
#define	X86FSET_CMOV		6
#define	X86FSET_MMX		7
#define	X86FSET_MCA		8
#define	X86FSET_PAE		9
#define	X86FSET_CX8		10
#define	X86FSET_PAT		11
#define	X86FSET_SEP		12
#define	X86FSET_SSE		13
#define	X86FSET_SSE2		14
#define	X86FSET_HTT		15
#define	X86FSET_ASYSC		16
#define	X86FSET_NX		17
#define	X86FSET_SSE3		18
#define	X86FSET_CX16		19
#define	X86FSET_CMP		20
#define	X86FSET_TSCP		21
#define	X86FSET_MWAIT		22
#define	X86FSET_SSE4A		23
#define	X86FSET_CPUID		24
#define	X86FSET_SSSE3		25
#define	X86FSET_SSE4_1		26
#define	X86FSET_SSE4_2		27
#define	X86FSET_1GPG		28
#define	X86FSET_CLFSH		29
#define	X86FSET_64		30
#define	X86FSET_AES		31
#define	X86FSET_PCLMULQDQ	32
#define	X86FSET_XSAVE		33
#define	X86FSET_AVX		34
#define	X86FSET_VMX		35
#define	X86FSET_SVM		36
#define	X86FSET_TOPOEXT		37
#define	X86FSET_F16C		38
#define	X86FSET_RDRAND		39
#define	X86FSET_X2APIC		40
#define	X86FSET_AVX2		41
#define	X86FSET_BMI1		42
#define	X86FSET_BMI2		43
#define	X86FSET_FMA		44
#define	X86FSET_SMEP		45
#define	X86FSET_SMAP		46
#define	X86FSET_ADX		47
#define	X86FSET_RDSEED		48
#define	X86FSET_MPX		49
#define	X86FSET_AVX512F		50
#define	X86FSET_AVX512DQ	51
#define	X86FSET_AVX512PF	52
#define	X86FSET_AVX512ER	53
#define	X86FSET_AVX512CD	54
#define	X86FSET_AVX512BW	55
#define	X86FSET_AVX512VL	56
#define	X86FSET_AVX512FMA	57
#define	X86FSET_AVX512VBMI	58
#define	X86FSET_AVX512VPOPCDQ	59
#define	X86FSET_AVX512NNIW	60
#define	X86FSET_AVX512FMAPS	61
#define	X86FSET_XSAVEOPT	62
#define	X86FSET_XSAVEC		63
#define	X86FSET_XSAVES		64
#define	X86FSET_SHA		65
#define	X86FSET_UMIP		66
#define	X86FSET_PKU		67
#define	X86FSET_OSPKE		68
#define	X86FSET_PCID		69
#define	X86FSET_INVPCID		70

/*
 * Intel Deep C-State invariant TSC in leaf 0x80000007.
 */
#define	CPUID_TSC_CSTATE_INVARIANCE	(0x100)

/*
 * Intel Deep C-state always-running local APIC timer
 */
#define	CPUID_CSTATE_ARAT	(0x4)

/*
 * Intel ENERGY_PERF_BIAS MSR indicated by feature bit CPUID.6.ECX[3].
 */
#define	CPUID_EPB_SUPPORT	(1 << 3)

/*
 * Intel TSC deadline timer
 */
#define	CPUID_DEADLINE_TSC	(1 << 24)

/*
 * x86_type is a legacy concept; this is supplanted
 * for most purposes by x86_featureset; modern CPUs
 * should be X86_TYPE_OTHER
 */
#define	X86_TYPE_OTHER		0
#define	X86_TYPE_486		1
#define	X86_TYPE_P5		2
#define	X86_TYPE_P6		3
#define	X86_TYPE_CYRIX_486	4
#define	X86_TYPE_CYRIX_6x86L	5
#define	X86_TYPE_CYRIX_6x86	6
#define	X86_TYPE_CYRIX_GXm	7
#define	X86_TYPE_CYRIX_6x86MX	8
#define	X86_TYPE_CYRIX_MediaGX	9
#define	X86_TYPE_CYRIX_MII	10
#define	X86_TYPE_VIA_CYRIX_III	11
#define	X86_TYPE_P4		12

/*
 * x86_vendor allows us to select between
 * implementation features and helps guide
 * the interpretation of the cpuid instruction.
 */
#define	X86_VENDOR_Intel	0
#define	X86_VENDORSTR_Intel	"GenuineIntel"

#define	X86_VENDOR_IntelClone	1

#define	X86_VENDOR_AMD		2
#define	X86_VENDORSTR_AMD	"AuthenticAMD"

#define	X86_VENDOR_Cyrix	3
#define	X86_VENDORSTR_CYRIX	"CyrixInstead"

#define	X86_VENDOR_UMC		4
#define	X86_VENDORSTR_UMC	"UMC UMC UMC "

#define	X86_VENDOR_NexGen	5
#define	X86_VENDORSTR_NexGen	"NexGenDriven"

#define	X86_VENDOR_Centaur	6
#define	X86_VENDORSTR_Centaur	"CentaurHauls"

#define	X86_VENDOR_Rise		7
#define	X86_VENDORSTR_Rise	"RiseRiseRise"

#define	X86_VENDOR_SiS		8
#define	X86_VENDORSTR_SiS	"SiS SiS SiS "

#define	X86_VENDOR_TM		9
#define	X86_VENDORSTR_TM	"GenuineTMx86"

#define	X86_VENDOR_NSC		10
#define	X86_VENDORSTR_NSC	"Geode by NSC"

/*
 * Vendor string max len + \0
 */
#define	X86_VENDOR_STRLEN	13

/*
 * Some vendor/family/model/stepping ranges are commonly grouped under
 * a single identifying banner by the vendor.  The following encode
 * that "revision" in a uint32_t with the 8 most significant bits
 * identifying the vendor with X86_VENDOR_*, the next 8 identifying the
 * family, and the remaining 16 typically forming a bitmask of revisions
 * within that family with more significant bits indicating "later" revisions.
 */

#define	_X86_CHIPREV_VENDOR_MASK	0xff000000u
#define	_X86_CHIPREV_VENDOR_SHIFT	24
#define	_X86_CHIPREV_FAMILY_MASK	0x00ff0000u
#define	_X86_CHIPREV_FAMILY_SHIFT	16
#define	_X86_CHIPREV_REV_MASK		0x0000ffffu

#define	_X86_CHIPREV_VENDOR(x) \
	(((x) & _X86_CHIPREV_VENDOR_MASK) >> _X86_CHIPREV_VENDOR_SHIFT)
#define	_X86_CHIPREV_FAMILY(x) \
	(((x) & _X86_CHIPREV_FAMILY_MASK) >> _X86_CHIPREV_FAMILY_SHIFT)
#define	_X86_CHIPREV_REV(x) \
	((x) & _X86_CHIPREV_REV_MASK)

/* True if x matches in vendor and family and if x matches the given rev mask */
#define	X86_CHIPREV_MATCH(x, mask) \
	(_X86_CHIPREV_VENDOR(x) == _X86_CHIPREV_VENDOR(mask) && \
	_X86_CHIPREV_FAMILY(x) == _X86_CHIPREV_FAMILY(mask) && \
	((_X86_CHIPREV_REV(x) & _X86_CHIPREV_REV(mask)) != 0))

/* True if x matches in vendor and family, and rev is at least minx */
#define	X86_CHIPREV_ATLEAST(x, minx) \
	(_X86_CHIPREV_VENDOR(x) == _X86_CHIPREV_VENDOR(minx) && \
	_X86_CHIPREV_FAMILY(x) == _X86_CHIPREV_FAMILY(minx) && \
	_X86_CHIPREV_REV(x) >= _X86_CHIPREV_REV(minx))

#define	_X86_CHIPREV_MKREV(vendor, family, rev) \
	((uint32_t)(vendor) << _X86_CHIPREV_VENDOR_SHIFT | \
	(family) << _X86_CHIPREV_FAMILY_SHIFT | (rev))

/* True if x matches in vendor, and family is at least minx */
#define	X86_CHIPFAM_ATLEAST(x, minx) \
	(_X86_CHIPREV_VENDOR(x) == _X86_CHIPREV_VENDOR(minx) && \
	_X86_CHIPREV_FAMILY(x) >= _X86_CHIPREV_FAMILY(minx))

/* Revision default */
#define	X86_CHIPREV_UNKNOWN	0x0

/*
 * Definitions for AMD Family 0xf. Minor revisions C0 and CG are
 * sufficiently different that we will distinguish them; in all other
 * case we will identify the major revision.
 */
#define	X86_CHIPREV_AMD_F_REV_B _X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0xf, 0x0001)
#define	X86_CHIPREV_AMD_F_REV_C0 _X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0xf, 0x0002)
#define	X86_CHIPREV_AMD_F_REV_CG _X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0xf, 0x0004)
#define	X86_CHIPREV_AMD_F_REV_D _X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0xf, 0x0008)
#define	X86_CHIPREV_AMD_F_REV_E _X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0xf, 0x0010)
#define	X86_CHIPREV_AMD_F_REV_F _X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0xf, 0x0020)
#define	X86_CHIPREV_AMD_F_REV_G _X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0xf, 0x0040)

/*
 * Definitions for AMD Family 0x10.  Rev A was Engineering Samples only.
 */
#define	X86_CHIPREV_AMD_10_REV_A \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x10, 0x0001)
#define	X86_CHIPREV_AMD_10_REV_B \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x10, 0x0002)
#define	X86_CHIPREV_AMD_10_REV_C2 \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x10, 0x0004)
#define	X86_CHIPREV_AMD_10_REV_C3 \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x10, 0x0008)
#define	X86_CHIPREV_AMD_10_REV_D0 \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x10, 0x0010)
#define	X86_CHIPREV_AMD_10_REV_D1 \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x10, 0x0020)
#define	X86_CHIPREV_AMD_10_REV_E \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x10, 0x0040)

/*
 * Definitions for AMD Family 0x11.
 */
#define	X86_CHIPREV_AMD_11_REV_B \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x11, 0x0002)

/*
 * Definitions for AMD Family 0x12.
 */
#define	X86_CHIPREV_AMD_12_REV_B \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x12, 0x0002)

/*
 * Definitions for AMD Family 0x14.
 */
#define	X86_CHIPREV_AMD_14_REV_B \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x14, 0x0002)
#define	X86_CHIPREV_AMD_14_REV_C \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x14, 0x0004)

/*
 * Definitions for AMD Family 0x15
 */
#define	X86_CHIPREV_AMD_15OR_REV_B2 \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x15, 0x0001)

#define	X86_CHIPREV_AMD_15TN_REV_A1 \
	_X86_CHIPREV_MKREV(X86_VENDOR_AMD, 0x15, 0x0002)

/*
 * Various socket/package types, extended as the need to distinguish
 * a new type arises.  The top 8 byte identfies the vendor and the
 * remaining 24 bits describe 24 socket types.
 */

#define	_X86_SOCKET_VENDOR_SHIFT	24
#define	_X86_SOCKET_VENDOR(x)	((x) >> _X86_SOCKET_VENDOR_SHIFT)
#define	_X86_SOCKET_TYPE_MASK	0x00ffffff
#define	_X86_SOCKET_TYPE(x)		((x) & _X86_SOCKET_TYPE_MASK)

#define	_X86_SOCKET_MKVAL(vendor, bitval) \
	((uint32_t)(vendor) << _X86_SOCKET_VENDOR_SHIFT | (bitval))

#define	X86_SOCKET_MATCH(s, mask) \
	(_X86_SOCKET_VENDOR(s) == _X86_SOCKET_VENDOR(mask) && \
	(_X86_SOCKET_TYPE(s) & _X86_SOCKET_TYPE(mask)) != 0)

#define	X86_SOCKET_UNKNOWN 0x0
	/*
	 * AMD socket types
	 */
#define	X86_SOCKET_754		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000001)
#define	X86_SOCKET_939		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000002)
#define	X86_SOCKET_940		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000004)
#define	X86_SOCKET_S1g1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000008)
#define	X86_SOCKET_AM2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000010)
#define	X86_SOCKET_F1207	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000020)
#define	X86_SOCKET_S1g2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000040)
#define	X86_SOCKET_S1g3		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000080)
#define	X86_SOCKET_AM		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000100)
#define	X86_SOCKET_AM2R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000200)
#define	X86_SOCKET_AM3		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000400)
#define	X86_SOCKET_G34		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x000800)
#define	X86_SOCKET_ASB2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x001000)
#define	X86_SOCKET_C32		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x002000)
#define	X86_SOCKET_S1g4		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x004000)
#define	X86_SOCKET_FT1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x008000)
#define	X86_SOCKET_FM1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x010000)
#define	X86_SOCKET_FS1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x020000)
#define	X86_SOCKET_AM3R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x040000)
#define	X86_SOCKET_FP2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x080000)
#define	X86_SOCKET_FS1R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x100000)
#define	X86_SOCKET_FM2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x200000)

/*
 * xgetbv/xsetbv support
 * See section 13.3 in vol. 1 of the Intel devlopers manual.
 */

#define	XFEATURE_ENABLED_MASK	0x0
/*
 * XFEATURE_ENABLED_MASK values (eax)
 * See setup_xfem().
 */
#define	XFEATURE_LEGACY_FP	0x1
#define	XFEATURE_SSE		0x2
#define	XFEATURE_AVX		0x4
#define	XFEATURE_MPX		0x18	/* 2 bits, both 0 or 1 */
#define	XFEATURE_AVX512		0xe0	/* 3 bits, all 0 or 1 */
	/* bit 8 unused */
#define	XFEATURE_PKRU		0x200
#define	XFEATURE_FP_ALL	\
	(XFEATURE_LEGACY_FP | XFEATURE_SSE | XFEATURE_AVX | XFEATURE_MPX | \
	XFEATURE_AVX512 | XFEATURE_PKRU)

/*
 * Define the set of xfeature flags that should be considered valid in the xsave
 * state vector when we initialize an lwp. This is distinct from the full set so
 * that all of the processor's normal logic and tracking of the xsave state is
 * usable. This should correspond to the state that's been initialized by the
 * ABI to hold meaningful values. Adding additional bits here can have serious
 * performance implications and cause performance degradations when using the
 * FPU vector (xmm) registers.
 */
#define	XFEATURE_FP_INITIAL	(XFEATURE_LEGACY_FP | XFEATURE_SSE)

#if !defined(_ASM)

#if defined(_KERNEL) || defined(_KMEMUSER)

#define	NUM_X86_FEATURES	71
extern uchar_t x86_featureset[];

extern void free_x86_featureset(void *featureset);
extern boolean_t is_x86_feature(void *featureset, uint_t feature);
extern void add_x86_feature(void *featureset, uint_t feature);
extern void remove_x86_feature(void *featureset, uint_t feature);
extern boolean_t compare_x86_featureset(void *setA, void *setB);
extern void print_x86_featureset(void *featureset);


extern uint_t x86_type;
extern uint_t x86_vendor;
extern uint_t x86_clflush_size;

extern uint_t pentiumpro_bug4046376;

extern const char CyrixInstead[];

#endif

#if defined(_KERNEL)

/*
 * This structure is used to pass arguments and get return values back
 * from the CPUID instruction in __cpuid_insn() routine.
 */
struct cpuid_regs {
	uint32_t	cp_eax;
	uint32_t	cp_ebx;
	uint32_t	cp_ecx;
	uint32_t	cp_edx;
};

extern int x86_use_pcid;
extern int x86_use_invpcid;

/*
 * Utility functions to get/set extended control registers (XCR)
 * Initial use is to get/set the contents of the XFEATURE_ENABLED_MASK.
 */
extern uint64_t get_xcr(uint_t);
extern void set_xcr(uint_t, uint64_t);

extern uint64_t rdmsr(uint_t);
extern void wrmsr(uint_t, const uint64_t);
extern uint64_t xrdmsr(uint_t);
extern void xwrmsr(uint_t, const uint64_t);
extern int checked_rdmsr(uint_t, uint64_t *);
extern int checked_wrmsr(uint_t, uint64_t);

extern void invalidate_cache(void);
extern ulong_t getcr4(void);
extern void setcr4(ulong_t);

extern void mtrr_sync(void);

extern void cpu_fast_syscall_enable(void);
extern void cpu_fast_syscall_disable(void);

struct cpu;

extern int cpuid_checkpass(struct cpu *, int);
extern uint32_t cpuid_insn(struct cpu *, struct cpuid_regs *);
extern uint32_t __cpuid_insn(struct cpuid_regs *);
extern int cpuid_getbrandstr(struct cpu *, char *, size_t);
extern int cpuid_getidstr(struct cpu *, char *, size_t);
extern const char *cpuid_getvendorstr(struct cpu *);
extern uint_t cpuid_getvendor(struct cpu *);
extern uint_t cpuid_getfamily(struct cpu *);
extern uint_t cpuid_getmodel(struct cpu *);
extern uint_t cpuid_getstep(struct cpu *);
extern uint_t cpuid_getsig(struct cpu *);
extern uint_t cpuid_get_ncpu_per_chip(struct cpu *);
extern uint_t cpuid_get_ncore_per_chip(struct cpu *);
extern uint_t cpuid_get_ncpu_sharing_last_cache(struct cpu *);
extern id_t cpuid_get_last_lvl_cacheid(struct cpu *);
extern int cpuid_get_chipid(struct cpu *);
extern id_t cpuid_get_coreid(struct cpu *);
extern int cpuid_get_pkgcoreid(struct cpu *);
extern int cpuid_get_clogid(struct cpu *);
extern int cpuid_get_cacheid(struct cpu *);
extern uint32_t cpuid_get_apicid(struct cpu *);
extern uint_t cpuid_get_procnodeid(struct cpu *cpu);
extern uint_t cpuid_get_procnodes_per_pkg(struct cpu *cpu);
extern uint_t cpuid_get_compunitid(struct cpu *cpu);
extern uint_t cpuid_get_cores_per_compunit(struct cpu *cpu);
extern size_t cpuid_get_xsave_size();
extern boolean_t cpuid_need_fp_excp_handling();
extern int cpuid_is_cmt(struct cpu *);
extern int cpuid_syscall32_insn(struct cpu *);
extern int getl2cacheinfo(struct cpu *, int *, int *, int *);

extern uint32_t cpuid_getchiprev(struct cpu *);
extern const char *cpuid_getchiprevstr(struct cpu *);
extern uint32_t cpuid_getsockettype(struct cpu *);
extern const char *cpuid_getsocketstr(struct cpu *);

extern int cpuid_have_cr8access(struct cpu *);

extern int cpuid_opteron_erratum(struct cpu *, uint_t);

struct cpuid_info;

extern void setx86isalist(void);
extern void cpuid_alloc_space(struct cpu *);
extern void cpuid_free_space(struct cpu *);
extern void cpuid_pass1(struct cpu *, uchar_t *);
extern void cpuid_pass2(struct cpu *);
extern void cpuid_pass3(struct cpu *);
extern void cpuid_pass4(struct cpu *, uint_t *);
extern void cpuid_set_cpu_properties(void *, processorid_t,
    struct cpuid_info *);

extern void cpuid_get_addrsize(struct cpu *, uint_t *, uint_t *);
extern uint_t cpuid_get_dtlb_nent(struct cpu *, size_t);

#if !defined(__xpv)
extern uint32_t *cpuid_mwait_alloc(struct cpu *);
extern void cpuid_mwait_free(struct cpu *);
extern int cpuid_deep_cstates_supported(void);
extern int cpuid_arat_supported(void);
extern int cpuid_iepb_supported(struct cpu *);
extern int cpuid_deadline_tsc_supported(void);
extern void vmware_port(int, uint32_t *);
#endif

struct cpu_ucode_info;

extern void ucode_alloc_space(struct cpu *);
extern void ucode_free_space(struct cpu *);
extern void ucode_check(struct cpu *);
extern void ucode_cleanup();

#if !defined(__xpv)
extern	char _tsc_mfence_start;
extern	char _tsc_mfence_end;
extern	char _tscp_start;
extern	char _tscp_end;
extern	char _no_rdtsc_start;
extern	char _no_rdtsc_end;
extern	char _tsc_lfence_start;
extern	char _tsc_lfence_end;
#endif

#if !defined(__xpv)
extern	char bcopy_patch_start;
extern	char bcopy_patch_end;
extern	char bcopy_ck_size;
#endif

extern void post_startup_cpu_fixups(void);

extern uint_t workaround_errata(struct cpu *);

#if defined(OPTERON_ERRATUM_93)
extern int opteron_erratum_93;
#endif

#if defined(OPTERON_ERRATUM_91)
extern int opteron_erratum_91;
#endif

#if defined(OPTERON_ERRATUM_100)
extern int opteron_erratum_100;
#endif

#if defined(OPTERON_ERRATUM_121)
extern int opteron_erratum_121;
#endif

#if defined(OPTERON_WORKAROUND_6323525)
extern int opteron_workaround_6323525;
extern void patch_workaround_6323525(void);
#endif

#if !defined(__xpv)
extern void determine_platform(void);
#endif
extern int get_hwenv(void);
extern int is_controldom(void);

extern void enable_pcid(void);

extern void xsave_setup_msr(struct cpu *);

/*
 * Hypervisor signatures
 */
#define	HVSIG_XEN_HVM	"XenVMMXenVMM"
#define	HVSIG_VMWARE	"VMwareVMware"
#define	HVSIG_KVM	"KVMKVMKVM"
#define	HVSIG_MICROSOFT	"Microsoft Hv"

/*
 * Defined hardware environments
 */
#define	HW_NATIVE	(1 << 0)	/* Running on bare metal */
#define	HW_XEN_PV	(1 << 1)	/* Running on Xen PVM */

#define	HW_XEN_HVM	(1 << 2)	/* Running on Xen HVM */
#define	HW_VMWARE	(1 << 3)	/* Running on VMware hypervisor */
#define	HW_KVM		(1 << 4)	/* Running on KVM hypervisor */
#define	HW_MICROSOFT	(1 << 5)	/* Running on Microsoft hypervisor */

#define	HW_VIRTUAL	(HW_XEN_HVM | HW_VMWARE | HW_KVM | HW_MICROSOFT)

#endif	/* _KERNEL */

#endif	/* !_ASM */

/*
 * VMware hypervisor related defines
 */
#define	VMWARE_HVMAGIC		0x564d5868
#define	VMWARE_HVPORT		0x5658
#define	VMWARE_HVCMD_GETVERSION	0x0a
#define	VMWARE_HVCMD_GETTSCFREQ	0x2d

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_X86_ARCHEXT_H */
