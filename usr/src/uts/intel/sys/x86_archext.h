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
 * Copyright 2020 Joyent, Inc.
 * Copyright 2012 Jens Elkner <jel+illumos@cs.uni-magdeburg.de>
 * Copyright 2012 Hans Rosenfeld <rosenfeld@grumpf.hope-2000.org>
 * Copyright 2014 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 * Copyright 2018 Nexenta Systems, Inc.
 * Copyright 2025 Oxide Computer Company
 * Copyright 2024 MNX Cloud, Inc.
 */

#ifndef _SYS_X86_ARCHEXT_H
#define	_SYS_X86_ARCHEXT_H

#if !defined(_ASM)
#include <sys/bitext.h>
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
#define	CPUID_INTC_ECX_PCLMULQDQ 0x00000002	/* PCLMULQDQ insn */
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

/*
 * AMD extended function 0x80000001 %ecx
 */

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
#define	CPUID_AMD_ECX_XOP	0x00000800	/* AMD: Extended Operation */
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
#define	CPUID_AMD_ECX_PCEC	0x00800000	/* AMD: Core ext perf counter */
#define	CUPID_AMD_ECX_PCENB	0x01000000	/* AMD: NB ext perf counter */
				/* 0x02000000 - reserved */
#define	CPUID_AMD_ECX_DBKP	0x40000000	/* AMD: Data breakpoint */
#define	CPUID_AMD_ECX_PERFTSC	0x08000000	/* AMD: TSC Perf Counter */
#define	CPUID_AMD_ECX_PERFL3	0x10000000	/* AMD: L3 Perf Counter */
#define	CPUID_AMD_ECX_MONITORX	0x20000000	/* AMD: clzero */
				/* 0x40000000 - reserved */
				/* 0x80000000 - reserved */

/*
 * AMD uses %ebx for some of their features (extended function 0x80000008).
 */
#define	CPUID_AMD_EBX_CLZERO		0x000000001 /* AMD: CLZERO instr */
#define	CPUID_AMD_EBX_IRCMSR		0x000000002 /* AMD: Ret. instrs MSR */
#define	CPUID_AMD_EBX_ERR_PTR_ZERO	0x000000004 /* AMD: FP Err. Ptr. Zero */
#define	CPUID_AMD_EBX_IBPB		0x000001000 /* AMD: IBPB */
#define	CPUID_AMD_EBX_IBRS		0x000004000 /* AMD: IBRS */
#define	CPUID_AMD_EBX_STIBP		0x000008000 /* AMD: STIBP */
#define	CPUID_AMD_EBX_IBRS_ALL		0x000010000 /* AMD: Enhanced IBRS */
#define	CPUID_AMD_EBX_STIBP_ALL		0x000020000 /* AMD: STIBP ALL */
#define	CPUID_AMD_EBX_PREFER_IBRS	0x000040000 /* AMD: Don't retpoline */
#define	CPUID_AMD_EBX_PPIN		0x000800000 /* AMD: PPIN Support */
#define	CPUID_AMD_EBX_SSBD		0x001000000 /* AMD: SSBD */
#define	CPUID_AMD_EBX_VIRT_SSBD		0x002000000 /* AMD: VIRT SSBD */
#define	CPUID_AMD_EBX_SSB_NO		0x004000000 /* AMD: SSB Fixed */

/*
 * AMD SVM features (extended function 0x8000000A).
 */
#define	CPUID_AMD_EDX_NESTED_PAGING	(1 << 0) /* AMD: Nested paging */
#define	CPUID_AMD_EDX_LBR_VIRT		(1 << 1) /* AMD: LBR virt. */
#define	CPUID_AMD_EDX_SVML		(1 << 2) /* AMD: SVM lock */
#define	CPUID_AMD_EDX_NRIPS		(1 << 3) /* AMD: NRIP save */
#define	CPUID_AMD_EDX_TSC_RATE_MSR	(1 << 4) /* AMD: TSC ratio ctrl */
#define	CPUID_AMD_EDX_VMCB_CLEAN	(1 << 5) /* AMD: VMCB clean bits */
#define	CPUID_AMD_EDX_FLUSH_ASID	(1 << 6) /* AMD: flush by ASID */
#define	CPUID_AMD_EDX_DECODE_ASSISTS	(1 << 7) /* AMD: decode assists */
#define	CPUID_AMD_EDX_PAUSE_INCPT	(1 << 8) /* AMD: pause intercept */
#define	CPUID_AMD_EDX_PAUSE_TRSH	(1 << 9) /* AMD: pause threshold */
#define	CPUID_AMD_EDX_AVIC		(1 << 10) /* AMD: AVIC */

/*
 * AMD Encrypted Memory Capabilities -- 0x8000_001F
 *
 * %ecx is the number of encrypted guests.
 * %edx is the minimum ASID value for SEV enabled, SEV-ES disabled guests
 */
#define	CPUID_AMD_8X1F_EAX_NVS		(1 << 29) /* VIRT_RMPUPDATE MSR */
#define	CPUID_AMD_8X1F_EAX_SCP		(1 << 28) /* SVSM Comm Page MSR */
#define	CPUID_AMD_8X1F_EAX_SMT_PROT	(1 << 25) /* SMT Protection */
#define	CPUID_AMD_8X1F_EAX_VMSAR_PROT	(1 << 24) /* VMSA Reg Protection */
#define	CPUID_AMD_8X1F_EAX_IBSVGC	(1 << 19) /* IBS Virt. for SEV-ES */
#define	CPUID_AMD_8X1F_EAX_VIRT_TOM	(1 << 18) /* Virt TOM MSR */
#define	CPUID_AMD_8X1F_EAX_VMGEXIT	(1 << 17) /* VMGEXIT Parameter */
#define	CPUID_AMD_8X1F_EAX_VTE		(1 << 16) /* Virt Transparent Enc. */
#define	CPUID_AMD_8X1F_EAX_NO_IBS	(1 << 15) /* No IBS by host */
#define	CPUID_AMD_8X1F_EAX_DBGSWP	(1 << 14) /* Debug state for SEV-ES */
#define	CPUID_AMD_8X1F_EAX_ALT_INJ	(1 << 13) /* Alternate Injection */
#define	CPUID_AMD_8X1F_EAX_RES_INJ	(1 << 12) /* Restricted Injection */
#define	CPUID_AMD_8X1F_EAX_64B_HOST	(1 << 11) /* SEV requires amd64 */
#define	CPUID_AMD_8X1F_EAX_HWECC	(1 << 10) /* HW cache coherency req */
#define	CPUID_AMD_8X1F_EAX_TSC_AUX	(1 << 9) /* TSC AUX Virtualization */
#define	CPUID_AMD_8X1F_EAX_SEC_TSC	(1 << 8) /* Secure TSC */
#define	CPUID_AMD_8X1F_EAX_VSSS		(1 << 7) /* VMPL Super. Shadow Stack */
#define	CPUID_AMD_8X1F_EAX_RMPQUERY	(1 << 6) /* RMPQUERY Instr */
#define	CPUID_AMD_8X1F_EAX_VMPL		(1 << 5) /* VM Permission Levels */
#define	CPUID_AMD_8X1F_EAX_SEV_SNP	(1 << 4) /* SEV Secure Nested Paging */
#define	CPUID_AMD_8X1F_EAX_SEV_ES	(1 << 3) /* SEV Encrypted State */
#define	CPUID_AMD_8X1F_EAX_PAGE_FLUSH	(1 << 2) /* Page Flush MSR */
#define	CPUID_AMD_8X1F_EAX_SEV		(1 << 1) /* Secure Encrypted Virt. */
#define	CPUID_AMD_8X1F_EAX_SME		(1 << 0) /* Secure Memory Encrypt. */

#define	CPUID_AMD_8X1F_EBX_NVMPL(r)	bitx32(r, 15, 12) /* num VM Perm lvl */
#define	CPUID_AMD_8X1F_EBX_PAR(r)	bitx32(r, 11, 6) /* paddr bit rem */
#define	CPUID_AMD_8X1F_EBX_CBIT(r)	bitx32(r, 5, 0)	/* C-bit loc in PTE */

/*
 * AMD Platform QoS Extended Features -- 0x8000_0020
 */
#define	CPUID_AMD_8X20_EBX_L3RR		(1 << 4) /* L3 Range Reservations */

/*
 * AMD Extended Feature 2 -- 0x8000_0021
 */
#define	CPUID_AMD_8X21_EAX_CPUID_DIS	(1 << 17) /* CPUID dis for CPL > 0 */
#define	CPUID_AMD_8X21_EAX_PREFETCH	(1 << 13) /* Prefetch control MSR  */
#define	CPUID_AMD_8X21_EAX_NO_SMMCTL	(1 << 9) /* No SMM_CTL MSR */
#define	CPUID_AMD_8X21_EAX_AIBRS	(1 << 8) /* Automatic IBRS */
#define	CPUID_AMD_8X21_EAX_UAI		(1 << 7) /* Upper Address Ignore */
#define	CPUID_AMD_8X21_EAX_SMM_PGLK	(1 << 3) /* SMM Page config lock */
#define	CPUID_AMD_8X21_EAX_LFENCE_SER	(1 << 2) /* LFENCE is dispatch serial */
#define	CPUID_AMD_8X21_EAX_NO_NDBP	(1 << 0) /* No nested data #BP */

#define	CPUID_AMD_8X21_EBX_MPS(r)	bitx32(11, 0) /* MCU Patch size x 16B */

/*
 * AMD Extended Performance Monitoring and Debug -- 0x8000_0022
 */
#define	CPUID_AMD_8X22_LBR_FRZ	(1 << 2)	/* Freeze PMC / LBR on ovflw */
#define	CPUID_AMD_8X22_LBR_STK	(1 << 1)	/* Last Branch Record Stack */
#define	CPUID_AMD_8X22_EAX_PMV2	(1 << 0)	/* Perfmon v2 */

#define	CPUID_AMD_8X22_EBX_NPMC_NB(r)	bitx32(r, 15, 10) /* # NB PMC */
#define	CPUID_AMD_8X22_EBX_LBR_SZ(r)	bitx32(r, 9, 4) /* # LBR Stack ents. */
#define	CPUID_AMD_8X22_EBX_NPMC_CORE(r)	bitx32(r, 3, 0)	/* # core PMC */

/*
 * AMD Secure Multi-key Encryption -- 0x8000_00023
 */
#define	CPUID_AMD_8X23_EAX_MEMHMK	(1 << 0) /* Secure Host Multi-Key Mem */

#define	CPUID_AMD_8X23_EBX_MAX_HMK(r)	bitx32(r, 15, 0) /* Max HMK IDs */

/*
 * AMD Extended CPU Topology -- 0x8000_0026
 *
 * This is AMD's version of extended CPU topology. The topology level is placed
 * in %ecx and also contains information about the heterogeneity of the CPUs at
 * the core level. Note, this is similar to, but not the same as Intel's 0x1f.
 *
 * The %eax values other than the APIC shift are only available when the type is
 * a core. The %ebx values other than the number of logical processors are only
 * available when the type is a core. The core and native model ID values are
 * processor specific.
 *
 * %edx is the entire extended APIC ID of the logical processor we're on.
 */
#define	CPUID_AMD_8X26_EAX_ASYM_TOPO(r)		bitx32(r, 31, 31)
#define	CPUID_AMD_8x26_EAX_HET_CORES(r)		bitx32(r, 30, 30)
#define	CPUID_AMD_8X26_EAX_EFF_AVAIL(r)		bitx32(r, 29, 29)
#define	CPUID_AMD_8X26_EAX_APIC_SHIFT(r)	bitx32(r, 4, 0)

#define	CPUID_AMD_8X26_EBX_CORE_TYPE(r)		bitx32(r, 31, 28)
#define	CPUID_AMD_8X26_EBX_MODEL_ID(r)		bitx32(r, 27, 24)
#define	CPUID_AMD_8X26_EBX_PWR_EFF(r)		bitx32(r, 23, 16)
#define	CPUID_AMD_8X26_EBX_NLOG_PROC(r)		bitx32(r, 15, 0)

#define	CPUID_AMD_8X26_ECX_TYPE(r)		bitx32(r, 15, 8)
#define	CPUID_AMD_8X26_TYPE_DONE	0	/* Technically reserved */
#define	CUPID_AMD_8X26_TYPE_CORE	1
#define	CUPID_AMD_8X26_TYPE_COMPLEX	2
#define	CUPID_AMD_8X26_TYPE_DIE		3
#define	CUPID_AMD_8X26_TYPE_SOCK	4
#define	CPUID_AMD_8X26_ECX_INPUT(r)		bitx32(r, 7, 0)

/*
 * Intel now seems to have claimed part of the "extended" function
 * space that we previously for non-Intel implementors to use.
 * More excitingly still, they've claimed bit 20 to mean LAHF/SAHF
 * is available in long mode i.e. what AMD indicate using bit 0.
 * On the other hand, everything else is labelled as reserved.
 */
#define	CPUID_INTC_ECX_AHF64	0x00100000	/* LAHF and SAHF in long mode */

/*
 * Intel uses cpuid leaf 6 to cover various thermal and power control
 * operations.
 */
#define	CPUID_INTC_EAX_DTS	0x00000001	/* Digital Thermal Sensor */
#define	CPUID_INTC_EAX_TURBO	0x00000002	/* Turboboost */
#define	CPUID_INTC_EAX_ARAT	0x00000004	/* APIC-Timer-Always-Running */
/* bit 3 is reserved */
#define	CPUID_INTC_EAX_PLN	0x00000010	/* Power limit notification */
#define	CPUID_INTC_EAX_ECMD	0x00000020	/* Clock mod. duty cycle */
#define	CPUID_INTC_EAX_PTM	0x00000040	/* Package thermal management */
#define	CPUID_INTC_EAX_HWP	0x00000080	/* HWP base registers */
#define	CPUID_INTC_EAX_HWP_NOT	0x00000100	/* HWP Notification */
#define	CPUID_INTC_EAX_HWP_ACT	0x00000200	/* HWP Activity Window */
#define	CPUID_INTC_EAX_HWP_EPR	0x00000400	/* HWP Energy Perf. Pref. */
#define	CPUID_INTC_EAX_HWP_PLR	0x00000800	/* HWP Package Level Request */
/* bit 12 is reserved */
#define	CPUID_INTC_EAX_HDC	0x00002000	/* HDC */
#define	CPUID_INTC_EAX_TURBO3	0x00004000	/* Turbo Boost Max Tech 3.0 */
#define	CPUID_INTC_EAX_HWP_CAP	0x00008000	/* HWP Capabilities */
#define	CPUID_INTC_EAX_HWP_PECI	0x00010000	/* HWP PECI override */
#define	CPUID_INTC_EAX_HWP_FLEX	0x00020000	/* Flexible HWP */
#define	CPUID_INTC_EAX_HWP_FAST	0x00040000	/* Fast IA32_HWP_REQUEST */
/* bit 19 is reserved */
#define	CPUID_INTC_EAX_HWP_IDLE	0x00100000	/* Ignore Idle Logical HWP */

#define	CPUID_INTC_EBX_DTS_NTRESH(x)	((x) & 0xf)

#define	CPUID_INTC_ECX_MAPERF	0x00000001	/* IA32_MPERF / IA32_APERF */
/* bits 1-2 are reserved */
#define	CPUID_INTC_ECX_PERFBIAS	0x00000008	/* IA32_ENERGY_PERF_BIAS */

/*
 * Intel also uses cpuid leaf 7 to have additional instructions and features.
 * Like some other leaves, but unlike the current ones we care about, it
 * requires us to specify both a leaf in %eax and a sub-leaf in %ecx. To deal
 * with the potential use of additional sub-leaves in the future, we now
 * specifically label the EBX features with their leaf and sub-leaf.
 */
#define	CPUID_INTC_EBX_7_0_FSGSBASE	0x00000001	/* FSGSBASE */
#define	CPUID_INTC_EBX_7_0_TSC_ADJ	0x00000002	/* TSC adjust MSR */
#define	CPUID_INTC_EBX_7_0_SGX		0x00000004	/* SGX */
#define	CPUID_INTC_EBX_7_0_BMI1		0x00000008	/* BMI1 instrs */
#define	CPUID_INTC_EBX_7_0_HLE		0x00000010	/* HLE */
#define	CPUID_INTC_EBX_7_0_AVX2		0x00000020	/* AVX2 supported */
#define	CPUID_INTC_EBX_7_0_FDP_EXCPN	0x00000040	/* FDP on exception */
#define	CPUID_INTC_EBX_7_0_SMEP		0x00000080	/* SMEP in CR4 */
#define	CPUID_INTC_EBX_7_0_BMI2		0x00000100	/* BMI2 instrs */
#define	CPUID_INTC_EBX_7_0_ENH_REP_MOV	0x00000200	/* Enhanced REP MOVSB */
#define	CPUID_INTC_EBX_7_0_INVPCID	0x00000400	/* invpcid instr */
#define	CPUID_INTC_EBX_7_0_RTM		0x00000800	/* RTM instrs */
#define	CPUID_INTC_EBX_7_0_PQM		0x00001000	/* QoS Monitoring */
#define	CPUID_INTC_EBX_7_0_DEP_CSDS	0x00002000	/* Deprecates CS/DS */
#define	CPUID_INTC_EBX_7_0_MPX		0x00004000	/* Mem. Prot. Ext. */
#define	CPUID_INTC_EBX_7_0_PQE		0x00080000	/* QoS Enforcement */
#define	CPUID_INTC_EBX_7_0_AVX512F	0x00010000	/* AVX512 foundation */
#define	CPUID_INTC_EBX_7_0_AVX512DQ	0x00020000	/* AVX512DQ */
#define	CPUID_INTC_EBX_7_0_RDSEED	0x00040000	/* RDSEED instr */
#define	CPUID_INTC_EBX_7_0_ADX		0x00080000	/* ADX instrs */
#define	CPUID_INTC_EBX_7_0_SMAP		0x00100000	/* SMAP in CR 4 */
#define	CPUID_INTC_EBX_7_0_AVX512IFMA	0x00200000	/* AVX512IFMA */
/* Bit 22 is reserved */
#define	CPUID_INTC_EBX_7_0_CLFLUSHOPT	0x00800000	/* CLFLUSOPT */
#define	CPUID_INTC_EBX_7_0_CLWB		0x01000000	/* CLWB */
#define	CPUID_INTC_EBX_7_0_PTRACE	0x02000000	/* Processor Trace */
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

#define	CPUID_INTC_ECX_7_0_PREFETCHWT1	0x00000001	/* PREFETCHWT1 */
#define	CPUID_INTC_ECX_7_0_AVX512VBMI	0x00000002	/* AVX512VBMI */
#define	CPUID_INTC_ECX_7_0_UMIP		0x00000004	/* UMIP */
#define	CPUID_INTC_ECX_7_0_PKU		0x00000008	/* umode prot. keys */
#define	CPUID_INTC_ECX_7_0_OSPKE	0x00000010	/* OSPKE */
#define	CPUID_INTC_ECX_7_0_WAITPKG	0x00000020	/* WAITPKG */
#define	CPUID_INTC_ECX_7_0_AVX512VBMI2	0x00000040	/* AVX512 VBMI2 */
#define	CPUID_INTC_ECX_7_0_CET_SS	0x00000080	/* CET Shadow Stack */
#define	CPUID_INTC_ECX_7_0_GFNI		0x00000100	/* GFNI */
#define	CPUID_INTC_ECX_7_0_VAES		0x00000200	/* VAES */
#define	CPUID_INTC_ECX_7_0_VPCLMULQDQ	0x00000400	/* VPCLMULQDQ */
#define	CPUID_INTC_ECX_7_0_AVX512VNNI	0x00000800	/* AVX512 VNNI */
#define	CPUID_INTC_ECX_7_0_AVX512BITALG	0x00001000	/* AVX512 BITALG */
#define	CPUID_INTC_ECX_7_0_TME_EN	0x00002000	/* Total Memory Encr. */
#define	CPUID_INTC_ECX_7_0_AVX512VPOPCDQ 0x00004000	/* AVX512 VPOPCNTDQ */
/* bit 15 is reserved */
#define	CPUID_INTC_ECX_7_0_LA57		0x00010000	/* 57-bit paging */
/* bits 17-21 are the value of MAWAU */
#define	CPUID_INTC_ECX_7_0_RDPID	0x00400000	/* RPID, IA32_TSC_AUX */
#define	CPUID_INTC_ECX_7_0_KLSUP	0x00800000	/* Key Locker */
/* bit 24 is reserved */
#define	CPUID_INTC_ECX_7_0_CLDEMOTE	0x02000000	/* Cache line demote */
/* bit 26 is resrved */
#define	CPUID_INTC_ECX_7_0_MOVDIRI	0x08000000	/* MOVDIRI insn */
#define	CPUID_INTC_ECX_7_0_MOVDIR64B	0x10000000	/* MOVDIR64B insn */
#define	CPUID_INTC_ECX_7_0_ENQCMD	0x20000000	/* Enqueue Stores */
#define	CPUID_INTC_ECX_7_0_SGXLC	0x40000000	/* SGX Launch config */
#define	CPUID_INTC_ECX_7_0_PKS		0x80000000	/* protection keys */

/*
 * While CPUID_INTC_ECX_7_0_GFNI, CPUID_INTC_ECX_7_0_VAES, and
 * CPUID_INTC_ECX_7_0_VPCLMULQDQ all have AVX512 components, they are still
 * valid when AVX512 is not. However, the following flags all are only valid
 * when AVX512 is present.
 */
#define	CPUID_INTC_ECX_7_0_ALL_AVX512 \
	(CPUID_INTC_ECX_7_0_AVX512VBMI | CPUID_INTC_ECX_7_0_AVX512VNNI | \
	CPUID_INTC_ECX_7_0_AVX512BITALG | CPUID_INTC_ECX_7_0_AVX512VPOPCDQ)

/* bits 0-1 are reserved */
#define	CPUID_INTC_EDX_7_0_AVX5124NNIW	0x00000004	/* AVX512 4NNIW */
#define	CPUID_INTC_EDX_7_0_AVX5124FMAPS	0x00000008	/* AVX512 4FMAPS */
#define	CPUID_INTC_EDX_7_0_FSREPMOV	0x00000010	/* fast short rep mov */
#define	CPUID_INTC_EDX_7_0_UINTR	0x00000020	/* user interrupts */
/* bits 6-7 are reserved */
#define	CPUID_INTC_EDX_7_0_AVX512VP2INT	0x00000100	/* VP2INTERSECT */
/* bit 9 is reserved */
#define	CPUID_INTC_EDX_7_0_MD_CLEAR	0x00000400	/* MB VERW */
/* bits 11-13 are reserved */
#define	CPUID_INTC_EDX_7_0_SERIALIZE	0x00004000	/* Serialize instr */
#define	CPUID_INTC_EDX_7_0_HYBRID	0x00008000	/* Hybrid CPU */
#define	CPUID_INTC_EDX_7_0_TSXLDTRK	0x00010000	/* TSX load track */
/* bit 17 is reserved */
#define	CPUID_INTC_EDX_7_0_PCONFIG	0x00040000	/* PCONFIG */
/* bit 19 is reserved */
#define	CPUID_INTC_EDX_7_0_CET_IBT	0x00100000	/* CET ind. branch */
/* bit 21 is reserved */
#define	CPUID_INTC_EDX_7_0_AMX_BF16	0x00400000	/* Tile F16 */
#define	CPUID_INTC_EDX_7_0_AVX512FP16	0x00800000	/* AVX512 FP16 */
#define	CPUID_INTC_EDX_7_0_AMX_TILE	0x01000000	/* Tile arch */
#define	CPUID_INTC_EDX_7_0_AMX_INT8	0x02000000	/* Tile INT8 */
#define	CPUID_INTC_EDX_7_0_SPEC_CTRL	0x04000000	/* Spec, IBPB, IBRS */
#define	CPUID_INTC_EDX_7_0_STIBP	0x08000000	/* STIBP */
#define	CPUID_INTC_EDX_7_0_FLUSH_CMD	0x10000000	/* IA32_FLUSH_CMD */
#define	CPUID_INTC_EDX_7_0_ARCH_CAPS	0x20000000	/* IA32_ARCH_CAPS */
#define	CPUID_INTC_EDX_7_0_SSBD		0x80000000	/* SSBD */

#define	CPUID_INTC_EDX_7_0_ALL_AVX512 \
	(CPUID_INTC_EDX_7_0_AVX5124NNIW | CPUID_INTC_EDX_7_0_AVX5124FMAPS | \
	CPUID_INTC_EDX_7_0_AVX512VP2INT | CPUID_INTC_EDX_7_0_AVX512FP16)

/* bits 0-3 are reserved */
#define	CPUID_INTC_EAX_7_1_AVXVNNI	0x00000010	/* VEX VNNI */
#define	CPUID_INTC_EAX_7_1_AVX512_BF16	0x00000020	/* AVX512 BF16 */
/* bits 6-9 are reserved */
#define	CPUID_INTC_EAX_7_1_ZL_MOVSB	0x00000400	/* zero-length MOVSB */
#define	CPUID_INTC_EAX_7_1_FS_STOSB	0x00000800	/* fast short STOSB */
#define	CPUID_INTC_EAX_7_1_FS_CMPSB	0x00001000	/* fast CMPSB, SCASB */
/* bits 13-21 are reserved */
#define	CPUID_INTC_EAX_7_1_HRESET	0x00400000	/* History Reset leaf */
/* bits 23-25 are reserved */
#define	CPUID_INTC_EAX_7_1_LAM		0x02000000	/* Linear addr mask */
/* bits 27-31 are reserved */

#define	CPUID_INTC_EDX_7_2_BHI_CTRL	(1U << 4U)	/* BHI controls */

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
#define	MSR_PRP4_LBSTK_FROM_8	0x688
#define	MSR_PRP4_LBSTK_FROM_9	0x689
#define	MSR_PRP4_LBSTK_FROM_10	0x68a
#define	MSR_PRP4_LBSTK_FROM_11	0x68b
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
#define	MSR_PRP4_LBSTK_TO_9	0x6c9
#define	MSR_PRP4_LBSTK_TO_10	0x6ca
#define	MSR_PRP4_LBSTK_TO_11	0x6cb
#define	MSR_PRP4_LBSTK_TO_12	0x6cc
#define	MSR_PRP4_LBSTK_TO_13	0x6cd
#define	MSR_PRP4_LBSTK_TO_14	0x6ce
#define	MSR_PRP4_LBSTK_TO_15	0x6cf

/*
 * PPIN definitions for Intel and AMD. Unfortunately, Intel and AMD use
 * different MSRS for this and different MSRS to control whether or not it
 * should be readable.
 */
#define	MSR_PPIN_CTL_INTC	0x04e
#define	MSR_PPIN_INTC		0x04f
#define	MSR_PLATFORM_INFO	0x0ce
#define	MSR_PLATFORM_INFO_PPIN	(1 << 23)

#define	MSR_PPIN_CTL_AMD	0xC00102F0
#define	MSR_PPIN_AMD		0xC00102F1

/*
 * These values are currently the same between Intel and AMD.
 */
#define	MSR_PPIN_CTL_MASK	0x03
#define	MSR_PPIN_CTL_DISABLED	0x00
#define	MSR_PPIN_CTL_LOCKED	0x01
#define	MSR_PPIN_CTL_ENABLED	0x02

/*
 * Intel IA32_ARCH_CAPABILITIES MSR.
 */
#define	MSR_IA32_ARCH_CAPABILITIES		0x10a
#define	IA32_ARCH_CAP_RDCL_NO			(1UL << 0)
#define	IA32_ARCH_CAP_IBRS_ALL			(1UL << 1)
#define	IA32_ARCH_CAP_RSBA			(1UL << 2)
#define	IA32_ARCH_CAP_SKIP_L1DFL_VMENTRY	(1UL << 3)
#define	IA32_ARCH_CAP_SSB_NO			(1UL << 4)
#define	IA32_ARCH_CAP_MDS_NO			(1UL << 5)
#define	IA32_ARCH_CAP_IF_PSCHANGE_MC_NO		(1UL << 6)
#define	IA32_ARCH_CAP_TSX_CTRL			(1UL << 7)
#define	IA32_ARCH_CAP_TAA_NO			(1UL << 8)
#define	IA32_ARCH_CAP_RESERVED_1		(1UL << 9)
#define	IA32_ARCH_CAP_MCU_CONTROL		(1UL << 10)
#define	IA32_ARCH_CAP_ENERGY_FILTERING_CTL	(1UL << 11)
#define	IA32_ARCH_CAP_DOITM			(1UL << 12)
#define	IA32_ARCH_CAP_SBDR_SSDP_NO		(1UL << 13)
#define	IA32_ARCH_CAP_FBSDP_NO			(1UL << 14)
#define	IA32_ARCH_CAP_PSDP_NO			(1UL << 15)
#define	IA32_ARCH_CAP_RESERVED_2		(1UL << 16)
#define	IA32_ARCH_CAP_FB_CLEAR			(1UL << 17)
#define	IA32_ARCH_CAP_FB_CLEAR_CTRL		(1UL << 18)
#define	IA32_ARCH_CAP_RRSBA			(1UL << 19)
#define	IA32_ARCH_CAP_BHI_NO			(1UL << 20)
#define	IA32_ARCH_CAP_XAPIC_DISABLE_STATUS	(1UL << 21)
#define	IA32_ARCH_CAP_RESERVED_3		(1UL << 22)
#define	IA32_ARCH_CAP_OVERCLOCKING_STATUS	(1UL << 23)
#define	IA32_ARCH_CAP_PBRSB_NO			(1UL << 24)
#define	IA32_ARCH_CAP_GDS_CTRL			(1UL << 25)
#define	IA32_ARCH_CAP_GDS_NO			(1UL << 26)
#define	IA32_ARCH_CAP_RFDS_NO			(1UL << 27)
#define	IA32_ARCH_CAP_RFDS_CLEAR		(1UL << 28)

/*
 * Intel Speculation related MSRs
 */
#define	MSR_IA32_SPEC_CTRL	0x48
#define	IA32_SPEC_CTRL_IBRS		(1UL << 0)
#define	IA32_SPEC_CTRL_STIBP		(1UL << 1)
#define	IA32_SPEC_CTRL_SSBD		(1UL << 2)
#define	IA32_SPEC_CTRL_IPRED_DIS_U	(1UL << 3)
#define	IA32_SPEC_CTRL_IPRED_DIS_S	(1UL << 4)
#define	IA32_SPEC_CTRL_RRSBA_DIS_U	(1UL << 5)
#define	IA32_SPEC_CTRL_RRSBA_DIS_S	(1UL << 6)
#define	IA32_SPEC_CTRL_PSFD		(1UL << 7)
#define	IA32_SPEC_CTRL_DDPD_U		(1UL << 8)
#define	IA32_SPEC_CTRL_BHI_DIS_S	(1UL << 10)

#define	MSR_IA32_PRED_CMD	0x49
#define	IA32_PRED_CMD_IBPB	0x01

#define	MSR_IA32_FLUSH_CMD	0x10b
#define	IA32_FLUSH_CMD_L1D	0x01

/*
 * Intel VMX related MSRs
 */
#define	MSR_IA32_FEAT_CTRL	0x03a
#define	IA32_FEAT_CTRL_LOCK	0x1
#define	IA32_FEAT_CTRL_SMX_EN	0x2
#define	IA32_FEAT_CTRL_VMX_EN	0x4

#define	MSR_IA32_VMX_BASIC		0x480
#define	IA32_VMX_BASIC_INS_OUTS		(1UL << 54)
#define	IA32_VMX_BASIC_TRUE_CTRLS	(1UL << 55)

#define	MSR_IA32_VMX_PROCBASED_CTLS		0x482
#define	MSR_IA32_VMX_TRUE_PROCBASED_CTLS	0x48e
#define	IA32_VMX_PROCBASED_2ND_CTLS	(1UL << 31)

#define	MSR_IA32_VMX_PROCBASED2_CTLS	0x48b
#define	IA32_VMX_PROCBASED2_EPT		(1UL << 1)
#define	IA32_VMX_PROCBASED2_VPID	(1UL << 5)

#define	MSR_IA32_VMX_EPT_VPID_CAP	0x48c
#define	IA32_VMX_EPT_VPID_EXEC_ONLY		(1UL << 0)
#define	IA32_VMX_EPT_VPID_PWL4			(1UL << 6)
#define	IA32_VMX_EPT_VPID_TYPE_UC		(1UL << 8)
#define	IA32_VMX_EPT_VPID_TYPE_WB		(1UL << 14)
#define	IA32_VMX_EPT_VPID_MAP_2M		(1UL << 16)
#define	IA32_VMX_EPT_VPID_MAP_1G		(1UL << 17)
#define	IA32_VMX_EPT_VPID_HW_AD			(1UL << 21)
#define	IA32_VMX_EPT_VPID_INVEPT		(1UL << 20)
#define	IA32_VMX_EPT_VPID_INVEPT_SINGLE		(1UL << 25)
#define	IA32_VMX_EPT_VPID_INVEPT_ALL		(1UL << 26)
#define	IA32_VMX_EPT_VPID_INVVPID		(1UL << 32)
#define	IA32_VMX_EPT_VPID_INVVPID_ADDR		(1UL << 40)
#define	IA32_VMX_EPT_VPID_INVVPID_SINGLE	(1UL << 41)
#define	IA32_VMX_EPT_VPID_INVVPID_ALL		(1UL << 42)
#define	IA32_VMX_EPT_VPID_INVVPID_RETAIN	(1UL << 43)

/*
 * Intel TSX Control MSRs
 */
#define	MSR_IA32_TSX_CTRL		0x122
#define	IA32_TSX_CTRL_RTM_DISABLE	0x01
#define	IA32_TSX_CTRL_CPUID_CLEAR	0x02

/*
 * Intel Thermal MSRs
 */
#define	MSR_IA32_THERM_INTERRUPT	0x19b
#define	IA32_THERM_INTERRUPT_HIGH_IE	0x00000001
#define	IA32_THERM_INTERRUPT_LOW_IE	0x00000002
#define	IA32_THERM_INTERRUPT_PROCHOT_IE	0x00000004
#define	IA32_THERM_INTERRUPT_FORCEPR_IE	0x00000008
#define	IA32_THERM_INTERRUPT_CRIT_IE	0x00000010
#define	IA32_THERM_INTERRUPT_TR1_VAL(x)	(((x) >> 8) & 0x7f)
#define	IA32_THERM_INTTERUPT_TR1_IE	0x00008000
#define	IA32_THERM_INTTERUPT_TR2_VAL(x)	(((x) >> 16) & 0x7f)
#define	IA32_THERM_INTERRUPT_TR2_IE	0x00800000
#define	IA32_THERM_INTERRUPT_PL_NE	0x01000000

#define	MSR_IA32_THERM_STATUS		0x19c
#define	IA32_THERM_STATUS_STATUS		0x00000001
#define	IA32_THERM_STATUS_STATUS_LOG		0x00000002
#define	IA32_THERM_STATUS_PROCHOT		0x00000004
#define	IA32_THERM_STATUS_PROCHOT_LOG		0x00000008
#define	IA32_THERM_STATUS_CRIT_STATUS		0x00000010
#define	IA32_THERM_STATUS_CRIT_LOG		0x00000020
#define	IA32_THERM_STATUS_TR1_STATUS		0x00000040
#define	IA32_THERM_STATUS_TR1_LOG		0x00000080
#define	IA32_THERM_STATUS_TR2_STATUS		0x00000100
#define	IA32_THERM_STATUS_TR2_LOG		0x00000200
#define	IA32_THERM_STATUS_POWER_LIMIT_STATUS	0x00000400
#define	IA32_THERM_STATUS_POWER_LIMIT_LOG	0x00000800
#define	IA32_THERM_STATUS_CURRENT_STATUS	0x00001000
#define	IA32_THERM_STATUS_CURRENT_LOG		0x00002000
#define	IA32_THERM_STATUS_CROSS_DOMAIN_STATUS	0x00004000
#define	IA32_THERM_STATUS_CROSS_DOMAIN_LOG	0x00008000
#define	IA32_THERM_STATUS_READING(x)		(((x) >> 16) & 0x7f)
#define	IA32_THERM_STATUS_RESOLUTION(x)		(((x) >> 27) & 0x0f)
#define	IA32_THERM_STATUS_READ_VALID		0x80000000

#define	MSR_TEMPERATURE_TARGET		0x1a2
#define	MSR_TEMPERATURE_TARGET_TARGET(x)	(((x) >> 16) & 0xff)
/*
 * Not all models support the offset. Refer to the Intel SDM Volume 4 for a list
 * of which models have support for which bits.
 */
#define	MSR_TEMPERATURE_TARGET_OFFSET(x)	(((x) >> 24) & 0x0f)

#define	MSR_IA32_PACKAGE_THERM_STATUS		0x1b1
#define	IA32_PKG_THERM_STATUS_STATUS		0x00000001
#define	IA32_PKG_THERM_STATUS_STATUS_LOG	0x00000002
#define	IA32_PKG_THERM_STATUS_PROCHOT		0x00000004
#define	IA32_PKG_THERM_STATUS_PROCHOT_LOG	0x00000008
#define	IA32_PKG_THERM_STATUS_CRIT_STATUS	0x00000010
#define	IA32_PKG_THERM_STATUS_CRIT_LOG		0x00000020
#define	IA32_PKG_THERM_STATUS_TR1_STATUS	0x00000040
#define	IA32_PKG_THERM_STATUS_TR1_LOG		0x00000080
#define	IA32_PKG_THERM_STATUS_TR2_STATUS	0x00000100
#define	IA32_PKG_THERM_STATUS_TR2_LOG		0x00000200
#define	IA32_PKG_THERM_STATUS_READING(x)	(((x) >> 16) & 0x7f)

#define	MSR_IA32_PACKAGE_THERM_INTERRUPT	0x1b2
#define	IA32_PKG_THERM_INTERRUPT_HIGH_IE	0x00000001
#define	IA32_PKG_THERM_INTERRUPT_LOW_IE		0x00000002
#define	IA32_PKG_THERM_INTERRUPT_PROCHOT_IE	0x00000004
#define	IA32_PKG_THERM_INTERRUPT_OVERHEAT_IE	0x00000010
#define	IA32_PKG_THERM_INTERRUPT_TR1_VAL(x)	(((x) >> 8) & 0x7f)
#define	IA32_PKG_THERM_INTTERUPT_TR1_IE		0x00008000
#define	IA32_PKG_THERM_INTTERUPT_TR2_VAL(x)	(((x) >> 16) & 0x7f)
#define	IA32_PKG_THERM_INTERRUPT_TR2_IE		0x00800000
#define	IA32_PKG_THERM_INTERRUPT_PL_NE		0x01000000

/*
 * AMD Performance counters
 *
 * Older (pre-F15h) CPUs exposed a set of 4 CPU performance counters, along with
 * corresponding control registers.  F15h and later CPUs added an additional 2
 * CPU counters, exposing them all through a new range of MSRs (with the
 * original 4 counters aliasing onto the new ones, entries 0-3)
 *
 * Support for those newer extended counters is denoted by CPUID_AMD_ECX_PCEC in
 * function 0x80000001.
 */
#define	MSR_AMD_K7_PERF_EVTSEL0		0xc0010000
#define	MSR_AMD_K7_PERF_EVTSEL1		0xc0010001
#define	MSR_AMD_K7_PERF_EVTSEL2		0xc0010002
#define	MSR_AMD_K7_PERF_EVTSEL3		0xc0010003
#define	MSR_AMD_K7_PERF_CTR0		0xc0010004
#define	MSR_AMD_K7_PERF_CTR1		0xc0010005
#define	MSR_AMD_K7_PERF_CTR2		0xc0010006
#define	MSR_AMD_K7_PERF_CTR3		0xc0010007

#define	MSR_AMD_F15H_PERF_EVTSEL0	0xc0010200
#define	MSR_AMD_F15H_PERF_EVTSEL1	0xc0010202
#define	MSR_AMD_F15H_PERF_EVTSEL2	0xc0010204
#define	MSR_AMD_F15H_PERF_EVTSEL3	0xc0010206
#define	MSR_AMD_F15H_PERF_EVTSEL4	0xc0010208
#define	MSR_AMD_F15H_PERF_EVTSEL5	0xc001020a

#define	MSR_AMD_F15H_PERF_CTR0		0xc0010201
#define	MSR_AMD_F15H_PERF_CTR1		0xc0010203
#define	MSR_AMD_F15H_PERF_CTR2		0xc0010205
#define	MSR_AMD_F15H_PERF_CTR3		0xc0010207
#define	MSR_AMD_F15H_PERF_CTR4		0xc0010209
#define	MSR_AMD_F15H_PERF_CTR5		0xc001020b

#define	AMD_PERF_EVTSEL_EVT_MASK	0xf000000ff	/* Event select bits */
#define	AMD_PERF_EVTSEL_UNIT_MASK	0xff00		/* Unit mask */
#define	AMD_PERF_EVTSEL_USER_MODE	(1 << 16)	/* User mode */
#define	AMD_PERF_EVTSEL_OS_MODE		(1 << 17)	/* OS mode */
#define	AMD_PERF_EVTSEL_EDGE		(1 << 18)	/* Edge detect */
#define	AMD_PERF_EVTSEL_INT_EN		(1 << 20)	/* Interrupt enable */
#define	AMD_PERF_EVTSEL_CTR_EN		(1 << 22)	/* Counter enable */
#define	AMD_PERF_EVTSEL_INV_CMP		(1 << 23)	/* Invert comparison */
#define	AMD_PERF_EVTSEL_CNT_MASK	0xff000000	/* Counter mask */
#define	AMD_PERF_EVTSEL_HG_MASK		0x30000000000	/* Host/guest mask */

#define	AMD_PERF_EVTSEL_HG_GUEST	0x10000000000	/* Guest-only */
#define	AMD_PERF_EVTSEL_HG_HOST		0x20000000000	/* Host-only */
#define	AMD_PERF_EVTSEL_HG_BOTH		0x30000000000	/* Guest and host */

/*
 * AMD TOM and TOM2 MSRs. These control the split between DRAM and MMIO below
 * and above 4 GiB respectively. These have existed since family 0xf.
 *
 * Note that these widened around the time of Zen 4, going from 48 to 52 bits.
 * However, in a presumed nod to backwards compatibily, the AMD APM Vol 2
 * section 7.9.4 ("Top of Memory"), states that "a given processor may implement
 * fewer than the architecturally-defined number of physical address bits."  It
 * also states that unused bits are ignored, though system software should zero
 * them for compatibility future extensions.  These facts taken together suggest
 * that we are safe to define these masks as the widest architecturally allowed.
 */
#define	MSR_AMD_TOM				0xc001001a
#define	MSR_AMD_TOM_MASK(x)			((x) & 0x000fffffff800000)
#define	MSR_AMD_TOM2				0xc001001d
#define	MSR_AMD_TOM2_MASK(x)			((x) & 0x000fffffff800000)


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
#define	X86FSET_IBRS		71
#define	X86FSET_IBPB		72
#define	X86FSET_STIBP		73
#define	X86FSET_SSBD		74
#define	X86FSET_SSBD_VIRT	75
#define	X86FSET_RDCL_NO		76
#define	X86FSET_IBRS_ALL	77
#define	X86FSET_RSBA		78
#define	X86FSET_SSB_NO		79
#define	X86FSET_STIBP_ALL	80
#define	X86FSET_FLUSH_CMD	81
#define	X86FSET_L1D_VM_NO	82
#define	X86FSET_FSGSBASE	83
#define	X86FSET_CLFLUSHOPT	84
#define	X86FSET_CLWB		85
#define	X86FSET_MONITORX	86
#define	X86FSET_CLZERO		87
#define	X86FSET_XOP		88
#define	X86FSET_FMA4		89
#define	X86FSET_TBM		90
#define	X86FSET_AVX512VNNI	91
#define	X86FSET_AMD_PCEC	92
#define	X86FSET_MD_CLEAR	93
#define	X86FSET_MDS_NO		94
#define	X86FSET_CORE_THERMAL	95
#define	X86FSET_PKG_THERMAL	96
#define	X86FSET_TSX_CTRL	97
#define	X86FSET_TAA_NO		98
#define	X86FSET_PPIN		99
#define	X86FSET_VAES		100
#define	X86FSET_VPCLMULQDQ	101
#define	X86FSET_LFENCE_SER	102
#define	X86FSET_GFNI		103
#define	X86FSET_AVX512_VP2INT	104
#define	X86FSET_AVX512_BITALG	105
#define	X86FSET_AVX512_VBMI2	106
#define	X86FSET_AVX512_BF16	107
#define	X86FSET_AUTO_IBRS	108
#define	X86FSET_RFDS_NO		109
#define	X86FSET_RFDS_CLEAR	110
#define	X86FSET_PBRSB_NO	111
#define	X86FSET_BHI_NO		112
#define	X86FSET_BHI_CTRL	113

/*
 * Intel Deep C-State invariant TSC in leaf 0x80000007.
 */
#define	CPUID_TSC_CSTATE_INVARIANCE	(0x100)

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

#define	X86_VENDOR_HYGON	11
#define	X86_VENDORSTR_HYGON	"HygonGenuine"

/*
 * Vendor string max len + \0
 */
#define	X86_VENDOR_STRLEN	13

/*
 * For lookups and matching functions only; not an actual vendor.
 */
#define	_X86_VENDOR_MATCH_ALL	0xff

/*
 * See the big theory statement at the top of cpuid.c for information about how
 * processor families and microarchitecture families relate to cpuid families,
 * models, and steppings.
 */

#define	_X86_CHIPREV_VENDOR_SHIFT	24
#define	_X86_CHIPREV_FAMILY_SHIFT	16

#define	_X86_CHIPREV_VENDOR(x)		\
	bitx32((uint32_t)(x), 31, _X86_CHIPREV_VENDOR_SHIFT)

#define	_X86_CHIPREV_FAMILY(x)		\
	bitx32((uint32_t)(x), 23, _X86_CHIPREV_FAMILY_SHIFT)

#define	_X86_CHIPREV_REV(x) \
	bitx32((uint32_t)(x), 15, 0)

#define	_X86_CHIPREV_MKREV(vendor, family, rev) \
	((uint32_t)(vendor) << _X86_CHIPREV_VENDOR_SHIFT | \
	(uint32_t)(family) << _X86_CHIPREV_FAMILY_SHIFT | (uint32_t)(rev))

/*
 * The legacy families here are a little bit unfortunate.  Part of this is that
 * the way AMD used the cpuid family/model/stepping changed somewhat over time,
 * but the more immediate reason it's this way is more that the way we use
 * chiprev/processor family changed with it.  The ancient amd_opteron and mc-amd
 * drivers used the chiprevs that were based on cpuid family, mainly 0xf and
 * 0x10.  amdzen_umc wants the processor family, in part because AMD's
 * overloading of the cpuid family has made it effectively useless for
 * discerning anything about the processor.  That also tied into the way
 * amd_revmap was previously organised in cpuid_subr.c: up to family 0x14
 * everything was just "rev A", "rev B", etc.; afterward we started using the
 * new shorthand, again tied to how AMD was presenting this information.
 * Because there are other consumers of the processor family, it no longer made
 * sense for amdzen to derive the processor family from the cpuid family/model
 * given that we have this collection of definitions already and code in
 * cpuid_subr.c to make use of them.  The result is this unified approach that
 * tries to keep old consumers happy while allowing new ones to get the degree
 * of detail they need and expect.  That required bending things a bit to make
 * them fit, though critically as long as AMD keep on their current path and all
 * new consumers look like the ones we are adding these days, we will be able to
 * continue making new additions that will match all the recent ones and the way
 * AMD are currently using families and models.  There is absolutely no reason
 * we couldn't go back and dig through all the legacy parts and break them down
 * the same way, then change the old MC and CPU drivers to match, but I didn't
 * feel like doing a lot of work for processors that it's unlikely anyone is
 * still using and even more unlikely anyone will introduce new code to support.
 * My compromise was to flesh things out starting where we already had more
 * detail even if nothing was consuming it programmatically: at 0x15.  Before
 * that, processor family and cpuid family were effectively the same, because
 * that's what those old consumers expect.
 */

#ifndef	_ASM
typedef enum x86_processor_family {
	X86_PF_UNKNOWN,
	X86_PF_AMD_LEGACY_F = 0xf,
	X86_PF_AMD_LEGACY_10 = 0x10,
	X86_PF_AMD_LEGACY_11 = 0x11,
	X86_PF_AMD_LEGACY_12 = 0x12,
	X86_PF_AMD_LEGACY_14 = 0x14,
	X86_PF_AMD_OROCHI,
	X86_PF_AMD_TRINITY,
	X86_PF_AMD_KAVERI,
	X86_PF_AMD_CARRIZO,
	X86_PF_AMD_STONEY_RIDGE,
	X86_PF_AMD_KABINI,
	X86_PF_AMD_MULLINS,
	X86_PF_AMD_NAPLES,
	X86_PF_AMD_PINNACLE_RIDGE,
	X86_PF_AMD_RAVEN_RIDGE,
	X86_PF_AMD_PICASSO,
	X86_PF_AMD_DALI,
	X86_PF_AMD_ROME,
	X86_PF_AMD_RENOIR,
	X86_PF_AMD_MATISSE,
	X86_PF_AMD_VAN_GOGH,
	X86_PF_AMD_MENDOCINO,
	X86_PF_HYGON_DHYANA,
	X86_PF_AMD_MILAN,
	X86_PF_AMD_GENOA,
	X86_PF_AMD_VERMEER,
	X86_PF_AMD_REMBRANDT,
	X86_PF_AMD_CEZANNE,
	X86_PF_AMD_RAPHAEL,
	X86_PF_AMD_PHOENIX,
	X86_PF_AMD_BERGAMO,
	X86_PF_AMD_TURIN,
	X86_PF_AMD_DENSE_TURIN,
	X86_PF_AMD_STRIX,
	X86_PF_AMD_GRANITE_RIDGE,
	X86_PF_AMD_KRACKAN,
	X86_PF_AMD_STRIX_HALO,

	X86_PF_ANY = 0xff
} x86_processor_family_t;

#define	_DECL_CHIPREV(_v, _f, _revn, _revb)	\
	X86_CHIPREV_ ## _v ## _ ## _f ## _ ## _revn =	\
	_X86_CHIPREV_MKREV(X86_VENDOR_ ## _v, X86_PF_ ## _v ## _ ## _f,	_revb)

#define	_X86_CHIPREV_REV_MATCH_ALL	0xffff

typedef enum x86_chiprev {
	X86_CHIPREV_UNKNOWN,
	_DECL_CHIPREV(AMD, LEGACY_F, REV_B, 0x0001),
	/*
	 * Definitions for AMD Family 0xf. Minor revisions C0 and CG are
	 * sufficiently different that we will distinguish them; in all other
	 * case we will identify the major revision.
	 */
	_DECL_CHIPREV(AMD, LEGACY_F, REV_C0, 0x0002),
	_DECL_CHIPREV(AMD, LEGACY_F, REV_CG, 0x0004),
	_DECL_CHIPREV(AMD, LEGACY_F, REV_D, 0x0008),
	_DECL_CHIPREV(AMD, LEGACY_F, REV_E, 0x0010),
	_DECL_CHIPREV(AMD, LEGACY_F, REV_F, 0x0020),
	_DECL_CHIPREV(AMD, LEGACY_F, REV_G, 0x0040),
	_DECL_CHIPREV(AMD, LEGACY_F, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, LEGACY_10, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, LEGACY_10, REV_A, 0x0002),
	_DECL_CHIPREV(AMD, LEGACY_10, REV_B, 0x0004),
	_DECL_CHIPREV(AMD, LEGACY_10, REV_C2, 0x0008),
	_DECL_CHIPREV(AMD, LEGACY_10, REV_C3, 0x0010),
	_DECL_CHIPREV(AMD, LEGACY_10, REV_D0, 0x0020),
	_DECL_CHIPREV(AMD, LEGACY_10, REV_D1, 0x0040),
	_DECL_CHIPREV(AMD, LEGACY_10, REV_E, 0x0080),
	_DECL_CHIPREV(AMD, LEGACY_10, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, LEGACY_11, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, LEGACY_11, REV_B, 0x0002),
	_DECL_CHIPREV(AMD, LEGACY_11, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, LEGACY_12, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, LEGACY_12, REV_B, 0x0002),
	_DECL_CHIPREV(AMD, LEGACY_12, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, LEGACY_14, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, LEGACY_14, REV_B, 0x0002),
	_DECL_CHIPREV(AMD, LEGACY_14, REV_C, 0x0004),
	_DECL_CHIPREV(AMD, LEGACY_14, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, OROCHI, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, OROCHI, REV_B2, 0x0002),
	_DECL_CHIPREV(AMD, OROCHI, REV_C0, 0x0004),
	_DECL_CHIPREV(AMD, OROCHI, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, TRINITY, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, TRINITY, REV_A1, 0x0002),
	_DECL_CHIPREV(AMD, TRINITY, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, KAVERI, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, KAVERI, REV_A1, 0x0002),
	_DECL_CHIPREV(AMD, KAVERI, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, CARRIZO, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, CARRIZO, REV_A0, 0x0002),
	_DECL_CHIPREV(AMD, CARRIZO, REV_A1, 0x0004),
	_DECL_CHIPREV(AMD, CARRIZO, REV_DDR4, 0x0008),
	_DECL_CHIPREV(AMD, CARRIZO, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, STONEY_RIDGE, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, STONEY_RIDGE, REV_A0, 0x0002),
	_DECL_CHIPREV(AMD, STONEY_RIDGE, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, KABINI, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, KABINI, A1, 0x0002),
	_DECL_CHIPREV(AMD, KABINI, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, MULLINS, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, MULLINS, A1, 0x0002),
	_DECL_CHIPREV(AMD, MULLINS, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, NAPLES, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, NAPLES, A0, 0x0002),
	_DECL_CHIPREV(AMD, NAPLES, B1, 0x0004),
	_DECL_CHIPREV(AMD, NAPLES, B2, 0x0008),
	_DECL_CHIPREV(AMD, NAPLES, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, PINNACLE_RIDGE, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, PINNACLE_RIDGE, B2, 0x0002),
	_DECL_CHIPREV(AMD, PINNACLE_RIDGE, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, RAVEN_RIDGE, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, RAVEN_RIDGE, B0, 0x0002),
	_DECL_CHIPREV(AMD, RAVEN_RIDGE, B1, 0x0004),
	_DECL_CHIPREV(AMD, RAVEN_RIDGE, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, PICASSO, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, PICASSO, B1, 0x0002),
	_DECL_CHIPREV(AMD, PICASSO, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, DALI, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, DALI, A1, 0x0002),
	_DECL_CHIPREV(AMD, DALI, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, ROME, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, ROME, A0, 0x0002),
	_DECL_CHIPREV(AMD, ROME, B0, 0x0004),
	_DECL_CHIPREV(AMD, ROME, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, RENOIR, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, RENOIR, A1, 0x0002),
	_DECL_CHIPREV(AMD, RENOIR, LCN_A1, 0x0004),
	_DECL_CHIPREV(AMD, RENOIR, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, MATISSE, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, MATISSE, B0, 0x0002),
	_DECL_CHIPREV(AMD, MATISSE, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, VAN_GOGH, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, VAN_GOGH, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, MENDOCINO, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, MENDOCINO, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(HYGON, DHYANA, UNKNOWN, 0x0001),
	_DECL_CHIPREV(HYGON, DHYANA, A1, 0x0002),
	_DECL_CHIPREV(HYGON, DHYANA, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, MILAN, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, MILAN, A0, 0x0002),
	_DECL_CHIPREV(AMD, MILAN, B0, 0x0004),
	_DECL_CHIPREV(AMD, MILAN, B1, 0x0008),
	_DECL_CHIPREV(AMD, MILAN, B2, 0x0010),
	_DECL_CHIPREV(AMD, MILAN, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, GENOA, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, GENOA, A0, 0x0002),
	_DECL_CHIPREV(AMD, GENOA, A1, 0x0004),
	_DECL_CHIPREV(AMD, GENOA, B0, 0x0008),
	_DECL_CHIPREV(AMD, GENOA, B1, 0x0010),
	_DECL_CHIPREV(AMD, GENOA, B2, 0x0020),
	_DECL_CHIPREV(AMD, GENOA, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, VERMEER, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, VERMEER, A0, 0x0002),
	_DECL_CHIPREV(AMD, VERMEER, B0, 0x0004),
	_DECL_CHIPREV(AMD, VERMEER, B2, 0x0008),	/* No B1 */
	_DECL_CHIPREV(AMD, VERMEER, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, REMBRANDT, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, REMBRANDT, A0, 0x0002),
	_DECL_CHIPREV(AMD, REMBRANDT, B0, 0x0004),
	_DECL_CHIPREV(AMD, REMBRANDT, B1, 0x0008),
	_DECL_CHIPREV(AMD, REMBRANDT, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, CEZANNE, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, CEZANNE, A0, 0x0002),
	_DECL_CHIPREV(AMD, CEZANNE, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, RAPHAEL, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, RAPHAEL, B2, 0x0002),
	_DECL_CHIPREV(AMD, RAPHAEL, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, PHOENIX, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, PHOENIX, A0, 0x0002),
	_DECL_CHIPREV(AMD, PHOENIX, A1, 0x0004),
	_DECL_CHIPREV(AMD, PHOENIX, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, BERGAMO, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, BERGAMO, A0, 0x0002),
	_DECL_CHIPREV(AMD, BERGAMO, A1, 0x0004),
	_DECL_CHIPREV(AMD, BERGAMO, A2, 0x0008),
	_DECL_CHIPREV(AMD, BERGAMO, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, TURIN, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, TURIN, A0, 0x0002),
	_DECL_CHIPREV(AMD, TURIN, B0, 0x0004),
	_DECL_CHIPREV(AMD, TURIN, B1, 0x0008),
	_DECL_CHIPREV(AMD, TURIN, C0, 0x0010),
	_DECL_CHIPREV(AMD, TURIN, C1, 0x0020),
	_DECL_CHIPREV(AMD, TURIN, ANY, _X86_CHIPREV_REV_MATCH_ALL),
	_DECL_CHIPREV(AMD, DENSE_TURIN, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, DENSE_TURIN, A0, 0x0002),
	_DECL_CHIPREV(AMD, DENSE_TURIN, B0, 0x0004),
	_DECL_CHIPREV(AMD, DENSE_TURIN, B1, 0x0008),
	_DECL_CHIPREV(AMD, DENSE_TURIN, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, STRIX, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, STRIX, B0, 0x0002),
	_DECL_CHIPREV(AMD, STRIX, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, GRANITE_RIDGE, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, GRANITE_RIDGE, B0, 0x0002),
	_DECL_CHIPREV(AMD, GRANITE_RIDGE, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, KRACKAN, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, KRACKAN, A0, 0x0002),
	_DECL_CHIPREV(AMD, KRACKAN, ANY, _X86_CHIPREV_REV_MATCH_ALL),

	_DECL_CHIPREV(AMD, STRIX_HALO, UNKNOWN, 0x0001),
	_DECL_CHIPREV(AMD, STRIX_HALO, A0, 0x0002),
	_DECL_CHIPREV(AMD, STRIX_HALO, ANY, _X86_CHIPREV_REV_MATCH_ALL),


	/* Keep at the end */
	X86_CHIPREV_ANY = _X86_CHIPREV_MKREV(_X86_VENDOR_MATCH_ALL, X86_PF_ANY,
	    _X86_CHIPREV_REV_MATCH_ALL)
} x86_chiprev_t;

#undef	_DECL_CHIPREV

/*
 * Same thing, but for microarchitecture (core implementations).  We are not
 * attempting to capture every possible fine-grained detail here; to the extent
 * that it matters, we do so in cpuid.c via ISA/feature bits.  We use the same
 * number of bits for each field as in chiprev.
 */

#define	_X86_UARCHREV_VENDOR(x)	_X86_CHIPREV_VENDOR(x)
#define	_X86_UARCHREV_UARCH(x)	_X86_CHIPREV_FAMILY(x)
#define	_X86_UARCHREV_REV(x)	_X86_CHIPREV_REV(x)

#define	_X86_UARCHREV_MKREV(vendor, family, rev) \
	_X86_CHIPREV_MKREV(vendor, family, rev)

typedef enum x86_uarch {
	X86_UARCH_UNKNOWN,

	X86_UARCH_AMD_LEGACY,
	X86_UARCH_AMD_ZEN1,
	X86_UARCH_AMD_ZENPLUS,
	X86_UARCH_AMD_ZEN2,
	X86_UARCH_AMD_ZEN3,
	X86_UARCH_AMD_ZEN4,
	X86_UARCH_AMD_ZEN5,

	X86_UARCH_ANY = 0xff
} x86_uarch_t;

#define	_DECL_UARCHREV(_v, _f, _revn, _revb)	\
	X86_UARCHREV_ ## _v ## _ ## _f ## _ ## _revn =	\
	_X86_UARCHREV_MKREV(X86_VENDOR_ ## _v, X86_UARCH_ ## _v ## _ ## _f, \
	_revb)

#define	_DECL_UARCHREV_NOREV(_v, _f, _revb)	\
	X86_UARCHREV_ ## _v ## _ ## _f =	\
	_X86_UARCHREV_MKREV(X86_VENDOR_ ## _v, X86_UARCH_ ## _v ## _ ## _f, \
	_revb)

#define	_X86_UARCHREV_REV_MATCH_ALL	0xffff

typedef enum x86_uarchrev {
	X86_UARCHREV_UNKNOWN,
	_DECL_UARCHREV_NOREV(AMD, LEGACY, 0x0001),
	_DECL_UARCHREV(AMD, LEGACY, ANY, _X86_UARCHREV_REV_MATCH_ALL),

	_DECL_UARCHREV_NOREV(AMD, ZEN1, 0x0001),
	_DECL_UARCHREV(AMD, ZEN1, ANY, _X86_UARCHREV_REV_MATCH_ALL),

	_DECL_UARCHREV_NOREV(AMD, ZENPLUS, 0x0001),
	_DECL_UARCHREV(AMD, ZENPLUS, ANY, _X86_UARCHREV_REV_MATCH_ALL),

	_DECL_UARCHREV(AMD, ZEN2, UNKNOWN, 0x0001),
	_DECL_UARCHREV(AMD, ZEN2, A0, 0x0002),
	_DECL_UARCHREV(AMD, ZEN2, B0, 0x0004),
	_DECL_UARCHREV(AMD, ZEN2, ANY, _X86_UARCHREV_REV_MATCH_ALL),

	_DECL_UARCHREV(AMD, ZEN3, UNKNOWN, 0x0001),
	_DECL_UARCHREV(AMD, ZEN3, A0, 0x0002),
	_DECL_UARCHREV(AMD, ZEN3, B0, 0x0004),
	_DECL_UARCHREV(AMD, ZEN3, B1, 0x0008),
	_DECL_UARCHREV(AMD, ZEN3, B2, 0x0010),
	_DECL_UARCHREV(AMD, ZEN3, ANY, _X86_UARCHREV_REV_MATCH_ALL),

	_DECL_UARCHREV(AMD, ZEN4, UNKNOWN, 0x0001),
	_DECL_UARCHREV(AMD, ZEN4, A0, 0x0002),
	_DECL_UARCHREV(AMD, ZEN4, A1, 0x0004),
	_DECL_UARCHREV(AMD, ZEN4, A2, 0x0008),
	_DECL_UARCHREV(AMD, ZEN4, B0, 0x0010),
	_DECL_UARCHREV(AMD, ZEN4, B1, 0x0020),
	_DECL_UARCHREV(AMD, ZEN4, B2, 0x0040),
	_DECL_UARCHREV(AMD, ZEN4, ANY, _X86_UARCHREV_REV_MATCH_ALL),

	_DECL_UARCHREV(AMD, ZEN5, UNKNOWN, 0x0001),
	_DECL_UARCHREV(AMD, ZEN5, A0, 0x0002),
	_DECL_UARCHREV(AMD, ZEN5, B0, 0x0004),
	_DECL_UARCHREV(AMD, ZEN5, B1, 0x0008),
	_DECL_UARCHREV(AMD, ZEN5, C0, 0x0010),
	_DECL_UARCHREV(AMD, ZEN5, C1, 0x0020),
	_DECL_UARCHREV(AMD, ZEN5, ANY, _X86_UARCHREV_REV_MATCH_ALL),

	/* Keep at the end */
	_X86_UARCHREV_ANY = _X86_UARCHREV_MKREV(_X86_VENDOR_MATCH_ALL,
	    X86_UARCH_ANY, _X86_UARCHREV_REV_MATCH_ALL)
} x86_uarchrev_t;

#undef	_DECL_UARCHREV

#endif	/* !_ASM */

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
#define	X86_SOCKET_754		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x01)
#define	X86_SOCKET_939		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x02)
#define	X86_SOCKET_940		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x03)
#define	X86_SOCKET_S1g1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x04)
#define	X86_SOCKET_AM2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x05)
#define	X86_SOCKET_F1207	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x06)
#define	X86_SOCKET_S1g2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x07)
#define	X86_SOCKET_S1g3		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x08)
#define	X86_SOCKET_AM		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x09)
#define	X86_SOCKET_AM2R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x0a)
#define	X86_SOCKET_AM3		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x0b)
#define	X86_SOCKET_G34		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x0c)
#define	X86_SOCKET_ASB2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x0d)
#define	X86_SOCKET_C32		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x0e)
#define	X86_SOCKET_S1g4		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x0f)
#define	X86_SOCKET_FT1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x10)
#define	X86_SOCKET_FM1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x11)
#define	X86_SOCKET_FS1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x12)
#define	X86_SOCKET_AM3R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x13)
#define	X86_SOCKET_FP2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x14)
#define	X86_SOCKET_FS1R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x15)
#define	X86_SOCKET_FM2		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x16)
#define	X86_SOCKET_FP3		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x17)
#define	X86_SOCKET_FM2R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x18)
#define	X86_SOCKET_FP4		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x19)
#define	X86_SOCKET_AM4		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x1a)
#define	X86_SOCKET_FT3		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x1b)
#define	X86_SOCKET_FT4		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x1c)
#define	X86_SOCKET_FS1B		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x1d)
#define	X86_SOCKET_FT3B		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x1e)
#define	X86_SOCKET_SP3		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x1f)
#define	X86_SOCKET_SP3R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x20)
#define	X86_SOCKET_FP5		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x21)
#define	X86_SOCKET_FP6		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x22)
#define	X86_SOCKET_STRX4	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x23)
#define	X86_SOCKET_SP5		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x24)
#define	X86_SOCKET_AM5		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x25)
#define	X86_SOCKET_FP7		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x26)
#define	X86_SOCKET_FP7R2	_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x27)
#define	X86_SOCKET_FF3		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x28)
#define	X86_SOCKET_FT6		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x29)
#define	X86_SOCKET_FP8		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x2a)
#define	X86_SOCKET_FL1		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x2b)
#define	X86_SOCKET_SP6		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x2c)
#define	X86_SOCKET_TR5		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x2d)
#define	X86_SOCKET_FP11		_X86_SOCKET_MKVAL(X86_VENDOR_AMD, 0x2e)
#define	X86_NUM_SOCKETS_AMD	0x2e

/*
 * Hygon socket types
 */
#define	X86_SOCKET_SL1		_X86_SOCKET_MKVAL(X86_VENDOR_HYGON, 0x01)
#define	X86_SOCKET_SL1R2	_X86_SOCKET_MKVAL(X86_VENDOR_HYGON, 0x02)
#define	X86_SOCKET_DM1		_X86_SOCKET_MKVAL(X86_VENDOR_HYGON, 0x03)
#define	X86_NUM_SOCKETS_HYGON	0x03

#define	X86_NUM_SOCKETS		(X86_NUM_SOCKETS_AMD + X86_NUM_SOCKETS_HYGON)

/*
 * Definitions for Intel processor models. These are all for Family 6
 * processors. This list and the Atom set below it are not exhuastive.
 */
#define	INTC_MODEL_YONAH		0x0e
#define	INTC_MODEL_MEROM		0x0f
#define	INTC_MODEL_MEROM_L		0x16
#define	INTC_MODEL_PENRYN		0x17
#define	INTC_MODEL_DUNNINGTON		0x1d

#define	INTC_MODEL_NEHALEM		0x1e
#define	INTC_MODEL_NEHALEM2		0x1f
#define	INTC_MODEL_NEHALEM_EP		0x1a
#define	INTC_MODEL_NEHALEM_EX		0x2e

#define	INTC_MODEL_WESTMERE		0x25
#define	INTC_MODEL_WESTMERE_EP		0x2c
#define	INTC_MODEL_WESTMERE_EX		0x2f

#define	INTC_MODEL_SANDYBRIDGE		0x2a
#define	INTC_MODEL_SANDYBRIDGE_XEON	0x2d
#define	INTC_MODEL_IVYBRIDGE		0x3a
#define	INTC_MODEL_IVYBRIDGE_XEON	0x3e

#define	INTC_MODEL_HASWELL		0x3c
#define	INTC_MODEL_HASWELL_ULT		0x45
#define	INTC_MODEL_HASWELL_GT3E		0x46
#define	INTC_MODEL_HASWELL_XEON		0x3f

#define	INTC_MODEL_BROADWELL		0x3d
#define	INTC_MODEL_BROADWELL_2		0x47
#define	INTC_MODEL_BROADWELL_XEON	0x4f
#define	INTC_MODEL_BROADWELL_XEON_D	0x56

#define	INTC_MODEL_SKYLAKE_MOBILE	0x4e
/*
 * Note, this model is shared with Cascade Lake and Cooper Lake.
 */
#define	INTC_MODEL_SKYLAKE_XEON		0x55
#define	INTC_MODEL_SKYLAKE_DESKTOP	0x5e

#define	INTC_MODEL_CANNON_LAKE		0x66

/*
 * Note, both Kaby Lake models are shared with Coffee Lake, Whiskey Lake, Amber
 * Lake, and some Comet Lake parts.
 */
#define	INTC_MODEL_KABYLAKE_MOBILE	0x8e
#define	INTC_MODEL_KABYLAKE_DESKTOP	0x9e

#define	INTC_MODEL_ICELAKE_XEON		0x6a
#define	INTC_MODEL_ICELAKE_MOBILE	0x7e
#define	INTC_MODEL_ICELAKE_XEON_DE	0x6c

#define	INTC_MODEL_TIGERLAKE_MOBILE	0x8c
#define	INTC_MODEL_TIGERLAKE_MOBILE_2	0x8d
#define	INTC_MODEL_SAPPHIRE_RAPIDS	0x8f

#define	INTC_MODEL_COMETLAKE		0xa5
#define	INTC_MODEL_COMETLAKE_MOBILE	0xa6
#define	INTC_MODEL_ROCKETLAKE		0xa7

#define	INTC_MODEL_ALDER_LAKE_DESKTOP	0x97
#define	INTC_MODEL_ALDER_LAKE_MOBILE	0x9a	/* And some Atom parts too */
#define	INTC_MODEL_RAPTOR_LAKE_MOBILE_1	0xb7
#define	INTC_MODEL_RAPTOR_LAKE_MOBILE_2	0xba
#define	INTC_MODEL_RAPTOR_LAKE_MOBILE_3	0xbf

#define	INTC_MODEL_METEOR_LAKE		0xaa

#define	INTC_MODEL_EMERALD_RAPIDS	0xcf

/*
 * Atom Processors
 */
#define	INTC_MODEL_SILVERTHORNE		0x1c
#define	INTC_MODEL_LINCROFT		0x26
#define	INTC_MODEL_PENWELL		0x27
#define	INTC_MODEL_CLOVERVIEW		0x35
#define	INTC_MODEL_CEDARVIEW		0x36
#define	INTC_MODEL_BAY_TRAIL		0x37
#define	INTC_MODEL_MERRIFIELD		0x4a
#define	INTC_MODEL_AVATON		0x4d
#define	INTC_MODEL_AIRMONT		0x4c
#define	INTC_MODEL_MOOREFIELD		0x5a
#define	INTC_MODEL_APOLLO_LAKE		0x5c
#define	INTC_MODEL_SOFIA_3G_R		0x5d
#define	INTC_MODEL_DENVERTON		0x5f
#define	INTC_MODEL_GEMINI_LAKE		0x7a
#define	INTC_MODEL_TREMONT		0x86	/* Parker Ridge & Snow Ridge */
#define	INTC_MODEL_LAKEFIELD		0x8a
#define	INTC_MODEL_ELKHART_LAKE		0x96
#define	INTC_MODEL_JASPER_LAKE		0x9c
#define	INTC_MODEL_ALDER_LAKE_N		0xbe	/* And some {desk,lap}top too */

/*
 * xgetbv/xsetbv support
 * See section 13.3 in vol. 1 of the Intel Developer's manual.
 */

#define	XFEATURE_ENABLED_MASK	0x0
/*
 * XFEATURE_ENABLED_MASK values (eax)
 * See setup_xfem().
 */
#define	XFEATURE_LEGACY_FP	(1 << 0)
#define	XFEATURE_SSE		(1 << 1)
#define	XFEATURE_AVX		(1 << 2)
/*
 * MPX is meant to be all or nothing, therefore for most of the kernel prefer
 * the XFEATURE_MPX definition over the individual state bits.
 */
#define	XFEATURE_MPX_BNDREGS	(1 << 3)
#define	XFEATURE_MPX_BNDCSR	(1 << 4)
#define	XFEATURE_MPX		(XFEATURE_MPX_BNDREGS | XFEATURE_MPX_BNDCSR)
/*
 * AX512 is meant to be all or nothing, therefore for most of the kernel prefer
 * the XFEATURE_AVX512 definition over the individual state bits.
 */
#define	XFEATURE_AVX512_OPMASK	(1 << 5)
#define	XFEATURE_AVX512_ZMM	(1 << 6)
#define	XFEATURE_AVX512_HI_ZMM	(1 << 7)
#define	XFEATURE_AVX512		(XFEATURE_AVX512_OPMASK | \
	XFEATURE_AVX512_ZMM | XFEATURE_AVX512_HI_ZMM)
	/* bit 8 unused */
#define	XFEATURE_PKRU		(1 << 9)
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

#define	NUM_X86_FEATURES	114
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

/*
 * These functions are all used to perform various side-channel mitigations.
 * Please see uts/intel/os/cpuid.c for more information.
 */
extern void (*spec_uarch_flush)(void);
extern void x86_rsb_stuff(void);
extern void x86_rsb_stuff_vmexit(void);
extern void x86_bhb_clear(void);
extern void x86_md_clear(void);

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
extern void wrmsr_and_test(uint_t, const uint64_t);

extern void invalidate_cache(void);
extern ulong_t getcr4(void);
extern void setcr4(ulong_t);

extern void mtrr_sync(void);

extern void cpu_fast_syscall_enable(void);
extern void cpu_fast_syscall_disable(void);

typedef enum cpuid_pass {
	CPUID_PASS_NONE = 0,
	CPUID_PASS_PRELUDE,
	CPUID_PASS_IDENT,
	CPUID_PASS_BASIC,
	CPUID_PASS_EXTENDED,
	CPUID_PASS_DYNAMIC,
	CPUID_PASS_RESOLVE
} cpuid_pass_t;

struct cpu;

extern boolean_t cpuid_checkpass(const struct cpu *const, const cpuid_pass_t);
extern void cpuid_execpass(struct cpu *, const cpuid_pass_t, void *);
extern void cpuid_pass_ucode(struct cpu *, uchar_t *);
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
extern size_t cpuid_get_xsave_size(void);
extern void cpuid_get_xsave_info(uint64_t, size_t *, size_t *);
extern boolean_t cpuid_need_fp_excp_handling(void);
extern int cpuid_is_cmt(struct cpu *);
extern int cpuid_syscall32_insn(struct cpu *);
extern int getl2cacheinfo(struct cpu *, int *, int *, int *);

extern x86_chiprev_t cpuid_getchiprev(struct cpu *);
extern const char *cpuid_getchiprevstr(struct cpu *);
extern uint32_t cpuid_getsockettype(struct cpu *);
extern const char *cpuid_getsocketstr(struct cpu *);
extern x86_uarchrev_t cpuid_getuarchrev(struct cpu *);

extern int cpuid_opteron_erratum(struct cpu *, uint_t);

struct cpuid_info;

extern void setx86isalist(void);
extern void cpuid_alloc_space(struct cpu *);
extern void cpuid_free_space(struct cpu *);
extern void cpuid_set_cpu_properties(void *, processorid_t,
    struct cpuid_info *);
extern void cpuid_post_ucodeadm(void);

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

extern x86_processor_family_t chiprev_family(const x86_chiprev_t);
extern boolean_t chiprev_matches(const x86_chiprev_t, const x86_chiprev_t);
extern boolean_t chiprev_at_least(const x86_chiprev_t, const x86_chiprev_t);

extern x86_uarch_t uarchrev_uarch(const x86_uarchrev_t);
extern boolean_t uarchrev_matches(const x86_uarchrev_t, const x86_uarchrev_t);
extern boolean_t uarchrev_at_least(const x86_uarchrev_t, const x86_uarchrev_t);

/*
 * Cache information intended for topology and wider use.
 */
typedef enum {
	X86_CACHE_TYPE_DATA,
	X86_CACHE_TYPE_INST,
	X86_CACHE_TYPE_UNIFIED
} x86_cache_type_t;

typedef enum {
	X86_CACHE_F_FULL_ASSOC	= 1 << 0
} x86_cache_flags_t;

typedef struct x86_cache {
	uint32_t		xc_level;
	x86_cache_type_t	xc_type;
	x86_cache_flags_t	xc_flags;
	uint32_t		xc_nparts;
	uint32_t		xc_nways;
	uint32_t		xc_line_size;
	uint64_t		xc_nsets;
	uint64_t		xc_size;
	uint64_t		xc_id;
	uint32_t		xc_apic_shift;
} x86_cache_t;

extern int cpuid_getncaches(struct cpu *, uint32_t *);
extern int cpuid_getcache(struct cpu *, uint32_t, x86_cache_t *);

struct cpu_ucode_info;

extern void ucode_alloc_space(struct cpu *);
extern void ucode_free_space(struct cpu *);
extern void ucode_init(void);
extern void ucode_check_boot(void);
extern void ucode_read_rev(struct cpu *);
extern void ucode_locate(struct cpu *);
extern void ucode_apply(struct cpu *);
extern void ucode_finish(struct cpu *);
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

#if defined(OPTERON_ERRATUM_147)
extern int opteron_erratum_147;
extern void patch_erratum_147(void);
#endif

#if !defined(__xpv)
extern void determine_platform(void);
#endif
extern int get_hwenv(void);
extern int is_controldom(void);

extern void enable_pcid(void);

extern void xsave_setup_msr(struct cpu *);

#if !defined(__xpv)
extern void reset_gdtr_limit(void);
#endif

extern int enable_platform_detection;

/*
 * Hypervisor signatures
 */
#define	HVSIG_XEN_HVM	"XenVMMXenVMM"
#define	HVSIG_VMWARE	"VMwareVMware"
#define	HVSIG_KVM	"KVMKVMKVM"
#define	HVSIG_MICROSOFT	"Microsoft Hv"
#define	HVSIG_BHYVE	"bhyve bhyve "
#define	HVSIG_QEMU_TCG	"TCGTCGTCGTCG"
#define	HVSIG_VIRTUALBOX	"VBoxVBoxVBox"
#define	HVSIG_ACRN	"ACRNACRNACRN"

/*
 * Defined hardware environments
 */
#define	HW_NATIVE	(1 << 0)	/* Running on bare metal */
#define	HW_XEN_PV	(1 << 1)	/* Running on Xen PVM */

#define	HW_XEN_HVM	(1 << 2)	/* Running on Xen HVM */
#define	HW_VMWARE	(1 << 3)	/* Running on VMware hypervisor */
#define	HW_KVM		(1 << 4)	/* Running on KVM hypervisor */
#define	HW_MICROSOFT	(1 << 5)	/* Running on Microsoft hypervisor */
#define	HW_BHYVE	(1 << 6)	/* Running on bhyve hypervisor */
#define	HW_QEMU_TCG	(1 << 7)	/* Running on QEMU TCG hypervisor */
#define	HW_VIRTUALBOX	(1 << 8)	/* Running on VirtualBox hypervisor */
#define	HW_ACRN		(1 << 9)	/* Running on ACRN hypervisor */

#define	HW_VIRTUAL	(HW_XEN_HVM | HW_VMWARE | HW_KVM | HW_MICROSOFT | \
	    HW_BHYVE | HW_QEMU_TCG | HW_VIRTUALBOX | HW_ACRN)

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
