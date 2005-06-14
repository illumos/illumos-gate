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

#ifndef _SYS_X86_ARCHEXT_H
#define	_SYS_X86_ARCHEXT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
						/* 0x40000000 - reserved */
#define	CPUID_INTC_EDX_PBE	0x80000000	/* Pending Break Enable */

#define	FMT_CPUID_INTC_EDX				\
	"\20"						\
	"\40pbe\36tm\35htt\34ss\33sse2\32sse\31fxsr"	\
	"\30mmx\27acpi\26ds\24clfsh\23psn\22pse36\21pat"\
	"\20cmov\17mca\16pge\15mtrr\14sep\12apic\11cx8"	\
	"\10mce\7pae\6msr\5tsc\4pse\3de\2vme\1fpu"

/*
 * cpuid instruction feature flags in %ecx (standard function 1)
 */

#define	CPUID_INTC_ECX_SSE3	0x00000001	/* Yet more SSE extensions */
						/* 0x00000002 - reserved */
						/* 0x00000004 - reserved */
#define	CPUID_INTC_ECX_MON	0x00000008	/* MONITOR/MWAIT */
#define	CPUID_INTC_ECX_DSCPL	0x00000010	/* CPL-qualified debug store */
						/* 0x00000020 - reserved */
						/* 0x00000040 - reserved */
#define	CPUID_INTC_ECX_EST	0x00000080	/* enhanced SpeedStep */
#define	CPUID_INTC_ECX_TM2	0x00000100	/* thermal monitoring */
						/* 0x00000200 - reserved */
#define	CPUID_INTC_ECX_CID	0x00000400	/* L1 context ID */
						/* 0x00000800 - reserved */
						/* 0x00001000 - reserved */
						/* 0x00002000 - reserved */
#define	CPUID_INTC_ECX_XTPR	0x00004000	/* disable task pri messages */

#define	FMT_CPUID_INTC_ECX			\
	"\20"					\
	"\20\17xtpr\13cid\11tm2"		\
	"\10est\5dscpl\4monitor\1sse3"

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
#define	CPUID_AMD_EDX_PAT	0x00010000	/* page attribute table */
#define	CPUID_AMD_EDX_PSE36	0x00020000	/* 36-bit pagesize extension */
				/* 0x00040000 - reserved */
				/* 0x00080000 - reserved */
#define	CPUID_AMD_EDX_NX	0x00100000	/* AMD: no-execute page prot */
				/* 0x00200000 - reserved */
#define	CPUID_AMD_EDX_MMXamd	0x00400000	/* AMD: MMX extensions */
#define	CPUID_AMD_EDX_MMX	0x00800000	/* MMX instructions */
#define	CPUID_AMD_EDX_FXSR	0x01000000	/* fxsave and fxrstor */
				/* 0x02000000 - reserved */
				/* 0x04000000 - reserved */
				/* 0x08000000 - reserved */
				/* 0x10000000 - reserved */
#define	CPUID_AMD_EDX_LM	0x20000000	/* AMD: long mode */
#define	CPUID_AMD_EDX_3DNowx	0x40000000	/* AMD: extensions to 3DNow! */
#define	CPUID_AMD_EDX_3DNow	0x80000000	/* AMD: 3DNow! instructions */

#define	FMT_CPUID_AMD_EDX					\
	"\20"							\
	"\40a3d\37a3d+\36lm\31fxsr"				\
	"\30mmx\27mmxext\25nx\22pse\21pat"			\
	"\20cmov\17mca\16pge\15mtrr\14syscall\12apic\11cx8"	\
	"\10mce\7pae\6msr\5tsc\4pse\3de\2vme\1fpu"

#define	CPUID_AMD_ECX_HTvalid	0x00000001	/* AMD: HTT bit valid */

#define	FMT_CPUID_AMD_ECX					\
	"\20"							\
	"\1htvalid"

#define	P5_MCHADDR	0x0
#define	P5_CESR		0x11
#define	P5_CTR0		0x12
#define	P5_CTR1		0x13

#define	K5_MCHADDR	0x0
#define	K5_MCHTYPE	0x01
#define	K5_TSC		0x10
#define	K5_TR12		0x12

#define	REG_MTRRCAP		0xfe
#define	REG_MTRRDEF		0x2ff
#define	REG_MTRR64K		0x250
#define	REG_MTRR16K1		0x258
#define	REG_MTRR16K2		0x259
#define	REG_MTRR4K1		0x268
#define	REG_MTRR4K2		0x269
#define	REG_MTRR4K3		0x26a
#define	REG_MTRR4K4		0x26b
#define	REG_MTRR4K5		0x26c
#define	REG_MTRR4K6		0x26d
#define	REG_MTRR4K7		0x26e
#define	REG_MTRR4K8		0x26f
#define	REG_MTRRPAT		0x277

#define	REG_MTRRPHYSBASE0	0x200
#define	REG_MTRRPHYSMASK7	0x20f
#define	REG_MC0_CTL		0x400
#define	REG_MC5_MISC		0x417
#define	REG_PERFCTR0		0xc1
#define	REG_PERFCTR1		0xc2

#define	REG_PERFEVNT0		0x186
#define	REG_PERFEVNT1		0x187

#define	REG_TSC			0x10	/* timestamp counter */
#define	REG_APIC_BASE_MSR	0x1b

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

#define	REG_MCG_CAP		0x179
#define	REG_MCG_STATUS		0x17a
#define	REG_MCG_CTL		0x17b

#define	REG_MC0_CTL		0x400
#define	REG_MC0_STATUS		0x401
#define	REG_MC0_ADDR		0x402
#define	REG_MC0_MISC		0x403
#define	REG_MC1_CTL		0x404
#define	REG_MC1_STATUS		0x405
#define	REG_MC1_ADDR		0x406
#define	REG_MC1_MISC		0x407
#define	REG_MC2_CTL		0x408
#define	REG_MC2_STATUS		0x409
#define	REG_MC2_ADDR		0x40a
#define	REG_MC2_MISC		0x40b
#define	REG_MC4_CTL		0x40c
#define	REG_MC4_STATUS		0x40d
#define	REG_MC4_ADDR		0x40e
#define	REG_MC4_MISC		0x40f
#define	REG_MC3_CTL		0x410
#define	REG_MC3_STATUS		0x411
#define	REG_MC3_ADDR		0x412
#define	REG_MC3_MISC		0x413

#define	P6_MCG_CAP_COUNT	5
#define	MCG_CAP_COUNT_MASK	0xff
#define	MCG_CAP_CTL_P		0x100

#define	MCG_STATUS_RIPV		0x01
#define	MCG_STATUS_EIPV		0x02
#define	MCG_STATUS_MCIP		0x04

#define	MCG_CTL_VALUE		0xffffffff

#define	MCI_CTL_VALUE		0xffffffff
#define	MCI_STATUS_ERRCODE	0xffff
#define	MCI_STATUS_MSERRCODE	0xffff0000
#define	MCI_STATUS_PCC		((long long)0x200000000000000)
#define	MCI_STATUS_ADDRV	((long long)0x400000000000000)
#define	MCI_STATUS_MISCV	((long long)0x800000000000000)
#define	MCI_STATUS_EN		((long long)0x1000000000000000)
#define	MCI_STATUS_UC		((long long)0x2000000000000000)
#define	MCI_STATUS_O		((long long)0x4000000000000000)
#define	MCI_STATUS_VAL		((long long)0x8000000000000000)

#define	MSERRCODE_SHFT		16


#define	MTRRTYPE_MASK		0xff


#define	MTRRCAP_FIX		0x100
#define	MTRRCAP_VCNTMASK	0xff
#define	MTRRCAP_USWC		0x400

#define	MTRRDEF_E		0x800
#define	MTRRDEF_FE		0x400

#define	MTRRPHYSMASK_V		0x800

#define	MTRR_TYPE_UC		0
#define	MTRR_TYPE_WC		1
#define	MTRR_TYPE_WT		4
#define	MTRR_TYPE_WP		5
#define	MTRR_TYPE_WB		6

/*
 * Page attribute table is setup in the following way
 * PAT0	Write-BACK
 * PAT1	Write-Through
 * PAT2	Unchacheable
 * PAT3	Uncacheable
 * PAT4 Uncacheable
 * PAT5	Write-Protect
 * PAT6	Write-Combine
 * PAT7 Uncacheable
 */
#define	PAT_DEFAULT_ATTRIBUTE \
	((uint64_t)MTRR_TYPE_WC << 48)|((uint64_t)MTRR_TYPE_WP << 40)| \
	(MTRR_TYPE_WT << 8)|(MTRR_TYPE_WB)


#define	MTRR_SETTYPE(a, t)	((a &= (uint64_t)~0xff),\
				    (a |= ((t) & 0xff)))
#define	MTRR_SETVINVALID(a)	((a) &= ~MTRRPHYSMASK_V)


#define	MTRR_SETVBASE(a, b, t)	((a) =\
					((((uint64_t)(b)) & 0xffffff000)|\
					(((uint32_t)(t)) & 0xff)))

#define	MTRR_SETVMASK(a, s, v) ((a) =\
				((~(((uint64_t)(s)) - 1) & 0xffffff000)|\
					(((uint32_t)(v)) << 11)))

#define	MTRR_GETVBASE(a)	(((uint64_t)(a)) & 0xffffff000)
#define	MTRR_GETVTYPE(a)	(((uint64_t)(a)) & 0xff)
#define	MTRR_GETVSIZE(a)	((~((uint64_t)(a)) + 1) & 0xffffff000)


#define	MAX_MTRRVAR	8

#if !defined(_ASM)
typedef	struct	mtrrvar {
	uint64_t	mtrrphys_base;
	uint64_t	mtrrphys_mask;
} mtrrvar_t;
#endif	/* _ASM */

#define	X86_LARGEPAGE	0x00000001
#define	X86_TSC		0x00000002
#define	X86_MSR		0x00000004
#define	X86_MTRR	0x00000008
#define	X86_PGE		0x00000010
#define	X86_CMOV	0x00000040
#define	X86_MMX 	0x00000080
#define	X86_MCA		0x00000100
#define	X86_PAE		0x00000200
#define	X86_CX8		0x00000400
#define	X86_PAT		0x00000800
#define	X86_SEP		0x00001000
#define	X86_SSE		0x00002000
#define	X86_SSE2	0x00004000
#define	X86_HTT		0x00008000
#define	X86_ASYSC	0x00010000
#define	X86_NX		0x00020000
#define	X86_SSE3	0x00040000
#define	X86_CX16	0x00080000
#define	X86_CMP		0x00100000
#define	X86_CPUID	0x01000000

#define	FMT_X86_FEATURE						\
	"\20"							\
	"\31cpuid"						\
	"\25cmp\24cx16\23sse3\22nx\21asysc"			\
	"\20htt\17sse2\16sse\15sep\14pat\13cx8\12pae\11mca"	\
	"\10mmx\7cmov\5pge\4mtrr\3msr\2tsc\1lgpg"

/*
 * x86_type is a legacy concept; this is supplanted
 * for most purposes by x86_feature; modern CPUs
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
#define	X86_VENDOR_Intel	0	/* GenuineIntel */
#define	X86_VENDOR_IntelClone	1	/* (an Intel clone) */
#define	X86_VENDOR_AMD		2	/* AuthenticAMD */
#define	X86_VENDOR_Cyrix	3	/* CyrixInstead */
#define	X86_VENDOR_UMC		4	/* UMC UMC UMC  */
#define	X86_VENDOR_NexGen	5	/* NexGenDriven */
#define	X86_VENDOR_Centaur	6	/* CentaurHauls */
#define	X86_VENDOR_Rise		7	/* RiseRiseRise */
#define	X86_VENDOR_SiS		8	/* SiS SiS SiS  */
#define	X86_VENDOR_TM		9	/* GenuineTMx86 */
#define	X86_VENDOR_NSC		10	/* Geode by NSC */

#if !defined(_ASM)

#if defined(_KERNEL) || defined(_KMEMUSER)

extern uint_t x86_feature;
extern uint_t x86_type;
extern uint_t x86_vendor;

extern ulong_t cr4_value;
extern uint_t pentiumpro_bug4046376;
extern uint_t pentiumpro_bug4064495;

extern uint_t enable486;

extern const char CyrixInstead[];

#endif

#if defined(_KERNEL)


extern uint64_t rdmsr(uint_t, uint64_t *);
extern void wrmsr(uint_t, const uint64_t *);
extern void invalidate_cache(void);
struct regs;
extern int mca_exception(struct regs *);
extern ulong_t getcr4(void);
extern void setcr4(ulong_t);
extern void mtrr_sync(void);

extern void cpu_fast_syscall_enable(void *);
extern void cpu_fast_syscall_disable(void *);

struct cpu;

extern int cpuid_checkpass(struct cpu *, int);
extern uint32_t cpuid_insn(struct cpu *,
    uint32_t, uint32_t *, uint32_t *, uint32_t *);
extern uint32_t __cpuid_insn(uint32_t, uint32_t *, uint32_t *, uint32_t *);
extern int cpuid_getbrandstr(struct cpu *, char *, size_t);
extern int cpuid_getidstr(struct cpu *, char *, size_t);
extern const char *cpuid_getvendorstr(struct cpu *);
extern uint_t cpuid_getvendor(struct cpu *);
extern uint_t cpuid_getfamily(struct cpu *);
extern uint_t cpuid_getmodel(struct cpu *);
extern uint_t cpuid_getstep(struct cpu *);
extern uint_t cpuid_get_ncpu_per_chip(struct cpu *);
extern int cpuid_is_ht(struct cpu *);
extern int cpuid_syscall32_insn(struct cpu *);
extern int getl2cacheinfo(struct cpu *, int *, int *, int *);

extern int cpuid_opteron_erratum(struct cpu *, uint_t);

struct cpuid_info;

extern void setx86isalist(void);
extern uint_t cpuid_pass1(struct cpu *);
extern void cpuid_pass2(struct cpu *);
extern void cpuid_pass3(struct cpu *);
extern uint_t cpuid_pass4(struct cpu *);
extern void add_cpunode2devtree(processorid_t, struct cpuid_info *);

extern void cpuid_get_addrsize(struct cpu *, uint_t *, uint_t *);
extern uint_t cpuid_get_dtlb_nent(struct cpu *, size_t);

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

#endif	/* _KERNEL */

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_X86_ARCHEXT_H */
