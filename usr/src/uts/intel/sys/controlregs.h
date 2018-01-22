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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018, Joyent, Inc.
 */

#ifndef	_SYS_CONTROLREGS_H
#define	_SYS_CONTROLREGS_H

#ifndef _ASM
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file describes the x86 architecture control registers which
 * are part of the privileged architecture.
 *
 * Many of these definitions are shared between IA-32-style and
 * AMD64-style processors.
 */

/* CR0 Register */

#define	CR0_PG	0x80000000		/* paging enabled	*/
#define	CR0_CD	0x40000000		/* cache disable	*/
#define	CR0_NW	0x20000000		/* not writethrough	*/
#define	CR0_AM	0x00040000		/* alignment mask	*/
#define	CR0_WP	0x00010000		/* write protect	*/
#define	CR0_NE	0x00000020		/* numeric error	*/
#define	CR0_ET	0x00000010		/* extension type	*/
#define	CR0_TS	0x00000008		/* task switch		*/
#define	CR0_EM	0x00000004		/* emulation		*/
#define	CR0_MP	0x00000002		/* monitor coprocessor	*/
#define	CR0_PE	0x00000001		/* protection enabled	*/

/* XX64 eliminate these compatibility defines */

#define	CR0_CE	CR0_CD
#define	CR0_WT	CR0_NW

#define	FMT_CR0	\
	"\20\40pg\37cd\36nw\35am\21wp\6ne\5et\4ts\3em\2mp\1pe"

/*
 * Set the FPU-related control bits to explain to the processor that
 * we're managing FPU state:
 * - set monitor coprocessor (allow TS bit to control FPU)
 * - set numeric exception (disable IGNNE# mechanism)
 * - set task switch (#nm on first fp instruction)
 * - clear emulate math bit (cause we're not emulating!)
 */
#define	CR0_ENABLE_FPU_FLAGS(cr)	\
	(((cr) | CR0_MP | CR0_NE | CR0_TS) & (uint32_t)~CR0_EM)

/*
 * Set the FPU-related control bits to explain to the processor that
 * we're -not- managing FPU state:
 * - set emulate (all fp instructions cause #nm)
 * - clear monitor coprocessor (so fwait/wait doesn't #nm)
 */
#define	CR0_DISABLE_FPU_FLAGS(cr)	\
	(((cr) | CR0_EM) & (uint32_t)~CR0_MP)

/* CR3 Register */

#define	CR3_PCD	0x00000010		/* cache disable 		*/
#define	CR3_PWT 0x00000008		/* write through 		*/
#if defined(_ASM)
#define	CR3_NOINVL_BIT	0x8000000000000000
#else
#define	CR3_NOINVL_BIT	0x8000000000000000ULL /* no invalidation	*/
#endif
#define	PCID_NONE	0x000		/* generic PCID			*/
#define	PCID_KERNEL	0x000		/* kernel's PCID		*/
#define	PCID_USER	0x001		/* user-space PCID		*/

/* CR4 Register */

#define	CR4_VME		0x0001		/* virtual-8086 mode extensions	*/
#define	CR4_PVI		0x0002		/* protected-mode virtual interrupts */
#define	CR4_TSD		0x0004		/* time stamp disable		*/
#define	CR4_DE		0x0008		/* debugging extensions		*/
#define	CR4_PSE		0x0010		/* page size extensions		*/
#define	CR4_PAE		0x0020		/* physical address extension	*/
#define	CR4_MCE		0x0040		/* machine check enable		*/
#define	CR4_PGE		0x0080		/* page global enable		*/
#define	CR4_PCE		0x0100		/* perf-monitoring counter enable */
#define	CR4_OSFXSR	0x0200		/* OS fxsave/fxrstor support	*/
#define	CR4_OSXMMEXCPT	0x0400		/* OS unmasked exception support */
					/* 0x0800 reserved */
					/* 0x1000 reserved */
#define	CR4_VMXE	0x2000
#define	CR4_SMXE	0x4000
#define	CR4_PCIDE	0x20000		/* PCID enable */
#define	CR4_OSXSAVE	0x40000		/* OS xsave/xrestore support	*/
#define	CR4_SMEP	0x100000	/* NX for user pages in kernel */
#define	CR4_SMAP	0x200000	/* kernel can't access user pages */

#define	FMT_CR4						\
	"\20\26smap\25smep\23osxsav\22pcide"		\
	"\17smxe\16vmxe\13xmme\12fxsr\11pce\10pge"	\
	"\7mce\6pae\5pse\4de\3tsd\2pvi\1vme"

/*
 * Enable the SSE-related control bits to explain to the processor that
 * we're managing XMM state and exceptions
 */
#define	CR4_ENABLE_SSE_FLAGS(cr)	\
	((cr) | CR4_OSFXSR | CR4_OSXMMEXCPT)

/*
 * Disable the SSE-related control bits to explain to the processor
 * that we're NOT managing XMM state
 */
#define	CR4_DISABLE_SSE_FLAGS(cr)	\
	((cr) & ~(uint32_t)(CR4_OSFXSR | CR4_OSXMMEXCPT))

/* Intel's SYSENTER configuration registers */

#define	MSR_INTC_SEP_CS	0x174		/* kernel code selector MSR */
#define	MSR_INTC_SEP_ESP 0x175		/* kernel esp MSR */
#define	MSR_INTC_SEP_EIP 0x176		/* kernel eip MSR */

/* Intel's microcode registers */
#define	MSR_INTC_UCODE_WRITE		0x79	/* microcode write */
#define	MSR_INTC_UCODE_REV		0x8b	/* microcode revision */
#define	INTC_UCODE_REV_SHIFT		32	/* Bits 63:32 */

/* Intel's platform identification */
#define	MSR_INTC_PLATFORM_ID		0x17
#define	INTC_PLATFORM_ID_SHIFT		50	/* Bit 52:50 */
#define	INTC_PLATFORM_ID_MASK		0x7

/* AMD's EFER register */

#define	MSR_AMD_EFER	0xc0000080	/* extended feature enable MSR */

#define	AMD_EFER_FFXSR	0x4000		/* fast fxsave/fxrstor		*/
#define	AMD_EFER_SVME	0x1000		/* svm enable			*/
#define	AMD_EFER_NXE	0x0800		/* no-execute enable		*/
#define	AMD_EFER_LMA	0x0400		/* long mode active (read-only)	*/
#define	AMD_EFER_LME	0x0100		/* long mode enable		*/
#define	AMD_EFER_SCE	0x0001		/* system call extensions	*/

#define	FMT_AMD_EFER \
	"\20\17ffxsr\15svme\14nxe\13lma\11lme\1sce"

/* AMD's SYSCFG register */

#define	MSR_AMD_SYSCFG	0xc0000010	/* system configuration MSR */

#define	AMD_SYSCFG_TOM2	0x200000	/* MtrrTom2En */
#define	AMD_SYSCFG_MVDM	0x100000	/* MtrrVarDramEn */
#define	AMD_SYSCFG_MFDM	0x080000	/* MtrrFixDramModEn */
#define	AMD_SYSCFG_MFDE	0x040000	/* MtrrFixDramEn */

#define	FMT_AMD_SYSCFG \
	"\20\26tom2\25mvdm\24mfdm\23mfde"

/* AMD's syscall/sysret MSRs */

#define	MSR_AMD_STAR	0xc0000081	/* %cs:%ss:%cs:%ss:%eip for syscall */
#define	MSR_AMD_LSTAR	0xc0000082	/* target %rip of 64-bit syscall */
#define	MSR_AMD_CSTAR	0xc0000083	/* target %rip of 32-bit syscall */
#define	MSR_AMD_SFMASK	0xc0000084	/* syscall flag mask */

/* AMD's FS.base and GS.base MSRs */

#define	MSR_AMD_FSBASE	0xc0000100	/* 64-bit base address for %fs */
#define	MSR_AMD_GSBASE	0xc0000101	/* 64-bit base address for %gs */
#define	MSR_AMD_KGSBASE	0xc0000102	/* swapgs swaps this with gsbase */
#define	MSR_AMD_TSCAUX	0xc0000103	/* %ecx value on rdtscp insn */

/* AMD's configuration MSRs, weakly documented in the revision guide */

#define	MSR_AMD_DC_CFG	0xc0011022

#define	AMD_DC_CFG_DIS_CNV_WC_SSO	(UINT64_C(1) << 3)
#define	AMD_DC_CFG_DIS_SMC_CHK_BUF	(UINT64_C(1) << 10)

/* AMD's HWCR MSR */

#define	MSR_AMD_HWCR	0xc0010015

#define	AMD_HWCR_TLBCACHEDIS		(UINT64_C(1) << 3)
#define	AMD_HWCR_FFDIS			0x00040	/* disable TLB Flush Filter */
#define	AMD_HWCR_MCI_STATUS_WREN	0x40000	/* enable write of MCi_STATUS */

/* AMD's NorthBridge Config MSR, SHOULD ONLY BE WRITTEN TO BY BIOS */

#define	MSR_AMD_NB_CFG	0xc001001f

#define	AMD_NB_CFG_SRQ_HEARTBEAT	(UINT64_C(1) << 20)
#define	AMD_NB_CFG_SRQ_SPR		(UINT64_C(1) << 32)

#define	MSR_AMD_BU_CFG	0xc0011023

#define	AMD_BU_CFG_E298			(UINT64_C(1) << 1)

#define	MSR_AMD_DE_CFG	0xc0011029

#define	AMD_DE_CFG_E721			(UINT64_C(1))

/* AMD's osvw MSRs */
#define	MSR_AMD_OSVW_ID_LEN		0xc0010140
#define	MSR_AMD_OSVW_STATUS		0xc0010141


#define	OSVW_ID_LEN_MASK		0xffffULL
#define	OSVW_ID_CNT_PER_MSR		64

/*
 * Enable PCI Extended Configuration Space (ECS) on Greyhound
 */
#define	AMD_GH_NB_CFG_EN_ECS		(UINT64_C(1) << 46)

/* AMD microcode patch loader */
#define	MSR_AMD_PATCHLEVEL	0x8b
#define	MSR_AMD_PATCHLOADER	0xc0010020

#ifdef __cplusplus
}
#endif

#endif	/* !_SYS_CONTROLREGS_H */
