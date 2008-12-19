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

#ifndef	_SYS_AUXV_386_H
#define	_SYS_AUXV_386_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Flags used in AT_SUN_HWCAP elements to describe various userland
 * instruction set extensions available on different processors.
 * The basic assumption is that of the i386 ABI; that is, i386 plus i387
 * floating point.
 *
 * Note that if a given bit is set; the implication is that the kernel
 * provides all the underlying architectural support for the correct
 * functioning of the extended instruction(s).
 */
#define	AV_386_FPU		0x00001	/* x87-style floating point */
#define	AV_386_TSC		0x00002	/* rdtsc insn */
#define	AV_386_CX8		0x00004	/* cmpxchg8b insn */
#define	AV_386_SEP		0x00008	/* sysenter and sysexit */
#define	AV_386_AMD_SYSC		0x00010	/* AMD's syscall and sysret */
#define	AV_386_CMOV		0x00020	/* conditional move insns */
#define	AV_386_MMX		0x00040	/* MMX insns */
#define	AV_386_AMD_MMX		0x00080	/* AMD's MMX insns */
#define	AV_386_AMD_3DNow	0x00100	/* AMD's 3Dnow! insns */
#define	AV_386_AMD_3DNowx	0x00200	/* AMD's 3Dnow! extended insns */
#define	AV_386_FXSR		0x00400	/* fxsave and fxrstor */
#define	AV_386_SSE		0x00800	/* SSE insns and regs */
#define	AV_386_SSE2		0x01000	/* SSE2 insns and regs */
#define	AV_386_PAUSE		0x02000	/* use pause insn (in spin loops) */
#define	AV_386_SSE3		0x04000	/* SSE3 insns and regs */
#define	AV_386_MON		0x08000	/* monitor/mwait insns */
#define	AV_386_CX16		0x10000	/* cmpxchg16b insn */
#define	AV_386_AHF		0x20000	/* lahf/sahf insns */
#define	AV_386_TSCP		0x40000	/* rdtscp instruction */
#define	AV_386_AMD_SSE4A	0x80000	/* AMD's SSE4A insns */
#define	AV_386_POPCNT		0x100000 /* POPCNT insn */
#define	AV_386_AMD_LZCNT	0x200000 /* AMD's LZCNT insn */
#define	AV_386_SSSE3		0x400000 /* Intel SSSE3 insns */
#define	AV_386_SSE4_1		0x800000 /* Intel SSE4.1 insns */
#define	AV_386_SSE4_2		0x1000000 /* Intel SSE4.2 insns */
#define	AV_386_MOVBE		0x2000000 /* Intel MOVBE insns */

#define	FMT_AV_386							\
	"\20"								\
	"\32movbe\31sse4.2"						\
	"\30sse4.1\27ssse3\26amd_lzcnt\25popcnt"			\
	"\24amd_sse4a\23tscp\22ahf\21cx16"				\
	"\20mon\17sse3\16pause\15sse2\14sse\13fxsr\12amd3dx\11amd3d"	\
	"\10amdmmx\7mmx\6cmov\5amdsysc\4sep\3cx8\2tsc\1fpu"

#ifdef __cplusplus
}
#endif

#endif	/* !_SYS_AUXV_386_H */
