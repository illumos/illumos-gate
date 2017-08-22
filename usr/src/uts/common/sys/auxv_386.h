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
 * Copyright (c) 2017, Joyent, Inc.
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
					/* 0x02000 withdrawn - do not assign */
#define	AV_386_SSE3		0x04000	/* SSE3 insns and regs */
					/* 0x08000 withdrawn - do not assign */
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
#define	AV_386_AES		0x4000000 /* Intel AES insns */
#define	AV_386_PCLMULQDQ	0x8000000 /* Intel PCLMULQDQ insn */
#define	AV_386_XSAVE		0x10000000 /* Intel XSAVE/XRSTOR insns */
#define	AV_386_AVX		0x20000000 /* Intel AVX insns */
#define	AV_386_VMX		0x40000000 /* Intel VMX support */
#define	AV_386_AMD_SVM		0x80000000 /* AMD SVM support */

#define	FMT_AV_386							\
	"\020"								\
	"\040svm\037vmx\036avx\035xsave"				\
	"\034pclmulqdq\033aes"						\
	"\032movbe\031sse4.2"						\
	"\030sse4.1\027ssse3\026amd_lzcnt\025popcnt"			\
	"\024amd_sse4a\023tscp\022ahf\021cx16"				\
	"\017sse3\015sse2\014sse\013fxsr\012amd3dx\011amd3d"		\
	"\010amdmmx\07mmx\06cmov\05amdsysc\04sep\03cx8\02tsc\01fpu"

/*
 * Flags used in AT_SUN_HWCAP2 elements
 */
#define	AV_386_2_F16C		0x00001	/* F16C half percision extensions */
#define	AV_386_2_RDRAND		0x00002	/* RDRAND insn */
#define	AV_386_2_BMI1		0x00004 /* BMI1 insns */
#define	AV_386_2_BMI2		0x00008 /* BMI2 insns */
#define	AV_386_2_FMA		0x00010	/* FMA insns */
#define	AV_386_2_AVX2		0x00020	/* AVX2 insns */
#define	AV_386_2_ADX		0x00040	/* ADX insns */
#define	AV_386_2_RDSEED		0x00080	/* RDSEED insn */
#define	AV_386_2_AVX512F	0x00100	/* AVX512 foundation insns */
#define	AV_386_2_AVX512DQ	0x00200	/* AVX512DQ insns */
#define	AV_386_2_AVX512IFMA	0x00400	/* AVX512IFMA insns */
#define	AV_386_2_AVX512PF	0x00800	/* AVX512PF insns */
#define	AV_386_2_AVX512ER	0x01000	/* AVX512ER insns */
#define	AV_386_2_AVX512CD	0x02000	/* AVX512CD insns */
#define	AV_386_2_AVX512BW	0x04000	/* AVX512BW insns */
#define	AV_386_2_AVX512VL	0x08000	/* AVX512VL insns */
#define	AV_386_2_AVX512VBMI	0x10000	/* AVX512VBMI insns */
#define	AV_386_2_AVX512VPOPCDQ	0x20000	/* AVX512VPOPCNTDQ insns */
#define	AV_386_2_AVX512_4NNIW	0x40000	/* AVX512 4NNIW insns */
#define	AV_386_2_AVX512_4FMAPS	0x80000	/* AVX512 4FMAPS insns */

#define	FMT_AV_386_2							\
	"\024avx512_4fmaps\023avx512_4nniw\022avx512vpopcntdq"		\
	"\021avx512vbmi\020avx512vl\017avx512bw\016avx512cd"		\
	"\015avx512er\014avx512pf\013avx512ifma\012avx512dq\011avx512f"	\
	"\010rdseed\07adx\06avx2\05fma\04bmi2\03bmi1\02rdrand\01f16c"

#ifdef __cplusplus
}
#endif

#endif	/* !_SYS_AUXV_386_H */
