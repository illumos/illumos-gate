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
 */

#include <sys/asm_linkage.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>

#if defined(__lint)

#include <sys/types.h>

uint32_t
bignum_use_sse2()
{ return (0); }

/* Not to be called by C code */
/* ARGSUSED */
uint32_t
big_mul_set_vec_sse2_r()
{ return (0); }

/* Not to be called by C code */
/* ARGSUSED */
uint32_t
big_mul_add_vec_sse2_r()
{ return (0); }

/* ARGSUSED */
uint32_t
big_mul_set_vec_sse2(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{ return (0); }

/* ARGSUSED */
uint32_t
big_mul_add_vec_sse2(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{ return (0); }

/* ARGSUSED */
void
big_mul_vec_sse2(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen)
{}

/* ARGSUSED */
void
big_sqr_vec_sse2(uint32_t *r, uint32_t *a, int len)
{}

#if defined(MMX_MANAGE)

/* ARGSUSED */
uint32_t
big_mul_set_vec_sse2_nsv(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{ return (0); }

/* ARGSUSED */
uint32_t
big_mul_add_vec_sse2_nsv(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{ return (0); }

/* Not to be called by C code */
/* ARGSUSED */
void
big_sqr_vec_sse2_fc(uint32_t *r, uint32_t *a, int len)
{}

#endif	/* MMX_MANAGE */

/*
 * UMUL
 *
 */

/* ARGSUSED */
uint32_t
big_mul_set_vec_umul(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{ return (0); }

/* ARGSUSED */
uint32_t
big_mul_add_vec_umul(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{ return (0); }

#else	/* __lint */

#if defined(MMX_MANAGE)

#if defined(_KERNEL)

#define	KPREEMPT_DISABLE call kpr_disable
#define	KPREEMPT_ENABLE call kpr_enable
#define	TEST_TS(reg)					\
	movl	%cr0, reg;				\
	clts;						\
	testl	$CR0_TS, reg

#else	/* _KERNEL */

#define	KPREEMPT_DISABLE
#define	KPREEMPT_ENABLE

#define	TEST_TS(reg)					\
	movl	$0, reg;				\
	testl	$CR0_TS, reg

#endif	/* _KERNEL */

#define	MMX_SIZE 8
#define	MMX_ALIGN 8

#define	SAVE_MMX_PROLOG(sreg, nreg)			\
	subl	$_MUL(MMX_SIZE, nreg + MMX_ALIGN), %esp;	\
	movl	%esp, sreg;				\
	addl	$MMX_ALIGN, sreg;			\
	andl	$-1![MMX_ALIGN-1], sreg;

#define	RSTOR_MMX_EPILOG(nreg)				\
	addl	$_MUL(MMX_SIZE, nreg + MMX_ALIGN), %esp;

#define	SAVE_MMX_0TO4(sreg)			\
	SAVE_MMX_PROLOG(sreg, 5);		\
	movq	%mm0, 0(sreg);			\
	movq	%mm1, 8(sreg);			\
	movq	%mm2, 16(sreg);			\
	movq	%mm3, 24(sreg);			\
	movq	%mm4, 32(sreg)

#define	RSTOR_MMX_0TO4(sreg)			\
	movq	0(sreg), %mm0;			\
	movq	8(sreg), %mm1;			\
	movq	16(sreg), %mm2;			\
	movq	24(sreg), %mm3;			\
	movq	32(sreg), %mm4;			\
	RSTOR_MMX_EPILOG(5)

#endif	/* MMX_MANAGE */

/ Note: this file contains implementations for
/	big_mul_set_vec()
/	big_mul_add_vec()
/	big_mul_vec()
/	big_sqr_vec()
/ One set of implementations is for SSE2-capable models.
/ The other uses no MMX, SSE, or SSE2 instructions, only
/ the x86 32 X 32 -> 64 unsigned multiply instruction, MUL.
/
/ The code for the implementations is grouped by SSE2 vs UMUL,
/ rather than grouping pairs of implementations for each function.
/ This is because the bignum implementation gets "imprinted"
/ on the correct implementation, at the time of first use,
/ so none of the code for the other implementations is ever
/ executed.  So, it is a no-brainer to layout the code to minimize
/ the "footprint" of executed code.

/ Can we use SSE2 instructions?  Return value is non-zero
/ if we can.
/
/ Note:
/   Using the cpuid instruction directly would work equally
/   well in userland and in the kernel, but we do not use the
/   cpuid instruction in the kernel, we use x86_featureset,
/   instead.  This means we honor any decisions the kernel
/   startup code may have made in setting this variable,
/   including disabling SSE2.  It might even be a good idea
/   to honor this kind of setting in userland, as well, but
/   the variable, x86_featureset is not readily available to
/   userland processes.
/
/ uint32_t
/ bignum_use_sse2()

	ENTRY(bignum_use_sse2)
#if defined(_KERNEL)
	xor	%eax, %eax
	bt	$X86FSET_SSE2, x86_featureset
	adc     %eax, %eax
#else	/* _KERNEL */
	pushl	%ebx
	movl	$1, %eax		/ Get feature information
	cpuid
	movl	%edx, %eax		/ set return value
	popl	%ebx
	andl	$CPUID_INTC_EDX_SSE2, %eax
#endif	/* _KERNEL */
	ret
	SET_SIZE(bignum_use_sse2)


/ ------------------------------------------------------------------------
/		SSE2 Implementations
/ ------------------------------------------------------------------------

/ r = a * digit, r and a are vectors of length len
/ returns the carry digit
/ Suitable only for x86 models that support SSE2 instruction set extensions
/
/ uint32_t
/ big_mul_set_vec_sse2_r(uint32_t *r, uint32_t *a, int len, uint32_t digit)
/
/ r	%edx
/ a	%ebx
/ len	%ecx
/ digit	%mm3
/
/ Does not touch the following registers: %esi, %edi, %mm4
/
/ N.B.:
/   This is strictly for internal use.
/   The interface is very light-weight.
/   All parameters are passed in registers.
/   It does not conform to the SYSV x86 ABI.
/   So, don't even think about calling this function directly from C code.
/
/ The basic multiply digit loop is unrolled 8 times.
/ Each comment is preceded by an instance number.
/ Instructions that have been moved retain their original, "natural"
/ instance number.  It should be easier this way to follow
/ the step-wise refinement process that went into constructing
/ the final code.

#define	UNROLL		8
#define	UNROLL32	32

	ENTRY(big_mul_set_vec_sse2_r)
	xorl	%eax, %eax	/ if (len == 0) return (0);
	testl	%ecx, %ecx
	jz	.L17

	pxor	%mm0, %mm0	/ cy = 0

.L15:
	cmpl	$UNROLL, %ecx
	jl	.L16
	movd	0(%ebx), %mm1	/ 1: mm1 = a[i]
	pmuludq	%mm3, %mm1	/ 1: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 1: mm0 = digit * a[i] + cy;
	movd	4(%ebx), %mm1	/ 2: mm1 = a[i]
	movd	%mm0, 0(%edx)	/ 1: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 1: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 2: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 2: mm0 = digit * a[i] + cy;
	movd	8(%ebx), %mm1	/ 3: mm1 = a[i]
	movd	%mm0, 4(%edx)	/ 2: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 2: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 3: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 3: mm0 = digit * a[i] + cy;
	movd	12(%ebx), %mm1	/ 4: mm1 = a[i]
	movd	%mm0, 8(%edx)	/ 3: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 3: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 4: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 4: mm0 = digit * a[i] + cy;
	movd	16(%ebx), %mm1	/ 5: mm1 = a[i]
	movd	%mm0, 12(%edx)	/ 4: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 4: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 5: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 5: mm0 = digit * a[i] + cy;
	movd	20(%ebx), %mm1	/ 6: mm1 = a[i]
	movd	%mm0, 16(%edx)	/ 5: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 5: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 6: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 6: mm0 = digit * a[i] + cy;
	movd	24(%ebx), %mm1	/ 7: mm1 = a[i]
	movd	%mm0, 20(%edx)	/ 6: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 6: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 7: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 7: mm0 = digit * a[i] + cy;
	movd	28(%ebx), %mm1	/ 8: mm1 = a[i]
	movd	%mm0, 24(%edx)	/ 7: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 7: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 8: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 8: mm0 = digit * a[i] + cy;
	movd	%mm0, 28(%edx)	/ 8: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 8: cy = product[63..32]

	leal	UNROLL32(%ebx), %ebx	/ a += UNROLL
	leal	UNROLL32(%edx), %edx	/ r += UNROLL
	subl	$UNROLL, %ecx		/ len -= UNROLL
	jz	.L17
	jmp	.L15

.L16:
	movd	0(%ebx), %mm1	/ 1: mm1 = a[i]
	pmuludq	%mm3, %mm1	/ 1: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 1: mm0 = digit * a[i] + cy;
	movd	%mm0, 0(%edx)	/ 1: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 1: cy = product[63..32]
	subl	$1, %ecx
	jz	.L17

	movd	4(%ebx), %mm1	/ 2: mm1 = a[i]
	pmuludq	%mm3, %mm1	/ 2: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 2: mm0 = digit * a[i] + cy;
	movd	%mm0, 4(%edx)	/ 2: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 2: cy = product[63..32]
	subl	$1, %ecx
	jz	.L17

	movd	8(%ebx), %mm1	/ 3: mm1 = a[i]
	pmuludq	%mm3, %mm1	/ 3: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 3: mm0 = digit * a[i] + cy;
	movd	%mm0, 8(%edx)	/ 3: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 3: cy = product[63..32]
	subl	$1, %ecx
	jz	.L17

	movd	12(%ebx), %mm1	/ 4: mm1 = a[i]
	pmuludq	%mm3, %mm1	/ 4: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 4: mm0 = digit * a[i] + cy;
	movd	%mm0, 12(%edx)	/ 4: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 4: cy = product[63..32]
	subl	$1, %ecx
	jz	.L17

	movd	16(%ebx), %mm1	/ 5: mm1 = a[i]
	pmuludq	%mm3, %mm1	/ 5: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 5: mm0 = digit * a[i] + cy;
	movd	%mm0, 16(%edx)	/ 5: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 5: cy = product[63..32]
	subl	$1, %ecx
	jz	.L17

	movd	20(%ebx), %mm1	/ 6: mm1 = a[i]
	pmuludq	%mm3, %mm1	/ 6: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 6: mm0 = digit * a[i] + cy;
	movd	%mm0, 20(%edx)	/ 6: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 6: cy = product[63..32]
	subl	$1, %ecx
	jz	.L17

	movd	24(%ebx), %mm1	/ 7: mm1 = a[i]
	pmuludq	%mm3, %mm1	/ 7: mm1 = digit * a[i]
	paddq	%mm1, %mm0	/ 7: mm0 = digit * a[i] + cy;
	movd	%mm0, 24(%edx)	/ 7: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 7: cy = product[63..32]

.L17:
	movd	%mm0, %eax	/ return (cy)
	/ no emms.  caller is responsible for emms
	ret
	SET_SIZE(big_mul_set_vec_sse2_r)


/ r = a * digit, r and a are vectors of length len
/ returns the carry digit
/ Suitable only for x86 models that support SSE2 instruction set extensions
/
/ r		 8(%ebp)	%edx
/ a		12(%ebp)	%ebx
/ len		16(%ebp)	%ecx
/ digit		20(%ebp)	%mm3
/
/ In userland, there is just the one function, big_mul_set_vec_sse2().
/ But in the kernel, there are two variations:
/    1. big_mul_set_vec_sse2() which does what is necessary to save and
/       restore state, if necessary, and to ensure that preemtion is
/       disabled.
/    2. big_mul_set_vec_sse2_nsv() which just does the work;
/       it is the caller's responsibility to ensure that MMX state
/       does not need to be saved and restored and that preemption
/       is already disabled.

#if defined(MMX_MANAGE)
	ENTRY(big_mul_set_vec_sse2)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	pushl	%esi
	KPREEMPT_DISABLE
	TEST_TS(%ebx)
	pushl	%ebx
	jnz	.setvec_no_save
	pushl	%edi
	SAVE_MMX_0TO4(%edi)
	movl	8(%ebp), %edx
	movl	12(%ebp), %ebx
	movl	16(%ebp), %ecx
	movd	20(%ebp), %mm3
	call	big_mul_set_vec_sse2_r
	movl	%eax, %esi
	RSTOR_MMX_0TO4(%edi)
	popl	%edi
	jmp	.setvec_rtn

.setvec_no_save:
	movl	8(%ebp), %edx
	movl	12(%ebp), %ebx
	movl	16(%ebp), %ecx
	movd	20(%ebp), %mm3
	call	big_mul_set_vec_sse2_r
	movl	%eax, %esi

.setvec_rtn:
	emms
	popl	%ebx
	movl	%ebx, %cr0
	KPREEMPT_ENABLE
	movl	%esi, %eax
	popl	%esi
	popl	%ebx
	leave
	ret
	SET_SIZE(big_mul_set_vec_sse2)

	ENTRY(big_mul_set_vec_sse2_nsv)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	movl	8(%ebp), %edx
	movl	12(%ebp), %ebx
	movl	16(%ebp), %ecx
	movd	20(%ebp), %mm3
	call	big_mul_set_vec_sse2_r
	popl	%ebx
	leave
	ret
	SET_SIZE(big_mul_set_vec_sse2_nsv)

#else	/* !defined(MMX_MANAGE) */

/ r = a * digit, r and a are vectors of length len
/ returns the carry digit
/ Suitable only for x86 models that support SSE2 instruction set extensions
/
/ r		 8(%ebp)	%edx
/ a		12(%ebp)	%ebx
/ len		16(%ebp)	%ecx
/ digit		20(%ebp)	%mm3

	ENTRY(big_mul_set_vec_sse2)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	movl	8(%ebp), %edx
	movl	12(%ebp), %ebx
	movl	16(%ebp), %ecx
	movd	20(%ebp), %mm3
	call	big_mul_set_vec_sse2_r
	popl	%ebx
	emms
	leave
	ret
	SET_SIZE(big_mul_set_vec_sse2)

#endif	/* MMX_MANAGE */


/ r = r + a * digit, r and a are vectors of length len
/ returns the carry digit
/ Suitable only for x86 models that support SSE2 instruction set extensions
/
/ uint32_t
/ big_mul_add_vec_sse2_r(uint32_t *r, uint32_t *a, int len, uint32_t digit)
/
/ r	%edx
/ a	%ebx
/ len	%ecx
/ digit	%mm3
/
/ N.B.:
/   This is strictly for internal use.
/   The interface is very light-weight.
/   All parameters are passed in registers.
/   It does not conform to the SYSV x86 ABI.
/   So, don't even think about calling this function directly from C code.
/
/ The basic multiply digit loop is unrolled 8 times.
/ Each comment is preceded by an instance number.
/ Instructions that have been moved retain their original, "natural"
/ instance number.  It should be easier this way to follow
/ the step-wise refinement process that went into constructing
/ the final code.

	ENTRY(big_mul_add_vec_sse2_r)
	xorl	%eax, %eax
	testl	%ecx, %ecx
	jz	.L27

	pxor	%mm0, %mm0	/ cy = 0

.L25:
	cmpl	$UNROLL, %ecx
	jl	.L26
	movd	0(%ebx), %mm1	/ 1: mm1 = a[i]
	movd	0(%edx), %mm2	/ 1: mm2 = r[i]
	pmuludq	%mm3, %mm1	/ 1: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 1: mm2 = digit * a[i] + r[i]
	movd	4(%ebx), %mm1	/ 2: mm1 = a[i]
	paddq	%mm2, %mm0	/ 1: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 0(%edx)	/ 1: r[i] = product[31..0]
	movd	4(%edx), %mm2	/ 2: mm2 = r[i]
	psrlq	$32, %mm0	/ 1: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 2: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 2: mm2 = digit * a[i] + r[i]
	movd	8(%ebx), %mm1	/ 3: mm1 = a[i]
	paddq	%mm2, %mm0	/ 2: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 4(%edx)	/ 2: r[i] = product[31..0]
	movd	8(%edx), %mm2	/ 3: mm2 = r[i]
	psrlq	$32, %mm0	/ 2: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 3: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 3: mm2 = digit * a[i] + r[i]
	movd	12(%ebx), %mm1	/ 4: mm1 = a[i]
	paddq	%mm2, %mm0	/ 3: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 8(%edx)	/ 3: r[i] = product[31..0]
	movd	12(%edx), %mm2	/ 4: mm2 = r[i]
	psrlq	$32, %mm0	/ 3: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 4: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 4: mm2 = digit * a[i] + r[i]
	movd	16(%ebx), %mm1	/ 5: mm1 = a[i]
	paddq	%mm2, %mm0	/ 4: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 12(%edx)	/ 4: r[i] = product[31..0]
	movd	16(%edx), %mm2	/ 5: mm2 = r[i]
	psrlq	$32, %mm0	/ 4: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 5: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 5: mm2 = digit * a[i] + r[i]
	movd	20(%ebx), %mm1	/ 6: mm1 = a[i]
	paddq	%mm2, %mm0	/ 5: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 16(%edx)	/ 5: r[i] = product[31..0]
	movd	20(%edx), %mm2	/ 6: mm2 = r[i]
	psrlq	$32, %mm0	/ 5: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 6: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 6: mm2 = digit * a[i] + r[i]
	movd	24(%ebx), %mm1	/ 7: mm1 = a[i]
	paddq	%mm2, %mm0	/ 6: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 20(%edx)	/ 6: r[i] = product[31..0]
	movd	24(%edx), %mm2	/ 7: mm2 = r[i]
	psrlq	$32, %mm0	/ 6: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 7: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 7: mm2 = digit * a[i] + r[i]
	movd	28(%ebx), %mm1	/ 8: mm1 = a[i]
	paddq	%mm2, %mm0	/ 7: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 24(%edx)	/ 7: r[i] = product[31..0]
	movd	28(%edx), %mm2	/ 8: mm2 = r[i]
	psrlq	$32, %mm0	/ 7: cy = product[63..32]

	pmuludq	%mm3, %mm1	/ 8: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 8: mm2 = digit * a[i] + r[i]
	paddq	%mm2, %mm0	/ 8: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 28(%edx)	/ 8: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 8: cy = product[63..32]

	leal	UNROLL32(%ebx), %ebx	/ a += UNROLL
	leal	UNROLL32(%edx), %edx	/ r += UNROLL
	subl	$UNROLL, %ecx		/ len -= UNROLL
	jz	.L27
	jmp	.L25

.L26:
	movd	0(%ebx), %mm1	/ 1: mm1 = a[i]
	movd	0(%edx), %mm2	/ 1: mm2 = r[i]
	pmuludq	%mm3, %mm1	/ 1: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 1: mm2 = digit * a[i] + r[i]
	paddq	%mm2, %mm0	/ 1: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 0(%edx)	/ 1: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 1: cy = product[63..32]
	subl	$1, %ecx
	jz	.L27

	movd	4(%ebx), %mm1	/ 2: mm1 = a[i]
	movd	4(%edx), %mm2	/ 2: mm2 = r[i]
	pmuludq	%mm3, %mm1	/ 2: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 2: mm2 = digit * a[i] + r[i]
	paddq	%mm2, %mm0	/ 2: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 4(%edx)	/ 2: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 2: cy = product[63..32]
	subl	$1, %ecx
	jz	.L27

	movd	8(%ebx), %mm1	/ 3: mm1 = a[i]
	movd	8(%edx), %mm2	/ 3: mm2 = r[i]
	pmuludq	%mm3, %mm1	/ 3: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 3: mm2 = digit * a[i] + r[i]
	paddq	%mm2, %mm0	/ 3: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 8(%edx)	/ 3: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 3: cy = product[63..32]
	subl	$1, %ecx
	jz	.L27

	movd	12(%ebx), %mm1	/ 4: mm1 = a[i]
	movd	12(%edx), %mm2	/ 4: mm2 = r[i]
	pmuludq	%mm3, %mm1	/ 4: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 4: mm2 = digit * a[i] + r[i]
	paddq	%mm2, %mm0	/ 4: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 12(%edx)	/ 4: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 4: cy = product[63..32]
	subl	$1, %ecx
	jz	.L27

	movd	16(%ebx), %mm1	/ 5: mm1 = a[i]
	movd	16(%edx), %mm2	/ 5: mm2 = r[i]
	pmuludq	%mm3, %mm1	/ 5: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 5: mm2 = digit * a[i] + r[i]
	paddq	%mm2, %mm0	/ 5: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 16(%edx)	/ 5: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 5: cy = product[63..32]
	subl	$1, %ecx
	jz	.L27

	movd	20(%ebx), %mm1	/ 6: mm1 = a[i]
	movd	20(%edx), %mm2	/ 6: mm2 = r[i]
	pmuludq	%mm3, %mm1	/ 6: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 6: mm2 = digit * a[i] + r[i]
	paddq	%mm2, %mm0	/ 6: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 20(%edx)	/ 6: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 6: cy = product[63..32]
	subl	$1, %ecx
	jz	.L27

	movd	24(%ebx), %mm1	/ 7: mm1 = a[i]
	movd	24(%edx), %mm2	/ 7: mm2 = r[i]
	pmuludq	%mm3, %mm1	/ 7: mm1 = digit * a[i]
	paddq	%mm1, %mm2	/ 7: mm2 = digit * a[i] + r[i]
	paddq	%mm2, %mm0	/ 7: mm0 = digit * a[i] + r[i] + cy;
	movd	%mm0, 24(%edx)	/ 7: r[i] = product[31..0]
	psrlq	$32, %mm0	/ 7: cy = product[63..32]

.L27:
	movd	%mm0, %eax
	/ no emms.  caller is responsible for emms
	ret
	SET_SIZE(big_mul_add_vec_sse2_r)


/ r = r + a * digit, r and a are vectors of length len
/ returns the carry digit
/ Suitable only for x86 models that support SSE2 instruction set extensions
/
/ r		 8(%ebp)	%edx
/ a		12(%ebp)	%ebx
/ len		16(%ebp)	%ecx
/ digit		20(%ebp)	%mm3
/
/ In userland, there is just the one function, big_mul_add_vec_sse2().
/ But in the kernel, there are two variations:
/    1. big_mul_add_vec_sse2() which does what is necessary to save and
/       restore state, if necessary, and to ensure that preemtion is
/       disabled.
/    2. big_mul_add_vec_sse2_nsv() which just does the work;
/       it is the caller's responsibility to ensure that MMX state
/       does not need to be saved and restored and that preemption
/       is already disabled.


#if defined(MMX_MANAGE)

	ENTRY(big_mul_add_vec_sse2)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	pushl	%esi
	KPREEMPT_DISABLE
	TEST_TS(%ebx)
	pushl	%ebx
	jnz	.addvec_no_save
	pushl	%edi
	SAVE_MMX_0TO4(%edi)
	movl	8(%ebp), %edx
	movl	12(%ebp), %ebx
	movl	16(%ebp), %ecx
	movd	20(%ebp), %mm3
	call	big_mul_add_vec_sse2_r
	movl	%eax, %esi
	RSTOR_MMX_0TO4(%edi)
	popl	%edi
	jmp	.addvec_rtn

.addvec_no_save:
	movl	8(%ebp), %edx
	movl	12(%ebp), %ebx
	movl	16(%ebp), %ecx
	movd	20(%ebp), %mm3
	call	big_mul_add_vec_sse2_r
	movl	%eax, %esi

.addvec_rtn:
	emms
	popl	%ebx
	movl	%ebx, %cr0
	KPREEMPT_ENABLE
	movl	%esi, %eax
	popl	%esi
	popl	%ebx
	leave
	ret
	SET_SIZE(big_mul_add_vec_sse2)

	ENTRY(big_mul_add_vec_sse2_nsv)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	movl	8(%ebp), %edx
	movl	12(%ebp), %ebx
	movl	16(%ebp), %ecx
	movd	20(%ebp), %mm3
	call	big_mul_add_vec_sse2_r
	popl	%ebx
	leave
	ret
	SET_SIZE(big_mul_add_vec_sse2_nsv)


#else	/* !defined(MMX_MANAGE) */

	ENTRY(big_mul_add_vec_sse2)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	movl	8(%ebp), %edx
	movl	12(%ebp), %ebx
	movl	16(%ebp), %ecx
	movd	20(%ebp), %mm3
	call	big_mul_add_vec_sse2_r
	popl	%ebx
	emms
	leave
	ret
	SET_SIZE(big_mul_add_vec_sse2)

#endif	/* MMX_MANAGE */


/ void
/ big_mul_vec_sse2(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen)
/ {
/ 	int i;
/
/ 	r[alen] = big_mul_set_vec_sse2(r, a, alen, b[0]);
/ 	for (i = 1; i < blen; ++i)
/ 		r[alen + i] = big_mul_add_vec_sse2(r+i, a, alen, b[i]);
/ }


#if defined(MMX_MANAGE)
	ENTRY(big_mul_vec_sse2_fc)
#else
	ENTRY(big_mul_vec_sse2)
#endif
	subl	$0x8, %esp
	pushl	%ebx
	pushl	%ebp
	pushl	%esi
	pushl	%edi
	movl	40(%esp), %eax
	movl	%eax, 20(%esp)
	pushl	(%eax)
	movl	40(%esp), %edi
	pushl	%edi
	movl	40(%esp), %esi
	pushl	%esi
	movl	40(%esp), %ebx
	pushl	%ebx
#if defined(MMX_MANAGE)
	call	big_mul_set_vec_sse2_nsv
#else
	call	big_mul_set_vec_sse2
#endif
	addl	$0x10, %esp
	movl	%eax, (%ebx,%edi,4)
	movl	44(%esp), %eax
	movl	%eax, 16(%esp)
	cmpl	$0x1, %eax
	jle	.mulvec_rtn
	movl	$0x1, %ebp

	.align 16
.mulvec_add:
	movl	20(%esp), %eax
	pushl	(%eax,%ebp,4)
	pushl	%edi
	pushl	%esi
	leal	(%ebx,%ebp,4), %eax
	pushl	%eax
#if defined(MMX_MANAGE)
	call	big_mul_add_vec_sse2_nsv
#else
	call	big_mul_add_vec_sse2
#endif
	addl	$0x10, %esp
	leal	(%ebp,%edi), %ecx
	movl	%eax, (%ebx,%ecx,4)
	incl	%ebp
	cmpl	16(%esp), %ebp
	jl	.mulvec_add
.mulvec_rtn:
#if defined(MMX_MANAGE)
	emms
#endif
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	addl	$0x8, %esp
	ret
#if defined(MMX_MANAGE)
	SET_SIZE(big_mul_vec_sse2_fc)
#else
	SET_SIZE(big_mul_vec_sse2)
#endif

#if defined(MMX_MANAGE)

	ENTRY(big_mul_vec_sse2)
	pushl	%ebp
	movl	%esp, %ebp
	subl	$8, %esp
	pushl	%edi
	KPREEMPT_DISABLE
	TEST_TS(%eax)
	movl	%eax, -8(%ebp)
	jnz	.mulvec_no_save
	SAVE_MMX_0TO4(%edi)
	movl	%edi, -4(%ebp)
.mulvec_no_save:
	movl	24(%ebp), %eax		/ blen
	pushl	%eax
	movl	20(%ebp), %eax		/ b
	pushl	%eax
	movl	16(%ebp), %eax		/ alen
	pushl	%eax
	movl	12(%ebp), %eax		/ a
	pushl	%eax
	movl	8(%ebp), %eax		/ r
	pushl	%eax
	call	big_mul_vec_sse2_fc
	addl	$20, %esp
	movl	-8(%ebp), %eax
	testl	$CR0_TS, %eax
	jnz	.mulvec_no_rstr
	movl	-4(%ebp), %edi
	RSTOR_MMX_0TO4(%edi)
.mulvec_no_rstr:
	movl	%eax, %cr0
	KPREEMPT_ENABLE
	popl	%edi
	leave
	ret
	SET_SIZE(big_mul_vec_sse2)

#endif	/* MMX_MANAGE */



#undef UNROLL
#undef UNROLL32


/ r = a * a, r and a are vectors of length len
/ Suitable only for x86 models that support SSE2 instruction set extensions
/
/ This function is not suitable for a truly general-purpose multiprecision
/ arithmetic library, because it does not work for "small" numbers, that is
/ numbers of 1 or 2 digits.  big_mul() just uses the ordinary big_mul_vec()
/ for any small numbers.

#if defined(MMX_MANAGE)
	ENTRY(big_sqr_vec_sse2_fc)
#else
	ENTRY(big_sqr_vec_sse2)
	pushl	%ebp
	movl	%esp, %ebp
#endif

	pushl	%ebx
	pushl	%edi
	pushl	%esi

	/ r[1..alen] = a[0] * a[1..alen-1]

	movl	8(%ebp), %edi		/ r = arg(r)
	movl	12(%ebp), %esi		/ a = arg(a)
	movl	16(%ebp), %ecx		/ cnt = arg(alen)
	movd	%ecx, %mm4		/ save_cnt = arg(alen)
	leal	4(%edi), %edx		/ dst = &r[1]
	movl	%esi, %ebx		/ src = a
	movd	0(%ebx), %mm3		/ mm3 = a[0]
	leal	4(%ebx), %ebx		/ src = &a[1]
	subl	$1, %ecx		/ --cnt
	call	big_mul_set_vec_sse2_r	/ r[1..alen-1] = a[0] * a[1..alen-1]
	movl	%edi, %edx		/ dst = r
	movl	%esi, %ebx		/ src = a
	movd	%mm4, %ecx		/ cnt = save_cnt
	movl	%eax, (%edx, %ecx, 4)	/ r[cnt] = cy

/	/* High-level vector C pseudocode */
/	for (i = 1; i < alen-1; ++i)
/		r[2*i + 1 ... ] += a[i] * a[i+1 .. alen-1]
/
/	/* Same thing, but slightly lower level C-like pseudocode */
/	i = 1;
/	r = &arg_r[2*i + 1];
/	a = &arg_a[i + 1];
/	digit = arg_a[i];
/	cnt = alen - 3;
/	while (cnt != 0) {
/		r[cnt] = big_mul_add_vec_sse2_r(r, a, cnt, digit);
/		r += 2;
/		++a;
/		--cnt;
/	}
/
/	/* Same thing, but even lower level
/	 * For example, pointers are raw pointers,
/	 * with no scaling by object size.
/	 */
/	r = arg_r + 12;	/* i == 1; 2i + 1 == 3;  4*3 == 12; */
/	a = arg_a + 8;
/	digit = *(arg_a + 4);
/	cnt = alen - 3;
/	while (cnt != 0) {
/		cy = big_mul_add_vec_sse2_r();
/		*(r + 4 * cnt) = cy;
/		r += 8;
/		a += 4;
/		--cnt;
/	}

	leal	4(%edi), %edi		/ r += 4; r = &r[1]
	leal	4(%esi), %esi		/ a += 4; a = &a[1]
	movd	%mm4, %ecx		/ cnt = save
	subl	$2, %ecx		/ cnt = alen - 2; i in 1..alen-2
	movd	%ecx, %mm4		/ save_cnt
	jecxz	.L32			/ while (cnt != 0) {
.L31:
	movd	0(%esi), %mm3		/ digit = a[i]
	leal	4(%esi), %esi		/ a += 4; a = &a[1]; a = &a[i + 1]
	leal	8(%edi), %edi		/ r += 8; r = &r[2]; r = &r[2 * i + 1]
	movl	%edi, %edx		/ edx = r
	movl	%esi, %ebx		/ ebx = a
	cmp	$1, %ecx		/ The last triangle term is special
	jz	.L32
	call	big_mul_add_vec_sse2_r
	movd	%mm4, %ecx		/ cnt = save_cnt
	movl	%eax, (%edi, %ecx, 4)	/ r[cnt] = cy
	subl	$1, %ecx		/ --cnt
	movd	%ecx, %mm4		/ save_cnt = cnt
	jmp	.L31			/ }

.L32:
	movd	0(%ebx), %mm1		/ mm1 = a[i + 1]
	movd	0(%edx), %mm2		/ mm2 = r[2 * i + 1]
	pmuludq	%mm3, %mm1		/ mm1 = p = digit * a[i + 1]
	paddq	%mm1, %mm2		/ mm2 = r[2 * i + 1] + p
	movd	%mm2, 0(%edx)		/ r[2 * i + 1] += lo32(p)
	psrlq	$32, %mm2		/ mm2 = cy
	movd	%mm2, 4(%edx)		/ r[2 * i + 2] = cy
	pxor	%mm2, %mm2
	movd	%mm2, 8(%edx)		/ r[2 * i + 3] = 0

	movl	8(%ebp), %edx		/ r = arg(r)
	movl	12(%ebp), %ebx		/ a = arg(a)
	movl	16(%ebp), %ecx		/ cnt = arg(alen)

	/ compute low-order corner
	/ p = a[0]**2
	/ r[0] = lo32(p)
	/ cy   = hi32(p)
	movd	0(%ebx), %mm2		/ mm2 = a[0]
	pmuludq	%mm2, %mm2		/ mm2 = p = a[0]**2
	movd	%mm2, 0(%edx)		/ r[0] = lo32(p)
	psrlq	$32, %mm2		/ mm2 = cy = hi32(p)

	/ p = 2 * r[1]
	/ t = p + cy
	/ r[1] = lo32(t)
	/ cy   = hi32(t)
	movd	4(%edx), %mm1		/ mm1 = r[1]
	psllq	$1, %mm1		/ mm1 = p = 2 * r[1]
	paddq	%mm1, %mm2		/ mm2 = t = p + cy
	movd	%mm2, 4(%edx)		/ r[1] = low32(t)
	psrlq	$32, %mm2		/ mm2 = cy = hi32(t)

	/ r[2..$-3] = inner_diagonal[*]**2 + 2 * r[2..$-3]
	subl	$2, %ecx		/ cnt = alen - 2
.L34:
	movd	4(%ebx), %mm0		/ mm0 = diag = a[i+1]
	pmuludq	%mm0, %mm0		/ mm0 = p = diag**2
	paddq	%mm0, %mm2		/ mm2 = t = p + cy
	movd	%mm2, %eax
	movd	%eax, %mm1		/ mm1 = lo32(t)
	psrlq	$32, %mm2		/ mm2 = hi32(t)

	movd	8(%edx), %mm3		/ mm3 = r[2*i]
	psllq	$1, %mm3		/ mm3 = 2*r[2*i]
	paddq	%mm3, %mm1		/ mm1 = 2*r[2*i] + lo32(t)
	movd	%mm1, 8(%edx)		/ r[2*i] = 2*r[2*i] + lo32(t)
	psrlq	$32, %mm1
	paddq	%mm1, %mm2

	movd	12(%edx), %mm3		/ mm3 = r[2*i+1]
	psllq	$1, %mm3		/ mm3 = 2*r[2*i+1]
	paddq	%mm3, %mm2		/ mm2 = 2*r[2*i+1] + hi32(t)
	movd	%mm2, 12(%edx)		/ r[2*i+1] = mm2
	psrlq	$32, %mm2		/ mm2 = cy
	leal	8(%edx), %edx		/ r += 2
	leal	4(%ebx), %ebx		/ ++a
	subl	$1, %ecx		/ --cnt
	jnz	.L34

	/ Carry from last triangle term must participate in doubling,
	/ but this step isn't paired up with a squaring the elements
	/ of the inner diagonal.
	/ r[$-3..$-2] += 2 * r[$-3..$-2] + cy
	movd	8(%edx), %mm3		/ mm3 = r[2*i]
	psllq	$1, %mm3		/ mm3 = 2*r[2*i]
	paddq	%mm3, %mm2		/ mm2 = 2*r[2*i] + cy
	movd	%mm2, 8(%edx)		/ r[2*i] = lo32(2*r[2*i] + cy)
	psrlq	$32, %mm2		/ mm2 = cy = hi32(2*r[2*i] + cy)

	movd	12(%edx), %mm3		/ mm3 = r[2*i+1]
	psllq	$1, %mm3		/ mm3 = 2*r[2*i+1]
	paddq	%mm3, %mm2		/ mm2 = 2*r[2*i+1] + cy
	movd	%mm2, 12(%edx)		/ r[2*i+1] = mm2
	psrlq	$32, %mm2		/ mm2 = cy

	/ compute high-order corner and add it in
	/ p = a[alen - 1]**2
	/ t = p + cy
	/ r[alen + alen - 2] += lo32(t)
	/ cy = hi32(t)
	/ r[alen + alen - 1] = cy
	movd	4(%ebx), %mm0		/ mm0 = a[$-1]
	movd	8(%edx), %mm3		/ mm3 = r[$-2]
	pmuludq	%mm0, %mm0		/ mm0 = p = a[$-1]**2
	paddq	%mm0, %mm2		/ mm2 = t = p + cy
	paddq	%mm3, %mm2		/ mm2 = r[$-2] + t
	movd	%mm2, 8(%edx)		/ r[$-2] = lo32(r[$-2] + t)
	psrlq	$32, %mm2		/ mm2 = cy = hi32(r[$-2] + t)
	movd	12(%edx), %mm3
	paddq	%mm3, %mm2
	movd	%mm2, 12(%edx)		/ r[$-1] += cy

.L35:
	emms
	popl	%esi
	popl	%edi
	popl	%ebx

#if defined(MMX_MANAGE)
	ret
	SET_SIZE(big_sqr_vec_sse2_fc)
#else
	leave
	ret
	SET_SIZE(big_sqr_vec_sse2)
#endif


#if defined(MMX_MANAGE)
	ENTRY(big_sqr_vec_sse2)
	pushl	%ebp
	movl	%esp, %ebp
	KPREEMPT_DISABLE
	TEST_TS(%ebx)
	pushl	%ebx
	jnz	.sqr_no_save
	pushl	%edi
	SAVE_MMX_0TO4(%edi)
	call	big_sqr_vec_sse2_fc
	RSTOR_MMX_0TO4(%edi)
	popl	%edi
	jmp	.sqr_rtn

.sqr_no_save:
	call	big_sqr_vec_sse2_fc

.sqr_rtn:
	popl	%ebx
	movl	%ebx, %cr0
	KPREEMPT_ENABLE
	leave
	ret
	SET_SIZE(big_sqr_vec_sse2)

#endif	/* MMX_MANAGE */

/ ------------------------------------------------------------------------
/		UMUL Implementations
/ ------------------------------------------------------------------------


/ r = a * digit, r and a are vectors of length len
/ returns the carry digit
/ Does not use any MMX, SSE, or SSE2 instructions.
/ Uses x86 unsigned 32 X 32 -> 64 multiply instruction, MUL.
/ This is a fall-back implementation for x86 models that do not support
/ the PMULUDQ instruction.
/
/ uint32_t
/ big_mul_set_vec_umul(uint32_t *r, uint32_t *a, int len, uint32_t digit)
/
/ r		 8(%ebp)	%edx	%edi
/ a		12(%ebp)	%ebx	%esi
/ len		16(%ebp)	%ecx
/ digit		20(%ebp)	%esi

	ENTRY(big_mul_set_vec_umul)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%edi
	pushl	%ebx
	movl	16(%ebp), %ecx
	xorl	%ebx, %ebx	/ cy = 0
	testl	%ecx, %ecx
	movl	8(%ebp), %edi
	movl	12(%ebp), %esi
	je	.L57

.L55:
	movl	(%esi), %eax	/ eax = a[i]
	leal	4(%esi), %esi	/ ++a
	mull	20(%ebp)	/ edx:eax = a[i] * digit
	addl	%ebx, %eax
	adcl	$0, %edx	/ edx:eax = a[i] * digit + cy
	movl	%eax, (%edi)	/ r[i] = product[31..0]
	movl	%edx, %ebx	/ cy = product[63..32]
	leal	4(%edi), %edi	/ ++r
	decl	%ecx		/ --len
	jnz	.L55		/ while (len != 0)
.L57:
	movl	%ebx, %eax
	popl	%ebx
	popl	%edi
	popl	%esi
	leave
	ret
	SET_SIZE(big_mul_set_vec_umul)


/ r = r + a * digit, r and a are vectors of length len
/ returns the carry digit
/ Does not use any MMX, SSE, or SSE2 instructions.
/ Uses x86 unsigned 32 X 32 -> 64 multiply instruction, MUL.
/ This is a fall-back implementation for x86 models that do not support
/ the PMULUDQ instruction.
/
/ uint32_t
/ big_mul_add_vec_umul(uint32_t *r, uint32_t *a, int len, uint32_t digit)
/
/ r		 8(%ebp)	%edx	%edi
/ a		12(%ebp)	%ebx	%esi
/ len		16(%ebp)	%ecx
/ digit		20(%ebp)	%esi

	ENTRY(big_mul_add_vec_umul)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%edi
	pushl	%ebx
	movl	16(%ebp), %ecx
	xorl	%ebx, %ebx	/ cy = 0
	testl	%ecx, %ecx
	movl	8(%ebp), %edi
	movl	12(%ebp), %esi
	je	.L67
	.align 4
.L65:
	movl	(%esi), %eax	/ eax = a[i]
	leal	4(%esi), %esi	/ ++a
	mull	20(%ebp)	/ edx:eax = a[i] * digit
	addl	(%edi), %eax
	adcl	$0, %edx	/ edx:eax = a[i] * digit + r[i]
	addl	%ebx, %eax
	adcl	$0, %edx	/ edx:eax = a[i] * digit + r[i] + cy
	movl	%eax, (%edi)	/ r[i] = product[31..0]
	movl	%edx, %ebx	/ cy = product[63..32]
	leal	4(%edi), %edi	/ ++r
	decl	%ecx		/ --len
	jnz	.L65		/ while (len != 0)
.L67:
	movl	%ebx, %eax
	popl	%ebx
	popl	%edi
	popl	%esi
	leave
	ret
	SET_SIZE(big_mul_add_vec_umul)

#endif	/* __lint */
