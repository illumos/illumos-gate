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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

/*      Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*      Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*        All Rights Reserved   */

/*      Copyright (c) 1987, 1988 Microsoft Corporation  */
/*        All Rights Reserved   */

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/x86_archext.h>

#if defined(__lint)
#include <sys/types.h>
#include <sys/fp.h>
#else
#include "assym.h"
#endif

#if defined(__lint)
 
uint_t
fpu_initial_probe(void)
{ return (0); }

#else	/* __lint */

	/*
	 * Returns zero if x87 "chip" is present(!)
	 */
	ENTRY_NP(fpu_initial_probe)
	CLTS
	fninit
	fnstsw	%ax
	movzbl	%al, %eax
	ret
	SET_SIZE(fpu_initial_probe)

#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
fxsave_insn(struct fxsave_state *fx)
{}

#else	/* __lint */

	ENTRY_NP(fxsave_insn)
	fxsaveq (%rdi)
	ret
	SET_SIZE(fxsave_insn)

#endif	/* __lint */

/*
 * One of these routines is called from any lwp with floating
 * point context as part of the prolog of a context switch.
 */

#if defined(__lint)

/*ARGSUSED*/
void
xsave_ctxt(void *arg)
{}

/*ARGSUSED*/
void
xsaveopt_ctxt(void *arg)
{}

/*ARGSUSED*/
void
fpxsave_ctxt(void *arg)
{}

#else	/* __lint */

/*
 * These three functions define the Intel "xsave" handling for CPUs with
 * different features. Newer AMD CPUs can also use these functions. See the
 * 'exception pointers' comment below.
 */
	ENTRY_NP(fpxsave_ctxt)	/* %rdi is a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movq	FPU_CTX_FPU_REGS(%rdi), %rdi /* fpu_regs.kfpu_u.kfpu_fx ptr */
	fxsaveq	(%rdi)
	STTS(%rsi)	/* trap on next fpu touch */
1:	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(fpxsave_ctxt)

	ENTRY_NP(xsave_ctxt)
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movl	FPU_CTX_FPU_XSAVE_MASK(%rdi), %eax /* xsave flags in EDX:EAX */
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%rdi), %edx
	movq	FPU_CTX_FPU_REGS(%rdi), %rsi /* fpu_regs.kfpu_u.kfpu_xs ptr */
	xsave	(%rsi)
	STTS(%rsi)	/* trap on next fpu touch */
1:	ret
	SET_SIZE(xsave_ctxt)

	ENTRY_NP(xsaveopt_ctxt)
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movl	FPU_CTX_FPU_XSAVE_MASK(%rdi), %eax /* xsave flags in EDX:EAX */
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%rdi), %edx
	movq	FPU_CTX_FPU_REGS(%rdi), %rsi /* fpu_regs.kfpu_u.kfpu_xs ptr */
	xsaveopt (%rsi)
	STTS(%rsi)	/* trap on next fpu touch */
1:	ret
	SET_SIZE(xsaveopt_ctxt)

/*
 * On certain AMD processors, the "exception pointers" (i.e. the last
 * instruction pointer, last data pointer, and last opcode) are saved by the
 * fxsave, xsave or xsaveopt instruction ONLY if the exception summary bit is
 * set.
 *
 * On newer CPUs, AMD has changed their behavior to mirror the Intel behavior.
 * We can detect this via an AMD specific cpuid feature bit
 * (CPUID_AMD_EBX_ERR_PTR_ZERO) and use the simpler Intel-oriented functions.
 * Otherwise we use these more complex functions on AMD CPUs. All three follow
 * the same logic after the xsave* instruction.
 */
	ENTRY_NP(fpxsave_excp_clr_ctxt)	/* %rdi is a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movq	FPU_CTX_FPU_REGS(%rdi), %rdi /* fpu_regs.kfpu_u.kfpu_fx ptr */
	fxsaveq	(%rdi)
	/*
	 * To ensure that we don't leak these values into the next context
	 * on the cpu, we could just issue an fninit here, but that's
	 * rather slow and so we issue an instruction sequence that
	 * clears them more quickly, if a little obscurely.
	 */
	btw	$7, FXSAVE_STATE_FSW(%rdi)	/* Test saved ES bit */
	jnc	0f				/* jump if ES = 0 */
	fnclex		/* clear pending x87 exceptions */
0:	ffree	%st(7)	/* clear tag bit to remove possible stack overflow */
	fildl	.fpzero_const(%rip)
			/* dummy load changes all exception pointers */
	STTS(%rsi)	/* trap on next fpu touch */
1:	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(fpxsave_excp_clr_ctxt)

	ENTRY_NP(xsave_excp_clr_ctxt)
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movl	FPU_CTX_FPU_XSAVE_MASK(%rdi), %eax
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%rdi), %edx
	movq	FPU_CTX_FPU_REGS(%rdi), %rsi /* fpu_regs.kfpu_u.kfpu_xs ptr */
	xsave	(%rsi)
	btw	$7, FXSAVE_STATE_FSW(%rsi)	/* Test saved ES bit */
	jnc	0f				/* jump if ES = 0 */
	fnclex		/* clear pending x87 exceptions */
0:	ffree	%st(7)	/* clear tag bit to remove possible stack overflow */
	fildl	.fpzero_const(%rip) /* dummy load changes all excp. pointers */
	STTS(%rsi)	/* trap on next fpu touch */
1:	ret
	SET_SIZE(xsave_excp_clr_ctxt)

	ENTRY_NP(xsaveopt_excp_clr_ctxt)
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movl	FPU_CTX_FPU_XSAVE_MASK(%rdi), %eax
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%rdi), %edx
	movq	FPU_CTX_FPU_REGS(%rdi), %rsi /* fpu_regs.kfpu_u.kfpu_xs ptr */
	xsaveopt (%rsi)
	btw	$7, FXSAVE_STATE_FSW(%rsi)	/* Test saved ES bit */
	jnc	0f				/* jump if ES = 0 */
	fnclex		/* clear pending x87 exceptions */
0:	ffree	%st(7)	/* clear tag bit to remove possible stack overflow */
	fildl	.fpzero_const(%rip) /* dummy load changes all excp. pointers */
	STTS(%rsi)	/* trap on next fpu touch */
1:	ret
	SET_SIZE(xsaveopt_excp_clr_ctxt)

	.align	8
.fpzero_const:
	.4byte	0x0
	.4byte	0x0

#endif	/* __lint */


#if defined(__lint)

/*ARGSUSED*/
void
fpsave(struct fnsave_state *f)
{}

/*ARGSUSED*/
void
fpxsave(struct fxsave_state *f)
{}

/*ARGSUSED*/
void
xsave(struct xsave_state *f, uint64_t m)
{}

/*ARGSUSED*/
void
xsaveopt(struct xsave_state *f, uint64_t m)
{}

#else	/* __lint */

	ENTRY_NP(fpxsave)
	CLTS
	fxsaveq (%rdi)
	fninit				/* clear exceptions, init x87 tags */
	STTS(%rdi)			/* set TS bit in %cr0 (disable FPU) */
	ret
	SET_SIZE(fpxsave)

	ENTRY_NP(xsave)
	CLTS
	movl	%esi, %eax		/* bv mask */
	movq	%rsi, %rdx
	shrq	$32, %rdx
	xsave	(%rdi)

	fninit				/* clear exceptions, init x87 tags */
	STTS(%rdi)			/* set TS bit in %cr0 (disable FPU) */
	ret
	SET_SIZE(xsave)

	ENTRY_NP(xsaveopt)
	CLTS
	movl	%esi, %eax		/* bv mask */
	movq	%rsi, %rdx
	shrq	$32, %rdx
	xsaveopt (%rdi)

	fninit				/* clear exceptions, init x87 tags */
	STTS(%rdi)			/* set TS bit in %cr0 (disable FPU) */
	ret
	SET_SIZE(xsaveopt)

#endif	/* __lint */

/*
 * These functions are used when restoring the FPU as part of the epilogue of a
 * context switch.
 */

#if defined(__lint)

/*ARGSUSED*/
void
fpxrestore_ctxt(void *arg)
{}

/*ARGSUSED*/
void
xrestore_ctxt(void *arg)
{}

#else	/* __lint */

	ENTRY(fpxrestore_ctxt)
	cmpl	$_CONST(FPU_EN|FPU_VALID), FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movq	FPU_CTX_FPU_REGS(%rdi), %rdi /* fpu_regs.kfpu_u.kfpu_fx ptr */
	CLTS
	fxrstorq	(%rdi)
1:
	ret
	SET_SIZE(fpxrestore_ctxt)

	ENTRY(xrestore_ctxt)
	cmpl	$_CONST(FPU_EN|FPU_VALID), FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movl	FPU_CTX_FPU_XSAVE_MASK(%rdi), %eax /* xsave flags in EDX:EAX */
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%rdi), %edx
	movq	FPU_CTX_FPU_REGS(%rdi), %rdi /* fpu_regs.kfpu_u.kfpu_xs ptr */
	CLTS
	xrstor	(%rdi)
1:
	ret
	SET_SIZE(xrestore_ctxt)

#endif	/* __lint */


#if defined(__lint)

/*ARGSUSED*/
void
fpxrestore(struct fxsave_state *f)
{}

/*ARGSUSED*/
void
xrestore(struct xsave_state *f, uint64_t m)
{}

#else	/* __lint */

	ENTRY_NP(fpxrestore)
	CLTS
	fxrstorq	(%rdi)
	ret
	SET_SIZE(fpxrestore)

	ENTRY_NP(xrestore)
	CLTS
	movl	%esi, %eax		/* bv mask */
	movq	%rsi, %rdx
	shrq	$32, %rdx
	xrstor	(%rdi)
	ret
	SET_SIZE(xrestore)

#endif	/* __lint */

/*
 * Disable the floating point unit.
 */

#if defined(__lint)

void
fpdisable(void)
{}

#else	/* __lint */

	ENTRY_NP(fpdisable)
	STTS(%rdi)			/* set TS bit in %cr0 (disable FPU) */ 
	ret
	SET_SIZE(fpdisable)

#endif	/* __lint */

/*
 * Initialize the fpu hardware.
 */

#if defined(__lint)

void
fpinit(void)
{}

#else	/* __lint */

	ENTRY_NP(fpinit)
	CLTS
	cmpl	$FP_XSAVE, fp_save_mech
	je	1f

	/* fxsave */
	leaq	sse_initial(%rip), %rax
	fxrstorq	(%rax)			/* load clean initial state */
	ret

1:	/* xsave */
	leaq	avx_initial(%rip), %rcx
	xorl	%edx, %edx
	movl	$XFEATURE_AVX, %eax
	bt	$X86FSET_AVX, x86_featureset
	cmovael	%edx, %eax
	orl	$(XFEATURE_LEGACY_FP | XFEATURE_SSE), %eax
	xrstor (%rcx)
	ret
	SET_SIZE(fpinit)

#endif	/* __lint */

/*
 * Clears FPU exception state.
 * Returns the FP status word.
 */

#if defined(__lint)

uint32_t
fperr_reset(void)
{ return (0); }

uint32_t
fpxerr_reset(void)
{ return (0); }

#else	/* __lint */

	ENTRY_NP(fperr_reset)
	CLTS
	xorl	%eax, %eax
	fnstsw	%ax
	fnclex
	ret
	SET_SIZE(fperr_reset)

	ENTRY_NP(fpxerr_reset)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$0x10, %rsp		/* make some temporary space */
	CLTS
	stmxcsr	(%rsp)
	movl	(%rsp), %eax
	andl	$_BITNOT(SSE_MXCSR_EFLAGS), (%rsp)
	ldmxcsr	(%rsp)			/* clear processor exceptions */
	leave
	ret
	SET_SIZE(fpxerr_reset)

#endif	/* __lint */

#if defined(__lint)

uint32_t
fpgetcwsw(void)
{
	return (0);
}

#else   /* __lint */

	ENTRY_NP(fpgetcwsw)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$0x10, %rsp		/* make some temporary space	*/
	CLTS
	fnstsw	(%rsp)			/* store the status word	*/
	fnstcw	2(%rsp)			/* store the control word	*/
	movl	(%rsp), %eax		/* put both in %eax		*/
	leave
	ret
	SET_SIZE(fpgetcwsw)

#endif  /* __lint */

/*
 * Returns the MXCSR register.
 */

#if defined(__lint)

uint32_t
fpgetmxcsr(void)
{
	return (0);
}

#else   /* __lint */

	ENTRY_NP(fpgetmxcsr)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$0x10, %rsp		/* make some temporary space */
	CLTS
	stmxcsr	(%rsp)
	movl	(%rsp), %eax
	leave
	ret
	SET_SIZE(fpgetmxcsr)

#endif  /* __lint */
