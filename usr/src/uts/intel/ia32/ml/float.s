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
 * Copyright (c) 2017, Joyent, Inc.
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

#if defined(__amd64)

	ENTRY_NP(fxsave_insn)
	fxsaveq (%rdi)
	ret
	SET_SIZE(fxsave_insn)

#elif defined(__i386)

	ENTRY_NP(fxsave_insn)
	movl	4(%esp), %eax
	fxsave	(%eax)
	ret
	SET_SIZE(fxsave_insn)

#endif

#endif	/* __lint */

#if defined(__i386)

/*
 * If (num1/num2 > num1/num3) the FPU has the FDIV bug.
 */

#if defined(__lint)

int
fpu_probe_pentium_fdivbug(void)
{ return (0); }

#else	/* __lint */

	ENTRY_NP(fpu_probe_pentium_fdivbug)
	fldl	.num1
	fldl	.num2
	fdivr	%st(1), %st
	fxch	%st(1)
	fdivl	.num3
	fcompp
	fstsw	%ax
	sahf
	jae	0f
	movl	$1, %eax
	ret

0:	xorl	%eax, %eax
	ret

	.align	4
.num1:	.4byte	0xbce4217d	/* 4.999999 */
	.4byte	0x4013ffff
.num2:	.4byte	0x0		/* 15.0 */
	.4byte	0x402e0000
.num3:	.4byte	0xde7210bf	/* 14.999999 */
	.4byte	0x402dffff
	SET_SIZE(fpu_probe_pentium_fdivbug)

#endif	/* __lint */

/*
 * To cope with processors that do not implement fxsave/fxrstor
 * instructions, patch hot paths in the kernel to use them only
 * when that feature has been detected.
 */

#if defined(__lint)

void
patch_sse(void)
{}

void
patch_sse2(void)
{}

void
patch_xsave(void)
{}

#else	/* __lint */

	ENTRY_NP(patch_sse)
	_HOT_PATCH_PROLOG
	/
	/	frstor (%ebx); nop	-> fxrstor (%ebx)
	/
	_HOT_PATCH(_fxrstor_ebx_insn, _patch_fxrstor_ebx, 3)
	/
	/	lock; xorl $0, (%esp)	-> sfence; ret
	/
	_HOT_PATCH(_sfence_ret_insn, _patch_sfence_ret, 4)
	_HOT_PATCH_EPILOG
	ret
_fxrstor_ebx_insn:			/ see ndptrap_frstor()
	fxrstor	(%ebx)
_ldmxcsr_ebx_insn:			/ see resume_from_zombie()
	ldmxcsr	(%ebx)
_sfence_ret_insn:			/ see membar_producer()
	sfence
	ret
	SET_SIZE(patch_sse)

	ENTRY_NP(patch_sse2)
	_HOT_PATCH_PROLOG
	/
	/	lock; xorl $0, (%esp)	-> lfence; ret
	/
	_HOT_PATCH(_lfence_ret_insn, _patch_lfence_ret, 4)
	_HOT_PATCH_EPILOG
	ret
_lfence_ret_insn:			/ see membar_consumer()
	lfence
	ret
	SET_SIZE(patch_sse2)

	/*
	 * Patch lazy fp restore instructions in the trap handler
	 * to use xrstor instead of frstor
	 */
	ENTRY_NP(patch_xsave)
	_HOT_PATCH_PROLOG
	/
	/	frstor (%ebx); nop	-> xrstor (%ebx)
	/
	_HOT_PATCH(_xrstor_ebx_insn, _patch_xrstor_ebx, 3)
	_HOT_PATCH_EPILOG
	ret
_xrstor_ebx_insn:			/ see ndptrap_frstor()
	xrstor (%ebx)
	SET_SIZE(patch_xsave)

#endif	/* __lint */
#endif	/* __i386 */

#if defined(__amd64)
#if defined(__lint)

void
patch_xsave(void)
{}

#else	/* __lint */

	/*
	 * Patch lazy fp restore instructions in the trap handler
	 * to use xrstor instead of fxrstorq
	 */
	ENTRY_NP(patch_xsave)
	pushq	%rbx
	pushq	%rbp
	pushq	%r15
	/
	/	fxrstorq (%rbx);	-> nop; xrstor (%rbx)
	/ loop doing the following for 4 bytes:
	/     hot_patch_kernel_text(_patch_xrstorq_rbx, _xrstor_rbx_insn, 1)
	/
	leaq	_patch_xrstorq_rbx(%rip), %rbx
	leaq	_xrstor_rbx_insn(%rip), %rbp
	movq	$4, %r15
1:
	movq	%rbx, %rdi			/* patch address */
	movzbq	(%rbp), %rsi			/* instruction byte */
	movq	$1, %rdx			/* count */
	call	hot_patch_kernel_text
	addq	$1, %rbx
	addq	$1, %rbp
	subq	$1, %r15
	jnz	1b

	popq	%r15
	popq	%rbp
	popq	%rbx
	ret

_xrstor_rbx_insn:			/ see ndptrap_frstor()
	# Because the fxrstorq instruction we're patching is 4 bytes long, due
	# to the 0x48 prefix (indicating 64-bit operand size), we patch 4 bytes
	# too.
	nop
	xrstor (%rbx)
	SET_SIZE(patch_xsave)

#endif	/* __lint */
#endif	/* __amd64 */

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

/*ARGSUSED*/
void
fpnsave_ctxt(void *arg)
{}

#else	/* __lint */

#if defined(__amd64)

/*
 * These three functions define the Intel "xsave" handling for CPUs with
 * different features. Newer AMD CPUs can also use these functions. See the
 * 'exception pointers' comment below.
 */
	ENTRY_NP(fpxsave_ctxt)	/* %rdi is a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%rdi)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%rdi)
	movq	FPU_CTX_FPU_REGS(%rdi), %rdi /* fpu_regs.kfpu_u.kfpu_fn ptr */
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
	movq	FPU_CTX_FPU_REGS(%rdi), %rdi /* fpu_regs.kfpu_u.kfpu_fn ptr */
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

#elif defined(__i386)

	ENTRY_NP(fpnsave_ctxt)
	movl	4(%esp), %eax		/* a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%eax)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%eax)
	movl	FPU_CTX_FPU_REGS(%eax), %eax /* fpu_regs.kfpu_u.kfpu_fx ptr */
	fnsave	(%eax)
			/* (fnsave also reinitializes x87 state) */
	STTS(%edx)	/* trap on next fpu touch */
1:	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(fpnsave_ctxt)

	ENTRY_NP(fpxsave_ctxt)
	movl	4(%esp), %eax		/* a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%eax)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%eax)
	movl	FPU_CTX_FPU_REGS(%eax), %eax /* fpu_regs.kfpu_u.kfpu_fn ptr */
	fxsave	(%eax)
	STTS(%edx)	/* trap on next fpu touch */
1:	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(fpxsave_ctxt)

	ENTRY_NP(xsave_ctxt)
	movl	4(%esp), %ecx		/* a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%ecx)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%ecx)
	movl	FPU_CTX_FPU_XSAVE_MASK(%ecx), %eax
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%ecx), %edx
	movl	FPU_CTX_FPU_REGS(%ecx), %ecx /* fpu_regs.kfpu_u.kfpu_xs ptr */
	xsave	(%ecx)
	STTS(%edx)	/* trap on next fpu touch */
1:	ret
	SET_SIZE(xsave_ctxt)

	ENTRY_NP(xsaveopt_ctxt)
	movl	4(%esp), %ecx		/* a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%ecx)
	jne	1f
	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%ecx)
	movl	FPU_CTX_FPU_XSAVE_MASK(%ecx), %eax
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%ecx), %edx
	movl	FPU_CTX_FPU_REGS(%ecx), %ecx /* fpu_regs.kfpu_u.kfpu_xs ptr */
	xsaveopt (%ecx)
	STTS(%edx)	/* trap on next fpu touch */
1:	ret
	SET_SIZE(xsaveopt_ctxt)

/*
 * See comment above the __amd64 implementation of fpxsave_excp_clr_ctxt()
 * for details about the following threee functions for AMD "exception pointer"
 * handling.
 */

	ENTRY_NP(fpxsave_excp_clr_ctxt)
	movl	4(%esp), %eax		/* a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%eax)
	jne	1f

	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%eax)
	movl	FPU_CTX_FPU_REGS(%eax), %eax /* fpu_regs.kfpu_u.kfpu_fn ptr */
	fxsave	(%eax)
	btw	$7, FXSAVE_STATE_FSW(%eax)	/* Test saved ES bit */
	jnc	0f				/* jump if ES = 0 */
	fnclex		/* clear pending x87 exceptions */
0:	ffree	%st(7)	/* clear tag bit to remove possible stack overflow */
	fildl	.fpzero_const
			/* dummy load changes all exception pointers */
	STTS(%edx)	/* trap on next fpu touch */
1:	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(fpxsave_excp_clr_ctxt)

	ENTRY_NP(xsave_excp_clr_ctxt)
	movl	4(%esp), %ecx		/* a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%ecx)
	jne	1f

	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%ecx)
	movl	FPU_CTX_FPU_XSAVE_MASK(%ecx), %eax
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%ecx), %edx
	movl	FPU_CTX_FPU_REGS(%ecx), %ecx /* fpu_regs.kfpu_u.kfpu_xs ptr */
	xsave	(%ecx)
	btw	$7, FXSAVE_STATE_FSW(%ecx)	/* Test saved ES bit */
	jnc	0f				/* jump if ES = 0 */
	fnclex		/* clear pending x87 exceptions */
0:	ffree	%st(7)	/* clear tag bit to remove possible stack overflow */
	fildl	.fpzero_const
			/* dummy load changes all exception pointers */
	STTS(%edx)	/* trap on next fpu touch */
1:	ret
	SET_SIZE(xsave_excp_clr_ctxt)

	ENTRY_NP(xsaveopt_excp_clr_ctxt)
	movl	4(%esp), %ecx		/* a struct fpu_ctx */
	cmpl	$FPU_EN, FPU_CTX_FPU_FLAGS(%ecx)
	jne	1f

	movl	$_CONST(FPU_VALID|FPU_EN), FPU_CTX_FPU_FLAGS(%ecx)
	movl	FPU_CTX_FPU_XSAVE_MASK(%ecx), %eax
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%ecx), %edx
	movl	FPU_CTX_FPU_REGS(%ecx), %ecx /* fpu_regs.kfpu_u.kfpu_xs ptr */
	xsaveopt (%ecx)
	btw	$7, FXSAVE_STATE_FSW(%ecx)	/* Test saved ES bit */
	jnc	0f				/* jump if ES = 0 */
	fnclex		/* clear pending x87 exceptions */
0:	ffree	%st(7)	/* clear tag bit to remove possible stack overflow */
	fildl	.fpzero_const
			/* dummy load changes all exception pointers */
	STTS(%edx)	/* trap on next fpu touch */
1:	ret
	SET_SIZE(xsaveopt_excp_clr_ctxt)

#endif	/* __i386 */

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

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY_NP(fpsave)
	CLTS
	movl	4(%esp), %eax
	fnsave	(%eax)
	STTS(%eax)			/* set TS bit in %cr0 (disable FPU) */
	ret
	SET_SIZE(fpsave)

	ENTRY_NP(fpxsave)
	CLTS
	movl	4(%esp), %eax
	fxsave	(%eax)
	fninit				/* clear exceptions, init x87 tags */
	STTS(%eax)			/* set TS bit in %cr0 (disable FPU) */
	ret
	SET_SIZE(fpxsave)

	ENTRY_NP(xsave)
	CLTS
	movl	4(%esp), %ecx
	movl	8(%esp), %eax
	movl	12(%esp), %edx
	xsave	(%ecx)

	fninit				/* clear exceptions, init x87 tags */
	STTS(%eax)			/* set TS bit in %cr0 (disable FPU) */
	ret
	SET_SIZE(xsave)

	ENTRY_NP(xsaveopt)
	CLTS
	movl	4(%esp), %ecx
	movl	8(%esp), %eax
	movl	12(%esp), %edx
	xsaveopt (%ecx)

	fninit				/* clear exceptions, init x87 tags */
	STTS(%eax)			/* set TS bit in %cr0 (disable FPU) */
	ret
	SET_SIZE(xsaveopt)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
fprestore(struct fnsave_state *f)
{}

/*ARGSUSED*/
void
fpxrestore(struct fxsave_state *f)
{}

/*ARGSUSED*/
void
xrestore(struct xsave_state *f, uint64_t m)
{}

#else	/* __lint */

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY_NP(fprestore)
	CLTS
	movl	4(%esp), %eax
	frstor	(%eax)
	ret
	SET_SIZE(fprestore)

	ENTRY_NP(fpxrestore)
	CLTS
	movl	4(%esp), %eax
	fxrstor	(%eax)
	ret
	SET_SIZE(fpxrestore)

	ENTRY_NP(xrestore)
	CLTS
	movl	4(%esp), %ecx
	movl	8(%esp), %eax
	movl	12(%esp), %edx
	xrstor	(%ecx)
	ret
	SET_SIZE(xrestore)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Disable the floating point unit.
 */

#if defined(__lint)

void
fpdisable(void)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(fpdisable)
	STTS(%rdi)			/* set TS bit in %cr0 (disable FPU) */ 
	ret
	SET_SIZE(fpdisable)

#elif defined(__i386)

	ENTRY_NP(fpdisable)
	STTS(%eax)
	ret
	SET_SIZE(fpdisable)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Initialize the fpu hardware.
 */

#if defined(__lint)

void
fpinit(void)
{}

#else	/* __lint */

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY_NP(fpinit)
	CLTS
	cmpl	$FP_FXSAVE, fp_save_mech
	je	1f
	cmpl	$FP_XSAVE, fp_save_mech
	je	2f

	/* fnsave */
	fninit
	movl	$x87_initial, %eax
	frstor	(%eax)			/* load clean initial state */
	ret

1:	/* fxsave */
	movl	$sse_initial, %eax
	fxrstor	(%eax)			/* load clean initial state */
	ret

2:	/* xsave */
	movl	$avx_initial, %ecx
	xorl	%edx, %edx
	movl	$XFEATURE_AVX, %eax
	bt	$X86FSET_AVX, x86_featureset
	cmovael	%edx, %eax
	orl	$(XFEATURE_LEGACY_FP | XFEATURE_SSE), %eax
	xrstor (%ecx)
	ret
	SET_SIZE(fpinit)

#endif	/* __i386 */
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

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY_NP(fperr_reset)
	CLTS
	xorl	%eax, %eax
	fnstsw	%ax
	fnclex
	ret
	SET_SIZE(fperr_reset)

	ENTRY_NP(fpxerr_reset)
	CLTS
	subl	$4, %esp		/* make some temporary space */
	stmxcsr	(%esp)
	movl	(%esp), %eax
	andl	$_BITNOT(SSE_MXCSR_EFLAGS), (%esp)
	ldmxcsr	(%esp)			/* clear processor exceptions */
	addl	$4, %esp
	ret
	SET_SIZE(fpxerr_reset)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

uint32_t
fpgetcwsw(void)
{
	return (0);
}

#else   /* __lint */

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY_NP(fpgetcwsw)
	CLTS
	subl	$4, %esp		/* make some temporary space	*/
	fnstsw	(%esp)			/* store the status word	*/
	fnstcw	2(%esp)			/* store the control word	*/
	movl	(%esp), %eax		/* put both in %eax		*/
	addl	$4, %esp
	ret
	SET_SIZE(fpgetcwsw)

#endif	/* __i386 */
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

#if defined(__amd64)

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

#elif defined(__i386)

	ENTRY_NP(fpgetmxcsr)
	CLTS
	subl	$4, %esp		/* make some temporary space */
	stmxcsr	(%esp)
	movl	(%esp), %eax
	addl	$4, %esp
	ret
	SET_SIZE(fpgetmxcsr)

#endif	/* __i386 */
#endif  /* __lint */
