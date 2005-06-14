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

/*      Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*      Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*        All Rights Reserved   */

/*      Copyright (c) 1987, 1988 Microsoft Corporation  */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
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

int fpu_exists = 1;
int fp_kind = FP_387;
int fpu_ignored = 0;

int use_sse_pagecopy = 0;
int use_sse_pagezero = 0;
int use_sse_copy = 0;

#if defined(__i386)

int fpu_pentium_fdivbug = 0;

#endif

#else	/* __lint */

	/*
	 * If fpu_exists is non-zero, fpu_probe will attempt to use any
	 * hardware FPU (subject to other constraints, see below).  If
	 * fpu_exists is zero, fpu_probe will report that there is no
	 * FPU even if there is one.
	 */
	DGDEF3(fpu_exists, 4, 4)
	.long	1

	DGDEF3(fp_kind, 4, 4)
	.long	FP_387		/* FP_NO, FP_287, FP_387, etc. */

	/*
	 * The variable fpu_ignored is provided to allow other code to
	 * determine whether emulation is being done because there is
	 * no FPU or because of an override requested via /etc/system.
	 */
	DGDEF3(fpu_ignored, 4, 4)
	.long	0

	/*
	 * Used by ppcopy, ppzero, and xcopyin to determine whether or not
	 * to use the SSE-based routines
	 */
	DGDEF3(use_sse_pagecopy, 4, 4)
	.long	0

	DGDEF3(use_sse_pagezero, 4, 4)
	.long	0

	DGDEF3(use_sse_copy, 4, 4)
	.long	0

#if defined(__i386)

	/*
	 * The variable fpu_pentium_fdivbug is provided to allow other code to
	 * determine whether the system contains a Pentium with the FDIV
	 * problem.
	 */
	DGDEF3(fpu_pentium_fdivbug, 4, 4)
	.long	0

	/*
	 * The following constants are used for detecting the Pentium
	 * divide bug.
	 */
	.align	4
num1:	.4byte	0xbce4217d	/* 4.999999 */
	.4byte	0x4013ffff
num2:	.4byte	0x0		/* 15.0 */
	.4byte	0x402e0000
num3:	.4byte	0xde7210bf	/* 14.999999 */
	.4byte	0x402dffff

#endif	/* __i386 */
#endif	/* __lint */

/*
 * FPU probe - check if we have any FP chip present by trying to do a reset.
 * If that succeeds, differentiate via cr0. Called from autoconf.
 */

#if defined(__lint)
 
/*ARGSUSED*/
void
fpu_probe(void)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(fpu_probe)
	pushq	%rbp
	movq	%rsp, %rbp
	clts				/* clear task switched bit in CR0 */
	fninit				/* initialize chip */
	fnstsw	%ax			/* get status */
	orb	%al, %al		/* status zero? 0 = chip present */
	jnz	no_fpu_hw

	/*
	 * Ignore the FPU if fp_exists == 0
	 */
	cmpl	$0, fpu_exists(%rip)
	je	ignore_fpu

	/*
	 * we have a chip of some sort; use cr0 to differentiate
	 */
	movq	%cr0, %rdx		/* check for fpu present flag */
	testl	$CR0_ET, %edx
	jz	no_fpu_hw		/* z -> fpu not present */
	testl	$X86_SSE, x86_feature(%rip)
	je	no_fpu_hw		/* SSE is utterly required */
	testl	$X86_SSE2, x86_feature(%rip)
	je	no_fpu_hw		/* SSE2 too .. */
	movl	$__FP_SSE, fp_kind(%rip)

	/*
	 * Tell the processor what we're doing via %cr4
	 */
	movq	%cr4, %rax
	orq	$_CONST(CR4_OSFXSR | CR4_OSXMMEXCPT), %rax
	movq	%rax, %cr4

	/*
	 * make other CPUs share the same cr4 settings
	 */
	orq	$_CONST(CR4_OSFXSR | CR4_OSXMMEXCPT), cr4_value(%rip)

	/*
	 * extract the MXCSR_MASK field from our first fxsave
	 */
	subq	$FXSAVE_STATE_SIZE, %rsp
	movl	$0, FXSAVE_STATE_MXCSR_MASK(%rsp)
	fxsave	(%rsp)
	movl	FXSAVE_STATE_MXCSR_MASK(%rsp), %eax
	cmpl	$0, %eax
	je	1f			/* default mask value set in fpu.c */
	movl	%eax, sse_mxcsr_mask(%rip) /* override mask set here */
1:
	movq	%cr0, %rax
	andq	$_BITNOT(CR0_TS|CR0_EM), %rdx	/* clear emulate math bit */
	orq	$_CONST(CR0_MP|CR0_NE), %rdx

	/*
	 * We have SSE and SSE2 so enable the extensions for
	 * non-temporal copies and stores.
	 */
	movl	$1, use_sse_pagecopy
	movl	$1, use_sse_pagezero
	movl	$1, use_sse_copy

	jmp	done

	/*
	 * Do not use the FPU at all
	 */
ignore_fpu:
	movl	$1, fpu_ignored(%rip)

	/*
	 * No FPU hardware present
	 */
no_fpu_hw:
	andq	$_BITNOT(CR0_MP), %rdx	/* clear math chip present */
	orq	$CR0_EM, %rdx		/* set emulate math bit */
	movl	$FP_NO, fp_kind(%rip)	/* signify that there is no FPU */
	movl	$0, fpu_exists(%rip)	/* no FPU present */
	/*
	 * Disable the XMM-related gorp too, in case the BIOS set them
	 */
	movq	%cr4, %rax
	andq	$_BITNOT(CR4_OSFXSR | CR4_OSXMMEXCPT), %rax
	movq	%rax, %cr4
	andq	$_BITNOT(CR4_OSFXSR | CR4_OSXMMEXCPT), cr4_value(%rip)

done:
	movq	%rdx, %cr0		/* set machine status word */
	leave
	ret
	SET_SIZE(fpu_probe)

#elif defined(__i386)

	ENTRY_NP(fpu_probe)
	clts				/ clear task switched bit in CR0
	fninit				/ initialize chip
	fnstsw	%ax			/ get status
	orb	%al, %al		/ status zero? 0 = chip present
	jnz	no_fpu_hw		/ no, use emulator
/
/ If there is an FP, look for the Pentium FDIV problem even if we
/ do not plan to use it.  Set fpu_pentium_fdivbug is a bad FPU is
/ detected.  Subsequent code can report the result if desired.
/
/ If (num1/num2 > num1/num3) the FPU has the FDIV bug.
/
	fldl	num1
	fldl	num2
	fdivr	%st(1), %st
	fxch	%st(1)
	fdivl	num3
	fcompp
	fstsw	%ax
	sahf
	jae	no_bug
	movl	$1, fpu_pentium_fdivbug
no_bug:
/
/ Repeat the earlier initialization sequence so that the FPU is left in
/ the expected state.
/
	fninit
	fnstsw	%ax
/
/ Ignore the FPU if fpu_exists == 0
/
	cmpl	$0, fpu_exists
	je	ignore_fpu
/
/ Ignore the FPU if it has the Pentium bug
/
	cmpl	$0, fpu_pentium_fdivbug
	jne	ignore_fpu
/
/ at this point we know we have a chip of some sort; 
/ use cr0 to differentiate.
/
	movl    %cr0, %edx		/ check for 387 present flag
	testl	$CR0_ET, %edx		/ ...
	jz	is287			/ z -> 387 not present
	movl	$FP_387, fp_kind	/ we have a 387 or later chip
/
/ clear the "XMM supported" bits in %cr4 in case the BIOS set them
/ erroneously -- see 4965674
/
	movl	%cr4, %eax
	andl	$_BITNOT(CR4_OSFXSR | CR4_OSXMMEXCPT), %eax
	movl	%eax, %cr4
	andl	$_BITNOT(CR4_OSFXSR | CR4_OSXMMEXCPT), cr4_value

	testl	$X86_SSE, x86_feature	/ can we do SSE?
	je	mathchip
/
/ aha .. we have an SSE-capable chip
/
/ - set fpsave_begin to fpxsave_begin
/ - hot patch performance critical code to use fxsave/fxrstor directly,
/   and hot patch membar_producer() to use sfence instead of lock
/ - tell the processor what we're doing via %cr4
/ - allow fully fledged #XM exceptions to be generated by SSE/SSE2
/   (the default mask set in fpinit() disables them)
/ - determine the mxcsr_mask so we can avoid setting reserved bits
/	
	movl	$__FP_SSE, fp_kind
	movl	$fpxsave_begin, %eax
	movl	%eax, fpsave_begin
	call	patch_sse
	mov	%cr4, %eax
	orl	$_CONST(CR4_OSFXSR | CR4_OSXMMEXCPT), %eax
	mov	%eax, %cr4
/
/ make other CPUs share the same cr4 settings
/
	orl	$_CONST(CR4_OSFXSR | CR4_OSXMMEXCPT), cr4_value
/
/ extract the MXCSR_MASK field from our first fxsave 
/
	subl	$FXSAVE_STATE_SIZE + XMM_ALIGN, %esp
	movl	%esp, %eax
	addl	$XMM_ALIGN, %eax
	andl	$_BITNOT(XMM_ALIGN-1), %eax	/* 16-byte alignment */
	movl	$0, FXSAVE_STATE_MXCSR_MASK(%eax)
	fxsave	(%eax)
	movl	FXSAVE_STATE_MXCSR_MASK(%eax), %eax
	addl	$FXSAVE_STATE_SIZE + XMM_ALIGN, %esp
	cmpl	$0, %eax
	je	1f			/ default mask value set in fpu.c
	movl	%eax, sse_mxcsr_mask	/ override mask set here
1:	testl	$X86_SSE2, x86_feature	/ can we do SSE2?
	je	mathchip
/
/ aha .. we have an SSE2-capable chip
/
/ - enable pagezero and pagecopy using non-temporal instructions
/ - hot patch membar_consumer() to use lfence instead of lock
/
	movl	$1, use_sse_pagecopy	/ will now call hwblkpagecopy
	movl	$1, use_sse_pagezero	/ will now call hwblkclr
	movl	$1, use_sse_copy
	call	patch_sse2
	jmp	mathchip
/
/ No 387; we must have an 80287.
/
is287:
#if !defined(__GNUC_AS__)
	fsetpm				/ set the 80287 into protected mode
	movl	$FP_287, fp_kind	/ we have a 287 chip
#else
	movl	$FP_NO, fp_kind		/ maybe just explode here instead?
#endif
/
/ We have either a 287, 387, 486 or P5.
/ Setup cr0 to reflect the FPU hw type.
/
mathchip:
	movl	%cr0, %edx
	andl	$_BITNOT(CR0_TS|CR0_EM), %edx	/* clear emulate math bit */
	orl	$_CONST(CR0_MP|CR0_NE), %edx
	jmp	cont

/ Do not use the FPU
ignore_fpu:
	movl	$1, fpu_ignored
/ No FP hw present.
no_fpu_hw:
	movl	%cr0, %edx
	andl	$_BITNOT(CR0_MP), %edx	/* clear math chip present */
	movl	$FP_NO, fp_kind		/ signify that there is no FPU
	movl	$0, fpu_exists		/ no FPU present
cont:
	movl	%edx, %cr0		/ set machine status word
	ret
	SET_SIZE(fpu_probe)

#define	HOT_PATCH(srcaddr, dstaddr, size)	\
	movl	$srcaddr, %esi;			\
	movl	$dstaddr, %edi;			\
	movl	$size, %ebx;			\
0:	pushl	$1;				\
	movzbl	(%esi), %eax;			\
	pushl	%eax;				\
	pushl	%edi;				\
	call	hot_patch_kernel_text;		\
	addl	$12, %esp;			\
	inc	%edi;				\
	inc	%esi;				\
	dec	%ebx;				\
	test	%ebx, %ebx;			\
	jne	0b

	/*
	 * To cope with processors that do not implement fxsave/fxrstor
	 * instructions, patch hot paths in the kernel to use them only
	 * when that feature has been detected.
	 */
	ENTRY_NP(patch_sse)
	push	%ebp
	mov	%esp, %ebp
	push	%ebx
	push	%esi
	push	%edi
	/
	/	frstor (%eax); nop	-> fxrstor (%eax)
	/
	HOT_PATCH(_fxrstor_eax_insn, _patch_fxrstor_eax, 3)
	/
	/	nop; nop; nop		-> ldmxcsr (%ebx)
	/
	HOT_PATCH(_ldmxcsr_ebx_insn, _patch_ldmxcsr_ebx, 3)
	/
	/	lock; xorl $0, (%esp)	-> sfence; ret
	/
	HOT_PATCH(_sfence_ret_insn, _patch_sfence_ret, 4)
	pop	%edi
	pop	%esi
	pop	%ebx
	mov	%ebp, %esp
	pop	%ebp
	ret
_fxrstor_eax_insn:			/ see ndptrap_frstor()
	fxrstor	(%eax)
_ldmxcsr_ebx_insn:			/ see resume_from_zombie()
	ldmxcsr	(%ebx)
_sfence_ret_insn:			/ see membar_producer()
	.byte	0xf, 0xae, 0xf8		/ [sfence instruction]
	ret
	SET_SIZE(patch_sse)

	/*
	 * Ditto, but this time for functions that depend upon SSE2 extensions
	 */
	ENTRY_NP(patch_sse2)
	push	%ebp
	mov	%esp, %ebp
	push	%ebx
	push	%esi
	push	%edi
	/
	/	lock; xorl $0, (%esp)	-> lfence; ret
	/
	HOT_PATCH(_lfence_ret_insn, _patch_lfence_ret, 4)
	pop	%edi
	pop	%esi
	pop	%ebx
	mov	%ebp, %esp
	pop	%ebp
	ret
_lfence_ret_insn:			/ see membar_consumer()
	.byte	0xf, 0xae, 0xe8		/ [lfence instruction]	
	ret
	SET_SIZE(patch_sse2)

#endif	/* __i386 */
#endif	/* __lint */

	
/*
 * One of these routines is called from any lwp with floating
 * point context as part of the prolog of a context switch; the
 * routine starts the floating point state save operation.
 * The completion of the save is forced by an fwait just before
 * we truly switch contexts..
 */

#if defined(__lint)

/*ARGSUSED*/
void
fpnsave_begin(void *arg)
{}

/*ARGSUSED*/
void
fpxsave_begin(void *arg)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(fpxsave_begin)
	movl	FPU_CTX_FPU_FLAGS(%rdi), %edx
	cmpl	$FPU_EN, %edx
	jne	1f
#if FPU_CTX_FPU_REGS != 0
	addq	FPU_CTX_FPU_REGS, %rdi
#endif
	fxsave	(%rdi)
	fnclex				/* clear pending x87 exceptions */
1:	ret
	SET_SIZE(fpxsave_begin)

#elif defined(__i386)

	ENTRY_NP(fpnsave_begin)
	mov	4(%esp), %eax		/ a struct fpu_ctx *
	mov	FPU_CTX_FPU_FLAGS(%eax), %edx
	cmpl	$FPU_EN, %edx
	jne	1f
#if FPU_CTX_FPU_REGS != 0
	addl	FPU_CTX_FPU_REGS, %eax
#endif
	fnsave	(%eax)
1:	ret
	SET_SIZE(fpnsave_begin)

	ENTRY_NP(fpxsave_begin)
	mov	4(%esp), %eax		/ a struct fpu_ctx *
	mov	FPU_CTX_FPU_FLAGS(%eax), %edx
	cmpl	$FPU_EN, %edx
	jne	1f
#if FPU_CTX_FPU_REGS != 0
	addl	FPU_CTX_FPU_REGS, %eax
#endif
	fxsave	(%eax)
	fnclex				/ Clear pending x87 exceptions
1:	ret
	SET_SIZE(fpxsave_begin)

#endif	/* __i386 */
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

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(fpxsave)
	clts				/* clear TS bit in CR0 */
	fxsave	(%rdi)
	fnclex				/* clear pending x87 exceptions */
	fwait				/* wait for completion */
	fninit				/* emulate fnsave: init x87 tags */
	movq	%cr0, %rax
	orq	$CR0_TS, %rax
	movq	%rax, %cr0		/* set TS bit in CR0 (disable FPU) */
	ret
	SET_SIZE(fpxsave)

#elif defined(__i386)

	ENTRY_NP(fpsave)
	clts				/ clear TS bit in CR0
	movl	4(%esp), %eax		/ load save address
	fnsave	(%eax)
	fwait				/ wait for completion
	movl	%cr0, %eax
	orl	$CR0_TS, %eax
	movl	%eax, %cr0		/ set TS bit in CR0 (disable FPU)
	ret
	SET_SIZE(fpsave)

	ENTRY_NP(fpxsave)
	clts				/ clear TS bit in CR0
	movl	4(%esp), %eax		/ save address
	fxsave	(%eax)
	fnclex				/ Clear pending x87 exceptions
	fwait				/ wait for completion
	fninit				/ emulate fnsave: init x87 tag words
	mov	%cr0, %eax
	orl	$CR0_TS, %eax
	movl	%eax, %cr0		/ set TS bit in CR0 (disable FPU)
	ret
	SET_SIZE(fpxsave)

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

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(fpxrestore)
	clts				/* clear TS bit in CR0 */
	fxrstor	(%rdi)
	ret
	SET_SIZE(fpxrestore)

#elif defined(__i386)

	ENTRY_NP(fprestore)
	clts				/ clear TS bit in CR0
	movl	4(%esp), %eax		/ load restore address
	frstor	(%eax)
	ret
	SET_SIZE(fprestore)

	ENTRY_NP(fpxrestore)
	clts				/ clear TS bit in CR0
	movl	4(%esp), %eax		/ load restore address
	fxrstor	(%eax)
	ret
	SET_SIZE(fpxrestore)

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
	movq	%cr0, %rax
	orq	$CR0_TS, %rax
	movq	%rax, %cr0		/* set TS bit in CR0 (disable FPU) */
	ret
	SET_SIZE(fpdisable)

#elif defined(__i386)

	ENTRY_NP(fpdisable)
	movl	%cr0, %eax
	orl	$CR0_TS, %eax
	movl	%eax, %cr0		/ set TS bit in CR0 (disable FPU)
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
	clts				/* clear TS bit in CR0 */
	leaq	sse_initial(%rip), %rax
	fxrstor	(%rax)			/* load clean initial state */
	ret
	SET_SIZE(fpinit)

#elif defined(__i386)

	ENTRY_NP(fpinit)
	clts				/ clear TS bit in CR0
	cmpl	$__FP_SSE, fp_kind
	je	1f

	fninit				/ initialize the chip
	movl	$x87_initial, %eax
	frstor	(%eax)			/ load clean initial state
	ret
1:
	movl	$sse_initial, %eax
	fxrstor	(%eax)			/ load clean initial state
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
{
	return (0);
}

uint32_t
fpxerr_reset(void)
{
	return (0);
}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(fperr_reset)
	xorl	%eax, %eax
	clts				/* clear TS bit in CR0 */
	fnstsw	%ax			/* get status */
	fnclex				/* clear processor exceptions */
	ret
	SET_SIZE(fperr_reset)

	ENTRY_NP(fpxerr_reset)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$0x10, %rsp		/* make some temporary space */
	clts				/* clear TS bit in CR0 */
	stmxcsr	(%rsp)			/* get status */
	movl	(%rsp), %eax
	andl	$_BITNOT(SSE_MXCSR_EFLAGS), (%rsp)
	ldmxcsr	(%rsp)			/* clear processor exceptions */
	leave
	ret
	SET_SIZE(fpxerr_reset)

#elif defined(__i386)

	ENTRY_NP(fperr_reset)
	xorl	%eax, %eax
	clts				/ clear TS bit in CR0
	fnstsw	%ax			/ get status
	fnclex				/ clear processor exceptions
	ret
	SET_SIZE(fperr_reset)

	ENTRY_NP(fpxerr_reset)
	clts				/ clear TS bit in CR0
	subl	$4, %esp		/ make some temporary space
	stmxcsr	(%esp)			/ get status
	movl	(%esp), %eax
	andl	$_BITNOT(SSE_MXCSR_EFLAGS), (%esp)
	ldmxcsr	(%esp)			/ clear processor exceptions
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
	clts				/* clear TS bit in CR0		*/
	fnstsw	(%rsp)			/* store the status word	*/
	fnstcw	2(%rsp)			/* store the control word	*/
	movl	(%rsp), %eax		/* put both in %eax		*/
	leave
	ret
	SET_SIZE(fpgetcwsw)

#elif defined(__i386)

	ENTRY_NP(fpgetcwsw)
	clts				/* clear TS bit in CR0		*/
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
	subq	$0x10, %rsp		/* make some temporary space	*/
	clts				/* clear TS bit in CR0		*/
	stmxcsr	(%rsp)			/* get status			*/
	movl	(%rsp), %eax
	leave
	ret
	SET_SIZE(fpgetmxcsr)

#elif defined(__i386)

	ENTRY_NP(fpgetmxcsr)
	clts				/* clear TS bit in CR0		*/
	subl	$4, %esp		/* make some temporary space	*/
	stmxcsr	(%esp)			/* get status			*/
	movl	(%esp), %eax
	addl	$4, %esp
	ret
	SET_SIZE(fpgetmxcsr)

#endif	/* __i386 */
#endif  /* __lint */
