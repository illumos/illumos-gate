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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>

/*
 * Kernel function call invocation
 */

#if defined(__lint)
/*ARGSUSED*/
uintptr_t
kaif_invoke(uintptr_t funcva, uint_t argc, const uintptr_t argv[])
{
	return (0);
}
#else
	/*
	 * A jump table containing the addresses for register argument copy
	 * code.
	 */
copyargs:
	.quad	cp0arg
	.quad	cp1arg
	.quad	cp2arg
	.quad	cp3arg
	.quad	cp4arg
	.quad	cp5arg
	.quad	cp6arg

	/*
	 * This is going to be fun.  We were called with the function pointer
	 * in in %rsi, argc in %rdx, and a pointer to an array of uintptr_t's
	 * (the arguments to be passed) in %rcx.  In the worst case, we need
	 * to move the first six arguments from the array to %rdi, %rsi, %rdx,
	 * %rcx, %r8, and %r9.  The remaining arguments need to be copied from
	 * the array to 0(%rsp), 8(%rsp), and so on.  Then we can call the
	 * function.
	 */

	ENTRY_NP(kaif_invoke)

	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12			/* our extra stack space */
	clrq	%r12

	movq	%rdi, %rax		/* function pointer */
	movq	%rdx, %rdi		/* argv */

	cmpq	$6, %rsi
	jle	stackdone

	/*
	 * More than six arguments.  Reserve space for the seventh and beyond on
	 * the stack, and copy them in.  To make the copy easier, we're going to
	 * pretend to reserve space on the stack for all of the arguments, thus
	 * allowing us to use the same scaling for the store as we do for the
	 * load.  When we're done copying the excess arguments, we'll move %rsp
	 * back, reclaiming the extra space we reserved.
	 */
	movq	%rsi, %r12
	subq	$6, %r12
	shlq	$3, %r12
	subq	%r12, %rsp
	subq	$0x30, %rsp		/* reserve 6 arg space for scaling */

1:	decq	%rsi
	movq	(%rdx, %rsi, 8), %r9
	movq	%r9, (%rsp, %rsi, 8)
	cmpq	$6, %rsi
	jg	1b

	addq	$0x30, %rsp		/* restore scaling arg space */

stackdone:
	/*
	 * Excess arguments have been copied and stripped from argc (or there
	 * weren't any to begin with).  Copy the first five to their ABI-
	 * designated registers.  We have to do this somewhat carefully, as
	 * argc (%rdx) and argv (%rsi) are in to-be-trampled registers.
	 */
	leaq	copyargs(%rip), %r9
	shlq	$3, %rsi
	addq	%rsi, %r9
	jmp	*(%r9)

cp6arg:	movq	0x28(%rdi), %r9
cp5arg:	movq	0x20(%rdi), %r8
cp4arg:	movq	0x18(%rdi), %rcx
cp3arg:	movq	0x10(%rdi), %rdx
cp2arg:	movq	0x08(%rdi), %rsi
cp1arg: movq	0x00(%rdi), %rdi
cp0arg:

	/* Arguments are copied.  Time to call the function */
	call	*%rax

	/*
	 * Deallocate the stack-based arguments, if any, and return to the
	 * caller.
	 */

	addq	%r12, %rsp
	popq	%r12
	leave
	ret

	SET_SIZE(kaif_invoke)

#endif
