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

/*
 * This crt1.o module is provided as the bare minimum required to build a
 * 64-bit progile executable with gcc -pg.  It is installed in /usr/lib/amd64
 * where it will be picked up by gcc, along with crti.o and crtn.o
 */

	.ident	"%Z%%M%	%I%	%E% SMI"

	.file	"gcrt1.s"

	.globl	_start
	.globl	_etext

/* global entities defined elsewhere but used here */
	.globl	main
	.globl	__fpstart
	.globl	_init
	.globl	_fini
	.globl	exit
	.globl	_exit
	.globl	monstartup
	.weak	_mcleanup
	.weak	_DYNAMIC

	.section	.data

	.weak	environ
	.set	environ,_environ
	.globl	_environ
	.type	_environ,@object
	.size	_environ,8
	.align	8
_environ:
	.8byte	0x0

	.globl	___Argv
	.type	___Argv,@object
	.size	___Argv,8
	.align	8
___Argv:
	.8byte	0x0

	.section	.text
	.align	8

/*
 *   The SVR4/i386 ABI (pages 3-29) says that when the entry
 *   point runs registers' %rbp, %rsp, %rdx values are specified
 *   the following:
 *
 *	%rbp The content of this register is unspecified at
 *		process initialization time, but the user code should mark
 *		the deepest stack frame by setting the frame pointer to zero.
 *		No other frame's %ebp should have a zero value.
 *
 *	%rsp Performing its usual job, the stack pointer holds the address
 *	of the bottom of the stack, which is guaranteed to be
 *	quadword aligned.
 *
 *		The stack contains the arguments and environment:
 *        ...
 *        envp[0]		(16+(8*argc))(%rsp)
 *        NULL			(8+(8*argc))(%rsp)
 *        ...
 *        argv[0]		8(%rsp)
 *        argc			0(%rsp)
 *
 *	%rdx In a conforming program, this register contains a function
 *		pointer that the application should register with atexit(BA_OS).
 *		This function is used for shared object termination code
 *		[see Dynamic Linking in Chapter 5 of the System V ABI].
 *
 */

	.type	_start,@function
_start:
/*
 * Allocate a NULL return address and a NULL previous %rbp as if
 * there was a genuine call to _start.
 */
	pushq	$0
	pushq	$0
	movq	%rsp,%rbp		/* The first stack frame */

/*
 * The stack now is
 *
 *        envp[0]		(32+(8*argc))(%rsp)      - (A)
 *        NULL			(24+(8*argc))(%rsp)
 *        ...
 *        argv[0]		24(%rbp)		 - (B)
 *        argc			16(%rbp)
 *	  0			8(%rbp)
 *	  0			0(%rbp)
 */

/*
 * Check to see if there is an _mcleanup() function linked in, and if so,
 * register it with atexit() as the last thing to be run by exit().
 */
	movq	%rdx,%r12		/* save rt_do_exit for later atexit */

	movq	$_mcleanup,%rdi
	testq	%rdi,%rdi
	jz	1f
	call	atexit
1:

	movq	$_DYNAMIC,%rax
	testq	%rax,%rax
	jz	1f
	movq	%r12,%rdi		/* register rt_do_exit */
	call	atexit
1:

	movq	$_fini,%rdi
	call	atexit

/* start profiling */
	pushq	%rbp
	movq	%rsp,%rbp
	movq	$_start,%rdi
	movq	$_etext,%rsi
	call	monstartup
	popq	%rbp

/*
 * Calculate the location of the envp array by adding the size of
 * the argv array to the start of the argv array.
 */
	movq	16(%rbp),%rax		/* argc */
	movq	_environ, %rcx
	testq	%rcx, %rcx		/* check if _environ==0 */
	jne	1f
	leaq	32(%rbp,%rax,8),%rcx	/* (A) */
	movq	%rcx,_environ		/* copy to _environ */
1:

/*
 * Force stack alignment - below here there must have been an even
 * number of un-popped pushq instructions whenever a call is reached
 */
	andq	$-16,%rsp
	pushq	%rdx
	leaq	24(%rbp),%rdx		/* argv (B) */
	movq	%rdx,___Argv
	pushq	%rcx
	pushq	%rdx
	pushq	%rax
	call	__fpstart
	call	_init
	popq	%rdi
	popq	%rsi
	popq	%rdx
	popq	%rcx
	call	main			/* main(argc,argv,envp) */
	pushq	%rax
	pushq	%rax
	movq	%rax,%rdi		/* and call exit */
	call	exit
	popq	%rdi
	popq	%rdi
	call	_exit		/* if user redefined exit, call _exit */
	hlt
	.size	_start, .-_start
