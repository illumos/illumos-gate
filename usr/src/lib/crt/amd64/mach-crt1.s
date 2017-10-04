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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>

	.file	"mach-crt1.s"

	.global	_start_crt

/*
 *   The SVR4/amd64 ABI (pages 3-29) says that when the entry
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
 *	  ...
 *	  envp[0]		(16+(8*argc))(%rsp)
 *	  NULL			(8+(8*argc))(%rsp)
 *	  ...
 *	  argv[0]		8(%rsp)
 *	  argc			0(%rsp)
 *
 *	%rdx In a conforming program, this register contains a function
 *		pointer that the application should register with atexit(BA_OS).
 *		This function is used for shared object termination code
 *		[see Dynamic Linking in Chapter 5 of the System V ABI].
 *
 */

ENTRY_NP(_start)
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
 *	  envp[0]		(32+(8*argc))(%rsp)	 - (A)
 *	  NULL			(24+(8*argc))(%rsp)
 *	  ...
 *	  argv[0]		24(%rbp)		 - (B)
 *	  argc			16(%rbp)
 *	  0			8(%rbp)
 *	  0			0(%rbp)
 */

	andq	$-16,%rsp		/* align the stack */
	movq	16(%rbp),%rdi		/* argc */
	leaq	24(%rbp),%rsi		/* argv */
	/* NB: rt_do_exit, if applicable, is already in %rdx */
	call	_start_crt
	hlt
SET_SIZE(_start)

/*
 * The following is here in case any object module compiled with cc -p
 *	was linked into this module.
 */
ENTRY_NP(_mcount)
	.weak	_mcount
	ret
SET_SIZE(_mcount)
