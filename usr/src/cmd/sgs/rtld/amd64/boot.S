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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Bootstrap routine for run-time linker.
 * We get control from exec which has loaded our text and
 * data into the process' address space and created the process
 * stack.
 *
 * On entry, the process stack looks like this:
 *
 *	#			# <- %rsp
 *	#_______________________#  high addresses
 *	#	strings		#
 *	#_______________________#
 *	#	0 word		#
 *	#_______________________#
 *	#	Auxiliary	#
 *	#	entries		#
 *	#	...		#
 *	#	(size varies)	#
 *	#_______________________#
 *	#	0 word		#
 *	#_______________________#
 *	#	Environment	#
 *	#	pointers	#
 *	#	...		#
 *	#	(one word each)	#
 *	#_______________________#
 *	#	0 word		#
 *	#_______________________#
 *	#	Argument	# low addresses
 *	#	pointers	#
 *	#	Argc words	#
 *	#_______________________#
 *	#	argc		#
 *	#_______________________# <- %rbp
 *
 *
 * We must calculate the address at which ld.so was loaded,
 * find the addr of the dynamic section of ld.so, of argv[0], and  of
 * the process' environment pointers - and pass the thing to _setup
 * to handle.  We then call _rtld - on return we jump to the entry
 * point for the executable.
 */

#if	defined(lint)

extern	unsigned long	_setup();
extern	void		atexit_fini();
void
main()
{
	(void) _setup();
	atexit_fini();
}

#else

#include	<link.h>

	.file	"boot.s"
	.text
	.globl	_rt_boot
	.globl	_setup
	.globl	_GLOBAL_OFFSET_TABLE_
	.type	_rt_boot,@function
	.align	4

_rt_alias:
	/ in case we were invoked from libc.so
	jmp	.get_got
_rt_boot:
	/ save for referencing args
	movq	%rsp,%rbp
	/ make room for a max sized boot vector
	subq	$EB_MAX_SIZE64,%rsp
	/ use esi as a pointer to &eb[0]
	movq	%rsp,%rsi
	/ set up tag for argv
	movq	$EB_ARGV,0(%rsi)
	/ get address of argv
	leaq	8(%rbp),%rax
	/ put after tag
	movq	%rax,8(%rsi)
	/ set up tag for envp
	movq	$EB_ENVP,16(%rsi)
	/ get # of args
	movq	(%rbp),%rax
	/ one for the zero & one for argc
	addq	$2,%rax
	/ now points past args & @ envp
	leaq	(%rbp,%rax,8),%rdi
	/ set envp
	movq	%rdi,24(%rsi)
	/ next
.L0:	addq	$8,%rdi
	/ search for 0 at end of env
	cmpq	$0,-8(%rdi)
	jne	.L0
	/ set up tag for auxv
	movq	$EB_AUXV,32(%rsi)
	/ point to auxv
	movq	%rdi,40(%rsi)
	/ set up NULL tag
	movq	$EB_NULL,48(%rsi)

	/ arg1 - address of &eb[0]
	movq	%rsi, %rdi
.get_got:
	leaq	_GLOBAL_OFFSET_TABLE_(%rip), %rbx
	/ addq	$_GLOBAL_OFFSET_TABLE_, %rbx
	movq	%rbx,%r9
	// addq	$[.L2-.L1], %rbx
	movq	%rbx,%r10

	movq	(%rbx),%rsi

	/ _setup(&eb[0], _DYNAMIC)
	call	_setup@PLT
	/ release stack frame
	movq	%rbp,%rsp

	movq	atexit_fini@GOTPCREL(%rip), %rdx
	/ transfer control to the executable
	jmp	*%rax
	.size	_rt_boot,.-_rt_boot
#endif
