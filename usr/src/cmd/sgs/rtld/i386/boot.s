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
 *	#			# <- %esp
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
 *	#_______________________# <- %ebp
 *
 *
 * We must calculate the address at which ld.so was loaded,
 * find the addr of the dynamic section of ld.so, of argv[0], and  of
 * the process' environment pointers - and pass the thing to _setup
 * to handle.  We then call _rtld - on return we jump to the entry
 * point for the a.out.
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

	/ init is called from the _init symbol in the CRT, however .init_array
	/ are called "naturally" from call_init.  Because of that, we need the
	/ stack aligned here so that initializers called via _array sections may
	/ safely use SIMD instructions.
_rt_alias:
	jmp	.get_ip			/ in case we were invoked from libc.so
_rt_boot:
	movl	%esp,%ebp		/ save for referencing args
	subl	$EB_MAX_SIZE32,%esp	/ make room for a max sized boot vector
	andl	$-16,%esp
	subl	$8,%esp
	movl	%esp,%esi		/ use esi as a pointer to &eb[0]
	movl	$EB_ARGV,0(%esi)	/ set up tag for argv
	leal	4(%ebp),%eax		/ get address of argv
	movl	%eax,4(%esi)		/ put after tag
	movl	$EB_ENVP,8(%esi)	/ set up tag for envp
	movl	(%ebp),%eax		/ get # of args
	addl	$2,%eax			/ one for the zero & one for argc
	leal	(%ebp,%eax,4),%edi	/ now points past args & @ envp
	movl	%edi,12(%esi)		/ set envp
.L0:	addl	$4,%edi			/ next
	cmpl	$0,-4(%edi)		/ search for 0 at end of env
	jne	.L0
	movl	$EB_AUXV,16(%esi)	/ set up tag for auxv
	movl	%edi,20(%esi)		/ point to auxv
	movl	$EB_NULL,24(%esi)	/ set up NULL tag
.get_ip:
	call	.L1			/ only way to get IP into a register
.L1:
	popl	%ebx			/ pop the IP we just "pushed"
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L1],%ebx
	pushl	(%ebx)			/ address of dynamic structure
	pushl	%esi			/ push &eb[0]

	call	_setup@PLT		/ _setup(&eb[0], _DYNAMIC)
	movl	%ebp,%esp		/ release stack frame

	movl	atexit_fini@GOT(%ebx), %edx
	jmp	*%eax 			/ transfer control to a.out
	.size	_rt_boot,.-_rt_boot

#endif
