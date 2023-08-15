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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"_rtboot.s"

/ bootstrap routine for run-time linker
/ we get control from exec which has loaded our text and
/ data into the process' address space and created the process
/ stack
/
/ on entry, the process stack looks like this:
/
/			# <- %esp
/_______________________#  high addresses
/	strings		#
/_______________________#
/	0 word		#
/_______________________#
/	Auxiliary	#
/	entries		#
/	...		#
/	(size varies)	#
/_______________________#
/	0 word		#
/_______________________#
/	Environment	#
/	pointers	#
/	...		#
/	(one word each)	#
/_______________________#
/	0 word		#
/_______________________#
/	Argument	# low addresses
/	pointers	#
/	Argc words	#
/_______________________#
/	argc		#
/_______________________# <- %ebp

#include <SYS.h>

	.set	EB_NULL,0
	.set	EB_DYNAMIC,1
	.set	EB_LDSO_BASE,2
	.set	EB_ARGV,3
	.set	EB_ENVP,4
	.set	EB_AUXV,5
	.set	EB_DEVZERO,6
	.set	EB_PAGESIZE,7
	.set	EB_MAX,8
	.set	EB_MAX_SIZE32,64

	.text
	.globl	__rtboot
	.globl	__rtld
	.type	__rtboot,@function
	.align	4
__rtboot:
	movl	%esp,%ebp
	subl	$EB_MAX_SIZE32,%esp	/ make room for a max sized boot vector
	movl	%esp,%esi		/ use esi as a pointer to &eb[0]
	movl	$EB_ARGV,0(%esi)	/ set up tag for argv
	leal	4(%ebp),%eax		/ get address of argv
	movl	%eax,4(%esi)		/ put after tag
	movl	$EB_ENVP,8(%esi)	/ set up tag for envp
	movl	(%ebp),%eax		/ get # of args
	addl	$2,%eax			/ one for the zero & one for argc
	leal	(%ebp,%eax,4),%edi	/ now points past args & @ envp
	movl	%edi,12(%esi)		/ set envp
	addl	$-4,%edi		/ start loop at &env[-1]
.L00:	addl	$4,%edi			/ next
	cmpl	$0,(%edi)		/ search for 0 at end of env
	jne	.L00
	addl	$4,%edi			/ advance past 0
	movl	$EB_AUXV,16(%esi)	/ set up tag for auxv
	movl	%edi,20(%esi)		/ point to auxv
	movl	$EB_NULL,24(%esi)	/ set up NULL tag
	call	.L01		/ only way to get IP into a register
.L01:	popl	%ebx		/ pop the IP we just "pushed"
	leal	s.EMPTY - .L01(%ebx),%eax
	pushl	%eax
	leal	s.ZERO - .L01(%ebx),%eax
	pushl	%eax
	leal	s.LDSO - .L01(%ebx),%eax
	pushl	%eax
	movl	%esp,%edi	/ save pointer to strings
	leal	f.MUNMAP - .L01(%ebx),%eax
	pushl	%eax
	leal	f.CLOSE - .L01(%ebx),%eax
	pushl	%eax
	leal	f.SYSCONFIG - .L01(%ebx),%eax
	pushl	%eax
	leal	f.FSTATAT - .L01(%ebx),%eax
	pushl	%eax
	leal	f.MMAP - .L01(%ebx),%eax
	pushl	%eax
	leal	f.OPENAT - .L01(%ebx),%eax
	pushl	%eax
	leal	f.PANIC - .L01(%ebx),%eax
	pushl	%eax
	movl	%esp,%ecx	/ save pointer to functions

	pushl	%ecx		/ address of functions
	pushl	%edi		/ address of strings
	pushl	%esi		/ &eb[0]
	call	__rtld		/ __rtld(&eb[0], strings, funcs)
	movl	%esi,%esp	/ restore the stack (but leaving boot vector)
	jmp	*%eax 		/ transfer control to ld.so.1
	.size	__rtboot,.-__rtboot

	.align	4
s.LDSO:		.string	"/usr/lib/ld.so.1"
s.ZERO:		.string	"/dev/zero"
s.EMPTY:	.string	"(null)"
s.ERROR:	.string	": no (or bad) /usr/lib/ld.so.1\n"
l.ERROR:

	.align	4
f.PANIC:
	movl	%esp,%ebp
/ Add using of argument string
	pushl	$l.ERROR - s.ERROR
	call	.L02
.L02:	popl	%ebx
	leal	s.ERROR - .L02(%ebx),%eax
	pushl	%eax
	pushl	$2
	call	f.WRITE
	jmp	f.EXIT
/ Not reached

f.OPENAT:
	movl	$SYS_openat,%eax
	jmp	__syscall
f.MMAP:
	movl	$SYS_mmap,%eax
	jmp	__syscall
f.MUNMAP:
	movl	$SYS_munmap,%eax
	jmp	__syscall
f.READ:
	movl	$SYS_read,%eax
	jmp	__syscall
f.WRITE:
	movl	$SYS_write,%eax
	jmp	__syscall
f.LSEEK:
	movl	$SYS_lseek,%eax
	jmp	__syscall
f.CLOSE:
	movl	$SYS_close,%eax
	jmp	__syscall
f.FSTATAT:
	movl	$SYS_fstatat,%eax
	jmp	__syscall
f.SYSCONFIG:
	movl	$SYS_sysconfig,%eax
	jmp	__syscall
f.EXIT:
	movl	$SYS_exit,%eax
/	jmp	__syscall
__syscall:
	int	$T_SYSCALLINT
	jc	__err_exit
	ret
__err_exit:
	movl	$-1,%eax
	ret
