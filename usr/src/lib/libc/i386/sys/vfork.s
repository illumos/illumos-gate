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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

	.file	"%M%"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(vfork,function)

#include "SYS.h"
#include <assym.h>

/ The child of vfork() will execute in the parent's address space,
/ thereby changing the stack before the parent runs again.
/ Therefore we have to be careful how we return from vfork().
/ Pity the poor debugger developer who has to deal with this kludge.
/
/ We block all blockable signals while performing the vfork() system call
/ trap.  This enables us to set curthread->ul_vfork safely, so that we
/ don't end up in a signal handler with curthread->ul_vfork set wrong.

	ENTRY(vfork)
	movl	0(%esp),%ecx		/ save %eip in %ecx
	_prologue_
	leal	_sref_(0f),%eax		/ arrange for RET to return here
	_epilogue_
	movl	%eax,0(%esp)
	ret

0:
	pushl	$MASKSET1		/ block signals
	pushl	$MASKSET0
	pushl	$SIG_SETMASK
	pushl	%ecx
	__SYSCALLINT(lwp_sigmask)
	addl	$16, %esp

	__SYSCALLINT(vfork)
	jae 	2f

	/ reconstruct stack before jumping to __cerror
	call	1f
1:	movl	%ecx,0(%esp)
	pushl	%eax		/ save the vfork() error number

	pushl	%gs:UL_SIGMASK+4	/ reinstate signals
	pushl	%gs:UL_SIGMASK
	pushl	$SIG_SETMASK
	pushl	%ecx
	__SYSCALLINT(lwp_sigmask)
	addl	$16, %esp

	popl	%eax		/ restore the vfork() error number
	jmp	__cerror

2:
	/ To determine if we are (still) a child of vfork(), the child
	/ increments curthread->ul_vfork by one and the parent decrements
	/ it by one.  If the result is zero, then we are not a child of
	/ vfork(), else we are.  We do this to deal with the case of
	/ a vfork() child calling vfork().
	/
	/ %edx is zero if we are the parent, non-zero if we are the child.
	/
	cmpl	$0,%edx
	jne	3f
	movl	%gs:UL_VFORK, %edx
	cmpl	$0, %edx	/ don't let it go negative
	je	4f
	subl	$1, %edx	/ curthread->ul_vfork--;
	jmp	4f
3:
	movl	$0,%eax		/ zero the return value in the child
	movl	%gs:UL_VFORK, %edx
	addl	$1, %edx	/ curthread->ul_vfork++;
4:
	movl	%edx, %gs:UL_VFORK
	/
	/ Clear the schedctl interface in both parent and child.
	/ (The child might have modified the parent.)
	/
	xorl	%edx, %edx
	movl	%edx, %gs:UL_SCHEDCTL
	movl	%edx, %gs:UL_SCHEDCTL_CALLED
	pushl	%eax		/ save the vfork() return value

	pushl	%gs:UL_SIGMASK+4	/ reinstate signals
	pushl	%gs:UL_SIGMASK
	pushl	$SIG_SETMASK
	pushl	%ecx
	__SYSCALLINT(lwp_sigmask)
	addl	$16, %esp

	popl	%eax		/ restore the vfork() return value
	jmp	*%ecx		/ jump back to the caller
	SET_SIZE(vfork)
