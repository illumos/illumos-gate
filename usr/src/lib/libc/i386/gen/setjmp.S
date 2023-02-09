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

	.file	"setjmp.s"

/	longjmp(env, val)
/ will generate a "return(val)" from
/ the last call to
/	setjmp(env)
/ by restoring registers ip, sp, bp, bx, si, and di from 'env'
/ and doing a return.

/ entry    reg	offset from (%si)
/ env[0] = %ebx	 0	/ register variables
/ env[1] = %esi	 4
/ env[2] = %edi	 8
/ env[3] = %ebp	 12	/ stack frame
/ env[4] = %esp	 16
/ env[5] = %eip	 20
/ env[6] = jmp flags 24

#include <sys/asm_linkage.h>
#include <../assym.h>

	ANSI_PRAGMA_WEAK(setjmp,function)
	ANSI_PRAGMA_WEAK(longjmp,function)

	ENTRY(setjmp)
	movl	4(%esp),%eax	/ jmpbuf address
	movl	%ebx,0(%eax)	/ save ebx
	movl	%esi,4(%eax)	/ save esi
	movl	%edi,8(%eax)	/ save edi
	movl	%ebp,12(%eax)	/ save caller's ebp

	movl	%gs:UL_SIGLINK, %ecx
	xorl	%edx, %edx
	test	%ecx, %ecx	/ are we in a signal handler?
	jnz	1f
	inc	%edx		/ no, tell longjmp to clear ul_siglink
1:	movl	%edx, 24(%eax)	/ set flag word

	popl	%edx		/ return address
	movl	%esp,16(%eax)	/ save caller's esp
	movl	%edx,20(%eax)	/ save caller's return address
	xorl	%eax, %eax	/ return 0
	pushl	%edx
	ret
	SET_SIZE(setjmp)

	ENTRY(longjmp)
	movl	4(%esp),%edx	/ first parameter after return addr
	movl	8(%esp),%eax	/ second parameter
	movl	0(%edx),%ebx	/ restore ebx
	movl	4(%edx),%esi	/ restore esi
	movl	8(%edx),%edi	/ restore edi
	movl	12(%edx),%ebp	/ restore caller's ebp
	movl	16(%edx),%esp	/ restore caller's esp

	movl	24(%edx), %ecx
	test	%ecx, %ecx	/ test flag word
	jz	1f
	xorl	%ecx, %ecx	/ if set, clear ul_siglink
	movl	%ecx, %gs:UL_SIGLINK
1:
	test	%eax,%eax	/ if val != 0
	jnz	1f		/ 	return val
	incl	%eax		/ else return 1
1:
	jmp	*20(%edx)	/ return to caller
	SET_SIZE(longjmp)
