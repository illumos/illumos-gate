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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"memchr.s"

/
/ memchr(sptr, c1, n)
/
/ Returns the pointer in sptr at which the character c1 appears;
/ or NULL if not found in chars; doesn't stop at \0.
/
/ Fast assembly language version of the following C-program memchr
/ which represents the `standard' for the C-library.
/
/	void *
/	memchr(const void *sptr, int c1, size_t n)
/	{
/		if (n != 0) {
/			unsigned char	c = (unsigned char)c1;
/			const unsigned char	*sp = sptr;
/
/			do {
/				if (*sp++ == c)
/					return ((void *)--sp);
/			} while (--n != 0);
/		}
/		return (NULL);
/	}
/

#include "SYS.h"

	.globl	memchr
	.align	4

	ENTRY(memchr)
	pushl	%edi		/ save register variable
	movl	8(%esp), %eax	/ %eax = string address
	movl	12(%esp), %ecx	/ %cl = byte that is sought
	movl	16(%esp), %edi	/ %edi = number of bytes
	cmpl	$4, %edi	/ if number of bytes < 4
	jb	.L1		/ goto .L1
	testl	$3, %eax	/ if %eax not word aligned
	jnz	.L2		/ goto .L2
	.align	4
.L3:
	movl	(%eax), %edx	/ move 1 word from (%eax) to %edx
	cmpb	%dl, %cl	/ if the first byte is %cl
	je	.L4		/ goto .L4 (found)
	cmpb	%dh, %cl	/ if the second byte is %cl
	je	.L5		/ goto .L5 (found)
	shrl	$16, %edx	/ right shift 16-bit
	cmpb	%dl, %cl	/ if the third byte is %cl
	je	.L6		/ goto .L6 (found)
	cmpb	%dh, %cl	/ if the fourth is %cl
	je	.L7		/ goto .L7 (found)
	subl	$4, %edi	/ decrement number of bytes by 4
	addl	$4, %eax	/ next word
	cmpl	$4, %edi	/ if number of bytes >= 4
	jae	.L3		/ goto .L3
.L1:
	cmpl	$0, %edi	/ if number of bytes == 0
	jz	.L8		/ goto .L8 (not found)
	cmpb	(%eax), %cl	/ if a byte in (%eax) is %cl
	je	.L4		/ goto .L4 (found)
	decl	%edi		/ decrement number of bytes by 1
	incl	%eax		/ next byte
	jmp	.L1		/ goto .L1
	.align	4
.L8:
	xorl	%eax, %eax	/ not found
	popl	%edi		/ restore register
	ret			/ return (0)
	.align	4
.L2:
	cmpl	$0, %edi	/ if number of bytes == 0
	jz	.L8		/ goto .L8 (not found)
	cmpb	(%eax), %cl	/ if a byte in (%eax) is %cl
	je	.L4		/ goto .L4 (found)
	incl	%eax		/ next byte
	decl	%edi		/ decrement number of bytes by 1
	testl	$3, %eax	/ if %eax not word aligned
	jnz	.L2		/ goto .L2
	cmpl	$4, %edi	/ if number of bytes >= 4
	jae	.L3		/ goto .L3 (word aligned)
	jmp	.L1		/ goto .L1
	.align	4
.L7:
	/ found at the fourth byte
	incl	%eax
.L6:
	/ found at the third byte
	incl	%eax
.L5:
	/ found at the second byte
	incl	%eax
.L4:
	/ found at the first byte
	popl	%edi		/ restore register variable
	ret
	SET_SIZE(memchr)
