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

	ENTRY(memchr) /* (void *s, uchar_t c, size_t n) */
	movl	%esi, %eax	/ move "c" to %eax
	cmpq	$4, %rdx	/ if number of bytes < 4
	jb	.L1		/ goto .L1
	testq	$3, %rdi	/ if %rdi not word aligned
	jnz	.L2		/ goto .L2
	.align	4
.L3:
	movl	(%rdi), %ecx	/ move 1 word from (%rdi) to %ecx
	cmpb	%cl, %al	/ if the first byte is %al
	je	.L4		/ goto .L4 (found)
	cmpb	%ch, %al	/ if the second byte is %al
	je	.L5		/ goto .L5 (found)
	shrl	$16, %ecx	/ right shift 16-bit
	cmpb	%cl, %al	/ if the third byte is %al
	je	.L6		/ goto .L6 (found)
	cmpb	%ch, %al	/ if the fourth is %al
	je	.L7		/ goto .L7 (found)
	subq	$4, %rdx	/ decrement number of bytes by 4
	addq	$4, %rdi	/ next word
	cmpq	$4, %rdx	/ if number of bytes >= 4
	jae	.L3		/ goto .L3
.L1:
	cmpq	$0, %rdx	/ if number of bytes == 0
	jz	.L8		/ goto .L8 (not found)
	cmpb	(%rdi), %al	/ if a byte in (%rdi) is %al
	je	.L4		/ goto .L4 (found)
	decq	%rdx		/ decrement number of bytes by 1
	incq	%rdi		/ next byte
	jmp	.L1		/ goto .L1
	.align	4
.L8:
	xorl	%eax, %eax	/ not found
	ret			/ return (0)
	.align	4
.L2:
	cmpq	$0, %rdx	/ if number of bytes == 0
	jz	.L8		/ goto .L8 (not found)
	cmpb	(%rdi), %al	/ if a byte in (%rdi) is %al
	je	.L4		/ goto .L4 (found)
	incq	%rdi		/ next byte
	decq	%rdx		/ decrement number of bytes by 1
	testq	$3, %rdi	/ if %rdi not word aligned
	jnz	.L2		/ goto .L2
	cmpq	$4, %rdx	/ if number of bytes >= 4
	jae	.L3		/ goto .L3 (word aligned)
	jmp	.L1		/ goto .L1
	.align	4
.L7:
	/ found at the fourth byte
	incq	%rdi
.L6:
	/ found at the third byte
	incq	%rdi
.L5:
	/ found at the second byte
	incq	%rdi
.L4:
	/ found at the first byte
	movq	%rdi,%rax
	ret
	SET_SIZE(memchr)
