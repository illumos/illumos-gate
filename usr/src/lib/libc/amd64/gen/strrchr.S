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

	.file	"strrchr.s"

/
/ strrchr(sp, c)
/
/ Returns the pointer in sp at which the character c last
/ appears; NULL if no found
/
/ Fast assembly language version of the following C-program strrchr
/ which represents the `standard' for the C-library.
/
/	char *
/	strrchr(const char *sp, int c)
/	{
/		char	*r = NULL;
/
/		do {
/			if (*sp == (char)c)
/				r = (char *)sp;
/		} while (*sp++);
/
/		return (r);
/	}
/

#include "SYS.h"

	ENTRY(strrchr)		/* (char *s, int c) */
	movl	$0, %eax	/ %rax = NULL (current occurrence)
	movl	%esi, %ecx	/ %cl == char to search for
	testq	$3, %rdi	/ if %rdi not word aligned
	jnz	.L1		/ goto .L1
	.align	4
.L3:
	movl	(%rdi), %edx	/ move 1 word from (%rdi) to %edx
	cmpb	%cl, %dl	/ if the fist byte is not %cl
	jne	.L4		/ goto .L4
	movq	%rdi, %rax	/ save this address to %rax
.L4:
	cmpb	$0, %dl		/ if a null termination
	je	.L8		/ goto .L8

	cmpb	%cl, %dh	/ if the second byte is not %cl
	jne	.L5		/ goto .L5
	leaq	1(%rdi), %rax	/ save this address to %rax
.L5:
	cmpb	$0, %dh		/ if a null termination
	je	.L8		/ goto .L8

	shrl	$16, %edx	/ right shift 16-bit
	cmpb	%cl, %dl	/ if the third byte is not %cl
	jne	.L6		/ goto .L6
	leaq	2(%rdi), %rax	/ save this address to %rax
.L6:
	cmpb	$0, %dl		/ if a null termination
	je	.L8		/ goto .L8

	cmpb	%cl, %dh	/ if the fourth byte is not %cl
	jne	.L7		/ goto .L7
	leaq	3(%rdi), %rax	/ save this address to %rax
.L7:
	cmpb	$0, %dh		/ if a null termination
	je	.L8		/ goto .L8

	addq	$4, %rdi	/ next word
	jmp	.L3		/ goto .L3
	.align	4
.L1:
	movb	(%rdi), %dl	/ move 1 byte from (%rdi) to %dl
	cmpb	%cl, %dl	/ if %dl is not %cl
	jne	.L2		/ goto .L2
	movq	%rdi, %rax	/ save this address to %rax
.L2:
	cmpb	$0, %dl		/ if a null termination
	je	.L8		/ goto .L8

	incq	%rdi		/ next byte
	testq	$3, %rdi	/ if %rdi not word aligned
	jnz	.L1		/ goto .L1
	jmp	.L3		/ goto .L3 (word aligned)
	.align	4
.L8:
	ret			/ %rax points to the last occurrence or NULL
	SET_SIZE(strrchr)
