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

	.file	"strncat.s"

/
/ strncat(s1, s2, n)
/
/ Concatenates s2 on the end of s1.  s1's space must be large enough.
/ At most n characters are moved.
/ Returns s1.
/
/ Fast assembly language version of the following C-program strncat
/ which represents the `standard' for the C-library.
/
/	char *
/	strncat(char *s1, const char *s2, size_t n)
/	{
/		char	*os1 = s1;
/
/		n++;
/		while (*s1++)
/			;
/		--s1;
/		while (*s1++ = *s2++)
/			if (--n == 0) {
/				s1[-1] = '\0';
/				break;
/			}
/		return (os1);
/	}
/
/ In this assembly language version, the following expression is used
/ to check if a 32-bit word data contains a null byte or not:
/	(((A & 0x7f7f7f7f) + 0x7f7f7f7f) | A) & 0x80808080
/ If the above expression geneates a value other than 0x80808080,
/ that means the 32-bit word data contains a null byte.
/
/ The above has been extended for 64-bit support.
/

#include "SYS.h"

	ENTRY(strncat)		/* (char *, char *, size_t) */
	movq	%rdi, %rax		/ save return value
	movabsq	$0x7f7f7f7f7f7f7f7f, %r8	/ %r8 = 0x7f...
	movq	%r8, %r9
	notq	%r9				/ %r9 = 0x80...
	testq	$7, %rdi		/ if %rdi not quadword aligned
	jnz	.L1			/ goto .L1
	.align	4
.L2:
	movq	(%rdi), %r11		/ move 1 quadword from (%rdi) to %r11
	movq	%r8, %rcx
	andq	%r11, %rcx		/ %rcx = %r11 & 0x7f7f7f7f
	addq	$8, %rdi		/ next quadword
	addq	%r8, %rcx		/ %rcx += 0x7f7f7f7f
	orq	%r11, %rcx		/ %rcx |= %r11
	andq	%r9, %rcx		/ %rcx &= 0x80808080
	cmpq	%r9, %rcx		/ if no null byte in this quadword
	je	.L2			/ goto .L2
	subq	$8, %rdi		/ post-incremented
.L1:
	cmpb	$0, (%rdi)		/ if a byte in (%rdi) is null
	je	.L3			/ goto .L3
	incq	%rdi			/ next byte
	testq	$7, %rdi		/ if %rdi not quadword aligned
	jnz	.L1			/ goto .L1
	jmp	.L2			/ goto .L2 (%rdi quadword aligned)
	.align	4
.L3:
	/ %rdi points to a null byte in destination string

	testq	$7, %rsi		/ if %rsi not quadword aligned
	jnz	.L4			/ goto .L4
	cmpq	$8, %rdx		/ if number of bytes < 8
	jb	.L7			/ goto .L7
	.align	4
.L5:
	movq	(%rsi), %r11		/ move 1 quadword from (%rsi) to %r11
	movq	%r8, %rcx
	andq	%r11, %rcx		/ %rcx = %r11 & 0x7f7f7f7f
	addq	$8, %rsi		/ next quadword
	addq	%r8, %rcx		/ %rcx += 0x7f7f7f7f
	orq	%r11, %rcx		/ %rcx |= %r11
	andq	%r9, %rcx		/ %rcx &= 0x80808080
	cmpq	%r9, %rcx		/ if null byte in this quadword
	jne	.L6			/ goto .L6
	movq	%r11, (%rdi)		/ copy this quadword to (%rdi)
	subq	$8, %rdx		/ decrement number of bytes by 8
	addq	$8, %rdi		/ next quadword
	cmpq	$8, %rdx		/ if number of bytes >= 8
	jae	.L5			/ goto .L5
	jmp	.L7			/ goto .L7
.L6:
	subq	$8, %rsi		/ post-incremented
	.align	4
.L7:
	/ number of bytes < 8  or  a null byte found in the quadword
	cmpq	$0, %rdx		/ if number of bytes == 0
	jz	.L8			/ goto .L8 (finished)
	movb	(%rsi), %r11b		/ %r11b = a byte in (%rsi)
	decq	%rdx			/ decrement number of bytes by 1
	movb	%r11b, (%rdi)		/ copy %r11b to (%rdi)
	incq	%rsi			/ next byte
	incq	%rdi			/ next byte
	cmpb	$0, %r11b		/ compare %r11b with a null byte
	je	.L9			/ if %r11b is a null, goto .L9
	jmp	.L7			/ goto .L7
	.align	4

.L4:
	/ %rsi not aligned
	cmpq	$0, %rdx		/ if number of bytes == 0
	jz	.L8			/ goto .L8 (finished)
	movb	(%rsi), %r11b		/ %r11b = a byte in (%rsi)
	decq	%rdx			/ decrement number of bytes by 1
	movb	%r11b, (%rdi)		/ copy %r11b to (%rdi)
	incq	%rdi			/ next byte
	incq	%rsi			/ next byte
	cmpb	$0, %r11b		/ compare %r11b with a null byte
	je	.L9			/ if %r11b is a null, goto .L9
	jmp	.L4			/ goto .L4
	.align	4
.L8:
	movb	$0, (%rdi)		/ null termination
.L9:
	ret
	SET_SIZE(strncat)
