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

	.file	"strcat.s"

/
/ strcat(s1, s2)
/
/ Concatenates s2 on the end of s1.  s1's space must be large enough.
/ Returns s1.
/
/ Fast assembly language version of the following C-program strcat
/ which represents the `standard' for the C-library.
/
/	char *
/	strcat(char *s1, const char *s2)
/	{
/		char	*os1 = s1;
/
/		while (*s1++)
/			;
/		--s1;
/		while (*s1++ = *s2++)
/			;
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

	ENTRY(strcat)	/* (char *s1, char *s2) */
	/ find a null byte in destination string
	movq	%rdi,%rax		/ prepare return value
	movabsq	$0x7f7f7f7f7f7f7f7f, %r8	/ %r8 = 0x7f...
	movq	%r8, %r9
	notq	%r9				/ %r9 = 0x80...
	testq	$7, %rdi		/ if %rdi not quadword aligned
	jnz	.L1			/ goto .L1
	.align	4
.L2:
	movq	(%rdi), %rdx		/ move 1 quadword from (%rdi) to %rdx
	movq	%r8, %rcx
	andq	%rdx, %rcx		/ %rcx = %rdx & 0x7f7f7f7f7f7f7f7f
	addq	$8, %rdi		/ next quadword
	addq	%r8, %rcx		/ %rcx += 0x7f7f7f7f7f7f7f7f
	orq	%rdx, %rcx		/ %rcx |= %rdx
	andq	%r9, %rcx		/ %rcx &= 0x8080808080808080
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
	.align	4
.L5:
	movq	(%rsi), %rdx		/ move 1 quadword from (%rsi) to %rdx
	movq	%r8, %rcx
	andq	%rdx, %rcx		/ %rcx = %rdx & 0x7f7f7f7f7f7f7f7f
	addq	$8, %rsi		/ next quadword
	addq	%r8, %rcx		/ %rcx += 0x7f7f7f7f7f7f7f7f
	orq	%rdx, %rcx		/ %rcx |= %rdx
	andq	%r9, %rcx		/ %rcx &= 0x8080808080808080
	cmpq	%r9, %rcx		/ if null byte in this quadaword
	jne	.L7			/ goto .L7
	movq	%rdx, (%rdi)		/ copy this quadword to (%rdi)
	addq	$8, %rdi		/ next quadword
	jmp	.L5			/ goto .L5
.L7:
	subq	$8, %rsi		/ post-incremented
	.align	4
.L4:
	movb	(%rsi), %dl		/ %dl = a byte in (%rsi)
	cmpb	$0, %dl			/ compare %dl with a null byte
	movb	%dl, (%rdi)		/ copy %dl to (%rdi)
	je	.L6			/ if %dl is a null, goto .L6
	incq	%rsi			/ next byte
	incq	%rdi			/ next byte
	testq	$7, %rsi		/ if %rsi not word aligned
	jnz	.L4			/ goto .L4
	jmp	.L5			/ goto .L5 (%rsi word aligned)
	.align	4
.L6:
	ret
	SET_SIZE(strcat)
