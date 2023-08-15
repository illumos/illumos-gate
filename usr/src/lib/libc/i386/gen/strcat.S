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

#include "SYS.h"

	ENTRY(strcat)
	pushl	%edi			/ save register variable
	/ find a null byte in destination string
	movl	8(%esp), %edi		/ %edi = destination string address
	testl	$3, %edi		/ if %edi not word aligned
	jnz	.L1			/ goto .L1
	.align	4
.L2:
	movl	(%edi), %edx		/ move 1 word from (%edi) to %edx
	movl	$0x7f7f7f7f, %ecx
	andl	%edx, %ecx		/ %ecx = %edx & 0x7f7f7f7f
	addl	$4, %edi		/ next word
	addl	$0x7f7f7f7f, %ecx	/ %ecx += 0x7f7f7f7f
	orl	%edx, %ecx		/ %ecx |= %edx
	andl	$0x80808080, %ecx	/ %ecx &= 0x80808080
	cmpl	$0x80808080, %ecx	/ if no null byte in this word
	je	.L2			/ goto .L2
	subl	$4, %edi		/ post-incremented
.L1:
	cmpb	$0, (%edi)		/ if a byte in (%edi) is null
	je	.L3			/ goto .L3
	incl	%edi			/ next byte
	testl	$3, %edi		/ if %edi not word aligned
	jnz	.L1			/ goto .L1
	jmp	.L2			/ goto .L2 (%edi word aligned)
	.align	4
.L3:
	/ %edi points to a null byte in destination string
	movl	12(%esp), %eax		/ %eax = source string address
	testl	$3, %eax		/ if %eax not word aligned
	jnz	.L4			/ goto .L4
	.align	4
.L5:
	movl	(%eax), %edx		/ move 1 word from (%eax) to %edx
	movl	$0x7f7f7f7f, %ecx
	andl	%edx, %ecx		/ %ecx = %edx & 0x7f7f7f7f
	addl	$4, %eax		/ next word
	addl	$0x7f7f7f7f, %ecx	/ %ecx += 0x7f7f7f7f
	orl	%edx, %ecx		/ %ecx |= %edx
	andl	$0x80808080, %ecx	/ %ecx &= 0x80808080
	cmpl	$0x80808080, %ecx	/ if null byte in this word
	jne	.L7			/ goto .L7
	movl	%edx, (%edi)		/ copy this word to (%edi)
	addl	$4, %edi		/ next word
	jmp	.L5			/ goto .L5
.L7:
	subl	$4, %eax		/ post-incremented
	.align	4
.L4:
	movb	(%eax), %dl		/ %dl = a byte in (%eax)
	cmpb	$0, %dl			/ compare %dl with a null byte
	movb	%dl, (%edi)		/ copy %dl to (%edi)
	je	.L6			/ if %dl is a null, goto .L6
	incl	%eax			/ next byte
	incl	%edi			/ next byte
	testl	$3, %eax		/ if %eax not word aligned
	jnz	.L4			/ goto .L4
	jmp	.L5			/ goto .L5 (%eax word aligned)
	.align	4
.L6:
	movl	8(%esp), %eax		/ return the destination address
	popl	%edi			/ restore register variable
	ret
	SET_SIZE(strcat)
