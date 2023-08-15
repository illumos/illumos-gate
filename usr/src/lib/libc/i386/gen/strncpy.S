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

	.file	"strncpy.s"

/
/ strncpy(s1, s2, n)
/
/ Copies s2 to s1, truncating or null-padding to always copy n bytes
/ Returns s1
/
/ Fast assembly language version of the following C-program strncpy
/ which represents the `standard' for the C-library.
/
/	char *
/	strncpy(char *s1, const char *s2, size_t n)
/	{
/		char	*os1 = s1;
/
/		n++;
/		while ((--n != 0) && ((*s1++ = *s2++) != '\0'))
/			;
/		if (n != 0)
/			while (--n != 0)
/				*s1++ = '\0';
/		return (os1);
/	}
/
/ In this assembly language version, the following expression is used
/ to check if a 32-bit word data contains a null byte or not:
/	(((A & 0x7f7f7f7f) + 0x7f7f7f7f) | A) & 0x80808080
/ If the above expression geneates a value other than 0x80808080,
/ that means the 32-bit word data contains a null byte.
/

/ Assume relatively long strings and small numbers of nulls at end.

#include "SYS.h"

	ENTRY(strncpy)
	pushl	%edi			/ save register variables
	pushl	%esi

	movl	16(%esp), %eax		/ %eax = source string address
	movl	12(%esp), %edi		/ %edi = destination string address
	movl	20(%esp), %esi		/ %esi = number of bytes

	testl	$3, %eax		/ if %eax not word aligned
	jnz	.L1			/ goto .L1
.L8:
	cmpl	$4, %esi		/ if number of bytes < 4
	jb	.L4			/ goto .L4
	.align	4
.L2:
	movl	(%eax), %edx		/ move 1 word from (%eax) to %edx
	movl	$0x7f7f7f7f, %ecx
	andl	%edx, %ecx		/ %ecx = %edx & 0x7f7f7f7f
	addl	$4, %eax		/ next word
	addl	$0x7f7f7f7f, %ecx	/ %ecx += 0x7f7f7f7f
	orl	%edx, %ecx		/ %ecx |= %edx
	andl	$0x80808080, %ecx	/ %ecx &= 0x80808080
	cmpl	$0x80808080, %ecx	/ if null byte in this word
	jne	.L3			/ goto .L3
	movl	%edx, (%edi)		/ copy this word to (%edi)
	subl	$4, %esi		/ decrement number of bytes by 4
	addl	$4, %edi		/ next word
	cmpl	$4, %esi		/ if number of bytes >= 4
	jae	.L2			/ goto .L2
	jmp	.L4			/ goto .L4
.L3:
	subl	$4, %eax		/ post-incremented
	.align	4
.L4:
	/ (number of bytes < 4) or (a null byte found in the word)
	cmpl	$0, %esi		/ if number of bytes == 0
	je	.L7			/ goto .L7 (finished)
	movb	(%eax), %dl		/ %dl = a byte in (%eax)
	decl	%esi			/ decrement number of bytes by 1
	movb	%dl, (%edi)		/ copy %dl to (%edi)
	incl	%eax			/ next byte
	incl	%edi			/ next byte
	cmpb	$0, %dl			/ compare %dl with a null byte
	je	.L5			/ if %dl is a null, goto .L5
	jmp	.L4			/ goto .L4
	.align	4
.L1:
	/ %eax not aligned
	cmpl	$0, %esi		/ if number of bytes == 0
	je	.L7			/ goto .L7 (finished)
	movb	(%eax), %dl		/ %dl = a byte in (%eax)
	decl	%esi			/ decrement number of bytes by 1
	movb	%dl, (%edi)		/ copy %dl to (%edi)
	incl	%edi			/ next byte
	incl	%eax			/ next byte
	cmpb	$0, %dl			/ compare %dl with a null byte
	je	.L5			/ if %dl is a null, goto .L5
	testl	$3, %eax		/ if %eax word aligned
	jz	.L8			/ goto .L8
	jmp	.L1			/ goto .L1 (not word aligned)
	.align	4
.L5:
	movl	%esi, %ecx		/ %ecx = length to copy null bytes
	xorl	%eax, %eax		/ clear %eax
	shrl	$2, %ecx		/ %ecx = words to copy null bytes
	rep ; sstol			/ rep;sstol is optimal
	andl	$3, %esi		/ %esi = leftover bytes
.L6:
	cmpl	$0, %esi		/ if number of bytes == 0
	jz	.L7			/ goto .L7 (finished)
	movb	$0, (%edi)		/ move a null byte to (%edi)
	decl	%esi			/ decrement number of bytes by 1
	incl	%edi			/ next byte
	jmp	.L6			/ goto .L6
	.align	4
.L7:
	movl	12(%esp), %eax		/ return the destination address
	popl	%esi			/ restore register variables
	popl	%edi
	ret
	SET_SIZE(strncpy)
