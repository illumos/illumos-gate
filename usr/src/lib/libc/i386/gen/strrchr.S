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

	ENTRY(strrchr)
	pushl	%edi		/ save register variable
	movl	8(%esp), %eax	/ %eax = string address
	movb	12(%esp), %cl	/ %cl = char sought
	movl	$0, %edi	/ %edi = NULL (current occurrence)

	testl	$3, %eax	/ if %eax not word aligned
	jnz	.L1		/ goto .L1
	.align	4
.L3:
	movl	(%eax), %edx	/ move 1 word from (%eax) to %edx
	cmpb	%cl, %dl	/ if the fist byte is not %cl
	jne	.L4		/ goto .L4
	movl	%eax, %edi	/ save this address to %edi
.L4:
	cmpb	$0, %dl		/ if a null termination
	je	.L8		/ goto .L8

	cmpb	%cl, %dh	/ if the second byte is not %cl
	jne	.L5		/ goto .L5
	leal	1(%eax), %edi	/ save this address to %edi
.L5:
	cmpb	$0, %dh		/ if a null termination
	je	.L8		/ goto .L8

	shrl	$16, %edx	/ right shift 16-bit
	cmpb	%cl, %dl	/ if the third byte is not %cl
	jne	.L6		/ goto .L6
	leal	2(%eax), %edi	/ save this address to %edi
.L6:
	cmpb	$0, %dl		/ if a null termination
	je	.L8		/ goto .L8

	cmpb	%cl, %dh	/ if the fourth byte is not %cl
	jne	.L7		/ goto .L7
	leal	3(%eax), %edi	/ save this address to %edi
.L7:
	cmpb	$0, %dh		/ if a null termination
	je	.L8		/ goto .L8

	addl	$4, %eax	/ next word
	jmp	.L3		/ goto .L3
	.align	4
.L1:
	movb	(%eax), %dl	/ move 1 byte from (%eax) to %dl
	cmpb	%cl, %dl	/ if %dl is not %cl
	jne	.L2		/ goto .L2
	movl	%eax, %edi	/ save this address to %edi
.L2:
	cmpb	$0, %dl		/ if a null termination
	je	.L8		/ goto .L8

	incl	%eax		/ next byte
	testl	$3, %eax	/ if %eax not word aligned
	jnz	.L1		/ goto .L1
	jmp	.L3		/ goto .L3 (word aligned)
	.align	4
.L8:
	movl	%edi, %eax	/ %edi points to the last occurrence or NULL
	popl	%edi		/ restore register variable
	ret
	SET_SIZE(strrchr)
