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

	.file	"memcmp.s"

/
/ memcmp(s1, s2, n)
/
/ Compares n bytes:  s1>s2: >0  s1==s2:  0  s1<s2:  <0
/
/ Fast assembly language version of the following C-program strcat
/ which represents the `standard' for the C-library.
/
/	int
/	memcmp(const void *s1, const void *s2, size_t n)
/	{
/		if (s1 != s2 && n != 0) {
/			const unsigned char	*ps1 = s1;
/			const unsigned char	*ps2 = s2;
/
/			do {
/				if (*ps1++ != *ps2++)
/					return (ps1[-1] - ps2[-1]);
/			} while (--n != 0);
/		}
/		return (NULL);
/	}
/
/ This implementation conforms to SVID but does not implement
/ the same algorithm as the portable version because it is
/ inconvenient to get the difference of the differing characters.

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(memcmp,function)

#include "SYS.h"

	ENTRY(memcmp)
	pushl	%edi		/ save register variable
	movl	8(%esp), %eax	/ %eax = address of string 1
	movl	12(%esp), %ecx	/ %ecx = address of string 2
	cmpl	%eax, %ecx	/ if the same string
	je	.equal		/ goto .equal
	movl	16(%esp), %edi	/ %edi = length in bytes
	cmpl	$4, %edi	/ if %edi < 4
	jb	.byte_check	/ goto .byte_check
	.align	4
.word_loop:
	movl	(%ecx), %edx	/ move 1 word from (%ecx) to %edx
	leal	-4(%edi), %edi	/ %edi -= 4
	cmpl	(%eax), %edx	/ compare 1 word from (%eax) with %edx
	jne	.word_not_equal	/ if not equal, goto .word_not_equal
	leal	4(%ecx), %ecx	/ %ecx += 4 (next word)
	leal	4(%eax), %eax	/ %eax += 4 (next word)
	cmpl	$4, %edi	/ if %edi >= 4
	jae	.word_loop	/ goto .word_loop
.byte_check:
	cmpl	$0, %edi	/ if %edi == 0
	je	.equal		/ goto .equal
	jmp	.byte_loop	/ goto .byte_loop (checks in bytes)
.word_not_equal:
	leal	4(%edi), %edi	/ %edi += 4 (post-decremented)
	.align	4
.byte_loop:
	movb	(%ecx),	%dl	/ move 1 byte from (%ecx) to %dl
	cmpb	%dl, (%eax)	/ compare %dl with 1 byte from (%eax)
	jne	.not_equal	/ if not equal, goto .not_equal
	incl	%ecx		/ %ecx++ (next byte)
	incl	%eax		/ %eax++ (next byte)
	decl	%edi		/ %edi--
	jnz	.byte_loop	/ if not zero, goto .byte_loop
.equal:
	xorl	%eax, %eax	/ %eax = 0
	popl	%edi		/ restore register variable
	ret			/ return (NULL)
	.align	4
.not_equal:
	sbbl	%eax, %eax	/ %eax = 0 if no carry, %eax = -1 if carry
	orl	$1, %eax	/ %eax = 1 if no carry, %eax = -1 if carry
	popl	%edi		/ restore register variable
	ret			/ return (NULL)
	SET_SIZE(memcmp)
