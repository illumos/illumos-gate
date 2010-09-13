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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"strcpy.s"

/
/ strcpy(s1, s2)
/
/ Copies string s2 to s1.  s1 must be large enough.
/ Returns s1
/
/
/ Fast assembly language version of the following C-program strcpy
/ which represents the `standard' for the C-library.
/
/	char *
/	strcpy(char *s1, const char *s2)
/	{
/		char	*os1 = s1;
/
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

	ENTRY(strcpy)
	push	%edi				/ save reg as per calling cvntn
	mov	12(%esp), %ecx			/ src ptr
	mov	8(%esp), %edi			/ dst ptr
	mov	%ecx, %eax			/ src
	sub	%edi, %ecx			/ src - dst
	and	$3, %eax			/ check src alignment
	jz	load
	sub	$4, %eax

byte_loop:
	movb	(%edi, %ecx, 1), %dl		/ load src byte
	movb	%dl, (%edi)			/ load dest byte
	inc	%edi				/ increment src and dest
	testb	%dl, %dl			/ is src zero?
	jz 	done
	inc	%eax				/ check src alignment
	jnz	byte_loop
	jmp 	load

store:
	mov	%eax, (%edi)			/ store word
	add	$4, %edi			/ incrment src and dest by 4
load:
	mov	(%edi, %ecx, 1), %eax		/ load word
	lea	-0x01010101(%eax), %edx		/ (word - 0x01010101)
	not	%eax				/ ~word
	and	%eax, %edx			/ (word - 0x01010101) & ~word
	not	%eax				/ word
	and	$0x80808080, %edx	/ (wd - 0x01010101) & ~wd & 0x80808080
	jz	store				/ store word w/o zero byte

has_zero_byte:
	movb	%al, (%edi)			/ store first byte
	testb	%al, %al			/ check first byte for zero
	jz	done
	movb	%ah, 1(%edi)			/ continue storing and checking
	testb	%ah, %ah
	jz	done
	shr	$16, %eax			/ grab last two bytes
	movb	%al, 2(%edi)
	testb	%al, %al
	jz	done
	movb	%ah, 3(%edi)
done:
	mov	8(%esp), %eax			/ return ptr to dest
	pop	%edi				/ restore as per calling cvntn
	ret
	SET_SIZE(strcpy)
