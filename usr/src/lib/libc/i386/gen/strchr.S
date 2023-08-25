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

	.file	"strchr.s"

#include "SYS.h"

	ENTRY(strchr)
	mov 4(%esp), %ecx		/ src string here
	mov 8(%esp), %edx		/ character to find
	mov %ecx, %eax			/ save src
	and $3, %ecx			/ check if src is aligned
	jz prepword			/ search wordwise if it is

	cmpb %dl, (%eax)		/ src == char?
	jz done
	cmpb $0, (%eax)			/ src == 0?
	jz not_found
	add $1, %eax			/ increment src
	cmp $3, %ecx			/ check alignment
	jz prepword
	cmpb %dl, (%eax)		/ src byte contains char?
	jz done
	cmpb $0, (%eax)			/ src byte == 0?
	jz not_found
	add $1, %eax			/ increment src ptr
	cmp $2, %ecx			/ check alignment
	jz prepword
	cmpb %dl, (%eax) 		/ check this byte
	jz done
	cmpb $0, (%eax)			/ is byte zero?
	jz not_found
	add $1, %eax			/ increment src ptr

prepword:
	push %ebx			/ save regs per calling convention
	push %esi
	and $0xff, %edx			/ only want 1st byte
	mov %edx, %ebx			/ copy character across all bytes in wd
	shl $8, %edx
	or %ebx, %edx
	mov %edx, %ebx
	shl $16, %edx
	or %ebx, %edx

	.align 16			/ align loop for max performance

searchchar:
	mov (%eax), %esi		/ load src word
	add $4, %eax			/ increment src by four
	mov %esi, %ebx			/ copy word
	lea -0x01010101(%esi), %ecx	/ (word - 0x01010101)
	xor %edx, %ebx			/ tmpword = word ^ char
	not %esi			/ ~word
	and $0x80808080, %esi		/ ~word & 0x80808080
	and %ecx, %esi			/ (wd - 0x01010101) & ~wd & 0x80808080
	jnz has_zero_byte
	lea -0x01010101(%ebx), %ecx	/ repeat with tmpword
	not %ebx
	and $0x80808080, %ebx
	and %ecx, %ebx
	jz searchchar			/ repeat if char not found

found_char:
	add $0x01010101, %ecx		/ restore tmpword
	pop %esi			/ restore esi ebx as per calling cvntn
	pop %ebx
	test $0x000000ff, %ecx		/ look for character's position in word
	jz done0
	test $0x0000ff00, %ecx
	jz done1
	test $0x00ff0000, %ecx
	jz done2
done3:
	sub $1, %eax
	ret
done2:
	sub $2, %eax
	ret
done1:
	sub $3, %eax
	ret
done0:
	sub $4, %eax
	ret
has_zero_byte:
	add $0x01010101, %ecx		/ restore registers here
	pop %esi
	pop %ebx
	cmpb %dl, %cl			/ check for character
	je done0
	testb %cl, %cl			/ check for null byte
	jz not_found
	cmpb %dh, %ch			/ continue checking for char, null
	je done1
	testb %ch, %ch
	jz not_found
	shr $16, %ecx			/ put bytes 2,3 into 8-but registers
	cmpb %dl, %cl
	je done2
	testb %cl, %cl
	jz not_found
	cmpb %dh, %ch			/ repeat checking last 2 bytes
	je done3
	testb %ch, %ch
	jz not_found
	sub $1, %eax			/ correct for last loop iteration
done:
	ret
not_found:
	xor %eax, %eax
	ret
	SET_SIZE(strchr)
