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

	.file	"strlen.s"

/
/ strlen(s)
/
/ Returns the number of non-NULL bytes in string argument.
/
/
/ Fast assembly language version of the following C-program strlen
/ which represents the `standard' for the C-library.
/
/	size_t
/	strlen(const char *s)
/	{
/		const char	*s0 = s + 1;
/
/		while (*s++ != '\0')
/			;
/		return (s - s0);
/	}
/
/ In this assembly language version, the following expression is used
/ to check if a 32-bit word data contains a null byte or not:
/	(((A & 0x7f7f7f7f) + 0x7f7f7f7f) | A) & 0x80808080
/ If the above expression geneates a value other than 0x80808080,
/ that means the 32-bit word data contains a null byte.
/

#include "SYS.h"

	ENTRY(strlen)
	mov	4(%esp), %edx		/ src in %edx
	mov	%edx, %eax		/ cpy src to %eax

	and	$3, %edx		/ is src aligned?
	jz	countbytes
					/ work byte-wise until aligned
	cmpb	$0, (%eax)		/ is *src == 0 ?
	jz	done
	inc	%eax			/ increment src
	cmp	$3, %edx		/ if aligned, jump to word-wise check
	jz	countbytes
	cmpb	$0, (%eax)
	jz	done
	inc	%eax
	cmp	$2, %edx
	jz	countbytes
	cmpb	$0, (%eax)
	jz	done
	inc	%eax

	.align    16

countbytes:
	mov	(%eax), %ecx		/ load wrd
	add	$4, %eax		/ increment src by 4 (bytes in word)
	lea	-0x01010101(%ecx), %edx	/ (wrd - 0x01010101)
	not	%ecx			/ ~wrd
	and	$0x80808080, %ecx	/ ~wrd & 0x80808080
	and	%edx, %ecx		/ (wrd - 0x01010101) & ~wrd & 0x80808080
	jz	countbytes		/ if zero, no null byte found -- cont

has_zero_byte:
	bsfl	%ecx, %ecx		/ find first set bit (null byte)
	shr	$3, %ecx		/ switch bit position to byte posn
	lea	-4(%eax, %ecx, 1), %eax	/ undo pre-increment and count bytes
done:
	sub	4(%esp), %eax		/ return (src - old_src)
	ret
	SET_SIZE(strlen)
