/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#include <sys/asm_linkage.h>

	.file	"fsr.s"

	.section	.data
	.align 4

/*
 * The following table maps trap enable bits in __fsr_init_value
 * (after shifting right one bit):
 *
 * bit 0 - inexact trap
 * bit 1 - division trap
 * bit 2 - underflow trap
 * bit 3 - overflow trap
 * bit 4 - invalid trap
 *
 * to exception masks in the floating point control word
 *
 * bit 0 - invalid mask
 * bit 2 - zero divide mask
 * bit 3 - overflow mask
 * bit 4 - underflow mask
 * bit 5 - inexact mask
 */
	.local	trap_table
	.type	trap_table,@object
trap_table:
	.byte	0b11111111
	.byte	0b11011111
	.byte	0b11111011
	.byte	0b11011011
	.byte	0b11101111
	.byte	0b11001111
	.byte	0b11101011
	.byte	0b11001011
	.byte	0b11110111
	.byte	0b11010111
	.byte	0b11110011
	.byte	0b11010011
	.byte	0b11100111
	.byte	0b11000111
	.byte	0b11100011
	.byte	0b11000011
	.byte	0b11111110
	.byte	0b11011110
	.byte	0b11111010
	.byte	0b11011010
	.byte	0b11101110
	.byte	0b11001110
	.byte	0b11101010
	.byte	0b11001010
	.byte	0b11110110
	.byte	0b11010110
	.byte	0b11110010
	.byte	0b11010010
	.byte	0b11100110
	.byte	0b11000110
	.byte	0b11100010
	.byte	0b11000010

	.size	trap_table,32

ENTRY_NP(__fsr)
	pushl	%ebp
	movl	%esp,%ebp
	pushl	%edx
	pushl	%ecx
	pushl	%ebx
	subl	$4,%esp

	/* Setup PIC */
	call	9f
9:	popl	%ebx
	addl	$_GLOBAL_OFFSET_TABLE_ + [. - 9b], %ebx

	movl	8(%ebp), %ecx		/* the value set by CG is passed in */
	shrl	$1,%ecx			/* get rid of fns bit */
	cmpl	$0,%ecx			/* if remaining bits are zero */
	je	3f			/*   there's nothing to do */

	fstcw	0(%esp)			/* store the control word */

	movl	%ecx,%edx
	andl	$0x1f,%edx		/* get the trap enable bits */
	movl	trap_table@GOT(%ebx), %eax
	addl	%eax,%edx
	movb	(%edx),%al
	andb	%al,0(%esp)	/* unmask the corresponding exceptions */

	testl	$0x200,%ecx		/* test denormal trap enable */
	jz	1f			/* skip if zero */

	andb	$0xfd,0(%esp)	/* unmask denormal exception */

1:
	movl	%ecx,%edx
	andl	$0x60,%edx		/* get the rounding direction */
	jz	1f			/* skip if zero */

	movl	%edx,%eax		/* exchange negative<->tozero */
	andl	$0x20,%eax		/*   leaving nearest and positive */
	shll	$1,%eax			/*   as is */
	xorl	%eax,%edx
	shll	$5,%edx
	andw	$0xf3ff,0(%esp)		/* update rounding direction */
	orw	%dx,0(%esp)

1:
	andl	$0x180,%ecx		/* get the rounding precision */
	jz	1f			/* skip if zero */

	xorl	$0x180,%ecx		/* reverse bits */
	shll	$1,%ecx
	andw	$0xfcff,0(%esp)		/* update rounding precision */
	orw	%cx,0(%esp)

1:
	fldcw	0(%esp)			/* load the modified control word */

3:
	addl	$4,%esp
	popl	%ebx
	popl	%ecx
	popl	%edx
	popl	%ebp
	ret
SET_SIZE(__fsr)
