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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"strcpy.s"

/*
 * strcpy(s1, s2)
 *
 * Copy string s2 to s1.  s1 must be large enough. Return s1.
 *
 * Fast assembler language version of the following C-program strcpy
 * which represents the `standard' for the C-library.
 *
 *	char *
 *	strcpy(s1, s2)
 *	register char *s1;
 *	register const char *s2;
 *	{
 *		char *os1 = s1;
 *
 *		while(*s1++ = *s2++)
 *			;
 *		return(os1);
 *	}
 *
 */

#include <sys/asm_linkage.h>

	! This implementation of strcpy works by first checking the
	! source alignment and copying byte, half byte, or word
	! quantities until the source ptr is aligned at an extended
	! word boundary.  Once this has occurred, the string is copied,
	! checking for zero bytes, depending upon its dst ptr alignment.
	! (methods for xword, word, half-word, and byte copies are present)

#ifdef	__sparcv9
#define	SAVESIZE	(8 * 3)
#define	STACK_OFFSET	(STACK_BIAS + MINFRAME)
#else
#define	SAVESIZE	(8 * 5)
#define	STACK_OFFSET	(STACK_BIAS + MINFRAME + 4)
#endif

#define LABEL_ADDRESS(label, reg)	 \
	.pushlocals			;\
0:	rd %pc, reg		  	;\
	add reg, (label) - 0b, reg	;\
	.poplocals

offset_table:
	.word	.storexword - offset_table	! Offset 0 => xword aligned
	.word	.storebyte1241 - offset_table	! Offset 1 or 5
	.word	.storehalfword - offset_table	! Offset 2 or 6
	.word	.storebyte1421 - offset_table	! Offset 3 or 7
	.word	.storeword - offset_table	! Offset 4

	.align	64
#ifdef	__sparcv9
	.skip	20
#else
	.skip	12
#endif

	ENTRY(strcpy)
	add	%sp, -SA(STACK_OFFSET + SAVESIZE), %sp
#ifndef	__sparcv9
	stx	%g4, [%sp + STACK_OFFSET + 24]
	stx	%g5, [%sp + STACK_OFFSET + 32]
#endif
	sethi	%hi(0x01010101), %o4		! 0x01010000
	sub	%o1, %o0, %o3		! src - dst
	or	%o4, %lo(0x01010101), %o4	! 0x01010101
	andcc	%o1, 7, %g5		! dword aligned ?
	sllx	%o4, 32, %o5			! 0x01010101 << 32
	mov	%o0, %o2		! save dst
	or	%o4, %o5, %o4			! 0x0101010101010101

	bz,pt	%ncc, .srcaligned	! yup
	sllx	%o4, 7, %o5			! 0x8080808080808080

	sub	%g0, %g5, %g4		! count = -off
	ldx	[%o1 + %g4], %o1	! val = *(addr + -off)
	mov	-1, %g1			! mask = -1
	sllx	%g5, 3, %g4		! shift = off * 8
	srlx	%g1, %g4, %g1		! -1 >> ((addr & 7) * 8)
	orn	%o1, %g1, %o1		! val |= ~mask

	andn	%o5, %o1, %g4		! ~val & 0x80
	sub	%o1, %o4, %g1		! val - 0x01
	andcc	%g4, %g1, %g4		! ~val & 0x80 & (val - 0x01)

	sllx	%g5, 3, %g4
	add	%o2, 8, %o2		! .zerobyte expects address = address + 8
	bnz,a,pn	%xcc, .zerobyte ! Zero byte in the first xword
	  sllx	%o1, %g4, %o1		! and data to be left justified

	sub	%o2, 8, %o2
	mov	8, %g4
	sub	%g4, %g5, %g1		! Bytes to be written
	sub	%g1, 1, %g4

1:	stub	%o1, [%o2 + %g4]
	dec	%g4
	brgez,pt	%g4, 1b
	srlx	%o1, 8, %o1

	add	%o2, %g1, %o2		! Move ptr by #bytes written

.srcaligned:
	!! Check if the first dword contains zero after src is aligned
	ldx	[%o2 + %o3], %o1	! x = src[]
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g4		! x - 0x0101010101010101
	andcc	%g4, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,a,pn	%xcc, .zerobyte	! x has zero byte, handle end cases
	  add	%o2, 8, %o2		! src += 8, dst += 8

	!! Determine the destination offset and branch
	!! to appropriate location
	and	%o2, 3, %g4
	and	%o2, 4, %g1
	or	%g1, %g4, %g1
	movrnz	%g4, 0, %g1
	movrnz	%g1, 4, %g4

	!! %g4 contains the index of the jump address
	!! Load the address from the table.
	LABEL_ADDRESS(offset_table, %g1)
	sllx	%g4, 2, %g4
	lduw	[%g1 + %g4], %g4
	jmp	%g1 + %g4
	add	%o2, 8, %o2		! src += 8, dst += 8

.storexword:
	stx	%o1, [%o2 - 8]		! store word to dst (address pre-incremented)

1:
	ldx	[%o2 + %o3], %o1	! src dword
	add	%o2, 8, %o2		! src += 8, dst += 8
	andn	%o5, %o1, %g1		! ~dword & 0x8080808080808080
	sub	%o1, %o4, %g4		! dword - 0x0101010101010101
	andcc	%g4, %g1, %g0		! ((dword - 0x0101010101010101) & ~dword & 0x8080808080808080)
	bz,a,pt	%xcc, 1b		! no zero byte if magic expression == 0
	  stx	%o1, [%o2 - 8]		! store word to dst (address pre-incremented)

	ba,a	.zerobyte

.storebyte1421:
	!! Offset 3 or 7
	srlx	%o1, 56, %g1		! %g1<7:0> = first byte; word aligned now
	stb	%g1, [%o2 - 8]		! store first byte
	srlx	%o1, 24, %g1		! %g1<31:0> = bytes 2, 3, 4, 5
	stw	%g1, [%o2 - 7]		! store bytes 2, 3, 4, 5
	srlx	%o1, 8, %g1		! %g1<15:0> = bytes 6, 7
	sth	%g1, [%o2 - 3]		! store bytes 6, 7

	stx	%l0, [%sp + STACK_OFFSET + 0]
	and	%o2, 7, %g1
	stx	%l1, [%sp + STACK_OFFSET + 8]
	cmp	%g1, 3
	stx	%l2, [%sp + STACK_OFFSET + 16]

	move	%ncc, 40, %l0
	move	%ncc, 24, %l1
	move	%ncc, -11, %l2

	movne	%ncc, 8, %l0
	movne	%ncc, 56, %l1
	movne	%ncc, -15, %l2

	ba	.dstaligned
	mov	%o1, %g5

.storebyte1241:
	!! Offset 1 or 5
	srlx	%o1, 56, %g1		! %g1<7:0> = first byte; word aligned now
	stb	%g1, [%o2 - 8]		! store first byte
	srlx	%o1, 40, %g1		! %g1<15:0> = bytes 2, 3
	sth	%g1, [%o2 - 7]		! store bytes 2, 3
	srlx	%o1, 8, %g1		! %g1<31:0> = bytes 4, 5, 6, 7
	stw	%g1, [%o2 - 5]		! store bytes 4, 5, 6, 7

	stx	%l0, [%sp + STACK_OFFSET + 0]
	and	%o2, 7, %g1
	stx	%l1, [%sp + STACK_OFFSET + 8]
	cmp	%g1, 1
	stx	%l2, [%sp + STACK_OFFSET + 16]

	move	%ncc, 56, %l0
	move	%ncc, 8, %l1
	move	%ncc, -9, %l2

	movne	%ncc, 24, %l0
	movne	%ncc, 40, %l1
	movne	%ncc, -13, %l2

	ba	.dstaligned
	mov	%o1, %g5

.storehalfword:
	srlx	%o1, 48, %g1		! get first and second byte
	sth	%g1, [%o2 - 8]		! store first and second byte; word aligned now
	srlx	%o1, 16, %g1		! %g1<31:0> = bytes 3, 4, 5, 6
	stw	%g1, [%o2 - 6]		! store bytes 3, 4, 5, 6

	stx	%l0, [%sp + STACK_OFFSET + 0]
	and	%o2, 7, %g1
	stx	%l1, [%sp + STACK_OFFSET + 8]
	cmp	%g1, 2
	stx	%l2, [%sp + STACK_OFFSET + 16]

	move	%ncc, 48, %l0
	move	%ncc, 16, %l1
	move	%ncc, -10, %l2

	movne	%ncc, 16, %l0
	movne	%ncc, 48, %l1
	movne	%ncc, -14, %l2

	ba	.dstaligned
	mov	%o1, %g5

.storeword:
	srlx	%o1, 32, %g1		! get bytes 1,2,3,4
	stw	%g1, [%o2 - 8]		! store bytes 1,2,3,4 (address is pre-incremented)

	stx	%l0, [%sp + STACK_OFFSET + 0]
	mov	32, %l0			! Num of bits to be shifted left
	stx	%l1, [%sp + STACK_OFFSET + 8]
	mov	32, %l1			! Num of bits to be shifted right
	stx	%l2, [%sp + STACK_OFFSET + 16]
	mov	-12, %l2		! -offset
	mov	%o1, %g5

	nop	! Do not delete. Used for alignment.
.dstaligned:
	ldx	[%o2 + %o3], %o1	! x = src[]
	add	%o2, 8, %o2		! src += 8, dst += 8
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g4		! x - 0x0101010101010101
	andcc	%g4, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,a,pn %xcc, .finishup	! x has zero byte, handle end cases
	  stb	%g5, [%o2 - 9]

	sllx	%g5, %l0, %g5
	srlx	%o1, %l1, %g4
	or	%g5, %g4, %g5

	stx	%g5, [%o2 + %l2]
	ba	.dstaligned
	mov	%o1, %g5

.finishup:
	cmp	%l0, 56
	be,pn	%ncc, .zerobyte_restore
	andcc	%o2, 1, %g0
	bnz,a	%ncc, 1f
	  srlx	%g5, 8, %g5

1:	srlx	%l1, 4, %g4	! g4 contains 1, 2 or 3
	sub	%g4, 1, %g4	! multiple of 16
	sllx	%g4, 4, %g4	! How many bits to shift
	srlx	%g5, %g4, %l0
	add	%o2, %l2, %g1

2:	sth	%l0, [%g1]
	sub	%g4, 16, %g4
	add	%g1, 2, %g1
	brgez,a,pt	%g4, 2b
	  srlx	%g5, %g4, %l0

.zerobyte_restore:
	ldx	[%sp + STACK_OFFSET + 0], %l0
	andn	%o5, %o1, %o3		! ~val & 0x80
	ldx	[%sp + STACK_OFFSET + 8], %l1
	sub	%o1, %o4, %g1		! val - 0x01
	ldx	[%sp + STACK_OFFSET + 16], %l2

	ba	1f
	andcc	%o3, %g1, %o3		! ~val & 0x80 & (val - 0x01)

.zerobyte:
	!! %o5:	0x8080808080808080
	!! %o4: 0x0101010101010101
	!! %o1: Left justified dowrd that contains 0 byte
	!! %o2: Address to be written + 8

	andn	%o5, %o1, %o3		! ~val & 0x80
	sub	%o1, %o4, %g1		! val - 0x01
	andcc	%o3, %g1, %o3		! ~val & 0x80 & (val - 0x01)

1:	srlx	%o3, 7, %o3		! shift 0x80 -> 0x01
	andn	%o3, %o1, %o3		! mask off leading 0x01 bytes
	lzd	%o3, %o4		! 7, 15, ... 63

	mov	64, %o5			! Calc # of bytes to be discarded
	inc	%o4			! Include the zero byte too
	sub	%o5, %o4, %o5		! after the null byte
	sub	%o2, 8, %o2		! Adjust address which is +8 here.
	srlx	%o1, %o5, %o1		! Discard them

	srlx	%o4, 3, %o4		! Bits to bytes to be written
	dec	%o4			! dec 1 to use it as offset

2:	stub	%o1, [%o2 + %o4]
	dec	%o4
	brgez,pt %o4, 2b
	srlx	%o1, 8, %o1

#ifndef	__sparcv9
	ldx	[%sp + STACK_OFFSET + 24], %g4
	ldx	[%sp + STACK_OFFSET + 32], %g5
#endif
	retl				! done with leaf function
	add	%sp, SA(STACK_OFFSET + SAVESIZE), %sp
	SET_SIZE(strcpy)
