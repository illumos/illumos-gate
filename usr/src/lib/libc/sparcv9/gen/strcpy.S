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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

	ENTRY(strcpy)

	.align 32

	sub	%o1, %o0, %o3		! src - dst
	andcc	%o1, 7, %o4		! dword aligned ?
	bz,pn	%ncc, .srcaligned	! yup
	mov	%o0, %o2		! save dst

.chkbyte:
	andcc	%o1, 1, %g0		! need to copy byte ?
	bz,pn	%ncc, .chkhalfword	! nope, maybe halfword
	sub	%g0, %o1, %g1		! %g1<2:0> = # of unaligned bytes
	ldub	[%o2 + %o3], %o5	! src[0]
	tst	%o5			! src[0] == 0 ?
	stb	%o5, [%o2]		! dst[0] = src[0]
	bz,pn	%ncc, .done		! yup, done
	inc	%o2			! src++, dst++

.chkhalfword:
	andcc	%g1, 2, %g0		! need to copy half-word ?
	bz,pn	%ncc, .chkword		! nope, maybe word
	nop				!
	lduh	[%o2 + %o3], %o5	! load src halfword
	srl	%o5, 8, %o4		! extract first byte
	tst	%o4			! first byte == 0 ?
	bz,pn	%ncc, .done		! yup, done
	stb	%o4, [%o2]		! store first byte
	andcc	%o5, 0xff, %g0		! extract second byte
	stb 	%o5, [%o2 + 1]		! store second byte
	bz,pn	%ncc, .done		! yup, 2nd byte zero, done
	add	%o2, 2, %o2		! src += 2

.chkword:
	andcc	%g1, 4, %g0		! need to copy word ?
	bz,pn	%ncc, .srcaligned	! nope
	nop				!
	lduw	[%o2 + %o3], %o5	! load src word
	srl	%o5, 24, %o4		! extract first byte
	tst	%o4			! is first byte zero ?
	bz,pn	%ncc, .done		! yup, done
	stb	%o4, [%o2]		! store first byte
	srl	%o5, 16, %o4		! extract second byte
	andcc	%o4, 0xff, %g0		! is second byte zero ?
	bz,pn	%ncc, .done		! yup, done
	stb	%o4, [%o2 + 1]		! store second byte
	srl	%o5, 8, %o4		! extract third byte
	andcc	%o4, 0xff, %g0		! third byte zero ?
	bz,pn	%ncc, .done		! yup, done
	stb	%o4, [%o2 + 2]		! store third byte
	andcc	%o5, 0xff, %g0		! fourth byte zero ?
	stb 	%o5, [%o2 + 3]		! store fourth byte
	bz,pn	%ncc, .done		! yup, fourth byte zero, done
	add	%o2, 4, %o2		! src += 2

.srcaligned:
	sethi	%hi(0x01010101), %o4	! Alan Mycroft's magic1
	or	%o4, %lo(0x01010101),%o4!  finish loading magic1
	sllx	%o4, 32, %o1		! spread magic1
	and	%o2, 3, %g4		! dst<1:0> to examine offset
	or	%o4, %o1, %o4		!   to all 64 bits
	cmp	%g4, 1			! dst offset of 1 or 5
	sllx	%o4, 7, %o5		!  Alan Mycroft's magic2
	be,pn	%ncc, .storebyte1241	! store 1, 2, 4, 1 bytes
	cmp	%g4, 3			! dst offset of 3 or 7
	be,pn	%ncc, .storebyte1421	! store 1, 4, 2, 1 bytes
	cmp	%g4, 2			! dst halfword aligned ?
	be,pn	%ncc, .storehalfword	! yup, store half-word wise
	andcc	%o2, 7, %g0		! dst word aligned ?
	bnz,pn	%ncc, .storeword2	! yup, store word wise
	.empty

.storedword:
	ldx	[%o2 + %o3], %o1	! src dword
	add	%o2, 8, %o2		! src += 8, dst += 8
	andn	%o5, %o1, %g1		! ~dword & 0x8080808080808080
	sub	%o1, %o4, %g4		! dword - 0x0101010101010101
	andcc	%g4, %g1, %g0		! ((dword - 0x0101010101010101) & ~dword & 0x8080808080808080)
	bz,a,pt	%ncc, .storedword	! no zero byte if magic expression == 0
	stx	%o1, [%o2 - 8]		! store word to dst (address pre-incremented)

.zerobyte:
	orn	%o4, %g0, %o4		! 0xffffffffffffffff
	sllx	%o4, 56, %o4		! 0xff00000000000000
	srlx	%o1, 56, %o3		! %o3<7:0> = first byte
	andcc	%o1, %o4, %g0		! first byte zero?
	bz,pn	%ncc, .done		! yup, done
	stb	%o3, [%o2 - 8]		! store first byte
	srlx	%o4, 8, %o4		! 0x00ff000000000000
	srlx	%o1, 48, %o3		! %o3<7:0> = second byte
	andcc	%o1, %o4, %g0		! second byte zero?
	bz,pn	%ncc, .done		! yup, done
	stb	%o3, [%o2 - 7]		! store second byte
	srlx	%o4, 8, %o4		! 0x0000ff0000000000
	srlx	%o1, 40, %o3		! %o3<7:0> = third byte
	andcc	%o1, %o4, %g0		! third byte zero?
	bz,pn	%ncc, .done		! yup, done
	stb	%o3, [%o2 - 6]		! store third byte
	srlx	%o4, 8, %o4		! 0x000000ff00000000
	srlx	%o1, 32, %o3		! %o3<7:0> = fourth byte
	andcc	%o1, %o4, %g0		! fourth byte zero?
	bz,pn	%ncc, .done		! yup, done
	stb	%o3, [%o2 - 5]		! store fourth byte
	srlx	%o4, 8, %o4		! 0x00000000ff000000
	srlx	%o1, 24, %o3		! %o3<7:0> = fifth byte
	andcc	%o1, %o4, %g0		! fifth byte zero?
	bz,pn	%ncc, .done		! yup, done
	stb	%o3, [%o2 - 4]		! store fifth byte
	srlx	%o4, 8, %o4		! 0x0000000000ff0000
	srlx	%o1, 16, %o3		! %o3<7:0> = sixth byte
	andcc	%o1, %o4, %g0		! sixth byte zero?
	bz,pn	%ncc, .done		! yup, done
	stb	%o3, [%o2 - 3]		! store sixth byte
	srlx	%o4, 8, %o4		! 0x000000000000ff00
	andcc	%o1, %o4, %g0		! seventh byte zero?
	srlx	%o1, 8, %o3		! %o3<7:0> = seventh byte
	bz,pn	%ncc, .done		! yup, done
	stb	%o3, [%o2 - 2]		! store seventh byte
	stb	%o1, [%o2 - 1]		! store eigth byte
.done:
	retl				! done with leaf function

	nop				! ensure following loop 16-byte aligned

.storebyte1421:
	ldx	[%o2 + %o3], %o1	! x = src[]
	add	%o2, 8, %o2		! src += 8, dst += 8
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g4		! x - 0x0101010101010101
	andcc	%g4, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	srlx	%o1, 56, %g1		! %g1<7:0> = first byte; word aligned now
	stb	%g1, [%o2 - 8]		! store first byte
	srlx	%o1, 24, %g1		! %g1<31:0> = bytes 2, 3, 4, 5
	stw	%g1, [%o2 - 7]		! store bytes 2, 3, 4, 5
	srlx	%o1, 8, %g1		! %g1<15:0> = bytes 6, 7
	sth	%g1, [%o2 - 3]		! store bytes 6, 7
	ba	.storebyte1421		! next dword
	stb	%o1, [%o2 - 1]		! store eigth byte

	nop				! ensure following loop 16-byte aligned
	nop				! ensure following loop 16-byte aligned

.storebyte1241:
	ldx	[%o2 + %o3], %o1	! x = src[]
	add	%o2, 8, %o2		! src += 8, dst += 8
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g4		! x - 0x0101010101010101
	andcc	%g4, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	srlx	%o1, 56, %g1		! %g1<7:0> = first byte; word aligned now
	stb	%g1, [%o2 - 8]		! store first byte
	srlx	%o1, 40, %g1		! %g1<15:0> = bytes 2, 3
	sth	%g1, [%o2 - 7]		! store bytes 2, 3
	srlx	%o1, 8, %g1		! %g1<31:0> = bytes 4, 5, 6, 7
	stw	%g1, [%o2 - 5]		! store bytes 4, 5, 6, 7
	ba	.storebyte1241		! next dword
	stb	%o1, [%o2 - 1]		! store eigth byte

	nop				! ensure following loop 16-byte aligned
	nop				! ensure following loop 16-byte aligned

.storehalfword:
	ldx	[%o2 + %o3], %o1	! x = src[]
	add	%o2, 8, %o2		! src += 8, dst += 8
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g4		! x - 0x0101010101010101
	andcc	%g4, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	srlx	%o1, 48, %g1		! get first and second byte
	sth	%g1, [%o2 - 8]		! store first and second byte; word aligned now
	srlx	%o1, 16, %g1		! %g1<31:0> = bytes 3, 4, 5, 6
	stw	%g1, [%o2 - 6]		! store bytes 3, 4, 5, 6
	ba	.storehalfword		! next word
	sth	%o1, [%o2 - 2]		! store seventh and eigth byte

.storeword:
	ldx	[%o2 + %o3], %o1	! x = src[]
.storeword2:
	add	%o2, 8, %o2		! src += 8, dst += 8
	andn	%o5, %o1, %g1		! ~x & 0x0x8080808080808080
	sub	%o1, %o4, %g4		! x - 0x0101010101010101
	andcc	%g4, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	srlx	%o1, 32, %g1		! get bytes 1,2,3,4
	stw	%g1, [%o2 - 8]		! store bytes 1,2,3,4 (address is pre-incremented)
	ba	.storeword		! no zero byte if magic expression == 0
	stw	%o1, [%o2 - 4]		! store bytes 5,6,7,8

	nop				! padding, do not remove!!!
	nop				! padding, do not remove!!!
	SET_SIZE(strcpy)

