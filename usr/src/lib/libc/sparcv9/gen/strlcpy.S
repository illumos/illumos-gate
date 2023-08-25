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

	.file	"strlcpy.s"

/*
 * The strlcpy() function copies at most dstsize-1 characters
 * (dstsize being the size of the string buffer dst) from src
 * to dst, truncating src if necessary. The result is always
 * null-terminated.  The function returns strlen(src). Buffer
 * overflow can be checked as follows:
 *
 *   if (strlcpy(dst, src, dstsize) >= dstsize)
 *           return -1;
 */

#include <sys/asm_linkage.h>

	! strlcpy implementation is similar to that of strcpy, except
	! in this case, the maximum size of the detination must be
	! tracked since it bounds our maximum copy size.  However,
	! we must still continue to check for zero since the routine
	! is expected to null-terminate any string that is within
	! the dest size bound.
	!
	! this method starts by checking for and arranging source alignment.
	! Once this has occurred, we copy based upon destination alignment.
	! This is either by xword, word, halfword, or byte.  As this occurs, we
	! check for a zero-byte.  If one is found, we branch to a method
	! which checks for the exact location of a zero-byte within a
	! larger xword/word/half-word quantity.


	ENTRY(strlcpy)

	.align 32

	save	%sp, -SA(WINDOWSIZE), %sp
	subcc	%g0, %i2, %g4		! n = -n, n == 0 ?
	bz,pn	%ncc, .getstrlen	! n == 0, must determine strlen
	add	%i1, %i2, %i3		! src = src + n
	andcc	%i1, 7, %i4		! src dword aligned ?
	bz,pn	%ncc, .dwordaligned	! yup
	add	%i0, %i2, %i2		! dst = dst + n
	sub	%i4, 8, %i4		! bytes until src aligned

.alignsrc:
	ldub	[%i3 + %g4], %l1	! src[]
	andcc	%l1, 0xff, %g0		! end of src reached (null byte) ?
	stub	%l1, [%i2 + %g4]	! dst[] = src[]
	bz,a	%ncc, .done		! yes, done
	add 	%i2, %g4, %i2		! need single dest pointer for strlen
	addcc	%g4, 1, %g4		! src++, dst++, n--
	bz,pn	%ncc, .forcenullunalign	! n == 0, force null byte, compute len
	addcc	%i4, 1, %i4		! src aligned now?
	bnz,a	%ncc, .alignsrc		! no, copy another byte
	nop				! pad

.dwordaligned:
	sethi	%hi(0x01010101), %i4	! Alan Mycroft's magic1
	add	%i2, %g4, %l0		! dst
	or	%i4, %lo(0x01010101),%i4!  finish loading magic1
	and	%l0, 3, %g1		! dst<1:0> to examine offset
	sllx	%i4, 32, %l1		! spread magic1
	cmp	%g1, 1			! dst offset of 1 or 5
	or	%i4, %l1, %i4		!   to all 64 bits
	sub	%i2, 8, %i2		! adjust for dest pre-incr in cpy loops
	be,pn	%ncc, .storebyte1241	! store 1, 2, 4, 1 bytes
	sllx	%i4, 7, %i5		!  Alan Mycroft's magic2
	cmp	%g1, 3			! dst offset of 3 or 7
	be,pn	%ncc, .storebyte1421	! store 1, 4, 2, 1 bytes
	cmp	%g1, 2			! dst halfword aligned ?
	be,pn	%ncc, .storehalfword	! yup, store half-word wise
	andcc	%l0, 7, %g0		! dst word aligned ?
	bnz,pn	%ncc, .storeword2	! yup, store word wise
	nop				! ensure loop is 16-byte aligned
	nop				! ensure loop is 16-byte aligned

.storedword:
	ldx	[%i3 + %g4], %l1	! src dword
	addcc	%g4, 8, %g4		! n += 8, src += 8, dst += 8
	bcs,pn	%ncc, .lastword		! if counter wraps, last word
	andn	%i5, %l1, %g1		! ~dword & 0x8080808080808080
	sub	%l1, %i4, %l0		! dword - 0x0101010101010101
	andcc	%l0, %g1, %g0		! ((dword - 0x0101010101010101) & ~dword & 0x8080808080808080)
	bz,a,pt	%ncc, .storedword	! no zero byte if magic expression == 0
	stx	%l1, [%i2 + %g4]	! store word to dst (address pre-incremented)

	! n has not expired, but src is at the end. we need to push out the
	! remaining src bytes. Since strlen(dts) == strlen(src), we can
	! compute the return value as the difference of final dst pointer
	! and the pointer to the start of dst

.zerobyte:
	add	%i2, %g4, %i2		! pointer to dest string
	srlx	%l1, 56, %g1		! first byte
	andcc	%g1, 0xff, %g0		! end of string ?
	bz,pn	%ncc, .done		! yup, copy done, return length
	stb	%g1, [%i2]		! store it
	add	%i2, 1, %i2		! dst++
	srlx	%l1, 48, %g1		! second byte
	andcc	%g1, 0xff, %g0		! end of string ?
	bz,pn	%ncc, .done		! yup, copy done, return length
	stb	%g1, [%i2]		! store it
	add	%i2, 1, %i2		! dst++
	srlx	%l1, 40, %g1		! third byte
	andcc	%g1, 0xff, %g0		! end of string ?
	bz,pn	%ncc, .done		! yup, copy done, return length
	stb	%g1, [%i2]		! store it
	add	%i2, 1, %i2		! dst++
	srlx	%l1, 32, %g1		! fourth byte
	andcc	%g1, 0xff, %g0		! end of string ?
	bz,pn	%ncc, .done		! yup, copy done, return length
	stb	%g1, [%i2]		! store it
	add	%i2, 1, %i2		! dst++
	srlx	%l1, 24, %g1		! fifth byte
	andcc	%g1, 0xff, %g0		! end of string ?
	bz,pn	%ncc, .done		! yup, copy done, return length
	stb	%g1, [%i2]		! store it
	add	%i2, 1, %i2		! dst++
	srlx	%l1, 16, %g1		! sixth byte
	andcc	%g1, 0xff, %g0		! end of string ?
	bz,pn	%ncc, .done		! yup, copy done, return length
	stb	%g1, [%i2]		! store it
	add	%i2, 1, %i2		! dst++
	srlx	%l1, 8, %g1		! seventh byte
	andcc	%g1, 0xff, %g0		! end of string ?
	bz,pn	%ncc, .done		! yup, copy done, return length
	stb	%g1, [%i2]		! store it
	stb	%l1, [%i2 + 1]		! store eigth byte
	add	%i2, 1, %i2		! dst++

.done:
	sub	%i2, %i0, %i0		! len = dst - orig dst
	ret				! subroutine done
	restore	%i0, %g0, %o0		! restore register window, return len

	! n expired, so this is the last word. It may contain null bytes.
	! Store bytes until n == 0. If a null byte is encountered during
	! processing of this last src word, we are done. Otherwise continue
	! to scan src until we hit the end, and compute strlen from the
	! difference between the pointer past the last byte of src and the
	! original pointer to the start of src

.lastword:
	add	%i2, %g4, %i2		! we want a single dst pointer here
	sub	%g4, 8, %g4		! undo counter pre-increment
	add	%i3, %g4, %i3		! we want a single src pointer here

	srlx	%l1, 56, %g1		! first byte
	andcc	%g1, 0xff, %g0		! end of src reached ?
	bz,pn	%ncc, .done		! yup
	stb	%g1, [%i2]		! store it
	inccc	%g4			! n--
	bz	.forcenull		! if n == 0, force null byte, compute len
	srlx	%l1, 48, %g1		! second byte
	add	%i2, 1, %i2		! dst++
	andcc	%g1, 0xff, %g0		! end of src reached ?
	bz,pn	%ncc, .done		! yup
	stb	%g1, [%i2]		! store it
	inccc	%g4			! n--
	bz	.forcenull		! if n == 0, force null byte, compute len
	srlx	%l1, 40, %g1		! third byte
	add	%i2, 1, %i2		! dst++
	andcc	%g1, 0xff, %g0		! end of src reached ?
	bz,pn	%ncc, .done		! yup
	stb	%g1, [%i2]		! store it
	inccc	%g4			! n--
	bz	.forcenull		! if n == 0, force null byte, compute strlen
	srlx	%l1, 32, %g1		! fourth byte
	add	%i2, 1, %i2		! dst++
	andcc	%g1, 0xff, %g0		! end of src reached ?
	bz,pn	%ncc, .done		! yup
	stb	%g1, [%i2]		! store it
	inccc	%g4			! n--
	bz	.forcenull		! if n == 0, force null byte, compute strlen
	srlx	%l1, 24, %g1		! fifth byte
	add	%i2, 1, %i2		! dst++
	andcc	%g1, 0xff, %g0		! end of src reached ?
	bz,pn	%ncc, .done		! yup
	stb	%g1, [%i2]		! store it
	inccc	%g4			! n--
	bz	.forcenull		! if n == 0, force null byte, compute strlen
	srlx	%l1, 16, %g1		! sixth byte
	add	%i2, 1, %i2		! dst++
	andcc	%g1, 0xff, %g0		! end of src reached ?
	bz,pn	%ncc, .done		! yup
	stb	%g1, [%i2]		! store it
	inccc	%g4			! n--
	bz	.forcenull		! if n == 0, force null byte, compute strlen
	srlx	%l1, 8, %g1		! seventh byte
	add	%i2, 1, %i2		! dst++
	andcc	%g1, 0xff, %g0		! end of src reached ?
	bz,pn	%ncc, .done		! yup
	stb	%g1, [%i2]		! store it
	inccc	%g4			! n--
	bz	.forcenull		! if n == 0, force null byte, compute strlen
	andcc	%l1, 0xff, %g0		! end of src reached ?
	add	%i2, 1, %i2		! dst++
	bz,pn	%ncc, .done		! yup
	stb	%l1, [%i2]		! store eigth byte

	! we need to force a null byte in the last position of dst
	! %i2 points to the location

.forcenull:
	stb	%g0, [%i2]		! force string terminating null byte

	! here: %i1 points to src start
	!	%i3 points is current src ptr (8-byte aligned)

.searchword:
	ldx	[%i3], %l1		! src dword
.searchword2:
	andn	%i5, %l1, %g1		! ~dword & 0x8080808080808080
	sub	%l1, %i4, %l0		! dword - 0x0101010101010101
	andcc	%l0, %g1, %g0		! ((dword - 0x0101010101010101) & ~dword & 0x80808080
	bz,a,pt	%ncc, .searchword	! no null byte if expression is 0
	add	%i3, 8, %i3		! src += 8

	mov	0xff, %i5		! create byte mask for null byte scanning
	sllx	%i5, 56, %i5		! mask for 1st byte = 0xff0000000000000000
.searchbyte:
	andcc	%l1, %i5, %g0		! current byte zero?
	srlx	%i5, 8, %i5		! byte mask for next byte
	bnz,a	%ncc, .searchbyte	! current byte != zero, continue search
	add	%i3, 1, %i3		! src++

.endfound:
	sub	%i3, %i1, %i0		! len = src - orig src
	ret				! done
	restore	%i0, %g0, %o0		! restore register window, return len
	nop				! align loop on 16-byte

.storebyte1421:
	ldx	[%i3 + %g4], %l1	! x = src[]
	addcc	%g4, 8, %g4		! src += 8, dst += 8
	bcs,pn	%ncc, .lastword		! if counter wraps, last word
	andn	%i5, %l1, %g1		! ~x & 0x8080808080808080
	sub	%l1, %i4, %l0		! x - 0x0101010101010101
	andcc	%l0, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! end of src found, may need to pad
	add	%i2, %g4, %l0		! dst (in pointer form)
	srlx	%l1, 56, %g1		! %g1<7:0> = first byte; word aligned now
	stb	%g1, [%l0]		! store first byte
	srlx	%l1, 24, %g1		! %g1<31:0> = bytes 2, 3, 4, 5
	stw	%g1, [%l0 + 1]		! store bytes 2, 3, 4, 5
	srlx	%l1, 8, %g1		! %g1<15:0> = bytes 6, 7
	sth	%g1, [%l0 + 5]		! store bytes 6, 7
	ba	.storebyte1421		! next dword
	stb	%l1, [%l0 + 7]		! store eigth byte

.storebyte1241:
	ldx	[%i3 + %g4], %l1	! x = src[]
	addcc	%g4, 8, %g4		! src += 8, dst += 8
	bcs,pn	%ncc, .lastword		! if counter wraps, last word
	andn	%i5, %l1, %g1		! ~x & 0x8080808080808080
	sub	%l1, %i4, %l0		! x - 0x0101010101010101
	andcc	%l0, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	add	%i2, %g4, %l0		! dst (in pointer form)
	srlx	%l1, 56, %g1		! %g1<7:0> = first byte; half-word aligned now
	stb	%g1, [%l0]		! store first byte
	srlx	%l1, 40, %g1		! %g1<15:0> = bytes 2, 3
	sth	%g1, [%l0 + 1]		! store bytes 2, 3
	srlx	%l1, 8, %g1		! %g1<31:0> = bytes 4, 5, 6, 7
	stw	%g1, [%l0 + 3]		! store bytes 4, 5, 6, 7
	ba	.storebyte1241		! next dword
	stb	%l1, [%l0 + 7]		! store eigth byte

.storehalfword:
	ldx	[%i3 + %g4], %l1	! x = src[]
	addcc	%g4, 8, %g4		! src += 8, dst += 8
	bcs,pn	%ncc, .lastword		! if counter wraps, last word
	andn	%i5, %l1, %g1		! ~x & 0x8080808080808080
	sub	%l1, %i4, %l0		! x - 0x0101010101010101
	andcc	%l0, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	add	%i2, %g4, %l0		! dst (in pointer form)
	srlx	%l1, 48, %g1		! %g1<15:0> = bytes 1, 2; word aligned now
	sth	%g1, [%l0]		! store bytes 1, 2
	srlx	%l1, 16, %g1		! %g1<31:0> = bytes 3, 4, 5, 6
	stw	%g1, [%l0 + 2]		! store bytes 3, 4, 5, 6
	ba	.storehalfword		! next dword
	sth	%l1, [%l0 + 6]		! store bytes 7, 8
	nop				! align next loop to 16-byte boundary
	nop				! align next loop to 16-byte boundary

.storeword2:
	ldx	[%i3 + %g4], %l1	! x = src[]
	addcc	%g4, 8, %g4		! src += 8, dst += 8
	bcs,pn	%ncc, .lastword		! if counter wraps, last word
	andn	%i5, %l1, %g1		! ~x & 0x8080808080808080
	sub	%l1, %i4, %l0		! x - 0x0101010101010101
	andcc	%l0, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	add	%i2, %g4, %l0		! dst (in pointer form)
	srlx	%l1, 32, %g1		! %g1<31:0> = bytes 1, 2, 3, 4
	stw	%g1, [%l0]		! store bytes 1, 2, 3, 4
	ba	.storeword2		! next dword
	stw	%l1, [%l0 + 4]		! store bytes 5, 6, 7, 8

	! n expired, i.e. end of destination buffer reached. Force null
	! null termination of dst, then scan src until end foudn for
	! determination of strlen(src)
	!
	! here: %i3 points to current src byte
	!       %i2 points one byte past end of dst
	! magic constants not loaded

.forcenullunalign:
	add	%i2, %g4, %i2		! we need a single dst ptr
	stb	%g0, [%i2 - 1]		! force string terminating null byte

.getstrlen:
	sethi	%hi(0x01010101), %i4	! Alan Mycroft's magic1
	or	%i4, %lo(0x01010101),%i4!  finish loading magic1
	sllx	%i4, 32, %i2		! spread magic1
	or	%i4, %i2, %i4		!   to all 64 bits
	sllx	%i4, 7, %i5		!  Alan Mycroft's magic2
	nop				! align loop to 16-byte boundary

.getstrlenloop:
	andcc	%i3, 7, %g0		! src dword aligned?
	bz,a,pn	%ncc, .searchword2	! yup, now search a dword at a time
	ldx	[%i3], %l1		! src dword
	ldub	[%i3], %l1		! load src byte
	andcc	%l1, 0xff, %g0		! end of src reached?
	bnz,a	%ncc, .getstrlenloop	! yup, return length
	add	%i3, 1, %i3		! src++
	sub	%i3, %i1, %i0		! len = src - orig src
	ret				! done
	restore	%i0, %g0, %o0		! restore register window, return len

	nop				! pad tp 16-byte boundary
	nop				! pad tp 16-byte boundary
	SET_SIZE(strlcpy)
