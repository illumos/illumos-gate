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

	.file	"strncpy.s"

/*
 * strncpy(s1, s2)
 *
 * Copy string s2 to s1, truncating or null-padding to always copy n bytes
 * return s1.
 *
 * Fast assembler language version of the following C-program for strncpy
 * which represents the `standard' for the C-library.
 *
 *	char *
 *	strncpy(char *s1, const char *s2, size_t n)
 *	{
 *		char *os1 = s1;
 *
 *		n++;
 *		while ((--n != 0) &&  ((*s1++ = *s2++) != '\0'))
 *			;
 *		if (n != 0)
 *			while (--n != 0)
 *				*s1++ = '\0';
 *		return (os1);
 *	}
 */

#include <sys/asm_linkage.h>

	! strncpy works similarly to strcpy, except that n bytes of s2
	! are copied to s1. If a null character is reached in s2 yet more
	! bytes remain to be copied, strncpy will copy null bytes into
	! the destination string.
	!
	! This implementation works by first aligning the src ptr and
	! performing small copies until it is aligned.  Then, the string
	! is copied based upon destination alignment.  (byte, half-word,
	! word, etc.)

	ENTRY(strncpy)

	.align 32
	nop				! pad to align loop on 16-byte boundary
	subcc	%g0, %o2, %g4		! n = -n, n == 0 ?
	bz,pn	%ncc, .done		! n == 0, done
	add	%o1, %o2, %o3		! src = src + n
	andcc	%o1, 7, %o4		! dword aligned ?
	bz,pn	%ncc, .dwordaligned	! yup
	add	%o0, %o2, %o2		! dst = dst + n
	sub	%o4, 8, %o4		! bytes until src aligned

.alignsrc:
	ldub	[%o3 + %g4], %o1	! src[]
	stb	%o1, [%o2 + %g4]	! dst[] = src[]
	addcc	%g4, 1, %g4		! src++, dst++, n--
	bz,pn	%ncc, .done		! n == 0, done
	tst	%o1			! end of src reached (null byte) ?
	bz,a	%ncc, .bytepad		! yes, at least one byte to pad here
	add 	%o2, %g4, %o3		! need single dest pointer for fill
	addcc	%o4, 1, %o4		! src aligned now?
	bnz,a	%ncc, .alignsrc		! no, copy another byte
	nop				! pad
	nop				! pad

.dwordaligned:
	sethi	%hi(0x01010101), %o4	! Alan Mycroft's magic1
	add	%o2, %g4, %g5		! dst
	or	%o4, %lo(0x01010101),%o4!  finish loading magic1
	and	%g5, 3, %g1		! dst<1:0> to examine offset
	sllx	%o4, 32, %o1		! spread magic1
	cmp	%g1, 1			! dst offset of 1 or 5
	or	%o4, %o1, %o4		!   to all 64 bits
	sub	%o2, 8, %o2		! adjust for dest pre-incr in cpy loops
	be,pn	%ncc, .storebyte1241	! store 1, 2, 4, 1 bytes
	sllx	%o4, 7, %o5		!  Alan Mycroft's magic2
	cmp	%g1, 3			! dst offset of 3 or 7
	be,pn	%ncc, .storebyte1421	! store 1, 4, 2, 1 bytes
	cmp	%g1, 2			! dst halfword aligned ?
	be,pn	%ncc, .storehalfword	! yup, store half-word wise
	andcc	%g5, 7, %g0		! dst word aligned ?
	bnz,pn	%ncc, .storeword2	! yup, store word wise
	nop				! ensure loop is 16-byte aligned

.storedword:
	ldx	[%o3 + %g4], %o1	! src dword
	addcc	%g4, 8, %g4		! n += 8, src += 8, dst += 8
	bcs,pn	%ncc,.lastword		! if counter wraps, last word
	andn	%o5, %o1, %g1		! ~dword & 0x8080808080808080
	sub	%o1, %o4, %g5		! dword - 0x0101010101010101
	andcc	%g5, %g1, %g0		! ((dword - 0x0101010101010101) & ~dword & 0x8080808080808080)
	bz,a,pt	%ncc, .storedword	! no zero byte if magic expression == 0
	stx	%o1, [%o2 + %g4]	! store word to dst (address pre-incremented)

	! n has not expired, but src is at the end. we need to push out the
	! remaining src bytes and then start padding with null bytes

.zerobyte:
	add	%o2, %g4, %o3		! pointer to dest string
	srlx	%o1, 56, %g1		! first byte
	stb	%g1, [%o3]		! store it
	andcc	%g1, 0xff, %g0		! end of string ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 48, %g1		! second byte
	stb	%g1, [%o3 + 1]		! store it
	andcc	%g1, 0xff, %g0		! end of string ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 40, %g1		! third byte
	stb	%g1, [%o3 + 2]		! store it
	andcc	%g1, 0xff, %g0		! end of string ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 32, %g1		! fourth byte
	stb	%g1, [%o3 + 3]		! store it
	andcc	%g1, 0xff, %g0		! end of string ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 24, %g1		! fifth byte
	stb	%g1, [%o3 + 4]		! store it
	andcc	%g1, 0xff, %g0		! end of string ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 16, %g1		! sixth byte
	stb	%g1, [%o3 + 5]		! store it
	andcc	%g1, 0xff, %g0		! end of string ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 8, %g1		! seventh byte
	stb	%g1, [%o3 + 6]		! store it
	andcc	%g1, 0xff, %g0		! end of string ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	stb	%o1, [%o3 + 7]		! store eighth byte
	addcc	%g4, 16, %g0		! number of pad bytes < 16 ?
	bcs,pn	%ncc, .bytepad		! yes, do simple byte wise fill
	add	%o3, 8, %o3		! dst += 8
	andcc	%o3, 7, %o4		! dst offset relative to dword boundary
	bz,pn	%ncc, .fillaligned	! dst already dword aligned

	! here there is a least one more byte to zero out: otherwise we would
	! have exited through label .lastword

	sub	%o4, 8, %o4		! bytes to align dst to dword boundary
.makealigned:
	stb	%g0, [%o3]		! dst[] = 0
	addcc	%g4, 1, %g4		! n--
	bz,pt	%ncc, .done		! n == 0, we are done
	addcc	%o4, 1, %o4		! any more byte needed to align
	bnz,pt	%ncc, .makealigned	! yup, pad another byte
	add	%o3, 1, %o3		! dst++
	nop				! pad to align copy loop below
	nop				! pad to align copy loop below

	! here we know that there at least another 8 bytes to pad, since
	! we don't get here unless there were >= 16 bytes to pad to begin
	! with, and we have padded at most 7 bytes suring dst aligning

.fillaligned:
	add	%g4, 7, %o2		! round up to next dword boundary
	and	%o2, -8, %o4		! pointer to next dword boundary
	and	%o2, 8, %o2		! dword count odd ? 8 : 0
	stx	%g0, [%o3]		! store first dword
	addcc	%o4, %o2, %o4		! dword count == 1 ?
	add	%g4, %o2, %g4		! if dword count odd, n -= 8
	bz,pt	%ncc, .bytepad		! if dword count == 1, pad leftover bytes
	add	%o3, %o2, %o3		! bump dst if dword count odd

.filldword:
	addcc	%o4, 16, %o4		! count -= 16
	stx	%g0, [%o3]		! dst[n] = 0
	stx	%g0, [%o3 + 8]		! dst[n+8] = 0
	add	%o3, 16, %o3		! dst += 16
	bcc,pt	%ncc, .filldword	! fill dwords until count == 0
	addcc	%g4, 16, %g4		! n -= 16
	bz,pn	%ncc, .done		! if n == 0, we are done

.bytepad:
	and	%g4, 1, %o2		! byte count odd ? 1 : 0
	stb	%g0, [%o3]		! store first byte
	addcc	%g4, %o2, %g4		! byte count == 1 ?
	bz,pt	%ncc, .done		! yup, we are done
	add	%o3, %o2, %o3		! bump pointer if odd

.fillbyte:
	addcc	%g4, 2, %g4		! n -= 2
	stb	%g0, [%o3]		! dst[n] = 0
	stb	%g0, [%o3 + 1]		! dst[n+1] = 0
	bnz,pt	%ncc, .fillbyte		! fill until n == 0
	add	%o3, 2, %o3		! dst += 2

.done:
	retl				! done
	nop				! pad to align loops below
	nop				! pad to align loops below

	! this is the last word. It may contain null bytes. store bytes
	! until n == 0. if null byte encountered, continue

.lastword:
	sub	%g4, 8, %g4		! undo counter pre-increment
	add	%o2, 8, %o2		! adjust dst for counter un-bumping

	srlx	%o1, 56, %g1		! first byte
	stb	%g1, [%o2 + %g4]	! store it
	inccc	%g4			! n--
	bz	.done			! if n == 0, we're done
	andcc	%g1, 0xff, %g0		! end of src reached ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 48, %g1		! second byte
	stb	%g1, [%o2 + %g4]	! store it
	inccc	%g4			! n--
	bz	.done			! if n == 0, we're done
	andcc	%g1, 0xff, %g0		! end of src reached ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 40, %g1		! third byte
	stb	%g1, [%o2 + %g4]	! store it
	inccc	%g4			! n--
	bz	.done			! if n == 0, we're done
	andcc	%g1, 0xff, %g0		! end of src reached ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 32, %g1		! fourth byte
	stb	%g1, [%o2 + %g4]	! store it
	inccc	%g4			! n--
	bz	.done			! if n == 0, we're done
	andcc	%g1, 0xff, %g0		! end of src reached ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 24, %g1		! fifth byte
	stb	%g1, [%o2 + %g4]	! store it
	inccc	%g4			! n--
	bz	.done			! if n == 0, we're done
	andcc	%g1, 0xff, %g0		! end of src reached ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 16, %g1		! sixth byte
	stb	%g1, [%o2 + %g4]	! store it
	inccc	%g4			! n--
	bz	.done			! if n == 0, we're done
	andcc	%g1, 0xff, %g0		! end of src reached ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	srlx	%o1, 8, %g1		! seventh byte
	stb	%g1, [%o2 + %g4]	! store it
	inccc	%g4			! n--
	bz	.done			! if n == 0, we're done
	andcc	%g1, 0xff, %g0		! end of src reached ?
	movz	%ncc, %g0, %o1		! if so, start padding with null bytes
	ba	.done			! here n must be zero, we are done
	stb	%o1, [%o2 + %g4]	! store eigth byte
	nop				! pad to align loops below
	nop				! pad to align loops below

.storebyte1421:
	ldx	[%o3 + %g4], %o1	! x = src[]
	addcc	%g4, 8, %g4		! src += 8, dst += 8
	bcs,pn	%ncc,.lastword		! if counter wraps, last word
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g5		! x - 0x0101010101010101
	andcc	%g5, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! end of src found, may need to pad
	add	%o2, %g4, %g5		! dst (in pointer form)
	srlx	%o1, 56, %g1		! %g1<7:0> = first byte; word aligned now
	stb	%g1, [%g5]		! store first byte
	srlx	%o1, 24, %g1		! %g1<31:0> = bytes 2, 3, 4, 5
	stw	%g1, [%g5 + 1]		! store bytes 2, 3, 4, 5
	srlx	%o1, 8, %g1		! %g1<15:0> = bytes 6, 7
	sth	%g1, [%g5 + 5]		! store bytes 6, 7
	ba	.storebyte1421		! next dword
	stb	%o1, [%g5 + 7]		! store eigth byte

.storebyte1241:
	ldx	[%o3 + %g4], %o1	! x = src[]
	addcc	%g4, 8, %g4		! src += 8, dst += 8
	bcs,pn	%ncc,.lastword		! if counter wraps, last word
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g5		! x - 0x0101010101010101
	andcc	%g5, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	add	%o2, %g4, %g5		! dst (in pointer form)
	srlx	%o1, 56, %g1		! %g1<7:0> = first byte; half-word aligned now
	stb	%g1, [%g5]		! store first byte
	srlx	%o1, 40, %g1		! %g1<15:0> = bytes 2, 3
	sth	%g1, [%g5 + 1]		! store bytes 2, 3
	srlx	%o1, 8, %g1		! %g1<31:0> = bytes 4, 5, 6, 7
	stw	%g1, [%g5 + 3]		! store bytes 4, 5, 6, 7
	ba	.storebyte1241		! next dword
	stb	%o1, [%g5 + 7]		! store eigth byte

.storehalfword:
	ldx	[%o3 + %g4], %o1	! x = src[]
	addcc	%g4, 8, %g4		! src += 8, dst += 8
	bcs,pn	%ncc,.lastword		! if counter wraps, last word
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g5		! x - 0x0101010101010101
	andcc	%g5, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	add	%o2, %g4, %g5		! dst (in pointer form)
	srlx	%o1, 48, %g1		! %g1<15:0> = bytes 1, 2; word aligned now
	sth	%g1, [%g5]		! store bytes 1, 2
	srlx	%o1, 16, %g1		! %g1<31:0> = bytes 3, 4, 5, 6
	stw	%g1, [%g5 + 2]		! store bytes 3, 4, 5, 6
	ba	.storehalfword		! next dword
	sth	%o1, [%g5 + 6]		! store bytes 7, 8
	nop				! align next loop to 16-byte boundary
	nop				! align next loop to 16-byte boundary

.storeword2:
	ldx	[%o3 + %g4], %o1	! x = src[]
	addcc	%g4, 8, %g4		! src += 8, dst += 8
	bcs,pn	%ncc,.lastword		! if counter wraps, last word
	andn	%o5, %o1, %g1		! ~x & 0x8080808080808080
	sub	%o1, %o4, %g5		! x - 0x0101010101010101
	andcc	%g5, %g1, %g0		! ((x - 0x0101010101010101) & ~x & 0x8080808080808080)
	bnz,pn	%ncc, .zerobyte		! x has zero byte, handle end cases
	add	%o2, %g4, %g5		! dst (in pointer form)
	srlx	%o1, 32, %g1		! %g1<31:0> = bytes 1, 2, 3, 4
	stw	%g1, [%g5]		! store bytes 1, 2, 3, 4
	ba	.storeword2		! next dword
	stw	%o1, [%g5 + 4]		! store bytes 5, 6, 7, 8

	! do not remove these pads, loop above may slow down otherwise

	nop				! pad
	nop				! pad

	SET_SIZE(strncpy)
