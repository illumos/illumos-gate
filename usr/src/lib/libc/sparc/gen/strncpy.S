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
	subcc	%g0, %o2, %o4		! n = -n
	bz	.doneshort		! if n == 0, done
	cmp	%o2, 7			! n < 7 ?
	add	%o1, %o2, %o3		! src = src + n
	blu	.shortcpy		! n < 7, use byte-wise copy
	add	%o0, %o2, %o2		! dst = dst + n
	andcc	%o1, 3, %o5		! src word aligned ?
	bz	.wordaligned		! yup
	save	%sp, -0x40, %sp		! create new register window
	sub	%i5, 4, %i5		! bytes until src aligned
	nop				! align loop on 16-byte boundary
	nop				! align loop on 16-byte boundary

.alignsrc:
	ldub	[%i3 + %i4], %i1	! src[]
	stb	%i1, [%i2 + %i4]	! dst[] = src[]
	inccc	%i4			! src++, dst++, n--
	bz	.done			! n == 0, done
	tst     %i1			! end of src reached (null byte) ?
	bz,a	.bytepad		! yes, at least one byte to pad here
	add 	%i2, %i4, %l0		! need single dest pointer for fill
	inccc	%i5			! src aligned now?
	bnz	.alignsrc		! no, copy another byte
	.empty

.wordaligned:
	add	%i2, %i4, %l0		! dst
	sethi	%hi(0x01010101), %l1	! Alan Mycroft's magic1
	sub	%i2, 4, %i2		! adjust for dest pre-incr in cpy loops
	or	%l1, %lo(0x01010101),%l1!  finish loading magic1
	andcc	%l0, 3, %g1		! destination word aligned ?
	bnz	.dstnotaligned		! nope
	sll	%l1, 7, %i5		! create Alan Mycroft's magic2

.storeword:
	lduw	[%i3 + %i4], %i1	! src dword
	addcc	%i4, 4, %i4		! n += 4, src += 4, dst += 4
	bcs	.lastword		! if counter wraps, last word
	andn	%i5, %i1, %g1		! ~dword & 0x80808080
	sub	%i1, %l1, %l0		! dword - 0x01010101
	andcc	%l0, %g1, %g0		! ((dword - 0x01010101) & ~dword & 0x80808080)
	bz,a	.storeword		! no zero byte if magic expression == 0
	stw	%i1, [%i2 + %i4]	! store word to dst (address pre-incremented)

	! n has not expired, but src is at the end. we need to push out the
	! remaining src bytes and then start padding with null bytes

.zerobyte:
	add	%i2, %i4, %l0		! pointer to dest string
	srl	%i1, 24, %g1		! first byte
	stb	%g1, [%l0]		! store it
	sub	%g1, 1, %g1		! byte == 0 ? -1 : byte - 1
	sra	%g1, 31, %g1		! byte == 0 ? -1 : 0
	andn	%i1, %g1, %i1		! if byte == 0, start padding with null bytes
	srl	%i1, 16, %g1		! second byte
	stb	%g1, [%l0 + 1]		! store it
	and	%g1, 0xff, %g1		! isolate byte
	sub	%g1, 1, %g1		! byte == 0 ? -1 : byte - 1
	sra	%g1, 31, %g1		! byte == 0 ? -1 : 0
	andn	%i1, %g1, %i1		! if byte == 0, start padding with null bytes
	srl	%i1, 8, %g1		! third byte
	stb	%g1, [%l0 + 2]		! store it
	and	%g1, 0xff, %g1		! isolate byte
	sub	%g1, 1, %g1		! byte == 0 ? -1 : byte - 1
	sra	%g1, 31, %g1		! byte == 0 ? -1 : 0
	andn	%i1, %g1, %i1		! if byte == 0, start padding with null bytes
	stb	%i1, [%l0 + 3]		! store fourth byte
	addcc	%i4, 8, %g0		! number of pad bytes < 8 ?
	bcs	.bytepad		! yes, do simple byte wise fill
	add	%l0, 4, %l0		! dst += 4
	andcc	%l0, 3, %l1		! dst offset relative to word boundary
	bz	.fillaligned		! dst already word aligned

	! here there is a least one more byte to zero out: otherwise we would
	! have exited through label .lastword

	sub	%l1, 4, %l1		! bytes to align dst to word boundary
.makealigned:
	stb	%g0, [%l0]		! dst[] = 0
	addcc	%i4, 1, %i4		! n--
	bz	.done			! n == 0, we are done
	addcc	%l1, 1, %l1		! any more byte needed to align
	bnz	.makealigned		! yup, pad another byte
	add	%l0, 1, %l0		! dst++
	nop				! pad to align copy loop below

	! here we know that there at least another 4 bytes to pad, since
	! we don't get here unless there were >= 8 bytes to pad to begin
	! with, and we have padded at most 3 bytes suring dst aligning

.fillaligned:
	add	%i4, 3, %i2		! round up to next word boundary
	and	%i2, -4, %l1		! pointer to next word boundary
	and	%i2, 4, %i2		! word count odd ? 4 : 0
	stw	%g0, [%l0]		! store first word
	addcc	%l1, %i2, %l1		! dword count == 1 ?
	add	%i4, %i2, %i4		! if word count odd, n -= 4
	bz	.bytepad		! if word count == 1, pad bytes left
	add	%l0, %i2, %l0		! bump dst if word count odd

.fillword:
	addcc	%l1, 8, %l1		! count -= 8
	stw	%g0, [%l0]		! dst[n] = 0
	stw	%g0, [%l0 + 4]		! dst[n+4] = 0
	add	%l0, 8, %l0		! dst += 8
	bcc	.fillword		! fill words until count == 0
	addcc	%i4, 8, %i4		! n -= 8
	bz	.done			! if n == 0, we are done
	.empty

.bytepad:
	and	%i4, 1, %i2		! byte count odd ? 1 : 0
	stb	%g0, [%l0]		! store first byte
	addcc	%i4, %i2, %i4		! byte count == 1 ?
	bz	.done			! yup, we are done
	add	%l0, %i2, %l0		! bump pointer if odd

.fillbyte:
	addcc	%i4, 2, %i4		! n -= 2
	stb	%g0, [%l0]		! dst[n] = 0
	stb	%g0, [%l0 + 1]		! dst[n+1] = 0
	bnz	.fillbyte		! fill until n == 0
	add	%l0, 2, %l0		! dst += 2

.done:
	ret				! done
	restore	%i0, %g0, %o0		! restore reg window, return dst

	! this is the last word. It may contain null bytes. store bytes
	! until n == 0. if null byte encountered, continue

.lastword:
	sub	%i4, 4, %i4		! undo counter pre-increment
	add	%i2, 4, %i2		! adjust dst for counter un-bumping

	srl	%i1, 24, %g1		! first byte
	stb	%g1, [%i2 + %i4]	! store it
	inccc	%i4			! n--
	bz	.done			! if n == 0, we're done
	sub	%g1, 1, %g1		! byte == 0 ? -1 : byte - 1
	sra	%g1, 31, %g1		! byte == 0 ? -1 : 0
	andn	%i1, %g1, %i1		! if byte == 0, start padding with null
	srl	%i1, 16, %g1		! second byte
	stb	%g1, [%i2 + %i4]	! store it
	inccc	%i4			! n--
	bz	.done			! if n == 0, we're done
	and	%g1, 0xff, %g1		! isolate byte
	sub	%g1, 1, %g1		! byte == 0 ? -1 : byte - 1
	sra	%g1, 31, %g1		! byte == 0 ? -1 : 0
	andn	%i1, %g1, %i1		! if byte == 0, start padding with null
	srl	%i1, 8, %g1		! third byte
	stb	%g1, [%i2 + %i4]	! store it
	inccc	%i4			! n--
	bz	.done			! if n == 0, we're done
	and	%g1, 0xff, %g1		! isolate byte
	sub	%g1, 1, %g1		! byte == 0 ? -1 : byte - 1
	sra	%g1, 31, %g1		! byte == 0 ? -1 : 0
	andn	%i1, %g1, %i1		! if byte == 0, start padding with null
	ba	.done			! here n must be zero, we are done
	stb	%i1, [%i2 + %i4]	! store fourth byte

.dstnotaligned:
	cmp	%g1, 2			! dst half word aligned?
	be	.storehalfword2		! yup, store half word at a time
	.empty
.storebyte:
	lduw	[%i3 + %i4], %i1	! x = src[]
	addcc	%i4, 4, %i4		! src += 4, dst += 4, n -= 4
	bcs	.lastword		! if counter wraps, last word
	andn	%i5, %i1, %g1		! ~x & 0x80808080
	sub	%i1, %l1, %l0		! x - 0x01010101
	andcc	%l0, %g1, %g0		! ((x - 0x01010101) & ~x & 0x80808080)
	bnz	.zerobyte		! end of src found, may need to pad
	add	%i2, %i4, %l0		! dst (in pointer form)
	srl	%i1, 24, %g1		! %g1<7:0> = 1st byte; half-word aligned now
	stb	%g1, [%l0]		! store first byte
	srl	%i1, 8, %g1		! %g1<15:0> = bytes 2, 3
	sth	%g1, [%l0 + 1]		! store bytes 2, 3
	ba	.storebyte		! next word
	stb	%i1, [%l0 + 3]		! store fourth byte
	nop
	nop

.storehalfword:
	lduw	[%i3 + %i4], %i1	! x = src[]
.storehalfword2:
	addcc	%i4, 4, %i4		! src += 4, dst += 4, n -= 4
	bcs	.lastword		! if counter wraps, last word
	andn	%i5, %i1, %g1		! ~x & 0x80808080
	sub	%i1, %l1, %l0		! x - 0x01010101
	andcc	%l0, %g1, %g0		! ((x -0x01010101) & ~x & 0x8080808080)
	bnz	.zerobyte		! x has zero byte, handle end cases
	add	%i2, %i4, %l0		! dst (in pointer form)
	srl	%i1, 16, %g1		! %g1<15:0> = bytes 1, 2
	sth	%g1, [%l0]		! store bytes 1, 2
	ba	.storehalfword		! next dword
	sth	%i1, [%l0 + 2]		! store bytes 3, 4

.shortcpy:
	ldub	[%o3 + %o4], %o5	! src[]
	stb	%o5, [%o2 + %o4]	! dst[] = src[]
	inccc	%o4			! src++, dst++, n--
	bz	.doneshort		! if n == 0, done
	tst	%o5			! src[] == 0 ?
	bnz,a	.shortcpy		! nope, next byte
	nop				! empty delay slot

.padbyte:
	stb	%g0, [%o2 + %o4]	! dst[] = 0
.padbyte2:
	addcc	%o4, 1, %o4		! dst++, n--
	bnz,a	.padbyte2		! if n != 0, next byte
	stb	%g0, [%o2 + %o4]	! dst[] = 0
	nop				! align label below to 16-byte boundary

.doneshort:
	retl				! return from leaf
	nop				! empty delay slot
	SET_SIZE(strncpy)
