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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * The ascii_strcasecmp() function is a case insensitive versions of strcmp().
 * It assumes the ASCII character set and ignores differences in case
 * when comparing lower and upper case characters. In other words, it
 * behaves as if both strings had been converted to lower case using
 * tolower() in the "C" locale on each byte, and the results had then
 * been compared using strcmp().
 *
 * The assembly code below is an optimized version of the following C
 * reference:
 *
 * static const char charmap[] = {
 *	'\000', '\001', '\002', '\003', '\004', '\005', '\006', '\007',
 *	'\010', '\011', '\012', '\013', '\014', '\015', '\016', '\017',
 *	'\020', '\021', '\022', '\023', '\024', '\025', '\026', '\027',
 *	'\030', '\031', '\032', '\033', '\034', '\035', '\036', '\037',
 *	'\040', '\041', '\042', '\043', '\044', '\045', '\046', '\047',
 *	'\050', '\051', '\052', '\053', '\054', '\055', '\056', '\057',
 *	'\060', '\061', '\062', '\063', '\064', '\065', '\066', '\067',
 *	'\070', '\071', '\072', '\073', '\074', '\075', '\076', '\077',
 *	'\100', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
 *	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
 *	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
 *	'\170', '\171', '\172', '\133', '\134', '\135', '\136', '\137',
 *	'\140', '\141', '\142', '\143', '\144', '\145', '\146', '\147',
 *	'\150', '\151', '\152', '\153', '\154', '\155', '\156', '\157',
 *	'\160', '\161', '\162', '\163', '\164', '\165', '\166', '\167',
 *	'\170', '\171', '\172', '\173', '\174', '\175', '\176', '\177',
 *	'\200', '\201', '\202', '\203', '\204', '\205', '\206', '\207',
 *	'\210', '\211', '\212', '\213', '\214', '\215', '\216', '\217',
 *	'\220', '\221', '\222', '\223', '\224', '\225', '\226', '\227',
 *	'\230', '\231', '\232', '\233', '\234', '\235', '\236', '\237',
 *	'\240', '\241', '\242', '\243', '\244', '\245', '\246', '\247',
 *	'\250', '\251', '\252', '\253', '\254', '\255', '\256', '\257',
 *	'\260', '\261', '\262', '\263', '\264', '\265', '\266', '\267',
 *	'\270', '\271', '\272', '\273', '\274', '\275', '\276', '\277',
 *	'\300', '\301', '\302', '\303', '\304', '\305', '\306', '\307',
 *	'\310', '\311', '\312', '\313', '\314', '\315', '\316', '\317',
 *	'\320', '\321', '\322', '\323', '\324', '\325', '\326', '\327',
 *	'\330', '\331', '\332', '\333', '\334', '\335', '\336', '\337',
 *	'\340', '\341', '\342', '\343', '\344', '\345', '\346', '\347',
 *	'\350', '\351', '\352', '\353', '\354', '\355', '\356', '\357',
 *	'\360', '\361', '\362', '\363', '\364', '\365', '\366', '\367',
 *	'\370', '\371', '\372', '\373', '\374', '\375', '\376', '\377',
 * };
 *
 * int
 * ascii_strcasecmp(const char *s1, const char *s2)
 * {
 *	const unsigned char	*cm = (const unsigned char *)charmap;
 *	const unsigned char	*us1 = (const unsigned char *)s1;
 *	const unsigned char	*us2 = (const unsigned char *)s2;
 *
 *	while (cm[*us1] == cm[*us2++])
 *		if (*us1++ == '\0')
 *			return (0);
 *	return (cm[*us1] - cm[*(us2 - 1)]);
 * }
 *
 * The following algorithm, from a 1987 news posting by Alan Mycroft, is
 * used for finding null bytes in a word:
 *
 * #define has_null(word) ((word - 0x01010101) & (~word & 0x80808080))
 *
 * The following algorithm is used for a wordwise tolower() operation:
 *
 * unsigned int
 * parallel_tolower (unsigned int x)
 * {
 *	unsigned int p;
 *	unsigned int q;
 *
 *	unsigned int m1 = 0x80808080;
 *	unsigned int m2 = 0x3f3f3f3f;
 *	unsigned int m3 = 0x25252525;
 *
 *	q = x & ~m1;// newb = byte & 0x7F
 *	p = q + m2; // newb > 0x5A --> MSB set
 *	q = q + m3; // newb < 0x41 --> MSB clear
 *	p = p & ~q; // newb > 0x40 && newb < 0x5B --> MSB set
 *	q = m1 & ~x;//  byte < 0x80 --> 0x80
 *	q = p & q;  // newb > 0x40 && newb < 0x5B && byte < 0x80 -> 0x80,else 0
 *	q = q >> 2; // newb > 0x40 && newb < 0x5B && byte < 0x80 -> 0x20,else 0
 *	return (x + q); // translate uppercase characters to lowercase
 * }
 *
 * Both algorithms have been tested exhaustively for all possible 2^32 inputs.
 */

#include <sys/asm_linkage.h>

	! The first part of this algorithm walks through the beginning of
	! both strings a byte at a time until the source ptr is  aligned to
	! a word boundary. During these steps, the bytes are translated to
	! lower-case if they are upper-case, and are checked against
	! the source string.

	ENTRY(ascii_strcasecmp)

	.align 32

	save	%sp, -SA(WINDOWSIZE), %sp
	subcc	%i0, %i1, %i2		! s1 == s2 ?
	bz,pn	%ncc, .stringsequal	! yup, done, strings equal
	andcc	%i0, 3, %i3		! s1 word-aligned ?
	bz,pn	%ncc, .s1aligned1	! yup
	sethi	%hi(0x80808080), %i4	! start loading Mycroft's magic1

	ldub	[%i1 + %i2], %i0	! s1[0]
	ldub	[%i1], %g1		! s2[0]
	sub	%i0, 'A', %l0		! transform for faster uppercase check
	sub	%g1, 'A', %l1		! transform for faster uppercase check
	cmp	%l0, ('Z' - 'A')	! s1[0] uppercase?
	bleu,a	.noxlate11		! yes
	add	%i0, ('a' - 'A'), %i0	! s1[0] = tolower(s1[0])
.noxlate11:
	cmp	%l1, ('Z' - 'A')	! s2[0] uppercase?
	bleu,a	.noxlate12		! yes
	add	%g1, ('a' - 'A'), %g1	! s2[0] = tolower(s2[0])
.noxlate12:
	subcc	%i0, %g1, %i0		! tolower(s1[0]) != tolower(s2[0]) ?
	bne,pn	%ncc, .done		! yup, done
	inc	%i1			! s1++, s2++
	addcc	%i0, %g1, %i0		! s1[0] == 0 ?
	bz,pn	%ncc, .done		! yup, done, strings equal
	cmp	%i3, 3			! s1 aligned now?
	bz	%ncc, .s1aligned2	! yup
	sethi	%hi(0x01010101), %i5	! start loading Mycroft's magic2

	ldub	[%i1 + %i2], %i0	! s1[1]
	ldub	[%i1], %g1		! s2[1]
	sub	%i0, 'A', %l0		! transform for faster uppercase check
	sub	%g1, 'A', %l1		! transform for faster uppercase check
	cmp	%l0, ('Z' - 'A')	! s1[1] uppercase?
	bleu,a	.noxlate21		! yes
	add	%i0, ('a' - 'A'), %i0	! s1[1] = tolower(s1[1])
.noxlate21:
	cmp	%l1, ('Z' - 'A')	! s2[1] uppercase?
	bleu,a	.noxlate22		! yes
	add	%g1, ('a' - 'A'), %g1	! s2[1] = tolower(s2[1])
.noxlate22:
	subcc	%i0, %g1, %i0		! tolower(s1[1]) != tolower(s2[1]) ?
	bne,pn	%ncc, .done		! yup, done
	inc	%i1			! s1++, s2++
	addcc	%i0, %g1, %i0		! s1[1] == 0 ?
	bz,pn	%ncc, .done		! yup, done, strings equal
	cmp	%i3, 2			! s1 aligned now?
	bz	%ncc, .s1aligned3	! yup
	or	%i4, %lo(0x80808080),%i4! finish loading Mycroft's magic1

	ldub	[%i1 + %i2], %i0	! s1[2]
	ldub	[%i1], %g1		! s2[2]
	sub	%i0, 'A', %l0		! transform for faster uppercase check
	sub	%g1, 'A', %l1		! transform for faster uppercase check
	cmp	%l0, ('Z' - 'A')	! s1[2] uppercase?
	bleu,a	.noxlate31		! yes
	add	%i0, ('a' - 'A'), %i0	! s1[2] = tolower(s1[2])
.noxlate31:
	cmp	%l1, ('Z' - 'A')	! s2[2] uppercase?
	bleu,a	.noxlate32		! yes
	add	%g1, ('a' - 'A'), %g1	! s2[2] = tolower(s2[2])
.noxlate32:
	subcc	%i0, %g1, %i0		! tolower(s1[2]) != tolower(s2[2]) ?
	bne,pn	%ncc, .done		! yup, done
	inc	%i1			! s1++, s2++
	addcc	%i0, %g1, %i0		! s1[2] == 0 ?
	bz,pn	%ncc, .done		! yup, done, strings equal
	or	%i5, %lo(0x01010101),%i5! finish loading Mycroft's magic2
	ba	.s1aligned4		! s1 aligned now
	andcc	%i1, 3, %i3		! s2 word-aligned ?

	! Here, we initialize our checks for a zero byte and decide
	! whether or not we can optimize further if we're fortunate
	! enough to have a word aligned desintation

.s1aligned1:
	sethi	%hi(0x01010101), %i5	! start loading Mycroft's magic2
.s1aligned2:
	or	%i4, %lo(0x80808080),%i4! finish loading Mycroft's magic1
.s1aligned3:
	or	%i5, %lo(0x01010101),%i5! finish loading Mycroft's magic2
	andcc	%i1, 3, %i3		! s2 word aligned ?
.s1aligned4:
	sethi	%hi(0x3f3f3f3f), %l2	! load m2 for parallel tolower()
	sethi	%hi(0x25252525), %l3	! load m3 for parallel tolower()
	or 	%l2, %lo(0x3f3f3f3f),%l2! finish loading m2
	bz	.word4			! yup, s2 word-aligned
	or 	%l3, %lo(0x25252525),%l3! finish loading m3

	add	%i2, %i3, %i2		! start adjusting offset s1-s2
	sll     %i3, 3, %l6    		! shift factor for left shifts
	andn	%i1, 3, %i1		! round s1 pointer down to next word
	sub	%g0, %l6, %l7		! shift factor for right shifts
	orn	%i3, %g0, %i3		! generate all ones
	lduw	[%i1], %i0		! new lower word from s2
	srl	%i3, %l6, %i3		! mask for fixing up bytes
	sll	%i0, %l6, %g1		! partial unaligned word from s2
	orn	%i0, %i3, %i0		! force start bytes to non-zero
	nop				! pad to align loop to 16-byte boundary
	nop				! pad to align loop to 16-byte boundary

	! This is the comparision procedure used if the destination is not
	! word aligned, if it is, we use word4 & cmp4

.cmp:
	andn	%i4, %i0, %l4		! ~word & 0x80808080
	sub	%i0, %i5, %l5		! word - 0x01010101
	andcc	%l5, %l4, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,a,pt	%ncc, .doload		! null byte in previous aligned s2 word
	lduw	[%i1 + 4], %i0		! load next aligned word from s2
.doload:
	srl	%i0, %l7, %i3		! byte 1 from new aligned word from s2
	or	%g1, %i3, %g1		! merge to get unaligned word from s2
	lduw	[%i1 + %i2], %i3	! x1 = word from s1
	andn	%i3, %i4, %l0		! q1 = x1 & ~m1
	andn	%g1, %i4, %l4		! q2 = x2 & ~m1
	add	%l0, %l2, %l1		! p1 = q1 + m2
	add	%l4, %l2, %l5		! p2 = q2 + m2
	add	%l0, %l3, %l0		! q1 = q1 + m3
	add	%l4, %l3, %l4		! q2 = q2 + m3
	andn	%l1, %l0, %l1		! p1 = p1 & ~q1
	andn	%l5, %l4, %l5		! p2 = p2 & ~q2
	andn	%i4, %i3, %l0		! q1 = m1 & ~x1
	andn	%i4, %g1, %l4		! q2 = m1 & ~x2
	and	%l0, %l1, %l0		! q1 = p1 & q1
	and	%l4, %l5, %l4		! q2 = p2 & q2
	srl	%l0, 2, %l0		! q1 = q1 >> 2
	srl	%l4, 2, %l4		! q2 = q2 >> 2
	add	%l0, %i3, %i3		! lowercase word from s1
	add	%l4, %g1, %g1		! lowercase word from s2
	cmp	%i3, %g1		! tolower(*s1) != tolower(*s2) ?
	bne	%icc, .wordsdiffer	! yup, now find byte that is different
	add	%i1, 4, %i1		! s1+=4, s2+=4
	andn	%i4, %i3, %l4		! ~word & 0x80808080
	sub	%i3, %i5, %l5		! word - 0x01010101
	andcc	%l5, %l4, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,pt	%ncc, .cmp		! no null-byte in s1 yet
	sll	%i0, %l6, %g1		! partial unaligned word from s2

	! words are equal but the end of s1 has been reached
	! this means the strings must be equal
.stringsequal:
	ret				! return
	restore	%g0, %g0, %o0		! return 0, i.e. strings are equal
	nop				! pad


	! we have a word aligned source and destination!  This means
	! things get to go fast!

.word4:
	lduw	[%i1 + %i2], %i3	! x1 = word from s1

.cmp4:
	andn	%i3, %i4, %l0		! q1 = x1 & ~m1
	lduw	[%i1], %g1		! x2 = word from s2
	andn	%g1, %i4, %l4		! q2 = x2 & ~m1
	add	%l0, %l2, %l1		! p1 = q1 + m2
	add	%l4, %l2, %l5		! p2 = q2 + m2
	add	%l0, %l3, %l0		! q1 = q1 + m3
	add	%l4, %l3, %l4		! q2 = q2 + m3
	andn	%l1, %l0, %l1		! p1 = p1 & ~q1
	andn	%l5, %l4, %l5		! p2 = p2 & ~q2
	andn	%i4, %i3, %l0		! q1 = m1 & ~x1
	andn	%i4, %g1, %l4		! q2 = m1 & ~x2
	and	%l0, %l1, %l0		! q1 = p1 & q1
	and	%l4, %l5, %l4		! q2 = p2 & q2
	srl	%l0, 2, %l0		! q1 = q1 >> 2
	srl	%l4, 2, %l4		! q2 = q2 >> 2
	add	%l0, %i3, %i3		! lowercase word from s1
	add	%l4, %g1, %g1		! lowercase word from s2
	cmp	%i3, %g1		! tolower(*s1) != tolower(*s2) ?
	bne,pn	%icc, .wordsdiffer	! yup, now find mismatching character
	add	%i1, 4, %i1		! s1+=4, s2+=4
	andn	%i4, %i3, %l4		! ~word & 0x80808080
	sub	%i3, %i5, %l5		! word - 0x01010101
	andcc	%l5, %l4, %g0		! (word - 0x01010101) & ~word & 0x80808080
	bz,a,pt	%icc, .cmp4		! no null-byte in s1 yet
	lduw	[%i1 + %i2], %i3	! load word from s1

	! words are equal but the end of s1 has been reached
	! this means the strings must be equal
.stringsequal4:
	ret				! return
	restore	%g0, %g0, %o0		! return 0, i.e. strings are equal

.wordsdiffer:
	srl	%g1, 24, %i2		! first byte of mismatching word in s2
	srl	%i3, 24, %i1		! first byte of mismatching word in s1
	subcc	%i1, %i2, %i0		! *s1-*s2
	bnz,pn	%ncc, .done		! bytes differ, return difference
	srl	%g1, 16, %i2		! second byte of mismatching word in s2
	andcc	%i1, 0xff, %i0		! *s1 == 0 ?
	bz,pn	%ncc, .done		! yup

	! we know byte 1 is equal, so can compare bytes 1,2 as a group

	srl	%i3, 16, %i1		! second byte of mismatching word in s1
	subcc	%i1, %i2, %i0		! *s1-*s2
	bnz,pn	%ncc, .done		! bytes differ, return difference
	srl	%g1, 8, %i2		! third byte of mismatching word in s2
	andcc	%i1, 0xff, %i0		! *s1 == 0 ?
	bz,pn	%ncc, .done		! yup

	! we know bytes 1, 2 are equal, so can compare bytes 1,2,3 as a group

	srl	%i3, 8, %i1		! third byte of mismatching word in s1
	subcc	%i1, %i2, %i0		! *s1-*s2
	bnz,pn	%ncc, .done		! bytes differ, return difference
	andcc	%i1, 0xff, %g0		! *s1 == 0 ?
	bz,pn	%ncc, .stringsequal	! yup

	! we know bytes 1,2,3 are equal, so can compare bytes 1,2,3,4 as group

	subcc	%i3, %g1, %i0		! *s1-*s2
	bz,a	.done			! bytes differ, return difference
	andcc	%i3, 0xff, %i0		! *s1 == 0 ?

.done:
	ret				! return
	restore	%i0, %g0, %o0		! return tolower(*s1) - tolower(*s2)

	SET_SIZE(ascii_strcasecmp)
