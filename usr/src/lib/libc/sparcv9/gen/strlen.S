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

	.file	"strlen.s"

/*
 * strlen(s)
 *
 * Given string s, return length (not including the terminating null).
 *
 * Fast assembler language version of the following C-program strlen
 * which represents the `standard' for the C-library.
 *
 *	size_t
 *	strlen(s)
 *	register const char *s;
 *	{
 *		register const char *s0 = s + 1;
 *
 *		while (*s++ != '\0')
 *			;
 *		return (s - s0);
 *	}
 */

#include <sys/asm_linkage.h>

	! The object of strlen is to, as quickly as possible, find the
	! null byte.  To this end, we attempt to get our string aligned
	! and then blast across it using Alan Mycroft's algorithm for
	! finding null bytes. If we are not aligned, the string is
	! checked a byte at a time until it is.  Once this occurs,
	! we can proceed word-wise across it.  Once a word with a
	! zero byte has been found, we then check the word a byte
	! at a time until we've located the zero byte, and return
	! the proper length.

	.align 32
	ENTRY(strlen)
	andcc		%o0, 3, %o4	! is src word aligned
	bz,pt		%icc, .nowalgnd
	mov		%o0, %o2

	cmp		%o4, 2		! is src half-word aligned
	be,a,pn		%icc, .s2algn
	lduh		[%o2], %o1

	ldub		[%o2], %o1
	tst		%o1		! byte zero?
	bz,pn		%icc, .done
	cmp		%o4, 3		! src is byte aligned

	be,pn		%icc, .nowalgnd
	inc		1, %o2

	lduh		[%o2], %o1

.s2algn:
	srl		%o1, 8, %o4
	tst		%o4
	bz,pn		%icc, .done
	andcc		%o1, 0xff, %g0

	bz,pn		%icc, .done
	inc		1, %o2

	inc		1, %o2

.nowalgnd:
	ld		[%o2], %o1
	sethi		%hi(0x01010101), %o4
	sethi		%hi(0x80808080), %o5
	or		%o4, %lo(0x01010101), %o4
	or		%o5, %lo(0x80808080), %o5

	andn		%o5, %o1, %o3
	sub		%o1, %o4, %g1
	andcc		%o3, %g1, %g0
	bnz,a,pn	%icc, .nullfound
	sethi		%hi(0xff000000), %o4

	ld		[%o2+4], %o1
	inc		4, %o2

.loop:						! this should be aligned to 32
	inc		4, %o2
	andn		%o5, %o1, %o3		! %o5 = ~word & 0x80808080
	sub		%o1, %o4, %g1		! %g1 = word - 0x01010101
	andcc		%o3, %g1, %g0
	bz,a,pt		%icc, .loop
	ld		[%o2], %o1

	dec		4, %o2
	sethi		%hi(0xff000000), %o4
.nullfound:
	andcc		%o1, %o4, %g0
	bz,pn		%icc, .done		! first byte zero
	srl		%o4, 8, %o4

	andcc		%o1, %o4, %g0
	bz,pn		%icc, .done		! second byte zero
	inc		1, %o2

	srl		%o4, 8, %o4
	andcc		%o1, %o4, %g0
	bz,pn		%icc, .done		! thrid byte zero
	inc		1, %o2

	inc		1, %o2			! fourth byte zero
.done:
	retl
	sub		%o2, %o0, %o0
	SET_SIZE(strlen)

