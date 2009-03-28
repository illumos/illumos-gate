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

	/*
	 * There are two key optimizations in the routine below.
	 * First, all memory accesses are 8 bytes wide.  The time
	 * for long strings is dominated by the latency of load
	 * instructions in the inner loop, and going 8 bytes at
	 * a time means 1/8th as much latency.
	 *
	 * Scanning an 8 byte word for a '\0' is made fast by
	 * this formula (due to Alan Mycroft):
	 *     ~x & 0x808080808080 & (x - 0x0101010101010101)
	 * The result of this formula is non-zero iff there's
	 * a '\0' somewhere in x.
	 *
	 * Second, the cost of short strings is dominated by the
	 * cost of figuring out which byte out of the last 8
	 * contained the '\0' that terminated the string.  We use
	 * properties of the formula above to convert scanning the
	 * word for '\0' into a single LZD instruction.
	 */
	.align	64
	.skip	4*4	! force .findnull to align to 64 bytes
	ENTRY_NP(strlen)
	and	%o0, 7, %o3			! off = addr & 7
	sethi	%hi(0x01010101), %o4		! 0x01010000

	sub	%g0, %o3, %o2			! count = -off
	or	%o4, %lo(0x01010101), %o4	! 0x01010101

	ldx	[%o0 + %o2], %o1		! val = *(addr + count)
	sllx	%o4, 32, %o5			! 0x01010101 << 32

	mov	-1, %g1				! mask = -1
	sllx	%o3, 3, %o3			! shift = off * 8

	or	%o4, %o5, %o4			! 0x0101010101010101
	srlx	%g1, %o3, %g1			! -1 >> ((addr & 7) * 8)

	sllx	%o4, 7, %o5			! 0x8080808080808080
	orn	%o1, %g1, %o1			! val |= ~mask
.strlen_findnull:
	!! %o0 - base address
	!! %o1 - xword from memory
	!! %o2 - index
	!! %o3 - result of test for '\0'
	!! %o4 - constant 0x0101.0101.0101.0101
	!! %o5 - constant 0x8080.8080.8080.8080
	!! %g1 - scratch
	andn	%o5, %o1, %o3		! ~val & 0x80
	sub	%o1, %o4, %g1		! val - 0x01
	andcc	%o3, %g1, %o3		! ~val & 0x80 & (val - 0x01)
	inc	8, %o2
	bz,a,pt	%xcc, .strlen_findnull
	  ldx	[%o0 + %o2], %o1

	/*
	 * The result of Mycroft's formula is a pattern of 0x80 and
	 * 0x00 bytes.  There's a 0x80 at every byte position where
	 * there was a '\0' character, but a string of 0x01 bytes
	 * immediately preceding a '\0' becomes a corresponding
	 * string of 0x80 bytes.  (e.g. 0x0101010101010100 becomes
	 * 0x8080808080808080).  We need one final step to discount
	 * any leading 0x01 bytes, and then LZD can tell us how many
	 * characters there were before the terminating '\0'.
	 */
	!! %o1 - last data word
	!! %o2 - length+8, plus 1-8 extra
	!! %o3 - xword with 0x80 for each 0x00 byte and leading 0x01
	sub	%o2, 8, %o2		! subtract off '\0' and last 8
	srlx	%o3, 7, %o3		! shift 0x80 -> 0x01
	andn	%o3, %o1, %o3		! mask off leading 0x01 bytes
	lzd	%o3, %o3		! 7, 15, ... 63
	srlx	%o3, 3, %o3		! 0 ... 7

	retl
	add	%o2, %o3, %o0		! add back bytes before '\0'

	SET_SIZE(strlen)
