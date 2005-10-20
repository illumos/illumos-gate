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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "base_conversion.h"

/*	The following should be coded as inline expansion templates.	*/

/*
 * Fundamental utilities that multiply two shorts into a unsigned long, add
 * carry, compute quotient and remainder in underlying base, and return
 * quo<<16 | rem as  a unsigned long.
 */

/*
 * C compilers tend to generate bad code - forcing full unsigned long by
 * unsigned long multiplies when what is really wanted is the unsigned long
 * product of half-long operands. Similarly the quotient and remainder are
 * all half-long. So these functions should really be implemented by inline
 * expansion templates.
 */

/* p = x * y + c ; return p */
unsigned long
_umac(_BIG_FLOAT_DIGIT x, _BIG_FLOAT_DIGIT y, unsigned long c)
{
	return (x * (unsigned long) y + c);
}

/* p = x + c ; return (p/10000 << 16 | p%10000) */
unsigned long
_carry_in_b10000(_BIG_FLOAT_DIGIT x, long unsigned c)		
{
	unsigned long   p = x + c ;

	return ((p / 10000) << 16) | (p % 10000);
}

void
_carry_propagate_two(unsigned long carry, _BIG_FLOAT_DIGIT *psignificand)
{
	/*
	 * Propagate carries in a base-2**16 significand.
	 */

	long unsigned   p;
	int             j;

	j = 0;
	while (carry != 0) {
	p = _carry_in_b65536(psignificand[j],carry);
		psignificand[j++] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
}

void
_carry_propagate_ten(unsigned long carry, _BIG_FLOAT_DIGIT *psignificand)
{
	/*
	 * Propagate carries in a base-10**4 significand.
	 */

	int             j;
	unsigned long p;

	j = 0;
	while (carry != 0) {
	p = _carry_in_b10000(psignificand[j],carry);
		psignificand[j++] = (_BIG_FLOAT_DIGIT) (p & 0xffff);
		carry = p >> 16;
	}
}
