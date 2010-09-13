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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "base_conversion.h"

/* conversion from hex chars to hex values */
#define	HEXVAL(c)	(('0' <= c && c <= '9')? c - '0' : \
			10 + (('a' <= c && c <= 'f')? c - 'a' : c - 'A'))

/*
 * Convert a hexadecimal record in *pd to unpacked form in *pu.
 *
 * Up to 30 hexadecimal digits from pd->ds are converted to a binary
 * value in px->significand, which is then normalized so that the most
 * significant bit is 1.  If there are additional, unused digits in
 * pd->ds, the least significant bit of px->significand will be set.
 */
static void
__hex_to_unpacked(decimal_record *pd, unpacked *pu)
{
	int	i, n;

	pu->sign = pd->sign;
	pu->fpclass = pd->fpclass;

	/*
	 * Adjust the (base two) exponent to reflect the fact that the
	 * radix point in *pd lies to the right of the last (base sixteen)
	 * digit while the radix point in *pu lies to the right of the
	 * most significant bit.
	 */
	pu->exponent = pd->exponent + (pd->ndigits << 2) - 1;

	/* fill in the significand */
	for (i = 0; i < 5; i++)
		pu->significand[i] = 0;

	n = pd->ndigits;
	if (n > 30)
		n = 30;
	for (i = 0; i < n; i++) {
		pu->significand[i >> 3] |= HEXVAL(pd->ds[i]) <<
		    ((7 - (i & 7)) << 2);
	}

	/* sanity check */
	if (pu->significand[0] == 0) {
		pu->fpclass = fp_zero;
		return;
	}

	/* normalize so the most significant bit is set */
	while (pu->significand[0] < 0x80000000u) {
		pu->significand[0] = (pu->significand[0] << 1) |
		    (pu->significand[1] >> 31);
		pu->significand[1] = (pu->significand[1] << 1) |
		    (pu->significand[2] >> 31);
		pu->significand[2] = (pu->significand[2] << 1) |
		    (pu->significand[3] >> 31);
		pu->significand[3] <<= 1;
		pu->exponent--;
	}

	/* if there are any unused digits, set a sticky bit */
	if (pd->ndigits > 30 || pd->more)
		pu->significand[4] = 1;
}

/*
 * The following routines convert the hexadecimal value encoded in the
 * decimal record *pd to a floating point value *px observing the round-
 * ing mode specified in rd and passing back any exceptions raised via
 * *ps.
 *
 * These routines assume pd->fpclass is either fp_zero or fp_normal.
 * If pd->fpclass is fp_zero, *px is set to zero with the sign indicated
 * by pd->sign and no exceptions are raised.  Otherwise, pd->ds must
 * contain a string of hexadecimal digits of length pd->ndigits > 0, and
 * the first digit must be nonzero.  Let m be the integer represented by
 * this string.  Then *px is set to a correctly rounded approximation to
 *
 *  (-1)^(pd->sign) * m * 2^(pd->exponent)
 *
 * with inexact, underflow, and/or overflow raised as appropriate.
 */

void
__hex_to_single(decimal_record *pd, enum fp_direction_type rd, single *px,
    fp_exception_field_type *ps)
{
	single_equivalence	kluge;
	unpacked		u;

	*ps = 0;
	if (pd->fpclass == fp_zero) {
		kluge.f.msw.sign = pd->sign? 1 : 0;
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		*px = kluge.x;
	} else {
		__hex_to_unpacked(pd, &u);
		__pack_single(&u, px, rd, ps);
		if (*ps != 0)
			__base_conversion_set_exception(*ps);
	}
}

void
__hex_to_double(decimal_record *pd, enum fp_direction_type rd, double *px,
    fp_exception_field_type *ps)
{
	double_equivalence	kluge;
	unpacked		u;

	*ps = 0;
	if (pd->fpclass == fp_zero) {
		kluge.f.msw.sign = pd->sign? 1 : 0;
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		*px = kluge.x;
	} else {
		__hex_to_unpacked(pd, &u);
		__pack_double(&u, px, rd, ps);
		if (*ps != 0)
			__base_conversion_set_exception(*ps);
	}
}

#if defined(__sparc)

void
__hex_to_quadruple(decimal_record *pd, enum fp_direction_type rd, quadruple *px,
    fp_exception_field_type *ps)
{
	quadruple_equivalence	kluge;
	unpacked		u;

	*ps = 0;
	if (pd->fpclass == fp_zero) {
		kluge.f.msw.sign = pd->sign? 1 : 0;
		kluge.f.msw.exponent = 0;
		kluge.f.msw.significand = 0;
		kluge.f.significand2 = 0;
		kluge.f.significand3 = 0;
		kluge.f.significand4 = 0;
		*px = kluge.x;
	} else {
		__hex_to_unpacked(pd, &u);
		__pack_quadruple(&u, px, rd, ps);
		if (*ps != 0)
			__base_conversion_set_exception(*ps);
	}
}

#elif defined(__i386) || defined(__amd64)

void
__hex_to_extended(decimal_record *pd, enum fp_direction_type rd, extended *px,
    fp_exception_field_type *ps)
{
	extended_equivalence	kluge;
	unpacked		u;

	*ps = 0;
	if (pd->fpclass == fp_zero) {
		kluge.f.msw.sign = pd->sign? 1 : 0;
		kluge.f.msw.exponent = 0;
		kluge.f.significand = 0;
		kluge.f.significand2 = 0;
		(*px)[0] = kluge.x[0];
		(*px)[1] = kluge.x[1];
		(*px)[2] = kluge.x[2];
	} else {
		__hex_to_unpacked(pd, &u);
		__pack_extended(&u, px, rd, ps);
		if (*ps != 0)
			__base_conversion_set_exception(*ps);
	}
}

#else
#error Unknown architecture
#endif
