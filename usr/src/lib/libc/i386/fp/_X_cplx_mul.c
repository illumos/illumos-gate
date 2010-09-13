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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * _X_cplx_mul(z, w) returns z * w with infinities handled according
 * to C99.
 *
 * If z and w are both finite, _X_cplx_mul(z, w) delivers the complex
 * product according to the usual formula: let a = Re(z), b = Im(z),
 * c = Re(w), and d = Im(w); then _X_cplx_mul(z, w) delivers x + I * y
 * where x = a * c - b * d and y = a * d + b * c.  Note that if both
 * ac and bd overflow, then at least one of ad or bc must also over-
 * flow, and vice versa, so that if one component of the product is
 * NaN, the other is infinite.  (Such a value is considered infinite
 * according to C99.)
 *
 * If one of z or w is infinite and the other is either finite nonzero
 * or infinite, _X_cplx_mul delivers an infinite result.  If one factor
 * is infinite and the other is zero, _X_cplx_mul delivers NaN + I * NaN.
 * C99 doesn't specify the latter case.
 *
 * C99 also doesn't specify what should happen if either z or w is a
 * complex NaN (i.e., neither finite nor infinite).  This implementation
 * delivers NaN + I * NaN in this case.
 *
 * This implementation can raise spurious underflow, overflow, invalid
 * operation, and inexact exceptions.  C99 allows this.
 */

#if !defined(i386) && !defined(__i386) && !defined(__amd64)
#error This code is for x86 only
#endif

static union {
	int	i;
	float	f;
} inf = {
	0x7f800000
};

/*
 * Return +1 if x is +Inf, -1 if x is -Inf, and 0 otherwise
 */
static int
testinfl(long double x)
{
	union {
		int		i[3];
		long double	e;
	} xx;

	xx.e = x;
	if ((xx.i[2] & 0x7fff) != 0x7fff || ((xx.i[1] << 1) | xx.i[0]) != 0)
		return (0);
	return (1 | ((xx.i[2] << 16) >> 31));
}

long double _Complex
_X_cplx_mul(long double _Complex z, long double _Complex w)
{
	long double _Complex	v;
	long double		a, b, c, d, x, y;
	int			recalc, i, j;

	/*
	 * The following is equivalent to
	 *
	 *  a = creall(z); b = cimagl(z);
	 *  c = creall(w); d = cimagl(w);
	 */
	a = ((long double *)&z)[0];
	b = ((long double *)&z)[1];
	c = ((long double *)&w)[0];
	d = ((long double *)&w)[1];

	x = a * c - b * d;
	y = a * d + b * c;

	if (x != x && y != y) {
		/*
		 * Both x and y are NaN, so z and w can't both be finite.
		 * If at least one of z or w is a complex NaN, and neither
		 * is infinite, then we might as well deliver NaN + I * NaN.
		 * So the only cases to check are when one of z or w is
		 * infinite.
		 */
		recalc = 0;
		i = testinfl(a);
		j = testinfl(b);
		if (i | j) { /* z is infinite */
			/* "factor out" infinity */
			a = i;
			b = j;
			recalc = 1;
		}
		i = testinfl(c);
		j = testinfl(d);
		if (i | j) { /* w is infinite */
			/* "factor out" infinity */
			c = i;
			d = j;
			recalc = 1;
		}
		if (recalc) {
			x = inf.f * (a * c - b * d);
			y = inf.f * (a * d + b * c);
		}
	}

	/*
	 * The following is equivalent to
	 *
	 *  return x + I * y;
	 */
	((long double *)&v)[0] = x;
	((long double *)&v)[1] = y;
	return (v);
}
