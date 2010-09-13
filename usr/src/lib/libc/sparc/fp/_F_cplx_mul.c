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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * _F_cplx_mul(z, w) returns z * w with infinities handled according
 * to C99.
 *
 * If z and w are both finite, _F_cplx_mul(z, w) delivers the complex
 * product according to the usual formula: let a = Re(z), b = Im(z),
 * c = Re(w), and d = Im(w); then _F_cplx_mul(z, w) delivers x + I * y
 * where x = a * c - b * d and y = a * d + b * c.  This implementation
 * uses double precision to form these expressions, so none of the
 * intermediate products can overflow.
 *
 * If one of z or w is infinite and the other is either finite nonzero
 * or infinite, _F_cplx_mul delivers an infinite result.  If one factor
 * is infinite and the other is zero, _F_cplx_mul delivers NaN + I * NaN.
 * C99 doesn't specify the latter case.
 *
 * C99 also doesn't specify what should happen if either z or w is a
 * complex NaN (i.e., neither finite nor infinite).  This implementation
 * delivers NaN + I * NaN in this case.
 *
 * This implementation can raise spurious invalid operation and inexact
 * exceptions.  C99 allows this.
 */

#if !defined(sparc) && !defined(__sparc)
#error This code is for SPARC only
#endif

static union {
	int	i[2];
	double	d;
} inf = {
	0x7ff00000, 0
};

/*
 * Return +1 if x is +Inf, -1 if x is -Inf, and 0 otherwise
 */
static int
testinff(float x)
{
	union {
		int	i;
		float	f;
	} xx;

	xx.f = x;
	return ((((xx.i << 1) - 0xff000000) == 0)? (1 | (xx.i >> 31)) : 0);
}

float _Complex
_F_cplx_mul(float _Complex z, float _Complex w)
{
	float _Complex	v;
	float		a, b, c, d;
	double		x, y;
	int		recalc, i, j;

	/*
	 * The following is equivalent to
	 *
	 *  a = crealf(z); b = cimagf(z);
	 *  c = crealf(w); d = cimagf(w);
	 */
	a = ((float *)&z)[0];
	b = ((float *)&z)[1];
	c = ((float *)&w)[0];
	d = ((float *)&w)[1];

	x = (double)a * c - (double)b * d;
	y = (double)a * d + (double)b * c;

	if (x != x && y != y) {
		/*
		 * Both x and y are NaN, so z and w can't both be finite.
		 * If at least one of z or w is a complex NaN, and neither
		 * is infinite, then we might as well deliver NaN + I * NaN.
		 * So the only cases to check are when one of z or w is
		 * infinite.
		 */
		recalc = 0;
		i = testinff(a);
		j = testinff(b);
		if (i | j) { /* z is infinite */
			/* "factor out" infinity */
			a = i;
			b = j;
			recalc = 1;
		}
		i = testinff(c);
		j = testinff(d);
		if (i | j) { /* w is infinite */
			/* "factor out" infinity */
			c = i;
			d = j;
			recalc = 1;
		}
		if (recalc) {
			x = inf.d * ((double)a * c - (double)b * d);
			y = inf.d * ((double)a * d + (double)b * c);
		}
	}

	/*
	 * The following is equivalent to
	 *
	 *  return x + I * y;
	 */
	((float *)&v)[0] = (float)x;
	((float *)&v)[1] = (float)y;
	return (v);
}
