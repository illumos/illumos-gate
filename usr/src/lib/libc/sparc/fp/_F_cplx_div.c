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
 * _F_cplx_div(z, w) returns z / w with infinities handled according
 * to C99.
 *
 * If z and w are both finite and w is nonzero, _F_cplx_div(z, w)
 * delivers the complex quotient q according to the usual formula:
 * let a = Re(z), b = Im(z), c = Re(w), and d = Im(w); then q = x +
 * I * y where x = (a * c + b * d) / r and y = (b * c - a * d) / r
 * with r = c * c + d * d.  This implementation computes intermediate
 * results in double precision to avoid premature underflow or over-
 * flow.
 *
 * If z is neither NaN nor zero and w is zero, or if z is infinite
 * and w is finite and nonzero, _F_cplx_div delivers an infinite
 * result.  If z is finite and w is infinite, _F_cplx_div delivers
 * a zero result.
 *
 * If z and w are both zero or both infinite, or if either z or w is
 * a complex NaN, _F_cplx_div delivers NaN + I * NaN.  C99 doesn't
 * specify these cases.
 *
 * This implementation can raise spurious invalid operation, inexact,
 * and division-by-zero exceptions.  C99 allows this.
 *
 * Warning: Do not attempt to "optimize" this code by removing multi-
 * plications by zero.
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
_F_cplx_div(float _Complex z, float _Complex w)
{
	float _Complex	v;
	union {
		int	i;
		float	f;
	} cc, dd;
	float		a, b, c, d;
	double		r, x, y;
	int		i, j, recalc;

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

	r = (double)c * c + (double)d * d;

	if (r == 0.0) {
		/* w is zero; multiply z by 1/Re(w) - I * Im(w) */
		c = 1.0f / c;
		i = testinff(a);
		j = testinff(b);
		if (i | j) { /* z is infinite */
			a = i;
			b = j;
		}
		((float *)&v)[0] = a * c + b * d;
		((float *)&v)[1] = b * c - a * d;
		return (v);
	}

	r = 1.0 / r;
	x = ((double)a * c + (double)b * d) * r;
	y = ((double)b * c - (double)a * d) * r;

	if (x != x && y != y) {
		/*
		 * Both x and y are NaN, so z and w can't both be finite
		 * and nonzero.  Since we handled the case w = 0 above,
		 * the only cases to check here are when one of z or w
		 * is infinite.
		 */
		r = 1.0;
		recalc = 0;
		i = testinff(a);
		j = testinff(b);
		if (i | j) { /* z is infinite */
			/* "factor out" infinity */
			a = i;
			b = j;
			r = inf.d;
			recalc = 1;
		}
		i = testinff(c);
		j = testinff(d);
		if (i | j) { /* w is infinite */
			/*
			 * "factor out" infinity, being careful to preserve
			 * signs of finite values
			 */
			cc.f = c;
			dd.f = d;
			c = i? i : ((cc.i < 0)? -0.0f : 0.0f);
			d = j? j : ((dd.i < 0)? -0.0f : 0.0f);
			r *= 0.0;
			recalc = 1;
		}
		if (recalc) {
			x = ((double)a * c + (double)b * d) * r;
			y = ((double)b * c - (double)a * d) * r;
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
