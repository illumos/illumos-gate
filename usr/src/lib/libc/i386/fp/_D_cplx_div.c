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
 * _D_cplx_div(z, w) returns z / w with infinities handled according
 * to C99.
 *
 * If z and w are both finite and w is nonzero, _D_cplx_div(z, w)
 * delivers the complex quotient q according to the usual formula:
 * let a = Re(z), b = Im(z), c = Re(w), and d = Im(w); then q = x +
 * I * y where x = (a * c + b * d) / r and y = (b * c - a * d) / r
 * with r = c * c + d * d.  This implementation computes intermediate
 * results in extended precision to avoid premature underflow or over-
 * flow.
 *
 * If z is neither NaN nor zero and w is zero, or if z is infinite
 * and w is finite and nonzero, _D_cplx_div delivers an infinite
 * result.  If z is finite and w is infinite, _D_cplx_div delivers
 * a zero result.
 *
 * If z and w are both zero or both infinite, or if either z or w is
 * a complex NaN, _D_cplx_div delivers NaN + I * NaN.  C99 doesn't
 * specify these cases.
 *
 * This implementation can raise spurious invalid operation, inexact,
 * and division-by-zero exceptions.  C99 allows this.
 *
 * Warning: Do not attempt to "optimize" this code by removing multi-
 * plications by zero.
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
testinf(double x)
{
	union {
		int	i[2];
		double	d;
	} xx;

	xx.d = x;
	return (((((xx.i[1] << 1) - 0xffe00000) | xx.i[0]) == 0)?
		(1 | (xx.i[1] >> 31)) : 0);
}

double _Complex
_D_cplx_div(double _Complex z, double _Complex w)
{
	double _Complex	v;
	union {
		int	i[2];
		double	d;
	} cc, dd;
	double		a, b, c, d;
	long double	r, x, y;
	int		i, j, recalc;

	/*
	 * The following is equivalent to
	 *
	 *  a = creal(z); b = cimag(z);
	 *  c = creal(w); d = cimag(w);
	 */
	/* LINTED alignment */
	a = ((double *)&z)[0];
	/* LINTED alignment */
	b = ((double *)&z)[1];
	/* LINTED alignment */
	c = ((double *)&w)[0];
	/* LINTED alignment */
	d = ((double *)&w)[1];

	r = (long double)c * c + (long double)d * d;

	if (r == 0.0f) {
		/* w is zero; multiply z by 1/Re(w) - I * Im(w) */
		c = 1.0f / c;
		i = testinf(a);
		j = testinf(b);
		if (i | j) { /* z is infinite */
			a = i;
			b = j;
		}
		/* LINTED alignment */
		((double *)&v)[0] = a * c + b * d;
		/* LINTED alignment */
		((double *)&v)[1] = b * c - a * d;
		return (v);
	}

	r = 1.0f / r;
	x = ((long double)a * c + (long double)b * d) * r;
	y = ((long double)b * c - (long double)a * d) * r;

	if (x != x && y != y) {
		/*
		 * Both x and y are NaN, so z and w can't both be finite
		 * and nonzero.  Since we handled the case w = 0 above,
		 * the only cases to check here are when one of z or w
		 * is infinite.
		 */
		r = 1.0f;
		recalc = 0;
		i = testinf(a);
		j = testinf(b);
		if (i | j) { /* z is infinite */
			/* "factor out" infinity */
			a = i;
			b = j;
			r = inf.f;
			recalc = 1;
		}
		i = testinf(c);
		j = testinf(d);
		if (i | j) { /* w is infinite */
			/*
			 * "factor out" infinity, being careful to preserve
			 * signs of finite values
			 */
			cc.d = c;
			dd.d = d;
			c = i? i : ((cc.i[1] < 0)? -0.0f : 0.0f);
			d = j? j : ((dd.i[1] < 0)? -0.0f : 0.0f);
			r *= 0.0f;
			recalc = 1;
		}
		if (recalc) {
			x = ((long double)a * c + (long double)b * d) * r;
			y = ((long double)b * c - (long double)a * d) * r;
		}
	}

	/*
	 * The following is equivalent to
	 *
	 *  return x + I * y;
	 */
	/* LINTED alignment */
	((double *)&v)[0] = (double)x;
	/* LINTED alignment */
	((double *)&v)[1] = (double)y;
	return (v);
}
