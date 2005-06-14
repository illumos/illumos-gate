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
 * _X_cplx_div(z, w) returns z / w with infinities handled according
 * to C99.
 *
 * If z and w are both finite and w is nonzero, _X_cplx_div delivers
 * the complex quotient q according to the usual formula: let a =
 * Re(z), b = Im(z), c = Re(w), and d = Im(w); then q = x + I * y
 * where x = (a * c + b * d) / r and y = (b * c - a * d) / r with
 * r = c * c + d * d.  This implementation scales to avoid premature
 * underflow or overflow.
 *
 * If z is neither NaN nor zero and w is zero, or if z is infinite
 * and w is finite and nonzero, _X_cplx_div delivers an infinite
 * result.  If z is finite and w is infinite, _X_cplx_div delivers
 * a zero result.
 *
 * If z and w are both zero or both infinite, or if either z or w is
 * a complex NaN, _X_cplx_div delivers NaN + I * NaN.  C99 doesn't
 * specify these cases.
 *
 * This implementation can raise spurious underflow, overflow, in-
 * valid operation, inexact, and division-by-zero exceptions.  C99
 * allows this.
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
_X_cplx_div(long double _Complex z, long double _Complex w)
{
	long double _Complex	v;
	union {
		int		i[3];
		long double	e;
	} aa, bb, cc, dd, ss;
	long double	a, b, c, d, r;
	int		ea, eb, ec, ed, ez, ew, es, i, j;

	/*
	 * The following is equivalent to
	 *
	 *  a = creall(*z); b = cimagl(*z);
	 *  c = creall(*w); d = cimagl(*w);
	 */
	a = ((long double *)&z)[0];
	b = ((long double *)&z)[1];
	c = ((long double *)&w)[0];
	d = ((long double *)&w)[1];

	/* extract exponents to estimate |z| and |w| */
	aa.e = a;
	bb.e = b;
	ea = aa.i[2] & 0x7fff;
	eb = bb.i[2] & 0x7fff;
	ez = (ea > eb)? ea : eb;

	cc.e = c;
	dd.e = d;
	ec = cc.i[2] & 0x7fff;
	ed = dd.i[2] & 0x7fff;
	ew = (ec > ed)? ec : ed;

	/* check for special cases */
	if (ew >= 0x7fff) { /* w is inf or nan */
		r = 0.0f;
		i = testinfl(c);
		j = testinfl(d);
		if (i | j) { /* w is infinite */
			/*
			 * "factor out" infinity, being careful to preserve
			 * signs of finite values
			 */
			c = i? i : (((cc.i[2] << 16) < 0)? -0.0f : 0.0f);
			d = j? j : (((dd.i[2] << 16) < 0)? -0.0f : 0.0f);
			if (ez >= 0x7ffe) {
				/* scale to avoid overflow below */
				c *= 0.5f;
				d *= 0.5f;
			}
		}
		((long double *)&v)[0] = (a * c + b * d) * r;
		((long double *)&v)[1] = (b * c - a * d) * r;
		return (v);
	}

	if (ew == 0 && (cc.i[1] | cc.i[0] | dd.i[1] | dd.i[0]) == 0) {
		/* w is zero; multiply z by 1/Re(w) - I * Im(w) */
		c = 1.0f / c;
		i = testinfl(a);
		j = testinfl(b);
		if (i | j) { /* z is infinite */
			a = i;
			b = j;
		}
		((long double *)&v)[0] = a * c + b * d;
		((long double *)&v)[1] = b * c - a * d;
		return (v);
	}

	if (ez >= 0x7fff) { /* z is inf or nan */
		i = testinfl(a);
		j = testinfl(b);
		if (i | j) { /* z is infinite */
			a = i;
			b = j;
			r = inf.f;
		}
		((long double *)&v)[0] = a * c + b * d;
		((long double *)&v)[1] = b * c - a * d;
		return (v);
	}

	/*
	 * Scale c and d to compute 1/|w|^2 and the real and imaginary
	 * parts of the quotient.
	 */
	es = ((ew >> 2) - ew) + 0x6ffd;
	if (ez < 0x0086) { /* |z| < 2^-16249 */
		if (((ew - 0x3efe) | (0x4083 - ew)) >= 0)
			es = ((0x4083 - ew) >> 1) + 0x3fff;
	}
	ss.i[2] = es;
	ss.i[1] = 0x80000000;
	ss.i[0] = 0;

	c *= ss.e;
	d *= ss.e;
	r = 1.0f / (c * c + d * d);

	c *= ss.e;
	d *= ss.e;

	((long double *)&v)[0] = (a * c + b * d) * r;
	((long double *)&v)[1] = (b * c - a * d) * r;
	return (v);
}
