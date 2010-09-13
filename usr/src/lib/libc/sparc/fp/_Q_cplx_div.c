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
 * On SPARC V8, _Q_cplx_div(v, z, w) sets *v = *z / *w with infin-
 * ities handling according to C99.
 *
 * On SPARC V9, _Q_cplx_div(z, w) returns *z / *w with infinities
 * handled according to C99.
 *
 * If z and w are both finite and w is nonzero, _Q_cplx_div delivers
 * the complex quotient q according to the usual formula: let a =
 * Re(z), b = Im(z), c = Re(w), and d = Im(w); then q = x + I * y
 * where x = (a * c + b * d) / r and y = (b * c - a * d) / r with
 * r = c * c + d * d.  This implementation scales to avoid premature
 * underflow or overflow.
 *
 * If z is neither NaN nor zero and w is zero, or if z is infinite
 * and w is finite and nonzero, _Q_cplx_div delivers an infinite
 * result.  If z is finite and w is infinite, _Q_cplx_div delivers
 * a zero result.
 *
 * If z and w are both zero or both infinite, or if either z or w is
 * a complex NaN, _Q_cplx_div delivers NaN + I * NaN.  C99 doesn't
 * specify these cases.
 *
 * This implementation can raise spurious underflow, overflow, in-
 * valid operation, inexact, and division-by-zero exceptions.  C99
 * allows this.
 */

#if !defined(sparc) && !defined(__sparc)
#error This code is for SPARC only
#endif

static union {
	int		i[4];
	long double	q;
} inf = {
	0x7fff0000, 0, 0, 0
};

/*
 * Return +1 if x is +Inf, -1 if x is -Inf, and 0 otherwise
 */
static int
testinfl(long double x)
{
	union {
		int		i[4];
		long double	q;
	} xx;

	xx.q = x;
	return (((((xx.i[0] << 1) - 0xfffe0000) | xx.i[1] | xx.i[2] | xx.i[3])
		== 0)? (1 | (xx.i[0] >> 31)) : 0);
}

#ifdef __sparcv9
long double _Complex
_Q_cplx_div(const long double _Complex *z, const long double _Complex *w)
{
	long double _Complex	v;
#else
void
_Q_cplx_div(long double _Complex *v, const long double _Complex *z,
	const long double _Complex *w)
{
#endif
	union {
		int		i[4];
		long double	q;
	} aa, bb, cc, dd, ss;
	long double	a, b, c, d, r;
	int		ha, hb, hc, hd, hz, hw, hs, i, j;

	/*
	 * The following is equivalent to
	 *
	 *  a = creall(*z); b = cimagl(*z);
	 *  c = creall(*w); d = cimagl(*w);
	 */
	a = ((long double *)z)[0];
	b = ((long double *)z)[1];
	c = ((long double *)w)[0];
	d = ((long double *)w)[1];

	/* extract high-order words to estimate |z| and |w| */
	aa.q = a;
	bb.q = b;
	ha = aa.i[0] & ~0x80000000;
	hb = bb.i[0] & ~0x80000000;
	hz = (ha > hb)? ha : hb;

	cc.q = c;
	dd.q = d;
	hc = cc.i[0] & ~0x80000000;
	hd = dd.i[0] & ~0x80000000;
	hw = (hc > hd)? hc : hd;

	/* check for special cases */
	if (hw >= 0x7fff0000) { /* w is inf or nan */
		r = 0.0l;
		i = testinfl(c);
		j = testinfl(d);
		if (i | j) { /* w is infinite */
			/*
			 * "factor out" infinity, being careful to preserve
			 * signs of finite values
			 */
			c = i? i : ((cc.i[0] < 0)? -0.0l : 0.0l);
			d = j? j : ((dd.i[0] < 0)? -0.0l : 0.0l);
			if (hz >= 0x7ffe0000) {
				/* scale to avoid overflow below */
				c *= 0.5l;
				d *= 0.5l;
			}
		}
		goto done;
	}

	if (hw == 0 && (cc.i[1] | cc.i[2] | cc.i[3] |
		dd.i[1] | dd.i[2] | dd.i[3]) == 0) {
		/* w is zero; multiply z by 1/Re(w) - I * Im(w) */
		r = 1.0l;
		c = 1.0l / c;
		i = testinfl(a);
		j = testinfl(b);
		if (i | j) { /* z is infinite */
			a = i;
			b = j;
		}
		goto done;
	}

	if (hz >= 0x7fff0000) { /* z is inf or nan */
		r = 1.0l;
		i = testinfl(a);
		j = testinfl(b);
		if (i | j) { /* z is infinite */
			a = i;
			b = j;
			r = inf.q;
		}
		goto done;
	}

	/*
	 * Scale c and d to compute 1/|w|^2 and the real and imaginary
	 * parts of the quotient.
	 */
	hs = (((hw >> 2) - hw) + 0x6ffd7fff) & 0xffff0000;
	if (hz < 0x00ea0000) { /* |z| < 2^-16149 */
		if (((hw - 0x3e380000) | (0x40e90000 - hw)) >= 0)
			hs = (((0x40e90000 - hw) >> 1) & 0xffff0000)
				+ 0x3fff0000;
	}
	ss.i[0] = hs;
	ss.i[1] = ss.i[2] = ss.i[3] = 0;

	c *= ss.q;
	d *= ss.q;
	r = 1.0l / (c * c + d * d);

	c *= ss.q;
	d *= ss.q;

done:
#ifdef __sparcv9
	((long double *)&v)[0] = (a * c + b * d) * r;
	((long double *)&v)[1] = (b * c - a * d) * r;
	return (v);
#else
	((long double *)v)[0] = (a * c + b * d) * r;
	((long double *)v)[1] = (b * c - a * d) * r;
#endif
}
