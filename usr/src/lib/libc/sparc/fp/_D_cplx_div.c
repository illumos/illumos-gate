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
 * _D_cplx_div(z, w) returns z / w with infinities handled according
 * to C99.
 *
 * If z and w are both finite and w is nonzero, _D_cplx_div(z, w)
 * delivers the complex quotient q according to the usual formula:
 * let a = Re(z), b = Im(z), c = Re(w), and d = Im(w); then q = x +
 * I * y where x = (a * c + b * d) / r and y = (b * c - a * d) / r
 * with r = c * c + d * d.  This implementation scales to avoid
 * premature underflow or overflow.
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
 * This implementation can raise spurious underflow, overflow, in-
 * valid operation, inexact, and division-by-zero exceptions.  C99
 * allows this.
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
testinf(double x)
{
	union {
		int	i[2];
		double	d;
	} xx;

	xx.d = x;
	return (((((xx.i[0] << 1) - 0xffe00000) | xx.i[1]) == 0)?
		(1 | (xx.i[0] >> 31)) : 0);
}

double _Complex
_D_cplx_div(double _Complex z, double _Complex w)
{
	double _Complex	v;
	union {
		int	i[2];
		double	d;
	} aa, bb, cc, dd, ss;
	double		a, b, c, d, r;
	int		ha, hb, hc, hd, hz, hw, hs, i, j;

	/*
	 * The following is equivalent to
	 *
	 *  a = creal(z); b = cimag(z);
	 *  c = creal(w); d = cimag(w);
	 */
	a = ((double *)&z)[0];
	b = ((double *)&z)[1];
	c = ((double *)&w)[0];
	d = ((double *)&w)[1];

	/* extract high-order words to estimate |z| and |w| */
	aa.d = a;
	bb.d = b;
	ha = aa.i[0] & ~0x80000000;
	hb = bb.i[0] & ~0x80000000;
	hz = (ha > hb)? ha : hb;

	cc.d = c;
	dd.d = d;
	hc = cc.i[0] & ~0x80000000;
	hd = dd.i[0] & ~0x80000000;
	hw = (hc > hd)? hc : hd;

	/* check for special cases */
	if (hw >= 0x7ff00000) { /* w is inf or nan */
		r = 0.0;
		i = testinf(c);
		j = testinf(d);
		if (i | j) { /* w is infinite */
			/*
			 * "factor out" infinity, being careful to preserve
			 * signs of finite values
			 */
			c = i? i : ((cc.i[0] < 0)? -0.0 : 0.0);
			d = j? j : ((dd.i[0] < 0)? -0.0 : 0.0);
			if (hz >= 0x7fe00000) {
				/* scale to avoid overflow below */
				c *= 0.5;
				d *= 0.5;
			}
		}
		((double *)&v)[0] = (a * c + b * d) * r;
		((double *)&v)[1] = (b * c - a * d) * r;
		return (v);
	}

	if (hw < 0x00100000) {
		/*
		 * This nonsense is needed to work around some SPARC
		 * implementations of nonstandard mode; if both parts
		 * of w are subnormal, multiply them by one to force
		 * them to be flushed to zero when nonstandard mode
		 * is enabled.  Sheesh.
		 */
		cc.d = c = c * 1.0;
		dd.d = d = d * 1.0;
		hc = cc.i[0] & ~0x80000000;
		hd = dd.i[0] & ~0x80000000;
		hw = (hc > hd)? hc : hd;
	}

	if (hw == 0 && (cc.i[1] | dd.i[1]) == 0) {
		/* w is zero; multiply z by 1/Re(w) - I * Im(w) */
		c = 1.0 / c;
		i = testinf(a);
		j = testinf(b);
		if (i | j) { /* z is infinite */
			a = i;
			b = j;
		}
		((double *)&v)[0] = a * c + b * d;
		((double *)&v)[1] = b * c - a * d;
		return (v);
	}

	if (hz >= 0x7ff00000) { /* z is inf or nan */
		r = 1.0;
		i = testinf(a);
		j = testinf(b);
		if (i | j) { /* z is infinite */
			a = i;
			b = j;
			r = inf.d;
		}
		((double *)&v)[0] = (a * c + b * d) * r;
		((double *)&v)[1] = (b * c - a * d) * r;
		return (v);
	}

	/*
	 * Scale c and d to compute 1/|w|^2 and the real and imaginary
	 * parts of the quotient.
	 *
	 * Note that for any s, if we let c' = sc, d' = sd, c'' = sc',
	 * and d'' = sd', then
	 *
	 *  (ac'' + bd'') / (c'^2 + d'^2) = (ac + bd) / (c^2 + d^2)
	 *
	 * and similarly for the imaginary part of the quotient.  We want
	 * to choose s such that (i) r := 1/(c'^2 + d'^2) can be computed
	 * without overflow or harmful underflow, and (ii) (ac'' + bd'')
	 * and (bc'' - ad'') can be computed without spurious overflow or
	 * harmful underflow.  To avoid unnecessary rounding, we restrict
	 * s to a power of two.
	 *
	 * To satisfy (i), we need to choose s such that max(|c'|,|d'|)
	 * is not too far from one.  To satisfy (ii), we need to choose
	 * s such that max(|c''|,|d''|) is also not too far from one.
	 * There is some leeway in our choice, but to keep the logic
	 * from getting overly complicated, we simply attempt to roughly
	 * balance these constraints by choosing s so as to make r about
	 * the same size as max(|c''|,|d''|).  This corresponds to choos-
	 * ing s to be a power of two near |w|^(-3/4).
	 *
	 * Regarding overflow, observe that if max(|c''|,|d''|) <= 1/2,
	 * then the computation of (ac'' + bd'') and (bc'' - ad'') can-
	 * not overflow; otherwise, the computation of either of these
	 * values can only incur overflow if the true result would be
	 * within a factor of two of the overflow threshold.  In other
	 * words, if we bias the choice of s such that at least one of
	 *
	 *  max(|c''|,|d''|) <= 1/2   or   r >= 2
	 *
	 * always holds, then no undeserved overflow can occur.
	 *
	 * To cope with underflow, note that if r < 2^-53, then any
	 * intermediate results that underflow are insignificant; either
	 * they will be added to normal results, rendering the under-
	 * flow no worse than ordinary roundoff, or they will contribute
	 * to a final result that is smaller than the smallest subnormal
	 * number.  Therefore, we need only modify the preceding logic
	 * when z is very small and w is not too far from one.  In that
	 * case, we can reduce the effect of any intermediate underflow
	 * to no worse than ordinary roundoff error by choosing s so as
	 * to make max(|c''|,|d''|) large enough that at least one of
	 * (ac'' + bd'') or (bc'' - ad'') is normal.
	 */
	hs = (((hw >> 2) - hw) + 0x6fd7ffff) & 0xfff00000;
	if (hz < 0x07200000) { /* |z| < 2^-909 */
		if (((hw - 0x32800000) | (0x47100000 - hw)) >= 0)
			hs = (((0x47100000 - hw) >> 1) & 0xfff00000)
				+ 0x3ff00000;
	}
	ss.i[0] = hs;
	ss.i[1] = 0;

	c *= ss.d;
	d *= ss.d;
	r = 1.0 / (c * c + d * d);

	c *= ss.d;
	d *= ss.d;
	((double *)&v)[0] = (a * c + b * d) * r;
	((double *)&v)[1] = (b * c - a * d) * r;
	return (v);
}
