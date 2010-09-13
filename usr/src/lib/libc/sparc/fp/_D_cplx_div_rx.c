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
 * _D_cplx_div_rx(a, w) returns a / w with infinities handled according
 * to C99.
 *
 * If a and w are both finite and w is nonzero, _D_cplx_div_rx(a, w)
 * delivers the complex quotient q according to the usual formula:
 * let c = Re(w), and d = Im(w); then q = x + I * y where x = (a * c)
 * / r and y = (-a * d) / r with r = c * c + d * d.  This implementa-
 * tion scales to avoid premature underflow or overflow.
 *
 * If a is neither NaN nor zero and w is zero, or if a is infinite
 * and w is finite and nonzero, _D_cplx_div_rx delivers an infinite
 * result.  If a is finite and w is infinite, _D_cplx_div_rx delivers
 * a zero result.
 *
 * If a and w are both zero or both infinite, or if either a or w is
 * NaN, _D_cplx_div_rx delivers NaN + I * NaN.  C99 doesn't specify
 * these cases.
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

/*
 * scl[i].d = 2^(250*(4-i)) for i = 0, ..., 9
 */
static const union {
	int	i[2];
	double	d;
} scl[9] = {
	{ 0x7e700000, 0 },
	{ 0x6ed00000, 0 },
	{ 0x5f300000, 0 },
	{ 0x4f900000, 0 },
	{ 0x3ff00000, 0 },
	{ 0x30500000, 0 },
	{ 0x20b00000, 0 },
	{ 0x11100000, 0 },
	{ 0x01700000, 0 }
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
_D_cplx_div_rx(double a, double _Complex w)
{
	double _Complex	v;
	union {
		int	i[2];
		double	d;
	} aa, cc, dd;
	double		c, d, sc, sd, r;
	int		ha, hc, hd, hw, i, j;

	/*
	 * The following is equivalent to
	 *
	 *  c = creal(w); d = cimag(w);
	 */
	c = ((double *)&w)[0];
	d = ((double *)&w)[1];

	/* extract high-order words to estimate |a| and |w| */
	aa.d = a;
	ha = aa.i[0] & ~0x80000000;

	cc.d = c;
	dd.d = d;
	hc = cc.i[0] & ~0x80000000;
	hd = dd.i[0] & ~0x80000000;
	hw = (hc > hd)? hc : hd;

	/* check for special cases */
	if (hw >= 0x7ff00000) { /* w is inf or nan */
		i = testinf(c);
		j = testinf(d);
		if (i | j) { /* w is infinite */
			c = (cc.i[0] < 0)? -0.0 : 0.0;
			d = (dd.i[0] < 0)? -0.0 : 0.0;
		} else /* w is nan */
			a *= c * d;
		((double *)&v)[0] = a * c;
		((double *)&v)[1] = -a * d;
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
		/* w is zero; multiply a by 1/Re(w) - I * Im(w) */
		c = 1.0 / c;
		i = testinf(a);
		if (i) { /* a is infinite */
			a = i;
		}
		((double *)&v)[0] = a * c;
		((double *)&v)[1] = (a == 0.0)? a * c : -a * d;
		return (v);
	}

	if (ha >= 0x7ff00000) { /* a is inf or nan */
		((double *)&v)[0] = a * c;
		((double *)&v)[1] = -a * d;
		return (v);
	}

	/*
	 * Compute the real and imaginary parts of the quotient,
	 * scaling to avoid overflow or underflow.
	 */
	hw = (hw - 0x38000000) >> 28;
	sc = c * scl[hw + 4].d;
	sd = d * scl[hw + 4].d;
	r = sc * sc + sd * sd;

	ha = (ha - 0x38000000) >> 28;
	a = (a * scl[ha + 4].d) / r;
	ha -= (hw + hw);

	hc = (hc - 0x38000000) >> 28;
	c = (c * scl[hc + 4].d) * a;
	hc += ha;

	hd = (hd - 0x38000000) >> 28;
	d = -(d * scl[hd + 4].d) * a;
	hd += ha;

	/* compensate for scaling */
	sc = scl[3].d; /* 2^250 */
	if (hc < 0) {
		hc = -hc;
		sc = scl[5].d; /* 2^-250 */
	}
	while (hc--)
		c *= sc;

	sd = scl[3].d;
	if (hd < 0) {
		hd = -hd;
		sd = scl[5].d;
	}
	while (hd--)
		d *= sd;

	((double *)&v)[0] = c;
	((double *)&v)[1] = d;
	return (v);
}
