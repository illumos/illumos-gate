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
 * _X_cplx_div_rx(a, w) returns a / w with infinities handled
 * according to C99.
 *
 * If a and w are both finite and w is nonzero, _X_cplx_div_rx de-
 * livers the complex quotient q according to the usual formula: let
 * c = Re(w), and d = Im(w); then q = x + I * y where x = (a * c) / r
 * and y = (-a * d) / r with r = c * c + d * d.  This implementation
 * scales to avoid premature underflow or overflow.
 *
 * If a is neither NaN nor zero and w is zero, or if a is infinite
 * and w is finite and nonzero, _X_cplx_div_rx delivers an infinite
 * result.  If a is finite and w is infinite, _X_cplx_div_rx delivers
 * a zero result.
 *
 * If a and w are both zero or both infinite, or if either a or w is
 * NaN, _X_cplx_div_rx delivers NaN + I * NaN.  C99 doesn't specify
 * these cases.
 *
 * This implementation can raise spurious underflow, overflow, in-
 * valid operation, inexact, and division-by-zero exceptions.  C99
 * allows this.
 */

#if !defined(i386) && !defined(__i386) && !defined(__amd64)
#error This code is for x86 only
#endif

/*
 * scl[i].e = 2^(4080*(4-i)) for i = 0, ..., 9
 */
static const union {
	unsigned int	i[3];
	long double	e;
} scl[9] = {
	{ 0, 0x80000000, 0x7fbf },
	{ 0, 0x80000000, 0x6fcf },
	{ 0, 0x80000000, 0x5fdf },
	{ 0, 0x80000000, 0x4fef },
	{ 0, 0x80000000, 0x3fff },
	{ 0, 0x80000000, 0x300f },
	{ 0, 0x80000000, 0x201f },
	{ 0, 0x80000000, 0x102f },
	{ 0, 0x80000000, 0x003f }
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
_X_cplx_div_rx(long double a, long double _Complex w)
{
	long double _Complex	v;
	union {
		int		i[3];
		long double	e;
	} aa, cc, dd;
	long double	c, d, sc, sd, r;
	int		ea, ec, ed, ew, i, j;

	/*
	 * The following is equivalent to
	 *
	 *  c = creall(*w); d = cimagl(*w);
	 */
	c = ((long double *)&w)[0];
	d = ((long double *)&w)[1];

	/* extract exponents to estimate |z| and |w| */
	aa.e = a;
	ea = aa.i[2] & 0x7fff;

	cc.e = c;
	dd.e = d;
	ec = cc.i[2] & 0x7fff;
	ed = dd.i[2] & 0x7fff;
	ew = (ec > ed)? ec : ed;

	/* check for special cases */
	if (ew >= 0x7fff) { /* w is inf or nan */
		i = testinfl(c);
		j = testinfl(d);
		if (i | j) { /* w is infinite */
			c = ((cc.i[2] << 16) < 0)? -0.0f : 0.0f;
			d = ((dd.i[2] << 16) < 0)? -0.0f : 0.0f;
		} else /* w is nan */
			a += c + d;
		((long double *)&v)[0] = a * c;
		((long double *)&v)[1] = -a * d;
		return (v);
	}

	if (ew == 0 && (cc.i[1] | cc.i[0] | dd.i[1] | dd.i[0]) == 0) {
		/* w is zero; multiply a by 1/Re(w) - I * Im(w) */
		c = 1.0f / c;
		i = testinfl(a);
		if (i) { /* a is infinite */
			a = i;
		}
		((long double *)&v)[0] = a * c;
		((long double *)&v)[1] = (a == 0.0f)? a * c : -a * d;
		return (v);
	}

	if (ea >= 0x7fff) { /* a is inf or nan */
		((long double *)&v)[0] = a * c;
		((long double *)&v)[1] = -a * d;
		return (v);
	}

	/*
	 * Compute the real and imaginary parts of the quotient,
	 * scaling to avoid overflow or underflow.
	 */
	ew = (ew - 0x3800) >> 12;
	sc = c * scl[ew + 4].e;
	sd = d * scl[ew + 4].e;
	r = sc * sc + sd * sd;

	ea = (ea - 0x3800) >> 12;
	a = (a * scl[ea + 4].e) / r;
	ea -= (ew + ew);

	ec = (ec - 0x3800) >> 12;
	c = (c * scl[ec + 4].e) * a;
	ec += ea;

	ed = (ed - 0x3800) >> 12;
	d = -(d * scl[ed + 4].e) * a;
	ed += ea;

	/* compensate for scaling */
	sc = scl[3].e; /* 2^4080 */
	if (ec < 0) {
		ec = -ec;
		sc = scl[5].e; /* 2^-4080 */
	}
	while (ec--)
		c *= sc;

	sd = scl[3].e;
	if (ed < 0) {
		ed = -ed;
		sd = scl[5].e;
	}
	while (ed--)
		d *= sd;

	((long double *)&v)[0] = c;
	((long double *)&v)[1] = d;
	return (v);
}
