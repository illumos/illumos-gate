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
 * On SPARC V8, _Q_cplx_div_ix(v, b, w) sets *v = (I * *b / *w) with
 * infinities handling according to C99.
 *
 * On SPARC V9, _Q_cplx_div_ix(b, w) returns (I * *b) / *w with in-
 * finities handled according to C99.
 *
 * If b and w are both finite and w is nonzero, _Q_cplx_div_ix de-
 * livers the complex quotient q according to the usual formula: let
 * c = Re(w), and d = Im(w); then q = x + I * y where x = (b * d) / r
 * and y = (-b * d) / r with r = c * c + d * d.  This implementation
 * scales to avoid premature underflow or overflow.
 *
 * If b is neither NaN nor zero and w is zero, or if b is infinite
 * and w is finite and nonzero, _Q_cplx_div_ix delivers an infinite
 * result.  If b is finite and w is infinite, _Q_cplx_div_ix delivers
 * a zero result.
 *
 * If b and w are both zero or both infinite, or if either b or w is
 * NaN, _Q_cplx_div_ix delivers NaN + I * NaN.  C99 doesn't specify
 * these cases.
 *
 * This implementation can raise spurious underflow, overflow, in-
 * valid operation, inexact, and division-by-zero exceptions.  C99
 * allows this.
 */

#if !defined(sparc) && !defined(__sparc)
#error This code is for SPARC only
#endif

extern void _Q_scl(long double *, int);
extern void _Q_scle(long double *, int);

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
_Q_cplx_div_ix(const long double *pb, const long double _Complex *w)
{
	long double _Complex	v;
#else
void
_Q_cplx_div_ix(long double _Complex *v, const long double *pb,
	const long double _Complex *w)
{
#endif
	union {
		int		i[4];
		long double	q;
	} bb, cc, dd;
	long double	b, c, d, sc, sd, r;
	int		hb, hc, hd, hw, i, j;

	b = *pb;

	/*
	 * The following is equivalent to
	 *
	 *  c = creall(*w); d = cimagl(*w);
	 */
	c = ((long double *)w)[0];
	d = ((long double *)w)[1];

	/* extract high-order words to estimate |b| and |w| */
	bb.q = b;
	hb = bb.i[0] & ~0x80000000;

	cc.q = c;
	dd.q = d;
	hc = cc.i[0] & ~0x80000000;
	hd = dd.i[0] & ~0x80000000;
	hw = (hc > hd)? hc : hd;

	/* check for special cases */
	if (hw >= 0x7fff0000) { /* w is inf or nan */
		i = testinfl(c);
		j = testinfl(d);
		if (i | j) { /* w is infinite */
			c = (cc.i[0] < 0)? -0.0l : 0.0l;
			d = (dd.i[0] < 0)? -0.0l : 0.0l;
		} else /* w is nan */
			b += c + d;
		c *= b;
		d *= b;
		goto done;
	}

	if (hw == 0 && (cc.i[1] | cc.i[2] | cc.i[3] |
		dd.i[1] | dd.i[2] | dd.i[3]) == 0) {
		/* w is zero; multiply b by 1/Re(w) - I * Im(w) */
		c = 1.0l / c;
		j = testinfl(b);
		if (j) { /* b is infinite */
			b = j;
		}
		c *= b;
		d = (b == 0.0l)? c : b * d;
		goto done;
	}

	if (hb >= 0x7fff0000) { /* a is inf or nan */
		c *= b;
		d *= b;
		goto done;
	}

	/*
	 * Compute the real and imaginary parts of the quotient,
	 * scaling to avoid overflow or underflow.
	 */
	hw = (hw - 0x3fff0000) >> 16;
	sc = c;
	sd = d;
	_Q_scl(&sc, -hw);
	_Q_scl(&sd, -hw);
	r = sc * sc + sd * sd;

	hb = (hb - 0x3fff0000) >> 16;
	_Q_scl(&b, -hb);
	b /= r;
	hb -= (hw + hw);

	hc = (hc - 0x3fff0000) >> 16;
	_Q_scl(&c, -hc);
	c *= b;
	hc += hb;

	hd = (hd - 0x3fff0000) >> 16;
	_Q_scl(&d, -hd);
	d *= b;
	hd += hb;

	/* compensate for scaling */
	_Q_scle(&c, hc);
	_Q_scle(&d, hd);

done:
#ifdef __sparcv9
	((long double *)&v)[0] = d;
	((long double *)&v)[1] = c;
	return (v);
#else
	((long double *)v)[0] = d;
	((long double *)v)[1] = c;
#endif
}
