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
 * _F_cplx_div_ix(b, w) returns (I * b) / w with infinities handled
 * according to C99.
 *
 * If b and w are both finite and w is nonzero, _F_cplx_div_ix(b, w)
 * delivers the complex quotient q according to the usual formula:
 * let c = Re(w), and d = Im(w); then q = x + I * y where x = (b * d)
 * / r and y = (b * c) / r with r = c * c + d * d.  This implementa-
 * tion computes intermediate results in extended precision to avoid
 * premature underflow or overflow.
 *
 * If b is neither NaN nor zero and w is zero, or if b is infinite
 * and w is finite and nonzero, _F_cplx_div_ix delivers an infinite
 * result.  If b is finite and w is infinite, _F_cplx_div_ix delivers
 * a zero result.
 *
 * If b and w are both zero or both infinite, or if either b or w is
 * NaN, _F_cplx_div_ix delivers NaN + I * NaN.  C99 doesn't specify
 * these cases.
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
_F_cplx_div_ix(float b, float _Complex w)
{
	float _Complex	v;
	union {
		int	i;
		float	f;
	} cc, dd;
	float		c, d;
	long double	r, x, y;
	int		i, j;

	/*
	 * The following is equivalent to
	 *
	 *  c = crealf(w); d = cimagf(w);
	 */
	c = ((float *)&w)[0];
	d = ((float *)&w)[1];

	r = (long double)c * c + (long double)d * d;

	if (r == 0.0f) {
		/* w is zero; multiply b by 1/Re(w) - I * Im(w) */
		c = 1.0f / c;
		j = testinff(b);
		if (j) { /* b is infinite */
			b = j;
		}
		((float *)&v)[0] = (b == 0.0f)? b * c : b * d;
		((float *)&v)[1] = b * c;
		return (v);
	}

	r = (long double)b / r;
	x = (long double)d * r;
	y = (long double)c * r;

	if (x != x || y != y) {
		/*
		 * x or y is NaN, so b and w can't both be finite and
		 * nonzero.  Since we handled the case w = 0 above, the
		 * only case to check here is when w is infinite.
		 */
		i = testinff(c);
		j = testinff(d);
		if (i | j) { /* w is infinite */
			cc.f = c;
			dd.f = d;
			c = (cc.i < 0)? -0.0f : 0.0f;
			d = (dd.i < 0)? -0.0f : 0.0f;
			x = (long double)d * b;
			y = (long double)c * b;
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
