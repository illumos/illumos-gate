/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak cpowl = __cpowl

#include "libm.h"				/* __k_clog_rl/__k_atan2l */
/* atan2l/atan2pil/exp2l/expl/fabsl/hypotl/isinfl/logl/powl/sincosl/sincospil */
#include "complex_wrapper.h"
#include "longdouble.h" 

#if defined(__sparc)
#define	HALF(x)  ((int *) &x)[3] = 0; ((int *) &x)[2] &= 0xfe000000
#define	LAST(x)  ((int *) &x)[3]
#elif defined(__x86)
#define	HALF(x)  ((int *) &x)[0] = 0
#define	LAST(x)  ((int *) &x)[0]
#endif

/* INDENT OFF */
static const int hiinf = 0x7fff0000;
static const long double
	tiny = 1.0e-4000L,
	huge = 1.0e4000L,
#if defined(__x86)
		/* 43 significant bits, 21 trailing zeros */
	ln2hil = 0.693147180559890330187045037746429443359375L,
	ln2lol = 5.497923018708371174712471612513436025525412068e-14L,
#else   /* sparc */
		/* 0x3FF962E4 2FEFA39E F35793C7 00000000 */
	ln2hil = 0.693147180559945309417231592858066493070671489074L,
	ln2lol = 5.28600110075004828645286235820646730106802446566153e-25L,
#endif
	invln2  = 1.442695040888963407359924681001892137427e+0000L,
	one = 1.0L,
	zero = 0.0L;
/* INDENT ON */

/*
 * Assuming |t[0]| > |t[1]| and |t[2]| > |t[3]|, sum4fpl subroutine
 * compute t[0] + t[1] + t[2] + t[3] into two long double fp numbers.
 */
static long double sum4fpl(long double ta[], long double *w)
{
	long double t1, t2, t3, t4, w1, w2, t;
	t1 = ta[0]; t2 = ta[1]; t3 = ta[2]; t4 = ta[3];
	/*
	 * Rearrange ti so that |t1| >= |t2| >= |t3| >= |t4|
	 */
	if (fabsl(t4) > fabsl(t1)) {
		t = t1; t1 = t3; t3 = t;
		t = t2; t2 = t4; t4 = t;
	} else if (fabsl(t3) > fabsl(t1)) {
		t = t1; t1 = t3;
		if (fabsl(t4) > fabsl(t2)) {
			t3 = t4; t4 = t2; t2 = t;
		} else {
			t3 = t2; t2 = t;
		}
	} else if (fabsl(t3) > fabsl(t2)) {
		t = t2; t2 = t3;
		if (fabsl(t4) > fabsl(t2)) {
			t3 = t4; t4 = t;
		} else
			t3 = t;
	}
	/* summing r = t1 + t2 + t3 + t4 to w1 + w2 */
	w1 = t3 + t4;
	w2 = t4 - (w1 - t3);
	t  = t2 + w1;
	w2 += w1 - (t - t2);
	w1 = t + w2;
	w2 += t - w1;
	t  = t1 + w1;
	w2 += w1 - (t - t1);
	w1 = t + w2;
	*w = w2 - (w1 - t);
	return (w1);
}

ldcomplex
cpowl(ldcomplex z, ldcomplex w) {
	ldcomplex ans;
	long double x, y, u, v, t, c, s, r;
	long double t1, t2, t3, t4, x1, x2, y1, y2, u1, v1, b[4], w1, w2;
	int ix, iy, hx, hy, hv, hu, iu, iv, i, j, k;

	x = LD_RE(z);
	y = LD_IM(z);
	u = LD_RE(w);
	v = LD_IM(w);
	hx = HI_XWORD(x);
	hy = HI_XWORD(y);
	hu = HI_XWORD(u);
	hv = HI_XWORD(v);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	iu = hu & 0x7fffffff;
	iv = hv & 0x7fffffff;

	j = 0;
	if (v == zero) {	/* z**(real) */
		if (u == one) {	/* (anything) ** 1  is itself */
			LD_RE(ans) = x;
			LD_IM(ans) = y;
		} else if (u == zero) {	/* (anything) ** 0  is 1 */
			LD_RE(ans) = one;
			LD_IM(ans) = zero;
		} else if (y == zero) {	/* real ** real */
			LD_IM(ans) = zero;
			if (hx < 0 && ix < hiinf && iu < hiinf) {
			/* -x ** u  is exp(i*pi*u)*pow(x,u) */
				r = powl(-x, u);
				sincospil(u, &s, &c);
				LD_RE(ans) = (c == zero)? c: c * r;
				LD_IM(ans) = (s == zero)? s: s * r;
			} else
				LD_RE(ans) = powl(x, u);
		} else if (x == zero || ix >= hiinf || iy >= hiinf) {
			if (isnanl(x) || isnanl(y) || isnanl(u))
				LD_RE(ans) = LD_IM(ans) = x + y + u;
			else {
				if (x == zero)
					r = fabsl(y);
				else
					r = fabsl(x) + fabsl(y);
				t = atan2pil(y, x);
				sincospil(t * u, &s, &c);
				LD_RE(ans) = (c == zero)? c: c * r;
				LD_IM(ans) = (s == zero)? s: s * r;
			}
		} else if (fabsl(x) == fabsl(y)) {    /* |x| = |y| */
			if (hx >= 0) {
				t = (hy >= 0)? 0.25L : -0.25L;
				sincospil(t * u, &s, &c);
			} else if ((LAST(u) & 3) == 0) {
				t = (hy >= 0)? 0.75L : -0.75L;
				sincospil(t * u, &s, &c);
			} else {
				r = (hy >= 0)? u : -u;
				t = -0.25L * r;
				w1 = r + t;
				w2 = t - (w1 - r);
				sincospil(w1, &t1, &t2);
				sincospil(w2, &t3, &t4);
				s = t1 * t4 + t3 * t2;
				c = t2 * t4 - t1 * t3;
			}
			if (ix < 0x3ffe0000)	/* |x| < 1/2 */
				r = powl(fabsl(x + x), u) * exp2l(-0.5L * u);
			else if (ix >= 0x3fff0000 || iu < 0x400cfff8)
				/* |x| >= 1 or |u| < 16383 */
				r = powl(fabsl(x), u) * exp2l(0.5L * u);
			else   /* special treatment */
				j = 2;
			if (j == 0) {
				LD_RE(ans) = (c == zero)? c: c * r;
				LD_IM(ans) = (s == zero)? s: s * r;
			}
		} else
			j = 1;
		if (j == 0)
			return (ans);
	}
	if (iu >= hiinf || iv >= hiinf || ix >= hiinf || iy >= hiinf) {
		/*
		 * non-zero imag part(s) with inf component(s) yields NaN
		 */
		t = fabsl(x) + fabsl(y) + fabsl(u) + fabsl(v);
		LD_RE(ans) = LD_IM(ans) = t - t;
	} else {
		k = 0;	/* no scaling */
		if (iu > 0x7ffe0000 || iv > 0x7ffe0000) {
			u *= 1.52587890625000000000e-05L;
			v *= 1.52587890625000000000e-05L;
			k = 1;	/* scale u and v by 2**-16 */
		}
		/*
		 * Use similated higher precision arithmetic to compute:
		 * r = u * log(hypot(x, y)) - v * atan2(y, x)
		 * q = u * atan2(y, x) + v * log(hypot(x, y))
		 */

		t1 = __k_clog_rl(x, y, &t2);
		t3 = __k_atan2l(y, x, &t4);
		x1 = t1; HALF(x1);
		y1 = t3; HALF(y1);
		u1 = u; HALF(u1);
		v1 = v; HALF(v1);
		x2 = t2 - (x1 - t1);    /* log(hypot(x,y)) = x1 + x2 */
		y2 = t4 - (y1 - t3);    /* atan2(y,x) = y1 + y2 */
		/* compute q = u * atan2(y, x) + v * log(hypot(x, y)) */
		if (j != 2) {
			b[0] = u1 * y1;
			b[1] = (u - u1) * y1 + u * y2;
			if (j == 1) {	/* v = 0 */
				w1 = b[0] + b[1];
				w2 = b[1] - (w1 - b[0]);
			} else {
				b[2] = v1 * x1;
				b[3] = (v - v1) * x1 + v * x2;
				w1 = sum4fpl(b, &w2);
			}
			sincosl(w1, &t1, &t2);
			sincosl(w2, &t3, &t4);
			s = t1 * t4 + t3 * t2;
			c = t2 * t4 - t1 * t3;
			if (k == 1)	/* square j times */
				for (i = 0; i < 10; i++) {
					t1 = s * c;
					c = (c + s) * (c - s);
					s = t1 + t1;
				}
		}
		/* compute r = u * (t1, t2) - v * (t3, t4) */
		b[0] = u1 * x1;
		b[1] = (u - u1) * x1 + u * x2;
		if (j == 1) {   /* v = 0 */
			w1 = b[0] + b[1];
			w2 = b[1] - (w1 - b[0]);
		} else {
			b[2] = -v1 * y1;
			b[3] = (v1 - v) * y1 - v * y2;
			w1 = sum4fpl(b, &w2);
		}
		/* scale back unless w1 is large enough to cause exception */
		if (k != 0 && fabsl(w1) < 20000.0L) {
			w1 *= 65536.0L; w2 *= 65536.0L;
		}
		hx = HI_XWORD(w1);
		ix = hx & 0x7fffffff;
		/* compute exp(w1 + w2) */
		k = 0;
		if (ix < 0x3f8c0000) /* exp(tiny < 2**-115) = 1 */
			r = one;
		else if (ix >= 0x400c6760) /* overflow/underflow */
			r = (hx < 0)? tiny * tiny : huge * huge;
		else {  /* compute exp(w1 + w2) */
			k = (int) (invln2 * w1 + ((hx >= 0)? 0.5L : -0.5L));
			t1 = (long double) k;
			t2 = w1 - t1 * ln2hil;
			t3 = w2 - t1 * ln2lol;
			r = expl(t2 + t3);
		}
		if (c != zero) c *= r;
		if (s != zero) s *= r;
		if (k != 0) {
			c = scalbnl(c, k);
			s = scalbnl(s, k);
		}
		LD_RE(ans) = c;
		LD_IM(ans) = s;
	}
	return (ans);
}
