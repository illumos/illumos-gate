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

#pragma weak cpow = __cpow

/* INDENT OFF */
/*
 * dcomplex cpow(dcomplex z);
 *
 * z**w analytically equivalent to
 *
 * cpow(z,w) = cexp(w clog(z))
 *
 * Let z = x+iy, w = u+iv.
 * Since
 *                        _________
 *                       / 2    2            -1   y
 *     log(x+iy) = log(\/ x  + y    ) + i tan   (---)
 *                                                x
 *
 *                  1       2    2         -1   y
 *               = --- log(x  + y ) + i tan   (---)
 *                  2                           x
 *                       u       2    2         -1  y
 * (u+iv)* log(x+iy) =  --- log(x  + y ) - v tan  (---)  +          (1)
 *                       2                          x
 *
 *                            v       2    2         -1  y
 *                     i * [ --- log(x  + y ) + u tan  (---) ]      (2)
 *                            2                          x
 *
 *                   = r + i q
 *
 * Therefore,
 *      w     r+iq    r
 *     z  =  e     = e  (cos(q)+i*sin(q))
 *                                   _______
 *                                  / 2   2
 *       r                        \/ x + y     -v*atan2(y,x)
 * Here e  can be expressed as:  u          * e
 *
 * Special cases (in the order of appearance):
 *      1.  (anything) ** 0  is 1
 *      2.  (anything) ** 1  is itself
 *      3.  When v = 0, y = 0:
 *            If x is finite and negative, and u is finite, then
 *               x ** u = exp(u*pi i) * pow(|x|, u);
 *            otherwise,
 *               x ** u = pow(x, u);
 *      4.  When v = 0, x = 0 or |x| = |y| or x is inf or y is inf:
 *               (x + y i) ** u = r * exp(q i)
 *          where
 *               r = hypot(x,y) ** u
 *               q = u * atan2pi(y, x)
 *
 *      5.  otherwise, z**w is NAN if any x, y, u, v is a Nan or inf
 *
 *      Note: many results of special cases are obtained in terms of
 *      polar coordinate. In the conversion from polar to rectangle:
 *                  r exp(q i) = r * cos(q) + r * sin(q) i,
 *      we regard r * 0 is 0 except when r is a NaN.
 */
/* INDENT ON */

#include "libm.h"	/* atan2/exp/fabs/hypot/log/pow/scalbn */
			/* atan2pi/exp2/sincos/sincospi/__k_clog_r/__k_atan2 */
#include "complex_wrapper.h"

extern void sincospi(double, double *, double *);

static const double
	huge = 1e300,
	tiny = 1e-300,
	invln2 = 1.44269504088896338700e+00,
	ln2hi = 6.93147180369123816490e-01,   /* 0x3fe62e42, 0xfee00000 */
	ln2lo = 1.90821492927058770002e-10,   /* 0x3dea39ef, 0x35793c76 */
	one = 1.0,
	zero = 0.0;

static const int hiinf = 0x7ff00000;
extern double atan2pi(double, double);

/*
 * Assuming |t[0]| > |t[1]| and |t[2]| > |t[3]|, sum4fp subroutine
 * compute t[0] + t[1] + t[2] + t[3] into two double fp numbers.
 */
static double
sum4fp(double ta[], double *w) {
	double t1, t2, t3, t4, w1, w2, t;
	t1 = ta[0]; t2 = ta[1]; t3 = ta[2]; t4 = ta[3];
	/*
	 * Rearrange ti so that |t1| >= |t2| >= |t3| >= |t4|
	 */
	if (fabs(t4) > fabs(t1)) {
		t = t1; t1 = t3; t3 = t;
		t = t2; t2 = t4; t4 = t;
	} else if (fabs(t3) > fabs(t1)) {
		t = t1; t1 = t3;
		if (fabs(t4) > fabs(t2)) {
			t3 = t4; t4 = t2; t2 = t;
		} else {
			t3 = t2; t2 = t;
		}
	} else if (fabs(t3) > fabs(t2)) {
		t = t2; t2 = t3;
		if (fabs(t4) > fabs(t2)) {
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

dcomplex
cpow(dcomplex z, dcomplex w) {
	dcomplex ans;
	double x, y, u, v, t, c, s, r, x2, y2;
	double b[4], t1, t2, t3, t4, w1, w2, u1, v1, x1, y1;
	int ix, iy, hx, lx, hy, ly, hv, hu, iu, iv, lu, lv;
	int i, j, k;

	x = D_RE(z);
	y = D_IM(z);
	u = D_RE(w);
	v = D_IM(w);
	hx = ((int *) &x)[HIWORD];
	lx = ((int *) &x)[LOWORD];
	hy = ((int *) &y)[HIWORD];
	ly = ((int *) &y)[LOWORD];
	hu = ((int *) &u)[HIWORD];
	lu = ((int *) &u)[LOWORD];
	hv = ((int *) &v)[HIWORD];
	lv = ((int *) &v)[LOWORD];
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	iu = hu & 0x7fffffff;
	iv = hv & 0x7fffffff;

	j = 0;
	if ((iv | lv) == 0) {	/* z**(real) */
		if (((hu - 0x3ff00000) | lu) == 0) {	/* z ** 1 = z */
			D_RE(ans) = x;
			D_IM(ans) = y;
		} else if ((iu | lu) == 0) {	/* z ** 0 = 1 */
			D_RE(ans) = one;
			D_IM(ans) = zero;
		} else if ((iy | ly) == 0) {	/* (real)**(real) */
			D_IM(ans) = zero;
			if (hx < 0 && ix < hiinf && iu < hiinf) {
				/* -x ** u  is exp(i*pi*u)*pow(x,u) */
				r = pow(-x, u);
				sincospi(u, &s, &c);
				D_RE(ans) = (c == zero)? c: c * r;
				D_IM(ans) = (s == zero)? s: s * r;
			} else
				D_RE(ans) = pow(x, u);
		} else if (((ix | lx) == 0) || ix >= hiinf || iy >= hiinf) {
			if (isnan(x) || isnan(y) || isnan(u))
				D_RE(ans) = D_IM(ans) = x + y + u;
			else {
				if ((ix | lx) == 0)
					r = fabs(y);
				else
					r = fabs(x) + fabs(y);
				t = atan2pi(y, x);
				sincospi(t * u, &s, &c);
				D_RE(ans) = (c == zero)? c: c * r;
				D_IM(ans) = (s == zero)? s: s * r;
			}
		} else if (((ix - iy) | (lx - ly)) == 0) {   /* |x| = |y| */
			if (hx >= 0) {
				t = (hy >= 0)? 0.25 : -0.25;
				sincospi(t * u, &s, &c);
			} else if ((lu & 3) == 0) {
				t = (hy >= 0)? 0.75 : -0.75;
				sincospi(t * u, &s, &c);
			} else {
				r = (hy >= 0)? u : -u;
				t = -0.25 * r;
				w1 = r + t;
				w2 = t - (w1 - r);
				sincospi(w1, &t1, &t2);
				sincospi(w2, &t3, &t4);
				s = t1 * t4 + t3 * t2;
				c = t2 * t4 - t1 * t3;
			}
			if (ix < 0x3fe00000)	/* |x| < 1/2 */
				r = pow(fabs(x + x), u) * exp2(-0.5 * u);
			else if (ix >= 0x3ff00000 || iu < 0x408ff800)
				/* |x| >= 1 or |u| < 1023 */
				r = pow(fabs(x), u) * exp2(0.5 * u);
			else   /* special treatment */
				j = 2;
			if (j == 0) {
				D_RE(ans) = (c == zero)? c: c * r;
				D_IM(ans) = (s == zero)? s: s * r;
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
		t = fabs(x) + fabs(y) + fabs(u) + fabs(v);
		D_RE(ans) = D_IM(ans) = t - t;
	} else {
		k = 0;	/* no scaling */
		if (iu > 0x7f000000 || iv > 0x7f000000) {
			u *= .0009765625; /* scale 2**-10 to avoid overflow */
			v *= .0009765625;
			k = 1;	/* scale by 2**-10 */
		}
		/*
		 * Use similated higher precision arithmetic to compute:
		 * r = u * log(hypot(x, y)) - v * atan2(y, x)
		 * q = u * atan2(y, x) + v * log(hypot(x, y))
		 */
		t1 = __k_clog_r(x, y, &t2);
		t3 = __k_atan2(y, x, &t4);
		x1 = t1;
		y1 = t3;
		u1 = u;
		v1 = v;
		((int *) &u1)[LOWORD] &= 0xf8000000;
		((int *) &v1)[LOWORD] &= 0xf8000000;
		((int *) &x1)[LOWORD] &= 0xf8000000;
		((int *) &y1)[LOWORD] &= 0xf8000000;
		x2 = t2 - (x1 - t1);	/* log(hypot(x,y)) = x1 + x2 */
		y2 = t4 - (y1 - t3);	/* atan2(y,x) = y1 + y2 */
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
				w1 = sum4fp(b, &w2);
			}
			sincos(w1, &t1, &t2);
			sincos(w2, &t3, &t4);
			s = t1 * t4 + t3 * t2;
			c = t2 * t4 - t1 * t3;
			if (k == 1)
			/*
			 * square (cos(q) + i sin(q)) k times to get
			 * (cos(2^k * q + i sin(2^k * q)
			 */
				for (i = 0; i < 10; i++) {
					t1 = s * c;
					c = (c + s) * (c - s);
					s = t1 + t1;
				}
		}
		/* compute r = u * (t1, t2) - v * (t3, t4) */
		b[0] = u1 * x1;
		b[1] = (u - u1) * x1 + u * x2;
		if (j == 1) {	/* v = 0 */
			w1 = b[0] + b[1];
			w2 = b[1] - (w1 - b[0]);
		} else {
			b[2] = -v1 * y1;
			b[3] = (v1 - v) * y1 - v * y2;
			w1 = sum4fp(b, &w2);
		}
		/* check over/underflow for exp(w1 + w2) */
		if (k && fabs(w1) < 1000.0) {
			w1 *= 1024; w2 *= 1024; k = 0;
		}
		hx = ((int *) &w1)[HIWORD];
		lx = ((int *) &w1)[LOWORD];
		ix = hx & 0x7fffffff;
		/* compute exp(w1 + w2) */
		if (ix < 0x3c900000) /* exp(tiny < 2**-54) = 1 */
			r = one;
		else if (ix >= 0x40880000) /* overflow/underflow */
			r = (hx < 0)? tiny * tiny : huge * huge;
		else {	/* compute exp(w1 + w2) */
			k = (int) (invln2 * w1 + ((hx >= 0)? 0.5 : -0.5));
			t1 = (double) k;
			t2 = w1 - t1 * ln2hi;
			t3 = w2 - t1 * ln2lo;
			r = exp(t2 + t3);
		}
		if (c != zero) c *= r;
		if (s != zero) s *= r;
		if (k != 0) {
			c = scalbn(c, k);
			s = scalbn(s, k);
		}
		D_RE(ans) = c;
		D_IM(ans) = s;
	}
	return (ans);
}
