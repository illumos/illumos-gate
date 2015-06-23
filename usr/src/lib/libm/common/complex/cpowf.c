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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak __cpowf = cpowf

#include "libm.h"
#include "complex_wrapper.h"

extern void sincospi(double, double *, double *);
extern void sincospif(float, float *, float *);
extern double atan2pi(double, double);
extern float atan2pif(float, float);

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

static const double
	dpi = 3.1415926535897931160E0,	/* Hex 2^ 1 * 1.921FB54442D18 */
	dhalf = 0.5,
	dsqrt2 = 1.41421356237309514547,	/* 3FF6A09E 667F3BCD */
	dinvpi = 0.3183098861837906715377675;

static const float one = 1.0F, zero = 0.0F;

#define	hiinf	0x7f800000

fcomplex
cpowf(fcomplex z, fcomplex w) {
	fcomplex	ans;
	float		x, y, u, v, t, c, s;
	double		dx, dy, du, dv, dt, dc, ds, dp, dq, dr;
	int		ix, iy, hx, hy, hv, hu, iu, iv, j;

	x = F_RE(z);
	y = F_IM(z);
	u = F_RE(w);
	v = F_IM(w);
	hx = THE_WORD(x);
	hy = THE_WORD(y);
	hu = THE_WORD(u);
	hv = THE_WORD(v);
	ix = hx & 0x7fffffff;
	iy = hy & 0x7fffffff;
	iu = hu & 0x7fffffff;
	iv = hv & 0x7fffffff;

	j = 0;
	if (iv == 0) {		/* z**(real) */
		if (hu == 0x3f800000) {	/* (anything) ** 1  is itself */
			F_RE(ans) = x;
			F_IM(ans) = y;
		} else if (iu == 0) {	/* (anything) ** 0  is 1 */
			F_RE(ans) = one;
			F_IM(ans) = zero;
		} else if (iy == 0) {	/* (real)**(real) */
			F_IM(ans) = zero;
			if (hx < 0 && ix < hiinf && iu < hiinf) {
				/* -x ** u  is exp(i*pi*u)*pow(x,u) */
				t = powf(-x, u);
				sincospif(u, &s, &c);
				F_RE(ans) = (c == zero)? c: c * t;
				F_IM(ans) = (s == zero)? s: s * t;
			} else {
				F_RE(ans) = powf(x, u);
			}
		} else if (ix == 0 || ix >= hiinf || iy >= hiinf) {
			if (ix > hiinf || iy > hiinf || iu > hiinf) {
				F_RE(ans) = F_IM(ans) = x + y + u;
			} else {
				v = fabsf(y);
				if (ix != 0)
					v += fabsf(x);
				t = atan2pif(y, x);
				sincospif(t * u, &s, &c);
				F_RE(ans) = (c == zero)? c: c * v;
				F_IM(ans) = (s == zero)? s: s * v;
			}
		} else if (ix == iy) {	/* if |x| == |y| */
#if defined(__i386) && !defined(__amd64)
			int	rp = __swapRP(fp_extended);
#endif
			dx = (double)x;
			du = (double)u;
			dt = (hx >= 0)? 0.25 : 0.75;
			if (hy < 0)
				dt = -dt;
			dr = pow(dsqrt2 * dx, du);
			sincospi(dt * du, &ds, &dc);
			F_RE(ans) = (float)(dr * dc);
			F_IM(ans) = (float)(dr * ds);
#if defined(__i386) && !defined(__amd64)
			if (rp != fp_extended)
				(void) __swapRP(rp);
#endif
		} else {
			j = 1;
		}
		if (j == 0)
			return (ans);
	}
	if (iu >= hiinf || iv >= hiinf || ix >= hiinf || iy >= hiinf) {
		/*
		 * non-zero imaginery part(s) with inf component(s) yields NaN
		 */
		t = fabsf(x) + fabsf(y) + fabsf(u) + fabsf(v);
		F_RE(ans) = F_IM(ans) = t - t;
	} else {
#if defined(__i386) && !defined(__amd64)
		int	rp = __swapRP(fp_extended);
#endif
		/* INDENT OFF */
		/*
		 * r = u*log(hypot(x,y))-v*atan2(y,x),
		 * q = u*atan2(y,x)+v*log(hypot(x,y))
		 * or
		 * r = u*log(hypot(x,y))-v*pi*atan2pi(y,x),
		 * q/pi = u*atan2pi(y,x)+v*log(hypot(x,y))/pi
		 * ans = exp(r)*(cospi(q/pi)  + i sinpi(q/pi))
		 */
		/* INDENT ON */
		dx = (double)x;
		dy = (double)y;
		du = (double)u;
		dv = (double)v;
		if (ix > 0x3f000000 && ix < 0x40000000)	/* .5 < |x| < 2 */
			dt = dhalf * log1p((dx - 1.0) * (dx + 1.0) + dy * dy);
		else if (iy > 0x3f000000 && iy < 0x40000000) /* .5 < |y| < 2 */
			dt = dhalf * log1p((dy - 1.0) * (dy + 1.0) + dx * dx);
		else
			dt = dhalf * log(dx * dx + dy * dy);
		dp = atan2pi(dy, dx);
		if (iv == 0) {	/* dv = 0 */
			dr = exp(du * dt);
			dq = du * dp;
		} else {
			dr = exp(du * dt - dv * dp * dpi);
			dq = du * dp + dv * dt * dinvpi;
		}
		sincospi(dq, &ds, &dc);
		F_RE(ans) = (float)(dr * dc);
		F_IM(ans) = (float)(dr * ds);
#if defined(__i386) && !defined(__amd64)
		if (rp != fp_extended)
			(void) __swapRP(rp);
#endif
	}
	return (ans);
}
