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

/*
 * double __k_lgamma(double x, int *signgamp);
 *
 * K.C. Ng, March, 1989.
 *
 * Part of the algorithm is based on W. Cody's lgamma function.
 */

#include "libm.h"

static const double
one	= 1.0,
zero	= 0.0,
hln2pi	= 0.9189385332046727417803297,	/* log(2*pi)/2 */
pi	= 3.1415926535897932384626434,
two52	= 4503599627370496.0,		/* 43300000,00000000 (used by sin_pi) */
/*
 * Numerator and denominator coefficients for rational minimax Approximation
 * P/Q over (0.5,1.5).
 */
D1 = 	-5.772156649015328605195174e-1,
p7 =	 4.945235359296727046734888e0,
p6 =	 2.018112620856775083915565e2,
p5 =	 2.290838373831346393026739e3,
p4 =	 1.131967205903380828685045e4,
p3 =	 2.855724635671635335736389e4,
p2 =	 3.848496228443793359990269e4,
p1 =	 2.637748787624195437963534e4,
p0 =	 7.225813979700288197698961e3,
q7 =	 6.748212550303777196073036e1,
q6 =	 1.113332393857199323513008e3,
q5 =	 7.738757056935398733233834e3,
q4 =	 2.763987074403340708898585e4,
q3 =	 5.499310206226157329794414e4,
q2 =	 6.161122180066002127833352e4,
q1 =	 3.635127591501940507276287e4,
q0 =	 8.785536302431013170870835e3,
/*
 * Numerator and denominator coefficients for rational minimax Approximation
 * G/H over (1.5,4.0).
 */
D2 =	 4.227843350984671393993777e-1,
g7 =	 4.974607845568932035012064e0,
g6 =	 5.424138599891070494101986e2,
g5 =	 1.550693864978364947665077e4,
g4 =	 1.847932904445632425417223e5,
g3 =	 1.088204769468828767498470e6,
g2 =	 3.338152967987029735917223e6,
g1 =	 5.106661678927352456275255e6,
g0 =	 3.074109054850539556250927e6,
h7 =	 1.830328399370592604055942e2,
h6 =	 7.765049321445005871323047e3,
h5 =	 1.331903827966074194402448e5,
h4 =	 1.136705821321969608938755e6,
h3 =	 5.267964117437946917577538e6,
h2 =	 1.346701454311101692290052e7,
h1 =	 1.782736530353274213975932e7,
h0 =	 9.533095591844353613395747e6,
/*
 * Numerator and denominator coefficients for rational minimax Approximation
 * U/V over (4.0,12.0).
 */
D4 =	 1.791759469228055000094023e0,
u7 =	 1.474502166059939948905062e4,
u6 =	 2.426813369486704502836312e6,
u5 =	 1.214755574045093227939592e8,
u4 =	 2.663432449630976949898078e9,
u3 =	 2.940378956634553899906876e10,
u2 =	 1.702665737765398868392998e11,
u1 =	 4.926125793377430887588120e11,
u0 =	 5.606251856223951465078242e11,
v7 =	 2.690530175870899333379843e3,
v6 =	 6.393885654300092398984238e5,
v5 =	 4.135599930241388052042842e7,
v4 =	 1.120872109616147941376570e9,
v3 =	 1.488613728678813811542398e10,
v2 =	 1.016803586272438228077304e11,
v1 =	 3.417476345507377132798597e11,
v0 =	 4.463158187419713286462081e11,
/*
 * Coefficients for minimax approximation over (12, INF).
 */
c5 =	-1.910444077728e-03,
c4 =	 8.4171387781295e-04,
c3 =	-5.952379913043012e-04,
c2 =	 7.93650793500350248e-04,
c1 =	-2.777777777777681622553e-03,
c0 =	 8.333333333333333331554247e-02,
c6 =	 5.7083835261e-03;

/*
 * Return sin(pi*x).  We assume x is finite and negative, and if it
 * is an integer, then the sign of the zero returned doesn't matter.
 */
static double
sin_pi(double x) {
	double	y, z;
	int	n;

	y = -x;
	if (y <= 0.25)
		return (__k_sin(pi * x, 0.0));
	if (y >= two52)
		return (zero);
	z = floor(y);
	if (y == z)
		return (zero);

	/* argument reduction: set y = |x| mod 2 */
	y *= 0.5;
	y = 2.0 * (y - floor(y));

	/* now floor(y * 4) tells which octant y is in */
	n = (int)(y * 4.0);
	switch (n) {
	case 0:
		y = __k_sin(pi * y, 0.0);
		break;
	case 1:
	case 2:
		y = __k_cos(pi * (0.5 - y), 0.0);
		break;
	case 3:
	case 4:
		y = __k_sin(pi * (1.0 - y), 0.0);
		break;
	case 5:
	case 6:
		y = -__k_cos(pi * (y - 1.5), 0.0);
		break;
	default:
		y = __k_sin(pi * (y - 2.0), 0.0);
		break;
	}
	return (-y);
}

static double
neg(double z, int *signgamp) {
	double	t, p;

	/*
	 * written by K.C. Ng,  Feb 2, 1989.
	 *
	 * Since
	 *		-z*G(-z)*G(z) = pi/sin(pi*z),
	 * we have
	 * 	G(-z) = -pi/(sin(pi*z)*G(z)*z)
	 * 	      =  pi/(sin(pi*(-z))*G(z)*z)
	 * Algorithm
	 *		z = |z|
	 *		t = sin_pi(z); ...note that when z>2**52, z is an int
	 *		and hence t=0.
	 *
	 *		if (t == 0.0) return 1.0/0.0;
	 *		if (t< 0.0) *signgamp = -1; else t= -t;
	 *		if (z+1.0 == 1.0)	...tiny z
	 *		    return -log(z);
	 *		else
	 *		    return log(pi/(t*z))-__k_lgamma(z, signgamp);
	 */

	t = sin_pi(z);			/* t := sin(pi*z) */
	if (t == zero)			/* return 1.0/0.0 = +INF */
		return (one / fabs(t));
	z = -z;
	p = z + one;
	if (p == one)
		p = -log(z);
	else
		p = log(pi / (fabs(t) * z)) - __k_lgamma(z, signgamp);
	if (t < zero)
		*signgamp = -1;
	return (p);
}

double
__k_lgamma(double x, int *signgamp) {
	double	t, p, q, cr, y;

	/* purge off +-inf, NaN and negative arguments */
	if (!finite(x))
		return (x * x);
	*signgamp = 1;
	if (signbit(x))
		return (neg(x, signgamp));

	/* lgamma(x) ~ log(1/x) for really tiny x */
	t = one + x;
	if (t == one) {
		if (x == zero)
			return (one / x);
		return (-log(x));
	}

	/* for tiny < x < inf */
	if (x <= 1.5) {
		if (x < 0.6796875) {
			cr = -log(x);
			y = x;
		} else {
			cr = zero;
			y = x - one;
		}

		if (x <= 0.5 || x >= 0.6796875) {
			if (x == one)
				return (zero);
			p = p0+y*(p1+y*(p2+y*(p3+y*(p4+y*(p5+y*(p6+y*p7))))));
			q = q0+y*(q1+y*(q2+y*(q3+y*(q4+y*(q5+y*(q6+y*
			    (q7+y)))))));
			return (cr+y*(D1+y*(p/q)));
		} else {
			y = x - one;
			p = g0+y*(g1+y*(g2+y*(g3+y*(g4+y*(g5+y*(g6+y*g7))))));
			q = h0+y*(h1+y*(h2+y*(h3+y*(h4+y*(h5+y*(h6+y*
			    (h7+y)))))));
			return (cr+y*(D2+y*(p/q)));
		}
	} else if (x <= 4.0) {
		if (x == 2.0)
			return (zero);
		y = x - 2.0;
		p = g0+y*(g1+y*(g2+y*(g3+y*(g4+y*(g5+y*(g6+y*g7))))));
		q = h0+y*(h1+y*(h2+y*(h3+y*(h4+y*(h5+y*(h6+y*(h7+y)))))));
		return (y*(D2+y*(p/q)));
	} else if (x <= 12.0) {
		y = x - 4.0;
		p = u0+y*(u1+y*(u2+y*(u3+y*(u4+y*(u5+y*(u6+y*u7))))));
		q = v0+y*(v1+y*(v2+y*(v3+y*(v4+y*(v5+y*(v6+y*(v7-y)))))));
		return (D4+y*(p/q));
	} else if (x <= 1.0e17) {		/* x ~< 2**(prec+3) */
		t = one / x;
		y = t * t;
		p = hln2pi+t*(c0+y*(c1+y*(c2+y*(c3+y*(c4+y*(c5+y*c6))))));
		q = log(x);
		return (x*(q-one)-(0.5*q-p));
	} else {			/* may overflow */
		return (x * (log(x) - 1.0));
	}
}
