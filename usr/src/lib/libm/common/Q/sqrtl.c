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

#pragma weak __sqrtl = sqrtl

#include "libm.h"
#include "longdouble.h"

extern int __swapTE(int);
extern int __swapEX(int);
extern enum fp_direction_type __swapRD(enum fp_direction_type);

/*
 * in struct longdouble, msw consists of
 *	unsigned short	sgn:1;
 *	unsigned short	exp:15;
 *	unsigned short	frac1:16;
 */

#ifdef __LITTLE_ENDIAN

/* array indices used to access words within a double */
#define	HIWORD	1
#define	LOWORD	0

/* structure used to access words within a quad */
union longdouble {
	struct {
		unsigned int	frac4;
		unsigned int	frac3;
		unsigned int	frac2;
		unsigned int	msw;
	} l;
	long double	d;
};

/* default NaN returned for sqrt(neg) */
static const union longdouble
	qnan = { 0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff };

/* signalling NaN used to raise invalid */
static const union {
	unsigned u[2];
	double d;
} snan = { 0, 0x7ff00001 };

#else

/* array indices used to access words within a double */
#define	HIWORD	0
#define	LOWORD	1

/* structure used to access words within a quad */
union longdouble {
	struct {
		unsigned int	msw;
		unsigned int	frac2;
		unsigned int	frac3;
		unsigned int	frac4;
	} l;
	long double	d;
};

/* default NaN returned for sqrt(neg) */
static const union longdouble
	qnan = { 0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff };

/* signalling NaN used to raise invalid */
static const union {
	unsigned u[2];
	double d;
} snan = { 0x7ff00001, 0 };

#endif /* __LITTLE_ENDIAN */


static const double
	zero = 0.0,
	half = 0.5,
	one = 1.0,
	huge = 1.0e300,
	tiny = 1.0e-300,
	two36 = 6.87194767360000000000e+10,
	two30 = 1.07374182400000000000e+09,
	two6 = 6.40000000000000000000e+01,
	two4 = 1.60000000000000000000e+01,
	twom18 = 3.81469726562500000000e-06,
	twom28 = 3.72529029846191406250e-09,
	twom42 = 2.27373675443232059479e-13,
	twom60 = 8.67361737988403547206e-19,
	twom62 = 2.16840434497100886801e-19,
	twom66 = 1.35525271560688054251e-20,
	twom90 = 8.07793566946316088742e-28,
	twom113 = 9.62964972193617926528e-35,
	twom124 = 4.70197740328915003187e-38;


/*
*	Extract the exponent and normalized significand (represented as
*	an array of five doubles) from a finite, nonzero quad.
*/
static int
__q_unpack(const union longdouble *x, double *s)
{
	union {
		double			d;
		unsigned int	l[2];
	} u;
	double			b;
	unsigned int	lx, w[3];
	int				ex;

	/* get the normalized significand and exponent */
	ex = (int) ((x->l.msw & 0x7fffffff) >> 16);
	lx = x->l.msw & 0xffff;
	if (ex)
	{
		lx |= 0x10000;
		w[0] = x->l.frac2;
		w[1] = x->l.frac3;
		w[2] = x->l.frac4;
	}
	else
	{
		if (lx | (x->l.frac2 & 0xfffe0000))
		{
			w[0] = x->l.frac2;
			w[1] = x->l.frac3;
			w[2] = x->l.frac4;
			ex = 1;
		}
		else if (x->l.frac2 | (x->l.frac3 & 0xfffe0000))
		{
			lx = x->l.frac2;
			w[0] = x->l.frac3;
			w[1] = x->l.frac4;
			w[2] = 0;
			ex = -31;
		}
		else if (x->l.frac3 | (x->l.frac4 & 0xfffe0000))
		{
			lx = x->l.frac3;
			w[0] = x->l.frac4;
			w[1] = w[2] = 0;
			ex = -63;
		}
		else
		{
			lx = x->l.frac4;
			w[0] = w[1] = w[2] = 0;
			ex = -95;
		}
		while ((lx & 0x10000) == 0)
		{
			lx = (lx << 1) | (w[0] >> 31);
			w[0] = (w[0] << 1) | (w[1] >> 31);
			w[1] = (w[1] << 1) | (w[2] >> 31);
			w[2] <<= 1;
			ex--;
		}
	}

	/* extract the significand into five doubles */
	u.l[HIWORD] = 0x42300000;
	u.l[LOWORD] = 0;
	b = u.d;
	u.l[LOWORD] = lx;
	s[0] = u.d - b;

	u.l[HIWORD] = 0x40300000;
	u.l[LOWORD] = 0;
	b = u.d;
	u.l[LOWORD] = w[0] & 0xffffff00;
	s[1] = u.d - b;

	u.l[HIWORD] = 0x3e300000;
	u.l[LOWORD] = 0;
	b = u.d;
	u.l[HIWORD] |= w[0] & 0xff;
	u.l[LOWORD] = w[1] & 0xffff0000;
	s[2] = u.d - b;

	u.l[HIWORD] = 0x3c300000;
	u.l[LOWORD] = 0;
	b = u.d;
	u.l[HIWORD] |= w[1] & 0xffff;
	u.l[LOWORD] = w[2] & 0xff000000;
	s[3] = u.d - b;

	u.l[HIWORD] = 0x3c300000;
	u.l[LOWORD] = 0;
	b = u.d;
	u.l[LOWORD] = w[2] & 0xffffff;
	s[4] = u.d - b;

	return ex - 0x3fff;
}


/*
*	Pack an exponent and array of three doubles representing a finite,
*	nonzero number into a quad.  Assume the sign is already there and
*	the rounding mode has been fudged accordingly.
*/
static void
__q_pack(const double *z, int exp, enum fp_direction_type rm,
	union longdouble *x, int *inexact)
{
	union {
		double			d;
		unsigned int	l[2];
	} u;
	double			s[3], t, t2;
	unsigned int	msw, frac2, frac3, frac4;

	/* bias exponent and strip off integer bit */
	exp += 0x3fff;
	s[0] = z[0] - one;
	s[1] = z[1];
	s[2] = z[2];

	/*
	 * chop the significand to obtain the fraction;
	 * use round-to-minus-infinity to ensure chopping
	 */
	(void) __swapRD(fp_negative);

	/* extract the first eighty bits of fraction */
	t = s[1] + s[2];
	u.d = two36 + (s[0] + t);
	msw = u.l[LOWORD];
	s[0] -= (u.d - two36);

	u.d = two4 + (s[0] + t);
	frac2 = u.l[LOWORD];
	s[0] -= (u.d - two4);

	u.d = twom28 + (s[0] + t);
	frac3 = u.l[LOWORD];
	s[0] -= (u.d - twom28);

	/* condense the remaining fraction; errors here won't matter */
	t = s[0] + s[1];
	s[1] = ((s[0] - t) + s[1]) + s[2];
	s[0] = t;

	/* get the last word of fraction */
	u.d = twom60 + (s[0] + s[1]);
	frac4 = u.l[LOWORD];
	s[0] -= (u.d - twom60);

	/*
	 * keep track of what's left for rounding; note that
	 * t2 will be non-negative due to rounding mode
	 */
	t = s[0] + s[1];
	t2 = (s[0] - t) + s[1];

	if (t != zero)
	{
		*inexact = 1;

		/* decide whether to round the fraction up */
		if (rm == fp_positive || (rm == fp_nearest && (t > twom113 ||
			(t == twom113 && (t2 != zero || frac4 & 1)))))
		{
			/* round up and renormalize if necessary */
			if (++frac4 == 0)
				if (++frac3 == 0)
					if (++frac2 == 0)
						if (++msw == 0x10000)
						{
							msw = 0;
							exp++;
						}
		}
	}

	/* assemble the result */
	x->l.msw |= msw | (exp << 16);
	x->l.frac2 = frac2;
	x->l.frac3 = frac3;
	x->l.frac4 = frac4;
}


/*
*	Compute the square root of x and place the TP result in s.
*/
static void
__q_tp_sqrt(const double *x, double *s)
{
	double	c, rr, r[3], tt[3], t[5];

	/* approximate the divisor for the Newton iteration */
	c = sqrt((x[0] + x[1]) + x[2]);
	rr = half / c;

	/* compute the first five "digits" of the square root */
	t[0] = (c + two30) - two30;
	tt[0] = t[0] + t[0];
	r[0] = ((x[0] - t[0] * t[0]) + x[1]) + x[2];

	t[1] = (rr * (r[0] + x[3]) + two6) - two6;
	tt[1] = t[1] + t[1];
	r[0] -= tt[0] * t[1];
	r[1] = x[3] - t[1] * t[1];
	c = (r[1] + twom18) - twom18;
	r[0] += c;
	r[1] = (r[1] - c) + x[4];

	t[2] = (rr * (r[0] + r[1]) + twom18) - twom18;
	tt[2] = t[2] + t[2];
	r[0] -= tt[0] * t[2];
	r[1] -= tt[1] * t[2];
	c = (r[1] + twom42) - twom42;
	r[0] += c;
	r[1] = (r[1] - c) - t[2] * t[2];

	t[3] = (rr * (r[0] + r[1]) + twom42) - twom42;
	r[0] = ((r[0] - tt[0] * t[3]) + r[1]) - tt[1] * t[3];
	r[1] = -tt[2] * t[3];
	c = (r[1] + twom90) - twom90;
	r[0] += c;
	r[1] = (r[1] - c) - t[3] * t[3];

	t[4] = (rr * (r[0] + r[1]) + twom66) - twom66;

	/* here we just need to get the sign of the remainder */
	c = (((((r[0] - tt[0] * t[4]) - tt[1] * t[4]) + r[1])
		- tt[2] * t[4]) - (t[3] + t[3]) * t[4]) - t[4] * t[4];

	/* reduce to three doubles */
	t[0] += t[1];
	t[1] = t[2] + t[3];
	t[2] = t[4];

	/* if the third term might lie on a rounding boundary, perturb it */
	if (c != zero && t[2] == (twom62 + t[2]) - twom62)
	{
		if (c < zero)
			t[2] -= twom124;
		else
			t[2] += twom124;
	}

	/* condense the square root */
	c = t[1] + t[2];
	t[2] += (t[1] - c);
	t[1] = c;
	c = t[0] + t[1];
	s[1] = t[1] + (t[0] - c);
	s[0] = c;
	if (s[1] == zero)
	{
		c = s[0] + t[2];
		s[1] = t[2] + (s[0] - c);
		s[0] = c;
		s[2] = zero;
	}
	else
	{
		c = s[1] + t[2];
		s[2] = t[2] + (s[1] - c);
		s[1] = c;
	}
}


long double
sqrtl(long double ldx)
{
	union	longdouble		x;
	volatile double			t;
	double					xx[5], zz[3];
	enum fp_direction_type	rm;
	int				ex, inexact, exc, traps;

	/* clear cexc */
	t = zero;
	t -= zero;

	/* check for zero operand */
	x.d = ldx;
	if (!((x.l.msw & 0x7fffffff) | x.l.frac2 | x.l.frac3 | x.l.frac4))
		return ldx;

	/* handle nan and inf cases */
	if ((x.l.msw & 0x7fffffff) >= 0x7fff0000)
	{
		if ((x.l.msw & 0xffff) | x.l.frac2 | x.l.frac3 | x.l.frac4)
		{
			if (!(x.l.msw & 0x8000))
			{
				/* snan, signal invalid */
				t += snan.d;
			}
			x.l.msw |= 0x8000;
			return x.d;
		}
		if (x.l.msw & 0x80000000)
		{
			/* sqrt(-inf), signal invalid */
			t = -one;
			t = sqrt(t);
			return qnan.d;
		}
		/* sqrt(inf), return inf */
		return x.d;
	}

	/* handle negative numbers */
	if (x.l.msw & 0x80000000)
	{
		t = -one;
		t = sqrt(t);
		return qnan.d;
	}

	/* now x is finite, positive */

	traps = __swapTE(0);
	exc = __swapEX(0);
	rm = __swapRD(fp_nearest);

	ex = __q_unpack(&x, xx);
	if (ex & 1)
	{
		/* make exponent even */
		xx[0] += xx[0];
		xx[1] += xx[1];
		xx[2] += xx[2];
		xx[3] += xx[3];
		xx[4] += xx[4];
		ex--;
	}
	__q_tp_sqrt(xx, zz);

	/* put everything together */
	x.l.msw = 0;
	inexact = 0;
	__q_pack(zz, ex >> 1, rm, &x, &inexact);

	(void) __swapRD(rm);
	(void) __swapEX(exc);
	(void) __swapTE(traps);
	if (inexact)
	{
		t = huge;
		t += tiny;
	}
	return x.d;
}
