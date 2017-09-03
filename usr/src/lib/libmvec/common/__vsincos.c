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

#include <sys/isa_defs.h>
#include <sys/ccompile.h>

#ifdef _LITTLE_ENDIAN
#define HI(x)	*(1+(int*)x)
#define LO(x)	*(unsigned*)x
#else
#define HI(x)	*(int*)x
#define LO(x)	*(1+(unsigned*)x)
#endif

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

/*
 * vsincos.c
 *
 * Vector sine and cosine function.  Just slight modifications to vcos.c.
 */

extern const double __vlibm_TBL_sincos_hi[], __vlibm_TBL_sincos_lo[];

static const double
	half[2]	= { 0.5, -0.5 },
	one		= 1.0,
	invpio2 = 0.636619772367581343075535,  /* 53 bits of pi/2 */
	pio2_1	= 1.570796326734125614166,  /* first 33 bits of pi/2 */
	pio2_2	= 6.077100506303965976596e-11, /* second 33 bits of pi/2 */
	pio2_3	= 2.022266248711166455796e-21, /* third 33 bits of pi/2 */
	pio2_3t	= 8.478427660368899643959e-32, /* pi/2 - pio2_3 */
	pp1		= -1.666666666605760465276263943134982554676e-0001,
	pp2		=  8.333261209690963126718376566146180944442e-0003,
	qq1		= -4.999999999977710986407023955908711557870e-0001,
	qq2		=  4.166654863857219350645055881018842089580e-0002,
	poly1[2]= { -1.666666666666629669805215138920301589656e-0001,
				-4.999999999999931701464060878888294524481e-0001 },
	poly2[2]= {  8.333333332390951295683993455280336376663e-0003,
				 4.166666666394861917535640593963708222319e-0002 },
	poly3[2]= { -1.984126237997976692791551778230098403960e-0004,
				-1.388888552656142867832756687736851681462e-0003 },
	poly4[2]= {  2.753403624854277237649987622848330351110e-0006,
				 2.478519423681460796618128289454530524759e-0005 };

/* Don't __ the following; acomp will handle it */
extern double fabs(double);
extern void __vlibm_vsincos_big(int, double *, int, double *, int, double *, int, int);

/*
 * y[i*stridey] := sin( x[i*stridex] ), for i = 0..n.
 * c[i*stridec] := cos( x[i*stridex] ), for i = 0..n.
 *
 * Calls __vlibm_vsincos_big to handle all elts which have abs >~ 1.647e+06.
 * Argument reduction is done here for elts pi/4 < arg < 1.647e+06.
 *
 * elts < 2^-27 use the approximation 1.0 ~ cos(x).
 */
void
__vsincos(int n, double * restrict x, int stridex,
				double * restrict y, int stridey,
				double * restrict c, int stridec)
{
	double		x0_or_one[4], x1_or_one[4], x2_or_one[4];
	double		y0_or_zero[4], y1_or_zero[4], y2_or_zero[4];
	double		x0, x1, x2,
			*py0, *py1, *py2,
			*pc0, *pc1, *pc2,
			*xsave, *ysave, *csave;
	unsigned	hx0, hx1, hx2, xsb0, xsb1, xsb2;
	int		i, biguns, nsave, sxsave, sysave, scsave;
	volatile int	v __unused;
	nsave = n;
	xsave = x;
	sxsave = stridex;
	ysave = y;
	sysave = stridey;
	csave = c;
	scsave = stridec;
	biguns = 0;

	do /* MAIN LOOP */
	{

		/* Gotos here so _break_ exits MAIN LOOP. */
LOOP0:  /* Find first arg in right range. */
		xsb0 = HI(x); /* get most significant word */
		hx0 = xsb0 & ~0x80000000; /* mask off sign bit */
		if (hx0 > 0x3fe921fb) {
			/* Too big: arg reduction needed, so leave for second part */
			biguns = 1;
			x += stridex;
			y += stridey;
			c += stridec;
			i = 0;
			if (--n <= 0)
				break;
			goto LOOP0;
		}
		if (hx0 < 0x3e400000) {
			/* Too small.  cos x ~ 1, sin x ~ x. */
			v = *x;
			*c = 1.0;
			*y = *x;
			x += stridex;
			y += stridey;
			c += stridec;
			i = 0;
			if (--n <= 0)
				break;
			goto LOOP0;
		}
		x0 = *x;
		py0 = y;
		pc0 = c;
		x += stridex;
		y += stridey;
		c += stridec;
		i = 1;
		if (--n <= 0)
			break;

LOOP1: /* Get second arg, same as above. */
		xsb1 = HI(x);
		hx1 = xsb1 & ~0x80000000;
		if (hx1 > 0x3fe921fb)
		{
			biguns = 1;
			x += stridex;
			y += stridey;
			c += stridec;
			i = 1;
			if (--n <= 0)
				break;
			goto LOOP1;
		}
		if (hx1 < 0x3e400000)
		{
			v = *x;
			*c = 1.0;
			*y = *x;
			x += stridex;
			y += stridey;
			c += stridec;
			i = 1;
			if (--n <= 0)
				break;
			goto LOOP1;
		}
		x1 = *x;
		py1 = y;
		pc1 = c;
		x += stridex;
		y += stridey;
		c += stridec;
		i = 2;
		if (--n <= 0)
			break;

LOOP2: /* Get third arg, same as above. */
		xsb2 = HI(x);
		hx2 = xsb2 & ~0x80000000;
		if (hx2 > 0x3fe921fb)
		{
			biguns = 1;
			x += stridex;
			y += stridey;
			c += stridec;
			i = 2;
			if (--n <= 0)
				break;
			goto LOOP2;
		}
		if (hx2 < 0x3e400000)
		{
			v = *x;
			*c = 1.0;
			*y = *x;
			x += stridex;
			y += stridey;
			c += stridec;
			i = 2;
			if (--n <= 0)
				break;
			goto LOOP2;
		}
		x2 = *x;
		py2 = y;
		pc2 = c;

		/*
		 * 0x3fc40000 = 5/32 ~ 0.15625
		 * Get msb after subtraction.  Will be 1 only if
		 * hx0 - 5/32 is negative.
		 */
		i = (hx2 - 0x3fc40000) >> 31;
		i |= ((hx1 - 0x3fc40000) >> 30) & 2;
		i |= ((hx0 - 0x3fc40000) >> 29) & 4;
		switch (i)
		{
			double		a1_0, a1_1, a1_2, a2_0, a2_1, a2_2;
			double		w0, w1, w2;
			double		t0, t1, t2, t1_0, t1_1, t1_2, t2_0, t2_1, t2_2;
			double		z0, z1, z2;
			unsigned	j0, j1, j2;

		case 0: /* All are > 5/32 */
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			j1 = (xsb1 + 0x4000) & 0xffff8000;
			j2 = (xsb2 + 0x4000) & 0xffff8000;

			HI(&t0) = j0;
			HI(&t1) = j1;
			HI(&t2) = j2;
			LO(&t0) = 0;
			LO(&t1) = 0;
			LO(&t2) = 0;

			x0 -= t0;
			x1 -= t1;
			x2 -= t2;

			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;

			t0 = z0 * (qq1 + z0 * qq2);
			t1 = z1 * (qq1 + z1 * qq2);
			t2 = z2 * (qq1 + z2 * qq2);

			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
			w2 = x2 * (one + z2 * (pp1 + z2 * pp2));

			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j2 = (((j2 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;

			xsb0 = (xsb0 >> 30) & 2;
			xsb1 = (xsb1 >> 30) & 2;
			xsb2 = (xsb2 >> 30) & 2;

			a1_0 = __vlibm_TBL_sincos_hi[j0+xsb0]; /* sin_hi(t) */
			a1_1 = __vlibm_TBL_sincos_hi[j1+xsb1];
			a1_2 = __vlibm_TBL_sincos_hi[j2+xsb2];

			a2_0 = __vlibm_TBL_sincos_hi[j0+1];	/* cos_hi(t) */
			a2_1 = __vlibm_TBL_sincos_hi[j1+1];
			a2_2 = __vlibm_TBL_sincos_hi[j2+1];
				/* cos_lo(t) */
			t2_0 = __vlibm_TBL_sincos_lo[j0+1] - (a1_0*w0 - a2_0*t0);
			t2_1 = __vlibm_TBL_sincos_lo[j1+1] - (a1_1*w1 - a2_1*t1);
			t2_2 = __vlibm_TBL_sincos_lo[j2+1] - (a1_2*w2 - a2_2*t2);

			*pc0 = a2_0 + t2_0;
			*pc1 = a2_1 + t2_1;
			*pc2 = a2_2 + t2_2;

			t1_0 = a2_0*w0 + a1_0*t0;
			t1_1 = a2_1*w1 + a1_1*t1;
			t1_2 = a2_2*w2 + a1_2*t2;

			t1_0 += __vlibm_TBL_sincos_lo[j0+xsb0]; /* sin_lo(t) */
			t1_1 += __vlibm_TBL_sincos_lo[j1+xsb1];
			t1_2 += __vlibm_TBL_sincos_lo[j2+xsb2];

			*py0 = a1_0 + t1_0;
			*py1 = a1_1 + t1_1;
			*py2 = a1_2 + t1_2;

			break;

		case 1:
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			j1 = (xsb1 + 0x4000) & 0xffff8000;
			HI(&t0) = j0;
			HI(&t1) = j1;
			LO(&t0) = 0;
			LO(&t1) = 0;
			x0 -= t0;
			x1 -= t1;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (qq1 + z0 * qq2);
			t1 = z1 * (qq1 + z1 * qq2);
			t2 = z2 * (poly3[1] + z2 * poly4[1]);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
			t2 = z2 * (poly1[1] + z2 * (poly2[1] + t2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			xsb1 = (xsb1 >> 30) & 2;

			a1_0 = __vlibm_TBL_sincos_hi[j0+xsb0]; /* sin_hi(t) */
			a1_1 = __vlibm_TBL_sincos_hi[j1+xsb1];

			a2_0 = __vlibm_TBL_sincos_hi[j0+1];	/* cos_hi(t) */
			a2_1 = __vlibm_TBL_sincos_hi[j1+1];
				/* cos_lo(t) */
			t2_0 = __vlibm_TBL_sincos_lo[j0+1] - (a1_0*w0 - a2_0*t0);
			t2_1 = __vlibm_TBL_sincos_lo[j1+1] - (a1_1*w1 - a2_1*t1);

			*pc0 = a2_0 + t2_0;
			*pc1 = a2_1 + t2_1;
			*pc2 = one + t2;

			t1_0 = a2_0*w0 + a1_0*t0;
			t1_1 = a2_1*w1 + a1_1*t1;
			t2 = z2 * (poly3[0] + z2 * poly4[0]);

			t1_0 += __vlibm_TBL_sincos_lo[j0+xsb0]; /* sin_lo(t) */
			t1_1 += __vlibm_TBL_sincos_lo[j1+xsb1];
			t2 = z2 * (poly1[0] + z2 * (poly2[0] + t2));

			*py0 = a1_0 + t1_0;
			*py1 = a1_1 + t1_1;
			t2 = x2 + x2 * t2;
			*py2 = t2;

			break;

		case 2:
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			j2 = (xsb2 + 0x4000) & 0xffff8000;
			HI(&t0) = j0;
			HI(&t2) = j2;
			LO(&t0) = 0;
			LO(&t2) = 0;
			x0 -= t0;
			x2 -= t2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (qq1 + z0 * qq2);
			t1 = z1 * (poly3[1] + z1 * poly4[1]);
			t2 = z2 * (qq1 + z2 * qq2);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			t1 = z1 * (poly1[1] + z1 * (poly2[1] + t1));
			w2 = x2 * (one + z2 * (pp1 + z2 * pp2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j2 = (((j2 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			xsb2 = (xsb2 >> 30) & 2;

			a1_0 = __vlibm_TBL_sincos_hi[j0+xsb0]; /* sin_hi(t) */
			a1_2 = __vlibm_TBL_sincos_hi[j2+xsb2];

			a2_0 = __vlibm_TBL_sincos_hi[j0+1];	/* cos_hi(t) */
			a2_2 = __vlibm_TBL_sincos_hi[j2+1];
				/* cos_lo(t) */
			t2_0 = __vlibm_TBL_sincos_lo[j0+1] - (a1_0*w0 - a2_0*t0);
			t2_2 = __vlibm_TBL_sincos_lo[j2+1] - (a1_2*w2 - a2_2*t2);

			*pc0 = a2_0 + t2_0;
			*pc1 = one + t1;
			*pc2 = a2_2 + t2_2;

			t1_0 = a2_0*w0 + a1_0*t0;
			t1 = z1 * (poly3[0] + z1 * poly4[0]);
			t1_2 = a2_2*w2 + a1_2*t2;

			t1_0 += __vlibm_TBL_sincos_lo[j0+xsb0]; /* sin_lo(t) */
			t1 = z1 * (poly1[0] + z1 * (poly2[0] + t1));
			t1_2 += __vlibm_TBL_sincos_lo[j2+xsb2];

			*py0 = a1_0 + t1_0;
			t1 = x1 + x1 * t1;
			*py1 = t1;
			*py2 = a1_2 + t1_2;

			break;

		case 3:
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			HI(&t0) = j0;
			LO(&t0) = 0;
			x0 -= t0;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (qq1 + z0 * qq2);
			t1 = z1 * (poly3[1] + z1 * poly4[1]);
			t2 = z2 * (poly3[1] + z2 * poly4[1]);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			t1 = z1 * (poly1[1] + z1 * (poly2[1] + t1));
			t2 = z2 * (poly1[1] + z2 * (poly2[1] + t2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			a1_0 = __vlibm_TBL_sincos_hi[j0+xsb0]; /* sin_hi(t) */

			a2_0 = __vlibm_TBL_sincos_hi[j0+1];	/* cos_hi(t) */

			t2_0 = __vlibm_TBL_sincos_lo[j0+1] - (a1_0*w0 - a2_0*t0);

			*pc0 = a2_0 + t2_0;
			*pc1 = one + t1;
			*pc2 = one + t2;

			t1_0 = a2_0*w0 + a1_0*t0;
			t1 = z1 * (poly3[0] + z1 * poly4[0]);
			t2 = z2 * (poly3[0] + z2 * poly4[0]);

			t1_0 += __vlibm_TBL_sincos_lo[j0+xsb0]; /* sin_lo(t) */
			t1 = z1 * (poly1[0] + z1 * (poly2[0] + t1));
			t2 = z2 * (poly1[0] + z2 * (poly2[0] + t2));

			*py0 = a1_0 + t1_0;
			t1 = x1 + x1 * t1;
			*py1 = t1;
			t2 = x2 + x2 * t2;
			*py2 = t2;

			break;

		case 4:
			j1 = (xsb1 + 0x4000) & 0xffff8000;
			j2 = (xsb2 + 0x4000) & 0xffff8000;
			HI(&t1) = j1;
			HI(&t2) = j2;
			LO(&t1) = 0;
			LO(&t2) = 0;
			x1 -= t1;
			x2 -= t2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (poly3[1] + z0 * poly4[1]);
			t1 = z1 * (qq1 + z1 * qq2);
			t2 = z2 * (qq1 + z2 * qq2);
			t0 = z0 * (poly1[1] + z0 * (poly2[1] + t0));
			w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
			w2 = x2 * (one + z2 * (pp1 + z2 * pp2));
			j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j2 = (((j2 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb1 = (xsb1 >> 30) & 2;
			xsb2 = (xsb2 >> 30) & 2;

			a1_1 = __vlibm_TBL_sincos_hi[j1+xsb1];
			a1_2 = __vlibm_TBL_sincos_hi[j2+xsb2];

			a2_1 = __vlibm_TBL_sincos_hi[j1+1];
			a2_2 = __vlibm_TBL_sincos_hi[j2+1];
				/* cos_lo(t) */
			t2_1 = __vlibm_TBL_sincos_lo[j1+1] - (a1_1*w1 - a2_1*t1);
			t2_2 = __vlibm_TBL_sincos_lo[j2+1] - (a1_2*w2 - a2_2*t2);

			*pc0 = one + t0;
			*pc1 = a2_1 + t2_1;
			*pc2 = a2_2 + t2_2;

			t0 = z0 * (poly3[0] + z0 * poly4[0]);
			t1_1 = a2_1*w1 + a1_1*t1;
			t1_2 = a2_2*w2 + a1_2*t2;

			t0 = z0 * (poly1[0] + z0 * (poly2[0] + t0));
			t1_1 += __vlibm_TBL_sincos_lo[j1+xsb1];
			t1_2 += __vlibm_TBL_sincos_lo[j2+xsb2];

			t0 = x0 + x0 * t0;
			*py0 = t0;
			*py1 = a1_1 + t1_1;
			*py2 = a1_2 + t1_2;

			break;

		case 5:
			j1 = (xsb1 + 0x4000) & 0xffff8000;
			HI(&t1) = j1;
			LO(&t1) = 0;
			x1 -= t1;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (poly3[1] + z0 * poly4[1]);
			t1 = z1 * (qq1 + z1 * qq2);
			t2 = z2 * (poly3[1] + z2 * poly4[1]);
			t0 = z0 * (poly1[1] + z0 * (poly2[1] + t0));
			w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
			t2 = z2 * (poly1[1] + z2 * (poly2[1] + t2));
			j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb1 = (xsb1 >> 30) & 2;

			a1_1 = __vlibm_TBL_sincos_hi[j1+xsb1];

			a2_1 = __vlibm_TBL_sincos_hi[j1+1];

			t2_1 = __vlibm_TBL_sincos_lo[j1+1] - (a1_1*w1 - a2_1*t1);

			*pc0 = one + t0;
			*pc1 = a2_1 + t2_1;
			*pc2 = one + t2;

			t0 = z0 * (poly3[0] + z0 * poly4[0]);
			t1_1 = a2_1*w1 + a1_1*t1;
			t2 = z2 * (poly3[0] + z2 * poly4[0]);

			t0 = z0 * (poly1[0] + z0 * (poly2[0] + t0));
			t1_1 += __vlibm_TBL_sincos_lo[j1+xsb1];
			t2 = z2 * (poly1[0] + z2 * (poly2[0] + t2));

			t0 = x0 + x0 * t0;
			*py0 = t0;
			*py1 = a1_1 + t1_1;
			t2 = x2 + x2 * t2;
			*py2 = t2;

			break;

		case 6:
			j2 = (xsb2 + 0x4000) & 0xffff8000;
			HI(&t2) = j2;
			LO(&t2) = 0;
			x2 -= t2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (poly3[1] + z0 * poly4[1]);
			t1 = z1 * (poly3[1] + z1 * poly4[1]);
			t2 = z2 * (qq1 + z2 * qq2);
			t0 = z0 * (poly1[1] + z0 * (poly2[1] + t0));
			t1 = z1 * (poly1[1] + z1 * (poly2[1] + t1));
			w2 = x2 * (one + z2 * (pp1 + z2 * pp2));
			j2 = (((j2 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb2 = (xsb2 >> 30) & 2;
			a1_2 = __vlibm_TBL_sincos_hi[j2+xsb2];

			a2_2 = __vlibm_TBL_sincos_hi[j2+1];

			t2_2 = __vlibm_TBL_sincos_lo[j2+1] - (a1_2*w2 - a2_2*t2);

			*pc0 = one + t0;
			*pc1 = one + t1;
			*pc2 = a2_2 + t2_2;

			t0 = z0 * (poly3[0] + z0 * poly4[0]);
			t1 = z1 * (poly3[0] + z1 * poly4[0]);
			t1_2 = a2_2*w2 + a1_2*t2;

			t0 = z0 * (poly1[0] + z0 * (poly2[0] + t0));
			t1 = z1 * (poly1[0] + z1 * (poly2[0] + t1));
			t1_2 += __vlibm_TBL_sincos_lo[j2+xsb2];

			t0 = x0 + x0 * t0;
			*py0 = t0;
			t1 = x1 + x1 * t1;
			*py1 = t1;
			*py2 = a1_2 + t1_2;

			break;

		case 7: /* All are < 5/32 */
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (poly3[1] + z0 * poly4[1]);
			t1 = z1 * (poly3[1] + z1 * poly4[1]);
			t2 = z2 * (poly3[1] + z2 * poly4[1]);
			t0 = z0 * (poly1[1] + z0 * (poly2[1] + t0));
			t1 = z1 * (poly1[1] + z1 * (poly2[1] + t1));
			t2 = z2 * (poly1[1] + z2 * (poly2[1] + t2));
			*pc0 = one + t0;
			*pc1 = one + t1;
			*pc2 = one + t2;
			t0 = z0 * (poly3[0] + z0 * poly4[0]);
			t1 = z1 * (poly3[0] + z1 * poly4[0]);
			t2 = z2 * (poly3[0] + z2 * poly4[0]);
			t0 = z0 * (poly1[0] + z0 * (poly2[0] + t0));
			t1 = z1 * (poly1[0] + z1 * (poly2[0] + t1));
			t2 = z2 * (poly1[0] + z2 * (poly2[0] + t2));
			t0 = x0 + x0 * t0;
			t1 = x1 + x1 * t1;
			t2 = x2 + x2 * t2;
			*py0 = t0;
			*py1 = t1;
			*py2 = t2;
			break;
		}

		x += stridex;
		y += stridey;
		c += stridec;
		i = 0;
	} while (--n > 0); /* END MAIN LOOP */

	/*
	 * CLEAN UP last 0, 1, or 2 elts.
	 */
	if (i > 0) /* Clean up elts at tail.  i < 3. */
	{
		double		a1_0, a1_1, a2_0, a2_1;
		double		w0, w1;
		double		t0, t1, t1_0, t1_1, t2_0, t2_1;
		double		z0, z1;
		unsigned	j0, j1;

		if (i > 1)
		{
			if (hx1 < 0x3fc40000)
			{
				z1 = x1 * x1;
				t1 = z1 * (poly3[1] + z1 * poly4[1]);
				t1 = z1 * (poly1[1] + z1 * (poly2[1] + t1));
				t1 = one + t1;
				*pc1 = t1;
				t1 = z1 * (poly3[0] + z1 * poly4[0]);
				t1 = z1 * (poly1[0] + z1 * (poly2[0] + t1));
				t1 = x1 + x1 * t1;
				*py1 = t1;
			}
			else
			{
				j1 = (xsb1 + 0x4000) & 0xffff8000;
				HI(&t1) = j1;
				LO(&t1) = 0;
				x1 -= t1;
				z1 = x1 * x1;
				t1 = z1 * (qq1 + z1 * qq2);
				w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
				j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
				xsb1 = (xsb1 >> 30) & 2;
				a1_1 = __vlibm_TBL_sincos_hi[j1+xsb1];
				a2_1 = __vlibm_TBL_sincos_hi[j1+1];
				t2_1 = __vlibm_TBL_sincos_lo[j1+1] - (a1_1*w1 - a2_1*t1);
				*pc1 = a2_1 + t2_1;
				t1_1 = a2_1*w1 + a1_1*t1;
				t1_1 += __vlibm_TBL_sincos_lo[j1+xsb1];
				*py1 = a1_1 + t1_1;
			}
		}
		if (hx0 < 0x3fc40000)
		{
			z0 = x0 * x0;
			t0 = z0 * (poly3[1] + z0 * poly4[1]);
			t0 = z0 * (poly1[1] + z0 * (poly2[1] + t0));
			t0 = one + t0;
			*pc0 = t0;
			t0 = z0 * (poly3[0] + z0 * poly4[0]);
			t0 = z0 * (poly1[0] + z0 * (poly2[0] + t0));
			t0 = x0 + x0 * t0;
			*py0 = t0;
		}
		else
		{
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			HI(&t0) = j0;
			LO(&t0) = 0;
			x0 -= t0;
			z0 = x0 * x0;
			t0 = z0 * (qq1 + z0 * qq2);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			a1_0 = __vlibm_TBL_sincos_hi[j0+xsb0]; /* sin_hi(t) */
			a2_0 = __vlibm_TBL_sincos_hi[j0+1];	/* cos_hi(t) */
			t2_0 = __vlibm_TBL_sincos_lo[j0+1] - (a1_0*w0 - a2_0*t0);
			*pc0 = a2_0 + t2_0;
			t1_0 = a2_0*w0 + a1_0*t0;
			t1_0 += __vlibm_TBL_sincos_lo[j0+xsb0]; /* sin_lo(t) */
			*py0 = a1_0 + t1_0;
		}
	} /* END CLEAN UP */

	if (!biguns)
		return;

	/*
	 * Take care of BIGUNS.
	 */
	n = nsave;
	x = xsave;
	stridex = sxsave;
	y = ysave;
	stridey = sysave;
	c = csave;
	stridec = scsave;
	biguns = 0;

	x0_or_one[1] = 1.0;
	x1_or_one[1] = 1.0;
	x2_or_one[1] = 1.0;
	x0_or_one[3] = -1.0;
	x1_or_one[3] = -1.0;
	x2_or_one[3] = -1.0;
	y0_or_zero[1] = 0.0;
	y1_or_zero[1] = 0.0;
	y2_or_zero[1] = 0.0;
	y0_or_zero[3] = 0.0;
	y1_or_zero[3] = 0.0;
	y2_or_zero[3] = 0.0;

	do
	{
		double		fn0, fn1, fn2, a0, a1, a2, w0, w1, w2, y0, y1, y2;
		unsigned	hx;
		int			n0, n1, n2;

		/*
		 * Find 3 more to work on: Not already done, not too big.
		 */
loop0:
		hx = HI(x);
		xsb0 = hx >> 31;
		hx &= ~0x80000000;
		if (hx <= 0x3fe921fb) /* Done above. */
		{
			x += stridex;
			y += stridey;
			c += stridec;
			i = 0;
			if (--n <= 0)
				break;
			goto loop0;
		}
		if (hx > 0x413921fb) /* (1.6471e+06) Too big: leave it. */
		{
			if (hx >= 0x7ff00000) /* Inf or NaN */
			{
				x0 = *x;
				*y = x0 - x0;
				*c = x0 - x0;
			}
			else {
				biguns = 1;
			}
			x += stridex;
			y += stridey;
			c += stridec;
			i = 0;
			if (--n <= 0)
				break;
			goto loop0;
		}
		x0 = *x;
		py0 = y;
		pc0 = c;
		x += stridex;
		y += stridey;
		c += stridec;
		i = 1;
		if (--n <= 0)
			break;

loop1:
		hx = HI(x);
		xsb1 = hx >> 31;
		hx &= ~0x80000000;
		if (hx <= 0x3fe921fb)
		{
			x += stridex;
			y += stridey;
			c += stridec;
			i = 1;
			if (--n <= 0)
				break;
			goto loop1;
		}
		if (hx > 0x413921fb)
		{
			if (hx >= 0x7ff00000)
			{
				x1 = *x;
				*y = x1 - x1;
				*c = x1 - x1;
			}
			else {
				biguns = 1;
			}
			x += stridex;
			y += stridey;
			c += stridec;
			i = 1;
			if (--n <= 0)
				break;
			goto loop1;
		}
		x1 = *x;
		py1 = y;
		pc1 = c;
		x += stridex;
		y += stridey;
		c += stridec;
		i = 2;
		if (--n <= 0)
			break;

loop2:
		hx = HI(x);
		xsb2 = hx >> 31;
		hx &= ~0x80000000;
		if (hx <= 0x3fe921fb)
		{
			x += stridex;
			y += stridey;
			c += stridec;
			i = 2;
			if (--n <= 0)
				break;
			goto loop2;
		}
		if (hx > 0x413921fb)
		{
			if (hx >= 0x7ff00000)
			{
				x2 = *x;
				*y = x2 - x2;
				*c = x2 - x2;
			}
			else {
				biguns = 1;
			}
			x += stridex;
			y += stridey;
			c += stridec;
			i = 2;
			if (--n <= 0)
				break;
			goto loop2;
		}
		x2 = *x;
		py2 = y;
		pc2 = c;

		n0 = (int) (x0 * invpio2 + half[xsb0]);
		n1 = (int) (x1 * invpio2 + half[xsb1]);
		n2 = (int) (x2 * invpio2 + half[xsb2]);
		fn0 = (double) n0;
		fn1 = (double) n1;
		fn2 = (double) n2;
		n0 &= 3;
		n1 &= 3;
		n2 &= 3;
		a0 = x0 - fn0 * pio2_1;
		a1 = x1 - fn1 * pio2_1;
		a2 = x2 - fn2 * pio2_1;
		w0 = fn0 * pio2_2;
		w1 = fn1 * pio2_2;
		w2 = fn2 * pio2_2;
		x0 = a0 - w0;
		x1 = a1 - w1;
		x2 = a2 - w2;
		y0 = (a0 - x0) - w0;
		y1 = (a1 - x1) - w1;
		y2 = (a2 - x2) - w2;
		a0 = x0;
		a1 = x1;
		a2 = x2;
		w0 = fn0 * pio2_3 - y0;
		w1 = fn1 * pio2_3 - y1;
		w2 = fn2 * pio2_3 - y2;
		x0 = a0 - w0;
		x1 = a1 - w1;
		x2 = a2 - w2;
		y0 = (a0 - x0) - w0;
		y1 = (a1 - x1) - w1;
		y2 = (a2 - x2) - w2;
		a0 = x0;
		a1 = x1;
		a2 = x2;
		w0 = fn0 * pio2_3t - y0;
		w1 = fn1 * pio2_3t - y1;
		w2 = fn2 * pio2_3t - y2;
		x0 = a0 - w0;
		x1 = a1 - w1;
		x2 = a2 - w2;
		y0 = (a0 - x0) - w0;
		y1 = (a1 - x1) - w1;
		y2 = (a2 - x2) - w2;
		xsb2 = HI(&x2);
		i = ((xsb2 & ~0x80000000) - 0x3fc40000) >> 31;
		xsb1 = HI(&x1);
		i |= (((xsb1 & ~0x80000000) - 0x3fc40000) >> 30) & 2;
		xsb0 = HI(&x0);
		i |= (((xsb0 & ~0x80000000) - 0x3fc40000) >> 29) & 4;
		switch (i)
		{
			double		a1_0, a1_1, a1_2, a2_0, a2_1, a2_2;
			double		t0, t1, t2, t1_0, t1_1, t1_2, t2_0, t2_1, t2_2;
			double		z0, z1, z2;
			unsigned	j0, j1, j2;

		case 0:
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			j1 = (xsb1 + 0x4000) & 0xffff8000;
			j2 = (xsb2 + 0x4000) & 0xffff8000;
			HI(&t0) = j0;
			HI(&t1) = j1;
			HI(&t2) = j2;
			LO(&t0) = 0;
			LO(&t1) = 0;
			LO(&t2) = 0;
			x0 = (x0 - t0) + y0;
			x1 = (x1 - t1) + y1;
			x2 = (x2 - t2) + y2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (qq1 + z0 * qq2);
			t1 = z1 * (qq1 + z1 * qq2);
			t2 = z2 * (qq1 + z2 * qq2);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
			w2 = x2 * (one + z2 * (pp1 + z2 * pp2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j2 = (((j2 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			xsb1 = (xsb1 >> 30) & 2;
			xsb2 = (xsb2 >> 30) & 2;
			n0 ^= (xsb0 & ~(n0 << 1));
			n1 ^= (xsb1 & ~(n1 << 1));
			n2 ^= (xsb2 & ~(n2 << 1));
			xsb0 |= 1;
			xsb1 |= 1;
			xsb2 |= 1;

			a1_0 = __vlibm_TBL_sincos_hi[j0+n0];
			a1_1 = __vlibm_TBL_sincos_hi[j1+n1];
			a1_2 = __vlibm_TBL_sincos_hi[j2+n2];

			a2_0 = __vlibm_TBL_sincos_hi[j0+((n0+xsb0)&3)];
			a2_1 = __vlibm_TBL_sincos_hi[j1+((n1+xsb1)&3)];
			a2_2 = __vlibm_TBL_sincos_hi[j2+((n2+xsb2)&3)];

			t2_0 = __vlibm_TBL_sincos_lo[j0+((n0+xsb0)&3)] - (a1_0*w0 - a2_0*t0);
			t2_1 = __vlibm_TBL_sincos_lo[j1+((n1+xsb1)&3)] - (a1_1*w1 - a2_1*t1);
			t2_2 = __vlibm_TBL_sincos_lo[j2+((n2+xsb2)&3)] - (a1_2*w2 - a2_2*t2);

			w0 *= a2_0;
			w1 *= a2_1;
			w2 *= a2_2;

			*pc0 = a2_0 + t2_0;
			*pc1 = a2_1 + t2_1;
			*pc2 = a2_2 + t2_2;

			t1_0 = w0 + a1_0*t0;
			t1_1 = w1 + a1_1*t1;
			t1_2 = w2 + a1_2*t2;

			t1_0 += __vlibm_TBL_sincos_lo[j0+n0];
			t1_1 += __vlibm_TBL_sincos_lo[j1+n1];
			t1_2 += __vlibm_TBL_sincos_lo[j2+n2];

			*py0 = a1_0 + t1_0;
			*py1 = a1_1 + t1_1;
			*py2 = a1_2 + t1_2;

			break;

		case 1:
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			j1 = (xsb1 + 0x4000) & 0xffff8000;
			j2 = n2 & 1;
			HI(&t0) = j0;
			HI(&t1) = j1;
			LO(&t0) = 0;
			LO(&t1) = 0;
			x2_or_one[0] = x2;
			x2_or_one[2] = -x2;
			x0 = (x0 - t0) + y0;
			x1 = (x1 - t1) + y1;
			y2_or_zero[0] = y2;
			y2_or_zero[2] = -y2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (qq1 + z0 * qq2);
			t1 = z1 * (qq1 + z1 * qq2);
			t2 = z2 * (poly3[j2] + z2 * poly4[j2]);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
			t2 = z2 * (poly1[j2] + z2 * (poly2[j2] + t2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			xsb1 = (xsb1 >> 30) & 2;
			n0 ^= (xsb0 & ~(n0 << 1));
			n1 ^= (xsb1 & ~(n1 << 1));
			xsb0 |= 1;
			xsb1 |= 1;
			a1_0 = __vlibm_TBL_sincos_hi[j0+n0];
			a1_1 = __vlibm_TBL_sincos_hi[j1+n1];

			a2_0 = __vlibm_TBL_sincos_hi[j0+((n0+xsb0)&3)];
			a2_1 = __vlibm_TBL_sincos_hi[j1+((n1+xsb1)&3)];

			t2_0 = __vlibm_TBL_sincos_lo[j0+((n0+xsb0)&3)] - (a1_0*w0 - a2_0*t0);
			t2_1 = __vlibm_TBL_sincos_lo[j1+((n1+xsb1)&3)] - (a1_1*w1 - a2_1*t1);
			t2 = x2_or_one[n2] + (y2_or_zero[n2] + x2_or_one[n2] * t2);

			*pc0 = a2_0 + t2_0;
			*pc1 = a2_1 + t2_1;
			*py2 = t2;

			n2 = (n2 + 1) & 3;
			j2 = (j2 + 1) & 1;
			t2 = z2 * (poly3[j2] + z2 * poly4[j2]);

			t1_0 = a2_0*w0 + a1_0*t0;
			t1_1 = a2_1*w1 + a1_1*t1;
			t2 = z2 * (poly1[j2] + z2 * (poly2[j2] + t2));

			t1_0 += __vlibm_TBL_sincos_lo[j0+n0];
			t1_1 += __vlibm_TBL_sincos_lo[j1+n1];
			t2 = x2_or_one[n2] + (y2_or_zero[n2] + x2_or_one[n2] * t2);

			*py0 = a1_0 + t1_0;
			*py1 = a1_1 + t1_1;
			*pc2 = t2;

			break;

		case 2:
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			j1 = n1 & 1;
			j2 = (xsb2 + 0x4000) & 0xffff8000;
			HI(&t0) = j0;
			HI(&t2) = j2;
			LO(&t0) = 0;
			LO(&t2) = 0;
			x1_or_one[0] = x1;
			x1_or_one[2] = -x1;
			x0 = (x0 - t0) + y0;
			y1_or_zero[0] = y1;
			y1_or_zero[2] = -y1;
			x2 = (x2 - t2) + y2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (qq1 + z0 * qq2);
			t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
			t2 = z2 * (qq1 + z2 * qq2);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
			w2 = x2 * (one + z2 * (pp1 + z2 * pp2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j2 = (((j2 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			xsb2 = (xsb2 >> 30) & 2;
			n0 ^= (xsb0 & ~(n0 << 1));
			n2 ^= (xsb2 & ~(n2 << 1));
			xsb0 |= 1;
			xsb2 |= 1;

			a1_0 = __vlibm_TBL_sincos_hi[j0+n0];
			a1_2 = __vlibm_TBL_sincos_hi[j2+n2];

			a2_0 = __vlibm_TBL_sincos_hi[j0+((n0+xsb0)&3)];
			a2_2 = __vlibm_TBL_sincos_hi[j2+((n2+xsb2)&3)];

			t2_0 = __vlibm_TBL_sincos_lo[j0+((n0+xsb0)&3)] - (a1_0*w0 - a2_0*t0);
			t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
			t2_2 = __vlibm_TBL_sincos_lo[j2+((n2+xsb2)&3)] - (a1_2*w2 - a2_2*t2);

			*pc0 = a2_0 + t2_0;
			*py1 = t1;
			*pc2 = a2_2 + t2_2;

			n1 = (n1 + 1) & 3;
			j1 = (j1 + 1) & 1;
			t1 = z1 * (poly3[j1] + z1 * poly4[j1]);

			t1_0 = a2_0*w0 + a1_0*t0;
			t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
			t1_2 = a2_2*w2 + a1_2*t2;

			t1_0 += __vlibm_TBL_sincos_lo[j0+n0];
			t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
			t1_2 += __vlibm_TBL_sincos_lo[j2+n2];

			*py0 = a1_0 + t1_0;
			*pc1 = t1;
			*py2 = a1_2 + t1_2;

			break;

		case 3:
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			j1 = n1 & 1;
			j2 = n2 & 1;
			HI(&t0) = j0;
			LO(&t0) = 0;
			x1_or_one[0] = x1;
			x1_or_one[2] = -x1;
			x2_or_one[0] = x2;
			x2_or_one[2] = -x2;
			x0 = (x0 - t0) + y0;
			y1_or_zero[0] = y1;
			y1_or_zero[2] = -y1;
			y2_or_zero[0] = y2;
			y2_or_zero[2] = -y2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (qq1 + z0 * qq2);
			t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
			t2 = z2 * (poly3[j2] + z2 * poly4[j2]);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
			t2 = z2 * (poly1[j2] + z2 * (poly2[j2] + t2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			n0 ^= (xsb0 & ~(n0 << 1));
			xsb0 |= 1;

			a1_0 = __vlibm_TBL_sincos_hi[j0+n0];
			a2_0 = __vlibm_TBL_sincos_hi[j0+((n0+xsb0)&3)];

			t2_0 = __vlibm_TBL_sincos_lo[j0+((n0+xsb0)&3)] - (a1_0*w0 - a2_0*t0);
			t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
			t2 = x2_or_one[n2] + (y2_or_zero[n2] + x2_or_one[n2] * t2);

			*pc0 = a2_0 + t2_0;
			*py1 = t1;
			*py2 = t2;

			n1 = (n1 + 1) & 3;
			n2 = (n2 + 1) & 3;
			j1 = (j1 + 1) & 1;
			j2 = (j2 + 1) & 1;

			t1_0 = a2_0*w0 + a1_0*t0;
			t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
			t2 = z2 * (poly3[j2] + z2 * poly4[j2]);

			t1_0 += __vlibm_TBL_sincos_lo[j0+n0];
			t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
			t2 = z2 * (poly1[j2] + z2 * (poly2[j2] + t2));

			t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
			t2 = x2_or_one[n2] + (y2_or_zero[n2] + x2_or_one[n2] * t2);

			*py0 = a1_0 + t1_0;
			*pc1 = t1;
			*pc2 = t2;

			break;

		case 4:
			j0 = n0 & 1;
			j1 = (xsb1 + 0x4000) & 0xffff8000;
			j2 = (xsb2 + 0x4000) & 0xffff8000;
			HI(&t1) = j1;
			HI(&t2) = j2;
			LO(&t1) = 0;
			LO(&t2) = 0;
			x0_or_one[0] = x0;
			x0_or_one[2] = -x0;
			y0_or_zero[0] = y0;
			y0_or_zero[2] = -y0;
			x1 = (x1 - t1) + y1;
			x2 = (x2 - t2) + y2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t1 = z1 * (qq1 + z1 * qq2);
			t2 = z2 * (qq1 + z2 * qq2);
			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
			w2 = x2 * (one + z2 * (pp1 + z2 * pp2));
			j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			j2 = (((j2 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb1 = (xsb1 >> 30) & 2;
			xsb2 = (xsb2 >> 30) & 2;
			n1 ^= (xsb1 & ~(n1 << 1));
			n2 ^= (xsb2 & ~(n2 << 1));
			xsb1 |= 1;
			xsb2 |= 1;

			a1_1 = __vlibm_TBL_sincos_hi[j1+n1];
			a1_2 = __vlibm_TBL_sincos_hi[j2+n2];

			a2_1 = __vlibm_TBL_sincos_hi[j1+((n1+xsb1)&3)];
			a2_2 = __vlibm_TBL_sincos_hi[j2+((n2+xsb2)&3)];

			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			t2_1 = __vlibm_TBL_sincos_lo[j1+((n1+xsb1)&3)] - (a1_1*w1 - a2_1*t1);
			t2_2 = __vlibm_TBL_sincos_lo[j2+((n2+xsb2)&3)] - (a1_2*w2 - a2_2*t2);

			*py0 = t0;
			*pc1 = a2_1 + t2_1;
			*pc2 = a2_2 + t2_2;

			n0 = (n0 + 1) & 3;
			j0 = (j0 + 1) & 1;
			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);

			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			t1_1 = a2_1*w1 + a1_1*t1;
			t1_2 = a2_2*w2 + a1_2*t2;

			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			t1_1 += __vlibm_TBL_sincos_lo[j1+n1];
			t1_2 += __vlibm_TBL_sincos_lo[j2+n2];

			*py1 = a1_1 + t1_1;
			*py2 = a1_2 + t1_2;
			*pc0 = t0;

			break;

		case 5:
			j0 = n0 & 1;
			j1 = (xsb1 + 0x4000) & 0xffff8000;
			j2 = n2 & 1;
			HI(&t1) = j1;
			LO(&t1) = 0;
			x0_or_one[0] = x0;
			x0_or_one[2] = -x0;
			x2_or_one[0] = x2;
			x2_or_one[2] = -x2;
			y0_or_zero[0] = y0;
			y0_or_zero[2] = -y0;
			x1 = (x1 - t1) + y1;
			y2_or_zero[0] = y2;
			y2_or_zero[2] = -y2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t1 = z1 * (qq1 + z1 * qq2);
			t2 = z2 * (poly3[j2] + z2 * poly4[j2]);
			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
			t2 = z2 * (poly1[j2] + z2 * (poly2[j2] + t2));
			j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb1 = (xsb1 >> 30) & 2;
			n1 ^= (xsb1 & ~(n1 << 1));
			xsb1 |= 1;

			a1_1 = __vlibm_TBL_sincos_hi[j1+n1];
			a2_1 = __vlibm_TBL_sincos_hi[j1+((n1+xsb1)&3)];

			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			t2_1 = __vlibm_TBL_sincos_lo[j1+((n1+xsb1)&3)] - (a1_1*w1 - a2_1*t1);
			t2 = x2_or_one[n2] + (y2_or_zero[n2] + x2_or_one[n2] * t2);

			*py0 = t0;
			*pc1 = a2_1 + t2_1;
			*py2 = t2;

			n0 = (n0 + 1) & 3;
			n2 = (n2 + 1) & 3;
			j0 = (j0 + 1) & 1;
			j2 = (j2 + 1) & 1;

			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t1_1 = a2_1*w1 + a1_1*t1;
			t2 = z2 * (poly3[j2] + z2 * poly4[j2]);

			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			t1_1 += __vlibm_TBL_sincos_lo[j1+n1];
			t2 = z2 * (poly1[j2] + z2 * (poly2[j2] + t2));

			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			t2 = x2_or_one[n2] + (y2_or_zero[n2] + x2_or_one[n2] * t2);

			*pc0 = t0;
			*py1 = a1_1 + t1_1;
			*pc2 = t2;

			break;

		case 6:
			j0 = n0 & 1;
			j1 = n1 & 1;
			j2 = (xsb2 + 0x4000) & 0xffff8000;
			HI(&t2) = j2;
			LO(&t2) = 0;
			x0_or_one[0] = x0;
			x0_or_one[2] = -x0;
			x1_or_one[0] = x1;
			x1_or_one[2] = -x1;
			y0_or_zero[0] = y0;
			y0_or_zero[2] = -y0;
			y1_or_zero[0] = y1;
			y1_or_zero[2] = -y1;
			x2 = (x2 - t2) + y2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
			t2 = z2 * (qq1 + z2 * qq2);
			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
			w2 = x2 * (one + z2 * (pp1 + z2 * pp2));
			j2 = (((j2 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb2 = (xsb2 >> 30) & 2;
			n2 ^= (xsb2 & ~(n2 << 1));
			xsb2 |= 1;

			a1_2 = __vlibm_TBL_sincos_hi[j2+n2];
			a2_2 = __vlibm_TBL_sincos_hi[j2+((n2+xsb2)&3)];

			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
			t2_2 = __vlibm_TBL_sincos_lo[j2+((n2+xsb2)&3)] - (a1_2*w2 - a2_2*t2);

			*py0 = t0;
			*py1 = t1;
			*pc2 = a2_2 + t2_2;

			n0 = (n0 + 1) & 3;
			n1 = (n1 + 1) & 3;
			j0 = (j0 + 1) & 1;
			j1 = (j1 + 1) & 1;

			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
			t1_2 = a2_2*w2 + a1_2*t2;

			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
			t1_2 += __vlibm_TBL_sincos_lo[j2+n2];

			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);

			*pc0 = t0;
			*pc1 = t1;
			*py2 = a1_2 + t1_2;

			break;

		case 7:
			j0 = n0 & 1;
			j1 = n1 & 1;
			j2 = n2 & 1;
			x0_or_one[0] = x0;
			x0_or_one[2] = -x0;
			x1_or_one[0] = x1;
			x1_or_one[2] = -x1;
			x2_or_one[0] = x2;
			x2_or_one[2] = -x2;
			y0_or_zero[0] = y0;
			y0_or_zero[2] = -y0;
			y1_or_zero[0] = y1;
			y1_or_zero[2] = -y1;
			y2_or_zero[0] = y2;
			y2_or_zero[2] = -y2;
			z0 = x0 * x0;
			z1 = x1 * x1;
			z2 = x2 * x2;
			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
			t2 = z2 * (poly3[j2] + z2 * poly4[j2]);
			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
			t2 = z2 * (poly1[j2] + z2 * (poly2[j2] + t2));
			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
			t2 = x2_or_one[n2] + (y2_or_zero[n2] + x2_or_one[n2] * t2);
			*py0 = t0;
			*py1 = t1;
			*py2 = t2;

			n0 = (n0 + 1) & 3;
			n1 = (n1 + 1) & 3;
			n2 = (n2 + 1) & 3;
			j0 = (j0 + 1) & 1;
			j1 = (j1 + 1) & 1;
			j2 = (j2 + 1) & 1;
			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
			t2 = z2 * (poly3[j2] + z2 * poly4[j2]);
			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
			t2 = z2 * (poly1[j2] + z2 * (poly2[j2] + t2));
			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
			t2 = x2_or_one[n2] + (y2_or_zero[n2] + x2_or_one[n2] * t2);
			*pc0 = t0;
			*pc1 = t1;
			*pc2 = t2;
			break;
		}

		x += stridex;
		y += stridey;
		c += stridec;
		i = 0;
	} while (--n > 0);

	if (i > 0)
	{
		double		a1_0, a1_1, a2_0, a2_1;
		double		t0, t1, t1_0, t1_1, t2_0, t2_1;
		double		fn0, fn1, a0, a1, w0, w1, y0, y1;
		double		z0, z1;
		unsigned	j0, j1;
		int		n0, n1;

		if (i > 1)
		{
			n1 = (int) (x1 * invpio2 + half[xsb1]);
			fn1 = (double) n1;
			n1 &= 3;
			a1 = x1 - fn1 * pio2_1;
			w1 = fn1 * pio2_2;
			x1 = a1 - w1;
			y1 = (a1 - x1) - w1;
			a1 = x1;
			w1 = fn1 * pio2_3 - y1;
			x1 = a1 - w1;
			y1 = (a1 - x1) - w1;
			a1 = x1;
			w1 = fn1 * pio2_3t - y1;
			x1 = a1 - w1;
			y1 = (a1 - x1) - w1;
			xsb1 = HI(&x1);
			if ((xsb1 & ~0x80000000) < 0x3fc40000)
			{
				j1 = n1 & 1;
				x1_or_one[0] = x1;
				x1_or_one[2] = -x1;
				y1_or_zero[0] = y1;
				y1_or_zero[2] = -y1;
				z1 = x1 * x1;
				t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
				t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
				t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
				*py1 = t1;
				n1 = (n1 + 1) & 3;
				j1 = (j1 + 1) & 1;
				t1 = z1 * (poly3[j1] + z1 * poly4[j1]);
				t1 = z1 * (poly1[j1] + z1 * (poly2[j1] + t1));
				t1 = x1_or_one[n1] + (y1_or_zero[n1] + x1_or_one[n1] * t1);
				*pc1 = t1;
			}
			else
			{
				j1 = (xsb1 + 0x4000) & 0xffff8000;
				HI(&t1) = j1;
				LO(&t1) = 0;
				x1 = (x1 - t1) + y1;
				z1 = x1 * x1;
				t1 = z1 * (qq1 + z1 * qq2);
				w1 = x1 * (one + z1 * (pp1 + z1 * pp2));
				j1 = (((j1 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
				xsb1 = (xsb1 >> 30) & 2;
				n1 ^= (xsb1 & ~(n1 << 1));
				xsb1 |= 1;
				a1_1 = __vlibm_TBL_sincos_hi[j1+n1];
				a2_1 = __vlibm_TBL_sincos_hi[j1+((n1+xsb1)&3)];
				t2_1 = __vlibm_TBL_sincos_lo[j1+((n1+xsb1)&3)] - (a1_1*w1 - a2_1*t1);
				*pc1 = a2_1 + t2_1;
				t1_1 = a2_1*w1 + a1_1*t1;
				t1_1 += __vlibm_TBL_sincos_lo[j1+n1];
				*py1 = a1_1 + t1_1;
			}
		}
		n0 = (int) (x0 * invpio2 + half[xsb0]);
		fn0 = (double) n0;
		n0 &= 3;
		a0 = x0 - fn0 * pio2_1;
		w0 = fn0 * pio2_2;
		x0 = a0 - w0;
		y0 = (a0 - x0) - w0;
		a0 = x0;
		w0 = fn0 * pio2_3 - y0;
		x0 = a0 - w0;
		y0 = (a0 - x0) - w0;
		a0 = x0;
		w0 = fn0 * pio2_3t - y0;
		x0 = a0 - w0;
		y0 = (a0 - x0) - w0;
		xsb0 = HI(&x0);
		if ((xsb0 & ~0x80000000) < 0x3fc40000)
		{
			j0 = n0 & 1;
			x0_or_one[0] = x0;
			x0_or_one[2] = -x0;
			y0_or_zero[0] = y0;
			y0_or_zero[2] = -y0;
			z0 = x0 * x0;
			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			*py0 = t0;
			n0 = (n0 + 1) & 3;
			j0 = (j0 + 1) & 1;
			t0 = z0 * (poly3[j0] + z0 * poly4[j0]);
			t0 = z0 * (poly1[j0] + z0 * (poly2[j0] + t0));
			t0 = x0_or_one[n0] + (y0_or_zero[n0] + x0_or_one[n0] * t0);
			*pc0 = t0;
		}
		else
		{
			j0 = (xsb0 + 0x4000) & 0xffff8000;
			HI(&t0) = j0;
			LO(&t0) = 0;
			x0 = (x0 - t0) + y0;
			z0 = x0 * x0;
			t0 = z0 * (qq1 + z0 * qq2);
			w0 = x0 * (one + z0 * (pp1 + z0 * pp2));
			j0 = (((j0 & ~0x80000000) - 0x3fc40000) >> 13) & ~0x3;
			xsb0 = (xsb0 >> 30) & 2;
			n0 ^= (xsb0 & ~(n0 << 1));
			xsb0 |= 1;
			a1_0 = __vlibm_TBL_sincos_hi[j0+n0];
			a2_0 = __vlibm_TBL_sincos_hi[j0+((n0+xsb0)&3)];
			t2_0 = __vlibm_TBL_sincos_lo[j0+((n0+xsb0)&3)] - (a1_0*w0 - a2_0*t0);
			*pc0 = a2_0 + t2_0;
			t1_0 = a2_0*w0 + a1_0*t0;
			t1_0 += __vlibm_TBL_sincos_lo[j0+n0];
			*py0 = a1_0 + t1_0;
		}
	}

	if (biguns) {
		__vlibm_vsincos_big(nsave, xsave, sxsave, ysave, sysave, csave, scsave, 0x413921fb);
	}
}
