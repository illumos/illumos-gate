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

extern const double __vlibm_TBL_sincos_hi[], __vlibm_TBL_sincos_lo[];
extern int __vlibm_rem_pio2m(double *, double *, int, int, int);

static const double
	zero	= 0.0,
	one		= 1.0,
	two24	= 16777216.0,
	pp1		= -1.666666666605760465276263943134982554676e-0001,
	pp2		=  8.333261209690963126718376566146180944442e-0003,
	p1		= -1.666666666666629669805215138920301589656e-0001,
	p2		=  8.333333332390951295683993455280336376663e-0003,
	p3		= -1.984126237997976692791551778230098403960e-0004,
	p4		=  2.753403624854277237649987622848330351110e-0006,
	qq1		= -4.999999999977710986407023955908711557870e-0001,
	qq2		=  4.166654863857219350645055881018842089580e-0002,
	q1		= -4.999999999999931701464060878888294524481e-0001,
	q2		=  4.166666666394861917535640593963708222319e-0002,
	q3		= -1.388888552656142867832756687736851681462e-0003,
	q4		=  2.478519423681460796618128289454530524759e-0005;

void
__vlibm_vsincos_big(int n, double * restrict x, int stridex,
	double * restrict ss, int stridess,
	double * restrict cc, int stridecc, int thresh)
{
	for (; n--; x += stridex, ss += stridess, cc += stridecc)
	{
		double		ts, tc, tx, tt[3], ty[2], t, w, z, c, s;
		unsigned	hx, xsb;
		int			e0, nx, j;

		hx = HI(x);
		xsb = hx & 0x80000000;
		hx &= ~0x80000000;
		if (hx <= thresh || hx >= 0x7ff00000)
			continue;

		/*
		 * Argument reduction part.
		 */
		e0 = (hx >> 20) - 1046;
		HI(&tx) = 0x41600000 | (hx & 0xfffff);
		LO(&tx) = LO(x);
		tt[0] = (double)((int) tx);
		tx = (tx - tt[0]) * two24;
		if (tx != zero)
		{
			nx = 2;
			tt[1] = (double)((int) tx);
			tt[2] = (tx - tt[1]) * two24;
			if (tt[2] != zero)
				nx = 3;
		}
		else
		{
			nx = 1;
			tt[1] = tt[2] = zero;
		}
		nx = __vlibm_rem_pio2m(tt, ty, e0, nx, 2);
		if (xsb)
		{
			nx = -nx;
			ty[0] = -ty[0];
			ty[1] = -ty[1];
		}

		/* now nx and ty[*] are the quadrant and reduced arg */
		hx = HI(&ty[0]);
		xsb = 0;
		if (hx & 0x80000000)
		{
			ty[0] = -ty[0];
			ty[1] = -ty[1];
			hx &= ~0x80000000;
			xsb = 1;
		}
		if (hx < 0x3fc40000)
		{
			z = ty[0] * ty[0];
			t = z * (q1 + z * (q2 + z * (q3 + z * q4)));
			c = one + t;
			t = z * (p1 + z * (p2 + z * (p3 + z * p4)));
			s = ty[0] + (ty[1] + ty[0] * t);
		}
		else {
			j = (hx + 0x4000) & 0x7fff8000;
			HI(&t) = j;
			LO(&t) = 0;
			ty[0] = (ty[0] - t) + ty[1];
			z = ty[0] * ty[0];
			t = z * (qq1 + z * qq2);
			w = ty[0] * (one + z * (pp1 + z * pp2));
			j = ((j - 0x3fc40000) >> 13) & ~3;

			c = __vlibm_TBL_sincos_hi[j+1];
			tc = __vlibm_TBL_sincos_lo[j+1] - (__vlibm_TBL_sincos_hi[j] * w - c * t);
			c += tc;

			s = __vlibm_TBL_sincos_hi[j];
			ts = (__vlibm_TBL_sincos_hi[j+1] * w + s * t) + __vlibm_TBL_sincos_lo[j];
			s += ts;
		}
		if (xsb) {
			s = -s;
		}

		switch (nx & 3) {
		case 0:
			*ss = s;
			*cc = c;
			break;

		case 1:
			*ss = c;
			*cc = -s;
			break;

		case 2:
			*ss = -s;
			*cc = -c;
			break;

		case 3:
			*ss = -c;
			*cc = s;
			break;
		}
	}
}
