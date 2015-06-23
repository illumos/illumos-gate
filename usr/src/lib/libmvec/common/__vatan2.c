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
#include "libm_inlines.h"

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

extern const double __vlibm_TBL_atan2[];

static const double
zero	=  0.0,
twom3	=  0.125,
one		=  1.0,
two110	=  1.2980742146337069071e+33,
pio4	=  7.8539816339744827900e-01,
pio2	=  1.5707963267948965580e+00,
pio2_lo	=  6.1232339957367658860e-17,
pi		=  3.1415926535897931160e+00,
pi_lo	=  1.2246467991473531772e-16,
p1		= -3.33333333333327571893331786354179101074860633009e-0001,
p2		=  1.99999999942671624230086497610394721817438631379e-0001,
p3		= -1.42856965565428636896183013324727205980484158356e-0001,
p4		=  1.10894981496317081405107718475040168084164825641e-0001;

/* Don't __ the following; acomp will handle it */
extern double fabs(double);

void
__vatan2(int n, double * restrict y, int stridey, double * restrict x,
	int stridex, double * restrict z, int stridez)
{
	double		x0, x1, x2, y0, y1, y2, *pz0, *pz1, *pz2;
	double		ah0, ah1, ah2, al0, al1, al2, t0, t1, t2;
	double		z0, z1, z2, sign0, sign1, sign2, xh;
	int			i, k, hx, hy, sx, sy;

	do
	{
loop0:
		hy = HI(y);
		sy = hy & 0x80000000;
		hy &= ~0x80000000;
		sign0 = (sy)? -one : one;

		hx = HI(x);
		sx = hx & 0x80000000;
		hx &= ~0x80000000;

		if (hy > hx || (hy == hx && LO(y) > LO(x)))
		{
			i = hx;
			hx = hy;
			hy = i;
			x0 = fabs(*y);
			y0 = fabs(*x);
			if (sx)
			{
				ah0 = pio2;
				al0 = pio2_lo;
			}
			else
			{
				ah0 = -pio2;
				al0 = -pio2_lo;
				sign0 = -sign0;
			}
		}
		else
		{
			x0 = fabs(*x);
			y0 = fabs(*y);
			if (sx)
			{
				ah0 = -pi;
				al0 = -pi_lo;
				sign0 = -sign0;
			}
			else
				ah0 = al0 = zero;
		}

		if (hx >= 0x7fe00000 || hx - hy >= 0x03600000)
		{
			if (hx >= 0x7ff00000)
			{
				if ((hx ^ 0x7ff00000) | LO(&x0)) /* nan */
					ah0 =  x0 + y0;
				else if (hy >= 0x7ff00000)
					ah0 += pio4;
				*z = sign0 * ah0;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 0;
				if (--n <= 0)
					break;
				goto loop0;
			}
			if (hx - hy >= 0x03600000)
			{
				if ((int) ah0 == 0)
					ah0 = y0 / x0;
				*z = sign0 * ah0;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 0;
				if (--n <= 0)
					break;
				goto loop0;
			}
			y0 *= twom3;
			x0 *= twom3;
			hy -= 0x00300000;
			hx -= 0x00300000;
		}
		else if (hy < 0x00100000)
		{
			if ((hy | LO(&y0)) == 0)
			{
				*z = sign0 * ah0;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 0;
				if (--n <= 0)
					break;
				goto loop0;
			}
			y0 *= two110;
			x0 *= two110;
			hy = HI(&y0);
			hx = HI(&x0);
		}

		k = (((hx - hy) + 0x00004000) >> 13) & ~0x3;
		if (k > 644)
			k = 644;
		ah0 += __vlibm_TBL_atan2[k];
		al0 += __vlibm_TBL_atan2[k+1];
		t0 = __vlibm_TBL_atan2[k+2];

		xh = x0;
		LO(&xh) = 0;
		z0 = ((y0 - t0 * xh) - t0 * (x0 - xh)) / (x0 + y0 * t0);
		pz0 = z;
		x += stridex;
		y += stridey;
		z += stridez;
		i = 1;
		if (--n <= 0)
			break;

loop1:
		hy = HI(y);
		sy = hy & 0x80000000;
		hy &= ~0x80000000;
		sign1 = (sy)? -one : one;

		hx = HI(x);
		sx = hx & 0x80000000;
		hx &= ~0x80000000;

		if (hy > hx || (hy == hx && LO(y) > LO(x)))
		{
			i = hx;
			hx = hy;
			hy = i;
			x1 = fabs(*y);
			y1 = fabs(*x);
			if (sx)
			{
				ah1 = pio2;
				al1 = pio2_lo;
			}
			else
			{
				ah1 = -pio2;
				al1 = -pio2_lo;
				sign1 = -sign1;
			}
		}
		else
		{
			x1 = fabs(*x);
			y1 = fabs(*y);
			if (sx)
			{
				ah1 = -pi;
				al1 = -pi_lo;
				sign1 = -sign1;
			}
			else
				ah1 = al1 = zero;
		}

		if (hx >= 0x7fe00000 || hx - hy >= 0x03600000)
		{
			if (hx >= 0x7ff00000)
			{
				if ((hx ^ 0x7ff00000) | LO(&x1)) /* nan */
					ah1 =  x1 + y1;
				else if (hy >= 0x7ff00000)
					ah1 += pio4;
				*z = sign1 * ah1;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 1;
				if (--n <= 0)
					break;
				goto loop1;
			}
			if (hx - hy >= 0x03600000)
			{
				if ((int) ah1 == 0)
					ah1 = y1 / x1;
				*z = sign1 * ah1;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 1;
				if (--n <= 0)
					break;
				goto loop1;
			}
			y1 *= twom3;
			x1 *= twom3;
			hy -= 0x00300000;
			hx -= 0x00300000;
		}
		else if (hy < 0x00100000)
		{
			if ((hy | LO(&y1)) == 0)
			{
				*z = sign1 * ah1;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 1;
				if (--n <= 0)
					break;
				goto loop1;
			}
			y1 *= two110;
			x1 *= two110;
			hy = HI(&y1);
			hx = HI(&x1);
		}

		k = (((hx - hy) + 0x00004000) >> 13) & ~0x3;
		if (k > 644)
			k = 644;
		ah1 += __vlibm_TBL_atan2[k];
		al1 += __vlibm_TBL_atan2[k+1];
		t1 = __vlibm_TBL_atan2[k+2];

		xh = x1;
		LO(&xh) = 0;
		z1 = ((y1 - t1 * xh) - t1 * (x1 - xh)) / (x1 + y1 * t1);
		pz1 = z;
		x += stridex;
		y += stridey;
		z += stridez;
		i = 2;
		if (--n <= 0)
			break;

loop2:
		hy = HI(y);
		sy = hy & 0x80000000;
		hy &= ~0x80000000;
		sign2 = (sy)? -one : one;

		hx = HI(x);
		sx = hx & 0x80000000;
		hx &= ~0x80000000;

		if (hy > hx || (hy == hx && LO(y) > LO(x)))
		{
			i = hx;
			hx = hy;
			hy = i;
			x2 = fabs(*y);
			y2 = fabs(*x);
			if (sx)
			{
				ah2 = pio2;
				al2 = pio2_lo;
			}
			else
			{
				ah2 = -pio2;
				al2 = -pio2_lo;
				sign2 = -sign2;
			}
		}
		else
		{
			x2 = fabs(*x);
			y2 = fabs(*y);
			if (sx)
			{
				ah2 = -pi;
				al2 = -pi_lo;
				sign2 = -sign2;
			}
			else
				ah2 = al2 = zero;
		}

		if (hx >= 0x7fe00000 || hx - hy >= 0x03600000)
		{
			if (hx >= 0x7ff00000)
			{
				if ((hx ^ 0x7ff00000) | LO(&x2)) /* nan */
					ah2 =  x2 + y2;
				else if (hy >= 0x7ff00000)
					ah2 += pio4;
				*z = sign2 * ah2;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 2;
				if (--n <= 0)
					break;
				goto loop2;
			}
			if (hx - hy >= 0x03600000)
			{
				if ((int) ah2 == 0)
					ah2 = y2 / x2;
				*z = sign2 * ah2;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 2;
				if (--n <= 0)
					break;
				goto loop2;
			}
			y2 *= twom3;
			x2 *= twom3;
			hy -= 0x00300000;
			hx -= 0x00300000;
		}
		else if (hy < 0x00100000)
		{
			if ((hy | LO(&y2)) == 0)
			{
				*z = sign2 * ah2;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 2;
				if (--n <= 0)
					break;
				goto loop2;
			}
			y2 *= two110;
			x2 *= two110;
			hy = HI(&y2);
			hx = HI(&x2);
		}

		k = (((hx - hy) + 0x00004000) >> 13) & ~0x3;
		if (k > 644)
			k = 644;
		ah2 += __vlibm_TBL_atan2[k];
		al2 += __vlibm_TBL_atan2[k+1];
		t2 = __vlibm_TBL_atan2[k+2];

		xh = x2;
		LO(&xh) = 0;
		z2 = ((y2 - t2 * xh) - t2 * (x2 - xh)) / (x2 + y2 * t2);
		pz2 = z;

		x0 = z0 * z0;
		x1 = z1 * z1;
		x2 = z2 * z2;

		t0 = ah0 + (z0 + (al0 + (z0 * x0) * (p1 + x0 *
			(p2 + x0 * (p3 + x0 * p4)))));
		t1 = ah1 + (z1 + (al1 + (z1 * x1) * (p1 + x1 *
			(p2 + x1 * (p3 + x1 * p4)))));
		t2 = ah2 + (z2 + (al2 + (z2 * x2) * (p1 + x2 *
			(p2 + x2 * (p3 + x2 * p4)))));

		*pz0 = sign0 * t0;
		*pz1 = sign1 * t1;
		*pz2 = sign2 * t2;

		x += stridex;
		y += stridey;
		z += stridez;
		i = 0;
	} while (--n > 0);

	if (i > 0)
	{
		if (i > 1)
		{
			x1 = z1 * z1;
			t1 = ah1 + (z1 + (al1 + (z1 * x1) * (p1 + x1 *
				(p2 + x1 * (p3 + x1 * p4)))));
			*pz1 = sign1 * t1;
		}

		x0 = z0 * z0;
		t0 = ah0 + (z0 + (al0 + (z0 * x0) * (p1 + x0 *
			(p2 + x0 * (p3 + x0 * p4)))));
		*pz0 = sign0 * t0;
	}
}
