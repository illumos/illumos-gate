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

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

extern const double __vlibm_TBL_atan1[];

static const double
pio4	=  7.8539816339744827900e-01,
pio2	=  1.5707963267948965580e+00,
pi	=  3.1415926535897931160e+00;

static const float
zero	=  0.0f,
one	=  1.0f,
q1      = -3.3333333333296428046e-01f,
q2      =  1.9999999186853752618e-01f,
twop24  =  16777216.0f;

void
__vatan2f(int n, float * restrict y, int stridey, float * restrict x,
	int stridex, float * restrict z, int stridez)
{
	float		x0, x1, x2, y0, y1, y2, *pz0 = 0, *pz1, *pz2;
	double		ah0, ah1, ah2;
	double		t0, t1, t2;
	double		sx0, sx1, sx2;
	double		sign0, sign1, sign2;
	int		i, k0 = 0, k1, k2, hx, sx, sy;
	int		hy0, hy1, hy2;
	float		base0 = 0.0, base1, base2;
	double		num0, num1, num2;
	double		den0, den1, den2;
	double		dx0, dx1, dx2;
	double		dy0, dy1, dy2;
	double		db0, db1, db2;

	do
	{
loop0:
		hy0 = *(int*)y;
		hx = *(int*)x;
		sign0 = one;
		sy = hy0 & 0x80000000;
		hy0 &= ~0x80000000;

		sx = hx & 0x80000000;
		hx &= ~0x80000000;

		if (hy0 > hx)
		{
			x0 = *y;
			y0 = *x;
			i = hx;
			hx = hy0;
			hy0 = i;
			if (sy) 
			{
				x0 = -x0;
				sign0 = -sign0;
			}
			if (sx)
			{
				y0 = -y0;
				ah0 = pio2;
			}
			else
			{
				ah0 = -pio2;
				sign0 = -sign0;
			}
		}
		else
		{
			y0 = *y;
			x0 = *x;
			if (sy) 
			{
				y0 = -y0;
				sign0 = -sign0;
			}
			if (sx)
			{
				x0 = -x0;
				ah0 = -pi;
				sign0 = -sign0;
			}
			else
				ah0 = zero;
		}

		if (hx >= 0x7f800000 || hx - hy0 >= 0x0c800000)
		{
			if (hx >= 0x7f800000)
			{
				if (hx ^ 0x7f800000) /* nan */
					ah0 =  x0 + y0;
				else if (hy0 >= 0x7f800000)
					ah0 += pio4;
			}
			else if ((int) ah0 == 0)
				ah0 = y0 / x0;
			*z = (sign0 == one) ? ah0 : -ah0; 
/* sign0*ah0 would change nan behavior relative to previous release */
			x += stridex;
			y += stridey;
			z += stridez;
			i = 0;
			if (--n <= 0)
				break;
			goto loop0;
		}
		if (hy0 < 0x00800000) {
			if (hy0 == 0)
			{
				*z = sign0 * (float) ah0;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 0;
				if (--n <= 0)
					break;
				goto loop0;
			}
			y0 *= twop24; /* scale subnormal y */
			x0 *= twop24; /* scale possibly subnormal x */
			hy0 = *(int*)&y0;
                        hx = *(int*)&x0;
		}
		pz0 = z;

		k0 = (hy0 - hx + 0x3f800000) & 0xfff80000;
		if (k0 >= 0x3C800000)          /* if |x| >= (1/64)... */
    		{ 
			*(int*)&base0 = k0;
       		 	k0 = (k0 - 0x3C800000) >> 18; /* (index >> 19) << 1) */
			k0 += 4;
				/* skip over 0,0,pi/2,pi/2 */
    		}  
    		else                            /* |x| < 1/64 */
    		{ 
			k0 = 0;
			base0 = zero;
    		}

		x += stridex;
		y += stridey;
		z += stridez;
		i = 1;
		if (--n <= 0)
			break;


loop1:
		hy1 = *(int*)y;
		hx = *(int*)x;
		sign1 = one;
		sy = hy1 & 0x80000000;
		hy1 &= ~0x80000000;

		sx = hx & 0x80000000;
		hx &= ~0x80000000;

		if (hy1 > hx)
		{
			x1 = *y;
			y1 = *x;
			i = hx;
			hx = hy1;
			hy1 = i;
			if (sy) 
			{
				x1 = -x1;
				sign1 = -sign1;
			}
			if (sx)
			{
				y1 = -y1;
				ah1 = pio2;
			}
			else
			{
				ah1 = -pio2;
				sign1 = -sign1;
			}
		}
		else
		{
			y1 = *y;
			x1 = *x;
			if (sy) 
			{
				y1 = -y1;
				sign1 = -sign1;
			}
			if (sx)
			{
				x1 = -x1;
				ah1 = -pi;
				sign1 = -sign1;
			}
			else
				ah1 = zero;
		}

		if (hx >= 0x7f800000 || hx - hy1 >= 0x0c800000)
		{
			if (hx >= 0x7f800000)
			{
				if (hx ^ 0x7f800000) /* nan */
					ah1 =  x1 + y1;
				else if (hy1 >= 0x7f800000)
					ah1 += pio4;
			}
			else if ((int) ah1 == 0)
				ah1 = y1 / x1;
			*z = (sign1 == one)? ah1 : -ah1;
			x += stridex;
			y += stridey;
			z += stridez;
			i = 1;
			if (--n <= 0)
				break;
			goto loop1;
		}
		if (hy1 < 0x00800000) {
			if (hy1 == 0)
			{
				*z = sign1 * (float) ah1;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 1;
				if (--n <= 0)
					break;
				goto loop1;
			}
			y1 *= twop24; /* scale subnormal y */
			x1 *= twop24; /* scale possibly subnormal x */
			hy1 = *(int*)&y1;
                        hx = *(int*)&x1;
		}
		pz1 = z;

		k1 = (hy1 - hx + 0x3f800000) & 0xfff80000;
		if (k1 >= 0x3C800000)          /* if |x| >= (1/64)... */
    		{ 
			*(int*)&base1 = k1;
       		 	k1 = (k1 - 0x3C800000) >> 18; /* (index >> 19) << 1) */
			k1 += 4;
				/* skip over 0,0,pi/2,pi/2 */
    		}  
    		else                            /* |x| < 1/64 */
    		{ 
       			k1 = 0;
			base1 = zero;
    		}

		x += stridex;
		y += stridey;
		z += stridez;
		i = 2;
		if (--n <= 0)
			break;

loop2:
		hy2 = *(int*)y;
		hx = *(int*)x;
		sign2 = one;
		sy = hy2 & 0x80000000;
		hy2 &= ~0x80000000;

		sx = hx & 0x80000000;
		hx &= ~0x80000000;

		if (hy2 > hx)
		{
			x2 = *y;
			y2 = *x;
			i = hx;
			hx = hy2;
			hy2 = i;
			if (sy) 
			{
				x2 = -x2;
				sign2 = -sign2;
			}
			if (sx)
			{
				y2 = -y2;
				ah2 = pio2;
			}
			else
			{
				ah2 = -pio2;
				sign2 = -sign2;
			}
		}
		else
		{
			y2 = *y;
			x2 = *x;
			if (sy) 
			{
				y2 = -y2;
				sign2 = -sign2;
			}
			if (sx)
			{
				x2 = -x2;
				ah2 = -pi;
				sign2 = -sign2;
			}
			else
				ah2 = zero;
		}

		if (hx >= 0x7f800000 || hx - hy2 >= 0x0c800000)
		{
			if (hx >= 0x7f800000)
			{
				if (hx ^ 0x7f800000) /* nan */
					ah2 =  x2 + y2;
				else if (hy2 >= 0x7f800000)
					ah2 += pio4;
			}
			else if ((int) ah2 == 0)
				ah2 = y2 / x2;
			*z = (sign2 == one)? ah2 : -ah2;
			x += stridex;
			y += stridey;
			z += stridez;
			i = 2;
			if (--n <= 0)
				break;
			goto loop2;
		}
		if (hy2 < 0x00800000) {
			if (hy2 == 0)
			{
				*z = sign2 * (float) ah2;
				x += stridex;
				y += stridey;
				z += stridez;
				i = 2;
				if (--n <= 0)
					break;
				goto loop2;
			}
			y2 *= twop24; /* scale subnormal y */
			x2 *= twop24; /* scale possibly subnormal x */
			hy2 = *(int*)&y2;
                        hx = *(int*)&x2;
		}

		pz2 = z;

		k2 = (hy2 - hx + 0x3f800000) & 0xfff80000;
		if (k2 >= 0x3C800000)          /* if |x| >= (1/64)... */
    		{ 
			*(int*)&base2 = k2;
       		 	k2 = (k2 - 0x3C800000) >> 18; /* (index >> 19) << 1) */
			k2 += 4;
				/* skip over 0,0,pi/2,pi/2 */
    		}  
    		else                            /* |x| < 1/64 */
    		{ 
			k2 = 0;
			base2 = zero;
    		}

		goto endloop;

endloop:

		ah2 += __vlibm_TBL_atan1[k2];	
		ah1 += __vlibm_TBL_atan1[k1];	
		ah0 += __vlibm_TBL_atan1[k0];	

		db2 = base2;
		db1 = base1;
		db0 = base0;
		dy2 = y2;
		dy1 = y1;
		dy0 = y0;
		dx2 = x2;
		dx1 = x1;
		dx0 = x0;

		num2 = dy2 - dx2 * db2;
		den2 = dx2 + dy2 * db2;

		num1 = dy1 - dx1 * db1;
		den1 = dx1 + dy1 * db1;

		num0 = dy0 - dx0 * db0;
		den0 = dx0 + dy0 * db0;

		t2 = num2 / den2;
		t1 = num1 / den1;
		t0 = num0 / den0;

		sx2 = t2 * t2;
		sx1 = t1 * t1;
		sx0 = t0 * t0;
 
		t2 += t2 * sx2 * (q1 + sx2 * q2);
 		t1 += t1 * sx1 * (q1 + sx1 * q2);
 		t0 += t0 * sx0 * (q1 + sx0 * q2);

		t2 += ah2;
		t1 += ah1;
		t0 += ah0;

		*pz2 = sign2 * t2;
		*pz1 = sign1 * t1;
		*pz0 = sign0 * t0;

		x += stridex;
		y += stridey;
		z += stridez;
		i = 0;
	} while (--n > 0);

	if (i > 1)
	{
		ah1 += __vlibm_TBL_atan1[k1];	
		t1 = (y1 - x1 * (double)base1) / 
			(x1 + y1 * (double)base1);
		sx1 = t1 * t1;
 		t1 += t1 * sx1 * (q1 + sx1 * q2);
		t1 += ah1;
		*pz1 = sign1 * t1;
	}

	if (i > 0)
	{
		ah0 += __vlibm_TBL_atan1[k0];	
		t0 = (y0 - x0 * (double)base0) / 
			(x0 + y0 * (double)base0);
		sx0 = t0 * t0;
 		t0 += t0 * sx0 * (q1 + sx0 * q2);
		t0 += ah0;
		*pz0 = sign0 * t0;
	}
}
