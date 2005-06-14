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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "quad.h"

static const double C[] = {
	0.0,
	0.5,
	1.0,
	2.0,
	68719476736.0,
	1048576.0,
	16.0,
	1.52587890625000000000e-05,
	5.96046447753906250000e-08,
	3.72529029846191406250e-09,
	8.67361737988403547206e-19,
	2.16840434497100886801e-19,
	1.32348898008484427979e-23,
	9.62964972193617926528e-35,
	4.70197740328915003187e-38
};

#define	zero	C[0]
#define	half	C[1]
#define	one	C[2]
#define	two	C[3]
#define	two36	C[4]
#define	two20	C[5]
#define	two4	C[6]
#define	twom16	C[7]
#define	twom24	C[8]
#define	twom28	C[9]
#define	twom60	C[10]
#define	twom62	C[11]
#define	twom76	C[12]
#define	twom113	C[13]
#define	twom124	C[14]

static const unsigned fsr_rn = 0xc0000000u;

#ifdef __sparcv9

/*
 * _Qp_mul(pz, x, y) sets *pz = *x * *y.
 */
void
_Qp_mul(union longdouble *pz, const union longdouble *x,
	const union longdouble *y)

#else

/*
 * _Q_mul(x, y) returns *x * *y.
 */
union longdouble
_Q_mul(const union longdouble *x, const union longdouble *y)

#endif	/* __sparcv9 */

{
	union longdouble	z;
	union xdouble		u;
	double			xx[5], yy[5], c, d, zz[9];
	unsigned int		xm, ym, fsr, lx, ly, wx[3], wy[3];
	unsigned int		msw, frac2, frac3, frac4, rm;
	int			ibit, ex, ey, ez, sign;

	xm = x->l.msw & 0x7fffffff;
	ym = y->l.msw & 0x7fffffff;
	sign = (x->l.msw ^ y->l.msw) & ~0x7fffffff;

	__quad_getfsrp(&fsr);

	/* handle nan and inf cases */
	if (xm >= 0x7fff0000 || ym >= 0x7fff0000) {
		/* handle nan cases according to V9 app. B */
		if (QUAD_ISNAN(*y)) {
			if (!(y->l.msw & 0x8000)) {
				/* snan, signal invalid */
				if (fsr & FSR_NVM) {
					__quad_fmulq(x, y, &Z);
				} else {
					Z = *y;
					Z.l.msw |= 0x8000;
					fsr = (fsr & ~FSR_CEXC) | FSR_NVA |
					    FSR_NVC;
					__quad_setfsrp(&fsr);
				}
				QUAD_RETURN(Z);
			} else if (QUAD_ISNAN(*x) && !(x->l.msw & 0x8000)) {
				/* snan, signal invalid */
				if (fsr & FSR_NVM) {
					__quad_fmulq(x, y, &Z);
				} else {
					Z = *x;
					Z.l.msw |= 0x8000;
					fsr = (fsr & ~FSR_CEXC) | FSR_NVA |
					    FSR_NVC;
					__quad_setfsrp(&fsr);
				}
				QUAD_RETURN(Z);
			}
			Z = *y;
			QUAD_RETURN(Z);
		}
		if (QUAD_ISNAN(*x)) {
			if (!(x->l.msw & 0x8000)) {
				/* snan, signal invalid */
				if (fsr & FSR_NVM) {
					__quad_fmulq(x, y, &Z);
				} else {
					Z = *x;
					Z.l.msw |= 0x8000;
					fsr = (fsr & ~FSR_CEXC) | FSR_NVA |
					    FSR_NVC;
					__quad_setfsrp(&fsr);
				}
				QUAD_RETURN(Z);
			}
			Z = *x;
			QUAD_RETURN(Z);
		}
		if (xm == 0x7fff0000) {
			/* x is inf */
			if (QUAD_ISZERO(*y)) {
				/* zero * inf, signal invalid */
				if (fsr & FSR_NVM) {
					__quad_fmulq(x, y, &Z);
				} else {
					Z.l.msw = 0x7fffffff;
					Z.l.frac2 = Z.l.frac3 =
					    Z.l.frac4 = 0xffffffff;
					fsr = (fsr & ~FSR_CEXC) | FSR_NVA |
					    FSR_NVC;
					__quad_setfsrp(&fsr);
				}
				QUAD_RETURN(Z);
			}
			/* inf * finite, return inf */
			Z.l.msw = sign | 0x7fff0000;
			Z.l.frac2 = Z.l.frac3 = Z.l.frac4 = 0;
			QUAD_RETURN(Z);
		}
		/* y is inf */
		if (QUAD_ISZERO(*x)) {
			/* zero * inf, signal invalid */
			if (fsr & FSR_NVM) {
				__quad_fmulq(x, y, &Z);
			} else {
				Z.l.msw = 0x7fffffff;
				Z.l.frac2 = Z.l.frac3 = Z.l.frac4 = 0xffffffff;
				fsr = (fsr & ~FSR_CEXC) | FSR_NVA | FSR_NVC;
				__quad_setfsrp(&fsr);
			}
			QUAD_RETURN(Z);
		}
		/* inf * finite, return inf */
		Z.l.msw = sign | 0x7fff0000;
		Z.l.frac2 = Z.l.frac3 = Z.l.frac4 = 0;
		QUAD_RETURN(Z);
	}

	/* handle zero cases */
	if (xm == 0 || ym == 0) {
		if (QUAD_ISZERO(*x) || QUAD_ISZERO(*y)) {
			Z.l.msw = sign;
			Z.l.frac2 = Z.l.frac3 = Z.l.frac4 = 0;
			QUAD_RETURN(Z);
		}
	}

	/* now x and y are finite, nonzero */
	__quad_setfsrp(&fsr_rn);

	/* get their normalized significands and exponents */
	ex = (int)(xm >> 16);
	lx = xm & 0xffff;
	if (ex) {
		lx |= 0x10000;
		wx[0] = x->l.frac2;
		wx[1] = x->l.frac3;
		wx[2] = x->l.frac4;
	} else {
		if (lx | (x->l.frac2 & 0xfffe0000)) {
			wx[0] = x->l.frac2;
			wx[1] = x->l.frac3;
			wx[2] = x->l.frac4;
			ex = 1;
		} else if (x->l.frac2 | (x->l.frac3 & 0xfffe0000)) {
			lx = x->l.frac2;
			wx[0] = x->l.frac3;
			wx[1] = x->l.frac4;
			wx[2] = 0;
			ex = -31;
		} else if (x->l.frac3 | (x->l.frac4 & 0xfffe0000)) {
			lx = x->l.frac3;
			wx[0] = x->l.frac4;
			wx[1] = wx[2] = 0;
			ex = -63;
		} else {
			lx = x->l.frac4;
			wx[0] = wx[1] = wx[2] = 0;
			ex = -95;
		}
		while ((lx & 0x10000) == 0) {
			lx = (lx << 1) | (wx[0] >> 31);
			wx[0] = (wx[0] << 1) | (wx[1] >> 31);
			wx[1] = (wx[1] << 1) | (wx[2] >> 31);
			wx[2] <<= 1;
			ex--;
		}
	}
	ez = ex - 0x3fff;

	ey = (int)(ym >> 16);
	ly = ym & 0xffff;
	if (ey) {
		ly |= 0x10000;
		wy[0] = y->l.frac2;
		wy[1] = y->l.frac3;
		wy[2] = y->l.frac4;
	} else {
		if (ly | (y->l.frac2 & 0xfffe0000)) {
			wy[0] = y->l.frac2;
			wy[1] = y->l.frac3;
			wy[2] = y->l.frac4;
			ey = 1;
		} else if (y->l.frac2 | (y->l.frac3 & 0xfffe0000)) {
			ly = y->l.frac2;
			wy[0] = y->l.frac3;
			wy[1] = y->l.frac4;
			wy[2] = 0;
			ey = -31;
		} else if (y->l.frac3 | (y->l.frac4 & 0xfffe0000)) {
			ly = y->l.frac3;
			wy[0] = y->l.frac4;
			wy[1] = wy[2] = 0;
			ey = -63;
		} else {
			ly = y->l.frac4;
			wy[0] = wy[1] = wy[2] = 0;
			ey = -95;
		}
		while ((ly & 0x10000) == 0) {
			ly = (ly << 1) | (wy[0] >> 31);
			wy[0] = (wy[0] << 1) | (wy[1] >> 31);
			wy[1] = (wy[1] << 1) | (wy[2] >> 31);
			wy[2] <<= 1;
			ey--;
		}
	}
	ez += ey;

	/* extract the significand into five doubles */
	c = twom16;
	xx[0] = (double)((int)lx) * c;
	yy[0] = (double)((int)ly) * c;

	c *= twom24;
	xx[1] = (double)((int)(wx[0] >> 8)) * c;
	yy[1] = (double)((int)(wy[0] >> 8)) * c;

	c *= twom24;
	xx[2] = (double)((int)(((wx[0] << 16) | (wx[1] >> 16)) &
	    0xffffff)) * c;
	yy[2] = (double)((int)(((wy[0] << 16) | (wy[1] >> 16)) &
	    0xffffff)) * c;

	c *= twom24;
	xx[3] = (double)((int)(((wx[1] << 8) | (wx[2] >> 24)) &
	    0xffffff)) * c;
	yy[3] = (double)((int)(((wy[1] << 8) | (wy[2] >> 24)) &
	    0xffffff)) * c;

	c *= twom24;
	xx[4] = (double)((int)(wx[2] & 0xffffff)) * c;
	yy[4] = (double)((int)(wy[2] & 0xffffff)) * c;

	/* form the "digits" of the product */
	zz[0] = xx[0] * yy[0];
	zz[1] = xx[0] * yy[1] + xx[1] * yy[0];
	zz[2] = xx[0] * yy[2] + xx[1] * yy[1] + xx[2] * yy[0];
	zz[3] = xx[0] * yy[3] + xx[1] * yy[2] + xx[2] * yy[1] +
	    xx[3] * yy[0];
	zz[4] = xx[0] * yy[4] + xx[1] * yy[3] + xx[2] * yy[2] +
	    xx[3] * yy[1] + xx[4] * yy[0];
	zz[5] = xx[1] * yy[4] + xx[2] * yy[3] + xx[3] * yy[2] +
	    xx[4] * yy[1];
	zz[6] = xx[2] * yy[4] + xx[3] * yy[3] + xx[4] * yy[2];
	zz[7] = xx[3] * yy[4] + xx[4] * yy[3];
	zz[8] = xx[4] * yy[4];

	/* collect the first few terms */
	c = (zz[1] + two20) - two20;
	zz[0] += c;
	zz[1] = zz[2] + (zz[1] - c);
	c = (zz[3] + twom28) - twom28;
	zz[1] += c;
	zz[2] = zz[4] + (zz[3] - c);

	/* propagate carries into the third term */
	d = zz[6] + (zz[7] + zz[8]);
	zz[2] += zz[5] + d;

	/* if the third term might lie on a rounding boundary, perturb it */
	/* as need be */
	if (zz[2] == (twom62 + zz[2]) - twom62)
	{
		c = (zz[5] + twom76) - twom76;
		if ((zz[5] - c) + d != zero)
			zz[2] += twom124;
	}

	/* propagate carries to the leading term */
	c = zz[1] + zz[2];
	zz[2] = zz[2] + (zz[1] - c);
	zz[1] = c;
	c = zz[0] + zz[1];
	zz[1] = zz[1] + (zz[0] - c);
	zz[0] = c;

	/* check for carry out */
	if (c >= two) {
		/* postnormalize */
		zz[0] *= half;
		zz[1] *= half;
		zz[2] *= half;
		ez++;
	}

	/* if exponent > 0 strip off integer bit, else denormalize */
	if (ez > 0) {
		ibit = 1;
		zz[0] -= one;
	} else {
		ibit = 0;
		if (ez > -128)
			u.l.hi = (unsigned)(0x3fe + ez) << 20;
		else
			u.l.hi = 0x37e00000;
		u.l.lo = 0;
		zz[0] *= u.d;
		zz[1] *= u.d;
		zz[2] *= u.d;
		ez = 0;
	}

	/* the first 48 bits of fraction come from zz[0] */
	u.d = d = two36 + zz[0];
	msw = u.l.lo;
	zz[0] -= (d - two36);

	u.d = d = two4 + zz[0];
	frac2 = u.l.lo;
	zz[0] -= (d - two4);

	/* the next 32 come from zz[0] and zz[1] */
	u.d = d = twom28 + (zz[0] + zz[1]);
	frac3 = u.l.lo;
	zz[0] -= (d - twom28);

	/* condense the remaining fraction; errors here won't matter */
	c = zz[0] + zz[1];
	zz[1] = ((zz[0] - c) + zz[1]) + zz[2];
	zz[0] = c;

	/* get the last word of fraction */
	u.d = d = twom60 + (zz[0] + zz[1]);
	frac4 = u.l.lo;
	zz[0] -= (d - twom60);

	/* keep track of what's left for rounding; note that the error */
	/* in computing c will be non-negative due to rounding mode */
	c = zz[0] + zz[1];

	/* get the rounding mode, fudging directed rounding modes */
	/* as though the result were positive */
	rm = fsr >> 30;
	if (sign)
		rm ^= (rm >> 1);

	/* round and raise exceptions */
	fsr &= ~FSR_CEXC;
	if (c != zero) {
		fsr |= FSR_NXC;

		/* decide whether to round the fraction up */
		if (rm == FSR_RP || (rm == FSR_RN && (c > twom113 ||
		    (c == twom113 && ((frac4 & 1) || (c - zz[0] != zz[1])))))) {
			/* round up and renormalize if necessary */
			if (++frac4 == 0)
				if (++frac3 == 0)
					if (++frac2 == 0)
						if (++msw == 0x10000) {
							msw = 0;
							ez++;
						}
		}
	}

	/* check for under/overflow */
	if (ez >= 0x7fff) {
		if (rm == FSR_RN || rm == FSR_RP) {
			z.l.msw = sign | 0x7fff0000;
			z.l.frac2 = z.l.frac3 = z.l.frac4 = 0;
		} else {
			z.l.msw = sign | 0x7ffeffff;
			z.l.frac2 = z.l.frac3 = z.l.frac4 = 0xffffffff;
		}
		fsr |= FSR_OFC | FSR_NXC;
	} else {
		z.l.msw = sign | (ez << 16) | msw;
		z.l.frac2 = frac2;
		z.l.frac3 = frac3;
		z.l.frac4 = frac4;

		/* !ibit => exact result was tiny before rounding, */
		/* t nonzero => result delivered is inexact */
		if (!ibit) {
			if (c != zero)
				fsr |= FSR_UFC | FSR_NXC;
			else if (fsr & FSR_UFM)
				fsr |= FSR_UFC;
		}
	}

	if ((fsr & FSR_CEXC) & (fsr >> 23)) {
		__quad_setfsrp(&fsr);
		__quad_fmulq(x, y, &Z);
	} else {
		Z = z;
		fsr |= (fsr & 0x1f) << 5;
		__quad_setfsrp(&fsr);
	}
	QUAD_RETURN(Z);
}
