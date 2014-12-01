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

#pragma weak fma = __fma

#include "libm.h"
#include "fma.h"
#include "fenv_inlines.h"

#if defined(__sparc)

static const union {
	unsigned i[2];
	double d;
} C[] = {
	{ 0x3fe00000u, 0 },
	{ 0x40000000u, 0 },
	{ 0x43300000u, 0 },
	{ 0x41a00000u, 0 },
	{ 0x3e500000u, 0 },
	{ 0x3df00000u, 0 },
	{ 0x3bf00000u, 0 },
	{ 0x7fe00000u, 0 },
	{ 0x00100000u, 0 },
	{ 0x00100001u, 0 }
};

#define	half	C[0].d
#define	two	C[1].d
#define	two52	C[2].d
#define	two27	C[3].d
#define	twom26	C[4].d
#define	twom32	C[5].d
#define	twom64	C[6].d
#define	huge	C[7].d
#define	tiny	C[8].d
#define	tiny2	C[9].d

static const unsigned int fsr_rm = 0xc0000000u;

/*
 * fma for SPARC: 64-bit double precision, big-endian
 */
double
__fma(double x, double y, double z) {
	union {
		unsigned i[2];
		double d;
	} xx, yy, zz;
	double xhi, yhi, xlo, ylo, t;
	unsigned int xy0, xy1, xy2, xy3, z0, z1, z2, z3, fsr, rm, sticky;
	int hx, hy, hz, ex, ey, ez, exy, sxy, sz, e, ibit;
	volatile double	dummy;

	/* extract the high order words of the arguments */
	xx.d = x;
	yy.d = y;
	zz.d = z;
	hx = xx.i[0] & ~0x80000000;
	hy = yy.i[0] & ~0x80000000;
	hz = zz.i[0] & ~0x80000000;

	/* dispense with inf, nan, and zero cases */
	if (hx >= 0x7ff00000 || hy >= 0x7ff00000 || (hx | xx.i[1]) == 0 ||
		(hy | yy.i[1]) == 0)	/* x or y is inf, nan, or zero */
		return (x * y + z);

	if (hz >= 0x7ff00000)	/* z is inf or nan */
		return (x + z);	/* avoid spurious under/overflow in x * y */

	if ((hz | zz.i[1]) == 0)	/* z is zero */
		/*
		 * x * y isn't zero but could underflow to zero,
		 * so don't add z, lest we perturb the sign
		 */
		return (x * y);

	/*
	 * now x, y, and z are all finite and nonzero; save the fsr and
	 * set round-to-negative-infinity mode (and clear nonstandard
	 * mode before we try to scale subnormal operands)
	 */
	__fenv_getfsr32(&fsr);
	__fenv_setfsr32(&fsr_rm);

	/* extract signs and exponents, and normalize subnormals */
	sxy = (xx.i[0] ^ yy.i[0]) & 0x80000000;
	sz = zz.i[0] & 0x80000000;
	ex = hx >> 20;
	if (!ex) {
		xx.d = x * two52;
		ex = ((xx.i[0] & ~0x80000000) >> 20) - 52;
	}
	ey = hy >> 20;
	if (!ey) {
		yy.d = y * two52;
		ey = ((yy.i[0] & ~0x80000000) >> 20) - 52;
	}
	ez = hz >> 20;
	if (!ez) {
		zz.d = z * two52;
		ez = ((zz.i[0] & ~0x80000000) >> 20) - 52;
	}

	/* multiply x*y to 106 bits */
	exy = ex + ey - 0x3ff;
	xx.i[0] = (xx.i[0] & 0xfffff) | 0x3ff00000;
	yy.i[0] = (yy.i[0] & 0xfffff) | 0x3ff00000;
	x = xx.d;
	y = yy.d;
	xhi = ((x + twom26) + two27) - two27;
	yhi = ((y + twom26) + two27) - two27;
	xlo = x - xhi;
	ylo = y - yhi;
	x *= y;
	y = ((xhi * yhi - x) + xhi * ylo + xlo * yhi) + xlo * ylo;
	if (x >= two) {
		x *= half;
		y *= half;
		exy++;
	}

	/* extract the significands */
	xx.d = x;
	xy0 = (xx.i[0] & 0xfffff) | 0x100000;
	xy1 = xx.i[1];
	yy.d = t = y + twom32;
	xy2 = yy.i[1];
	yy.d = (y - (t - twom32)) + twom64;
	xy3 = yy.i[1];
	z0 = (zz.i[0] & 0xfffff) | 0x100000;
	z1 = zz.i[1];
	z2 = z3 = 0;

	/*
	 * now x*y is represented by sxy, exy, and xy[0-3], and z is
	 * represented likewise; swap if need be so |xy| <= |z|
	 */
	if (exy > ez || (exy == ez && (xy0 > z0 || (xy0 == z0 &&
		(xy1 > z1 || (xy1 == z1 && (xy2 | xy3) != 0)))))) {
		e = sxy; sxy = sz; sz = e;
		e = exy; exy = ez; ez = e;
		e = xy0; xy0 = z0; z0 = e;
		e = xy1; xy1 = z1; z1 = e;
		z2 = xy2; xy2 = 0;
		z3 = xy3; xy3 = 0;
	}

	/* shift the significand of xy keeping a sticky bit */
	e = ez - exy;
	if (e > 116) {
		xy0 = xy1 = xy2 = 0;
		xy3 = 1;
	} else if (e >= 96) {
		sticky = xy3 | xy2 | xy1 | ((xy0 << 1) << (127 - e));
		xy3 = xy0 >> (e - 96);
		if (sticky)
			xy3 |= 1;
		xy0 = xy1 = xy2 = 0;
	} else if (e >= 64) {
		sticky = xy3 | xy2 | ((xy1 << 1) << (95 - e));
		xy3 = (xy1 >> (e - 64)) | ((xy0 << 1) << (95 - e));
		if (sticky)
			xy3 |= 1;
		xy2 = xy0 >> (e - 64);
		xy0 = xy1 = 0;
	} else if (e >= 32) {
		sticky = xy3 | ((xy2 << 1) << (63 - e));
		xy3 = (xy2 >> (e - 32)) | ((xy1 << 1) << (63 - e));
		if (sticky)
			xy3 |= 1;
		xy2 = (xy1 >> (e - 32)) | ((xy0 << 1) << (63 - e));
		xy1 = xy0 >> (e - 32);
		xy0 = 0;
	} else if (e) {
		sticky = (xy3 << 1) << (31 - e);
		xy3 = (xy3 >> e) | ((xy2 << 1) << (31 - e));
		if (sticky)
			xy3 |= 1;
		xy2 = (xy2 >> e) | ((xy1 << 1) << (31 - e));
		xy1 = (xy1 >> e) | ((xy0 << 1) << (31 - e));
		xy0 >>= e;
	}

	/* if this is a magnitude subtract, negate the significand of xy */
	if (sxy ^ sz) {
		xy0 = ~xy0;
		xy1 = ~xy1;
		xy2 = ~xy2;
		xy3 = -xy3;
		if (xy3 == 0)
			if (++xy2 == 0)
				if (++xy1 == 0)
					xy0++;
	}

	/* add, propagating carries */
	z3 += xy3;
	e = (z3 < xy3);
	z2 += xy2;
	if (e) {
		z2++;
		e = (z2 <= xy2);
	} else
		e = (z2 < xy2);
	z1 += xy1;
	if (e) {
		z1++;
		e = (z1 <= xy1);
	} else
		e = (z1 < xy1);
	z0 += xy0;
	if (e)
		z0++;

	/* postnormalize and collect rounding information into z2 */
	if (ez < 1) {
		/* result is tiny; shift right until exponent is within range */
		e = 1 - ez;
		if (e > 56) {
			z2 = 1;	/* result can't be exactly zero */
			z0 = z1 = 0;
		} else if (e >= 32) {
			sticky = z3 | z2 | ((z1 << 1) << (63 - e));
			z2 = (z1 >> (e - 32)) | ((z0 << 1) << (63 - e));
			if (sticky)
				z2 |= 1;
			z1 = z0 >> (e - 32);
			z0 = 0;
		} else {
			sticky = z3 | (z2 << 1) << (31 - e);
			z2 = (z2 >> e) | ((z1 << 1) << (31 - e));
			if (sticky)
				z2 |= 1;
			z1 = (z1 >> e) | ((z0 << 1) << (31 - e));
			z0 >>= e;
		}
		ez = 1;
	} else if (z0 >= 0x200000) {
		/* carry out; shift right by one */
		sticky = (z2 & 1) | z3;
		z2 = (z2 >> 1) | (z1 << 31);
		if (sticky)
			z2 |= 1;
		z1 = (z1 >> 1) | (z0 << 31);
		z0 >>= 1;
		ez++;
	} else {
		if (z0 < 0x100000 && (z0 | z1 | z2 | z3) != 0) {
			/*
			 * borrow/cancellation; shift left as much as
			 * exponent allows
			 */
			while (!(z0 | (z1 & 0xffe00000)) && ez >= 33) {
				z0 = z1;
				z1 = z2;
				z2 = z3;
				z3 = 0;
				ez -= 32;
			}
			while (z0 < 0x100000 && ez > 1) {
				z0 = (z0 << 1) | (z1 >> 31);
				z1 = (z1 << 1) | (z2 >> 31);
				z2 = (z2 << 1) | (z3 >> 31);
				z3 <<= 1;
				ez--;
			}
		}
		if (z3)
			z2 |= 1;
	}

	/* get the rounding mode and clear current exceptions */
	rm = fsr >> 30;
	fsr &= ~FSR_CEXC;

	/* strip off the integer bit, if there is one */
	ibit = z0 & 0x100000;
	if (ibit)
		z0 -= 0x100000;
	else {
		ez = 0;
		if (!(z0 | z1 | z2)) { /* exact zero */
			zz.i[0] = rm == FSR_RM ? 0x80000000 : 0;
			zz.i[1] = 0;
			__fenv_setfsr32(&fsr);
			return (zz.d);
		}
	}

	/*
	 * flip the sense of directed roundings if the result is negative;
	 * the logic below applies to a positive result
	 */
	if (sz)
		rm ^= rm >> 1;

	/* round and raise exceptions */
	if (z2) {
		fsr |= FSR_NXC;

		/* decide whether to round the fraction up */
		if (rm == FSR_RP || (rm == FSR_RN && (z2 > 0x80000000u ||
			(z2 == 0x80000000u && (z1 & 1))))) {
			/* round up and renormalize if necessary */
			if (++z1 == 0) {
				if (++z0 == 0x100000) {
					z0 = 0;
					ez++;
				}
			}
		}
	}

	/* check for under/overflow */
	if (ez >= 0x7ff) {
		if (rm == FSR_RN || rm == FSR_RP) {
			zz.i[0] = sz | 0x7ff00000;
			zz.i[1] = 0;
		} else {
			zz.i[0] = sz | 0x7fefffff;
			zz.i[1] = 0xffffffff;
		}
		fsr |= FSR_OFC | FSR_NXC;
	} else {
		zz.i[0] = sz | (ez << 20) | z0;
		zz.i[1] = z1;

		/*
		 * !ibit => exact result was tiny before rounding,
		 * z2 nonzero => result delivered is inexact
		 */
		if (!ibit) {
			if (z2)
				fsr |= FSR_UFC | FSR_NXC;
			else if (fsr & FSR_UFM)
				fsr |= FSR_UFC;
		}
	}

	/* restore the fsr and emulate exceptions as needed */
	if ((fsr & FSR_CEXC) & (fsr >> 23)) {
		__fenv_setfsr32(&fsr);
		if (fsr & FSR_OFC) {
			dummy = huge;
			dummy *= huge;
		} else if (fsr & FSR_UFC) {
			dummy = tiny;
			if (fsr & FSR_NXC)
				dummy *= tiny;
			else
				dummy -= tiny2;
		} else {
			dummy = huge;
			dummy += tiny;
		}
	} else {
		fsr |= (fsr & 0x1f) << 5;
		__fenv_setfsr32(&fsr);
	}
	return (zz.d);
}

#elif defined(__x86)

#if defined(__amd64)
#define	NI	4
#else
#define	NI	3
#endif

/*
 *  fma for x86: 64-bit double precision, little-endian
 */
double
__fma(double x, double y, double z) {
	union {
		unsigned i[NI];
		long double e;
	} xx, yy, zz;
	long double xe, ye, xhi, xlo, yhi, ylo;
	int ex, ey, ez;
	unsigned cwsw, oldcwsw, rm;

	/* convert the operands to double extended */
	xx.e = (long double) x;
	yy.e = (long double) y;
	zz.e = (long double) z;

	/* extract the exponents of the arguments */
	ex = xx.i[2] & 0x7fff;
	ey = yy.i[2] & 0x7fff;
	ez = zz.i[2] & 0x7fff;

	/* dispense with inf, nan, and zero cases */
	if (ex == 0x7fff || ey == 0x7fff || ex == 0 || ey == 0)
		/* x or y is inf, nan, or zero */
		return ((double) (xx.e * yy.e + zz.e));

	if (ez >= 0x7fff) /* z is inf or nan */
		return ((double) (xx.e + zz.e));
					/* avoid spurious inexact in x * y */

	/*
	 * save the control and status words, mask all exceptions, and
	 * set rounding to 64-bit precision and to-nearest
	 */
	__fenv_getcwsw(&oldcwsw);
	cwsw = (oldcwsw & 0xf0c0ffff) | 0x033f0000;
	__fenv_setcwsw(&cwsw);

	/* multiply x*y to 106 bits */
	xe = xx.e;
	xx.i[0] = 0;
	xhi = xx.e; /* hi 32 bits */
	xlo = xe - xhi; /* lo 21 bits */
	ye = yy.e;
	yy.i[0] = 0;
	yhi = yy.e;
	ylo = ye - yhi;
	xe = xe * ye;
	ye = ((xhi * yhi - xe) + xhi * ylo + xlo * yhi) + xlo * ylo;

	/* distill the sum of xe, ye, and z */
	xhi = ye + zz.e;
	yhi = xhi - ye;
	xlo = (zz.e - yhi) + (ye - (xhi - yhi));
						/* now (xhi,xlo) = ye + z */

	yhi = xe + xhi;
	ye = yhi - xe;
	ylo = (xhi - ye) + (xe - (yhi - ye));	/* now (yhi,ylo) = xe + xhi */

	xhi = xlo + ylo;
	xe = xhi - xlo;
	xlo = (ylo - xe) + (xlo - (xhi - xe));	/* now (xhi,xlo) = xlo + ylo */

	yy.e = yhi + xhi;
	ylo = (yhi - yy.e) + xhi;		/* now (yy.e,ylo) = xhi + yhi */

	if (yy.i[1] != 0) {	/* yy.e is nonzero */
		/* perturb yy.e if its least significant 10 bits are zero */
		if (!(yy.i[0] & 0x3ff)) {
			xx.e = ylo + xlo;
			if (xx.i[1] != 0) {
				xx.i[2] = (xx.i[2] & 0x8000) |
					((yy.i[2] & 0x7fff) - 63);
				xx.i[1] = 0x80000000;
				xx.i[0] = 0;
				yy.e += xx.e;
			}
		}
	} else {
		/* set sign of zero result according to rounding direction */
		rm = oldcwsw & 0x0c000000;
		yy.i[2] = ((rm == FCW_RM)? 0x8000 : 0);
	}

	/*
	 * restore the control and status words and convert the result
	 * to double
	 */
	__fenv_setcwsw(&oldcwsw);
	return ((double) yy.e);
}

#else
#error Unknown architecture
#endif
