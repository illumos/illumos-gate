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

#if defined(ELFOBJ)
#pragma weak fmal = __fmal
#endif

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
	{ 0x3ef00000u, 0 },
	{ 0x3e700000u, 0 },
	{ 0x41300000u, 0 },
	{ 0x3e300000u, 0 },
	{ 0x3b300000u, 0 },
	{ 0x38300000u, 0 },
	{ 0x42300000u, 0 },
	{ 0x3df00000u, 0 },
	{ 0x7fe00000u, 0 },
	{ 0x00100000u, 0 },
	{ 0x00100001u, 0 },
	{ 0, 0 },
	{ 0x7ff00000u, 0 },
	{ 0x7ff00001u, 0 }
};

#define	half	C[0].d
#define	two	C[1].d
#define	twom16	C[2].d
#define	twom24	C[3].d
#define	two20	C[4].d
#define	twom28	C[5].d
#define	twom76	C[6].d
#define	twom124	C[7].d
#define	two36	C[8].d
#define	twom32	C[9].d
#define	huge	C[10].d
#define	tiny	C[11].d
#define	tiny2	C[12].d
#define	zero	C[13].d
#define	inf	C[14].d
#define	snan	C[15].d

static const unsigned int fsr_rm = 0xc0000000u;

/*
 * fmal for SPARC: 128-bit quad precision, big-endian
 */
long double
__fmal(long double x, long double y, long double z) {
	union {
		unsigned int i[4];
		long double q;
	} xx, yy, zz;
	union {
		unsigned int i[2];
		double d;
	} u;
	double dx[5], dy[5], dxy[9], c, s;
	unsigned int xy0, xy1, xy2, xy3, xy4, xy5, xy6, xy7;
	unsigned int z0, z1, z2, z3, z4, z5, z6, z7;
	unsigned int rm, sticky;
	unsigned int fsr;
	int hx, hy, hz, ex, ey, ez, exy, sxy, sz, e, ibit;
	int cx, cy, cz;
	volatile double	dummy;

	/* extract the high order words of the arguments */
	xx.q = x;
	yy.q = y;
	zz.q = z;
	hx = xx.i[0] & ~0x80000000;
	hy = yy.i[0] & ~0x80000000;
	hz = zz.i[0] & ~0x80000000;

	/*
	 * distinguish zero, finite nonzero, infinite, and quiet nan
	 * arguments; raise invalid and return for signaling nans
	 */
	if (hx >= 0x7fff0000) {
		if ((hx & 0xffff) | xx.i[1] | xx.i[2] | xx.i[3]) {
			if (!(hx & 0x8000)) {
				/* signaling nan, raise invalid */
				dummy = snan;
				dummy += snan;
				xx.i[0] |= 0x8000;
				return (xx.q);
			}
			cx = 3;	/* quiet nan */
		} else
			cx = 2;	/* inf */
	} else if (hx == 0) {
		cx = (xx.i[1] | xx.i[2] | xx.i[3]) ? 1 : 0;
				/* subnormal or zero */
	} else
		cx = 1;		/* finite nonzero */

	if (hy >= 0x7fff0000) {
		if ((hy & 0xffff) | yy.i[1] | yy.i[2] | yy.i[3]) {
			if (!(hy & 0x8000)) {
				dummy = snan;
				dummy += snan;
				yy.i[0] |= 0x8000;
				return (yy.q);
			}
			cy = 3;
		} else
			cy = 2;
	} else if (hy == 0) {
		cy = (yy.i[1] | yy.i[2] | yy.i[3]) ? 1 : 0;
	} else
		cy = 1;

	if (hz >= 0x7fff0000) {
		if ((hz & 0xffff) | zz.i[1] | zz.i[2] | zz.i[3]) {
			if (!(hz & 0x8000)) {
				dummy = snan;
				dummy += snan;
				zz.i[0] |= 0x8000;
				return (zz.q);
			}
			cz = 3;
		} else
			cz = 2;
	} else if (hz == 0) {
		cz = (zz.i[1] | zz.i[2] | zz.i[3]) ? 1 : 0;
	} else
		cz = 1;

	/* get the fsr and clear current exceptions */
	__fenv_getfsr32(&fsr);
	fsr &= ~FSR_CEXC;

	/* handle all other zero, inf, and nan cases */
	if (cx != 1 || cy != 1 || cz != 1) {
		/* if x or y is a quiet nan, return it */
		if (cx == 3) {
			__fenv_setfsr32(&fsr);
			return (x);
		}
		if (cy == 3) {
			__fenv_setfsr32(&fsr);
			return (y);
		}

		/* if x*y is 0*inf, raise invalid and return the default nan */
		if ((cx == 0 && cy == 2) || (cx == 2 && cy == 0)) {
			dummy = zero;
			dummy *= inf;
			zz.i[0] = 0x7fffffff;
			zz.i[1] = zz.i[2] = zz.i[3] = 0xffffffff;
			return (zz.q);
		}

		/* if z is a quiet nan, return it */
		if (cz == 3) {
			__fenv_setfsr32(&fsr);
			return (z);
		}

		/*
		 * now none of x, y, or z is nan; handle cases where x or y
		 * is inf
		 */
		if (cx == 2 || cy == 2) {
			/*
			 * if z is also inf, either we have inf-inf or
			 * the result is the same as z depending on signs
			 */
			if (cz == 2) {
				if ((int) ((xx.i[0] ^ yy.i[0]) ^ zz.i[0]) < 0) {
					dummy = inf;
					dummy -= inf;
					zz.i[0] = 0x7fffffff;
					zz.i[1] = zz.i[2] = zz.i[3] =
						0xffffffff;
					return (zz.q);
				}
				__fenv_setfsr32(&fsr);
				return (z);
			}

			/* otherwise the result is inf with appropriate sign */
			zz.i[0] = ((xx.i[0] ^ yy.i[0]) & 0x80000000) |
				0x7fff0000;
			zz.i[1] = zz.i[2] = zz.i[3] = 0;
			__fenv_setfsr32(&fsr);
			return (zz.q);
		}

		/* if z is inf, return it */
		if (cz == 2) {
			__fenv_setfsr32(&fsr);
			return (z);
		}

		/*
		 * now x, y, and z are all finite; handle cases where x or y
		 * is zero
		 */
		if (cx == 0 || cy == 0) {
			/* either we have 0-0 or the result is the same as z */
			if (cz == 0 && (int) ((xx.i[0] ^ yy.i[0]) ^ zz.i[0]) <
				0) {
				zz.i[0] = (fsr >> 30) == FSR_RM ? 0x80000000 :
					0;
				__fenv_setfsr32(&fsr);
				return (zz.q);
			}
			__fenv_setfsr32(&fsr);
			return (z);
		}

		/* if we get here, x and y are nonzero finite, z must be zero */
		return (x * y);
	}

	/*
	 * now x, y, and z are all finite and nonzero; set round-to-
	 * negative-infinity mode
	 */
	__fenv_setfsr32(&fsr_rm);

	/*
	 * get the signs and exponents and normalize the significands
	 * of x and y
	 */
	sxy = (xx.i[0] ^ yy.i[0]) & 0x80000000;
	ex = hx >> 16;
	hx &= 0xffff;
	if (!ex) {
		if (hx | (xx.i[1] & 0xfffe0000)) {
			ex = 1;
		} else if (xx.i[1] | (xx.i[2] & 0xfffe0000)) {
			hx = xx.i[1];
			xx.i[1] = xx.i[2];
			xx.i[2] = xx.i[3];
			xx.i[3] = 0;
			ex = -31;
		} else if (xx.i[2] | (xx.i[3] & 0xfffe0000)) {
			hx = xx.i[2];
			xx.i[1] = xx.i[3];
			xx.i[2] = xx.i[3] = 0;
			ex = -63;
		} else {
			hx = xx.i[3];
			xx.i[1] = xx.i[2] = xx.i[3] = 0;
			ex = -95;
		}
		while ((hx & 0x10000) == 0) {
			hx = (hx << 1) | (xx.i[1] >> 31);
			xx.i[1] = (xx.i[1] << 1) | (xx.i[2] >> 31);
			xx.i[2] = (xx.i[2] << 1) | (xx.i[3] >> 31);
			xx.i[3] <<= 1;
			ex--;
		}
	} else
		hx |= 0x10000;
	ey = hy >> 16;
	hy &= 0xffff;
	if (!ey) {
		if (hy | (yy.i[1] & 0xfffe0000)) {
			ey = 1;
		} else if (yy.i[1] | (yy.i[2] & 0xfffe0000)) {
			hy = yy.i[1];
			yy.i[1] = yy.i[2];
			yy.i[2] = yy.i[3];
			yy.i[3] = 0;
			ey = -31;
		} else if (yy.i[2] | (yy.i[3] & 0xfffe0000)) {
			hy = yy.i[2];
			yy.i[1] = yy.i[3];
			yy.i[2] = yy.i[3] = 0;
			ey = -63;
		} else {
			hy = yy.i[3];
			yy.i[1] = yy.i[2] = yy.i[3] = 0;
			ey = -95;
		}
		while ((hy & 0x10000) == 0) {
			hy = (hy << 1) | (yy.i[1] >> 31);
			yy.i[1] = (yy.i[1] << 1) | (yy.i[2] >> 31);
			yy.i[2] = (yy.i[2] << 1) | (yy.i[3] >> 31);
			yy.i[3] <<= 1;
			ey--;
		}
	} else
		hy |= 0x10000;
	exy = ex + ey - 0x3fff;

	/* convert the significands of x and y to doubles */
	c = twom16;
	dx[0] = (double) ((int) hx) * c;
	dy[0] = (double) ((int) hy) * c;

	c *= twom24;
	dx[1] = (double) ((int) (xx.i[1] >> 8)) * c;
	dy[1] = (double) ((int) (yy.i[1] >> 8)) * c;

	c *= twom24;
	dx[2] = (double) ((int) (((xx.i[1] << 16) | (xx.i[2] >> 16)) &
	    0xffffff)) * c;
	dy[2] = (double) ((int) (((yy.i[1] << 16) | (yy.i[2] >> 16)) &
	    0xffffff)) * c;

	c *= twom24;
	dx[3] = (double) ((int) (((xx.i[2] << 8) | (xx.i[3] >> 24)) &
	    0xffffff)) * c;
	dy[3] = (double) ((int) (((yy.i[2] << 8) | (yy.i[3] >> 24)) &
	    0xffffff)) * c;

	c *= twom24;
	dx[4] = (double) ((int) (xx.i[3] & 0xffffff)) * c;
	dy[4] = (double) ((int) (yy.i[3] & 0xffffff)) * c;

	/* form the "digits" of the product */
	dxy[0] = dx[0] * dy[0];
	dxy[1] = dx[0] * dy[1] + dx[1] * dy[0];
	dxy[2] = dx[0] * dy[2] + dx[1] * dy[1] + dx[2] * dy[0];
	dxy[3] = dx[0] * dy[3] + dx[1] * dy[2] + dx[2] * dy[1] +
	    dx[3] * dy[0];
	dxy[4] = dx[0] * dy[4] + dx[1] * dy[3] + dx[2] * dy[2] +
	    dx[3] * dy[1] + dx[4] * dy[0];
	dxy[5] = dx[1] * dy[4] + dx[2] * dy[3] + dx[3] * dy[2] +
	    dx[4] * dy[1];
	dxy[6] = dx[2] * dy[4] + dx[3] * dy[3] + dx[4] * dy[2];
	dxy[7] = dx[3] * dy[4] + dx[4] * dy[3];
	dxy[8] = dx[4] * dy[4];

	/* split odd-numbered terms and combine into even-numbered terms */
	c = (dxy[1] + two20) - two20;
	dxy[0] += c;
	dxy[1] -= c;
	c = (dxy[3] + twom28) - twom28;
	dxy[2] += c + dxy[1];
	dxy[3] -= c;
	c = (dxy[5] + twom76) - twom76;
	dxy[4] += c + dxy[3];
	dxy[5] -= c;
	c = (dxy[7] + twom124) - twom124;
	dxy[6] += c + dxy[5];
	dxy[8] += (dxy[7] - c);

	/* propagate carries, adjusting the exponent if need be */
	dxy[7] = dxy[6] + dxy[8];
	dxy[5] = dxy[4] + dxy[7];
	dxy[3] = dxy[2] + dxy[5];
	dxy[1] = dxy[0] + dxy[3];
	if (dxy[1] >= two) {
		dxy[0] *= half;
		dxy[1] *= half;
		dxy[2] *= half;
		dxy[3] *= half;
		dxy[4] *= half;
		dxy[5] *= half;
		dxy[6] *= half;
		dxy[7] *= half;
		dxy[8] *= half;
		exy++;
	}

	/* extract the significand of x*y */
	s = two36;
	u.d = c = dxy[1] + s;
	xy0 = u.i[1];
	c -= s;
	dxy[1] -= c;
	dxy[0] -= c;

	s *= twom32;
	u.d = c = dxy[1] + s;
	xy1 = u.i[1];
	c -= s;
	dxy[2] += (dxy[0] - c);
	dxy[3] = dxy[2] + dxy[5];

	s *= twom32;
	u.d = c = dxy[3] + s;
	xy2 = u.i[1];
	c -= s;
	dxy[4] += (dxy[2] - c);
	dxy[5] = dxy[4] + dxy[7];

	s *= twom32;
	u.d = c = dxy[5] + s;
	xy3 = u.i[1];
	c -= s;
	dxy[4] -= c;
	dxy[5] = dxy[4] + dxy[7];

	s *= twom32;
	u.d = c = dxy[5] + s;
	xy4 = u.i[1];
	c -= s;
	dxy[6] += (dxy[4] - c);
	dxy[7] = dxy[6] + dxy[8];

	s *= twom32;
	u.d = c = dxy[7] + s;
	xy5 = u.i[1];
	c -= s;
	dxy[8] += (dxy[6] - c);

	s *= twom32;
	u.d = c = dxy[8] + s;
	xy6 = u.i[1];
	c -= s;
	dxy[8] -= c;

	s *= twom32;
	u.d = c = dxy[8] + s;
	xy7 = u.i[1];

	/* extract the sign, exponent, and significand of z */
	sz = zz.i[0] & 0x80000000;
	ez = hz >> 16;
	z0 = hz & 0xffff;
	if (!ez) {
		if (z0 | (zz.i[1] & 0xfffe0000)) {
			z1 = zz.i[1];
			z2 = zz.i[2];
			z3 = zz.i[3];
			ez = 1;
		} else if (zz.i[1] | (zz.i[2] & 0xfffe0000)) {
			z0 = zz.i[1];
			z1 = zz.i[2];
			z2 = zz.i[3];
			z3 = 0;
			ez = -31;
		} else if (zz.i[2] | (zz.i[3] & 0xfffe0000)) {
			z0 = zz.i[2];
			z1 = zz.i[3];
			z2 = z3 = 0;
			ez = -63;
		} else {
			z0 = zz.i[3];
			z1 = z2 = z3 = 0;
			ez = -95;
		}
		while ((z0 & 0x10000) == 0) {
			z0 = (z0 << 1) | (z1 >> 31);
			z1 = (z1 << 1) | (z2 >> 31);
			z2 = (z2 << 1) | (z3 >> 31);
			z3 <<= 1;
			ez--;
		}
	} else {
		z0 |= 0x10000;
		z1 = zz.i[1];
		z2 = zz.i[2];
		z3 = zz.i[3];
	}
	z4 = z5 = z6 = z7 = 0;

	/*
	 * now x*y is represented by sxy, exy, and xy[0-7], and z is
	 * represented likewise; swap if need be so |xy| <= |z|
	 */
	if (exy > ez || (exy == ez && (xy0 > z0 || (xy0 == z0 && (xy1 > z1 ||
		(xy1 == z1 && (xy2 > z2 || (xy2 == z2 && (xy3 > z3 ||
		(xy3 == z3 && (xy4 | xy5 | xy6 | xy7) != 0)))))))))) {
		e = sxy; sxy = sz; sz = e;
		e = exy; exy = ez; ez = e;
		e = xy0; xy0 = z0; z0 = e;
		e = xy1; xy1 = z1; z1 = e;
		e = xy2; xy2 = z2; z2 = e;
		e = xy3; xy3 = z3; z3 = e;
		z4 = xy4; xy4 = 0;
		z5 = xy5; xy5 = 0;
		z6 = xy6; xy6 = 0;
		z7 = xy7; xy7 = 0;
	}

	/* shift the significand of xy keeping a sticky bit */
	e = ez - exy;
	if (e > 236) {
		xy0 = xy1 = xy2 = xy3 = xy4 = xy5 = xy6 = 0;
		xy7 = 1;
	} else if (e >= 224) {
		sticky = xy7 | xy6 | xy5 | xy4 | xy3 | xy2 | xy1 |
			((xy0 << 1) << (255 - e));
		xy7 = xy0 >> (e - 224);
		if (sticky)
			xy7 |= 1;
		xy0 = xy1 = xy2 = xy3 = xy4 = xy5 = xy6 = 0;
	} else if (e >= 192) {
		sticky = xy7 | xy6 | xy5 | xy4 | xy3 | xy2 |
			((xy1 << 1) << (223 - e));
		xy7 = (xy1 >> (e - 192)) | ((xy0 << 1) << (223 - e));
		if (sticky)
			xy7 |= 1;
		xy6 = xy0 >> (e - 192);
		xy0 = xy1 = xy2 = xy3 = xy4 = xy5 = 0;
	} else if (e >= 160) {
		sticky = xy7 | xy6 | xy5 | xy4 | xy3 |
			((xy2 << 1) << (191 - e));
		xy7 = (xy2 >> (e - 160)) | ((xy1 << 1) << (191 - e));
		if (sticky)
			xy7 |= 1;
		xy6 = (xy1 >> (e - 160)) | ((xy0 << 1) << (191 - e));
		xy5 = xy0 >> (e - 160);
		xy0 = xy1 = xy2 = xy3 = xy4 = 0;
	} else if (e >= 128) {
		sticky = xy7 | xy6 | xy5 | xy4 | ((xy3 << 1) << (159 - e));
		xy7 = (xy3 >> (e - 128)) | ((xy2 << 1) << (159 - e));
		if (sticky)
			xy7 |= 1;
		xy6 = (xy2 >> (e - 128)) | ((xy1 << 1) << (159 - e));
		xy5 = (xy1 >> (e - 128)) | ((xy0 << 1) << (159 - e));
		xy4 = xy0 >> (e - 128);
		xy0 = xy1 = xy2 = xy3 = 0;
	} else if (e >= 96) {
		sticky = xy7 | xy6 | xy5 | ((xy4 << 1) << (127 - e));
		xy7 = (xy4 >> (e - 96)) | ((xy3 << 1) << (127 - e));
		if (sticky)
			xy7 |= 1;
		xy6 = (xy3 >> (e - 96)) | ((xy2 << 1) << (127 - e));
		xy5 = (xy2 >> (e - 96)) | ((xy1 << 1) << (127 - e));
		xy4 = (xy1 >> (e - 96)) | ((xy0 << 1) << (127 - e));
		xy3 = xy0 >> (e - 96);
		xy0 = xy1 = xy2 = 0;
	} else if (e >= 64) {
		sticky = xy7 | xy6 | ((xy5 << 1) << (95 - e));
		xy7 = (xy5 >> (e - 64)) | ((xy4 << 1) << (95 - e));
		if (sticky)
			xy7 |= 1;
		xy6 = (xy4 >> (e - 64)) | ((xy3 << 1) << (95 - e));
		xy5 = (xy3 >> (e - 64)) | ((xy2 << 1) << (95 - e));
		xy4 = (xy2 >> (e - 64)) | ((xy1 << 1) << (95 - e));
		xy3 = (xy1 >> (e - 64)) | ((xy0 << 1) << (95 - e));
		xy2 = xy0 >> (e - 64);
		xy0 = xy1 = 0;
	} else if (e >= 32) {
		sticky = xy7 | ((xy6 << 1) << (63 - e));
		xy7 = (xy6 >> (e - 32)) | ((xy5 << 1) << (63 - e));
		if (sticky)
			xy7 |= 1;
		xy6 = (xy5 >> (e - 32)) | ((xy4 << 1) << (63 - e));
		xy5 = (xy4 >> (e - 32)) | ((xy3 << 1) << (63 - e));
		xy4 = (xy3 >> (e - 32)) | ((xy2 << 1) << (63 - e));
		xy3 = (xy2 >> (e - 32)) | ((xy1 << 1) << (63 - e));
		xy2 = (xy1 >> (e - 32)) | ((xy0 << 1) << (63 - e));
		xy1 = xy0 >> (e - 32);
		xy0 = 0;
	} else if (e) {
		sticky = (xy7 << 1) << (31 - e);
		xy7 = (xy7 >> e) | ((xy6 << 1) << (31 - e));
		if (sticky)
			xy7 |= 1;
		xy6 = (xy6 >> e) | ((xy5 << 1) << (31 - e));
		xy5 = (xy5 >> e) | ((xy4 << 1) << (31 - e));
		xy4 = (xy4 >> e) | ((xy3 << 1) << (31 - e));
		xy3 = (xy3 >> e) | ((xy2 << 1) << (31 - e));
		xy2 = (xy2 >> e) | ((xy1 << 1) << (31 - e));
		xy1 = (xy1 >> e) | ((xy0 << 1) << (31 - e));
		xy0 >>= e;
	}

	/* if this is a magnitude subtract, negate the significand of xy */
	if (sxy ^ sz) {
		xy0 = ~xy0;
		xy1 = ~xy1;
		xy2 = ~xy2;
		xy3 = ~xy3;
		xy4 = ~xy4;
		xy5 = ~xy5;
		xy6 = ~xy6;
		xy7 = -xy7;
		if (xy7 == 0)
			if (++xy6 == 0)
				if (++xy5 == 0)
					if (++xy4 == 0)
						if (++xy3 == 0)
							if (++xy2 == 0)
								if (++xy1 == 0)
									xy0++;
	}

	/* add, propagating carries */
	z7 += xy7;
	e = (z7 < xy7);
	z6 += xy6;
	if (e) {
		z6++;
		e = (z6 <= xy6);
	} else
		e = (z6 < xy6);
	z5 += xy5;
	if (e) {
		z5++;
		e = (z5 <= xy5);
	} else
		e = (z5 < xy5);
	z4 += xy4;
	if (e) {
		z4++;
		e = (z4 <= xy4);
	} else
		e = (z4 < xy4);
	z3 += xy3;
	if (e) {
		z3++;
		e = (z3 <= xy3);
	} else
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

	/* postnormalize and collect rounding information into z4 */
	if (ez < 1) {
		/* result is tiny; shift right until exponent is within range */
		e = 1 - ez;
		if (e > 116) {
			z4 = 1; /* result can't be exactly zero */
			z0 = z1 = z2 = z3 = 0;
		} else if (e >= 96) {
			sticky = z7 | z6 | z5 | z4 | z3 | z2 |
				((z1 << 1) << (127 - e));
			z4 = (z1 >> (e - 96)) | ((z0 << 1) << (127 - e));
			if (sticky)
				z4 |= 1;
			z3 = z0 >> (e - 96);
			z0 = z1 = z2 = 0;
		} else if (e >= 64) {
			sticky = z7 | z6 | z5 | z4 | z3 |
				((z2 << 1) << (95 - e));
			z4 = (z2 >> (e - 64)) | ((z1 << 1) << (95 - e));
			if (sticky)
				z4 |= 1;
			z3 = (z1 >> (e - 64)) | ((z0 << 1) << (95 - e));
			z2 = z0 >> (e - 64);
			z0 = z1 = 0;
		} else if (e >= 32) {
			sticky = z7 | z6 | z5 | z4 | ((z3 << 1) << (63 - e));
			z4 = (z3 >> (e - 32)) | ((z2 << 1) << (63 - e));
			if (sticky)
				z4 |= 1;
			z3 = (z2 >> (e - 32)) | ((z1 << 1) << (63 - e));
			z2 = (z1 >> (e - 32)) | ((z0 << 1) << (63 - e));
			z1 = z0 >> (e - 32);
			z0 = 0;
		} else {
			sticky = z7 | z6 | z5 | (z4 << 1) << (31 - e);
			z4 = (z4 >> e) | ((z3 << 1) << (31 - e));
			if (sticky)
				z4 |= 1;
			z3 = (z3 >> e) | ((z2 << 1) << (31 - e));
			z2 = (z2 >> e) | ((z1 << 1) << (31 - e));
			z1 = (z1 >> e) | ((z0 << 1) << (31 - e));
			z0 >>= e;
		}
		ez = 1;
	} else if (z0 >= 0x20000) {
		/* carry out; shift right by one */
		sticky = (z4 & 1) | z5 | z6 | z7;
		z4 = (z4 >> 1) | (z3 << 31);
		if (sticky)
			z4 |= 1;
		z3 = (z3 >> 1) | (z2 << 31);
		z2 = (z2 >> 1) | (z1 << 31);
		z1 = (z1 >> 1) | (z0 << 31);
		z0 >>= 1;
		ez++;
	} else {
		if (z0 < 0x10000 && (z0 | z1 | z2 | z3 | z4 | z5 | z6 | z7)
			!= 0) {
			/*
			 * borrow/cancellation; shift left as much as
			 * exponent allows
			 */
			while (!(z0 | (z1 & 0xfffe0000)) && ez >= 33) {
				z0 = z1;
				z1 = z2;
				z2 = z3;
				z3 = z4;
				z4 = z5;
				z5 = z6;
				z6 = z7;
				z7 = 0;
				ez -= 32;
			}
			while (z0 < 0x10000 && ez > 1) {
				z0 = (z0 << 1) | (z1 >> 31);
				z1 = (z1 << 1) | (z2 >> 31);
				z2 = (z2 << 1) | (z3 >> 31);
				z3 = (z3 << 1) | (z4 >> 31);
				z4 = (z4 << 1) | (z5 >> 31);
				z5 = (z5 << 1) | (z6 >> 31);
				z6 = (z6 << 1) | (z7 >> 31);
				z7 <<= 1;
				ez--;
			}
		}
		if (z5 | z6 | z7)
			z4 |= 1;
	}

	/* get the rounding mode */
	rm = fsr >> 30;

	/* strip off the integer bit, if there is one */
	ibit = z0 & 0x10000;
	if (ibit)
		z0 -= 0x10000;
	else {
		ez = 0;
		if (!(z0 | z1 | z2 | z3 | z4)) { /* exact zero */
			zz.i[0] = rm == FSR_RM ? 0x80000000 : 0;
			zz.i[1] = zz.i[2] = zz.i[3] = 0;
			__fenv_setfsr32(&fsr);
			return (zz.q);
		}
	}

	/*
	 * flip the sense of directed roundings if the result is negative;
	 * the logic below applies to a positive result
	 */
	if (sz)
		rm ^= rm >> 1;

	/* round and raise exceptions */
	if (z4) {
		fsr |= FSR_NXC;

		/* decide whether to round the fraction up */
		if (rm == FSR_RP || (rm == FSR_RN && (z4 > 0x80000000u ||
			(z4 == 0x80000000u && (z3 & 1))))) {
			/* round up and renormalize if necessary */
			if (++z3 == 0)
				if (++z2 == 0)
					if (++z1 == 0)
						if (++z0 == 0x10000) {
							z0 = 0;
							ez++;
						}
		}
	}

	/* check for under/overflow */
	if (ez >= 0x7fff) {
		if (rm == FSR_RN || rm == FSR_RP) {
			zz.i[0] = sz | 0x7fff0000;
			zz.i[1] = zz.i[2] = zz.i[3] = 0;
		} else {
			zz.i[0] = sz | 0x7ffeffff;
			zz.i[1] = zz.i[2] = zz.i[3] = 0xffffffff;
		}
		fsr |= FSR_OFC | FSR_NXC;
	} else {
		zz.i[0] = sz | (ez << 16) | z0;
		zz.i[1] = z1;
		zz.i[2] = z2;
		zz.i[3] = z3;

		/*
		 * !ibit => exact result was tiny before rounding,
		 * z4 nonzero => result delivered is inexact
		 */
		if (!ibit) {
			if (z4)
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
	return (zz.q);
}

#elif defined(__x86)

static const union {
	unsigned i[2];
	double d;
} C[] = {
	{ 0, 0x3fe00000u },
	{ 0, 0x40000000u },
	{ 0, 0x3df00000u },
	{ 0, 0x3bf00000u },
	{ 0, 0x41f00000u },
	{ 0, 0x43e00000u },
	{ 0, 0x7fe00000u },
	{ 0, 0x00100000u },
	{ 0, 0x00100001u }
};

#define	half	C[0].d
#define	two	C[1].d
#define	twom32	C[2].d
#define	twom64	C[3].d
#define	two32	C[4].d
#define	two63	C[5].d
#define	huge	C[6].d
#define	tiny	C[7].d
#define	tiny2	C[8].d

#if defined(__amd64)
#define	NI	4
#else
#define	NI	3
#endif

/*
 * fmal for x86: 80-bit extended double precision, little-endian
 */
long double
__fmal(long double x, long double y, long double z) {
	union {
		unsigned i[NI];
		long double e;
	} xx, yy, zz;
	long double xhi, yhi, xlo, ylo, t;
	unsigned xy0, xy1, xy2, xy3, xy4, z0, z1, z2, z3, z4;
	unsigned oldcwsw, cwsw, rm, sticky, carry;
	int ex, ey, ez, exy, sxy, sz, e, tinyafter;
	volatile double	dummy;

	/* extract the exponents of the arguments */
	xx.e = x;
	yy.e = y;
	zz.e = z;
	ex = xx.i[2] & 0x7fff;
	ey = yy.i[2] & 0x7fff;
	ez = zz.i[2] & 0x7fff;

	/* dispense with inf, nan, and zero cases */
	if (ex == 0x7fff || ey == 0x7fff || (ex | xx.i[1] | xx.i[0]) == 0 ||
		(ey | yy.i[1] | yy.i[0]) == 0)	/* x or y is inf, nan, or 0 */
		return (x * y + z);

	if (ez == 0x7fff)			/* z is inf or nan */
		return (x + z);	/* avoid spurious under/overflow in x * y */

	if ((ez | zz.i[1] | zz.i[0]) == 0)	/* z is zero */
		/*
		 * x * y isn't zero but could underflow to zero,
		 * so don't add z, lest we perturb the sign
		 */
		return (x * y);

	/*
	 * now x, y, and z are all finite and nonzero; extract signs and
	 * normalize the significands (this will raise the denormal operand
	 * exception if need be)
	 */
	sxy = (xx.i[2] ^ yy.i[2]) & 0x8000;
	sz = zz.i[2] & 0x8000;
	if (!ex) {
		xx.e = x * two63;
		ex = (xx.i[2] & 0x7fff) - 63;
	}
	if (!ey) {
		yy.e = y * two63;
		ey = (yy.i[2] & 0x7fff) - 63;
	}
	if (!ez) {
		zz.e = z * two63;
		ez = (zz.i[2] & 0x7fff) - 63;
	}

	/*
	 * save the control and status words, mask all exceptions, and
	 * set rounding to 64-bit precision and toward-zero
	 */
	__fenv_getcwsw(&oldcwsw);
	cwsw = (oldcwsw & 0xf0c0ffff) | 0x0f3f0000;
	__fenv_setcwsw(&cwsw);

	/* multiply x*y to 128 bits */
	exy = ex + ey - 0x3fff;
	xx.i[2] = 0x3fff;
	yy.i[2] = 0x3fff;
	x = xx.e;
	y = yy.e;
	xhi = ((x + twom32) + two32) - two32;
	yhi = ((y + twom32) + two32) - two32;
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
	xx.e = x;
	xy0 = xx.i[1];
	xy1 = xx.i[0];
	yy.e = t = y + twom32;
	xy2 = yy.i[0];
	yy.e = (y - (t - twom32)) + twom64;
	xy3 = yy.i[0];
	xy4 = 0;
	z0 = zz.i[1];
	z1 = zz.i[0];
	z2 = z3 = z4 = 0;

	/*
	 * now x*y is represented by sxy, exy, and xy[0-4], and z is
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
	if (e > 130) {
		xy0 = xy1 = xy2 = xy3 = 0;
		xy4 = 1;
	} else if (e >= 128) {
		sticky = xy3 | xy2 | xy1 | ((xy0 << 1) << (159 - e));
		xy4 = xy0 >> (e - 128);
		if (sticky)
			xy4 |= 1;
		xy0 = xy1 = xy2 = xy3 = 0;
	} else if (e >= 96) {
		sticky = xy3 | xy2 | ((xy1 << 1) << (127 - e));
		xy4 = (xy1 >> (e - 96)) | ((xy0 << 1) << (127 - e));
		if (sticky)
			xy4 |= 1;
		xy3 = xy0 >> (e - 96);
		xy0 = xy1 = xy2 = 0;
	} else if (e >= 64) {
		sticky = xy3 | ((xy2 << 1) << (95 - e));
		xy4 = (xy2 >> (e - 64)) | ((xy1 << 1) << (95 - e));
		if (sticky)
			xy4 |= 1;
		xy3 = (xy1 >> (e - 64)) | ((xy0 << 1) << (95 - e));
		xy2 = xy0 >> (e - 64);
		xy0 = xy1 = 0;
	} else if (e >= 32) {
		sticky = (xy3 << 1) << (63 - e);
		xy4 = (xy3 >> (e - 32)) | ((xy2 << 1) << (63 - e));
		if (sticky)
			xy4 |= 1;
		xy3 = (xy2 >> (e - 32)) | ((xy1 << 1) << (63 - e));
		xy2 = (xy1 >> (e - 32)) | ((xy0 << 1) << (63 - e));
		xy1 = xy0 >> (e - 32);
		xy0 = 0;
	} else if (e) {
		xy4 = (xy3 << 1) << (31 - e);
		xy3 = (xy3 >> e) | ((xy2 << 1) << (31 - e));
		xy2 = (xy2 >> e) | ((xy1 << 1) << (31 - e));
		xy1 = (xy1 >> e) | ((xy0 << 1) << (31 - e));
		xy0 >>= e;
	}

	/* if this is a magnitude subtract, negate the significand of xy */
	if (sxy ^ sz) {
		xy0 = ~xy0;
		xy1 = ~xy1;
		xy2 = ~xy2;
		xy3 = ~xy3;
		xy4 = -xy4;
		if (xy4 == 0)
			if (++xy3 == 0)
				if (++xy2 == 0)
					if (++xy1 == 0)
						xy0++;
	}

	/* add, propagating carries */
	z4 += xy4;
	carry = (z4 < xy4);
	z3 += xy3;
	if (carry) {
		z3++;
		carry = (z3 <= xy3);
	} else
		carry = (z3 < xy3);
	z2 += xy2;
	if (carry) {
		z2++;
		carry = (z2 <= xy2);
	} else
		carry = (z2 < xy2);
	z1 += xy1;
	if (carry) {
		z1++;
		carry = (z1 <= xy1);
	} else
		carry = (z1 < xy1);
	z0 += xy0;
	if (carry) {
		z0++;
		carry = (z0 <= xy0);
	} else
		carry = (z0 < xy0);

	/* for a magnitude subtract, ignore the last carry out */
	if (sxy ^ sz)
		carry = 0;

	/* postnormalize and collect rounding information into z2 */
	if (ez < 1) {
		/* result is tiny; shift right until exponent is within range */
		e = 1 - ez;
		if (e > 67) {
			z2 = 1;	/* result can't be exactly zero */
			z0 = z1 = 0;
		} else if (e >= 64) {
			sticky = z4 | z3 | z2 | z1 | ((z0 << 1) << (95 - e));
			z2 = (z0 >> (e - 64)) | ((carry << 1) << (95 - e));
			if (sticky)
				z2 |= 1;
			z1 = carry >> (e - 64);
			z0 = 0;
		} else if (e >= 32) {
			sticky = z4 | z3 | z2 | ((z1 << 1) << (63 - e));
			z2 = (z1 >> (e - 32)) | ((z0 << 1) << (63 - e));
			if (sticky)
				z2 |= 1;
			z1 = (z0 >> (e - 32)) | ((carry << 1) << (63 - e));
			z0 = carry >> (e - 32);
		} else {
			sticky = z4 | z3 | (z2 << 1) << (31 - e);
			z2 = (z2 >> e) | ((z1 << 1) << (31 - e));
			if (sticky)
				z2 |= 1;
			z1 = (z1 >> e) | ((z0 << 1) << (31 - e));
			z0 = (z0 >> e) | ((carry << 1) << (31 - e));
		}
		ez = 1;
	} else if (carry) {
		/* carry out; shift right by one */
		sticky = (z2 & 1) | z3 | z4;
		z2 = (z2 >> 1) | (z1 << 31);
		if (sticky)
			z2 |= 1;
		z1 = (z1 >> 1) | (z0 << 31);
		z0 = (z0 >> 1) | 0x80000000;
		ez++;
	} else {
		if (z0 < 0x80000000u && (z0 | z1 | z2 | z3 | z4) != 0) {
			/*
			 * borrow/cancellation; shift left as much as
			 * exponent allows
			 */
			while (!z0 && ez >= 33) {
				z0 = z1;
				z1 = z2;
				z2 = z3;
				z3 = z4;
				z4 = 0;
				ez -= 32;
			}
			while (z0 < 0x80000000u && ez > 1) {
				z0 = (z0 << 1) | (z1 >> 31);
				z1 = (z1 << 1) | (z2 >> 31);
				z2 = (z2 << 1) | (z3 >> 31);
				z3 = (z3 << 1) | (z4 >> 31);
				z4 <<= 1;
				ez--;
			}
		}
		if (z3 | z4)
			z2 |= 1;
	}

	/* get the rounding mode */
	rm = oldcwsw & 0x0c000000;

	/* adjust exponent if result is subnormal */
	tinyafter = 0;
	if (!(z0 & 0x80000000)) {
		ez = 0;
		tinyafter = 1;
		if (!(z0 | z1 | z2)) { /* exact zero */
			zz.i[2] = rm == FCW_RM ? 0x8000 : 0;
			zz.i[1] = zz.i[0] = 0;
			__fenv_setcwsw(&oldcwsw);
			return (zz.e);
		}
	}

	/*
	 * flip the sense of directed roundings if the result is negative;
	 * the logic below applies to a positive result
	 */
	if (sz && (rm == FCW_RM || rm == FCW_RP))
		rm = (FCW_RM + FCW_RP) - rm;

	/* round */
	if (z2) {
		if (rm == FCW_RP || (rm == FCW_RN && (z2 > 0x80000000u ||
			(z2 == 0x80000000u && (z1 & 1))))) {
			/* round up and renormalize if necessary */
			if (++z1 == 0) {
				if (++z0 == 0) {
					z0 = 0x80000000;
					ez++;
				} else if (z0 == 0x80000000) {
					/* rounded up to smallest normal */
					ez = 1;
					if ((rm == FCW_RP && z2 >
						0x80000000u) || (rm == FCW_RN &&
						z2 >= 0xc0000000u))
						/*
						 * would have rounded up to
						 * smallest normal even with
						 * unbounded range
						 */
						tinyafter = 0;
				}
			}
		}
	}

	/* restore the control and status words, check for over/underflow */
	__fenv_setcwsw(&oldcwsw);
	if (ez >= 0x7fff) {
		if (rm == FCW_RN || rm == FCW_RP) {
			zz.i[2] = sz | 0x7fff;
			zz.i[1] = 0x80000000;
			zz.i[0] = 0;
		} else {
			zz.i[2] = sz | 0x7ffe;
			zz.i[1] = 0xffffffff;
			zz.i[0] = 0xffffffff;
		}
		dummy = huge;
		dummy *= huge;
	} else {
		zz.i[2] = sz | ez;
		zz.i[1] = z0;
		zz.i[0] = z1;

		/*
		 * tinyafter => result rounded w/ unbounded range would be tiny,
		 * z2 nonzero => result delivered is inexact
		 */
		if (tinyafter) {
			dummy = tiny;
			if (z2)
				dummy *= tiny;
			else
				dummy -= tiny2;
		} else if (z2) {
			dummy = huge;
			dummy += tiny;
		}
	}

	return (zz.e);
}

#else
#error Unknown architecture
#endif
