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

#pragma weak __remquo = remquo

/* INDENT OFF */
/*
 * double remquo(double x, double y, int *quo) return remainder(x,y) and an
 * integer pointer quo such that *quo = N mod {2**31}, where N is the
 * exact integral part of x/y rounded to nearest even.
 *
 * remquo call internal fmodquo
 */
/* INDENT ON */

#include "libm.h"
#include "libm_protos.h"
#include <math.h>		/* fabs() */
#include <sys/isa_defs.h>

#if defined(_BIG_ENDIAN)
#define	HIWORD	0
#define	LOWORD	1
#else
#define	HIWORD	1
#define	LOWORD	0
#endif
#define	__HI(x)	((int *) &x)[HIWORD]
#define	__LO(x)	((int *) &x)[LOWORD]

static const double one = 1.0, Zero[] = {0.0, -0.0};

static double
fmodquo(double x, double y, int *quo) {
	int n, hx, hy, hz, ix, iy, sx, sq, i, m;
	unsigned lx, ly, lz;

	hx = __HI(x);		/* high word of x */
	lx = __LO(x);		/* low  word of x */
	hy = __HI(y);		/* high word of y */
	ly = __LO(y);		/* low  word of y */
	sx = hx & 0x80000000;	/* sign of x */
	sq = (hx ^ hy) & 0x80000000;	/* sign of x/y */
	hx ^= sx;		/* |x| */
	hy &= 0x7fffffff;	/* |y| */

	/* purge off exception values */
	*quo = 0;
	if ((hy | ly) == 0 || hx >= 0x7ff00000 ||	/* y=0, or x !finite */
	    (hy | ((ly | -ly) >> 31)) > 0x7ff00000)	/* or y is NaN */
		return ((x * y) / (x * y));
	if (hx <= hy) {
		if (hx < hy || lx < ly)
			return (x);	/* |x|<|y| return x */
		if (lx == ly) {
			*quo = 1 + (sq >> 30);
			/* |x|=|y| return x*0 */
			return (Zero[(unsigned) sx >> 31]);
		}
	}

	/* determine ix = ilogb(x) */
	if (hx < 0x00100000) {	/* subnormal x */
		if (hx == 0) {
			for (ix = -1043, i = lx; i > 0; i <<= 1)
				ix -= 1;
		} else {
			for (ix = -1022, i = (hx << 11); i > 0; i <<= 1)
				ix -= 1;
		}
	} else
		ix = (hx >> 20) - 1023;

	/* determine iy = ilogb(y) */
	if (hy < 0x00100000) {	/* subnormal y */
		if (hy == 0) {
			for (iy = -1043, i = ly; i > 0; i <<= 1)
				iy -= 1;
		} else {
			for (iy = -1022, i = (hy << 11); i > 0; i <<= 1)
				iy -= 1;
		}
	} else
		iy = (hy >> 20) - 1023;

	/* set up {hx,lx}, {hy,ly} and align y to x */
	if (ix >= -1022)
		hx = 0x00100000 | (0x000fffff & hx);
	else {			/* subnormal x, shift x to normal */
		n = -1022 - ix;
		if (n <= 31) {
			hx = (hx << n) | (lx >> (32 - n));
			lx <<= n;
		} else {
			hx = lx << (n - 32);
			lx = 0;
		}
	}
	if (iy >= -1022)
		hy = 0x00100000 | (0x000fffff & hy);
	else {			/* subnormal y, shift y to normal */
		n = -1022 - iy;
		if (n <= 31) {
			hy = (hy << n) | (ly >> (32 - n));
			ly <<= n;
		} else {
			hy = ly << (n - 32);
			ly = 0;
		}
	}

	/* fix point fmod */
	n = ix - iy;
	m = 0;
	while (n--) {
		hz = hx - hy;
		lz = lx - ly;
		if (lx < ly)
			hz -= 1;
		if (hz < 0) {
			hx = hx + hx + (lx >> 31);
			lx = lx + lx;
		} else {
			m += 1;
			if ((hz | lz) == 0) {	/* return sign(x)*0 */
				if (n < 31)
					m <<= 1 + n;
				else
					m = 0;
				m &= 0x7fffffff;
				*quo = sq >= 0 ? m : -m;
				return (Zero[(unsigned) sx >> 31]);
			}
			hx = hz + hz + (lz >> 31);
			lx = lz + lz;
		}
		m += m;
	}
	hz = hx - hy;
	lz = lx - ly;
	if (lx < ly)
		hz -= 1;
	if (hz >= 0) {
		hx = hz;
		lx = lz;
		m += 1;
	}
	m &= 0x7fffffff;
	*quo = sq >= 0 ? m : -m;

	/* convert back to floating value and restore the sign */
	if ((hx | lx) == 0) {	/* return sign(x)*0 */
		return (Zero[(unsigned) sx >> 31]);
	}
	while (hx < 0x00100000) {	/* normalize x */
		hx = hx + hx + (lx >> 31);
		lx = lx + lx;
		iy -= 1;
	}
	if (iy >= -1022) {	/* normalize output */
		hx = (hx - 0x00100000) | ((iy + 1023) << 20);
		__HI(x) = hx | sx;
		__LO(x) = lx;
	} else {			/* subnormal output */
		n = -1022 - iy;
		if (n <= 20) {
			lx = (lx >> n) | ((unsigned) hx << (32 - n));
			hx >>= n;
		} else if (n <= 31) {
			lx = (hx << (32 - n)) | (lx >> n);
			hx = sx;
		} else {
			lx = hx >> (n - 32);
			hx = sx;
		}
		__HI(x) = hx | sx;
		__LO(x) = lx;
		x *= one;	/* create necessary signal */
	}
	return (x);		/* exact output */
}

#define	zero	Zero[0]

double
remquo(double x, double y, int *quo) {
	int hx, hy, sx, sq;
	double v;
	unsigned ly;

	hx = __HI(x);		/* high word of x */
	hy = __HI(y);		/* high word of y */
	ly = __LO(y);		/* low  word of y */
	sx = hx & 0x80000000;	/* sign of x */
	sq = (hx ^ hy) & 0x80000000;	/* sign of x/y */
	hx ^= sx;		/* |x| */
	hy &= 0x7fffffff;	/* |y| */

	/* purge off exception values */
	*quo = 0;
	if ((hy | ly) == 0 || hx >= 0x7ff00000 ||	/* y=0, or x !finite */
	    (hy | ((ly | -ly) >> 31)) > 0x7ff00000)	/* or y is NaN */
		return ((x * y) / (x * y));

	y = fabs(y);
	x = fabs(x);
	if (hy <= 0x7fdfffff) {
		x = fmodquo(x, y + y, quo);
		*quo = ((*quo) & 0x3fffffff) << 1;
	}
	if (hy < 0x00200000) {
		if (x + x > y) {
			*quo += 1;
			if (x == y)
				x = zero;
			else
				x -= y;
			if (x + x >= y) {
				x -= y;
				*quo += 1;
			}
		}
	} else {
		v = 0.5 * y;
		if (x > v) {
			*quo += 1;
			if (x == y)
				x = zero;
			else
				x -= y;
			if (x >= v) {
				x -= y;
				*quo += 1;
			}
		}
	}
	if (sq != 0)
		*quo = -(*quo);
	return (sx == 0 ? x : -x);
}
