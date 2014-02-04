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

/*
 * Given X, __vlibm_rem_pio2m finds Y and an integer n such that
 * Y = X - n*pi/2 and |Y| < pi/2.
 *
 * On entry, X is represented by x, an array of nx 24-bit integers
 * stored in double precision format, and e:
 *
 *   X = sum (x[i] * 2^(e - 24*i))
 *
 * nx must be 1, 2, or 3, and e must be >= -24.  For example, a
 * suitable representation for the double precision number z can
 * be computed as follows:
 *
 *	e  = ilogb(z)-23
 *	z  = scalbn(z,-e)
 *	for i = 0,1,2
 *		x[i] = floor(z)
 *		z    = (z-x[i])*2**24
 *
 * On exit, Y is approximated by y[0] if prec is 0 and by the un-
 * evaluated sum y[0] + y[1] if prec != 0.  The approximation is
 * accurate to 53 bits in the former case and to at least 72 bits
 * in the latter.
 *
 * __vlibm_rem_pio2m returns n mod 8.
 *
 * Notes:
 *
 * As n is the integer nearest X * 2/pi, we approximate the latter
 * product to a precision that is determined dynamically so as to
 * ensure that the final value Y is approximated accurately enough.
 * We don't bother to compute terms in the product that are multiples
 * of 8, so the cost of this multiplication is independent of the
 * magnitude of X.  The variable ip determines the offset into the
 * array ipio2 of the first term we need to use.  The variable eq0
 * is the corresponding exponent of the first partial product.
 *
 * The partial products are scaled, summed, and split into an array
 * of non-overlapping 24-bit terms (not necessarily having the same
 * signs).  Each partial product overlaps three elements of the
 * resulting array:
 *
 *	q[i]   xxxxxxxxxxxxxx
 *	q[i+1]       xxxxxxxxxxxxxx
 *	q[i+2]             xxxxxxxxxxxxxx
 *	...                      ...
 *
 *
 *	r[i]     xxxxxx
 *      r[i+1]         xxxxxx
 *      r[i+2]               xxxxxx
 *	...                        ...
 *
 * In order that the last element of the r array have some correct
 * bits, we compute an extra term in the q array, but we don't bother
 * to split this last term into 24-bit chunks; thus, the final term
 * of the r array could have more than 24 bits, but this doesn't
 * matter.
 *
 * After we subtract the nearest integer to the product, we multiply
 * the remaining part of r by pi/2 to obtain Y.  Before we compute
 * this last product, however, we make sure that the remaining part
 * of r has at least five nonzero terms, computing more if need be.
 * This ensures that even if the first nonzero term is only a single
 * bit and the last term is wrong in several trailing bits, we still
 * have enough accuracy to obtain 72 bits of Y.
 *
 * IMPORTANT: This code assumes that the rounding mode is round-to-
 * nearest in several key places.  First, after we compute X * 2/pi,
 * we round to the nearest integer by adding and subtracting a power
 * of two.  This step must be done in round-to-nearest mode to ensure
 * that the remainder is less than 1/2 in absolute value.  (Because
 * we only take two adjacent terms of r into account when we perform
 * this rounding, in very rare cases the remainder could be just
 * barely greater than 1/2, but this shouldn't matter in practice.)
 *
 * Second, we also split the partial products of X * 2/pi into 24-bit
 * pieces by adding and subtracting a power of two.  In this step,
 * round-to-nearest mode is important in order to guarantee that
 * the index of the first nonzero term in the remainder gives an
 * accurate indication of the number of significant terms.  For
 * example, suppose eq0 = -1, so that r[1] is a multiple of 1/2 and
 * |r[2]| < 1/2.  After we subtract the nearest integer, r[1] could
 * be -1/2, and r[2] could be very nearly 1/2, so that r[1] != 0,
 * yet the remainder is much smaller than the least significant bit
 * corresponding to r[1].  As long as we use round-to-nearest mode,
 * this can't happen; instead, the absolute value of each r[j] will
 * be less than 1/2 the least significant bit corresponding to r[j-1],
 * so that the entire remainder must be at least half as large as
 * the first nonzero term (or perhaps just barely smaller than this).
 */

#include <sys/isa_defs.h>

#ifdef _LITTLE_ENDIAN
#define HIWORD	1
#define LOWORD	0
#else
#define HIWORD	0
#define LOWORD	1
#endif

/* 396 hex digits of 2/pi, with two leading zeroes to make life easier */
static const double ipio2[] = {
	0, 0,
	0xA2F983, 0x6E4E44, 0x1529FC, 0x2757D1, 0xF534DD, 0xC0DB62,
	0x95993C, 0x439041, 0xFE5163, 0xABDEBB, 0xC561B7, 0x246E3A,
	0x424DD2, 0xE00649, 0x2EEA09, 0xD1921C, 0xFE1DEB, 0x1CB129,
	0xA73EE8, 0x8235F5, 0x2EBB44, 0x84E99C, 0x7026B4, 0x5F7E41,
	0x3991D6, 0x398353, 0x39F49C, 0x845F8B, 0xBDF928, 0x3B1FF8,
	0x97FFDE, 0x05980F, 0xEF2F11, 0x8B5A0A, 0x6D1F6D, 0x367ECF,
	0x27CB09, 0xB74F46, 0x3F669E, 0x5FEA2D, 0x7527BA, 0xC7EBE5,
	0xF17B3D, 0x0739F7, 0x8A5292, 0xEA6BFB, 0x5FB11F, 0x8D5D08,
	0x560330, 0x46FC7B, 0x6BABF0, 0xCFBC20, 0x9AF436, 0x1DA9E3,
	0x91615E, 0xE61B08, 0x659985, 0x5F14A0, 0x68408D, 0xFFD880,
	0x4D7327, 0x310606, 0x1556CA, 0x73A8C9, 0x60E27B, 0xC08C6B,
};

/* pi/2 in 24-bit pieces */
static const double pio2[] = {
	1.57079625129699707031e+00,
	7.54978941586159635335e-08,
	5.39030252995776476554e-15,
	3.28200341580791294123e-22,
	1.27065575308067607349e-29,
};

/* miscellaneous constants */
static const double
	zero	= 0.0,
	two24	= 16777216.0,
	round1	= 6755399441055744.0,	/* 3 * 2^51 */
	round24	= 113336795588871485128704.0, /* 3 * 2^75 */
	twon24	= 5.960464477539062500E-8;

int
__vlibm_rem_pio2m(double *x, double *y, int e, int nx, int prec)
{
	union {
		double	d;
		int	i[2];
	} s;
	double	z, t, p, q[20], r[21], *pr;
	int	nq, ip, n, i, j, k, eq0, eqnqm1;

	/* determine ip and eq0; note that -48 <= eq0 <= 2 */
	ip = (e - 3) / 24;
	if (ip < 0)
		ip = 0;
	eq0 = e - 24 * (ip + 1);

	/* compute q[0,...,5] = x * ipio2 and initialize nq and eqnqm1 */
	if (nx == 3) {
		q[0] = x[0] * ipio2[ip+2] + x[1] * ipio2[ip+1] + x[2] * ipio2[ip];
		q[1] = x[0] * ipio2[ip+3] + x[1] * ipio2[ip+2] + x[2] * ipio2[ip+1];
		q[2] = x[0] * ipio2[ip+4] + x[1] * ipio2[ip+3] + x[2] * ipio2[ip+2];
		q[3] = x[0] * ipio2[ip+5] + x[1] * ipio2[ip+4] + x[2] * ipio2[ip+3];
		q[4] = x[0] * ipio2[ip+6] + x[1] * ipio2[ip+5] + x[2] * ipio2[ip+4];
		q[5] = x[0] * ipio2[ip+7] + x[1] * ipio2[ip+6] + x[2] * ipio2[ip+5];
	} else if (nx == 2) {
		q[0] = x[0] * ipio2[ip+2] + x[1] * ipio2[ip+1];
		q[1] = x[0] * ipio2[ip+3] + x[1] * ipio2[ip+2];
		q[2] = x[0] * ipio2[ip+4] + x[1] * ipio2[ip+3];
		q[3] = x[0] * ipio2[ip+5] + x[1] * ipio2[ip+4];
		q[4] = x[0] * ipio2[ip+6] + x[1] * ipio2[ip+5];
		q[5] = x[0] * ipio2[ip+7] + x[1] * ipio2[ip+6];
	} else {
		q[0] = x[0] * ipio2[ip+2];
		q[1] = x[0] * ipio2[ip+3];
		q[2] = x[0] * ipio2[ip+4];
		q[3] = x[0] * ipio2[ip+5];
		q[4] = x[0] * ipio2[ip+6];
		q[5] = x[0] * ipio2[ip+7];
	}
	nq = 5;
	eqnqm1 = eq0 - 96;

recompute:
	/* propagate carries and incorporate powers of two */
	s.i[HIWORD] = (0x3ff + eqnqm1) << 20;
	s.i[LOWORD] = 0;
	p = s.d;
	z = q[nq] * twon24;
	for (j = nq-1; j >= 1; j--) {
		z += q[j];
		t = (z + round24) - round24; /* must be rounded to nearest */
		r[j+1] = (z - t) * p;
		z = t * twon24;
		p *= two24;
	}
	z += q[0];
	t = (z + round24) - round24; /* must be rounded to nearest */
	r[1] = (z - t) * p;
	r[0] = t * p;

	/* form n = [r] mod 8 and leave the fractional part of r */
	if (eq0 > 0) {
		/* binary point lies within r[2] */
		z = r[2] + r[3];
		t = (z + round1) - round1; /* must be rounded to nearest */
		r[2] -= t;
		n = (int)(r[1] + t);
		r[0] = r[1] = zero;
	} else if (eq0 > -24) {
		/* binary point lies within or just to the right of r[1] */
		z = r[1] + r[2];
		t = (z + round1) - round1; /* must be rounded to nearest */
		r[1] -= t;
		z = r[0] + t;
		/* cut off high part of z so conversion to int doesn't
		   overflow */
		t = (z + round24) - round24;
		n = (int)(z - t);
		r[0] = zero;
	} else {
		/* binary point lies within or just to the right of r[0] */
		z = r[0] + r[1];
		t = (z + round1) - round1; /* must be rounded to nearest */
		r[0] -= t;
		n = (int)t;
	}

	/* count the number of leading zeroes in r */
	for (j = 0; j <= nq; j++) {
		if (r[j] != zero)
			break;
	}

	/* if fewer than 5 terms remain, add more */
	if (nq - j < 4) {
		k = 4 - (nq - j);
		/*
		 * compute q[nq+1] to q[nq+k]
		 *
		 * For some reason, writing out the nx loop explicitly
		 * for each of the three possible values (as above) seems
		 * to run a little slower, so we'll leave this code as is.
		 */
		for (i = nq + 1; i <= nq + k; i++) {
			t = x[0] * ipio2[ip+2+i];
			for (j = 1; j < nx; j++)
				t += x[j] * ipio2[ip+2+i-j];
			q[i] = t;
			eqnqm1 -= 24;
		}
		nq += k;
		goto recompute;
	}

	/* set pr and nq so that pr[0,...,nq] is the part of r remaining */
	pr = &r[j];
	nq = nq - j;

	/* compute pio2 * pr[0,...,nq]; note that nq >= 4 here */
	q[0] = pio2[0] * pr[0];
	q[1] = pio2[0] * pr[1] + pio2[1] * pr[0];
	q[2] = pio2[0] * pr[2] + pio2[1] * pr[1] + pio2[2] * pr[0];
	q[3] = pio2[0] * pr[3] + pio2[1] * pr[2] + pio2[2] * pr[1]
	    + pio2[3] * pr[0];
	for (i = 4; i <= nq; i++) {
		q[i] = pio2[0] * pr[i] + pio2[1] * pr[i-1] + pio2[2] * pr[i-2]
		    + pio2[3] * pr[i-3] + pio2[4] * pr[i-4];
	}

	/* sum q in increasing order to obtain the first term of y */
	t = q[nq];
	for (i = nq - 1; i >= 0; i--)
		t += q[i];
	y[0] = t;
	if (prec) {
		/* subtract and sum again in decreasing order
		   to obtain the second term */
		t = q[0] - t;
		for (i = 1; i <= nq; i++)
			t += q[i];
		y[1] = t;
	}

	return (n & 7);
}
