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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * int __rem_pio2m(x,y,e0,nx,prec,ipio2)
 * double x[],y[]; int e0,nx,prec; const int ipio2[];
 *
 * __rem_pio2m return the last three digits of N with
 *		y = x - N*pi/2
 * so that |y| < pi/4.
 *
 * The method is to compute the integer (mod 8) and fraction parts of
 * (2/pi)*x without doing the full multiplication. In general we
 * skip the part of the product that are known to be a huge integer (
 * more accurately, = 0 mod 8 ). Thus the number of operations are
 * independent of the exponent of the input.
 *
 * (2/PI) is represented by an array of 24-bit integers in ipio2[].
 * Here PI could as well be a machine value pi.
 *
 * Input parameters:
 * 	x[]	The input value (must be positive) is broken into nx
 *		pieces of 24-bit integers in double precision format.
 *		x[i] will be the i-th 24 bit of x. The scaled exponent
 *		of x[0] is given in input parameter e0 (i.e., x[0]*2^e0
 *		match x's up to 24 bits.
 *
 *		Example of breaking a double z into x[0]+x[1]+x[2]:
 *			e0 = ilogb(z)-23
 *			z  = scalbn(z,-e0)
 *		for i = 0,1,2
 *			x[i] =  floor(z)
 *			z    = (z-x[i])*2**24
 *
 *
 *	y[]	ouput result in an array of double precision numbers.
 *		The dimension of y[] is:
 *			24-bit  precision	1
 *			53-bit  precision	2
 *			64-bit  precision	2
 *			113-bit precision	3
 *		The actual value is the sum of them. Thus for 113-bit
 *		precsion, one may have to do something like:
 *
 *		long double t,w,r_head, r_tail;
 *		t = (long double)y[2] + (long double)y[1];
 *		w = (long double)y[0];
 *		r_head = t+w;
 *		r_tail = w - (r_head - t);
 *
 *	e0	The exponent of x[0]
 *
 *	nx	dimension of x[]
 *
 *  	prec	an interger indicating the precision:
 *			0	24  bits (single)
 *			1	53  bits (double)
 *			2	64  bits (extended)
 *			3	113 bits (quad)
 *
 *	ipio2[]
 *		integer array, contains the (24*i)-th to (24*i+23)-th
 *		bit of 2/pi or 2/PI after binary point. The corresponding
 *		floating value is
 *
 *			ipio2[i] * 2^(-24(i+1)).
 *
 * External function:
 *	double scalbn( ), floor( );
 *
 *
 * Here is the description of some local variables:
 *
 * 	jk	jk+1 is the initial number of terms of ipio2[] needed
 *		in the computation. The recommended value is 3,4,4,
 *		6 for single, double, extended,and quad.
 *
 * 	jz	local integer variable indicating the number of
 *		terms of ipio2[] used.
 *
 *	jx	nx - 1
 *
 *	jv	index for pointing to the suitable ipio2[] for the
 *		computation. In general, we want
 *			( 2^e0*x[0] * ipio2[jv-1]*2^(-24jv) )/8
 *		is an integer. Thus
 *			e0-3-24*jv >= 0 or (e0-3)/24 >= jv
 *		Hence jv = max(0,(e0-3)/24).
 *
 *	jp	jp+1 is the number of terms in pio2[] needed, jp = jk.
 *
 * 	q[]	double array with integral value, representing the
 *		24-bits chunk of the product of x and 2/pi.
 *
 *	q0	the corresponding exponent of q[0]. Note that the
 *		exponent for q[i] would be q0-24*i.
 *
 *	pio2[]	double precision array, obtained by cutting pi/2
 *		into 24 bits chunks.
 *
 *	f[]	ipio2[] in floating point
 *
 *	iq[]	integer array by breaking up q[] in 24-bits chunk.
 *
 *	fq[]	final product of x*(2/pi) in fq[0],..,fq[jk]
 *
 *	ih	integer. If >0 it indicats q[] is >= 0.5, hence
 *		it also indicates the *sign* of the result.
 *
 */

#include "libm.h"

#if defined(__i386) && !defined(__amd64)
extern int __swapRP(int);
#endif

static const int init_jk[] = { 3, 4, 4, 6 }; /* initial value for jk */

static const double pio2[] = {
	1.57079625129699707031e+00,
	7.54978941586159635335e-08,
	5.39030252995776476554e-15,
	3.28200341580791294123e-22,
	1.27065575308067607349e-29,
	1.22933308981111328932e-36,
	2.73370053816464559624e-44,
	2.16741683877804819444e-51,
};

static const double
	zero	= 0.0,
	one	= 1.0,
	half	= 0.5,
	eight	= 8.0,
	eighth	= 0.125,
	two24	= 16777216.0,
	twon24	= 5.960464477539062500E-8;

int
__rem_pio2m(double *x, double *y, int e0, int nx, int prec, const int *ipio2)
{
	int	jz, jx, jv, jp, jk, carry, n, iq[20];
	int	i, j, k, m, q0, ih;
	double	z, fw, f[20], fq[20], q[20];
#if defined(__i386) && !defined(__amd64)
	int	rp;

	rp = __swapRP(fp_extended);
#endif

	/* initialize jk */
	jp = jk = init_jk[prec];

	/* determine jx,jv,q0, note that 3>q0 */
	jx = nx - 1;
	jv = (e0 - 3) / 24;
	if (jv < 0)
		jv = 0;
	q0 = e0 - 24 * (jv + 1);

	/* set up f[0] to f[jx+jk] where f[jx+jk] = ipio2[jv+jk] */
	j = jv - jx;
	m = jx + jk;
	for (i = 0; i <= m; i++, j++)
		f[i] = (j < 0)? zero : (double)ipio2[j];

	/* compute q[0],q[1],...q[jk] */
	for (i = 0; i <= jk; i++) {
		for (j = 0, fw = zero; j <= jx; j++)
			fw += x[j] * f[jx+i-j];
		q[i] = fw;
	}

	jz = jk;
recompute:
	/* distill q[] into iq[] reversingly */
	for (i = 0, j = jz, z = q[jz]; j > 0; i++, j--) {
		fw = (double)((int)(twon24 * z));
		iq[i] = (int)(z - two24 * fw);
		z = q[j-1] + fw;
	}

	/* compute n */
	z = scalbn(z, q0);		/* actual value of z */
	z -= eight * floor(z * eighth);	/* trim off integer >= 8 */
	n = (int)z;
	z -= (double)n;
	ih = 0;
	if (q0 > 0) {			/* need iq[jz-1] to determine n */
		i = (iq[jz-1] >> (24 - q0));
		n += i;
		iq[jz-1] -= i << (24 - q0);
		ih = iq[jz-1] >> (23 - q0);
	} else if (q0 == 0) {
		ih = iq[jz-1] >> 23;
	} else if (z >= half) {
		ih = 2;
	}

	if (ih > 0) {	/* q > 0.5 */
		n += 1;
		carry = 0;
		for (i = 0; i < jz; i++) {	/* compute 1-q */
			j = iq[i];
			if (carry == 0) {
				if (j != 0) {
					carry = 1;
					iq[i] = 0x1000000 - j;
				}
			} else {
				iq[i] = 0xffffff - j;
			}
		}
		if (q0 > 0) {		/* rare case: chance is 1 in 12 */
			switch (q0) {
			case 1:
				iq[jz-1] &= 0x7fffff;
				break;
			case 2:
				iq[jz-1] &= 0x3fffff;
				break;
			}
		}
		if (ih == 2) {
			z = one - z;
			if (carry != 0)
				z -= scalbn(one, q0);
		}
	}

	/* check if recomputation is needed */
	if (z == zero) {
		j = 0;
		for (i = jz - 1; i >= jk; i--)
			j |= iq[i];
		if (j == 0) {	/* need recomputation */
			/* set k to no. of terms needed */
			for (k = 1; iq[jk-k] == 0; k++)
				;

			/* add q[jz+1] to q[jz+k] */
			for (i = jz + 1; i <= jz + k; i++) {
				f[jx+i] = (double)ipio2[jv+i];
				for (j = 0, fw = zero; j <= jx; j++)
					fw += x[j] * f[jx+i-j];
				q[i] = fw;
			}
			jz += k;
			goto recompute;
		}
	}

	/* cut out zero terms */
	if (z == zero) {
		jz -= 1;
		q0 -= 24;
		while (iq[jz] == 0) {
			jz--;
			q0 -= 24;
		}
	} else {		/* break z into 24-bit if neccessary */
		z = scalbn(z, -q0);
		if (z >= two24) {
			fw = (double)((int)(twon24 * z));
			iq[jz] = (int)(z - two24 * fw);
			jz += 1;
			q0 += 24;
			iq[jz] = (int)fw;
		} else {
			iq[jz] = (int)z;
		}
	}

	/* convert integer "bit" chunk to floating-point value */
	fw = scalbn(one, q0);
	for (i = jz; i >= 0; i--) {
		q[i] = fw * (double)iq[i];
		fw *= twon24;
	}

	/* compute pio2[0,...,jp]*q[jz,...,0] */
	for (i = jz; i >= 0; i--) {
		for (fw = zero, k = 0; k <= jp && k <= jz - i; k++)
			fw += pio2[k] * q[i+k];
		fq[jz-i] = fw;
	}

	/* compress fq[] into y[] */
	switch (prec) {
	case 0:
		fw = zero;
		for (i = jz; i >= 0; i--)
			fw += fq[i];
		y[0] = (ih == 0)? fw : -fw;
		break;

	case 1:
	case 2:
		fw = zero;
		for (i = jz; i >= 0; i--)
			fw += fq[i];
		y[0] = (ih == 0)? fw : -fw;
		fw = fq[0] - fw;
		for (i = 1; i <= jz; i++)
			fw += fq[i];
		y[1] = (ih == 0)? fw : -fw;
		break;

	default:
		for (i = jz; i > 0; i--) {
			fw = fq[i-1] + fq[i];
			fq[i] += fq[i-1] - fw;
			fq[i-1] = fw;
		}
		for (i = jz; i > 1; i--) {
			fw = fq[i-1] + fq[i];
			fq[i] += fq[i-1] - fw;
			fq[i-1] = fw;
		}
		for (fw = zero, i = jz; i >= 2; i--)
			fw += fq[i];
		if (ih == 0) {
			y[0] = fq[0];
			y[1] = fq[1];
			y[2] = fw;
		} else {
			y[0] = -fq[0];
			y[1] = -fq[1];
			y[2] = -fw;
		}
	}

#if defined(__i386) && !defined(__amd64)
	(void) __swapRP(rp);
#endif
	return (n & 7);
}
