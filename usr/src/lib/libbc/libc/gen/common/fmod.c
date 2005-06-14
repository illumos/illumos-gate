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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

/* Special version adapted from libm for use in libc. */

#ifdef i386
static          n0 = 1, n1 = 0;
#else
static          n0 = 0, n1 = 1;
#endif

static double   two52 = 4.503599627370496000E+15;
static double   twom52 = 2.220446049250313081E-16;

static double 
setexception(n, x)
	int             n;
	double          x;
{
}

double 
copysign(x, y)
	double          x, y;
{
	long           *px = (long *) &x;
	long           *py = (long *) &y;
	px[n0] = (px[n0] & 0x7fffffff) | (py[n0] & 0x80000000);
	return x;
}

static double 
fabs(x)
	double          x;
{
	long           *px = (long *) &x;
#ifdef i386
	px[1] &= 0x7fffffff;
#else
	px[0] &= 0x7fffffff;
#endif
	return x;
}

static int 
finite(x)
	double          x;
{
	long           *px = (long *) &x;
	return ((px[n0] & 0x7ff00000) != 0x7ff00000);
}

static int 
ilogb(x)
	double          x;
{
	long           *px = (long *) &x, k;
	k = px[n0] & 0x7ff00000;
	if (k == 0) {
		if ((px[n1] | (px[n0] & 0x7fffffff)) == 0)
			return 0x80000001;
		else {
			x *= two52;
			return ((px[n0] & 0x7ff00000) >> 20) - 1075;
		}
	} else if (k != 0x7ff00000)
		return (k >> 20) - 1023;
	else
		return 0x7fffffff;
}

static double 
scalbn(x, n)
	double          x;
	int             n;
{
	long           *px = (long *) &x, k;
	double          twom54 = twom52 * 0.25;
	k = (px[n0] & 0x7ff00000) >> 20;
	if (k == 0x7ff)
		return x + x;
	if ((px[n1] | (px[n0] & 0x7fffffff)) == 0)
		return x;
	if (k == 0) {
		x *= two52;
		k = ((px[n0] & 0x7ff00000) >> 20) - 52;
	}
	k = k + n;
	if (n > 5000)
		return setexception(2, x);
	if (n < -5000)
		return setexception(1, x);
	if (k > 0x7fe)
		return setexception(2, x);
	if (k <= -54)
		return setexception(1, x);
	if (k > 0) {
		px[n0] = (px[n0] & 0x800fffff) | (k << 20);
		return x;
	}
	k += 54;
	px[n0] = (px[n0] & 0x800fffff) | (k << 20);
	return x * twom54;
}

double 
fmod(x, y)
	double          x, y;
{
	int             ny, nr;
	double          r, z, w;
int finite(), ilogb(); 
double fabs(), scalbn(), copysign();

	/* purge off exception values */
	if (!finite(x) || y != y || y == 0.0) {
		return (x * y) / (x * y);
	}
	/* scale and subtract to get the remainder */
	r = fabs(x);
	y = fabs(y);
	ny = ilogb(y);
	while (r >= y) {
		nr = ilogb(r);
		if (nr == ny)
			w = y;
		else {
			z = scalbn(y, nr - ny - 1);
			w = z + z;
		}
		if (r >= w)
			r -= w;
		else
			r -= z;
	}

	/* restore sign */
	return copysign(r, x);
}
