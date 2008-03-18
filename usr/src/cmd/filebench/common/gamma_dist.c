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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <math.h>

/*
 * This is valid for 0 < a <= 1
 *
 * From Knuth Volume 2, 3rd edition, pages 586 - 587.
 */
static double
gamma_dist_knuth_algG(double a, double (*src)(unsigned short *),
    unsigned short *xi)
{
	double p, U, V, X, q;

	p = M_E/(a + M_E);
G2:
	/* get a random number U */
	U = (*src)(xi);

	do {
		/* get a random number V */
		V = (*src)(xi);

	} while (V == 0);

	if (U < p) {
		X = pow(V, 1/a);
		/* q = e^(-X) */
		q = exp(-X);
	} else {
		X = 1 - log(V);
		q = pow(X, a-1);
	}

	/*
	 * X now has density g, and q = f(X)/cg(X)
	 */

	/* get a random number U */
	U = (*src)(xi);

	if (U >= q)
		goto G2;
	return (X);
}

/*
 * This is valid for a > 1
 *
 * From Knuth Volume 2, 3rd edition, page 134.
 */
static double
gamma_dist_knuth_algA(double a, double (*src)(unsigned short *),
    unsigned short *xi)
{
	double U, Y, X, V;

A1:
	/* get a random number U */
	U = (*src)(xi);

	Y = tan(M_PI*U);
	X = (sqrt((2*a) - 1) * Y) + a - 1;

	if (X <= 0)
		goto A1;

	/* get a random number V */
	V = (*src)(xi);

	if (V > ((1 + (Y*Y)) * exp((a-1) * log(X/(a-1)) - sqrt(2*a -1) * Y)))
		goto A1;

	return (X);
}

/*
 * fetch a uniformly distributed random number using the drand48 generator
 */
/* ARGSUSED */
static double
default_src(unsigned short *xi)
{
	return (drand48());
}

/*
 * Sample the gamma distributed random variable with gamma 'a' and
 * result mulitplier 'b', which is usually mean/gamma. Uses the default
 * drand48 random number generator as input
 */
double
gamma_dist_knuth(double a, double b)
{
	if (a <= 1.0)
		return (b * gamma_dist_knuth_algG(a, default_src, NULL));
	else
		return (b * gamma_dist_knuth_algA(a, default_src, NULL));
}

/*
 * Sample the gamma distributed random variable with gamma 'a' and
 * multiplier 'b', which is mean / gamma adjusted for the specified
 * minimum value. The suppled random number source function is
 * used to optain the uniformly distributed random numbers.
 */
double
gamma_dist_knuth_src(double a, double b,
    double (*src)(unsigned short *), unsigned short *xi)
{
	if (a <= 1.0)
		return (b * gamma_dist_knuth_algG(a, src, xi));
	else
		return (b * gamma_dist_knuth_algA(a, src, xi));
}
