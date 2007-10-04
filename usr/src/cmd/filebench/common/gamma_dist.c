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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
gamma_dist_knuth_algG(double a)
{
	double p, U, V, X, q;

	p = M_E/(a + M_E);
G2:
	U = drand48();
	do {
		V = drand48();
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
	U = drand48();
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
gamma_dist_knuth_algA(double a)
{
	double U, Y, X, V;

A1:
	U = drand48();
	Y = tan(M_PI*U);
	X = (sqrt((2*a) - 1) * Y) + a - 1;

	if (X <= 0)
		goto A1;

	V = drand48();
	/* V > (1 + Y^2) * exp((a - 1) * log(X / (a - 1)) - sqrt(2a - 1) * Y) */
	if (V > ((1 + (Y*Y)) * exp((a-1) * log(X/(a-1)) - sqrt(2*a -1) * Y)))
		goto A1;

	return (X);
}

double
gamma_dist_knuth(double a, double b)
{
	if (a <= 1.0)
		return (b * gamma_dist_knuth_algG(a));
	else
		return (b * gamma_dist_knuth_algA(a));
}
