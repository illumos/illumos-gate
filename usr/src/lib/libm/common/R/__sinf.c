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

#include "libm.h"

/* INDENT OFF */
/*
 * float __k_sin(double x);
 * kernel (float) sin function on [-pi/4, pi/4], pi/4 ~ 0.785398164
 * Input x is in double and assumed to be bounded by ~pi/4 in magnitude.
 *
 * Method: Let z = x * x, then
 *      S(x) = x(S0 + S1*z)(S2 + S3*z + z*z)
 * where
 *	S0 =   1.85735322054308378716204874632872525989806770558e-0003,
 *	S1 =  -1.95035094218403635082921458859320791358115801259e-0004,
 *	S2 =   5.38400550766074785970952495168558701485841707252e+0002,
 *	S3 =  -3.31975110777873728964197739157371509422022905947e+0001,
 *
 * The remez error is bound by  |(sin(x) - S(x))/x| < 2**(-28.2)
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following constants.
 * The decimal values may be used, provided that the compiler will convert
 * from decimal to binary accurately enough to produce the hexadecimal values
 * shown.
 */
/* INDENT ON */

static const double q[] = {
/* S0 = */  1.85735322054308378716204874632872525989806770558e-0003,
/* S1 = */ -1.95035094218403635082921458859320791358115801259e-0004,
/* S2 = */  5.38400550766074785970952495168558701485841707252e+0002,
/* S3 = */ -3.31975110777873728964197739157371509422022905947e+0001,
};

#define	S0  q[0]
#define	S1  q[1]
#define	S2  q[2]
#define	S3  q[3]

float
__k_sinf(double x) {
	float ft;
	double z;
	int hx;

	hx = ((int *) &x)[HIWORD];	/* hx = leading x */
	if ((hx & ~0x80000000) < 0x3f100000) {	/* if |x| < 2**-14 */
		ft = (float) x;
		if ((int) x == 0)	/* raise inexact if x != 0 */
			return (ft);
	}
	z = x * x;
	ft = (float) ((x * (S0 + z * S1)) * (S2 + z * (S3 + z)));
	return (ft);
}
