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
 * float __k_cos(double x);
 * kernel (float) cos function on [-pi/4, pi/4], pi/4 ~ 0.785398164
 * Input x is in double and assumed to be bounded by ~pi/4 in magnitude.
 *
 * Method: Let z = x * x, then
 *	C(x) = (C0 + C1*z + C2*z*z) * (C3 + C4*z + z*z)
 * where
 *	C0 =   1.09349482127188401868272000389539985058873853699e-0003
 *	C1 =  -5.03324285989964979398034700054920226866107675091e-0004
 *	C2 =   2.43792880266971107750418061559602239831538067410e-0005
 *	C3 =   9.14499072605666582228127405245558035523741471271e+0002
 *	C4 =  -3.63151270591815439197122504991683846785293207730e+0001
 *
 * The remez error is bound by  |cos(x) - C(x)| < 2**(-34.2)
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following constants.
 * The decimal values may be used, provided that the compiler will convert
 * from decimal to binary accurately enough to produce the hexadecimal values
 * shown.
 */
/* INDENT ON */

static const double q[] = {
/* C0 = */   1.09349482127188401868272000389539985058873853699e-0003,
/* C1 = */  -5.03324285989964979398034700054920226866107675091e-0004,
/* C2 = */   2.43792880266971107750418061559602239831538067410e-0005,
/* C3 = */   9.14499072605666582228127405245558035523741471271e+0002,
/* C4 = */  -3.63151270591815439197122504991683846785293207730e+0001,
};

#define	C0	q[0]
#define	C1	q[1]
#define	C2	q[2]
#define	C3	q[3]
#define	C4	q[4]

float
__k_cosf(double x) {
	float ft;
	double z;
	int hx;

	hx = ((int *) &x)[HIWORD];	/* hx = leading x  */
	if ((hx & ~0x80000000) < 0x3f100000) {	/* |x| < 2**-14 */
		ft = (float) 1;
		if (((int) x) == 0)	/* raise inexact if x != 0 */
			return (ft);
	}
	z = x * x;
	ft = (float) (((C0 + z * C1) + (z * z) * C2) * (C3 + z * (C4 + z)));
	return (ft);
}
