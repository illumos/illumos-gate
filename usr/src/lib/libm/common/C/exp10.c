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

/* INDENT OFF */
/*
 * exp10(x)
 * Code by K.C. Ng for SUN 4.0 libm.
 * Method :
 *	n = nint(x*(log10/log2));
 *	exp10(x) = 10**x = exp(x*ln(10)) = exp(n*ln2+(x*ln10-n*ln2))
 *		 = 2**n*exp(ln10*(x-n*log2/log10)))
 *	If x is an integer < 23 then use repeat multiplication. For
 *	10**22 is the largest representable integer.
 */
/* INDENT ON */

#include "libm.h"

static const double C[] = {
	3.3219280948736234787,	/* log(10)/log(2) */
	2.3025850929940456840,	/* log(10) */
	3.0102999565860955045E-1,	/* log(2)/log(10) high */
	5.3716447674669983622E-12,	/* log(2)/log(10) low */
	0.0,
	0.5,
	1.0,
	10.0,
	1.0e300,
	1.0e-300,
};

#define	lg10	C[0]
#define	ln10	C[1]
#define	logt2hi	C[2]
#define	logt2lo	C[3]
#define	zero	C[4]
#define	half	C[5]
#define	one	C[6]
#define	ten	C[7]
#define	huge	C[8]
#define	tiny	C[9]

double
exp10(double x) {
	double	t, pt;
	int	ix, hx, k;

	ix = ((int *)&x)[HIWORD];
	hx = ix & ~0x80000000;

	if (hx >= 0x4074a000) {	/* |x| >= 330 or x is nan */
		if (hx >= 0x7ff00000) {	/* x is inf or nan */
			if (ix == 0xfff00000 && ((int *)&x)[LOWORD] == 0)
				return (zero);
			return (x * x);
		}
		t = (ix < 0)? tiny : huge;
		return (t * t);
	}

	if (hx < 0x3c000000)
		return (one + x);

	k = (int)x;
	if (0 <= k && k < 23 && (double)k == x) {
		/* x is a small positive integer */
		t = one;
		pt = ten;
		if (k & 1)
			t = ten;
		k >>= 1;
		while (k) {
			pt *= pt;
			if (k & 1)
				t *= pt;
			k >>= 1;
		}
		return (t);
	}
	t = x * lg10;
	k = (int)((ix < 0)? t - half : t + half);
	return (scalbn(exp(ln10 * ((x - k * logt2hi) - k * logt2lo)), k));
}
