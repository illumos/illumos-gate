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

#pragma weak exp10l = __exp10l

#include "libm.h"
#include "longdouble.h"

/*
 * exp10l(x)
 *	n = nint(x*(log10/log2)) ;
 *	exp10(x) = 10**x = exp(x*ln(10)) = exp(n*ln2+(x*ln10-n*ln2))
 *		 = 2**n*exp(ln10*(x-n*log2/log10)))
 *	If x is an integer <= M then use repeat multiplication. For
 *	10**M is the largest representable integer, where
 *		M = 10		single precision (24 bits)
 *		M = 22		double precision (53 bits)
 *		M = 48		quadruple precision (113 bits)
 */

#define	TINY 	1.0e-20L	/* single: 1e-5, double: 1e-10, quad: 1e-20 */
#define	LG10OVT	4933.L		/* single:  39, double:  309, quad:  4933 */
#define	LG10UFT	-4966.L		/* single: -45, double: -323, quad: -4966 */
#define	M	48
			/* logt2hi : last 32 bits is zero for quad prec */
#define	LOGT2HI	0.30102999566398119521373889472420986034688L
#define	LOGT2LO	2.831664213089468167896664371953e-31L

static const long double
	zero	= 0.0L,
	tiny	= TINY * TINY,
	one	= 1.0L,
	lg10	= 3.321928094887362347870319429489390175865e+0000L,
	ln10	= 2.302585092994045684017991454684364207601e+0000L,
	logt2hi	= LOGT2HI,
	logt2lo	= LOGT2LO,
	lg10ovt	= LG10OVT,
	lg10uft	= LG10UFT;

long double
exp10l(long double x) {
	long double t, tenp;
	int k;

	if (!finitel(x)) {
		if (isnanl(x) || x > zero)
			return (x + x);
		else
			return (zero);
	}
	if (fabsl(x) < tiny)
		return (one + x);
	if (x <= lg10ovt)
		if (x >= lg10uft) {
			k = (int) x;
			tenp = 10.0L;
					/* x is a small +integer */
			if (0 <= k && k <= M && (long double) k == x) {
				t = one;
				if (k & 1)
					t *= tenp;
				k >>= 1;
				while (k) {
					tenp *= tenp;
					if (k & 1)
						t *= tenp;
					k >>= 1;
				}
				return (t);
			}
			t = anintl(x * lg10);
			return (scalbnl(expl(ln10 * ((x - t * logt2hi) -
				t * logt2lo)), (int) t));
		} else
			return (scalbnl(one, -50000));	/* underflow */
	else
			return (scalbnl(one, 50000));	/* overflow  */
}
