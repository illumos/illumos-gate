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

#if defined(ELFOBJ)
#pragma weak log10l = __log10l
#endif

/*
 * log10l(X)
 *
 * Method :
 *	Let log10_2hi = leading 98(SPARC)/49(x86) bits of log10(2) and
 *	    log10_2lo = log10(2) - log10_2hi,
 *	    ivln10   = 1/log(10) rounded.
 *	Then
 *		n = ilogb(x),
 *		if (n<0)  n = n+1;
 *		x = scalbn(x,-n);
 *		LOG10(x) := n*log10_2hi + (n*log10_2lo + ivln10*log(x))
 *
 * Note1:
 *	For fear of destroying log10(10**n)=n, the rounding mode is
 *	set to Round-to-Nearest.
 *
 * Special cases:
 *	log10(x) is NaN with signal if x < 0;
 *	log10(+INF) is +INF with no signal; log10(0) is -INF with signal;
 *	log10(NaN) is that NaN with no signal;
 *	log10(10**N) = N  for N=0,1,...,22.
 *
 * Constants:
 * The hexadecimal values are the intended ones for the following constants.
 * The decimal values may be used, provided that the compiler will convert
 * from decimal to binary accurately enough to produce the hexadecimal values
 * shown.
 */

#include "libm.h"
#include "longdouble.h"

#if defined(__x86)
#define	__swapRD	__swap87RD
#endif
extern enum fp_direction_type __swapRD(enum fp_direction_type);

static const long double
	zero	  = 0.0L,
	ivln10    = 4.342944819032518276511289189166050822944e-0001L,
	one	  = 1.0L,
#if defined(__x86)
	log10_2hi = 3.010299956639803653501985536422580480576e-01L,
	log10_2lo = 8.298635403410822349787106337291183585413e-16L;
#elif defined(__sparc)
	log10_2hi = 3.010299956639811952137388947242098603469e-01L,
	log10_2lo = 2.831664213089468167896664371953210945664e-31L;
#else
#error Unknown Architecture!
#endif

long double
log10l(long double x) {
	long double y, z;
	enum fp_direction_type rd;
	int n;

	if (!finitel(x))
		return (x + fabsl(x));	/* x is +-INF or NaN */
	else if (x > zero) {
		n = ilogbl(x);
		if (n < 0)
			n += 1;
		rd = __swapRD(fp_nearest);
		y = n;
		x = scalbnl(x, -n);
		z = y * log10_2lo + ivln10 * logl(x);
		z += y * log10_2hi;
		if (rd != fp_nearest)
			(void) __swapRD(rd);
		return (z);
	} else if (x == zero)	/* -INF */
		return (-one / zero);
	else			/* x <0, return NaN */
		return (zero / zero);
}
