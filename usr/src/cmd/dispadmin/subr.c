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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <limits.h>

#include "dispadmin.h"


/*
 * Utility functions for dispadmin command.
 */


void
fatalerr(const char *format, ...)
{
	va_list ap;

	(void) va_start(ap, format);
	(void) vfprintf(stderr, format, ap);
	va_end(ap);
	exit(1);
}


/*
 * hrtconvert() returns the interval specified by htp as a single
 * value in resolution htp->hrt_res.  Returns -1 on overflow.
 */
long
hrtconvert(hrtimer_t *htp)
{
	long	sum;
	long	product;

	product = htp->hrt_secs * htp->hrt_res;

	if (product / htp->hrt_res == htp->hrt_secs) {
		sum = product + htp->hrt_rem;
		if (sum - htp->hrt_rem == product) {
			return (sum);
		}
	}
	return (-1);
}

/*
 * The following routine was removed from libc (libc/port/gen/hrtnewres.c).
 * It has also been added to priocntl, so if you fix it here, you should
 * also probably fix it there. In the long term, this should be recoded to
 * not be hrt'ish.
 */

/*
 *	Convert interval expressed in htp->hrt_res to new_res.
 *
 *	Calculate: (interval * new_res) / htp->hrt_res  rounding off as
 *		specified by round.
 *
 *	Note:	All args are assumed to be positive.  If
 *	the last divide results in something bigger than
 *	a long, then -1 is returned instead.
 */

int
_hrtnewres(hrtimer_t *htp, ulong_t new_res, long round)
{
	long		interval;
	longlong_t	dint;
	longlong_t	dto_res;
	longlong_t	drem;
	longlong_t	dfrom_res;
	longlong_t	prod;
	longlong_t	quot;
	long		numerator;
	long		result;
	ulong_t		modulus;
	ulong_t		twomodulus;
	long		temp;

	if (htp->hrt_res == 0 || new_res == 0 ||
	    new_res > NANOSEC || htp->hrt_rem < 0)
		return (-1);

	if (htp->hrt_rem >= htp->hrt_res) {
		htp->hrt_secs += htp->hrt_rem / htp->hrt_res;
		htp->hrt_rem = htp->hrt_rem % htp->hrt_res;
	}

	interval = htp->hrt_rem;
	if (interval == 0) {
		htp->hrt_res = new_res;
		return (0);
	}

	/*
	 *	Try to do the calculations in single precision first
	 *	(for speed).  If they overflow, use double precision.
	 *	What we want to compute is:
	 *
	 *		(interval * new_res) / hrt->hrt_res
	 */

	numerator = interval * new_res;

	if (numerator / new_res  ==  interval) {

		/*
		 *	The above multiply didn't give overflow since
		 *	the division got back the original number.  Go
		 *	ahead and compute the result.
		 */

		result = numerator / htp->hrt_res;

		/*
		 *	For HRT_RND, compute the value of:
		 *
		 *		(interval * new_res) % htp->hrt_res
		 *
		 *	If it is greater than half of the htp->hrt_res,
		 *	then rounding increases the result by 1.
		 *
		 *	For HRT_RNDUP, we increase the result by 1 if:
		 *
		 *		result * htp->hrt_res != numerator
		 *
		 *	because this tells us we truncated when calculating
		 *	result above.
		 *
		 *	We also check for overflow when incrementing result
		 *	although this is extremely rare.
		 */

		if (round == HRT_RND) {
			modulus = numerator - result * htp->hrt_res;
			if ((twomodulus = 2 * modulus) / 2 == modulus) {

				/*
				 * No overflow (if we overflow in calculation
				 * of twomodulus we fall through and use
				 * double precision).
				 */
				if (twomodulus >= htp->hrt_res) {
					temp = result + 1;
					if (temp - 1 == result)
						result++;
					else
						return (-1);
				}
				htp->hrt_res = new_res;
				htp->hrt_rem = result;
				return (0);
			}
		} else if (round == HRT_RNDUP) {
			if (result * htp->hrt_res != numerator) {
				temp = result + 1;
				if (temp - 1 == result)
					result++;
				else
					return (-1);
			}
			htp->hrt_res = new_res;
			htp->hrt_rem = result;
			return (0);
		} else {	/* round == HRT_TRUNC */
			htp->hrt_res = new_res;
			htp->hrt_rem = result;
			return (0);
		}
	}

	/*
	 *	We would get overflow doing the calculation is
	 *	single precision so do it the slow but careful way.
	 *
	 *	Compute the interval times the resolution we are
	 *	going to.
	 */

	dint = interval;
	dto_res = new_res;
	prod = dint * dto_res;

	/*
	 *	For HRT_RND the result will be equal to:
	 *
	 *		((interval * new_res) + htp->hrt_res / 2) / htp->hrt_res
	 *
	 *	and for HRT_RNDUP we use:
	 *
	 *		((interval * new_res) + htp->hrt_res - 1) / htp->hrt_res
	 *
	 * 	This is a different but equivalent way of rounding.
	 */

	if (round == HRT_RND) {
		drem = htp->hrt_res / 2;
		prod = prod + drem;
	} else if (round == HRT_RNDUP) {
		drem = htp->hrt_res - 1;
		prod = prod + drem;
	}

	dfrom_res = htp->hrt_res;
	quot = prod / dfrom_res;

	/*
	 *	If the quotient won't fit in a long, then we have
	 *	overflow.  Otherwise, return the result.
	 */

	if (quot > UINT_MAX) {
		return (-1);
	} else {
		htp->hrt_res = new_res;
		htp->hrt_rem = (int)quot;
		return (0);
	}
}
