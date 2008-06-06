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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	ecvt converts to decimal
 *	the number of digits is specified by ndigit
 *	decpt is set to the position of the decimal point
 *	sign is set to 0 for positive, 1 for negative
 *
 */

#pragma weak _ecvt = ecvt
#pragma weak _fcvt = fcvt

#include "lint.h"
#include <sys/types.h>
#include <values.h>
#include <nan.h>
#include <string.h>
#include "tsd.h"

#define	NMAX	((DSIGNIF * 3 + 19)/10) /* restrict max precision */
#define	NDIG	80

static char *cvt(double, int, int *, int *, int);

char *
ecvt(double value, int ndigit, int *decpt, int *sign)
{
	return (cvt(value, ndigit, decpt, sign, 0));
}

char *
fcvt(double value, int ndigit, int *decpt, int *sign)
{
	return (cvt(value, ndigit, decpt, sign, 1));
}

static char *
cvt(double value, int ndigit, int *decpt, int *sign, int f_flag)
{
	char *buf = tsdalloc(_T_ECVT, NDIG, NULL);
	char *p = &buf[0], *p_last = &buf[ndigit];

	buf[0] = '\0';

	if (IsNANorINF(value)) {
		if (IsINF(value))  /* value is an INF, return "inf" */
			(void) strncpy(buf, "inf", NDIG);
		else /* value is a NaN, return "NaN" */
			(void) strncpy(buf, "nan", NDIG);

		return (buf);
	}

	if ((*sign = (value < 0.0)) != 0)
		value = -value;
	*decpt = 0;
	if (value != 0.0) {
/*
 * rescale to range [1.0, 10.0)
 * in binary for speed and to minimize error build-up
 * even for the IEEE standard with its high exponents,
 *  it's probably better for speed to just loop on them
 */
		static const struct s { double p10; int n; } s[] = {
			1e32,	32,
			1e16,	16,
			1e8,	8,
			1e4,	4,
			1e2,	2,
			1e1,	1,
		};
		const struct s *sp = s;

		++*decpt;
		if (value >= 2.0 * MAXPOWTWO) /* can't be precisely integral */
			do {
				for (; value >= sp->p10; *decpt += sp->n)
					value /= sp->p10;
			} while (sp++->n > 1);
		else if (value >= 10.0) { /* convert integer part separately */
			double pow10 = 10.0, powtemp;

			while ((powtemp = 10.0 * pow10) <= value)
				pow10 = powtemp;
			for (; ; pow10 /= 10.0) {
				int digit = value/pow10;
				*p++ = digit + '0';
				value -= digit * pow10;
				++*decpt;
				if (pow10 <= 10.0)
					break;
			}
		} else if (value < 1.0)
			do {
				for (; value * sp->p10 < 10.0; *decpt -= sp->n)
					value *= sp->p10;
			} while (sp++->n > 1);
	}
	if (f_flag)
		p_last += *decpt;
	if (p_last >= buf) {
		if (p_last > &buf[NDIG - 2])
			p_last = &buf[NDIG - 2];
		for (; ; ++p) {
			if (value == 0 || p >= &buf[NMAX])
				*p = '0';
			else {
				int intx; /* intx in [0, 9] */
				*p = (intx = (int)value) + '0';
				value = 10.0 * (value - (double)intx);
			}
			if (p >= p_last) {
				p = p_last;
				break;
			}
		}
		if (*p >= '5') /* check rounding in last place + 1 */
			do {
				if (p == buf) { /* rollover from 99999... */
					buf[0] = '1'; /* later digits are 0 */
					++*decpt;
					if (f_flag)
						++p_last;
					break;
				}
				*p = '0';
			} while (++*--p > '9'); /* propagate carries left */
		*p_last = '\0';
	}
	return (buf);
}
