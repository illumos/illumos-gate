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
#include <stdlib.h>
#include <floatingpoint.h>
#include "tsd.h"

char *
ecvt(double number, int ndigits, int *decpt, int *sign)
{
	char *buf = tsdalloc(_T_ECVT, DECIMAL_STRING_LENGTH, NULL);

	return (econvert(number, ndigits, decpt, sign, buf));
}

char *
fcvt(double number, int ndigits, int *decpt, int *sign)
{
	char *buf = tsdalloc(_T_ECVT, DECIMAL_STRING_LENGTH, NULL);
	char *ptr, *val;
	char ch;
	int deci_val;

	ptr = fconvert(number, ndigits, decpt, sign, buf);

	val = ptr;
	deci_val = *decpt;

	while ((ch = *ptr) != 0) {
		if (ch != '0') { /* You execute this if there are no */
				    /* leading zero's remaining. */
			*decpt = deci_val; /* If there are leading zero's */
			return (ptr);		/* gets updated. */
		}
		ptr++;
		deci_val--;
	}
	return (val);
}

char *
qecvt(
	long double	number,
	int		ndigits,
	int		*decpt,
	int		*sign)
{
	char *buf = tsdalloc(_T_ECVT, DECIMAL_STRING_LENGTH, NULL);

	return (qeconvert(&number, ndigits, decpt, sign, buf));
}

char *
qfcvt(long double number, int ndigits, int *decpt, int *sign)
{
	char *buf = tsdalloc(_T_ECVT, DECIMAL_STRING_LENGTH, NULL);

	return (qfconvert(&number, ndigits, decpt, sign, buf));
}

char *
qgcvt(long double number, int ndigits, char *buffer)
{
	return (qgconvert(&number, ndigits, 0, buffer));
}
