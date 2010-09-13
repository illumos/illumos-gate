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

#include "lint.h"
#include "base_conversion.h"
#include <sys/types.h>
#include "libc.h"

char *
fconvert(double arg, int ndigits, int *decpt, int *sign, char *buf)
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type ef;
	int		i;

#if defined(__sparc)
	dm.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	dm.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	dm.df = fixed_form;	/* F format. */
	if (ndigits <= -DECIMAL_STRING_LENGTH)
		ndigits = -DECIMAL_STRING_LENGTH + 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;	/* Number of digits after point. */
	double_to_decimal(&arg, &dm, &dr, &ef);
	*sign = dr.sign;
	switch (dr.fpclass) {
	case fp_normal:
	case fp_subnormal:
		*decpt = dr.exponent + dr.ndigits;
		for (i = 0; i < dr.ndigits; i++)
			buf[i] = dr.ds[i];
		/*
		 * Pad with zeroes if we didn't get all the digits
		 * we asked for.
		 */
		if (ndigits > 0 && dr.exponent > -ndigits) {
			while (i < dr.ndigits + dr.exponent + ndigits)
				buf[i++] = '0';
		}
		buf[i] = 0;
		break;
	case fp_zero:
		*decpt = 0;
		buf[0] = '0';
		for (i = 1; i < ndigits; i++)
			buf[i] = '0';
		buf[i] = 0;
		break;
	default:
		*decpt = 0;
		__infnanstring(dr.fpclass, ndigits, buf);
		break;
	}
	return (buf);
}

char *
sfconvert(single *arg, int ndigits, int *decpt, int *sign, char *buf)
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type ef;
	int		i;

#if defined(__sparc)
	dm.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	dm.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	dm.df = fixed_form;	/* F format. */
	if (ndigits <= -DECIMAL_STRING_LENGTH)
		ndigits = -DECIMAL_STRING_LENGTH + 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;	/* Number of digits after point. */
	single_to_decimal(arg, &dm, &dr, &ef);
	*sign = dr.sign;
	switch (dr.fpclass) {
	case fp_normal:
	case fp_subnormal:
		*decpt = dr.exponent + dr.ndigits;
		for (i = 0; i < dr.ndigits; i++)
			buf[i] = dr.ds[i];
		/*
		 * Pad with zeroes if we didn't get all the digits
		 * we asked for.
		 */
		if (ndigits > 0 && dr.exponent > -ndigits) {
			while (i < dr.ndigits + dr.exponent + ndigits)
				buf[i++] = '0';
		}
		buf[i] = 0;
		break;
	case fp_zero:
		*decpt = 0;
		buf[0] = '0';
		for (i = 1; i < ndigits; i++)
			buf[i] = '0';
		buf[i] = 0;
		break;
	default:
		*decpt = 0;
		__infnanstring(dr.fpclass, ndigits, buf);
		break;
	}
	return (buf);
}

char *
qfconvert(quadruple *arg, int ndigits, int *decpt, int *sign, char *buf)
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type ef;
	int		i;

#if defined(__sparc)
	dm.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	dm.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	dm.df = fixed_form;	/* F format. */
	if (ndigits <= -DECIMAL_STRING_LENGTH)
		ndigits = -DECIMAL_STRING_LENGTH + 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;	/* Number of digits after point. */
#if defined(__sparc)
	quadruple_to_decimal(arg, &dm, &dr, &ef);
#elif defined(__i386) || defined(__amd64)
	extended_to_decimal((extended *)arg, &dm, &dr, &ef);
#else
#error Unknown architecture
#endif
	*sign = dr.sign;
	if (ef & (1 << fp_overflow)) {
		/*
		 * *_to_decimal raises overflow whenever dr.ds isn't large
		 * enough to hold all the digits requested.  For float and
		 * double, this can only happen when the requested format
		 * would require trailing zeroes, in which case fconvert
		 * and sfconvert just add them.  For long double, the arg-
		 * ument might be large enough that even the nonzero digits
		 * would overflow dr.ds, so we punt instead.  (We could
		 * distinguish these two cases, but it doesn't seem worth
		 * changing things now, particularly since no real appli-
		 * cation prints floating point numbers to 500 digits.)
		 */
		*decpt = 0;
		buf[0] = 0;
		return (buf);
	}
	switch (dr.fpclass) {
	case fp_normal:
	case fp_subnormal:
		*decpt = dr.exponent + dr.ndigits;
		for (i = 0; i < dr.ndigits; i++)
			buf[i] = dr.ds[i];
		buf[i] = 0;
		break;
	case fp_zero:
		*decpt = 0;
		buf[0] = '0';
		for (i = 1; i < ndigits; i++)
			buf[i] = '0';
		buf[i] = 0;
		break;
	default:
		*decpt = 0;
		__infnanstring(dr.fpclass, ndigits, buf);
		break;
	}
	return (buf);
}
