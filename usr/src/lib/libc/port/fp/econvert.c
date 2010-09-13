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
#include <string.h>
#include <sys/types.h>
#include "libc.h"

/*
 * Copies the appropriate string for a datum of class cl into *buf,
 * choosing "Inf" or "Infinity" according to ndigits, the desired
 * output string length.
 */
void
__infnanstring(enum fp_class_type cl, int ndigits, char *buf)
{
	if (cl == fp_infinity) {
		if (ndigits < 8)
			(void) memcpy(buf, "Inf", 4);
		else
			(void) memcpy(buf, "Infinity", 9);
		__inf_written = 1;
	} else {
		(void) memcpy(buf, "NaN", 4);
		__nan_written = 1;
	}
}

char *
econvert(double arg, int ndigits, int *decpt, int *sign, char *buf)
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
	dm.df = floating_form;	/* E format. */
	if (ndigits <= 0)
		ndigits = 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;	/* Number of significant digits. */
	double_to_decimal(&arg, &dm, &dr, &ef);
	*sign = dr.sign;
	switch (dr.fpclass) {
	case fp_normal:
	case fp_subnormal:
		*decpt = dr.exponent + ndigits;
		for (i = 0; i < ndigits; i++)
			buf[i] = dr.ds[i];
		buf[ndigits] = 0;
		break;
	case fp_zero:
		*decpt = 1;
		for (i = 0; i < ndigits; i++)
			buf[i] = '0';
		buf[ndigits] = 0;
		break;
	default:
		*decpt = 0;
		__infnanstring(dr.fpclass, ndigits, buf);
		break;
	}
	return (buf);
}

char *
seconvert(single *arg, int ndigits, int *decpt, int *sign, char *buf)
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
	dm.df = floating_form;	/* E format. */
	if (ndigits <= 0)
		ndigits = 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;	/* Number of significant digits. */
	single_to_decimal(arg, &dm, &dr, &ef);
	*sign = dr.sign;
	switch (dr.fpclass) {
	case fp_normal:
	case fp_subnormal:
		*decpt = dr.exponent + ndigits;
		for (i = 0; i < ndigits; i++)
			buf[i] = dr.ds[i];
		buf[ndigits] = 0;
		break;
	case fp_zero:
		*decpt = 1;
		for (i = 0; i < ndigits; i++)
			buf[i] = '0';
		buf[ndigits] = 0;
		break;
	default:
		*decpt = 0;
		__infnanstring(dr.fpclass, ndigits, buf);
		break;
	}
	return (buf);
}

char *
qeconvert(quadruple *arg, int ndigits, int *decpt, int *sign, char *buf)
{
	decimal_mode	dm;
	decimal_record	dr;
	fp_exception_field_type ef;
	int		i;

#if defined(__sparc)
	dm.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	dm.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	dm.df = floating_form;	/* E format. */
	if (ndigits <= 0)
		ndigits = 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;	/* Number of significant digits. */
#if defined(__sparc)
	quadruple_to_decimal(arg, &dm, &dr, &ef);
#elif defined(__i386) || defined(__amd64)
	extended_to_decimal((extended *)arg, &dm, &dr, &ef);
#else
#error Unknown architecture
#endif
	*sign = dr.sign;
	switch (dr.fpclass) {
	case fp_normal:
	case fp_subnormal:
		*decpt = dr.exponent + ndigits;
		for (i = 0; i < ndigits; i++)
			buf[i] = dr.ds[i];
		buf[ndigits] = 0;
		break;
	case fp_zero:
		*decpt = 1;
		for (i = 0; i < ndigits; i++)
			buf[i] = '0';
		buf[ndigits] = 0;
		break;
	default:
		*decpt = 0;
		__infnanstring(dr.fpclass, ndigits, buf);
		break;
	}
	return (buf);
}
