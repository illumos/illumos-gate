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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

#include "base_conversion.h"

char           *
qeconvert(arg, ndigits, decpt, sign, buf)
	quadruple         *arg;
	int             ndigits, *decpt, *sign;
	char           *buf;
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type ef;
	int             i;
	static char     *nanstring = "NaN";
	static char     *infstring = "Infinity";
	char           *pc;
	int             nc;

	dm.rd = fp_direction;	/* Rounding direction. */
	dm.df = floating_form;	/* E format. */
	dm.ndigits = ndigits;	/* Number of significant digits. */
	quadruple_to_decimal(arg, &dm, &dr, &ef);
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
	case fp_infinity:
		*decpt = 0;
		pc = infstring;
		if (ndigits < 8)
			nc = 3;
		else
			nc = 8;
		goto movestring;
	case fp_quiet:
	case fp_signaling:
		*decpt = 0;
		pc = nanstring;
		nc = 3;
movestring:
		for (i = 0; i < nc; i++)
			buf[i] = pc[i];
		buf[nc] = 0;
		break;
	}
	return buf;		/* For compatibility with ecvt. */
}

char           *
qfconvert(arg, ndigits, decpt, sign, buf)
	quadruple         *arg;
	int             ndigits, *decpt, *sign;
	char           *buf;
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type ef;
	int             i;

	dm.rd = fp_direction;	/* Rounding direction. */
	dm.df = fixed_form;	/* F format. */
	dm.ndigits = ndigits;	/* Number of digits after point. */
	quadruple_to_decimal(arg, &dm, &dr, &ef);
	*sign = dr.sign;
	switch (dr.fpclass) {
	case fp_normal:
	case fp_subnormal:
		if (ndigits >= 0)
			*decpt = dr.ndigits - ndigits;
		else
			*decpt = dr.ndigits;
		for (i = 0; i < dr.ndigits; i++)
			buf[i] = dr.ds[i];
		buf[dr.ndigits] = 0;
		break;
	case fp_zero:
		*decpt = 0;
		buf[0] = '0';
		for (i = 1; i < ndigits; i++)
			buf[i] = '0';
		buf[i] = 0;
		break;
	case fp_infinity:
		*decpt = 0;
		if (ndigits < 8)
			buf = "Inf";
		else
			buf = "Infinity";
		break;
	case fp_quiet:
	case fp_signaling:
		*decpt = 0;
		buf = "NaN";
		break;
	}
	return buf;		/* For compatibility with fcvt. */
}

extern void    _gcvt();

char           *
qgconvert(number, ndigit, trailing, buf)
	quadruple         *number;
	int             ndigit, trailing;
	char           *buf;
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type fef;

	dm.rd = fp_direction;
	dm.df = floating_form;
	dm.ndigits = ndigit;
	quadruple_to_decimal(number, &dm, &dr, &fef);
	_gcvt(ndigit, &dr, trailing, buf);
	return (buf);
}
