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

/*
 * gcvt  - Floating output conversion to minimal length string
 */

#include "base_conversion.h"
#ifndef PRE41
#include <locale.h>
#endif

void
_gcvt(ndigit, pd, trailing, buf)
	int             ndigit;
	decimal_record *pd;
	char           *buf;
{
	char           *p, *pstring;
	int             i;
	static char     *inf8 = "Infinity";
	static char     *inf3 = "Inf";
	static char     *nan = "NaN";
#ifdef PRE41
	char decpt = '.';
#else
	char decpt = *(localeconv()->decimal_point);
#endif

	p = buf;
	if (pd->sign)
		*(p++) = '-';
	switch (pd->fpclass) {
	case fp_zero:
		*(p++) = '0';
		if (trailing != 0) {
			*(p++) = decpt;
			for (i = 0; i < ndigit - 1; i++)
				*(p++) = '0';
		}
		break;
	case fp_infinity:
		if (ndigit < 8)
			pstring = inf3;
		else
			pstring = inf8;
		goto copystring;
	case fp_quiet:
	case fp_signaling:
		pstring = nan;
copystring:
		for (i = 0; *pstring != 0;)
			*(p++) = *(pstring++);
		break;
	default:
		if ((pd->exponent > 0) || (pd->exponent < -(ndigit + 3))) {	/* E format. */
			char            estring[4];
			int             n;

			i = 0;
			*(p++) = pd->ds[0];
			*(p++) = decpt;
			for (i = 1; pd->ds[i] != 0;)
				*(p++) = pd->ds[i++];
			if (trailing == 0) {	/* Remove trailing zeros and . */
				p--;
				while (*p == '0')
					p--;
				if (*p != decpt)
					p++;
			}
			*(p++) = 'e';
			n = pd->exponent + i - 1;
			if (n >= 0)
				*(p++) = '+';
			else {
				*(p++) = '-';
				n = -n;
			}
			_fourdigitsquick((short unsigned) n, estring);
			for (i = 0; estring[i] == '0'; i++);	/* Find end of zeros. */
			if (i > 2)
				i = 2;	/* Guarantee two zeros. */
			for (; i <= 3;)
				*(p++) = estring[i++];	/* Copy exp digits. */
		} else {	/* F format. */
			if (pd->exponent >= (1 - ndigit)) {	/* x.xxx */
				for (i = 0; i < (ndigit + pd->exponent);)
					*(p++) = pd->ds[i++];
				*(p++) = decpt;
				if (pd->ds[i] != 0) {	/* More follows point. */
					for (; i < ndigit;)
						*(p++) = pd->ds[i++];
				}
			} else {/* 0.00xxxx */
				*(p++) = '0';
				*(p++) = decpt;
				for (i = 0; i < -(pd->exponent + ndigit); i++)
					*(p++) = '0';
				for (i = 0; pd->ds[i] != 0;)
					*(p++) = pd->ds[i++];
			}
			if (trailing == 0) {	/* Remove trailing zeros and point. */
				p--;
				while (*p == '0')
					p--;
				if (*p != decpt)
					p++;
			}
		}
	}
	*(p++) = 0;
}

char           *
gconvert(number, ndigit, trailing, buf)
	double          number;
	int             ndigit, trailing;
	char           *buf;
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type fef;

	dm.rd = fp_direction;
	dm.df = floating_form;
	dm.ndigits = ndigit;
	double_to_decimal(&number, &dm, &dr, &fef);
	_gcvt(ndigit, &dr, trailing, buf);
	return (buf);
}

char           *
gcvt(number, ndigit, buf)
	double          number;
	int             ndigit;
	char           *buf;
{
	return (gconvert(number, ndigit, 0, buf));
}
