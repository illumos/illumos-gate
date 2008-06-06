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
#include <locale.h>

static void
__k_gconvert(int ndigits, decimal_record *pd, int trailing, char *buf)
{
	char	*p;
	int	i;
	char	decpt = *(localeconv()->decimal_point);

	p = buf;
	if (pd->sign)
		*(p++) = '-';
	switch (pd->fpclass) {
	case fp_zero:
		*(p++) = '0';
		if (trailing != 0) {
			*(p++) = decpt;
			for (i = 0; i < ndigits - 1; i++)
				*(p++) = '0';
		}
		*p++ = 0;
		break;
	case fp_subnormal:
	case fp_normal:
		if ((pd->exponent > 0) || (pd->exponent < -(ndigits + 3))) {
			/* E format. */
			char	estring[4];
			int	n;

			*(p++) = pd->ds[0];
			*(p++) = decpt;
			for (i = 1; pd->ds[i] != 0; )
				*(p++) = pd->ds[i++];
			if (trailing == 0) {
				/* Remove trailing zeros and . */
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
			__four_digits_quick((unsigned short) n, estring);

				/* Find end of zeros. */
			for (i = 0; estring[i] == '0'; i++)
				;

			if (i > 2)
				i = 2;	/* Guarantee two zeros. */
			for (; i <= 3; )
				*(p++) = estring[i++];	/* Copy exp digits. */
		} else {	/* F format. */
			if (pd->exponent >= (1 - ndigits)) {	/* x.xxx */
				for (i = 0; i < (ndigits + pd->exponent); )
					*(p++) = pd->ds[i++];
				*(p++) = decpt;
				if (pd->ds[i] != 0) {
					/* More follows point. */
					for (; i < ndigits; )
						*(p++) = pd->ds[i++];
				}
			} else { /* 0.00xxxx */
				*(p++) = '0';
				*(p++) = decpt;
				for (i = 0; i < -(pd->exponent + ndigits); i++)
					*(p++) = '0';
				for (i = 0; pd->ds[i] != 0; )
					*(p++) = pd->ds[i++];
			}
			if (trailing == 0) {
				/* Remove trailing zeros and point. */
				p--;
				while (*p == '0')
					p--;
				if (*p != decpt)
					p++;
			}
		}
		*(p++) = 0;
		break;
	default:
		__infnanstring(pd->fpclass, ndigits, p);
		break;
	}
}

char *
gconvert(double number, int ndigits, int trailing, char *buf)
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type fef;

#if defined(__sparc)
	dm.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	dm.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	dm.df = floating_form;
	if (ndigits < 0)
		ndigits = 6;
	else if (ndigits == 0)
		ndigits = 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;
	double_to_decimal(&number, &dm, &dr, &fef);
	__k_gconvert(ndigits, &dr, trailing, buf);
	return (buf);
}

char *
sgconvert(single *number, int ndigits, int trailing, char *buf)
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type fef;

#if defined(__sparc)
	dm.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	dm.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	dm.df = floating_form;
	if (ndigits < 0)
		ndigits = 6;
	else if (ndigits == 0)
		ndigits = 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;
	single_to_decimal(number, &dm, &dr, &fef);
	__k_gconvert(ndigits, &dr, trailing, buf);
	return (buf);
}

char *
qgconvert(quadruple *number, int ndigits, int trailing, char *buf)
{
	decimal_mode    dm;
	decimal_record  dr;
	fp_exception_field_type fef;

#if defined(__sparc)
	dm.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	dm.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	dm.df = floating_form;
	if (ndigits < 0)
		ndigits = 6;
	else if (ndigits == 0)
		ndigits = 1;
	else if (ndigits >= DECIMAL_STRING_LENGTH)
		ndigits = DECIMAL_STRING_LENGTH - 1;
	dm.ndigits = ndigits;
#if defined(__sparc)
	quadruple_to_decimal(number, &dm, &dr, &fef);
#elif defined(__i386) || defined(__amd64)
	extended_to_decimal((extended *)number, &dm, &dr, &fef);
#else
#error Unknown architecture
#endif
	__k_gconvert(ndigits, &dr, trailing, buf);
	return (buf);
}
