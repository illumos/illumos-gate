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
/*	  All Rights Reserved	*/

/*
 * Copyright 2025 Bill Sommerfeld
 */

#include "lint.h"
#include <errno.h>
#include <stdio.h>
#include <values.h>
#include <floatingpoint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <xlocale.h>
#include "libc.h"
#include "xpg6.h"

double
strtod(const char *cp, char **ptr)
{
	return (strtod_l(cp, ptr, uselocale(NULL)));
}

double
strtod_l(const char *cp, char **ptr, locale_t loc)
{
	double		x;
	decimal_mode	mr;
	decimal_record  dr;
	fp_exception_field_type fs;
	enum decimal_string_form form;
	char		*pechar;
	int		lc;

	lc = (__xpg6 & _C99SUSv3_recognize_hexfp)? -1 : 0;
	string_to_decimal_l((char **)&cp, MAXINT, lc, &dr, &form, &pechar, loc);
	if (ptr != NULL)
		*ptr = (char *)cp;
	if (form == invalid_form)
		return (0.0);	/* Shameful kluge for SVID's sake. */
#if defined(__sparc)
	mr.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	mr.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	if ((int)form < 0)
		__hex_to_double(&dr, mr.rd, &x, &fs);
	else
		decimal_to_double(&x, &mr, &dr, &fs);
	if (fs & ((1 << fp_overflow) | (1 << fp_underflow)))
		errno = ERANGE;
	return (x);
}

float
strtof(const char *cp, char **ptr)
{
	return (strtof_l(cp, ptr, uselocale(NULL)));
}

float
strtof_l(const char *cp, char **ptr, locale_t loc)
{
	float		x;
	decimal_mode	mr;
	decimal_record	dr;
	fp_exception_field_type fs;
	enum decimal_string_form form;
	char		*pechar;

	string_to_decimal_l((char **)&cp, MAXINT, -1, &dr, &form, &pechar, loc);
	if (ptr != NULL)
		*ptr = (char *)cp;
	if (form == invalid_form)
		return (0.0f);
#if defined(__sparc)
	mr.rd = _QgetRD();
#elif defined(__i386) || defined(__amd64)
	mr.rd = __xgetRD();
#else
#error Unknown architecture
#endif
	if ((int)form < 0)
		__hex_to_single(&dr, mr.rd, &x, &fs);
	else
		decimal_to_single(&x, &mr, &dr, &fs);
	if (fs & ((1 << fp_overflow) | (1 << fp_underflow)))
		errno = ERANGE;
	return (x);
}

long double
strtold(const char *cp, char **ptr)
{
	return (strtold_l(cp, ptr, uselocale(NULL)));
}

long double
strtold_l(const char *cp, char **ptr, locale_t loc)
{
	long double	x;
	decimal_mode	mr;
	decimal_record	dr;
	fp_exception_field_type fs;
	enum decimal_string_form form;
	char		*pechar;

	string_to_decimal_l((char **)&cp, MAXINT, -1, &dr, &form, &pechar, loc);
	if (ptr != NULL)
		*ptr = (char *)cp;
	if (form == invalid_form)
		return (0.0L);
#if defined(__sparc)
	mr.rd = _QgetRD();
	if ((int)form < 0)
		__hex_to_quadruple(&dr, mr.rd, &x, &fs);
	else
		decimal_to_quadruple(&x, &mr, &dr, &fs);
#elif defined(__i386) || defined(__amd64)
	mr.rd = __xgetRD();
	if ((int)form < 0)
		__hex_to_extended(&dr, mr.rd, (extended *)&x, &fs);
	else
		decimal_to_extended((extended *)&x, &mr, &dr, &fs);
#else
#error Unknown architecture
#endif
	if (fs & ((1 << fp_overflow) | (1 << fp_underflow)))
		errno = ERANGE;
	return (x);
}
