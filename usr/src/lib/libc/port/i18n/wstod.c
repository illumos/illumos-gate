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
 * This file is based on /usr/src/lib/libc/port/gen/strtod.c and
 * /usr/src/lib/libc/sparc/fp/string_decim.c
 */

#pragma weak _wcstod = wcstod
#pragma weak _wstod = wstod

#include "lint.h"
#include <errno.h>
#include <stdio.h>
#include <values.h>
#include <floatingpoint.h>
#include <stddef.h>
#include <wctype.h>
#include "base_conversion.h"	/* from usr/src/lib/libc/inc */
#include <locale.h>
#include "libc.h"
#include "xpg6.h"

static void wstring_to_decimal(const wchar_t **, int, decimal_record *, int *);

double
wcstod(const wchar_t *cp, wchar_t **ptr)
{
	double		x;
	decimal_mode	mr;
	decimal_record	dr;
	fp_exception_field_type fs;
	int 		form;

	wstring_to_decimal(&cp, __xpg6 & _C99SUSv3_recognize_hexfp, &dr, &form);
	if (ptr != NULL)
		*ptr = (wchar_t *)cp;
	if (form == 0)
		return (0.0);	/* Shameful kluge for SVID's sake. */
#if defined(__i386) || defined(__amd64)
	mr.rd = __xgetRD();
#elif defined(__sparc)
	mr.rd = _QgetRD();
#else
#error Unknown architecture!
#endif
	if (form < 0)
		__hex_to_double(&dr, mr.rd, &x, &fs);
	else
		decimal_to_double(&x, &mr, &dr, &fs);
	if (fs & ((1 << fp_overflow) | (1 << fp_underflow)))
		errno = ERANGE;
	return (x);
}

float
wcstof(const wchar_t *cp, wchar_t **ptr)
{
	float		x;
	decimal_mode	mr;
	decimal_record	dr;
	fp_exception_field_type fs;
	int		form;

	wstring_to_decimal(&cp, 1, &dr, &form);
	if (ptr != NULL)
		*ptr = (wchar_t *)cp;
	if (form == 0)
		return (0.0f);
#if defined(__i386) || defined(__amd64)
	mr.rd = __xgetRD();
#elif defined(__sparc)
	mr.rd = _QgetRD();
#else
#error Unknown architecture!
#endif
	if (form < 0)
		__hex_to_single(&dr, mr.rd, &x, &fs);
	else
		decimal_to_single(&x, &mr, &dr, &fs);
	if (fs & ((1 << fp_overflow) | (1 << fp_underflow)))
		errno = ERANGE;
	return (x);
}

long double
wcstold(const wchar_t *cp, wchar_t **ptr)
{
	long double	x;
	decimal_mode	mr;
	decimal_record	dr;
	fp_exception_field_type fs;
	int		form;

	wstring_to_decimal(&cp, 1, &dr, &form);
	if (ptr != NULL)
		*ptr = (wchar_t *)cp;
	if (form == 0)
		return (0.0L);
#if defined(__i386) || defined(__amd64)
	mr.rd = __xgetRD();
	if (form < 0)
		__hex_to_extended(&dr, mr.rd, (extended *)&x, &fs);
	else
		decimal_to_extended((extended *)&x, &mr, &dr, &fs);
#elif defined(__sparc)
	mr.rd = _QgetRD();
	if (form < 0)
		__hex_to_quadruple(&dr, mr.rd, &x, &fs);
	else
		decimal_to_quadruple(&x, &mr, &dr, &fs);
#else
#error Unknown architecture!
#endif
	if (fs & ((1 << fp_overflow) | (1 << fp_underflow)))
		errno = ERANGE;
	return (x);
}

double
wstod(const wchar_t *cp, wchar_t **ptr)
{
	return (wcstod(cp, ptr));
}

static const char *infstring = "INFINITY";
static const char *nanstring = "NAN";

/*
 * The following macro is applied to wchar_t arguments solely for the
 * purpose of comparing the result with one of the characters in the
 * strings above.
 */
#define	UCASE(c)	(((L'a' <= c) && (c <= L'z'))? c - 32 : c)

/*
 * The following macro yields an expression that is true whenever
 * the argument is a valid nonzero digit for the form being parsed.
 */
#define	NZDIGIT(c)	((L'1' <= c && c <= L'9') || (form < 0 && \
			((L'a' <= c && c <= L'f') || (L'A' <= c && c <= L'F'))))

/*
 * wstring_to_decimal is modelled on string_to_decimal, the majority
 * of which can be found in the common file char_to_decimal.h.  The
 * significant differences are:
 *
 * 1. This code recognizes only C99 (hex fp strings and restricted
 *    characters in parentheses following "nan") vs. C90 modes, no
 *    Fortran conventions.
 *
 * 2. *pform is an int rather than an enum decimal_string_form.  On
 *    return, *pform == 0 if no valid token was found, *pform < 0
 *    if a C99 hex fp string was found, and *pform > 0 if a decimal
 *    string was found.
 */
static void
wstring_to_decimal(const wchar_t **ppc, int c99, decimal_record *pd,
    int *pform)
{
	const wchar_t	*cp = *ppc; /* last character seen */
	const wchar_t	*good = cp - 1;	/* last character accepted */
	wchar_t		current; /* always equal to *cp */
	int		sigfound;
	int		ids = 0;
	int		i, agree;
	int		nzbp = 0; /* number of zeros before point */
	int		nzap = 0; /* number of zeros after point */
	char		decpt;
	int		nfast, nfastlimit;
	char		*pfast;
	int		e, esign;
	int		expshift = 0;
	int		form;

	/*
	 * This routine assumes that the radix point is a single
	 * ASCII character, so that following this assignment, the
	 * condition (current == decpt) will correctly detect it.
	 */
	decpt = *(localeconv()->decimal_point);

	/* input is invalid until we find something */
	pd->fpclass = fp_signaling;
	pd->sign = 0;
	pd->exponent = 0;
	pd->ds[0] = '\0';
	pd->more = 0;
	pd->ndigits = 0;
	*pform = form = 0;

	/* skip white space */
	current = *cp;
	while (iswspace((wint_t)current))
		current = *++cp;

	/* look for optional leading sign */
	if (current == L'+') {
		current = *++cp;
	} else if (current == L'-') {
		pd->sign = 1;
		current = *++cp;
	}

	sigfound = -1;		/* -1 = no digits found yet */

	/*
	 * Admissible first non-white-space, non-sign characters are
	 * 0-9, i, I, n, N, or the radix point.
	 */
	if (L'1' <= current && current <= L'9') {
		pd->fpclass = fp_normal;
		form = 1;
		good = cp;
		sigfound = 1;	/* 1 = significant digits found */
		pd->ds[ids++] = (char)current;
		current = *++cp;
	} else {
		switch (current) {
		case L'0':
			/*
			 * Accept the leading zero and set pd->fpclass
			 * accordingly, but don't set sigfound until we
			 * determine that this isn't a "fake" hex string
			 * (i.e., 0x.p...).
			 */
			good = cp;
			pd->fpclass = fp_zero;
			if (c99) {
				/* look for a hex fp string */
				current = *++cp;
				if (current == L'X' || current == L'x') {
					/* assume hex fp form */
					form = -1;
					expshift = 2;
					current = *++cp;
					/*
					 * Only a digit or radix point can
					 * follow "0x".
					 */
					if (NZDIGIT(current)) {
						pd->fpclass = fp_normal;
						good = cp;
						sigfound = 1;
						pd->ds[ids++] = (char)current;
						current = *++cp;
						break;
					} else if (current == (wchar_t)decpt) {
						current = *++cp;
						goto afterpoint;
					} else if (current != L'0') {
						/* not hex fp after all */
						form = 1;
						expshift = 0;
						goto done;
					}
				} else {
					form = 1;
				}
			} else {
				form = 1;
			}

			/* skip all leading zeros */
			while (current == L'0')
				current = *++cp;
			good = cp - 1;
			sigfound = 0;	/* 0 = only zeros found so far */
			break;

		case L'i':
		case L'I':
			/* look for inf or infinity */
			current = *++cp;
			agree = 1;
			while (agree <= 7 &&
			    UCASE(current) == (wchar_t)infstring[agree]) {
				current = *++cp;
				agree++;
			}
			if (agree >= 3) {
				/* found valid infinity */
				pd->fpclass = fp_infinity;
				form = 1;
				good = (agree < 8)? cp + 2 - agree : cp - 1;
				__inf_read = 1;
			}
			goto done;

		case L'n':
		case L'N':
			/* look for nan or nan(string) */
			current = *++cp;
			agree = 1;
			while (agree <= 2 &&
			    UCASE(current) == (wchar_t)nanstring[agree]) {
				current = *++cp;
				agree++;
			}
			if (agree == 3) {
				/* found valid NaN */
				pd->fpclass = fp_quiet;
				form = 1;
				good = cp - 1;
				__nan_read = 1;
				if (current == L'(') {
					/* accept parenthesized string */
					if (c99) {
						do {
							current = *++cp;
						} while (iswalnum(current) ||
						    current == L'_');
					} else {
						do {
							current = *++cp;
						} while (current &&
						    current != L')');
					}
					if (current == L')')
						good = cp;
				}
			}
			goto done;

		default:
			if (current == (wchar_t)decpt) {
				/*
				 * Don't accept the radix point just yet;
				 * we need to see at least one digit.
				 */
				current = *++cp;
				goto afterpoint;
			}
			goto done;
		}
	}

nextnumber:
	/*
	 * Admissible characters after the first digit are a valid
	 * digit, an exponent delimiter (E or e for decimal form,
	 * P or p for hex form), or the radix point.  (Note that we
	 * can't get here unless we've already found a digit.)
	 */
	if (NZDIGIT(current)) {
		/*
		 * Found another nonzero digit.  If there's enough room
		 * in pd->ds, store any intervening zeros we've found so far
		 * and then store this digit.  Otherwise, stop storing
		 * digits in pd->ds and set pd->more.
		 */
		if (ids + nzbp + 2 < DECIMAL_STRING_LENGTH) {
			for (i = 0; i < nzbp; i++)
				pd->ds[ids++] = '0';
			pd->ds[ids++] = (char)current;
		} else {
			pd->exponent += (nzbp + 1) << expshift;
			pd->more = 1;
			if (ids < DECIMAL_STRING_LENGTH) {
				pd->ds[ids] = '\0';
				pd->ndigits = ids;
				/* don't store any more digits */
				ids = DECIMAL_STRING_LENGTH;
			}
		}
		pd->fpclass = fp_normal;
		sigfound = 1;
		nzbp = 0;
		current = *++cp;

		/*
		 * Use an optimized loop to grab a consecutive sequence
		 * of nonzero digits quickly.
		 */
		nfastlimit = DECIMAL_STRING_LENGTH - 3 - ids;
		for (nfast = 0, pfast = &(pd->ds[ids]);
		    nfast < nfastlimit && NZDIGIT(current);
		    nfast++) {
			*pfast++ = (char)current;
			current = *++cp;
		}
		ids += nfast;
		if (current == L'0')
			goto nextnumberzero;	/* common case */
		/* advance good to the last accepted digit */
		good = cp - 1;
		goto nextnumber;
	} else {
		switch (current) {
		case L'0':
nextnumberzero:
			/*
			 * Count zeros before the radix point.  Later we
			 * will either put these zeros into pd->ds or add
			 * nzbp to pd->exponent to account for them.
			 */
			while (current == L'0') {
				nzbp++;
				current = *++cp;
			}
			good = cp - 1;
			goto nextnumber;

		case L'E':
		case L'e':
			if (form < 0)
				goto done;
			goto exponent;

		case L'P':
		case L'p':
			if (form > 0)
				goto done;
			goto exponent;

		default:
			if (current == decpt) {
				/* accept the radix point */
				good = cp;
				current = *++cp;
				goto afterpoint;
			}
			goto done;
		}
	}

afterpoint:
	/*
	 * Admissible characters after the radix point are a valid digit
	 * or an exponent delimiter.  (Note that it is possible to get
	 * here even though we haven't found any digits yet.)
	 */
	if (NZDIGIT(current)) {
		if (form == 0)
			form = 1;
		if (sigfound < 1) {
			/* no significant digits found until now */
			pd->fpclass = fp_normal;
			sigfound = 1;
			pd->ds[ids++] = (char)current;
			pd->exponent = (-(nzap + 1)) << expshift;
		} else {
			/* significant digits have been found */
			if (ids + nzbp + nzap + 2 < DECIMAL_STRING_LENGTH) {
				for (i = 0; i < nzbp + nzap; i++)
					pd->ds[ids++] = '0';
				pd->ds[ids++] = (char)current;
				pd->exponent -= (nzap + 1) << expshift;
			} else {
				pd->exponent += nzbp << expshift;
				pd->more = 1;
				if (ids < DECIMAL_STRING_LENGTH) {
					pd->ds[ids] = '\0';
					pd->ndigits = ids;
					/* don't store any more digits */
					ids = DECIMAL_STRING_LENGTH;
				}
			}
		}
		nzbp = 0;
		nzap = 0;
		current = *++cp;

		/*
		 * Use an optimized loop to grab a consecutive sequence
		 * of nonzero digits quickly.
		 */
		nfastlimit = DECIMAL_STRING_LENGTH - 3 - ids;
		for (nfast = 0, pfast = &(pd->ds[ids]);
		    nfast < nfastlimit && NZDIGIT(current);
		    nfast++) {
			*pfast++ = (char)current;
			current = *++cp;
		}
		ids += nfast;
		pd->exponent -= nfast << expshift;
		if (current == L'0')
			goto zeroafterpoint;
		/* advance good to the last accepted digit */
		good = cp - 1;
		goto afterpoint;
	} else {
		switch (current) {
		case L'0':
			if (form == 0)
				form = 1;
			if (sigfound == -1) {
				pd->fpclass = fp_zero;
				sigfound = 0;
			}
zeroafterpoint:
			/*
			 * Count zeros after the radix point.  If we find
			 * any more nonzero digits later, we will put these
			 * zeros into pd->ds and decrease pd->exponent by
			 * nzap.
			 */
			while (current == L'0') {
				nzap++;
				current = *++cp;
			}
			good = cp - 1;
			goto afterpoint;

		case L'E':
		case L'e':
			/* don't accept exponent without preceding digits */
			if (sigfound == -1 || form < 0)
				goto done;
			break;

		case L'P':
		case L'p':
			/* don't accept exponent without preceding digits */
			if (sigfound == -1 || form > 0)
				goto done;
			break;

		default:
			goto done;
		}
	}

exponent:
	e = 0;
	esign = 0;

	/* look for optional exponent sign */
	current = *++cp;
	if (current == L'+') {
		current = *++cp;
	} else if (current == L'-') {
		esign = 1;
		current = *++cp;
	}

	/*
	 * Accumulate explicit exponent.  Note that if we don't find at
	 * least one digit, good won't be updated and e will remain 0.
	 * Also, we keep e from getting too large so we don't overflow
	 * the range of int (but notice that the threshold is large
	 * enough that any larger e would cause the result to underflow
	 * or overflow anyway).
	 */
	while (L'0' <= current && current <= L'9') {
		good = cp;
		if (e <= 1000000)
			e = 10 * e + current - L'0';
		current = *++cp;
	}
	if (esign)
		pd->exponent -= e;
	else
		pd->exponent += e;

done:
	/*
	 * If we found any zeros before the radix point that were not
	 * accounted for earlier, adjust the exponent.  (This is only
	 * relevant when pd->fpclass == fp_normal, but it's harmless
	 * in all other cases.)
	 */
	pd->exponent += nzbp << expshift;

	/* terminate pd->ds if we haven't already */
	if (ids < DECIMAL_STRING_LENGTH) {
		pd->ds[ids] = '\0';
		pd->ndigits = ids;
	}

	/*
	 * If we accepted any characters, advance *ppc to point to the
	 * first character we didn't accept; otherwise, pass back a
	 * signaling nan.
	 */
	if (good >= *ppc) {
		*ppc = good + 1;
	} else {
		pd->fpclass = fp_signaling;
		pd->sign = 0;
		form = 0;
	}

	*pform = form;
}
