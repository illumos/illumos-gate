/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2001 Alexey Zelkin <phantom@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef	_LCONV_C99
#define	_LCONV_C99
#endif

#include "lint.h"
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <monetary.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "localeimpl.h"
#include "lmonetary.h"
#include "lnumeric.h"

/* internal flags */
#define	NEED_GROUPING		0x01	/* print digits grouped (default) */
#define	SIGN_POSN_USED		0x02	/* '+' or '(' usage flag */
#define	LOCALE_POSN		0x04	/* use locale defined +/- (default) */
#define	PARENTH_POSN		0x08	/* enclose negative amount in () */
#define	SUPRESS_CURR_SYMBOL	0x10	/* supress the currency from output */
#define	LEFT_JUSTIFY		0x20	/* left justify */
#define	USE_INTL_CURRENCY	0x40	/* use international currency symbol */
#define	IS_NEGATIVE		0x80	/* is argument value negative ? */

/* internal macros */
#define	PRINT(CH) {						\
	if (dst >= s + maxsize) 				\
		goto e2big_error;				\
	*dst++ = CH;						\
}

#define	PRINTS(STR) {						\
	const char *tmps = STR;					\
	while (*tmps != '\0')					\
		PRINT(*tmps++);					\
}

#define	GET_NUMBER(VAR)	{					\
	VAR = 0;						\
	while (isdigit((unsigned char)*fmt)) {			\
		if (VAR > INT_MAX / 10)				\
			goto e2big_error;			\
		VAR *= 10;					\
		VAR += *fmt - '0';				\
		if (VAR < 0)					\
			goto e2big_error;			\
		fmt++;						\
	}							\
}

#define	GRPCPY(howmany) {					\
	int i = howmany;					\
	while (i-- > 0) {					\
		avalue_size--;					\
		*--bufend = *(avalue+avalue_size+padded);	\
	}							\
}

#define	GRPSEP {						\
	bufend -= thousands_len;				\
	(void) memcpy(bufend, thousands_sep, thousands_len);	\
	groups++;						\
}

static void setup_vars(const struct lc_monetary *, int, char *, char *, char *,
    const char **);
static int calc_left_pad(const struct lc_monetary *, int, const char *);
static char *format_grouped_double(const struct lc_monetary *,
    const struct lc_numeric *, double, int *, int, int, int);

ssize_t
strfmon_impl(char *_RESTRICT_KYWD s, size_t maxsize, locale_t loc,
    const char *_RESTRICT_KYWD format, va_list ap)
{
	char 		*dst;		/* output destination pointer */
	const char 	*fmt;		/* current format poistion pointer */
	char		*asciivalue;	/* formatted double pointer */

	int		flags;		/* formatting options */
	int		pad_char;	/* padding character */
	int		pad_size;	/* pad size */
	int		width;		/* field width */
	int		left_prec;	/* left precision */
	int		right_prec;	/* right precision */
	double		value;		/* just value */
	char		space_char = ' '; /* space after currency */

	char		cs_precedes;	/* values from struct lc_monetary */
	char		sep_by_space;
	char		sign_posn;
	const char	*signstr;
	const char	*currency_symbol;

	char		*tmpptr;	/* temporary vars */
	int		sverrno;
	const struct lc_monetary *lmon;		/* monetary structure */
	const struct lc_numeric *lnum;		/* numeric structure */

	lmon = loc->monetary;
	lnum = loc->numeric;

	dst = s;
	fmt = format;
	asciivalue = NULL;
	currency_symbol = NULL;
	pad_size = 0;

	while (*fmt) {
		/* pass nonformating characters AS IS */
		if (*fmt != '%')
			goto literal;

		/* '%' found ! */

		/* "%%" mean just '%' */
		if (*(fmt+1) == '%') {
			fmt++;
	literal:
			PRINT(*fmt++);
			continue;
		}

		/* set up initial values */
		flags = (NEED_GROUPING|LOCALE_POSN);
		pad_char = ' ';		/* padding character is "space" */
		left_prec = -1;		/* no left precision specified */
		right_prec = -1;	/* no right precision specified */
		width = -1;		/* no width specified */
		value = 0;		/* we have no value to print now */

		/* Flags */
		for (;;) {
			switch (*++fmt) {
				case '=':	/* fill character */
					pad_char = *++fmt;
					if (pad_char == '\0')
						goto format_error;
					continue;
				case '^':	/* not group currency  */
					flags &= ~(NEED_GROUPING);
					continue;
				case '+':	/* use locale defined signs */
					if (flags & SIGN_POSN_USED)
						goto format_error;
					flags |= (SIGN_POSN_USED|LOCALE_POSN);
					continue;
				case '(':	/* enclose negatives with () */
					if (flags & SIGN_POSN_USED)
						goto format_error;
					flags |= (SIGN_POSN_USED|PARENTH_POSN);
					continue;
				case '!':	/* suppress currency symbol */
					flags |= SUPRESS_CURR_SYMBOL;
					continue;
				case '-':	/* alignment (left)  */
					flags |= LEFT_JUSTIFY;
					continue;
				default:
					break;
			}
			break;
		}

		/* field Width */
		if (isdigit((unsigned char)*fmt)) {
			GET_NUMBER(width);
			/*
			 * Do we have enough space to put number with
			 * required width ?
			 */
			if ((unsigned int)width >= maxsize - (dst - s))
				goto e2big_error;
		}

		/* Left precision */
		if (*fmt == '#') {
			if (!isdigit((unsigned char)*++fmt))
				goto format_error;
			GET_NUMBER(left_prec);
			if ((unsigned int)left_prec >= maxsize - (dst - s))
				goto e2big_error;
		}

		/* Right precision */
		if (*fmt == '.') {
			if (!isdigit((unsigned char)*++fmt))
				goto format_error;
			GET_NUMBER(right_prec);
			if ((unsigned int)right_prec >= maxsize - (dst - s) -
			    left_prec)
				goto e2big_error;
		}

		/* Conversion Characters */
		switch (*fmt++) {
			case 'i':	/* use internaltion currency format */
				flags |= USE_INTL_CURRENCY;
				break;
			case 'n':	/* use national currency format */
				flags &= ~(USE_INTL_CURRENCY);
				break;
			default:
				/* required char missing or premature EOS */
				goto format_error;
		}

		if (flags & USE_INTL_CURRENCY) {
			currency_symbol = lmon->int_curr_symbol;
			/* by definition three letters followed by a space */
			if (currency_symbol != NULL)
				space_char = currency_symbol[3];
		} else
			currency_symbol = lmon->currency_symbol;

		/* value itself */
		value = va_arg(ap, double);

		/* detect sign */
		if (value < 0) {
			flags |= IS_NEGATIVE;
			value = -value;
		}

		/* fill left_prec with amount of padding chars */
		if (left_prec >= 0) {
			pad_size = calc_left_pad(lmon, (flags ^ IS_NEGATIVE),
			    currency_symbol) -
			    calc_left_pad(lmon, flags, currency_symbol);
			if (pad_size < 0)
				pad_size = 0;
		}

		if (asciivalue != NULL)
			free(asciivalue);
		asciivalue = format_grouped_double(lmon, lnum, value, &flags,
		    left_prec, right_prec, pad_char);
		if (asciivalue == NULL)
			goto end_error;		/* errno already set */
						/* to ENOMEM by malloc() */

		/* set some variables for later use */
		setup_vars(lmon, flags, &cs_precedes, &sep_by_space,
		    &sign_posn, &signstr);

		/*
		 * Description of some LC_MONETARY's values:
		 *
		 * p_cs_precedes & n_cs_precedes
		 *
		 * = 1 - $currency_symbol precedes the value
		 *	 for a monetary quantity with a non-negative value
		 * = 0 - symbol succeeds the value
		 *
		 * p_sep_by_space & n_sep_by_space
		 *
		 * = 0 - no space separates $currency_symbol
		 *	 from the value for a monetary quantity with a
		 *	 non-negative value
		 * = 1 - space separates the symbol from the value
		 * = 2 - space separates the symbol and the sign string,
		 *	 if adjacent.
		 *
		 * p_sign_posn & n_sign_posn
		 *
		 * = 0 - parentheses enclose the quantity and the
		 *	 $currency_symbol
		 * = 1 - the sign string precedes the quantity and the
		 *	 $currency_symbol
		 * = 2 - the sign string succeeds the quantity and the
		 *	 $currency_symbol
		 * = 3 - the sign string precedes the $currency_symbol
		 * = 4 - the sign string succeeds the $currency_symbol
		 *
		 */

		tmpptr = dst;

		while (pad_size-- > 0)
			PRINT(' ');

		if (sign_posn == 0 && (flags & IS_NEGATIVE))
			PRINT('(');

		if (cs_precedes == 1) {
			if (sign_posn == 1 || sign_posn == 3) {
				PRINTS(signstr);
				if (sep_by_space == 2)
					PRINT(' ');
			}

			if (!(flags & SUPRESS_CURR_SYMBOL)) {
				PRINTS(currency_symbol);

				if (sign_posn == 4) {
					if (sep_by_space == 2)
						PRINT(space_char);
					PRINTS(signstr);
					if (sep_by_space == 1)
						PRINT(' ');
				} else if (sep_by_space == 1)
					PRINT(space_char);
			}
		} else if (sign_posn == 1)
			PRINTS(signstr);

		PRINTS(asciivalue);

		if (cs_precedes == 0) {
			if (sign_posn == 3) {
				if (sep_by_space == 1)
					PRINT(' ');
				PRINTS(signstr);
			}

			if (!(flags & SUPRESS_CURR_SYMBOL)) {
				if ((sign_posn == 3 && sep_by_space == 2) ||
				    (sep_by_space == 1 && (sign_posn == 0 ||
				    sign_posn == 1 || sign_posn == 2 ||
				    sign_posn == 4)))
					PRINT(space_char);
				PRINTS(currency_symbol); /* XXX: len */
				if (sign_posn == 4) {
					if (sep_by_space == 2)
						PRINT(' ');
					PRINTS(signstr);
				}
			}
		}

		if (sign_posn == 2) {
			if (sep_by_space == 2)
				PRINT(' ');
			PRINTS(signstr);
		}

		if (sign_posn == 0 && (flags & IS_NEGATIVE))
			PRINT(')');

		if (dst - tmpptr < width) {
			if (flags & LEFT_JUSTIFY) {
				while (dst - tmpptr < width)
					PRINT(' ');
			} else {
				pad_size = dst-tmpptr;
				(void) memmove(tmpptr + width-pad_size, tmpptr,
				    pad_size);
				(void) memset(tmpptr, ' ', width-pad_size);
				dst += width-pad_size;
			}
		}
	}

	PRINT('\0');
	free(asciivalue);
	return (dst - s - 1);	/* size of put data except trailing '\0' */

e2big_error:
	errno = E2BIG;
	goto end_error;

format_error:
	errno = EINVAL;

end_error:
	sverrno = errno;
	if (asciivalue != NULL)
		free(asciivalue);
	errno = sverrno;
	return (-1);
}

ssize_t
strfmon(char *_RESTRICT_KYWD s, size_t maxsize,
    const char *_RESTRICT_KYWD format, ...)
{
	va_list ap;
	ssize_t ret;

	va_start(ap, format);
	ret = strfmon_impl(s, maxsize, uselocale(NULL), format, ap);
	va_end(ap);
	return (ret);
}

ssize_t
strfmon_l(char *_RESTRICT_KYWD s, size_t maxsize, locale_t loc,
    const char *_RESTRICT_KYWD format, ...)
{
	ssize_t ret;
	va_list ap;
	va_start(ap, format);
	ret = strfmon_impl(s, maxsize, loc, format, ap);
	va_end(ap);
	return (ret);
}

static void
setup_vars(const struct lc_monetary *lmon, int flags, char *cs_precedes,
    char *sep_by_space, char *sign_posn, const char **signstr)
{
	if ((flags & IS_NEGATIVE) && (flags & USE_INTL_CURRENCY)) {
		*cs_precedes = lmon->int_n_cs_precedes[0];
		*sep_by_space = lmon->int_n_sep_by_space[0];
		*sign_posn = (flags & PARENTH_POSN) ? 0 :
		    lmon->int_n_sign_posn[0];
		*signstr = (lmon->negative_sign[0] == '\0') ? "-" :
		    lmon->negative_sign;
	} else if (flags & USE_INTL_CURRENCY) {
		*cs_precedes = lmon->int_p_cs_precedes[0];
		*sep_by_space = lmon->int_p_sep_by_space[0];
		*sign_posn = (flags & PARENTH_POSN) ? 0 :
		    lmon->int_p_sign_posn[0];
		*signstr = lmon->positive_sign;
	} else if (flags & IS_NEGATIVE) {
		*cs_precedes = lmon->n_cs_precedes[0];
		*sep_by_space = lmon->n_sep_by_space[0];
		*sign_posn = (flags & PARENTH_POSN) ? 0 : lmon->n_sign_posn[0];
		*signstr = (lmon->negative_sign[0] == '\0') ? "-" :
		    lmon->negative_sign;
	} else {
		*cs_precedes = lmon->p_cs_precedes[0];
		*sep_by_space = lmon->p_sep_by_space[0];
		*sign_posn = (flags & PARENTH_POSN) ? 0 : lmon->p_sign_posn[0];
		*signstr = lmon->positive_sign;
	}

	/* Set default values for unspecified information. */
	if (*cs_precedes != 0)
		*cs_precedes = 1;
	if (*sep_by_space == CHAR_MAX)
		*sep_by_space = 0;
	if (*sign_posn == CHAR_MAX)
		*sign_posn = 0;
}

static int
calc_left_pad(const struct lc_monetary *lmon, int flags, const char *cur_symb)
{
	char cs_precedes, sep_by_space, sign_posn;
	const char *signstr;
	int left_chars = 0;

	setup_vars(lmon, flags, &cs_precedes, &sep_by_space, &sign_posn,
	    &signstr);

	if (cs_precedes != 0) {
		left_chars += strlen(cur_symb);
		if (sep_by_space != 0)
			left_chars++;
	}

	switch (sign_posn) {
		case 1:
			left_chars += strlen(signstr);
			break;
		case 3:
		case 4:
			if (cs_precedes != 0)
				left_chars += strlen(signstr);
	}
	return (left_chars);
}

static int
get_groups(int size, const char *grouping)
{

	int	chars = 0;

	if (*grouping == CHAR_MAX || *grouping <= 0)	/* no grouping ? */
		return (0);

	while (size > (int)*grouping) {
		chars++;
		size -= (int)*grouping++;
		/* no more grouping ? */
		if (*grouping == CHAR_MAX)
			break;
		/* rest grouping with same value ? */
		if (*grouping == 0) {
			chars += (size - 1) / *(grouping - 1);
			break;
		}
	}
	return (chars);
}

/* convert double to ASCII */
static char *
format_grouped_double(const struct lc_monetary *lmon,
    const struct lc_numeric *lnum,
    double value, int *flags, int left_prec, int right_prec, int pad_char)
{

	char		*rslt;
	char		*avalue;
	int		avalue_size;
	char		fmt[32];

	size_t		bufsize;
	char		*bufend;

	int		padded;

	const char	*grouping;
	const char	*decimal_point;
	const char	*thousands_sep;
	int		decimal_len;
	int		thousands_len;

	int groups = 0;

	grouping = lmon->mon_grouping;
	decimal_point = lmon->mon_decimal_point;
	if (*decimal_point == '\0')
		decimal_point = lnum->decimal_point;
	thousands_sep = lmon->mon_thousands_sep;
	if (*thousands_sep == '\0')
		thousands_sep = lnum->thousands_sep;

	decimal_len = strlen(decimal_point);	/* usually 1 */
	thousands_len = strlen(thousands_sep);	/* 0 or 1 usually */

	/* fill left_prec with default value */
	if (left_prec == -1)
		left_prec = 0;

	/* fill right_prec with default value */
	if (right_prec == -1) {
		if (*flags & USE_INTL_CURRENCY)
			right_prec = lmon->int_frac_digits[0];
		else
			right_prec = lmon->frac_digits[0];

		if (right_prec == CHAR_MAX)	/* POSIX locale ? */
			right_prec = 2;
	}

	if (*flags & NEED_GROUPING)
		left_prec += get_groups(left_prec, grouping);

	/* convert to string */
	(void) snprintf(fmt, sizeof (fmt), "%%%d.%df",
	    left_prec + right_prec + 1, right_prec);
	avalue_size = asprintf(&avalue, fmt, value);
	if (avalue_size < 0)
		return (NULL);

	/*
	 * Make sure that we've enough space for result string.
	 * This assumes that digits take up at least much space as
	 * grouping and radix characters.  The worst case currently known
	 * is for Arabic, where two-byte UTF-8 sequences are used for both
	 * decimal and thousands seperators, and groups can be a small as two
	 * decimal digits.  This will do no worse than doubling the storage
	 * requirement.
	 */
	bufsize = strlen(avalue)*2+1;
	rslt = calloc(1, bufsize);
	if (rslt == NULL) {
		free(avalue);
		return (NULL);
	}
	bufend = rslt + bufsize - 1;	/* reserve space for trailing '\0' */

	/* skip spaces at beginning */
	padded = 0;
	while (avalue[padded] == ' ') {
		padded++;
		avalue_size--;
	}

	if (right_prec > 0) {
		bufend -= right_prec;
		(void) memcpy(bufend, avalue + avalue_size+padded-right_prec,
		    right_prec);
		bufend -= decimal_len;
		(void) memcpy(bufend, decimal_point, decimal_len);
		avalue_size -= (right_prec + decimal_len);
	}

	if ((*flags & NEED_GROUPING) &&
	    thousands_len != 0 &&
	    *grouping != CHAR_MAX &&
	    *grouping > 0) {
		while (avalue_size > (int)*grouping) {
			GRPCPY(*grouping);
			GRPSEP;
			grouping++;

			/* no more grouping ? */
			if (*grouping == CHAR_MAX)
				break;

			/* rest grouping with same value ? */
			if (*grouping == 0) {
				grouping--;
				while (avalue_size > *grouping) {
					GRPCPY(*grouping);
					GRPSEP;
				}
			}
		}
		if (avalue_size != 0)
			GRPCPY(avalue_size);
		padded -= groups;

	} else {
		bufend -= avalue_size;
		(void) memcpy(bufend, avalue+padded, avalue_size);
		if (right_prec == 0)
			padded--;	/* decrease assumed $decimal_point */
	}

	/* do padding with pad_char */
	if (padded > 0) {
		bufend -= padded;
		(void) memset(bufend, pad_char, padded);
	}

	bufsize = bufsize - (bufend - rslt) + 1;
	(void) memmove(rslt, bufend, bufsize);
	free(avalue);
	return (rslt);
}
