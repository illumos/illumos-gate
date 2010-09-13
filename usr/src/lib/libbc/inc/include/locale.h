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
/*
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__locale_h
#define	__locale_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Locale indices.
 */

#ifndef	NULL
#define	NULL		0
#endif

#define	LC_ALL		0
#define	LC_CTYPE	1
#define	LC_NUMERIC	2
#define	LC_TIME		3
#define	LC_MONETARY	4
#ifndef	_POSIX_SOURCE
#define	LANGINFO	5
#endif
#define	LC_COLLATE	6
#define	LC_MESSAGES	7

#ifndef	_POSIX_SOURCE
#define	MAXLOCALE	8

#define	ON	1
#define	OFF	0
/* The maximum number of characters in the locale name */

#define	MAXLOCALENAME   14

/* The maximum number of substitute mappings in LC_COLLATE table */

#define	MAXSUBS   	64

/* Max width of domain name */

#define	MAXDOMAIN	255

/* Max width of format string for message domains */

#define	MAXFMTS		32

/* Max width of the message string */

#define	MAXMSGSTR	255

/* The directory where category components are kept */

#define	LOCALE_DIR	"/usr/share/lib/locale/"

/* The directory that is private to an individual workstation user */

#define	PRIVATE_LOCALE_DIR	"/etc/locale/"

/* The name of the file that contains default locale */

#define	DEFAULT_LOC		".default"


/* size of "ctype" */

#define	CTYPE_SIZE	514
#endif	/* _POSIX_SOURCE */

extern char *		setlocale(/* int category, const char *locale */);
extern struct lconv *	localeconv(/* void */);
#ifndef	_POSIX_SOURCE
extern struct dtconv *	localdtconv();
#endif

/*
 * Numeric and monetary conversion information.
 */
struct lconv {
	char	*decimal_point;	/* decimal point character */
	char	*thousands_sep;	/* thousands separator character */
	char	*grouping;	/* grouping of digits */
	char	*int_curr_symbol;	/* international currency symbol */
	char	*currency_symbol;	/* local currency symbol */
	char	*mon_decimal_point;	/* monetary decimal point character */
	char	*mon_thousands_sep;	/* monetary thousands separator */
	char	*mon_grouping;	/* monetary grouping of digits */
	char	*positive_sign;	/* monetary credit symbol */
	char	*negative_sign;	/* monetary debit symbol */
	char	int_frac_digits; /* intl monetary number of fractional digits */
	char	frac_digits;	/* monetary number of fractional digits */
	char	p_cs_precedes;	/* true if currency symbol precedes credit */
	char	p_sep_by_space;	/* true if space separates c.s.  from credit */
	char	n_cs_precedes;	/* true if currency symbol precedes debit */
	char	n_sep_by_space;	/* true if space separates c.s.  from debit */
	char	p_sign_posn;	/* position of sign for credit */
	char	n_sign_posn;	/* position of sign for debit */
};

#ifndef	_POSIX_SOURCE
/*
 * Date and time conversion information.
 */
struct dtconv {
	char	*abbrev_month_names[12];	/* abbreviated month names */
	char	*month_names[12];	/* full month names */
	char	*abbrev_weekday_names[7];	/* abbreviated weekday names */
	char	*weekday_names[7];	/* full weekday names */
	char	*time_format;	/* time format */
	char	*sdate_format;	/* short date format */
	char	*dtime_format;	/* date/time format */
	char	*am_string;	/* AM string */
	char	*pm_string;	/* PM string */
	char	*ldate_format;	/* long date format */
};

/*
 * Langinfo
 */
struct langinfo {
	char *yesstr;	/* yes string */
	char *nostr;	/* nostr */
};

/*
 * NLS nl_init
 */
#define	valid(ptr) (ptr != (char *) NULL)
#define	nl_init(lang) ((valid(lang) && *lang) ? \
    (valid(setlocale (LC_ALL, lang) ) ? 0 : -1) \
    : -1)
#endif	/* _POSIX_SOURCE */

#endif	/* !__locale_h */
