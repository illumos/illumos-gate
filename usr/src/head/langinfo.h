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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */


#ifndef	_LANGINFO_H
#define	_LANGINFO_H

#include <sys/feature_tests.h>
#include <nl_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The seven days of the week in their full beauty
 */

#define	DAY_1	  1	/* sunday */
#define	DAY_2	  2	/* monday */
#define	DAY_3	  3	/* tuesday */
#define	DAY_4	  4	/* wednesday */
#define	DAY_5	  5	/* thursday */
#define	DAY_6	  6	/* friday */
#define	DAY_7	  7	/* saturday */

/*
 * The abbreviated seven days of the week
 */

#define	ABDAY_1	  8  /* sun */
#define	ABDAY_2	  9  /* mon */
#define	ABDAY_3	  10 /* tue */
#define	ABDAY_4	  11 /* wed */
#define	ABDAY_5	  12 /* thu */
#define	ABDAY_6	  13 /* fri */
#define	ABDAY_7	  14 /* sat */

/*
 * The full names of the twelve months...
 */

#define	MON_1	  15 /* january */
#define	MON_2	  16 /* february */
#define	MON_3	  17 /* march */
#define	MON_4	  18 /* april */
#define	MON_5	  19 /* may */
#define	MON_6	  20 /* june */
#define	MON_7	  21 /* july */
#define	MON_8	  22 /* august */
#define	MON_9	  23 /* september */
#define	MON_10	  24 /* october */
#define	MON_11	  25 /* november */
#define	MON_12	  26 /* december */

/*
 * ... and their abbreviated form
 */

#define	ABMON_1	  27 /* jan */
#define	ABMON_2	  28 /* feb */
#define	ABMON_3	  29 /* mar */
#define	ABMON_4	  30 /* apr */
#define	ABMON_5	  31 /* may */
#define	ABMON_6	  32 /* jun */
#define	ABMON_7	  33 /* jul */
#define	ABMON_8	  34 /* aug */
#define	ABMON_9	  35 /* sep */
#define	ABMON_10  36 /* oct */
#define	ABMON_11  37 /* nov */
#define	ABMON_12  38 /* dec */

/*
 * plus some special strings you might need to know
 */

#define	RADIXCHAR 39	/* radix character */
#define	THOUSEP	  40	/* separator for thousand */
/* YESSTR and NOSTR marked as legacy in XPG5 and removed in SUSv3 */
#if !defined(_XPG6) || defined(__EXTENSIONS__)
#define	YESSTR	  41    /* affirmative response for yes/no queries */
#define	NOSTR	  42  	/* negative response for yes/no queries */
#endif /* !defined(_XPG6) || defined(__EXTENSIONS__ */
#define	CRNCYSTR  43 	/* currency symbol */

/*
 * Default string used to format date and time
 *	e.g. Sunday, August 24 21:08:38 MET 1986
 */

#define	D_T_FMT	  44 	/* string for formatting date and time */
#define	D_FMT	  45	/* date format */
#define	T_FMT	  46	/* time format */
#define	AM_STR	  47	/* am string */
#define	PM_STR	  48	/* pm string */

/*
 * Additions for XPG4 (XSH4) Compliance
 */

#define	CODESET		49	/* codeset name */
#define	T_FMT_AMPM	50	/* am or pm time format string */
#define	ERA		51	/* era description segments */
#define	ERA_D_FMT	52	/* era date format string */
#define	ERA_D_T_FMT	53	/* era date and time format string */
#define	ERA_T_FMT	54	/* era time format string */
#define	ALT_DIGITS	55	/* alternative symbols for digits */
#define	YESEXPR		56	/* affirmative response expression */
#define	NOEXPR		57	/* negative response expression */
#define	_DATE_FMT	58	/* strftime format for date(1) */

#if defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE)
#define	MAXSTRMSG	58 /* Maximum number of strings in langinfo */
#endif /* defined(__EXTENSIONS__) || !defined(_XOPEN_SOURCE) */

/*
 * and the definitions of functions langinfo(3C)
 */
#if defined(__STDC__)
char   *nl_langinfo(nl_item);	/* get a string from the database	*/
#else
char   *nl_langinfo();		/* get a string from the database	*/
#endif

#if defined(_XPG7) || !defined(_STRICT_SYMBOLS)
#ifndef	_LOCALE_T
#define	_LOCALE_T
typedef struct locale *locale_t;
#endif

#if defined(__STDC__)
char	*nl_langinfo_l(nl_item, locale_t);
#else
char	*nl_langinfo_l();
#endif
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _LANGINFO_H */
