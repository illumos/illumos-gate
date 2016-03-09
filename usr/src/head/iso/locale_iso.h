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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 * Copyright 2014 PALO, Richard.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <locale.h>.
 */

#ifndef	_ISO_LOCALE_ISO_H
#define	_ISO_LOCALE_ISO_H

#include <sys/feature_tests.h>
#include <sys/null.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __cplusplus >= 199711L
namespace std {
#endif

struct lconv {
	char *decimal_point;
	char *thousands_sep;
	char *grouping;
	char *int_curr_symbol;
	char *currency_symbol;
	char *mon_decimal_point;
	char *mon_thousands_sep;
	char *mon_grouping;
	char *positive_sign;
	char *negative_sign;
	char int_frac_digits;
	char frac_digits;
	char p_cs_precedes;
	char p_sep_by_space;
	char n_cs_precedes;
	char n_sep_by_space;
	char p_sign_posn;
	char n_sign_posn;

/*
 * New in IEEE Std 1003.1-2001 for alignment with the ISO/IEC 9899:1999
 * standard.  Namespace and binary compatibility dictate that visibility
 * of these new members be limited.  Visibility is limited to a strictly
 * conforming ANSI C environment (-Xc) or if _LCONV_C99 is defined.
 */
#if (defined(_STRICT_STDC) && defined(_STDC_C99)) || defined(_LCONV_C99)
	char int_p_cs_precedes;
	char int_p_sep_by_space;
	char int_n_cs_precedes;
	char int_n_sep_by_space;
	char int_p_sign_posn;
	char int_n_sign_posn;
#endif
};

#define	LC_CTYPE	0
#define	LC_NUMERIC	1
#define	LC_TIME		2
#define	LC_COLLATE	3
#define	LC_MONETARY	4
#define	LC_MESSAGES	5
#define	LC_ALL		6

extern char	*setlocale(int, const char *);
extern struct lconv *localeconv(void);

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_LOCALE_ISO_H */
