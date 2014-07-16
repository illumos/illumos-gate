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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
 *
 * Portions of this file developed by Garrett D'Amore are licensed
 * under the terms of the Common Development and Distribution License (CDDL)
 * version 1.0 only.  The use of subsequent versions of the License are
 * is specifically prohibited unless those terms are not in conflict with
 * version 1.0 of the License.  You can find this license on-line at
 * http://www.illumos.org/license/CDDL
 */

#ifndef _LOCALE_H
#define	_LOCALE_H

#include <iso/locale_iso.h>

#if (!defined(_STRICT_STDC) && !defined(__XOPEN_OR_POSIX)) || \
	defined(__EXTENSIONS__)
#include <libintl.h>
#endif

/*
 * Allow global visibility for symbols defined in
 * C++ "std" namespace in <iso/locale_iso.h>.
 */
#if __cplusplus >= 199711L
using std::lconv;
using std::setlocale;
using std::localeconv;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	_LastCategory	LC_MESSAGES	/* This must be last category */

#define	_ValidCategory(c) \
	(((int)(c) >= LC_CTYPE) && ((int)(c) <= _LastCategory) || \
	((int)c == LC_ALL))


#if defined(_XPG7) || !defined(_STRICT_SYMBOLS)

/*
 * These were added in POSIX 2008 as part of the newlocale() specification.
 */
#define	LC_CTYPE_MASK		(1 << LC_CTYPE)
#define	LC_NUMERIC_MASK		(1 << LC_NUMERIC)
#define	LC_TIME_MASK		(1 << LC_TIME)
#define	LC_COLLATE_MASK		(1 << LC_COLLATE)
#define	LC_MONETARY_MASK	(1 << LC_MONETARY)
#define	LC_MESSAGES_MASK	(1 << LC_MESSAGES)
#define	LC_ALL_MASK		(0x3f)

#ifndef _LOCALE_T
#define	_LOCALE_T
typedef struct _locale *locale_t;
#endif

#if	defined(__STDC__)
extern locale_t	duplocale(locale_t);
extern void	freelocale(locale_t);
extern locale_t	newlocale(int, const char *, locale_t);
extern locale_t	uselocale(locale_t);
#else	/* __STDC__ */
extern locale_t	duplocale();
extern void	freelocale();
extern locale_t	newlocale();
extern locale_t	uselocale();
#endif	/* __STDC__ */

#define	LC_GLOBAL_LOCALE	(__global_locale())
extern locale_t			__global_locale(void);

#endif	/* defined(_XPG7) || !defined(_STRICT_SYMBOLS) */

#ifdef	__cplusplus
}
#endif

#endif	/* _LOCALE_H */
