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
 *
 * Copyright (c) 1995, 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_STRINGS_H
#define	_STRINGS_H

#include <sys/types.h>
#include <sys/feature_tests.h>

#if !defined(_XOPEN_SOURCE) || defined(__EXTENSIONS__)
#include <string.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

extern int bcmp(const void *, const void *, size_t);
extern void bcopy(const void *, void *, size_t);
extern void bzero(void *, size_t);

extern char *index(const char *, int);
extern char *rindex(const char *, int);

/*
 * X/Open System Interfaces and Headers, Issue 4, Version 2, defines
 * both <string.h> and <strings.h>.  The namespace requirements
 * do not permit the visibility of anything other than what is
 * specifically defined for each of these headers.  As a result,
 * inclusion of <string.h> would result in declarations not allowed
 * in <strings.h>.
 *
 * <strings.h> is not defined by ISO C.  In a strict ISO C environment,
 * explicitly including this header is treated as a request for the
 * interfaces it provides.  _STRICT_POSIX distinguishes that case from
 * strict POSIX and XPG environments, where the requested edition
 * determines which interfaces are visible.
 */
#if !defined(_STRICT_POSIX) || defined(_XPG4_2)
extern int ffs(int);
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, size_t);
#endif /* !_STRICT_POSIX || _XPG4_2 */

#if !defined(_STRICT_POSIX) || defined(_XPG7)
#ifndef	_LOCALE_T
#define	_LOCALE_T
typedef struct _locale *locale_t;
#endif
extern int strcasecmp_l(const char *, const char *, locale_t);
extern int strncasecmp_l(const char *, const char *, size_t, locale_t);
#endif	/* !_STRICT_POSIX || _XPG7 */

#if !defined(_STRICT_POSIX) || defined(_XPG8)
extern int ffsl(long);
extern int ffsll(long long);
#endif	/* !_STRICT_POSIX || _XPG8 */

#ifdef	__cplusplus
}
#endif

#endif	/* _STRINGS_H */
