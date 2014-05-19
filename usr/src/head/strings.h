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
 * Copyright (c) 1995, 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */
/*
 * Copyright 2013 Garrett D'Amore <garrett@damore.org>
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

#if defined(__STDC__)

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
 * in <strings.h>, and making the following prototypes visible for
 * anything other than X/Open UNIX Extension would result in
 * conflicts with what is now in <string.h>.
 */
#if defined(_XPG4_2) && !defined(__EXTENSIONS__)
extern int ffs(int);
extern int strcasecmp(const char *, const char *);
extern int strncasecmp(const char *, const char *, size_t);
#if defined(_XPG7)
#ifndef	_LOCALE_T
#define	_LOCALE_T
typedef struct locale *locale_t;
#endif
extern int strcasecmp_l(const char *, const char *, locale_t);
extern int strncasecmp_l(const char *, const char *, size_t, locale_t);
#endif	/* defined(_XPG7) */
#endif	/* defined(_XPG4_2) && !defined(__EXTENSIONS__) */

#else

extern int bcmp();
extern void bcopy();
extern void bzero();

extern char *index();
extern char *rindex();

#if defined(_XPG4_2) && !defined(__EXTENSIONS__)
extern int ffs();
extern int strcasecmp();
extern int strncasecmp();
#if defined(_XPG7)
extern int strcasecmp_l();
extern int strncasecmp_l();
#endif
#endif /* defined(_XPG4_2) && !defined(__EXTENSIONS__) */

#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _STRINGS_H */
