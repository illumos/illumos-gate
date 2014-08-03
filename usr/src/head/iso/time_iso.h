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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * An application should not include this header directly.  Instead it
 * should be included only through the inclusion of other Sun headers.
 *
 * The contents of this header is limited to identifiers specified in the
 * C Standard.  Any new identifiers specified in future amendments to the
 * C Standard must be placed in this header.  If these new identifiers
 * are required to also be in the C++ Standard "std" namespace, then for
 * anything other than macro definitions, corresponding "using" directives
 * must also be added to <time.h.h>.
 */

#ifndef _ISO_TIME_ISO_H
#define	_ISO_TIME_ISO_H

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if __cplusplus >= 199711L
namespace std {
#endif

#ifndef NULL
#if defined(_LP64)
#define	NULL	0L
#else
#define	NULL	0
#endif
#endif

#if !defined(_SIZE_T) || __cplusplus >= 199711L
#define	_SIZE_T
#if defined(_LP64) || defined(_I32LPx)
typedef	unsigned long	size_t;		/* size of something in bytes */
#else
typedef unsigned	size_t;		/* (historical version) */
#endif
#endif	/* !_SIZE_T */

#if !defined(_CLOCK_T) || __cplusplus >= 199711L
#define	_CLOCK_T
typedef	long	clock_t;
#endif	/* !_CLOCK_T */

#if !defined(_TIME_T) || __cplusplus >= 199711L
#define	_TIME_T
typedef	long	time_t;
#endif	/* !_TIME_T */

#define	CLOCKS_PER_SEC		1000000L

struct	tm {	/* see ctime(3) */
	int	tm_sec;
	int	tm_min;
	int	tm_hour;
	int	tm_mday;
	int	tm_mon;
	int	tm_year;
	int	tm_wday;
	int	tm_yday;
	int	tm_isdst;
};


extern char *asctime(const struct tm *);
extern clock_t clock(void);
extern char *ctime(const time_t *);
extern double difftime(time_t, time_t);
extern struct tm *gmtime(const time_t *);
extern struct tm *localtime(const time_t *);
extern time_t mktime(struct tm *);
extern time_t time(time_t *);
extern size_t strftime(char *_RESTRICT_KYWD, size_t, const char *_RESTRICT_KYWD,
	const struct tm *_RESTRICT_KYWD);

#if __cplusplus >= 199711L
}
#endif /* end of namespace std */

#ifdef	__cplusplus
}
#endif

#endif	/* _ISO_TIME_ISO_H */
