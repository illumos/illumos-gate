/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014-2016 PALO, Richard.
 */

#ifndef _SYS_NULL_H
#define	_SYS_NULL_H

#include <sys/feature_tests.h>

#ifndef	NULL

/*
 * POSIX.1-2008 requires that the NULL macro be cast to type void *.
 * Historically, this has not been done, so we only enable this in a
 * POSIX.1-2008 compilation environment.
 */

#if defined(_XPG7) && !defined(__cplusplus)
#define	NULL	((void *)0)
#else

/*
 * ISO C++ requires that the NULL macro be a constant integral type evaluating
 * to zero until C++11, and an integer or pointer literal with value zero from
 * C++11 onwards.
 */

#if defined(__cplusplus) && __cplusplus >= 201103L
#define	NULL	nullptr
#else
#if defined(_LP64)
#define	NULL	0L
#else
#define	NULL	0
#endif	/* _LP64 */
#endif	/* C++11 */
#endif	/* _XPG7 */

#endif	/* NULL */

#endif	/* _SYS_NULL_H */
