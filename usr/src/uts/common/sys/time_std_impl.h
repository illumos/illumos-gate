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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Implementation-private header.  An application should not include
 * this header directly.  The definitions contained here are standards
 * namespace safe.  The timespec_t and timestruc_t structures as defined
 * in <sys/time_impl.h>, contain member names that break X/Open and POSIX
 * namespace when included by <sys/stat.h> or <sys/siginfo.h>.  This
 * header was created to provide namespace safe definitions that are
 * made visible only in the X/Open and POSIX compilation environments.
 */

#ifndef _SYS_TIME_STD_IMPL_H
#define	_SYS_TIME_STD_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if !defined(_TIME_T) || __cplusplus >= 199711L
#define	_TIME_T
typedef	long	time_t;		/* time of day in seconds */
#endif	/* _TIME_T */

typedef	struct	_timespec {
	time_t	__tv_sec;	/* seconds */
	long	__tv_nsec;	/* and nanoseconds */
} _timespec_t;

typedef	struct	_timespec	_timestruc_t;	/* definition per SVr4 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TIME_STD_IMPL_H */
