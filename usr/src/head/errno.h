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
/*	  All Rights Reserved	*/


/*
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _ERRNO_H
#define	_ERRNO_H

/*
 * Error codes
 */

#include <sys/errno.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_LP64)
/*
 * The symbols _sys_errlist and _sys_nerr are not visible in the
 * LP64 libc.  Use strerror(3C) instead.
 */
#endif /* _LP64 */

#if defined(_REENTRANT) || defined(_TS_ERRNO) || _POSIX_C_SOURCE - 0 >= 199506L
extern int *___errno();
#define	errno (*(___errno()))
#else
extern int errno;
/* ANSI C++ requires that errno be a macro */
#if __cplusplus >= 199711L
#define	errno errno
#endif
#endif	/* defined(_REENTRANT) || defined(_TS_ERRNO) */

#ifdef	__cplusplus
}
#endif

#endif	/* _ERRNO_H */
