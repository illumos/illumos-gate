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
 * Copyright (c) 1991 by Sun Microsystems, Inc.
 */

#ifndef _SYS_ASYNCH_H
#define	_SYS_ASYNCH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/feature_tests.h>
#include <sys/types.h>
#include <sys/aio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	AIO_INPROGRESS	-2	/* values not set by the system */

/* large file compilation environment setup */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma redefine_extname	aioread		aioread64
#pragma redefine_extname	aiowrite	aiowrite64
#else
#define	aioread			aioread64
#define	aiowrite		aiowrite64
#endif
#endif /* _FILE_OFFSET_BITS */

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	aioread64	aioread
#pragma	redefine_extname	aiowrite64	aiowrite
#else
#define	aioread64	aioread
#define	aiowrite64	aiowrite
#endif
#endif	/* _LP64 && _LARGEFILE64_SOURCE */
extern int aioread(int, caddr_t, int, off_t, int, aio_result_t *);
extern int aiowrite(int, caddr_t, int, off_t, int, aio_result_t *);
extern int aiocancel(aio_result_t *);
extern aio_result_t *aiowait(struct timeval *);

/* transitional large file interfaces */
#if	defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	    !defined(__PRAGMA_REDEFINE_EXTNAME))
extern int aioread64(int, caddr_t, int, off64_t, int, aio_result_t *);
extern int aiowrite64(int, caddr_t, int, off64_t, int, aio_result_t *);
#endif	/* _LARGEFILE64_SOURCE... */

#define	MAXASYNCHIO 200		/* maxi.number of outstanding i/o's */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_ASYNCH_H */
