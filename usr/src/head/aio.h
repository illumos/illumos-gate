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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _AIO_H
#define	_AIO_H

#include <sys/feature_tests.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/siginfo.h>
#include <sys/aiocb.h>
#include <time.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if	(_POSIX_C_SOURCE - 0 > 0) && (_POSIX_C_SOURCE - 0 <= 2)
#error	"POSIX Asynchronous I/O is not supported in POSIX.1-1990"
#endif

/* large file compilation environment setup */
#if !defined(_LP64) && _FILE_OFFSET_BITS == 64
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	aio_read	aio_read64
#pragma	redefine_extname	aio_write	aio_write64
#pragma	redefine_extname	lio_listio	lio_listio64
#pragma	redefine_extname	aio_error	aio_error64
#pragma	redefine_extname	aio_return	aio_return64
#pragma	redefine_extname	aio_cancel	aio_cancel64
#pragma	redefine_extname	aio_suspend	aio_suspend64
#pragma	redefine_extname	aio_fsync	aio_fsync64
#pragma	redefine_extname	aio_waitn	aio_waitn64
#else
#define	aiocb		aiocb64
#define	aiocb_t		aiocb64_t
#define	aio_read	aio_read64
#define	aio_write	aio_write64
#define	lio_listio	lio_listio64
#define	aio_error	aio_error64
#define	aio_return	aio_return64
#define	aio_cancel	aio_cancel64
#define	aio_suspend	aio_suspend64
#define	aio_fsync	aio_fsync64
#define	aio_waitn	aio_waitn64
#endif
#endif /* !_LP64 && _FILE_OFFSET_BITS == 64 */

#if defined(_LP64) && defined(_LARGEFILE64_SOURCE)
/*
 * In the LP64 compilation environment, map the 64-bit-explicit versions
 * back to the generic versions: all i/o operations are already "large file"
 */
#ifdef __PRAGMA_REDEFINE_EXTNAME
#pragma	redefine_extname	aio_read64	aio_read
#pragma	redefine_extname	aio_write64	aio_write
#pragma	redefine_extname	lio_listio64	lio_listio
#pragma	redefine_extname	aio_error64	aio_error
#pragma	redefine_extname	aio_return64	aio_return
#pragma	redefine_extname	aio_cancel64	aio_cancel
#pragma	redefine_extname	aio_suspend64	aio_suspend
#pragma	redefine_extname	aio_fsync64	aio_fsync
#pragma	redefine_extname	aio_waitn64	aio_waitn
#else
#define	aiocb64		aiocb
#define	aiocb64_t	aiocb_t
#define	aio_read64	aio_read
#define	aio_write64	aio_write
#define	lio_listio64	lio_listio
#define	aio_error64	aio_error
#define	aio_return64	aio_return
#define	aio_cancel64	aio_cancel
#define	aio_suspend64	aio_suspend
#define	aio_fsync64	aio_fsync
#define	aio_waitn64	aio_waitn
#endif
#endif	/* _LP64 && _LARGEFILE64_SOURCE */

/*
 * function prototypes
 */
extern int	aio_read(aiocb_t *);
extern int	aio_write(aiocb_t *);
extern int	lio_listio(int,
		    aiocb_t *_RESTRICT_KYWD const *_RESTRICT_KYWD,
		    int, struct sigevent *_RESTRICT_KYWD);
extern int	aio_error(const aiocb_t *);
extern ssize_t	aio_return(aiocb_t *);
extern int	aio_cancel(int, aiocb_t *);
extern int	aio_suspend(const aiocb_t *const[], int,
		    const struct timespec *);
extern int	aio_fsync(int, aiocb_t *);
extern int	aio_waitn(aiocb_t *[], uint_t, uint_t *,
		    const struct timespec *);


#if defined(_LARGEFILE64_SOURCE) && !((_FILE_OFFSET_BITS == 64) && \
	!defined(__PRAGMA_REDEFINE_EXTNAME))
extern int	aio_read64(aiocb64_t *);
extern int	aio_write64(aiocb64_t *);
extern int	lio_listio64(int,
			aiocb64_t *_RESTRICT_KYWD const *_RESTRICT_KYWD,
			int, struct sigevent *_RESTRICT_KYWD);
extern int	aio_error64(const aiocb64_t *);
extern ssize_t	aio_return64(aiocb64_t *);
extern int	aio_cancel64(int, aiocb64_t *);
extern int	aio_suspend64(const aiocb64_t *const[], int,
			const struct timespec *);
extern int	aio_fsync64(int, aiocb64_t *);
extern int	aio_waitn64(aiocb64_t *[], uint_t, uint_t *,
		    const struct timespec *);
#endif	/* _LARGEFILE64_SOURCE */

#ifdef	__cplusplus
}
#endif

#endif	/* _AIO_H */
