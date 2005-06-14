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
 * The POSIX async. I/O functionality is
 * implemented in libaio/common/posix_aio.c
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <aio.h>
#include <sys/types.h>
#include <errno.h>
#include "pos4.h"

#pragma weak close = __posix_aio_close
#pragma weak fork = __posix_aio_fork

extern int _libaio_close(int fd);
extern pid_t _libaio_fork(void);

int
__posix_aio_close(int fd)
{
	return (_libaio_close(fd));
}

pid_t
__posix_aio_fork(void)
{
	return (_libaio_fork());
}

int
aio_cancel(int fildes, struct aiocb *aiocbp)
{
	return (__aio_cancel(fildes, aiocbp));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
aio_cancel64(int fildes, struct aiocb64 *aiocbp)
{
	return (__aio_cancel64(fildes, aiocbp));
}

#endif

int
aio_error(const struct aiocb *aiocbp)
{
	return (__aio_error(aiocbp));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
aio_error64(const struct aiocb64 *aiocbp)
{
	return (__aio_error64(aiocbp));
}

#endif

int
aio_fsync(int op, struct aiocb *aiocbp)
{
	return (__aio_fsync(op, aiocbp));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
aio_fsync64(int op, struct aiocb64 *aiocbp)
{
	return (__aio_fsync64(op, aiocbp));
}

#endif

int
aio_read(struct aiocb *aiocbp)
{
	return (__aio_read(aiocbp));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
aio_read64(struct aiocb64 *aiocbp)
{
	return (__aio_read64(aiocbp));
}

#endif

ssize_t
aio_return(struct aiocb *aiocbp)
{
	return (__aio_return(aiocbp));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

ssize_t
aio_return64(struct aiocb64 *aiocbp)
{
	return (__aio_return64(aiocbp));
}

#endif

int
aio_suspend(const struct aiocb * const list[], int nent,
    const struct timespec *timeout)
{
	return (__aio_suspend((void **)list, nent, timeout, 0));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
aio_suspend64(const struct aiocb64 * const list[], int nent,
    const struct timespec *timeout)
{
	return (__aio_suspend((void **)list, nent, timeout, 1));
}

#endif

int
aio_write(struct aiocb *aiocbp)
{
	return (__aio_write(aiocbp));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
aio_write64(struct aiocb64 *aiocbp)
{
	return (__aio_write64(aiocbp));
}

#endif

int
lio_listio(int mode,
	struct aiocb *_RESTRICT_KYWD const *_RESTRICT_KYWD list,
	int nent, struct sigevent *_RESTRICT_KYWD sig)
{
	return (__lio_listio(mode, list, nent, sig));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
lio_listio64(int mode,
	struct aiocb64 *_RESTRICT_KYWD const *_RESTRICT_KYWD list,
	int nent, struct sigevent *_RESTRICT_KYWD sig)
{
	return (__lio_listio64(mode, list, nent, sig));
}

#endif


int
aio_waitn(aiocb_t *list[], uint_t nent, uint_t *nwait,
	const struct timespec *timeout)
{
	return (__aio_waitn((void **)list, nent, nwait, timeout, 0));
}

#if defined(_LARGEFILE64_SOURCE) && !defined(_LP64)

int
aio_waitn64(aiocb64_t *list[], uint_t nent, uint_t *nwait,
	const struct timespec *timeout)
{
	return (__aio_waitn((void **)list, nent, nwait, timeout, 1));
}

#endif
