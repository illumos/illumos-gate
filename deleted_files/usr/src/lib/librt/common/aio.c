/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The POSIX async. I/O functionality is
 * implemented in libaio/common/posix_aio.c
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak close = __posix_aio_close

#include "c_synonyms.h"
#include <aio.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include "pos4.h"
#include "sigev_thread.h"

extern int _libaio_close(int fd);

/*
 * There is but one spawner for all aio operations.
 */
thread_communication_data_t *sigev_aio_tcd = NULL;

mutex_t sigev_aio_lock = DEFAULTMUTEX;
cond_t sigev_aio_cv = DEFAULTCV;
int sigev_aio_busy = 0;

static int
__sigev_thread_init(struct sigevent *sigevp)
{
	thread_communication_data_t *tcdp;
	int port;
	int rc = 0;

	(void) mutex_lock(&sigev_aio_lock);
	while (sigev_aio_busy)
		(void) cond_wait(&sigev_aio_cv, &sigev_aio_lock);
	if ((tcdp = sigev_aio_tcd) != NULL)
		port = tcdp->tcd_port;
	else {
		sigev_aio_busy = 1;
		(void) mutex_unlock(&sigev_aio_lock);

		tcdp = setup_sigev_handler(sigevp, AIO);
		if (tcdp == NULL) {
			port = -1;
			rc = -1;
		} else if (launch_spawner(tcdp) != 0) {
			free_sigev_handler(tcdp);
			tcdp = NULL;
			port = -1;
			rc = -1;
		} else {
			port = tcdp->tcd_port;
		}

		(void) mutex_lock(&sigev_aio_lock);
		sigev_aio_tcd = tcdp;
		sigev_aio_busy = 0;
		(void) cond_broadcast(&sigev_aio_cv);
	}
	(void) mutex_unlock(&sigev_aio_lock);
	sigevp->sigev_signo = port;
	return (rc);
}

static int
__posix_sigev_thread(aiocb_t *aiocbp)
{
	struct sigevent *sigevp;

	if (aiocbp != NULL) {
		sigevp = &aiocbp->aio_sigevent;
		if (sigevp->sigev_notify == SIGEV_THREAD &&
		    sigevp->sigev_notify_function != NULL)
			return (__sigev_thread_init(sigevp));
	}
	return (0);
}

#if !defined(_LP64)
static int
__posix_sigev_thread64(aiocb64_t *aiocbp)
{
	struct sigevent *sigevp;

	if (aiocbp != NULL) {
		sigevp = &aiocbp->aio_sigevent;
		if (sigevp->sigev_notify == SIGEV_THREAD &&
		    sigevp->sigev_notify_function != NULL)
			return (__sigev_thread_init(sigevp));
	}
	return (0);
}
#endif

int
__posix_aio_close(int fd)
{
	return (_libaio_close(fd));
}

int
aio_cancel(int fildes, aiocb_t *aiocbp)
{
	return (__aio_cancel(fildes, aiocbp));
}

#if !defined(_LP64)

int
aio_cancel64(int fildes, aiocb64_t *aiocbp)
{
	return (__aio_cancel64(fildes, aiocbp));
}

#endif

int
aio_error(const aiocb_t *aiocbp)
{
	return (__aio_error(aiocbp));
}

#if !defined(_LP64)

int
aio_error64(const aiocb64_t *aiocbp)
{
	return (__aio_error64(aiocbp));
}

#endif

int
aio_fsync(int op, aiocb_t *aiocbp)
{
	int rc;

	if ((rc = __posix_sigev_thread(aiocbp)) == 0)
		rc = __aio_fsync(op, aiocbp);
	return (rc);

}

#if !defined(_LP64)

int
aio_fsync64(int op, aiocb64_t *aiocbp)
{
	int rc;

	if ((rc = __posix_sigev_thread64(aiocbp)) == 0)
		rc = __aio_fsync64(op, aiocbp);
	return (rc);
}

#endif

int
aio_read(aiocb_t *aiocbp)
{
	int rc;

	if ((rc = __posix_sigev_thread(aiocbp)) == 0)
		rc = __aio_read(aiocbp);
	return (rc);
}

#if !defined(_LP64)

int
aio_read64(aiocb64_t *aiocbp)
{
	int rc;

	if ((rc = __posix_sigev_thread64(aiocbp)) == 0)
		rc = __aio_read64(aiocbp);
	return (rc);
}

#endif

ssize_t
aio_return(aiocb_t *aiocbp)
{
	return (__aio_return(aiocbp));
}

#if !defined(_LP64)

ssize_t
aio_return64(aiocb64_t *aiocbp)
{
	return (__aio_return64(aiocbp));
}

#endif

int
aio_suspend(const aiocb_t * const list[], int nent,
    const timespec_t *timeout)
{
	return (__aio_suspend((void **)list, nent, timeout, 0));
}

#if !defined(_LP64)

int
aio_suspend64(const aiocb64_t * const list[], int nent,
    const timespec_t *timeout)
{
	return (__aio_suspend((void **)list, nent, timeout, 1));
}

#endif

int
aio_write(aiocb_t *aiocbp)
{
	int rc;

	if ((rc = __posix_sigev_thread(aiocbp)) == 0)
		rc = __aio_write(aiocbp);
	return (rc);
}

#if !defined(_LP64)

int
aio_write64(aiocb64_t *aiocbp)
{
	int rc;

	if ((rc = __posix_sigev_thread64(aiocbp)) == 0)
		rc = __aio_write64(aiocbp);
	return (rc);
}

#endif

int
lio_listio(int mode,
	aiocb_t *_RESTRICT_KYWD const *_RESTRICT_KYWD list,
	int nent, struct sigevent *_RESTRICT_KYWD sigevp)
{
	int i;
	aiocb_t *aiocbp;

	for (i = 0; i < nent; i++) {
		if ((aiocbp = list[i]) != NULL &&
		    aiocbp->aio_sigevent.sigev_notify == SIGEV_THREAD &&
		    __posix_sigev_thread(aiocbp) != 0)
			return (-1);
	}
	if (sigevp != NULL &&
	    sigevp->sigev_notify == SIGEV_THREAD &&
	    sigevp->sigev_notify_function != NULL &&
	    __sigev_thread_init(sigevp) != 0)
		return (-1);

	return (__lio_listio(mode, list, nent, sigevp));
}

#if !defined(_LP64)

int
lio_listio64(int mode,
	aiocb64_t *_RESTRICT_KYWD const *_RESTRICT_KYWD list,
	int nent, struct sigevent *_RESTRICT_KYWD sigevp)
{
	int i;
	aiocb64_t *aiocbp;

	for (i = 0; i < nent; i++) {
		if ((aiocbp = list[i]) != NULL &&
		    aiocbp->aio_sigevent.sigev_notify == SIGEV_THREAD &&
		    __posix_sigev_thread64(aiocbp) != 0)
			return (-1);
	}
	if (sigevp != NULL &&
	    sigevp->sigev_notify == SIGEV_THREAD &&
	    sigevp->sigev_notify_function != NULL &&
	    __sigev_thread_init(sigevp) != 0)
		return (-1);

	return (__lio_listio64(mode, list, nent, sigevp));
}

#endif


int
aio_waitn(aiocb_t *list[], uint_t nent, uint_t *nwait,
	const timespec_t *timeout)
{
	return (__aio_waitn((void **)list, nent, nwait, timeout));
}

#if !defined(_LP64)

int
aio_waitn64(aiocb64_t *list[], uint_t nent, uint_t *nwait,
	const timespec_t *timeout)
{
	return (__aio_waitn((void **)list, nent, nwait, timeout));
}

#endif
