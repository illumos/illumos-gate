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
 * These are largely extern definitions for functions that librt
 * finds elsewhere (in libaio or libc).
 */

#ifndef	_POS4_H
#define	_POS4_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <aio.h>
#include <time.h>
#include <signal.h>
#include <siginfo.h>
#include <unistd.h>
#include <semaphore.h>

extern int __aio_cancel(int, aiocb_t *);
extern int __aio_cancel64(int, aiocb64_t *);
extern int __aio_error(const aiocb_t *);
extern int __aio_error64(const aiocb64_t *);
extern int __aio_fsync(int, aiocb_t *);
extern int __aio_fsync64(int, aiocb64_t *);
extern int __aio_read(aiocb_t *);
extern int __aio_read64(aiocb64_t *);
extern ssize_t __aio_return(aiocb_t *);
extern ssize_t __aio_return64(aiocb64_t *);
extern int __aio_suspend(void **, int, const timespec_t *, int);
extern int __aio_write(aiocb_t *);
extern int __aio_write64(aiocb64_t *);
extern int __lio_listio(int,
	aiocb_t *_RESTRICT_KYWD const *_RESTRICT_KYWD list,
	int, struct sigevent *_RESTRICT_KYWD);
extern int __lio_listio64(int,
	aiocb64_t *_RESTRICT_KYWD const *_RESTRICT_KYWD list,
	int, struct sigevent *_RESTRICT_KYWD);
extern int __aio_waitn(void **list, uint_t, uint_t *, const timespec_t *);

extern int __clock_getres(clockid_t, timespec_t *);
extern int __clock_gettime(clockid_t, timespec_t *);
extern int __clock_settime(clockid_t, const timespec_t *);
extern int __timer_create(clockid_t, struct sigevent *, timer_t *);
extern int __timer_delete(timer_t);
extern int __timer_getoverrun(timer_t);
extern int __timer_gettime(timer_t, itimerspec_t *);
extern int __timer_settime(timer_t, int, const itimerspec_t *, itimerspec_t *);

extern int __clock_nanosleep(clockid_t, int, const timespec_t *, timespec_t *);
extern int __nanosleep(const timespec_t *, timespec_t *);

extern int __sigtimedwait(const sigset_t *, siginfo_t *,
	const timespec_t *);
extern int __sigqueue(pid_t pid, int signo,
	/* const union sigval */ void *value, int si_code);
extern void _thr_yield(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _POS4_H */
