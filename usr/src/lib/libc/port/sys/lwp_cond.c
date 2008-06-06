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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <sys/types.h>

#include <time.h>
#include <errno.h>
#include <synch.h>
#include <sys/synch32.h>
#include <pthread.h>

extern int ___lwp_cond_wait(lwp_cond_t *, lwp_mutex_t *, timespec_t *, int);
extern int ___lwp_mutex_timedlock(lwp_mutex_t *, timespec_t *);

int
_lwp_cond_wait(cond_t *cv, mutex_t *mp)
{
	int error;

	error = ___lwp_cond_wait(cv, mp, NULL, 0);
	if (mp->mutex_type & (PTHREAD_PRIO_INHERIT|PTHREAD_PRIO_PROTECT))
		(void) ___lwp_mutex_timedlock(mp, NULL);
	else
		(void) _lwp_mutex_lock(mp);
	return (error);
}

int
_lwp_cond_reltimedwait(cond_t *cv, mutex_t *mp, timespec_t *relts)
{
	int error;

	if (relts != NULL &&
	    (relts->tv_sec < 0 || (ulong_t)relts->tv_nsec >= NANOSEC))
		return (EINVAL);
	error = ___lwp_cond_wait(cv, mp, relts, 0);
	if (mp->mutex_type & (PTHREAD_PRIO_INHERIT|PTHREAD_PRIO_PROTECT))
		(void) ___lwp_mutex_timedlock(mp, NULL);
	else
		(void) _lwp_mutex_lock(mp);
	return (error);
}

int
_lwp_cond_timedwait(cond_t *cv, mutex_t *mp, timespec_t *absts)
{
	extern void abstime_to_reltime(clockid_t,
	    const timespec_t *, timespec_t *);
	timespec_t tslocal;

	abstime_to_reltime(CLOCK_REALTIME, absts, &tslocal);
	return (_lwp_cond_reltimedwait(cv, mp, &tslocal));
}
