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
 * Copyright (c) 1994, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mhd_local.h"

/*
 * manipulate conditional variables, handle errors
 */
void
mhd_cv_init(
	cond_t	*cvp
)
{
	if (cond_init(cvp, USYNC_THREAD, NULL) != 0) {
		mhd_perror("cond_init");
		mhd_exit(1);
	}
}

void
mhd_cv_destroy(
	cond_t	*cvp
)
{
	if (cond_destroy(cvp) != 0) {
		mhd_perror("cond_destroy");
		mhd_exit(1);
	}
}

void
mhd_cv_wait(
	cond_t	*cvp,
	mutex_t	*mp
)
{
	int	err;

	assert(MUTEX_HELD(mp));
	if (((err = cond_wait(cvp, mp)) != 0) &&
	    (err != EINTR)) {
		errno = err;
		mhd_perror("cond_wait");
		mhd_exit(1);
	}
}

void
mhd_cv_timedwait(
	cond_t			*cvp,
	mutex_t			*mp,
	mhd_msec_t		to
)
{
	struct itimerval	new, old;
	int			err;

	/* check lock */
	assert(MUTEX_HELD(mp));
	assert(to != 0);

	/* set timer */
	new.it_interval.tv_sec = 0;
	new.it_interval.tv_usec = 0;
	new.it_value.tv_sec = to / 1000;
	new.it_value.tv_usec = (to % 1000) * 1000;
	if (setitimer(ITIMER_REAL, &new, &old) != 0) {
		mhd_perror("cond_wait");
		mhd_exit(1);
	}

	/* wait for condition or timeout */
	if (((err = cond_wait(cvp, mp)) != 0) &&
	    (err != EINTR)) {
		errno = err;
		mhd_perror("cond_wait");
		mhd_exit(1);
	}

	/* reset timer */
	if (err != EINTR) {
		new.it_interval.tv_sec = 0;
		new.it_interval.tv_usec = 0;
		new.it_value.tv_sec = 0;
		new.it_value.tv_usec = 0;
		if (setitimer(ITIMER_REAL, &new, &old) != 0) {
			mhd_perror("cond_wait");
			mhd_exit(1);
		}
	}
}

void
mhd_cv_broadcast(
	cond_t	*cvp
)
{
	if (cond_broadcast(cvp) != 0) {
		mhd_perror("cond_broadcast");
		mhd_exit(1);
	}
}

/*
 * manipulate mutexs, handle errors
 */
void
mhd_mx_init(
	mutex_t	*mp
)
{
	if (mutex_init(mp, USYNC_THREAD, NULL) != 0) {
		mhd_perror("mutex_init");
		mhd_exit(1);
	}
}

void
mhd_mx_destroy(
	mutex_t	*mp
)
{
	if (mutex_destroy(mp) != 0) {
		mhd_perror("mutex_destroy");
		mhd_exit(1);
	}
}

void
mhd_mx_lock(
	mutex_t	*mp
)
{
	if (mutex_lock(mp) != 0) {
		mhd_perror("mutex_lock");
		mhd_exit(1);
	}
}

void
mhd_mx_unlock(
	mutex_t	*mp
)
{
	assert(MUTEX_HELD(mp));
	if (mutex_unlock(mp) != 0) {
		mhd_perror("mutex_unlock");
		mhd_exit(1);
	}
}

/*
 * manipulate rwlockss, handle errors
 */
void
mhd_rw_rdlock(
	rwlock_t	*rwlp
)
{
	if (rw_rdlock(rwlp) != 0) {
		mhd_perror("rw_rdlock");
		mhd_exit(1);
	}
}

void
mhd_rw_wrlock(
	rwlock_t	*rwlp
)
{
	if (rw_wrlock(rwlp) != 0) {
		mhd_perror("rw_wrlock");
		mhd_exit(1);
	}
}

void
mhd_rw_unlock(
	rwlock_t	*rwlp
)
{
	if (rw_unlock(rwlp) != 0) {
		mhd_perror("rw_unlock");
		mhd_exit(1);
	}
}
