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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <sys/rwstlock.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/lockstat.h>
#include <sys/sysmacros.h>
#include <sys/condvar_impl.h>

/*
 * Alternate rwlock that is interruptible and can be released by a thread
 * other than the one that acquired the lock.
 *
 * There is no priority inheritance mechanism for these locks.
 * For RW_READER, writers have priority over readers, so reader starvation
 * is possible; as with rwlocks, this behavior may be overridden by
 * specifying RW_READER_STARVEWRITER.
 */

/*
 * Common code to grab a lock.  There are three cases:
 *
 * (1) If RWST_TRYENTER is set, we try the lock without blocking.
 *     In this case we return 1 on success, 0 on failure.
 *
 * (2) If RWST_SIG is set, we block interruptibly until we get the lock.
 *     In this case we return 0 on success, EINTR if we're interrupted.
 *
 * (3) If neither flag is set, we block uninterruptibly until we get the lock.
 *     In this case we return 0 (we always succeed).
 */
static int
rwst_enter_common(rwstlock_t *l, krw_t rw, int flags)
{
	hrtime_t sleep_time;
	int writer;
	intptr_t readers;

	mutex_enter(&l->rwst_lock);
	if (rw == RW_READER || rw == RW_READER_STARVEWRITER) {
		while (RWST_WRITE_HELD(l) ||
		    (rw != RW_READER_STARVEWRITER && RWST_WRITE_WANTED(l))) {

			if (flags & RWST_TRYENTER) {
				mutex_exit(&l->rwst_lock);
				return (0);
			}
			if (panicstr)
				return (0);

			if (RWST_WRITE_HELD(l)) {
				writer = 1;
				readers = 0;
			} else {
				writer = 0;
				readers = l->rwst_count;
			}
			sleep_time = -gethrtime();
			if (!RWST_READ_WAIT(l, flags)) {
				mutex_exit(&l->rwst_lock);
				return (EINTR);
			}
			sleep_time += gethrtime();
			LOCKSTAT_RECORD4(LS_RW_ENTER_BLOCK, l, sleep_time, rw,
			    writer, readers);
		}
		RWST_READ_ENTER(l);
		LOCKSTAT_RECORD(LS_RW_ENTER_ACQUIRE, l, rw);
	} else {
		ASSERT(rw == RW_WRITER);
		while (RWST_HELD(l)) {
			if (flags & RWST_TRYENTER) {
				mutex_exit(&l->rwst_lock);
				return (0);
			}
			if (panicstr)
				return (0);
			if (RWST_WRITE_HELD(l)) {
				writer = 1;
				readers = 0;
			} else {
				writer = 0;
				readers = l->rwst_count;
			}
			sleep_time = -gethrtime();
			if (!RWST_WRITE_WAIT(l, flags)) {
				if (!RWST_WRITE_HELD(l) &&
				    !RWST_WRITE_WANTED(l))
					RWST_READ_WAKE_ALL(l);
				mutex_exit(&l->rwst_lock);
				return (EINTR);
			}
			sleep_time += gethrtime();
			LOCKSTAT_RECORD4(LS_RW_ENTER_BLOCK, l, sleep_time, rw,
			    writer, readers);
		}
		RWST_WRITE_ENTER(l);
		LOCKSTAT_RECORD(LS_RW_ENTER_ACQUIRE, l, rw);
	}
	mutex_exit(&l->rwst_lock);
	return (flags & RWST_TRYENTER);
}

void
rwst_exit(rwstlock_t *l)
{
	mutex_enter(&l->rwst_lock);
	if (RWST_WRITE_HELD(l)) {
		LOCKSTAT_RECORD(LS_RW_EXIT_RELEASE, l, RW_WRITER);
		RWST_WRITE_EXIT(l);
	} else {
		ASSERT(RWST_READ_HELD(l));
		LOCKSTAT_RECORD(LS_RW_EXIT_RELEASE, l, RW_READER);
		RWST_READ_EXIT(l);
	}
	if (!RWST_WRITE_WANTED(l))
		RWST_READ_WAKE_ALL(l);
	else if (!RWST_HELD(l))
		RWST_WRITE_WAKE_ONE(l);
	mutex_exit(&l->rwst_lock);
}

void
rwst_enter(rwstlock_t *l, krw_t rw)
{
	(void) rwst_enter_common(l, rw, 0);
}

int
rwst_enter_sig(rwstlock_t *l, krw_t rw)
{
	return (rwst_enter_common(l, rw, RWST_SIG));
}

int
rwst_tryenter(rwstlock_t *l, krw_t rw)
{
	return (rwst_enter_common(l, rw, RWST_TRYENTER));
}

int
rwst_lock_held(rwstlock_t *l, krw_t rw)
{
	if (rw != RW_WRITER)
		return (RWST_READ_HELD(l));
	ASSERT(rw == RW_WRITER);
	return (RWST_WRITE_OWNER(l));
}

/*ARGSUSED*/
void
rwst_init(rwstlock_t *l, char *name, krw_type_t krw_t, void *arg)
{
	l->rwst_count = 0;
	mutex_init(&l->rwst_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&l->rwst_rcv, NULL, CV_DEFAULT, NULL);
	cv_init(&l->rwst_wcv, NULL, CV_DEFAULT, NULL);
}

void
rwst_destroy(rwstlock_t *l)
{
	ASSERT(l->rwst_count == 0);
	mutex_destroy(&l->rwst_lock);
	cv_destroy(&l->rwst_rcv);
	cv_destroy(&l->rwst_wcv);
}

struct _kthread *
rwst_owner(rwstlock_t *l)
{
	return (RWST_OWNER(l));
}
