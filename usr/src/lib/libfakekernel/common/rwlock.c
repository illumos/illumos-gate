/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * rwlock(9f)
 */

/* This is the API we're emulating */
#include <sys/rwlock.h>

#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/param.h>
#include <sys/synch32.h>
#include <sys/thread.h>

/* avoiding synch.h */
int	rwlock_init(lwp_rwlock_t *, int, void *);
int	rwlock_destroy(lwp_rwlock_t *);
int	rw_rdlock(lwp_rwlock_t *);
int	rw_wrlock(lwp_rwlock_t *);
int	rw_unlock(lwp_rwlock_t *);
int	rw_tryrdlock(lwp_rwlock_t *);
int	rw_trywrlock(lwp_rwlock_t *);
int	_rw_read_held(void *);
int	_rw_write_held(void *);

/*ARGSUSED*/
void
rw_init(krwlock_t *rwlp, char *name, krw_type_t type, void *arg)
{
	(void) rwlock_init(&rwlp->rw_lock, USYNC_THREAD, NULL);
	rwlp->rw_owner = _KTHREAD_INVALID;
}

void
rw_destroy(krwlock_t *rwlp)
{
	(void) rwlock_destroy(&rwlp->rw_lock);
	rwlp->rw_owner = _KTHREAD_INVALID;
}

void
rw_enter(krwlock_t *rwlp, krw_t rw)
{
	int rc;

	if (rw == RW_READER) {
		rc = rw_rdlock(&rwlp->rw_lock);
	} else {
		rc = rw_wrlock(&rwlp->rw_lock);
		rwlp->rw_owner = _curthread();
	}
	VERIFY(rc == 0);
}

void
rw_exit(krwlock_t *rwlp)
{
	if (_rw_write_held(&rwlp->rw_lock)) {
		ASSERT(rwlp->rw_owner == _curthread());
		rwlp->rw_owner = _KTHREAD_INVALID;
	}
	(void) rw_unlock(&rwlp->rw_lock);
}

int
rw_tryenter(krwlock_t *rwlp, krw_t rw)
{
	int rv;

	if (rw == RW_WRITER) {
		rv = rw_trywrlock(&rwlp->rw_lock);
		if (rv == 0)
			rwlp->rw_owner = _curthread();
	} else
		rv = rw_tryrdlock(&rwlp->rw_lock);

	return ((rv == 0) ? 1 : 0);
}

/*ARGSUSED*/
int
rw_tryupgrade(krwlock_t *rwlp)
{

	return (0);
}

void
rw_downgrade(krwlock_t *rwlp)
{
	ASSERT(rwlp->rw_owner == _curthread());
	rwlp->rw_owner = _KTHREAD_INVALID;
	VERIFY(rw_unlock(&rwlp->rw_lock) == 0);
	VERIFY(rw_rdlock(&rwlp->rw_lock) == 0);
}

int
rw_read_held(krwlock_t *rwlp)
{
	return (_rw_read_held(rwlp));
}

int
rw_write_held(krwlock_t *rwlp)
{
	return (_rw_write_held(rwlp));
}

int
rw_lock_held(krwlock_t *rwlp)
{
	return (rw_read_held(rwlp) || rw_write_held(rwlp));
}

/*
 * Return the kthread_t * of the lock owner
 */
void *
rw_owner(krwlock_t *rwlp)
{
	return (rwlp->rw_owner);
}
