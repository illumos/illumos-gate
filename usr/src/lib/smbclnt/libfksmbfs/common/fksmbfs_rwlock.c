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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 */

/*
 * A homegrown reader/writer lock implementation.  It addresses
 * two requirements not addressed by the system primitives.  They
 * are that the `enter" operation is optionally interruptible and
 * that that they can be re`enter'ed by writers without deadlock.
 *
 * All of this was borrowed from NFS.
 * See: uts/common/fs/nfs/nfs_subr.c
 *
 * XXX: Could we make this serve our needs instead?
 * See: uts/common/os/rwstlock.c
 * (and then use it for NFS too)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/vnode.h>

#include <smbfs/smbfs.h>
#include <smbfs/smbfs_node.h>
#include <smbfs/smbfs_subr.h>


/*
 * Only can return non-zero if intr != 0.
 */
int
smbfs_rw_enter_sig(smbfs_rwlock_t *l, krw_t rw, int intr)
{

	mutex_enter(&l->lock);

	/*
	 * If this is a nested enter, then allow it.  There
	 * must be as many exits as enters through.
	 */
	if (l->owner == curthread) {
		/* lock is held for writing by current thread */
		ASSERT(rw == RW_READER || rw == RW_WRITER);
		l->count--;
	} else if (rw == RW_READER) {
		/*
		 * While there is a writer active or writers waiting,
		 * then wait for them to finish up and move on.  Then,
		 * increment the count to indicate that a reader is
		 * active.
		 */
		while (l->count < 0 || l->waiters > 0) {
			if (intr) {
				// lwp_nostop stuff...
				(void) cv_wait_sig(&l->cv, &l->lock);
			} else
				cv_wait(&l->cv, &l->lock);
		}
		ASSERT(l->count < INT_MAX);
#ifdef SMBDEBUG
		if ((l->count % 10000) == 9999)
			cmn_err(CE_WARN, "smbfs_rw_enter_sig: count %d on"
			    "rwlock @ %p\n", l->count, (void *)&l);
#endif
		l->count++;
	} else {
		ASSERT(rw == RW_WRITER);
		/*
		 * While there are readers active or a writer
		 * active, then wait for all of the readers
		 * to finish or for the writer to finish.
		 * Then, set the owner field to curthread and
		 * decrement count to indicate that a writer
		 * is active.
		 */
		while (l->count > 0 || l->owner != NULL) {
			l->waiters++;
			if (intr) {
				// lwp_nostop stuff...
				if (!cv_wait_sig(&l->cv, &l->lock)) {
					l->waiters--;
					cv_broadcast(&l->cv);
					mutex_exit(&l->lock);
					return (EINTR);
				}
			} else
				cv_wait(&l->cv, &l->lock);
			l->waiters--;
		}
		l->owner = curthread;
		l->count--;
	}

	mutex_exit(&l->lock);

	return (0);
}

/*
 * If the lock is available, obtain it and return non-zero.  If there is
 * already a conflicting lock, return 0 immediately.
 */

int
smbfs_rw_tryenter(smbfs_rwlock_t *l, krw_t rw)
{
	mutex_enter(&l->lock);

	/*
	 * If this is a nested enter, then allow it.  There
	 * must be as many exits as enters through.
	 */
	if (l->owner == curthread) {
		/* lock is held for writing by current thread */
		ASSERT(rw == RW_READER || rw == RW_WRITER);
		l->count--;
	} else if (rw == RW_READER) {
		/*
		 * If there is a writer active or writers waiting, deny the
		 * lock.  Otherwise, bump the count of readers.
		 */
		if (l->count < 0 || l->waiters > 0) {
			mutex_exit(&l->lock);
			return (0);
		}
		l->count++;
	} else {
		ASSERT(rw == RW_WRITER);
		/*
		 * If there are readers active or a writer active, deny the
		 * lock.  Otherwise, set the owner field to curthread and
		 * decrement count to indicate that a writer is active.
		 */
		if (l->count > 0 || l->owner != NULL) {
			mutex_exit(&l->lock);
			return (0);
		}
		l->owner = curthread;
		l->count--;
	}

	mutex_exit(&l->lock);

	return (1);
}

void
smbfs_rw_exit(smbfs_rwlock_t *l)
{

	mutex_enter(&l->lock);
	/*
	 * If this is releasing a writer lock, then increment count to
	 * indicate that there is one less writer active.  If this was
	 * the last of possibly nested writer locks, then clear the owner
	 * field as well to indicate that there is no writer active
	 * and wakeup any possible waiting writers or readers.
	 *
	 * If releasing a reader lock, then just decrement count to
	 * indicate that there is one less reader active.  If this was
	 * the last active reader and there are writer(s) waiting,
	 * then wake up the first.
	 */
	if (l->owner != NULL) {
		ASSERT(l->owner == curthread);
		l->count++;
		if (l->count == 0) {
			l->owner = NULL;
			cv_broadcast(&l->cv);
		}
	} else {
		ASSERT(l->count > 0);
		l->count--;
		if (l->count == 0 && l->waiters > 0)
			cv_broadcast(&l->cv);
	}
	mutex_exit(&l->lock);
}

int
smbfs_rw_lock_held(smbfs_rwlock_t *l, krw_t rw)
{

	if (rw == RW_READER)
		return (l->count > 0);
	ASSERT(rw == RW_WRITER);
	return (l->count < 0);
}

/* ARGSUSED */
void
smbfs_rw_init(smbfs_rwlock_t *l, char *name, krw_type_t type, void *arg)
{

	l->count = 0;
	l->waiters = 0;
	l->owner = NULL;
	mutex_init(&l->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&l->cv, NULL, CV_DEFAULT, NULL);
}

void
smbfs_rw_destroy(smbfs_rwlock_t *l)
{

	mutex_destroy(&l->lock);
	cv_destroy(&l->cv);
}
