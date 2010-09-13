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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <synch.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dhcpmsg.h>
#include <unistd.h>
#include <dhcp_svc_private.h>

#include "container.h"

/*
 * Container locking code -- warning: serious pain ahead.
 *
 * This code synchronizes access to a given container across multiple
 * threads in this (dsvclockd) process, and optionally synchronizes across
 * multiple instances of dsvclockd running on different hosts.  The
 * synchronization allows multiple readers or a single writer at one time.
 *
 * Since by definition there is at most one dsvclockd running per host and
 * all requests by all threads in all processes running on that host funnel
 * into it, this code effectively synchronizes access to a given container
 * across all threads in all processes running on a given host.  This means
 * that the optional synchronization across multiple instances of dsvclockd
 * on different hosts provides true cross-host synchronization for all
 * threads in all processes on all cooperating machines (though all hosts
 * must have write access to a common directory).
 *
 * The container synchronization here should be viewed as a two step
 * process, where the first step is optional:
 *
 *	1. Synchronize access across the set of cooperating dsvclockd's
 *	   on multiple hosts.  This is known as acquiring the host lock.
 *
 *	2. Synchronize access across the set of threads running inside
 *	   this dsvclockd process.  This is known as acquiring the
 *	   intra-process lock.
 *
 * In order to implement the first (host lock) step, we use fcntl()-based
 * file locking on a file inside an NFS-shared directory and rely on NFS to
 * do our synchronization for us.  Note that this can only be used to
 * implement the first step since fcntl()-based locks are process locks,
 * and the effects of using these locks with multiple threads are not
 * defined.  Furthermore, note that this means it requires some fancy
 * footwork to ensure that only one thread in a given dsvclockd process
 * tries to acquire the fcntl() lock for that process.
 *
 * In order to implement the second step, we use custom-made reader-writer
 * locks since the stock Solaris ones don't quite have the semantics we
 * need -- in particular, we need to relax the requirement that the thread
 * which acquired the lock is the one releasing it.
 *
 * Lock ordering guidelines:
 *
 * For the most part, this code does not acquire more than one container
 * lock at a time -- whenever feasible, please do the same.  If you must
 * acquire more than one lock at a time, the correct order is:
 *
 *	1. cn_nholds_lock
 *	2. cn_lock
 *	3. cn_hlock_lock
 */

static int host_lock(dsvcd_container_t *, int, boolean_t);
static int host_unlock(dsvcd_container_t *);
static unsigned int cn_nlocks(dsvcd_container_t *);

/*
 * Create a container identified by `cn_id'; returns an instance of the new
 * container upon success, or NULL on failure.  Note that `cn_id' is
 * treated as a pathname and thus must be a unique name for the container
 * across all containers, container versions, and datastores -- additionally,
 * if `crosshost' is set, then the directory named by `cn_id' must be a
 * directory mounted on all cooperating hosts.
 */
dsvcd_container_t *
cn_create(const char *cn_id, boolean_t crosshost)
{
	dsvcd_container_t *cn;

	dhcpmsg(MSG_VERBOSE, "creating %scontainer synchpoint `%s'", crosshost ?
	    "crosshost " : "", cn_id);

	cn = calloc(1, sizeof (dsvcd_container_t));
	if (cn == NULL)
		return (NULL);

	cn->cn_id = strdup(cn_id);
	if (cn->cn_id == NULL) {
		free(cn);
		return (NULL);
	}

	(void) mutex_init(&cn->cn_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&cn->cn_hlock_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&cn->cn_nholds_lock, USYNC_THREAD, NULL);

	(void) cond_init(&cn->cn_hlockcv, USYNC_THREAD, NULL);

	cn->cn_whead	  = NULL;
	cn->cn_wtail	  = NULL;
	cn->cn_nholds	  = 0;
	cn->cn_closing	  = B_FALSE;
	cn->cn_crosshost  = crosshost;
	cn->cn_hlockstate = CN_HUNLOCKED;
	cn->cn_hlockcount = 0;

	return (cn);
}

/*
 * Destroy container `cn'; wait a decent amount of time for activity on the
 * container to quiesce first.  If the caller has not prohibited other
 * threads from calling into the container yet, this may take a long time.
 */
void
cn_destroy(dsvcd_container_t *cn)
{
	unsigned int	attempts;
	unsigned int	nstalelocks;

	dhcpmsg(MSG_VERBOSE, "destroying container synchpoint `%s'", cn->cn_id);

	(void) mutex_lock(&cn->cn_lock);
	cn->cn_closing = B_TRUE;
	(void) mutex_unlock(&cn->cn_lock);

	/*
	 * Wait for up to CN_DESTROY_WAIT seconds for all the lock holders
	 * to relinquish their locks.  If the container has locks that seem
	 * to be stale, then warn the user before destroying it.  The locks
	 * will be unlocked automatically when we exit.
	 */
	for (attempts = 0; attempts < CN_DESTROY_WAIT; attempts++) {
		nstalelocks = cn_nlocks(cn);
		if (nstalelocks == 0)
			break;

		(void) sleep(1);
	}

	if (nstalelocks == 1) {
		dhcpmsg(MSG_WARNING, "unlocking stale lock on "
		    "container `%s'", cn->cn_id);
	} else if (nstalelocks != 0) {
		dhcpmsg(MSG_WARNING, "unlocking %d stale locks on "
		    "container `%s'", nstalelocks, cn->cn_id);
	}

	(void) cond_destroy(&cn->cn_hlockcv);
	(void) mutex_destroy(&cn->cn_nholds_lock);
	(void) mutex_destroy(&cn->cn_hlock_lock);
	(void) mutex_destroy(&cn->cn_lock);

	free(cn->cn_id);
	free(cn);
}

/*
 * Wait (block) until a lock of type `locktype' is obtained on container
 * `cn'.  Returns a DSVC_* return code; if DSVC_SUCCESS is returned, then
 * the lock is held upon return.  Must be called with the container's
 * cn_nholds_lock held on entry; returns with it unlocked.
 */
static int
cn_wait_for_lock(dsvcd_container_t *cn, dsvcd_locktype_t locktype)
{
	dsvcd_waitlist_t	waititem;
	int			retval = DSVC_SUCCESS;

	assert(MUTEX_HELD(&cn->cn_nholds_lock));
	assert(cn->cn_nholds != 0);

	waititem.wl_next = NULL;
	waititem.wl_prev = NULL;
	waititem.wl_locktype = locktype;
	(void) cond_init(&waititem.wl_cv, USYNC_THREAD, NULL);

	/*
	 * Chain our stack-local waititem onto the list; this keeps us from
	 * having to worry about allocation failures and also makes it easy
	 * for cn_unlock() to just pull us off the list without worrying
	 * about freeing the memory.
	 *
	 * Note that we can do this because by definition we are blocked in
	 * this function until we are signalled.
	 */
	if (cn->cn_whead != NULL) {
		waititem.wl_prev = cn->cn_wtail;
		cn->cn_wtail->wl_next = &waititem;
		cn->cn_wtail = &waititem;
	} else {
		cn->cn_whead = &waititem;
		cn->cn_wtail = &waititem;
	}

	do {
		if (cond_wait(&waititem.wl_cv, &cn->cn_nholds_lock) != 0) {
			dhcpmsg(MSG_DEBUG, "cn_wait_for_lock: cond_wait error");
			retval = DSVC_INTERNAL;
			break;
		}
	} while ((locktype == DSVCD_RDLOCK && cn->cn_nholds == -1) ||
	    (locktype == DSVCD_WRLOCK && cn->cn_nholds != 0));

	(void) cond_destroy(&waititem.wl_cv);

	assert(MUTEX_HELD(&cn->cn_nholds_lock));

	/*
	 * We got woken up; pull ourselves off of the local waitlist.
	 */
	if (waititem.wl_prev != NULL)
		waititem.wl_prev->wl_next = waititem.wl_next;
	else
		cn->cn_whead = waititem.wl_next;

	if (waititem.wl_next != NULL)
		waititem.wl_next->wl_prev = waititem.wl_prev;
	else
		cn->cn_wtail = waititem.wl_prev;

	if (retval == DSVC_SUCCESS) {
		if (locktype == DSVCD_WRLOCK)
			cn->cn_nholds = -1;
		else
			cn->cn_nholds++;
	}

	/*
	 * If we just acquired a read lock and the next waiter is waiting
	 * for a readlock too, signal the waiter.  Note that we wake each
	 * reader up one-by-one like this to avoid excessive contention on
	 * cn_nholds_lock.
	 */
	if (locktype == DSVCD_RDLOCK && cn->cn_whead != NULL &&
	    cn->cn_whead->wl_locktype == DSVCD_RDLOCK)
		(void) cond_signal(&cn->cn_whead->wl_cv);

	(void) mutex_unlock(&cn->cn_nholds_lock);
	return (retval);
}

/*
 * Lock container `cn' for reader (shared) access.  If the container cannot
 * be locked immediately (there is currently a writer lock held or a writer
 * lock waiting for the lock), then if `nonblock' is B_TRUE, DSVC_BUSY is
 * returned.  Otherwise, block until the lock can be obtained.  Returns a
 * DSVC_* code.
 */
int
cn_rdlock(dsvcd_container_t *cn, boolean_t nonblock)
{
	int	retval;

	/*
	 * The container is going away; no new lock requests.
	 */
	(void) mutex_lock(&cn->cn_lock);
	if (cn->cn_closing) {
		(void) mutex_unlock(&cn->cn_lock);
		return (DSVC_SYNCH_ERR);
	}
	(void) mutex_unlock(&cn->cn_lock);

	/*
	 * See if we can grab the lock without having to block; only
	 * possible if we can acquire the host lock without blocking, if
	 * the lock is not currently owned by a writer and if there are no
	 * writers currently enqueued for accessing this lock (we know that
	 * if there's a waiter it must be a writer since this code doesn't
	 * enqueue readers until there's a writer enqueued).  We enqueue
	 * these requests to improve fairness.
	 */
	(void) mutex_lock(&cn->cn_nholds_lock);

	if (cn->cn_nholds != -1 && cn->cn_whead == NULL &&
	    host_lock(cn, F_RDLCK, B_TRUE) == DSVC_SUCCESS) {
		cn->cn_nholds++;
		(void) mutex_unlock(&cn->cn_nholds_lock);
		return (DSVC_SUCCESS);
	}

	(void) mutex_unlock(&cn->cn_nholds_lock);

	/*
	 * Cannot grab the lock without blocking somewhere; wait until we
	 * can grab the host lock, then with that lock held obtain our
	 * intra-process lock.
	 */
	if (nonblock)
		return (DSVC_BUSY);
	retval = host_lock(cn, F_RDLCK, B_FALSE);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * We've got the read lock; if there aren't any writers currently
	 * contending for our intra-process lock then succeed immediately.
	 * It's possible for there to be waiters but for nholds to be zero
	 * via the following scenario:
	 *
	 *	1. The last holder of a lock unlocks, dropping nholds to
	 *	   zero and signaling the head waiter on the waitlist.
	 *
	 *	2. The last holder drops cn_nholds_lock.
	 *
	 *	3. We acquire cn_nholds_lock before the signaled waiter
	 *	   does.
	 *
	 * Note that this case won't cause a deadlock even if we didn't
	 * check for it here (when the waiter finally gets cn_nholds_lock,
	 * it'll find that the waitlist is once again non-NULL, and signal
	 * the us).  However, as an optimization, handle the case here.
	 */
	(void) mutex_lock(&cn->cn_nholds_lock);
	if (cn->cn_nholds != -1 &&
	    (cn->cn_whead == NULL || cn->cn_nholds == 0)) {
		cn->cn_nholds++;
		(void) mutex_unlock(&cn->cn_nholds_lock);
		return (DSVC_SUCCESS);
	}

	/* cn_wait_for_lock() will drop cn_nholds_lock */
	retval = cn_wait_for_lock(cn, DSVCD_RDLOCK);
	if (retval != DSVC_SUCCESS) {
		(void) host_unlock(cn);
		return (retval);
	}
	return (DSVC_SUCCESS);
}

/*
 * Lock container `cn' for writer (exclusive) access.  If the container
 * cannot be locked immediately (there are currently readers or a writer),
 * then if `nonblock' is B_TRUE, DSVC_BUSY is returned.  Otherwise, block
 * until the lock can be obtained.  Returns a DSVC_* code.
 */
int
cn_wrlock(dsvcd_container_t *cn, boolean_t nonblock)
{
	int	retval;

	/*
	 * The container is going away; no new lock requests.
	 */
	(void) mutex_lock(&cn->cn_lock);
	if (cn->cn_closing) {
		(void) mutex_unlock(&cn->cn_lock);
		return (DSVC_SYNCH_ERR);
	}
	(void) mutex_unlock(&cn->cn_lock);

	/*
	 * See if we can grab the lock without having to block; only
	 * possible if there are no current writers within our process and
	 * that we can immediately acquire the host lock.
	 */
	(void) mutex_lock(&cn->cn_nholds_lock);

	if (cn->cn_nholds == 0 &&
	    host_lock(cn, F_WRLCK, B_TRUE) == DSVC_SUCCESS) {
		cn->cn_nholds = -1;
		(void) mutex_unlock(&cn->cn_nholds_lock);
		return (DSVC_SUCCESS);
	}

	(void) mutex_unlock(&cn->cn_nholds_lock);

	/*
	 * Cannot grab the lock without blocking somewhere; wait until we
	 * can grab the host lock, then with that lock held obtain our
	 * intra-process lock.
	 */
	if (nonblock)
		return (DSVC_BUSY);
	retval = host_lock(cn, F_WRLCK, B_FALSE);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * We've got the host lock; if there aren't any writers currently
	 * contending for our intra-process lock then succeed immediately.
	 */
	(void) mutex_lock(&cn->cn_nholds_lock);
	if (cn->cn_nholds == 0) {
		cn->cn_nholds = -1;
		(void) mutex_unlock(&cn->cn_nholds_lock);
		return (DSVC_SUCCESS);
	}

	/* cn_wait_for_lock() will drop cn_nholds_lock */
	retval = cn_wait_for_lock(cn, DSVCD_WRLOCK);
	if (retval != DSVC_SUCCESS) {
		(void) host_unlock(cn);
		return (retval);
	}
	return (DSVC_SUCCESS);
}

/*
 * Unlock reader or writer lock on container `cn'; returns a DSVC_* code
 */
int
cn_unlock(dsvcd_container_t *cn)
{
	(void) mutex_lock(&cn->cn_nholds_lock);

	if (cn->cn_nholds == 0) {
		(void) mutex_unlock(&cn->cn_nholds_lock);
		return (DSVC_SYNCH_ERR);
	}

	if (cn->cn_nholds != -1 && cn->cn_nholds != 1) {
		cn->cn_nholds--;
		(void) host_unlock(cn);
		(void) mutex_unlock(&cn->cn_nholds_lock);
		return (DSVC_SUCCESS);
	}

	/*
	 * The last reader or a writer just unlocked -- signal the first
	 * waiter.  To avoid a thundering herd, we only signal the first
	 * waiter, even if there are multiple readers ready to go --
	 * instead, each reader is responsible for signaling the next
	 * in cn_wait_for_lock().
	 */
	cn->cn_nholds = 0;
	if (cn->cn_whead != NULL)
		(void) cond_signal(&cn->cn_whead->wl_cv);

	(void) host_unlock(cn);
	(void) mutex_unlock(&cn->cn_nholds_lock);

	return (DSVC_SUCCESS);
}

/*
 * Find out what kind of lock is on `cn'.  Note that this is just a
 * snapshot in time and without additional locks the answer may be invalid
 * by the time the function returns.
 */
dsvcd_locktype_t
cn_locktype(dsvcd_container_t *cn)
{
	int nholds;

	(void) mutex_lock(&cn->cn_nholds_lock);
	nholds = cn->cn_nholds;
	(void) mutex_unlock(&cn->cn_nholds_lock);

	if (nholds == 0)
		return (DSVCD_NOLOCK);
	else if (nholds > 0)
		return (DSVCD_RDLOCK);
	else
		return (DSVCD_WRLOCK);
}

/*
 * Obtain a lock of type `locktype' on container `cn' such that we have
 * shared or exclusive access to this container across all hosts.  If
 * `nonblock' is true and the lock cannot be obtained return DSVC_BUSY.  If
 * the lock is already held, the number of instances of the lock "checked
 * out" by this host is incremented.
 */
static int
host_lock(dsvcd_container_t *cn, int locktype, boolean_t nonblock)
{
	struct flock	flock;
	int		fd;
	char		*basename, lockpath[MAXPATHLEN];
	int		error;

	if (!cn->cn_crosshost)
		return (DSVC_SUCCESS);

	/*
	 * Before we wait for a while, see if the container is going away;
	 * if so, fail now so the container can drain quicker..
	 */
	(void) mutex_lock(&cn->cn_lock);
	if (cn->cn_closing) {
		(void) mutex_unlock(&cn->cn_lock);
		return (DSVC_SYNCH_ERR);
	}
	(void) mutex_unlock(&cn->cn_lock);

	/*
	 * Note that we only wait if (1) there's already a thread trying to
	 * grab the host lock on our host or if (2) this host currently
	 * holds a host shared lock and we need an exclusive lock.  Note
	 * that we do *not* wait in the following situations:
	 *
	 *	* This host holds an exclusive host lock and another
	 *	  exclusive host lock request comes in.  We rely on the
	 *	  intra-process lock to do the synchronization.
	 *
	 *	* This host holds an exclusive host lock and a shared host
	 *	  lock request comes in.  Since this host already has
	 *	  exclusive access, we already implicitly hold the shared
	 *	  host lock as far as this host is concerned, so just rely
	 *	  on the intra-process lock to do the synchronization.
	 *
	 * These semantics make sense as long as one remembers that the
	 * host lock merely provides exclusive or shared access for a given
	 * host or set of hosts -- that is, exclusive access is exclusive
	 * access for that machine, not for the given request.
	 */
	(void) mutex_lock(&cn->cn_hlock_lock);

	while (cn->cn_hlockstate == CN_HPENDING ||
	    cn->cn_hlockstate == CN_HRDLOCKED && locktype == F_WRLCK) {
		if (nonblock) {
			(void) mutex_unlock(&cn->cn_hlock_lock);
			return (DSVC_BUSY);
		}

		if (cond_wait(&cn->cn_hlockcv, &cn->cn_hlock_lock) != 0) {
			(void) mutex_unlock(&cn->cn_hlock_lock);
			return (DSVC_SYNCH_ERR);
		}
	}

	if (cn->cn_hlockstate == CN_HRDLOCKED ||
	    cn->cn_hlockstate == CN_HWRLOCKED) {
		/*
		 * Already locked; just bump the held lock count.
		 */
		assert(cn->cn_hlockcount > 0);
		cn->cn_hlockcount++;
		(void) mutex_unlock(&cn->cn_hlock_lock);
		return (DSVC_SUCCESS);
	}

	/*
	 * We're the thread that's going to try to acquire the host lock.
	 */

	assert(cn->cn_hlockcount == 0);

	/*
	 * Create the lock file as a hidden file in the directory named by
	 * cn_id.  So if cn_id is /var/dhcp/SUNWfiles1_dhcptab, we want the
	 * lock file to be /var/dhcp/.SUNWfiles1_dhcptab.lock.  Please, no
	 * giggles about the snprintf().
	 */
	basename = strrchr(cn->cn_id, '/');
	if (basename == NULL)
		basename = cn->cn_id;
	else
		basename++;

	(void) snprintf(lockpath, MAXPATHLEN, "%.*s.%s.lock",
	    basename - cn->cn_id, cn->cn_id, basename);
	fd = open(lockpath, O_RDWR|O_CREAT, 0600);
	if (fd == -1) {
		(void) mutex_unlock(&cn->cn_hlock_lock);
		return (DSVC_SYNCH_ERR);
	}

	cn->cn_hlockstate = CN_HPENDING;
	(void) mutex_unlock(&cn->cn_hlock_lock);

	flock.l_len	= 0;
	flock.l_type	= locktype;
	flock.l_start	= 0;
	flock.l_whence	= SEEK_SET;

	if (fcntl(fd, nonblock ? F_SETLK : F_SETLKW, &flock) == -1) {
		/*
		 * For some reason we couldn't acquire the lock.  Reset the
		 * host lock state to "unlocked" and signal another thread
		 * (if there's one waiting) to pick up where we left off.
		 */
		error = errno;
		(void) mutex_lock(&cn->cn_hlock_lock);
		cn->cn_hlockstate = CN_HUNLOCKED;
		(void) cond_signal(&cn->cn_hlockcv);
		(void) mutex_unlock(&cn->cn_hlock_lock);
		(void) close(fd);
		return (error == EAGAIN ? DSVC_BUSY : DSVC_SYNCH_ERR);
	}

	/*
	 * Got the lock; wake up all the waiters since they can all succeed
	 */
	(void) mutex_lock(&cn->cn_hlock_lock);
	cn->cn_hlockstate = (locktype == F_WRLCK ? CN_HWRLOCKED : CN_HRDLOCKED);
	cn->cn_hlockcount++;
	cn->cn_hlockfd = fd;
	(void) cond_broadcast(&cn->cn_hlockcv);
	(void) mutex_unlock(&cn->cn_hlock_lock);

	return (DSVC_SUCCESS);
}

/*
 * Unlock a checked out instance of a shared or exclusive lock on container
 * `cn'; if the number of checked out instances goes to zero, then the host
 * lock is unlocked so that other hosts may compete for it.
 */
static int
host_unlock(dsvcd_container_t *cn)
{
	struct flock	flock;

	if (!cn->cn_crosshost)
		return (DSVC_SUCCESS);

	assert(cn->cn_hlockcount > 0);

	(void) mutex_lock(&cn->cn_hlock_lock);
	if (cn->cn_hlockcount > 1) {
		/*
		 * Not the last unlock by this host; just decrement the
		 * held lock count.
		 */
		cn->cn_hlockcount--;
		(void) mutex_unlock(&cn->cn_hlock_lock);
		return (DSVC_SUCCESS);
	}

	flock.l_len	= 0;
	flock.l_type	= F_UNLCK;
	flock.l_start	= 0;
	flock.l_whence	= SEEK_SET;

	if (fcntl(cn->cn_hlockfd, F_SETLK, &flock) == -1) {
		(void) mutex_unlock(&cn->cn_hlock_lock);
		return (DSVC_SYNCH_ERR);
	}

	/*
	 * Note that we don't unlink the lockfile for a number of reasons,
	 * the most blatant reason being:
	 *
	 *	1. Several hosts lock the lockfile for shared access.
	 *	2. One host unlocks the lockfile and unlinks it (here).
	 *	3. Another host comes in, goes to exclusively lock the
	 *	   lockfile, finds no lockfile, and creates a new one
	 *	   (meanwhile, the other hosts are still accessing the
	 *	   container through the unlinked lockfile).
	 *
	 * We could put in some hairy code to try to unlink lockfiles
	 * elsewhere (when possible), but it hardly seems worth it since
	 * inodes are cheap.
	 */

	(void) close(cn->cn_hlockfd);
	cn->cn_hlockcount = 0;
	cn->cn_hlockstate = CN_HUNLOCKED;
	/*
	 * We need to signal `cn_hlockcv' in case there are threads which
	 * are waiting on it to attempt flock() exclusive access (see the
	 * comments in host_lock() for more details about this case).
	 */
	(void) cond_signal(&cn->cn_hlockcv);
	(void) mutex_unlock(&cn->cn_hlock_lock);

	return (DSVC_SUCCESS);
}

/*
 * Return the number of locks currently held for container `cn'.
 */
static unsigned int
cn_nlocks(dsvcd_container_t *cn)
{
	unsigned int nlocks;

	(void) mutex_lock(&cn->cn_nholds_lock);
	(void) mutex_lock(&cn->cn_hlock_lock);

	switch (cn->cn_nholds) {
	case 0:
		nlocks = cn->cn_hlockcount;
		break;
	case -1:
		nlocks = 1;
		break;
	default:
		nlocks = cn->cn_nholds;
		break;
	}

	dhcpmsg(MSG_DEBUG, "cn_nlocks: nholds=%d hlockstate=%d hlockcount=%d",
	    cn->cn_nholds, cn->cn_hlockstate, cn->cn_hlockcount);

	(void) mutex_unlock(&cn->cn_hlock_lock);
	(void) mutex_unlock(&cn->cn_nholds_lock);

	return (nlocks);
}
