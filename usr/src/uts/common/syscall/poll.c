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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2012, 2016 by Delphix. All rights reserved.
 * Copyright 2015, Joyent, Inc.
 */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/mode.h>
#include <sys/proc.h>
#include <sys/uio.h>
#include <sys/poll_impl.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/bitmap.h>
#include <sys/kstat.h>
#include <sys/rctl.h>
#include <sys/port_impl.h>
#include <sys/schedctl.h>
#include <sys/cpu.h>

#define	NPHLOCKS	64	/* Number of locks; must be power of 2 */
#define	PHLOCKADDR(php)	&plocks[(((uintptr_t)(php)) >> 8) & (NPHLOCKS - 1)]
#define	PHLOCK(php)	PHLOCKADDR(php).pp_lock
#define	PH_ENTER(php)	mutex_enter(PHLOCK(php))
#define	PH_EXIT(php)	mutex_exit(PHLOCK(php))
#define	VALID_POLL_EVENTS	(POLLIN | POLLPRI | POLLOUT | POLLRDNORM \
	| POLLRDBAND | POLLWRBAND | POLLHUP | POLLERR | POLLNVAL)

/*
 * global counters to collect some stats
 */
static struct {
	kstat_named_t	polllistmiss;	/* failed to find a cached poll list */
	kstat_named_t	pollcachehit;	/* list matched 100% w/ cached one */
	kstat_named_t	pollcachephit;	/* list matched < 100% w/ cached one */
	kstat_named_t	pollcachemiss;	/* every list entry is dif from cache */
	kstat_named_t	pollunlockfail;	/* failed to perform pollunlock */
} pollstats = {
	{ "polllistmiss",	KSTAT_DATA_UINT64 },
	{ "pollcachehit",	KSTAT_DATA_UINT64 },
	{ "pollcachephit",	KSTAT_DATA_UINT64 },
	{ "pollcachemiss",	KSTAT_DATA_UINT64 },
	{ "pollunlockfail",	KSTAT_DATA_UINT64 }
};

kstat_named_t *pollstats_ptr = (kstat_named_t *)&pollstats;
uint_t pollstats_ndata = sizeof (pollstats) / sizeof (kstat_named_t);

struct pplock	{
	kmutex_t	pp_lock;
	short		pp_flag;
	kcondvar_t	pp_wait_cv;
	int32_t		pp_pad;		/* to a nice round 16 bytes */
};

static struct pplock plocks[NPHLOCKS];	/* Hash array of pollhead locks */

/* Contention lock & list for preventing deadlocks in recursive /dev/poll. */
static	kmutex_t	pollstate_contenders_lock;
static	pollstate_t	*pollstate_contenders = NULL;

#ifdef DEBUG
static int pollchecksanity(pollstate_t *, nfds_t);
static int pollcheckxref(pollstate_t *, int);
static void pollcheckphlist(void);
static int pollcheckrevents(pollstate_t *, int, int, int);
static void checkpolldat(pollstate_t *);
#endif	/* DEBUG */
static int plist_chkdupfd(file_t *, polldat_t *, pollstate_t *, pollfd_t *, int,
    int *);

/*
 * Data structure overview:
 * The per-thread poll state consists of
 *	one pollstate_t
 *	one pollcache_t
 *	one bitmap with one event bit per fd
 *	a (two-dimensional) hashed array of polldat_t structures - one entry
 *	per fd
 *
 * This conglomerate of data structures interact with
 *	the pollhead which is used by VOP_POLL and pollwakeup
 *	(protected by the PHLOCK, cached array of plocks), and
 *	the fpollinfo list hanging off the fi_list which is used to notify
 *	poll when a cached fd is closed. This is protected by uf_lock.
 *
 * Invariants:
 *	pd_php (pollhead pointer) is set iff (if and only if) the polldat
 *	is on that pollhead. This is modified atomically under pc_lock.
 *
 *	pd_fp (file_t pointer) is set iff the thread is on the fpollinfo
 *	list for that open file.
 *	This is modified atomically under pc_lock.
 *
 *	pd_count is the sum (over all values of i) of pd_ref[i].xf_refcnt.
 *	Iff pd_ref[i].xf_refcnt >= 1 then
 *		ps_pcacheset[i].pcs_pollfd[pd_ref[i].xf_position].fd == pd_fd
 *	Iff pd_ref[i].xf_refcnt > 1 then
 *		In ps_pcacheset[i].pcs_pollfd between index
 *		pd_ref[i].xf_position] and the end of the list
 *		there are xf_refcnt entries with .fd == pd_fd
 *
 * Locking design:
 * Whenever possible the design relies on the fact that the poll cache state
 * is per thread thus for both poll and exit it is self-synchronizing.
 * Thus the key interactions where other threads access the state are:
 *	pollwakeup (and polltime), and
 *	close cleaning up the cached references to an open file
 *
 * The two key locks in poll proper is ps_lock and pc_lock.
 *
 * The ps_lock is used for synchronization between poll, (lwp_)exit and close
 * to ensure that modifications to pollcacheset structure are serialized.
 * This lock is held through most of poll() except where poll sleeps
 * since there is little need to handle closes concurrently with the execution
 * of poll.
 * The pc_lock protects most of the fields in pollcache structure and polldat
 * structures (which are accessed by poll, pollwakeup, and polltime)
 * with the exception of fields that are only modified when only one thread
 * can access this per-thread state.
 * Those exceptions occur in poll when first allocating the per-thread state,
 * when poll grows the number of polldat (never shrinks), and when
 * exit/pollcleanup has ensured that there are no references from either
 * pollheads or fpollinfo to the threads poll state.
 *
 * Poll(2) system call is the only path which ps_lock and pc_lock are both
 * held, in that order. It needs ps_lock to synchronize with close and
 * lwp_exit; and pc_lock with pollwakeup.
 *
 * The locking interaction between pc_lock and PHLOCK take into account
 * that poll acquires these locks in the order of pc_lock and then PHLOCK
 * while pollwakeup does it in the reverse order. Thus pollwakeup implements
 * deadlock avoidance by dropping the locks and reacquiring them in the
 * reverse order. For this to work pollwakeup needs to prevent the thread
 * from exiting and freeing all of the poll related state. Thus is done
 * using
 *	the pc_no_exit lock
 *	the pc_busy counter
 *	the pc_busy_cv condition variable
 *
 * The locking interaction between pc_lock and uf_lock has similar
 * issues. Poll holds ps_lock and/or pc_lock across calls to getf/releasef
 * which acquire uf_lock. The poll cleanup in close needs to hold uf_lock
 * to prevent poll or exit from doing a delfpollinfo after which the thread
 * might exit. But the cleanup needs to acquire pc_lock when modifying
 * the poll cache state. The solution is to use pc_busy and do the close
 * cleanup in two phases:
 *	First close calls pollblockexit which increments pc_busy.
 *	This prevents the per-thread poll related state from being freed.
 *	Then close drops uf_lock and calls pollcacheclean.
 *	This routine can then acquire pc_lock and remove any references
 *	to the closing fd (as well as recording that it has been closed
 *	so that a POLLNVAL can be generated even if the fd is reused before
 *	poll has been woken up and checked getf() again).
 *
 * When removing a polled fd from poll cache, the fd is always removed
 * from pollhead list first and then from fpollinfo list, i.e.,
 * pollhead_delete() is called before delfpollinfo().
 *
 *
 * Locking hierarchy:
 *	pc_no_exit is a leaf level lock.
 *	ps_lock is held when acquiring pc_lock (except when pollwakeup
 *	acquires pc_lock).
 *	pc_lock might be held when acquiring PHLOCK (pollhead_insert/
 *	pollhead_delete)
 *	pc_lock is always held (but this is not required)
 *	when acquiring PHLOCK (in polladd/pollhead_delete and pollwakeup called
 *	from pcache_clean_entry).
 *	pc_lock is held across addfpollinfo/delfpollinfo which acquire
 *	uf_lock.
 *	pc_lock is held across getf/releasef which acquire uf_lock.
 *	ps_lock might be held across getf/releasef which acquire uf_lock.
 *	pollwakeup tries to acquire pc_lock while holding PHLOCK
 *	but drops the locks and reacquire them in reverse order to avoid
 *	deadlock.
 *
 * Note also that there is deadlock avoidance support for VOP_POLL routines
 * and pollwakeup involving a file system or driver lock.
 * See below.
 */

/*
 * Deadlock avoidance support for VOP_POLL() routines.  This is
 * sometimes necessary to prevent deadlock between polling threads
 * (which hold poll locks on entry to xx_poll(), then acquire foo)
 * and pollwakeup() threads (which hold foo, then acquire poll locks).
 *
 * pollunlock(*cookie) releases whatever poll locks the current thread holds,
 *	setting a cookie for use by pollrelock();
 *
 * pollrelock(cookie) reacquires previously dropped poll locks;
 *
 * polllock(php, mutex) does the common case: pollunlock(),
 *	acquire the problematic mutex, pollrelock().
 *
 * If polllock() or pollunlock() return non-zero, it indicates that a recursive
 * /dev/poll is in progress and pollcache locks cannot be dropped.  Callers
 * must handle this by indicating a POLLNVAL in the revents of the VOP_POLL.
 */
int
pollunlock(int *lockstate)
{
	pollstate_t *ps = curthread->t_pollstate;
	pollcache_t *pcp;

	ASSERT(lockstate != NULL);

	/*
	 * There is no way to safely perform a pollunlock() while in the depths
	 * of a recursive /dev/poll operation.
	 */
	if (ps != NULL && ps->ps_depth > 1) {
		ps->ps_flags |= POLLSTATE_ULFAIL;
		pollstats.pollunlockfail.value.ui64++;
		return (-1);
	}

	/*
	 * t_pollcache is set by /dev/poll and event ports (port_fd.c).
	 * If the pollrelock/pollunlock is called as a result of poll(2),
	 * the t_pollcache should be NULL.
	 */
	if (curthread->t_pollcache == NULL)
		pcp = ps->ps_pcache;
	else
		pcp = curthread->t_pollcache;

	if (!mutex_owned(&pcp->pc_lock)) {
		*lockstate = 0;
	} else {
		*lockstate = 1;
		mutex_exit(&pcp->pc_lock);
	}
	return (0);
}

void
pollrelock(int lockstate)
{
	pollstate_t *ps = curthread->t_pollstate;
	pollcache_t *pcp;

	/* Skip this whole ordeal if the pollcache was not locked to begin */
	if (lockstate == 0)
		return;

	/*
	 * t_pollcache is set by /dev/poll and event ports (port_fd.c).
	 * If the pollrelock/pollunlock is called as a result of poll(2),
	 * the t_pollcache should be NULL.
	 */
	if (curthread->t_pollcache == NULL)
		pcp = ps->ps_pcache;
	else
		pcp = curthread->t_pollcache;

	mutex_enter(&pcp->pc_lock);
}

/* ARGSUSED */
int
polllock(pollhead_t *php, kmutex_t *lp)
{
	if (mutex_tryenter(lp) == 0) {
		int state;

		if (pollunlock(&state) != 0) {
			return (-1);
		}
		mutex_enter(lp);
		pollrelock(state);
	}
	return (0);
}

static int
poll_common(pollfd_t *fds, nfds_t nfds, timespec_t *tsp, k_sigset_t *ksetp)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	int fdcnt = 0;
	int i;
	hrtime_t deadline; /* hrtime value when we want to return */
	pollfd_t *pollfdp;
	pollstate_t *ps;
	pollcache_t *pcp;
	int error = 0;
	nfds_t old_nfds;
	int cacheindex = 0;	/* which cache set is used */

	/*
	 * Determine the precise future time of the requested timeout, if any.
	 */
	if (tsp == NULL) {
		deadline = -1;
	} else if (tsp->tv_sec == 0 && tsp->tv_nsec == 0) {
		deadline = 0;
	} else {
		/* They must wait at least a tick. */
		deadline = ((hrtime_t)tsp->tv_sec * NANOSEC) + tsp->tv_nsec;
		deadline = MAX(deadline, nsec_per_tick);
		deadline += gethrtime();
	}

	/*
	 * Reset our signal mask, if requested.
	 */
	if (ksetp != NULL) {
		mutex_enter(&p->p_lock);
		schedctl_finish_sigblock(t);
		lwp->lwp_sigoldmask = t->t_hold;
		t->t_hold = *ksetp;
		t->t_flag |= T_TOMASK;
		/*
		 * Call cv_reltimedwait_sig() just to check for signals.
		 * We will return immediately with either 0 or -1.
		 */
		if (!cv_reltimedwait_sig(&t->t_delay_cv, &p->p_lock, 0,
		    TR_CLOCK_TICK)) {
			mutex_exit(&p->p_lock);
			error = EINTR;
			goto pollout;
		}
		mutex_exit(&p->p_lock);
	}

	/*
	 * Check to see if this one just wants to use poll() as a timeout.
	 * If yes then bypass all the other stuff and make it sleep.
	 */
	if (nfds == 0) {
		/*
		 * Sleep until we have passed the requested future
		 * time or until interrupted by a signal.
		 * Do not check for signals if we do not want to wait.
		 */
		if (deadline != 0) {
			mutex_enter(&t->t_delay_lock);
			while ((error = cv_timedwait_sig_hrtime(&t->t_delay_cv,
			    &t->t_delay_lock, deadline)) > 0)
				continue;
			mutex_exit(&t->t_delay_lock);
			error = (error == 0) ? EINTR : 0;
		}
		goto pollout;
	}

	if (nfds > p->p_fno_ctl) {
		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_NOFILE],
		    p->p_rctls, p, RCA_SAFE);
		mutex_exit(&p->p_lock);
		error = EINVAL;
		goto pollout;
	}

	/*
	 * Need to allocate memory for pollstate before anything because
	 * the mutex and cv are created in this space
	 */
	ps = pollstate_create();

	if (ps->ps_pcache == NULL)
		ps->ps_pcache = pcache_alloc();
	pcp = ps->ps_pcache;

	/*
	 * NOTE: for performance, buffers are saved across poll() calls.
	 * The theory is that if a process polls heavily, it tends to poll
	 * on the same set of descriptors.  Therefore, we only reallocate
	 * buffers when nfds changes.  There is no hysteresis control,
	 * because there is no data to suggest that this is necessary;
	 * the penalty of reallocating is not *that* great in any event.
	 */
	old_nfds = ps->ps_nfds;
	if (nfds != old_nfds) {

		kmem_free(ps->ps_pollfd, old_nfds * sizeof (pollfd_t));
		pollfdp = kmem_alloc(nfds * sizeof (pollfd_t), KM_SLEEP);
		ps->ps_pollfd = pollfdp;
		ps->ps_nfds = nfds;
	}

	pollfdp = ps->ps_pollfd;
	if (copyin(fds, pollfdp, nfds * sizeof (pollfd_t))) {
		error = EFAULT;
		goto pollout;
	}

	if (fds == NULL) {
		/*
		 * If the process has page 0 mapped, then the copyin() above
		 * will succeed even if fds is NULL.  However, our cached
		 * poll lists are keyed by the address of the passed-in fds
		 * structure, and we use the value NULL to indicate an unused
		 * poll cache list entry.  As such, we elect not to support
		 * NULL as a valid (user) memory address and fail the poll()
		 * call.
		 */
		error = EINVAL;
		goto pollout;
	}

	/*
	 * If this thread polls for the first time, allocate ALL poll
	 * cache data structures and cache the poll fd list. This
	 * allocation is delayed till now because lwp's polling 0 fd
	 * (i.e. using poll as timeout()) don't need this memory.
	 */
	mutex_enter(&ps->ps_lock);
	pcp = ps->ps_pcache;
	ASSERT(pcp != NULL);
	if (pcp->pc_bitmap == NULL) {
		pcache_create(pcp, nfds);
		/*
		 * poll and cache this poll fd list in ps_pcacheset[0].
		 */
		error = pcacheset_cache_list(ps, fds, &fdcnt, cacheindex);
		if (fdcnt || error) {
			mutex_exit(&ps->ps_lock);
			goto pollout;
		}
	} else {
		pollcacheset_t	*pcset = ps->ps_pcacheset;

		/*
		 * Not first time polling. Select a cached poll list by
		 * matching user pollfd list buffer address.
		 */
		for (cacheindex = 0; cacheindex < ps->ps_nsets; cacheindex++) {
			if (pcset[cacheindex].pcs_usradr == (uintptr_t)fds) {
				if ((++pcset[cacheindex].pcs_count) == 0) {
					/*
					 * counter is wrapping around.
					 */
					pcacheset_reset_count(ps, cacheindex);
				}
				/*
				 * examine and resolve possible
				 * difference of the current poll
				 * list and previously cached one.
				 * If there is an error during resolve(),
				 * the callee will guarantee the consistency
				 * of cached poll list and cache content.
				 */
				error = pcacheset_resolve(ps, nfds, &fdcnt,
				    cacheindex);
				if (error) {
					mutex_exit(&ps->ps_lock);
					goto pollout;
				}
				break;
			}

			/*
			 * Note that pcs_usradr field of an used entry won't be
			 * NULL because it stores the address of passed-in fds,
			 * and NULL fds will not be cached (Then it is either
			 * the special timeout case when nfds is 0 or it returns
			 * failure directly).
			 */
			if (pcset[cacheindex].pcs_usradr == NULL) {
				/*
				 * found an unused entry. Use it to cache
				 * this poll list.
				 */
				error = pcacheset_cache_list(ps, fds, &fdcnt,
				    cacheindex);
				if (fdcnt || error) {
					mutex_exit(&ps->ps_lock);
					goto pollout;
				}
				break;
			}
		}
		if (cacheindex == ps->ps_nsets) {
			/*
			 * We failed to find a matching cached poll fd list.
			 * replace an old list.
			 */
			pollstats.polllistmiss.value.ui64++;
			cacheindex = pcacheset_replace(ps);
			ASSERT(cacheindex < ps->ps_nsets);
			pcset[cacheindex].pcs_usradr = (uintptr_t)fds;
			error = pcacheset_resolve(ps, nfds, &fdcnt, cacheindex);
			if (error) {
				mutex_exit(&ps->ps_lock);
				goto pollout;
			}
		}
	}

	/*
	 * Always scan the bitmap with the lock on the pollcache held.
	 * This is to make sure that a wakeup does not come undetected.
	 * If the lock is not held, a pollwakeup could have come for an
	 * fd we already checked but before this thread sleeps, in which
	 * case the wakeup is missed. Now we hold the pcache lock and
	 * check the bitmap again. This will prevent wakeup from happening
	 * while we hold pcache lock since pollwakeup() will also lock
	 * the pcache before updating poll bitmap.
	 */
	mutex_enter(&pcp->pc_lock);
	for (;;) {
		pcp->pc_flag = 0;
		error = pcache_poll(pollfdp, ps, nfds, &fdcnt, cacheindex);
		if (fdcnt || error) {
			mutex_exit(&pcp->pc_lock);
			mutex_exit(&ps->ps_lock);
			break;
		}

		/*
		 * If PC_POLLWAKE is set, a pollwakeup() was performed on
		 * one of the file descriptors.  This can happen only if
		 * one of the VOP_POLL() functions dropped pcp->pc_lock.
		 * The only current cases of this is in procfs (prpoll())
		 * and STREAMS (strpoll()).
		 */
		if (pcp->pc_flag & PC_POLLWAKE)
			continue;

		/*
		 * If you get here, the poll of fds was unsuccessful.
		 * Wait until some fd becomes readable, writable, or gets
		 * an exception, or until a signal or a timeout occurs.
		 * Do not check for signals if we have a zero timeout.
		 */
		mutex_exit(&ps->ps_lock);
		if (deadline == 0) {
			error = -1;
		} else {
			error = cv_timedwait_sig_hrtime(&pcp->pc_cv,
			    &pcp->pc_lock, deadline);
		}
		mutex_exit(&pcp->pc_lock);
		/*
		 * If we have received a signal or timed out
		 * then break out and return.
		 */
		if (error <= 0) {
			error = (error == 0) ? EINTR : 0;
			break;
		}
		/*
		 * We have not received a signal or timed out.
		 * Continue around and poll fds again.
		 */
		mutex_enter(&ps->ps_lock);
		mutex_enter(&pcp->pc_lock);
	}

pollout:
	/*
	 * If we changed the signal mask but we received
	 * no signal then restore the signal mask.
	 * Otherwise psig() will deal with the signal mask.
	 */
	if (ksetp != NULL) {
		mutex_enter(&p->p_lock);
		if (lwp->lwp_cursig == 0) {
			t->t_hold = lwp->lwp_sigoldmask;
			t->t_flag &= ~T_TOMASK;
		}
		mutex_exit(&p->p_lock);
	}

	if (error)
		return (set_errno(error));

	/*
	 * Copy out the events and return the fdcnt to the user.
	 */
	if (nfds != 0 &&
	    copyout(pollfdp, fds, nfds * sizeof (pollfd_t)))
		return (set_errno(EFAULT));

#ifdef DEBUG
	/*
	 * Another sanity check:
	 */
	if (fdcnt) {
		int	reventcnt = 0;

		for (i = 0; i < nfds; i++) {
			if (pollfdp[i].fd < 0) {
				ASSERT(pollfdp[i].revents == 0);
				continue;
			}
			if (pollfdp[i].revents) {
				reventcnt++;
			}
		}
		ASSERT(fdcnt == reventcnt);
	} else {
		for (i = 0; i < nfds; i++) {
			ASSERT(pollfdp[i].revents == 0);
		}
	}
#endif	/* DEBUG */

	return (fdcnt);
}

/*
 * This is the system call trap that poll(),
 * select() and pselect() are built upon.
 * It is a private interface between libc and the kernel.
 */
int
pollsys(pollfd_t *fds, nfds_t nfds, timespec_t *timeoutp, sigset_t *setp)
{
	timespec_t ts;
	timespec_t *tsp;
	sigset_t set;
	k_sigset_t kset;
	k_sigset_t *ksetp;
	model_t datamodel = get_udatamodel();

	if (timeoutp == NULL)
		tsp = NULL;
	else {
		if (datamodel == DATAMODEL_NATIVE) {
			if (copyin(timeoutp, &ts, sizeof (ts)))
				return (set_errno(EFAULT));
		} else {
			timespec32_t ts32;

			if (copyin(timeoutp, &ts32, sizeof (ts32)))
				return (set_errno(EFAULT));
			TIMESPEC32_TO_TIMESPEC(&ts, &ts32)
		}

		if (itimerspecfix(&ts))
			return (set_errno(EINVAL));
		tsp = &ts;
	}

	if (setp == NULL)
		ksetp = NULL;
	else {
		if (copyin(setp, &set, sizeof (set)))
			return (set_errno(EFAULT));
		sigutok(&set, &kset);
		ksetp = &kset;
	}

	return (poll_common(fds, nfds, tsp, ksetp));
}

/*
 * Clean up any state left around by poll(2). Called when a thread exits.
 */
void
pollcleanup()
{
	pollstate_t *ps = curthread->t_pollstate;
	pollcache_t *pcp;

	if (ps == NULL)
		return;
	pcp = ps->ps_pcache;
	/*
	 * free up all cached poll fds
	 */
	if (pcp == NULL) {
		/* this pollstate is used by /dev/poll */
		goto pollcleanout;
	}

	if (pcp->pc_bitmap != NULL) {
		ASSERT(MUTEX_NOT_HELD(&ps->ps_lock));
		/*
		 * a close lwp can race with us when cleaning up a polldat
		 * entry. We hold the ps_lock when cleaning hash table.
		 * Since this pollcache is going away anyway, there is no
		 * need to hold the pc_lock.
		 */
		mutex_enter(&ps->ps_lock);
		pcache_clean(pcp);
		mutex_exit(&ps->ps_lock);
#ifdef DEBUG
		/*
		 * At this point, all fds cached by this lwp should be
		 * cleaned up. There should be no fd in fi_list still
		 * reference this thread.
		 */
		checkfpollinfo();	/* sanity check */
		pollcheckphlist();	/* sanity check */
#endif	/* DEBUG */
	}
	/*
	 * Be sure no one is referencing thread before exiting
	 */
	mutex_enter(&pcp->pc_no_exit);
	ASSERT(pcp->pc_busy >= 0);
	while (pcp->pc_busy > 0)
		cv_wait(&pcp->pc_busy_cv, &pcp->pc_no_exit);
	mutex_exit(&pcp->pc_no_exit);
pollcleanout:
	pollstate_destroy(ps);
	curthread->t_pollstate = NULL;
}

/*
 * pollwakeup() - poke threads waiting in poll() for some event
 * on a particular object.
 *
 * The threads hanging off of the specified pollhead structure are scanned.
 * If their event mask matches the specified event(s), then pollnotify() is
 * called to poke the thread.
 *
 * Multiple events may be specified.  When POLLHUP or POLLERR are specified,
 * all waiting threads are poked.
 *
 * It is important that pollnotify() not drop the lock protecting the list
 * of threads.
 */
void
pollwakeup(pollhead_t *php, short events_arg)
{
	polldat_t	*pdp;
	int		events = (ushort_t)events_arg;
	struct plist {
		port_t *pp;
		int	pevents;
		struct plist *next;
		};
	struct plist *plhead = NULL, *pltail = NULL;

retry:
	PH_ENTER(php);

	for (pdp = php->ph_list; pdp; pdp = pdp->pd_next) {
		if ((pdp->pd_events & events) ||
		    (events & (POLLHUP | POLLERR))) {

			pollcache_t 	*pcp;

			if (pdp->pd_portev != NULL) {
				port_kevent_t	*pkevp = pdp->pd_portev;
				/*
				 * Object (fd) is associated with an event port,
				 * => send event notification to the port.
				 */
				ASSERT(pkevp->portkev_source == PORT_SOURCE_FD);
				mutex_enter(&pkevp->portkev_lock);
				if (pkevp->portkev_flags & PORT_KEV_VALID) {
					int pevents;

					pkevp->portkev_flags &= ~PORT_KEV_VALID;
					pkevp->portkev_events |= events &
					    (pdp->pd_events | POLLHUP |
					    POLLERR);
					/*
					 * portkev_lock mutex will be released
					 * by port_send_event().
					 */
					port_send_event(pkevp);

					/*
					 * If we have some thread polling the
					 * port's fd, add it to the list. They
					 * will be notified later.
					 * The port_pollwkup() will flag the
					 * port_t so that it will not disappear
					 * till port_pollwkdone() is called.
					 */
					pevents =
					    port_pollwkup(pkevp->portkev_port);
					if (pevents) {
						struct plist *t;
						t = kmem_zalloc(
						    sizeof (struct plist),
						    KM_SLEEP);
						t->pp = pkevp->portkev_port;
						t->pevents = pevents;
						if (plhead == NULL) {
							plhead = t;
						} else {
							pltail->next = t;
						}
						pltail = t;
					}
				} else {
					mutex_exit(&pkevp->portkev_lock);
				}
				continue;
			}

			pcp = pdp->pd_pcache;

			/*
			 * Try to grab the lock for this thread. If
			 * we don't get it then we may deadlock so
			 * back out and restart all over again. Note
			 * that the failure rate is very very low.
			 */
			if (mutex_tryenter(&pcp->pc_lock)) {
				pollnotify(pcp, pdp->pd_fd);
				mutex_exit(&pcp->pc_lock);
			} else {
				/*
				 * We are here because:
				 *	1) This thread has been woke up
				 *	   and is trying to get out of poll().
				 *	2) Some other thread is also here
				 *	   but with a different pollhead lock.
				 *
				 * So, we need to drop the lock on pollhead
				 * because of (1) but we want to prevent
				 * that thread from doing lwp_exit() or
				 * devpoll close. We want to ensure that
				 * the pollcache pointer is still invalid.
				 *
				 * Solution: Grab the pcp->pc_no_exit lock,
				 * increment the pc_busy counter, drop every
				 * lock in sight. Get out of the way and wait
				 * for type (2) threads to finish.
				 */

				mutex_enter(&pcp->pc_no_exit);
				pcp->pc_busy++;	/* prevents exit()'s */
				mutex_exit(&pcp->pc_no_exit);

				PH_EXIT(php);
				mutex_enter(&pcp->pc_lock);
				mutex_exit(&pcp->pc_lock);
				mutex_enter(&pcp->pc_no_exit);
				pcp->pc_busy--;
				if (pcp->pc_busy == 0) {
					/*
					 * Wakeup the thread waiting in
					 * thread_exit().
					 */
					cv_signal(&pcp->pc_busy_cv);
				}
				mutex_exit(&pcp->pc_no_exit);
				goto retry;
			}
		}
	}


	/*
	 * Event ports - If this php is of the port on the list,
	 * call port_pollwkdone() to release it. The port_pollwkdone()
	 * needs to be called before dropping the PH lock so that any new
	 * thread attempting to poll this port are blocked. There can be
	 * only one thread here in pollwakeup notifying this port's fd.
	 */
	if (plhead != NULL && &plhead->pp->port_pollhd == php) {
		struct plist *t;
		port_pollwkdone(plhead->pp);
		t = plhead;
		plhead = plhead->next;
		kmem_free(t, sizeof (struct plist));
	}
	PH_EXIT(php);

	/*
	 * Event ports - Notify threads polling the event port's fd.
	 * This is normally done in port_send_event() where it calls
	 * pollwakeup() on the port. But, for PORT_SOURCE_FD source alone,
	 * we do it here in pollwakeup() to avoid a recursive call.
	 */
	if (plhead != NULL) {
		php = &plhead->pp->port_pollhd;
		events = plhead->pevents;
		goto retry;
	}
}

/*
 * This function is called to inform a thread (or threads) that an event being
 * polled on has occurred.  The pollstate lock on the thread should be held
 * on entry.
 */
void
pollnotify(pollcache_t *pcp, int fd)
{
	ASSERT(fd < pcp->pc_mapsize);
	ASSERT(MUTEX_HELD(&pcp->pc_lock));
	BT_SET(pcp->pc_bitmap, fd);
	pcp->pc_flag |= PC_POLLWAKE;
	cv_broadcast(&pcp->pc_cv);
	pcache_wake_parents(pcp);
}

/*
 * add a polldat entry to pollhead ph_list. The polldat struct is used
 * by pollwakeup to wake sleeping pollers when polled events has happened.
 */
void
pollhead_insert(pollhead_t *php, polldat_t *pdp)
{
	PH_ENTER(php);
	ASSERT(pdp->pd_next == NULL);
#ifdef DEBUG
	{
		/*
		 * the polldat should not be already on the list
		 */
		polldat_t *wp;
		for (wp = php->ph_list; wp; wp = wp->pd_next) {
			ASSERT(wp != pdp);
		}
	}
#endif	/* DEBUG */
	pdp->pd_next = php->ph_list;
	php->ph_list = pdp;
	PH_EXIT(php);
}

/*
 * Delete the polldat entry from ph_list.
 */
void
pollhead_delete(pollhead_t *php, polldat_t *pdp)
{
	polldat_t *wp;
	polldat_t **wpp;

	PH_ENTER(php);
	for (wpp = &php->ph_list; (wp = *wpp) != NULL; wpp = &wp->pd_next) {
		if (wp == pdp) {
			*wpp = pdp->pd_next;
			pdp->pd_next = NULL;
			break;
		}
	}
#ifdef DEBUG
	/* assert that pdp is no longer in the list */
	for (wp = *wpp; wp; wp = wp->pd_next) {
		ASSERT(wp != pdp);
	}
#endif	/* DEBUG */
	PH_EXIT(php);
}

/*
 * walk through the poll fd lists to see if they are identical. This is an
 * expensive operation and should not be done more than once for each poll()
 * call.
 *
 * As an optimization (i.e., not having to go through the lists more than
 * once), this routine also clear the revents field of pollfd in 'current'.
 * Zeroing out the revents field of each entry in current poll list is
 * required by poll man page.
 *
 * Since the events field of cached list has illegal poll events filtered
 * out, the current list applies the same filtering before comparison.
 *
 * The routine stops when it detects a meaningful difference, or when it
 * exhausts the lists.
 */
int
pcacheset_cmp(pollfd_t *current, pollfd_t *cached, pollfd_t *newlist, int n)
{
	int    ix;

	for (ix = 0; ix < n; ix++) {
		/* Prefetch 64 bytes worth of 8-byte elements */
		if ((ix & 0x7) == 0) {
			prefetch_write_many((caddr_t)&current[ix + 8]);
			prefetch_write_many((caddr_t)&cached[ix + 8]);
		}
		if (current[ix].fd == cached[ix].fd) {
			/*
			 * Filter out invalid poll events while we are in
			 * inside the loop.
			 */
			if (current[ix].events & ~VALID_POLL_EVENTS) {
				current[ix].events &= VALID_POLL_EVENTS;
				if (newlist != NULL)
					newlist[ix].events = current[ix].events;
			}
			if (current[ix].events == cached[ix].events) {
				current[ix].revents = 0;
				continue;
			}
		}
		if ((current[ix].fd < 0) && (cached[ix].fd < 0)) {
			current[ix].revents = 0;
			continue;
		}
		return (ix);
	}
	return (ix);
}

/*
 * This routine returns a pointer to a cached poll fd entry, or NULL if it
 * does not find it in the hash table.
 */
polldat_t *
pcache_lookup_fd(pollcache_t *pcp, int fd)
{
	int hashindex;
	polldat_t *pdp;

	hashindex = POLLHASH(pcp->pc_hashsize, fd);
	pdp = pcp->pc_hash[hashindex];
	while (pdp != NULL) {
		if (pdp->pd_fd == fd)
			break;
		pdp = pdp->pd_hashnext;
	}
	return (pdp);
}

polldat_t *
pcache_alloc_fd(int nsets)
{
	polldat_t *pdp;

	pdp = kmem_zalloc(sizeof (polldat_t), KM_SLEEP);
	if (nsets > 0) {
		pdp->pd_ref = kmem_zalloc(sizeof (xref_t) * nsets, KM_SLEEP);
		pdp->pd_nsets = nsets;
	}
	return (pdp);
}

/*
 * This routine  inserts a polldat into the pollcache's hash table. It
 * may be necessary to grow the size of the hash table.
 */
void
pcache_insert_fd(pollcache_t *pcp, polldat_t *pdp, nfds_t nfds)
{
	int hashindex;
	int fd;

	if ((pcp->pc_fdcount > pcp->pc_hashsize * POLLHASHTHRESHOLD) ||
	    (nfds > pcp->pc_hashsize * POLLHASHTHRESHOLD)) {
		pcache_grow_hashtbl(pcp, nfds);
	}
	fd = pdp->pd_fd;
	hashindex = POLLHASH(pcp->pc_hashsize, fd);
	pdp->pd_hashnext = pcp->pc_hash[hashindex];
	pcp->pc_hash[hashindex] = pdp;
	pcp->pc_fdcount++;

#ifdef DEBUG
	{
		/*
		 * same fd should not appear on a hash list twice
		 */
		polldat_t *pdp1;
		for (pdp1 = pdp->pd_hashnext; pdp1; pdp1 = pdp1->pd_hashnext) {
			ASSERT(pdp->pd_fd != pdp1->pd_fd);
		}
	}
#endif	/* DEBUG */
}

/*
 * Grow the hash table -- either double the table size or round it to the
 * nearest multiples of POLLHASHCHUNKSZ, whichever is bigger. Rehash all the
 * elements on the hash table.
 */
void
pcache_grow_hashtbl(pollcache_t *pcp, nfds_t nfds)
{
	int	oldsize;
	polldat_t **oldtbl;
	polldat_t *pdp, *pdp1;
	int	i;
#ifdef DEBUG
	int	count = 0;
#endif

	ASSERT(pcp->pc_hashsize % POLLHASHCHUNKSZ == 0);
	oldsize = pcp->pc_hashsize;
	oldtbl = pcp->pc_hash;
	if (nfds > pcp->pc_hashsize * POLLHASHINC) {
		pcp->pc_hashsize = (nfds + POLLHASHCHUNKSZ - 1) &
		    ~(POLLHASHCHUNKSZ - 1);
	} else {
		pcp->pc_hashsize = pcp->pc_hashsize * POLLHASHINC;
	}
	pcp->pc_hash = kmem_zalloc(pcp->pc_hashsize * sizeof (polldat_t *),
	    KM_SLEEP);
	/*
	 * rehash existing elements
	 */
	pcp->pc_fdcount = 0;
	for (i = 0; i < oldsize; i++) {
		pdp = oldtbl[i];
		while (pdp != NULL) {
			pdp1 = pdp->pd_hashnext;
			pcache_insert_fd(pcp, pdp, nfds);
			pdp = pdp1;
#ifdef DEBUG
			count++;
#endif
		}
	}
	kmem_free(oldtbl, oldsize * sizeof (polldat_t *));
	ASSERT(pcp->pc_fdcount == count);
}

void
pcache_grow_map(pollcache_t *pcp, int fd)
{
	int  	newsize;
	ulong_t	*newmap;

	/*
	 * grow to nearest multiple of POLLMAPCHUNK, assuming POLLMAPCHUNK is
	 * power of 2.
	 */
	newsize = (fd + POLLMAPCHUNK) & ~(POLLMAPCHUNK - 1);
	newmap = kmem_zalloc((newsize / BT_NBIPUL) * sizeof (ulong_t),
	    KM_SLEEP);
	/*
	 * don't want pollwakeup to set a bit while growing the bitmap.
	 */
	ASSERT(mutex_owned(&pcp->pc_lock) == 0);
	mutex_enter(&pcp->pc_lock);
	bcopy(pcp->pc_bitmap, newmap,
	    (pcp->pc_mapsize / BT_NBIPUL) * sizeof (ulong_t));
	kmem_free(pcp->pc_bitmap,
	    (pcp->pc_mapsize /BT_NBIPUL) * sizeof (ulong_t));
	pcp->pc_bitmap = newmap;
	pcp->pc_mapsize = newsize;
	mutex_exit(&pcp->pc_lock);
}

/*
 * remove all the reference from pollhead list and fpollinfo lists.
 */
void
pcache_clean(pollcache_t *pcp)
{
	int i;
	polldat_t **hashtbl;
	polldat_t *pdp;

	ASSERT(MUTEX_HELD(&curthread->t_pollstate->ps_lock));
	hashtbl = pcp->pc_hash;
	for (i = 0; i < pcp->pc_hashsize; i++) {
		for (pdp = hashtbl[i]; pdp; pdp = pdp->pd_hashnext) {
			if (pdp->pd_php != NULL) {
				pollhead_delete(pdp->pd_php, pdp);
				pdp->pd_php = NULL;
			}
			if (pdp->pd_fp != NULL) {
				delfpollinfo(pdp->pd_fd);
				pdp->pd_fp = NULL;
			}
		}
	}
}

void
pcacheset_invalidate(pollstate_t *ps, polldat_t *pdp)
{
	int 	i;
	int	fd = pdp->pd_fd;

	/*
	 * we come here because an earlier close() on this cached poll fd.
	 */
	ASSERT(pdp->pd_fp == NULL);
	ASSERT(MUTEX_HELD(&ps->ps_lock));
	pdp->pd_events = 0;
	for (i = 0; i < ps->ps_nsets; i++) {
		xref_t		*refp;
		pollcacheset_t	*pcsp;

		ASSERT(pdp->pd_ref != NULL);
		refp = &pdp->pd_ref[i];
		if (refp->xf_refcnt) {
			ASSERT(refp->xf_position >= 0);
			pcsp = &ps->ps_pcacheset[i];
			if (refp->xf_refcnt == 1) {
				pcsp->pcs_pollfd[refp->xf_position].fd = -1;
				refp->xf_refcnt = 0;
				pdp->pd_count--;
			} else if (refp->xf_refcnt > 1) {
				int	j;

				/*
				 * turn off every appearance in pcs_pollfd list
				 */
				for (j = refp->xf_position;
				    j < pcsp->pcs_nfds; j++) {
					if (pcsp->pcs_pollfd[j].fd == fd) {
						pcsp->pcs_pollfd[j].fd = -1;
						refp->xf_refcnt--;
						pdp->pd_count--;
					}
				}
			}
			ASSERT(refp->xf_refcnt == 0);
			refp->xf_position = POLLPOSINVAL;
		}
	}
	ASSERT(pdp->pd_count == 0);
}

/*
 * Insert poll fd into the pollcache, and add poll registration.
 * This routine is called after getf() and before releasef(). So the vnode
 * can not disappear even if we block here.
 * If there is an error, the polled fd is not cached.
 */
int
pcache_insert(pollstate_t *ps, file_t *fp, pollfd_t *pollfdp, int *fdcntp,
    ssize_t pos, int which)
{
	pollcache_t	*pcp = ps->ps_pcache;
	polldat_t	*pdp;
	int		error;
	int		fd;
	pollhead_t	*memphp = NULL;
	xref_t		*refp;
	int		newpollfd = 0;

	ASSERT(MUTEX_HELD(&ps->ps_lock));
	/*
	 * The poll caching uses the existing VOP_POLL interface. If there
	 * is no polled events, we want the polled device to set its "some
	 * one is sleeping in poll" flag. When the polled events happen
	 * later, the driver will call pollwakeup(). We achieve this by
	 * always passing 0 in the third parameter ("anyyet") when calling
	 * VOP_POLL. This parameter is not looked at by drivers when the
	 * polled events exist. If a driver chooses to ignore this parameter
	 * and call pollwakeup whenever the polled events happen, that will
	 * be OK too.
	 */
	ASSERT(curthread->t_pollcache == NULL);
	error = VOP_POLL(fp->f_vnode, pollfdp->events, 0, &pollfdp->revents,
	    &memphp, NULL);
	if (error) {
		return (error);
	}
	if (pollfdp->revents) {
		(*fdcntp)++;
	}
	/*
	 * polling the underlying device succeeded. Now we can cache it.
	 * A close can't come in here because we have not done a releasef()
	 * yet.
	 */
	fd = pollfdp->fd;
	pdp = pcache_lookup_fd(pcp, fd);
	if (pdp == NULL) {
		ASSERT(ps->ps_nsets > 0);
		pdp = pcache_alloc_fd(ps->ps_nsets);
		newpollfd = 1;
	}
	/*
	 * If this entry was used to cache a poll fd which was closed, and
	 * this entry has not been cleaned, do it now.
	 */
	if ((pdp->pd_count > 0) && (pdp->pd_fp == NULL)) {
		pcacheset_invalidate(ps, pdp);
		ASSERT(pdp->pd_next == NULL);
	}
	if (pdp->pd_count == 0) {
		pdp->pd_fd = fd;
		pdp->pd_fp = fp;
		addfpollinfo(fd);
		pdp->pd_thread = curthread;
		pdp->pd_pcache = pcp;
		/*
		 * the entry is never used or cleared by removing a cached
		 * pollfd (pcache_delete_fd). So all the fields should be clear.
		 */
		ASSERT(pdp->pd_next == NULL);
	}

	/*
	 * A polled fd is considered cached. So there should be a fpollinfo
	 * entry on uf_fpollinfo list.
	 */
	ASSERT(infpollinfo(fd));
	/*
	 * If there is an inconsistency, we want to know it here.
	 */
	ASSERT(pdp->pd_fp == fp);

	/*
	 * XXX pd_events is a union of all polled events on this fd, possibly
	 * by different threads. Unless this is a new first poll(), pd_events
	 * never shrinks. If an event is no longer polled by a process, there
	 * is no way to cancel that event. In that case, poll degrade to its
	 * old form -- polling on this fd every time poll() is called. The
	 * assumption is an app always polls the same type of events.
	 */
	pdp->pd_events |= pollfdp->events;

	pdp->pd_count++;
	/*
	 * There is not much special handling for multiple appearances of
	 * same fd other than xf_position always recording the first
	 * appearance in poll list. If this is called from pcacheset_cache_list,
	 * a VOP_POLL is called on every pollfd entry; therefore each
	 * revents and fdcnt should be set correctly. If this is called from
	 * pcacheset_resolve, we don't care about fdcnt here. Pollreadmap will
	 * pick up the right count and handle revents field of each pollfd
	 * entry.
	 */
	ASSERT(pdp->pd_ref != NULL);
	refp = &pdp->pd_ref[which];
	if (refp->xf_refcnt == 0) {
		refp->xf_position = pos;
	} else {
		/*
		 * xf_position records the fd's first appearance in poll list
		 */
		if (pos < refp->xf_position) {
			refp->xf_position = pos;
		}
	}
	ASSERT(pollfdp->fd == ps->ps_pollfd[refp->xf_position].fd);
	refp->xf_refcnt++;
	if (fd >= pcp->pc_mapsize) {
		pcache_grow_map(pcp, fd);
	}
	if (fd > pcp->pc_mapend) {
		pcp->pc_mapend = fd;
	}
	if (newpollfd != 0) {
		pcache_insert_fd(ps->ps_pcache, pdp, ps->ps_nfds);
	}
	if (memphp) {
		if (pdp->pd_php == NULL) {
			pollhead_insert(memphp, pdp);
			pdp->pd_php = memphp;
		} else {
			if (memphp != pdp->pd_php) {
				/*
				 * layered devices (e.g. console driver)
				 * may change the vnode and thus the pollhead
				 * pointer out from underneath us.
				 */
				pollhead_delete(pdp->pd_php, pdp);
				pollhead_insert(memphp, pdp);
				pdp->pd_php = memphp;
			}
		}
	}
	/*
	 * Since there is a considerable window between VOP_POLL and when
	 * we actually put the polldat struct on the pollhead list, we could
	 * miss a pollwakeup. In the case of polling additional events, we
	 * don't update the events until after VOP_POLL. So we could miss
	 * pollwakeup there too. So we always set the bit here just to be
	 * safe. The real performance gain is in subsequent pcache_poll.
	 */
	mutex_enter(&pcp->pc_lock);
	BT_SET(pcp->pc_bitmap, fd);
	mutex_exit(&pcp->pc_lock);
	return (0);
}

/*
 * The entry is not really deleted. The fields are cleared so that the
 * entry is no longer useful, but it will remain in the hash table for reuse
 * later. It will be freed when the polling lwp exits.
 */
int
pcache_delete_fd(pollstate_t *ps, int fd, size_t pos, int which, uint_t cevent)
{
	pollcache_t	*pcp = ps->ps_pcache;
	polldat_t	*pdp;
	xref_t		*refp;

	ASSERT(fd < pcp->pc_mapsize);
	ASSERT(MUTEX_HELD(&ps->ps_lock));

	pdp = pcache_lookup_fd(pcp, fd);
	ASSERT(pdp != NULL);
	ASSERT(pdp->pd_count > 0);
	ASSERT(pdp->pd_ref != NULL);
	refp = &pdp->pd_ref[which];
	if (pdp->pd_count == 1) {
		pdp->pd_events = 0;
		refp->xf_position = POLLPOSINVAL;
		ASSERT(refp->xf_refcnt == 1);
		refp->xf_refcnt = 0;
		if (pdp->pd_php) {
			/*
			 * It is possible for a wakeup thread to get ahead
			 * of the following pollhead_delete and set the bit in
			 * bitmap.  It is OK because the bit will be cleared
			 * here anyway.
			 */
			pollhead_delete(pdp->pd_php, pdp);
			pdp->pd_php = NULL;
		}
		pdp->pd_count = 0;
		if (pdp->pd_fp != NULL) {
			pdp->pd_fp = NULL;
			delfpollinfo(fd);
		}
		mutex_enter(&pcp->pc_lock);
		BT_CLEAR(pcp->pc_bitmap, fd);
		mutex_exit(&pcp->pc_lock);
		return (0);
	}
	if ((cevent & POLLCLOSED) == POLLCLOSED) {
		/*
		 * fd cached here has been closed. This is the first
		 * pcache_delete_fd called after the close. Clean up the
		 * entire entry.
		 */
		pcacheset_invalidate(ps, pdp);
		ASSERT(pdp->pd_php == NULL);
		mutex_enter(&pcp->pc_lock);
		BT_CLEAR(pcp->pc_bitmap, fd);
		mutex_exit(&pcp->pc_lock);
		return (0);
	}
#ifdef DEBUG
	if (getf(fd) != NULL) {
		ASSERT(infpollinfo(fd));
		releasef(fd);
	}
#endif	/* DEBUG */
	pdp->pd_count--;
	ASSERT(refp->xf_refcnt > 0);
	if (--refp->xf_refcnt == 0) {
		refp->xf_position = POLLPOSINVAL;
	} else {
		ASSERT(pos >= refp->xf_position);
		if (pos == refp->xf_position) {
			/*
			 * The xref position is no longer valid.
			 * Reset it to a special value and let
			 * caller know it needs to updatexref()
			 * with a new xf_position value.
			 */
			refp->xf_position = POLLPOSTRANS;
			return (1);
		}
	}
	return (0);
}

void
pcache_update_xref(pollcache_t *pcp, int fd, ssize_t pos, int which)
{
	polldat_t	*pdp;

	pdp = pcache_lookup_fd(pcp, fd);
	ASSERT(pdp != NULL);
	ASSERT(pdp->pd_ref != NULL);
	pdp->pd_ref[which].xf_position = pos;
}

#ifdef DEBUG
/*
 * For each polled fd, it's either in the bitmap or cached in
 * pcache hash table. If this routine returns 0, something is wrong.
 */
static int
pollchecksanity(pollstate_t *ps, nfds_t nfds)
{
	int    		i;
	int		fd;
	pollcache_t	*pcp = ps->ps_pcache;
	polldat_t	*pdp;
	pollfd_t	*pollfdp = ps->ps_pollfd;
	file_t		*fp;

	ASSERT(MUTEX_HELD(&ps->ps_lock));
	for (i = 0; i < nfds; i++) {
		fd = pollfdp[i].fd;
		if (fd < 0) {
			ASSERT(pollfdp[i].revents == 0);
			continue;
		}
		if (pollfdp[i].revents == POLLNVAL)
			continue;
		if ((fp = getf(fd)) == NULL)
			continue;
		pdp = pcache_lookup_fd(pcp, fd);
		ASSERT(pdp != NULL);
		ASSERT(infpollinfo(fd));
		ASSERT(pdp->pd_fp == fp);
		releasef(fd);
		if (BT_TEST(pcp->pc_bitmap, fd))
			continue;
		if (pdp->pd_php == NULL)
			return (0);
	}
	return (1);
}
#endif	/* DEBUG */

/*
 * resolve the difference between the current poll list and a cached one.
 */
int
pcacheset_resolve(pollstate_t *ps, nfds_t nfds, int *fdcntp, int which)
{
	int    		i;
	pollcache_t	*pcp = ps->ps_pcache;
	pollfd_t	*newlist = NULL;
	pollfd_t	*current = ps->ps_pollfd;
	pollfd_t	*cached;
	pollcacheset_t	*pcsp;
	int		common;
	int		count = 0;
	int		offset;
	int		remain;
	int		fd;
	file_t		*fp;
	int		fdcnt = 0;
	int		cnt = 0;
	nfds_t		old_nfds;
	int		error = 0;
	int		mismatch = 0;

	ASSERT(MUTEX_HELD(&ps->ps_lock));
#ifdef DEBUG
	checkpolldat(ps);
#endif
	pcsp = &ps->ps_pcacheset[which];
	old_nfds = pcsp->pcs_nfds;
	common = (nfds > old_nfds) ? old_nfds : nfds;
	if (nfds != old_nfds) {
		/*
		 * the length of poll list has changed. allocate a new
		 * pollfd list.
		 */
		newlist = kmem_alloc(nfds * sizeof (pollfd_t), KM_SLEEP);
		bcopy(current, newlist, sizeof (pollfd_t) * nfds);
	}
	/*
	 * Compare the overlapping part of the current fd list with the
	 * cached one. Whenever a difference is found, resolve it.
	 * The comparison is done on the current poll list and the
	 * cached list. But we may be setting up the newlist to be the
	 * cached list for next poll.
	 */
	cached = pcsp->pcs_pollfd;
	remain = common;

	while (count < common) {
		int	tmpfd;
		pollfd_t *np;

		np = (newlist != NULL) ? &newlist[count] : NULL;
		offset = pcacheset_cmp(&current[count], &cached[count], np,
		    remain);
		/*
		 * Collect stats. If lists are completed the first time,
		 * it's a hit. Otherwise, it's a partial hit or miss.
		 */
		if ((count == 0) && (offset == common)) {
			pollstats.pollcachehit.value.ui64++;
		} else {
			mismatch++;
		}
		count += offset;
		if (offset < remain) {
			ASSERT(count < common);
			ASSERT((current[count].fd != cached[count].fd) ||
			    (current[count].events != cached[count].events));
			/*
			 * Filter out invalid events.
			 */
			if (current[count].events & ~VALID_POLL_EVENTS) {
				if (newlist != NULL) {
					newlist[count].events =
					    current[count].events &=
					    VALID_POLL_EVENTS;
				} else {
					current[count].events &=
					    VALID_POLL_EVENTS;
				}
			}
			/*
			 * when resolving a difference, we always remove the
			 * fd from cache before inserting one into cache.
			 */
			if (cached[count].fd >= 0) {
				tmpfd = cached[count].fd;
				if (pcache_delete_fd(ps, tmpfd, count, which,
				    (uint_t)cached[count].events)) {
					/*
					 * This should be rare but needed for
					 * correctness.
					 *
					 * The first appearance in cached list
					 * is being "turned off". The same fd
					 * appear more than once in the cached
					 * poll list. Find the next one on the
					 * list and update the cached
					 * xf_position field.
					 */
					for (i = count + 1; i < old_nfds; i++) {
						if (cached[i].fd == tmpfd) {
							pcache_update_xref(pcp,
							    tmpfd, (ssize_t)i,
							    which);
							break;
						}
					}
					ASSERT(i <= old_nfds);
				}
				/*
				 * In case a new cache list is allocated,
				 * need to keep both cache lists in sync
				 * b/c the new one can be freed if we have
				 * an error later.
				 */
				cached[count].fd = -1;
				if (newlist != NULL) {
					newlist[count].fd = -1;
				}
			}
			if ((tmpfd = current[count].fd) >= 0) {
				/*
				 * add to the cached fd tbl and bitmap.
				 */
				if ((fp = getf(tmpfd)) == NULL) {
					current[count].revents = POLLNVAL;
					if (newlist != NULL) {
						newlist[count].fd = -1;
					}
					cached[count].fd = -1;
					fdcnt++;
				} else {
					/*
					 * Here we don't care about the
					 * fdcnt. We will examine the bitmap
					 * later and pick up the correct
					 * fdcnt there. So we never bother
					 * to check value of 'cnt'.
					 */
					error = pcache_insert(ps, fp,
					    &current[count], &cnt,
					    (ssize_t)count, which);
					/*
					 * if no error, we want to do releasef
					 * after we updated cache poll list
					 * entry so that close() won't race
					 * us.
					 */
					if (error) {
						/*
						 * If we encountered an error,
						 * we have invalidated an
						 * entry in cached poll list
						 * (in pcache_delete_fd() above)
						 * but failed to add one here.
						 * This is OK b/c what's in the
						 * cached list is consistent
						 * with content of cache.
						 * It will not have any ill
						 * effect on next poll().
						 */
						releasef(tmpfd);
						if (newlist != NULL) {
							kmem_free(newlist,
							    nfds *
							    sizeof (pollfd_t));
						}
						return (error);
					}
					/*
					 * If we have allocated a new(temp)
					 * cache list, we need to keep both
					 * in sync b/c the new one can be freed
					 * if we have an error later.
					 */
					if (newlist != NULL) {
						newlist[count].fd =
						    current[count].fd;
						newlist[count].events =
						    current[count].events;
					}
					cached[count].fd = current[count].fd;
					cached[count].events =
					    current[count].events;
					releasef(tmpfd);
				}
			} else {
				current[count].revents = 0;
			}
			count++;
			remain = common - count;
		}
	}
	if (mismatch != 0) {
		if (mismatch == common) {
			pollstats.pollcachemiss.value.ui64++;
		} else {
			pollstats.pollcachephit.value.ui64++;
		}
	}
	/*
	 * take care of the non overlapping part of a list
	 */
	if (nfds > old_nfds) {
		ASSERT(newlist != NULL);
		for (i = old_nfds; i < nfds; i++) {
			/* filter out invalid events */
			if (current[i].events & ~VALID_POLL_EVENTS) {
				newlist[i].events = current[i].events =
				    current[i].events & VALID_POLL_EVENTS;
			}
			if ((fd = current[i].fd) < 0) {
				current[i].revents = 0;
				continue;
			}
			/*
			 * add to the cached fd tbl and bitmap.
			 */
			if ((fp = getf(fd)) == NULL) {
				current[i].revents = POLLNVAL;
				newlist[i].fd = -1;
				fdcnt++;
				continue;
			}
			/*
			 * Here we don't care about the
			 * fdcnt. We will examine the bitmap
			 * later and pick up the correct
			 * fdcnt there. So we never bother to
			 * check 'cnt'.
			 */
			error = pcache_insert(ps, fp, &current[i], &cnt,
			    (ssize_t)i, which);
			releasef(fd);
			if (error) {
				/*
				 * Here we are half way through adding newly
				 * polled fd. Undo enough to keep the cache
				 * list consistent with the cache content.
				 */
				pcacheset_remove_list(ps, current, old_nfds,
				    i, which, 0);
				kmem_free(newlist, nfds * sizeof (pollfd_t));
				return (error);
			}
		}
	}
	if (old_nfds > nfds) {
		/*
		 * remove the fd's which are no longer polled.
		 */
		pcacheset_remove_list(ps, pcsp->pcs_pollfd, nfds, old_nfds,
		    which, 1);
	}
	/*
	 * set difference resolved. update nfds and cachedlist
	 * in pollstate struct.
	 */
	if (newlist != NULL) {
		kmem_free(pcsp->pcs_pollfd, old_nfds * sizeof (pollfd_t));
		/*
		 * By now, the pollfd.revents field should
		 * all be zeroed.
		 */
		pcsp->pcs_pollfd = newlist;
		pcsp->pcs_nfds = nfds;
	}
	ASSERT(*fdcntp == 0);
	*fdcntp = fdcnt;
	/*
	 * By now for every fd in pollfdp, one of the following should be
	 * true. Otherwise we will miss a polled event.
	 *
	 * 1. the bit corresponding to the fd in bitmap is set. So VOP_POLL
	 *    will be called on this fd in next poll.
	 * 2. the fd is cached in the pcache (i.e. pd_php is set). So
	 *    pollnotify will happen.
	 */
	ASSERT(pollchecksanity(ps, nfds));
	/*
	 * make sure cross reference between cached poll lists and cached
	 * poll fds are correct.
	 */
	ASSERT(pollcheckxref(ps, which));
	/*
	 * ensure each polldat in pollcache reference a polled fd in
	 * pollcacheset.
	 */
#ifdef DEBUG
	checkpolldat(ps);
#endif
	return (0);
}

#ifdef DEBUG
static int
pollscanrevents(pollcache_t *pcp, pollfd_t *pollfdp, nfds_t nfds)
{
	int i;
	int reventcnt = 0;

	for (i = 0; i < nfds; i++) {
		if (pollfdp[i].fd < 0) {
			ASSERT(pollfdp[i].revents == 0);
			continue;
		}
		if (pollfdp[i].revents) {
			reventcnt++;
		}
		if (pollfdp[i].revents && (pollfdp[i].revents != POLLNVAL)) {
			ASSERT(BT_TEST(pcp->pc_bitmap, pollfdp[i].fd));
		}
	}
	return (reventcnt);
}
#endif	/* DEBUG */

/*
 * read the bitmap and poll on fds corresponding to the '1' bits. The ps_lock
 * is held upon entry.
 */
int
pcache_poll(pollfd_t *pollfdp, pollstate_t *ps, nfds_t nfds, int *fdcntp,
    int which)
{
	int		i;
	pollcache_t	*pcp;
	int 		fd;
	int 		begin, end, done;
	pollhead_t	*php;
	int		fdcnt;
	int		error = 0;
	file_t		*fp;
	polldat_t	*pdp;
	xref_t		*refp;
	int		entry;

	pcp = ps->ps_pcache;
	ASSERT(MUTEX_HELD(&ps->ps_lock));
	ASSERT(MUTEX_HELD(&pcp->pc_lock));
retry:
	done = 0;
	begin = 0;
	fdcnt = 0;
	end = pcp->pc_mapend;
	while ((fdcnt < nfds) && !done) {
		php = NULL;
		/*
		 * only poll fds which may have events
		 */
		fd = bt_getlowbit(pcp->pc_bitmap, begin, end);
		ASSERT(fd <= end);
		if (fd >= 0) {
			ASSERT(pollcheckrevents(ps, begin, fd, which));
			/*
			 * adjust map pointers for next round
			 */
			if (fd == end) {
				done = 1;
			} else {
				begin = fd + 1;
			}
			/*
			 * A bitmap caches poll state information of
			 * multiple poll lists. Call VOP_POLL only if
			 * the bit corresponds to an fd in this poll
			 * list.
			 */
			pdp = pcache_lookup_fd(pcp, fd);
			ASSERT(pdp != NULL);
			ASSERT(pdp->pd_ref != NULL);
			refp = &pdp->pd_ref[which];
			if (refp->xf_refcnt == 0)
				continue;
			entry = refp->xf_position;
			ASSERT((entry >= 0) && (entry < nfds));
			ASSERT(pollfdp[entry].fd == fd);
			/*
			 * we are in this routine implies that we have
			 * successfully polled this fd in the past.
			 * Check to see this fd is closed while we are
			 * blocked in poll. This ensures that we don't
			 * miss a close on the fd in the case this fd is
			 * reused.
			 */
			if (pdp->pd_fp == NULL) {
				ASSERT(pdp->pd_count > 0);
				pollfdp[entry].revents = POLLNVAL;
				fdcnt++;
				if (refp->xf_refcnt > 1) {
					/*
					 * this fd appeared multiple time
					 * in the poll list. Find all of them.
					 */
					for (i = entry + 1; i < nfds; i++) {
						if (pollfdp[i].fd == fd) {
							pollfdp[i].revents =
							    POLLNVAL;
							fdcnt++;
						}
					}
				}
				pcacheset_invalidate(ps, pdp);
				continue;
			}
			/*
			 * We can be here polling a device that is being
			 * closed (i.e. the file pointer is set to NULL,
			 * but pollcacheclean has not happened yet).
			 */
			if ((fp = getf(fd)) == NULL) {
				pollfdp[entry].revents = POLLNVAL;
				fdcnt++;
				if (refp->xf_refcnt > 1) {
					/*
					 * this fd appeared multiple time
					 * in the poll list. Find all of them.
					 */
					for (i = entry + 1; i < nfds; i++) {
						if (pollfdp[i].fd == fd) {
							pollfdp[i].revents =
							    POLLNVAL;
							fdcnt++;
						}
					}
				}
				continue;
			}
			ASSERT(pdp->pd_fp == fp);
			ASSERT(infpollinfo(fd));
			/*
			 * Since we no longer hold poll head lock across
			 * VOP_POLL, pollunlock logic can be simplifed.
			 */
			ASSERT(pdp->pd_php == NULL ||
			    MUTEX_NOT_HELD(PHLOCK(pdp->pd_php)));
			/*
			 * underlying file systems may set a "pollpending"
			 * flag when it sees the poll may block. Pollwakeup()
			 * is called by wakeup thread if pollpending is set.
			 * Pass a 0 fdcnt so that the underlying file system
			 * will set the "pollpending" flag set when there is
			 * no polled events.
			 *
			 * Use pollfdp[].events for actual polling because
			 * the pd_events is union of all cached poll events
			 * on this fd. The events parameter also affects
			 * how the polled device sets the "poll pending"
			 * flag.
			 */
			ASSERT(curthread->t_pollcache == NULL);
			error = VOP_POLL(fp->f_vnode, pollfdp[entry].events, 0,
			    &pollfdp[entry].revents, &php, NULL);
			/*
			 * releasef after completely done with this cached
			 * poll entry. To prevent close() coming in to clear
			 * this entry.
			 */
			if (error) {
				releasef(fd);
				break;
			}
			/*
			 * layered devices (e.g. console driver)
			 * may change the vnode and thus the pollhead
			 * pointer out from underneath us.
			 */
			if (php != NULL && pdp->pd_php != NULL &&
			    php != pdp->pd_php) {
				releasef(fd);
				pollhead_delete(pdp->pd_php, pdp);
				pdp->pd_php = php;
				pollhead_insert(php, pdp);
				/*
				 * We could have missed a wakeup on the new
				 * target device. Make sure the new target
				 * gets polled once.
				 */
				BT_SET(pcp->pc_bitmap, fd);
				goto retry;
			}

			if (pollfdp[entry].revents) {
				ASSERT(refp->xf_refcnt >= 1);
				fdcnt++;
				if (refp->xf_refcnt > 1) {
					/*
					 * this fd appeared multiple time
					 * in the poll list. This is rare but
					 * we have to look at all of them for
					 * correctness.
					 */
					error = plist_chkdupfd(fp, pdp, ps,
					    pollfdp, entry, &fdcnt);
					if (error > 0) {
						releasef(fd);
						break;
					}
					if (error < 0) {
						goto retry;
					}
				}
				releasef(fd);
			} else {
				/*
				 * VOP_POLL didn't return any revents. We can
				 * clear the bit in bitmap only if we have the
				 * pollhead ptr cached and no other cached
				 * entry is polling different events on this fd.
				 * VOP_POLL may have dropped the ps_lock. Make
				 * sure pollwakeup has not happened before clear
				 * the bit.
				 */
				if ((pdp->pd_php != NULL) &&
				    (pollfdp[entry].events == pdp->pd_events) &&
				    ((pcp->pc_flag & PC_POLLWAKE) == 0)) {
					BT_CLEAR(pcp->pc_bitmap, fd);
				}
				/*
				 * if the fd can be cached now but not before,
				 * do it now.
				 */
				if ((pdp->pd_php == NULL) && (php != NULL)) {
					pdp->pd_php = php;
					pollhead_insert(php, pdp);
					/*
					 * We are inserting a polldat struct for
					 * the first time. We may have missed a
					 * wakeup on this device. Re-poll once.
					 * This should be a rare event.
					 */
					releasef(fd);
					goto retry;
				}
				if (refp->xf_refcnt > 1) {
					/*
					 * this fd appeared multiple time
					 * in the poll list. This is rare but
					 * we have to look at all of them for
					 * correctness.
					 */
					error = plist_chkdupfd(fp, pdp, ps,
					    pollfdp, entry, &fdcnt);
					if (error > 0) {
						releasef(fd);
						break;
					}
					if (error < 0) {
						goto retry;
					}
				}
				releasef(fd);
			}
		} else {
			done = 1;
			ASSERT(pollcheckrevents(ps, begin, end + 1, which));
		}
	}
	if (!error) {
		ASSERT(*fdcntp + fdcnt == pollscanrevents(pcp, pollfdp, nfds));
		*fdcntp += fdcnt;
	}
	return (error);
}

/*
 * Going through the poll list without much locking. Poll all fds and
 * cache all valid fds in the pollcache.
 */
int
pcacheset_cache_list(pollstate_t *ps, pollfd_t *fds, int *fdcntp, int which)
{
	pollfd_t	*pollfdp = ps->ps_pollfd;
	pollcacheset_t	*pcacheset = ps->ps_pcacheset;
	pollfd_t	*newfdlist;
	int		i;
	int		fd;
	file_t		*fp;
	int		error = 0;

	ASSERT(MUTEX_HELD(&ps->ps_lock));
	ASSERT(which < ps->ps_nsets);
	ASSERT(pcacheset != NULL);
	ASSERT(pcacheset[which].pcs_pollfd == NULL);
	newfdlist  = kmem_alloc(ps->ps_nfds * sizeof (pollfd_t), KM_SLEEP);
	/*
	 * cache the new poll list in pollcachset.
	 */
	bcopy(pollfdp, newfdlist, sizeof (pollfd_t) * ps->ps_nfds);

	pcacheset[which].pcs_pollfd = newfdlist;
	pcacheset[which].pcs_nfds = ps->ps_nfds;
	pcacheset[which].pcs_usradr = (uintptr_t)fds;

	/*
	 * We have saved a copy of current poll fd list in one pollcacheset.
	 * The 'revents' field of the new list is not yet set to 0. Loop
	 * through the new list just to do that is expensive. We do that
	 * while polling the list.
	 */
	for (i = 0; i < ps->ps_nfds; i++) {
		fd = pollfdp[i].fd;
		/*
		 * We also filter out the illegal poll events in the event
		 * field for the cached poll list/set.
		 */
		if (pollfdp[i].events & ~VALID_POLL_EVENTS) {
			newfdlist[i].events = pollfdp[i].events =
			    pollfdp[i].events & VALID_POLL_EVENTS;
		}
		if (fd < 0) {
			pollfdp[i].revents = 0;
			continue;
		}
		if ((fp = getf(fd)) == NULL) {
			pollfdp[i].revents = POLLNVAL;
			/*
			 * invalidate this cache entry in the cached poll list
			 */
			newfdlist[i].fd = -1;
			(*fdcntp)++;
			continue;
		}
		/*
		 * cache this fd.
		 */
		error = pcache_insert(ps, fp, &pollfdp[i], fdcntp, (ssize_t)i,
		    which);
		releasef(fd);
		if (error) {
			/*
			 * Here we are half way through caching a new
			 * poll list. Undo every thing.
			 */
			pcacheset_remove_list(ps, pollfdp, 0, i, which, 0);
			kmem_free(newfdlist, ps->ps_nfds * sizeof (pollfd_t));
			pcacheset[which].pcs_pollfd = NULL;
			pcacheset[which].pcs_usradr = NULL;
			break;
		}
	}
	return (error);
}

/*
 * called by pollcacheclean() to set the fp NULL. It also sets polled events
 * in pcacheset entries to a special events 'POLLCLOSED'. Do a pollwakeup to
 * wake any sleeping poller, then remove the polldat from the driver.
 * The routine is called with ps_pcachelock held.
 */
void
pcache_clean_entry(pollstate_t *ps, int fd)
{
	pollcache_t	*pcp;
	polldat_t	*pdp;
	int		i;

	ASSERT(ps != NULL);
	ASSERT(MUTEX_HELD(&ps->ps_lock));
	pcp = ps->ps_pcache;
	ASSERT(pcp);
	pdp = pcache_lookup_fd(pcp, fd);
	ASSERT(pdp != NULL);
	/*
	 * the corresponding fpollinfo in fi_list has been removed by
	 * a close on this fd. Reset the cached fp ptr here.
	 */
	pdp->pd_fp = NULL;
	/*
	 * XXX - This routine also touches data in pcacheset struct.
	 *
	 * set the event in cached poll lists to POLLCLOSED. This invalidate
	 * the cached poll fd entry in that poll list, which will force a
	 * removal of this cached entry in next poll(). The cleanup is done
	 * at the removal time.
	 */
	ASSERT(pdp->pd_ref != NULL);
	for (i = 0; i < ps->ps_nsets; i++) {
		xref_t		*refp;
		pollcacheset_t	*pcsp;

		refp = &pdp->pd_ref[i];
		if (refp->xf_refcnt) {
			ASSERT(refp->xf_position >= 0);
			pcsp = &ps->ps_pcacheset[i];
			if (refp->xf_refcnt == 1) {
				pcsp->pcs_pollfd[refp->xf_position].events =
				    (short)POLLCLOSED;
			}
			if (refp->xf_refcnt > 1) {
				int	j;
				/*
				 * mark every matching entry in pcs_pollfd
				 */
				for (j = refp->xf_position;
				    j < pcsp->pcs_nfds; j++) {
					if (pcsp->pcs_pollfd[j].fd == fd) {
						pcsp->pcs_pollfd[j].events =
						    (short)POLLCLOSED;
					}
				}
			}
		}
	}
	if (pdp->pd_php) {
		pollwakeup(pdp->pd_php, POLLHUP);
		pollhead_delete(pdp->pd_php, pdp);
		pdp->pd_php = NULL;
	}
}

void
pcache_wake_parents(pollcache_t *pcp)
{
	pcachelink_t *pl, *pln;

	ASSERT(MUTEX_HELD(&pcp->pc_lock));

	for (pl = pcp->pc_parents; pl != NULL; pl = pln) {
		mutex_enter(&pl->pcl_lock);
		if (pl->pcl_state == PCL_VALID) {
			ASSERT(pl->pcl_parent_pc != NULL);
			cv_broadcast(&pl->pcl_parent_pc->pc_cv);
		}
		pln = pl->pcl_parent_next;
		mutex_exit(&pl->pcl_lock);
	}
}

/*
 * Initialize thread pollstate structure.
 * It will persist for the life of the thread, until it calls pollcleanup().
 */
pollstate_t *
pollstate_create()
{
	pollstate_t *ps = curthread->t_pollstate;

	if (ps == NULL) {
		/*
		 * This is the first time this thread has ever polled, so we
		 * have to create its pollstate structure.
		 */
		ps = kmem_zalloc(sizeof (pollstate_t), KM_SLEEP);
		ps->ps_nsets = POLLFDSETS;
		ps->ps_pcacheset = pcacheset_create(ps->ps_nsets);
		curthread->t_pollstate = ps;
	} else {
		ASSERT(ps->ps_depth == 0);
		ASSERT(ps->ps_flags == 0);
		ASSERT(ps->ps_pc_stack[0] == 0);
	}
	return (ps);
}

void
pollstate_destroy(pollstate_t *ps)
{
	if (ps->ps_pollfd != NULL) {
		kmem_free(ps->ps_pollfd, ps->ps_nfds * sizeof (pollfd_t));
		ps->ps_pollfd = NULL;
	}
	if (ps->ps_pcache != NULL) {
		pcache_destroy(ps->ps_pcache);
		ps->ps_pcache = NULL;
	}
	pcacheset_destroy(ps->ps_pcacheset, ps->ps_nsets);
	ps->ps_pcacheset = NULL;
	if (ps->ps_dpbuf != NULL) {
		kmem_free(ps->ps_dpbuf, ps->ps_dpbufsize);
		ps->ps_dpbuf = NULL;
	}
	mutex_destroy(&ps->ps_lock);
	kmem_free(ps, sizeof (pollstate_t));
}

static int
pollstate_contend(pollstate_t *ps, pollcache_t *pcp)
{
	pollstate_t *rem, *next;
	pollcache_t *desired_pc;
	int result = 0, depth_total;

	mutex_enter(&pollstate_contenders_lock);
	/*
	 * There is a small chance that the pollcache of interest became
	 * available while we were waiting on the contenders lock.
	 */
	if (mutex_tryenter(&pcp->pc_lock) != 0) {
		goto out;
	}

	/*
	 * Walk the list of contended pollstates, searching for evidence of a
	 * deadlock condition.
	 */
	depth_total = ps->ps_depth;
	desired_pc = pcp;
	for (rem = pollstate_contenders; rem != NULL; rem = next) {
		int i, j;
		next = rem->ps_contend_nextp;

		/* Is this pollstate holding the pollcache of interest? */
		for (i = 0; i < rem->ps_depth; i++) {
			if (rem->ps_pc_stack[i] != desired_pc) {
				continue;
			}

			/*
			 * The remote pollstate holds the pollcache lock we
			 * desire.  If it is waiting on a pollcache we hold,
			 * then we can report the obvious deadlock.
			 */
			ASSERT(rem->ps_contend_pc != NULL);
			for (j = 0; j < ps->ps_depth; j++) {
				if (rem->ps_contend_pc == ps->ps_pc_stack[j]) {
					rem->ps_flags |= POLLSTATE_STALEMATE;
					result = -1;
					goto out;
				}
			}

			/*
			 * The remote pollstate is not blocking on a pollcache
			 * which would deadlock against us.  That pollcache
			 * may, however, be held by a pollstate which would
			 * result in a deadlock.
			 *
			 * To detect such a condition, we continue walking
			 * through the list using the pollcache blocking the
			 * remote thread as our new search target.
			 *
			 * Return to the front of pollstate_contenders since it
			 * is not ordered to guarantee complete dependency
			 * traversal.  The below depth tracking places an upper
			 * bound on iterations.
			 */
			desired_pc = rem->ps_contend_pc;
			next = pollstate_contenders;

			/*
			 * The recursion depth of the remote pollstate is used
			 * to calculate a final depth for the local /dev/poll
			 * recursion, since those locks will be acquired
			 * eventually.  If that value exceeds the defined
			 * limit, we can report the failure now instead of
			 * recursing to that failure depth.
			 */
			depth_total += (rem->ps_depth - i);
			if (depth_total >= POLLMAXDEPTH) {
				result = -1;
				goto out;
			}
		}
	}

	/*
	 * No deadlock partner was found.  The only course of action is to
	 * record ourself as a contended pollstate and wait for the pollcache
	 * mutex to become available.
	 */
	ps->ps_contend_pc = pcp;
	ps->ps_contend_nextp = pollstate_contenders;
	ps->ps_contend_pnextp = &pollstate_contenders;
	if (pollstate_contenders != NULL) {
		pollstate_contenders->ps_contend_pnextp =
		    &ps->ps_contend_nextp;
	}
	pollstate_contenders = ps;

	mutex_exit(&pollstate_contenders_lock);
	mutex_enter(&pcp->pc_lock);
	mutex_enter(&pollstate_contenders_lock);

	/*
	 * Our acquisition of the pollcache mutex may be due to another thread
	 * giving up in the face of deadlock with us.  If that is the case,
	 * we too should report the failure.
	 */
	if ((ps->ps_flags & POLLSTATE_STALEMATE) != 0) {
		result = -1;
		ps->ps_flags &= ~POLLSTATE_STALEMATE;
		mutex_exit(&pcp->pc_lock);
	}

	/* Remove ourself from the contenders list. */
	if (ps->ps_contend_nextp != NULL) {
		ps->ps_contend_nextp->ps_contend_pnextp =
		    ps->ps_contend_pnextp;
	}
	*ps->ps_contend_pnextp = ps->ps_contend_nextp;
	ps->ps_contend_pc = NULL;
	ps->ps_contend_nextp = NULL;
	ps->ps_contend_pnextp = NULL;

out:
	mutex_exit(&pollstate_contenders_lock);
	return (result);
}

int
pollstate_enter(pollcache_t *pcp)
{
	pollstate_t *ps = curthread->t_pollstate;
	int i;

	if (ps == NULL) {
		/*
		 * The thread pollstate may not be initialized if VOP_POLL is
		 * called on a recursion-enabled /dev/poll handle from outside
		 * the poll() or /dev/poll codepaths.
		 */
		return (PSE_FAIL_POLLSTATE);
	}
	if (ps->ps_depth >= POLLMAXDEPTH) {
		return (PSE_FAIL_DEPTH);
	}
	/*
	 * Check the desired pollcache against pollcaches we already have
	 * locked.  Such a loop is the most simple deadlock scenario.
	 */
	for (i = 0; i < ps->ps_depth; i++) {
		if (ps->ps_pc_stack[i] == pcp) {
			return (PSE_FAIL_LOOP);
		}
	}
	ASSERT(ps->ps_pc_stack[i] == NULL);

	if (ps->ps_depth == 0) {
		/* Locking initial the pollcache requires no caution */
		mutex_enter(&pcp->pc_lock);
	} else if (mutex_tryenter(&pcp->pc_lock) == 0) {
		if (pollstate_contend(ps, pcp) != 0) {
			/* This pollcache cannot safely be locked. */
			return (PSE_FAIL_DEADLOCK);
		}
	}

	ps->ps_pc_stack[ps->ps_depth++] = pcp;
	return (PSE_SUCCESS);
}

void
pollstate_exit(pollcache_t *pcp)
{
	pollstate_t *ps = curthread->t_pollstate;

	VERIFY(ps != NULL);
	VERIFY(ps->ps_pc_stack[ps->ps_depth - 1] == pcp);

	mutex_exit(&pcp->pc_lock);
	ps->ps_pc_stack[--ps->ps_depth] = NULL;
	VERIFY(ps->ps_depth >= 0);
}


/*
 * We are holding the appropriate uf_lock entering this routine.
 * Bump up the ps_busy count to prevent the thread from exiting.
 */
void
pollblockexit(fpollinfo_t *fpip)
{
	for (; fpip; fpip = fpip->fp_next) {
		pollcache_t *pcp = fpip->fp_thread->t_pollstate->ps_pcache;

		mutex_enter(&pcp->pc_no_exit);
		pcp->pc_busy++;  /* prevents exit()'s */
		mutex_exit(&pcp->pc_no_exit);
	}
}

/*
 * Complete phase 2 of cached poll fd cleanup. Call pcache_clean_entry to mark
 * the pcacheset events field POLLCLOSED to force the next poll() to remove
 * this cache entry. We can't clean the polldat entry clean up here because
 * lwp block in poll() needs the info to return. Wakeup anyone blocked in
 * poll and let exiting lwp go. No lock is help upon entry. So it's OK for
 * pcache_clean_entry to call pollwakeup().
 */
void
pollcacheclean(fpollinfo_t *fip, int fd)
{
	struct fpollinfo	*fpip, *fpip2;

	fpip = fip;
	while (fpip) {
		pollstate_t *ps = fpip->fp_thread->t_pollstate;
		pollcache_t *pcp = ps->ps_pcache;

		mutex_enter(&ps->ps_lock);
		pcache_clean_entry(ps, fd);
		mutex_exit(&ps->ps_lock);
		mutex_enter(&pcp->pc_no_exit);
		pcp->pc_busy--;
		if (pcp->pc_busy == 0) {
			/*
			 * Wakeup the thread waiting in
			 * thread_exit().
			 */
			cv_signal(&pcp->pc_busy_cv);
		}
		mutex_exit(&pcp->pc_no_exit);

		fpip2 = fpip;
		fpip = fpip->fp_next;
		kmem_free(fpip2, sizeof (fpollinfo_t));
	}
}

/*
 * one of the cache line's counter is wrapping around. Reset all cache line
 * counters to zero except one. This is simplistic, but probably works
 * effectively.
 */
void
pcacheset_reset_count(pollstate_t *ps, int index)
{
	int	i;

	ASSERT(MUTEX_HELD(&ps->ps_lock));
	for (i = 0; i < ps->ps_nsets; i++) {
		if (ps->ps_pcacheset[i].pcs_pollfd != NULL) {
			ps->ps_pcacheset[i].pcs_count = 0;
		}
	}
	ps->ps_pcacheset[index].pcs_count = 1;
}

/*
 * this routine implements poll cache list replacement policy.
 * It is currently choose the "least used".
 */
int
pcacheset_replace(pollstate_t *ps)
{
	int i;
	int index = 0;

	ASSERT(MUTEX_HELD(&ps->ps_lock));
	for (i = 1; i < ps->ps_nsets; i++) {
		if (ps->ps_pcacheset[index].pcs_count >
		    ps->ps_pcacheset[i].pcs_count) {
			index = i;
		}
	}
	ps->ps_pcacheset[index].pcs_count = 0;
	return (index);
}

/*
 * this routine is called by strclose to remove remaining polldat struct on
 * the pollhead list of the device being closed. There are two reasons as why
 * the polldat structures still remain on the pollhead list:
 *
 * (1) The layered device(e.g.the console driver).
 * In this case, the existence of a polldat implies that the thread putting
 * the polldat on this list has not exited yet. Before the thread exits, it
 * will have to hold this pollhead lock to remove the polldat. So holding the
 * pollhead lock here effectively prevents the thread which put the polldat
 * on this list from exiting.
 *
 * (2) /dev/poll.
 * When a polled fd is cached in /dev/poll, its polldat will remain on the
 * pollhead list if the process has not done a POLLREMOVE before closing the
 * polled fd. We just unlink it here.
 */
void
pollhead_clean(pollhead_t *php)
{
	polldat_t	*pdp;

	/*
	 * In case(1), while we must prevent the thread in question from
	 * exiting, we must also obey the proper locking order, i.e.
	 * (ps_lock -> phlock).
	 */
	PH_ENTER(php);
	while (php->ph_list != NULL) {
		pollstate_t	*ps;
		pollcache_t	*pcp;

		pdp = php->ph_list;
		ASSERT(pdp->pd_php == php);
		if (pdp->pd_thread == NULL) {
			/*
			 * This is case(2). Since the ph_lock is sufficient
			 * to synchronize this lwp with any other /dev/poll
			 * lwp, just unlink the polldat.
			 */
			php->ph_list = pdp->pd_next;
			pdp->pd_php = NULL;
			pdp->pd_next = NULL;
			continue;
		}
		ps = pdp->pd_thread->t_pollstate;
		ASSERT(ps != NULL);
		pcp = pdp->pd_pcache;
		ASSERT(pcp != NULL);
		mutex_enter(&pcp->pc_no_exit);
		pcp->pc_busy++;  /* prevents exit()'s */
		mutex_exit(&pcp->pc_no_exit);
		/*
		 * Now get the locks in proper order to avoid deadlock.
		 */
		PH_EXIT(php);
		mutex_enter(&ps->ps_lock);
		/*
		 * while we dropped the pollhead lock, the element could be
		 * taken off the list already.
		 */
		PH_ENTER(php);
		if (pdp->pd_php == php) {
			ASSERT(pdp == php->ph_list);
			php->ph_list = pdp->pd_next;
			pdp->pd_php = NULL;
			pdp->pd_next = NULL;
		}
		PH_EXIT(php);
		mutex_exit(&ps->ps_lock);
		mutex_enter(&pcp->pc_no_exit);
		pcp->pc_busy--;
		if (pcp->pc_busy == 0) {
			/*
			 * Wakeup the thread waiting in
			 * thread_exit().
			 */
			cv_signal(&pcp->pc_busy_cv);
		}
		mutex_exit(&pcp->pc_no_exit);
		PH_ENTER(php);
	}
	PH_EXIT(php);
}

/*
 * The remove_list is called to cleanup a partially cached 'current' list or
 * to remove a partial list which is no longer cached. The flag value of 1
 * indicates the second case.
 */
void
pcacheset_remove_list(pollstate_t *ps, pollfd_t *pollfdp, int start, int end,
    int cacheindex, int flag)
{
	int i;

	ASSERT(MUTEX_HELD(&ps->ps_lock));
	for (i = start; i < end; i++) {
		if ((pollfdp[i].fd >= 0) &&
		    (flag || !(pollfdp[i].revents & POLLNVAL))) {
			if (pcache_delete_fd(ps, pollfdp[i].fd, i, cacheindex,
			    (uint_t)pollfdp[i].events)) {
				int j;
				int fd = pollfdp[i].fd;

				for (j = i + 1; j < end; j++) {
					if (pollfdp[j].fd == fd) {
						pcache_update_xref(
						    ps->ps_pcache, fd,
						    (ssize_t)j, cacheindex);
						break;
					}
				}
				ASSERT(j <= end);
			}
		}
	}
}

#ifdef DEBUG

#include<sys/strsubr.h>
/*
 * make sure curthread is not on anyone's pollhead list any more.
 */
static void
pollcheckphlist()
{
	int i;
	file_t *fp;
	uf_entry_t *ufp;
	uf_info_t *fip = P_FINFO(curproc);
	struct stdata *stp;
	polldat_t *pdp;

	mutex_enter(&fip->fi_lock);
	for (i = 0; i < fip->fi_nfiles; i++) {
		UF_ENTER(ufp, fip, i);
		if ((fp = ufp->uf_file) != NULL) {
			if ((stp = fp->f_vnode->v_stream) != NULL) {
				PH_ENTER(&stp->sd_pollist);
				pdp = stp->sd_pollist.ph_list;
				while (pdp) {
					ASSERT(pdp->pd_thread != curthread);
					pdp = pdp->pd_next;
				}
				PH_EXIT(&stp->sd_pollist);
			}
		}
		UF_EXIT(ufp);
	}
	mutex_exit(&fip->fi_lock);
}

/*
 * for resolved set poll list, the xref info in the pcache should be
 * consistent with this poll list.
 */
static int
pollcheckxref(pollstate_t *ps, int cacheindex)
{
	pollfd_t *pollfdp = ps->ps_pcacheset[cacheindex].pcs_pollfd;
	pollcache_t *pcp = ps->ps_pcache;
	polldat_t *pdp;
	int	i;
	xref_t	*refp;

	for (i = 0; i < ps->ps_pcacheset[cacheindex].pcs_nfds; i++) {
		if (pollfdp[i].fd < 0) {
			continue;
		}
		pdp = pcache_lookup_fd(pcp, pollfdp[i].fd);
		ASSERT(pdp != NULL);
		ASSERT(pdp->pd_ref != NULL);
		refp = &pdp->pd_ref[cacheindex];
		if (refp->xf_position >= 0) {
			ASSERT(refp->xf_refcnt >= 1);
			ASSERT(pollfdp[refp->xf_position].fd == pdp->pd_fd);
			if (refp->xf_refcnt > 1) {
				int	j;
				int	count = 0;

				for (j = refp->xf_position;
				    j < ps->ps_pcacheset[cacheindex].pcs_nfds;
				    j++) {
					if (pollfdp[j].fd == pdp->pd_fd) {
						count++;
					}
				}
				ASSERT(count == refp->xf_refcnt);
			}
		}
	}
	return (1);
}

/*
 * For every cached pollfd, its polldat struct should be consistent with
 * what is in the pcacheset lists.
 */
static void
checkpolldat(pollstate_t *ps)
{
	pollcache_t	*pcp = ps->ps_pcache;
	polldat_t	**hashtbl;
	int		i;

	hashtbl = pcp->pc_hash;
	for (i = 0; i < pcp->pc_hashsize; i++) {
		polldat_t	*pdp;

		for (pdp = hashtbl[i]; pdp; pdp = pdp->pd_hashnext) {
			ASSERT(pdp->pd_ref != NULL);
			if (pdp->pd_count > 0) {
				xref_t		*refp;
				int		j;
				pollcacheset_t	*pcsp;
				pollfd_t	*pollfd;

				for (j = 0; j < ps->ps_nsets; j++) {
					refp = &pdp->pd_ref[j];
					if (refp->xf_refcnt > 0) {
						pcsp = &ps->ps_pcacheset[j];
				ASSERT(refp->xf_position < pcsp->pcs_nfds);
						pollfd = pcsp->pcs_pollfd;
			ASSERT(pdp->pd_fd == pollfd[refp->xf_position].fd);
					}
				}
			}
		}
	}
}

/*
 * every wfd element on ph_list must have a corresponding fpollinfo on the
 * uf_fpollinfo list. This is a variation of infpollinfo() w/o holding locks.
 */
void
checkwfdlist(vnode_t *vp, fpollinfo_t *fpip)
{
	stdata_t *stp;
	polldat_t *pdp;
	fpollinfo_t *fpip2;

	if ((stp = vp->v_stream) == NULL) {
		return;
	}
	PH_ENTER(&stp->sd_pollist);
	for (pdp = stp->sd_pollist.ph_list; pdp; pdp = pdp->pd_next) {
		if (pdp->pd_thread != NULL &&
		    pdp->pd_thread->t_procp == curthread->t_procp) {
			for (fpip2 = fpip; fpip2; fpip2 = fpip2->fp_next) {
				if (pdp->pd_thread == fpip2->fp_thread) {
					break;
				}
			}
			ASSERT(fpip2 != NULL);
		}
	}
	PH_EXIT(&stp->sd_pollist);
}

/*
 * For each cached fd whose bit is not set in bitmap, its revents field in
 * current poll list should be 0.
 */
static int
pollcheckrevents(pollstate_t *ps, int begin, int end, int cacheindex)
{
	pollcache_t	*pcp = ps->ps_pcache;
	pollfd_t	*pollfdp = ps->ps_pollfd;
	int		i;

	for (i = begin; i < end; i++) {
		polldat_t	*pdp;

		ASSERT(!BT_TEST(pcp->pc_bitmap, i));
		pdp = pcache_lookup_fd(pcp, i);
		if (pdp && pdp->pd_fp != NULL) {
			xref_t *refp;
			int entry;

			ASSERT(pdp->pd_ref != NULL);
			refp = &pdp->pd_ref[cacheindex];
			if (refp->xf_refcnt == 0) {
				continue;
			}
			entry = refp->xf_position;
			ASSERT(entry >= 0);
			ASSERT(pollfdp[entry].revents == 0);
			if (refp->xf_refcnt > 1) {
				int j;

				for (j = entry + 1; j < ps->ps_nfds; j++) {
					if (pollfdp[j].fd == i) {
						ASSERT(pollfdp[j].revents == 0);
					}
				}
			}
		}
	}
	return (1);
}

#endif	/* DEBUG */

pollcache_t *
pcache_alloc()
{
	return (kmem_zalloc(sizeof (pollcache_t), KM_SLEEP));
}

void
pcache_create(pollcache_t *pcp, nfds_t nfds)
{
	size_t	mapsize;

	/*
	 * allocate enough bits for the poll fd list
	 */
	if ((mapsize = POLLMAPCHUNK) <= nfds) {
		mapsize = (nfds + POLLMAPCHUNK - 1) & ~(POLLMAPCHUNK - 1);
	}
	pcp->pc_bitmap = kmem_zalloc((mapsize / BT_NBIPUL) * sizeof (ulong_t),
	    KM_SLEEP);
	pcp->pc_mapsize = mapsize;
	/*
	 * The hash size is at least POLLHASHCHUNKSZ. If user polls a large
	 * number of fd to start with, allocate a bigger hash table (to the
	 * nearest multiple of POLLHASHCHUNKSZ) because dynamically growing a
	 * hash table is expensive.
	 */
	if (nfds < POLLHASHCHUNKSZ) {
		pcp->pc_hashsize = POLLHASHCHUNKSZ;
	} else {
		pcp->pc_hashsize = (nfds + POLLHASHCHUNKSZ - 1) &
		    ~(POLLHASHCHUNKSZ - 1);
	}
	pcp->pc_hash = kmem_zalloc(pcp->pc_hashsize * sizeof (polldat_t *),
	    KM_SLEEP);
}

void
pcache_destroy(pollcache_t *pcp)
{
	polldat_t	**hashtbl;
	int i;

	hashtbl = pcp->pc_hash;
	for (i = 0; i < pcp->pc_hashsize; i++) {
		if (hashtbl[i] != NULL) {
			polldat_t *pdp, *pdp2;

			pdp = hashtbl[i];
			while (pdp != NULL) {
				pdp2 = pdp->pd_hashnext;
				if (pdp->pd_ref != NULL) {
					kmem_free(pdp->pd_ref, sizeof (xref_t) *
					    pdp->pd_nsets);
				}
				kmem_free(pdp, sizeof (polldat_t));
				pdp = pdp2;
				pcp->pc_fdcount--;
			}
		}
	}
	ASSERT(pcp->pc_fdcount == 0);
	kmem_free(pcp->pc_hash, sizeof (polldat_t *) * pcp->pc_hashsize);
	kmem_free(pcp->pc_bitmap,
	    sizeof (ulong_t) * (pcp->pc_mapsize/BT_NBIPUL));
	mutex_destroy(&pcp->pc_no_exit);
	mutex_destroy(&pcp->pc_lock);
	cv_destroy(&pcp->pc_cv);
	cv_destroy(&pcp->pc_busy_cv);
	kmem_free(pcp, sizeof (pollcache_t));
}

pollcacheset_t *
pcacheset_create(int nsets)
{
	return (kmem_zalloc(sizeof (pollcacheset_t) * nsets, KM_SLEEP));
}

void
pcacheset_destroy(pollcacheset_t *pcsp, int nsets)
{
	int i;

	for (i = 0; i < nsets; i++) {
		if (pcsp[i].pcs_pollfd != NULL) {
			kmem_free(pcsp[i].pcs_pollfd, pcsp[i].pcs_nfds *
			    sizeof (pollfd_t));
		}
	}
	kmem_free(pcsp, sizeof (pollcacheset_t) * nsets);
}

/*
 * Check each duplicated poll fd in the poll list. It may be necessary to
 * VOP_POLL the same fd again using different poll events. getf() has been
 * done by caller. This routine returns 0 if it can sucessfully process the
 * entire poll fd list. It returns -1 if underlying vnode has changed during
 * a VOP_POLL, in which case the caller has to repoll. It returns a positive
 * value if VOP_POLL failed.
 */
static int
plist_chkdupfd(file_t *fp, polldat_t *pdp, pollstate_t *psp, pollfd_t *pollfdp,
    int entry, int *fdcntp)
{
	int	i;
	int	fd;
	nfds_t	nfds = psp->ps_nfds;

	fd = pollfdp[entry].fd;
	for (i = entry + 1; i < nfds; i++) {
		if (pollfdp[i].fd == fd) {
			if (pollfdp[i].events == pollfdp[entry].events) {
				if ((pollfdp[i].revents =
				    pollfdp[entry].revents) != 0) {
					(*fdcntp)++;
				}
			} else {

				int	error;
				pollhead_t *php;
				pollcache_t *pcp = psp->ps_pcache;

				/*
				 * the events are different. VOP_POLL on this
				 * fd so that we don't miss any revents.
				 */
				php = NULL;
				ASSERT(curthread->t_pollcache == NULL);
				error = VOP_POLL(fp->f_vnode,
				    pollfdp[i].events, 0,
				    &pollfdp[i].revents, &php, NULL);
				if (error) {
					return (error);
				}
				/*
				 * layered devices(e.g. console driver)
				 * may change the vnode and thus the pollhead
				 * pointer out from underneath us.
				 */
				if (php != NULL && pdp->pd_php != NULL &&
				    php != pdp->pd_php) {
					pollhead_delete(pdp->pd_php, pdp);
					pdp->pd_php = php;
					pollhead_insert(php, pdp);
					/*
					 * We could have missed a wakeup on the
					 * new target device. Make sure the new
					 * target gets polled once.
					 */
					BT_SET(pcp->pc_bitmap, fd);
					return (-1);
				}
				if (pollfdp[i].revents) {
					(*fdcntp)++;
				}
			}
		}
	}
	return (0);
}
