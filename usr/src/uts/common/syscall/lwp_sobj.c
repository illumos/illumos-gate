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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/prsystm.h>
#include <sys/kmem.h>
#include <sys/sobject.h>
#include <sys/fault.h>
#include <sys/procfs.h>
#include <sys/watchpoint.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/machlock.h>
#include <sys/debug.h>
#include <sys/synch.h>
#include <sys/synch32.h>
#include <sys/mman.h>
#include <sys/class.h>
#include <sys/schedctl.h>
#include <sys/sleepq.h>
#include <sys/policy.h>
#include <sys/tnf_probe.h>
#include <sys/lwpchan_impl.h>
#include <sys/turnstile.h>
#include <sys/atomic.h>
#include <sys/lwp_timer_impl.h>
#include <sys/lwp_upimutex_impl.h>
#include <vm/as.h>
#include <sys/sdt.h>

static kthread_t *lwpsobj_owner(caddr_t);
static void lwp_unsleep(kthread_t *t);
static void lwp_change_pri(kthread_t *t, pri_t pri, pri_t *t_prip);
static void lwp_mutex_cleanup(lwpchan_entry_t *ent, uint16_t lockflg);
static void lwp_mutex_unregister(void *uaddr);
static void set_owner_pid(lwp_mutex_t *, uintptr_t, pid_t);
static int iswanted(kthread_t *, lwpchan_t *);

extern int lwp_cond_signal(lwp_cond_t *cv);

/*
 * Maximum number of user prio inheritance locks that can be held by a thread.
 * Used to limit kmem for each thread. This is a per-thread limit that
 * can be administered on a system wide basis (using /etc/system).
 *
 * Also, when a limit, say maxlwps is added for numbers of lwps within a
 * process, the per-thread limit automatically becomes a process-wide limit
 * of maximum number of held upi locks within a process:
 *      maxheldupimx = maxnestupimx * maxlwps;
 */
static uint32_t maxnestupimx = 2000;

/*
 * The sobj_ops vector exports a set of functions needed when a thread
 * is asleep on a synchronization object of this type.
 */
static sobj_ops_t lwp_sobj_ops = {
	SOBJ_USER, lwpsobj_owner, lwp_unsleep, lwp_change_pri
};

static kthread_t *lwpsobj_pi_owner(upimutex_t *up);

static sobj_ops_t lwp_sobj_pi_ops = {
	SOBJ_USER_PI, lwpsobj_pi_owner, turnstile_unsleep,
	turnstile_change_pri
};

static sleepq_head_t	lwpsleepq[NSLEEPQ];
upib_t			upimutextab[UPIMUTEX_TABSIZE];

#define	LWPCHAN_LOCK_SHIFT	10	/* 1024 locks for each pool */
#define	LWPCHAN_LOCK_SIZE	(1 << LWPCHAN_LOCK_SHIFT)

/*
 * We know that both lc_wchan and lc_wchan0 are addresses that most
 * likely are 8-byte aligned, so we shift off the low-order 3 bits.
 * 'pool' is either 0 or 1.
 */
#define	LWPCHAN_LOCK_HASH(X, pool) \
	(((((X) >> 3) ^ ((X) >> (LWPCHAN_LOCK_SHIFT + 3))) & \
	(LWPCHAN_LOCK_SIZE - 1)) + ((pool)? LWPCHAN_LOCK_SIZE : 0))

static kmutex_t		lwpchanlock[2 * LWPCHAN_LOCK_SIZE];

/*
 * Is this a POSIX threads user-level lock requiring priority inheritance?
 */
#define	UPIMUTEX(type)	((type) & LOCK_PRIO_INHERIT)

static sleepq_head_t *
lwpsqhash(lwpchan_t *lwpchan)
{
	uint_t x = (uintptr_t)lwpchan->lc_wchan ^ (uintptr_t)lwpchan->lc_wchan0;
	return (&lwpsleepq[SQHASHINDEX(x)]);
}

/*
 * Lock an lwpchan.
 * Keep this in sync with lwpchan_unlock(), below.
 */
static void
lwpchan_lock(lwpchan_t *lwpchan, int pool)
{
	uint_t x = (uintptr_t)lwpchan->lc_wchan ^ (uintptr_t)lwpchan->lc_wchan0;
	mutex_enter(&lwpchanlock[LWPCHAN_LOCK_HASH(x, pool)]);
}

/*
 * Unlock an lwpchan.
 * Keep this in sync with lwpchan_lock(), above.
 */
static void
lwpchan_unlock(lwpchan_t *lwpchan, int pool)
{
	uint_t x = (uintptr_t)lwpchan->lc_wchan ^ (uintptr_t)lwpchan->lc_wchan0;
	mutex_exit(&lwpchanlock[LWPCHAN_LOCK_HASH(x, pool)]);
}

/*
 * Delete mappings from the lwpchan cache for pages that are being
 * unmapped by as_unmap().  Given a range of addresses, "start" to "end",
 * all mappings within the range are deleted from the lwpchan cache.
 */
void
lwpchan_delete_mapping(proc_t *p, caddr_t start, caddr_t end)
{
	lwpchan_data_t *lcp;
	lwpchan_hashbucket_t *hashbucket;
	lwpchan_hashbucket_t *endbucket;
	lwpchan_entry_t *ent;
	lwpchan_entry_t **prev;
	caddr_t addr;

	mutex_enter(&p->p_lcp_lock);
	lcp = p->p_lcp;
	hashbucket = lcp->lwpchan_cache;
	endbucket = hashbucket + lcp->lwpchan_size;
	for (; hashbucket < endbucket; hashbucket++) {
		if (hashbucket->lwpchan_chain == NULL)
			continue;
		mutex_enter(&hashbucket->lwpchan_lock);
		prev = &hashbucket->lwpchan_chain;
		/* check entire chain */
		while ((ent = *prev) != NULL) {
			addr = ent->lwpchan_addr;
			if (start <= addr && addr < end) {
				*prev = ent->lwpchan_next;
				/*
				 * We do this only for the obsolete type
				 * USYNC_PROCESS_ROBUST.  Otherwise robust
				 * locks do not draw ELOCKUNMAPPED or
				 * EOWNERDEAD due to being unmapped.
				 */
				if (ent->lwpchan_pool == LWPCHAN_MPPOOL &&
				    (ent->lwpchan_type & USYNC_PROCESS_ROBUST))
					lwp_mutex_cleanup(ent, LOCK_UNMAPPED);
				/*
				 * If there is a user-level robust lock
				 * registration, mark it as invalid.
				 */
				if ((addr = ent->lwpchan_uaddr) != NULL)
					lwp_mutex_unregister(addr);
				kmem_free(ent, sizeof (*ent));
				atomic_dec_32(&lcp->lwpchan_entries);
			} else {
				prev = &ent->lwpchan_next;
			}
		}
		mutex_exit(&hashbucket->lwpchan_lock);
	}
	mutex_exit(&p->p_lcp_lock);
}

/*
 * Given an lwpchan cache pointer and a process virtual address,
 * return a pointer to the corresponding lwpchan hash bucket.
 */
static lwpchan_hashbucket_t *
lwpchan_bucket(lwpchan_data_t *lcp, uintptr_t addr)
{
	uint_t i;

	/*
	 * All user-level sync object addresses are 8-byte aligned.
	 * Ignore the lowest 3 bits of the address and use the
	 * higher-order 2*lwpchan_bits bits for the hash index.
	 */
	addr >>= 3;
	i = (addr ^ (addr >> lcp->lwpchan_bits)) & lcp->lwpchan_mask;
	return (lcp->lwpchan_cache + i);
}

/*
 * (Re)allocate the per-process lwpchan cache.
 */
static void
lwpchan_alloc_cache(proc_t *p, uint_t bits)
{
	lwpchan_data_t *lcp;
	lwpchan_data_t *old_lcp;
	lwpchan_hashbucket_t *hashbucket;
	lwpchan_hashbucket_t *endbucket;
	lwpchan_hashbucket_t *newbucket;
	lwpchan_entry_t *ent;
	lwpchan_entry_t *next;
	uint_t count;

	ASSERT(bits >= LWPCHAN_INITIAL_BITS && bits <= LWPCHAN_MAX_BITS);

	lcp = kmem_alloc(sizeof (lwpchan_data_t), KM_SLEEP);
	lcp->lwpchan_bits = bits;
	lcp->lwpchan_size = 1 << lcp->lwpchan_bits;
	lcp->lwpchan_mask = lcp->lwpchan_size - 1;
	lcp->lwpchan_entries = 0;
	lcp->lwpchan_cache = kmem_zalloc(lcp->lwpchan_size *
	    sizeof (lwpchan_hashbucket_t), KM_SLEEP);
	lcp->lwpchan_next_data = NULL;

	mutex_enter(&p->p_lcp_lock);
	if ((old_lcp = p->p_lcp) != NULL) {
		if (old_lcp->lwpchan_bits >= bits) {
			/* someone beat us to it */
			mutex_exit(&p->p_lcp_lock);
			kmem_free(lcp->lwpchan_cache, lcp->lwpchan_size *
			    sizeof (lwpchan_hashbucket_t));
			kmem_free(lcp, sizeof (lwpchan_data_t));
			return;
		}
		/*
		 * Acquire all of the old hash table locks.
		 */
		hashbucket = old_lcp->lwpchan_cache;
		endbucket = hashbucket + old_lcp->lwpchan_size;
		for (; hashbucket < endbucket; hashbucket++)
			mutex_enter(&hashbucket->lwpchan_lock);
		/*
		 * Move all of the old hash table entries to the
		 * new hash table.  The new hash table has not yet
		 * been installed so we don't need any of its locks.
		 */
		count = 0;
		hashbucket = old_lcp->lwpchan_cache;
		for (; hashbucket < endbucket; hashbucket++) {
			ent = hashbucket->lwpchan_chain;
			while (ent != NULL) {
				next = ent->lwpchan_next;
				newbucket = lwpchan_bucket(lcp,
				    (uintptr_t)ent->lwpchan_addr);
				ent->lwpchan_next = newbucket->lwpchan_chain;
				newbucket->lwpchan_chain = ent;
				ent = next;
				count++;
			}
			hashbucket->lwpchan_chain = NULL;
		}
		lcp->lwpchan_entries = count;
	}

	/*
	 * Retire the old hash table.  We can't actually kmem_free() it
	 * now because someone may still have a pointer to it.  Instead,
	 * we link it onto the new hash table's list of retired hash tables.
	 * The new hash table is double the size of the previous one, so
	 * the total size of all retired hash tables is less than the size
	 * of the new one.  exit() and exec() free the retired hash tables
	 * (see lwpchan_destroy_cache(), below).
	 */
	lcp->lwpchan_next_data = old_lcp;

	/*
	 * As soon as we store the new lcp, future locking operations will
	 * use it.  Therefore, we must ensure that all the state we've just
	 * established reaches global visibility before the new lcp does.
	 */
	membar_producer();
	p->p_lcp = lcp;

	if (old_lcp != NULL) {
		/*
		 * Release all of the old hash table locks.
		 */
		hashbucket = old_lcp->lwpchan_cache;
		for (; hashbucket < endbucket; hashbucket++)
			mutex_exit(&hashbucket->lwpchan_lock);
	}
	mutex_exit(&p->p_lcp_lock);
}

/*
 * Deallocate the lwpchan cache, and any dynamically allocated mappings.
 * Called when the process exits or execs.  All lwps except one have
 * exited so we need no locks here.
 */
void
lwpchan_destroy_cache(int exec)
{
	proc_t *p = curproc;
	lwpchan_hashbucket_t *hashbucket;
	lwpchan_hashbucket_t *endbucket;
	lwpchan_data_t *lcp;
	lwpchan_entry_t *ent;
	lwpchan_entry_t *next;
	uint16_t lockflg;

	lcp = p->p_lcp;
	p->p_lcp = NULL;

	lockflg = exec? LOCK_UNMAPPED : LOCK_OWNERDEAD;
	hashbucket = lcp->lwpchan_cache;
	endbucket = hashbucket + lcp->lwpchan_size;
	for (; hashbucket < endbucket; hashbucket++) {
		ent = hashbucket->lwpchan_chain;
		hashbucket->lwpchan_chain = NULL;
		while (ent != NULL) {
			next = ent->lwpchan_next;
			if (ent->lwpchan_pool == LWPCHAN_MPPOOL &&
			    (ent->lwpchan_type & (USYNC_PROCESS | LOCK_ROBUST))
			    == (USYNC_PROCESS | LOCK_ROBUST))
				lwp_mutex_cleanup(ent, lockflg);
			kmem_free(ent, sizeof (*ent));
			ent = next;
		}
	}

	while (lcp != NULL) {
		lwpchan_data_t *next_lcp = lcp->lwpchan_next_data;
		kmem_free(lcp->lwpchan_cache, lcp->lwpchan_size *
		    sizeof (lwpchan_hashbucket_t));
		kmem_free(lcp, sizeof (lwpchan_data_t));
		lcp = next_lcp;
	}
}

/*
 * Return zero when there is an entry in the lwpchan cache for the
 * given process virtual address and non-zero when there is not.
 * The returned non-zero value is the current length of the
 * hash chain plus one.  The caller holds the hash bucket lock.
 */
static uint_t
lwpchan_cache_mapping(caddr_t addr, int type, int pool, lwpchan_t *lwpchan,
	lwpchan_hashbucket_t *hashbucket)
{
	lwpchan_entry_t *ent;
	uint_t count = 1;

	for (ent = hashbucket->lwpchan_chain; ent; ent = ent->lwpchan_next) {
		if (ent->lwpchan_addr == addr) {
			if (ent->lwpchan_type != type ||
			    ent->lwpchan_pool != pool) {
				/*
				 * This shouldn't happen, but might if the
				 * process reuses its memory for different
				 * types of sync objects.  We test first
				 * to avoid grabbing the memory cache line.
				 */
				ent->lwpchan_type = (uint16_t)type;
				ent->lwpchan_pool = (uint16_t)pool;
			}
			*lwpchan = ent->lwpchan_lwpchan;
			return (0);
		}
		count++;
	}
	return (count);
}

/*
 * Return the cached lwpchan mapping if cached, otherwise insert
 * a virtual address to lwpchan mapping into the cache.
 */
static int
lwpchan_get_mapping(struct as *as, caddr_t addr, caddr_t uaddr,
	int type, lwpchan_t *lwpchan, int pool)
{
	proc_t *p = curproc;
	lwpchan_data_t *lcp;
	lwpchan_hashbucket_t *hashbucket;
	lwpchan_entry_t *ent;
	memid_t	memid;
	uint_t count;
	uint_t bits;

top:
	/* initialize the lwpchan cache, if necesary */
	if ((lcp = p->p_lcp) == NULL) {
		lwpchan_alloc_cache(p, LWPCHAN_INITIAL_BITS);
		goto top;
	}
	hashbucket = lwpchan_bucket(lcp, (uintptr_t)addr);
	mutex_enter(&hashbucket->lwpchan_lock);
	if (lcp != p->p_lcp) {
		/* someone resized the lwpchan cache; start over */
		mutex_exit(&hashbucket->lwpchan_lock);
		goto top;
	}
	if (lwpchan_cache_mapping(addr, type, pool, lwpchan, hashbucket) == 0) {
		/* it's in the cache */
		mutex_exit(&hashbucket->lwpchan_lock);
		return (1);
	}
	mutex_exit(&hashbucket->lwpchan_lock);
	if (as_getmemid(as, addr, &memid) != 0)
		return (0);
	lwpchan->lc_wchan0 = (caddr_t)(uintptr_t)memid.val[0];
	lwpchan->lc_wchan = (caddr_t)(uintptr_t)memid.val[1];
	ent = kmem_alloc(sizeof (lwpchan_entry_t), KM_SLEEP);
	mutex_enter(&hashbucket->lwpchan_lock);
	if (lcp != p->p_lcp) {
		/* someone resized the lwpchan cache; start over */
		mutex_exit(&hashbucket->lwpchan_lock);
		kmem_free(ent, sizeof (*ent));
		goto top;
	}
	count = lwpchan_cache_mapping(addr, type, pool, lwpchan, hashbucket);
	if (count == 0) {
		/* someone else added this entry to the cache */
		mutex_exit(&hashbucket->lwpchan_lock);
		kmem_free(ent, sizeof (*ent));
		return (1);
	}
	if (count > lcp->lwpchan_bits + 2 && /* larger table, longer chains */
	    (bits = lcp->lwpchan_bits) < LWPCHAN_MAX_BITS) {
		/* hash chain too long; reallocate the hash table */
		mutex_exit(&hashbucket->lwpchan_lock);
		kmem_free(ent, sizeof (*ent));
		lwpchan_alloc_cache(p, bits + 1);
		goto top;
	}
	ent->lwpchan_addr = addr;
	ent->lwpchan_uaddr = uaddr;
	ent->lwpchan_type = (uint16_t)type;
	ent->lwpchan_pool = (uint16_t)pool;
	ent->lwpchan_lwpchan = *lwpchan;
	ent->lwpchan_next = hashbucket->lwpchan_chain;
	hashbucket->lwpchan_chain = ent;
	atomic_inc_32(&lcp->lwpchan_entries);
	mutex_exit(&hashbucket->lwpchan_lock);
	return (1);
}

/*
 * Return a unique pair of identifiers that corresponds to a
 * synchronization object's virtual address.  Process-shared
 * sync objects usually get vnode/offset from as_getmemid().
 */
static int
get_lwpchan(struct as *as, caddr_t addr, int type, lwpchan_t *lwpchan, int pool)
{
	/*
	 * If the lwp synch object is defined to be process-private,
	 * we just make the first field of the lwpchan be 'as' and
	 * the second field be the synch object's virtual address.
	 * (segvn_getmemid() does the same for MAP_PRIVATE mappings.)
	 * The lwpchan cache is used only for process-shared objects.
	 */
	if (!(type & USYNC_PROCESS)) {
		lwpchan->lc_wchan0 = (caddr_t)as;
		lwpchan->lc_wchan = addr;
		return (1);
	}

	return (lwpchan_get_mapping(as, addr, NULL, type, lwpchan, pool));
}

static void
lwp_block(lwpchan_t *lwpchan)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	sleepq_head_t *sqh;

	thread_lock(t);
	t->t_flag |= T_WAKEABLE;
	t->t_lwpchan = *lwpchan;
	t->t_sobj_ops = &lwp_sobj_ops;
	t->t_release = 0;
	sqh = lwpsqhash(lwpchan);
	disp_lock_enter_high(&sqh->sq_lock);
	CL_SLEEP(t);
	DTRACE_SCHED(sleep);
	THREAD_SLEEP(t, &sqh->sq_lock);
	sleepq_insert(&sqh->sq_queue, t);
	thread_unlock(t);
	lwp->lwp_asleep = 1;
	lwp->lwp_sysabort = 0;
	lwp->lwp_ru.nvcsw++;
	(void) new_mstate(curthread, LMS_SLEEP);
}

static kthread_t *
lwpsobj_pi_owner(upimutex_t *up)
{
	return (up->upi_owner);
}

static struct upimutex *
upi_get(upib_t *upibp, lwpchan_t *lcp)
{
	struct upimutex *upip;

	for (upip = upibp->upib_first; upip != NULL;
	    upip = upip->upi_nextchain) {
		if (upip->upi_lwpchan.lc_wchan0 == lcp->lc_wchan0 &&
		    upip->upi_lwpchan.lc_wchan == lcp->lc_wchan)
			break;
	}
	return (upip);
}

static void
upi_chain_add(upib_t *upibp, struct upimutex *upimutex)
{
	ASSERT(MUTEX_HELD(&upibp->upib_lock));

	/*
	 * Insert upimutex at front of list. Maybe a bit unfair
	 * but assume that not many lwpchans hash to the same
	 * upimutextab bucket, i.e. the list of upimutexes from
	 * upib_first is not too long.
	 */
	upimutex->upi_nextchain = upibp->upib_first;
	upibp->upib_first = upimutex;
}

static void
upi_chain_del(upib_t *upibp, struct upimutex *upimutex)
{
	struct upimutex **prev;

	ASSERT(MUTEX_HELD(&upibp->upib_lock));

	prev = &upibp->upib_first;
	while (*prev != upimutex) {
		prev = &(*prev)->upi_nextchain;
	}
	*prev = upimutex->upi_nextchain;
	upimutex->upi_nextchain = NULL;
}

/*
 * Add upimutex to chain of upimutexes held by curthread.
 * Returns number of upimutexes held by curthread.
 */
static uint32_t
upi_mylist_add(struct upimutex *upimutex)
{
	kthread_t *t = curthread;

	/*
	 * Insert upimutex at front of list of upimutexes owned by t. This
	 * would match typical LIFO order in which nested locks are acquired
	 * and released.
	 */
	upimutex->upi_nextowned = t->t_upimutex;
	t->t_upimutex = upimutex;
	t->t_nupinest++;
	ASSERT(t->t_nupinest > 0);
	return (t->t_nupinest);
}

/*
 * Delete upimutex from list of upimutexes owned by curthread.
 */
static void
upi_mylist_del(struct upimutex *upimutex)
{
	kthread_t *t = curthread;
	struct upimutex **prev;

	/*
	 * Since the order in which nested locks are acquired and released,
	 * is typically LIFO, and typical nesting levels are not too deep, the
	 * following should not be expensive in the general case.
	 */
	prev = &t->t_upimutex;
	while (*prev != upimutex) {
		prev = &(*prev)->upi_nextowned;
	}
	*prev = upimutex->upi_nextowned;
	upimutex->upi_nextowned = NULL;
	ASSERT(t->t_nupinest > 0);
	t->t_nupinest--;
}

/*
 * Returns true if upimutex is owned. Should be called only when upim points
 * to kmem which cannot disappear from underneath.
 */
static int
upi_owned(upimutex_t *upim)
{
	return (upim->upi_owner == curthread);
}

/*
 * Returns pointer to kernel object (upimutex_t *) if lp is owned.
 */
static struct upimutex *
lwp_upimutex_owned(lwp_mutex_t *lp, uint8_t type)
{
	lwpchan_t lwpchan;
	upib_t *upibp;
	struct upimutex *upimutex;

	if (!get_lwpchan(curproc->p_as, (caddr_t)lp, type,
	    &lwpchan, LWPCHAN_MPPOOL))
		return (NULL);

	upibp = &UPI_CHAIN(lwpchan);
	mutex_enter(&upibp->upib_lock);
	upimutex = upi_get(upibp, &lwpchan);
	if (upimutex == NULL || upimutex->upi_owner != curthread) {
		mutex_exit(&upibp->upib_lock);
		return (NULL);
	}
	mutex_exit(&upibp->upib_lock);
	return (upimutex);
}

/*
 * Unlocks upimutex, waking up waiters if any. upimutex kmem is freed if
 * no lock hand-off occurrs.
 */
static void
upimutex_unlock(struct upimutex *upimutex, uint16_t flag)
{
	turnstile_t *ts;
	upib_t *upibp;
	kthread_t *newowner;

	upi_mylist_del(upimutex);
	upibp = upimutex->upi_upibp;
	mutex_enter(&upibp->upib_lock);
	if (upimutex->upi_waiter != 0) { /* if waiters */
		ts = turnstile_lookup(upimutex);
		if (ts != NULL && !(flag & LOCK_NOTRECOVERABLE)) {
			/* hand-off lock to highest prio waiter */
			newowner = ts->ts_sleepq[TS_WRITER_Q].sq_first;
			upimutex->upi_owner = newowner;
			if (ts->ts_waiters == 1)
				upimutex->upi_waiter = 0;
			turnstile_wakeup(ts, TS_WRITER_Q, 1, newowner);
			mutex_exit(&upibp->upib_lock);
			return;
		} else if (ts != NULL) {
			/* LOCK_NOTRECOVERABLE: wakeup all */
			turnstile_wakeup(ts, TS_WRITER_Q, ts->ts_waiters, NULL);
		} else {
			/*
			 * Misleading w bit. Waiters might have been
			 * interrupted. No need to clear the w bit (upimutex
			 * will soon be freed). Re-calculate PI from existing
			 * waiters.
			 */
			turnstile_exit(upimutex);
			turnstile_pi_recalc();
		}
	}
	/*
	 * no waiters, or LOCK_NOTRECOVERABLE.
	 * remove from the bucket chain of upi mutexes.
	 * de-allocate kernel memory (upimutex).
	 */
	upi_chain_del(upimutex->upi_upibp, upimutex);
	mutex_exit(&upibp->upib_lock);
	kmem_free(upimutex, sizeof (upimutex_t));
}

static int
lwp_upimutex_lock(lwp_mutex_t *lp, uint8_t type, int try, lwp_timer_t *lwptp)
{
	label_t ljb;
	int error = 0;
	lwpchan_t lwpchan;
	uint16_t flag;
	upib_t *upibp;
	volatile struct upimutex *upimutex = NULL;
	turnstile_t *ts;
	uint32_t nupinest;
	volatile int upilocked = 0;

	if (on_fault(&ljb)) {
		if (upilocked)
			upimutex_unlock((upimutex_t *)upimutex, 0);
		error = EFAULT;
		goto out;
	}
	if (!get_lwpchan(curproc->p_as, (caddr_t)lp, type,
	    &lwpchan, LWPCHAN_MPPOOL)) {
		error = EFAULT;
		goto out;
	}
	upibp = &UPI_CHAIN(lwpchan);
retry:
	mutex_enter(&upibp->upib_lock);
	upimutex = upi_get(upibp, &lwpchan);
	if (upimutex == NULL)  {
		/* lock available since lwpchan has no upimutex */
		upimutex = kmem_zalloc(sizeof (upimutex_t), KM_SLEEP);
		upi_chain_add(upibp, (upimutex_t *)upimutex);
		upimutex->upi_owner = curthread; /* grab lock */
		upimutex->upi_upibp = upibp;
		upimutex->upi_vaddr = lp;
		upimutex->upi_lwpchan = lwpchan;
		mutex_exit(&upibp->upib_lock);
		nupinest = upi_mylist_add((upimutex_t *)upimutex);
		upilocked = 1;
		fuword16_noerr(&lp->mutex_flag, &flag);
		if (nupinest > maxnestupimx &&
		    secpolicy_resource(CRED()) != 0) {
			upimutex_unlock((upimutex_t *)upimutex, flag);
			error = ENOMEM;
			goto out;
		}
		if (flag & LOCK_NOTRECOVERABLE) {
			/*
			 * Since the setting of LOCK_NOTRECOVERABLE
			 * was done under the high-level upi mutex,
			 * in lwp_upimutex_unlock(), this flag needs to
			 * be checked while holding the upi mutex.
			 * If set, this thread should return without
			 * the lock held, and with the right error code.
			 */
			upimutex_unlock((upimutex_t *)upimutex, flag);
			upilocked = 0;
			error = ENOTRECOVERABLE;
		} else if (flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED)) {
			if (flag & LOCK_OWNERDEAD)
				error = EOWNERDEAD;
			else if (type & USYNC_PROCESS_ROBUST)
				error = ELOCKUNMAPPED;
			else
				error = EOWNERDEAD;
		}
		goto out;
	}
	/*
	 * If a upimutex object exists, it must have an owner.
	 * This is due to lock hand-off, and release of upimutex when no
	 * waiters are present at unlock time,
	 */
	ASSERT(upimutex->upi_owner != NULL);
	if (upimutex->upi_owner == curthread) {
		/*
		 * The user wrapper can check if the mutex type is
		 * ERRORCHECK: if not, it should stall at user-level.
		 * If so, it should return the error code.
		 */
		mutex_exit(&upibp->upib_lock);
		error = EDEADLK;
		goto out;
	}
	if (try == UPIMUTEX_TRY) {
		mutex_exit(&upibp->upib_lock);
		error = EBUSY;
		goto out;
	}
	/*
	 * Block for the lock.
	 */
	if ((error = lwptp->lwpt_time_error) != 0) {
		/*
		 * The SUSV3 Posix spec is very clear that we
		 * should get no error from validating the
		 * timer until we would actually sleep.
		 */
		mutex_exit(&upibp->upib_lock);
		goto out;
	}
	if (lwptp->lwpt_tsp != NULL) {
		/*
		 * Unlike the protocol for other lwp timedwait operations,
		 * we must drop t_delay_lock before going to sleep in
		 * turnstile_block() for a upi mutex.
		 * See the comments below and in turnstile.c
		 */
		mutex_enter(&curthread->t_delay_lock);
		(void) lwp_timer_enqueue(lwptp);
		mutex_exit(&curthread->t_delay_lock);
	}
	/*
	 * Now, set the waiter bit and block for the lock in turnstile_block().
	 * No need to preserve the previous wbit since a lock try is not
	 * attempted after setting the wait bit. Wait bit is set under
	 * the upib_lock, which is not released until the turnstile lock
	 * is acquired. Say, the upimutex is L:
	 *
	 * 1. upib_lock is held so the waiter does not have to retry L after
	 *    setting the wait bit: since the owner has to grab the upib_lock
	 *    to unlock L, it will certainly see the wait bit set.
	 * 2. upib_lock is not released until the turnstile lock is acquired.
	 *    This is the key to preventing a missed wake-up. Otherwise, the
	 *    owner could acquire the upib_lock, and the tc_lock, to call
	 *    turnstile_wakeup(). All this, before the waiter gets tc_lock
	 *    to sleep in turnstile_block(). turnstile_wakeup() will then not
	 *    find this waiter, resulting in the missed wakeup.
	 * 3. The upib_lock, being a kernel mutex, cannot be released while
	 *    holding the tc_lock (since mutex_exit() could need to acquire
	 *    the same tc_lock)...and so is held when calling turnstile_block().
	 *    The address of upib_lock is passed to turnstile_block() which
	 *    releases it after releasing all turnstile locks, and before going
	 *    to sleep in swtch().
	 * 4. The waiter value cannot be a count of waiters, because a waiter
	 *    can be interrupted. The interrupt occurs under the tc_lock, at
	 *    which point, the upib_lock cannot be locked, to decrement waiter
	 *    count. So, just treat the waiter state as a bit, not a count.
	 */
	ts = turnstile_lookup((upimutex_t *)upimutex);
	upimutex->upi_waiter = 1;
	error = turnstile_block(ts, TS_WRITER_Q, (upimutex_t *)upimutex,
	    &lwp_sobj_pi_ops, &upibp->upib_lock, lwptp);
	/*
	 * Hand-off implies that we wakeup holding the lock, except when:
	 *	- deadlock is detected
	 *	- lock is not recoverable
	 *	- we got an interrupt or timeout
	 * If we wake up due to an interrupt or timeout, we may
	 * or may not be holding the lock due to mutex hand-off.
	 * Use lwp_upimutex_owned() to check if we do hold the lock.
	 */
	if (error != 0) {
		if ((error == EINTR || error == ETIME) &&
		    (upimutex = lwp_upimutex_owned(lp, type))) {
			/*
			 * Unlock and return - the re-startable syscall will
			 * try the lock again if we got EINTR.
			 */
			(void) upi_mylist_add((upimutex_t *)upimutex);
			upimutex_unlock((upimutex_t *)upimutex, 0);
		}
		/*
		 * The only other possible error is EDEADLK.  If so, upimutex
		 * is valid, since its owner is deadlocked with curthread.
		 */
		ASSERT(error == EINTR || error == ETIME ||
		    (error == EDEADLK && !upi_owned((upimutex_t *)upimutex)));
		ASSERT(!lwp_upimutex_owned(lp, type));
		goto out;
	}
	if (lwp_upimutex_owned(lp, type)) {
		ASSERT(lwp_upimutex_owned(lp, type) == upimutex);
		nupinest = upi_mylist_add((upimutex_t *)upimutex);
		upilocked = 1;
	}
	/*
	 * Now, need to read the user-level lp->mutex_flag to do the following:
	 *
	 * - if lock is held, check if EOWNERDEAD or ELOCKUNMAPPED
	 *   should be returned.
	 * - if lock isn't held, check if ENOTRECOVERABLE should
	 *   be returned.
	 *
	 * Now, either lp->mutex_flag is readable or it's not. If not
	 * readable, the on_fault path will cause a return with EFAULT
	 * as it should.  If it is readable, the state of the flag
	 * encodes the robustness state of the lock:
	 *
	 * If the upimutex is locked here, the flag's LOCK_OWNERDEAD
	 * or LOCK_UNMAPPED setting will influence the return code
	 * appropriately.  If the upimutex is not locked here, this
	 * could be due to a spurious wake-up or a NOTRECOVERABLE
	 * event.  The flag's setting can be used to distinguish
	 * between these two events.
	 */
	fuword16_noerr(&lp->mutex_flag, &flag);
	if (upilocked) {
		/*
		 * If the thread wakes up from turnstile_block with the lock
		 * held, the flag could not be set to LOCK_NOTRECOVERABLE,
		 * since it would not have been handed-off the lock.
		 * So, no need to check for this case.
		 */
		if (nupinest > maxnestupimx &&
		    secpolicy_resource(CRED()) != 0) {
			upimutex_unlock((upimutex_t *)upimutex, flag);
			upilocked = 0;
			error = ENOMEM;
		} else if (flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED)) {
			if (flag & LOCK_OWNERDEAD)
				error = EOWNERDEAD;
			else if (type & USYNC_PROCESS_ROBUST)
				error = ELOCKUNMAPPED;
			else
				error = EOWNERDEAD;
		}
	} else {
		/*
		 * Wake-up without the upimutex held. Either this is a
		 * spurious wake-up (due to signals, forkall(), whatever), or
		 * it is a LOCK_NOTRECOVERABLE robustness event. The setting
		 * of the mutex flag can be used to distinguish between the
		 * two events.
		 */
		if (flag & LOCK_NOTRECOVERABLE) {
			error = ENOTRECOVERABLE;
		} else {
			/*
			 * Here, the flag could be set to LOCK_OWNERDEAD or
			 * not. In both cases, this is a spurious wakeup,
			 * since the upi lock is not held, but the thread
			 * has returned from turnstile_block().
			 *
			 * The user flag could be LOCK_OWNERDEAD if, at the
			 * same time as curthread having been woken up
			 * spuriously, the owner (say Tdead) has died, marked
			 * the mutex flag accordingly, and handed off the lock
			 * to some other waiter (say Tnew). curthread just
			 * happened to read the flag while Tnew has yet to deal
			 * with the owner-dead event.
			 *
			 * In this event, curthread should retry the lock.
			 * If Tnew is able to cleanup the lock, curthread
			 * will eventually get the lock with a zero error code,
			 * If Tnew is unable to cleanup, its eventual call to
			 * unlock the lock will result in the mutex flag being
			 * set to LOCK_NOTRECOVERABLE, and the wake-up of
			 * all waiters, including curthread, which will then
			 * eventually return ENOTRECOVERABLE due to the above
			 * check.
			 *
			 * Of course, if the user-flag is not set with
			 * LOCK_OWNERDEAD, retrying is the thing to do, since
			 * this is definitely a spurious wakeup.
			 */
			goto retry;
		}
	}

out:
	no_fault();
	return (error);
}


static int
lwp_upimutex_unlock(lwp_mutex_t *lp, uint8_t type)
{
	label_t ljb;
	int error = 0;
	lwpchan_t lwpchan;
	uint16_t flag;
	upib_t *upibp;
	volatile struct upimutex *upimutex = NULL;
	volatile int upilocked = 0;

	if (on_fault(&ljb)) {
		if (upilocked)
			upimutex_unlock((upimutex_t *)upimutex, 0);
		error = EFAULT;
		goto out;
	}
	if (!get_lwpchan(curproc->p_as, (caddr_t)lp, type,
	    &lwpchan, LWPCHAN_MPPOOL)) {
		error = EFAULT;
		goto out;
	}
	upibp = &UPI_CHAIN(lwpchan);
	mutex_enter(&upibp->upib_lock);
	upimutex = upi_get(upibp, &lwpchan);
	/*
	 * If the lock is not held, or the owner is not curthread, return
	 * error. The user-level wrapper can return this error or stall,
	 * depending on whether mutex is of ERRORCHECK type or not.
	 */
	if (upimutex == NULL || upimutex->upi_owner != curthread) {
		mutex_exit(&upibp->upib_lock);
		error = EPERM;
		goto out;
	}
	mutex_exit(&upibp->upib_lock); /* release for user memory access */
	upilocked = 1;
	fuword16_noerr(&lp->mutex_flag, &flag);
	if (flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED)) {
		/*
		 * transition mutex to the LOCK_NOTRECOVERABLE state.
		 */
		flag &= ~(LOCK_OWNERDEAD | LOCK_UNMAPPED);
		flag |= LOCK_NOTRECOVERABLE;
		suword16_noerr(&lp->mutex_flag, flag);
	}
	set_owner_pid(lp, 0, 0);
	upimutex_unlock((upimutex_t *)upimutex, flag);
	upilocked = 0;
out:
	no_fault();
	return (error);
}

/*
 * Set the owner and ownerpid fields of a user-level mutex.
 */
static void
set_owner_pid(lwp_mutex_t *lp, uintptr_t owner, pid_t pid)
{
	union {
		uint64_t word64;
		uint32_t word32[2];
	} un;

	un.word64 = (uint64_t)owner;

	suword32_noerr(&lp->mutex_ownerpid, pid);
#if defined(_LP64)
	if (((uintptr_t)lp & (_LONG_LONG_ALIGNMENT - 1)) == 0) { /* aligned */
		suword64_noerr(&lp->mutex_owner, un.word64);
		return;
	}
#endif
	/* mutex is unaligned or we are running on a 32-bit kernel */
	suword32_noerr((uint32_t *)&lp->mutex_owner, un.word32[0]);
	suword32_noerr((uint32_t *)&lp->mutex_owner + 1, un.word32[1]);
}

/*
 * Clear the contents of a user-level mutex; return the flags.
 * Used only by upi_dead() and lwp_mutex_cleanup(), below.
 */
static uint16_t
lwp_clear_mutex(lwp_mutex_t *lp, uint16_t lockflg)
{
	uint16_t flag;

	fuword16_noerr(&lp->mutex_flag, &flag);
	if ((flag &
	    (LOCK_OWNERDEAD | LOCK_UNMAPPED | LOCK_NOTRECOVERABLE)) == 0) {
		flag |= lockflg;
		suword16_noerr(&lp->mutex_flag, flag);
	}
	set_owner_pid(lp, 0, 0);
	suword8_noerr(&lp->mutex_rcount, 0);

	return (flag);
}

/*
 * Mark user mutex state, corresponding to kernel upimutex,
 * as LOCK_UNMAPPED or LOCK_OWNERDEAD, as appropriate
 */
static int
upi_dead(upimutex_t *upip, uint16_t lockflg)
{
	label_t ljb;
	int error = 0;
	lwp_mutex_t *lp;

	if (on_fault(&ljb)) {
		error = EFAULT;
		goto out;
	}

	lp = upip->upi_vaddr;
	(void) lwp_clear_mutex(lp, lockflg);
	suword8_noerr(&lp->mutex_lockw, 0);
out:
	no_fault();
	return (error);
}

/*
 * Unlock all upimutexes held by curthread, since curthread is dying.
 * For each upimutex, attempt to mark its corresponding user mutex object as
 * dead.
 */
void
upimutex_cleanup()
{
	kthread_t *t = curthread;
	uint16_t lockflg = (ttoproc(t)->p_proc_flag & P_PR_EXEC)?
	    LOCK_UNMAPPED : LOCK_OWNERDEAD;
	struct upimutex *upip;

	while ((upip = t->t_upimutex) != NULL) {
		if (upi_dead(upip, lockflg) != 0) {
			/*
			 * If the user object associated with this upimutex is
			 * unmapped, unlock upimutex with the
			 * LOCK_NOTRECOVERABLE flag, so that all waiters are
			 * woken up. Since user object is unmapped, it could
			 * not be marked as dead or notrecoverable.
			 * The waiters will now all wake up and return
			 * ENOTRECOVERABLE, since they would find that the lock
			 * has not been handed-off to them.
			 * See lwp_upimutex_lock().
			 */
			upimutex_unlock(upip, LOCK_NOTRECOVERABLE);
		} else {
			/*
			 * The user object has been updated as dead.
			 * Unlock the upimutex: if no waiters, upip kmem will
			 * be freed. If there is a waiter, the lock will be
			 * handed off. If exit() is in progress, each existing
			 * waiter will successively get the lock, as owners
			 * die, and each new owner will call this routine as
			 * it dies. The last owner will free kmem, since
			 * it will find the upimutex has no waiters. So,
			 * eventually, the kmem is guaranteed to be freed.
			 */
			upimutex_unlock(upip, 0);
		}
		/*
		 * Note that the call to upimutex_unlock() above will delete
		 * upimutex from the t_upimutexes chain. And so the
		 * while loop will eventually terminate.
		 */
	}
}

int
lwp_mutex_timedlock(lwp_mutex_t *lp, timespec_t *tsp, uintptr_t owner)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	lwp_timer_t lwpt;
	caddr_t timedwait;
	int error = 0;
	int time_error;
	clock_t tim = -1;
	uchar_t waiters;
	volatile int locked = 0;
	volatile int watched = 0;
	label_t ljb;
	volatile uint8_t type = 0;
	lwpchan_t lwpchan;
	sleepq_head_t *sqh;
	uint16_t flag;
	int imm_timeout = 0;

	if ((caddr_t)lp >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	/*
	 * Put the lwp in an orderly state for debugging,
	 * in case we are stopped while sleeping, below.
	 */
	prstop(PR_REQUESTED, 0);

	timedwait = (caddr_t)tsp;
	if ((time_error = lwp_timer_copyin(&lwpt, tsp)) == 0 &&
	    lwpt.lwpt_imm_timeout) {
		imm_timeout = 1;
		timedwait = NULL;
	}

	/*
	 * Although LMS_USER_LOCK implies "asleep waiting for user-mode lock",
	 * this micro state is really a run state. If the thread indeed blocks,
	 * this state becomes valid. If not, the state is converted back to
	 * LMS_SYSTEM. So, it is OK to set the mstate here, instead of just
	 * when blocking.
	 */
	(void) new_mstate(t, LMS_USER_LOCK);
	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
		error = EFAULT;
		goto out;
	}
	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword8_noerr(&lp->mutex_type, (uint8_t *)&type);
	suword8_noerr(&lp->mutex_type, type);
	if (UPIMUTEX(type)) {
		no_fault();
		error = lwp_upimutex_lock(lp, type, UPIMUTEX_BLOCK, &lwpt);
		if (error == 0 || error == EOWNERDEAD || error == ELOCKUNMAPPED)
			set_owner_pid(lp, owner,
			    (type & USYNC_PROCESS)? p->p_pid : 0);
		if (tsp && !time_error)	/* copyout the residual time left */
			error = lwp_timer_copyout(&lwpt, error);
		if (error)
			return (set_errno(error));
		return (0);
	}
	if (!get_lwpchan(curproc->p_as, (caddr_t)lp, type,
	    &lwpchan, LWPCHAN_MPPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_MPPOOL);
	locked = 1;
	if (type & LOCK_ROBUST) {
		fuword16_noerr(&lp->mutex_flag, &flag);
		if (flag & LOCK_NOTRECOVERABLE) {
			lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
			error = ENOTRECOVERABLE;
			goto out;
		}
	}
	fuword8_noerr(&lp->mutex_waiters, &waiters);
	suword8_noerr(&lp->mutex_waiters, 1);

	/*
	 * If watchpoints are set, they need to be restored, since
	 * atomic accesses of memory such as the call to ulock_try()
	 * below cannot be watched.
	 */

	watched = watch_disable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);

	while (!ulock_try(&lp->mutex_lockw)) {
		if (time_error) {
			/*
			 * The SUSV3 Posix spec is very clear that we
			 * should get no error from validating the
			 * timer until we would actually sleep.
			 */
			error = time_error;
			break;
		}

		if (watched) {
			watch_enable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);
			watched = 0;
		}

		if (timedwait) {
			/*
			 * If we successfully queue the timeout,
			 * then don't drop t_delay_lock until
			 * we are on the sleep queue (below).
			 */
			mutex_enter(&t->t_delay_lock);
			if (lwp_timer_enqueue(&lwpt) != 0) {
				mutex_exit(&t->t_delay_lock);
				imm_timeout = 1;
				timedwait = NULL;
			}
		}
		lwp_block(&lwpchan);
		/*
		 * Nothing should happen to cause the lwp to go to
		 * sleep again until after it returns from swtch().
		 */
		if (timedwait)
			mutex_exit(&t->t_delay_lock);
		locked = 0;
		lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
		if (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t) || imm_timeout)
			setrun(t);
		swtch();
		t->t_flag &= ~T_WAKEABLE;
		if (timedwait)
			tim = lwp_timer_dequeue(&lwpt);
		setallwatch();
		if (ISSIG(t, FORREAL) || lwp->lwp_sysabort || MUSTRETURN(p, t))
			error = EINTR;
		else if (imm_timeout || (timedwait && tim == -1))
			error = ETIME;
		if (error) {
			lwp->lwp_asleep = 0;
			lwp->lwp_sysabort = 0;
			watched = watch_disable_addr((caddr_t)lp, sizeof (*lp),
			    S_WRITE);

			/*
			 * Need to re-compute waiters bit. The waiters field in
			 * the lock is not reliable. Either of two things could
			 * have occurred: no lwp may have called lwp_release()
			 * for me but I have woken up due to a signal or
			 * timeout.  In this case, the waiter bit is incorrect
			 * since it is still set to 1, set above.
			 * OR an lwp_release() did occur for some other lwp on
			 * the same lwpchan. In this case, the waiter bit is
			 * correct.  But which event occurred, one can't tell.
			 * So, recompute.
			 */
			lwpchan_lock(&lwpchan, LWPCHAN_MPPOOL);
			locked = 1;
			sqh = lwpsqhash(&lwpchan);
			disp_lock_enter(&sqh->sq_lock);
			waiters = iswanted(sqh->sq_queue.sq_first, &lwpchan);
			disp_lock_exit(&sqh->sq_lock);
			break;
		}
		lwp->lwp_asleep = 0;
		watched = watch_disable_addr((caddr_t)lp, sizeof (*lp),
		    S_WRITE);
		lwpchan_lock(&lwpchan, LWPCHAN_MPPOOL);
		locked = 1;
		fuword8_noerr(&lp->mutex_waiters, &waiters);
		suword8_noerr(&lp->mutex_waiters, 1);
		if (type & LOCK_ROBUST) {
			fuword16_noerr(&lp->mutex_flag, &flag);
			if (flag & LOCK_NOTRECOVERABLE) {
				error = ENOTRECOVERABLE;
				break;
			}
		}
	}

	if (t->t_mstate == LMS_USER_LOCK)
		(void) new_mstate(t, LMS_SYSTEM);

	if (error == 0) {
		set_owner_pid(lp, owner, (type & USYNC_PROCESS)? p->p_pid : 0);
		if (type & LOCK_ROBUST) {
			fuword16_noerr(&lp->mutex_flag, &flag);
			if (flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED)) {
				if (flag & LOCK_OWNERDEAD)
					error = EOWNERDEAD;
				else if (type & USYNC_PROCESS_ROBUST)
					error = ELOCKUNMAPPED;
				else
					error = EOWNERDEAD;
			}
		}
	}
	suword8_noerr(&lp->mutex_waiters, waiters);
	locked = 0;
	lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);
	if (tsp && !time_error)		/* copyout the residual time left */
		error = lwp_timer_copyout(&lwpt, error);
	if (error)
		return (set_errno(error));
	return (0);
}

static int
iswanted(kthread_t *t, lwpchan_t *lwpchan)
{
	/*
	 * The caller holds the dispatcher lock on the sleep queue.
	 */
	while (t != NULL) {
		if (t->t_lwpchan.lc_wchan0 == lwpchan->lc_wchan0 &&
		    t->t_lwpchan.lc_wchan == lwpchan->lc_wchan)
			return (1);
		t = t->t_link;
	}
	return (0);
}

/*
 * Return the highest priority thread sleeping on this lwpchan.
 */
static kthread_t *
lwp_queue_waiter(lwpchan_t *lwpchan)
{
	sleepq_head_t *sqh;
	kthread_t *tp;

	sqh = lwpsqhash(lwpchan);
	disp_lock_enter(&sqh->sq_lock);		/* lock the sleep queue */
	for (tp = sqh->sq_queue.sq_first; tp != NULL; tp = tp->t_link) {
		if (tp->t_lwpchan.lc_wchan0 == lwpchan->lc_wchan0 &&
		    tp->t_lwpchan.lc_wchan == lwpchan->lc_wchan)
			break;
	}
	disp_lock_exit(&sqh->sq_lock);
	return (tp);
}

static int
lwp_release(lwpchan_t *lwpchan, uchar_t *waiters, int sync_type)
{
	sleepq_head_t *sqh;
	kthread_t *tp;
	kthread_t **tpp;

	sqh = lwpsqhash(lwpchan);
	disp_lock_enter(&sqh->sq_lock);		/* lock the sleep queue */
	tpp = &sqh->sq_queue.sq_first;
	while ((tp = *tpp) != NULL) {
		if (tp->t_lwpchan.lc_wchan0 == lwpchan->lc_wchan0 &&
		    tp->t_lwpchan.lc_wchan == lwpchan->lc_wchan) {
			/*
			 * The following is typically false. It could be true
			 * only if lwp_release() is called from
			 * lwp_mutex_wakeup() after reading the waiters field
			 * from memory in which the lwp lock used to be, but has
			 * since been re-used to hold a lwp cv or lwp semaphore.
			 * The thread "tp" found to match the lwp lock's wchan
			 * is actually sleeping for the cv or semaphore which
			 * now has the same wchan. In this case, lwp_release()
			 * should return failure.
			 */
			if (sync_type != (tp->t_flag & T_WAITCVSEM)) {
				ASSERT(sync_type == 0);
				/*
				 * assert that this can happen only for mutexes
				 * i.e. sync_type == 0, for correctly written
				 * user programs.
				 */
				disp_lock_exit(&sqh->sq_lock);
				return (0);
			}
			*waiters = iswanted(tp->t_link, lwpchan);
			sleepq_unlink(tpp, tp);
			DTRACE_SCHED1(wakeup, kthread_t *, tp);
			tp->t_wchan0 = NULL;
			tp->t_wchan = NULL;
			tp->t_sobj_ops = NULL;
			tp->t_release = 1;
			THREAD_TRANSITION(tp);	/* drops sleepq lock */
			CL_WAKEUP(tp);
			thread_unlock(tp);	/* drop run queue lock */
			return (1);
		}
		tpp = &tp->t_link;
	}
	*waiters = 0;
	disp_lock_exit(&sqh->sq_lock);
	return (0);
}

static void
lwp_release_all(lwpchan_t *lwpchan)
{
	sleepq_head_t	*sqh;
	kthread_t *tp;
	kthread_t **tpp;

	sqh = lwpsqhash(lwpchan);
	disp_lock_enter(&sqh->sq_lock);		/* lock sleep q queue */
	tpp = &sqh->sq_queue.sq_first;
	while ((tp = *tpp) != NULL) {
		if (tp->t_lwpchan.lc_wchan0 == lwpchan->lc_wchan0 &&
		    tp->t_lwpchan.lc_wchan == lwpchan->lc_wchan) {
			sleepq_unlink(tpp, tp);
			DTRACE_SCHED1(wakeup, kthread_t *, tp);
			tp->t_wchan0 = NULL;
			tp->t_wchan = NULL;
			tp->t_sobj_ops = NULL;
			CL_WAKEUP(tp);
			thread_unlock_high(tp);	/* release run queue lock */
		} else {
			tpp = &tp->t_link;
		}
	}
	disp_lock_exit(&sqh->sq_lock);		/* drop sleep q lock */
}

/*
 * unblock a lwp that is trying to acquire this mutex. the blocked
 * lwp resumes and retries to acquire the lock.
 */
int
lwp_mutex_wakeup(lwp_mutex_t *lp, int release_all)
{
	proc_t *p = ttoproc(curthread);
	lwpchan_t lwpchan;
	uchar_t waiters;
	volatile int locked = 0;
	volatile int watched = 0;
	volatile uint8_t type = 0;
	label_t ljb;
	int error = 0;

	if ((caddr_t)lp >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	watched = watch_disable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);

	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
		error = EFAULT;
		goto out;
	}
	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword8_noerr(&lp->mutex_type, (uint8_t *)&type);
	suword8_noerr(&lp->mutex_type, type);
	if (!get_lwpchan(curproc->p_as, (caddr_t)lp, type,
	    &lwpchan, LWPCHAN_MPPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_MPPOOL);
	locked = 1;
	/*
	 * Always wake up an lwp (if any) waiting on lwpchan. The woken lwp will
	 * re-try the lock in lwp_mutex_timedlock(). The call to lwp_release()
	 * may fail.  If it fails, do not write into the waiter bit.
	 * The call to lwp_release() might fail due to one of three reasons:
	 *
	 * 	1. due to the thread which set the waiter bit not actually
	 *	   sleeping since it got the lock on the re-try. The waiter
	 *	   bit will then be correctly updated by that thread. This
	 *	   window may be closed by reading the wait bit again here
	 *	   and not calling lwp_release() at all if it is zero.
	 *	2. the thread which set the waiter bit and went to sleep
	 *	   was woken up by a signal. This time, the waiter recomputes
	 *	   the wait bit in the return with EINTR code.
	 *	3. the waiter bit read by lwp_mutex_wakeup() was in
	 *	   memory that has been re-used after the lock was dropped.
	 *	   In this case, writing into the waiter bit would cause data
	 *	   corruption.
	 */
	if (release_all)
		lwp_release_all(&lwpchan);
	else if (lwp_release(&lwpchan, &waiters, 0))
		suword8_noerr(&lp->mutex_waiters, waiters);
	lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * lwp_cond_wait() has four arguments, a pointer to a condition variable,
 * a pointer to a mutex, a pointer to a timespec for a timed wait and
 * a flag telling the kernel whether or not to honor the kernel/user
 * schedctl parking protocol (see schedctl_is_park() in schedctl.c).
 * The kernel puts the lwp to sleep on a unique pair of caddr_t's called an
 * lwpchan, returned by get_lwpchan().  If the timespec pointer is non-NULL,
 * it is used an an in/out parameter.  On entry, it contains the relative
 * time until timeout.  On exit, we copyout the residual time left to it.
 */
int
lwp_cond_wait(lwp_cond_t *cv, lwp_mutex_t *mp, timespec_t *tsp, int check_park)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	lwp_timer_t lwpt;
	lwpchan_t cv_lwpchan;
	lwpchan_t m_lwpchan;
	caddr_t timedwait;
	volatile uint16_t type = 0;
	volatile uint8_t mtype = 0;
	uchar_t waiters;
	volatile int error;
	clock_t tim = -1;
	volatile int locked = 0;
	volatile int m_locked = 0;
	volatile int cvwatched = 0;
	volatile int mpwatched = 0;
	label_t ljb;
	volatile int no_lwpchan = 1;
	int imm_timeout = 0;
	int imm_unpark = 0;

	if ((caddr_t)cv >= p->p_as->a_userlimit ||
	    (caddr_t)mp >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	/*
	 * Put the lwp in an orderly state for debugging,
	 * in case we are stopped while sleeping, below.
	 */
	prstop(PR_REQUESTED, 0);

	timedwait = (caddr_t)tsp;
	if ((error = lwp_timer_copyin(&lwpt, tsp)) != 0)
		return (set_errno(error));
	if (lwpt.lwpt_imm_timeout) {
		imm_timeout = 1;
		timedwait = NULL;
	}

	(void) new_mstate(t, LMS_USER_LOCK);

	if (on_fault(&ljb)) {
		if (no_lwpchan) {
			error = EFAULT;
			goto out;
		}
		if (m_locked) {
			m_locked = 0;
			lwpchan_unlock(&m_lwpchan, LWPCHAN_MPPOOL);
		}
		if (locked) {
			locked = 0;
			lwpchan_unlock(&cv_lwpchan, LWPCHAN_CVPOOL);
		}
		/*
		 * set up another on_fault() for a possible fault
		 * on the user lock accessed at "efault"
		 */
		if (on_fault(&ljb)) {
			if (m_locked) {
				m_locked = 0;
				lwpchan_unlock(&m_lwpchan, LWPCHAN_MPPOOL);
			}
			goto out;
		}
		error = EFAULT;
		goto efault;
	}

	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword8_noerr(&mp->mutex_type, (uint8_t *)&mtype);
	suword8_noerr(&mp->mutex_type, mtype);
	if (UPIMUTEX(mtype) == 0) {
		/* convert user level mutex, "mp", to a unique lwpchan */
		/* check if mtype is ok to use below, instead of type from cv */
		if (!get_lwpchan(p->p_as, (caddr_t)mp, mtype,
		    &m_lwpchan, LWPCHAN_MPPOOL)) {
			error = EFAULT;
			goto out;
		}
	}
	fuword16_noerr(&cv->cond_type, (uint16_t *)&type);
	suword16_noerr(&cv->cond_type, type);
	/* convert user level condition variable, "cv", to a unique lwpchan */
	if (!get_lwpchan(p->p_as, (caddr_t)cv, type,
	    &cv_lwpchan, LWPCHAN_CVPOOL)) {
		error = EFAULT;
		goto out;
	}
	no_lwpchan = 0;
	cvwatched = watch_disable_addr((caddr_t)cv, sizeof (*cv), S_WRITE);
	if (UPIMUTEX(mtype) == 0)
		mpwatched = watch_disable_addr((caddr_t)mp, sizeof (*mp),
		    S_WRITE);

	/*
	 * lwpchan_lock ensures that the calling lwp is put to sleep atomically
	 * with respect to a possible wakeup which is a result of either
	 * an lwp_cond_signal() or an lwp_cond_broadcast().
	 *
	 * What's misleading, is that the lwp is put to sleep after the
	 * condition variable's mutex is released.  This is OK as long as
	 * the release operation is also done while holding lwpchan_lock.
	 * The lwp is then put to sleep when the possibility of pagefaulting
	 * or sleeping is completely eliminated.
	 */
	lwpchan_lock(&cv_lwpchan, LWPCHAN_CVPOOL);
	locked = 1;
	if (UPIMUTEX(mtype) == 0) {
		lwpchan_lock(&m_lwpchan, LWPCHAN_MPPOOL);
		m_locked = 1;
		suword8_noerr(&cv->cond_waiters_kernel, 1);
		/*
		 * unlock the condition variable's mutex. (pagefaults are
		 * possible here.)
		 */
		set_owner_pid(mp, 0, 0);
		ulock_clear(&mp->mutex_lockw);
		fuword8_noerr(&mp->mutex_waiters, &waiters);
		if (waiters != 0) {
			/*
			 * Given the locking of lwpchan_lock around the release
			 * of the mutex and checking for waiters, the following
			 * call to lwp_release() can fail ONLY if the lock
			 * acquirer is interrupted after setting the waiter bit,
			 * calling lwp_block() and releasing lwpchan_lock.
			 * In this case, it could get pulled off the lwp sleep
			 * q (via setrun()) before the following call to
			 * lwp_release() occurs. In this case, the lock
			 * requestor will update the waiter bit correctly by
			 * re-evaluating it.
			 */
			if (lwp_release(&m_lwpchan, &waiters, 0))
				suword8_noerr(&mp->mutex_waiters, waiters);
		}
		m_locked = 0;
		lwpchan_unlock(&m_lwpchan, LWPCHAN_MPPOOL);
	} else {
		suword8_noerr(&cv->cond_waiters_kernel, 1);
		error = lwp_upimutex_unlock(mp, mtype);
		if (error) {	/* if the upimutex unlock failed */
			locked = 0;
			lwpchan_unlock(&cv_lwpchan, LWPCHAN_CVPOOL);
			goto out;
		}
	}
	no_fault();

	if (mpwatched) {
		watch_enable_addr((caddr_t)mp, sizeof (*mp), S_WRITE);
		mpwatched = 0;
	}
	if (cvwatched) {
		watch_enable_addr((caddr_t)cv, sizeof (*cv), S_WRITE);
		cvwatched = 0;
	}

	if (check_park && (!schedctl_is_park() || t->t_unpark)) {
		/*
		 * We received a signal at user-level before calling here
		 * or another thread wants us to return immediately
		 * with EINTR.  See lwp_unpark().
		 */
		imm_unpark = 1;
		t->t_unpark = 0;
		timedwait = NULL;
	} else if (timedwait) {
		/*
		 * If we successfully queue the timeout,
		 * then don't drop t_delay_lock until
		 * we are on the sleep queue (below).
		 */
		mutex_enter(&t->t_delay_lock);
		if (lwp_timer_enqueue(&lwpt) != 0) {
			mutex_exit(&t->t_delay_lock);
			imm_timeout = 1;
			timedwait = NULL;
		}
	}
	t->t_flag |= T_WAITCVSEM;
	lwp_block(&cv_lwpchan);
	/*
	 * Nothing should happen to cause the lwp to go to sleep
	 * until after it returns from swtch().
	 */
	if (timedwait)
		mutex_exit(&t->t_delay_lock);
	locked = 0;
	lwpchan_unlock(&cv_lwpchan, LWPCHAN_CVPOOL);
	if (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t) ||
	    (imm_timeout | imm_unpark))
		setrun(t);
	swtch();
	t->t_flag &= ~(T_WAITCVSEM | T_WAKEABLE);
	if (timedwait)
		tim = lwp_timer_dequeue(&lwpt);
	if (ISSIG(t, FORREAL) || lwp->lwp_sysabort ||
	    MUSTRETURN(p, t) || imm_unpark)
		error = EINTR;
	else if (imm_timeout || (timedwait && tim == -1))
		error = ETIME;
	lwp->lwp_asleep = 0;
	lwp->lwp_sysabort = 0;
	setallwatch();

	if (t->t_mstate == LMS_USER_LOCK)
		(void) new_mstate(t, LMS_SYSTEM);

	if (tsp && check_park)		/* copyout the residual time left */
		error = lwp_timer_copyout(&lwpt, error);

	/* the mutex is reacquired by the caller on return to user level */
	if (error) {
		/*
		 * If we were concurrently lwp_cond_signal()d and we
		 * received a UNIX signal or got a timeout, then perform
		 * another lwp_cond_signal() to avoid consuming the wakeup.
		 */
		if (t->t_release)
			(void) lwp_cond_signal(cv);
		return (set_errno(error));
	}
	return (0);

efault:
	/*
	 * make sure that the user level lock is dropped before
	 * returning to caller, since the caller always re-acquires it.
	 */
	if (UPIMUTEX(mtype) == 0) {
		lwpchan_lock(&m_lwpchan, LWPCHAN_MPPOOL);
		m_locked = 1;
		set_owner_pid(mp, 0, 0);
		ulock_clear(&mp->mutex_lockw);
		fuword8_noerr(&mp->mutex_waiters, &waiters);
		if (waiters != 0) {
			/*
			 * See comment above on lock clearing and lwp_release()
			 * success/failure.
			 */
			if (lwp_release(&m_lwpchan, &waiters, 0))
				suword8_noerr(&mp->mutex_waiters, waiters);
		}
		m_locked = 0;
		lwpchan_unlock(&m_lwpchan, LWPCHAN_MPPOOL);
	} else {
		(void) lwp_upimutex_unlock(mp, mtype);
	}
out:
	no_fault();
	if (mpwatched)
		watch_enable_addr((caddr_t)mp, sizeof (*mp), S_WRITE);
	if (cvwatched)
		watch_enable_addr((caddr_t)cv, sizeof (*cv), S_WRITE);
	if (t->t_mstate == LMS_USER_LOCK)
		(void) new_mstate(t, LMS_SYSTEM);
	return (set_errno(error));
}

/*
 * wakeup one lwp that's blocked on this condition variable.
 */
int
lwp_cond_signal(lwp_cond_t *cv)
{
	proc_t *p = ttoproc(curthread);
	lwpchan_t lwpchan;
	uchar_t waiters;
	volatile uint16_t type = 0;
	volatile int locked = 0;
	volatile int watched = 0;
	label_t ljb;
	int error = 0;

	if ((caddr_t)cv >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	watched = watch_disable_addr((caddr_t)cv, sizeof (*cv), S_WRITE);

	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		error = EFAULT;
		goto out;
	}
	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword16_noerr(&cv->cond_type, (uint16_t *)&type);
	suword16_noerr(&cv->cond_type, type);
	if (!get_lwpchan(curproc->p_as, (caddr_t)cv, type,
	    &lwpchan, LWPCHAN_CVPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_CVPOOL);
	locked = 1;
	fuword8_noerr(&cv->cond_waiters_kernel, &waiters);
	if (waiters != 0) {
		/*
		 * The following call to lwp_release() might fail but it is
		 * OK to write into the waiters bit below, since the memory
		 * could not have been re-used or unmapped (for correctly
		 * written user programs) as in the case of lwp_mutex_wakeup().
		 * For an incorrect program, we should not care about data
		 * corruption since this is just one instance of other places
		 * where corruption can occur for such a program. Of course
		 * if the memory is unmapped, normal fault recovery occurs.
		 */
		(void) lwp_release(&lwpchan, &waiters, T_WAITCVSEM);
		suword8_noerr(&cv->cond_waiters_kernel, waiters);
	}
	lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)cv, sizeof (*cv), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * wakeup every lwp that's blocked on this condition variable.
 */
int
lwp_cond_broadcast(lwp_cond_t *cv)
{
	proc_t *p = ttoproc(curthread);
	lwpchan_t lwpchan;
	volatile uint16_t type = 0;
	volatile int locked = 0;
	volatile int watched = 0;
	label_t ljb;
	uchar_t waiters;
	int error = 0;

	if ((caddr_t)cv >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	watched = watch_disable_addr((caddr_t)cv, sizeof (*cv), S_WRITE);

	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		error = EFAULT;
		goto out;
	}
	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword16_noerr(&cv->cond_type, (uint16_t *)&type);
	suword16_noerr(&cv->cond_type, type);
	if (!get_lwpchan(curproc->p_as, (caddr_t)cv, type,
	    &lwpchan, LWPCHAN_CVPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_CVPOOL);
	locked = 1;
	fuword8_noerr(&cv->cond_waiters_kernel, &waiters);
	if (waiters != 0) {
		lwp_release_all(&lwpchan);
		suword8_noerr(&cv->cond_waiters_kernel, 0);
	}
	lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)cv, sizeof (*cv), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}

int
lwp_sema_trywait(lwp_sema_t *sp)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	label_t ljb;
	volatile int locked = 0;
	volatile int watched = 0;
	volatile uint16_t type = 0;
	int count;
	lwpchan_t lwpchan;
	uchar_t waiters;
	int error = 0;

	if ((caddr_t)sp >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	watched = watch_disable_addr((caddr_t)sp, sizeof (*sp), S_WRITE);

	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		error = EFAULT;
		goto out;
	}
	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword16_noerr((void *)&sp->sema_type, (uint16_t *)&type);
	suword16_noerr((void *)&sp->sema_type, type);
	if (!get_lwpchan(p->p_as, (caddr_t)sp, type,
	    &lwpchan, LWPCHAN_CVPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_CVPOOL);
	locked = 1;
	fuword32_noerr((void *)&sp->sema_count, (uint32_t *)&count);
	if (count == 0)
		error = EBUSY;
	else
		suword32_noerr((void *)&sp->sema_count, --count);
	if (count != 0) {
		fuword8_noerr(&sp->sema_waiters, &waiters);
		if (waiters != 0) {
			(void) lwp_release(&lwpchan, &waiters, T_WAITCVSEM);
			suword8_noerr(&sp->sema_waiters, waiters);
		}
	}
	lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, sizeof (*sp), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * See lwp_cond_wait(), above, for an explanation of the 'check_park' argument.
 */
int
lwp_sema_timedwait(lwp_sema_t *sp, timespec_t *tsp, int check_park)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	lwp_timer_t lwpt;
	caddr_t timedwait;
	clock_t tim = -1;
	label_t ljb;
	volatile int locked = 0;
	volatile int watched = 0;
	volatile uint16_t type = 0;
	int count;
	lwpchan_t lwpchan;
	uchar_t waiters;
	int error = 0;
	int time_error;
	int imm_timeout = 0;
	int imm_unpark = 0;

	if ((caddr_t)sp >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	/*
	 * Put the lwp in an orderly state for debugging,
	 * in case we are stopped while sleeping, below.
	 */
	prstop(PR_REQUESTED, 0);

	timedwait = (caddr_t)tsp;
	if ((time_error = lwp_timer_copyin(&lwpt, tsp)) == 0 &&
	    lwpt.lwpt_imm_timeout) {
		imm_timeout = 1;
		timedwait = NULL;
	}

	watched = watch_disable_addr((caddr_t)sp, sizeof (*sp), S_WRITE);

	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		error = EFAULT;
		goto out;
	}
	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword16_noerr((void *)&sp->sema_type, (uint16_t *)&type);
	suword16_noerr((void *)&sp->sema_type, type);
	if (!get_lwpchan(p->p_as, (caddr_t)sp, type,
	    &lwpchan, LWPCHAN_CVPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_CVPOOL);
	locked = 1;
	fuword32_noerr((void *)&sp->sema_count, (uint32_t *)&count);
	while (error == 0 && count == 0) {
		if (time_error) {
			/*
			 * The SUSV3 Posix spec is very clear that we
			 * should get no error from validating the
			 * timer until we would actually sleep.
			 */
			error = time_error;
			break;
		}
		suword8_noerr(&sp->sema_waiters, 1);
		if (watched)
			watch_enable_addr((caddr_t)sp, sizeof (*sp), S_WRITE);
		if (check_park && (!schedctl_is_park() || t->t_unpark)) {
			/*
			 * We received a signal at user-level before calling
			 * here or another thread wants us to return
			 * immediately with EINTR.  See lwp_unpark().
			 */
			imm_unpark = 1;
			t->t_unpark = 0;
			timedwait = NULL;
		} else if (timedwait) {
			/*
			 * If we successfully queue the timeout,
			 * then don't drop t_delay_lock until
			 * we are on the sleep queue (below).
			 */
			mutex_enter(&t->t_delay_lock);
			if (lwp_timer_enqueue(&lwpt) != 0) {
				mutex_exit(&t->t_delay_lock);
				imm_timeout = 1;
				timedwait = NULL;
			}
		}
		t->t_flag |= T_WAITCVSEM;
		lwp_block(&lwpchan);
		/*
		 * Nothing should happen to cause the lwp to sleep
		 * again until after it returns from swtch().
		 */
		if (timedwait)
			mutex_exit(&t->t_delay_lock);
		locked = 0;
		lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		if (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t) ||
		    (imm_timeout | imm_unpark))
			setrun(t);
		swtch();
		t->t_flag &= ~(T_WAITCVSEM | T_WAKEABLE);
		if (timedwait)
			tim = lwp_timer_dequeue(&lwpt);
		setallwatch();
		if (ISSIG(t, FORREAL) || lwp->lwp_sysabort ||
		    MUSTRETURN(p, t) || imm_unpark)
			error = EINTR;
		else if (imm_timeout || (timedwait && tim == -1))
			error = ETIME;
		lwp->lwp_asleep = 0;
		lwp->lwp_sysabort = 0;
		watched = watch_disable_addr((caddr_t)sp,
		    sizeof (*sp), S_WRITE);
		lwpchan_lock(&lwpchan, LWPCHAN_CVPOOL);
		locked = 1;
		fuword32_noerr((void *)&sp->sema_count, (uint32_t *)&count);
	}
	if (error == 0)
		suword32_noerr((void *)&sp->sema_count, --count);
	if (count != 0) {
		(void) lwp_release(&lwpchan, &waiters, T_WAITCVSEM);
		suword8_noerr(&sp->sema_waiters, waiters);
	}
	lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, sizeof (*sp), S_WRITE);
	if (tsp && check_park && !time_error)
		error = lwp_timer_copyout(&lwpt, error);
	if (error)
		return (set_errno(error));
	return (0);
}

int
lwp_sema_post(lwp_sema_t *sp)
{
	proc_t *p = ttoproc(curthread);
	label_t ljb;
	volatile int locked = 0;
	volatile int watched = 0;
	volatile uint16_t type = 0;
	int count;
	lwpchan_t lwpchan;
	uchar_t waiters;
	int error = 0;

	if ((caddr_t)sp >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	watched = watch_disable_addr((caddr_t)sp, sizeof (*sp), S_WRITE);

	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		error = EFAULT;
		goto out;
	}
	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword16_noerr(&sp->sema_type, (uint16_t *)&type);
	suword16_noerr(&sp->sema_type, type);
	if (!get_lwpchan(curproc->p_as, (caddr_t)sp, type,
	    &lwpchan, LWPCHAN_CVPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_CVPOOL);
	locked = 1;
	fuword32_noerr(&sp->sema_count, (uint32_t *)&count);
	if (count == _SEM_VALUE_MAX)
		error = EOVERFLOW;
	else
		suword32_noerr(&sp->sema_count, ++count);
	if (count == 1) {
		fuword8_noerr(&sp->sema_waiters, &waiters);
		if (waiters) {
			(void) lwp_release(&lwpchan, &waiters, T_WAITCVSEM);
			suword8_noerr(&sp->sema_waiters, waiters);
		}
	}
	lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)sp, sizeof (*sp), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}

#define	TRW_WANT_WRITE		0x1
#define	TRW_LOCK_GRANTED	0x2

#define	READ_LOCK		0
#define	WRITE_LOCK		1
#define	TRY_FLAG		0x10
#define	READ_LOCK_TRY		(READ_LOCK | TRY_FLAG)
#define	WRITE_LOCK_TRY		(WRITE_LOCK | TRY_FLAG)

/*
 * Release one writer or one or more readers. Compute the rwstate word to
 * reflect the new state of the queue. For a safe hand-off we copy the new
 * rwstate value back to userland before we wake any of the new lock holders.
 *
 * Note that sleepq_insert() implements a prioritized FIFO (with writers
 * being given precedence over readers of the same priority).
 *
 * If the first thread is a reader we scan the queue releasing all readers
 * until we hit a writer or the end of the queue. If the first thread is a
 * writer we still need to check for another writer.
 */
void
lwp_rwlock_release(lwpchan_t *lwpchan, lwp_rwlock_t *rw)
{
	sleepq_head_t *sqh;
	kthread_t *tp;
	kthread_t **tpp;
	kthread_t *tpnext;
	kthread_t *wakelist = NULL;
	uint32_t rwstate = 0;
	int wcount = 0;
	int rcount = 0;

	sqh = lwpsqhash(lwpchan);
	disp_lock_enter(&sqh->sq_lock);
	tpp = &sqh->sq_queue.sq_first;
	while ((tp = *tpp) != NULL) {
		if (tp->t_lwpchan.lc_wchan0 == lwpchan->lc_wchan0 &&
		    tp->t_lwpchan.lc_wchan == lwpchan->lc_wchan) {
			if (tp->t_writer & TRW_WANT_WRITE) {
				if ((wcount++ == 0) && (rcount == 0)) {
					rwstate |= URW_WRITE_LOCKED;

					/* Just one writer to wake. */
					sleepq_unlink(tpp, tp);
					wakelist = tp;

					/* tpp already set for next thread. */
					continue;
				} else {
					rwstate |= URW_HAS_WAITERS;
					/* We need look no further. */
					break;
				}
			} else {
				rcount++;
				if (wcount == 0) {
					rwstate++;

					/* Add reader to wake list. */
					sleepq_unlink(tpp, tp);
					tp->t_link = wakelist;
					wakelist = tp;

					/* tpp already set for next thread. */
					continue;
				} else {
					rwstate |= URW_HAS_WAITERS;
					/* We need look no further. */
					break;
				}
			}
		}
		tpp = &tp->t_link;
	}

	/* Copy the new rwstate back to userland. */
	suword32_noerr(&rw->rwlock_readers, rwstate);

	/* Wake the new lock holder(s) up. */
	tp = wakelist;
	while (tp != NULL) {
		DTRACE_SCHED1(wakeup, kthread_t *, tp);
		tp->t_wchan0 = NULL;
		tp->t_wchan = NULL;
		tp->t_sobj_ops = NULL;
		tp->t_writer |= TRW_LOCK_GRANTED;
		tpnext = tp->t_link;
		tp->t_link = NULL;
		CL_WAKEUP(tp);
		thread_unlock_high(tp);
		tp = tpnext;
	}

	disp_lock_exit(&sqh->sq_lock);
}

/*
 * We enter here holding the user-level mutex, which we must release before
 * returning or blocking. Based on lwp_cond_wait().
 */
static int
lwp_rwlock_lock(lwp_rwlock_t *rw, timespec_t *tsp, int rd_wr)
{
	lwp_mutex_t *mp = NULL;
	kthread_t *t = curthread;
	kthread_t *tp;
	klwp_t *lwp = ttolwp(t);
	proc_t *p = ttoproc(t);
	lwp_timer_t lwpt;
	lwpchan_t lwpchan;
	lwpchan_t mlwpchan;
	caddr_t timedwait;
	volatile uint16_t type = 0;
	volatile uint8_t mtype = 0;
	uchar_t mwaiters;
	volatile int error = 0;
	int time_error;
	clock_t tim = -1;
	volatile int locked = 0;
	volatile int mlocked = 0;
	volatile int watched = 0;
	volatile int mwatched = 0;
	label_t ljb;
	volatile int no_lwpchan = 1;
	int imm_timeout = 0;
	int try_flag;
	uint32_t rwstate;
	int acquired = 0;

	/* We only check rw because the mutex is included in it. */
	if ((caddr_t)rw >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	/*
	 * Put the lwp in an orderly state for debugging,
	 * in case we are stopped while sleeping, below.
	 */
	prstop(PR_REQUESTED, 0);

	/* We must only report this error if we are about to sleep (later). */
	timedwait = (caddr_t)tsp;
	if ((time_error = lwp_timer_copyin(&lwpt, tsp)) == 0 &&
	    lwpt.lwpt_imm_timeout) {
		imm_timeout = 1;
		timedwait = NULL;
	}

	(void) new_mstate(t, LMS_USER_LOCK);

	if (on_fault(&ljb)) {
		if (no_lwpchan) {
			error = EFAULT;
			goto out_nodrop;
		}
		if (mlocked) {
			mlocked = 0;
			lwpchan_unlock(&mlwpchan, LWPCHAN_MPPOOL);
		}
		if (locked) {
			locked = 0;
			lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		}
		/*
		 * Set up another on_fault() for a possible fault
		 * on the user lock accessed at "out_drop".
		 */
		if (on_fault(&ljb)) {
			if (mlocked) {
				mlocked = 0;
				lwpchan_unlock(&mlwpchan, LWPCHAN_MPPOOL);
			}
			error = EFAULT;
			goto out_nodrop;
		}
		error = EFAULT;
		goto out_nodrop;
	}

	/* Process rd_wr (including sanity check). */
	try_flag = (rd_wr & TRY_FLAG);
	rd_wr &= ~TRY_FLAG;
	if ((rd_wr != READ_LOCK) && (rd_wr != WRITE_LOCK)) {
		error = EINVAL;
		goto out_nodrop;
	}

	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	mp = &rw->mutex;
	fuword8_noerr(&mp->mutex_type, (uint8_t *)&mtype);
	fuword16_noerr(&rw->rwlock_type, (uint16_t *)&type);
	suword8_noerr(&mp->mutex_type, mtype);
	suword16_noerr(&rw->rwlock_type, type);

	/* We can only continue for simple USYNC_PROCESS locks. */
	if ((mtype != USYNC_PROCESS) || (type != USYNC_PROCESS)) {
		error = EINVAL;
		goto out_nodrop;
	}

	/* Convert user level mutex, "mp", to a unique lwpchan. */
	if (!get_lwpchan(p->p_as, (caddr_t)mp, mtype,
	    &mlwpchan, LWPCHAN_MPPOOL)) {
		error = EFAULT;
		goto out_nodrop;
	}

	/* Convert user level rwlock, "rw", to a unique lwpchan. */
	if (!get_lwpchan(p->p_as, (caddr_t)rw, type,
	    &lwpchan, LWPCHAN_CVPOOL)) {
		error = EFAULT;
		goto out_nodrop;
	}

	no_lwpchan = 0;
	watched = watch_disable_addr((caddr_t)rw, sizeof (*rw), S_WRITE);
	mwatched = watch_disable_addr((caddr_t)mp, sizeof (*mp), S_WRITE);

	/*
	 * lwpchan_lock() ensures that the calling LWP is put to sleep
	 * atomically with respect to a possible wakeup which is a result
	 * of lwp_rwlock_unlock().
	 *
	 * What's misleading is that the LWP is put to sleep after the
	 * rwlock's mutex is released. This is OK as long as the release
	 * operation is also done while holding mlwpchan. The LWP is then
	 * put to sleep when the possibility of pagefaulting or sleeping
	 * has been completely eliminated.
	 */
	lwpchan_lock(&lwpchan, LWPCHAN_CVPOOL);
	locked = 1;
	lwpchan_lock(&mlwpchan, LWPCHAN_MPPOOL);
	mlocked = 1;

	/*
	 * Fetch the current rwlock state.
	 *
	 * The possibility of spurious wake-ups or killed waiters means
	 * rwstate's URW_HAS_WAITERS bit may indicate false positives.
	 * We only fix these if they are important to us.
	 *
	 * Although various error states can be observed here (e.g. the lock
	 * is not held, but there are waiters) we assume these are applicaton
	 * errors and so we take no corrective action.
	 */
	fuword32_noerr(&rw->rwlock_readers, &rwstate);
	/*
	 * We cannot legitimately get here from user-level
	 * without URW_HAS_WAITERS being set.
	 * Set it now to guard against user-level error.
	 */
	rwstate |= URW_HAS_WAITERS;

	/*
	 * We can try only if the lock isn't held by a writer.
	 */
	if (!(rwstate & URW_WRITE_LOCKED)) {
		tp = lwp_queue_waiter(&lwpchan);
		if (tp == NULL) {
			/*
			 * Hmmm, rwstate indicates waiters but there are
			 * none queued. This could just be the result of a
			 * spurious wakeup, so let's ignore it.
			 *
			 * We now have a chance to acquire the lock
			 * uncontended, but this is the last chance for
			 * a writer to acquire the lock without blocking.
			 */
			if (rd_wr == READ_LOCK) {
				rwstate++;
				acquired = 1;
			} else if ((rwstate & URW_READERS_MASK) == 0) {
				rwstate |= URW_WRITE_LOCKED;
				acquired = 1;
			}
		} else if (rd_wr == READ_LOCK) {
			/*
			 * This is the last chance for a reader to acquire
			 * the lock now, but it can only do so if there is
			 * no writer of equal or greater priority at the
			 * head of the queue .
			 *
			 * It is also just possible that there is a reader
			 * at the head of the queue. This may be the result
			 * of a spurious wakeup or an application failure.
			 * In this case we only acquire the lock if we have
			 * equal or greater priority. It is not our job to
			 * release spurious waiters.
			 */
			pri_t our_pri = DISP_PRIO(t);
			pri_t his_pri = DISP_PRIO(tp);

			if ((our_pri > his_pri) || ((our_pri == his_pri) &&
			    !(tp->t_writer & TRW_WANT_WRITE))) {
				rwstate++;
				acquired = 1;
			}
		}
	}

	if (acquired || try_flag || time_error) {
		/*
		 * We're not going to block this time.
		 */
		suword32_noerr(&rw->rwlock_readers, rwstate);
		lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		locked = 0;

		if (acquired) {
			/*
			 * Got the lock!
			 */
			error = 0;

		} else if (try_flag) {
			/*
			 * We didn't get the lock and we're about to block.
			 * If we're doing a trylock, return EBUSY instead.
			 */
			error = EBUSY;

		} else if (time_error) {
			/*
			 * The SUSV3 POSIX spec is very clear that we should
			 * get no error from validating the timer (above)
			 * until we would actually sleep.
			 */
			error = time_error;
		}

		goto out_drop;
	}

	/*
	 * We're about to block, so indicate what kind of waiter we are.
	 */
	t->t_writer = 0;
	if (rd_wr == WRITE_LOCK)
		t->t_writer = TRW_WANT_WRITE;
	suword32_noerr(&rw->rwlock_readers, rwstate);

	/*
	 * Unlock the rwlock's mutex (pagefaults are possible here).
	 */
	set_owner_pid(mp, 0, 0);
	ulock_clear(&mp->mutex_lockw);
	fuword8_noerr(&mp->mutex_waiters, &mwaiters);
	if (mwaiters != 0) {
		/*
		 * Given the locking of mlwpchan around the release of
		 * the mutex and checking for waiters, the following
		 * call to lwp_release() can fail ONLY if the lock
		 * acquirer is interrupted after setting the waiter bit,
		 * calling lwp_block() and releasing mlwpchan.
		 * In this case, it could get pulled off the LWP sleep
		 * queue (via setrun()) before the following call to
		 * lwp_release() occurs, and the lock requestor will
		 * update the waiter bit correctly by re-evaluating it.
		 */
		if (lwp_release(&mlwpchan, &mwaiters, 0))
			suword8_noerr(&mp->mutex_waiters, mwaiters);
	}
	lwpchan_unlock(&mlwpchan, LWPCHAN_MPPOOL);
	mlocked = 0;
	no_fault();

	if (mwatched) {
		watch_enable_addr((caddr_t)mp, sizeof (*mp), S_WRITE);
		mwatched = 0;
	}
	if (watched) {
		watch_enable_addr((caddr_t)rw, sizeof (*rw), S_WRITE);
		watched = 0;
	}

	if (timedwait) {
		/*
		 * If we successfully queue the timeout,
		 * then don't drop t_delay_lock until
		 * we are on the sleep queue (below).
		 */
		mutex_enter(&t->t_delay_lock);
		if (lwp_timer_enqueue(&lwpt) != 0) {
			mutex_exit(&t->t_delay_lock);
			imm_timeout = 1;
			timedwait = NULL;
		}
	}
	t->t_flag |= T_WAITCVSEM;
	lwp_block(&lwpchan);

	/*
	 * Nothing should happen to cause the LWp to go to sleep until after
	 * it returns from swtch().
	 */
	if (timedwait)
		mutex_exit(&t->t_delay_lock);
	locked = 0;
	lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
	if (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t) || imm_timeout)
		setrun(t);
	swtch();

	/*
	 * We're back, but we need to work out why. Were we interrupted? Did
	 * we timeout? Were we granted the lock?
	 */
	error = EAGAIN;
	acquired = (t->t_writer & TRW_LOCK_GRANTED);
	t->t_writer = 0;
	t->t_flag &= ~(T_WAITCVSEM | T_WAKEABLE);
	if (timedwait)
		tim = lwp_timer_dequeue(&lwpt);
	if (ISSIG(t, FORREAL) || lwp->lwp_sysabort || MUSTRETURN(p, t))
		error = EINTR;
	else if (imm_timeout || (timedwait && tim == -1))
		error = ETIME;
	lwp->lwp_asleep = 0;
	lwp->lwp_sysabort = 0;
	setallwatch();

	/*
	 * If we were granted the lock we don't care about EINTR or ETIME.
	 */
	if (acquired)
		error = 0;

	if (t->t_mstate == LMS_USER_LOCK)
		(void) new_mstate(t, LMS_SYSTEM);

	if (error)
		return (set_errno(error));
	return (0);

out_drop:
	/*
	 * Make sure that the user level lock is dropped before returning
	 * to the caller.
	 */
	if (!mlocked) {
		lwpchan_lock(&mlwpchan, LWPCHAN_MPPOOL);
		mlocked = 1;
	}
	set_owner_pid(mp, 0, 0);
	ulock_clear(&mp->mutex_lockw);
	fuword8_noerr(&mp->mutex_waiters, &mwaiters);
	if (mwaiters != 0) {
		/*
		 * See comment above on lock clearing and lwp_release()
		 * success/failure.
		 */
		if (lwp_release(&mlwpchan, &mwaiters, 0))
			suword8_noerr(&mp->mutex_waiters, mwaiters);
	}
	lwpchan_unlock(&mlwpchan, LWPCHAN_MPPOOL);
	mlocked = 0;

out_nodrop:
	no_fault();
	if (mwatched)
		watch_enable_addr((caddr_t)mp, sizeof (*mp), S_WRITE);
	if (watched)
		watch_enable_addr((caddr_t)rw, sizeof (*rw), S_WRITE);
	if (t->t_mstate == LMS_USER_LOCK)
		(void) new_mstate(t, LMS_SYSTEM);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * We enter here holding the user-level mutex but, unlike lwp_rwlock_lock(),
 * we never drop the lock.
 */
static int
lwp_rwlock_unlock(lwp_rwlock_t *rw)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	lwpchan_t lwpchan;
	volatile uint16_t type = 0;
	volatile int error = 0;
	volatile int locked = 0;
	volatile int watched = 0;
	label_t ljb;
	volatile int no_lwpchan = 1;
	uint32_t rwstate;

	/* We only check rw because the mutex is included in it. */
	if ((caddr_t)rw >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	if (on_fault(&ljb)) {
		if (no_lwpchan) {
			error = EFAULT;
			goto out_nodrop;
		}
		if (locked) {
			locked = 0;
			lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
		}
		error = EFAULT;
		goto out_nodrop;
	}

	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword16_noerr(&rw->rwlock_type, (uint16_t *)&type);
	suword16_noerr(&rw->rwlock_type, type);

	/* We can only continue for simple USYNC_PROCESS locks. */
	if (type != USYNC_PROCESS) {
		error = EINVAL;
		goto out_nodrop;
	}

	/* Convert user level rwlock, "rw", to a unique lwpchan. */
	if (!get_lwpchan(p->p_as, (caddr_t)rw, type,
	    &lwpchan, LWPCHAN_CVPOOL)) {
		error = EFAULT;
		goto out_nodrop;
	}

	no_lwpchan = 0;
	watched = watch_disable_addr((caddr_t)rw, sizeof (*rw), S_WRITE);

	lwpchan_lock(&lwpchan, LWPCHAN_CVPOOL);
	locked = 1;

	/*
	 * We can resolve multiple readers (except the last reader) here.
	 * For the last reader or a writer we need lwp_rwlock_release(),
	 * to which we also delegate the task of copying the new rwstate
	 * back to userland (see the comment there).
	 */
	fuword32_noerr(&rw->rwlock_readers, &rwstate);
	if (rwstate & URW_WRITE_LOCKED)
		lwp_rwlock_release(&lwpchan, rw);
	else if ((rwstate & URW_READERS_MASK) > 0) {
		rwstate--;
		if ((rwstate & URW_READERS_MASK) == 0)
			lwp_rwlock_release(&lwpchan, rw);
		else
			suword32_noerr(&rw->rwlock_readers, rwstate);
	}

	lwpchan_unlock(&lwpchan, LWPCHAN_CVPOOL);
	locked = 0;
	error = 0;

out_nodrop:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)rw, sizeof (*rw), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}

int
lwp_rwlock_sys(int subcode, lwp_rwlock_t *rwlp, timespec_t *tsp)
{
	switch (subcode) {
	case 0:
		return (lwp_rwlock_lock(rwlp, tsp, READ_LOCK));
	case 1:
		return (lwp_rwlock_lock(rwlp, tsp, WRITE_LOCK));
	case 2:
		return (lwp_rwlock_lock(rwlp, NULL, READ_LOCK_TRY));
	case 3:
		return (lwp_rwlock_lock(rwlp, NULL, WRITE_LOCK_TRY));
	case 4:
		return (lwp_rwlock_unlock(rwlp));
	}
	return (set_errno(EINVAL));
}

/*
 * Return the owner of the user-level s-object.
 * Since we can't really do this, return NULL.
 */
/* ARGSUSED */
static kthread_t *
lwpsobj_owner(caddr_t sobj)
{
	return ((kthread_t *)NULL);
}

/*
 * Wake up a thread asleep on a user-level synchronization
 * object.
 */
static void
lwp_unsleep(kthread_t *t)
{
	ASSERT(THREAD_LOCK_HELD(t));
	if (t->t_wchan0 != NULL) {
		sleepq_head_t *sqh;
		sleepq_t *sqp = t->t_sleepq;

		if (sqp != NULL) {
			sqh = lwpsqhash(&t->t_lwpchan);
			ASSERT(&sqh->sq_queue == sqp);
			sleepq_unsleep(t);
			disp_lock_exit_high(&sqh->sq_lock);
			CL_SETRUN(t);
			return;
		}
	}
	panic("lwp_unsleep: thread %p not on sleepq", (void *)t);
}

/*
 * Change the priority of a thread asleep on a user-level
 * synchronization object. To maintain proper priority order,
 * we:
 *	o dequeue the thread.
 *	o change its priority.
 *	o re-enqueue the thread.
 * Assumption: the thread is locked on entry.
 */
static void
lwp_change_pri(kthread_t *t, pri_t pri, pri_t *t_prip)
{
	ASSERT(THREAD_LOCK_HELD(t));
	if (t->t_wchan0 != NULL) {
		sleepq_t   *sqp = t->t_sleepq;

		sleepq_dequeue(t);
		*t_prip = pri;
		sleepq_insert(sqp, t);
	} else
		panic("lwp_change_pri: %p not on a sleep queue", (void *)t);
}

/*
 * Clean up a left-over process-shared robust mutex
 */
static void
lwp_mutex_cleanup(lwpchan_entry_t *ent, uint16_t lockflg)
{
	uint16_t flag;
	uchar_t waiters;
	label_t ljb;
	pid_t owner_pid;
	lwp_mutex_t *lp;
	volatile int locked = 0;
	volatile int watched = 0;
	volatile struct upimutex *upimutex = NULL;
	volatile int upilocked = 0;

	if ((ent->lwpchan_type & (USYNC_PROCESS | LOCK_ROBUST))
	    != (USYNC_PROCESS | LOCK_ROBUST))
		return;

	lp = (lwp_mutex_t *)ent->lwpchan_addr;
	watched = watch_disable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);
	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&ent->lwpchan_lwpchan, LWPCHAN_MPPOOL);
		if (upilocked)
			upimutex_unlock((upimutex_t *)upimutex, 0);
		goto out;
	}

	fuword32_noerr(&lp->mutex_ownerpid, (uint32_t *)&owner_pid);

	if (UPIMUTEX(ent->lwpchan_type)) {
		lwpchan_t lwpchan = ent->lwpchan_lwpchan;
		upib_t *upibp = &UPI_CHAIN(lwpchan);

		if (owner_pid != curproc->p_pid)
			goto out;
		mutex_enter(&upibp->upib_lock);
		upimutex = upi_get(upibp, &lwpchan);
		if (upimutex == NULL || upimutex->upi_owner != curthread) {
			mutex_exit(&upibp->upib_lock);
			goto out;
		}
		mutex_exit(&upibp->upib_lock);
		upilocked = 1;
		flag = lwp_clear_mutex(lp, lockflg);
		suword8_noerr(&lp->mutex_lockw, 0);
		upimutex_unlock((upimutex_t *)upimutex, flag);
	} else {
		lwpchan_lock(&ent->lwpchan_lwpchan, LWPCHAN_MPPOOL);
		locked = 1;
		/*
		 * Clear the spinners count because one of our
		 * threads could have been spinning for this lock
		 * at user level when the process was suddenly killed.
		 * There is no harm in this since user-level libc code
		 * will adapt to the sudden change in the spinner count.
		 */
		suword8_noerr(&lp->mutex_spinners, 0);
		if (owner_pid != curproc->p_pid) {
			/*
			 * We are not the owner.  There may or may not be one.
			 * If there are waiters, we wake up one or all of them.
			 * It doesn't hurt to wake them up in error since
			 * they will just retry the lock and go to sleep
			 * again if necessary.
			 */
			fuword8_noerr(&lp->mutex_waiters, &waiters);
			if (waiters != 0) {	/* there are waiters */
				fuword16_noerr(&lp->mutex_flag, &flag);
				if (flag & LOCK_NOTRECOVERABLE) {
					lwp_release_all(&ent->lwpchan_lwpchan);
					suword8_noerr(&lp->mutex_waiters, 0);
				} else if (lwp_release(&ent->lwpchan_lwpchan,
				    &waiters, 0)) {
					suword8_noerr(&lp->mutex_waiters,
					    waiters);
				}
			}
		} else {
			/*
			 * We are the owner.  Release it.
			 */
			(void) lwp_clear_mutex(lp, lockflg);
			ulock_clear(&lp->mutex_lockw);
			fuword8_noerr(&lp->mutex_waiters, &waiters);
			if (waiters &&
			    lwp_release(&ent->lwpchan_lwpchan, &waiters, 0))
				suword8_noerr(&lp->mutex_waiters, waiters);
		}
		lwpchan_unlock(&ent->lwpchan_lwpchan, LWPCHAN_MPPOOL);
	}
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);
}

/*
 * Register a process-shared robust mutex in the lwpchan cache.
 */
int
lwp_mutex_register(lwp_mutex_t *lp, caddr_t uaddr)
{
	int error = 0;
	volatile int watched;
	label_t ljb;
	uint8_t type;
	lwpchan_t lwpchan;

	if ((caddr_t)lp >= (caddr_t)USERLIMIT)
		return (set_errno(EFAULT));

	watched = watch_disable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);

	if (on_fault(&ljb)) {
		error = EFAULT;
	} else {
		/*
		 * Force Copy-on-write if necessary and ensure that the
		 * synchronization object resides in read/write memory.
		 * Cause an EFAULT return now if this is not so.
		 */
		fuword8_noerr(&lp->mutex_type, &type);
		suword8_noerr(&lp->mutex_type, type);
		if ((type & (USYNC_PROCESS|LOCK_ROBUST))
		    != (USYNC_PROCESS|LOCK_ROBUST)) {
			error = EINVAL;
		} else if (!lwpchan_get_mapping(curproc->p_as, (caddr_t)lp,
		    uaddr, type, &lwpchan, LWPCHAN_MPPOOL)) {
			error = EFAULT;
		}
	}
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * There is a user-level robust lock registration in libc.
 * Mark it as invalid by storing -1 into the location of the pointer.
 */
static void
lwp_mutex_unregister(void *uaddr)
{
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		(void) sulword(uaddr, (ulong_t)-1);
#ifdef _SYSCALL32_IMPL
	} else {
		(void) suword32(uaddr, (uint32_t)-1);
#endif
	}
}

int
lwp_mutex_trylock(lwp_mutex_t *lp, uintptr_t owner)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	int error = 0;
	volatile int locked = 0;
	volatile int watched = 0;
	label_t ljb;
	volatile uint8_t type = 0;
	uint16_t flag;
	lwpchan_t lwpchan;

	if ((caddr_t)lp >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	(void) new_mstate(t, LMS_USER_LOCK);

	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
		error = EFAULT;
		goto out;
	}
	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword8_noerr(&lp->mutex_type, (uint8_t *)&type);
	suword8_noerr(&lp->mutex_type, type);
	if (UPIMUTEX(type)) {
		no_fault();
		error = lwp_upimutex_lock(lp, type, UPIMUTEX_TRY, NULL);
		if (error == 0 || error == EOWNERDEAD || error == ELOCKUNMAPPED)
			set_owner_pid(lp, owner,
			    (type & USYNC_PROCESS)? p->p_pid : 0);
		if (error)
			return (set_errno(error));
		return (0);
	}
	if (!get_lwpchan(curproc->p_as, (caddr_t)lp, type,
	    &lwpchan, LWPCHAN_MPPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_MPPOOL);
	locked = 1;
	if (type & LOCK_ROBUST) {
		fuword16_noerr(&lp->mutex_flag, &flag);
		if (flag & LOCK_NOTRECOVERABLE) {
			lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
			error =  ENOTRECOVERABLE;
			goto out;
		}
	}

	watched = watch_disable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);

	if (!ulock_try(&lp->mutex_lockw))
		error = EBUSY;
	else {
		set_owner_pid(lp, owner, (type & USYNC_PROCESS)? p->p_pid : 0);
		if (type & LOCK_ROBUST) {
			fuword16_noerr(&lp->mutex_flag, &flag);
			if (flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED)) {
				if (flag & LOCK_OWNERDEAD)
					error = EOWNERDEAD;
				else if (type & USYNC_PROCESS_ROBUST)
					error = ELOCKUNMAPPED;
				else
					error = EOWNERDEAD;
			}
		}
	}
	locked = 0;
	lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
out:

	if (t->t_mstate == LMS_USER_LOCK)
		(void) new_mstate(t, LMS_SYSTEM);

	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}

/*
 * unlock the mutex and unblock lwps that is trying to acquire this mutex.
 * the blocked lwp resumes and retries to acquire the lock.
 */
int
lwp_mutex_unlock(lwp_mutex_t *lp)
{
	proc_t *p = ttoproc(curthread);
	lwpchan_t lwpchan;
	uchar_t waiters;
	volatile int locked = 0;
	volatile int watched = 0;
	volatile uint8_t type = 0;
	label_t ljb;
	uint16_t flag;
	int error = 0;

	if ((caddr_t)lp >= p->p_as->a_userlimit)
		return (set_errno(EFAULT));

	if (on_fault(&ljb)) {
		if (locked)
			lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
		error = EFAULT;
		goto out;
	}

	/*
	 * Force Copy-on-write if necessary and ensure that the
	 * synchronization object resides in read/write memory.
	 * Cause an EFAULT return now if this is not so.
	 */
	fuword8_noerr(&lp->mutex_type, (uint8_t *)&type);
	suword8_noerr(&lp->mutex_type, type);

	if (UPIMUTEX(type)) {
		no_fault();
		error = lwp_upimutex_unlock(lp, type);
		if (error)
			return (set_errno(error));
		return (0);
	}

	watched = watch_disable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);

	if (!get_lwpchan(curproc->p_as, (caddr_t)lp, type,
	    &lwpchan, LWPCHAN_MPPOOL)) {
		error = EFAULT;
		goto out;
	}
	lwpchan_lock(&lwpchan, LWPCHAN_MPPOOL);
	locked = 1;
	if (type & LOCK_ROBUST) {
		fuword16_noerr(&lp->mutex_flag, &flag);
		if (flag & (LOCK_OWNERDEAD | LOCK_UNMAPPED)) {
			flag &= ~(LOCK_OWNERDEAD | LOCK_UNMAPPED);
			flag |= LOCK_NOTRECOVERABLE;
			suword16_noerr(&lp->mutex_flag, flag);
		}
	}
	set_owner_pid(lp, 0, 0);
	ulock_clear(&lp->mutex_lockw);
	/*
	 * Always wake up an lwp (if any) waiting on lwpchan. The woken lwp will
	 * re-try the lock in lwp_mutex_timedlock(). The call to lwp_release()
	 * may fail.  If it fails, do not write into the waiter bit.
	 * The call to lwp_release() might fail due to one of three reasons:
	 *
	 * 	1. due to the thread which set the waiter bit not actually
	 *	   sleeping since it got the lock on the re-try. The waiter
	 *	   bit will then be correctly updated by that thread. This
	 *	   window may be closed by reading the wait bit again here
	 *	   and not calling lwp_release() at all if it is zero.
	 *	2. the thread which set the waiter bit and went to sleep
	 *	   was woken up by a signal. This time, the waiter recomputes
	 *	   the wait bit in the return with EINTR code.
	 *	3. the waiter bit read by lwp_mutex_wakeup() was in
	 *	   memory that has been re-used after the lock was dropped.
	 *	   In this case, writing into the waiter bit would cause data
	 *	   corruption.
	 */
	fuword8_noerr(&lp->mutex_waiters, &waiters);
	if (waiters) {
		if ((type & LOCK_ROBUST) &&
		    (flag & LOCK_NOTRECOVERABLE)) {
			lwp_release_all(&lwpchan);
			suword8_noerr(&lp->mutex_waiters, 0);
		} else if (lwp_release(&lwpchan, &waiters, 0)) {
			suword8_noerr(&lp->mutex_waiters, waiters);
		}
	}

	lwpchan_unlock(&lwpchan, LWPCHAN_MPPOOL);
out:
	no_fault();
	if (watched)
		watch_enable_addr((caddr_t)lp, sizeof (*lp), S_WRITE);
	if (error)
		return (set_errno(error));
	return (0);
}
