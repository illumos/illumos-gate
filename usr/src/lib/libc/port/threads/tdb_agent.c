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

/*
 * This file contains most of the functionality
 * required to support the threads portion of libc_db.
 */

#include "lint.h"
#include "thr_uberdata.h"

static void
tdb_event_ready(void) {}

static void
tdb_event_sleep(void) {}

static void
tdb_event_switchto(void) {}

static void
tdb_event_switchfrom(void) {}

static void
tdb_event_lock_try(void) {}

static void
tdb_event_catchsig(void) {}

static void
tdb_event_idle(void) {}

static void
tdb_event_create(void) {}

static void
tdb_event_death(void) {}

static void
tdb_event_preempt(void) {}

static void
tdb_event_pri_inherit(void) {}

static void
tdb_event_reap(void) {}

static void
tdb_event_concurrency(void) {}

static void
tdb_event_timeout(void) {}

/*
 * uberflags.uf_tdb_register_sync is set to REGISTER_SYNC_ENABLE by a debugger
 * to empty the table and then enable synchronization object registration.
 *
 * uberflags.uf_tdb_register_sync is set to REGISTER_SYNC_DISABLE by a debugger
 * to empty the table and then disable synchronization object registration.
 */

const tdb_ev_func_t tdb_events[TD_MAX_EVENT_NUM - TD_MIN_EVENT_NUM + 1] = {
	tdb_event_ready,
	tdb_event_sleep,
	tdb_event_switchto,
	tdb_event_switchfrom,
	tdb_event_lock_try,
	tdb_event_catchsig,
	tdb_event_idle,
	tdb_event_create,
	tdb_event_death,
	tdb_event_preempt,
	tdb_event_pri_inherit,
	tdb_event_reap,
	tdb_event_concurrency,
	tdb_event_timeout
};

#if TDB_HASH_SHIFT != 15
#error "this is all broken because TDB_HASH_SHIFT is not 15"
#endif

static uint_t
tdb_addr_hash(void *addr)
{
	/*
	 * This knows for a fact that the hash table has
	 * 32K entries; that is, that TDB_HASH_SHIFT is 15.
	 */
#ifdef	_LP64
	uint64_t value60 = ((uintptr_t)addr >> 4);	/* 60 bits */
	uint32_t value30 = (value60 >> 30) ^ (value60 & 0x3fffffff);
#else
	uint32_t value30 = ((uintptr_t)addr >> 2);	/* 30 bits */
#endif
	return ((value30 >> 15) ^ (value30 & 0x7fff));
}

static tdb_sync_stats_t *
alloc_sync_addr(void *addr)
{
	uberdata_t *udp = curthread->ul_uberdata;
	tdb_t *tdbp = &udp->tdb;
	tdb_sync_stats_t *sap;

	ASSERT(MUTEX_OWNED(&udp->tdb_hash_lock, curthread));

	if ((sap = tdbp->tdb_sync_addr_free) == NULL) {
		void *vaddr;
		int i;

		/*
		 * Don't keep trying after mmap() has already failed.
		 */
		if (tdbp->tdb_hash_alloc_failed)
			return (NULL);

		/* double the allocation each time */
		tdbp->tdb_sync_alloc *= 2;
		if ((vaddr = mmap(NULL,
		    tdbp->tdb_sync_alloc * sizeof (tdb_sync_stats_t),
		    PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON,
		    -1, (off_t)0)) == MAP_FAILED) {
			tdbp->tdb_hash_alloc_failed = 1;
			return (NULL);
		}
		sap = tdbp->tdb_sync_addr_free = vaddr;
		for (i = 1; i < tdbp->tdb_sync_alloc; sap++, i++)
			sap->next = (uintptr_t)(sap + 1);
		sap->next = (uintptr_t)0;
		tdbp->tdb_sync_addr_last = sap;

		sap = tdbp->tdb_sync_addr_free;
	}

	tdbp->tdb_sync_addr_free = (tdb_sync_stats_t *)(uintptr_t)sap->next;
	sap->next = (uintptr_t)0;
	sap->sync_addr = (uintptr_t)addr;
	(void) memset(&sap->un, 0, sizeof (sap->un));
	return (sap);
}

static void
initialize_sync_hash()
{
	uberdata_t *udp = curthread->ul_uberdata;
	tdb_t *tdbp = &udp->tdb;
	uint64_t *addr_hash;
	tdb_sync_stats_t *sap;
	void *vaddr;
	int i;

	if (tdbp->tdb_hash_alloc_failed)
		return;
	lmutex_lock(&udp->tdb_hash_lock);
	if (udp->uberflags.uf_tdb_register_sync == REGISTER_SYNC_DISABLE) {
		/*
		 * There is no point allocating the hash table
		 * if we are disabling registration.
		 */
		udp->uberflags.uf_tdb_register_sync = REGISTER_SYNC_OFF;
		lmutex_unlock(&udp->tdb_hash_lock);
		return;
	}
	if (tdbp->tdb_sync_addr_hash != NULL || tdbp->tdb_hash_alloc_failed) {
		lmutex_unlock(&udp->tdb_hash_lock);
		return;
	}
	/* start with a free list of 2k elements */
	tdbp->tdb_sync_alloc = 2*1024;
	if ((vaddr = mmap(NULL, TDB_HASH_SIZE * sizeof (uint64_t) +
	    tdbp->tdb_sync_alloc * sizeof (tdb_sync_stats_t),
	    PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON,
	    -1, (off_t)0)) == MAP_FAILED) {
		tdbp->tdb_hash_alloc_failed = 1;
		return;
	}
	addr_hash = vaddr;

	/* initialize the free list */
	tdbp->tdb_sync_addr_free = sap =
	    (tdb_sync_stats_t *)&addr_hash[TDB_HASH_SIZE];
	for (i = 1; i < tdbp->tdb_sync_alloc; sap++, i++)
		sap->next = (uintptr_t)(sap + 1);
	sap->next = (uintptr_t)0;
	tdbp->tdb_sync_addr_last = sap;

	/* insert &udp->tdb_hash_lock itself into the new (empty) table */
	udp->tdb_hash_lock_stats.next = (uintptr_t)0;
	udp->tdb_hash_lock_stats.sync_addr = (uintptr_t)&udp->tdb_hash_lock;
	addr_hash[tdb_addr_hash(&udp->tdb_hash_lock)] =
	    (uintptr_t)&udp->tdb_hash_lock_stats;

	tdbp->tdb_register_count = 1;
	/* assign to tdb_sync_addr_hash only after fully initialized */
	membar_producer();
	tdbp->tdb_sync_addr_hash = addr_hash;
	lmutex_unlock(&udp->tdb_hash_lock);
}

tdb_sync_stats_t *
tdb_sync_obj_register(void *addr, int *new)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	tdb_t *tdbp = &udp->tdb;
	uint64_t *sapp;
	tdb_sync_stats_t *sap = NULL;
	int locked = 0;
	int i;

	/*
	 * Don't start statistics collection until
	 * we have initialized the primary link map.
	 */
	if (!self->ul_primarymap)
		return (NULL);

	if (new)
		*new = 0;
	/*
	 * To avoid recursion problems, we must do two things:
	 * 1. Make a special case for tdb_hash_lock (we use it internally).
	 * 2. Deal with the dynamic linker's lock interface:
	 *    When calling any external function, we may invoke the
	 *    dynamic linker.  It grabs a lock, which calls back here.
	 *    This only happens on the first call to the external
	 *    function, so we can just return NULL if we are called
	 *    recursively (and miss the first count).
	 */
	if (addr == (void *)&udp->tdb_hash_lock)
		return (&udp->tdb_hash_lock_stats);
	if (self->ul_sync_obj_reg)		/* recursive call */
		return (NULL);
	self->ul_sync_obj_reg = 1;

	/*
	 * On the first time through, initialize the hash table and free list.
	 */
	if (tdbp->tdb_sync_addr_hash == NULL) {
		initialize_sync_hash();
		if (tdbp->tdb_sync_addr_hash == NULL) {	/* utter failure */
			udp->uberflags.uf_tdb_register_sync = REGISTER_SYNC_OFF;
			goto out;
		}
	}
	membar_consumer();

	sapp = &tdbp->tdb_sync_addr_hash[tdb_addr_hash(addr)];
	if (udp->uberflags.uf_tdb_register_sync == REGISTER_SYNC_ON) {
		/*
		 * Look up an address in the synchronization object hash table.
		 * No lock is required since it can only deliver a false
		 * negative, in which case we fall into the locked case below.
		 */
		for (sap = (tdb_sync_stats_t *)(uintptr_t)*sapp; sap != NULL;
		    sap = (tdb_sync_stats_t *)(uintptr_t)sap->next) {
			if (sap->sync_addr == (uintptr_t)addr)
				goto out;
		}
	}

	/*
	 * The search with no lock held failed or a special action is required.
	 * Grab tdb_hash_lock to do special actions and/or get a precise result.
	 */
	lmutex_lock(&udp->tdb_hash_lock);
	locked = 1;

	switch (udp->uberflags.uf_tdb_register_sync) {
	case REGISTER_SYNC_ON:
		break;
	case REGISTER_SYNC_OFF:
		goto out;
	default:
		/*
		 * For all debugger actions, first zero out the
		 * statistics block of every element in the hash table.
		 */
		for (i = 0; i < TDB_HASH_SIZE; i++)
			for (sap = (tdb_sync_stats_t *)
			    (uintptr_t)tdbp->tdb_sync_addr_hash[i];
			    sap != NULL;
			    sap = (tdb_sync_stats_t *)(uintptr_t)sap->next)
				(void) memset(&sap->un, 0, sizeof (sap->un));

		switch (udp->uberflags.uf_tdb_register_sync) {
		case REGISTER_SYNC_ENABLE:
			udp->uberflags.uf_tdb_register_sync = REGISTER_SYNC_ON;
			break;
		case REGISTER_SYNC_DISABLE:
		default:
			udp->uberflags.uf_tdb_register_sync = REGISTER_SYNC_OFF;
			goto out;
		}
		break;
	}

	/*
	 * Perform the search while holding tdb_hash_lock.
	 * Keep track of the insertion point.
	 */
	while ((sap = (tdb_sync_stats_t *)(uintptr_t)*sapp) != NULL) {
		if (sap->sync_addr == (uintptr_t)addr)
			break;
		sapp = &sap->next;
	}

	/*
	 * Insert a new element if necessary.
	 */
	if (sap == NULL && (sap = alloc_sync_addr(addr)) != NULL) {
		*sapp = (uintptr_t)sap;
		tdbp->tdb_register_count++;
		if (new)
			*new = 1;
	}

out:
	if (locked)
		lmutex_unlock(&udp->tdb_hash_lock);
	self->ul_sync_obj_reg = 0;
	return (sap);
}

void
tdb_sync_obj_deregister(void *addr)
{
	uberdata_t *udp = curthread->ul_uberdata;
	tdb_t *tdbp = &udp->tdb;
	uint64_t *sapp;
	tdb_sync_stats_t *sap;
	uint_t hash;

	/*
	 * tdb_hash_lock is never destroyed.
	 */
	ASSERT(addr != &udp->tdb_hash_lock);

	/*
	 * Avoid acquiring tdb_hash_lock if lock statistics gathering has
	 * never been initiated or there is nothing in the hash bucket.
	 * (Once the hash table is allocated, it is never deallocated.)
	 */
	if (tdbp->tdb_sync_addr_hash == NULL ||
	    tdbp->tdb_sync_addr_hash[hash = tdb_addr_hash(addr)] == 0)
		return;

	lmutex_lock(&udp->tdb_hash_lock);
	sapp = &tdbp->tdb_sync_addr_hash[hash];
	while ((sap = (tdb_sync_stats_t *)(uintptr_t)*sapp) != NULL) {
		if (sap->sync_addr == (uintptr_t)addr) {
			/* remove it from the hash table */
			*sapp = sap->next;
			tdbp->tdb_register_count--;
			/* clear it */
			sap->next = (uintptr_t)0;
			sap->sync_addr = (uintptr_t)0;
			/* insert it on the tail of the free list */
			if (tdbp->tdb_sync_addr_free == NULL) {
				tdbp->tdb_sync_addr_free = sap;
				tdbp->tdb_sync_addr_last = sap;
			} else {
				tdbp->tdb_sync_addr_last->next = (uintptr_t)sap;
				tdbp->tdb_sync_addr_last = sap;
			}
			break;
		}
		sapp = &sap->next;
	}
	lmutex_unlock(&udp->tdb_hash_lock);
}

/*
 * Return a mutex statistics block for the given mutex.
 */
tdb_mutex_stats_t *
tdb_mutex_stats(mutex_t *mp)
{
	tdb_sync_stats_t *tssp;

	/* avoid stealing the cache line unnecessarily */
	if (mp->mutex_magic != MUTEX_MAGIC)
		mp->mutex_magic = MUTEX_MAGIC;
	if ((tssp = tdb_sync_obj_register(mp, NULL)) == NULL)
		return (NULL);
	tssp->un.type = TDB_MUTEX;
	return (&tssp->un.mutex);
}

/*
 * Return a condvar statistics block for the given condvar.
 */
tdb_cond_stats_t *
tdb_cond_stats(cond_t *cvp)
{
	tdb_sync_stats_t *tssp;

	/* avoid stealing the cache line unnecessarily */
	if (cvp->cond_magic != COND_MAGIC)
		cvp->cond_magic = COND_MAGIC;
	if ((tssp = tdb_sync_obj_register(cvp, NULL)) == NULL)
		return (NULL);
	tssp->un.type = TDB_COND;
	return (&tssp->un.cond);
}

/*
 * Return an rwlock statistics block for the given rwlock.
 */
tdb_rwlock_stats_t *
tdb_rwlock_stats(rwlock_t *rwlp)
{
	tdb_sync_stats_t *tssp;

	/* avoid stealing the cache line unnecessarily */
	if (rwlp->magic != RWL_MAGIC)
		rwlp->magic = RWL_MAGIC;
	if ((tssp = tdb_sync_obj_register(rwlp, NULL)) == NULL)
		return (NULL);
	tssp->un.type = TDB_RWLOCK;
	return (&tssp->un.rwlock);
}

/*
 * Return a semaphore statistics block for the given semaphore.
 */
tdb_sema_stats_t *
tdb_sema_stats(sema_t *sp)
{
	tdb_sync_stats_t *tssp;
	int new;

	/* avoid stealing the cache line unnecessarily */
	if (sp->magic != SEMA_MAGIC)
		sp->magic = SEMA_MAGIC;
	if ((tssp = tdb_sync_obj_register(sp, &new)) == NULL)
		return (NULL);
	tssp->un.type = TDB_SEMA;
	if (new) {
		tssp->un.sema.sema_max_count = sp->count;
		tssp->un.sema.sema_min_count = sp->count;
	}
	return (&tssp->un.sema);
}
