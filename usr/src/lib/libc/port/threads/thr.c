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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 * Copyright (c) 2017 by The MathWorks, Inc. All rights reserved.
 */
/*
 * Copyright 2016 Joyent, Inc.
 */

#include "lint.h"
#include "thr_uberdata.h"
#include <pthread.h>
#include <procfs.h>
#include <sys/uio.h>
#include <ctype.h>
#include "libc.h"

/*
 * These symbols should not be exported from libc, but
 * /lib/libm.so.2 references _thr_main.  libm needs to be fixed.
 * Also, some older versions of the Studio compiler/debugger
 * components reference them.  These need to be fixed, too.
 */
#pragma weak _thr_main = thr_main
#pragma weak _thr_create = thr_create
#pragma weak _thr_join = thr_join
#pragma weak _thr_self = thr_self

#undef errno
extern int errno;

/*
 * Between Solaris 2.5 and Solaris 9, __threaded was used to indicate
 * "we are linked with libthread".  The Sun Workshop 6 update 1 compilation
 * system used it illegally (it is a consolidation private symbol).
 * To accommodate this and possibly other abusers of the symbol,
 * we make it always equal to 1 now that libthread has been folded
 * into libc.  The new __libc_threaded symbol is used to indicate
 * the new meaning, "more than one thread exists".
 */
int __threaded = 1;		/* always equal to 1 */
int __libc_threaded = 0;	/* zero until first thr_create() */

/*
 * thr_concurrency and pthread_concurrency are not used by the library.
 * They exist solely to hold and return the values set by calls to
 * thr_setconcurrency() and pthread_setconcurrency().
 * Because thr_concurrency is affected by the THR_NEW_LWP flag
 * to thr_create(), thr_concurrency is protected by link_lock.
 */
static	int	thr_concurrency = 1;
static	int	pthread_concurrency;

#define	HASHTBLSZ	1024	/* must be a power of two */
#define	TIDHASH(tid, udp)	(tid & (udp)->hash_mask)

/* initial allocation, just enough for one lwp */
#pragma align 64(init_hash_table)
thr_hash_table_t init_hash_table[1] = {
	{ DEFAULTMUTEX, DEFAULTCV, NULL },
};

extern const Lc_interface rtld_funcs[];

/*
 * The weak version is known to libc_db and mdb.
 */
#pragma weak _uberdata = __uberdata
uberdata_t __uberdata = {
	{ DEFAULTMUTEX, NULL, 0 },	/* link_lock */
	{ RECURSIVEMUTEX, NULL, 0 },	/* ld_lock */
	{ RECURSIVEMUTEX, NULL, 0 },	/* fork_lock */
	{ RECURSIVEMUTEX, NULL, 0 },	/* atfork_lock */
	{ RECURSIVEMUTEX, NULL, 0 },	/* callout_lock */
	{ DEFAULTMUTEX, NULL, 0 },	/* tdb_hash_lock */
	{ 0, },				/* tdb_hash_lock_stats */
	{ { 0 }, },			/* siguaction[NSIG] */
	{{ DEFAULTMUTEX, NULL, 0 },		/* bucket[NBUCKETS] */
	{ DEFAULTMUTEX, NULL, 0 },
	{ DEFAULTMUTEX, NULL, 0 },
	{ DEFAULTMUTEX, NULL, 0 },
	{ DEFAULTMUTEX, NULL, 0 },
	{ DEFAULTMUTEX, NULL, 0 },
	{ DEFAULTMUTEX, NULL, 0 },
	{ DEFAULTMUTEX, NULL, 0 },
	{ DEFAULTMUTEX, NULL, 0 },
	{ DEFAULTMUTEX, NULL, 0 }},
	{ RECURSIVEMUTEX, NULL, NULL },		/* atexit_root */
	{ RECURSIVEMUTEX, NULL },		/* quickexit_root */
	{ DEFAULTMUTEX, 0, 0, NULL },		/* tsd_metadata */
	{ DEFAULTMUTEX, {0, 0}, {0, 0} },	/* tls_metadata */
	0,			/* primary_map */
	0,			/* bucket_init */
	0,			/* pad[0] */
	0,			/* pad[1] */
	{ 0 },			/* uberflags */
	NULL,			/* queue_head */
	init_hash_table,	/* thr_hash_table */
	1,			/* hash_size: size of the hash table */
	0,			/* hash_mask: hash_size - 1 */
	NULL,			/* ulwp_one */
	NULL,			/* all_lwps */
	NULL,			/* all_zombies */
	0,			/* nthreads */
	0,			/* nzombies */
	0,			/* ndaemons */
	0,			/* pid */
	sigacthandler,		/* sigacthandler */
	NULL,			/* lwp_stacks */
	NULL,			/* lwp_laststack */
	0,			/* nfreestack */
	10,			/* thread_stack_cache */
	NULL,			/* ulwp_freelist */
	NULL,			/* ulwp_lastfree */
	NULL,			/* ulwp_replace_free */
	NULL,			/* ulwp_replace_last */
	NULL,			/* atforklist */
	NULL,			/* robustlocks */
	NULL,			/* robustlist */
	NULL,			/* progname */
	NULL,			/* ub_comm_page */
	NULL,			/* __tdb_bootstrap */
	{			/* tdb */
		NULL,		/* tdb_sync_addr_hash */
		0,		/* tdb_register_count */
		0,		/* tdb_hash_alloc_failed */
		NULL,		/* tdb_sync_addr_free */
		NULL,		/* tdb_sync_addr_last */
		0,		/* tdb_sync_alloc */
		{ 0, 0 },	/* tdb_ev_global_mask */
		tdb_events,	/* tdb_events array */
	},
};

/*
 * The weak version is known to libc_db and mdb.
 */
#pragma weak _tdb_bootstrap = __tdb_bootstrap
uberdata_t **__tdb_bootstrap = NULL;

int	thread_queue_fifo = 4;
int	thread_queue_dump = 0;
int	thread_cond_wait_defer = 0;
int	thread_error_detection = 0;
int	thread_async_safe = 0;
int	thread_stack_cache = 10;
int	thread_door_noreserve = 0;
int	thread_locks_misaligned = 0;

static	ulwp_t	*ulwp_alloc(void);
static	void	ulwp_free(ulwp_t *);

/*
 * Insert the lwp into the hash table.
 */
void
hash_in_unlocked(ulwp_t *ulwp, int ix, uberdata_t *udp)
{
	ulwp->ul_hash = udp->thr_hash_table[ix].hash_bucket;
	udp->thr_hash_table[ix].hash_bucket = ulwp;
	ulwp->ul_ix = ix;
}

void
hash_in(ulwp_t *ulwp, uberdata_t *udp)
{
	int ix = TIDHASH(ulwp->ul_lwpid, udp);
	mutex_t *mp = &udp->thr_hash_table[ix].hash_lock;

	lmutex_lock(mp);
	hash_in_unlocked(ulwp, ix, udp);
	lmutex_unlock(mp);
}

/*
 * Delete the lwp from the hash table.
 */
void
hash_out_unlocked(ulwp_t *ulwp, int ix, uberdata_t *udp)
{
	ulwp_t **ulwpp;

	for (ulwpp = &udp->thr_hash_table[ix].hash_bucket;
	    ulwp != *ulwpp;
	    ulwpp = &(*ulwpp)->ul_hash)
		;
	*ulwpp = ulwp->ul_hash;
	ulwp->ul_hash = NULL;
	ulwp->ul_ix = -1;
}

void
hash_out(ulwp_t *ulwp, uberdata_t *udp)
{
	int ix;

	if ((ix = ulwp->ul_ix) >= 0) {
		mutex_t *mp = &udp->thr_hash_table[ix].hash_lock;

		lmutex_lock(mp);
		hash_out_unlocked(ulwp, ix, udp);
		lmutex_unlock(mp);
	}
}

/*
 * Retain stack information for thread structures that are being recycled for
 * new threads.  All other members of the thread structure should be zeroed.
 */
static void
ulwp_clean(ulwp_t *ulwp)
{
	caddr_t stk = ulwp->ul_stk;
	size_t mapsiz = ulwp->ul_mapsiz;
	size_t guardsize = ulwp->ul_guardsize;
	uintptr_t stktop = ulwp->ul_stktop;
	size_t stksiz = ulwp->ul_stksiz;

	(void) memset(ulwp, 0, sizeof (*ulwp));

	ulwp->ul_stk = stk;
	ulwp->ul_mapsiz = mapsiz;
	ulwp->ul_guardsize = guardsize;
	ulwp->ul_stktop = stktop;
	ulwp->ul_stksiz = stksiz;
}

static int stackprot;

/*
 * Answer the question, "Is the lwp in question really dead?"
 * We must inquire of the operating system to be really sure
 * because the lwp may have called lwp_exit() but it has not
 * yet completed the exit.
 */
static int
dead_and_buried(ulwp_t *ulwp)
{
	if (ulwp->ul_lwpid == (lwpid_t)(-1))
		return (1);
	if (ulwp->ul_dead && ulwp->ul_detached &&
	    _lwp_kill(ulwp->ul_lwpid, 0) == ESRCH) {
		ulwp->ul_lwpid = (lwpid_t)(-1);
		return (1);
	}
	return (0);
}

/*
 * Attempt to keep the stack cache within the specified cache limit.
 */
static void
trim_stack_cache(int cache_limit)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *prev = NULL;
	ulwp_t **ulwpp = &udp->lwp_stacks;
	ulwp_t *ulwp;

	ASSERT(udp->nthreads <= 1 || MUTEX_OWNED(&udp->link_lock, self));

	while (udp->nfreestack > cache_limit && (ulwp = *ulwpp) != NULL) {
		if (dead_and_buried(ulwp)) {
			*ulwpp = ulwp->ul_next;
			if (ulwp == udp->lwp_laststack)
				udp->lwp_laststack = prev;
			hash_out(ulwp, udp);
			udp->nfreestack--;
			(void) munmap(ulwp->ul_stk, ulwp->ul_mapsiz);
			/*
			 * Now put the free ulwp on the ulwp freelist.
			 */
			ulwp->ul_mapsiz = 0;
			ulwp->ul_next = NULL;
			if (udp->ulwp_freelist == NULL)
				udp->ulwp_freelist = udp->ulwp_lastfree = ulwp;
			else {
				udp->ulwp_lastfree->ul_next = ulwp;
				udp->ulwp_lastfree = ulwp;
			}
		} else {
			prev = ulwp;
			ulwpp = &ulwp->ul_next;
		}
	}
}

/*
 * Find an unused stack of the requested size
 * or create a new stack of the requested size.
 * Return a pointer to the ulwp_t structure referring to the stack, or NULL.
 * thr_exit() stores 1 in the ul_dead member.
 * thr_join() stores -1 in the ul_lwpid member.
 */
static ulwp_t *
find_stack(size_t stksize, size_t guardsize)
{
	static size_t pagesize = 0;

	uberdata_t *udp = curthread->ul_uberdata;
	size_t mapsize;
	ulwp_t *prev;
	ulwp_t *ulwp;
	ulwp_t **ulwpp;
	void *stk;

	/*
	 * The stack is allocated PROT_READ|PROT_WRITE|PROT_EXEC
	 * unless overridden by the system's configuration.
	 */
	if (stackprot == 0) {	/* do this once */
		long lprot = _sysconf(_SC_STACK_PROT);
		if (lprot <= 0)
			lprot = (PROT_READ|PROT_WRITE|PROT_EXEC);
		stackprot = (int)lprot;
	}
	if (pagesize == 0)	/* do this once */
		pagesize = _sysconf(_SC_PAGESIZE);

	/*
	 * One megabyte stacks by default, but subtract off
	 * two pages for the system-created red zones.
	 * Round up a non-zero stack size to a pagesize multiple.
	 */
	if (stksize == 0)
		stksize = DEFAULTSTACK - 2 * pagesize;
	else
		stksize = ((stksize + pagesize - 1) & -pagesize);

	/*
	 * Round up the mapping size to a multiple of pagesize.
	 * Note: mmap() provides at least one page of red zone
	 * so we deduct that from the value of guardsize.
	 */
	if (guardsize != 0)
		guardsize = ((guardsize + pagesize - 1) & -pagesize) - pagesize;
	mapsize = stksize + guardsize;

	lmutex_lock(&udp->link_lock);
	for (prev = NULL, ulwpp = &udp->lwp_stacks;
	    (ulwp = *ulwpp) != NULL;
	    prev = ulwp, ulwpp = &ulwp->ul_next) {
		if (ulwp->ul_mapsiz == mapsize &&
		    ulwp->ul_guardsize == guardsize &&
		    dead_and_buried(ulwp)) {
			/*
			 * The previous lwp is gone; reuse the stack.
			 * Remove the ulwp from the stack list.
			 */
			*ulwpp = ulwp->ul_next;
			ulwp->ul_next = NULL;
			if (ulwp == udp->lwp_laststack)
				udp->lwp_laststack = prev;
			hash_out(ulwp, udp);
			udp->nfreestack--;
			lmutex_unlock(&udp->link_lock);
			ulwp_clean(ulwp);
			return (ulwp);
		}
	}

	/*
	 * None of the cached stacks matched our mapping size.
	 * Reduce the stack cache to get rid of possibly
	 * very old stacks that will never be reused.
	 */
	if (udp->nfreestack > udp->thread_stack_cache)
		trim_stack_cache(udp->thread_stack_cache);
	else if (udp->nfreestack > 0)
		trim_stack_cache(udp->nfreestack - 1);
	lmutex_unlock(&udp->link_lock);

	/*
	 * Create a new stack.
	 */
	if ((stk = mmap(NULL, mapsize, stackprot,
	    MAP_PRIVATE|MAP_NORESERVE|MAP_ANON, -1, (off_t)0)) != MAP_FAILED) {
		/*
		 * We have allocated our stack.  Now allocate the ulwp.
		 */
		ulwp = ulwp_alloc();
		if (ulwp == NULL)
			(void) munmap(stk, mapsize);
		else {
			ulwp->ul_stk = stk;
			ulwp->ul_mapsiz = mapsize;
			ulwp->ul_guardsize = guardsize;
			ulwp->ul_stktop = (uintptr_t)stk + mapsize;
			ulwp->ul_stksiz = stksize;
			if (guardsize)	/* protect the extra red zone */
				(void) mprotect(stk, guardsize, PROT_NONE);
		}
	}
	return (ulwp);
}

/*
 * Get a ulwp_t structure from the free list or allocate a new one.
 * Such ulwp_t's do not have a stack allocated by the library.
 */
static ulwp_t *
ulwp_alloc(void)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	size_t tls_size;
	ulwp_t *prev;
	ulwp_t *ulwp;
	ulwp_t **ulwpp;
	caddr_t data;

	lmutex_lock(&udp->link_lock);
	for (prev = NULL, ulwpp = &udp->ulwp_freelist;
	    (ulwp = *ulwpp) != NULL;
	    prev = ulwp, ulwpp = &ulwp->ul_next) {
		if (dead_and_buried(ulwp)) {
			*ulwpp = ulwp->ul_next;
			ulwp->ul_next = NULL;
			if (ulwp == udp->ulwp_lastfree)
				udp->ulwp_lastfree = prev;
			hash_out(ulwp, udp);
			lmutex_unlock(&udp->link_lock);
			ulwp_clean(ulwp);
			return (ulwp);
		}
	}
	lmutex_unlock(&udp->link_lock);

	tls_size = roundup64(udp->tls_metadata.static_tls.tls_size);
	data = lmalloc(sizeof (*ulwp) + tls_size);
	if (data != NULL) {
		/* LINTED pointer cast may result in improper alignment */
		ulwp = (ulwp_t *)(data + tls_size);
	}
	return (ulwp);
}

/*
 * Free a ulwp structure.
 * If there is an associated stack, put it on the stack list and
 * munmap() previously freed stacks up to the residual cache limit.
 * Else put it on the ulwp free list and never call lfree() on it.
 */
static void
ulwp_free(ulwp_t *ulwp)
{
	uberdata_t *udp = curthread->ul_uberdata;

	ASSERT(udp->nthreads <= 1 || MUTEX_OWNED(&udp->link_lock, curthread));
	ulwp->ul_next = NULL;
	if (ulwp == udp->ulwp_one)	/* don't reuse the primoridal stack */
		/*EMPTY*/;
	else if (ulwp->ul_mapsiz != 0) {
		if (udp->lwp_stacks == NULL)
			udp->lwp_stacks = udp->lwp_laststack = ulwp;
		else {
			udp->lwp_laststack->ul_next = ulwp;
			udp->lwp_laststack = ulwp;
		}
		if (++udp->nfreestack > udp->thread_stack_cache)
			trim_stack_cache(udp->thread_stack_cache);
	} else {
		if (udp->ulwp_freelist == NULL)
			udp->ulwp_freelist = udp->ulwp_lastfree = ulwp;
		else {
			udp->ulwp_lastfree->ul_next = ulwp;
			udp->ulwp_lastfree = ulwp;
		}
	}
}

/*
 * Find a named lwp and return a pointer to its hash list location.
 * On success, returns with the hash lock held.
 */
ulwp_t **
find_lwpp(thread_t tid)
{
	uberdata_t *udp = curthread->ul_uberdata;
	int ix = TIDHASH(tid, udp);
	mutex_t *mp = &udp->thr_hash_table[ix].hash_lock;
	ulwp_t *ulwp;
	ulwp_t **ulwpp;

	if (tid == 0)
		return (NULL);

	lmutex_lock(mp);
	for (ulwpp = &udp->thr_hash_table[ix].hash_bucket;
	    (ulwp = *ulwpp) != NULL;
	    ulwpp = &ulwp->ul_hash) {
		if (ulwp->ul_lwpid == tid)
			return (ulwpp);
	}
	lmutex_unlock(mp);
	return (NULL);
}

/*
 * Wake up all lwps waiting on this lwp for some reason.
 */
void
ulwp_broadcast(ulwp_t *ulwp)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;

	ASSERT(MUTEX_OWNED(ulwp_mutex(ulwp, udp), self));
	(void) cond_broadcast(ulwp_condvar(ulwp, udp));
}

/*
 * Find a named lwp and return a pointer to it.
 * Returns with the hash lock held.
 */
ulwp_t *
find_lwp(thread_t tid)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp = NULL;
	ulwp_t **ulwpp;

	if (self->ul_lwpid == tid) {
		ulwp = self;
		ulwp_lock(ulwp, udp);
	} else if ((ulwpp = find_lwpp(tid)) != NULL) {
		ulwp = *ulwpp;
	}

	if (ulwp && ulwp->ul_dead) {
		ulwp_unlock(ulwp, udp);
		ulwp = NULL;
	}

	return (ulwp);
}

int
_thrp_create(void *stk, size_t stksize, void *(*func)(void *), void *arg,
    long flags, thread_t *new_thread, size_t guardsize)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ucontext_t uc;
	uint_t lwp_flags;
	thread_t tid;
	int error;
	ulwp_t *ulwp;

	/*
	 * Enforce the restriction of not creating any threads
	 * until the primary link map has been initialized.
	 * Also, disallow thread creation to a child of vfork().
	 */
	if (!self->ul_primarymap || self->ul_vfork)
		return (ENOTSUP);

	if (udp->hash_size == 1)
		finish_init();

	if ((stk || stksize) && stksize < MINSTACK)
		return (EINVAL);

	if (stk == NULL) {
		if ((ulwp = find_stack(stksize, guardsize)) == NULL)
			return (ENOMEM);
		stksize = ulwp->ul_mapsiz - ulwp->ul_guardsize;
	} else {
		/* initialize the private stack */
		if ((ulwp = ulwp_alloc()) == NULL)
			return (ENOMEM);
		ulwp->ul_stk = stk;
		ulwp->ul_stktop = (uintptr_t)stk + stksize;
		ulwp->ul_stksiz = stksize;
	}
	/* ulwp is not in the hash table; make sure hash_out() doesn't fail */
	ulwp->ul_ix = -1;
	ulwp->ul_errnop = &ulwp->ul_errno;

	lwp_flags = LWP_SUSPENDED;
	if (flags & (THR_DETACHED|THR_DAEMON)) {
		flags |= THR_DETACHED;
		lwp_flags |= LWP_DETACHED;
	}
	if (flags & THR_DAEMON)
		lwp_flags |= LWP_DAEMON;

	/* creating a thread: enforce mt-correctness in mutex_lock() */
	self->ul_async_safe = 1;

	/* per-thread copies of global variables, for speed */
	ulwp->ul_queue_fifo = self->ul_queue_fifo;
	ulwp->ul_cond_wait_defer = self->ul_cond_wait_defer;
	ulwp->ul_error_detection = self->ul_error_detection;
	ulwp->ul_async_safe = self->ul_async_safe;
	ulwp->ul_max_spinners = self->ul_max_spinners;
	ulwp->ul_adaptive_spin = self->ul_adaptive_spin;
	ulwp->ul_queue_spin = self->ul_queue_spin;
	ulwp->ul_door_noreserve = self->ul_door_noreserve;
	ulwp->ul_misaligned = self->ul_misaligned;

	/* new thread inherits creating thread's scheduling parameters */
	ulwp->ul_policy = self->ul_policy;
	ulwp->ul_pri = (self->ul_epri? self->ul_epri : self->ul_pri);
	ulwp->ul_cid = self->ul_cid;
	ulwp->ul_rtclassid = self->ul_rtclassid;

	ulwp->ul_primarymap = self->ul_primarymap;
	ulwp->ul_self = ulwp;
	ulwp->ul_uberdata = udp;

	/* debugger support */
	ulwp->ul_usropts = flags;

#ifdef __sparc
	/*
	 * We cache several instructions in the thread structure for use
	 * by the fasttrap DTrace provider. When changing this, read the
	 * comment in fasttrap.h for the all the other places that must
	 * be changed.
	 */
	ulwp->ul_dsave = 0x9de04000;	/* save %g1, %g0, %sp */
	ulwp->ul_drestore = 0x81e80000;	/* restore %g0, %g0, %g0 */
	ulwp->ul_dftret = 0x91d0203a;	/* ta 0x3a */
	ulwp->ul_dreturn = 0x81ca0000;	/* return %o0 */
#endif

	ulwp->ul_startpc = func;
	ulwp->ul_startarg = arg;
	_fpinherit(ulwp);
	/*
	 * Defer signals on the new thread until its TLS constructors
	 * have been called.  _thrp_setup() will call sigon() after
	 * it has called tls_setup().
	 */
	ulwp->ul_sigdefer = 1;

	error = setup_context(&uc, _thrp_setup, ulwp,
	    (caddr_t)ulwp->ul_stk + ulwp->ul_guardsize, stksize);
	if (error != 0 && stk != NULL)	/* inaccessible stack */
		error = EFAULT;

	/*
	 * Call enter_critical() to avoid being suspended until we
	 * have linked the new thread into the proper lists.
	 * This is necessary because forkall() and fork1() must
	 * suspend all threads and they must see a complete list.
	 */
	enter_critical(self);
	uc.uc_sigmask = ulwp->ul_sigmask = self->ul_sigmask;
	if (error != 0 ||
	    (error = __lwp_create(&uc, lwp_flags, &tid)) != 0) {
		exit_critical(self);
		ulwp->ul_lwpid = (lwpid_t)(-1);
		ulwp->ul_dead = 1;
		ulwp->ul_detached = 1;
		lmutex_lock(&udp->link_lock);
		ulwp_free(ulwp);
		lmutex_unlock(&udp->link_lock);
		return (error);
	}
	self->ul_nocancel = 0;	/* cancellation is now possible */
	udp->uberflags.uf_mt = 1;
	if (new_thread)
		*new_thread = tid;
	if (flags & THR_DETACHED)
		ulwp->ul_detached = 1;
	ulwp->ul_lwpid = tid;
	ulwp->ul_stop = TSTP_REGULAR;
	if (flags & THR_SUSPENDED)
		ulwp->ul_created = 1;

	lmutex_lock(&udp->link_lock);
	ulwp->ul_forw = udp->all_lwps;
	ulwp->ul_back = udp->all_lwps->ul_back;
	ulwp->ul_back->ul_forw = ulwp;
	ulwp->ul_forw->ul_back = ulwp;
	hash_in(ulwp, udp);
	udp->nthreads++;
	if (flags & THR_DAEMON)
		udp->ndaemons++;
	if (flags & THR_NEW_LWP)
		thr_concurrency++;
	__libc_threaded = 1;		/* inform stdio */
	lmutex_unlock(&udp->link_lock);

	if (__td_event_report(self, TD_CREATE, udp)) {
		self->ul_td_evbuf.eventnum = TD_CREATE;
		self->ul_td_evbuf.eventdata = (void *)(uintptr_t)tid;
		tdb_event(TD_CREATE, udp);
	}

	exit_critical(self);

	if (!(flags & THR_SUSPENDED))
		(void) _thrp_continue(tid, TSTP_REGULAR);

	return (0);
}

int
thr_create(void *stk, size_t stksize, void *(*func)(void *), void *arg,
    long flags, thread_t *new_thread)
{
	return (_thrp_create(stk, stksize, func, arg, flags, new_thread, 0));
}

/*
 * A special cancellation cleanup hook for DCE.
 * cleanuphndlr, when it is not NULL, will contain a callback
 * function to be called before a thread is terminated in
 * thr_exit() as a result of being cancelled.
 */
static void (*cleanuphndlr)(void) = NULL;

/*
 * _pthread_setcleanupinit: sets the cleanup hook.
 */
int
_pthread_setcleanupinit(void (*func)(void))
{
	cleanuphndlr = func;
	return (0);
}

void
_thrp_exit()
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *replace = NULL;

	if (__td_event_report(self, TD_DEATH, udp)) {
		self->ul_td_evbuf.eventnum = TD_DEATH;
		tdb_event(TD_DEATH, udp);
	}

	ASSERT(self->ul_sigdefer != 0);

	lmutex_lock(&udp->link_lock);
	udp->nthreads--;
	if (self->ul_usropts & THR_NEW_LWP)
		thr_concurrency--;
	if (self->ul_usropts & THR_DAEMON)
		udp->ndaemons--;
	else if (udp->nthreads == udp->ndaemons) {
		/*
		 * We are the last non-daemon thread exiting.
		 * Exit the process.  We retain our TSD and TLS so
		 * that atexit() application functions can use them.
		 */
		lmutex_unlock(&udp->link_lock);
		exit(0);
		thr_panic("_thrp_exit(): exit(0) returned");
	}
	lmutex_unlock(&udp->link_lock);

	/*
	 * tsd_exit() may call its destructor free(), thus depending on
	 * tmem, therefore tmem_exit() needs to be called after tsd_exit()
	 * and tls_exit().
	 */
	tsd_exit();		/* deallocate thread-specific data */
	tls_exit();		/* deallocate thread-local storage */
	tmem_exit();		/* deallocate tmem allocations */
	heldlock_exit();	/* deal with left-over held locks */

	/* block all signals to finish exiting */
	block_all_signals(self);
	/* also prevent ourself from being suspended */
	enter_critical(self);
	rwl_free(self);
	lmutex_lock(&udp->link_lock);
	ulwp_free(self);
	(void) ulwp_lock(self, udp);

	if (self->ul_mapsiz && !self->ul_detached) {
		/*
		 * We want to free the stack for reuse but must keep
		 * the ulwp_t struct for the benefit of thr_join().
		 * For this purpose we allocate a replacement ulwp_t.
		 */
		if ((replace = udp->ulwp_replace_free) == NULL)
			replace = lmalloc(REPLACEMENT_SIZE);
		else if ((udp->ulwp_replace_free = replace->ul_next) == NULL)
			udp->ulwp_replace_last = NULL;
	}

	if (udp->all_lwps == self)
		udp->all_lwps = self->ul_forw;
	if (udp->all_lwps == self)
		udp->all_lwps = NULL;
	else {
		self->ul_forw->ul_back = self->ul_back;
		self->ul_back->ul_forw = self->ul_forw;
	}
	self->ul_forw = self->ul_back = NULL;
#if defined(THREAD_DEBUG)
	/* collect queue lock statistics before marking ourself dead */
	record_spin_locks(self);
#endif
	self->ul_dead = 1;
	self->ul_pleasestop = 0;
	if (replace != NULL) {
		int ix = self->ul_ix;		/* the hash index */
		(void) memcpy(replace, self, REPLACEMENT_SIZE);
		replace->ul_self = replace;
		replace->ul_next = NULL;	/* clone not on stack list */
		replace->ul_mapsiz = 0;		/* allows clone to be freed */
		replace->ul_replace = 1;	/* requires clone to be freed */
		hash_out_unlocked(self, ix, udp);
		hash_in_unlocked(replace, ix, udp);
		ASSERT(!(self->ul_detached));
		self->ul_detached = 1;		/* this frees the stack */
		self->ul_schedctl = NULL;
		self->ul_schedctl_called = &udp->uberflags;
		set_curthread(self = replace);
		/*
		 * Having just changed the address of curthread, we
		 * must reset the ownership of the locks we hold so
		 * that assertions will not fire when we release them.
		 */
		udp->link_lock.mutex_owner = (uintptr_t)self;
		ulwp_mutex(self, udp)->mutex_owner = (uintptr_t)self;
		/*
		 * NOTE:
		 * On i386, %gs still references the original, not the
		 * replacement, ulwp structure.  Fetching the replacement
		 * curthread pointer via %gs:0 works correctly since the
		 * original ulwp structure will not be reallocated until
		 * this lwp has completed its lwp_exit() system call (see
		 * dead_and_buried()), but from here on out, we must make
		 * no references to %gs:<offset> other than %gs:0.
		 */
	}
	/*
	 * Put non-detached terminated threads in the all_zombies list.
	 */
	if (!self->ul_detached) {
		udp->nzombies++;
		if (udp->all_zombies == NULL) {
			ASSERT(udp->nzombies == 1);
			udp->all_zombies = self->ul_forw = self->ul_back = self;
		} else {
			self->ul_forw = udp->all_zombies;
			self->ul_back = udp->all_zombies->ul_back;
			self->ul_back->ul_forw = self;
			self->ul_forw->ul_back = self;
		}
	}
	/*
	 * Notify everyone waiting for this thread.
	 */
	ulwp_broadcast(self);
	(void) ulwp_unlock(self, udp);
	/*
	 * Prevent any more references to the schedctl data.
	 * We are exiting and continue_fork() may not find us.
	 * Do this just before dropping link_lock, since fork
	 * serializes on link_lock.
	 */
	self->ul_schedctl = NULL;
	self->ul_schedctl_called = &udp->uberflags;
	lmutex_unlock(&udp->link_lock);

	ASSERT(self->ul_critical == 1);
	ASSERT(self->ul_preempt == 0);
	_lwp_terminate();	/* never returns */
	thr_panic("_thrp_exit(): _lwp_terminate() returned");
}

#if defined(THREAD_DEBUG)
void
collect_queue_statistics()
{
	uberdata_t *udp = curthread->ul_uberdata;
	ulwp_t *ulwp;

	if (thread_queue_dump) {
		lmutex_lock(&udp->link_lock);
		if ((ulwp = udp->all_lwps) != NULL) {
			do {
				record_spin_locks(ulwp);
			} while ((ulwp = ulwp->ul_forw) != udp->all_lwps);
		}
		lmutex_unlock(&udp->link_lock);
	}
}
#endif

static void __NORETURN
_thrp_exit_common(void *status, int unwind)
{
	ulwp_t *self = curthread;
	int cancelled = (self->ul_cancel_pending && status == PTHREAD_CANCELED);

	ASSERT(self->ul_critical == 0 && self->ul_preempt == 0);

	/*
	 * Disable cancellation and call the special DCE cancellation
	 * cleanup hook if it is enabled.  Do nothing else before calling
	 * the DCE cancellation cleanup hook; it may call longjmp() and
	 * never return here.
	 */
	self->ul_cancel_disabled = 1;
	self->ul_cancel_async = 0;
	self->ul_save_async = 0;
	self->ul_cancelable = 0;
	self->ul_cancel_pending = 0;
	set_cancel_pending_flag(self, 1);
	if (cancelled && cleanuphndlr != NULL)
		(*cleanuphndlr)();

	/*
	 * Block application signals while we are exiting.
	 * We call out to C++, TSD, and TLS destructors while exiting
	 * and these are application-defined, so we cannot be assured
	 * that they won't reset the signal mask.  We use sigoff() to
	 * defer any signals that may be received as a result of this
	 * bad behavior.  Such signals will be lost to the process
	 * when the thread finishes exiting.
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &maskset, NULL);
	sigoff(self);

	self->ul_rval = status;

	/*
	 * If thr_exit is being called from the places where
	 * C++ destructors are to be called such as cancellation
	 * points, then set this flag. It is checked in _t_cancel()
	 * to decide whether _ex_unwind() is to be called or not.
	 */
	if (unwind)
		self->ul_unwind = 1;

	/*
	 * _thrp_unwind() will eventually call _thrp_exit().
	 * It never returns.
	 */
	_thrp_unwind(NULL);
	thr_panic("_thrp_exit_common(): _thrp_unwind() returned");

	for (;;)	/* to shut the compiler up about __NORETURN */
		continue;
}

/*
 * Called when a thread returns from its start function.
 * We are at the top of the stack; no unwinding is necessary.
 */
void
_thrp_terminate(void *status)
{
	_thrp_exit_common(status, 0);
}

#pragma weak pthread_exit = thr_exit
#pragma weak _thr_exit = thr_exit
void
thr_exit(void *status)
{
	_thrp_exit_common(status, 1);
}

int
_thrp_join(thread_t tid, thread_t *departed, void **status, int do_cancel)
{
	uberdata_t *udp = curthread->ul_uberdata;
	mutex_t *mp;
	void *rval;
	thread_t found;
	ulwp_t *ulwp;
	ulwp_t **ulwpp;
	int replace;
	int error;

	if (do_cancel)
		error = lwp_wait(tid, &found);
	else {
		while ((error = __lwp_wait(tid, &found)) == EINTR)
			;
	}
	if (error)
		return (error);

	/*
	 * We must hold link_lock to avoid a race condition with find_stack().
	 */
	lmutex_lock(&udp->link_lock);
	if ((ulwpp = find_lwpp(found)) == NULL) {
		/*
		 * lwp_wait() found an lwp that the library doesn't know
		 * about.  It must have been created with _lwp_create().
		 * Just return its lwpid; we can't know its status.
		 */
		lmutex_unlock(&udp->link_lock);
		rval = NULL;
	} else {
		/*
		 * Remove ulwp from the hash table.
		 */
		ulwp = *ulwpp;
		*ulwpp = ulwp->ul_hash;
		ulwp->ul_hash = NULL;
		/*
		 * Remove ulwp from all_zombies list.
		 */
		ASSERT(udp->nzombies >= 1);
		if (udp->all_zombies == ulwp)
			udp->all_zombies = ulwp->ul_forw;
		if (udp->all_zombies == ulwp)
			udp->all_zombies = NULL;
		else {
			ulwp->ul_forw->ul_back = ulwp->ul_back;
			ulwp->ul_back->ul_forw = ulwp->ul_forw;
		}
		ulwp->ul_forw = ulwp->ul_back = NULL;
		udp->nzombies--;
		ASSERT(ulwp->ul_dead && !ulwp->ul_detached &&
		    !(ulwp->ul_usropts & (THR_DETACHED|THR_DAEMON)));
		/*
		 * We can't call ulwp_unlock(ulwp) after we set
		 * ulwp->ul_ix = -1 so we have to get a pointer to the
		 * ulwp's hash table mutex now in order to unlock it below.
		 */
		mp = ulwp_mutex(ulwp, udp);
		ulwp->ul_lwpid = (lwpid_t)(-1);
		ulwp->ul_ix = -1;
		rval = ulwp->ul_rval;
		replace = ulwp->ul_replace;
		lmutex_unlock(mp);
		if (replace) {
			ulwp->ul_next = NULL;
			if (udp->ulwp_replace_free == NULL)
				udp->ulwp_replace_free =
				    udp->ulwp_replace_last = ulwp;
			else {
				udp->ulwp_replace_last->ul_next = ulwp;
				udp->ulwp_replace_last = ulwp;
			}
		}
		lmutex_unlock(&udp->link_lock);
	}

	if (departed != NULL)
		*departed = found;
	if (status != NULL)
		*status = rval;
	return (0);
}

int
thr_join(thread_t tid, thread_t *departed, void **status)
{
	int error = _thrp_join(tid, departed, status, 1);
	return ((error == EINVAL)? ESRCH : error);
}

/*
 * pthread_join() differs from Solaris thr_join():
 * It does not return the departed thread's id
 * and hence does not have a "departed" argument.
 * It returns EINVAL if tid refers to a detached thread.
 */
#pragma weak _pthread_join = pthread_join
int
pthread_join(pthread_t tid, void **status)
{
	return ((tid == 0)? ESRCH : _thrp_join(tid, NULL, status, 1));
}

int
pthread_detach(pthread_t tid)
{
	uberdata_t *udp = curthread->ul_uberdata;
	ulwp_t *ulwp;
	ulwp_t **ulwpp;
	int error = 0;

	if ((ulwpp = find_lwpp(tid)) == NULL)
		return (ESRCH);
	ulwp = *ulwpp;

	if (ulwp->ul_dead) {
		ulwp_unlock(ulwp, udp);
		error = _thrp_join(tid, NULL, NULL, 0);
	} else {
		error = __lwp_detach(tid);
		ulwp->ul_detached = 1;
		ulwp->ul_usropts |= THR_DETACHED;
		ulwp_unlock(ulwp, udp);
	}
	return (error);
}

static const char *
ematch(const char *ev, const char *match)
{
	int c;

	while ((c = *match++) != '\0') {
		if (*ev++ != c)
			return (NULL);
	}
	if (*ev++ != '=')
		return (NULL);
	return (ev);
}

static int
envvar(const char *ev, const char *match, int limit)
{
	int val = -1;
	const char *ename;

	if ((ename = ematch(ev, match)) != NULL) {
		int c;
		for (val = 0; (c = *ename) != '\0'; ename++) {
			if (!isdigit(c)) {
				val = -1;
				break;
			}
			val = val * 10 + (c - '0');
			if (val > limit) {
				val = limit;
				break;
			}
		}
	}
	return (val);
}

static void
etest(const char *ev)
{
	int value;

	if ((value = envvar(ev, "QUEUE_SPIN", 1000000)) >= 0)
		thread_queue_spin = value;
	if ((value = envvar(ev, "ADAPTIVE_SPIN", 1000000)) >= 0)
		thread_adaptive_spin = value;
	if ((value = envvar(ev, "MAX_SPINNERS", 255)) >= 0)
		thread_max_spinners = value;
	if ((value = envvar(ev, "QUEUE_FIFO", 8)) >= 0)
		thread_queue_fifo = value;
#if defined(THREAD_DEBUG)
	if ((value = envvar(ev, "QUEUE_VERIFY", 1)) >= 0)
		thread_queue_verify = value;
	if ((value = envvar(ev, "QUEUE_DUMP", 1)) >= 0)
		thread_queue_dump = value;
#endif
	if ((value = envvar(ev, "STACK_CACHE", 10000)) >= 0)
		thread_stack_cache = value;
	if ((value = envvar(ev, "COND_WAIT_DEFER", 1)) >= 0)
		thread_cond_wait_defer = value;
	if ((value = envvar(ev, "ERROR_DETECTION", 2)) >= 0)
		thread_error_detection = value;
	if ((value = envvar(ev, "ASYNC_SAFE", 1)) >= 0)
		thread_async_safe = value;
	if ((value = envvar(ev, "DOOR_NORESERVE", 1)) >= 0)
		thread_door_noreserve = value;
	if ((value = envvar(ev, "LOCKS_MISALIGNED", 1)) >= 0)
		thread_locks_misaligned = value;
}

/*
 * Look for and evaluate environment variables of the form "_THREAD_*".
 * For compatibility with the past, we also look for environment
 * names of the form "LIBTHREAD_*".
 */
static void
set_thread_vars()
{
	extern const char **_environ;
	const char **pev;
	const char *ev;
	char c;

	if ((pev = _environ) == NULL)
		return;
	while ((ev = *pev++) != NULL) {
		c = *ev;
		if (c == '_' && strncmp(ev, "_THREAD_", 8) == 0)
			etest(ev + 8);
		if (c == 'L' && strncmp(ev, "LIBTHREAD_", 10) == 0)
			etest(ev + 10);
	}
}

/* PROBE_SUPPORT begin */
#pragma weak __tnf_probe_notify
extern void __tnf_probe_notify(void);
/* PROBE_SUPPORT end */

/* same as atexit() but private to the library */
extern int _atexit(void (*)(void));

/* same as _cleanup() but private to the library */
extern void __cleanup(void);

extern void atfork_init(void);

#ifdef __amd64
extern void __proc64id(void);
#endif

static void
init_auxv_data(uberdata_t *udp)
{
	Dl_argsinfo_t args;

	udp->ub_comm_page = NULL;
	if (dlinfo(RTLD_SELF, RTLD_DI_ARGSINFO, &args) < 0)
		return;

	while (args.dla_auxv->a_type != AT_NULL) {
		if (args.dla_auxv->a_type == AT_SUN_COMMPAGE) {
			udp->ub_comm_page = args.dla_auxv->a_un.a_ptr;
		}
		args.dla_auxv++;
	}
}

/*
 * libc_init() is called by ld.so.1 for library initialization.
 * We perform minimal initialization; enough to work with the main thread.
 */
void
libc_init(void)
{
	uberdata_t *udp = &__uberdata;
	ulwp_t *oldself = __curthread();
	ucontext_t uc;
	ulwp_t *self;
	struct rlimit rl;
	caddr_t data;
	size_t tls_size;
	int setmask;

	/*
	 * For the initial stage of initialization, we must be careful
	 * not to call any function that could possibly call _cerror().
	 * For this purpose, we call only the raw system call wrappers.
	 */

#ifdef __amd64
	/*
	 * Gather information about cache layouts for optimized
	 * AMD and Intel assembler strfoo() and memfoo() functions.
	 */
	__proc64id();
#endif

	/*
	 * Every libc, regardless of which link map, must register __cleanup().
	 */
	(void) _atexit(__cleanup);

	/*
	 * Every libc, regardless of link map, needs to go through and check
	 * its aux vectors.  Doing so will indicate whether or not this has
	 * been given a comm page (to optimize certain system actions).
	 */
	init_auxv_data(udp);

	/*
	 * We keep our uberdata on one of (a) the first alternate link map
	 * or (b) the primary link map.  We switch to the primary link map
	 * and stay there once we see it.  All intermediate link maps are
	 * subject to being unloaded at any time.
	 */
	if (oldself != NULL && (oldself->ul_primarymap || !primary_link_map)) {
		__tdb_bootstrap = oldself->ul_uberdata->tdb_bootstrap;
		mutex_setup();
		atfork_init();	/* every link map needs atfork() processing */
		init_progname();
		return;
	}

	/*
	 * To establish the main stack information, we have to get our context.
	 * This is also convenient to use for getting our signal mask.
	 */
	uc.uc_flags = UC_ALL;
	(void) __getcontext(&uc);
	ASSERT(uc.uc_link == NULL);

	tls_size = roundup64(udp->tls_metadata.static_tls.tls_size);
	ASSERT(primary_link_map || tls_size == 0);
	data = lmalloc(sizeof (ulwp_t) + tls_size);
	if (data == NULL)
		thr_panic("cannot allocate thread structure for main thread");
	/* LINTED pointer cast may result in improper alignment */
	self = (ulwp_t *)(data + tls_size);
	init_hash_table[0].hash_bucket = self;

	self->ul_sigmask = uc.uc_sigmask;
	delete_reserved_signals(&self->ul_sigmask);
	/*
	 * Are the old and new sets different?
	 * (This can happen if we are currently blocking SIGCANCEL.)
	 * If so, we must explicitly set our signal mask, below.
	 */
	setmask =
	    ((self->ul_sigmask.__sigbits[0] ^ uc.uc_sigmask.__sigbits[0]) |
	    (self->ul_sigmask.__sigbits[1] ^ uc.uc_sigmask.__sigbits[1]) |
	    (self->ul_sigmask.__sigbits[2] ^ uc.uc_sigmask.__sigbits[2]) |
	    (self->ul_sigmask.__sigbits[3] ^ uc.uc_sigmask.__sigbits[3]));

#ifdef __sparc
	/*
	 * We cache several instructions in the thread structure for use
	 * by the fasttrap DTrace provider. When changing this, read the
	 * comment in fasttrap.h for the all the other places that must
	 * be changed.
	 */
	self->ul_dsave = 0x9de04000;	/* save %g1, %g0, %sp */
	self->ul_drestore = 0x81e80000;	/* restore %g0, %g0, %g0 */
	self->ul_dftret = 0x91d0203a;	/* ta 0x3a */
	self->ul_dreturn = 0x81ca0000;	/* return %o0 */
#endif

	self->ul_stktop = (uintptr_t)uc.uc_stack.ss_sp + uc.uc_stack.ss_size;
	(void) getrlimit(RLIMIT_STACK, &rl);
	self->ul_stksiz = rl.rlim_cur;
	self->ul_stk = (caddr_t)(self->ul_stktop - self->ul_stksiz);

	self->ul_forw = self->ul_back = self;
	self->ul_hash = NULL;
	self->ul_ix = 0;
	self->ul_lwpid = 1; /* _lwp_self() */
	self->ul_main = 1;
	self->ul_self = self;
	self->ul_policy = -1;		/* initialize only when needed */
	self->ul_pri = 0;
	self->ul_cid = 0;
	self->ul_rtclassid = -1;
	self->ul_uberdata = udp;
	if (oldself != NULL) {
		int i;

		ASSERT(primary_link_map);
		ASSERT(oldself->ul_main == 1);
		self->ul_stsd = oldself->ul_stsd;
		for (i = 0; i < TSD_NFAST; i++)
			self->ul_ftsd[i] = oldself->ul_ftsd[i];
		self->ul_tls = oldself->ul_tls;
		/*
		 * Retrieve all pointers to uberdata allocated
		 * while running on previous link maps.
		 * We would like to do a structure assignment here, but
		 * gcc turns structure assignments into calls to memcpy(),
		 * a function exported from libc.  We can't call any such
		 * external functions until we establish curthread, below,
		 * so we just call our private version of memcpy().
		 */
		(void) memcpy(udp, oldself->ul_uberdata, sizeof (*udp));
		/*
		 * These items point to global data on the primary link map.
		 */
		udp->thr_hash_table = init_hash_table;
		udp->sigacthandler = sigacthandler;
		udp->tdb.tdb_events = tdb_events;
		ASSERT(udp->nthreads == 1 && !udp->uberflags.uf_mt);
		ASSERT(udp->lwp_stacks == NULL);
		ASSERT(udp->ulwp_freelist == NULL);
		ASSERT(udp->ulwp_replace_free == NULL);
		ASSERT(udp->hash_size == 1);
	}
	udp->all_lwps = self;
	udp->ulwp_one = self;
	udp->pid = getpid();
	udp->nthreads = 1;
	/*
	 * In every link map, tdb_bootstrap points to the same piece of
	 * allocated memory.  When the primary link map is initialized,
	 * the allocated memory is assigned a pointer to the one true
	 * uberdata.  This allows libc_db to initialize itself regardless
	 * of which instance of libc it finds in the address space.
	 */
	if (udp->tdb_bootstrap == NULL)
		udp->tdb_bootstrap = lmalloc(sizeof (uberdata_t *));
	__tdb_bootstrap = udp->tdb_bootstrap;
	if (primary_link_map) {
		self->ul_primarymap = 1;
		udp->primary_map = 1;
		*udp->tdb_bootstrap = udp;
	}
	/*
	 * Cancellation can't happen until:
	 *	pthread_cancel() is called
	 * or:
	 *	another thread is created
	 * For now, as a single-threaded process, set the flag that tells
	 * PROLOGUE/EPILOGUE (in scalls.c) that cancellation can't happen.
	 */
	self->ul_nocancel = 1;

#if defined(__amd64)
	(void) ___lwp_private(_LWP_SETPRIVATE, _LWP_FSBASE, self);
#elif defined(__i386)
	(void) ___lwp_private(_LWP_SETPRIVATE, _LWP_GSBASE, self);
#endif	/* __i386 || __amd64 */
	set_curthread(self);		/* redundant on i386 */
	/*
	 * Now curthread is established and it is safe to call any
	 * function in libc except one that uses thread-local storage.
	 */
	self->ul_errnop = &errno;
	if (oldself != NULL) {
		/* tls_size was zero when oldself was allocated */
		lfree(oldself, sizeof (ulwp_t));
	}
	mutex_setup();
	atfork_init();
	signal_init();

	/*
	 * If the stack is unlimited, we set the size to zero to disable
	 * stack checking.
	 * XXX: Work harder here.  Get the stack size from /proc/self/rmap
	 */
	if (self->ul_stksiz == RLIM_INFINITY) {
		self->ul_ustack.ss_sp = (void *)self->ul_stktop;
		self->ul_ustack.ss_size = 0;
	} else {
		self->ul_ustack.ss_sp = self->ul_stk;
		self->ul_ustack.ss_size = self->ul_stksiz;
	}
	self->ul_ustack.ss_flags = 0;
	(void) setustack(&self->ul_ustack);

	/*
	 * Get the variables that affect thread behavior from the environment.
	 */
	set_thread_vars();
	udp->uberflags.uf_thread_error_detection = (char)thread_error_detection;
	udp->thread_stack_cache = thread_stack_cache;

	/*
	 * Make per-thread copies of global variables, for speed.
	 */
	self->ul_queue_fifo = (char)thread_queue_fifo;
	self->ul_cond_wait_defer = (char)thread_cond_wait_defer;
	self->ul_error_detection = (char)thread_error_detection;
	self->ul_async_safe = (char)thread_async_safe;
	self->ul_door_noreserve = (char)thread_door_noreserve;
	self->ul_misaligned = (char)thread_locks_misaligned;
	self->ul_max_spinners = (uint8_t)thread_max_spinners;
	self->ul_adaptive_spin = thread_adaptive_spin;
	self->ul_queue_spin = thread_queue_spin;

#if defined(__sparc) && !defined(_LP64)
	if (self->ul_misaligned) {
		/*
		 * Tell the kernel to fix up ldx/stx instructions that
		 * refer to non-8-byte aligned data instead of giving
		 * the process an alignment trap and generating SIGBUS.
		 *
		 * Programs compiled for 32-bit sparc with the Studio SS12
		 * compiler get this done for them automatically (in _init()).
		 * We do it here for the benefit of programs compiled with
		 * other compilers, like gcc.
		 *
		 * This is necessary for the _THREAD_LOCKS_MISALIGNED=1
		 * environment variable horrible hack to work.
		 */
		extern void _do_fix_align(void);
		_do_fix_align();
	}
#endif

	/*
	 * When we have initialized the primary link map, inform
	 * the dynamic linker about our interface functions.
	 * Set up our pointer to the program name.
	 */
	if (self->ul_primarymap)
		_ld_libc((void *)rtld_funcs);
	init_progname();

	/*
	 * Defer signals until TLS constructors have been called.
	 */
	sigoff(self);
	tls_setup();
	sigon(self);
	if (setmask)
		(void) restore_signals(self);

	/*
	 * Make private copies of __xpg4 and __xpg6 so libc can test
	 * them after this point without invoking the dynamic linker.
	 */
	libc__xpg4 = __xpg4;
	libc__xpg6 = __xpg6;

	/* PROBE_SUPPORT begin */
	if (self->ul_primarymap && __tnf_probe_notify != NULL)
		__tnf_probe_notify();
	/* PROBE_SUPPORT end */

	init_sigev_thread();
	init_aio();

	/*
	 * We need to reset __threaded dynamically at runtime, so that
	 * __threaded can be bound to __threaded outside libc which may not
	 * have initial value of 1 (without a copy relocation in a.out).
	 */
	__threaded = 1;
}

#pragma fini(libc_fini)
void
libc_fini()
{
	/*
	 * If we are doing fini processing for the instance of libc
	 * on the first alternate link map (this happens only when
	 * the dynamic linker rejects a bad audit library), then clear
	 * __curthread().  We abandon whatever memory was allocated by
	 * lmalloc() while running on this alternate link-map but we
	 * don't care (and can't find the memory in any case); we just
	 * want to protect the application from this bad audit library.
	 * No fini processing is done by libc in the normal case.
	 */

	uberdata_t *udp = curthread->ul_uberdata;

	if (udp->primary_map == 0 && udp == &__uberdata)
		set_curthread(NULL);
}

/*
 * finish_init is called when we are about to become multi-threaded,
 * that is, on the first call to thr_create().
 */
void
finish_init()
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	thr_hash_table_t *htp;
	void *data;
	int i;

	/*
	 * No locks needed here; we are single-threaded on the first call.
	 * We can be called only after the primary link map has been set up.
	 */
	ASSERT(self->ul_primarymap);
	ASSERT(self == udp->ulwp_one);
	ASSERT(!udp->uberflags.uf_mt);
	ASSERT(udp->hash_size == 1);

	/*
	 * Initialize self->ul_policy, self->ul_cid, and self->ul_pri.
	 */
	update_sched(self);

	/*
	 * Allocate the queue_head array if not already allocated.
	 */
	if (udp->queue_head == NULL)
		queue_alloc();

	/*
	 * Now allocate the thread hash table.
	 */
	if ((data = mmap(NULL, HASHTBLSZ * sizeof (thr_hash_table_t),
	    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, (off_t)0))
	    == MAP_FAILED)
		thr_panic("cannot allocate thread hash table");

	udp->thr_hash_table = htp = (thr_hash_table_t *)data;
	udp->hash_size = HASHTBLSZ;
	udp->hash_mask = HASHTBLSZ - 1;

	for (i = 0; i < HASHTBLSZ; i++, htp++) {
		htp->hash_lock.mutex_flag = LOCK_INITED;
		htp->hash_lock.mutex_magic = MUTEX_MAGIC;
		htp->hash_cond.cond_magic = COND_MAGIC;
	}
	hash_in_unlocked(self, TIDHASH(self->ul_lwpid, udp), udp);

	/*
	 * Set up the SIGCANCEL handler for threads cancellation.
	 */
	setup_cancelsig(SIGCANCEL);

	/*
	 * Arrange to do special things on exit --
	 * - collect queue statistics from all remaining active threads.
	 * - dump queue statistics to stderr if _THREAD_QUEUE_DUMP is set.
	 * - grab assert_lock to ensure that assertion failures
	 *   and a core dump take precedence over _exit().
	 * (Functions are called in the reverse order of their registration.)
	 */
	(void) _atexit(grab_assert_lock);
#if defined(THREAD_DEBUG)
	(void) _atexit(dump_queue_statistics);
	(void) _atexit(collect_queue_statistics);
#endif
}

/*
 * Used only by postfork1_child(), below.
 */
static void
mark_dead_and_buried(ulwp_t *ulwp)
{
	ulwp->ul_dead = 1;
	ulwp->ul_lwpid = (lwpid_t)(-1);
	ulwp->ul_hash = NULL;
	ulwp->ul_ix = -1;
	ulwp->ul_schedctl = NULL;
	ulwp->ul_schedctl_called = NULL;
}

/*
 * This is called from fork1() in the child.
 * Reset our data structures to reflect one lwp.
 */
void
postfork1_child()
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	queue_head_t *qp;
	ulwp_t *next;
	ulwp_t *ulwp;
	int i;

	/* daemon threads shouldn't call fork1(), but oh well... */
	self->ul_usropts &= ~THR_DAEMON;
	udp->nthreads = 1;
	udp->ndaemons = 0;
	udp->uberflags.uf_mt = 0;
	__libc_threaded = 0;
	for (i = 0; i < udp->hash_size; i++)
		udp->thr_hash_table[i].hash_bucket = NULL;
	self->ul_lwpid = _lwp_self();
	hash_in_unlocked(self, TIDHASH(self->ul_lwpid, udp), udp);

	/*
	 * Some thread in the parent might have been suspended
	 * while holding udp->callout_lock or udp->ld_lock.
	 * Reinitialize the child's copies.
	 */
	(void) mutex_init(&udp->callout_lock,
	    USYNC_THREAD | LOCK_RECURSIVE, NULL);
	(void) mutex_init(&udp->ld_lock,
	    USYNC_THREAD | LOCK_RECURSIVE, NULL);

	/* no one in the child is on a sleep queue; reinitialize */
	if ((qp = udp->queue_head) != NULL) {
		(void) memset(qp, 0, 2 * QHASHSIZE * sizeof (queue_head_t));
		for (i = 0; i < 2 * QHASHSIZE; qp++, i++) {
			qp->qh_type = (i < QHASHSIZE)? MX : CV;
			qp->qh_lock.mutex_flag = LOCK_INITED;
			qp->qh_lock.mutex_magic = MUTEX_MAGIC;
			qp->qh_hlist = &qp->qh_def_root;
#if defined(THREAD_DEBUG)
			qp->qh_hlen = 1;
			qp->qh_hmax = 1;
#endif
		}
	}

	/*
	 * Do post-fork1 processing for subsystems that need it.
	 * We need to do this before unmapping all of the abandoned
	 * threads' stacks, below(), because the post-fork1 actions
	 * might require access to those stacks.
	 */
	postfork1_child_sigev_aio();
	postfork1_child_sigev_mq();
	postfork1_child_sigev_timer();
	postfork1_child_aio();
	/*
	 * The above subsystems use thread pools, so this action
	 * must be performed after those actions.
	 */
	postfork1_child_tpool();

	/*
	 * All lwps except ourself are gone.  Mark them so.
	 * First mark all of the lwps that have already been freed.
	 * Then mark and free all of the active lwps except ourself.
	 * Since we are single-threaded, no locks are required here.
	 */
	for (ulwp = udp->lwp_stacks; ulwp != NULL; ulwp = ulwp->ul_next)
		mark_dead_and_buried(ulwp);
	for (ulwp = udp->ulwp_freelist; ulwp != NULL; ulwp = ulwp->ul_next)
		mark_dead_and_buried(ulwp);
	for (ulwp = self->ul_forw; ulwp != self; ulwp = next) {
		next = ulwp->ul_forw;
		ulwp->ul_forw = ulwp->ul_back = NULL;
		mark_dead_and_buried(ulwp);
		tsd_free(ulwp);
		tls_free(ulwp);
		rwl_free(ulwp);
		heldlock_free(ulwp);
		ulwp_free(ulwp);
	}
	self->ul_forw = self->ul_back = udp->all_lwps = self;
	if (self != udp->ulwp_one)
		mark_dead_and_buried(udp->ulwp_one);
	if ((ulwp = udp->all_zombies) != NULL) {
		ASSERT(udp->nzombies != 0);
		do {
			next = ulwp->ul_forw;
			ulwp->ul_forw = ulwp->ul_back = NULL;
			mark_dead_and_buried(ulwp);
			udp->nzombies--;
			if (ulwp->ul_replace) {
				ulwp->ul_next = NULL;
				if (udp->ulwp_replace_free == NULL) {
					udp->ulwp_replace_free =
					    udp->ulwp_replace_last = ulwp;
				} else {
					udp->ulwp_replace_last->ul_next = ulwp;
					udp->ulwp_replace_last = ulwp;
				}
			}
		} while ((ulwp = next) != udp->all_zombies);
		ASSERT(udp->nzombies == 0);
		udp->all_zombies = NULL;
		udp->nzombies = 0;
	}
	trim_stack_cache(0);
}

lwpid_t
lwp_self(void)
{
	return (curthread->ul_lwpid);
}

#pragma weak _ti_thr_self = thr_self
#pragma weak pthread_self = thr_self
thread_t
thr_self()
{
	return (curthread->ul_lwpid);
}

int
thr_main()
{
	ulwp_t *self = __curthread();

	return ((self == NULL)? -1 : self->ul_main);
}

int
_thrp_cancelled(void)
{
	return (curthread->ul_rval == PTHREAD_CANCELED);
}

int
_thrp_stksegment(ulwp_t *ulwp, stack_t *stk)
{
	stk->ss_sp = (void *)ulwp->ul_stktop;
	stk->ss_size = ulwp->ul_stksiz;
	stk->ss_flags = 0;
	return (0);
}

#pragma weak _thr_stksegment = thr_stksegment
int
thr_stksegment(stack_t *stk)
{
	return (_thrp_stksegment(curthread, stk));
}

void
force_continue(ulwp_t *ulwp)
{
#if defined(THREAD_DEBUG)
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
#endif
	int error;
	timespec_t ts;

	ASSERT(MUTEX_OWNED(&udp->fork_lock, self));
	ASSERT(MUTEX_OWNED(ulwp_mutex(ulwp, udp), self));

	for (;;) {
		error = _lwp_continue(ulwp->ul_lwpid);
		if (error != 0 && error != EINTR)
			break;
		error = 0;
		if (ulwp->ul_stopping) {	/* it is stopping itself */
			ts.tv_sec = 0;		/* give it a chance to run */
			ts.tv_nsec = 100000;	/* 100 usecs or clock tick */
			(void) __nanosleep(&ts, NULL);
		}
		if (!ulwp->ul_stopping)		/* it is running now */
			break;			/* so we are done */
		/*
		 * It is marked as being in the process of stopping
		 * itself.  Loop around and continue it again.
		 * It may not have been stopped the first time.
		 */
	}
}

/*
 * Suspend an lwp with lwp_suspend(), then move it to a safe point,
 * that is, to a point where ul_critical and ul_rtld are both zero.
 * On return, the ulwp_lock() is dropped as with ulwp_unlock().
 * If 'link_dropped' is non-NULL, then 'link_lock' is held on entry.
 * If we have to drop link_lock, we store 1 through link_dropped.
 * If the lwp exits before it can be suspended, we return ESRCH.
 */
int
safe_suspend(ulwp_t *ulwp, uchar_t whystopped, int *link_dropped)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	cond_t *cvp = ulwp_condvar(ulwp, udp);
	mutex_t *mp = ulwp_mutex(ulwp, udp);
	thread_t tid = ulwp->ul_lwpid;
	int ix = ulwp->ul_ix;
	int error = 0;

	ASSERT(whystopped == TSTP_REGULAR ||
	    whystopped == TSTP_MUTATOR ||
	    whystopped == TSTP_FORK);
	ASSERT(ulwp != self);
	ASSERT(!ulwp->ul_stop);
	ASSERT(MUTEX_OWNED(&udp->fork_lock, self));
	ASSERT(MUTEX_OWNED(mp, self));

	if (link_dropped != NULL)
		*link_dropped = 0;

	/*
	 * We must grab the target's spin lock before suspending it.
	 * See the comments below and in _thrp_suspend() for why.
	 */
	spin_lock_set(&ulwp->ul_spinlock);
	(void) ___lwp_suspend(tid);
	spin_lock_clear(&ulwp->ul_spinlock);

top:
	if ((ulwp->ul_critical == 0 && ulwp->ul_rtld == 0) ||
	    ulwp->ul_stopping) {
		/* thread is already safe */
		ulwp->ul_stop |= whystopped;
	} else {
		/*
		 * Setting ul_pleasestop causes the target thread to stop
		 * itself in _thrp_suspend(), below, after we drop its lock.
		 * We must continue the critical thread before dropping
		 * link_lock because the critical thread may be holding
		 * the queue lock for link_lock.  This is delicate.
		 */
		ulwp->ul_pleasestop |= whystopped;
		force_continue(ulwp);
		if (link_dropped != NULL) {
			*link_dropped = 1;
			lmutex_unlock(&udp->link_lock);
			/* be sure to drop link_lock only once */
			link_dropped = NULL;
		}

		/*
		 * The thread may disappear by calling thr_exit() so we
		 * cannot rely on the ulwp pointer after dropping the lock.
		 * Instead, we search the hash table to find it again.
		 * When we return, we may find that the thread has been
		 * continued by some other thread.  The suspend/continue
		 * interfaces are prone to such race conditions by design.
		 */
		while (ulwp && !ulwp->ul_dead && !ulwp->ul_stop &&
		    (ulwp->ul_pleasestop & whystopped)) {
			(void) __cond_wait(cvp, mp);
			for (ulwp = udp->thr_hash_table[ix].hash_bucket;
			    ulwp != NULL; ulwp = ulwp->ul_hash) {
				if (ulwp->ul_lwpid == tid)
					break;
			}
		}

		if (ulwp == NULL || ulwp->ul_dead)
			error = ESRCH;
		else {
			/*
			 * Do another lwp_suspend() to make sure we don't
			 * return until the target thread is fully stopped
			 * in the kernel.  Don't apply lwp_suspend() until
			 * we know that the target is not holding any
			 * queue locks, that is, that it has completed
			 * ulwp_unlock(self) and has, or at least is
			 * about to, call lwp_suspend() on itself.  We do
			 * this by grabbing the target's spin lock.
			 */
			ASSERT(ulwp->ul_lwpid == tid);
			spin_lock_set(&ulwp->ul_spinlock);
			(void) ___lwp_suspend(tid);
			spin_lock_clear(&ulwp->ul_spinlock);
			/*
			 * If some other thread did a thr_continue()
			 * on the target thread we have to start over.
			 */
			if (!ulwp->ul_stopping || !(ulwp->ul_stop & whystopped))
				goto top;
		}
	}

	(void) cond_broadcast(cvp);
	lmutex_unlock(mp);
	return (error);
}

int
_thrp_suspend(thread_t tid, uchar_t whystopped)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp;
	int error = 0;

	ASSERT((whystopped & (TSTP_REGULAR|TSTP_MUTATOR|TSTP_FORK)) != 0);
	ASSERT((whystopped & ~(TSTP_REGULAR|TSTP_MUTATOR|TSTP_FORK)) == 0);

	/*
	 * We can't suspend anyone except ourself while
	 * some other thread is performing a fork.
	 * This also allows only one suspension at a time.
	 */
	if (tid != self->ul_lwpid)
		fork_lock_enter();

	if ((ulwp = find_lwp(tid)) == NULL)
		error = ESRCH;
	else if (whystopped == TSTP_MUTATOR && !ulwp->ul_mutator) {
		ulwp_unlock(ulwp, udp);
		error = EINVAL;
	} else if (ulwp->ul_stop) {	/* already stopped */
		ulwp->ul_stop |= whystopped;
		ulwp_broadcast(ulwp);
		ulwp_unlock(ulwp, udp);
	} else if (ulwp != self) {
		/*
		 * After suspending the other thread, move it out of a
		 * critical section and deal with the schedctl mappings.
		 * safe_suspend() suspends the other thread, calls
		 * ulwp_broadcast(ulwp) and drops the ulwp lock.
		 */
		error = safe_suspend(ulwp, whystopped, NULL);
	} else {
		int schedctl_after_fork = 0;

		/*
		 * We are suspending ourself.  We must not take a signal
		 * until we return from lwp_suspend() and clear ul_stopping.
		 * This is to guard against siglongjmp().
		 */
		enter_critical(self);
		self->ul_sp = stkptr();
		_flush_windows();	/* sparc */
		self->ul_pleasestop = 0;
		self->ul_stop |= whystopped;
		/*
		 * Grab our spin lock before dropping ulwp_mutex(self).
		 * This prevents the suspending thread from applying
		 * lwp_suspend() to us before we emerge from
		 * lmutex_unlock(mp) and have dropped mp's queue lock.
		 */
		spin_lock_set(&self->ul_spinlock);
		self->ul_stopping = 1;
		ulwp_broadcast(self);
		ulwp_unlock(self, udp);
		/*
		 * From this point until we return from lwp_suspend(),
		 * we must not call any function that might invoke the
		 * dynamic linker, that is, we can only call functions
		 * private to the library.
		 *
		 * Also, this is a nasty race condition for a process
		 * that is undergoing a forkall() operation:
		 * Once we clear our spinlock (below), we are vulnerable
		 * to being suspended by the forkall() thread before
		 * we manage to suspend ourself in ___lwp_suspend().
		 * See safe_suspend() and force_continue().
		 *
		 * To avoid a SIGSEGV due to the disappearance
		 * of the schedctl mappings in the child process,
		 * which can happen in spin_lock_clear() if we
		 * are suspended while we are in the middle of
		 * its call to preempt(), we preemptively clear
		 * our own schedctl pointer before dropping our
		 * spinlock.  We reinstate it, in both the parent
		 * and (if this really is a forkall()) the child.
		 */
		if (whystopped & TSTP_FORK) {
			schedctl_after_fork = 1;
			self->ul_schedctl = NULL;
			self->ul_schedctl_called = &udp->uberflags;
		}
		spin_lock_clear(&self->ul_spinlock);
		(void) ___lwp_suspend(tid);
		/*
		 * Somebody else continued us.
		 * We can't grab ulwp_lock(self)
		 * until after clearing ul_stopping.
		 * force_continue() relies on this.
		 */
		self->ul_stopping = 0;
		self->ul_sp = 0;
		if (schedctl_after_fork) {
			self->ul_schedctl_called = NULL;
			self->ul_schedctl = NULL;
			(void) setup_schedctl();
		}
		ulwp_lock(self, udp);
		ulwp_broadcast(self);
		ulwp_unlock(self, udp);
		exit_critical(self);
	}

	if (tid != self->ul_lwpid)
		fork_lock_exit();

	return (error);
}

/*
 * Suspend all lwps other than ourself in preparation for fork.
 */
void
suspend_fork()
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp;
	int link_dropped;

	ASSERT(MUTEX_OWNED(&udp->fork_lock, self));
top:
	lmutex_lock(&udp->link_lock);

	for (ulwp = self->ul_forw; ulwp != self; ulwp = ulwp->ul_forw) {
		ulwp_lock(ulwp, udp);
		if (ulwp->ul_stop) {	/* already stopped */
			ulwp->ul_stop |= TSTP_FORK;
			ulwp_broadcast(ulwp);
			ulwp_unlock(ulwp, udp);
		} else {
			/*
			 * Move the stopped lwp out of a critical section.
			 */
			if (safe_suspend(ulwp, TSTP_FORK, &link_dropped) ||
			    link_dropped)
				goto top;
		}
	}

	lmutex_unlock(&udp->link_lock);
}

void
continue_fork(int child)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp;

	ASSERT(MUTEX_OWNED(&udp->fork_lock, self));

	/*
	 * Clear the schedctl pointers in the child of forkall().
	 */
	if (child) {
		for (ulwp = self->ul_forw; ulwp != self; ulwp = ulwp->ul_forw) {
			ulwp->ul_schedctl_called =
			    ulwp->ul_dead? &udp->uberflags : NULL;
			ulwp->ul_schedctl = NULL;
		}
	}

	/*
	 * Set all lwps that were stopped for fork() running again.
	 */
	lmutex_lock(&udp->link_lock);
	for (ulwp = self->ul_forw; ulwp != self; ulwp = ulwp->ul_forw) {
		mutex_t *mp = ulwp_mutex(ulwp, udp);
		lmutex_lock(mp);
		ASSERT(ulwp->ul_stop & TSTP_FORK);
		ulwp->ul_stop &= ~TSTP_FORK;
		ulwp_broadcast(ulwp);
		if (!ulwp->ul_stop)
			force_continue(ulwp);
		lmutex_unlock(mp);
	}
	lmutex_unlock(&udp->link_lock);
}

int
_thrp_continue(thread_t tid, uchar_t whystopped)
{
	uberdata_t *udp = curthread->ul_uberdata;
	ulwp_t *ulwp;
	mutex_t *mp;
	int error = 0;

	ASSERT(whystopped == TSTP_REGULAR ||
	    whystopped == TSTP_MUTATOR);

	/*
	 * We single-thread the entire thread suspend/continue mechanism.
	 */
	fork_lock_enter();

	if ((ulwp = find_lwp(tid)) == NULL) {
		fork_lock_exit();
		return (ESRCH);
	}

	mp = ulwp_mutex(ulwp, udp);
	if ((whystopped == TSTP_MUTATOR && !ulwp->ul_mutator)) {
		error = EINVAL;
	} else if (ulwp->ul_stop & whystopped) {
		ulwp->ul_stop &= ~whystopped;
		ulwp_broadcast(ulwp);
		if (!ulwp->ul_stop) {
			if (whystopped == TSTP_REGULAR && ulwp->ul_created) {
				ulwp->ul_sp = 0;
				ulwp->ul_created = 0;
			}
			force_continue(ulwp);
		}
	}
	lmutex_unlock(mp);

	fork_lock_exit();
	return (error);
}

int
thr_suspend(thread_t tid)
{
	return (_thrp_suspend(tid, TSTP_REGULAR));
}

int
thr_continue(thread_t tid)
{
	return (_thrp_continue(tid, TSTP_REGULAR));
}

void
thr_yield()
{
	yield();
}

#pragma weak pthread_kill = thr_kill
#pragma weak _thr_kill = thr_kill
int
thr_kill(thread_t tid, int sig)
{
	if (sig == SIGCANCEL)
		return (EINVAL);
	return (_lwp_kill(tid, sig));
}

/*
 * Exit a critical section, take deferred actions if necessary.
 * Called from exit_critical() and from sigon().
 */
void
do_exit_critical()
{
	ulwp_t *self = curthread;
	int sig;

	ASSERT(self->ul_critical == 0);

	/*
	 * Don't suspend ourself or take a deferred signal while dying
	 * or while executing inside the dynamic linker (ld.so.1).
	 */
	if (self->ul_dead || self->ul_rtld)
		return;

	while (self->ul_pleasestop ||
	    (self->ul_cursig != 0 && self->ul_sigdefer == 0)) {
		/*
		 * Avoid a recursive call to exit_critical() in _thrp_suspend()
		 * by keeping self->ul_critical == 1 here.
		 */
		self->ul_critical++;
		while (self->ul_pleasestop) {
			/*
			 * Guard against suspending ourself while on a sleep
			 * queue.  See the comments in call_user_handler().
			 */
			unsleep_self();
			set_parking_flag(self, 0);
			(void) _thrp_suspend(self->ul_lwpid,
			    self->ul_pleasestop);
		}
		self->ul_critical--;

		if ((sig = self->ul_cursig) != 0 && self->ul_sigdefer == 0) {
			/*
			 * Clear ul_cursig before proceeding.
			 * This protects us from the dynamic linker's
			 * calls to bind_guard()/bind_clear() in the
			 * event that it is invoked to resolve a symbol
			 * like take_deferred_signal() below.
			 */
			self->ul_cursig = 0;
			take_deferred_signal(sig);
			ASSERT(self->ul_cursig == 0);
		}
	}
	ASSERT(self->ul_critical == 0);
}

/*
 * _ti_bind_guard() and _ti_bind_clear() are called by the dynamic linker
 * (ld.so.1) when it has do do something, like resolve a symbol to be called
 * by the application or one of its libraries.  _ti_bind_guard() is called
 * on entry to ld.so.1, _ti_bind_clear() on exit from ld.so.1 back to the
 * application.  The dynamic linker gets special dispensation from libc to
 * run in a critical region (all signals deferred and no thread suspension
 * or forking allowed), and to be immune from cancellation for the duration.
 */
int
_ti_bind_guard(int flags)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int bindflag = (flags & THR_FLG_RTLD);

	if ((self->ul_bindflags & bindflag) == bindflag)
		return (0);
	self->ul_bindflags |= bindflag;
	if ((flags & (THR_FLG_NOLOCK | THR_FLG_REENTER)) == THR_FLG_NOLOCK) {
		sigoff(self);	/* see no signals while holding ld_lock */
		self->ul_rtld++;	/* don't suspend while in ld.so.1 */
		(void) mutex_lock(&udp->ld_lock);
	}
	enter_critical(self);
	self->ul_save_state = self->ul_cancel_disabled;
	self->ul_cancel_disabled = 1;
	set_cancel_pending_flag(self, 0);
	return (1);
}

int
_ti_bind_clear(int flags)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	int bindflag = (flags & THR_FLG_RTLD);

	if ((self->ul_bindflags & bindflag) == 0)
		return (self->ul_bindflags);
	self->ul_bindflags &= ~bindflag;
	self->ul_cancel_disabled = self->ul_save_state;
	set_cancel_pending_flag(self, 0);
	exit_critical(self);
	if ((flags & (THR_FLG_NOLOCK | THR_FLG_REENTER)) == THR_FLG_NOLOCK) {
		if (MUTEX_OWNED(&udp->ld_lock, self)) {
			(void) mutex_unlock(&udp->ld_lock);
			self->ul_rtld--;
			sigon(self);	/* reenable signals */
		}
	}
	return (self->ul_bindflags);
}

/*
 * Tell the dynamic linker (ld.so.1) whether or not it was entered from
 * a critical region in libc.  Return zero if not, else return non-zero.
 */
int
_ti_critical(void)
{
	ulwp_t *self = curthread;
	int level = self->ul_critical;

	if ((self->ul_bindflags & THR_FLG_RTLD) == 0 || level == 0)
		return (level);	/* ld.so.1 hasn't (yet) called enter() */
	return (level - 1);
}

/*
 * sigoff() and sigon() enable cond_wait() to behave (optionally) like
 * it does in the old libthread (see the comments in cond_wait_queue()).
 * Also, signals are deferred at thread startup until TLS constructors
 * have all been called, at which time _thrp_setup() calls sigon().
 *
 * _sigoff() and _sigon() are external consolidation-private interfaces to
 * sigoff() and sigon(), respectively, in libc.  These are used in libnsl.
 * Also, _sigoff() and _sigon() are called from dbx's run-time checking
 * (librtc.so) to defer signals during its critical sections (not to be
 * confused with libc critical sections [see exit_critical() above]).
 */
void
_sigoff(void)
{
	ulwp_t *self = curthread;

	sigoff(self);
}

void
_sigon(void)
{
	ulwp_t *self = curthread;

	ASSERT(self->ul_sigdefer > 0);
	sigon(self);
}

int
thr_getconcurrency()
{
	return (thr_concurrency);
}

int
pthread_getconcurrency()
{
	return (pthread_concurrency);
}

int
thr_setconcurrency(int new_level)
{
	uberdata_t *udp = curthread->ul_uberdata;

	if (new_level < 0)
		return (EINVAL);
	if (new_level > 65536)		/* 65536 is totally arbitrary */
		return (EAGAIN);
	lmutex_lock(&udp->link_lock);
	if (new_level > thr_concurrency)
		thr_concurrency = new_level;
	lmutex_unlock(&udp->link_lock);
	return (0);
}

int
pthread_setconcurrency(int new_level)
{
	if (new_level < 0)
		return (EINVAL);
	if (new_level > 65536)		/* 65536 is totally arbitrary */
		return (EAGAIN);
	pthread_concurrency = new_level;
	return (0);
}

size_t
thr_min_stack(void)
{
	return (MINSTACK);
}

int
__nthreads(void)
{
	return (curthread->ul_uberdata->nthreads);
}

/*
 * XXX
 * The remainder of this file implements the private interfaces to java for
 * garbage collection.  It is no longer used, at least by java 1.2.
 * It can all go away once all old JVMs have disappeared.
 */

int	suspendingallmutators;	/* when non-zero, suspending all mutators. */
int	suspendedallmutators;	/* when non-zero, all mutators suspended. */
int	mutatorsbarrier;	/* when non-zero, mutators barrier imposed. */
mutex_t	mutatorslock = DEFAULTMUTEX;	/* used to enforce mutators barrier. */
cond_t	mutatorscv = DEFAULTCV;		/* where non-mutators sleep. */

/*
 * Get the available register state for the target thread.
 * Return non-volatile registers: TRS_NONVOLATILE
 */
#pragma weak _thr_getstate = thr_getstate
int
thr_getstate(thread_t tid, int *flag, lwpid_t *lwp, stack_t *ss, gregset_t rs)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t **ulwpp;
	ulwp_t *ulwp;
	int error = 0;
	int trs_flag = TRS_LWPID;

	if (tid == 0 || self->ul_lwpid == tid) {
		ulwp = self;
		ulwp_lock(ulwp, udp);
	} else if ((ulwpp = find_lwpp(tid)) != NULL) {
		ulwp = *ulwpp;
	} else {
		if (flag)
			*flag = TRS_INVALID;
		return (ESRCH);
	}

	if (ulwp->ul_dead) {
		trs_flag = TRS_INVALID;
	} else if (!ulwp->ul_stop && !suspendedallmutators) {
		error = EINVAL;
		trs_flag = TRS_INVALID;
	} else if (ulwp->ul_stop) {
		trs_flag = TRS_NONVOLATILE;
		getgregs(ulwp, rs);
	}

	if (flag)
		*flag = trs_flag;
	if (lwp)
		*lwp = tid;
	if (ss != NULL)
		(void) _thrp_stksegment(ulwp, ss);

	ulwp_unlock(ulwp, udp);
	return (error);
}

/*
 * Set the appropriate register state for the target thread.
 * This is not used by java.  It exists solely for the MSTC test suite.
 */
#pragma weak _thr_setstate = thr_setstate
int
thr_setstate(thread_t tid, int flag, gregset_t rs)
{
	uberdata_t *udp = curthread->ul_uberdata;
	ulwp_t *ulwp;
	int error = 0;

	if ((ulwp = find_lwp(tid)) == NULL)
		return (ESRCH);

	if (!ulwp->ul_stop && !suspendedallmutators)
		error = EINVAL;
	else if (rs != NULL) {
		switch (flag) {
		case TRS_NONVOLATILE:
			/* do /proc stuff here? */
			if (ulwp->ul_stop)
				setgregs(ulwp, rs);
			else
				error = EINVAL;
			break;
		case TRS_LWPID:		/* do /proc stuff here? */
		default:
			error = EINVAL;
			break;
		}
	}

	ulwp_unlock(ulwp, udp);
	return (error);
}

int
getlwpstatus(thread_t tid, struct lwpstatus *sp)
{
	extern ssize_t __pread(int, void *, size_t, off_t);
	char buf[100];
	int fd;

	/* "/proc/self/lwp/%u/lwpstatus" w/o stdio */
	(void) strcpy(buf, "/proc/self/lwp/");
	ultos((uint64_t)tid, 10, buf + strlen(buf));
	(void) strcat(buf, "/lwpstatus");
	if ((fd = __open(buf, O_RDONLY, 0)) >= 0) {
		while (__pread(fd, sp, sizeof (*sp), 0) == sizeof (*sp)) {
			if (sp->pr_flags & PR_STOPPED) {
				(void) __close(fd);
				return (0);
			}
			yield();	/* give it a chance to stop */
		}
		(void) __close(fd);
	}
	return (-1);
}

int
putlwpregs(thread_t tid, prgregset_t prp)
{
	extern ssize_t __writev(int, const struct iovec *, int);
	char buf[100];
	int fd;
	long dstop_sreg[2];
	long run_null[2];
	iovec_t iov[3];

	/* "/proc/self/lwp/%u/lwpctl" w/o stdio */
	(void) strcpy(buf, "/proc/self/lwp/");
	ultos((uint64_t)tid, 10, buf + strlen(buf));
	(void) strcat(buf, "/lwpctl");
	if ((fd = __open(buf, O_WRONLY, 0)) >= 0) {
		dstop_sreg[0] = PCDSTOP;	/* direct it to stop */
		dstop_sreg[1] = PCSREG;		/* set the registers */
		iov[0].iov_base = (caddr_t)dstop_sreg;
		iov[0].iov_len = sizeof (dstop_sreg);
		iov[1].iov_base = (caddr_t)prp;	/* from the register set */
		iov[1].iov_len = sizeof (prgregset_t);
		run_null[0] = PCRUN;		/* make it runnable again */
		run_null[1] = 0;
		iov[2].iov_base = (caddr_t)run_null;
		iov[2].iov_len = sizeof (run_null);
		if (__writev(fd, iov, 3) >= 0) {
			(void) __close(fd);
			return (0);
		}
		(void) __close(fd);
	}
	return (-1);
}

static ulong_t
gettsp_slow(thread_t tid)
{
	char buf[100];
	struct lwpstatus status;

	if (getlwpstatus(tid, &status) != 0) {
		/* "__gettsp(%u): can't read lwpstatus" w/o stdio */
		(void) strcpy(buf, "__gettsp(");
		ultos((uint64_t)tid, 10, buf + strlen(buf));
		(void) strcat(buf, "): can't read lwpstatus");
		thr_panic(buf);
	}
	return (status.pr_reg[R_SP]);
}

ulong_t
__gettsp(thread_t tid)
{
	uberdata_t *udp = curthread->ul_uberdata;
	ulwp_t *ulwp;
	ulong_t result;

	if ((ulwp = find_lwp(tid)) == NULL)
		return (0);

	if (ulwp->ul_stop && (result = ulwp->ul_sp) != 0) {
		ulwp_unlock(ulwp, udp);
		return (result);
	}

	result = gettsp_slow(tid);
	ulwp_unlock(ulwp, udp);
	return (result);
}

/*
 * This tells java stack walkers how to find the ucontext
 * structure passed to signal handlers.
 */
#pragma weak _thr_sighndlrinfo = thr_sighndlrinfo
void
thr_sighndlrinfo(void (**func)(), int *funcsize)
{
	*func = &__sighndlr;
	*funcsize = (char *)&__sighndlrend - (char *)&__sighndlr;
}

/*
 * Mark a thread a mutator or reset a mutator to being a default,
 * non-mutator thread.
 */
#pragma weak _thr_setmutator = thr_setmutator
int
thr_setmutator(thread_t tid, int enabled)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp;
	int error;
	int cancel_state;

	enabled = enabled? 1 : 0;
top:
	if (tid == 0) {
		ulwp = self;
		ulwp_lock(ulwp, udp);
	} else if ((ulwp = find_lwp(tid)) == NULL) {
		return (ESRCH);
	}

	/*
	 * The target thread should be the caller itself or a suspended thread.
	 * This prevents the target from also changing its ul_mutator field.
	 */
	error = 0;
	if (ulwp != self && !ulwp->ul_stop && enabled)
		error = EINVAL;
	else if (ulwp->ul_mutator != enabled) {
		lmutex_lock(&mutatorslock);
		if (mutatorsbarrier) {
			ulwp_unlock(ulwp, udp);
			(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
			    &cancel_state);
			while (mutatorsbarrier)
				(void) cond_wait(&mutatorscv, &mutatorslock);
			(void) pthread_setcancelstate(cancel_state, NULL);
			lmutex_unlock(&mutatorslock);
			goto top;
		}
		ulwp->ul_mutator = enabled;
		lmutex_unlock(&mutatorslock);
	}

	ulwp_unlock(ulwp, udp);
	return (error);
}

/*
 * Establish a barrier against new mutators.  Any non-mutator trying
 * to become a mutator is suspended until the barrier is removed.
 */
#pragma weak _thr_mutators_barrier = thr_mutators_barrier
void
thr_mutators_barrier(int enabled)
{
	int oldvalue;
	int cancel_state;

	lmutex_lock(&mutatorslock);

	/*
	 * Wait if trying to set the barrier while it is already set.
	 */
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	while (mutatorsbarrier && enabled)
		(void) cond_wait(&mutatorscv, &mutatorslock);
	(void) pthread_setcancelstate(cancel_state, NULL);

	oldvalue = mutatorsbarrier;
	mutatorsbarrier = enabled;
	/*
	 * Wakeup any blocked non-mutators when barrier is removed.
	 */
	if (oldvalue && !enabled)
		(void) cond_broadcast(&mutatorscv);
	lmutex_unlock(&mutatorslock);
}

/*
 * Suspend the set of all mutators except for the caller.  The list
 * of actively running threads is searched and only the mutators
 * in this list are suspended.  Actively running non-mutators remain
 * running.  Any other thread is suspended.
 */
#pragma weak _thr_suspend_allmutators = thr_suspend_allmutators
int
thr_suspend_allmutators(void)
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp;
	int link_dropped;

	/*
	 * We single-thread the entire thread suspend/continue mechanism.
	 */
	fork_lock_enter();

top:
	lmutex_lock(&udp->link_lock);

	if (suspendingallmutators || suspendedallmutators) {
		lmutex_unlock(&udp->link_lock);
		fork_lock_exit();
		return (EINVAL);
	}
	suspendingallmutators = 1;

	for (ulwp = self->ul_forw; ulwp != self; ulwp = ulwp->ul_forw) {
		ulwp_lock(ulwp, udp);
		if (!ulwp->ul_mutator) {
			ulwp_unlock(ulwp, udp);
		} else if (ulwp->ul_stop) {	/* already stopped */
			ulwp->ul_stop |= TSTP_MUTATOR;
			ulwp_broadcast(ulwp);
			ulwp_unlock(ulwp, udp);
		} else {
			/*
			 * Move the stopped lwp out of a critical section.
			 */
			if (safe_suspend(ulwp, TSTP_MUTATOR, &link_dropped) ||
			    link_dropped) {
				suspendingallmutators = 0;
				goto top;
			}
		}
	}

	suspendedallmutators = 1;
	suspendingallmutators = 0;
	lmutex_unlock(&udp->link_lock);
	fork_lock_exit();
	return (0);
}

/*
 * Suspend the target mutator.  The caller is permitted to suspend
 * itself.  If a mutator barrier is enabled, the caller will suspend
 * itself as though it had been suspended by thr_suspend_allmutators().
 * When the barrier is removed, this thread will be resumed.  Any
 * suspended mutator, whether suspended by thr_suspend_mutator(), or by
 * thr_suspend_allmutators(), can be resumed by thr_continue_mutator().
 */
#pragma weak _thr_suspend_mutator = thr_suspend_mutator
int
thr_suspend_mutator(thread_t tid)
{
	if (tid == 0)
		tid = curthread->ul_lwpid;
	return (_thrp_suspend(tid, TSTP_MUTATOR));
}

/*
 * Resume the set of all suspended mutators.
 */
#pragma weak _thr_continue_allmutators = thr_continue_allmutators
int
thr_continue_allmutators()
{
	ulwp_t *self = curthread;
	uberdata_t *udp = self->ul_uberdata;
	ulwp_t *ulwp;

	/*
	 * We single-thread the entire thread suspend/continue mechanism.
	 */
	fork_lock_enter();

	lmutex_lock(&udp->link_lock);
	if (!suspendedallmutators) {
		lmutex_unlock(&udp->link_lock);
		fork_lock_exit();
		return (EINVAL);
	}
	suspendedallmutators = 0;

	for (ulwp = self->ul_forw; ulwp != self; ulwp = ulwp->ul_forw) {
		mutex_t *mp = ulwp_mutex(ulwp, udp);
		lmutex_lock(mp);
		if (ulwp->ul_stop & TSTP_MUTATOR) {
			ulwp->ul_stop &= ~TSTP_MUTATOR;
			ulwp_broadcast(ulwp);
			if (!ulwp->ul_stop)
				force_continue(ulwp);
		}
		lmutex_unlock(mp);
	}

	lmutex_unlock(&udp->link_lock);
	fork_lock_exit();
	return (0);
}

/*
 * Resume a suspended mutator.
 */
#pragma weak _thr_continue_mutator = thr_continue_mutator
int
thr_continue_mutator(thread_t tid)
{
	return (_thrp_continue(tid, TSTP_MUTATOR));
}

#pragma weak _thr_wait_mutator = thr_wait_mutator
int
thr_wait_mutator(thread_t tid, int dontwait)
{
	uberdata_t *udp = curthread->ul_uberdata;
	ulwp_t *ulwp;
	int cancel_state;
	int error = 0;

	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
top:
	if ((ulwp = find_lwp(tid)) == NULL) {
		(void) pthread_setcancelstate(cancel_state, NULL);
		return (ESRCH);
	}

	if (!ulwp->ul_mutator)
		error = EINVAL;
	else if (dontwait) {
		if (!(ulwp->ul_stop & TSTP_MUTATOR))
			error = EWOULDBLOCK;
	} else if (!(ulwp->ul_stop & TSTP_MUTATOR)) {
		cond_t *cvp = ulwp_condvar(ulwp, udp);
		mutex_t *mp = ulwp_mutex(ulwp, udp);

		(void) cond_wait(cvp, mp);
		(void) lmutex_unlock(mp);
		goto top;
	}

	ulwp_unlock(ulwp, udp);
	(void) pthread_setcancelstate(cancel_state, NULL);
	return (error);
}

/* PROBE_SUPPORT begin */

void
thr_probe_setup(void *data)
{
	curthread->ul_tpdp = data;
}

static void *
_thread_probe_getfunc()
{
	return (curthread->ul_tpdp);
}

void * (*thr_probe_getfunc_addr)(void) = _thread_probe_getfunc;

/* ARGSUSED */
void
_resume(ulwp_t *ulwp, caddr_t sp, int dontsave)
{
	/* never called */
}

/* ARGSUSED */
void
_resume_ret(ulwp_t *oldlwp)
{
	/* never called */
}

/* PROBE_SUPPORT end */
