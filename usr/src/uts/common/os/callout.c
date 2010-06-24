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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/callo.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/kmem.h>
#include <sys/kmem_impl.h>
#include <sys/cmn_err.h>
#include <sys/callb.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>

int callout_init_done;				/* useful during boot */

/*
 * Callout tables.  See timeout(9F) for details.
 */
static int callout_threads;			/* callout normal threads */
static hrtime_t callout_debug_hrtime;		/* debugger entry time */
static int callout_chunk;			/* callout heap chunk size */
static int callout_min_reap;			/* callout minimum reap count */
static int callout_tolerance;			/* callout hires tolerance */
static callout_table_t *callout_boot_ct;	/* Boot CPU's callout tables */
static clock_t callout_max_ticks;		/* max interval */
static hrtime_t callout_longterm;		/* longterm nanoseconds */
static ulong_t callout_counter_low;		/* callout ID increment */
static ulong_t callout_table_bits;		/* number of table bits in ID */
static ulong_t callout_table_mask;		/* mask for the table bits */
static callout_cache_t *callout_caches;		/* linked list of caches */
#pragma align 64(callout_table)
static callout_table_t *callout_table;		/* global callout table array */

/*
 * We run 'realtime' callouts at PIL 1 (CY_LOW_LEVEL). For 'normal'
 * callouts, from PIL 10 (CY_LOCK_LEVEL) we dispatch the callout,
 * via taskq, to a thread that executes at PIL 0 - so we end up running
 * 'normal' callouts at PIL 0.
 */
static volatile int callout_realtime_level = CY_LOW_LEVEL;
static volatile int callout_normal_level = CY_LOCK_LEVEL;

static char *callout_kstat_names[] = {
	"callout_timeouts",
	"callout_timeouts_pending",
	"callout_untimeouts_unexpired",
	"callout_untimeouts_executing",
	"callout_untimeouts_expired",
	"callout_expirations",
	"callout_allocations",
	"callout_cleanups",
};

static hrtime_t	callout_heap_process(callout_table_t *, hrtime_t, int);

#define	CALLOUT_HASH_INSERT(hash, cp, cnext, cprev)	\
{							\
	callout_hash_t *hashp = &(hash);		\
							\
	cp->cprev = NULL;				\
	cp->cnext = hashp->ch_head;			\
	if (hashp->ch_head == NULL)			\
		hashp->ch_tail = cp;			\
	else						\
		cp->cnext->cprev = cp;			\
	hashp->ch_head = cp;				\
}

#define	CALLOUT_HASH_APPEND(hash, cp, cnext, cprev)	\
{							\
	callout_hash_t *hashp = &(hash);		\
							\
	cp->cnext = NULL;				\
	cp->cprev = hashp->ch_tail;			\
	if (hashp->ch_tail == NULL)			\
		hashp->ch_head = cp;			\
	else						\
		cp->cprev->cnext = cp;			\
	hashp->ch_tail = cp;				\
}

#define	CALLOUT_HASH_DELETE(hash, cp, cnext, cprev)	\
{							\
	callout_hash_t *hashp = &(hash);		\
							\
	if (cp->cnext == NULL)				\
		hashp->ch_tail = cp->cprev;		\
	else						\
		cp->cnext->cprev = cp->cprev;		\
	if (cp->cprev == NULL)				\
		hashp->ch_head = cp->cnext;		\
	else						\
		cp->cprev->cnext = cp->cnext;		\
}

/*
 * These definitions help us queue callouts and callout lists. Here is
 * the queueing rationale:
 *
 *	- callouts are queued in a FIFO manner in the ID hash table.
 *	  TCP timers are typically cancelled in the same order that they
 *	  were issued. The FIFO queueing shortens the search for a callout
 *	  during untimeout().
 *
 *	- callouts are queued in a FIFO manner in their callout lists.
 *	  This ensures that the callouts are executed in the same order that
 *	  they were queued. This is fair. Plus, it helps to make each
 *	  callout expiration timely. It also favors cancellations.
 *
 *	- callout lists are queued in the following manner in the callout
 *	  hash table buckets:
 *
 *		- appended, if the callout list is a 1-nanosecond resolution
 *		  callout list. When a callout is created, we first look for
 *		  a callout list that has the same expiration so we can avoid
 *		  allocating a callout list and inserting the expiration into
 *		  the heap. However, we do not want to look at 1-nanosecond
 *		  resolution callout lists as we will seldom find a match in
 *		  them. Keeping these callout lists in the rear of the hash
 *		  buckets allows us to skip these during the lookup.
 *
 *		- inserted at the beginning, if the callout list is not a
 *		  1-nanosecond resolution callout list. This also has the
 *		  side-effect of keeping the long term timers away from the
 *		  front of the buckets.
 *
 *	- callout lists are queued in a FIFO manner in the expired callouts
 *	  list. This ensures that callout lists are executed in the order
 *	  of expiration.
 */
#define	CALLOUT_APPEND(ct, cp)						\
	CALLOUT_HASH_APPEND(ct->ct_idhash[CALLOUT_IDHASH(cp->c_xid)],	\
		cp, c_idnext, c_idprev);				\
	CALLOUT_HASH_APPEND(cp->c_list->cl_callouts, cp, c_clnext, c_clprev)

#define	CALLOUT_DELETE(ct, cp)						\
	CALLOUT_HASH_DELETE(ct->ct_idhash[CALLOUT_IDHASH(cp->c_xid)],	\
		cp, c_idnext, c_idprev);				\
	CALLOUT_HASH_DELETE(cp->c_list->cl_callouts, cp, c_clnext, c_clprev)

#define	CALLOUT_LIST_INSERT(hash, cl)				\
	CALLOUT_HASH_INSERT(hash, cl, cl_next, cl_prev)

#define	CALLOUT_LIST_APPEND(hash, cl)				\
	CALLOUT_HASH_APPEND(hash, cl, cl_next, cl_prev)

#define	CALLOUT_LIST_DELETE(hash, cl)				\
	CALLOUT_HASH_DELETE(hash, cl, cl_next, cl_prev)

#define	CALLOUT_LIST_BEFORE(cl, nextcl)			\
{							\
	(cl)->cl_prev = (nextcl)->cl_prev;		\
	(cl)->cl_next = (nextcl);			\
	(nextcl)->cl_prev = (cl);			\
	if (cl->cl_prev != NULL)			\
		cl->cl_prev->cl_next = cl;		\
}

/*
 * For normal callouts, there is a deadlock scenario if two callouts that
 * have an inter-dependency end up on the same callout list. To break the
 * deadlock, you need two taskq threads running in parallel. We compute
 * the number of taskq threads here using a bunch of conditions to make
 * it optimal for the common case. This is an ugly hack, but one that is
 * necessary (sigh).
 */
#define	CALLOUT_THRESHOLD	100000000
#define	CALLOUT_EXEC_COMPUTE(ct, nextexp, exec)				\
{									\
	callout_list_t *cl;						\
									\
	cl = ct->ct_expired.ch_head;					\
	if (cl == NULL) {						\
		/*							\
		 * If the expired list is NULL, there is nothing to	\
		 * process.						\
		 */							\
		exec = 0;						\
	} else if ((cl->cl_next == NULL) &&				\
	    (cl->cl_callouts.ch_head == cl->cl_callouts.ch_tail)) {	\
		/*							\
		 * If there is only one callout list and it contains	\
		 * only one callout, there is no need for two threads.	\
		 */							\
		exec = 1;						\
	} else if ((nextexp) > (gethrtime() + CALLOUT_THRESHOLD)) {	\
		/*							\
		 * If the next expiration of the cyclic is way out into	\
		 * the future, we need two threads.			\
		 */							\
		exec = 2;						\
	} else {							\
		/*							\
		 * We have multiple callouts to process. But the cyclic	\
		 * will fire in the near future. So, we only need one	\
		 * thread for now.					\
		 */							\
		exec = 1;						\
	}								\
}

/*
 * Macro to swap two heap items.
 */
#define	CALLOUT_SWAP(h1, h2)		\
{					\
	callout_heap_t tmp;		\
					\
	tmp = *h1;			\
	*h1 = *h2;			\
	*h2 = tmp;			\
}

/*
 * Macro to free a callout list.
 */
#define	CALLOUT_LIST_FREE(ct, cl)			\
{							\
	cl->cl_next = ct->ct_lfree;			\
	ct->ct_lfree = cl;				\
	cl->cl_flags |= CALLOUT_LIST_FLAG_FREE;		\
}

/*
 * Macro to free a callout.
 */
#define	CALLOUT_FREE(ct, cl)			\
{						\
	cp->c_idnext = ct->ct_free;		\
	ct->ct_free = cp;			\
	cp->c_xid |= CALLOUT_ID_FREE;		\
}

/*
 * Allocate a callout structure.  We try quite hard because we
 * can't sleep, and if we can't do the allocation, we're toast.
 * Failing all, we try a KM_PANIC allocation. Note that we never
 * deallocate a callout. See untimeout() for the reasoning.
 */
static callout_t *
callout_alloc(callout_table_t *ct)
{
	size_t size;
	callout_t *cp;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	mutex_exit(&ct->ct_mutex);

	cp = kmem_cache_alloc(ct->ct_cache, KM_NOSLEEP);
	if (cp == NULL) {
		size = sizeof (callout_t);
		cp = kmem_alloc_tryhard(size, &size, KM_NOSLEEP | KM_PANIC);
	}
	cp->c_xid = 0;
	cp->c_executor = NULL;
	cv_init(&cp->c_done, NULL, CV_DEFAULT, NULL);
	cp->c_waiting = 0;

	mutex_enter(&ct->ct_mutex);
	ct->ct_allocations++;
	return (cp);
}

/*
 * Allocate a callout list structure.  We try quite hard because we
 * can't sleep, and if we can't do the allocation, we're toast.
 * Failing all, we try a KM_PANIC allocation. Note that we never
 * deallocate a callout list.
 */
static void
callout_list_alloc(callout_table_t *ct)
{
	size_t size;
	callout_list_t *cl;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	mutex_exit(&ct->ct_mutex);

	cl = kmem_cache_alloc(ct->ct_lcache, KM_NOSLEEP);
	if (cl == NULL) {
		size = sizeof (callout_list_t);
		cl = kmem_alloc_tryhard(size, &size, KM_NOSLEEP | KM_PANIC);
	}
	bzero(cl, sizeof (callout_list_t));

	mutex_enter(&ct->ct_mutex);
	CALLOUT_LIST_FREE(ct, cl);
}

/*
 * Find a callout list that corresponds to an expiration and matching flags.
 */
static callout_list_t *
callout_list_get(callout_table_t *ct, hrtime_t expiration, int flags, int hash)
{
	callout_list_t *cl;
	int clflags;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	if (flags & CALLOUT_LIST_FLAG_NANO) {
		/*
		 * This is a 1-nanosecond resolution callout. We will rarely
		 * find a match for this. So, bail out.
		 */
		return (NULL);
	}

	clflags = (CALLOUT_LIST_FLAG_ABSOLUTE | CALLOUT_LIST_FLAG_HRESTIME);
	for (cl = ct->ct_clhash[hash].ch_head; (cl != NULL); cl = cl->cl_next) {
		/*
		 * If we have reached a 1-nanosecond resolution callout list,
		 * we don't have much hope of finding a match in this hash
		 * bucket. So, just bail out.
		 */
		if (cl->cl_flags & CALLOUT_LIST_FLAG_NANO)
			return (NULL);

		if ((cl->cl_expiration == expiration) &&
		    ((cl->cl_flags & clflags) == (flags & clflags)))
			return (cl);
	}

	return (NULL);
}

/*
 * Add a new callout list into a callout table's queue in sorted order by
 * expiration.
 */
static int
callout_queue_add(callout_table_t *ct, callout_list_t *cl)
{
	callout_list_t *nextcl;
	hrtime_t expiration;

	expiration = cl->cl_expiration;
	nextcl = ct->ct_queue.ch_head;
	if ((nextcl == NULL) || (expiration < nextcl->cl_expiration)) {
		CALLOUT_LIST_INSERT(ct->ct_queue, cl);
		return (1);
	}

	while (nextcl != NULL) {
		if (expiration < nextcl->cl_expiration) {
			CALLOUT_LIST_BEFORE(cl, nextcl);
			return (0);
		}
		nextcl = nextcl->cl_next;
	}
	CALLOUT_LIST_APPEND(ct->ct_queue, cl);

	return (0);
}

/*
 * Insert a callout list into a callout table's queue and reprogram the queue
 * cyclic if needed.
 */
static void
callout_queue_insert(callout_table_t *ct, callout_list_t *cl)
{
	cl->cl_flags |= CALLOUT_LIST_FLAG_QUEUED;

	/*
	 * Add the callout to the callout queue. If it ends up at the head,
	 * the cyclic needs to be reprogrammed as we have an earlier
	 * expiration.
	 *
	 * Also, during the CPR suspend phase, do not reprogram the cyclic.
	 * We don't want any callout activity. When the CPR resume phase is
	 * entered, the cyclic will be programmed for the earliest expiration
	 * in the queue.
	 */
	if (callout_queue_add(ct, cl) && (ct->ct_suspend == 0))
		(void) cyclic_reprogram(ct->ct_qcyclic, cl->cl_expiration);
}

/*
 * Delete and handle all past expirations in a callout table's queue.
 */
static hrtime_t
callout_queue_delete(callout_table_t *ct)
{
	callout_list_t *cl;
	hrtime_t now;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	now = gethrtime();
	while ((cl = ct->ct_queue.ch_head) != NULL) {
		if (cl->cl_expiration > now)
			break;
		cl->cl_flags &= ~CALLOUT_LIST_FLAG_QUEUED;
		CALLOUT_LIST_DELETE(ct->ct_queue, cl);
		CALLOUT_LIST_APPEND(ct->ct_expired, cl);
	}

	/*
	 * If this callout queue is empty or callouts have been suspended,
	 * just return.
	 */
	if ((cl == NULL) || (ct->ct_suspend > 0))
		return (CY_INFINITY);

	(void) cyclic_reprogram(ct->ct_qcyclic, cl->cl_expiration);

	return (cl->cl_expiration);
}

static hrtime_t
callout_queue_process(callout_table_t *ct, hrtime_t delta, int timechange)
{
	callout_list_t *firstcl, *cl;
	hrtime_t expiration, now;
	int clflags;
	callout_hash_t temp;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	firstcl = ct->ct_queue.ch_head;
	if (firstcl == NULL)
		return (CY_INFINITY);

	/*
	 * We walk the callout queue. If we encounter a hrestime entry that
	 * must be removed, we clean it out. Otherwise, we apply any
	 * adjustments needed to it. Because of the latter, we need to
	 * recreate the list as we go along.
	 */
	temp = ct->ct_queue;
	ct->ct_queue.ch_head = NULL;
	ct->ct_queue.ch_tail = NULL;

	clflags = (CALLOUT_LIST_FLAG_HRESTIME | CALLOUT_LIST_FLAG_ABSOLUTE);
	now = gethrtime();
	while ((cl = temp.ch_head) != NULL) {
		CALLOUT_LIST_DELETE(temp, cl);

		/*
		 * Delete the callout and expire it, if one of the following
		 * is true:
		 *	- the callout has expired
		 *	- the callout is an absolute hrestime one and
		 *	  there has been a system time change
		 */
		if ((cl->cl_expiration <= now) ||
		    (timechange && ((cl->cl_flags & clflags) == clflags))) {
			cl->cl_flags &= ~CALLOUT_LIST_FLAG_QUEUED;
			CALLOUT_LIST_APPEND(ct->ct_expired, cl);
			continue;
		}

		/*
		 * Apply adjustments, if any. Adjustments are applied after
		 * the system returns from KMDB or OBP. They are only applied
		 * to relative callout lists.
		 */
		if (delta && !(cl->cl_flags & CALLOUT_LIST_FLAG_ABSOLUTE)) {
			expiration = cl->cl_expiration + delta;
			if (expiration <= 0)
				expiration = CY_INFINITY;
			cl->cl_expiration = expiration;
		}

		(void) callout_queue_add(ct, cl);
	}

	/*
	 * We need to return the expiration to help program the cyclic.
	 * If there are expired callouts, the cyclic needs to go off
	 * immediately. If the queue has become empty, then we return infinity.
	 * Else, we return the expiration of the earliest callout in the queue.
	 */
	if (ct->ct_expired.ch_head != NULL)
		return (gethrtime());

	cl = ct->ct_queue.ch_head;
	if (cl == NULL)
		return (CY_INFINITY);

	return (cl->cl_expiration);
}

/*
 * Initialize a callout table's heap, if necessary. Preallocate some free
 * entries so we don't have to check for NULL elsewhere.
 */
static void
callout_heap_init(callout_table_t *ct)
{
	size_t size;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_heap == NULL);

	ct->ct_heap_num = 0;
	ct->ct_heap_max = callout_chunk;
	size = sizeof (callout_heap_t) * callout_chunk;
	ct->ct_heap = kmem_alloc(size, KM_SLEEP);
}

/*
 * Reallocate the heap. Return 0 if the heap is still full at the end of it.
 * Return 1 otherwise. Note that the heap only expands, it never contracts.
 */
static int
callout_heap_expand(callout_table_t *ct)
{
	size_t max, size, osize;
	callout_heap_t *heap;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_heap_num <= ct->ct_heap_max);

	while (ct->ct_heap_num == ct->ct_heap_max) {
		max = ct->ct_heap_max;
		mutex_exit(&ct->ct_mutex);

		osize = sizeof (callout_heap_t) * max;
		size = sizeof (callout_heap_t) * (max + callout_chunk);
		heap = kmem_alloc(size, KM_NOSLEEP);

		mutex_enter(&ct->ct_mutex);
		if (heap == NULL) {
			/*
			 * We could not allocate memory. If we can free up
			 * some entries, that would be great.
			 */
			if (ct->ct_nreap > 0)
				(void) callout_heap_process(ct, 0, 0);
			/*
			 * If we still have no space in the heap, inform the
			 * caller.
			 */
			if (ct->ct_heap_num == ct->ct_heap_max)
				return (0);
			return (1);
		}
		if (max < ct->ct_heap_max) {
			/*
			 * Someone beat us to the allocation. Free what we
			 * just allocated and proceed.
			 */
			kmem_free(heap, size);
			continue;
		}

		bcopy(ct->ct_heap, heap, osize);
		kmem_free(ct->ct_heap, osize);
		ct->ct_heap = heap;
		ct->ct_heap_max = size / sizeof (callout_heap_t);
	}

	return (1);
}

/*
 * Move an expiration from the bottom of the heap to its correct place
 * in the heap. If we reached the root doing this, return 1. Else,
 * return 0.
 */
static int
callout_upheap(callout_table_t *ct)
{
	int current, parent;
	callout_heap_t *heap, *hcurrent, *hparent;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_heap_num >= 1);

	if (ct->ct_heap_num == 1) {
		return (1);
	}

	heap = ct->ct_heap;
	current = ct->ct_heap_num - 1;

	for (;;) {
		parent = CALLOUT_HEAP_PARENT(current);
		hparent = &heap[parent];
		hcurrent = &heap[current];

		/*
		 * We have an expiration later than our parent; we're done.
		 */
		if (hcurrent->ch_expiration >= hparent->ch_expiration) {
			return (0);
		}

		/*
		 * We need to swap with our parent, and continue up the heap.
		 */
		CALLOUT_SWAP(hparent, hcurrent);

		/*
		 * If we just reached the root, we're done.
		 */
		if (parent == 0) {
			return (1);
		}

		current = parent;
	}
	/*NOTREACHED*/
}

/*
 * Insert a new heap item into a callout table's heap.
 */
static void
callout_heap_insert(callout_table_t *ct, callout_list_t *cl)
{
	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_heap_num < ct->ct_heap_max);

	cl->cl_flags |= CALLOUT_LIST_FLAG_HEAPED;
	/*
	 * First, copy the expiration and callout list pointer to the bottom
	 * of the heap.
	 */
	ct->ct_heap[ct->ct_heap_num].ch_expiration = cl->cl_expiration;
	ct->ct_heap[ct->ct_heap_num].ch_list = cl;
	ct->ct_heap_num++;

	/*
	 * Now, perform an upheap operation. If we reached the root, then
	 * the cyclic needs to be reprogrammed as we have an earlier
	 * expiration.
	 *
	 * Also, during the CPR suspend phase, do not reprogram the cyclic.
	 * We don't want any callout activity. When the CPR resume phase is
	 * entered, the cyclic will be programmed for the earliest expiration
	 * in the heap.
	 */
	if (callout_upheap(ct) && (ct->ct_suspend == 0))
		(void) cyclic_reprogram(ct->ct_cyclic, cl->cl_expiration);
}

/*
 * Move an expiration from the top of the heap to its correct place
 * in the heap.
 */
static void
callout_downheap(callout_table_t *ct)
{
	int current, left, right, nelems;
	callout_heap_t *heap, *hleft, *hright, *hcurrent;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_heap_num >= 1);

	heap = ct->ct_heap;
	current = 0;
	nelems = ct->ct_heap_num;

	for (;;) {
		/*
		 * If we don't have a left child (i.e., we're a leaf), we're
		 * done.
		 */
		if ((left = CALLOUT_HEAP_LEFT(current)) >= nelems)
			return;

		hleft = &heap[left];
		hcurrent = &heap[current];

		right = CALLOUT_HEAP_RIGHT(current);

		/*
		 * Even if we don't have a right child, we still need to compare
		 * our expiration against that of our left child.
		 */
		if (right >= nelems)
			goto comp_left;

		hright = &heap[right];

		/*
		 * We have both a left and a right child.  We need to compare
		 * the expiration of the children to determine which
		 * expires earlier.
		 */
		if (hright->ch_expiration < hleft->ch_expiration) {
			/*
			 * Our right child is the earlier of our children.
			 * We'll now compare our expiration to its expiration.
			 * If ours is the earlier one, we're done.
			 */
			if (hcurrent->ch_expiration <= hright->ch_expiration)
				return;

			/*
			 * Our right child expires earlier than we do; swap
			 * with our right child, and descend right.
			 */
			CALLOUT_SWAP(hright, hcurrent);
			current = right;
			continue;
		}

comp_left:
		/*
		 * Our left child is the earlier of our children (or we have
		 * no right child).  We'll now compare our expiration
		 * to its expiration. If ours is the earlier one, we're done.
		 */
		if (hcurrent->ch_expiration <= hleft->ch_expiration)
			return;

		/*
		 * Our left child expires earlier than we do; swap with our
		 * left child, and descend left.
		 */
		CALLOUT_SWAP(hleft, hcurrent);
		current = left;
	}
}

/*
 * Delete and handle all past expirations in a callout table's heap.
 */
static hrtime_t
callout_heap_delete(callout_table_t *ct)
{
	hrtime_t now, expiration, next;
	callout_list_t *cl;
	callout_heap_t *heap;
	int hash;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	if (CALLOUT_CLEANUP(ct)) {
		/*
		 * There are too many heap elements pointing to empty callout
		 * lists. Clean them out.
		 */
		(void) callout_heap_process(ct, 0, 0);
	}

	now = gethrtime();
	heap = ct->ct_heap;

	while (ct->ct_heap_num > 0) {
		expiration = heap->ch_expiration;
		hash = CALLOUT_CLHASH(expiration);
		cl = heap->ch_list;
		ASSERT(expiration == cl->cl_expiration);

		if (cl->cl_callouts.ch_head == NULL) {
			/*
			 * If the callout list is empty, reap it.
			 * Decrement the reap count.
			 */
			CALLOUT_LIST_DELETE(ct->ct_clhash[hash], cl);
			CALLOUT_LIST_FREE(ct, cl);
			ct->ct_nreap--;
		} else {
			/*
			 * If the root of the heap expires in the future,
			 * bail out.
			 */
			if (expiration > now)
				break;

			/*
			 * Move the callout list for this expiration to the
			 * list of expired callout lists. It will be processed
			 * by the callout executor.
			 */
			cl->cl_flags &= ~CALLOUT_LIST_FLAG_HEAPED;
			CALLOUT_LIST_DELETE(ct->ct_clhash[hash], cl);
			CALLOUT_LIST_APPEND(ct->ct_expired, cl);
		}

		/*
		 * Now delete the root. This is done by swapping the root with
		 * the last item in the heap and downheaping the item.
		 */
		ct->ct_heap_num--;
		if (ct->ct_heap_num > 0) {
			heap[0] = heap[ct->ct_heap_num];
			callout_downheap(ct);
		}
	}

	/*
	 * If this callout table is empty or callouts have been suspended,
	 * just return. The cyclic has already been programmed to
	 * infinity by the cyclic subsystem.
	 */
	if ((ct->ct_heap_num == 0) || (ct->ct_suspend > 0))
		return (CY_INFINITY);

	/*
	 * If the top expirations are within callout_tolerance of each other,
	 * delay the cyclic expire so that they can be processed together.
	 * This is to prevent high resolution timers from swamping the system
	 * with cyclic activity.
	 */
	if (ct->ct_heap_num > 2) {
		next = expiration + callout_tolerance;
		if ((heap[1].ch_expiration < next) ||
		    (heap[2].ch_expiration < next))
			expiration = next;
	}

	(void) cyclic_reprogram(ct->ct_cyclic, expiration);

	return (expiration);
}

/*
 * There are some situations when the entire heap is walked and processed.
 * This function is called to do the processing. These are the situations:
 *
 * 1. When the reap count reaches its threshold, the heap has to be cleared
 *    of all empty callout lists.
 *
 * 2. When the system enters and exits KMDB/OBP, all entries in the heap
 *    need to be adjusted by the interval spent in KMDB/OBP.
 *
 * 3. When system time is changed, the heap has to be scanned for
 *    absolute hrestime timers. These need to be removed from the heap
 *    and expired immediately.
 *
 * In cases 2 and 3, it is a good idea to do 1 as well since we are
 * scanning the heap anyway.
 *
 * If the root gets changed and/or callout lists are expired, return the
 * new expiration to the caller so he can reprogram the cyclic accordingly.
 */
static hrtime_t
callout_heap_process(callout_table_t *ct, hrtime_t delta, int timechange)
{
	callout_heap_t *heap;
	callout_list_t *cl;
	hrtime_t expiration, now;
	int i, hash, clflags;
	ulong_t num;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	if (ct->ct_heap_num == 0)
		return (CY_INFINITY);

	if (ct->ct_nreap > 0)
		ct->ct_cleanups++;

	heap = ct->ct_heap;

	/*
	 * We walk the heap from the top to the bottom. If we encounter
	 * a heap item that points to an empty callout list, we clean
	 * it out. If we encounter a hrestime entry that must be removed,
	 * again we clean it out. Otherwise, we apply any adjustments needed
	 * to an element.
	 *
	 * During the walk, we also compact the heap from the bottom and
	 * reconstruct the heap using upheap operations. This is very
	 * efficient if the number of elements to be cleaned is greater than
	 * or equal to half the heap. This is the common case.
	 *
	 * Even in the non-common case, the upheap operations should be short
	 * as the entries below generally tend to be bigger than the entries
	 * above.
	 */
	num = ct->ct_heap_num;
	ct->ct_heap_num = 0;
	clflags = (CALLOUT_LIST_FLAG_HRESTIME | CALLOUT_LIST_FLAG_ABSOLUTE);
	now = gethrtime();
	for (i = 0; i < num; i++) {
		cl = heap[i].ch_list;
		/*
		 * If the callout list is empty, delete the heap element and
		 * free the callout list.
		 */
		if (cl->cl_callouts.ch_head == NULL) {
			hash = CALLOUT_CLHASH(cl->cl_expiration);
			CALLOUT_LIST_DELETE(ct->ct_clhash[hash], cl);
			CALLOUT_LIST_FREE(ct, cl);
			continue;
		}

		/*
		 * Delete the heap element and expire the callout list, if
		 * one of the following is true:
		 *	- the callout list has expired
		 *	- the callout list is an absolute hrestime one and
		 *	  there has been a system time change
		 */
		if ((cl->cl_expiration <= now) ||
		    (timechange && ((cl->cl_flags & clflags) == clflags))) {
			hash = CALLOUT_CLHASH(cl->cl_expiration);
			cl->cl_flags &= ~CALLOUT_LIST_FLAG_HEAPED;
			CALLOUT_LIST_DELETE(ct->ct_clhash[hash], cl);
			CALLOUT_LIST_APPEND(ct->ct_expired, cl);
			continue;
		}

		/*
		 * Apply adjustments, if any. Adjustments are applied after
		 * the system returns from KMDB or OBP. They are only applied
		 * to relative callout lists.
		 */
		if (delta && !(cl->cl_flags & CALLOUT_LIST_FLAG_ABSOLUTE)) {
			hash = CALLOUT_CLHASH(cl->cl_expiration);
			CALLOUT_LIST_DELETE(ct->ct_clhash[hash], cl);
			expiration = cl->cl_expiration + delta;
			if (expiration <= 0)
				expiration = CY_INFINITY;
			heap[i].ch_expiration = expiration;
			cl->cl_expiration = expiration;
			hash = CALLOUT_CLHASH(cl->cl_expiration);
			if (cl->cl_flags & CALLOUT_LIST_FLAG_NANO) {
				CALLOUT_LIST_APPEND(ct->ct_clhash[hash], cl);
			} else {
				CALLOUT_LIST_INSERT(ct->ct_clhash[hash], cl);
			}
		}

		heap[ct->ct_heap_num] = heap[i];
		ct->ct_heap_num++;
		(void) callout_upheap(ct);
	}

	ct->ct_nreap = 0;

	/*
	 * We need to return the expiration to help program the cyclic.
	 * If there are expired callouts, the cyclic needs to go off
	 * immediately. If the heap has become empty, then we return infinity.
	 * Else, return the expiration of the earliest callout in the heap.
	 */
	if (ct->ct_expired.ch_head != NULL)
		return (gethrtime());

	if (ct->ct_heap_num == 0)
		return (CY_INFINITY);

	return (heap->ch_expiration);
}

/*
 * Common function used to create normal and realtime callouts.
 *
 * Realtime callouts are handled at CY_LOW_PIL by a cyclic handler. So,
 * there is one restriction on a realtime callout handler - it should not
 * directly or indirectly acquire cpu_lock. CPU offline waits for pending
 * cyclic handlers to complete while holding cpu_lock. So, if a realtime
 * callout handler were to try to get cpu_lock, there would be a deadlock
 * during CPU offline.
 */
callout_id_t
timeout_generic(int type, void (*func)(void *), void *arg,
	hrtime_t expiration, hrtime_t resolution, int flags)
{
	callout_table_t *ct;
	callout_t *cp;
	callout_id_t id;
	callout_list_t *cl;
	hrtime_t now, interval;
	int hash, clflags;

	ASSERT(resolution > 0);
	ASSERT(func != NULL);

	/*
	 * We get the current hrtime right upfront so that latencies in
	 * this function do not affect the accuracy of the callout.
	 */
	now = gethrtime();

	/*
	 * We disable kernel preemption so that we remain on the same CPU
	 * throughout. If we needed to reprogram the callout table's cyclic,
	 * we can avoid X-calls if we are on the same CPU.
	 *
	 * Note that callout_alloc() releases and reacquires the callout
	 * table mutex. While reacquiring the mutex, it is possible for us
	 * to go to sleep and later migrate to another CPU. This should be
	 * pretty rare, though.
	 */
	kpreempt_disable();

	ct = &callout_table[CALLOUT_TABLE(type, CPU->cpu_seqid)];
	mutex_enter(&ct->ct_mutex);

	if (ct->ct_cyclic == CYCLIC_NONE) {
		mutex_exit(&ct->ct_mutex);
		/*
		 * The callout table has not yet been initialized fully.
		 * So, put this one on the boot callout table which is
		 * always initialized.
		 */
		ct = &callout_boot_ct[type];
		mutex_enter(&ct->ct_mutex);
	}

	if (CALLOUT_CLEANUP(ct)) {
		/*
		 * There are too many heap elements pointing to empty callout
		 * lists. Clean them out. Since cleanup is only done once
		 * in a while, no need to reprogram the cyclic if the root
		 * of the heap gets cleaned out.
		 */
		(void) callout_heap_process(ct, 0, 0);
	}

	if ((cp = ct->ct_free) == NULL)
		cp = callout_alloc(ct);
	else
		ct->ct_free = cp->c_idnext;

	cp->c_func = func;
	cp->c_arg = arg;

	/*
	 * Compute the expiration hrtime.
	 */
	if (flags & CALLOUT_FLAG_ABSOLUTE) {
		interval = expiration - now;
	} else {
		interval = expiration;
		expiration += now;
	}

	if (resolution > 1) {
		/*
		 * Align expiration to the specified resolution.
		 */
		if (flags & CALLOUT_FLAG_ROUNDUP)
			expiration += resolution - 1;
		expiration = (expiration / resolution) * resolution;
	}

	if (expiration <= 0) {
		/*
		 * expiration hrtime overflow has occurred. Just set the
		 * expiration to infinity.
		 */
		expiration = CY_INFINITY;
	}

	/*
	 * Assign an ID to this callout
	 */
	if (flags & CALLOUT_FLAG_32BIT) {
		if (interval > callout_longterm) {
			id = (ct->ct_long_id - callout_counter_low);
			id |= CALLOUT_COUNTER_HIGH;
			ct->ct_long_id = id;
		} else {
			id = (ct->ct_short_id - callout_counter_low);
			id |= CALLOUT_COUNTER_HIGH;
			ct->ct_short_id = id;
		}
	} else {
		id = (ct->ct_gen_id - callout_counter_low);
		if ((id & CALLOUT_COUNTER_HIGH) == 0) {
			id |= CALLOUT_COUNTER_HIGH;
			id += CALLOUT_GENERATION_LOW;
		}
		ct->ct_gen_id = id;
	}

	cp->c_xid = id;

	clflags = 0;
	if (flags & CALLOUT_FLAG_ABSOLUTE)
		clflags |= CALLOUT_LIST_FLAG_ABSOLUTE;
	if (flags & CALLOUT_FLAG_HRESTIME)
		clflags |= CALLOUT_LIST_FLAG_HRESTIME;
	if (resolution == 1)
		clflags |= CALLOUT_LIST_FLAG_NANO;
	hash = CALLOUT_CLHASH(expiration);

again:
	/*
	 * Try to see if a callout list already exists for this expiration.
	 */
	cl = callout_list_get(ct, expiration, clflags, hash);
	if (cl == NULL) {
		/*
		 * Check the free list. If we don't find one, we have to
		 * take the slow path and allocate from kmem.
		 */
		if ((cl = ct->ct_lfree) == NULL) {
			callout_list_alloc(ct);
			/*
			 * In the above call, we drop the lock, allocate and
			 * reacquire the lock. So, we could have been away
			 * for a while. In the meantime, someone could have
			 * inserted a callout list with the same expiration.
			 * Plus, the heap could have become full. So, the best
			 * course is to repeat the steps. This should be an
			 * infrequent event.
			 */
			goto again;
		}
		ct->ct_lfree = cl->cl_next;
		cl->cl_expiration = expiration;
		cl->cl_flags = clflags;

		/*
		 * Check if we have enough space in the heap to insert one
		 * expiration. If not, expand the heap.
		 */
		if (ct->ct_heap_num == ct->ct_heap_max) {
			if (callout_heap_expand(ct) == 0) {
				/*
				 * Could not expand the heap. Just queue it.
				 */
				callout_queue_insert(ct, cl);
				goto out;
			}

			/*
			 * In the above call, we drop the lock, allocate and
			 * reacquire the lock. So, we could have been away
			 * for a while. In the meantime, someone could have
			 * inserted a callout list with the same expiration.
			 * But we will not go back and check for it as this
			 * should be a really infrequent event. There is no
			 * point.
			 */
		}

		if (clflags & CALLOUT_LIST_FLAG_NANO) {
			CALLOUT_LIST_APPEND(ct->ct_clhash[hash], cl);
		} else {
			CALLOUT_LIST_INSERT(ct->ct_clhash[hash], cl);
		}

		/*
		 * This is a new expiration. So, insert it into the heap.
		 * This will also reprogram the cyclic, if the expiration
		 * propagated to the root of the heap.
		 */
		callout_heap_insert(ct, cl);
	} else {
		/*
		 * If the callout list was empty, untimeout_generic() would
		 * have incremented a reap count. Decrement the reap count
		 * as we are going to insert a callout into this list.
		 */
		if (cl->cl_callouts.ch_head == NULL)
			ct->ct_nreap--;
	}
out:
	cp->c_list = cl;
	CALLOUT_APPEND(ct, cp);

	ct->ct_timeouts++;
	ct->ct_timeouts_pending++;

	mutex_exit(&ct->ct_mutex);

	kpreempt_enable();

	TRACE_4(TR_FAC_CALLOUT, TR_TIMEOUT,
	    "timeout:%K(%p) in %llx expiration, cp %p", func, arg, expiration,
	    cp);

	return (id);
}

timeout_id_t
timeout(void (*func)(void *), void *arg, clock_t delta)
{
	ulong_t id;

	/*
	 * Make sure the callout runs at least 1 tick in the future.
	 */
	if (delta <= 0)
		delta = 1;
	else if (delta > callout_max_ticks)
		delta = callout_max_ticks;

	id =  (ulong_t)timeout_generic(CALLOUT_NORMAL, func, arg,
	    TICK_TO_NSEC(delta), nsec_per_tick, CALLOUT_LEGACY);

	return ((timeout_id_t)id);
}

/*
 * Convenience function that creates a normal callout with default parameters
 * and returns a full ID.
 */
callout_id_t
timeout_default(void (*func)(void *), void *arg, clock_t delta)
{
	callout_id_t id;

	/*
	 * Make sure the callout runs at least 1 tick in the future.
	 */
	if (delta <= 0)
		delta = 1;
	else if (delta > callout_max_ticks)
		delta = callout_max_ticks;

	id = timeout_generic(CALLOUT_NORMAL, func, arg, TICK_TO_NSEC(delta),
	    nsec_per_tick, 0);

	return (id);
}

timeout_id_t
realtime_timeout(void (*func)(void *), void *arg, clock_t delta)
{
	ulong_t id;

	/*
	 * Make sure the callout runs at least 1 tick in the future.
	 */
	if (delta <= 0)
		delta = 1;
	else if (delta > callout_max_ticks)
		delta = callout_max_ticks;

	id =  (ulong_t)timeout_generic(CALLOUT_REALTIME, func, arg,
	    TICK_TO_NSEC(delta), nsec_per_tick, CALLOUT_LEGACY);

	return ((timeout_id_t)id);
}

/*
 * Convenience function that creates a realtime callout with default parameters
 * and returns a full ID.
 */
callout_id_t
realtime_timeout_default(void (*func)(void *), void *arg, clock_t delta)
{
	callout_id_t id;

	/*
	 * Make sure the callout runs at least 1 tick in the future.
	 */
	if (delta <= 0)
		delta = 1;
	else if (delta > callout_max_ticks)
		delta = callout_max_ticks;

	id = timeout_generic(CALLOUT_REALTIME, func, arg, TICK_TO_NSEC(delta),
	    nsec_per_tick, 0);

	return (id);
}

hrtime_t
untimeout_generic(callout_id_t id, int nowait)
{
	callout_table_t *ct;
	callout_t *cp;
	callout_id_t xid;
	callout_list_t *cl;
	int hash, flags;
	callout_id_t bogus;

	ct = &callout_table[CALLOUT_ID_TO_TABLE(id)];
	hash = CALLOUT_IDHASH(id);

	mutex_enter(&ct->ct_mutex);

	/*
	 * Search the ID hash table for the callout.
	 */
	for (cp = ct->ct_idhash[hash].ch_head; cp; cp = cp->c_idnext) {

		xid = cp->c_xid;

		/*
		 * Match the ID and generation number.
		 */
		if ((xid & CALLOUT_ID_MASK) != id)
			continue;

		if ((xid & CALLOUT_EXECUTING) == 0) {
			hrtime_t expiration;

			/*
			 * Delete the callout. If the callout list becomes
			 * NULL, we don't remove it from the table. This is
			 * so it can be reused. If the empty callout list
			 * corresponds to the top of the the callout heap, we
			 * don't reprogram the table cyclic here. This is in
			 * order to avoid lots of X-calls to the CPU associated
			 * with the callout table.
			 */
			cl = cp->c_list;
			expiration = cl->cl_expiration;
			CALLOUT_DELETE(ct, cp);
			CALLOUT_FREE(ct, cp);
			ct->ct_untimeouts_unexpired++;
			ct->ct_timeouts_pending--;

			/*
			 * If the callout list has become empty, there are 3
			 * possibilities. If it is present:
			 *	- in the heap, it needs to be cleaned along
			 *	  with its heap entry. Increment a reap count.
			 *	- in the callout queue, free it.
			 *	- in the expired list, free it.
			 */
			if (cl->cl_callouts.ch_head == NULL) {
				flags = cl->cl_flags;
				if (flags & CALLOUT_LIST_FLAG_HEAPED) {
					ct->ct_nreap++;
				} else if (flags & CALLOUT_LIST_FLAG_QUEUED) {
					CALLOUT_LIST_DELETE(ct->ct_queue, cl);
					CALLOUT_LIST_FREE(ct, cl);
				} else {
					CALLOUT_LIST_DELETE(ct->ct_expired, cl);
					CALLOUT_LIST_FREE(ct, cl);
				}
			}
			mutex_exit(&ct->ct_mutex);

			expiration -= gethrtime();
			TRACE_2(TR_FAC_CALLOUT, TR_UNTIMEOUT,
			    "untimeout:ID %lx hrtime left %llx", id,
			    expiration);
			return (expiration < 0 ? 0 : expiration);
		}

		ct->ct_untimeouts_executing++;
		/*
		 * The callout we want to delete is currently executing.
		 * The DDI states that we must wait until the callout
		 * completes before returning, so we block on c_done until the
		 * callout ID changes (to the old ID if it's on the freelist,
		 * or to a new callout ID if it's in use).  This implicitly
		 * assumes that callout structures are persistent (they are).
		 */
		if (cp->c_executor == curthread) {
			/*
			 * The timeout handler called untimeout() on itself.
			 * Stupid, but legal.  We can't wait for the timeout
			 * to complete without deadlocking, so we just return.
			 */
			mutex_exit(&ct->ct_mutex);
			TRACE_1(TR_FAC_CALLOUT, TR_UNTIMEOUT_SELF,
			    "untimeout_self:ID %x", id);
			return (-1);
		}
		if (nowait == 0) {
			/*
			 * We need to wait. Indicate that we are waiting by
			 * incrementing c_waiting. This prevents the executor
			 * from doing a wakeup on c_done if there are no
			 * waiters.
			 */
			while (cp->c_xid == xid) {
				cp->c_waiting = 1;
				cv_wait(&cp->c_done, &ct->ct_mutex);
			}
		}
		mutex_exit(&ct->ct_mutex);
		TRACE_1(TR_FAC_CALLOUT, TR_UNTIMEOUT_EXECUTING,
		    "untimeout_executing:ID %lx", id);
		return (-1);
	}
	ct->ct_untimeouts_expired++;

	mutex_exit(&ct->ct_mutex);
	TRACE_1(TR_FAC_CALLOUT, TR_UNTIMEOUT_BOGUS_ID,
	    "untimeout_bogus_id:ID %lx", id);

	/*
	 * We didn't find the specified callout ID.  This means either
	 * (1) the callout already fired, or (2) the caller passed us
	 * a bogus value.  Perform a sanity check to detect case (2).
	 */
	bogus = (CALLOUT_ID_FLAGS | CALLOUT_COUNTER_HIGH);
	if (((id & bogus) != CALLOUT_COUNTER_HIGH) && (id != 0))
		panic("untimeout: impossible timeout id %llx",
		    (unsigned long long)id);

	return (-1);
}

clock_t
untimeout(timeout_id_t id_arg)
{
	hrtime_t hleft;
	clock_t tleft;
	callout_id_t id;

	id = (ulong_t)id_arg;
	hleft = untimeout_generic(id, 0);
	if (hleft < 0)
		tleft = -1;
	else if (hleft == 0)
		tleft = 0;
	else
		tleft = NSEC_TO_TICK(hleft);

	return (tleft);
}

/*
 * Convenience function to untimeout a timeout with a full ID with default
 * parameters.
 */
clock_t
untimeout_default(callout_id_t id, int nowait)
{
	hrtime_t hleft;
	clock_t tleft;

	hleft = untimeout_generic(id, nowait);
	if (hleft < 0)
		tleft = -1;
	else if (hleft == 0)
		tleft = 0;
	else
		tleft = NSEC_TO_TICK(hleft);

	return (tleft);
}

/*
 * Expire all the callouts queued in the specified callout list.
 */
static void
callout_list_expire(callout_table_t *ct, callout_list_t *cl)
{
	callout_t *cp, *cnext;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(cl != NULL);

	for (cp = cl->cl_callouts.ch_head; cp != NULL; cp = cnext) {
		/*
		 * Multiple executor threads could be running at the same
		 * time. If this callout is already being executed,
		 * go on to the next one.
		 */
		if (cp->c_xid & CALLOUT_EXECUTING) {
			cnext = cp->c_clnext;
			continue;
		}

		/*
		 * Indicate to untimeout() that a callout is
		 * being expired by the executor.
		 */
		cp->c_xid |= CALLOUT_EXECUTING;
		cp->c_executor = curthread;
		mutex_exit(&ct->ct_mutex);

		DTRACE_PROBE1(callout__start, callout_t *, cp);
		(*cp->c_func)(cp->c_arg);
		DTRACE_PROBE1(callout__end, callout_t *, cp);

		mutex_enter(&ct->ct_mutex);

		ct->ct_expirations++;
		ct->ct_timeouts_pending--;
		/*
		 * Indicate completion for c_done.
		 */
		cp->c_xid &= ~CALLOUT_EXECUTING;
		cp->c_executor = NULL;
		cnext = cp->c_clnext;

		/*
		 * Delete callout from ID hash table and the callout
		 * list, return to freelist, and tell any untimeout() that
		 * cares that we're done.
		 */
		CALLOUT_DELETE(ct, cp);
		CALLOUT_FREE(ct, cp);

		if (cp->c_waiting) {
			cp->c_waiting = 0;
			cv_broadcast(&cp->c_done);
		}
	}
}

/*
 * Execute all expired callout lists for a callout table.
 */
static void
callout_expire(callout_table_t *ct)
{
	callout_list_t *cl, *clnext;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	for (cl = ct->ct_expired.ch_head; (cl != NULL); cl = clnext) {
		/*
		 * Expire all the callouts in this callout list.
		 */
		callout_list_expire(ct, cl);

		clnext = cl->cl_next;
		if (cl->cl_callouts.ch_head == NULL) {
			/*
			 * Free the callout list.
			 */
			CALLOUT_LIST_DELETE(ct->ct_expired, cl);
			CALLOUT_LIST_FREE(ct, cl);
		}
	}
}

/*
 * The cyclic handlers below process callouts in two steps:
 *
 *	1. Find all expired callout lists and queue them in a separate
 *	   list of expired callouts.
 *	2. Execute the expired callout lists.
 *
 * This is done for two reasons:
 *
 *	1. We want to quickly find the next earliest expiration to program
 *	   the cyclic to and reprogram it. We can do this right at the end
 *	   of step 1.
 *	2. The realtime cyclic handler expires callouts in place. However,
 *	   for normal callouts, callouts are expired by a taskq thread.
 *	   So, it is simpler and more robust to have the taskq thread just
 *	   do step 2.
 */

/*
 * Realtime callout cyclic handlers.
 */
void
callout_realtime(callout_table_t *ct)
{
	mutex_enter(&ct->ct_mutex);
	(void) callout_heap_delete(ct);
	callout_expire(ct);
	mutex_exit(&ct->ct_mutex);
}

void
callout_queue_realtime(callout_table_t *ct)
{
	mutex_enter(&ct->ct_mutex);
	(void) callout_queue_delete(ct);
	callout_expire(ct);
	mutex_exit(&ct->ct_mutex);
}

void
callout_execute(callout_table_t *ct)
{
	mutex_enter(&ct->ct_mutex);
	callout_expire(ct);
	mutex_exit(&ct->ct_mutex);
}

/*
 * Normal callout cyclic handlers.
 */
void
callout_normal(callout_table_t *ct)
{
	int i, exec;
	hrtime_t exp;

	mutex_enter(&ct->ct_mutex);
	exp = callout_heap_delete(ct);
	CALLOUT_EXEC_COMPUTE(ct, exp, exec);
	mutex_exit(&ct->ct_mutex);

	for (i = 0; i < exec; i++) {
		ASSERT(ct->ct_taskq != NULL);
		(void) taskq_dispatch(ct->ct_taskq,
		    (task_func_t *)callout_execute, ct, TQ_NOSLEEP);
	}
}

void
callout_queue_normal(callout_table_t *ct)
{
	int i, exec;
	hrtime_t exp;

	mutex_enter(&ct->ct_mutex);
	exp = callout_queue_delete(ct);
	CALLOUT_EXEC_COMPUTE(ct, exp, exec);
	mutex_exit(&ct->ct_mutex);

	for (i = 0; i < exec; i++) {
		ASSERT(ct->ct_taskq != NULL);
		(void) taskq_dispatch(ct->ct_taskq,
		    (task_func_t *)callout_execute, ct, TQ_NOSLEEP);
	}
}

/*
 * Suspend callout processing.
 */
static void
callout_suspend(void)
{
	int t, f;
	callout_table_t *ct;

	/*
	 * Traverse every callout table in the system and suspend callout
	 * processing.
	 *
	 * We need to suspend all the tables (including the inactive ones)
	 * so that if a table is made active while the suspend is still on,
	 * the table remains suspended.
	 */
	for (f = 0; f < max_ncpus; f++) {
		for (t = 0; t < CALLOUT_NTYPES; t++) {
			ct = &callout_table[CALLOUT_TABLE(t, f)];

			mutex_enter(&ct->ct_mutex);
			ct->ct_suspend++;
			if (ct->ct_cyclic == CYCLIC_NONE) {
				mutex_exit(&ct->ct_mutex);
				continue;
			}
			if (ct->ct_suspend == 1) {
				(void) cyclic_reprogram(ct->ct_cyclic,
				    CY_INFINITY);
				(void) cyclic_reprogram(ct->ct_qcyclic,
				    CY_INFINITY);
			}
			mutex_exit(&ct->ct_mutex);
		}
	}
}

/*
 * Resume callout processing.
 */
static void
callout_resume(hrtime_t delta, int timechange)
{
	hrtime_t hexp, qexp;
	int t, f;
	callout_table_t *ct;

	/*
	 * Traverse every callout table in the system and resume callout
	 * processing. For active tables, perform any hrtime adjustments
	 * necessary.
	 */
	for (f = 0; f < max_ncpus; f++) {
		for (t = 0; t < CALLOUT_NTYPES; t++) {
			ct = &callout_table[CALLOUT_TABLE(t, f)];

			mutex_enter(&ct->ct_mutex);
			if (ct->ct_cyclic == CYCLIC_NONE) {
				ct->ct_suspend--;
				mutex_exit(&ct->ct_mutex);
				continue;
			}

			/*
			 * If a delta is specified, adjust the expirations in
			 * the heap by delta. Also, if the caller indicates
			 * a timechange, process that. This step also cleans
			 * out any empty callout lists that might happen to
			 * be there.
			 */
			hexp = callout_heap_process(ct, delta, timechange);
			qexp = callout_queue_process(ct, delta, timechange);

			ct->ct_suspend--;
			if (ct->ct_suspend == 0) {
				(void) cyclic_reprogram(ct->ct_cyclic, hexp);
				(void) cyclic_reprogram(ct->ct_qcyclic, qexp);
			}

			mutex_exit(&ct->ct_mutex);
		}
	}
}

/*
 * Callback handler used by CPR to stop and resume callouts.
 * The cyclic subsystem saves and restores hrtime during CPR.
 * That is why callout_resume() is called with a 0 delta.
 * Although hrtime is the same, hrestime (system time) has
 * progressed during CPR. So, we have to indicate a time change
 * to expire the absolute hrestime timers.
 */
/*ARGSUSED*/
static boolean_t
callout_cpr_callb(void *arg, int code)
{
	if (code == CB_CODE_CPR_CHKPT)
		callout_suspend();
	else
		callout_resume(0, 1);

	return (B_TRUE);
}

/*
 * Callback handler invoked when the debugger is entered or exited.
 */
/*ARGSUSED*/
static boolean_t
callout_debug_callb(void *arg, int code)
{
	hrtime_t delta;

	/*
	 * When the system enters the debugger. make a note of the hrtime.
	 * When it is resumed, compute how long the system was in the
	 * debugger. This interval should not be counted for callouts.
	 */
	if (code == 0) {
		callout_suspend();
		callout_debug_hrtime = gethrtime();
	} else {
		delta = gethrtime() - callout_debug_hrtime;
		callout_resume(delta, 0);
	}

	return (B_TRUE);
}

/*
 * Move the absolute hrestime callouts to the expired list. Then program the
 * table's cyclic to expire immediately so that the callouts can be executed
 * immediately.
 */
static void
callout_hrestime_one(callout_table_t *ct)
{
	hrtime_t hexp, qexp;

	mutex_enter(&ct->ct_mutex);
	if (ct->ct_cyclic == CYCLIC_NONE) {
		mutex_exit(&ct->ct_mutex);
		return;
	}

	/*
	 * Walk the heap and process all the absolute hrestime entries.
	 */
	hexp = callout_heap_process(ct, 0, 1);
	qexp = callout_queue_process(ct, 0, 1);

	if (ct->ct_suspend == 0) {
		(void) cyclic_reprogram(ct->ct_cyclic, hexp);
		(void) cyclic_reprogram(ct->ct_qcyclic, qexp);
	}

	mutex_exit(&ct->ct_mutex);
}

/*
 * This function is called whenever system time (hrestime) is changed
 * explicitly. All the HRESTIME callouts must be expired at once.
 */
/*ARGSUSED*/
void
callout_hrestime(void)
{
	int t, f;
	callout_table_t *ct;

	/*
	 * Traverse every callout table in the system and process the hrestime
	 * callouts therein.
	 *
	 * We look at all the tables because we don't know which ones were
	 * onlined and offlined in the past. The offlined tables may still
	 * have active cyclics processing timers somewhere.
	 */
	for (f = 0; f < max_ncpus; f++) {
		for (t = 0; t < CALLOUT_NTYPES; t++) {
			ct = &callout_table[CALLOUT_TABLE(t, f)];
			callout_hrestime_one(ct);
		}
	}
}

/*
 * Create the hash tables for this callout table.
 */
static void
callout_hash_init(callout_table_t *ct)
{
	size_t size;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT((ct->ct_idhash == NULL) && (ct->ct_clhash == NULL));

	size = sizeof (callout_hash_t) * CALLOUT_BUCKETS;
	ct->ct_idhash = kmem_zalloc(size, KM_SLEEP);
	ct->ct_clhash = kmem_zalloc(size, KM_SLEEP);
}

/*
 * Create per-callout table kstats.
 */
static void
callout_kstat_init(callout_table_t *ct)
{
	callout_stat_type_t stat;
	kstat_t *ct_kstats;
	int ndx;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_kstats == NULL);

	ndx = ct - callout_table;
	ct_kstats = kstat_create("unix", ndx, "callout",
	    "misc", KSTAT_TYPE_NAMED, CALLOUT_NUM_STATS, KSTAT_FLAG_VIRTUAL);

	if (ct_kstats == NULL) {
		cmn_err(CE_WARN, "kstat_create for callout table %p failed",
		    (void *)ct);
	} else {
		ct_kstats->ks_data = ct->ct_kstat_data;
		for (stat = 0; stat < CALLOUT_NUM_STATS; stat++)
			kstat_named_init(&ct->ct_kstat_data[stat],
			    callout_kstat_names[stat], KSTAT_DATA_INT64);
		ct->ct_kstats = ct_kstats;
		kstat_install(ct_kstats);
	}
}

static void
callout_cyclic_init(callout_table_t *ct)
{
	cyc_handler_t hdlr;
	cyc_time_t when;
	processorid_t seqid;
	int t;
	cyclic_id_t cyclic, qcyclic;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	t = ct->ct_type;
	seqid = CALLOUT_TABLE_SEQID(ct);

	/*
	 * Create the taskq thread if the table type is normal.
	 * Realtime tables are handled at PIL1 by a softint
	 * handler.
	 */
	if (t == CALLOUT_NORMAL) {
		ASSERT(ct->ct_taskq == NULL);
		/*
		 * Each callout thread consumes exactly one
		 * task structure while active.  Therefore,
		 * prepopulating with 2 * callout_threads tasks
		 * ensures that there's at least one task per
		 * thread that's either scheduled or on the
		 * freelist.  In turn, this guarantees that
		 * taskq_dispatch() will always either succeed
		 * (because there's a free task structure) or
		 * be unnecessary (because "callout_excute(ct)"
		 * has already scheduled).
		 */
		ct->ct_taskq =
		    taskq_create_instance("callout_taskq", seqid,
		    callout_threads, maxclsyspri,
		    2 * callout_threads, 2 * callout_threads,
		    TASKQ_PREPOPULATE | TASKQ_CPR_SAFE);
	}

	/*
	 * callouts can only be created in a table whose
	 * cyclic has been initialized.
	 */
	ASSERT(ct->ct_heap_num == 0);

	/*
	 * Drop the mutex before creating the callout cyclics. cyclic_add()
	 * could potentially expand the cyclic heap. We don't want to be
	 * holding the callout table mutex in that case. Note that this
	 * function is called during CPU online. cpu_lock is held at this
	 * point. So, only one thread can be executing the cyclic add logic
	 * below at any time.
	 */
	mutex_exit(&ct->ct_mutex);

	/*
	 * Create the callout table cyclics.
	 *
	 * The realtime cyclic handler executes at low PIL. The normal cyclic
	 * handler executes at lock PIL. This is because there are cases
	 * where code can block at PIL > 1 waiting for a normal callout handler
	 * to unblock it directly or indirectly. If the normal cyclic were to
	 * be executed at low PIL, it could get blocked out by the waiter
	 * and cause a deadlock.
	 */
	ASSERT(ct->ct_cyclic == CYCLIC_NONE);

	if (t == CALLOUT_REALTIME) {
		hdlr.cyh_level = callout_realtime_level;
		hdlr.cyh_func = (cyc_func_t)callout_realtime;
	} else {
		hdlr.cyh_level = callout_normal_level;
		hdlr.cyh_func = (cyc_func_t)callout_normal;
	}
	hdlr.cyh_arg = ct;
	when.cyt_when = CY_INFINITY;
	when.cyt_interval = CY_INFINITY;

	cyclic = cyclic_add(&hdlr, &when);

	if (t == CALLOUT_REALTIME)
		hdlr.cyh_func = (cyc_func_t)callout_queue_realtime;
	else
		hdlr.cyh_func = (cyc_func_t)callout_queue_normal;

	qcyclic = cyclic_add(&hdlr, &when);

	mutex_enter(&ct->ct_mutex);
	ct->ct_cyclic = cyclic;
	ct->ct_qcyclic = qcyclic;
}

void
callout_cpu_online(cpu_t *cp)
{
	lgrp_handle_t hand;
	callout_cache_t *cache;
	char s[KMEM_CACHE_NAMELEN];
	callout_table_t *ct;
	processorid_t seqid;
	int t;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Locate the cache corresponding to the onlined CPU's lgroup.
	 * Note that access to callout_caches is protected by cpu_lock.
	 */
	hand = lgrp_plat_cpu_to_hand(cp->cpu_id);
	for (cache = callout_caches; cache != NULL; cache = cache->cc_next) {
		if (cache->cc_hand == hand)
			break;
	}

	/*
	 * If not found, create one. The caches are never destroyed.
	 */
	if (cache == NULL) {
		cache = kmem_alloc(sizeof (callout_cache_t), KM_SLEEP);
		cache->cc_hand = hand;
		(void) snprintf(s, KMEM_CACHE_NAMELEN, "callout_cache%lx",
		    (long)hand);
		cache->cc_cache = kmem_cache_create(s, sizeof (callout_t),
		    CALLOUT_ALIGN, NULL, NULL, NULL, NULL, NULL, 0);
		(void) snprintf(s, KMEM_CACHE_NAMELEN, "callout_lcache%lx",
		    (long)hand);
		cache->cc_lcache = kmem_cache_create(s, sizeof (callout_list_t),
		    CALLOUT_ALIGN, NULL, NULL, NULL, NULL, NULL, 0);
		cache->cc_next = callout_caches;
		callout_caches = cache;
	}

	seqid = cp->cpu_seqid;

	for (t = 0; t < CALLOUT_NTYPES; t++) {
		ct = &callout_table[CALLOUT_TABLE(t, seqid)];

		mutex_enter(&ct->ct_mutex);
		/*
		 * Store convinience pointers to the kmem caches
		 * in the callout table. These assignments should always be
		 * done as callout tables can map to different physical
		 * CPUs each time.
		 */
		ct->ct_cache = cache->cc_cache;
		ct->ct_lcache = cache->cc_lcache;

		/*
		 * We use the heap pointer to check if stuff has been
		 * initialized for this callout table.
		 */
		if (ct->ct_heap == NULL) {
			callout_heap_init(ct);
			callout_hash_init(ct);
			callout_kstat_init(ct);
			callout_cyclic_init(ct);
		}

		mutex_exit(&ct->ct_mutex);

		/*
		 * Move the cyclics to this CPU by doing a bind.
		 */
		cyclic_bind(ct->ct_cyclic, cp, NULL);
		cyclic_bind(ct->ct_qcyclic, cp, NULL);
	}
}

void
callout_cpu_offline(cpu_t *cp)
{
	callout_table_t *ct;
	processorid_t seqid;
	int t;

	ASSERT(MUTEX_HELD(&cpu_lock));

	seqid = cp->cpu_seqid;

	for (t = 0; t < CALLOUT_NTYPES; t++) {
		ct = &callout_table[CALLOUT_TABLE(t, seqid)];

		/*
		 * Unbind the cyclics. This will allow the cyclic subsystem
		 * to juggle the cyclics during CPU offline.
		 */
		cyclic_bind(ct->ct_cyclic, NULL, NULL);
		cyclic_bind(ct->ct_qcyclic, NULL, NULL);
	}
}

/*
 * This is called to perform per-CPU initialization for slave CPUs at
 * boot time.
 */
void
callout_mp_init(void)
{
	cpu_t *cp;
	size_t min, max;

	if (callout_chunk == CALLOUT_CHUNK) {
		/*
		 * No one has specified a chunk in /etc/system. We need to
		 * compute it here based on the number of online CPUs and
		 * available physical memory.
		 */
		min = CALLOUT_MIN_HEAP_SIZE;
		max = ptob(physmem / CALLOUT_MEM_FRACTION);
		if (min > max)
			min = max;
		callout_chunk = min / sizeof (callout_heap_t);
		callout_chunk /= ncpus_online;
		callout_chunk = P2ROUNDUP(callout_chunk, CALLOUT_CHUNK);
	}

	mutex_enter(&cpu_lock);

	cp = cpu_active;
	do {
		callout_cpu_online(cp);
	} while ((cp = cp->cpu_next_onln) != cpu_active);

	mutex_exit(&cpu_lock);
}

/*
 * Initialize all callout tables.  Called at boot time just before clkstart().
 */
void
callout_init(void)
{
	int f, t;
	size_t size;
	int table_id;
	callout_table_t *ct;
	long bits, fanout;
	uintptr_t buf;

	/*
	 * Initialize callout globals.
	 */
	bits = 0;
	for (fanout = 1; (fanout < max_ncpus); fanout <<= 1)
		bits++;
	callout_table_bits = CALLOUT_TYPE_BITS + bits;
	callout_table_mask = (1 << callout_table_bits) - 1;
	callout_counter_low = 1 << CALLOUT_COUNTER_SHIFT;
	callout_longterm = TICK_TO_NSEC(CALLOUT_LONGTERM_TICKS);
	callout_max_ticks = CALLOUT_MAX_TICKS;
	if (callout_min_reap == 0)
		callout_min_reap = CALLOUT_MIN_REAP;

	if (callout_tolerance <= 0)
		callout_tolerance = CALLOUT_TOLERANCE;
	if (callout_threads <= 0)
		callout_threads = CALLOUT_THREADS;
	if (callout_chunk <= 0)
		callout_chunk = CALLOUT_CHUNK;
	else
		callout_chunk = P2ROUNDUP(callout_chunk, CALLOUT_CHUNK);

	/*
	 * Allocate all the callout tables based on max_ncpus. We have chosen
	 * to do boot-time allocation instead of dynamic allocation because:
	 *
	 *	- the size of the callout tables is not too large.
	 *	- there are race conditions involved in making this dynamic.
	 *	- the hash tables that go with the callout tables consume
	 *	  most of the memory and they are only allocated in
	 *	  callout_cpu_online().
	 *
	 * Each CPU has two tables that are consecutive in the array. The first
	 * one is for realtime callouts and the second one is for normal ones.
	 *
	 * We do this alignment dance to make sure that callout table
	 * structures will always be on a cache line boundary.
	 */
	size = sizeof (callout_table_t) * CALLOUT_NTYPES * max_ncpus;
	size += CALLOUT_ALIGN;
	buf = (uintptr_t)kmem_zalloc(size, KM_SLEEP);
	callout_table = (callout_table_t *)P2ROUNDUP(buf, CALLOUT_ALIGN);

	size = sizeof (kstat_named_t) * CALLOUT_NUM_STATS;
	/*
	 * Now, initialize the tables for all the CPUs.
	 */
	for (f = 0; f < max_ncpus; f++) {
		for (t = 0; t < CALLOUT_NTYPES; t++) {
			table_id = CALLOUT_TABLE(t, f);
			ct = &callout_table[table_id];
			ct->ct_type = t;
			mutex_init(&ct->ct_mutex, NULL, MUTEX_DEFAULT, NULL);
			/*
			 * Precompute the base IDs for long and short-term
			 * legacy IDs. This makes ID generation during
			 * timeout() fast.
			 */
			ct->ct_short_id = CALLOUT_SHORT_ID(table_id);
			ct->ct_long_id = CALLOUT_LONG_ID(table_id);
			/*
			 * Precompute the base ID for generation-based IDs.
			 * Note that when the first ID gets allocated, the
			 * ID will wrap. This will cause the generation
			 * number to be incremented to 1.
			 */
			ct->ct_gen_id = CALLOUT_SHORT_ID(table_id);
			/*
			 * Initialize the cyclics as NONE. This will get set
			 * during CPU online. This is so that partially
			 * populated systems will only have the required
			 * number of cyclics, not more.
			 */
			ct->ct_cyclic = CYCLIC_NONE;
			ct->ct_qcyclic = CYCLIC_NONE;
			ct->ct_kstat_data = kmem_zalloc(size, KM_SLEEP);
		}
	}

	/*
	 * Add the callback for CPR. This is called during checkpoint
	 * resume to suspend and resume callouts.
	 */
	(void) callb_add(callout_cpr_callb, 0, CB_CL_CPR_CALLOUT,
	    "callout_cpr");
	(void) callb_add(callout_debug_callb, 0, CB_CL_ENTER_DEBUGGER,
	    "callout_debug");

	/*
	 * Call the per-CPU initialization function for the boot CPU. This
	 * is done here because the function is not called automatically for
	 * the boot CPU from the CPU online/offline hooks. Note that the
	 * CPU lock is taken here because of convention.
	 */
	mutex_enter(&cpu_lock);
	callout_boot_ct = &callout_table[CALLOUT_TABLE(0, CPU->cpu_seqid)];
	callout_cpu_online(CPU);
	mutex_exit(&cpu_lock);

	/* heads-up to boot-time clients that timeouts now available */
	callout_init_done = 1;
}
