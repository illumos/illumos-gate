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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

/*
 * Callout tables.  See timeout(9F) for details.
 */
static hrtime_t callout_debug_hrtime;		/* debugger entry time */
static int callout_min_resolution;		/* Minimum resolution */
static callout_table_t *callout_boot_ct;	/* Boot CPU's callout tables */
static clock_t callout_max_ticks;		/* max interval */
static hrtime_t callout_longterm;		/* longterm nanoseconds */
static ulong_t callout_counter_low;		/* callout ID increment */
static ulong_t callout_table_bits;		/* number of table bits in ID */
static ulong_t callout_table_mask;		/* mask for the table bits */
static callout_cache_t *callout_caches;		/* linked list of caches */
#pragma align 64(callout_table)
static callout_table_t *callout_table;		/* global callout table array */

static char *callout_kstat_names[] = {
	"callout_timeouts",
	"callout_timeouts_pending",
	"callout_untimeouts_unexpired",
	"callout_untimeouts_executing",
	"callout_untimeouts_expired",
	"callout_expirations",
	"callout_allocations",
};

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
 *	- callout lists are queued in a LIFO manner in the callout list hash
 *	  table. This ensures that long term timers stay at the rear of the
 *	  hash lists.
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
	cl->cl_next = ct->ct_lfree;
	ct->ct_lfree = cl;
}

/*
 * Find the callout list that corresponds to an expiration. There can
 * be only one.
 */
static callout_list_t *
callout_list_get(callout_table_t *ct, hrtime_t expiration, int hash)
{
	callout_list_t *cl;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	for (cl = ct->ct_clhash[hash].ch_head; (cl != NULL); cl = cl->cl_next) {
		if (cl->cl_expiration == expiration)
			return (cl);
	}

	return (NULL);
}

/*
 * Find the callout list that corresponds to an expiration. There can
 * be only one. If the callout list is null, free it. Else, return it.
 */
static callout_list_t *
callout_list_check(callout_table_t *ct, hrtime_t expiration, int hash)
{
	callout_list_t *cl;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	cl = callout_list_get(ct, expiration, hash);
	if (cl != NULL) {
		if (cl->cl_callouts.ch_head != NULL) {
			/*
			 * There is exactly one callout list for every
			 * unique expiration. So, we are done.
			 */
			return (cl);
		}

		CALLOUT_LIST_DELETE(ct->ct_clhash[hash], cl);
		cl->cl_next = ct->ct_lfree;
		ct->ct_lfree = cl;
	}

	return (NULL);
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
	ct->ct_heap_max = CALLOUT_CHUNK;
	size = sizeof (hrtime_t) * CALLOUT_CHUNK;
	ct->ct_heap = kmem_alloc(size, KM_SLEEP);
}

/*
 * Reallocate the heap. We try quite hard because we can't sleep, and if
 * we can't do the allocation, we're toast. Failing all, we try a KM_PANIC
 * allocation. Note that the heap only expands, it never contracts.
 */
static void
callout_heap_expand(callout_table_t *ct)
{
	size_t max, size, osize;
	hrtime_t *heap;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_heap_num <= ct->ct_heap_max);

	while (ct->ct_heap_num == ct->ct_heap_max) {
		max = ct->ct_heap_max;
		mutex_exit(&ct->ct_mutex);

		osize = sizeof (hrtime_t) * max;
		size = sizeof (hrtime_t) * (max + CALLOUT_CHUNK);
		heap = kmem_alloc_tryhard(size, &size, KM_NOSLEEP | KM_PANIC);

		mutex_enter(&ct->ct_mutex);
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
		ct->ct_heap_max = size / sizeof (hrtime_t);
	}
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
	hrtime_t *heap, current_expiration, parent_expiration;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_heap_num >= 1);

	if (ct->ct_heap_num == 1) {
		return (1);
	}

	heap = ct->ct_heap;
	current = ct->ct_heap_num - 1;

	for (;;) {
		parent = CALLOUT_HEAP_PARENT(current);
		current_expiration = heap[current];
		parent_expiration = heap[parent];

		/*
		 * We have an expiration later than our parent; we're done.
		 */
		if (current_expiration >= parent_expiration) {
			return (0);
		}

		/*
		 * We need to swap with our parent, and continue up the heap.
		 */
		heap[parent] = current_expiration;
		heap[current] = parent_expiration;

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
 * Insert a new, unique expiration into a callout table's heap.
 */
static void
callout_heap_insert(callout_table_t *ct, hrtime_t expiration)
{
	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(ct->ct_heap_num < ct->ct_heap_max);

	/*
	 * First, copy the expiration to the bottom of the heap.
	 */
	ct->ct_heap[ct->ct_heap_num] = expiration;
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
		(void) cyclic_reprogram(ct->ct_cyclic, expiration);
}

/*
 * Move an expiration from the top of the heap to its correct place
 * in the heap.
 */
static void
callout_downheap(callout_table_t *ct)
{
	int left, right, current, nelems;
	hrtime_t *heap, left_expiration, right_expiration, current_expiration;

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

		left_expiration = heap[left];
		current_expiration = heap[current];

		right = CALLOUT_HEAP_RIGHT(current);

		/*
		 * Even if we don't have a right child, we still need to compare
		 * our expiration against that of our left child.
		 */
		if (right >= nelems)
			goto comp_left;

		right_expiration = heap[right];

		/*
		 * We have both a left and a right child.  We need to compare
		 * the expiration of the children to determine which
		 * expires earlier.
		 */
		if (right_expiration < left_expiration) {
			/*
			 * Our right child is the earlier of our children.
			 * We'll now compare our expiration to its expiration.
			 * If ours is the earlier one, we're done.
			 */
			if (current_expiration <= right_expiration)
				return;

			/*
			 * Our right child expires earlier than we do; swap
			 * with our right child, and descend right.
			 */
			heap[right] = current_expiration;
			heap[current] = right_expiration;
			current = right;
			continue;
		}

comp_left:
		/*
		 * Our left child is the earlier of our children (or we have
		 * no right child).  We'll now compare our expiration
		 * to its expiration. If ours is the earlier one, we're done.
		 */
		if (current_expiration <= left_expiration)
			return;

		/*
		 * Our left child expires earlier than we do; swap with our
		 * left child, and descend left.
		 */
		heap[left] = current_expiration;
		heap[current] = left_expiration;
		current = left;
	}
}

/*
 * Delete and handle all past expirations in a callout table's heap.
 */
static void
callout_heap_delete(callout_table_t *ct)
{
	hrtime_t now, expiration;
	callout_list_t *cl;
	int hash;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	now = gethrtime();

	while (ct->ct_heap_num > 0) {
		expiration = ct->ct_heap[0];
		/*
		 * Find the callout list that corresponds to the expiration.
		 * If the callout list is empty, callout_list_check()
		 * will free the callout list and return NULL.
		 */
		hash = CALLOUT_CLHASH(expiration);
		cl = callout_list_check(ct, expiration, hash);
		if (cl != NULL) {
			/*
			 * If the root of the heap expires in the future, we are
			 * done. We are doing this check here instead of at the
			 * beginning because we want to first free all the
			 * empty callout lists at the top of the heap.
			 */
			if (expiration > now)
				break;

			/*
			 * Move the callout list for this expiration to the
			 * list of expired callout lists. It will be processed
			 * by the callout executor.
			 */
			CALLOUT_LIST_DELETE(ct->ct_clhash[hash], cl);
			CALLOUT_LIST_APPEND(ct->ct_expired, cl);
		}

		/*
		 * Now delete the root. This is done by swapping the root with
		 * the last item in the heap and downheaping the item.
		 */
		ct->ct_heap_num--;
		if (ct->ct_heap_num > 0) {
			ct->ct_heap[0] = ct->ct_heap[ct->ct_heap_num];
			callout_downheap(ct);
		}
	}

	/*
	 * If this callout table is empty or callouts have been suspended
	 * by CPR, just return. The cyclic has already been programmed to
	 * infinity by the cyclic subsystem.
	 */
	if ((ct->ct_heap_num == 0) || (ct->ct_suspend > 0))
		return;

	(void) cyclic_reprogram(ct->ct_cyclic, expiration);
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
	int hash;

	ASSERT(resolution > 0);
	ASSERT(func != NULL);

	/*
	 * Please see comment about minimum resolution in callout_init().
	 */
	if (resolution < callout_min_resolution)
		resolution = callout_min_resolution;

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

	if ((cp = ct->ct_free) == NULL)
		cp = callout_alloc(ct);
	else
		ct->ct_free = cp->c_idnext;

	cp->c_func = func;
	cp->c_arg = arg;

	/*
	 * Compute the expiration hrtime.
	 */
	now = gethrtime();
	if (flags & CALLOUT_FLAG_ABSOLUTE) {
		ASSERT(expiration > 0);
		interval = expiration - now;
	} else {
		interval = expiration;
		expiration += now;
		ASSERT(expiration > 0);
	}
	if (flags & CALLOUT_FLAG_ROUNDUP)
		expiration += resolution - 1;
	expiration = (expiration / resolution) * resolution;
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
	if (flags & CALLOUT_FLAG_HRESTIME)
		cp->c_xid |= CALLOUT_HRESTIME;

	hash = CALLOUT_CLHASH(expiration);

again:
	/*
	 * Try to see if a callout list already exists for this expiration.
	 * Most of the time, this will be the case.
	 */
	cl = callout_list_get(ct, expiration, hash);
	if (cl == NULL) {
		/*
		 * Check if we have enough space in the heap to insert one
		 * expiration. If not, expand the heap.
		 */
		if (ct->ct_heap_num == ct->ct_heap_max) {
			callout_heap_expand(ct);
			/*
			 * In the above call, we drop the lock, allocate and
			 * reacquire the lock. So, we could have been away
			 * for a while. In the meantime, someone could have
			 * inserted a callout list with the same expiration.
			 * So, the best course is to repeat the steps. This
			 * should be an infrequent event.
			 */
			goto again;
		}

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

		CALLOUT_LIST_INSERT(ct->ct_clhash[hash], cl);

		/*
		 * This is a new expiration. So, insert it into the heap.
		 * This will also reprogram the cyclic, if the expiration
		 * propagated to the root of the heap.
		 */
		callout_heap_insert(ct, expiration);
	}
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
	int hash;
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

		cl = cp->c_list;
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
			expiration = cl->cl_expiration;
			CALLOUT_DELETE(ct, cp);
			cp->c_idnext = ct->ct_free;
			ct->ct_free = cp;
			ct->ct_untimeouts_unexpired++;
			ct->ct_timeouts_pending--;
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
		 * completes before returning, so we block on cl_done until the
		 * callout ID changes (to the old ID if it's on the freelist,
		 * or to a new callout ID if it's in use).  This implicitly
		 * assumes that callout structures are persistent (they are).
		 */
		if (cl->cl_executor == curthread) {
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
			 * incrementing cl_waiting. This prevents the executor
			 * from doing a wakeup on cl_done if there are no
			 * waiters.
			 */
			while (cp->c_xid == xid) {
				cl->cl_waiting = 1;
				cv_wait(&cl->cl_done, &ct->ct_mutex);
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
	bogus = (CALLOUT_EXECUTING | CALLOUT_HRESTIME | CALLOUT_COUNTER_HIGH);
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
	callout_t *cp;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));
	ASSERT(cl != NULL);

	cl->cl_executor = curthread;

	while ((cp = cl->cl_callouts.ch_head) != NULL) {
		/*
		 * Indicate to untimeout() that a callout is
		 * being expired by the executor.
		 */
		cp->c_xid |= CALLOUT_EXECUTING;
		mutex_exit(&ct->ct_mutex);

		DTRACE_PROBE1(callout__start, callout_t *, cp);
		(*cp->c_func)(cp->c_arg);
		DTRACE_PROBE1(callout__end, callout_t *, cp);

		mutex_enter(&ct->ct_mutex);

		ct->ct_expirations++;
		ct->ct_timeouts_pending--;
		/*
		 * Indicate completion for cl_done.
		 */
		cp->c_xid &= ~CALLOUT_EXECUTING;

		/*
		 * Delete callout from ID hash table and the callout
		 * list, return to freelist, and tell any untimeout() that
		 * cares that we're done.
		 */
		CALLOUT_DELETE(ct, cp);
		cp->c_idnext = ct->ct_free;
		ct->ct_free = cp;

		if (cl->cl_waiting) {
			cl->cl_waiting = 0;
			cv_broadcast(&cl->cl_done);
		}
	}

	cl->cl_executor = NULL;
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
		 * Multiple executor threads could be running at the same
		 * time. Each callout list is processed by only one thread.
		 * If this callout list is already being processed by another
		 * executor, go on to the next one.
		 */
		if (cl->cl_executor != NULL) {
			clnext = cl->cl_next;
			continue;
		}

		/*
		 * Expire all the callouts in this callout list.
		 */
		callout_list_expire(ct, cl);

		/*
		 * Free the callout list.
		 */
		clnext = cl->cl_next;
		CALLOUT_LIST_DELETE(ct->ct_expired, cl);
		cl->cl_next = ct->ct_lfree;
		ct->ct_lfree = cl;
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
 * Realtime callout cyclic handler.
 */
void
callout_realtime(callout_table_t *ct)
{
	mutex_enter(&ct->ct_mutex);
	callout_heap_delete(ct);
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
 * Normal callout cyclic handler.
 */
void
callout_normal(callout_table_t *ct)
{
	int exec;

	mutex_enter(&ct->ct_mutex);
	callout_heap_delete(ct);
	exec = (ct->ct_expired.ch_head != NULL);
	mutex_exit(&ct->ct_mutex);

	if (exec) {
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
			if (ct->ct_suspend == 1)
				(void) cyclic_reprogram(ct->ct_cyclic,
				    CY_INFINITY);
			mutex_exit(&ct->ct_mutex);
		}
	}
}

static void
callout_adjust(callout_table_t *ct, hrtime_t delta)
{
	int hash, newhash;
	hrtime_t expiration;
	callout_list_t *cl;
	callout_hash_t list;

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	/*
	 * In order to adjust the expirations, we null out the heap. Then,
	 * we reinsert adjusted expirations in the heap. Keeps it simple.
	 * Note that since the CALLOUT_TABLE_SUSPENDED flag is set by the
	 * caller, the heap insert does not result in cyclic reprogramming.
	 */
	ct->ct_heap_num = 0;

	/*
	 * First, remove all the callout lists from the table and string them
	 * in a list.
	 */
	list.ch_head = list.ch_tail = NULL;
	for (hash = 0; hash < CALLOUT_BUCKETS; hash++) {
		while ((cl = ct->ct_clhash[hash].ch_head) != NULL) {
			CALLOUT_LIST_DELETE(ct->ct_clhash[hash], cl);
			CALLOUT_LIST_APPEND(list, cl);
		}
	}

	/*
	 * Now, traverse the callout lists and adjust their expirations.
	 */
	while ((cl = list.ch_head) != NULL) {
		CALLOUT_LIST_DELETE(list, cl);
		/*
		 * Set the new expiration and reinsert in the right
		 * hash bucket.
		 */
		expiration = cl->cl_expiration;
		expiration += delta;
		cl->cl_expiration = expiration;
		newhash = CALLOUT_CLHASH(expiration);
		CALLOUT_LIST_INSERT(ct->ct_clhash[newhash], cl);
		callout_heap_insert(ct, expiration);
	}
}

/*
 * Resume callout processing.
 */
static void
callout_resume(hrtime_t delta)
{
	hrtime_t exp;
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

			if (delta)
				callout_adjust(ct, delta);

			ct->ct_suspend--;
			if (ct->ct_suspend == 0) {
				/*
				 * If the expired list is non-empty, then have
				 * the cyclic expire immediately. Else, program
				 * the cyclic based on the heap.
				 */
				if (ct->ct_expired.ch_head != NULL)
					exp = gethrtime();
				else if (ct->ct_heap_num > 0)
					exp = ct->ct_heap[0];
				else
					exp = 0;
				if (exp != 0)
					(void) cyclic_reprogram(ct->ct_cyclic,
					    exp);
			}
			mutex_exit(&ct->ct_mutex);
		}
	}
}

/*
 * Callback handler used by CPR to stop and resume callouts.
 */
/*ARGSUSED*/
static boolean_t
callout_cpr_callb(void *arg, int code)
{
	if (code == CB_CODE_CPR_CHKPT)
		callout_suspend();
	else
		callout_resume(0);

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
		callout_resume(delta);
	}

	return (B_TRUE);
}

/*
 * Move the hrestime callouts to the expired list. Then program the table's
 * cyclic to expire immediately so that the callouts can be executed
 * immediately.
 */
static void
callout_hrestime_one(callout_table_t *ct)
{
	callout_list_t *cl, *ecl;
	callout_t *cp;
	int hash;

	mutex_enter(&ct->ct_mutex);
	if (ct->ct_heap_num == 0) {
		mutex_exit(&ct->ct_mutex);
		return;
	}

	if (ct->ct_lfree == NULL)
		callout_list_alloc(ct);
	ecl = ct->ct_lfree;
	ct->ct_lfree = ecl->cl_next;

	for (hash = 0; hash < CALLOUT_BUCKETS; hash++) {
		for (cl = ct->ct_clhash[hash].ch_head; cl; cl = cl->cl_next) {
			for (cp = cl->cl_callouts.ch_head; cp;
			    cp = cp->c_clnext) {
				if ((cp->c_xid & CALLOUT_HRESTIME) == 0)
					continue;
				CALLOUT_HASH_DELETE(cl->cl_callouts, cp,
				    c_clnext, c_clprev);
				cp->c_list = ecl;
				CALLOUT_HASH_APPEND(ecl->cl_callouts, cp,
				    c_clnext, c_clprev);
			}
		}
	}

	if (ecl->cl_callouts.ch_head != NULL) {
		CALLOUT_LIST_APPEND(ct->ct_expired, ecl);
		if (ct->ct_suspend == 0)
			(void) cyclic_reprogram(ct->ct_cyclic, gethrtime());
	} else {
		ecl->cl_next = ct->ct_lfree;
		ct->ct_lfree = ecl;
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

	ASSERT(MUTEX_HELD(&ct->ct_mutex));

	t = CALLOUT_TABLE_TYPE(ct);
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
		 * prepopulating with 2 * CALLOUT_THREADS tasks
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
		    CALLOUT_THREADS, maxclsyspri,
		    2 * CALLOUT_THREADS, 2 * CALLOUT_THREADS,
		    TASKQ_PREPOPULATE | TASKQ_CPR_SAFE);
	}

	/*
	 * callouts can only be created in a table whose
	 * cyclic has been initialized.
	 */
	ASSERT(ct->ct_heap_num == 0);

	/*
	 * Create the callout table cyclics.
	 */
	ASSERT(ct->ct_cyclic == CYCLIC_NONE);

	hdlr.cyh_func = (cyc_func_t)CALLOUT_CYCLIC_HANDLER(t);
	hdlr.cyh_level = CY_LOW_LEVEL;
	hdlr.cyh_arg = ct;
	when.cyt_when = CY_INFINITY;
	when.cyt_interval = CY_INFINITY;

	ct->ct_cyclic = cyclic_add(&hdlr, &when);
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
		 * Move the cyclic to this CPU by doing a bind.
		 */
		cyclic_bind(ct->ct_cyclic, cp, NULL);
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
		 * Unbind the cyclic. This will allow the cyclic subsystem
		 * to juggle the cyclic during CPU offline.
		 */
		cyclic_bind(ct->ct_cyclic, NULL, NULL);
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

	/*
	 * Because of the variability in timing behavior across systems with
	 * different architectures, we cannot allow arbitrarily low
	 * resolutions. The minimum resolution has to be determined in a
	 * platform-specific way. Until then, we define a blanket minimum
	 * resolution for callouts of CALLOUT_MIN_RESOLUTION.
	 *
	 * If, in the future, someone requires lower resolution timers, they
	 * can do one of two things:
	 *
	 *	- Define a lower value for callout_min_resolution. This would
	 *	  affect all clients of the callout subsystem. If this done
	 *	  via /etc/system, then no code changes are required and it
	 *	  would affect only that customer.
	 *
	 *	- Define a flag to be passed to timeout creation that allows
	 *	  the lower resolution. This involves code changes. But it
	 *	  would affect only the calling module. It is the developer's
	 *	  responsibility to test on all systems and make sure that
	 *	  everything works.
	 */
	if (callout_min_resolution <= 0)
		callout_min_resolution = CALLOUT_MIN_RESOLUTION;

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
			 * Initialize the cyclic as NONE. This will get set
			 * during CPU online. This is so that partially
			 * populated systems will only have the required
			 * number of cyclics, not more.
			 */
			ct->ct_cyclic = CYCLIC_NONE;
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
}
