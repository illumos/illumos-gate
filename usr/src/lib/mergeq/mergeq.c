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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Merge queue
 *
 * A multi-threaded merging queue.
 *
 * The general constraint of the merge queue is that if a set of items are
 * inserted into the queue in the same order, then no matter how many threads
 * are on the scene, we will always process the items in the same order. The
 * secondary constraint is that to support environments that must be
 * single-threaded, we explicitly *must not* create a thread in the case where
 * the number of requested threads is just one.
 *
 * To that end, we've designed our queue as a circular buffer. We will grow that
 * buffer to contain enough space for all the input items, after which we'll
 * then treat it as a circular buffer.
 *
 * Items will be issued to a processing function two at a time, until there is
 * only one item remaining in the queue, at which point we will be doing any
 * merging work.
 *
 * A given queue has three different entries that we care about tracking:
 *
 * o mq_nproc   - What is the slot of the next item to process for something
 *                looking for work.
 *
 * o mq_next    - What is the slot of the next item that should be inserted into
 *                the queue.
 *
 * o mq_ncommit - What is the slot of the next item that should be committed.
 *
 * When a thread comes and looks for work, we pop entries off of the queue based
 * on the index provided by mq_nproc. At the same time, it also gets the slot
 * that it should place the result in, which is mq_next. However, because we
 * have multiple threads that are operating on the system, we want to make sure
 * that we push things onto the queue in order. We do that by allocating a slot
 * to each task and when it completes, it waits for its slot to be ready based
 * on it being the value of mq_ncommit.
 *
 * In addition, we keep track of the number of items in the queue as well as the
 * number of active workers. There's also a generation count that is used to
 * figure out when the various values might lap one another.
 *
 * The following images show what happens when we have a queue with six items
 * and whose capacity has been shrunk to six, to better fit in the screen.
 *
 *
 * 1) This is the initial configuration of the queue right before any processing
 * is done in the context of mergeq_merge(). Every box has an initial item for
 * merging in it (represented by an 'x'). Here, the mq_nproc, mq_next, and
 * mq_ncommit will all point at the initial entry. However, the mq_next has
 * already lapped around the array and thus has a generation count of one.
 *
 * The '+' characters indicate which bucket the corresponding value of mq_nproc,
 * mq_ncommit, and mq_nproc.
 *
 *                     +---++---++---++---++---++---+
 *                     | X || X || X || X || X || X |
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)   +
 *     mq_ncommit (g0)   +
 *       mq_nproc (g0)   +
 *
 * 2) This shows the state right as the first thread begins to process an entry.
 * Note in this example we will have two threads processing this queue. Note,
 * mq_ncommit has not advanced. This is because the first thread has started
 * processing entries, but it has not finished, and thus we can't commit it.
 * We've incremented mq_next by one because it has gone ahead and assigned a
 * single entry. We've incremented mq_nproc by two, because we have removed two
 * entries and thus will have another set available.
 *
 *                     +---++---++---++---++---++---+     t1 - slot 0
 *                     |   ||   || X || X || X || X |     t2 - idle
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)        +
 *     mq_ncommit (g0)   +
 *       mq_nproc (g0)             +
 *
 *
 * 3) This shows the state right after the second thread begins to process an
 * entry, note that the first thread has not finished. The changes are very
 * similar to the previous state, we've advanced, mq_nproc and mq_next, but not
 * mq_ncommit.
 *
 *                     +---++---++---++---++---++---+     t1 - slot 0
 *                     |   ||   ||   ||   || X || X |     t2 - slot 1
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)             +
 *     mq_ncommit (g0)   +
 *       mq_nproc (g0)                       +
 *
 * 4) This shows the state after thread one has finished processing an item, but
 * before it does anything else. Note that even if thread two finishes early, it
 * cannot commit its item until thread one finishes. Here 'Y' refers to the
 * result of merging the first two 'X's.
 *
 *                     +---++---++---++---++---++---+     t1 - idle
 *                     | Y ||   ||   ||   || X || X |     t2 - slot 1
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)             +
 *     mq_ncommit (g0)        +
 *       mq_nproc (g0)                       +
 *
 * 5) This shows the state after thread one has begun to process the next round
 * and after thread two has committed, but before it begins processing the next
 * item. Note that mq_nproc has wrapped around and we've bumped its generation
 * counter.
 *
 *                     +---++---++---++---++---++---+     t1 - slot 2
 *                     | Y || Y ||   ||   ||   ||   |     t2 - idle
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)                  +
 *     mq_ncommit (g0)             +
 *       mq_nproc (g0)   +
 *
 * 6) Here, thread two, will take the next two Y values and thread 1 will commit
 * its 'Y'. Thread one now must wait until thread two finishes such that it can
 * do additional work.
 *
 *                     +---++---++---++---++---++---+     t1 - waiting
 *                     |   ||   || Y ||   ||   ||   |     t2 - slot 3
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)                       +
 *     mq_ncommit (g0)                  +
 *       mq_nproc (g0)             +
 *
 * 7) Here, thread two has committed and thread one is about to go process the
 * final entry. The character 'Z' represents the results of merging two 'Y's.
 *
 *                     +---++---++---++---++---++---+     t1 - idle
 *                     |   ||   || Y || Z ||   ||   |     t2 - idle
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)                       +
 *     mq_ncommit (g0)                       +
 *       mq_nproc (g0)             +
 *
 * 8) Here, thread one is processing the final item. Thread two is waiting in
 * mergeq_pop() for enough items to be available. In this case, it will never
 * happen; however, once all threads have finished it will break out.
 *
 *                     +---++---++---++---++---++---+     t1 - slot 4
 *                     |   ||   ||   ||   ||   ||   |     t2 - idle
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)                            +
 *     mq_ncommit (g0)                       +
 *       mq_nproc (g0)                       +
 *
 * 9) This is the final state of the queue, it has a single '*' item which is
 * the final merge result. At this point, both thread one and thread two would
 * stop processing and we'll return the result to the user.
 *
 *                     +---++---++---++---++---++---+     t1 - slot 4
 *                     |   ||   ||   ||   || * ||   |     t2 - idle
 *                     +---++---++---++---++---++---+
 *        mq_next (g1)                            +
 *     mq_ncommit (g0)                       +
 *       mq_nproc (g0)                       +
 *
 *
 * Note, that if at any point in time the processing function fails, then all
 * the merges will quiesce and that error will be propagated back to the user.
 */

#include <strings.h>
#include <sys/debug.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#include "mergeq.h"

struct mergeq {
	mutex_t mq_lock;	/* Protects items below */
	cond_t	mq_cond;	/* Condition variable */
	void **mq_items;	/* Array of items to process */
	size_t mq_nitems;	/* Number of items in the queue */
	size_t mq_cap;		/* Capacity of the items */
	size_t mq_next;		/* Place to put next entry */
	size_t mq_gnext;	/* Generation for next */
	size_t mq_nproc;	/* Index of next thing to process */
	size_t mq_gnproc;	/* Generation for next proc */
	size_t mq_ncommit;	/* Index of the next thing to commit */
	size_t mq_gncommit;	/* Commit generation */
	uint_t mq_nactthrs;	/* Number of active threads */
	uint_t mq_ndthreads;	/* Desired number of threads */
	thread_t *mq_thrs;	/* Actual threads */
	mergeq_proc_f *mq_func;	/* Processing function */
	void *mq_arg;		/* Argument for processing */
	boolean_t mq_working;	/* Are we working on processing */
	boolean_t mq_iserror;	/* Have we encountered an error? */
	int mq_error;
};

#define	MERGEQ_DEFAULT_CAP	64

static int
mergeq_error(int err)
{
	errno = err;
	return (MERGEQ_ERROR);
}

void
mergeq_fini(mergeq_t *mqp)
{
	if (mqp == NULL)
		return;

	VERIFY(mqp->mq_working != B_TRUE);

	if (mqp->mq_items != NULL)
		mergeq_free(mqp->mq_items, sizeof (void *) * mqp->mq_cap);
	if (mqp->mq_ndthreads > 0) {
		mergeq_free(mqp->mq_thrs, sizeof (thread_t) *
		    mqp->mq_ndthreads);
	}
	VERIFY0(cond_destroy(&mqp->mq_cond));
	VERIFY0(mutex_destroy(&mqp->mq_lock));
	mergeq_free(mqp, sizeof (mergeq_t));
}

int
mergeq_init(mergeq_t **outp, uint_t nthrs)
{
	int ret;
	mergeq_t *mqp;

	mqp = mergeq_alloc(sizeof (mergeq_t));
	if (mqp == NULL)
		return (mergeq_error(ENOMEM));

	bzero(mqp, sizeof (mergeq_t));
	mqp->mq_items = mergeq_alloc(sizeof (void *) * MERGEQ_DEFAULT_CAP);
	if (mqp->mq_items == NULL) {
		mergeq_free(mqp, sizeof (mergeq_t));
		return (mergeq_error(ENOMEM));
	}
	bzero(mqp->mq_items, sizeof (void *) * MERGEQ_DEFAULT_CAP);

	mqp->mq_ndthreads = nthrs - 1;
	if (mqp->mq_ndthreads > 0) {
		mqp->mq_thrs = mergeq_alloc(sizeof (thread_t) *
		    mqp->mq_ndthreads);
		if (mqp->mq_thrs == NULL) {
			mergeq_free(mqp->mq_items, sizeof (void *) *
			    MERGEQ_DEFAULT_CAP);
			mergeq_free(mqp, sizeof (mergeq_t));
			return (mergeq_error(ENOMEM));
		}
	}

	if ((ret = mutex_init(&mqp->mq_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL)) != 0) {
		if (mqp->mq_ndthreads > 0) {
			mergeq_free(mqp->mq_thrs,
			    sizeof (thread_t) * mqp->mq_ndthreads);
		}
		mergeq_free(mqp->mq_items, sizeof (void *) *
		    MERGEQ_DEFAULT_CAP);
		mergeq_free(mqp, sizeof (mergeq_t));
		return (mergeq_error(ret));
	}

	if ((ret = cond_init(&mqp->mq_cond, USYNC_THREAD, NULL)) != 0) {
		VERIFY0(mutex_destroy(&mqp->mq_lock));
		if (mqp->mq_ndthreads > 0) {
			mergeq_free(mqp->mq_thrs,
			    sizeof (thread_t) * mqp->mq_ndthreads);
		}
		mergeq_free(mqp->mq_items, sizeof (void *) *
		    MERGEQ_DEFAULT_CAP);
		mergeq_free(mqp, sizeof (mergeq_t));
		return (mergeq_error(ret));
	}

	mqp->mq_cap = MERGEQ_DEFAULT_CAP;
	*outp = mqp;
	return (0);
}

static void
mergeq_reset(mergeq_t *mqp)
{
	VERIFY(MUTEX_HELD(&mqp->mq_lock));
	VERIFY(mqp->mq_working == B_FALSE);
	if (mqp->mq_cap != 0)
		bzero(mqp->mq_items, sizeof (void *) * mqp->mq_cap);
	mqp->mq_nitems = 0;
	mqp->mq_next = 0;
	mqp->mq_gnext = 0;
	mqp->mq_nproc = 0;
	mqp->mq_gnproc = 0;
	mqp->mq_ncommit = 0;
	mqp->mq_gncommit = 0;
	mqp->mq_func = NULL;
	mqp->mq_arg = NULL;
	mqp->mq_iserror = B_FALSE;
	mqp->mq_error = 0;
}

static int
mergeq_grow(mergeq_t *mqp)
{
	size_t ncap;
	void **items;

	VERIFY(MUTEX_HELD(&mqp->mq_lock));
	VERIFY(mqp->mq_working == B_FALSE);

	if (SIZE_MAX - mqp->mq_cap < MERGEQ_DEFAULT_CAP)
		return (ENOSPC);

	ncap = mqp->mq_cap + MERGEQ_DEFAULT_CAP;
	items = mergeq_alloc(ncap * sizeof (void *));
	if (items == NULL)
		return (ENOMEM);

	bzero(items, ncap * sizeof (void *));
	bcopy(mqp->mq_items, items, mqp->mq_cap * sizeof (void *));
	mergeq_free(mqp->mq_items, sizeof (mqp->mq_cap) * sizeof (void *));
	mqp->mq_items = items;
	mqp->mq_cap = ncap;
	return (0);
}

int
mergeq_add(mergeq_t *mqp, void *item)
{
	VERIFY0(mutex_lock(&mqp->mq_lock));
	if (mqp->mq_working == B_TRUE) {
		VERIFY0(mutex_unlock(&mqp->mq_lock));
		return (mergeq_error(ENXIO));
	}

	if (mqp->mq_next == mqp->mq_cap) {
		int ret;

		if ((ret = mergeq_grow(mqp)) != 0) {
			VERIFY0(mutex_unlock(&mqp->mq_lock));
			return (mergeq_error(ret));
		}
	}
	mqp->mq_items[mqp->mq_next] = item;
	mqp->mq_next++;
	mqp->mq_nitems++;

	VERIFY0(mutex_unlock(&mqp->mq_lock));
	return (0);
}

static size_t
mergeq_slot(mergeq_t *mqp)
{
	size_t s;

	VERIFY(MUTEX_HELD(&mqp->mq_lock));
	VERIFY(mqp->mq_next < mqp->mq_cap);

	/*
	 * This probably should be a cv / wait thing.
	 */
	VERIFY(mqp->mq_nproc != (mqp->mq_next + 1) % mqp->mq_cap);

	s = mqp->mq_next;
	mqp->mq_next++;
	if (mqp->mq_next == mqp->mq_cap) {
		mqp->mq_next %= mqp->mq_cap;
		mqp->mq_gnext++;
	}

	return (s);
}

/*
 * Internal function to push items onto the queue which is now a circular
 * buffer. This should only be used once we begin working on the queue.
 */
static void
mergeq_push(mergeq_t *mqp, size_t slot, void *item)
{
	VERIFY(MUTEX_HELD(&mqp->mq_lock));
	VERIFY(slot < mqp->mq_cap);

	/*
	 * We need to verify that we don't push over something that exists.
	 * Based on the design, this should never happen. However, in the face
	 * of bugs, anything is possible.
	 */
	while (mqp->mq_ncommit != slot && mqp->mq_iserror == B_FALSE)
		(void) cond_wait(&mqp->mq_cond, &mqp->mq_lock);

	if (mqp->mq_iserror == B_TRUE)
		return;

	mqp->mq_items[slot] = item;
	mqp->mq_nitems++;
	mqp->mq_ncommit++;
	if (mqp->mq_ncommit == mqp->mq_cap) {
		mqp->mq_ncommit %= mqp->mq_cap;
		mqp->mq_gncommit++;
	}
	(void) cond_broadcast(&mqp->mq_cond);
}

static void *
mergeq_pop_one(mergeq_t *mqp)
{
	void *out;

	/*
	 * We can't move mq_nproc beyond mq_next if they're on the same
	 * generation.
	 */
	VERIFY(mqp->mq_gnext != mqp->mq_gnproc ||
	    mqp->mq_nproc != mqp->mq_next);

	out = mqp->mq_items[mqp->mq_nproc];

	mqp->mq_items[mqp->mq_nproc] = NULL;
	mqp->mq_nproc++;
	if (mqp->mq_nproc == mqp->mq_cap) {
		mqp->mq_nproc %= mqp->mq_cap;
		mqp->mq_gnproc++;
	}
	mqp->mq_nitems--;

	return (out);
}

/*
 * Pop a set of two entries from the queue. We may not have anything to process
 * at the moment, eg. be waiting for someone to add something. In which case,
 * we'll be sitting and waiting.
 */
static boolean_t
mergeq_pop(mergeq_t *mqp, void **first, void **second)
{
	VERIFY(MUTEX_HELD(&mqp->mq_lock));
	VERIFY(mqp->mq_nproc < mqp->mq_cap);

	while (mqp->mq_nitems < 2 && mqp->mq_nactthrs > 0 &&
	    mqp->mq_iserror == B_FALSE)
		(void) cond_wait(&mqp->mq_cond, &mqp->mq_lock);

	if (mqp->mq_iserror == B_TRUE)
		return (B_FALSE);

	if (mqp->mq_nitems < 2 && mqp->mq_nactthrs == 0) {
		VERIFY(mqp->mq_iserror == B_TRUE || mqp->mq_nitems == 1);
		return (B_FALSE);
	}
	VERIFY(mqp->mq_nitems >= 2);

	*first = mergeq_pop_one(mqp);
	*second = mergeq_pop_one(mqp);

	return (B_TRUE);
}

static void *
mergeq_thr_merge(void *arg)
{
	mergeq_t *mqp = arg;

	VERIFY0(mutex_lock(&mqp->mq_lock));

	/*
	 * Check to make sure creation worked and if not, fail fast.
	 */
	if (mqp->mq_iserror == B_TRUE) {
		VERIFY0(mutex_unlock(&mqp->mq_lock));
		return (NULL);
	}

	for (;;) {
		void *first, *second, *out;
		int ret;
		size_t slot;

		if (mqp->mq_nitems == 1 && mqp->mq_nactthrs == 0) {
			VERIFY0(mutex_unlock(&mqp->mq_lock));
			return (NULL);
		}

		if (mergeq_pop(mqp, &first, &second) == B_FALSE) {
			VERIFY0(mutex_unlock(&mqp->mq_lock));
			return (NULL);
		}
		slot = mergeq_slot(mqp);

		mqp->mq_nactthrs++;

		VERIFY0(mutex_unlock(&mqp->mq_lock));
		ret = mqp->mq_func(first, second, &out, mqp->mq_arg);
		VERIFY0(mutex_lock(&mqp->mq_lock));

		if (ret != 0) {
			if (mqp->mq_iserror == B_FALSE) {
				mqp->mq_iserror = B_TRUE;
				mqp->mq_error = ret;
				(void) cond_broadcast(&mqp->mq_cond);
			}
			mqp->mq_nactthrs--;
			VERIFY0(mutex_unlock(&mqp->mq_lock));
			return (NULL);
		}
		mergeq_push(mqp, slot, out);
		mqp->mq_nactthrs--;
	}
}

int
mergeq_merge(mergeq_t *mqp, mergeq_proc_f *func, void *arg, void **outp,
    int *errp)
{
	int ret, i;
	boolean_t seterr = B_FALSE;

	if (mqp == NULL || func == NULL || outp == NULL) {
		return (mergeq_error(EINVAL));
	}

	VERIFY0(mutex_lock(&mqp->mq_lock));
	if (mqp->mq_working == B_TRUE) {
		VERIFY0(mutex_unlock(&mqp->mq_lock));
		return (mergeq_error(EBUSY));
	}

	if (mqp->mq_nitems == 0) {
		*outp = NULL;
		mergeq_reset(mqp);
		VERIFY0(mutex_unlock(&mqp->mq_lock));
		return (0);
	}

	/*
	 * Now that we've finished adding items to the queue, turn it into a
	 * circular buffer.
	 */
	mqp->mq_func = func;
	mqp->mq_arg = arg;
	mqp->mq_nproc = 0;
	mqp->mq_working = B_TRUE;
	if (mqp->mq_next == mqp->mq_cap) {
		mqp->mq_next %= mqp->mq_cap;
		mqp->mq_gnext++;
	}
	mqp->mq_ncommit = mqp->mq_next;

	ret = 0;
	for (i = 0; i < mqp->mq_ndthreads; i++) {
		ret = thr_create(NULL, 0, mergeq_thr_merge, mqp, 0,
		    &mqp->mq_thrs[i]);
		if (ret != 0) {
			mqp->mq_iserror = B_TRUE;
			break;
		}
	}

	VERIFY0(mutex_unlock(&mqp->mq_lock));
	if (ret == 0)
		(void) mergeq_thr_merge(mqp);

	for (i = 0; i < mqp->mq_ndthreads; i++) {
		VERIFY0(thr_join(mqp->mq_thrs[i], NULL, NULL));
	}

	VERIFY0(mutex_lock(&mqp->mq_lock));

	VERIFY(mqp->mq_nactthrs == 0);
	mqp->mq_working = B_FALSE;
	if (ret == 0 && mqp->mq_iserror == B_FALSE) {
		VERIFY(mqp->mq_nitems == 1);
		*outp = mergeq_pop_one(mqp);
	} else if (ret == 0 && mqp->mq_iserror == B_TRUE) {
		ret = MERGEQ_UERROR;
		if (errp != NULL)
			*errp = mqp->mq_error;
	} else {
		seterr = B_TRUE;
	}

	mergeq_reset(mqp);
	VERIFY0(mutex_unlock(&mqp->mq_lock));

	if (seterr == B_TRUE)
		return (mergeq_error(ret));

	return (ret);
}
