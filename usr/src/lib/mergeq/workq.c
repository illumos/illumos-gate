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
 * Work queue
 *
 * A multi-threaded work queue.
 *
 * The general design of this is to add a fixed number of items to the queue and
 * then drain them with the specified number of threads.
 */

#include <strings.h>
#include <sys/debug.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#include "workq.h"

struct workq {
	mutex_t wq_lock;	/* Protects below items */
	cond_t wq_cond;		/* Condition variable */
	void **wq_items;	/* Array of items to process */
	size_t wq_nitems;	/* Number of items in queue */
	size_t wq_cap;		/* Queue capacity */
	size_t wq_next;		/* Next item to process */
	uint_t wq_ndthreads;	/* Desired number of threads */
	thread_t *wq_thrs;	/* Actual threads */
	workq_proc_f *wq_func;	/* Processing function */
	void *wq_arg;		/* Argument for processing */
	boolean_t wq_working;	/* Are we actively using it? */
	boolean_t wq_iserror;	/* Have we encountered an error? */
	int wq_error;		/* Error value, if any */
};

#define	WORKQ_DEFAULT_CAP	64

static int
workq_error(int err)
{
	VERIFY(err != 0);
	errno = err;
	return (WORKQ_ERROR);
}

void
workq_fini(workq_t *wqp)
{
	if (wqp == NULL)
		return;

	VERIFY(wqp->wq_working != B_TRUE);
	VERIFY0(mutex_destroy(&wqp->wq_lock));
	VERIFY0(cond_destroy(&wqp->wq_cond));
	if (wqp->wq_cap > 0)
		workq_free(wqp->wq_items, sizeof (void *) * wqp->wq_cap);
	if (wqp->wq_ndthreads > 0)
		workq_free(wqp->wq_thrs, sizeof (thread_t) * wqp->wq_ndthreads);
	workq_free(wqp, sizeof (workq_t));
}

int
workq_init(workq_t **outp, uint_t nthrs)
{
	int ret;
	workq_t *wqp;

	wqp = workq_alloc(sizeof (workq_t));
	if (wqp == NULL)
		return (workq_error(ENOMEM));

	bzero(wqp, sizeof (workq_t));
	wqp->wq_items = workq_alloc(sizeof (void *) * WORKQ_DEFAULT_CAP);
	if (wqp->wq_items == NULL) {
		workq_free(wqp, sizeof (workq_t));
		return (workq_error(ENOMEM));
	}
	bzero(wqp->wq_items, sizeof (void *) * WORKQ_DEFAULT_CAP);

	wqp->wq_ndthreads = nthrs - 1;
	if (wqp->wq_ndthreads > 0) {
		wqp->wq_thrs = workq_alloc(sizeof (thread_t) *
		    wqp->wq_ndthreads);
		if (wqp->wq_thrs == NULL) {
			workq_free(wqp->wq_items, sizeof (void *) *
			    WORKQ_DEFAULT_CAP);
			workq_free(wqp, sizeof (workq_t));
			return (workq_error(ENOMEM));
		}
	}

	if ((ret = mutex_init(&wqp->wq_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL)) != 0) {
		if (wqp->wq_ndthreads > 0) {
			workq_free(wqp->wq_thrs,
			    sizeof (thread_t) * wqp->wq_ndthreads);
		}
		workq_free(wqp->wq_items, sizeof (void *) * WORKQ_DEFAULT_CAP);
		workq_free(wqp, sizeof (workq_t));
		return (workq_error(ret));
	}

	if ((ret = cond_init(&wqp->wq_cond, USYNC_THREAD, NULL)) != 0) {
		VERIFY0(mutex_destroy(&wqp->wq_lock));
		if (wqp->wq_ndthreads > 0) {
			workq_free(wqp->wq_thrs,
			    sizeof (thread_t) * wqp->wq_ndthreads);
		}
		workq_free(wqp->wq_items, sizeof (void *) * WORKQ_DEFAULT_CAP);
		workq_free(wqp, sizeof (workq_t));
		return (workq_error(ret));
	}

	wqp->wq_cap = WORKQ_DEFAULT_CAP;
	*outp = wqp;
	return (0);
}

static void
workq_reset(workq_t *wqp)
{
	VERIFY(MUTEX_HELD(&wqp->wq_lock));
	VERIFY(wqp->wq_working == B_FALSE);
	if (wqp->wq_cap > 0)
		bzero(wqp->wq_items, sizeof (void *) * wqp->wq_cap);
	wqp->wq_nitems = 0;
	wqp->wq_next = 0;
	wqp->wq_func = NULL;
	wqp->wq_arg = NULL;
	wqp->wq_iserror = B_FALSE;
	wqp->wq_error = 0;
}

static int
workq_grow(workq_t *wqp)
{
	size_t ncap;
	void **items;

	VERIFY(MUTEX_HELD(&wqp->wq_lock));
	VERIFY(wqp->wq_working == B_FALSE);

	if (SIZE_MAX - wqp->wq_cap < WORKQ_DEFAULT_CAP)
		return (ENOSPC);

	ncap = wqp->wq_cap + WORKQ_DEFAULT_CAP;
	items = workq_alloc(ncap * sizeof (void *));
	if (items == NULL)
		return (ENOMEM);

	bzero(items, ncap * sizeof (void *));
	bcopy(wqp->wq_items, items, wqp->wq_cap * sizeof (void *));
	workq_free(wqp->wq_items, sizeof (void *) * wqp->wq_cap);
	wqp->wq_items = items;
	wqp->wq_cap = ncap;
	return (0);
}

int
workq_add(workq_t *wqp, void *item)
{
	VERIFY0(mutex_lock(&wqp->wq_lock));
	if (wqp->wq_working == B_TRUE) {
		VERIFY0(mutex_unlock(&wqp->wq_lock));
		return (workq_error(ENXIO));
	}

	if (wqp->wq_nitems == wqp->wq_cap) {
		int ret;

		if ((ret = workq_grow(wqp)) != 0) {
			VERIFY0(mutex_unlock(&wqp->wq_lock));
			return (workq_error(ret));
		}
	}

	wqp->wq_items[wqp->wq_nitems] = item;
	wqp->wq_nitems++;

	VERIFY0(mutex_unlock(&wqp->wq_lock));

	return (0);
}

static void *
workq_pop(workq_t *wqp)
{
	void *out;

	VERIFY(MUTEX_HELD(&wqp->wq_lock));
	VERIFY(wqp->wq_next < wqp->wq_nitems);

	out = wqp->wq_items[wqp->wq_next];
	wqp->wq_items[wqp->wq_next] = NULL;
	wqp->wq_next++;

	return (out);
}

static void *
workq_thr_work(void *arg)
{
	workq_t *wqp = arg;

	VERIFY0(mutex_lock(&wqp->wq_lock));
	VERIFY(wqp->wq_working == B_TRUE);

	for (;;) {
		int ret;
		void *item;

		if (wqp->wq_iserror == B_TRUE ||
		    wqp->wq_next == wqp->wq_nitems) {
			VERIFY0(mutex_unlock(&wqp->wq_lock));
			return (NULL);
		}

		item = workq_pop(wqp);

		VERIFY0(mutex_unlock(&wqp->wq_lock));
		ret = wqp->wq_func(item, wqp->wq_arg);
		VERIFY0(mutex_lock(&wqp->wq_lock));

		if (ret != 0) {
			if (wqp->wq_iserror == B_FALSE) {
				wqp->wq_iserror = B_TRUE;
				wqp->wq_error = ret;
			}
			VERIFY0(mutex_unlock(&wqp->wq_lock));
			return (NULL);
		}
	}
}

int
workq_work(workq_t *wqp, workq_proc_f *func, void *arg, int *errp)
{
	int i, ret;
	boolean_t seterr = B_FALSE;

	if (wqp == NULL || func == NULL)
		return (workq_error(EINVAL));

	VERIFY0(mutex_lock(&wqp->wq_lock));
	if (wqp->wq_working == B_TRUE) {
		VERIFY0(mutex_unlock(&wqp->wq_lock));
		return (workq_error(EBUSY));
	}

	if (wqp->wq_nitems == 0) {
		workq_reset(wqp);
		VERIFY0(mutex_unlock(&wqp->wq_lock));
		return (0);
	}

	wqp->wq_func = func;
	wqp->wq_arg = arg;
	wqp->wq_next = 0;
	wqp->wq_working = B_TRUE;

	ret = 0;
	for (i = 0; i < wqp->wq_ndthreads; i++) {
		ret = thr_create(NULL, 0, workq_thr_work, wqp, 0,
		    &wqp->wq_thrs[i]);
		if (ret != 0) {
			wqp->wq_iserror = B_TRUE;
		}
	}

	VERIFY0(mutex_unlock(&wqp->wq_lock));
	if (ret == 0)
		(void) workq_thr_work(wqp);

	for (i = 0; i < wqp->wq_ndthreads; i++) {
		VERIFY0(thr_join(wqp->wq_thrs[i], NULL, NULL));
	}

	VERIFY0(mutex_lock(&wqp->wq_lock));
	wqp->wq_working = B_FALSE;
	if (ret == 0 && wqp->wq_iserror == B_TRUE) {
		ret = WORKQ_UERROR;
		if (errp != NULL)
			*errp = wqp->wq_error;
	} else if (ret != 0) {
		VERIFY(wqp->wq_iserror == B_FALSE);
		seterr = B_TRUE;
	}

	workq_reset(wqp);
	VERIFY0(mutex_unlock(&wqp->wq_lock));

	if (seterr == B_TRUE)
		return (workq_error(ret));

	return (ret);
}
