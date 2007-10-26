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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/atomic.h>
#include <sys/callb.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/taskq.h>
#include <sys/dditypes.h>
#include <sys/ddi_timer.h>
#include <sys/disp.h>
#include <sys/kobj.h>
#include <sys/note.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/types.h>

/*
 * global variables for timeout request
 */
static kmem_cache_t *req_cache;		/* kmem cache for timeout request */

/*
 * taskq parameters for cyclic_timer
 *
 * timer_taskq_num:
 * timer_taskq_num represents the number of taskq threads.
 * Currently 4 threads are pooled to handle periodic timeout requests.
 * This number is chosen based on the fact that the callout (one-time
 * timeout framework) uses 8 threads with TQ_NOSLEEP; the periodic timeout
 * calls taskq_dispatch() with TQ_SLEEP instead, and in this case, 4 threads
 * should be sufficient to handle periodic timeout requests. (see also
 * timer_taskq_max_num below)
 *
 * timer_taskq_min_num:
 * timer_taskq_min_num represents the number of pre-populated taskq_ent
 * structures, and this variable holds the same value as timer_taskq_num does.
 *
 * timer_taskq_max_num:
 * Since TQ_SLEEP is set when taskq_dispatch() is called, the framework waits
 * for one second if more taskq_ent structures than timer_taskq_max_num are
 * required. However, from the timeout point of view, one second is much longer
 * than expected, and to prevent this occurrence, timer_taskq_max_num should
 * hold a sufficiently-large value, which is 128 here. Note that since the size
 * of taskq_ent_t is relatively small, this doesn't use up the resource so much.
 * (Currently the size is less than 8k at most)
 *
 * About the detailed explanation of the taskq function arguments, please see
 * usr/src/uts/common/os/taskq.c.
 */
int timer_taskq_num = 4;		/* taskq thread number */
int timer_taskq_min_num = 4;		/* min. number of taskq_ent structs */
int timer_taskq_max_num = 128;		/* max. number of taskq_ent structs */
static taskq_t *tm_taskq;		/* taskq thread pool */
static kthread_t *tm_work_thread;	/* work thread invoking taskq */

/*
 * timer variables
 */
static cyc_timer_t *ddi_timer;		/* ddi timer based on the cyclic */
static volatile hrtime_t timer_hrtime;	/* current tick time on the timer */

/*
 * Variable used for the suspend/resume.
 */
static volatile boolean_t timer_suspended;

/*
 * Kernel taskq queue to ddi timer
 */
static list_t kern_queue;	/* kernel thread request queue */
static kcondvar_t kern_cv;	/* condition variable for taskq queue */

/*
 * Software interrupt queue dedicated to ddi timer
 */
static list_t intr_queue;	/* software interrupt request queue */
static uint_t intr_state;	/* software interrupt state */

/*
 * This lock is used to protect the intr_queue and kern_queue.
 * It's also used to protect the intr_state which represents the software
 * interrupt state for the timer.
 */
static kmutex_t	disp_req_lock;

/*
 * the periodic timer interrupt priority level
 */
enum {
	TM_IPL_0 = 0,			/* kernel context */
	TM_IPL_1, TM_IPL_2, TM_IPL_3,	/* level 1-3 */
	TM_IPL_4, TM_IPL_5, TM_IPL_6,	/* level 4-6 */
	TM_IPL_7, TM_IPL_8, TM_IPL_9,	/* level 7-9 */
	TM_IPL_10			/* level 10 */
};

/*
 * A callback handler used by CPR to stop and resume callouts.
 * Since the taskq uses TASKQ_CPR_SAFE, the function just set the boolean
 * flag to timer_suspended here.
 */
/*ARGSUSED*/
static boolean_t
timer_cpr_callb(void *arg, int code)
{
	timer_suspended = (code == CB_CODE_CPR_CHKPT);
	return (B_TRUE);
}

/*
 * Return a proposed timeout request id. add_req() determines whether
 * or not the proposed one is used. If it's not suitable, add_req()
 * recalls get_req_cnt(). To reduce the lock contention between the
 * timer and i_untimeout(), the atomic instruction should be used here.
 */
static timeout_t
get_req_cnt(void)
{
	static volatile ulong_t timeout_cnt = 0;
	return ((timeout_t)atomic_inc_ulong_nv(&timeout_cnt));
}

/*
 * Get the system resolution.
 * Note. currently there is a restriction about the system resolution, and
 * the 10ms tick (the default clock resolution) is only supported now.
 */
static hrtime_t
i_get_res(void)
{
	return ((hrtime_t)10000000); /* 10ms tick only */
}

/*
 * Return the value for the cog of the timing wheel.
 * TICK_FACTOR is used to gain a finer cog on the clock resolution.
 */
static hrtime_t
tw_tick(hrtime_t time)
{
	return ((time << TICK_FACTOR) / ddi_timer->res);
}

/*
 * Calculate the expiration time for the timeout request.
 */
static hrtime_t
expire_tick(tm_req_t *req)
{
	return (tw_tick(req->exp_time));
}

/*
 * Register a timeout request to the timer. This function is used
 * in i_timeout().
 */
static timeout_t
add_req(tm_req_t *req)
{
	timer_tw_t *tid, *tw;
	tm_req_t *next;
	timeout_t id;

retry:
	/*
	 * Retrieve a timeout request id. Since i_timeout() needs to return
	 * a non-zero value, re-try if the zero is gotten.
	 */
	if ((id = get_req_cnt()) == 0)
		id = get_req_cnt();

	/*
	 * Check if the id is not used yet. Since the framework now deals
	 * with the periodic timeout requests, we cannot assume the id
	 * allocated (long) before doesn't exist any more when it will
	 * be re-assigned again (especially on 32bit) but need to handle
	 * this case to solve the conflicts. If it's used already, retry
	 * another.
	 */
	tid = &ddi_timer->idhash[TM_HASH((uintptr_t)id)];
	mutex_enter(&tid->lock);
	for (next = list_head(&tid->req); next != NULL;
	    next = list_next(&tid->req, next)) {
		if (next->id == id) {
			mutex_exit(&tid->lock);
			goto retry;
		}
	}
	/* Nobody uses this id yet */
	req->id = id;

	/*
	 * Register this request to the timer.
	 * The list operation must be list_insert_head().
	 * Other operations can degrade performance.
	 */
	list_insert_head(&tid->req, req);
	mutex_exit(&tid->lock);

	tw = &ddi_timer->exhash[TM_HASH(expire_tick(req))];
	mutex_enter(&tw->lock);
	/*
	 * Other operations than list_insert_head() can
	 * degrade performance here.
	 */
	list_insert_head(&tw->req, req);
	mutex_exit(&tw->lock);

	return (id);
}

/*
 * Periodic timeout requests cannot be removed until they are canceled
 * explicitly. Until then, they need to be re-registerd after they are
 * fired. transfer_req() re-registers the requests for the next fires.
 * Note. transfer_req() sends the cv_signal to timeout_execute(), which
 * runs in interrupt context. Make sure this function will not be blocked,
 * otherwise the deadlock situation can occur.
 */
static void
transfer_req(tm_req_t *req, timer_tw_t *tw)
{
	timer_tw_t *new_tw;
	hrtime_t curr_time;
	ASSERT(tw && MUTEX_HELD(&tw->lock));

	/* Calculate the next expiration time by interval */
	req->exp_time += req->interval;
	curr_time = gethrtime();

	/*
	 * If a long time (more than 1 clock resolution) has already
	 * passed for some reason (e.g. debugger or high interrupt),
	 * round up the next expiration to the appropriate one
	 * since this request is periodic and never catches with it.
	 */
	if (curr_time - req->exp_time >= ddi_timer->res) {
		req->exp_time = roundup(curr_time + req->interval,
		    ddi_timer->res);
	}

	/*
	 * Re-register this request.
	 * Note. since it is guaranteed that the timer is invoked on only
	 * one CPU at any time (by the cyclic subsystem), a deadlock
	 * cannot occur regardless of the lock order here.
	 */
	new_tw = &ddi_timer->exhash[TM_HASH(expire_tick(req))];

	/*
	 * If it's on the timer cog already, there is nothing
	 * to do. Just return.
	 */
	if (new_tw == tw)
		return;

	/* Remove this request from the timer */
	list_remove(&tw->req, req);

	/* Re-register this request to the timer */
	mutex_enter(&new_tw->lock);

	/*
	 * Other operations than list_insert_head() can
	 * degrade performance here.
	 */
	list_insert_head(&new_tw->req, req);
	mutex_exit(&new_tw->lock);

	/*
	 * Set the TM_TRANSFER flag and notify the request is transfered
	 * completely. This prevents a race in the case that this request
	 * is serviced on another CPU already.
	 */
	mutex_enter(&req->lock);
	req->flags |= TM_TRANSFER;
	cv_signal(&req->cv);
	mutex_exit(&req->lock);
}

/*
 * Execute timeout requests.
 * Note. since timeout_execute() can run in interrupt context and block
 * on condition variables, there are restrictions on the timer code that
 * signals these condition variables (see i_untimeout(), transfer_req(),
 * and condvar(9F)). Functions that signal these cvs must ensure that
 * they will not be blocked (for memory allocations or any other reason)
 * since condition variables don't support priority inheritance.
 */
static void
timeout_execute(void *arg)
{
	tm_req_t *req = (tm_req_t *)arg;
	ASSERT(req->flags & TM_INVOKING && !(req->flags & TM_EXECUTING));

	for (;;) {
		/*
		 * Check if this request is canceled. If it's canceled, do not
		 * execute this request.
		 */
		mutex_enter(&req->lock);
		if (!(req->flags & TM_CANCEL)) {
			/*
			 * Set the current thread to prevent a dead lock
			 * situation in case that this timeout request is
			 * canceled in the handler being invoked now.
			 * (this doesn't violate the spec) Set TM_EXECUTING
			 * to show this handler is invoked soon.
			 */
			req->h_thread = curthread;
			req->flags |= TM_EXECUTING;
			mutex_exit(&req->lock);

			/* The handler is invoked without holding any locks */
			(*req->handler)(req->arg);

			/*
			 * Set TM_COMPLETE and notify the request is complete
			 * now.
			 */
			mutex_enter(&req->lock);
			req->flags |= TM_COMPLETE;
			if (req->flags & TM_COMPWAIT)
				cv_signal(&req->cv);
		}

		/*
		 * The handler is invoked at this point. If this request
		 * is not canceled, prepare for the next fire.
		 */
		if (req->flags & TM_CANCEL) {
			timer_tw_t *tw;
			/*
			 * Wait until the timer finishes all things for
			 * this request.
			 */
			while (!(req->flags & TM_TRANSFER))
				cv_wait(&req->cv, &req->lock);
			mutex_exit(&req->lock);
			ASSERT(req->flags & TM_TRANSFER);

			/* Remove this request from the timer */
			tw = &ddi_timer->exhash[TM_HASH(expire_tick(req))];
			mutex_enter(&tw->lock);
			list_remove(&tw->req, req);
			mutex_exit(&tw->lock);

			/*
			 * Wait until i_untimeout() can go ahead.
			 * This prevents the request from being freed before
			 * i_untimeout() is complete.
			 */
			mutex_enter(&req->lock);
			while (req->flags & TM_COMPWAIT)
				cv_wait(&req->cv, &req->lock);
			mutex_exit(&req->lock);
			ASSERT(!(req->flags & TM_COMPWAIT));

			/* Free this request */
			kmem_cache_free(req_cache, req);
			return;
		}
		ASSERT(req->flags & TM_EXECUTING);

		/*
		 * TM_EXECUTING must be set at this point.
		 * Unset the flag.
		 */
		req->flags &= ~(TM_EXECUTING | TM_TRANSFER);

		/*
		 * Decrease the request cnt. The reqest cnt shows
		 * how many times this request is executed now.
		 * If this counter becomes the zero, drop TM_INVOKING
		 * to show there is no requests to do now.
		 */
		req->cnt--;
		if (req->cnt == 0) {
			req->flags &= ~TM_INVOKING;
			mutex_exit(&req->lock);
			return;
		}
		mutex_exit(&req->lock);
	}
}

/*
 * Timeout worker thread for processing task queue.
 */
static void
timeout_taskq_thread(void *arg)
{
	_NOTE(ARGUNUSED(arg));
	tm_req_t *kern_req;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &disp_req_lock, callb_generic_cpr,
	    "timeout_taskq_thread");

	/*
	 * This thread is wakened up when a new request is added to
	 * the queue. Then pick up all requests and dispatch them
	 * via taskq_dispatch().
	 */
	for (;;) {
		/*
		 * Check the queue and pick up a request if the queue
		 * is not NULL.
		 */
		mutex_enter(&disp_req_lock);
		while ((kern_req = list_head(&kern_queue)) == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&kern_cv, &disp_req_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &disp_req_lock);
		}
		list_remove(&kern_queue, kern_req);
		mutex_exit(&disp_req_lock);

		/* Execute the timeout request via the taskq thread */
		(void) taskq_dispatch(tm_taskq, timeout_execute,
		    (void *)kern_req, TQ_SLEEP);
	}
}

/*
 * Dispatch the timeout request based on the level specified.
 * If the level is equal to zero, notify the worker thread to
 * call taskq_dispatch() in kernel context. If the level is bigger
 * than zero, add a software interrupt request to the queue and raise
 * the interrupt level to the specified one.
 */
static void
timeout_dispatch(tm_req_t *req)
{
	int level = req->level;
	extern void sir_on(int);

	if (level == TM_IPL_0) {
		/* Add a new request to the tail */
		mutex_enter(&disp_req_lock);
		list_insert_tail(&kern_queue, req);
		mutex_exit(&disp_req_lock);

		/*
		 * notify the worker thread that this request
		 * is newly added to the queue.
		 * Note. this cv_signal() can be called after the
		 * mutex_lock.
		 */
		cv_signal(&kern_cv);
	} else {
		/* Add a new request to the tail */
		mutex_enter(&disp_req_lock);
		list_insert_tail(&intr_queue, req);

		/* Issue the software interrupt */
		if (intr_state & TM_INTR_START(level)) {
			/*
			 * timer_softintr() is already running; no need to
			 * raise a siron. Due to lock protection of
			 * the intr_queue and intr_state, we know that
			 * timer_softintr() will see the new addition to
			 * the intr_queue.
			 */
			mutex_exit(&disp_req_lock);
		} else {
			intr_state |= TM_INTR_SET(level);
			mutex_exit(&disp_req_lock);

			/* Raise an interrupt to execute timeout requests */
			sir_on(level);
		}
	}
}

/*
 * Check the software interrupt queue and invoke requests at the specified
 * interrupt level.
 * Note that the queue may change during call so that the disp_req_lock
 * and the intr_state are used to protect it.
 * The software interrupts supported here are up to the level 10. Higher
 * than 10 interrupts cannot be supported.
 */
void
timer_softintr(int level)
{
	tm_req_t *intr_req;
	ASSERT(level >= TM_IPL_1 && level <= TM_IPL_10);

	/* Check if we are asked to process the softcall list */
	mutex_enter(&disp_req_lock);
	if (!(intr_state & TM_INTR_SET(level))) {
		mutex_exit(&disp_req_lock);
		return;
	}

	/* Notify this software interrupt request will be executed soon */
	intr_state |= TM_INTR_START(level);
	intr_state &= ~TM_INTR_SET(level);

	/* loop the link until there is no requests */
	for (intr_req = list_head(&intr_queue); intr_req != NULL;
	    /* Nothing */) {

		/* Check the interrupt level */
		if (intr_req->level != level) {
			intr_req = list_next(&intr_queue, intr_req);
			continue;
		}
		list_remove(&intr_queue, intr_req);
		mutex_exit(&disp_req_lock);

		/* Execute the software interrupt request */
		timeout_execute(intr_req);

		mutex_enter(&disp_req_lock);
		/* Restart the loop since new requests might be added */
		intr_req = list_head(&intr_queue);
	}

	/* reset the interrupt state */
	intr_state &= ~TM_INTR_START(level);
	mutex_exit(&disp_req_lock);
}

/*
 *  void
 *  cyclic_timer(void)
 *
 *  Overview
 *   cyclic_timer() is a function invoked periodically by the cyclic
 *   subsystem.
 *
 *   The function calls timeout_invoke() with timeout requests whose
 *   expiration time is already reached.
 *
 *  Arguments
 *   Nothing
 *
 *  Return value
 *   Nothing
 */
void
cyclic_timer(void)
{
	tm_req_t *req;
	timer_tw_t *tw;
	hrtime_t curr_tick, curr;

	/* If the system is suspended, just return */
	if (timer_suspended)
		return;

	/* Get the current time */
	timer_hrtime = ddi_timer->tick_time = curr = gethrtime();
	curr_tick = tw_tick(ddi_timer->tick_time);

restart:
	/*
	 * Check the timer cogs to see if there are timeout requests
	 * who reach the expiration time. Call timeout_invoke() to execute
	 * the requests, then.
	 */
	while (curr_tick >= ddi_timer->tick) {
		tm_req_t *next;
		tw = &ddi_timer->exhash[TM_HASH(ddi_timer->tick)];
		mutex_enter(&tw->lock);
		for (req = list_head(&tw->req); req != NULL; req = next) {
			next = list_next(&tw->req, req);
			/*
			 * If this request is already obsolete, free
			 * it here.
			 */
			if (req->flags & TM_UTMCOMP) {
				/*
				 * Remove this request from the timer,
				 * then free it.
				 */
				list_remove(&tw->req, req);
				kmem_cache_free(req_cache, req);
			} else if (curr >= req->exp_time) {
				mutex_enter(&req->lock);
				/*
				 * Check if this request is canceled, but not
				 * being executed now.
				 */
				if (req->flags & TM_CANCEL &&
				    !(req->flags & TM_INVOKING)) {
					mutex_exit(&req->lock);
					continue;
				}
				/*
				 * Record how many times timeout_execute()
				 * must be invoked.
				 */
				req->cnt++;
				/*
				 * Invoke timeout_execute() via taskq or
				 * software interrupt.
				 */
				if (req->flags & TM_INVOKING) {
					/*
					 * If it's already invoked,
					 * There is nothing to do.
					 */
					mutex_exit(&req->lock);
				} else {
					req->flags |= TM_INVOKING;
					mutex_exit(&req->lock);
					/*
					 * Dispatch this timeout request.
					 * timeout_dispatch() chooses either
					 * a software interrupt or taskq thread
					 * based on the level.
					 */
					timeout_dispatch(req);
				}
				/*
				 * Periodic timeout requests must prepare for
				 * the next fire.
				 */
				transfer_req(req, tw);
			}
		}
		mutex_exit(&tw->lock);
		ddi_timer->tick++;
	}

	/*
	 * Check the current time. If we spend some amount of time,
	 * double-check if some of the requests reaches the expiration
	 * time during the work.
	 */
	curr = gethrtime();
	curr_tick = tw_tick(curr);
	if (curr_tick >= ddi_timer->tick) {
		ddi_timer->tick -= 1;
		goto restart;
	}
	/* Adjustment for the next rolling */
	ddi_timer->tick -= 1;
}

/*
 *  void
 *  timer_init(void)
 *
 *  Overview
 *    timer_init() allocates the internal data structures used by
 *    i_timeout(), i_untimeout() and the timer.
 *
 *  Arguments
 *    Nothing
 *
 *  Return value
 *    Nothing
 *
 *  Caller's context
 *    timer_init() can be called in kernel context only.
 */
void
timer_init(void)
{
	int i;

	/* Create kmem_cache for timeout requests */
	req_cache = kmem_cache_create("timeout_request", sizeof (tm_req_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);

	/* Initialize the timer which is invoked by the cyclic subsystem */
	ddi_timer = kmem_alloc(sizeof (cyc_timer_t), KM_SLEEP);
	ddi_timer->res = nsec_per_tick;
	ddi_timer->tick = tw_tick(gethrtime());
	ddi_timer->tick_time = 0;

	/* Initialize the timing wheel */
	bzero((char *)&ddi_timer->idhash[0], TM_HASH_SZ * sizeof (timer_tw_t));
	bzero((char *)&ddi_timer->exhash[0], TM_HASH_SZ * sizeof (timer_tw_t));

	for (i = 0; i < TM_HASH_SZ; i++) {
		list_create(&ddi_timer->idhash[i].req, sizeof (tm_req_t),
		    offsetof(tm_req_t, id_req));
		mutex_init(&ddi_timer->idhash[i].lock, NULL, MUTEX_ADAPTIVE,
		    NULL);

		list_create(&ddi_timer->exhash[i].req, sizeof (tm_req_t),
		    offsetof(tm_req_t, ex_req));
		mutex_init(&ddi_timer->exhash[i].lock, NULL, MUTEX_ADAPTIVE,
		    NULL);
	}

	/* Create a taskq thread pool */
	tm_taskq = taskq_create_instance("timeout_taskq", 0,
	    timer_taskq_num, MAXCLSYSPRI,
	    timer_taskq_min_num, timer_taskq_max_num,
	    TASKQ_PREPOPULATE | TASKQ_CPR_SAFE);

	/*
	 * Initialize the taskq queue which is dedicated to this timeout
	 * interface/timer.
	 */
	list_create(&kern_queue, sizeof (tm_req_t),
	    offsetof(tm_req_t, disp_req));

	/* Create a worker thread to dispatch the taskq thread */
	tm_work_thread = thread_create(NULL, 0, timeout_taskq_thread, NULL,
	    0, &p0, TS_RUN, MAXCLSYSPRI);

	/*
	 * Initialize the software interrupt queue which is dedicated to
	 * this timeout interface/timer.
	 */
	list_create(&intr_queue, sizeof (tm_req_t),
	    offsetof(tm_req_t, disp_req));

	/*
	 * Initialize the mutex lock used for both of kern_queue and
	 * intr_queue.
	 */
	mutex_init(&disp_req_lock, NULL, MUTEX_ADAPTIVE, NULL);
	cv_init(&kern_cv, NULL, CV_DEFAULT, NULL);

	/* Register the callback handler for the system suspend/resume */
	(void) callb_add(timer_cpr_callb, 0, CB_CL_CPR_CALLOUT, "cyclicTimer");
}

/*
 *  timeout_t
 *  i_timeout(void (*func)(void *), void *arg,  hrtime_t interval,
 *      int level, int flags)
 *
 *  Overview
 *    i_timeout() is an internal function scheduling the passed function
 *    to be invoked in the interval in nanoseconds. The callback function
 *    keeps invoked until the request is explicitly canceled by i_untimeout().
 *    This function is used for ddi_periodic_add(9F).
 *
 *  Arguments
 *
 *    func: the callback function
 *          the callback function will be invoked in kernel context if
 *          the level passed is the zero. Otherwise be invoked in interrupt
 *          context at the specified level by the argument "level".
 *
 *          Note that It's guaranteed by the cyclic subsystem that the
 *          function is invoked on the only one CPU and is never executed
 *          simultaneously even on MP system.
 *
 *     arg: the argument passed to the callback function
 *
 * interval: interval time in nanoseconds
 *          if the interval is the zero, the timer resolution is used.
 *
 *  level : callback interrupt level
 *          If the value is 0 (the zero), the callback function is invoked
 *          in kernel context. If the value is more than 0 (the zero), but
 *          less than or equal to 10, the callback function is invoked in
 *          interrupt context at the specified interrupt level.
 *          This value must be in range of 0-10.
 *
 *  Return value
 *    returns a non-zero opaque value (timeout_t) on success.
 *
 *  Caller's context
 *    i_timeout() can be called in user, kernel or interrupt context.
 *    It cannot be called in high interrupt context.
 *
 *  Note. This function is used by ddi_periodic_add(), which cannot
 *  be called in interrupt context. As a result, this function is called
 *  in user or kernel context only in practice.
 *
 */
timeout_t
i_timeout(void (*func)(void *), void *arg, hrtime_t interval, int level)
{
	hrtime_t start_time = gethrtime(), res;
	tm_req_t *req = NULL;

	/* Allocate and initialize the timeout request */
	req = kmem_cache_alloc(req_cache, KM_SLEEP);
	req->handler = func;
	req->arg = arg;
	req->h_thread = NULL;
	req->level = level;
	req->flags = 0;
	req->cnt = 0;
	mutex_init(&req->lock, NULL, MUTEX_ADAPTIVE, NULL);
	cv_init(&req->cv, NULL, CV_DEFAULT, NULL);

	/*
	 * The resolution must be finer than or equal to
	 * the requested interval. If it's not, set the resolution
	 * to the interval.
	 * Note. There is a restriction currently. Regardless of the
	 * clock resolution used here, 10ms is set as the timer resolution.
	 * Even on the 1ms resolution timer, the minimum interval is 10ms.
	 */
	if ((res = i_get_res()) > interval) {
		uintptr_t pc = (uintptr_t)req->handler;
		ulong_t off;
		cmn_err(CE_WARN,
		    "The periodic timeout (handler=%s, interval=%lld) "
		    "requests a finer interval than the supported resolution. "
		    "It rounds up to %lld\n", kobj_getsymname(pc, &off),
		    interval, res);
		interval = res;
	}

	/*
	 * If the specified interval is already multiples of
	 * the resolution, use it as is. Otherwise, it rounds
	 * up to multiples of the timer resolution.
	 */
	req->interval = roundup(interval, i_get_res());

	/*
	 * For the periodic timeout requests, the first expiration time will
	 * be adjusted to the timer tick edge to take advantage of the cyclic
	 * subsystem. In that case, the first fire is likely not an expected
	 * one, but the fires later can be more accurate due to this.
	 */
	req->exp_time = roundup(start_time + req->interval, i_get_res());

	/* Add the request to the timer */
	return (add_req(req));
}

/*
 *  void
 *  i_untimeout(timeout_t req)
 *
 *  Overview
 *    i_untimeout() is an internal function canceling the i_timeout()
 *    request previously issued.
 *    This function is used for ddi_periodic_delete(9F).
 *
 *  Argument
 *      req: timeout_t opaque value i_timeout() returned previously.
 *
 *  Return value
 *      Nothing.
 *
 *  Caller's context
 *    i_untimeout() can be called in user, kernel or interrupt context.
 *    It cannot be called in high interrupt context.
 *
 *  Note. This function is used by ddi_periodic_delete(), which cannot
 *  be called in interrupt context. As a result, this function is called
 *  in user or kernel context only in practice. Also i_untimeout() sends
 *  the cv_signal to timeout_execute(), which runs in interrupt context.
 *  Make sure this function will not be blocked, otherwise the deadlock
 *  situation can occur. See timeout_execute().
 */
void
i_untimeout(timeout_t timeout_req)
{
	timer_tw_t *tid;
	tm_req_t *req;
	timeout_t id;

	/* Retrieve the id for this timeout request */
	id = (timeout_t)timeout_req;
	tid = &ddi_timer->idhash[TM_HASH((uintptr_t)id)];

	mutex_enter(&tid->lock);
	for (req = list_head(&tid->req); req != NULL;
	    req = list_next(&tid->req, req)) {
		if (req->id == id)
			break;
	}
	if (req == NULL) {
		/* There is no requests with this id after all */
		mutex_exit(&tid->lock);
		return;
	}
	mutex_enter(&req->lock);

	/* Unregister this request first */
	list_remove(&tid->req, req);

	/* Notify that this request is canceled */
	req->flags |= TM_CANCEL;

	/* Check if the handler is invoked */
	if (req->flags & TM_INVOKING) {
		/*
		 * If this request is not yet executed or is already finished
		 * then there is nothing to do but just return. Otherwise
		 * we'll have to wait for the callback execution being complete.
		 */
		if (!(req->flags & TM_EXECUTING) || req->flags & TM_COMPLETE) {
			/* There is nothing to do any more */
			mutex_exit(&req->lock);
			mutex_exit(&tid->lock);
			return;
		}

		/*
		 * If this is the recursive call, there is nothing
		 * to do any more. This is the case that i_untimeout()
		 * is called in the handler.
		 */
		if (req->h_thread == curthread) {
			mutex_exit(&req->lock);
			mutex_exit(&tid->lock);
			return;
		}

		/*
		 * Notify that i_untimeout() is waiting until this request
		 * is complete.
		 */
		req->flags |= TM_COMPWAIT;
		mutex_exit(&tid->lock);

		/*
		 * Wait for this timeout request being complete before
		 * the return.
		 */
		while (!(req->flags & TM_COMPLETE))
			cv_wait(&req->cv, &req->lock);
		req->flags &= ~TM_COMPWAIT;
		cv_signal(&req->cv);
		mutex_exit(&req->lock);
		return;
	}
	mutex_exit(&req->lock);
	mutex_exit(&tid->lock);

	/*
	 * Notify untimeout() is about to be finished, and this request
	 * can be freed.
	 */
	atomic_or_uint(&req->flags, TM_UTMCOMP);
}
