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

/*
 * Simple implementation of timeout functionality. The granuality is a sec
 */
#include <pthread.h>
#include <stdlib.h>

uint_t		sip_timeout(void *arg, void (*callback_func)(void *),
		    struct timeval *timeout_time);
boolean_t	sip_untimeout(uint_t);

typedef struct timeout {
	struct timeout *sip_timeout_next;
	hrtime_t sip_timeout_val;
	void (*sip_timeout_callback_func)(void *);
	void *sip_timeout_callback_func_arg;
	int   sip_timeout_id;
} sip_timeout_t;

static pthread_mutex_t timeout_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  timeout_cond_var = PTHREAD_COND_INITIALIZER;
static sip_timeout_t *timeout_list;
static sip_timeout_t *timeout_current_start;
static sip_timeout_t *timeout_current_end;

/*
 * LONG_SLEEP_TIME = (24 * 60 * 60 * NANOSEC)
 */
#define	LONG_SLEEP_TIME	(0x15180LL * 0x3B9ACA00LL)

uint_t timer_id = 0;

/*
 * Invoke the callback function
 */
/* ARGSUSED */
static void *
sip_run_to_functions(void *arg)
{
	sip_timeout_t *timeout = NULL;

	(void) pthread_mutex_lock(&timeout_mutex);
	while (timeout_current_start != NULL) {
		timeout = timeout_current_start;
		if (timeout_current_end == timeout_current_start)
			timeout_current_start = timeout_current_end = NULL;
		else
			timeout_current_start = timeout->sip_timeout_next;
		(void) pthread_mutex_unlock(&timeout_mutex);
		timeout->sip_timeout_callback_func(
		    timeout->sip_timeout_callback_func_arg);
		free(timeout);
		(void) pthread_mutex_lock(&timeout_mutex);
	}
	(void) pthread_mutex_unlock(&timeout_mutex);
	pthread_exit(NULL);
	return ((void *)0);
}

/*
 * In the very very unlikely case timer id wraps around and we have two timers
 * with the same id. If that happens timer with the least amount of time left
 * will be deleted. In case both timers have same time left than the one that
 * was scheduled first will be deleted as it will be in the front of the list.
 */
boolean_t
sip_untimeout(uint_t id)
{
	boolean_t	ret = B_FALSE;
	sip_timeout_t	*current, *last;

	last = NULL;
	(void) pthread_mutex_lock(&timeout_mutex);

	/*
	 * Check if this is in the to-be run list
	 */
	if (timeout_current_start != NULL) {
		current = timeout_current_start;
		while (current != NULL) {
			if (current->sip_timeout_id == id) {
				if (current == timeout_current_start) {
					timeout_current_start =
					    current->sip_timeout_next;
				} else {
					last->sip_timeout_next =
					    current->sip_timeout_next;
				}
				if (current == timeout_current_end)
					timeout_current_end = last;
				if (current->sip_timeout_callback_func_arg !=
				    NULL) {
					free(current->
					    sip_timeout_callback_func_arg);
					current->sip_timeout_callback_func_arg =
					    NULL;
				}
				free(current);
				ret = B_TRUE;
				break;
			}
			last = current;
			current = current->sip_timeout_next;
		}
	}

	/*
	 * Check if this is in the to-be scheduled list
	 */
	if (!ret && timeout_list != NULL) {
		last = NULL;
		current = timeout_list;
		while (current != NULL) {
			if (current->sip_timeout_id == id) {
				if (current == timeout_list) {
					timeout_list =
					    current->sip_timeout_next;
				} else {
					last->sip_timeout_next =
					    current->sip_timeout_next;
				}
				if (current->sip_timeout_callback_func_arg !=
				    NULL) {
					free(current->
					    sip_timeout_callback_func_arg);
					current->sip_timeout_callback_func_arg =
					    NULL;
				}
				free(current);
				ret = B_TRUE;
				break;
			}
			last = current;
			current = current->sip_timeout_next;
		}
	}
	(void) pthread_mutex_unlock(&timeout_mutex);
	return (ret);
}

/*
 * Add a new timeout
 */
uint_t
sip_timeout(void *arg, void (*callback_func)(void *),
    struct timeval *timeout_time)
{
	sip_timeout_t	*new_timeout;
	sip_timeout_t	*current;
	sip_timeout_t	*last;
	hrtime_t	future_time;
	uint_t		tid;
#ifdef	__linux__
	struct timespec	tspec;
	hrtime_t	now;
#endif

	new_timeout = malloc(sizeof (sip_timeout_t));
	if (new_timeout == NULL)
		return (0);

#ifdef	__linux__
	if (clock_gettime(CLOCK_REALTIME, &tspec) != 0)
		return (0);
	now = (hrtime_t)tspec.tv_sec * (hrtime_t)NANOSEC + tspec.tv_nsec;
	future_time = (hrtime_t)timeout_time->tv_sec * (hrtime_t)NANOSEC +
	    (hrtime_t)(timeout_time->tv_usec * MILLISEC) + now;
#else
	future_time = (hrtime_t)timeout_time->tv_sec * (hrtime_t)NANOSEC +
	    (hrtime_t)(timeout_time->tv_usec * MILLISEC) + gethrtime();
#endif
	if (future_time <= 0L) {
		free(new_timeout);
		return (0);
	}

	new_timeout->sip_timeout_next = NULL;
	new_timeout->sip_timeout_val = future_time;
	new_timeout->sip_timeout_callback_func = callback_func;
	new_timeout->sip_timeout_callback_func_arg = arg;
	(void) pthread_mutex_lock(&timeout_mutex);
	timer_id++;
	if (timer_id == 0)
		timer_id++;
	tid = timer_id;
	new_timeout->sip_timeout_id = tid;
	last = current = timeout_list;
	while (current != NULL) {
		if (current->sip_timeout_val <= new_timeout->sip_timeout_val) {
			last = current;
			current = current->sip_timeout_next;
		} else {
			break;
		}
	}

	if (current == timeout_list) {
		new_timeout->sip_timeout_next  = timeout_list;
		timeout_list = new_timeout;
	} else {
		new_timeout->sip_timeout_next = current,
		last->sip_timeout_next = new_timeout;
	}
	(void) pthread_cond_signal(&timeout_cond_var);
	(void) pthread_mutex_unlock(&timeout_mutex);
	return (tid);
}

/*
 * Schedule the next timeout
 */
static hrtime_t
sip_schedule_to_functions()
{
	sip_timeout_t		*timeout = NULL;
	sip_timeout_t		*last = NULL;
	boolean_t		create_thread = B_FALSE;
	hrtime_t		current_time;
#ifdef	__linux__
	struct timespec	tspec;
#endif

	/*
	 * Thread is holding the mutex.
	 */
#ifdef	__linux__
	if (clock_gettime(CLOCK_REALTIME, &tspec) != 0)
		return ((hrtime_t)LONG_SLEEP_TIME + current_time);
	current_time = (hrtime_t)tspec.tv_sec * (hrtime_t)NANOSEC +
	    tspec.tv_nsec;
#else
	current_time = gethrtime();
#endif
	if (timeout_list == NULL)
		return ((hrtime_t)LONG_SLEEP_TIME + current_time);
	timeout = timeout_list;

	/*
	 * Get all the timeouts that have fired.
	 */
	while (timeout != NULL && timeout->sip_timeout_val <= current_time) {
		last = timeout;
		timeout = timeout->sip_timeout_next;
	}

	timeout = last;
	if (timeout != NULL) {
		if (timeout_current_end != NULL) {
			timeout_current_end->sip_timeout_next = timeout_list;
			timeout_current_end = timeout;
		} else {
			timeout_current_start = timeout_list;
			timeout_current_end = timeout;
			create_thread = B_TRUE;
		}
		timeout_list = timeout->sip_timeout_next;
		timeout->sip_timeout_next = NULL;
		if (create_thread) {
			pthread_t	thr;

			(void) pthread_create(&thr, NULL, sip_run_to_functions,
			    NULL);
			(void) pthread_detach(thr);
		}
	}
	if (timeout_list != NULL)
		return (timeout_list->sip_timeout_val);
	else
		return ((hrtime_t)LONG_SLEEP_TIME + current_time);
}

/*
 * The timer routine
 */
/* ARGSUSED */
static void *
sip_timer_thr(void *arg)
{
	timestruc_t	to;
	hrtime_t	current_time;
	hrtime_t	next_timeout;
	hrtime_t	delta;
	struct timeval tim;
#ifdef	__linux__
	struct timespec	tspec;
#endif
	delta = (hrtime_t)5 * NANOSEC;
	(void) pthread_mutex_lock(&timeout_mutex);
	for (;;) {
		(void) gettimeofday(&tim, NULL);
		to.tv_sec = tim.tv_sec + (delta / NANOSEC);
		to.tv_nsec = (hrtime_t)(tim.tv_usec * MILLISEC) +
		    (delta % NANOSEC);
		if (to.tv_nsec > NANOSEC) {
			to.tv_sec += (to.tv_nsec / NANOSEC);
			to.tv_nsec %= NANOSEC;
		}
		(void) pthread_cond_timedwait(&timeout_cond_var,
		    &timeout_mutex, &to);
		/*
		 * We return from timedwait because we either timed out
		 * or a new element was added and we need to reset the time
		 */
again:
		next_timeout =  sip_schedule_to_functions();
#ifdef	__linux__
		if (clock_gettime(CLOCK_REALTIME, &tspec) != 0)
			goto again; /* ??? */
		current_time = (hrtime_t)tspec.tv_sec * (hrtime_t)NANOSEC +
		    tspec.tv_nsec;
#else
		current_time = gethrtime();
#endif
		delta = next_timeout - current_time;
		if (delta <= 0)
			goto again;
	}
	/* NOTREACHED */
	return ((void *)0);
}

/*
 * The init routine, starts the timer thread
 */
void
sip_timeout_init()
{
	static boolean_t	timout_init = B_FALSE;
	pthread_t		thread1;

	(void) pthread_mutex_lock(&timeout_mutex);
	if (timout_init == B_FALSE) {
		timout_init = B_TRUE;
		(void) pthread_mutex_unlock(&timeout_mutex);
	} else {
		(void) pthread_mutex_unlock(&timeout_mutex);
		return;
	}
	(void) pthread_create(&thread1, NULL, sip_timer_thr, NULL);
}
