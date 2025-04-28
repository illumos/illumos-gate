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

#include "lint.h"
#include "thr_uberdata.h"
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <thread.h>
#include <pthread.h>
#include <synch.h>
#include <port.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <sys/aiocb.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include "sigev_thread.h"

/*
 * There is but one spawner for all aio operations.
 */
thread_communication_data_t *sigev_aio_tcd = NULL;

/*
 * Set non-zero via _RT_DEBUG to enable debugging printf's.
 */
static int _rt_debug = 0;

void
init_sigev_thread(void)
{
	char *ldebug;

	if ((ldebug = getenv("_RT_DEBUG")) != NULL)
		_rt_debug = atoi(ldebug);
}

/*
 * Routine to print debug messages:
 * If _rt_debug is set, printf the debug message to stderr
 * with an appropriate prefix.
 */
/*PRINTFLIKE1*/
static void
_rt_dprintf(const char *format, ...)
{
	if (_rt_debug) {
		va_list alist;

		va_start(alist, format);
		flockfile(stderr);
		pthread_cleanup_push(funlockfile, stderr);
		(void) fputs("DEBUG: ", stderr);
		(void) vfprintf(stderr, format, alist);
		pthread_cleanup_pop(1);		/* funlockfile(stderr) */
		va_end(alist);
	}
}

/*
 * The notify_thread() function can be used as the start function of a new
 * thread but it is normally called from notifier(), below, in the context
 * of a thread pool worker thread.  It is used as the start function of a
 * new thread only when individual pthread attributes differ from those
 * that are common to all workers.  This only occurs in the AIO case.
 */
static void *
notify_thread(void *arg)
{
	sigev_thread_data_t *stdp = arg;
	void (*function)(union sigval) = stdp->std_func;
	union sigval argument = stdp->std_arg;

	lfree(stdp, sizeof (*stdp));
	function(argument);
	return (NULL);
}

/*
 * Thread pool interface to call the user-supplied notification function.
 */
static void
notifier(void *arg)
{
	(void) notify_thread(arg);
}

/*
 * This routine adds a new work request, described by function
 * and argument, to the list of outstanding jobs.
 * It returns 0 indicating success.  A value != 0 indicates an error.
 */
static int
sigev_add_work(thread_communication_data_t *tcdp,
    void (*function)(union sigval), union sigval argument)
{
	tpool_t *tpool = tcdp->tcd_poolp;
	sigev_thread_data_t *stdp;

	if (tpool == NULL)
		return (EINVAL);
	if ((stdp = lmalloc(sizeof (*stdp))) == NULL)
		return (errno);
	stdp->std_func = function;
	stdp->std_arg = argument;
	if (tpool_dispatch(tpool, notifier, stdp) != 0) {
		lfree(stdp, sizeof (*stdp));
		return (errno);
	}
	return (0);
}

static void
sigev_destroy_pool(thread_communication_data_t *tcdp)
{
	if (tcdp->tcd_poolp != NULL)
		tpool_abandon(tcdp->tcd_poolp);
	tcdp->tcd_poolp = NULL;

	if (tcdp->tcd_subsystem == MQ) {
		/*
		 * synchronize with del_sigev_mq()
		 */
		sig_mutex_lock(&tcdp->tcd_lock);
		tcdp->tcd_server_id = 0;
		if (tcdp->tcd_msg_closing) {
			(void) cond_broadcast(&tcdp->tcd_cv);
			sig_mutex_unlock(&tcdp->tcd_lock);
			return;		/* del_sigev_mq() will free the tcd */
		}
		sig_mutex_unlock(&tcdp->tcd_lock);
	}

	/*
	 * now delete everything
	 */
	free_sigev_handler(tcdp);
}

/*
 * timer_spawner(), mqueue_spawner(), and aio_spawner() are the main
 * functions for the daemon threads that get the event(s) for the
 * respective SIGEV_THREAD subsystems.  There is one timer spawner for
 * each timer_create(), one mqueue spawner for every mq_open(), and
 * exactly one aio spawner for all aio requests.  These spawners add
 * work requests to be done by a pool of daemon worker threads.  In case
 * the event requires creation of a worker thread with different pthread
 * attributes than those from the pool of workers, a new daemon thread
 * with these attributes is spawned apart from the pool of workers.
 * If the spawner fails to add work or fails to create an additional
 * thread because of lacking resources, it puts the event back into
 * the kernel queue and re-tries some time later.
 */

void *
timer_spawner(void *arg)
{
	thread_communication_data_t *tcdp = (thread_communication_data_t *)arg;
	port_event_t port_event;

	/* destroy the pool if we are cancelled */
	pthread_cleanup_push(sigev_destroy_pool, tcdp);

	for (;;) {
		if (port_get(tcdp->tcd_port, &port_event, NULL) != 0) {
			_rt_dprintf("port_get on port %d failed with %d <%s>\n",
			    tcdp->tcd_port, errno, strerror(errno));
			break;
		}
		switch (port_event.portev_source) {
		case PORT_SOURCE_TIMER:
			break;
		case PORT_SOURCE_ALERT:
			if (port_event.portev_events != SIGEV_THREAD_TERM)
				errno = EPROTO;
			goto out;
		default:
			_rt_dprintf("port_get on port %d returned %u "
			    "(not PORT_SOURCE_TIMER)\n",
			    tcdp->tcd_port, port_event.portev_source);
			errno = EPROTO;
			goto out;
		}

		tcdp->tcd_overruns = port_event.portev_events - 1;
		if (sigev_add_work(tcdp,
		    tcdp->tcd_notif.sigev_notify_function,
		    tcdp->tcd_notif.sigev_value) != 0)
			break;
		/* wait until job is done before looking for another */
		tpool_wait(tcdp->tcd_poolp);
	}
out:
	pthread_cleanup_pop(1);
	return (NULL);
}

void *
mqueue_spawner(void *arg)
{
	thread_communication_data_t *tcdp = (thread_communication_data_t *)arg;
	int ret = 0;
	int ntype;
	void (*function)(union sigval);
	union sigval argument;

	/* destroy the pool if we are cancelled */
	pthread_cleanup_push(sigev_destroy_pool, tcdp);

	while (ret == 0) {
		sig_mutex_lock(&tcdp->tcd_lock);
		pthread_cleanup_push(sig_mutex_unlock, &tcdp->tcd_lock);
		while ((ntype = tcdp->tcd_msg_enabled) == 0)
			(void) sig_cond_wait(&tcdp->tcd_cv, &tcdp->tcd_lock);
		pthread_cleanup_pop(1);

		while (sem_wait(tcdp->tcd_msg_avail) == -1)
			continue;

		sig_mutex_lock(&tcdp->tcd_lock);
		tcdp->tcd_msg_enabled = 0;
		sig_mutex_unlock(&tcdp->tcd_lock);

		/* ASSERT(ntype == SIGEV_THREAD || ntype == SIGEV_PORT); */
		if (ntype == SIGEV_THREAD) {
			function = tcdp->tcd_notif.sigev_notify_function;
			argument.sival_ptr = tcdp->tcd_msg_userval;
			ret = sigev_add_work(tcdp, function, argument);
		} else {	/* ntype == SIGEV_PORT */
			ret = _port_dispatch(tcdp->tcd_port, 0, PORT_SOURCE_MQ,
			    0, (uintptr_t)tcdp->tcd_msg_object,
			    tcdp->tcd_msg_userval);
		}
	}
	sig_mutex_unlock(&tcdp->tcd_lock);

	pthread_cleanup_pop(1);
	return (NULL);
}

void *
aio_spawner(void *arg)
{
	thread_communication_data_t *tcdp = (thread_communication_data_t *)arg;
	int error = 0;
	void (*function)(union sigval);
	union sigval argument;
	port_event_t port_event;
	struct sigevent *sigevp;
	timespec_t delta;
	pthread_attr_t *attrp;

	/* destroy the pool if we are cancelled */
	pthread_cleanup_push(sigev_destroy_pool, tcdp);

	while (error == 0) {
		if (port_get(tcdp->tcd_port, &port_event, NULL) != 0) {
			error = errno;
			_rt_dprintf("port_get on port %d failed with %d <%s>\n",
			    tcdp->tcd_port, error, strerror(error));
			break;
		}
		switch (port_event.portev_source) {
		case PORT_SOURCE_AIO:
			break;
		case PORT_SOURCE_ALERT:
			if (port_event.portev_events != SIGEV_THREAD_TERM)
				errno = EPROTO;
			goto out;
		default:
			_rt_dprintf("port_get on port %d returned %u "
			    "(not PORT_SOURCE_AIO)\n",
			    tcdp->tcd_port, port_event.portev_source);
			errno = EPROTO;
			goto out;
		}
		argument.sival_ptr = port_event.portev_user;
		switch (port_event.portev_events) {
		case AIOLIO:
#if !defined(_LP64)
		case AIOLIO64:
#endif
			sigevp = (struct sigevent *)port_event.portev_object;
			function = sigevp->sigev_notify_function;
			attrp = sigevp->sigev_notify_attributes;
			break;
		case AIOAREAD:
		case AIOAWRITE:
		case AIOFSYNC:
			{
			aiocb_t *aiocbp =
			    (aiocb_t *)port_event.portev_object;
			function = aiocbp->aio_sigevent.sigev_notify_function;
			attrp = aiocbp->aio_sigevent.sigev_notify_attributes;
			break;
			}
#if !defined(_LP64)
		case AIOAREAD64:
		case AIOAWRITE64:
		case AIOFSYNC64:
			{
			aiocb64_t *aiocbp =
			    (aiocb64_t *)port_event.portev_object;
			function = aiocbp->aio_sigevent.sigev_notify_function;
			attrp = aiocbp->aio_sigevent.sigev_notify_attributes;
			break;
			}
#endif
		default:
			function = NULL;
			attrp = NULL;
			break;
		}

		if (function == NULL)
			error = EINVAL;
		else if (pthread_attr_equal(attrp, tcdp->tcd_attrp))
			error = sigev_add_work(tcdp, function, argument);
		else {
			/*
			 * The attributes don't match.
			 * Spawn a thread with the non-matching attributes.
			 */
			pthread_attr_t local_attr;
			sigev_thread_data_t *stdp;

			if ((stdp = lmalloc(sizeof (*stdp))) == NULL)
				error = ENOMEM;
			else
				error = pthread_attr_clone(&local_attr, attrp);

			if (error == 0) {
				(void) pthread_attr_setdetachstate(
				    &local_attr, PTHREAD_CREATE_DETACHED);
				(void) pthread_attr_setdaemonstate_np(
				    &local_attr, PTHREAD_CREATE_DAEMON_NP);
				stdp->std_func = function;
				stdp->std_arg = argument;
				error = pthread_create(NULL, &local_attr,
				    notify_thread, stdp);
				(void) pthread_attr_destroy(&local_attr);
			}
			if (error && stdp != NULL)
				lfree(stdp, sizeof (*stdp));
		}

		if (error) {
			_rt_dprintf("Cannot add work, error=%d <%s>.\n",
			    error, strerror(error));
			if (error == EAGAIN || error == ENOMEM) {
				/* (Temporary) no resources are available. */
				if (_port_dispatch(tcdp->tcd_port, 0,
				    PORT_SOURCE_AIO, port_event.portev_events,
				    port_event.portev_object,
				    port_event.portev_user) != 0)
					break;
				error = 0;
				delta.tv_sec = 0;
				delta.tv_nsec = NANOSEC / 20;	/* 50 msec */
				(void) nanosleep(&delta, NULL);
			}
		}
	}
out:
	pthread_cleanup_pop(1);
	return (NULL);
}

/*
 * Allocate a thread_communication_data_t block.
 */
static thread_communication_data_t *
alloc_sigev_handler(subsystem_t caller)
{
	thread_communication_data_t *tcdp;

	if ((tcdp = lmalloc(sizeof (*tcdp))) != NULL) {
		tcdp->tcd_subsystem = caller;
		tcdp->tcd_port = -1;
		(void) mutex_init(&tcdp->tcd_lock, USYNC_THREAD, NULL);
		(void) cond_init(&tcdp->tcd_cv, USYNC_THREAD, NULL);
	}
	return (tcdp);
}

/*
 * Free a thread_communication_data_t block.
 */
void
free_sigev_handler(thread_communication_data_t *tcdp)
{
	if (tcdp->tcd_attrp) {
		(void) pthread_attr_destroy(tcdp->tcd_attrp);
		tcdp->tcd_attrp = NULL;
	}
	(void) memset(&tcdp->tcd_notif, 0, sizeof (tcdp->tcd_notif));

	switch (tcdp->tcd_subsystem) {
	case TIMER:
	case AIO:
		if (tcdp->tcd_port >= 0)
			(void) close(tcdp->tcd_port);
		break;
	case MQ:
		tcdp->tcd_msg_avail = NULL;
		tcdp->tcd_msg_object = NULL;
		tcdp->tcd_msg_userval = NULL;
		tcdp->tcd_msg_enabled = 0;
		break;
	}

	lfree(tcdp, sizeof (*tcdp));
}

/*
 * Initialize data structure and create the port.
 */
thread_communication_data_t *
setup_sigev_handler(const struct sigevent *sigevp, subsystem_t caller)
{
	thread_communication_data_t *tcdp;
	int error;

	if (sigevp == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if ((tcdp = alloc_sigev_handler(caller)) == NULL) {
		errno = ENOMEM;
		return (NULL);
	}

	if (sigevp->sigev_notify_attributes == NULL)
		tcdp->tcd_attrp = NULL;		/* default attributes */
	else {
		/*
		 * We cannot just copy the sigevp->sigev_notify_attributes
		 * pointer.  We need to initialize a new pthread_attr_t
		 * structure with the values from the user-supplied
		 * pthread_attr_t.
		 */
		tcdp->tcd_attrp = &tcdp->tcd_user_attr;
		error = pthread_attr_clone(tcdp->tcd_attrp,
		    sigevp->sigev_notify_attributes);
		if (error) {
			tcdp->tcd_attrp = NULL;
			free_sigev_handler(tcdp);
			errno = error;
			return (NULL);
		}
	}
	tcdp->tcd_notif = *sigevp;
	tcdp->tcd_notif.sigev_notify_attributes = tcdp->tcd_attrp;

	if (caller == TIMER || caller == AIO) {
		if ((tcdp->tcd_port = port_create()) < 0 ||
		    fcntl(tcdp->tcd_port, FD_CLOEXEC) == -1) {
			free_sigev_handler(tcdp);
			errno = EBADF;
			return (NULL);
		}
	}
	return (tcdp);
}

/*
 * Create a thread pool and launch the spawner.
 */
int
launch_spawner(thread_communication_data_t *tcdp)
{
	int ret;
	int maxworkers;
	void *(*spawner)(void *);
	sigset_t set;
	sigset_t oset;

	switch (tcdp->tcd_subsystem) {
	case TIMER:
		spawner = timer_spawner;
		maxworkers = 1;
		break;
	case MQ:
		spawner = mqueue_spawner;
		maxworkers = 1;
		break;
	case AIO:
		spawner = aio_spawner;
		maxworkers = 100;
		break;
	default:
		return (-1);
	}
	tcdp->tcd_poolp = tpool_create(1, maxworkers, 20,
	    tcdp->tcd_notif.sigev_notify_attributes);
	if (tcdp->tcd_poolp == NULL)
		return (-1);
	/* create the spawner with all signals blocked */
	(void) sigfillset(&set);
	(void) thr_sigsetmask(SIG_SETMASK, &set, &oset);
	ret = thr_create(NULL, 0, spawner, tcdp,
	    THR_DETACHED | THR_DAEMON, &tcdp->tcd_server_id);
	(void) thr_sigsetmask(SIG_SETMASK, &oset, NULL);
	if (ret != 0) {
		tpool_destroy(tcdp->tcd_poolp);
		tcdp->tcd_poolp = NULL;
		return (-1);
	}
	return (0);
}

/*
 * Delete the data associated with the sigev_thread timer, if timer is
 * associated with such a notification option.
 * Destroy the timer_spawner thread.
 */
int
del_sigev_timer(timer_t timer)
{
	int rc = 0;
	thread_communication_data_t *tcdp;

	if ((uint_t)timer < timer_max && (tcdp = timer_tcd[timer]) != NULL) {
		sig_mutex_lock(&tcdp->tcd_lock);
		if (tcdp->tcd_port >= 0) {
			if ((rc = port_alert(tcdp->tcd_port,
			    PORT_ALERT_SET, SIGEV_THREAD_TERM, NULL)) == 0) {
				_rt_dprintf("del_sigev_timer(%d) OK.\n", timer);
			}
		}
		timer_tcd[timer] = NULL;
		sig_mutex_unlock(&tcdp->tcd_lock);
	}
	return (rc);
}

int
sigev_timer_getoverrun(timer_t timer)
{
	thread_communication_data_t *tcdp;

	if ((uint_t)timer < timer_max && (tcdp = timer_tcd[timer]) != NULL)
		return (tcdp->tcd_overruns);
	return (0);
}

static void
del_sigev_mq_cleanup(thread_communication_data_t *tcdp)
{
	sig_mutex_unlock(&tcdp->tcd_lock);
	free_sigev_handler(tcdp);
}

/*
 * Delete the data associated with the sigev_thread message queue,
 * if the message queue is associated with such a notification option.
 * Destroy the mqueue_spawner thread.
 */
void
del_sigev_mq(thread_communication_data_t *tcdp)
{
	pthread_t server_id;
	int rc;

	sig_mutex_lock(&tcdp->tcd_lock);

	server_id = tcdp->tcd_server_id;
	tcdp->tcd_msg_closing = 1;
	if ((rc = pthread_cancel(server_id)) != 0) {	/* "can't happen" */
		sig_mutex_unlock(&tcdp->tcd_lock);
		_rt_dprintf("Fail to cancel %u with error %d <%s>.\n",
		    server_id, rc, strerror(rc));
		return;
	}

	/*
	 * wait for sigev_destroy_pool() to finish
	 */
	pthread_cleanup_push(del_sigev_mq_cleanup, tcdp);
	while (tcdp->tcd_server_id == server_id)
		(void) sig_cond_wait(&tcdp->tcd_cv, &tcdp->tcd_lock);
	pthread_cleanup_pop(1);
}

/*
 * POSIX aio:
 * If the notification type is SIGEV_THREAD, set up
 * the port number for notifications.  Create the
 * thread pool and launch the spawner if necessary.
 * If the notification type is not SIGEV_THREAD, do nothing.
 */
int
_aio_sigev_thread_init(struct sigevent *sigevp)
{
	static mutex_t sigev_aio_lock = DEFAULTMUTEX;
	static cond_t sigev_aio_cv = DEFAULTCV;
	static int sigev_aio_busy = 0;

	thread_communication_data_t *tcdp;
	int port;
	int cancel_state;
	int rc = 0;

	if (sigevp == NULL ||
	    sigevp->sigev_notify != SIGEV_THREAD ||
	    sigevp->sigev_notify_function == NULL)
		return (0);

	lmutex_lock(&sigev_aio_lock);
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	while (sigev_aio_busy)
		(void) cond_wait(&sigev_aio_cv, &sigev_aio_lock);
	(void) pthread_setcancelstate(cancel_state, NULL);
	if ((tcdp = sigev_aio_tcd) != NULL)
		port = tcdp->tcd_port;
	else {
		sigev_aio_busy = 1;
		lmutex_unlock(&sigev_aio_lock);

		tcdp = setup_sigev_handler(sigevp, AIO);
		if (tcdp == NULL) {
			port = -1;
			rc = -1;
		} else if (launch_spawner(tcdp) != 0) {
			free_sigev_handler(tcdp);
			tcdp = NULL;
			port = -1;
			rc = -1;
		} else {
			port = tcdp->tcd_port;
		}

		lmutex_lock(&sigev_aio_lock);
		sigev_aio_tcd = tcdp;
		sigev_aio_busy = 0;
		(void) cond_broadcast(&sigev_aio_cv);
	}
	lmutex_unlock(&sigev_aio_lock);
	sigevp->sigev_signo = port;
	return (rc);
}

int
_aio_sigev_thread(aiocb_t *aiocbp)
{
	if (aiocbp == NULL)
		return (0);
	return (_aio_sigev_thread_init(&aiocbp->aio_sigevent));
}

#if !defined(_LP64)
int
_aio_sigev_thread64(aiocb64_t *aiocbp)
{
	if (aiocbp == NULL)
		return (0);
	return (_aio_sigev_thread_init(&aiocbp->aio_sigevent));
}
#endif

/*
 * Cleanup POSIX aio after fork1() in the child process.
 */
void
postfork1_child_sigev_aio(void)
{
	thread_communication_data_t *tcdp;

	if ((tcdp = sigev_aio_tcd) != NULL) {
		sigev_aio_tcd = NULL;
		tcd_teardown(tcdp);
	}
}

/*
 * Utility function for the various postfork1_child_sigev_*() functions.
 * Clean up the tcdp data structure and close the port.
 */
void
tcd_teardown(thread_communication_data_t *tcdp)
{
	if (tcdp->tcd_poolp != NULL)
		tpool_abandon(tcdp->tcd_poolp);
	tcdp->tcd_poolp = NULL;
	tcdp->tcd_server_id = 0;
	free_sigev_handler(tcdp);
}
