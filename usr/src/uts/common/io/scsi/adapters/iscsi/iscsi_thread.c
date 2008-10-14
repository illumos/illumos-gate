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

#include "iscsi_thread.h"

static	void	iscsi_threads_entry(void *arg);

/*
 * iscsi_thread_create - Creates the needed resources to handle a thread
 */
iscsi_thread_t *
iscsi_thread_create(dev_info_t *dip, char *name,
    iscsi_thread_ep_t entry_point, void *arg)
{
	iscsi_thread_t		*thread;

	thread = kmem_zalloc(sizeof (iscsi_thread_t), KM_SLEEP);

	if (thread != NULL) {

		thread->tq = ddi_taskq_create(dip, name, 1,
		    TASKQ_DEFAULTPRI, 0);

		if (thread->tq != NULL) {
			thread->signature	= SIG_ISCSI_THREAD;
			thread->dip		= dip;
			thread->entry_point	= entry_point;
			thread->arg		= arg;
			thread->state		= ISCSI_THREAD_STATE_STOPPED;
			thread->sign.bitmap	= 0;
			mutex_init(&thread->mgnt.mtx, NULL, MUTEX_DRIVER, NULL);
			mutex_init(&thread->sign.mtx, NULL, MUTEX_DRIVER, NULL);
			cv_init(&thread->sign.cdv, NULL, CV_DRIVER, NULL);
		} else {
			kmem_free(thread, sizeof (iscsi_thread_t));
			thread = NULL;
		}
	}

	return (thread);
}

/*
 * iscsi_thread_destroy - Releases the needed resources to handle a thread
 */
void
iscsi_thread_destroy(
	iscsi_thread_t		*thread
)
{
	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	mutex_enter(&thread->mgnt.mtx);

	switch (thread->state) {

	case ISCSI_THREAD_STATE_STARTED:

		/* A kill signal is sent first. */
		thread->state = ISCSI_THREAD_STATE_DESTROYING;
		mutex_enter(&thread->sign.mtx);
		if (!(thread->sign.bitmap & ISCSI_THREAD_SIGNAL_KILL)) {
			thread->sign.bitmap |= ISCSI_THREAD_SIGNAL_KILL;
			cv_signal(&thread->sign.cdv);
		}
		mutex_exit(&thread->sign.mtx);
		ddi_taskq_wait(thread->tq);
		break;

	case ISCSI_THREAD_STATE_STOPPED:

		/* Switch the state and wait for the thread to exit. */
		thread->state = ISCSI_THREAD_STATE_DESTROYING;
		break;

	default:
		ASSERT(0);
		break;
	}

	mutex_exit(&thread->mgnt.mtx);
	ddi_taskq_destroy(thread->tq);
	cv_destroy(&thread->sign.cdv);
	mutex_destroy(&thread->sign.mtx);
	mutex_destroy(&thread->mgnt.mtx);
	thread->signature = (uint32_t)~SIG_ISCSI_THREAD;
	kmem_free(thread, sizeof (iscsi_thread_t));
}

/*
 * iscsi_thread_start - Starts the thread given as an entry parameter
 */
boolean_t
iscsi_thread_start(
	iscsi_thread_t		*thread
)
{
	boolean_t		ret = B_FALSE;

	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	mutex_enter(&thread->mgnt.mtx);

	switch (thread->state) {

	case ISCSI_THREAD_STATE_STARTED:

		mutex_enter(&thread->sign.mtx);

		thread->state = ISCSI_THREAD_STATE_STOPPING;

		if (!(thread->sign.bitmap & ISCSI_THREAD_SIGNAL_KILL)) {
			thread->sign.bitmap |= ISCSI_THREAD_SIGNAL_KILL;
			cv_signal(&thread->sign.cdv);
		}
		mutex_exit(&thread->sign.mtx);
		ddi_taskq_wait(thread->tq);
		thread->state = ISCSI_THREAD_STATE_STOPPED;
		/* FALLTHRU */

	case ISCSI_THREAD_STATE_STOPPED:

		thread->sign.bitmap = 0;
		thread->state	    = ISCSI_THREAD_STATE_STARTING;

		if (ddi_taskq_dispatch(thread->tq, iscsi_threads_entry,
		    thread, DDI_SLEEP) == DDI_SUCCESS) {
			/*
			 * The dispatch succeeded.
			 */
			thread->state = ISCSI_THREAD_STATE_STARTED;
			ret = B_TRUE;
		}
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&thread->mgnt.mtx);
	return (ret);
}

/*
 * iscsi_thread_stop -
 */
boolean_t
iscsi_thread_stop(
	iscsi_thread_t		*thread
)
{
	boolean_t		ret = B_FALSE;

	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	mutex_enter(&thread->mgnt.mtx);

	switch (thread->state) {

	case ISCSI_THREAD_STATE_STARTED:

		mutex_enter(&thread->sign.mtx);

		thread->state = ISCSI_THREAD_STATE_STOPPING;

		if (!(thread->sign.bitmap & ISCSI_THREAD_SIGNAL_KILL)) {
			thread->sign.bitmap |= ISCSI_THREAD_SIGNAL_KILL;
			cv_signal(&thread->sign.cdv);
		}
		mutex_exit(&thread->sign.mtx);
		ddi_taskq_wait(thread->tq);
		thread->state = ISCSI_THREAD_STATE_STOPPED;
		ret = B_TRUE;
		break;

	case ISCSI_THREAD_STATE_STOPPED:
		ret = B_TRUE;
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&thread->mgnt.mtx);
	return (ret);
}

/*
 * iscsi_thread_send_kill -
 */
void
iscsi_thread_send_kill(
	iscsi_thread_t		*thread
)
{
	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	mutex_enter(&thread->mgnt.mtx);

	switch (thread->state) {

	case ISCSI_THREAD_STATE_STARTED:

		mutex_enter(&thread->sign.mtx);
		if (!(thread->sign.bitmap & ISCSI_THREAD_SIGNAL_KILL)) {
			thread->sign.bitmap |= ISCSI_THREAD_SIGNAL_KILL;
			cv_signal(&thread->sign.cdv);
		}
		mutex_exit(&thread->sign.mtx);
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&thread->mgnt.mtx);
}

/*
 * iscsi_thread_send_wakeup -
 */
void
iscsi_thread_send_wakeup(
	iscsi_thread_t		*thread
)
{
	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	mutex_enter(&thread->mgnt.mtx);

	switch (thread->state) {

	case ISCSI_THREAD_STATE_STARTED:

		mutex_enter(&thread->sign.mtx);
		if (!(thread->sign.bitmap & ISCSI_THREAD_SIGNAL_WAKEUP)) {
			thread->sign.bitmap |= ISCSI_THREAD_SIGNAL_WAKEUP;
			cv_signal(&thread->sign.cdv);
		}
		mutex_exit(&thread->sign.mtx);
		break;

	default:
		break;
	}
	mutex_exit(&thread->mgnt.mtx);
}

/*
 * iscsi_thread_check_signals -
 */
uint32_t
iscsi_thread_check_signals(
	iscsi_thread_t		*thread
)
{
	uint32_t		bitmap;

	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	/* Acquire the mutex before anychecking. */
	mutex_enter(&thread->sign.mtx);
	bitmap = thread->sign.bitmap;
	mutex_exit(&thread->sign.mtx);
	return (bitmap);
}
/*
 * iscsi_thread_wait -
 */
int
iscsi_thread_wait(
	iscsi_thread_t		*thread,
	clock_t			timeout
)
{
	int			rtn = 1;

	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	/* Acquire the mutex before anychecking. */
	mutex_enter(&thread->sign.mtx);

	/* Check the signals. */
	if (thread->sign.bitmap & ISCSI_THREAD_SIGNAL_KILL) {
		goto signal_kill;
	} else if (thread->sign.bitmap & ISCSI_THREAD_SIGNAL_WAKEUP) {
		goto signal_wakeup;
	} else if (timeout == 0) {
		goto iscsi_thread_sleep_exit;
	}

	if (timeout == -1) {
		cv_wait(&thread->sign.cdv, &thread->sign.mtx);
	} else {
		rtn = cv_timedwait(&thread->sign.cdv, &thread->sign.mtx,
		    (ddi_get_lbolt() + timeout));
	}

	/* Check the signals. */
	if (thread->sign.bitmap & ISCSI_THREAD_SIGNAL_KILL) {
		goto signal_kill;
	} else if (thread->sign.bitmap & ISCSI_THREAD_SIGNAL_WAKEUP) {
		goto signal_wakeup;
	}

iscsi_thread_sleep_exit:
	mutex_exit(&thread->sign.mtx);
	return (rtn);

signal_kill:
	mutex_exit(&thread->sign.mtx);
	return (0);

signal_wakeup:
	thread->sign.bitmap &= ~ISCSI_THREAD_SIGNAL_WAKEUP;
	mutex_exit(&thread->sign.mtx);
	return (1);
}

/*
 * iscsi_threads_entry - Common entry point for all threads
 */
static
void
iscsi_threads_entry(
	void			*arg
)
{
	iscsi_thread_t		*thread;

	thread = (iscsi_thread_t *)arg;

	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	(thread->entry_point)(thread, thread->arg);
}
