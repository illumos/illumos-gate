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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/tzfile.h>
#include <sys/atomic.h>
#include <sys/kidmap.h>
#include <sys/time.h>
#include <sys/spl.h>
#include <sys/random.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_xdr.h>
#include <smbsrv/smb_vops.h>
#include <smbsrv/smb_idmap.h>

#include <sys/sid.h>
#include <sys/priv_names.h>

#ifdef	_FAKE_KERNEL
#define	THR_TO_DID(t)	((kt_did_t)(uintptr_t)t)
#else
#define	THR_TO_DID(t)	(t->t_did)
#endif

static boolean_t smb_thread_continue_timedwait_locked(smb_thread_t *, int);

/*
 * smb_thread_entry_point
 *
 * Common entry point for all the threads created through smb_thread_start.
 * The state of the thread is set to "running" at the beginning and moved to
 * "exiting" just before calling thread_exit(). The condition variable is
 *  also signaled.
 */
static void
smb_thread_entry_point(
    smb_thread_t	*thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);
	mutex_enter(&thread->sth_mtx);
	ASSERT(thread->sth_state == SMB_THREAD_STATE_STARTING);

	if (!thread->sth_kill) {
		thread->sth_state = SMB_THREAD_STATE_RUNNING;
		cv_signal(&thread->sth_cv);
		mutex_exit(&thread->sth_mtx);

		/* Run the real thread entry point. */
		thread->sth_ep(thread, thread->sth_ep_arg);

		mutex_enter(&thread->sth_mtx);
	}
	/*
	 * It's tempting to clear sth_did here too, but don't.
	 * That's needed in thread_join().
	 */
	thread->sth_th = NULL;
	thread->sth_state = SMB_THREAD_STATE_EXITING;
	cv_broadcast(&thread->sth_cv);
	mutex_exit(&thread->sth_mtx);
	zthread_exit();
}

/*
 * smb_thread_init
 */
void
smb_thread_init(
    smb_thread_t	*thread,
    char		*name,
    smb_thread_ep_t	ep,
    void		*ep_arg,
    pri_t		pri)
{
	ASSERT(thread->sth_magic != SMB_THREAD_MAGIC);

	bzero(thread, sizeof (*thread));

	(void) strlcpy(thread->sth_name, name, sizeof (thread->sth_name));
	thread->sth_ep = ep;
	thread->sth_ep_arg = ep_arg;
	thread->sth_state = SMB_THREAD_STATE_EXITED;
	thread->sth_pri = pri;
	mutex_init(&thread->sth_mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&thread->sth_cv, NULL, CV_DEFAULT, NULL);
	thread->sth_magic = SMB_THREAD_MAGIC;
}

/*
 * smb_thread_destroy
 */
void
smb_thread_destroy(
    smb_thread_t	*thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);
	ASSERT(thread->sth_state == SMB_THREAD_STATE_EXITED);
	thread->sth_magic = 0;
	mutex_destroy(&thread->sth_mtx);
	cv_destroy(&thread->sth_cv);
}

/*
 * smb_thread_start
 *
 * This function starts a thread with the parameters provided. It waits until
 * the state of the thread has been moved to running.
 */
/*ARGSUSED*/
int
smb_thread_start(
    smb_thread_t	*thread)
{
	int		rc = 0;
	kthread_t	*tmpthread;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_EXITED:
		thread->sth_state = SMB_THREAD_STATE_STARTING;
		mutex_exit(&thread->sth_mtx);
		tmpthread = zthread_create(NULL, 0, smb_thread_entry_point,
		    thread, 0, thread->sth_pri);
		ASSERT(tmpthread != NULL);
		mutex_enter(&thread->sth_mtx);
		thread->sth_th = tmpthread;
		thread->sth_did = THR_TO_DID(tmpthread);
		while (thread->sth_state == SMB_THREAD_STATE_STARTING)
			cv_wait(&thread->sth_cv, &thread->sth_mtx);
		if (thread->sth_state != SMB_THREAD_STATE_RUNNING)
			rc = -1;
		break;
	default:
		ASSERT(0);
		rc = -1;
		break;
	}
	mutex_exit(&thread->sth_mtx);
	return (rc);
}

/*
 * smb_thread_stop
 *
 * This function signals a thread to kill itself and waits until the "exiting"
 * state has been reached.
 */
void
smb_thread_stop(smb_thread_t *thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_RUNNING:
	case SMB_THREAD_STATE_STARTING:
		if (!thread->sth_kill) {
			thread->sth_kill = B_TRUE;
			cv_broadcast(&thread->sth_cv);
			while (thread->sth_state != SMB_THREAD_STATE_EXITING)
				cv_wait(&thread->sth_cv, &thread->sth_mtx);
			mutex_exit(&thread->sth_mtx);
			thread_join(thread->sth_did);
			mutex_enter(&thread->sth_mtx);
			thread->sth_state = SMB_THREAD_STATE_EXITED;
			thread->sth_did = 0;
			thread->sth_kill = B_FALSE;
			cv_broadcast(&thread->sth_cv);
			break;
		}
		/* FALLTHROUGH */

	case SMB_THREAD_STATE_EXITING:
		if (thread->sth_kill) {
			while (thread->sth_state != SMB_THREAD_STATE_EXITED)
				cv_wait(&thread->sth_cv, &thread->sth_mtx);
		} else {
			thread->sth_state = SMB_THREAD_STATE_EXITED;
			thread->sth_did = 0;
		}
		break;

	case SMB_THREAD_STATE_EXITED:
		break;

	default:
		ASSERT(0);
		break;
	}
	mutex_exit(&thread->sth_mtx);
}

/*
 * smb_thread_signal
 *
 * This function signals a thread.
 */
void
smb_thread_signal(smb_thread_t *thread)
{
	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	switch (thread->sth_state) {
	case SMB_THREAD_STATE_RUNNING:
		cv_signal(&thread->sth_cv);
		break;

	default:
		break;
	}
	mutex_exit(&thread->sth_mtx);
}

boolean_t
smb_thread_continue(smb_thread_t *thread)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	result = smb_thread_continue_timedwait_locked(thread, 0);
	mutex_exit(&thread->sth_mtx);

	return (result);
}

boolean_t
smb_thread_continue_nowait(smb_thread_t *thread)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	/*
	 * Setting ticks=-1 requests a non-blocking check.  We will
	 * still block if the thread is in "suspend" state.
	 */
	result = smb_thread_continue_timedwait_locked(thread, -1);
	mutex_exit(&thread->sth_mtx);

	return (result);
}

boolean_t
smb_thread_continue_timedwait(smb_thread_t *thread, int seconds)
{
	boolean_t result;

	ASSERT(thread->sth_magic == SMB_THREAD_MAGIC);

	mutex_enter(&thread->sth_mtx);
	result = smb_thread_continue_timedwait_locked(thread,
	    SEC_TO_TICK(seconds));
	mutex_exit(&thread->sth_mtx);

	return (result);
}

/*
 * smb_thread_continue_timedwait_locked
 *
 * Internal only.  Ticks==-1 means don't block, Ticks == 0 means wait
 * indefinitely
 */
static boolean_t
smb_thread_continue_timedwait_locked(smb_thread_t *thread, int ticks)
{
	boolean_t	result;

	/* -1 means don't block */
	if (ticks != -1 && !thread->sth_kill) {
		if (ticks == 0) {
			cv_wait(&thread->sth_cv, &thread->sth_mtx);
		} else {
			(void) cv_reltimedwait(&thread->sth_cv,
			    &thread->sth_mtx, (clock_t)ticks, TR_CLOCK_TICK);
		}
	}
	result = (thread->sth_kill == 0);

	return (result);
}
