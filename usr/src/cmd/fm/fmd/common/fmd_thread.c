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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <signal.h>

#include <fmd_alloc.h>
#include <fmd_thread.h>
#include <fmd_module.h>
#include <fmd_error.h>
#include <fmd_subr.h>
#include <fmd.h>

fmd_thread_t *
fmd_thread_xcreate(fmd_module_t *mp, pthread_t tid)
{
	fmd_thread_t *tp = fmd_alloc(sizeof (fmd_thread_t), FMD_SLEEP);

	tp->thr_mod = mp;
	tp->thr_tid = tid;
	tp->thr_func = NULL;
	tp->thr_arg = NULL;
	tp->thr_trdata = fmd_trace_create();
	tp->thr_trfunc = fmd.d_thr_trace;
	tp->thr_errdepth = 0;
	tp->thr_isdoor = 0;

	(void) pthread_mutex_lock(&fmd.d_thr_lock);
	fmd_list_append(&fmd.d_thr_list, tp);
	(void) pthread_mutex_unlock(&fmd.d_thr_lock);

	return (tp);
}

static void *
fmd_thread_start(void *arg)
{
	fmd_thread_t *tp = arg;

	if (pthread_setspecific(fmd.d_key, tp) != 0)
		fmd_panic("failed to initialize thread key to %p", arg);

	if (!tp->thr_isdoor) {
		(void) pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
		(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	}

	tp->thr_func(tp->thr_arg);
	return (NULL);
}

static fmd_thread_t *
fmd_thread_create_cmn(fmd_module_t *mp, fmd_thread_f *func, void *arg,
    int isdoor)
{
	fmd_thread_t *tp = fmd_alloc(sizeof (fmd_thread_t), FMD_SLEEP);
	sigset_t oset, nset;
	int err;

	tp->thr_mod = mp;
	tp->thr_func = func;
	tp->thr_arg = arg;
	tp->thr_trdata = fmd_trace_create();
	tp->thr_trfunc = fmd.d_thr_trace;
	tp->thr_errdepth = 0;
	tp->thr_isdoor = isdoor;

	(void) sigfillset(&nset);
	(void) sigdelset(&nset, SIGABRT); /* always unblocked for fmd_panic() */
	if (!isdoor)
		(void) sigdelset(&nset, fmd.d_thr_sig); /* fmd_thr_signal() */

	(void) pthread_sigmask(SIG_SETMASK, &nset, &oset);
	err = pthread_create(&tp->thr_tid, NULL, fmd_thread_start, tp);
	(void) pthread_sigmask(SIG_SETMASK, &oset, NULL);

	if (err != 0) {
		fmd_free(tp, sizeof (fmd_thread_t));
		return (NULL);
	}

	(void) pthread_mutex_lock(&fmd.d_thr_lock);
	fmd_list_append(&fmd.d_thr_list, tp);
	(void) pthread_mutex_unlock(&fmd.d_thr_lock);

	return (tp);
}

fmd_thread_t *
fmd_thread_create(fmd_module_t *mp, fmd_thread_f *func, void *arg)
{
	return (fmd_thread_create_cmn(mp, func, arg, 0));
}

fmd_thread_t *
fmd_doorthread_create(fmd_module_t *mp, fmd_thread_f *func, void *arg)
{
	return (fmd_thread_create_cmn(mp, func, arg, 1));
}

void
fmd_thread_destroy(fmd_thread_t *tp, int flag)
{
	if (flag == FMD_THREAD_JOIN && tp->thr_tid != pthread_self() &&
	    pthread_join(tp->thr_tid, NULL) != 0) {
		fmd_error(EFMD_MOD_JOIN, "failed to join thread for module "
		    "%s (tid %u)\n", tp->thr_mod->mod_name, tp->thr_tid);
	}

	(void) pthread_mutex_lock(&fmd.d_thr_lock);
	fmd_list_delete(&fmd.d_thr_list, tp);
	(void) pthread_mutex_unlock(&fmd.d_thr_lock);

	fmd_trace_destroy(tp->thr_trdata);
	fmd_free(tp, sizeof (fmd_thread_t));
}
