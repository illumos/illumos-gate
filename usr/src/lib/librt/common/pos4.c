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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "c_synonyms.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "mqlib.h"
#include "thread_pool.h"

extern mutex_t semlock;
extern mutex_t md5_lock;

extern void prefork1_tpool(void);
extern void postfork1_parent_tpool(void);
extern void postfork1_child_tpool(void);

/*
 * A spawner and its workers are gone.
 * We are here to clean up the data structures and close the port.
 */
static void
tcd_teardown(thread_communication_data_t *tcdp)
{
	if (tcdp->tcd_poolp != NULL)
		tpool_abandon(tcdp->tcd_poolp);
	tcdp->tcd_poolp = NULL;
	tcdp->tcd_server_id = 0;
	free_sigev_handler(tcdp);
}

static void
_rt_prepare_fork(void)
{
	thread_communication_data_t *tcdp;
	mqdes_t *mqdp;
	int timer;

	(void) mutex_lock(&sigev_aio_lock);
	while (sigev_aio_busy)
		(void) cond_wait(&sigev_aio_cv, &sigev_aio_lock);
	(void) mutex_lock(&semlock);
	(void) mutex_lock(&md5_lock);
	if ((tcdp = sigev_aio_tcd) != NULL)
		(void) mutex_lock(&tcdp->tcd_lock);

	(void) mutex_lock(&mq_list_lock);
	for (mqdp = mq_list; mqdp; mqdp = mqdp->mqd_next) {
		if ((tcdp = mqdp->mqd_tcd) != NULL)
			(void) mutex_lock(&tcdp->tcd_lock);
	}

	for (timer = 0; timer < timer_max; timer++) {
		if ((tcdp = timer_tcd[timer]) != NULL)
			(void) mutex_lock(&tcdp->tcd_lock);
	}
	(void) mutex_lock(&free_tcd_lock);

	prefork1_tpool();
}

static void
_rt_release_locks(void)
{
	thread_communication_data_t *tcdp;
	mqdes_t *mqdp;
	int timer;

	(void) mutex_unlock(&free_tcd_lock);
	for (timer = 0; timer < timer_max; timer++) {
		if ((tcdp = timer_tcd[timer]) != NULL)
			(void) mutex_unlock(&tcdp->tcd_lock);
	}

	for (mqdp = mq_list; mqdp; mqdp = mqdp->mqd_next) {
		if ((tcdp = mqdp->mqd_tcd) != NULL)
			(void) mutex_unlock(&tcdp->tcd_lock);
	}
	(void) mutex_unlock(&mq_list_lock);

	if ((tcdp = sigev_aio_tcd) != NULL)
		(void) mutex_unlock(&tcdp->tcd_lock);
	(void) mutex_unlock(&md5_lock);
	(void) mutex_unlock(&semlock);
	(void) mutex_unlock(&sigev_aio_lock);
}

static void
_rt_parent_fork(void)
{
	postfork1_parent_tpool();
	_rt_release_locks();
}

static void
_rt_child_fork(void)
{
	mqdes_t *mqdp;
	int timer;

	postfork1_child_tpool();
	_rt_release_locks();

	/*
	 * All of the spawners and workers are gone; free their structures.
	 */

	if (sigev_aio_tcd != NULL) {				/* AIO */
		tcd_teardown(sigev_aio_tcd);
		sigev_aio_tcd = NULL;
	}

	for (mqdp = mq_list; mqdp; mqdp = mqdp->mqd_next) {	/* MQ */
		if (mqdp->mqd_tcd != NULL) {
			tcd_teardown(mqdp->mqd_tcd);
			mqdp->mqd_tcd = NULL;
		}
	}

	for (timer = 0; timer < timer_max; timer++) {		/* TIMER */
		if (timer_tcd[timer] != NULL) {
			tcd_teardown(timer_tcd[timer]);
			timer_tcd[timer] = NULL;
		}
	}
}

#pragma init(_rt_init)
static void
_rt_init(void)
{
	(void) pthread_atfork(_rt_prepare_fork,
	    _rt_parent_fork, _rt_child_fork);
}
