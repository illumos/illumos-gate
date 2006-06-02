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

#include <pthread.h>
#include <malloc.h>
#include <memory.h>
#include "dataq.h"
#include <assert.h>

#ifndef NDEBUG
static int
dataq_check(dataq_t *ptr)	/* call while holding lock! */
{
	assert(ptr->num_data == ll_check(&ptr->data));
	assert(ptr->num_waiters == ll_check(&ptr->waiters));
	return (1);
}
#endif

int
dataq_init(dataq_t *ptr)
{
	ptr->num_data = 0;
	ptr->num_waiters = 0;
	ll_init(&ptr->data);
	ll_init(&ptr->waiters);
	(void) pthread_mutex_init(&ptr->lock, NULL);
	assert((pthread_mutex_lock(&ptr->lock) == 0) &&
		(dataq_check(ptr) == 1) &&
		(pthread_mutex_unlock(&ptr->lock) == 0));
	return (0);
}

int
dataq_enqueue(dataq_t *dataq, void *in)
{
	dataq_data_t *ptr = (dataq_data_t *)malloc(sizeof (*ptr));
	dataq_waiter_t *sleeper;

	if (ptr == NULL)
		return (-1);
	ptr->data = in;
	(void) pthread_mutex_lock(&dataq->lock);
	assert(dataq_check(dataq));
	ll_enqueue(&dataq->data, &ptr->list);
	dataq->num_data++;
	if (dataq->num_waiters) {
		/*LINTED*/
		sleeper = (dataq_waiter_t *)ll_peek(&dataq->waiters);
		sleeper->wakeup = 1;
		(void) pthread_cond_signal(&sleeper->cv);
	}
	assert(dataq_check(dataq));
	(void) pthread_mutex_unlock(&dataq->lock);
	return (0);
}

int
dataq_dequeue(dataq_t *dataq, void **outptr, int try)
{
	dataq_data_t *dptr;
	dataq_waiter_t *sleeper;

	(void) pthread_mutex_lock(&dataq->lock);
	if ((dataq->num_waiters > 0) ||
	    ((dptr = (dataq_data_t *)ll_dequeue(&dataq->data)) == NULL)) {
		dataq_waiter_t wait;
		if (try) {
			(void) pthread_mutex_unlock(&dataq->lock);
			return (1);
		}
		wait.wakeup = 0;
		(void) pthread_cond_init(&wait.cv, NULL);
		dataq->num_waiters++;
		ll_enqueue(&dataq->waiters, &wait.list);
		while (wait.wakeup == 0)
			(void) pthread_cond_wait(&wait.cv, &dataq->lock);
		(void) ll_dequeue(&dataq->waiters);
		dataq->num_waiters--;
		(void) pthread_cond_destroy(&wait.cv);
		dptr = (dataq_data_t *)ll_dequeue(&dataq->data);
	}
	dataq->num_data--;
	if (dataq->num_data && dataq->num_waiters) {
		/*LINTED*/
		sleeper = (dataq_waiter_t *)ll_peek(&dataq->waiters);
		sleeper->wakeup = 1;
		(void) pthread_cond_signal(&sleeper->cv);
	}
	(void) pthread_mutex_unlock(&dataq->lock);
	*outptr = dptr->data;
	free(dptr);
	return (0);
}

static void
dataq_data_destroy(void * p)
{
	dataq_data_t *d = (dataq_data_t *)p;
	free(d->data);
	free(d);
}

static void
dataq_waiters_destroy(void * p)
{
	dataq_waiter_t *d = (dataq_waiter_t *)p;
	(void) pthread_cond_destroy(&d->cv);
	free(d);
}

int
dataq_destroy(dataq_t *dataq)
{
	(void) pthread_mutex_destroy(&dataq->lock);
	ll_mapf(&dataq->data, dataq_data_destroy);
	ll_mapf(&dataq->waiters, dataq_waiters_destroy);
	return (0);
}
