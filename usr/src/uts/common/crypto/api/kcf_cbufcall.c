/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * crypto_bufcall(9F) group of routines.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/callb.h>
#include <sys/ksynch.h>
#include <sys/systm.h>
#include <sys/taskq_impl.h>
#include <sys/crypto/api.h>
#include <sys/crypto/sched_impl.h>

/*
 * All pending crypto bufcalls are put on a list. cbuf_list_lock
 * protects changes to this list.
 *
 * The following locking order is maintained in the code - The
 * global cbuf_list_lock followed by the individual lock
 * in a crypto bufcall structure (kc_lock).
 */
kmutex_t	cbuf_list_lock;
kcondvar_t	cbuf_list_cv;	/* cv the service thread waits on */
static kcf_cbuf_elem_t *cbuf_list_head;
static kcf_cbuf_elem_t *cbuf_list_tail;

/*
 * Allocate and return a handle to be used for crypto_bufcall().
 * Can be called from user context only.
 */
crypto_bc_t
crypto_bufcall_alloc(void)
{
	kcf_cbuf_elem_t *cbufp;

	cbufp = kmem_zalloc(sizeof (kcf_cbuf_elem_t), KM_SLEEP);
	mutex_init(&cbufp->kc_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cbufp->kc_cv, NULL, CV_DEFAULT, NULL);
	cbufp->kc_state = CBUF_FREE;

	return (cbufp);
}

/*
 * Free the handle if possible. Returns CRYPTO_SUCCESS if the handle
 * is freed. Else it returns CRYPTO_BUSY.
 *
 * The client should do a crypto_unbufcall() if it receives a
 * CRYPTO_BUSY.
 *
 * Can be called both from user and interrupt context.
 */
int
crypto_bufcall_free(crypto_bc_t bc)
{
	kcf_cbuf_elem_t *cbufp = (kcf_cbuf_elem_t *)bc;

	mutex_enter(&cbufp->kc_lock);
	if (cbufp->kc_state != CBUF_FREE) {
		mutex_exit(&cbufp->kc_lock);
		return (CRYPTO_BUSY);
	}
	mutex_exit(&cbufp->kc_lock);

	mutex_destroy(&cbufp->kc_lock);
	cv_destroy(&cbufp->kc_cv);
	kmem_free(cbufp, sizeof (kcf_cbuf_elem_t));

	return (CRYPTO_SUCCESS);
}

/*
 * Schedule func() to be called when queue space is available to
 * submit a crypto request.
 *
 * Can be called both from user and interrupt context.
 */
int
crypto_bufcall(crypto_bc_t bc, void (*func)(void *arg), void *arg)
{
	kcf_cbuf_elem_t *cbufp;

	cbufp = (kcf_cbuf_elem_t *)bc;
	if (cbufp == NULL || func == NULL) {
		return (CRYPTO_ARGUMENTS_BAD);
	}

	mutex_enter(&cbuf_list_lock);
	mutex_enter(&cbufp->kc_lock);
	if (cbufp->kc_state != CBUF_FREE) {
		mutex_exit(&cbufp->kc_lock);
		mutex_exit(&cbuf_list_lock);
		return (CRYPTO_BUSY);
	}

	cbufp->kc_state = CBUF_WAITING;
	cbufp->kc_func = func;
	cbufp->kc_arg = arg;
	cbufp->kc_prev = cbufp->kc_next = NULL;

	if (cbuf_list_head == NULL) {
		cbuf_list_head = cbuf_list_tail = cbufp;
	} else {
		cbuf_list_tail->kc_next = cbufp;
		cbufp->kc_prev = cbuf_list_tail;
		cbuf_list_tail = cbufp;
	}

	/*
	 * Signal the crypto_bufcall_service thread to start
	 * working on this crypto bufcall request.
	 */
	cv_signal(&cbuf_list_cv);
	mutex_exit(&cbufp->kc_lock);
	mutex_exit(&cbuf_list_lock);

	return (CRYPTO_SUCCESS);
}

/*
 * Cancel a pending crypto bufcall request. If the bufcall
 * is currently executing, we wait till it is complete.
 *
 * Can only be called from user context.
 */
int
crypto_unbufcall(crypto_bc_t bc)
{
	kcf_cbuf_elem_t *cbufp = (kcf_cbuf_elem_t *)bc;

	mutex_enter(&cbuf_list_lock);
	mutex_enter(&cbufp->kc_lock);

	if (cbufp->kc_state == CBUF_WAITING) {
		kcf_cbuf_elem_t *nextp = cbufp->kc_next;
		kcf_cbuf_elem_t *prevp = cbufp->kc_prev;

		if (nextp != NULL)
			nextp->kc_prev = prevp;
		else
			cbuf_list_tail = prevp;

		if (prevp != NULL)
			prevp->kc_next = nextp;
		else
			cbuf_list_head = nextp;
		cbufp->kc_state = CBUF_FREE;
	} else if (cbufp->kc_state == CBUF_RUNNING) {
		mutex_exit(&cbuf_list_lock);
		/*
		 * crypto_bufcall_service thread is working
		 * on this element. We will wait for that
		 * thread to signal us when done.
		 */
		while (cbufp->kc_state == CBUF_RUNNING)
			cv_wait(&cbufp->kc_cv, &cbufp->kc_lock);
		mutex_exit(&cbufp->kc_lock);

		return (CRYPTO_SUCCESS);
	}

	mutex_exit(&cbufp->kc_lock);
	mutex_exit(&cbuf_list_lock);

	return (CRYPTO_SUCCESS);
}

/*
 * We sample the number of jobs. We do not hold the lock
 * as it is not necessary to get the exact count.
 */
#define	KCF_GSWQ_AVAIL	(gswq->gs_maxjobs - gswq->gs_njobs)

/*
 * One queue space each for init, update, and final.
 */
#define	GSWQ_MINFREE	3

/*
 * Go through the list of crypto bufcalls and do the necessary
 * callbacks.
 */
static void
kcf_run_cbufcalls(void)
{
	kcf_cbuf_elem_t *cbufp;
	int count;

	mutex_enter(&cbuf_list_lock);

	/*
	 * Get estimate of available queue space from KCF_GSWQ_AVAIL.
	 * We can call 'n' crypto bufcall callback functions where
	 * n * GSWQ_MINFREE <= available queue space.
	 *
	 * TO DO - Extend the check to taskqs of hardware providers.
	 * For now, we handle only the software providers.
	 */
	count = KCF_GSWQ_AVAIL;
	while ((cbufp = cbuf_list_head) != NULL) {
		if (GSWQ_MINFREE <= count) {
			count -= GSWQ_MINFREE;
			mutex_enter(&cbufp->kc_lock);
			cbuf_list_head = cbufp->kc_next;
			cbufp->kc_state = CBUF_RUNNING;
			mutex_exit(&cbufp->kc_lock);
			mutex_exit(&cbuf_list_lock);

			(*cbufp->kc_func)(cbufp->kc_arg);

			mutex_enter(&cbufp->kc_lock);
			cbufp->kc_state = CBUF_FREE;
			cv_broadcast(&cbufp->kc_cv);
			mutex_exit(&cbufp->kc_lock);

			mutex_enter(&cbuf_list_lock);
		} else {
			/*
			 * There is not enough queue space in this
			 * round. We bail out and try again
			 * later.
			 */
			break;
		}
	}
	if (cbuf_list_head == NULL)
		cbuf_list_tail = NULL;

	mutex_exit(&cbuf_list_lock);
}

/*
 * Background processing of crypto bufcalls.
 */
void
crypto_bufcall_service(void)
{
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &cbuf_list_lock, callb_generic_cpr,
	    "crypto_bufcall_service");

	mutex_enter(&cbuf_list_lock);

	for (;;) {
		if (cbuf_list_head != NULL && KCF_GSWQ_AVAIL >= GSWQ_MINFREE) {
			mutex_exit(&cbuf_list_lock);
			kcf_run_cbufcalls();
			mutex_enter(&cbuf_list_lock);
		}

		if (cbuf_list_head != NULL) {
			/*
			 * Wait 30 seconds for queue space to become available.
			 * This number is reasonable as it does not cause
			 * much CPU overhead. We could wait on a condition
			 * variable and the global software dequeue routine can
			 * signal us. But, it adds overhead to that routine
			 * which we want to avoid. Also, the client is prepared
			 * to wait any way.
			 */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			mutex_exit(&cbuf_list_lock);
			delay(30 * drv_usectohz(1000000));
			mutex_enter(&cbuf_list_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &cbuf_list_lock);
		}

		/* Wait for new work to arrive */
		if (cbuf_list_head == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&cbuf_list_cv, &cbuf_list_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &cbuf_list_lock);
		}
	}
}
