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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <slp-internal.h>
#include <slp_net_utils.h>

SLPError SLPOpen(const char *pcLang, SLPBoolean isAsync, SLPHandle *phSLP) {
	slp_handle_impl_t *hp;

	if (!pcLang || !phSLP) {
		return (SLP_PARAMETER_BAD);
	}

	/* allocate the handle */
	if (!(hp = malloc(sizeof (*hp)))) {
		slp_err(LOG_CRIT, 0, "SLPOpen", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	/* initialize outcall synchronization */
	hp->pending_outcall = SLP_FALSE;
	(void) mutex_init(&(hp->outcall_lock), USYNC_THREAD, NULL);
	(void) cond_init(&(hp->outcall_cv), USYNC_THREAD, NULL);
	hp->close_on_end = SLP_FALSE;
	hp->consumer_tid = 0;

	/* locale property overrides argument */
	if (!(hp->locale = SLPGetProperty(SLP_CONFIG_LOCALE))) {
		hp->locale = pcLang;
	}
	/* Make sure the language string is under our ownership */
	if (!(hp->locale = strdup(hp->locale))) {
		free(hp);
		slp_err(LOG_CRIT, 0, "SLPOpen", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	hp->cancel = 0;

	/* Asynchronous operation? */
	if (isAsync)
		hp->async = SLP_TRUE;
	else
		hp->async = SLP_FALSE;

	/* TCP vars -- these are NULL until actually needed */
	hp->tcp_lock = NULL;
	hp->tcp_wait = NULL;
	hp->tcp_ref_cnt = 0;

	/* Consumer / Producer pipe */
	hp->q = NULL;

	/* Interface info, loaded on demand */
	hp->ifinfo = NULL;

	/* force multicast, false by default */
	hp->force_multicast = SLP_FALSE;

	/* internal call, false by default */
	hp->internal_call = SLP_FALSE;

	*phSLP = hp;
	return (SLP_OK);
}

void slp_cleanup_handle(slp_handle_impl_t *hp) {
	/* free the handle */
	if (hp->tcp_lock) free(hp->tcp_lock);
	if (hp->tcp_wait) free(hp->tcp_wait);
	if (hp->ifinfo) {
		slp_free_ifinfo(hp->ifinfo);
		free(hp->ifinfo);
	}
	free((void *) hp->locale);
	free(hp);
}

void SLPClose(SLPHandle hSLP) {
	slp_handle_impl_t *hp = (slp_handle_impl_t *)hSLP;

	if (!hSLP) {
		return;
	}

	/*
	 * If an outcall is pending on this handle:
	 *   If we are being called from a callback resulting
	 *   from the outcall associated with this handle or
	 *   if close_on_end has already been set:
	 *	just set close on end and return -- the cleanup
	 *	will be done when the outcall is finished.
	 *   else
	 *	wait on the outcall cv for the outcall to complete
	 * Proceed with cleanup
	 */
	(void) mutex_lock(&(hp->outcall_lock));
	if (hp->pending_outcall) {
	    /* end the consumer thread */
	    /* this will also kill the producer thread and close net */
	    hp->cancel = 1;
	    if (hp->q) {
		if (slp_enqueue_at_head(hp->q, NULL) != SLP_OK) {
		    goto cleanup;
		}
	    }

	    if (thr_self() == hp->consumer_tid || hp->close_on_end) {
		/* SLPClose called from callback */
		hp->close_on_end = SLP_TRUE;
		(void) mutex_unlock(&(hp->outcall_lock));
		return;
	    }
	    /* else not called from callback; wait for outcall to end */
	    while (hp->pending_outcall) {
		(void) cond_wait(&(hp->outcall_cv), &(hp->outcall_lock));
	    }
	}
	(void) mutex_unlock(&(hp->outcall_lock));

cleanup:
	slp_cleanup_handle(hp);
}
