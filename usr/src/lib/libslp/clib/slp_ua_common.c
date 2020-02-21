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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <slp-internal.h>

/* This is used to pass needed params to consumer_thr and slp_call */
struct thr_call_args {
	slp_handle_impl_t *hp;
	SLPGenericAppCB *cb;
	void *cookie;
	SLPMsgReplyCB *msg_cb;
	slp_target_list_t *targets;
};

static void *consumer(void *);
static void *slp_call(void *);
static SLPError check_message_fit(slp_handle_impl_t *, slp_target_list_t *);

SLPError slp_ua_common(SLPHandle hSLP, const char *scopes,
    SLPGenericAppCB cb, void *cookie, SLPMsgReplyCB msg_cb)
{
	slp_handle_impl_t *hp;
	slp_target_list_t *targets;
	struct thr_call_args *args;
	slp_queue_t *q;
	SLPError err;
	thread_t tid;
	int terr;

	hp = (slp_handle_impl_t *)hSLP;

	/* select targets */
	if ((err = slp_new_target_list(hp, scopes, &targets)) != SLP_OK)
		return (err);
	if ((err = check_message_fit(hp, targets)) != SLP_OK) {
		slp_destroy_target_list(targets);
		return (err);
	}

	/* populate the args structure */
	args = malloc(sizeof (*args));
	if (args == NULL) {
		slp_err(LOG_CRIT, 0, "ua_common", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	args->hp = hp;
	args->cb = cb;
	args->cookie = cookie;
	args->msg_cb = msg_cb;
	args->targets = targets;

	/* create the queue that this call will use */
	q = slp_new_queue(&err);	/* freed in consumer_thr */
	if (err != SLP_OK)
		goto error;
	hp->q = q;

	/* kick off the producer thread */
	if ((terr = thr_create(NULL, 0, slp_call, args, 0, &tid)) != 0) {
		slp_err(LOG_CRIT, 0, "ua_common", "could not start thread: %s",
		    strerror(terr));
		err = SLP_INTERNAL_SYSTEM_ERROR;
		goto error;
	}
	hp->producer_tid = tid;

	if (hp->async) {
		/* kick off the consumer thread */
		if ((terr = thr_create(NULL, 0, consumer,
		    args, 0, NULL)) != 0) {
			slp_err(LOG_CRIT, 0, "ua_common",
			    "could not start thread: %s",
			    strerror(terr));
			err = SLP_INTERNAL_SYSTEM_ERROR;
			/* cleanup producer thread, if necessary */
			hp->cancel = 1;
			(void) thr_join(tid, NULL, NULL);

			goto error;
		}
		return (SLP_OK);
	}
	/* else	sync */
	return ((SLPError)consumer(args));
error:
	free(args);
	return (err);
}

static void *
consumer(void *ap)
{
	slp_handle_impl_t *hp;
	char *reply;
	void *collator;
	int numResults = 0;
	struct thr_call_args *args = (struct thr_call_args *)ap;

	hp = args->hp;
	collator = NULL;
	hp->consumer_tid = thr_self();
	/* while cb wants more and there is more to get ... */
	for (;;) {
		SLPBoolean cont;

		reply = slp_dequeue(hp->q);
		/* reply == NULL if no more available or SLPClosed */
		cont = args->msg_cb(hp, reply, args->cb, args->cookie,
		    &collator, &numResults);

		if (reply) {
			free(reply);
		} else {
			break;
		}

		if (!cont) {
			/* cb doesn't want any more; invoke last call */
			args->msg_cb(hp, NULL, args->cb, args->cookie,
			    &collator, &numResults);
			break;
		}
	}
	/* cleanup */
	/* clean stop producer [thread] */
	hp->cancel = 1;
	(void) thr_join(hp->producer_tid, NULL, NULL);

	/* empty and free queue */
	slp_flush_queue(hp->q, free);
	slp_destroy_queue(hp->q);

	free(args);
	slp_end_call(hp);
	return ((void *)SLP_OK);
}

/*
 * This is the producer thread
 */
static void *
slp_call(void *ap)
{
	struct thr_call_args *args = (struct thr_call_args *)ap;
	slp_target_t *t;
	const char *uc_scopes, *mc_scopes;
	SLPBoolean use_tcp = SLP_FALSE;
	size_t len;

	/* Unicast */
	if (uc_scopes = slp_get_uc_scopes(args->targets)) {
		size_t mtu;
		int i;

		/* calculate msg length */
		len = slp_hdrlang_length(args->hp);
		for (i = 0; i < args->hp->msg.iovlen; i++) {
			len += args->hp->msg.iov[i].iov_len;
		}
		len += strlen(uc_scopes);

		mtu = slp_get_mtu();
		if (len > mtu)
			use_tcp = SLP_TRUE;

		for (t = slp_next_uc_target(args->targets); t != NULL;
		    t = slp_next_uc_target(args->targets)) {
			if (args->hp->cancel)
				break;

			if (use_tcp)
				slp_uc_tcp_send(args->hp, t, uc_scopes,
				    SLP_FALSE, 0);
			else
				slp_uc_udp_send(args->hp, t, uc_scopes);
		}
	}

	/* Multicast */
	if ((!args->hp->cancel) &&
	    (mc_scopes = slp_get_mc_scopes(args->targets)))
		slp_mc_send(args->hp, mc_scopes);

	/* Wait for TCP to complete, if necessary */
	if (args->hp->tcp_lock)
		slp_tcp_wait(args->hp);

	slp_destroy_target_list(args->targets);

	/* free the message */
	free(args->hp->msg.iov);
	free(args->hp->msg.msg);

	/* null terminate message queue */
	(void) slp_enqueue(args->hp->q, NULL);

	thr_exit(NULL);	/* we're outa here */
}

/*
 * If the message to be sent needs to be multicast, check that it
 * can fit into a datagram. If not, return BUFFER_OVERFLOW, otherwise
 * return SLP_OK.
 */
static SLPError check_message_fit(slp_handle_impl_t *hp,
					slp_target_list_t *targets) {
	size_t msgSize;
	int i;
	const char *mc_scopes;

	if (!(mc_scopes = slp_get_mc_scopes(targets)))
		return (SLP_OK);	/* no mc targets to worry about */

	msgSize = slp_hdrlang_length(hp);
	for (i = 0; i < hp->msg.iovlen; i++) {
		msgSize += hp->msg.iov[i].iov_len;
	}
	msgSize += strlen(mc_scopes);

	if (msgSize > slp_get_mtu())
		return (SLP_BUFFER_OVERFLOW);
	return (SLP_OK);
}
