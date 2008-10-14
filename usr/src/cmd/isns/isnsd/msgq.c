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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <synch.h>

#include "isns_server.h"
#include "isns_msgq.h"
#include "isns_cache.h"
#include "isns_obj.h"
#include "isns_log.h"

msg_queue_t *
queue_calloc(
)
{
	msg_queue_t *q;

	q = (msg_queue_t *)calloc(1, sizeof (msg_queue_t));

	if (q) {
		if (sema_init(&q->q_sema, 0, USYNC_THREAD, NULL) ||
		    pthread_mutex_init(&q->q_mutex, NULL)) {
			free(q);
			q = NULL;
		}
	}

	return (q);
}

int
queue_msg_set(
	msg_queue_t *q,
	msg_id_t id,
	void *data
)
{
	msg_text_t *msg;

	msg = (msg_text_t *)calloc(1, sizeof (msg_text_t));

	if (!msg) {
		return (1);
	}

	msg->id = id;
	msg->data = data;

	(void) pthread_mutex_lock(&q->q_mutex);

	if (q->q_head == NULL) {
		ASSERT(!q->q_tail);
		q->q_head = msg;
		q->q_tail = msg;
	} else {
		ASSERT(q->q_tail);
		q->q_tail->next = msg;
		msg->prev = q->q_tail;
		q->q_tail = msg;
	}

	(void) pthread_mutex_unlock(&q->q_mutex);

	(void) sema_post(&q->q_sema);

	return (0);
}

msg_text_t *
queue_msg_get(
	msg_queue_t *q
)
{
	msg_text_t *msg;

	while (sema_wait(&q->q_sema)) {
		(void) sleep(1);
	}

	(void) pthread_mutex_lock(&q->q_mutex);

	msg = q->q_head;
	ASSERT(msg);
	q->q_head = msg->next;
	if (q->q_head == NULL) {
		q->q_tail = NULL;
	}

	(void) pthread_mutex_unlock(&q->q_mutex);

	return (msg);
}

void
queue_msg_free(
	msg_text_t *msg
)
{
	free(msg);
}
