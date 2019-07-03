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

/*
 * A synchronized FIFO queue for inter-thread producer-consumer semantics.
 * This queue will handle multiple writers and readers simultaneously.
 *
 * The following operations are provided:
 * slp_new_queue:	create a new queue
 * slp_enqueue:		place a message at the end of the queue
 * slp_enqueue_at_head:	place a message the the start of the queue
 * slp_dequeue:		remove and return the next message on the queue
 *				(waits indefinately)
 * slp_dequeue_timed:	remove and return the next message on the queue
 *				(waits only for a specified time)
 * slp_flush_queue:	flushes and frees all messages on a queue
 * slp_destroy_queue:	frees an empty queue.
 */

#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <syslog.h>
#include <slp.h>
#include <slp-internal.h>

/* Private implementation details */
struct queue_entry {
	void *msg;
	struct queue_entry *next;
};
typedef struct queue_entry slp_queue_entry_t;

struct queue {
	slp_queue_entry_t *head;
	slp_queue_entry_t *tail;
	mutex_t *lock;
	cond_t *wait;
	int count;
};

/*
 * Creates, initializes, and returns a new queue.
 * If an initialization error occured, returns NULL and sets err to
 * the appropriate SLP error code.
 * queues can operate in one of two modes: timed-wait, and infinite
 * wait. The timeout parameter specifies which of these modes should
 * be enabled for the new queue.
 */
slp_queue_t *slp_new_queue(SLPError *err) {
	mutex_t *lock;
	cond_t *wait;
	struct queue *q;

	*err = SLP_OK;

	/* initialize new mutex and semaphore */
	if ((lock = calloc(1, sizeof (*lock))) == NULL) {
		*err = SLP_MEMORY_ALLOC_FAILED;
		slp_err(LOG_CRIT, 0, "slp_new_queue", "out of memory");
		return (NULL);
	}

	/* intialize condition vars */
	if (!(wait = calloc(1, sizeof (*wait)))) {
		*err = SLP_MEMORY_ALLOC_FAILED;
		slp_err(LOG_CRIT, 0, "slp_new_queue", "out of memory");
		return (NULL);
	}
	(void) cond_init(wait, USYNC_THREAD, NULL);

	/* create the queue */
	if ((q = malloc(sizeof (*q))) == NULL) {
		*err = SLP_MEMORY_ALLOC_FAILED;
		slp_err(LOG_CRIT, 0, "slp_new_queue", "out of memory");
		return (NULL);
	}

	q->head = NULL;
	q->lock = lock;
	q->wait = wait;
	q->count = 0;

	return (q);
}

/*
 * Adds msg to the tail of queue q.
 * Returns an SLP error code: SLP_OK for no error, or SLP_MEMORY_ALLOC_FAILED
 * if it couldn't allocate memory.
 */
SLPError slp_enqueue(slp_queue_t *qa, void *msg) {
	slp_queue_entry_t *qe;
	struct queue *q = qa;

	if ((qe = malloc(sizeof (*qe))) == NULL) {
		slp_err(LOG_CRIT, 0, "slp_enqueue", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	(void) mutex_lock(q->lock);
	qe->msg = msg;
	qe->next = NULL;
	if (q->head != NULL) {	/* queue is not emptry */
		q->tail->next = qe;
		q->tail = qe;
	} else {		/* queue is empty */
		q->head = q->tail = qe;
	}
	q->count++;
	(void) mutex_unlock(q->lock);
	(void) cond_signal(q->wait);

	return (SLP_OK);
}

/*
 * Inserts a message at the head of the queue. This is useful for inserting
 * things like cancel messages.
 */
SLPError slp_enqueue_at_head(slp_queue_t *qa, void *msg) {
	slp_queue_entry_t *qe;
	struct queue *q = qa;

	if ((qe = malloc(sizeof (*qe))) == NULL) {
		slp_err(LOG_CRIT, 0, "slp_enqueue", "out of memory");
		return (SLP_MEMORY_ALLOC_FAILED);
	}

	(void) mutex_lock(q->lock);
	qe->msg = msg;
	qe->next = q->head;
	q->head = qe;

	q->count++;
	(void) mutex_unlock(q->lock);
	(void) cond_signal(q->wait);

	return (SLP_OK);
}

/*
 * The core functionality for dequeue.
 */
static void *dequeue_nolock(struct queue *q) {
	void *msg;
	slp_queue_entry_t *qe = q->head;

	if (!qe)
		return (NULL);	/* shouldn't get here */
	msg = qe->msg;
	if (!qe->next)		/* last one in queue */
		q->head = q->tail = NULL;
	else
		q->head = qe->next;
	free(qe);
	q->count--;
	return (msg);
}

/*
 * Returns the first message waiting or arriving in the queue, or if no
 * message is available after waiting the amount of time specified in
 * 'to', returns NULL, and sets 'etimed' to true. If an error occured,
 * returns NULL and sets 'etimed' to false.
 */
void *slp_dequeue_timed(slp_queue_t *qa, timestruc_t *to, SLPBoolean *etimed) {
	int err;
	void *ans;
	struct queue *q = qa;

	if (etimed)
		*etimed = SLP_FALSE;

	(void) mutex_lock(q->lock);
	if (q->count > 0) {
		/* something's in the q, so no need to wait */
		goto msg_available;
	}

	/* else wait */
	while (q->count == 0) {
		if (to) {
			err = cond_timedwait(q->wait, q->lock, to);
		} else {
			err = cond_wait(q->wait, q->lock);
		}
		if (err == ETIME) {
			(void) mutex_unlock(q->lock);
			*etimed = SLP_TRUE;
			return (NULL);
		}
	}

msg_available:
	ans = dequeue_nolock(q);
	(void) mutex_unlock(q->lock);
	return (ans);
}

/*
 * Removes the first message from the queue and returns it.
 * Returns NULL only on internal error.
 */
void *slp_dequeue(slp_queue_t *qa) {
	return (slp_dequeue_timed(qa, NULL, NULL));
}

/*
 * Flushes the queue, using the caller-specified free function to
 * free each message in the queue.
 */
void slp_flush_queue(slp_queue_t *qa, void (*free_f)(void *)) {
	slp_queue_entry_t *p, *pn;
	struct queue *q = qa;

	for (p = q->head; p; p = pn) {
		pn = p->next;
		free_f(p);
	}
}

/*
 * Frees a queue.
 * The queue must be empty before it can be destroyed; slp_flush_queue
 * can be used to empty a queue.
 */
void slp_destroy_queue(slp_queue_t *qa) {
	struct queue *q = qa;

	(void) mutex_destroy(q->lock);
	(void) cond_destroy(q->wait);
	free(q->lock);
	free(q->wait);
	free(q);
}
