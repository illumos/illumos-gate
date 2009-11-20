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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <pthread.h>
#include <memory.h>
#include "queue.h"
#include <stdio.h>
#include <assert.h>
#include "plugin.h"

#define	DEBUG	0

#if DEBUG
extern FILE *dbfp;
extern FILE *__auditd_debug_file_open();
#define	DPRINT(x) {(void) fprintf x; }
#else
#define	DPRINT(x)
#endif

void
audit_queue_init(au_queue_t *q)
{
	q->auq_head = NULL;
	q->auq_tail = NULL;
	(void) pthread_mutex_init(&q->auq_lock, NULL);
	q->auq_count = 0;
#if DEBUG
	if (dbfp == NULL) {
		dbfp = __auditd_debug_file_open();
	}
#endif
}

/*
 * enqueue()	caller creates queue entry
 */

void
audit_enqueue(au_queue_t *q,  void *p)
{
	(void) pthread_mutex_lock(&q->auq_lock);

	DPRINT((dbfp, "enqueue0(%X): p=%X, head=%X, tail=%X, count=%d\n",
	    q, p, q->auq_head, q->auq_tail, q->auq_count));

	if (q->auq_head == NULL)
		q->auq_head = p;
	else {
		DPRINT((dbfp, "\tindirect tail=%X\n",
		    &(((audit_link_t *)(q->auq_tail))->aln_next)));

		((audit_link_t *)(q->auq_tail))->aln_next = p;
	}
	q->auq_tail = p;
	((audit_link_t *)p)->aln_next = NULL;
	q->auq_count++;

	DPRINT((dbfp, "enqueue1(%X): p=%X, head=%X, tail=%X, "
	    "count=%d, pnext=%X\n",
	    q, p, q->auq_head, q->auq_tail, q->auq_count,
	    ((audit_link_t *)p)->aln_next));

	(void) pthread_mutex_unlock(&q->auq_lock);
}

/*
 * audit_dequeue() returns entry; caller is responsible for free
 */

int
audit_dequeue(au_queue_t *q, void **p)
{
	(void) pthread_mutex_lock(&q->auq_lock);

	if ((*p = q->auq_head) == NULL) {
		DPRINT((dbfp, "dequeue1(%X): p=%X, head=%X, "
		    "tail=%X, count=%d\n",
		    q, *p, q->auq_head, q->auq_tail, q->auq_count));

		(void) pthread_mutex_unlock(&q->auq_lock);
		return (1);
	}
	q->auq_count--;

	/* if *p is the last, next is NULL */
	q->auq_head = ((audit_link_t *)*p)->aln_next;

	DPRINT((dbfp, "dequeue0(%X): p=%X, head=%X, tail=%X, "
	    "count=%d, pnext=%X\n",
	    q, *p, q->auq_head, q->auq_tail, q->auq_count,
	    ((audit_link_t *)*p)->aln_next));

	(void) pthread_mutex_unlock(&q->auq_lock);
	return (0);
}

/*
 * increment ref count
 */
void
audit_incr_ref(pthread_mutex_t *l, audit_rec_t *p)
{
	(void) pthread_mutex_lock(l);
	p->abq_ref_count++;
	DPRINT((dbfp, "incr_ref: p=%X, count=%d\n",
	    p, p->abq_ref_count));
	(void) pthread_mutex_unlock(l);
}
/*
 * decrement reference count; if it reaches zero,
 * return a pointer to it.  Otherwise, return NULL.
 */
audit_rec_t *
audit_release(pthread_mutex_t *l, audit_rec_t *p)
{
	assert(p != NULL);

	(void) pthread_mutex_lock(l);

	DPRINT((dbfp, "release: p=%X, count=%d\n",
	    p, p->abq_ref_count));

	if (--(p->abq_ref_count) > 0) {
		(void) pthread_mutex_unlock(l);
		return (NULL);
	}
	(void) pthread_mutex_unlock(l);

	return (p);
}

int
audit_queue_size(au_queue_t *q)
{
	int	size;

	(void) pthread_mutex_lock(&q->auq_lock);
	size = q->auq_count;
	(void) pthread_mutex_unlock(&q->auq_lock);

	return (size);
}


void
audit_queue_destroy(au_queue_t *q)
{
	(void) pthread_mutex_destroy(&q->auq_lock);
}
