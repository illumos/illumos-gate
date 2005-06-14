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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _THQ_H
#define	_THQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the definitions for the thread
 * management module (thq.h).
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

typedef void * (*PFP)(void *);

typedef void * (*PFP2)(void *, void *);

typedef struct tq_listS {
	void * arg;
	struct tq_listS *next;
} tq_listT, * tq_listTp;

typedef struct {
	tq_listTp first;	/* first element in the queue */
	tq_listTp last;		/* last  element in the queue */
	pthread_mutex_t lock;	/* queue mutex */
	pthread_cond_t cond;	/* queue condition to signal new elements */
	int *shutdown;		/* variable to test for shutdown condition */
	int shutalloc;		/* was shutdown variable allocated locally */
	int stopping;		/* queue is currently stopping */
	int queue_size;		/* current size of the queue */
	int nb_thr;		/* current nb of threads pocessing the queue */
	int thr_waiting;	/* current nb of threads waiting */
	int max_thr;		/* max allowed threads to process the queue  */
	int min_thr;		/* min nb of threads to keep alive */
	int wd_mask;		/* Watchdog mask */
	boolean_t cleanup;	/* Will we kill inactive threads */
	PFP doit;		/* function to call to process the queue */
	PFP2 endit;		/* function called before to end the thread */
	void *arg;		/* argument to pass to the doit/endit func. */
	pthread_t *tids;	/* array of thread ids for watchdog */
} tqT, * tqTp;

extern tqTp   tq_alloc(PFP,	/* function to process the queue */
    PFP2,			/* function called before to end */
    void *,			/* arg passed to both functions */
    int *,			/* shutdown variable to test */
    int,			/* max allowed threads */
    int,			/* min allowed threads */
    boolean_t);			/* If TRUE all inactive threads are killed */

extern int    tq_queue(tqTp,	/* pointer to the queue */
    void *);			/* element to be queued */

/*
 * tq_dequeue returns the first "arg" passed to tq_queue
 */
extern void * tq_dequeue(tqTp,	/* pointer to the queue */
    void *);			/* pointer to "shutdown" arguments */

/*
 * tq_shutdown, shutdown the queue (alternate way to shutdown if you don't
 * have a global shutdown integer
 *
 * shutdown can be immediate (1) or delayed until there is nothing more
 * in the queue (immediate = 0)
 *
 * when you call this function, no more argument can be queued using
 * tq_queue.
 *
 * when tq_dequeue returns, the queue pointer is not allocated anymore
 *
 */
extern void tq_shutdown(tqTp,	/* pointer to the queue */
    int);			/* 1: don't wait, 0: wait for queue */
					/* to be empty */

#ifdef __cplusplus
}
#endif

#endif /* _THQ_H */
