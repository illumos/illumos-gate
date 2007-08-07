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
 * Copyright 1999-2002 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: thq.c
 *
 * This file contains all of the routines used for thread
 * queue management. Thread queue management provides an
 * interface for an application to dispatch processing of a
 * data object to a pool of threads.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#include "thq.h"

#define	DEFAULT_MIN_THREADS	10
#define	DEFAULT_MAX_THREADS	100

/*
 * Function: tq_alloc
 *
 * Arguments:	action - Pointer to the function that new threads
 *			must call.
 *		end - Pointer to a function that will be called
 *			if threads are being killed (optional).
 *		arg - Pointer that will be passed as an argument
 *			to new threads created (optional).
 *		shutdown - Pointer to the shutdown flag. If this
 *			is provided, if the pointer contains a
 *			non-zero value, the thread queueing system
 *			will assume that the process is shutting
 *			down (optional).
 *		max - The maximum number of threads
 *		min - The minimum number of threads
 *
 * Description: This function is used to create the thread
 *		queue. The end, arg and shutdown parameters
 *		MAY be set to NULL. If the max and min are
 *		not provided, we will use our own defaults.
 *
 *		Once the thread queue has been allocated, we
 *		will initialize it, and init the the lock and
 *		condition variables.
 *
 * Returns:	Upon successful completion, the function will
 *		return a pointer to a thread queue, otherwise
 *		NULL
 */
tqTp
tq_alloc(PFP action, PFP2 end, void *arg, int *shutdown, int max, int min,
    boolean_t cleanup)
{
	tqTp queue;
	if (action == NULL) {
		/* no function passed, error */
		errno = EINVAL;
		return (NULL);
	} /* end if */
	/* if those parameters are not passed, take default ones */
	if (max <= 0) max = DEFAULT_MAX_THREADS;
	if (min <= 0) min = DEFAULT_MIN_THREADS;
	queue = (tqTp) calloc(1, sizeof (tqT));
	if (queue == NULL) {
		return (NULL);
	} /* end if */
	if (shutdown == NULL) {
		shutdown = (int *)calloc(1, sizeof (int));
		if (shutdown == NULL) {
			free(queue);
			return (NULL);
		} /* end if */
		queue->shutalloc = 1;
	}
	if (queue != NULL && shutdown != NULL) {
		/*
		 * The wd_mask mechanism is used to accelerate the search of
		 * a "hole" in the queue->tid[] structure whenever we needed
		 * to create a new thread and to accelerate the search of a
		 * tid in the queue->tid[] structure whenever we needed to
		 * end a thread. The previous code(i.e., wd_mask = 0) was
		 * always parsing this structure sequentially with the
		 * consequent problems:
		 *
		 * + in thr creations, "holes" where not uniformly distributed
		 * through the queue->tid[] structure BUT condensed at the end
		 * of it.
		 *
		 * + in thr_ ends, finding the thread tid associated to the
		 * thread to be ended was not optimal
		 *
		 * With the wd_mask mechanism, on the contrary:
		 *
		 * + in thr creations, the new assigned tid is itself used
		 * for the indexation on the queue->tid[] and stored at the
		 * first "hole" found from that position. If we get to
		 * queue->tid[MAX], we round in circle and come back to
		 * queue->tid[0]
		 *
		 * + in thr_deletions, the old pid is itself used for the
		 * indexation on the queue->tid[], accelerating the search.
		 *
		 * This mechanism is much faster than the old one, specially
		 * considering that, as tid assignments are(were! when not
		 * detached) sequential, if the queue->tid[] contains 256
		 * elements, by the time the thread with tid 259 will be
		 * created there are enormous chances that the thread(259-256
		 * = 3) with tid 3 has already ended, hence, finding a
		 * "hole" in the queue->tid[] structure.
		 */
		queue->wd_mask	= 0;
		queue->doit	= action;
		queue->endit	= end;
		queue->arg	= arg;
		queue->shutdown	= shutdown;
		queue->max_thr	= max;
		queue->min_thr	= min;
		queue->cleanup	= cleanup;

		if ((max << 1) < 32) {
			queue->tids = (pthread_t *)calloc(32,
			    sizeof (pthread_t));
			queue->wd_mask = 0x1F;
		} else if ((max << 1) < 64) {
			queue->tids = (pthread_t *)calloc(64,
			    sizeof (pthread_t));
			queue->wd_mask = 0x3F;
		} else if ((max << 1) < 128) {
			queue->tids = (pthread_t *)calloc(128,
			    sizeof (pthread_t));
			queue->wd_mask = 0x7F;
		} else if ((max << 1) < 256) {
			queue->tids = (pthread_t *)calloc(256,
			    sizeof (pthread_t));
			queue->wd_mask = 0xFF;
		} else if ((max << 1) < 512) {
			queue->tids = (pthread_t *)calloc(512,
			    sizeof (pthread_t));
			queue->wd_mask = 0x01FF;
		} else if ((max << 1) < 1024) {
			queue->tids = (pthread_t *)calloc(1024,
			    sizeof (pthread_t));
			queue->wd_mask = 0x03FF;
		} else if ((max << 1) < 2048) {
			queue->tids = (pthread_t *)calloc(2048,
			    sizeof (pthread_t));
			queue->wd_mask = 0x07FF;
		} else if (max < 4096) {
			queue->tids = (pthread_t *)calloc(4096,
			    sizeof (pthread_t));
			queue->wd_mask = 0x0FFF;
		} else if (max < 8192) {
			queue->tids = (pthread_t *)calloc(8192,
			    sizeof (pthread_t));
			queue->wd_mask = 0x1FFF;
		} else if (max < 16384) {
			queue->tids = (pthread_t *)calloc(16384,
			    sizeof (pthread_t));
			queue->wd_mask = 0x3FFF;
		} else {
			queue->tids = (pthread_t *)calloc(max,
			    sizeof (pthread_t));
		}

		if (queue->tids == NULL) {
			if (queue->shutalloc) {
				free(shutdown);
			} /* end if */
			free(queue);
			return (NULL);
		} /* end if */
		(void) pthread_mutex_init(&(queue->lock), NULL);
		(void) pthread_cond_init(&(queue->cond), NULL);
	} /* end if */
	return (queue);
}


/*
 * Function: dump_queue
 *
 * Arguments:	queue - Pointer to the thread queue
 *
 * Description: This function is provided for debugging purposes
 *		but is not currently used in the code, and will
 *		print out the contents of the thread queue.
 *
 * Returns:
 */
#ifndef lint
void
dump_queue(tqTp queue)
{
	tq_listTp cur;
	(void) printf("first %p, last %p, ",  (void *)queue->first,
	    (void *)queue->last);
	for (cur = queue->first; cur; cur = cur->next) {
		(void) printf("%p:%p ", (void *)cur, (void *)cur->arg);
	} /* end for */
	(void) printf("\n");
}
#endif

/*
 * Function: timedthread
 *
 * Arguments:	arg - Pointer to an argument that will be
 *			provided to the new thread.
 *
 * Description: This strange function will sleep for 4 seconds
 *		before calling the thread callback routine.
 *
 * Returns: should never return.
 */
static void
timedthread(void * arg)
{
	tqTp queue = (tqTp)arg;

	(void) sleep(4);
	(void)  (*(queue->doit))(queue->arg);
}

/*
 * Function: create_new_thread
 *
 * Arguments:	queue - Pointer to the thread queue
 *		timer - Determines whether we need to
 *			wait before we call the new
 *			thread.
 *
 * Description:	This function is used to create a new
 *		thread. If the number of threads waiting
 *		is smaller than the number of items in
 *		our queue, and we have not reached our
 *		maximum number of threads, a new thread
 *		will be created.
 *
 * Returns: int, 0 if successful
 */
static int
create_new_thread(tqTp queue, int timer)
{
	int i;
	pthread_t tid;

	if (queue->thr_waiting < queue->queue_size &&
	    queue->nb_thr < queue->max_thr) {
		/* create a thread to manage this request */
		++(queue->nb_thr);
		if (timer) {
			if (pthread_create(&tid, NULL,
			    (void *(*)())timedthread, queue) != 0) {
				return (-1);
			} /* end if */
		} /* end if */
		else if (pthread_create(&tid, NULL,
			    (void *(*)())queue->doit, queue->arg) != 0) {
			return (-1);
		} /* end if */

		if (pthread_detach(tid)) {
			/*
			 * Unable to detach the thread, let's kill it.
			 */
			(void)  pthread_cancel(tid);
		}

		/*
		 * put the thread id into the saved array for the
		 * watchdog mechanism
		 */
		if (queue->wd_mask) {
			int htid = tid & queue->wd_mask;
			for (i = htid; i < queue->wd_mask; ++i) {
				if (queue->tids[i] == 0) {
					queue->tids[i] = tid;
					break;
				} /* end if */
			} /* end for */
			if (i == queue->wd_mask) {
				for (i = 0; i < htid; ++i) {
					if (queue->tids[i] == 0) {
						queue->tids[i] = tid;
						break;
					} /* end if */
				} /* end for */
			}
		} else {
			for (i = 0; i < queue->max_thr; ++i) {
				if (queue->tids[i] == 0) {
					queue->tids[i] = tid;
					break;
				} /* end if */
			} /* end for */
		}
	} /* end if */
	return (0);
}

/*
 * Function: tq_queue
 *
 * Arguments:	queue - Pointer to the thread queue
 *		arg - Pointer to object to be processed
 *
 * Description: queue an action to be done in the arg queue
 *		and signal any waiting thread that something
 *		is to be processed. If we notice that we've
 *		reached our maximum number of threads, and no
 *		threads are in the waiting state, we will
 *		make sure that all threads stil exist.
 *
 *		if arg is null, special case, just send the signal
 *		(probably in case of shutdown)
 *
 * Returns: int, 0 if successful
 */
int
tq_queue(tqTp queue, void *arg)
{
	tq_listTp cur;
	int i;
	static int times_called = 0;
	static int gc = 0;

	if (!gc) {
		if ((++times_called) >= (queue->max_thr >> 1)) {
			times_called = 0;
			gc = 1;
		}
	}

	if (queue == NULL) {
		return (0);
	} /* end if */
	if (*(queue->shutdown) || queue->stopping) {
		/*
		 * shutdown condition, broadcast to all the threads waiting to
		 * terminate them
		 * and refuse new stuff in the queue
		 */
		(void) pthread_cond_broadcast(&(queue->cond));
		return (-1);
	}
	if (arg) {
		if ((cur = (tq_listTp)calloc(1, sizeof (tq_listT))) == NULL) {
			return (-1);
		} /* end if */
		cur->arg = arg;
		(void) pthread_mutex_lock(&(queue->lock));
		if (queue->last) {
			queue->last->next = cur;
		} /* end if */
		queue->last = cur;
		cur->next = 0;
		if (queue->first == NULL) {
			queue->first = cur;
		} /* end if */
		++(queue->queue_size);
		if (queue->thr_waiting == 0 &&
		    queue->nb_thr == queue->max_thr && gc) {
			/*
			 * Since it is possible that some threads have exited
			 * by themselves, if we reach the maximum number of
			 * threads, we will kill with signal 0, which simply
			 * ensures that the thread is still valid. If the
			 * thread is no longer valid, we will free the entry
			 * in the queue.
			 */
			int max;
			gc = 0;

			max = (queue->wd_mask) ? queue->wd_mask :
			    queue->max_thr;

			for (i = 0; i < max; ++i) {
				if (queue->tids[i] != 0) {
					if (pthread_kill(queue->tids[i], 0)) {
						queue->tids[i] = 0;
						--(queue->nb_thr);
					} /* end if */
				} /* end if */
			} /* end for */
		} /* end if */
		/*
		 * if size of the queue > nb of thread waiting and we
		 * didn't reach the maximum number of threads, create a
		 * new one
		 */
		if (create_new_thread(queue, 0)) {
			return (-1);
		}
	} /* end if */
	else
		(void) pthread_mutex_lock(&(queue->lock));
	/* just signal one of the waiting threads */
	(void) pthread_cond_signal(&(queue->cond));
	(void) pthread_mutex_unlock(&(queue->lock));
	return (0);
}

/*
 * Function: tq_end_thread
 *
 * Arguments:	queue - Pointer to the thread queue
 *		endit_arg - parameter to be passed to
 *			the thread shutdown function.
 *
 * Description: This function is called when a thread
 *		needs to be shutdown. if a termination
 *		function was provided during tq_alloc(),
 *		we will call it with the argument provided.
 *
 *		If the shutdown flag is not set, we will
 *		create another thread, otherwise we will
 *		send a broadcast that we are shutting down.
 *
 * Returns:
 */
static void
tq_end_thread(tqTp queue, void * endit_arg)
{
	pthread_t tid = pthread_self();
	int i;
	/*
	 * call the finish function of the thread
	 */
	if (queue->endit) {
		(void)  (*(queue->endit))(queue->arg, endit_arg);
	} /* end if */

	if (queue->wd_mask) {
		int htid = tid & queue->wd_mask;
		for (i = htid; i < queue->wd_mask; ++i) {
			if (queue->tids[i] == tid) {
				queue->tids[i] = 0;
				break;
			} /* end if */
		} /* end for */
		if (i == queue->wd_mask) {
			for (i = 0; i < htid; ++i) {
				if (queue->tids[i] == tid) {
					queue->tids[i] = 0;
					break;
				} /* end if */
			} /* end for */
		}
	} else {
		for (i = 0; i < queue->max_thr; ++i) {
			if (queue->tids[i] == tid) {
				queue->tids[i] = 0;
				break;
			} /* end if */
		} /* end for */
	}

	/*
	 * It is possible that while we started to shutdown, a new item
	 * showed up on the queue. By calling create_new_thread() we
	 * will create such a thread, only if necessary.
	 */
	if (!*(queue->shutdown))
		(void)  create_new_thread(queue, 1);
	/*
	 * and terminate the thread
	 */
	if (*(queue->shutdown)) {
		/* shutdown condition, warn the waiting function if any */
		(void) pthread_cond_broadcast(&(queue->cond));
	}
	/*
	 * update number of active threads
	 */
	--(queue->thr_waiting);
	--(queue->nb_thr);
	/*
	 * unlock the queue
	 */
	(void) pthread_mutex_unlock(&(queue->lock));
	pthread_exit(0);
} /* end static void tq_end_thread */

/*
 * Function: tq_dequeue
 *
 * Arguments:	queue - Pointer to the thread queue
 *		endit_arg - parameter to be passed to
 *			the thread shutdown function.
 *
 * Description: This function is called by the threads
 *		to retrieve an object to process. If
 *		the caller ends up waiting for 30 seconds
 *		without processing anything, we will
 *		terminate the thread.
 *
 * Returns:	a pointer to an object to process taken
 *		from the queue.
 */
void *
tq_dequeue(tqTp queue, void * endit_arg)
{
	tq_listTp cur;
	void *    arg;

	if (queue == NULL) {
		return (NULL);
	} /* end if */
	(void) pthread_mutex_lock(&(queue->lock));
	++(queue->thr_waiting);
	/* dump_queue(queue); */
	while (!*(queue->shutdown)) {
		/*
		 * if something in the queue, dequeue it and return the
		 * action to be done
		 */
		if (queue->first) {
			cur = queue->first;
			queue->first = queue->first->next;
			if (queue->first == NULL) {
				queue->last = NULL;
				if (queue->stopping) {
					(void) pthread_cond_broadcast(
							&(queue->cond));
				} /* end if */
			} /* end if */
			--(queue->queue_size);
			--(queue->thr_waiting);
			(void) pthread_mutex_unlock(&(queue->lock));
			arg = cur->arg;
			free(cur);
			return (arg);
		} else {
			timestruc_t to;
			int rc;
			to.tv_sec = 30;
			to.tv_nsec = 0;
			/*
			 * wait for the condition arg_loop to be set
			 * or a signal occurs, or a timeout
			 */
			rc = pthread_cond_reltimedwait_np(&(queue->cond),
			    &(queue->lock), &to);
			if ((rc ==  ETIME || rc == ETIMEDOUT) &&
			    queue->nb_thr > queue->min_thr &&
			    queue->cleanup == _B_TRUE) {
				/*
				 * we don't want to keep this thread alive
				 * call shutdown function, release the lock
				 * and exit
				 */
				tq_end_thread(queue, endit_arg);
			}
		} /* end if */
	} /* end while */
	/*
	 * shutdown condition
	 *
	 * end the thread
	 * call shutdown function, release the lock and exit
	 */
	tq_end_thread(queue, endit_arg);
	return (NULL); /* never called, just here for the compiler */
}

/*
 * Function: tq_shutdown
 *
 * Arguments:	queue - Pointer to the thread queue
 *		immediate - shutdown immediately flag
 *
 * Description: This function is called to free the thread
 *		queue, and to kill all threads that were
 *		allocated as a result of the creation of the
 *		thread queue. If the immediate flag is set
 *		to non-zero, we will kill all threads
 *		immediately, otherwise we will wait for all
 *		threads to shutdown.
 *
 * Returns:
 */
void
tq_shutdown(tqTp queue, int immediate)
{
	timestruc_t to;
	(void) pthread_mutex_lock(&(queue->lock));
	queue->stopping = 1;
	if (!immediate) {
		while (queue->first != NULL && *(queue->shutdown) == 0) {
			to.tv_sec = 1;
			to.tv_nsec = 0;
			(void) pthread_cond_reltimedwait_np(&(queue->cond),
			    &(queue->lock),
			    &to);
		}
	} /* end if */

	/*
	 * shutdown condition, broadcast to all the threads waiting to
	 * terminate them
	 */
	*(queue->shutdown) = 1;
	while (queue->nb_thr > 0) {
		(void) pthread_cond_broadcast(&(queue->cond));
		to.tv_sec = 1;
		to.tv_nsec = 0;
		(void) pthread_cond_reltimedwait_np(&(queue->cond),
						&(queue->lock), &to);
	} /* end while */
	free(queue->tids);
	if (queue->shutalloc) {
		free(queue->shutdown);
	} /* end if */
	free(queue);
}
