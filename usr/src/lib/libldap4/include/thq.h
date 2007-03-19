/*
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>

typedef void * (*PFP)(void *);

typedef void * (*PFP2)(void *, void *);

typedef struct tq_listS {
	void * arg;
	struct tq_listS * next;
} tq_listT, * tq_listTp;

typedef struct {
  tq_listTp first;            /* first element in the queue                */
	tq_listTp last;             /* last  element in the queue                */
	pthread_mutex_t   lock;     /* queue mutex                               */
	pthread_cond_t    cond;     /* queue condition to signal new elements    */
	int *     shutdown;         /* variable to test to see shutdown condition*/
	int       shutalloc;        /* is the shutdown variable allocated locally*/
	int       stopping;         /* queue is currently stopping               */
	int       queue_size;       /* current size of the queue                 */
	int       nb_thr;           /* current nb of threads pocessing the queue */
	int       thr_waiting;      /* current nb of threads waiting             */
	int       max_thr;          /* max allowed threads to process the queue  */
	int       min_thr;          /* min nb of threads to keep alive           */
	PFP       doit;             /* function to call to process the queue     */
	PFP2      endit;            /* function called before to end the thread  */
	void *    arg;              /* argument to pass to the doit/endit func.  */
	pthread_t * tids;           /* array of thread ids for watchdog          */
} tqT, * tqTp;

extern tqTp   tq_alloc(PFP process_func,   /* function to process the queue */
                       PFP2 shutdown_func, /* function called before to end */
                       void * func_arg,    /* arg passed to both functions  */
                       int * shutdown,     /* shutdown variable to test     */
                       int max,            /* max allowed threads           */
                       int min);           /* min allowed threads           */

extern int    tq_queue(tqTp queue,         /* pointer to the queue          */
                       void * arg);        /* element to be queued          */

/* tq_dequeue returns the first "arg" passed to tq_queue */
extern void * tq_dequeue(tqTp queue,            /* pointer to the queue          */
                         void * endit_arg);     /* pointer to "shutdown" arguments */ 
/*
 * tq_end_thread terminates the current
 * thread and restarts a new one if necessary
 */
extern void tq_end_thread (tqTp queue,          /* pointer to the queue          */
                          void * endit_arg);    /* pointer to "shutdown" arguments */

/*
 * tq_shutdown, shutdown the queue (alternate way to shutdown if you don't
 * have a global shutdown integer
 *
 * shutdown can be immediate (1) or delayed until there is nothing more
 * in the queue (immadiate = 0)
 *
 * when you call this function, no more argument can be queued using
 * tq_queue.
 * 
 * when tq_dequeue returns, the queue pointer is not allocated anymore
 *
 */
extern void tq_shutdown(tqTp queue,     /* pointer to the queue          */
                        int immediate); /* 1: don't wait, 0: wait for queue */
																				/*                   to be empty    */
