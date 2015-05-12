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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 */

/*	Copyright (c) 1983, 1984, 1985,  1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Server-side remote procedure call interface.
 *
 * Master transport handle (SVCMASTERXPRT).
 *   The master transport handle structure is shared among service
 *   threads processing events on the transport. Some fields in the
 *   master structure are protected by locks
 *   - xp_req_lock protects the request queue:
 *	xp_req_head, xp_req_tail, xp_reqs, xp_size, xp_full, xp_enable
 *   - xp_thread_lock protects the thread (clone) counts
 *	xp_threads, xp_detached_threads, xp_wq
 *   Each master transport is registered to exactly one thread pool.
 *
 * Clone transport handle (SVCXPRT)
 *   The clone transport handle structure is a per-service-thread handle
 *   to the transport. The structure carries all the fields/buffers used
 *   for request processing. A service thread or, in other words, a clone
 *   structure, can be linked to an arbitrary master structure to process
 *   requests on this transport. The master handle keeps track of reference
 *   counts of threads (clones) linked to it. A service thread can switch
 *   to another transport by unlinking its clone handle from the current
 *   transport and linking to a new one. Switching is relatively inexpensive
 *   but it involves locking (master's xprt->xp_thread_lock).
 *
 * Pools.
 *   A pool represents a kernel RPC service (NFS, Lock Manager, etc.).
 *   Transports related to the service are registered to the service pool.
 *   Service threads can switch between different transports in the pool.
 *   Thus, each service has its own pool of service threads. The maximum
 *   number of threads in a pool is pool->p_maxthreads. This limit allows
 *   to restrict resource usage by the service. Some fields are protected
 *   by locks:
 *   - p_req_lock protects several counts and flags:
 *	p_reqs, p_size, p_walkers, p_asleep, p_drowsy, p_req_cv
 *   - p_thread_lock governs other thread counts:
 *	p_threads, p_detached_threads, p_reserved_threads, p_closing
 *
 *   In addition, each pool contains a doubly-linked list of transports,
 *   an `xprt-ready' queue and a creator thread (see below). Threads in
 *   the pool share some other parameters such as stack size and
 *   polling timeout.
 *
 *   Pools are initialized through the svc_pool_create() function called from
 *   the nfssys() system call. However, thread creation must be done by
 *   the userland agent. This is done by using SVCPOOL_WAIT and
 *   SVCPOOL_RUN arguments to nfssys(), which call svc_wait() and
 *   svc_do_run(), respectively. Once the pool has been initialized,
 *   the userland process must set up a 'creator' thread. This thread
 *   should park itself in the kernel by calling svc_wait(). If
 *   svc_wait() returns successfully, it should fork off a new worker
 *   thread, which then calls svc_do_run() in order to get work. When
 *   that thread is complete, svc_do_run() will return, and the user
 *   program should call thr_exit().
 *
 *   When we try to register a new pool and there is an old pool with
 *   the same id in the doubly linked pool list (this happens when we kill
 *   and restart nfsd or lockd), then we unlink the old pool from the list
 *   and mark its state as `closing'. After that the transports can still
 *   process requests but new transports won't be registered. When all the
 *   transports and service threads associated with the pool are gone the
 *   creator thread (see below) will clean up the pool structure and exit.
 *
 * svc_queuereq() and svc_run().
 *   The kernel RPC server is interrupt driven. The svc_queuereq() interrupt
 *   routine is called to deliver an RPC request. The service threads
 *   loop in svc_run(). The interrupt function queues a request on the
 *   transport's queue and it makes sure that the request is serviced.
 *   It may either wake up one of sleeping threads, or ask for a new thread
 *   to be created, or, if the previous request is just being picked up, do
 *   nothing. In the last case the service thread that is picking up the
 *   previous request will wake up or create the next thread. After a service
 *   thread processes a request and sends a reply it returns to svc_run()
 *   and svc_run() calls svc_poll() to find new input.
 *
 * svc_poll().
 *   In order to avoid unnecessary locking, which causes performance
 *   problems, we always look for a pending request on the current transport.
 *   If there is none we take a hint from the pool's `xprt-ready' queue.
 *   If the queue had an overflow we switch to the `drain' mode checking
 *   each transport  in the pool's transport list. Once we find a
 *   master transport handle with a pending request we latch the request
 *   lock on this transport and return to svc_run(). If the request
 *   belongs to a transport different than the one the service thread is
 *   linked to we need to unlink and link again.
 *
 *   A service thread goes asleep when there are no pending
 *   requests on the transports registered on the pool's transports.
 *   All the pool's threads sleep on the same condition variable.
 *   If a thread has been sleeping for too long period of time
 *   (by default 5 seconds) it wakes up and exits.  Also when a transport
 *   is closing sleeping threads wake up to unlink from this transport.
 *
 * The `xprt-ready' queue.
 *   If a service thread finds no request on a transport it is currently linked
 *   to it will find another transport with a pending request. To make
 *   this search more efficient each pool has an `xprt-ready' queue.
 *   The queue is a FIFO. When the interrupt routine queues a request it also
 *   inserts a pointer to the transport into the `xprt-ready' queue. A
 *   thread looking for a transport with a pending request can pop up a
 *   transport and check for a request. The request can be already gone
 *   since it could be taken by a thread linked to that transport. In such a
 *   case we try the next hint. The `xprt-ready' queue has fixed size (by
 *   default 256 nodes). If it overflows svc_poll() has to switch to the
 *   less efficient but safe `drain' mode and walk through the pool's
 *   transport list.
 *
 *   Both the svc_poll() loop and the `xprt-ready' queue are optimized
 *   for the peak load case that is for the situation when the queue is not
 *   empty, there are all the time few pending requests, and a service
 *   thread which has just processed a request does not go asleep but picks
 *   up immediately the next request.
 *
 * Thread creator.
 *   Each pool has a thread creator associated with it. The creator thread
 *   sleeps on a condition variable and waits for a signal to create a
 *   service thread. The actual thread creation is done in userland by
 *   the method described in "Pools" above.
 *
 *   Signaling threads should turn on the `creator signaled' flag, and
 *   can avoid sending signals when the flag is on. The flag is cleared
 *   when the thread is created.
 *
 *   When the pool is in closing state (ie it has been already unregistered
 *   from the pool list) the last thread on the last transport in the pool
 *   should turn the p_creator_exit flag on. The creator thread will
 *   clean up the pool structure and exit.
 *
 * Thread reservation; Detaching service threads.
 *   A service thread can detach itself to block for an extended amount
 *   of time. However, to keep the service active we need to guarantee
 *   at least pool->p_redline non-detached threads that can process incoming
 *   requests. This, the maximum number of detached and reserved threads is
 *   p->p_maxthreads - p->p_redline. A service thread should first acquire
 *   a reservation, and if the reservation was granted it can detach itself.
 *   If a reservation was granted but the thread does not detach itself
 *   it should cancel the reservation before it returns to svc_run().
 */

#include <sys/param.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tiuser.h>
#include <sys/t_kuser.h>
#include <netinet/in.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <rpc/svc.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/tihdr.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/file.h>
#include <sys/systm.h>
#include <sys/callb.h>
#include <sys/vtrace.h>
#include <sys/zone.h>
#include <nfs/nfs.h>
#include <sys/tsol/label_macro.h>

#define	RQCRED_SIZE	400	/* this size is excessive */

/*
 * Defines for svc_poll()
 */
#define	SVC_EXPRTGONE ((SVCMASTERXPRT *)1)	/* Transport is closing */
#define	SVC_ETIMEDOUT ((SVCMASTERXPRT *)2)	/* Timeout */
#define	SVC_EINTR ((SVCMASTERXPRT *)3)		/* Interrupted by signal */

/*
 * Default stack size for service threads.
 */
#define	DEFAULT_SVC_RUN_STKSIZE		(0)	/* default kernel stack */

int    svc_default_stksize = DEFAULT_SVC_RUN_STKSIZE;

/*
 * Default polling timeout for service threads.
 * Multiplied by hz when used.
 */
#define	DEFAULT_SVC_POLL_TIMEOUT	(5)	/* seconds */

clock_t svc_default_timeout = DEFAULT_SVC_POLL_TIMEOUT;

/*
 * Size of the `xprt-ready' queue.
 */
#define	DEFAULT_SVC_QSIZE		(256)	/* qnodes */

size_t svc_default_qsize = DEFAULT_SVC_QSIZE;

/*
 * Default limit for the number of service threads.
 */
#define	DEFAULT_SVC_MAXTHREADS		(INT16_MAX)

int    svc_default_maxthreads = DEFAULT_SVC_MAXTHREADS;

/*
 * Maximum number of requests from the same transport (in `drain' mode).
 */
#define	DEFAULT_SVC_MAX_SAME_XPRT	(8)

int    svc_default_max_same_xprt = DEFAULT_SVC_MAX_SAME_XPRT;


/*
 * Default `Redline' of non-detached threads.
 * Total number of detached and reserved threads in an RPC server
 * thread pool is limited to pool->p_maxthreads - svc_redline.
 */
#define	DEFAULT_SVC_REDLINE		(1)

int    svc_default_redline = DEFAULT_SVC_REDLINE;

/*
 * A node for the `xprt-ready' queue.
 * See below.
 */
struct __svcxprt_qnode {
	__SVCXPRT_QNODE	*q_next;
	SVCMASTERXPRT	*q_xprt;
};

/*
 * Global SVC variables (private).
 */
struct svc_globals {
	SVCPOOL		*svc_pools;
	kmutex_t	svc_plock;
};

/*
 * Debug variable to check for rdma based
 * transport startup and cleanup. Contorlled
 * through /etc/system. Off by default.
 */
int rdma_check = 0;

/*
 * This allows disabling flow control in svc_queuereq().
 */
volatile int svc_flowcontrol_disable = 0;

/*
 * Authentication parameters list.
 */
static caddr_t rqcred_head;
static kmutex_t rqcred_lock;

/*
 * Pointers to transport specific `rele' routines in rpcmod (set from rpcmod).
 */
void	(*rpc_rele)(queue_t *, mblk_t *, bool_t) = NULL;
void	(*mir_rele)(queue_t *, mblk_t *, bool_t) = NULL;

/* ARGSUSED */
void
rpc_rdma_rele(queue_t *q, mblk_t *mp, bool_t enable)
{
}
void    (*rdma_rele)(queue_t *, mblk_t *, bool_t) = rpc_rdma_rele;


/*
 * This macro picks which `rele' routine to use, based on the transport type.
 */
#define	RELE_PROC(xprt) \
	((xprt)->xp_type == T_RDMA ? rdma_rele : \
	(((xprt)->xp_type == T_CLTS) ? rpc_rele : mir_rele))

/*
 * If true, then keep quiet about version mismatch.
 * This macro is for broadcast RPC only. We have no broadcast RPC in
 * kernel now but one may define a flag in the transport structure
 * and redefine this macro.
 */
#define	version_keepquiet(xprt)	(FALSE)

/*
 * ZSD key used to retrieve zone-specific svc globals
 */
static zone_key_t svc_zone_key;

static void svc_callout_free(SVCMASTERXPRT *);
static void svc_xprt_qinit(SVCPOOL *, size_t);
static void svc_xprt_qdestroy(SVCPOOL *);
static void svc_thread_creator(SVCPOOL *);
static void svc_creator_signal(SVCPOOL *);
static void svc_creator_signalexit(SVCPOOL *);
static void svc_pool_unregister(struct svc_globals *, SVCPOOL *);
static int svc_run(SVCPOOL *);

/* ARGSUSED */
static void *
svc_zoneinit(zoneid_t zoneid)
{
	struct svc_globals *svc;

	svc = kmem_alloc(sizeof (*svc), KM_SLEEP);
	mutex_init(&svc->svc_plock, NULL, MUTEX_DEFAULT, NULL);
	svc->svc_pools = NULL;
	return (svc);
}

/* ARGSUSED */
static void
svc_zoneshutdown(zoneid_t zoneid, void *arg)
{
	struct svc_globals *svc = arg;
	SVCPOOL *pool;

	mutex_enter(&svc->svc_plock);
	while ((pool = svc->svc_pools) != NULL) {
		svc_pool_unregister(svc, pool);
	}
	mutex_exit(&svc->svc_plock);
}

/* ARGSUSED */
static void
svc_zonefini(zoneid_t zoneid, void *arg)
{
	struct svc_globals *svc = arg;

	ASSERT(svc->svc_pools == NULL);
	mutex_destroy(&svc->svc_plock);
	kmem_free(svc, sizeof (*svc));
}

/*
 * Global SVC init routine.
 * Initialize global generic and transport type specific structures
 * used by the kernel RPC server side. This routine is called only
 * once when the module is being loaded.
 */
void
svc_init()
{
	zone_key_create(&svc_zone_key, svc_zoneinit, svc_zoneshutdown,
	    svc_zonefini);
	svc_cots_init();
	svc_clts_init();
}

/*
 * Destroy the SVCPOOL structure.
 */
static void
svc_pool_cleanup(SVCPOOL *pool)
{
	ASSERT(pool->p_threads + pool->p_detached_threads == 0);
	ASSERT(pool->p_lcount == 0);
	ASSERT(pool->p_closing);

	/*
	 * Call the user supplied shutdown function.  This is done
	 * here so the user of the pool will be able to cleanup
	 * service related resources.
	 */
	if (pool->p_shutdown != NULL)
		(pool->p_shutdown)();

	/* Destroy `xprt-ready' queue */
	svc_xprt_qdestroy(pool);

	/* Destroy transport list */
	rw_destroy(&pool->p_lrwlock);

	/* Destroy locks and condition variables */
	mutex_destroy(&pool->p_thread_lock);
	mutex_destroy(&pool->p_req_lock);
	cv_destroy(&pool->p_req_cv);

	/* Destroy creator's locks and condition variables */
	mutex_destroy(&pool->p_creator_lock);
	cv_destroy(&pool->p_creator_cv);
	mutex_destroy(&pool->p_user_lock);
	cv_destroy(&pool->p_user_cv);

	/* Free pool structure */
	kmem_free(pool, sizeof (SVCPOOL));
}

/*
 * If all the transports and service threads are already gone
 * signal the creator thread to clean up and exit.
 */
static bool_t
svc_pool_tryexit(SVCPOOL *pool)
{
	ASSERT(MUTEX_HELD(&pool->p_thread_lock));
	ASSERT(pool->p_closing);

	if (pool->p_threads + pool->p_detached_threads == 0) {
		rw_enter(&pool->p_lrwlock, RW_READER);
		if (pool->p_lcount == 0) {
			/*
			 * Release the locks before sending a signal.
			 */
			rw_exit(&pool->p_lrwlock);
			mutex_exit(&pool->p_thread_lock);

			/*
			 * Notify the creator thread to clean up and exit
			 *
			 * NOTICE: No references to the pool beyond this point!
			 *		   The pool is being destroyed.
			 */
			ASSERT(!MUTEX_HELD(&pool->p_thread_lock));
			svc_creator_signalexit(pool);

			return (TRUE);
		}
		rw_exit(&pool->p_lrwlock);
	}

	ASSERT(MUTEX_HELD(&pool->p_thread_lock));
	return (FALSE);
}

/*
 * Find a pool with a given id.
 */
static SVCPOOL *
svc_pool_find(struct svc_globals *svc, int id)
{
	SVCPOOL *pool;

	ASSERT(MUTEX_HELD(&svc->svc_plock));

	/*
	 * Search the list for a pool with a matching id
	 * and register the transport handle with that pool.
	 */
	for (pool = svc->svc_pools; pool; pool = pool->p_next)
		if (pool->p_id == id)
			return (pool);

	return (NULL);
}

/*
 * PSARC 2003/523 Contract Private Interface
 * svc_do_run
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
int
svc_do_run(int id)
{
	SVCPOOL *pool;
	int err = 0;
	struct svc_globals *svc;

	svc = zone_getspecific(svc_zone_key, curproc->p_zone);
	mutex_enter(&svc->svc_plock);

	pool = svc_pool_find(svc, id);

	mutex_exit(&svc->svc_plock);

	if (pool == NULL)
		return (ENOENT);

	/*
	 * Increment counter of pool threads now
	 * that a thread has been created.
	 */
	mutex_enter(&pool->p_thread_lock);
	pool->p_threads++;
	mutex_exit(&pool->p_thread_lock);

	/* Give work to the new thread. */
	err = svc_run(pool);

	return (err);
}

/*
 * Unregister a pool from the pool list.
 * Set the closing state. If all the transports and service threads
 * are already gone signal the creator thread to clean up and exit.
 */
static void
svc_pool_unregister(struct svc_globals *svc, SVCPOOL *pool)
{
	SVCPOOL *next = pool->p_next;
	SVCPOOL *prev = pool->p_prev;

	ASSERT(MUTEX_HELD(&svc->svc_plock));

	/* Remove from the list */
	if (pool == svc->svc_pools)
		svc->svc_pools = next;
	if (next)
		next->p_prev = prev;
	if (prev)
		prev->p_next = next;
	pool->p_next = pool->p_prev = NULL;

	/*
	 * Offline the pool. Mark the pool as closing.
	 * If there are no transports in this pool notify
	 * the creator thread to clean it up and exit.
	 */
	mutex_enter(&pool->p_thread_lock);
	if (pool->p_offline != NULL)
		(pool->p_offline)();
	pool->p_closing = TRUE;
	if (svc_pool_tryexit(pool))
		return;
	mutex_exit(&pool->p_thread_lock);
}

/*
 * Register a pool with a given id in the global doubly linked pool list.
 * - if there is a pool with the same id in the list then unregister it
 * - insert the new pool into the list.
 */
static void
svc_pool_register(struct svc_globals *svc, SVCPOOL *pool, int id)
{
	SVCPOOL *old_pool;

	/*
	 * If there is a pool with the same id then remove it from
	 * the list and mark the pool as closing.
	 */
	mutex_enter(&svc->svc_plock);

	if (old_pool = svc_pool_find(svc, id))
		svc_pool_unregister(svc, old_pool);

	/* Insert into the doubly linked list */
	pool->p_id = id;
	pool->p_next = svc->svc_pools;
	pool->p_prev = NULL;
	if (svc->svc_pools)
		svc->svc_pools->p_prev = pool;
	svc->svc_pools = pool;

	mutex_exit(&svc->svc_plock);
}

/*
 * Initialize a newly created pool structure
 */
static int
svc_pool_init(SVCPOOL *pool, uint_t maxthreads, uint_t redline,
	uint_t qsize, uint_t timeout, uint_t stksize, uint_t max_same_xprt)
{
	klwp_t *lwp = ttolwp(curthread);

	ASSERT(pool);

	if (maxthreads == 0)
		maxthreads = svc_default_maxthreads;
	if (redline == 0)
		redline = svc_default_redline;
	if (qsize == 0)
		qsize = svc_default_qsize;
	if (timeout == 0)
		timeout = svc_default_timeout;
	if (stksize == 0)
		stksize = svc_default_stksize;
	if (max_same_xprt == 0)
		max_same_xprt = svc_default_max_same_xprt;

	if (maxthreads < redline)
		return (EINVAL);

	/* Allocate and initialize the `xprt-ready' queue */
	svc_xprt_qinit(pool, qsize);

	/* Initialize doubly-linked xprt list */
	rw_init(&pool->p_lrwlock, NULL, RW_DEFAULT, NULL);

	/*
	 * Setting lwp_childstksz on the current lwp so that
	 * descendants of this lwp get the modified stacksize, if
	 * it is defined. It is important that either this lwp or
	 * one of its descendants do the actual servicepool thread
	 * creation to maintain the stacksize inheritance.
	 */
	if (lwp != NULL)
		lwp->lwp_childstksz = stksize;

	/* Initialize thread limits, locks and condition variables */
	pool->p_maxthreads = maxthreads;
	pool->p_redline = redline;
	pool->p_timeout = timeout * hz;
	pool->p_stksize = stksize;
	pool->p_max_same_xprt = max_same_xprt;
	mutex_init(&pool->p_thread_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&pool->p_req_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pool->p_req_cv, NULL, CV_DEFAULT, NULL);

	/* Initialize userland creator */
	pool->p_user_exit = FALSE;
	pool->p_signal_create_thread = FALSE;
	pool->p_user_waiting = FALSE;
	mutex_init(&pool->p_user_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pool->p_user_cv, NULL, CV_DEFAULT, NULL);

	/* Initialize the creator and start the creator thread */
	pool->p_creator_exit = FALSE;
	mutex_init(&pool->p_creator_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pool->p_creator_cv, NULL, CV_DEFAULT, NULL);

	(void) zthread_create(NULL, pool->p_stksize, svc_thread_creator,
	    pool, 0, minclsyspri);

	return (0);
}

/*
 * PSARC 2003/523 Contract Private Interface
 * svc_pool_create
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 *
 * Create an kernel RPC server-side thread/transport pool.
 *
 * This is public interface for creation of a server RPC thread pool
 * for a given service provider. Transports registered with the pool's id
 * will be served by a pool's threads. This function is called from the
 * nfssys() system call.
 */
int
svc_pool_create(struct svcpool_args *args)
{
	SVCPOOL *pool;
	int error;
	struct svc_globals *svc;

	/*
	 * Caller should check credentials in a way appropriate
	 * in the context of the call.
	 */

	svc = zone_getspecific(svc_zone_key, curproc->p_zone);
	/* Allocate a new pool */
	pool = kmem_zalloc(sizeof (SVCPOOL), KM_SLEEP);

	/*
	 * Initialize the pool structure and create a creator thread.
	 */
	error = svc_pool_init(pool, args->maxthreads, args->redline,
	    args->qsize, args->timeout, args->stksize, args->max_same_xprt);

	if (error) {
		kmem_free(pool, sizeof (SVCPOOL));
		return (error);
	}

	/* Register the pool with the global pool list */
	svc_pool_register(svc, pool, args->id);

	return (0);
}

int
svc_pool_control(int id, int cmd, void *arg)
{
	SVCPOOL *pool;
	struct svc_globals *svc;

	svc = zone_getspecific(svc_zone_key, curproc->p_zone);

	switch (cmd) {
	case SVCPSET_SHUTDOWN_PROC:
		/*
		 * Search the list for a pool with a matching id
		 * and register the transport handle with that pool.
		 */
		mutex_enter(&svc->svc_plock);

		if ((pool = svc_pool_find(svc, id)) == NULL) {
			mutex_exit(&svc->svc_plock);
			return (ENOENT);
		}
		/*
		 * Grab the transport list lock before releasing the
		 * pool list lock
		 */
		rw_enter(&pool->p_lrwlock, RW_WRITER);
		mutex_exit(&svc->svc_plock);

		pool->p_shutdown = *((void (*)())arg);

		rw_exit(&pool->p_lrwlock);

		return (0);
	case SVCPSET_UNREGISTER_PROC:
		/*
		 * Search the list for a pool with a matching id
		 * and register the unregister callback handle with that pool.
		 */
		mutex_enter(&svc->svc_plock);

		if ((pool = svc_pool_find(svc, id)) == NULL) {
			mutex_exit(&svc->svc_plock);
			return (ENOENT);
		}
		/*
		 * Grab the transport list lock before releasing the
		 * pool list lock
		 */
		rw_enter(&pool->p_lrwlock, RW_WRITER);
		mutex_exit(&svc->svc_plock);

		pool->p_offline = *((void (*)())arg);

		rw_exit(&pool->p_lrwlock);

		return (0);
	default:
		return (EINVAL);
	}
}

/*
 * Pool's transport list manipulation routines.
 * - svc_xprt_register()
 * - svc_xprt_unregister()
 *
 * svc_xprt_register() is called from svc_tli_kcreate() to
 * insert a new master transport handle into the doubly linked
 * list of server transport handles (one list per pool).
 *
 * The list is used by svc_poll(), when it operates in `drain'
 * mode, to search for a next transport with a pending request.
 */

int
svc_xprt_register(SVCMASTERXPRT *xprt, int id)
{
	SVCMASTERXPRT *prev, *next;
	SVCPOOL *pool;
	struct svc_globals *svc;

	svc = zone_getspecific(svc_zone_key, curproc->p_zone);
	/*
	 * Search the list for a pool with a matching id
	 * and register the transport handle with that pool.
	 */
	mutex_enter(&svc->svc_plock);

	if ((pool = svc_pool_find(svc, id)) == NULL) {
		mutex_exit(&svc->svc_plock);
		return (ENOENT);
	}

	/* Grab the transport list lock before releasing the pool list lock */
	rw_enter(&pool->p_lrwlock, RW_WRITER);
	mutex_exit(&svc->svc_plock);

	/* Don't register new transports when the pool is in closing state */
	if (pool->p_closing) {
		rw_exit(&pool->p_lrwlock);
		return (EBUSY);
	}

	/*
	 * Initialize xp_pool to point to the pool.
	 * We don't want to go through the pool list every time.
	 */
	xprt->xp_pool = pool;

	/*
	 * Insert a transport handle into the list.
	 * The list head points to the most recently inserted transport.
	 */
	if (pool->p_lhead == NULL)
		pool->p_lhead = xprt->xp_prev = xprt->xp_next = xprt;
	else {
		next = pool->p_lhead;
		prev = pool->p_lhead->xp_prev;

		xprt->xp_next = next;
		xprt->xp_prev = prev;

		pool->p_lhead = prev->xp_next = next->xp_prev = xprt;
	}

	/* Increment the transports count */
	pool->p_lcount++;

	rw_exit(&pool->p_lrwlock);
	return (0);
}

/*
 * Called from svc_xprt_cleanup() to remove a master transport handle
 * from the pool's list of server transports (when a transport is
 * being destroyed).
 */
void
svc_xprt_unregister(SVCMASTERXPRT *xprt)
{
	SVCPOOL *pool = xprt->xp_pool;

	/*
	 * Unlink xprt from the list.
	 * If the list head points to this xprt then move it
	 * to the next xprt or reset to NULL if this is the last
	 * xprt in the list.
	 */
	rw_enter(&pool->p_lrwlock, RW_WRITER);

	if (xprt == xprt->xp_next)
		pool->p_lhead = NULL;
	else {
		SVCMASTERXPRT *next = xprt->xp_next;
		SVCMASTERXPRT *prev = xprt->xp_prev;

		next->xp_prev = prev;
		prev->xp_next = next;

		if (pool->p_lhead == xprt)
			pool->p_lhead = next;
	}

	xprt->xp_next = xprt->xp_prev = NULL;

	/* Decrement list count */
	pool->p_lcount--;

	rw_exit(&pool->p_lrwlock);
}

static void
svc_xprt_qdestroy(SVCPOOL *pool)
{
	mutex_destroy(&pool->p_qend_lock);
	kmem_free(pool->p_qbody, pool->p_qsize * sizeof (__SVCXPRT_QNODE));
}

/*
 * Initialize an `xprt-ready' queue for a given pool.
 */
static void
svc_xprt_qinit(SVCPOOL *pool, size_t qsize)
{
	int i;

	pool->p_qsize = qsize;
	pool->p_qbody = kmem_zalloc(pool->p_qsize * sizeof (__SVCXPRT_QNODE),
	    KM_SLEEP);

	for (i = 0; i < pool->p_qsize - 1; i++)
		pool->p_qbody[i].q_next = &(pool->p_qbody[i+1]);

	pool->p_qbody[pool->p_qsize-1].q_next = &(pool->p_qbody[0]);
	pool->p_qtop = &(pool->p_qbody[0]);
	pool->p_qend = &(pool->p_qbody[0]);

	mutex_init(&pool->p_qend_lock, NULL, MUTEX_DEFAULT, NULL);
}

/*
 * Called from the svc_queuereq() interrupt routine to queue
 * a hint for svc_poll() which transport has a pending request.
 * - insert a pointer to xprt into the xprt-ready queue (FIFO)
 * - if the xprt-ready queue is full turn the overflow flag on.
 *
 * NOTICE: pool->p_qtop is protected by the pool's request lock
 * and the caller (svc_queuereq()) must hold the lock.
 */
static void
svc_xprt_qput(SVCPOOL *pool, SVCMASTERXPRT *xprt)
{
	ASSERT(MUTEX_HELD(&pool->p_req_lock));

	/* If the overflow flag is on there is nothing we can do */
	if (pool->p_qoverflow)
		return;

	/* If the queue is full turn the overflow flag on and exit */
	if (pool->p_qtop->q_next == pool->p_qend) {
		mutex_enter(&pool->p_qend_lock);
		if (pool->p_qtop->q_next == pool->p_qend) {
			pool->p_qoverflow = TRUE;
			mutex_exit(&pool->p_qend_lock);
			return;
		}
		mutex_exit(&pool->p_qend_lock);
	}

	/* Insert a hint and move pool->p_qtop */
	pool->p_qtop->q_xprt = xprt;
	pool->p_qtop = pool->p_qtop->q_next;
}

/*
 * Called from svc_poll() to get a hint which transport has a
 * pending request. Returns a pointer to a transport or NULL if the
 * `xprt-ready' queue is empty.
 *
 * Since we do not acquire the pool's request lock while checking if
 * the queue is empty we may miss a request that is just being delivered.
 * However this is ok since svc_poll() will retry again until the
 * count indicates that there are pending requests for this pool.
 */
static SVCMASTERXPRT *
svc_xprt_qget(SVCPOOL *pool)
{
	SVCMASTERXPRT *xprt;

	mutex_enter(&pool->p_qend_lock);
	do {
		/*
		 * If the queue is empty return NULL.
		 * Since we do not acquire the pool's request lock which
		 * protects pool->p_qtop this is not exact check. However,
		 * this is safe - if we miss a request here svc_poll()
		 * will retry again.
		 */
		if (pool->p_qend == pool->p_qtop) {
			mutex_exit(&pool->p_qend_lock);
			return (NULL);
		}

		/* Get a hint and move pool->p_qend */
		xprt = pool->p_qend->q_xprt;
		pool->p_qend = pool->p_qend->q_next;

		/* Skip fields deleted by svc_xprt_qdelete()	 */
	} while (xprt == NULL);
	mutex_exit(&pool->p_qend_lock);

	return (xprt);
}

/*
 * Delete all the references to a transport handle that
 * is being destroyed from the xprt-ready queue.
 * Deleted pointers are replaced with NULLs.
 */
static void
svc_xprt_qdelete(SVCPOOL *pool, SVCMASTERXPRT *xprt)
{
	__SVCXPRT_QNODE *q;

	mutex_enter(&pool->p_req_lock);
	for (q = pool->p_qend; q != pool->p_qtop; q = q->q_next) {
		if (q->q_xprt == xprt)
			q->q_xprt = NULL;
	}
	mutex_exit(&pool->p_req_lock);
}

/*
 * Destructor for a master server transport handle.
 * - if there are no more non-detached threads linked to this transport
 *   then, if requested, call xp_closeproc (we don't wait for detached
 *   threads linked to this transport to complete).
 * - if there are no more threads linked to this
 *   transport then
 *   a) remove references to this transport from the xprt-ready queue
 *   b) remove a reference to this transport from the pool's transport list
 *   c) call a transport specific `destroy' function
 *   d) cancel remaining thread reservations.
 *
 * NOTICE: Caller must hold the transport's thread lock.
 */
static void
svc_xprt_cleanup(SVCMASTERXPRT *xprt, bool_t detached)
{
	ASSERT(MUTEX_HELD(&xprt->xp_thread_lock));
	ASSERT(xprt->xp_wq == NULL);

	/*
	 * If called from the last non-detached thread
	 * it should call the closeproc on this transport.
	 */
	if (!detached && xprt->xp_threads == 0 && xprt->xp_closeproc) {
		(*(xprt->xp_closeproc)) (xprt);
	}

	if (xprt->xp_threads + xprt->xp_detached_threads > 0)
		mutex_exit(&xprt->xp_thread_lock);
	else {
		/* Remove references to xprt from the `xprt-ready' queue */
		svc_xprt_qdelete(xprt->xp_pool, xprt);

		/* Unregister xprt from the pool's transport list */
		svc_xprt_unregister(xprt);
		svc_callout_free(xprt);
		SVC_DESTROY(xprt);
	}
}

/*
 * Find a dispatch routine for a given prog/vers pair.
 * This function is called from svc_getreq() to search the callout
 * table for an entry with a matching RPC program number `prog'
 * and a version range that covers `vers'.
 * - if it finds a matching entry it returns pointer to the dispatch routine
 * - otherwise it returns NULL and, if `minp' or `maxp' are not NULL,
 *   fills them with, respectively, lowest version and highest version
 *   supported for the program `prog'
 */
static SVC_DISPATCH *
svc_callout_find(SVCXPRT *xprt, rpcprog_t prog, rpcvers_t vers,
    rpcvers_t *vers_min, rpcvers_t *vers_max)
{
	SVC_CALLOUT_TABLE *sct = xprt->xp_sct;
	int i;

	*vers_min = ~(rpcvers_t)0;
	*vers_max = 0;

	for (i = 0; i < sct->sct_size; i++) {
		SVC_CALLOUT *sc = &sct->sct_sc[i];

		if (prog == sc->sc_prog) {
			if (vers >= sc->sc_versmin && vers <= sc->sc_versmax)
				return (sc->sc_dispatch);

			if (*vers_max < sc->sc_versmax)
				*vers_max = sc->sc_versmax;
			if (*vers_min > sc->sc_versmin)
				*vers_min = sc->sc_versmin;
		}
	}

	return (NULL);
}

/*
 * Optionally free callout table allocated for this transport by
 * the service provider.
 */
static void
svc_callout_free(SVCMASTERXPRT *xprt)
{
	SVC_CALLOUT_TABLE *sct = xprt->xp_sct;

	if (sct->sct_free) {
		kmem_free(sct->sct_sc, sct->sct_size * sizeof (SVC_CALLOUT));
		kmem_free(sct, sizeof (SVC_CALLOUT_TABLE));
	}
}

/*
 * Send a reply to an RPC request
 *
 * PSARC 2003/523 Contract Private Interface
 * svc_sendreply
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
bool_t
svc_sendreply(const SVCXPRT *clone_xprt, const xdrproc_t xdr_results,
    const caddr_t xdr_location)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = clone_xprt->xp_verf;
	rply.acpted_rply.ar_stat = SUCCESS;
	rply.acpted_rply.ar_results.where = xdr_location;
	rply.acpted_rply.ar_results.proc = xdr_results;

	return (SVC_REPLY((SVCXPRT *)clone_xprt, &rply));
}

/*
 * No procedure error reply
 *
 * PSARC 2003/523 Contract Private Interface
 * svcerr_noproc
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
void
svcerr_noproc(const SVCXPRT *clone_xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = clone_xprt->xp_verf;
	rply.acpted_rply.ar_stat = PROC_UNAVAIL;
	SVC_FREERES((SVCXPRT *)clone_xprt);
	SVC_REPLY((SVCXPRT *)clone_xprt, &rply);
}

/*
 * Can't decode arguments error reply
 *
 * PSARC 2003/523 Contract Private Interface
 * svcerr_decode
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
void
svcerr_decode(const SVCXPRT *clone_xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = clone_xprt->xp_verf;
	rply.acpted_rply.ar_stat = GARBAGE_ARGS;
	SVC_FREERES((SVCXPRT *)clone_xprt);
	SVC_REPLY((SVCXPRT *)clone_xprt, &rply);
}

/*
 * Some system error
 */
void
svcerr_systemerr(const SVCXPRT *clone_xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = clone_xprt->xp_verf;
	rply.acpted_rply.ar_stat = SYSTEM_ERR;
	SVC_FREERES((SVCXPRT *)clone_xprt);
	SVC_REPLY((SVCXPRT *)clone_xprt, &rply);
}

/*
 * Authentication error reply
 */
void
svcerr_auth(const SVCXPRT *clone_xprt, const enum auth_stat why)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_DENIED;
	rply.rjcted_rply.rj_stat = AUTH_ERROR;
	rply.rjcted_rply.rj_why = why;
	SVC_FREERES((SVCXPRT *)clone_xprt);
	SVC_REPLY((SVCXPRT *)clone_xprt, &rply);
}

/*
 * Authentication too weak error reply
 */
void
svcerr_weakauth(const SVCXPRT *clone_xprt)
{
	svcerr_auth((SVCXPRT *)clone_xprt, AUTH_TOOWEAK);
}

/*
 * Authentication error; bad credentials
 */
void
svcerr_badcred(const SVCXPRT *clone_xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_DENIED;
	rply.rjcted_rply.rj_stat = AUTH_ERROR;
	rply.rjcted_rply.rj_why = AUTH_BADCRED;
	SVC_FREERES((SVCXPRT *)clone_xprt);
	SVC_REPLY((SVCXPRT *)clone_xprt, &rply);
}

/*
 * Program unavailable error reply
 *
 * PSARC 2003/523 Contract Private Interface
 * svcerr_noprog
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
void
svcerr_noprog(const SVCXPRT *clone_xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = clone_xprt->xp_verf;
	rply.acpted_rply.ar_stat = PROG_UNAVAIL;
	SVC_FREERES((SVCXPRT *)clone_xprt);
	SVC_REPLY((SVCXPRT *)clone_xprt, &rply);
}

/*
 * Program version mismatch error reply
 *
 * PSARC 2003/523 Contract Private Interface
 * svcerr_progvers
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
void
svcerr_progvers(const SVCXPRT *clone_xprt,
    const rpcvers_t low_vers, const rpcvers_t high_vers)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = clone_xprt->xp_verf;
	rply.acpted_rply.ar_stat = PROG_MISMATCH;
	rply.acpted_rply.ar_vers.low = low_vers;
	rply.acpted_rply.ar_vers.high = high_vers;
	SVC_FREERES((SVCXPRT *)clone_xprt);
	SVC_REPLY((SVCXPRT *)clone_xprt, &rply);
}

/*
 * Get server side input from some transport.
 *
 * Statement of authentication parameters management:
 * This function owns and manages all authentication parameters, specifically
 * the "raw" parameters (msg.rm_call.cb_cred and msg.rm_call.cb_verf) and
 * the "cooked" credentials (rqst->rq_clntcred).
 * However, this function does not know the structure of the cooked
 * credentials, so it make the following assumptions:
 *   a) the structure is contiguous (no pointers), and
 *   b) the cred structure size does not exceed RQCRED_SIZE bytes.
 * In all events, all three parameters are freed upon exit from this routine.
 * The storage is trivially managed on the call stack in user land, but
 * is malloced in kernel land.
 *
 * Note: the xprt's xp_svc_lock is not held while the service's dispatch
 * routine is running.	If we decide to implement svc_unregister(), we'll
 * need to decide whether it's okay for a thread to unregister a service
 * while a request is being processed.	If we decide that this is a
 * problem, we can probably use some sort of reference counting scheme to
 * keep the callout entry from going away until the request has completed.
 */
static void
svc_getreq(
	SVCXPRT *clone_xprt,	/* clone transport handle */
	mblk_t *mp)
{
	struct rpc_msg msg;
	struct svc_req r;
	char  *cred_area;	/* too big to allocate on call stack */

	TRACE_0(TR_FAC_KRPC, TR_SVC_GETREQ_START,
	    "svc_getreq_start:");

	ASSERT(clone_xprt->xp_master != NULL);
	ASSERT(!is_system_labeled() || msg_getcred(mp, NULL) != NULL ||
	    mp->b_datap->db_type != M_DATA);

	/*
	 * Firstly, allocate the authentication parameters' storage
	 */
	mutex_enter(&rqcred_lock);
	if (rqcred_head) {
		cred_area = rqcred_head;

		/* LINTED pointer alignment */
		rqcred_head = *(caddr_t *)rqcred_head;
		mutex_exit(&rqcred_lock);
	} else {
		mutex_exit(&rqcred_lock);
		cred_area = kmem_alloc(2 * MAX_AUTH_BYTES + RQCRED_SIZE,
		    KM_SLEEP);
	}
	msg.rm_call.cb_cred.oa_base = cred_area;
	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
	r.rq_clntcred = &(cred_area[2 * MAX_AUTH_BYTES]);

	/*
	 * underlying transport recv routine may modify mblk data
	 * and make it difficult to extract label afterwards. So
	 * get the label from the raw mblk data now.
	 */
	if (is_system_labeled()) {
		cred_t *cr;

		r.rq_label = kmem_alloc(sizeof (bslabel_t), KM_SLEEP);
		cr = msg_getcred(mp, NULL);
		ASSERT(cr != NULL);

		bcopy(label2bslabel(crgetlabel(cr)), r.rq_label,
		    sizeof (bslabel_t));
	} else {
		r.rq_label = NULL;
	}

	/*
	 * Now receive a message from the transport.
	 */
	if (SVC_RECV(clone_xprt, mp, &msg)) {
		void (*dispatchroutine) (struct svc_req *, SVCXPRT *);
		rpcvers_t vers_min;
		rpcvers_t vers_max;
		bool_t no_dispatch;
		enum auth_stat why;

		/*
		 * Find the registered program and call its
		 * dispatch routine.
		 */
		r.rq_xprt = clone_xprt;
		r.rq_prog = msg.rm_call.cb_prog;
		r.rq_vers = msg.rm_call.cb_vers;
		r.rq_proc = msg.rm_call.cb_proc;
		r.rq_cred = msg.rm_call.cb_cred;

		/*
		 * First authenticate the message.
		 */
		TRACE_0(TR_FAC_KRPC, TR_SVC_GETREQ_AUTH_START,
		    "svc_getreq_auth_start:");
		if ((why = sec_svc_msg(&r, &msg, &no_dispatch)) != AUTH_OK) {
			TRACE_1(TR_FAC_KRPC, TR_SVC_GETREQ_AUTH_END,
			    "svc_getreq_auth_end:(%S)", "failed");
			svcerr_auth(clone_xprt, why);
			/*
			 * Free the arguments.
			 */
			(void) SVC_FREEARGS(clone_xprt, NULL, NULL);
		} else if (no_dispatch) {
			/*
			 * XXX - when bug id 4053736 is done, remove
			 * the SVC_FREEARGS() call.
			 */
			(void) SVC_FREEARGS(clone_xprt, NULL, NULL);
		} else {
			TRACE_1(TR_FAC_KRPC, TR_SVC_GETREQ_AUTH_END,
			    "svc_getreq_auth_end:(%S)", "good");

			dispatchroutine = svc_callout_find(clone_xprt,
			    r.rq_prog, r.rq_vers, &vers_min, &vers_max);

			if (dispatchroutine) {
				(*dispatchroutine) (&r, clone_xprt);
			} else {
				/*
				 * If we got here, the program or version
				 * is not served ...
				 */
				if (vers_max == 0 ||
				    version_keepquiet(clone_xprt))
					svcerr_noprog(clone_xprt);
				else
					svcerr_progvers(clone_xprt, vers_min,
					    vers_max);

				/*
				 * Free the arguments. For successful calls
				 * this is done by the dispatch routine.
				 */
				(void) SVC_FREEARGS(clone_xprt, NULL, NULL);
				/* Fall through to ... */
			}
			/*
			 * Call cleanup procedure for RPCSEC_GSS.
			 * This is a hack since there is currently no
			 * op, such as SVC_CLEANAUTH. rpc_gss_cleanup
			 * should only be called for a non null proc.
			 * Null procs in RPC GSS are overloaded to
			 * provide context setup and control. The main
			 * purpose of rpc_gss_cleanup is to decrement the
			 * reference count associated with the cached
			 * GSS security context. We should never get here
			 * for an RPCSEC_GSS null proc since *no_dispatch
			 * would have been set to true from sec_svc_msg above.
			 */
			if (r.rq_cred.oa_flavor == RPCSEC_GSS)
				rpc_gss_cleanup(clone_xprt);
		}
	}

	if (r.rq_label != NULL)
		kmem_free(r.rq_label, sizeof (bslabel_t));

	/*
	 * Free authentication parameters' storage
	 */
	mutex_enter(&rqcred_lock);
	/* LINTED pointer alignment */
	*(caddr_t *)cred_area = rqcred_head;
	rqcred_head = cred_area;
	mutex_exit(&rqcred_lock);
}

/*
 * Allocate new clone transport handle.
 */
SVCXPRT *
svc_clone_init(void)
{
	SVCXPRT *clone_xprt;

	clone_xprt = kmem_zalloc(sizeof (SVCXPRT), KM_SLEEP);
	clone_xprt->xp_cred = crget();
	return (clone_xprt);
}

/*
 * Free memory allocated by svc_clone_init.
 */
void
svc_clone_free(SVCXPRT *clone_xprt)
{
	/* Fre credentials from crget() */
	if (clone_xprt->xp_cred)
		crfree(clone_xprt->xp_cred);
	kmem_free(clone_xprt, sizeof (SVCXPRT));
}

/*
 * Link a per-thread clone transport handle to a master
 * - increment a thread reference count on the master
 * - copy some of the master's fields to the clone
 * - call a transport specific clone routine.
 */
void
svc_clone_link(SVCMASTERXPRT *xprt, SVCXPRT *clone_xprt, SVCXPRT *clone_xprt2)
{
	cred_t *cred = clone_xprt->xp_cred;

	ASSERT(cred);

	/*
	 * Bump up master's thread count.
	 * Linking a per-thread clone transport handle to a master
	 * associates a service thread with the master.
	 */
	mutex_enter(&xprt->xp_thread_lock);
	xprt->xp_threads++;
	mutex_exit(&xprt->xp_thread_lock);

	/* Clear everything */
	bzero(clone_xprt, sizeof (SVCXPRT));

	/* Set pointer to the master transport stucture */
	clone_xprt->xp_master = xprt;

	/* Structure copy of all the common fields */
	clone_xprt->xp_xpc = xprt->xp_xpc;

	/* Restore per-thread fields (xp_cred) */
	clone_xprt->xp_cred = cred;

	if (clone_xprt2)
		SVC_CLONE_XPRT(clone_xprt2, clone_xprt);
}

/*
 * Unlink a non-detached clone transport handle from a master
 * - decrement a thread reference count on the master
 * - if the transport is closing (xp_wq is NULL) call svc_xprt_cleanup();
 *   if this is the last non-detached/absolute thread on this transport
 *   then it will close/destroy the transport
 * - call transport specific function to destroy the clone handle
 * - clear xp_master to avoid recursion.
 */
void
svc_clone_unlink(SVCXPRT *clone_xprt)
{
	SVCMASTERXPRT *xprt = clone_xprt->xp_master;

	/* This cannot be a detached thread */
	ASSERT(!clone_xprt->xp_detached);
	ASSERT(xprt->xp_threads > 0);

	/* Decrement a reference count on the transport */
	mutex_enter(&xprt->xp_thread_lock);
	xprt->xp_threads--;

	/* svc_xprt_cleanup() unlocks xp_thread_lock or destroys xprt */
	if (xprt->xp_wq)
		mutex_exit(&xprt->xp_thread_lock);
	else
		svc_xprt_cleanup(xprt, FALSE);

	/* Call a transport specific clone `destroy' function */
	SVC_CLONE_DESTROY(clone_xprt);

	/* Clear xp_master */
	clone_xprt->xp_master = NULL;
}

/*
 * Unlink a detached clone transport handle from a master
 * - decrement the thread count on the master
 * - if the transport is closing (xp_wq is NULL) call svc_xprt_cleanup();
 *   if this is the last thread on this transport then it will destroy
 *   the transport.
 * - call a transport specific function to destroy the clone handle
 * - clear xp_master to avoid recursion.
 */
static void
svc_clone_unlinkdetached(SVCXPRT *clone_xprt)
{
	SVCMASTERXPRT *xprt = clone_xprt->xp_master;

	/* This must be a detached thread */
	ASSERT(clone_xprt->xp_detached);
	ASSERT(xprt->xp_detached_threads > 0);
	ASSERT(xprt->xp_threads + xprt->xp_detached_threads > 0);

	/* Grab xprt->xp_thread_lock and decrement link counts */
	mutex_enter(&xprt->xp_thread_lock);
	xprt->xp_detached_threads--;

	/* svc_xprt_cleanup() unlocks xp_thread_lock or destroys xprt */
	if (xprt->xp_wq)
		mutex_exit(&xprt->xp_thread_lock);
	else
		svc_xprt_cleanup(xprt, TRUE);

	/* Call transport specific clone `destroy' function */
	SVC_CLONE_DESTROY(clone_xprt);

	/* Clear xp_master */
	clone_xprt->xp_master = NULL;
}

/*
 * Try to exit a non-detached service thread
 * - check if there are enough threads left
 * - if this thread (ie its clone transport handle) are linked
 *   to a master transport then unlink it
 * - free the clone structure
 * - return to userland for thread exit
 *
 * If this is the last non-detached or the last thread on this
 * transport then the call to svc_clone_unlink() will, respectively,
 * close and/or destroy the transport.
 */
static void
svc_thread_exit(SVCPOOL *pool, SVCXPRT *clone_xprt)
{
	if (clone_xprt->xp_master)
		svc_clone_unlink(clone_xprt);
	svc_clone_free(clone_xprt);

	mutex_enter(&pool->p_thread_lock);
	pool->p_threads--;
	if (pool->p_closing && svc_pool_tryexit(pool))
		/* return -  thread exit will be handled at user level */
		return;
	mutex_exit(&pool->p_thread_lock);

	/* return -  thread exit will be handled at user level */
}

/*
 * Exit a detached service thread that returned to svc_run
 * - decrement the `detached thread' count for the pool
 * - unlink the detached clone transport handle from the master
 * - free the clone structure
 * - return to userland for thread exit
 *
 * If this is the last thread on this transport then the call
 * to svc_clone_unlinkdetached() will destroy the transport.
 */
static void
svc_thread_exitdetached(SVCPOOL *pool, SVCXPRT *clone_xprt)
{
	/* This must be a detached thread */
	ASSERT(clone_xprt->xp_master);
	ASSERT(clone_xprt->xp_detached);
	ASSERT(!MUTEX_HELD(&pool->p_thread_lock));

	svc_clone_unlinkdetached(clone_xprt);
	svc_clone_free(clone_xprt);

	mutex_enter(&pool->p_thread_lock);

	ASSERT(pool->p_reserved_threads >= 0);
	ASSERT(pool->p_detached_threads > 0);

	pool->p_detached_threads--;
	if (pool->p_closing && svc_pool_tryexit(pool))
		/* return -  thread exit will be handled at user level */
		return;
	mutex_exit(&pool->p_thread_lock);

	/* return -  thread exit will be handled at user level */
}

/*
 * PSARC 2003/523 Contract Private Interface
 * svc_wait
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
int
svc_wait(int id)
{
	SVCPOOL *pool;
	int	err = 0;
	struct svc_globals *svc;

	svc = zone_getspecific(svc_zone_key, curproc->p_zone);
	mutex_enter(&svc->svc_plock);
	pool = svc_pool_find(svc, id);
	mutex_exit(&svc->svc_plock);

	if (pool == NULL)
		return (ENOENT);

	mutex_enter(&pool->p_user_lock);

	/* Check if there's already a user thread waiting on this pool */
	if (pool->p_user_waiting) {
		mutex_exit(&pool->p_user_lock);
		return (EBUSY);
	}

	pool->p_user_waiting = TRUE;

	/* Go to sleep, waiting for the signaled flag. */
	while (!pool->p_signal_create_thread && !pool->p_user_exit) {
		if (cv_wait_sig(&pool->p_user_cv, &pool->p_user_lock) == 0) {
			/* Interrupted, return to handle exit or signal */
			pool->p_user_waiting = FALSE;
			pool->p_signal_create_thread = FALSE;
			mutex_exit(&pool->p_user_lock);

			/*
			 * Thread has been interrupted and therefore
			 * the service daemon is leaving as well so
			 * let's go ahead and remove the service
			 * pool at this time.
			 */
			mutex_enter(&svc->svc_plock);
			svc_pool_unregister(svc, pool);
			mutex_exit(&svc->svc_plock);

			return (EINTR);
		}
	}

	pool->p_signal_create_thread = FALSE;
	pool->p_user_waiting = FALSE;

	/*
	 * About to exit the service pool. Set return value
	 * to let the userland code know our intent. Signal
	 * svc_thread_creator() so that it can clean up the
	 * pool structure.
	 */
	if (pool->p_user_exit) {
		err = ECANCELED;
		cv_signal(&pool->p_user_cv);
	}

	mutex_exit(&pool->p_user_lock);

	/* Return to userland with error code, for possible thread creation. */
	return (err);
}

/*
 * `Service threads' creator thread.
 * The creator thread waits for a signal to create new thread.
 */
static void
svc_thread_creator(SVCPOOL *pool)
{
	callb_cpr_t cpr_info;	/* CPR info for the creator thread */

	CALLB_CPR_INIT(&cpr_info, &pool->p_creator_lock, callb_generic_cpr,
	    "svc_thread_creator");

	for (;;) {
		mutex_enter(&pool->p_creator_lock);

		/* Check if someone set the exit flag */
		if (pool->p_creator_exit)
			break;

		/* Clear the `signaled' flag and go asleep */
		pool->p_creator_signaled = FALSE;

		CALLB_CPR_SAFE_BEGIN(&cpr_info);
		cv_wait(&pool->p_creator_cv, &pool->p_creator_lock);
		CALLB_CPR_SAFE_END(&cpr_info, &pool->p_creator_lock);

		/* Check if someone signaled to exit */
		if (pool->p_creator_exit)
			break;

		mutex_exit(&pool->p_creator_lock);

		mutex_enter(&pool->p_thread_lock);

		/*
		 * When the pool is in closing state and all the transports
		 * are gone the creator should not create any new threads.
		 */
		if (pool->p_closing) {
			rw_enter(&pool->p_lrwlock, RW_READER);
			if (pool->p_lcount == 0) {
				rw_exit(&pool->p_lrwlock);
				mutex_exit(&pool->p_thread_lock);
				continue;
			}
			rw_exit(&pool->p_lrwlock);
		}

		/*
		 * Create a new service thread now.
		 */
		ASSERT(pool->p_reserved_threads >= 0);
		ASSERT(pool->p_detached_threads >= 0);

		if (pool->p_threads + pool->p_detached_threads <
		    pool->p_maxthreads) {
			/*
			 * Signal the service pool wait thread
			 * only if it hasn't already been signaled.
			 */
			mutex_enter(&pool->p_user_lock);
			if (pool->p_signal_create_thread == FALSE) {
				pool->p_signal_create_thread = TRUE;
				cv_signal(&pool->p_user_cv);
			}
			mutex_exit(&pool->p_user_lock);

		}

		mutex_exit(&pool->p_thread_lock);
	}

	/*
	 * Pool is closed. Cleanup and exit.
	 */

	/* Signal userland creator thread that it can stop now. */
	mutex_enter(&pool->p_user_lock);
	pool->p_user_exit = TRUE;
	cv_broadcast(&pool->p_user_cv);
	mutex_exit(&pool->p_user_lock);

	/* Wait for svc_wait() to be done with the pool */
	mutex_enter(&pool->p_user_lock);
	while (pool->p_user_waiting) {
		CALLB_CPR_SAFE_BEGIN(&cpr_info);
		cv_wait(&pool->p_user_cv, &pool->p_user_lock);
		CALLB_CPR_SAFE_END(&cpr_info, &pool->p_creator_lock);
	}
	mutex_exit(&pool->p_user_lock);

	CALLB_CPR_EXIT(&cpr_info);
	svc_pool_cleanup(pool);
	zthread_exit();
}

/*
 * If the creator thread  is idle signal it to create
 * a new service thread.
 */
static void
svc_creator_signal(SVCPOOL *pool)
{
	mutex_enter(&pool->p_creator_lock);
	if (pool->p_creator_signaled == FALSE) {
		pool->p_creator_signaled = TRUE;
		cv_signal(&pool->p_creator_cv);
	}
	mutex_exit(&pool->p_creator_lock);
}

/*
 * Notify the creator thread to clean up and exit.
 */
static void
svc_creator_signalexit(SVCPOOL *pool)
{
	mutex_enter(&pool->p_creator_lock);
	pool->p_creator_exit = TRUE;
	cv_signal(&pool->p_creator_cv);
	mutex_exit(&pool->p_creator_lock);
}

/*
 * Polling part of the svc_run().
 * - search for a transport with a pending request
 * - when one is found then latch the request lock and return to svc_run()
 * - if there is no request go asleep and wait for a signal
 * - handle two exceptions:
 *   a) current transport is closing
 *   b) timeout waiting for a new request
 *   in both cases return to svc_run()
 */
static SVCMASTERXPRT *
svc_poll(SVCPOOL *pool, SVCMASTERXPRT *xprt, SVCXPRT *clone_xprt)
{
	/*
	 * Main loop iterates until
	 * a) we find a pending request,
	 * b) detect that the current transport is closing
	 * c) time out waiting for a new request.
	 */
	for (;;) {
		SVCMASTERXPRT *next;
		clock_t timeleft;

		/*
		 * Step 1.
		 * Check if there is a pending request on the current
		 * transport handle so that we can avoid cloning.
		 * If so then decrement the `pending-request' count for
		 * the pool and return to svc_run().
		 *
		 * We need to prevent a potential starvation. When
		 * a selected transport has all pending requests coming in
		 * all the time then the service threads will never switch to
		 * another transport. With a limited number of service
		 * threads some transports may be never serviced.
		 * To prevent such a scenario we pick up at most
		 * pool->p_max_same_xprt requests from the same transport
		 * and then take a hint from the xprt-ready queue or walk
		 * the transport list.
		 */
		if (xprt && xprt->xp_req_head && (!pool->p_qoverflow ||
		    clone_xprt->xp_same_xprt++ < pool->p_max_same_xprt)) {
			mutex_enter(&xprt->xp_req_lock);
			if (xprt->xp_req_head)
				return (xprt);
			mutex_exit(&xprt->xp_req_lock);
		}
		clone_xprt->xp_same_xprt = 0;

		/*
		 * Step 2.
		 * If there is no request on the current transport try to
		 * find another transport with a pending request.
		 */
		mutex_enter(&pool->p_req_lock);
		pool->p_walkers++;
		mutex_exit(&pool->p_req_lock);

		/*
		 * Make sure that transports will not be destroyed just
		 * while we are checking them.
		 */
		rw_enter(&pool->p_lrwlock, RW_READER);

		for (;;) {
			SVCMASTERXPRT *hint;

			/*
			 * Get the next transport from the xprt-ready queue.
			 * This is a hint. There is no guarantee that the
			 * transport still has a pending request since it
			 * could be picked up by another thread in step 1.
			 *
			 * If the transport has a pending request then keep
			 * it locked. Decrement the `pending-requests' for
			 * the pool and `walking-threads' counts, and return
			 * to svc_run().
			 */
			hint = svc_xprt_qget(pool);

			if (hint && hint->xp_req_head) {
				mutex_enter(&hint->xp_req_lock);
				if (hint->xp_req_head) {
					rw_exit(&pool->p_lrwlock);

					mutex_enter(&pool->p_req_lock);
					pool->p_walkers--;
					mutex_exit(&pool->p_req_lock);

					return (hint);
				}
				mutex_exit(&hint->xp_req_lock);
			}

			/*
			 * If there was no hint in the xprt-ready queue then
			 * - if there is less pending requests than polling
			 *   threads go asleep
			 * - otherwise check if there was an overflow in the
			 *   xprt-ready queue; if so, then we need to break
			 *   the `drain' mode
			 */
			if (hint == NULL) {
				if (pool->p_reqs < pool->p_walkers) {
					mutex_enter(&pool->p_req_lock);
					if (pool->p_reqs < pool->p_walkers)
						goto sleep;
					mutex_exit(&pool->p_req_lock);
				}
				if (pool->p_qoverflow) {
					break;
				}
			}
		}

		/*
		 * If there was an overflow in the xprt-ready queue then we
		 * need to switch to the `drain' mode, i.e. walk through the
		 * pool's transport list and search for a transport with a
		 * pending request. If we manage to drain all the pending
		 * requests then we can clear the overflow flag. This will
		 * switch svc_poll() back to taking hints from the xprt-ready
		 * queue (which is generally more efficient).
		 *
		 * If there are no registered transports simply go asleep.
		 */
		if (xprt == NULL && pool->p_lhead == NULL) {
			mutex_enter(&pool->p_req_lock);
			goto sleep;
		}

		/*
		 * `Walk' through the pool's list of master server
		 * transport handles. Continue to loop until there are less
		 * looping threads then pending requests.
		 */
		next = xprt ? xprt->xp_next : pool->p_lhead;

		for (;;) {
			/*
			 * Check if there is a request on this transport.
			 *
			 * Since blocking on a locked mutex is very expensive
			 * check for a request without a lock first. If we miss
			 * a request that is just being delivered but this will
			 * cost at most one full walk through the list.
			 */
			if (next->xp_req_head) {
				/*
				 * Check again, now with a lock.
				 */
				mutex_enter(&next->xp_req_lock);
				if (next->xp_req_head) {
					rw_exit(&pool->p_lrwlock);

					mutex_enter(&pool->p_req_lock);
					pool->p_walkers--;
					mutex_exit(&pool->p_req_lock);

					return (next);
				}
				mutex_exit(&next->xp_req_lock);
			}

			/*
			 * Continue to `walk' through the pool's
			 * transport list until there is less requests
			 * than walkers. Check this condition without
			 * a lock first to avoid contention on a mutex.
			 */
			if (pool->p_reqs < pool->p_walkers) {
				/* Check again, now with the lock. */
				mutex_enter(&pool->p_req_lock);
				if (pool->p_reqs < pool->p_walkers)
					break;	/* goto sleep */
				mutex_exit(&pool->p_req_lock);
			}

			next = next->xp_next;
		}

	sleep:
		/*
		 * No work to do. Stop the `walk' and go asleep.
		 * Decrement the `walking-threads' count for the pool.
		 */
		pool->p_walkers--;
		rw_exit(&pool->p_lrwlock);

		/*
		 * Count us as asleep, mark this thread as safe
		 * for suspend and wait for a request.
		 */
		pool->p_asleep++;
		timeleft = cv_reltimedwait_sig(&pool->p_req_cv,
		    &pool->p_req_lock, pool->p_timeout, TR_CLOCK_TICK);

		/*
		 * If the drowsy flag is on this means that
		 * someone has signaled a wakeup. In such a case
		 * the `asleep-threads' count has already updated
		 * so just clear the flag.
		 *
		 * If the drowsy flag is off then we need to update
		 * the `asleep-threads' count.
		 */
		if (pool->p_drowsy) {
			pool->p_drowsy = FALSE;
			/*
			 * If the thread is here because it timedout,
			 * instead of returning SVC_ETIMEDOUT, it is
			 * time to do some more work.
			 */
			if (timeleft == -1)
				timeleft = 1;
		} else {
			pool->p_asleep--;
		}
		mutex_exit(&pool->p_req_lock);

		/*
		 * If we received a signal while waiting for a
		 * request, inform svc_run(), so that we can return
		 * to user level and exit.
		 */
		if (timeleft == 0)
			return (SVC_EINTR);

		/*
		 * If the current transport is gone then notify
		 * svc_run() to unlink from it.
		 */
		if (xprt && xprt->xp_wq == NULL)
			return (SVC_EXPRTGONE);

		/*
		 * If we have timed out waiting for a request inform
		 * svc_run() that we probably don't need this thread.
		 */
		if (timeleft == -1)
			return (SVC_ETIMEDOUT);
	}
}

/*
 * calculate memory space used by message
 */
static size_t
svc_msgsize(mblk_t *mp)
{
	size_t count = 0;

	for (; mp; mp = mp->b_cont)
		count += MBLKSIZE(mp);

	return (count);
}

/*
 * svc_flowcontrol() attempts to turn the flow control on or off for the
 * transport.
 *
 * On input the xprt->xp_full determines whether the flow control is currently
 * off (FALSE) or on (TRUE).  If it is off we do tests to see whether we should
 * turn it on, and vice versa.
 *
 * There are two conditions considered for the flow control.  Both conditions
 * have the low and the high watermark.  Once the high watermark is reached in
 * EITHER condition the flow control is turned on.  For turning the flow
 * control off BOTH conditions must be below the low watermark.
 *
 * Condition #1 - Number of requests queued:
 *
 * The max number of threads working on the pool is roughly pool->p_maxthreads.
 * Every thread could handle up to pool->p_max_same_xprt requests from one
 * transport before it moves to another transport.  See svc_poll() for details.
 * In case all threads in the pool are working on a transport they will handle
 * no more than enough_reqs (pool->p_maxthreads * pool->p_max_same_xprt)
 * requests in one shot from that transport.  We are turning the flow control
 * on once the high watermark is reached for a transport so that the underlying
 * queue knows the rate of incoming requests is higher than we are able to
 * handle.
 *
 * The high watermark: 2 * enough_reqs
 * The low watermark: enough_reqs
 *
 * Condition #2 - Length of the data payload for the queued messages/requests:
 *
 * We want to prevent a particular pool exhausting the memory, so once the
 * total length of queued requests for the whole pool reaches the high
 * watermark we start to turn on the flow control for significant memory
 * consumers (individual transports).  To keep the implementation simple
 * enough, this condition is not exact, because we count only the data part of
 * the queued requests and we ignore the overhead.  For our purposes this
 * should be enough.  We should also consider that up to pool->p_maxthreads
 * threads for the pool might work on large requests (this is not counted for
 * this condition).  We need to leave some space for rest of the system and for
 * other big memory consumers (like ZFS).  Also, after the flow control is
 * turned on (on cots transports) we can start to accumulate a few megabytes in
 * queues for each transport.
 *
 * Usually, the big memory consumers are NFS WRITE requests, so we do not
 * expect to see this condition met for other than NFS pools.
 *
 * The high watermark: 1/5 of available memory
 * The low watermark: 1/6 of available memory
 *
 * Once the high watermark is reached we turn the flow control on only for
 * transports exceeding a per-transport memory limit.  The per-transport
 * fraction of memory is calculated as:
 *
 * the high watermark / number of transports
 *
 * For transports with less than the per-transport fraction of memory consumed,
 * the flow control is not turned on, so they are not blocked by a few "hungry"
 * transports.  Because of this, the total memory consumption for the
 * particular pool might grow up to 2 * the high watermark.
 *
 * The individual transports are unblocked once their consumption is below:
 *
 * per-transport fraction of memory / 2
 *
 * or once the total memory consumption for the whole pool falls below the low
 * watermark.
 *
 */
static void
svc_flowcontrol(SVCMASTERXPRT *xprt)
{
	SVCPOOL *pool = xprt->xp_pool;
	size_t totalmem = ptob(physmem);
	int enough_reqs = pool->p_maxthreads * pool->p_max_same_xprt;

	ASSERT(MUTEX_HELD(&xprt->xp_req_lock));

	/* Should we turn the flow control on? */
	if (xprt->xp_full == FALSE) {
		/* Is flow control disabled? */
		if (svc_flowcontrol_disable != 0)
			return;

		/* Is there enough requests queued? */
		if (xprt->xp_reqs >= enough_reqs * 2) {
			xprt->xp_full = TRUE;
			return;
		}

		/*
		 * If this pool uses over 20% of memory and this transport is
		 * significant memory consumer then we are full
		 */
		if (pool->p_size >= totalmem / 5 &&
		    xprt->xp_size >= totalmem / 5 / pool->p_lcount)
			xprt->xp_full = TRUE;

		return;
	}

	/* We might want to turn the flow control off */

	/* Do we still have enough requests? */
	if (xprt->xp_reqs > enough_reqs)
		return;

	/*
	 * If this pool still uses over 16% of memory and this transport is
	 * still significant memory consumer then we are still full
	 */
	if (pool->p_size >= totalmem / 6 &&
	    xprt->xp_size >= totalmem / 5 / pool->p_lcount / 2)
		return;

	/* Turn the flow control off and make sure rpcmod is notified */
	xprt->xp_full = FALSE;
	xprt->xp_enable = TRUE;
}

/*
 * Main loop of the kernel RPC server
 * - wait for input (find a transport with a pending request).
 * - dequeue the request
 * - call a registered server routine to process the requests
 *
 * There can many threads running concurrently in this loop
 * on the same or on different transports.
 */
static int
svc_run(SVCPOOL *pool)
{
	SVCMASTERXPRT *xprt = NULL;	/* master transport handle  */
	SVCXPRT *clone_xprt;	/* clone for this thread    */
	proc_t *p = ttoproc(curthread);

	/* Allocate a clone transport handle for this thread */
	clone_xprt = svc_clone_init();

	/*
	 * The loop iterates until the thread becomes
	 * idle too long or the transport is gone.
	 */
	for (;;) {
		SVCMASTERXPRT *next;
		mblk_t *mp;
		bool_t enable;
		size_t size;

		TRACE_0(TR_FAC_KRPC, TR_SVC_RUN, "svc_run");

		/*
		 * If the process is exiting/killed, return
		 * immediately without processing any more
		 * requests.
		 */
		if (p->p_flag & (SEXITING | SKILLED)) {
			svc_thread_exit(pool, clone_xprt);
			return (EINTR);
		}

		/* Find a transport with a pending request */
		next = svc_poll(pool, xprt, clone_xprt);

		/*
		 * If svc_poll() finds a transport with a request
		 * it latches xp_req_lock on it. Therefore we need
		 * to dequeue the request and release the lock as
		 * soon as possible.
		 */
		ASSERT(next != NULL &&
		    (next == SVC_EXPRTGONE ||
		    next == SVC_ETIMEDOUT ||
		    next == SVC_EINTR ||
		    MUTEX_HELD(&next->xp_req_lock)));

		/* Ooops! Current transport is closing. Unlink now */
		if (next == SVC_EXPRTGONE) {
			svc_clone_unlink(clone_xprt);
			xprt = NULL;
			continue;
		}

		/* Ooops! Timeout while waiting for a request. Exit */
		if (next == SVC_ETIMEDOUT) {
			svc_thread_exit(pool, clone_xprt);
			return (0);
		}

		/*
		 * Interrupted by a signal while waiting for a
		 * request. Return to userspace and exit.
		 */
		if (next == SVC_EINTR) {
			svc_thread_exit(pool, clone_xprt);
			return (EINTR);
		}

		/*
		 * De-queue the request and release the request lock
		 * on this transport (latched by svc_poll()).
		 */
		mp = next->xp_req_head;
		next->xp_req_head = mp->b_next;
		mp->b_next = (mblk_t *)0;
		size = svc_msgsize(mp);

		mutex_enter(&pool->p_req_lock);
		pool->p_reqs--;
		if (pool->p_reqs == 0)
			pool->p_qoverflow = FALSE;
		pool->p_size -= size;
		mutex_exit(&pool->p_req_lock);

		next->xp_reqs--;
		next->xp_size -= size;

		if (next->xp_full)
			svc_flowcontrol(next);

		TRACE_2(TR_FAC_KRPC, TR_NFSFP_QUE_REQ_DEQ,
		    "rpc_que_req_deq:pool %p mp %p", pool, mp);
		mutex_exit(&next->xp_req_lock);

		/*
		 * If this is a new request on a current transport then
		 * the clone structure is already properly initialized.
		 * Otherwise, if the request is on a different transport,
		 * unlink from the current master and link to
		 * the one we got a request on.
		 */
		if (next != xprt) {
			if (xprt)
				svc_clone_unlink(clone_xprt);
			svc_clone_link(next, clone_xprt, NULL);
			xprt = next;
		}

		/*
		 * If there are more requests and req_cv hasn't
		 * been signaled yet then wake up one more thread now.
		 *
		 * We avoid signaling req_cv until the most recently
		 * signaled thread wakes up and gets CPU to clear
		 * the `drowsy' flag.
		 */
		if (!(pool->p_drowsy || pool->p_reqs <= pool->p_walkers ||
		    pool->p_asleep == 0)) {
			mutex_enter(&pool->p_req_lock);

			if (pool->p_drowsy || pool->p_reqs <= pool->p_walkers ||
			    pool->p_asleep == 0)
				mutex_exit(&pool->p_req_lock);
			else {
				pool->p_asleep--;
				pool->p_drowsy = TRUE;

				cv_signal(&pool->p_req_cv);
				mutex_exit(&pool->p_req_lock);
			}
		}

		/*
		 * If there are no asleep/signaled threads, we are
		 * still below pool->p_maxthreads limit, and no thread is
		 * currently being created then signal the creator
		 * for one more service thread.
		 *
		 * The asleep and drowsy checks are not protected
		 * by a lock since it hurts performance and a wrong
		 * decision is not essential.
		 */
		if (pool->p_asleep == 0 && !pool->p_drowsy &&
		    pool->p_threads + pool->p_detached_threads <
		    pool->p_maxthreads)
			svc_creator_signal(pool);

		/*
		 * Process the request.
		 */
		svc_getreq(clone_xprt, mp);

		/* If thread had a reservation it should have been canceled */
		ASSERT(!clone_xprt->xp_reserved);

		/*
		 * If the clone is marked detached then exit.
		 * The rpcmod slot has already been released
		 * when we detached this thread.
		 */
		if (clone_xprt->xp_detached) {
			svc_thread_exitdetached(pool, clone_xprt);
			return (0);
		}

		/*
		 * Release our reference on the rpcmod
		 * slot attached to xp_wq->q_ptr.
		 */
		mutex_enter(&xprt->xp_req_lock);
		enable = xprt->xp_enable;
		if (enable)
			xprt->xp_enable = FALSE;
		mutex_exit(&xprt->xp_req_lock);
		(*RELE_PROC(xprt)) (clone_xprt->xp_wq, NULL, enable);
	}
	/* NOTREACHED */
}

/*
 * Flush any pending requests for the queue and
 * free the associated mblks.
 */
void
svc_queueclean(queue_t *q)
{
	SVCMASTERXPRT *xprt = ((void **) q->q_ptr)[0];
	mblk_t *mp;
	SVCPOOL *pool;

	/*
	 * clean up the requests
	 */
	mutex_enter(&xprt->xp_req_lock);
	pool = xprt->xp_pool;
	while ((mp = xprt->xp_req_head) != NULL) {
		/* remove the request from the list */
		xprt->xp_req_head = mp->b_next;
		mp->b_next = (mblk_t *)0;
		(*RELE_PROC(xprt)) (xprt->xp_wq, mp, FALSE);
	}

	mutex_enter(&pool->p_req_lock);
	pool->p_reqs -= xprt->xp_reqs;
	pool->p_size -= xprt->xp_size;
	mutex_exit(&pool->p_req_lock);

	xprt->xp_reqs = 0;
	xprt->xp_size = 0;
	xprt->xp_full = FALSE;
	xprt->xp_enable = FALSE;
	mutex_exit(&xprt->xp_req_lock);
}

/*
 * This routine is called by rpcmod to inform kernel RPC that a
 * queue is closing. It is called after all the requests have been
 * picked up (that is after all the slots on the queue have
 * been released by kernel RPC). It is also guaranteed that no more
 * request will be delivered on this transport.
 *
 * - clear xp_wq to mark the master server transport handle as closing
 * - if there are no more threads on this transport close/destroy it
 * - otherwise, leave the linked threads to close/destroy the transport
 *   later.
 */
void
svc_queueclose(queue_t *q)
{
	SVCMASTERXPRT *xprt = ((void **) q->q_ptr)[0];

	if (xprt == NULL) {
		/*
		 * If there is no master xprt associated with this stream,
		 * then there is nothing to do.  This happens regularly
		 * with connection-oriented listening streams created by
		 * nfsd.
		 */
		return;
	}

	mutex_enter(&xprt->xp_thread_lock);

	ASSERT(xprt->xp_req_head == NULL);
	ASSERT(xprt->xp_wq != NULL);

	xprt->xp_wq = NULL;

	if (xprt->xp_threads == 0) {
		SVCPOOL *pool = xprt->xp_pool;

		/*
		 * svc_xprt_cleanup() destroys the transport
		 * or releases the transport thread lock
		 */
		svc_xprt_cleanup(xprt, FALSE);

		mutex_enter(&pool->p_thread_lock);

		/*
		 * If the pool is in closing state and this was
		 * the last transport in the pool then signal the creator
		 * thread to clean up and exit.
		 */
		if (pool->p_closing && svc_pool_tryexit(pool)) {
			return;
		}
		mutex_exit(&pool->p_thread_lock);
	} else {
		/*
		 * There are still some threads linked to the transport.  They
		 * are very likely sleeping in svc_poll().  We could wake up
		 * them by broadcasting on the p_req_cv condition variable, but
		 * that might give us a performance penalty if there are too
		 * many sleeping threads.
		 *
		 * Instead, we do nothing here.  The linked threads will unlink
		 * themselves and destroy the transport once they are woken up
		 * on timeout, or by new request.  There is no reason to hurry
		 * up now with the thread wake up.
		 */

		/*
		 *  NOTICE: No references to the master transport structure
		 *	    beyond this point!
		 */
		mutex_exit(&xprt->xp_thread_lock);
	}
}

/*
 * Interrupt `request delivery' routine called from rpcmod
 * - put a request at the tail of the transport request queue
 * - insert a hint for svc_poll() into the xprt-ready queue
 * - increment the `pending-requests' count for the pool
 * - handle flow control
 * - wake up a thread sleeping in svc_poll() if necessary
 * - if all the threads are running ask the creator for a new one.
 */
bool_t
svc_queuereq(queue_t *q, mblk_t *mp, bool_t flowcontrol)
{
	SVCMASTERXPRT *xprt = ((void **) q->q_ptr)[0];
	SVCPOOL *pool = xprt->xp_pool;
	size_t size;

	TRACE_0(TR_FAC_KRPC, TR_SVC_QUEUEREQ_START, "svc_queuereq_start");

	ASSERT(!is_system_labeled() || msg_getcred(mp, NULL) != NULL ||
	    mp->b_datap->db_type != M_DATA);

	/*
	 * Step 1.
	 * Grab the transport's request lock and the
	 * pool's request lock so that when we put
	 * the request at the tail of the transport's
	 * request queue, possibly put the request on
	 * the xprt ready queue and increment the
	 * pending request count it looks atomic.
	 */
	mutex_enter(&xprt->xp_req_lock);
	if (flowcontrol && xprt->xp_full) {
		mutex_exit(&xprt->xp_req_lock);

		return (FALSE);
	}
	ASSERT(xprt->xp_full == FALSE);
	mutex_enter(&pool->p_req_lock);
	if (xprt->xp_req_head == NULL)
		xprt->xp_req_head = mp;
	else
		xprt->xp_req_tail->b_next = mp;
	xprt->xp_req_tail = mp;

	/*
	 * Step 2.
	 * Insert a hint into the xprt-ready queue, increment
	 * counters, handle flow control, and wake up
	 * a thread sleeping in svc_poll() if necessary.
	 */

	/* Insert pointer to this transport into the xprt-ready queue */
	svc_xprt_qput(pool, xprt);

	/* Increment counters */
	pool->p_reqs++;
	xprt->xp_reqs++;

	size = svc_msgsize(mp);
	xprt->xp_size += size;
	pool->p_size += size;

	/* Handle flow control */
	if (flowcontrol)
		svc_flowcontrol(xprt);

	TRACE_2(TR_FAC_KRPC, TR_NFSFP_QUE_REQ_ENQ,
	    "rpc_que_req_enq:pool %p mp %p", pool, mp);

	/*
	 * If there are more requests and req_cv hasn't
	 * been signaled yet then wake up one more thread now.
	 *
	 * We avoid signaling req_cv until the most recently
	 * signaled thread wakes up and gets CPU to clear
	 * the `drowsy' flag.
	 */
	if (pool->p_drowsy || pool->p_reqs <= pool->p_walkers ||
	    pool->p_asleep == 0) {
		mutex_exit(&pool->p_req_lock);
	} else {
		pool->p_drowsy = TRUE;
		pool->p_asleep--;

		/*
		 * Signal wakeup and drop the request lock.
		 */
		cv_signal(&pool->p_req_cv);
		mutex_exit(&pool->p_req_lock);
	}
	mutex_exit(&xprt->xp_req_lock);

	/*
	 * Step 3.
	 * If there are no asleep/signaled threads, we are
	 * still below pool->p_maxthreads limit, and no thread is
	 * currently being created then signal the creator
	 * for one more service thread.
	 *
	 * The asleep and drowsy checks are not not protected
	 * by a lock since it hurts performance and a wrong
	 * decision is not essential.
	 */
	if (pool->p_asleep == 0 && !pool->p_drowsy &&
	    pool->p_threads + pool->p_detached_threads < pool->p_maxthreads)
		svc_creator_signal(pool);

	TRACE_1(TR_FAC_KRPC, TR_SVC_QUEUEREQ_END,
	    "svc_queuereq_end:(%S)", "end");

	return (TRUE);
}

/*
 * Reserve a service thread so that it can be detached later.
 * This reservation is required to make sure that when it tries to
 * detach itself the total number of detached threads does not exceed
 * pool->p_maxthreads - pool->p_redline (i.e. that we can have
 * up to pool->p_redline non-detached threads).
 *
 * If the thread does not detach itself later, it should cancel the
 * reservation before returning to svc_run().
 *
 * - check if there is room for more reserved/detached threads
 * - if so, then increment the `reserved threads' count for the pool
 * - mark the thread as reserved (setting the flag in the clone transport
 *   handle for this thread
 * - returns 1 if the reservation succeeded, 0 if it failed.
 */
int
svc_reserve_thread(SVCXPRT *clone_xprt)
{
	SVCPOOL *pool = clone_xprt->xp_master->xp_pool;

	/* Recursive reservations are not allowed */
	ASSERT(!clone_xprt->xp_reserved);
	ASSERT(!clone_xprt->xp_detached);

	/* Check pool counts if there is room for reservation */
	mutex_enter(&pool->p_thread_lock);
	if (pool->p_reserved_threads + pool->p_detached_threads >=
	    pool->p_maxthreads - pool->p_redline) {
		mutex_exit(&pool->p_thread_lock);
		return (0);
	}
	pool->p_reserved_threads++;
	mutex_exit(&pool->p_thread_lock);

	/* Mark the thread (clone handle) as reserved */
	clone_xprt->xp_reserved = TRUE;

	return (1);
}

/*
 * Cancel a reservation for a thread.
 * - decrement the `reserved threads' count for the pool
 * - clear the flag in the clone transport handle for this thread.
 */
void
svc_unreserve_thread(SVCXPRT *clone_xprt)
{
	SVCPOOL *pool = clone_xprt->xp_master->xp_pool;

	/* Thread must have a reservation */
	ASSERT(clone_xprt->xp_reserved);
	ASSERT(!clone_xprt->xp_detached);

	/* Decrement global count */
	mutex_enter(&pool->p_thread_lock);
	pool->p_reserved_threads--;
	mutex_exit(&pool->p_thread_lock);

	/* Clear reservation flag */
	clone_xprt->xp_reserved = FALSE;
}

/*
 * Detach a thread from its transport, so that it can block for an
 * extended time.  Because the transport can be closed after the thread is
 * detached, the thread should have already sent off a reply if it was
 * going to send one.
 *
 * - decrement `non-detached threads' count and increment `detached threads'
 *   counts for the transport
 * - decrement the  `non-detached threads' and `reserved threads'
 *   counts and increment the `detached threads' count for the pool
 * - release the rpcmod slot
 * - mark the clone (thread) as detached.
 *
 * No need to return a pointer to the thread's CPR information, since
 * the thread has a userland identity.
 *
 * NOTICE: a thread must not detach itself without making a prior reservation
 *	   through svc_thread_reserve().
 */
callb_cpr_t *
svc_detach_thread(SVCXPRT *clone_xprt)
{
	SVCMASTERXPRT *xprt = clone_xprt->xp_master;
	SVCPOOL *pool = xprt->xp_pool;
	bool_t enable;

	/* Thread must have a reservation */
	ASSERT(clone_xprt->xp_reserved);
	ASSERT(!clone_xprt->xp_detached);

	/* Bookkeeping for this transport */
	mutex_enter(&xprt->xp_thread_lock);
	xprt->xp_threads--;
	xprt->xp_detached_threads++;
	mutex_exit(&xprt->xp_thread_lock);

	/* Bookkeeping for the pool */
	mutex_enter(&pool->p_thread_lock);
	pool->p_threads--;
	pool->p_reserved_threads--;
	pool->p_detached_threads++;
	mutex_exit(&pool->p_thread_lock);

	/* Release an rpcmod slot for this request */
	mutex_enter(&xprt->xp_req_lock);
	enable = xprt->xp_enable;
	if (enable)
		xprt->xp_enable = FALSE;
	mutex_exit(&xprt->xp_req_lock);
	(*RELE_PROC(xprt)) (clone_xprt->xp_wq, NULL, enable);

	/* Mark the clone (thread) as detached */
	clone_xprt->xp_reserved = FALSE;
	clone_xprt->xp_detached = TRUE;

	return (NULL);
}

/*
 * This routine is responsible for extracting RDMA plugin master XPRT,
 * unregister from the SVCPOOL and initiate plugin specific cleanup.
 * It is passed a list/group of rdma transports as records which are
 * active in a given registered or unregistered kRPC thread pool. Its shuts
 * all active rdma transports in that pool. If the thread active on the trasport
 * happens to be last thread for that pool, it will signal the creater thread
 * to cleanup the pool and destroy the xprt in svc_queueclose()
 */
void
rdma_stop(rdma_xprt_group_t *rdma_xprts)
{
	SVCMASTERXPRT *xprt;
	rdma_xprt_record_t *curr_rec;
	queue_t *q;
	mblk_t *mp;
	int i, rtg_count;
	SVCPOOL *pool;

	if (rdma_xprts->rtg_count == 0)
		return;

	rtg_count = rdma_xprts->rtg_count;

	for (i = 0; i < rtg_count; i++) {
		curr_rec = rdma_xprts->rtg_listhead;
		rdma_xprts->rtg_listhead = curr_rec->rtr_next;
		rdma_xprts->rtg_count--;
		curr_rec->rtr_next = NULL;
		xprt = curr_rec->rtr_xprt_ptr;
		q = xprt->xp_wq;
		svc_rdma_kstop(xprt);

		mutex_enter(&xprt->xp_req_lock);
		pool = xprt->xp_pool;
		while ((mp = xprt->xp_req_head) != NULL) {
			rdma_recv_data_t *rdp = (rdma_recv_data_t *)mp->b_rptr;

			/* remove the request from the list */
			xprt->xp_req_head = mp->b_next;
			mp->b_next = (mblk_t *)0;

			RDMA_BUF_FREE(rdp->conn, &rdp->rpcmsg);
			RDMA_REL_CONN(rdp->conn);
			freemsg(mp);
		}
		mutex_enter(&pool->p_req_lock);
		pool->p_reqs -= xprt->xp_reqs;
		pool->p_size -= xprt->xp_size;
		mutex_exit(&pool->p_req_lock);
		xprt->xp_reqs = 0;
		xprt->xp_size = 0;
		xprt->xp_full = FALSE;
		xprt->xp_enable = FALSE;
		mutex_exit(&xprt->xp_req_lock);
		svc_queueclose(q);
#ifdef	DEBUG
		if (rdma_check)
			cmn_err(CE_NOTE, "rdma_stop: Exited svc_queueclose\n");
#endif
		/*
		 * Free the rdma transport record for the expunged rdma
		 * based master transport handle.
		 */
		kmem_free(curr_rec, sizeof (rdma_xprt_record_t));
		if (!rdma_xprts->rtg_listhead)
			break;
	}
}


/*
 * rpc_msg_dup/rpc_msg_free
 * Currently only used by svc_rpcsec_gss.c but put in this file as it
 * may be useful to others in the future.
 * But future consumers should be careful cuz so far
 *   - only tested/used for call msgs (not reply)
 *   - only tested/used with call verf oa_length==0
 */
struct rpc_msg *
rpc_msg_dup(struct rpc_msg *src)
{
	struct rpc_msg *dst;
	struct opaque_auth oa_src, oa_dst;

	dst = kmem_alloc(sizeof (*dst), KM_SLEEP);

	dst->rm_xid = src->rm_xid;
	dst->rm_direction = src->rm_direction;

	dst->rm_call.cb_rpcvers = src->rm_call.cb_rpcvers;
	dst->rm_call.cb_prog = src->rm_call.cb_prog;
	dst->rm_call.cb_vers = src->rm_call.cb_vers;
	dst->rm_call.cb_proc = src->rm_call.cb_proc;

	/* dup opaque auth call body cred */
	oa_src = src->rm_call.cb_cred;

	oa_dst.oa_flavor = oa_src.oa_flavor;
	oa_dst.oa_base = kmem_alloc(oa_src.oa_length, KM_SLEEP);

	bcopy(oa_src.oa_base, oa_dst.oa_base, oa_src.oa_length);
	oa_dst.oa_length = oa_src.oa_length;

	dst->rm_call.cb_cred = oa_dst;

	/* dup or just alloc opaque auth call body verifier */
	if (src->rm_call.cb_verf.oa_length > 0) {
		oa_src = src->rm_call.cb_verf;

		oa_dst.oa_flavor = oa_src.oa_flavor;
		oa_dst.oa_base = kmem_alloc(oa_src.oa_length, KM_SLEEP);

		bcopy(oa_src.oa_base, oa_dst.oa_base, oa_src.oa_length);
		oa_dst.oa_length = oa_src.oa_length;

		dst->rm_call.cb_verf = oa_dst;
	} else {
		oa_dst.oa_flavor = -1;  /* will be set later */
		oa_dst.oa_base = kmem_alloc(MAX_AUTH_BYTES, KM_SLEEP);

		oa_dst.oa_length = 0;   /* will be set later */

		dst->rm_call.cb_verf = oa_dst;
	}
	return (dst);

error:
	kmem_free(dst->rm_call.cb_cred.oa_base,	dst->rm_call.cb_cred.oa_length);
	kmem_free(dst, sizeof (*dst));
	return (NULL);
}

void
rpc_msg_free(struct rpc_msg **msg, int cb_verf_oa_length)
{
	struct rpc_msg *m = *msg;

	kmem_free(m->rm_call.cb_cred.oa_base, m->rm_call.cb_cred.oa_length);
	m->rm_call.cb_cred.oa_base = NULL;
	m->rm_call.cb_cred.oa_length = 0;

	kmem_free(m->rm_call.cb_verf.oa_base, cb_verf_oa_length);
	m->rm_call.cb_verf.oa_base = NULL;
	m->rm_call.cb_verf.oa_length = 0;

	kmem_free(m, sizeof (*m));
	m = NULL;
}
