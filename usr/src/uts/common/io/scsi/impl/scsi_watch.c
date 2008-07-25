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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * generic scsi device watch
 */

#if DEBUG || lint
#define	SWDEBUG
#endif

/*
 * debug goodies
 */
#ifdef SWDEBUG
static int swdebug = 0;
#define	DEBUGGING	((scsi_options & SCSI_DEBUG_TGT) && sddebug > 1)
#define	SW_DEBUG	if (swdebug == 1) scsi_log
#define	SW_DEBUG2	if (swdebug > 1) scsi_log
#else	/* SWDEBUG */
#define	swdebug		(0)
#define	DEBUGGING	(0)
#define	SW_DEBUG	if (0) scsi_log
#define	SW_DEBUG2	if (0) scsi_log
#endif



/*
 * Includes, Declarations and Local Data
 */

#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/var.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/callb.h>

/*
 * macro for filling in lun value for scsi-1 support
 */
#define	FILL_SCSI1_LUN(devp, pkt) \
	if ((devp->sd_address.a_lun > 0) && \
	    (devp->sd_inq->inq_ansi == 0x1)) { \
		((union scsi_cdb *)(pkt)->pkt_cdbp)->scc_lun = \
		    devp->sd_address.a_lun; \
	}

char *sw_label = "scsi-watch";

static int scsi_watch_io_time = SCSI_WATCH_IO_TIME;

/*
 * all info resides in the scsi watch structure
 *
 * the monitoring is performed by one separate thread which works
 * from a linked list of scsi_watch_request packets
 */
static struct scsi_watch {
	kthread_t		*sw_thread;	/* the watch thread	*/
	kmutex_t		sw_mutex;	/* mutex protecting list */
						/* and this structure */
	kcondvar_t		sw_cv;		/* cv for waking up thread */
	struct scsi_watch_request *sw_head;	/* head of linked list	*/
						/* of request structures */
	uchar_t			sw_state;	/* for suspend-resume */
	uchar_t			sw_flags;	/* to start at head of list */
						/* for watch thread */
	struct scsi_watch_request *swr_current; /* the command waiting to be */
						/* processed by the watch */
						/* thread which is being */
						/* blocked */
} sw;

#if !defined(lint)
_NOTE(MUTEX_PROTECTS_DATA(scsi_watch::sw_mutex, scsi_watch))
#endif

/*
 * Values for sw_state
 */
#define	SW_RUNNING		0
#define	SW_SUSPEND_REQUESTED	1
#define	SW_SUSPENDED		2

/*
 * values for sw_flags
 */
#define	SW_START_HEAD		0x1

struct scsi_watch_request {
	struct scsi_watch_request *swr_next;	/* linked request list	*/
	struct scsi_watch_request *swr_prev;
	clock_t			swr_interval;	/* interval between TURs */
	clock_t			swr_timeout;	/* count down		*/
	uchar_t			swr_busy;	/* TUR in progress	*/
	uchar_t			swr_what;	/* watch or stop	*/
	uchar_t			swr_sense_length; /* required sense length */
	struct scsi_pkt		*swr_pkt;	/* TUR pkt itself	*/
	struct scsi_pkt		*swr_rqpkt;	/* request sense pkt	*/
	struct buf		*swr_rqbp;	/* bp for request sense data */
	int			(*swr_callback)(); /* callback to driver */
	caddr_t			swr_callback_arg;
	kcondvar_t		swr_terminate_cv; /* cv to wait on to cleanup */
						/* request synchronously */
	int			swr_ref;	/*  refer count to the swr */
	uchar_t			suspend_destroy; /* flag for free later */
};

/*
 * values for swr flags
 */
#define	SUSPEND_DESTROY		1

#if !defined(lint)
_NOTE(SCHEME_PROTECTS_DATA("unshared data", scsi_watch_request))
#endif

/*
 * values for sw_what
 */
#define	SWR_WATCH		0	/* device watch */
#define	SWR_STOP		1	/* stop monitoring and destroy swr */
#define	SWR_SUSPEND_REQUESTED	2	/* req. pending suspend */
#define	SWR_SUSPENDED		3	/* req. is suspended */

static void scsi_watch_request_destroy(struct scsi_watch_request *swr);
static void scsi_watch_thread(void);
static void scsi_watch_request_intr(struct scsi_pkt *pkt);

/*
 * setup, called from _init(), the thread is created when we need it
 * and exits when there is nothing to do anymore and everything has been
 * cleaned up (ie. resources deallocated)
 */
void
scsi_watch_init()
{
/* NO OTHER THREADS ARE RUNNING */
	mutex_init(&sw.sw_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sw.sw_cv, NULL, CV_DRIVER, NULL);
	sw.sw_state = SW_RUNNING;
	sw.sw_flags = 0;
	sw.swr_current = NULL;
}

/*
 * cleaning up, called from _fini()
 */
void
scsi_watch_fini()
{
/* NO OTHER THREADS ARE RUNNING */
	/*
	 * hope and pray that the thread has exited
	 */
	ASSERT(sw.sw_thread == 0);
	mutex_destroy(&sw.sw_mutex);
	cv_destroy(&sw.sw_cv);
}

/*
 * allocate an swr (scsi watch request structure) and initialize pkts
 */
#define	ROUTE		&devp->sd_address

opaque_t
scsi_watch_request_submit(
	struct scsi_device	*devp,
	int			interval,
	int			sense_length,
	int			(*callback)(),	/* callback function */
	caddr_t			cb_arg)		/* device number */
{
	register struct scsi_watch_request	*swr = NULL;
	register struct scsi_watch_request	*sswr, *p;
	struct buf				*bp = NULL;
	struct scsi_pkt				*rqpkt = NULL;
	struct scsi_pkt				*pkt = NULL;
	uchar_t					dtype;

	SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
	    "scsi_watch_request_submit: Entering ...\n");

	mutex_enter(&sw.sw_mutex);
	if (sw.sw_thread == 0) {
		register kthread_t	*t;

		t = thread_create((caddr_t)NULL, 0, scsi_watch_thread,
		    NULL, 0, &p0, TS_RUN, v.v_maxsyspri - 2);
		sw.sw_thread = t;
	}

	for (p = sw.sw_head; p != NULL; p = p->swr_next) {
		if ((p->swr_callback_arg == cb_arg) &&
		    (p->swr_callback == callback))
			break;
	}

	/* update time interval for an existing request */
	if (p) {
		if (p->swr_what != SWR_STOP) {
			p->swr_timeout = p->swr_interval
			    = drv_usectohz(interval);
			p->swr_what = SWR_WATCH;
			p->swr_ref++;
			cv_signal(&sw.sw_cv);
			mutex_exit(&sw.sw_mutex);
			return ((opaque_t)p);
		}
	}
	mutex_exit(&sw.sw_mutex);

	/*
	 * allocate space for scsi_watch_request
	 */
	swr = kmem_zalloc(sizeof (struct scsi_watch_request), KM_SLEEP);

	/*
	 * allocate request sense bp and pkt and make cmd
	 * we shouldn't really need it if ARQ is enabled but it is useful
	 * if the ARQ failed.
	 */
	bp = scsi_alloc_consistent_buf(ROUTE, NULL,
	    sense_length, B_READ, SLEEP_FUNC, NULL);

	rqpkt = scsi_init_pkt(ROUTE, (struct scsi_pkt *)NULL,
	    bp, CDB_GROUP0, 1, 0, PKT_CONSISTENT, SLEEP_FUNC, NULL);

	(void) scsi_setup_cdb((union scsi_cdb *)rqpkt->pkt_cdbp,
	    SCMD_REQUEST_SENSE, 0, SENSE_LENGTH, 0);
	FILL_SCSI1_LUN(devp, rqpkt);
	rqpkt->pkt_private = (opaque_t)swr;
	rqpkt->pkt_time = scsi_watch_io_time;
	rqpkt->pkt_comp = scsi_watch_request_intr;
	rqpkt->pkt_flags |= FLAG_HEAD;

	/*
	 * Create TUR pkt or a zero byte WRITE(10) based on the
	 * disk-type for reservation state.
	 * For inq_dtype of SBC (DIRECT, dtype == 0)
	 * OR for RBC devices (dtype is 0xE) AND for
	 * ANSI version of SPC/SPC-2/SPC-3 (inq_ansi == 3-5).
	 */

	dtype = devp->sd_inq->inq_dtype & DTYPE_MASK;
	if (((dtype == 0) || (dtype == 0xE)) &&
	    (devp->sd_inq->inq_ansi > 2)) {
		pkt = scsi_init_pkt(ROUTE, (struct scsi_pkt *)NULL, NULL,
		    CDB_GROUP1, sizeof (struct scsi_arq_status),
		    0, 0, SLEEP_FUNC, NULL);

		(void) scsi_setup_cdb((union scsi_cdb *)pkt->pkt_cdbp,
		    SCMD_WRITE_G1, 0, 0, 0);
	} else {
		pkt = scsi_init_pkt(ROUTE, (struct scsi_pkt *)NULL, NULL,
		    CDB_GROUP0, sizeof (struct scsi_arq_status),
		    0, 0, SLEEP_FUNC, NULL);

		(void) scsi_setup_cdb((union scsi_cdb *)pkt->pkt_cdbp,
		    SCMD_TEST_UNIT_READY, 0, 0, 0);
		FILL_SCSI1_LUN(devp, pkt);
	}

	pkt->pkt_private = (opaque_t)swr;
	pkt->pkt_time = scsi_watch_io_time;
	pkt->pkt_comp = scsi_watch_request_intr;
	if (scsi_ifgetcap(&pkt->pkt_address, "tagged-qing", 1) == 1) {
		pkt->pkt_flags |= FLAG_STAG;
	}

	/*
	 * set the allocated resources in swr
	 */
	swr->swr_rqbp = bp;
	swr->swr_rqpkt = rqpkt;
	swr->swr_pkt = pkt;
	swr->swr_timeout = swr->swr_interval = drv_usectohz(interval);
	swr->swr_callback = callback;
	swr->swr_callback_arg = cb_arg;
	swr->swr_what = SWR_WATCH;
	swr->swr_sense_length = (uchar_t)sense_length;
	swr->swr_ref = 1;
	cv_init(&swr->swr_terminate_cv, NULL, CV_DRIVER, NULL);

	/*
	 * add to the list and wake up the thread
	 */
	mutex_enter(&sw.sw_mutex);
	swr->swr_next = sw.sw_head;
	swr->swr_prev = NULL;
	if (sw.sw_head) {
		sw.sw_head->swr_prev = swr;
	}
	sw.sw_head = swr;

	/*
	 * reset all timeouts, so all requests are in sync again
	 * XXX there is a small window where the watch thread releases
	 * the mutex so that could upset the resyncing
	 */
	sswr = swr;
	while (sswr) {
		sswr->swr_timeout = swr->swr_interval;
		sswr = sswr->swr_next;
	}
	cv_signal(&sw.sw_cv);
	mutex_exit(&sw.sw_mutex);
	return ((opaque_t)swr);
}


/*
 * called by (eg. pwr management) to resume the scsi_watch_thread
 */
void
scsi_watch_resume(opaque_t token)
{
	struct scsi_watch_request *swr = (struct scsi_watch_request *)NULL;
	/*
	 * Change the state to SW_RUNNING and wake up the scsi_watch_thread
	 */
	SW_DEBUG(0, sw_label, SCSI_DEBUG, "scsi_watch_resume:\n");
	mutex_enter(&sw.sw_mutex);

	if (!sw.sw_head)
		goto exit;

	/* search for token */
	for (swr = sw.sw_head; swr; swr = swr->swr_next) {
		if (swr == (struct scsi_watch_request *)token)
			break;
	}

	/* if we can't find this value, then we just do nothing */
	if (swr == (struct scsi_watch_request *)NULL)
		goto exit;

	swr->swr_what = SWR_WATCH;


	/* see if all swr's are awake, then start the thread again */
	for (swr = sw.sw_head; swr; swr = swr->swr_next) {
		if (swr->swr_what != SWR_WATCH)
			goto exit;
	}

	sw.sw_state = SW_RUNNING;
	cv_signal(&sw.sw_cv);

exit:
	mutex_exit(&sw.sw_mutex);
}


/*
 * called by clients (eg. pwr management) to suspend the scsi_watch_thread
 */
void
scsi_watch_suspend(opaque_t token)
{
	struct scsi_watch_request *swr = (struct scsi_watch_request *)NULL;
	clock_t	now;
	clock_t halfsec_delay = drv_usectohz(500000);

	SW_DEBUG(0, sw_label, SCSI_DEBUG, "scsi_watch_suspend:\n");

	mutex_enter(&sw.sw_mutex);

	if (!sw.sw_head)
		goto exit;

	/* search for token */
	for (swr = sw.sw_head; swr; swr = swr->swr_next) {
		if (swr == (struct scsi_watch_request *)token)
			break;
	}

	/* if we can't find this value, then we just do nothing */
	if (swr == (struct scsi_watch_request *)NULL)
		goto exit;


	for (;;) {
		if (swr->swr_busy) {
			/*
			 * XXX: Assumes that this thread can rerun
			 * till all outstanding cmds are complete
			 */
			swr->swr_what = SWR_SUSPEND_REQUESTED;
			now = ddi_get_lbolt();
			(void) cv_timedwait(&sw.sw_cv, &sw.sw_mutex,
			    now + halfsec_delay);
		} else {
			swr->swr_what = SWR_SUSPENDED;
			break;
		}
	}

	/* see if all swr's are suspended, then suspend the thread */
	for (swr = sw.sw_head; swr; swr = swr->swr_next) {
		if (swr->swr_what != SWR_SUSPENDED)
			goto exit;
	}

	sw.sw_state = SW_SUSPENDED;

exit:
	mutex_exit(&sw.sw_mutex);
}

/*
 * destroy swr, called for watch thread
 */
static void
scsi_watch_request_destroy(struct scsi_watch_request *swr)
{
	ASSERT(MUTEX_HELD(&sw.sw_mutex));
	ASSERT(swr->swr_busy == 0);

	SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
	    "scsi_watch_request_destroy: Entering ...\n");
	if (swr->swr_ref != 0)
		return;

	/*
	 * remove swr from linked list and destroy pkts
	 */
	if (swr->swr_prev) {
		swr->swr_prev->swr_next = swr->swr_next;
	}
	if (swr->swr_next) {
		swr->swr_next->swr_prev = swr->swr_prev;
	}
	if (sw.sw_head == swr) {
		sw.sw_head = swr->swr_next;
	}
	if (sw.swr_current == swr) {
		swr->suspend_destroy = SUSPEND_DESTROY;
		sw.swr_current = NULL;
	}

	scsi_destroy_pkt(swr->swr_rqpkt);
	scsi_free_consistent_buf(swr->swr_rqbp);
	scsi_destroy_pkt(swr->swr_pkt);
	cv_signal(&swr->swr_terminate_cv);
}

/*
 * scsi_watch_request_terminate()
 * called by requestor to terminate any pending watch request.
 * if the request is currently "busy", and the caller cannot wait, failure
 * is returned. O/w the request is cleaned up immediately.
 */
int
scsi_watch_request_terminate(opaque_t token, int flags)
{
	struct scsi_watch_request *swr =
	    (struct scsi_watch_request *)token;
	struct scsi_watch_request *sswr;

	int count = 0;
	int free_flag = 0;

	/*
	 * We try to clean up this request if we can. We also inform
	 * the watch thread that we mucked around the list so it has
	 * to start reading from head of list again.
	 */
	SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
	    "scsi_watch_request_terminate: Entering(0x%p) ...\n",
	    (void *)swr);
	mutex_enter(&sw.sw_mutex);

	/*
	 * check if it is still in the list
	 */
	sswr = sw.sw_head;
	while (sswr) {
		if (sswr == swr) {
			swr->swr_ref--;
			count = swr->swr_ref;

			if (swr->swr_busy) {
				if (flags == SCSI_WATCH_TERMINATE_NOWAIT) {
					mutex_exit(&sw.sw_mutex);
					return (SCSI_WATCH_TERMINATE_FAIL);
				}
				if (count != 0 && flags !=
				    SCSI_WATCH_TERMINATE_ALL_WAIT) {
					mutex_exit(&sw.sw_mutex);
					return (SCSI_WATCH_TERMINATE_SUCCESS);
				}
				if (SCSI_WATCH_TERMINATE_ALL_WAIT == flags) {
					swr->swr_ref = 0;
					count = 0;
				}
				swr->swr_what = SWR_STOP;
				cv_wait(&swr->swr_terminate_cv, &sw.sw_mutex);
				free_flag = 1;
				goto done;
			} else {
				if (SCSI_WATCH_TERMINATE_NOWAIT == flags ||
				    SCSI_WATCH_TERMINATE_ALL_WAIT == flags) {
					swr->swr_ref = 0;
					count = 0;
				}
				scsi_watch_request_destroy(swr);
				if (0 == count) {
					sw.sw_flags |= SW_START_HEAD;
					free_flag = 1;
				}
				goto done;
			}
		}
		sswr = sswr->swr_next;
	}
done:
	mutex_exit(&sw.sw_mutex);
	if (!sswr) {
		return (SCSI_WATCH_TERMINATE_FAIL);
	}
	if (1 == free_flag &&
	    sswr->suspend_destroy != SUSPEND_DESTROY) {
		cv_destroy(&swr->swr_terminate_cv);
		kmem_free((caddr_t)swr, sizeof (struct scsi_watch_request));
	}

	return (SCSI_WATCH_TERMINATE_SUCCESS);
}


/*
 * The routines scsi_watch_thread & scsi_watch_request_intr are
 * on different threads.
 * If there is no work to be done by the lower level driver
 * then swr->swr_busy will not be set.
 * In this case we will call CALLB_CPR_SAFE_BEGIN before
 * calling cv_timedwait.
 * In the other case where there is work to be done by
 * the lower level driver then the flag swr->swr_busy will
 * be set.
 * We cannot call CALLB_CPR_SAFE_BEGIN at this point the reason
 * is the intr thread can interfere with our operations. So
 * we do a cv_timedwait here. Now at the completion of the
 * lower level driver's work we will call CALLB_CPR_SAFE_BEGIN
 * in scsi_watch_request_intr.
 * In all the cases we will call CALLB_CPR_SAFE_END only if
 * we already called a CALLB_CPR_SAFE_BEGIN and this is flagged
 * by sw_cpr_flag.
 * Warlock has a problem when we use different locks
 * on the same type of structure in different contexts.
 * We use callb_cpr_t in both scsi_watch and esp_callback threads.
 * we use different mutexe's in different threads. And
 * this is not acceptable to warlock. To avoid this
 * problem we use the same name for the mutex in
 * both scsi_watch & esp_callback. when __lock_lint is not defined
 * esp_callback uses the mutex on the stack and in scsi_watch
 * a static variable. But when __lock_lint is defined
 * we make a mutex which is global in esp_callback and
 * a external mutex for scsi_watch.
 */
static int sw_cmd_count = 0;
static int sw_cpr_flag = 0;
static callb_cpr_t cpr_info;
#ifndef __lock_lint
static kmutex_t cpr_mutex;
#else
extern kmutex_t cpr_mutex;
#endif

#if !defined(lint)
_NOTE(MUTEX_PROTECTS_DATA(cpr_mutex, cpr_info))
_NOTE(MUTEX_PROTECTS_DATA(cpr_mutex, sw_cmd_count))
#endif
/*
 * the scsi watch thread:
 * it either wakes up if there is work to do or if the cv_timeait
 * timed out
 * normally, it wakes up every <delay> seconds and checks the list.
 * the interval is not very accurate if the cv was signalled but that
 * really doesn't matter much
 * it is more important that we fire off all TURs simulataneously so
 * we don't have to wake up frequently
 */
static void
scsi_watch_thread()
{
	struct scsi_watch_request	*swr, *next;
	clock_t				now;
	clock_t				last_delay = 0;
	clock_t				next_delay = 0;
	clock_t				onesec = drv_usectohz(1000000);
	clock_t				exit_delay = 60 * onesec;

	SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
	    "scsi_watch_thread: Entering ...\n");

#if !defined(lint)
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	mutex_init(&cpr_mutex, NULL, MUTEX_DRIVER, NULL);
	CALLB_CPR_INIT(&cpr_info,
	    &cpr_mutex, callb_generic_cpr, "scsi_watch");
	sw_cpr_flag = 0;
#if !defined(lint)
	/*LINTED*/
	_NOTE(COMPETING_THREADS_NOW);
#endif
	/*
	 * grab the mutex and wait for work
	 */
	mutex_enter(&sw.sw_mutex);
	if (sw.sw_head == NULL) {
		cv_wait(&sw.sw_cv, &sw.sw_mutex);
	}

	/*
	 * now loop forever for work; if queue is empty exit
	 */
	for (;;) {
head:
		swr = sw.sw_head;
		while (swr) {

			/*
			 * If state is not running, wait for scsi_watch_resume
			 * to signal restart, but before going into cv_wait
			 * need to let the PM framework know that it is safe
			 * to stop this thread for CPR
			 */
			if (sw.sw_state != SW_RUNNING) {
				SW_DEBUG(0, sw_label, SCSI_DEBUG,
				    "scsi_watch_thread suspended\n");
				mutex_enter(&cpr_mutex);
				if (!sw_cmd_count) {
					CALLB_CPR_SAFE_BEGIN(&cpr_info);
					sw_cpr_flag = 1;
				}
				mutex_exit(&cpr_mutex);
				sw.swr_current = swr;
				cv_wait(&sw.sw_cv, &sw.sw_mutex);


				/*
				 * Need to let the PM framework know that it
				 * is no longer safe to stop the thread for
				 * CPR.
				 */
				mutex_exit(&sw.sw_mutex);
				mutex_enter(&cpr_mutex);
				if (sw_cpr_flag == 1) {
					CALLB_CPR_SAFE_END(
					    &cpr_info, &cpr_mutex);
					sw_cpr_flag = 0;
				}
				mutex_exit(&cpr_mutex);
				mutex_enter(&sw.sw_mutex);
				if (SUSPEND_DESTROY == swr->suspend_destroy) {
					cv_destroy(&swr->swr_terminate_cv);
					kmem_free((caddr_t)swr,
					    sizeof (struct scsi_watch_request));
					goto head;
				} else {
					sw.swr_current = NULL;
				}
			}
			if (next_delay == 0) {
				next_delay = swr->swr_timeout;
			} else {
				next_delay = min(swr->swr_timeout, next_delay);
			}

			swr->swr_timeout -= last_delay;
			next = swr->swr_next;

			SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
			    "scsi_watch_thread: "
			    "swr(0x%p),what=%x,timeout=%lx,"
			    "interval=%lx,delay=%lx\n",
			    (void *)swr, swr->swr_what, swr->swr_timeout,
			    swr->swr_interval, last_delay);

			switch (swr->swr_what) {
			case SWR_SUSPENDED:
			case SWR_SUSPEND_REQUESTED:
				/* if we are suspended, don't do anything */
				break;

			case SWR_STOP:
				if (swr->swr_busy == 0) {
					scsi_watch_request_destroy(swr);
				}
				break;

			default:
				if (swr->swr_timeout <= 0 && !swr->swr_busy) {
					swr->swr_busy = 1;

					/*
					 * submit the cmd and let the completion
					 * function handle the result
					 * release the mutex (good practice)
					 * this should be safe even if the list
					 * is changing
					 */
					mutex_exit(&sw.sw_mutex);
					mutex_enter(&cpr_mutex);
					sw_cmd_count++;
					mutex_exit(&cpr_mutex);
					SW_DEBUG((dev_info_t *)NULL,
					    sw_label, SCSI_DEBUG,
					    "scsi_watch_thread: "
					    "Starting TUR\n");
					if (scsi_transport(swr->swr_pkt) !=
					    TRAN_ACCEPT) {

						/*
						 * try again later
						 */
						swr->swr_busy = 0;
						SW_DEBUG((dev_info_t *)NULL,
						    sw_label, SCSI_DEBUG,
						    "scsi_watch_thread: "
						    "Transport Failed\n");
						mutex_enter(&cpr_mutex);
						sw_cmd_count--;
						mutex_exit(&cpr_mutex);
					}
					mutex_enter(&sw.sw_mutex);
					swr->swr_timeout = swr->swr_interval;
				}
				break;
			}
			swr = next;
			if (sw.sw_flags & SW_START_HEAD) {
				sw.sw_flags &= ~SW_START_HEAD;
				goto head;
			}
		}

		/*
		 * delay using cv_timedwait; we return when
		 * signalled or timed out
		 */
		if (sw.sw_head != NULL) {
			if (next_delay <= 0) {
				next_delay = onesec;
			}
		} else {
			next_delay = exit_delay;
		}
		now = ddi_get_lbolt();

		mutex_enter(&cpr_mutex);
		if (!sw_cmd_count) {
			CALLB_CPR_SAFE_BEGIN(&cpr_info);
			sw_cpr_flag = 1;
		}
		mutex_exit(&cpr_mutex);
		/*
		 * if we return from cv_timedwait because we were
		 * signalled, the delay is not accurate but that doesn't
		 * really matter
		 */
		(void) cv_timedwait(&sw.sw_cv, &sw.sw_mutex, now + next_delay);
		mutex_exit(&sw.sw_mutex);
		mutex_enter(&cpr_mutex);
		if (sw_cpr_flag == 1) {
			CALLB_CPR_SAFE_END(&cpr_info, &cpr_mutex);
			sw_cpr_flag = 0;
		}
		mutex_exit(&cpr_mutex);
		mutex_enter(&sw.sw_mutex);
		last_delay = next_delay;
		next_delay = 0;

		/*
		 * is there still work to do?
		 */
		if (sw.sw_head == NULL) {
			break;
		}
	}

	/*
	 * no more work to do, reset sw_thread and exit
	 */
	sw.sw_thread = 0;
	mutex_exit(&sw.sw_mutex);
#ifndef __lock_lint
	mutex_enter(&cpr_mutex);
	CALLB_CPR_EXIT(&cpr_info);
#endif
	mutex_destroy(&cpr_mutex);
	SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
	    "scsi_watch_thread: Exiting ...\n");
}

/*
 * callback completion function for scsi watch pkt
 */
#define	SCBP(pkt)	((struct scsi_status *)(pkt)->pkt_scbp)
#define	SCBP_C(pkt)	((*(pkt)->pkt_scbp) & STATUS_MASK)

static void
scsi_watch_request_intr(struct scsi_pkt *pkt)
{
	struct scsi_watch_result	result;
	struct scsi_watch_request	*swr =
	    (struct scsi_watch_request *)pkt->pkt_private;
	struct scsi_status		*rqstatusp;
	struct scsi_extended_sense	*rqsensep = NULL;
	int				amt = 0;

	SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
	    "scsi_watch_intr: Entering ...\n");

	/*
	 * first check if it is the TUR or RQS pkt
	 */
	if (pkt == swr->swr_pkt) {
		if (SCBP_C(pkt) != STATUS_GOOD &&
		    SCBP_C(pkt) != STATUS_RESERVATION_CONFLICT) {
			if (SCBP(pkt)->sts_chk &&
			    ((pkt->pkt_state & STATE_ARQ_DONE) == 0)) {

				/*
				 * submit the request sense pkt
				 */
				SW_DEBUG((dev_info_t *)NULL,
				    sw_label, SCSI_DEBUG,
				    "scsi_watch_intr: "
				    "Submitting a Request Sense "
				    "Packet\n");
				if (scsi_transport(swr->swr_rqpkt) !=
				    TRAN_ACCEPT) {

					/*
					 * just give up and try again later
					 */
					SW_DEBUG((dev_info_t *)NULL,
					    sw_label, SCSI_DEBUG,
					    "scsi_watch_intr: "
					    "Request Sense "
					    "Transport Failed\n");
					goto done;
				}

				/*
				 * wait for rqsense to complete
				 */
				return;

			} else	if (SCBP(pkt)->sts_chk) {

				/*
				 * check the autorequest sense data
				 */
				struct scsi_arq_status	*arqstat =
				    (struct scsi_arq_status *)pkt->pkt_scbp;

				rqstatusp = &arqstat->sts_rqpkt_status;
				rqsensep = &arqstat->sts_sensedata;
				amt = swr->swr_sense_length -
				    arqstat->sts_rqpkt_resid;
				SW_DEBUG((dev_info_t *)NULL,
				    sw_label, SCSI_DEBUG,
				    "scsi_watch_intr: "
				    "Auto Request Sense, amt=%x\n", amt);
			}
		}

	} else if (pkt == swr->swr_rqpkt) {

		/*
		 * check the request sense data
		 */
		rqstatusp = (struct scsi_status *)pkt->pkt_scbp;
		rqsensep = (struct scsi_extended_sense *)
		    swr->swr_rqbp->b_un.b_addr;
		amt = swr->swr_sense_length - pkt->pkt_resid;
		SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
		    "scsi_watch_intr: "
		    "Request Sense Completed, amt=%x\n", amt);
	} else {

		/*
		 * should not reach here!!!
		 */
		scsi_log((dev_info_t *)NULL, sw_label, CE_PANIC,
		    "scsi_watch_intr: Bad Packet(0x%p)", (void *)pkt);
	}

	if (rqsensep) {

		/*
		 * check rqsense status and data
		 */
		if (rqstatusp->sts_busy || rqstatusp->sts_chk) {

			/*
			 * try again later
			 */
			SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
			    "scsi_watch_intr: "
			    "Auto Request Sense Failed - "
			    "Busy or Check Condition\n");
			goto done;
		}

		SW_DEBUG((dev_info_t *)NULL, sw_label, SCSI_DEBUG,
		    "scsi_watch_intr: "
		    "es_key=%x, adq=%x, amt=%x\n",
		    rqsensep->es_key, rqsensep->es_add_code, amt);
	}

	/*
	 * callback to target driver to do the real work
	 */
	result.statusp = SCBP(swr->swr_pkt);
	result.sensep = rqsensep;
	result.actual_sense_length = (uchar_t)amt;
	result.pkt = swr->swr_pkt;

	if ((*swr->swr_callback)(swr->swr_callback_arg, &result)) {
		swr->swr_what = SWR_STOP;
	}

done:
	swr->swr_busy = 0;
	mutex_enter(&cpr_mutex);
	sw_cmd_count --;
	if (!sw_cmd_count) {
		CALLB_CPR_SAFE_BEGIN(&cpr_info);
		sw_cpr_flag = 1;
	}
	mutex_exit(&cpr_mutex);
}
