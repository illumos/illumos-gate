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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/session.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/poll.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/uio.h>
#include <sys/cmn_err.h>
#include <sys/priocntl.h>
#include <sys/procset.h>
#include <sys/vmem.h>
#include <sys/bitmap.h>
#include <sys/kmem.h>
#include <sys/siginfo.h>
#include <sys/vtrace.h>
#include <sys/callb.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/vmsystm.h>
#include <vm/page.h>
#include <sys/atomic.h>
#include <sys/suntpi.h>
#include <sys/strlog.h>
#include <sys/promif.h>
#include <sys/project.h>
#include <sys/vm.h>
#include <sys/taskq.h>
#include <sys/sunddi.h>
#include <sys/sunldi_impl.h>
#include <sys/strsun.h>
#include <sys/isa_defs.h>
#include <sys/multidata.h>
#include <sys/pattr.h>
#include <sys/strft.h>
#include <sys/fs/snode.h>
#include <sys/zone.h>
#include <sys/open.h>
#include <sys/sunldi.h>
#include <sys/sad.h>
#include <sys/netstack.h>

#define	O_SAMESTR(q)	(((q)->q_next) && \
	(((q)->q_flag & QREADR) == ((q)->q_next->q_flag & QREADR)))

/*
 * WARNING:
 * The variables and routines in this file are private, belonging
 * to the STREAMS subsystem. These should not be used by modules
 * or drivers. Compatibility will not be guaranteed.
 */

/*
 * Id value used to distinguish between different multiplexor links.
 */
static int32_t lnk_id = 0;

#define	STREAMS_LOPRI MINCLSYSPRI
static pri_t streams_lopri = STREAMS_LOPRI;

#define	STRSTAT(x)	(str_statistics.x.value.ui64++)
typedef struct str_stat {
	kstat_named_t	sqenables;
	kstat_named_t	stenables;
	kstat_named_t	syncqservice;
	kstat_named_t	freebs;
	kstat_named_t	qwr_outer;
	kstat_named_t	rservice;
	kstat_named_t	strwaits;
	kstat_named_t	taskqfails;
	kstat_named_t	bufcalls;
	kstat_named_t	qhelps;
	kstat_named_t	qremoved;
	kstat_named_t	sqremoved;
	kstat_named_t	bcwaits;
	kstat_named_t	sqtoomany;
} str_stat_t;

static str_stat_t str_statistics = {
	{ "sqenables",		KSTAT_DATA_UINT64 },
	{ "stenables",		KSTAT_DATA_UINT64 },
	{ "syncqservice",	KSTAT_DATA_UINT64 },
	{ "freebs",		KSTAT_DATA_UINT64 },
	{ "qwr_outer",		KSTAT_DATA_UINT64 },
	{ "rservice",		KSTAT_DATA_UINT64 },
	{ "strwaits",		KSTAT_DATA_UINT64 },
	{ "taskqfails",		KSTAT_DATA_UINT64 },
	{ "bufcalls",		KSTAT_DATA_UINT64 },
	{ "qhelps",		KSTAT_DATA_UINT64 },
	{ "qremoved",		KSTAT_DATA_UINT64 },
	{ "sqremoved",		KSTAT_DATA_UINT64 },
	{ "bcwaits",		KSTAT_DATA_UINT64 },
	{ "sqtoomany",		KSTAT_DATA_UINT64 },
};

static kstat_t *str_kstat;

/*
 * qrunflag was used previously to control background scheduling of queues. It
 * is not used anymore, but kept here in case some module still wants to access
 * it via qready() and setqsched macros.
 */
char qrunflag;			/*  Unused */

/*
 * Most of the streams scheduling is done via task queues. Task queues may fail
 * for non-sleep dispatches, so there are two backup threads servicing failed
 * requests for queues and syncqs. Both of these threads also service failed
 * dispatches freebs requests. Queues are put in the list specified by `qhead'
 * and `qtail' pointers, syncqs use `sqhead' and `sqtail' pointers and freebs
 * requests are put into `freebs_list' which has no tail pointer. All three
 * lists are protected by a single `service_queue' lock and use
 * `services_to_run' condition variable for signaling background threads. Use of
 * a single lock should not be a problem because it is only used under heavy
 * loads when task queues start to fail and at that time it may be a good idea
 * to throttle scheduling requests.
 *
 * NOTE: queues and syncqs should be scheduled by two separate threads because
 * queue servicing may be blocked waiting for a syncq which may be also
 * scheduled for background execution. This may create a deadlock when only one
 * thread is used for both.
 */

static taskq_t *streams_taskq;		/* Used for most STREAMS scheduling */

static kmutex_t service_queue;		/* protects all of servicing vars */
static kcondvar_t services_to_run;	/* wake up background service thread */
static kcondvar_t syncqs_to_run;	/* wake up background service thread */

/*
 * List of queues scheduled for background processing due to lack of resources
 * in the task queues. Protected by service_queue lock;
 */
static struct queue *qhead;
static struct queue *qtail;

/*
 * Same list for syncqs
 */
static syncq_t *sqhead;
static syncq_t *sqtail;

static mblk_t *freebs_list;	/* list of buffers to free */

/*
 * Backup threads for servicing queues and syncqs
 */
kthread_t *streams_qbkgrnd_thread;
kthread_t *streams_sqbkgrnd_thread;

/*
 * Bufcalls related variables.
 */
struct bclist	strbcalls;	/* list of waiting bufcalls */
kmutex_t	strbcall_lock;	/* protects bufcall list (strbcalls) */
kcondvar_t	strbcall_cv;	/* Signaling when a bufcall is added */
kmutex_t	bcall_monitor;	/* sleep/wakeup style monitor */
kcondvar_t	bcall_cv;	/* wait 'till executing bufcall completes */
kthread_t	*bc_bkgrnd_thread; /* Thread to service bufcall requests */

kmutex_t	strresources;	/* protects global resources */
kmutex_t	muxifier;	/* single-threads multiplexor creation */

static void	*str_stack_init(netstackid_t stackid, netstack_t *ns);
static void	str_stack_shutdown(netstackid_t stackid, void *arg);
static void	str_stack_fini(netstackid_t stackid, void *arg);

/*
 * run_queues is no longer used, but is kept in case some 3rd party
 * module/driver decides to use it.
 */
int run_queues = 0;

/*
 * sq_max_size is the depth of the syncq (in number of messages) before
 * qfill_syncq() starts QFULL'ing destination queues. As its primary
 * consumer - IP is no longer D_MTPERMOD, but there may be other
 * modules/drivers depend on this syncq flow control, we prefer to
 * choose a large number as the default value. For potential
 * performance gain, this value is tunable in /etc/system.
 */
int sq_max_size = 10000;

/*
 * The number of ciputctrl structures per syncq and stream we create when
 * needed.
 */
int n_ciputctrl;
int max_n_ciputctrl = 16;
/*
 * If n_ciputctrl is < min_n_ciputctrl don't even create ciputctrl_cache.
 */
int min_n_ciputctrl = 2;

/*
 * Per-driver/module syncqs
 * ========================
 *
 * For drivers/modules that use PERMOD or outer syncqs we keep a list of
 * perdm structures, new entries being added (and new syncqs allocated) when
 * setq() encounters a module/driver with a streamtab that it hasn't seen
 * before.
 * The reason for this mechanism is that some modules and drivers share a
 * common streamtab and it is necessary for those modules and drivers to also
 * share a common PERMOD syncq.
 *
 * perdm_list --> dm_str == streamtab_1
 *                dm_sq == syncq_1
 *                dm_ref
 *                dm_next --> dm_str == streamtab_2
 *                            dm_sq == syncq_2
 *                            dm_ref
 *                            dm_next --> ... NULL
 *
 * The dm_ref field is incremented for each new driver/module that takes
 * a reference to the perdm structure and hence shares the syncq.
 * References are held in the fmodsw_impl_t structure for each STREAMS module
 * or the dev_impl array (indexed by device major number) for each driver.
 *
 * perdm_list -> [dm_ref == 1] -> [dm_ref == 2] -> [dm_ref == 1] -> NULL
 *		     ^                 ^ ^               ^
 *                   |  ______________/  |               |
 *                   | /                 |               |
 * dev_impl:     ...|x|y|...          module A	      module B
 *
 * When a module/driver is unloaded the reference count is decremented and,
 * when it falls to zero, the perdm structure is removed from the list and
 * the syncq is freed (see rele_dm()).
 */
perdm_t *perdm_list = NULL;
static krwlock_t perdm_rwlock;
cdevsw_impl_t *devimpl;

extern struct qinit strdata;
extern struct qinit stwdata;

static void runservice(queue_t *);
static void streams_bufcall_service(void);
static void streams_qbkgrnd_service(void);
static void streams_sqbkgrnd_service(void);
static syncq_t *new_syncq(void);
static void free_syncq(syncq_t *);
static void outer_insert(syncq_t *, syncq_t *);
static void outer_remove(syncq_t *, syncq_t *);
static void write_now(syncq_t *);
static void clr_qfull(queue_t *);
static void runbufcalls(void);
static void sqenable(syncq_t *);
static void sqfill_events(syncq_t *, queue_t *, mblk_t *, void (*)());
static void wait_q_syncq(queue_t *);
static void backenable_insertedq(queue_t *);

static void queue_service(queue_t *);
static void stream_service(stdata_t *);
static void syncq_service(syncq_t *);
static void qwriter_outer_service(syncq_t *);
static void mblk_free(mblk_t *);
#ifdef DEBUG
static int qprocsareon(queue_t *);
#endif

static void set_nfsrv_ptr(queue_t *, queue_t *, queue_t *, queue_t *);
static void reset_nfsrv_ptr(queue_t *, queue_t *);
void set_qfull(queue_t *);

static void sq_run_events(syncq_t *);
static int propagate_syncq(queue_t *);

static void	blocksq(syncq_t *, ushort_t, int);
static void	unblocksq(syncq_t *, ushort_t, int);
static int	dropsq(syncq_t *, uint16_t);
static void	emptysq(syncq_t *);
static sqlist_t *sqlist_alloc(struct stdata *, int);
static void	sqlist_free(sqlist_t *);
static sqlist_t	*sqlist_build(queue_t *, struct stdata *, boolean_t);
static void	sqlist_insert(sqlist_t *, syncq_t *);
static void	sqlist_insertall(sqlist_t *, queue_t *);

static void	strsetuio(stdata_t *);

struct kmem_cache *stream_head_cache;
struct kmem_cache *queue_cache;
struct kmem_cache *syncq_cache;
struct kmem_cache *qband_cache;
struct kmem_cache *linkinfo_cache;
struct kmem_cache *ciputctrl_cache = NULL;

static linkinfo_t *linkinfo_list;

/* Global esballoc throttling queue */
static esb_queue_t system_esbq;

/* Array of esballoc throttling queues, of length esbq_nelem */
static esb_queue_t *volatile system_esbq_array;
static int esbq_nelem;
static kmutex_t esbq_lock;
static int esbq_log2_cpus_per_q = 0;

/* Scale the system_esbq length by setting number of CPUs per queue. */
uint_t esbq_cpus_per_q = 1;

/*
 * esballoc tunable parameters.
 */
int		esbq_max_qlen = 0x16;	/* throttled queue length */
clock_t		esbq_timeout = 0x8;	/* timeout to process esb queue */

/*
 * Routines to handle esballoc queueing.
 */
static void esballoc_process_queue(esb_queue_t *);
static void esballoc_enqueue_mblk(mblk_t *);
static void esballoc_timer(void *);
static void esballoc_set_timer(esb_queue_t *, clock_t);
static void esballoc_mblk_free(mblk_t *);

/*
 *  Qinit structure and Module_info structures
 *	for passthru read and write queues
 */

static void pass_wput(queue_t *, mblk_t *);
static queue_t *link_addpassthru(stdata_t *);
static void link_rempassthru(queue_t *);

struct  module_info passthru_info = {
	0,
	"passthru",
	0,
	INFPSZ,
	STRHIGH,
	STRLOW
};

struct  qinit passthru_rinit = {
	(int (*)())putnext,
	NULL,
	NULL,
	NULL,
	NULL,
	&passthru_info,
	NULL
};

struct  qinit passthru_winit = {
	(int (*)()) pass_wput,
	NULL,
	NULL,
	NULL,
	NULL,
	&passthru_info,
	NULL
};

/*
 * Verify correctness of list head/tail pointers.
 */
#define	LISTCHECK(head, tail, link) {				\
	EQUIV(head, tail);					\
	IMPLY(tail != NULL, tail->link == NULL);		\
}

/*
 * Enqueue a list element `el' in the end of a list denoted by `head' and `tail'
 * using a `link' field.
 */
#define	ENQUEUE(el, head, tail, link) {				\
	ASSERT(el->link == NULL);				\
	LISTCHECK(head, tail, link);				\
	if (head == NULL)					\
		head = el;					\
	else							\
		tail->link = el;				\
	tail = el;						\
}

/*
 * Dequeue the first element of the list denoted by `head' and `tail' pointers
 * using a `link' field and put result into `el'.
 */
#define	DQ(el, head, tail, link) {				\
	LISTCHECK(head, tail, link);				\
	el = head;						\
	if (head != NULL) {					\
		head = head->link;				\
		if (head == NULL)				\
			tail = NULL;				\
		el->link = NULL;				\
	}							\
}

/*
 * Remove `el' from the list using `chase' and `curr' pointers and return result
 * in `succeed'.
 */
#define	RMQ(el, head, tail, link, chase, curr, succeed) {	\
	LISTCHECK(head, tail, link);				\
	chase = NULL;						\
	succeed = 0;						\
	for (curr = head; (curr != el) && (curr != NULL); curr = curr->link) \
		chase = curr;					\
	if (curr != NULL) {					\
		succeed = 1;					\
		ASSERT(curr == el);				\
		if (chase != NULL)				\
			chase->link = curr->link;		\
		else						\
			head = curr->link;			\
		curr->link = NULL;				\
		if (curr == tail)				\
			tail = chase;				\
	}							\
	LISTCHECK(head, tail, link);				\
}

/* Handling of delayed messages on the inner syncq. */

/*
 * DEBUG versions should use function versions (to simplify tracing) and
 * non-DEBUG kernels should use macro versions.
 */

/*
 * Put a queue on the syncq list of queues.
 * Assumes SQLOCK held.
 */
#define	SQPUT_Q(sq, qp)							\
{									\
	ASSERT(MUTEX_HELD(SQLOCK(sq)));					\
	if (!(qp->q_sqflags & Q_SQQUEUED)) {				\
		/* The queue should not be linked anywhere */		\
		ASSERT((qp->q_sqprev == NULL) && (qp->q_sqnext == NULL)); \
		/* Head and tail may only be NULL simultaneously */	\
		EQUIV(sq->sq_head, sq->sq_tail);			\
		/* Queue may be only enqueued on its syncq */		\
		ASSERT(sq == qp->q_syncq);				\
		/* Check the correctness of SQ_MESSAGES flag */		\
		EQUIV(sq->sq_head, (sq->sq_flags & SQ_MESSAGES));	\
		/* Sanity check first/last elements of the list */	\
		IMPLY(sq->sq_head != NULL, sq->sq_head->q_sqprev == NULL);\
		IMPLY(sq->sq_tail != NULL, sq->sq_tail->q_sqnext == NULL);\
		/*							\
		 * Sanity check of priority field: empty queue should	\
		 * have zero priority					\
		 * and nqueues equal to zero.				\
		 */							\
		IMPLY(sq->sq_head == NULL, sq->sq_pri == 0);		\
		/* Sanity check of sq_nqueues field */			\
		EQUIV(sq->sq_head, sq->sq_nqueues);			\
		if (sq->sq_head == NULL) {				\
			sq->sq_head = sq->sq_tail = qp;			\
			sq->sq_flags |= SQ_MESSAGES;			\
		} else if (qp->q_spri == 0) {				\
			qp->q_sqprev = sq->sq_tail;			\
			sq->sq_tail->q_sqnext = qp;			\
			sq->sq_tail = qp;				\
		} else {						\
			/*						\
			 * Put this queue in priority order: higher	\
			 * priority gets closer to the head.		\
			 */						\
			queue_t **qpp = &sq->sq_tail;			\
			queue_t *qnext = NULL;				\
									\
			while (*qpp != NULL && qp->q_spri > (*qpp)->q_spri) { \
				qnext = *qpp;				\
				qpp = &(*qpp)->q_sqprev;		\
			}						\
			qp->q_sqnext = qnext;				\
			qp->q_sqprev = *qpp;				\
			if (*qpp != NULL) {				\
				(*qpp)->q_sqnext = qp;			\
			} else {					\
				sq->sq_head = qp;			\
				sq->sq_pri = sq->sq_head->q_spri;	\
			}						\
			*qpp = qp;					\
		}							\
		qp->q_sqflags |= Q_SQQUEUED;				\
		qp->q_sqtstamp = ddi_get_lbolt();			\
		sq->sq_nqueues++;					\
	}								\
}

/*
 * Remove a queue from the syncq list
 * Assumes SQLOCK held.
 */
#define	SQRM_Q(sq, qp)							\
	{								\
		ASSERT(MUTEX_HELD(SQLOCK(sq)));				\
		ASSERT(qp->q_sqflags & Q_SQQUEUED);			\
		ASSERT(sq->sq_head != NULL && sq->sq_tail != NULL);	\
		ASSERT((sq->sq_flags & SQ_MESSAGES) != 0);		\
		/* Check that the queue is actually in the list */	\
		ASSERT(qp->q_sqnext != NULL || sq->sq_tail == qp);	\
		ASSERT(qp->q_sqprev != NULL || sq->sq_head == qp);	\
		ASSERT(sq->sq_nqueues != 0);				\
		if (qp->q_sqprev == NULL) {				\
			/* First queue on list, make head q_sqnext */	\
			sq->sq_head = qp->q_sqnext;			\
		} else {						\
			/* Make prev->next == next */			\
			qp->q_sqprev->q_sqnext = qp->q_sqnext;		\
		}							\
		if (qp->q_sqnext == NULL) {				\
			/* Last queue on list, make tail sqprev */	\
			sq->sq_tail = qp->q_sqprev;			\
		} else {						\
			/* Make next->prev == prev */			\
			qp->q_sqnext->q_sqprev = qp->q_sqprev;		\
		}							\
		/* clear out references on this queue */		\
		qp->q_sqprev = qp->q_sqnext = NULL;			\
		qp->q_sqflags &= ~Q_SQQUEUED;				\
		/* If there is nothing queued, clear SQ_MESSAGES */	\
		if (sq->sq_head != NULL) {				\
			sq->sq_pri = sq->sq_head->q_spri;		\
		} else	{						\
			sq->sq_flags &= ~SQ_MESSAGES;			\
			sq->sq_pri = 0;					\
		}							\
		sq->sq_nqueues--;					\
		ASSERT(sq->sq_head != NULL || sq->sq_evhead != NULL ||	\
		    (sq->sq_flags & SQ_QUEUED) == 0);			\
	}

/* Hide the definition from the header file. */
#ifdef SQPUT_MP
#undef SQPUT_MP
#endif

/*
 * Put a message on the queue syncq.
 * Assumes QLOCK held.
 */
#define	SQPUT_MP(qp, mp)						\
	{								\
		ASSERT(MUTEX_HELD(QLOCK(qp)));				\
		ASSERT(qp->q_sqhead == NULL ||				\
		    (qp->q_sqtail != NULL &&				\
		    qp->q_sqtail->b_next == NULL));			\
		qp->q_syncqmsgs++;					\
		ASSERT(qp->q_syncqmsgs != 0);	/* Wraparound */	\
		if (qp->q_sqhead == NULL) {				\
			qp->q_sqhead = qp->q_sqtail = mp;		\
		} else {						\
			qp->q_sqtail->b_next = mp;			\
			qp->q_sqtail = mp;				\
		}							\
		ASSERT(qp->q_syncqmsgs > 0);				\
		set_qfull(qp);						\
	}

#define	SQ_PUTCOUNT_SETFAST_LOCKED(sq) {				\
		ASSERT(MUTEX_HELD(SQLOCK(sq)));				\
		if ((sq)->sq_ciputctrl != NULL) {			\
			int i;						\
			int nlocks = (sq)->sq_nciputctrl;		\
			ciputctrl_t *cip = (sq)->sq_ciputctrl;		\
			ASSERT((sq)->sq_type & SQ_CIPUT);		\
			for (i = 0; i <= nlocks; i++) {			\
				ASSERT(MUTEX_HELD(&cip[i].ciputctrl_lock)); \
				cip[i].ciputctrl_count |= SQ_FASTPUT;	\
			}						\
		}							\
	}


#define	SQ_PUTCOUNT_CLRFAST_LOCKED(sq) {				\
		ASSERT(MUTEX_HELD(SQLOCK(sq)));				\
		if ((sq)->sq_ciputctrl != NULL) {			\
			int i;						\
			int nlocks = (sq)->sq_nciputctrl;		\
			ciputctrl_t *cip = (sq)->sq_ciputctrl;		\
			ASSERT((sq)->sq_type & SQ_CIPUT);		\
			for (i = 0; i <= nlocks; i++) {			\
				ASSERT(MUTEX_HELD(&cip[i].ciputctrl_lock)); \
				cip[i].ciputctrl_count &= ~SQ_FASTPUT;	\
			}						\
		}							\
	}

/*
 * Run service procedures for all queues in the stream head.
 */
#define	STR_SERVICE(stp, q) {						\
	ASSERT(MUTEX_HELD(&stp->sd_qlock));				\
	while (stp->sd_qhead != NULL) {					\
		DQ(q, stp->sd_qhead, stp->sd_qtail, q_link);		\
		ASSERT(stp->sd_nqueues > 0);				\
		stp->sd_nqueues--;					\
		ASSERT(!(q->q_flag & QINSERVICE));			\
		mutex_exit(&stp->sd_qlock);				\
		queue_service(q);					\
		mutex_enter(&stp->sd_qlock);				\
	}								\
	ASSERT(stp->sd_nqueues == 0);					\
	ASSERT((stp->sd_qhead == NULL) && (stp->sd_qtail == NULL));	\
}

/*
 * Constructor/destructor routines for the stream head cache
 */
/* ARGSUSED */
static int
stream_head_constructor(void *buf, void *cdrarg, int kmflags)
{
	stdata_t *stp = buf;

	mutex_init(&stp->sd_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&stp->sd_reflock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&stp->sd_qlock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&stp->sd_monitor, NULL, CV_DEFAULT, NULL);
	cv_init(&stp->sd_iocmonitor, NULL, CV_DEFAULT, NULL);
	cv_init(&stp->sd_refmonitor, NULL, CV_DEFAULT, NULL);
	cv_init(&stp->sd_qcv, NULL, CV_DEFAULT, NULL);
	cv_init(&stp->sd_zcopy_wait, NULL, CV_DEFAULT, NULL);
	stp->sd_wrq = NULL;

	return (0);
}

/* ARGSUSED */
static void
stream_head_destructor(void *buf, void *cdrarg)
{
	stdata_t *stp = buf;

	mutex_destroy(&stp->sd_lock);
	mutex_destroy(&stp->sd_reflock);
	mutex_destroy(&stp->sd_qlock);
	cv_destroy(&stp->sd_monitor);
	cv_destroy(&stp->sd_iocmonitor);
	cv_destroy(&stp->sd_refmonitor);
	cv_destroy(&stp->sd_qcv);
	cv_destroy(&stp->sd_zcopy_wait);
}

/*
 * Constructor/destructor routines for the queue cache
 */
/* ARGSUSED */
static int
queue_constructor(void *buf, void *cdrarg, int kmflags)
{
	queinfo_t *qip = buf;
	queue_t *qp = &qip->qu_rqueue;
	queue_t *wqp = &qip->qu_wqueue;
	syncq_t	*sq = &qip->qu_syncq;

	qp->q_first = NULL;
	qp->q_link = NULL;
	qp->q_count = 0;
	qp->q_mblkcnt = 0;
	qp->q_sqhead = NULL;
	qp->q_sqtail = NULL;
	qp->q_sqnext = NULL;
	qp->q_sqprev = NULL;
	qp->q_sqflags = 0;
	qp->q_rwcnt = 0;
	qp->q_spri = 0;

	mutex_init(QLOCK(qp), NULL, MUTEX_DEFAULT, NULL);
	cv_init(&qp->q_wait, NULL, CV_DEFAULT, NULL);

	wqp->q_first = NULL;
	wqp->q_link = NULL;
	wqp->q_count = 0;
	wqp->q_mblkcnt = 0;
	wqp->q_sqhead = NULL;
	wqp->q_sqtail = NULL;
	wqp->q_sqnext = NULL;
	wqp->q_sqprev = NULL;
	wqp->q_sqflags = 0;
	wqp->q_rwcnt = 0;
	wqp->q_spri = 0;

	mutex_init(QLOCK(wqp), NULL, MUTEX_DEFAULT, NULL);
	cv_init(&wqp->q_wait, NULL, CV_DEFAULT, NULL);

	sq->sq_head = NULL;
	sq->sq_tail = NULL;
	sq->sq_evhead = NULL;
	sq->sq_evtail = NULL;
	sq->sq_callbpend = NULL;
	sq->sq_outer = NULL;
	sq->sq_onext = NULL;
	sq->sq_oprev = NULL;
	sq->sq_next = NULL;
	sq->sq_svcflags = 0;
	sq->sq_servcount = 0;
	sq->sq_needexcl = 0;
	sq->sq_nqueues = 0;
	sq->sq_pri = 0;

	mutex_init(&sq->sq_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sq->sq_wait, NULL, CV_DEFAULT, NULL);
	cv_init(&sq->sq_exitwait, NULL, CV_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static void
queue_destructor(void *buf, void *cdrarg)
{
	queinfo_t *qip = buf;
	queue_t *qp = &qip->qu_rqueue;
	queue_t *wqp = &qip->qu_wqueue;
	syncq_t	*sq = &qip->qu_syncq;

	ASSERT(qp->q_sqhead == NULL);
	ASSERT(wqp->q_sqhead == NULL);
	ASSERT(qp->q_sqnext == NULL);
	ASSERT(wqp->q_sqnext == NULL);
	ASSERT(qp->q_rwcnt == 0);
	ASSERT(wqp->q_rwcnt == 0);

	mutex_destroy(&qp->q_lock);
	cv_destroy(&qp->q_wait);

	mutex_destroy(&wqp->q_lock);
	cv_destroy(&wqp->q_wait);

	mutex_destroy(&sq->sq_lock);
	cv_destroy(&sq->sq_wait);
	cv_destroy(&sq->sq_exitwait);
}

/*
 * Constructor/destructor routines for the syncq cache
 */
/* ARGSUSED */
static int
syncq_constructor(void *buf, void *cdrarg, int kmflags)
{
	syncq_t	*sq = buf;

	bzero(buf, sizeof (syncq_t));

	mutex_init(&sq->sq_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sq->sq_wait, NULL, CV_DEFAULT, NULL);
	cv_init(&sq->sq_exitwait, NULL, CV_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static void
syncq_destructor(void *buf, void *cdrarg)
{
	syncq_t	*sq = buf;

	ASSERT(sq->sq_head == NULL);
	ASSERT(sq->sq_tail == NULL);
	ASSERT(sq->sq_evhead == NULL);
	ASSERT(sq->sq_evtail == NULL);
	ASSERT(sq->sq_callbpend == NULL);
	ASSERT(sq->sq_callbflags == 0);
	ASSERT(sq->sq_outer == NULL);
	ASSERT(sq->sq_onext == NULL);
	ASSERT(sq->sq_oprev == NULL);
	ASSERT(sq->sq_next == NULL);
	ASSERT(sq->sq_needexcl == 0);
	ASSERT(sq->sq_svcflags == 0);
	ASSERT(sq->sq_servcount == 0);
	ASSERT(sq->sq_nqueues == 0);
	ASSERT(sq->sq_pri == 0);
	ASSERT(sq->sq_count == 0);
	ASSERT(sq->sq_rmqcount == 0);
	ASSERT(sq->sq_cancelid == 0);
	ASSERT(sq->sq_ciputctrl == NULL);
	ASSERT(sq->sq_nciputctrl == 0);
	ASSERT(sq->sq_type == 0);
	ASSERT(sq->sq_flags == 0);

	mutex_destroy(&sq->sq_lock);
	cv_destroy(&sq->sq_wait);
	cv_destroy(&sq->sq_exitwait);
}

/* ARGSUSED */
static int
ciputctrl_constructor(void *buf, void *cdrarg, int kmflags)
{
	ciputctrl_t *cip = buf;
	int i;

	for (i = 0; i < n_ciputctrl; i++) {
		cip[i].ciputctrl_count = SQ_FASTPUT;
		mutex_init(&cip[i].ciputctrl_lock, NULL, MUTEX_DEFAULT, NULL);
	}

	return (0);
}

/* ARGSUSED */
static void
ciputctrl_destructor(void *buf, void *cdrarg)
{
	ciputctrl_t *cip = buf;
	int i;

	for (i = 0; i < n_ciputctrl; i++) {
		ASSERT(cip[i].ciputctrl_count & SQ_FASTPUT);
		mutex_destroy(&cip[i].ciputctrl_lock);
	}
}

/*
 * Init routine run from main at boot time.
 */
void
strinit(void)
{
	int ncpus = ((boot_max_ncpus == -1) ? max_ncpus : boot_max_ncpus);

	stream_head_cache = kmem_cache_create("stream_head_cache",
	    sizeof (stdata_t), 0,
	    stream_head_constructor, stream_head_destructor, NULL,
	    NULL, NULL, 0);

	queue_cache = kmem_cache_create("queue_cache", sizeof (queinfo_t), 0,
	    queue_constructor, queue_destructor, NULL, NULL, NULL, 0);

	syncq_cache = kmem_cache_create("syncq_cache", sizeof (syncq_t), 0,
	    syncq_constructor, syncq_destructor, NULL, NULL, NULL, 0);

	qband_cache = kmem_cache_create("qband_cache",
	    sizeof (qband_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	linkinfo_cache = kmem_cache_create("linkinfo_cache",
	    sizeof (linkinfo_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	n_ciputctrl = ncpus;
	n_ciputctrl = 1 << highbit(n_ciputctrl - 1);
	ASSERT(n_ciputctrl >= 1);
	n_ciputctrl = MIN(n_ciputctrl, max_n_ciputctrl);
	if (n_ciputctrl >= min_n_ciputctrl) {
		ciputctrl_cache = kmem_cache_create("ciputctrl_cache",
		    sizeof (ciputctrl_t) * n_ciputctrl,
		    sizeof (ciputctrl_t), ciputctrl_constructor,
		    ciputctrl_destructor, NULL, NULL, NULL, 0);
	}

	streams_taskq = system_taskq;

	if (streams_taskq == NULL)
		panic("strinit: no memory for streams taskq!");

	bc_bkgrnd_thread = thread_create(NULL, 0,
	    streams_bufcall_service, NULL, 0, &p0, TS_RUN, streams_lopri);

	streams_qbkgrnd_thread = thread_create(NULL, 0,
	    streams_qbkgrnd_service, NULL, 0, &p0, TS_RUN, streams_lopri);

	streams_sqbkgrnd_thread = thread_create(NULL, 0,
	    streams_sqbkgrnd_service, NULL, 0, &p0, TS_RUN, streams_lopri);

	/*
	 * Create STREAMS kstats.
	 */
	str_kstat = kstat_create("streams", 0, "strstat",
	    "net", KSTAT_TYPE_NAMED,
	    sizeof (str_statistics) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (str_kstat != NULL) {
		str_kstat->ks_data = &str_statistics;
		kstat_install(str_kstat);
	}

	/*
	 * TPI support routine initialisation.
	 */
	tpi_init();

	/*
	 * Handle to have autopush and persistent link information per
	 * zone.
	 * Note: uses shutdown hook instead of destroy hook so that the
	 * persistent links can be torn down before the destroy hooks
	 * in the TCP/IP stack are called.
	 */
	netstack_register(NS_STR, str_stack_init, str_stack_shutdown,
	    str_stack_fini);
}

void
str_sendsig(vnode_t *vp, int event, uchar_t band, int error)
{
	struct stdata *stp;

	ASSERT(vp->v_stream);
	stp = vp->v_stream;
	/* Have to hold sd_lock to prevent siglist from changing */
	mutex_enter(&stp->sd_lock);
	if (stp->sd_sigflags & event)
		strsendsig(stp->sd_siglist, event, band, error);
	mutex_exit(&stp->sd_lock);
}

/*
 * Send the "sevent" set of signals to a process.
 * This might send more than one signal if the process is registered
 * for multiple events. The caller should pass in an sevent that only
 * includes the events for which the process has registered.
 */
static void
dosendsig(proc_t *proc, int events, int sevent, k_siginfo_t *info,
	uchar_t band, int error)
{
	ASSERT(MUTEX_HELD(&proc->p_lock));

	info->si_band = 0;
	info->si_errno = 0;

	if (sevent & S_ERROR) {
		sevent &= ~S_ERROR;
		info->si_code = POLL_ERR;
		info->si_errno = error;
		TRACE_2(TR_FAC_STREAMS_FR, TR_STRSENDSIG,
		    "strsendsig:proc %p info %p", proc, info);
		sigaddq(proc, NULL, info, KM_NOSLEEP);
		info->si_errno = 0;
	}
	if (sevent & S_HANGUP) {
		sevent &= ~S_HANGUP;
		info->si_code = POLL_HUP;
		TRACE_2(TR_FAC_STREAMS_FR, TR_STRSENDSIG,
		    "strsendsig:proc %p info %p", proc, info);
		sigaddq(proc, NULL, info, KM_NOSLEEP);
	}
	if (sevent & S_HIPRI) {
		sevent &= ~S_HIPRI;
		info->si_code = POLL_PRI;
		TRACE_2(TR_FAC_STREAMS_FR, TR_STRSENDSIG,
		    "strsendsig:proc %p info %p", proc, info);
		sigaddq(proc, NULL, info, KM_NOSLEEP);
	}
	if (sevent & S_RDBAND) {
		sevent &= ~S_RDBAND;
		if (events & S_BANDURG)
			sigtoproc(proc, NULL, SIGURG);
		else
			sigtoproc(proc, NULL, SIGPOLL);
	}
	if (sevent & S_WRBAND) {
		sevent &= ~S_WRBAND;
		sigtoproc(proc, NULL, SIGPOLL);
	}
	if (sevent & S_INPUT) {
		sevent &= ~S_INPUT;
		info->si_code = POLL_IN;
		info->si_band = band;
		TRACE_2(TR_FAC_STREAMS_FR, TR_STRSENDSIG,
		    "strsendsig:proc %p info %p", proc, info);
		sigaddq(proc, NULL, info, KM_NOSLEEP);
		info->si_band = 0;
	}
	if (sevent & S_OUTPUT) {
		sevent &= ~S_OUTPUT;
		info->si_code = POLL_OUT;
		info->si_band = band;
		TRACE_2(TR_FAC_STREAMS_FR, TR_STRSENDSIG,
		    "strsendsig:proc %p info %p", proc, info);
		sigaddq(proc, NULL, info, KM_NOSLEEP);
		info->si_band = 0;
	}
	if (sevent & S_MSG) {
		sevent &= ~S_MSG;
		info->si_code = POLL_MSG;
		info->si_band = band;
		TRACE_2(TR_FAC_STREAMS_FR, TR_STRSENDSIG,
		    "strsendsig:proc %p info %p", proc, info);
		sigaddq(proc, NULL, info, KM_NOSLEEP);
		info->si_band = 0;
	}
	if (sevent & S_RDNORM) {
		sevent &= ~S_RDNORM;
		sigtoproc(proc, NULL, SIGPOLL);
	}
	if (sevent != 0) {
		panic("strsendsig: unknown event(s) %x", sevent);
	}
}

/*
 * Send SIGPOLL/SIGURG signal to all processes and process groups
 * registered on the given signal list that want a signal for at
 * least one of the specified events.
 *
 * Must be called with exclusive access to siglist (caller holding sd_lock).
 *
 * strioctl(I_SETSIG/I_ESETSIG) will only change siglist when holding
 * sd_lock and the ioctl code maintains a PID_HOLD on the pid structure
 * while it is in the siglist.
 *
 * For performance reasons (MP scalability) the code drops pidlock
 * when sending signals to a single process.
 * When sending to a process group the code holds
 * pidlock to prevent the membership in the process group from changing
 * while walking the p_pglink list.
 */
void
strsendsig(strsig_t *siglist, int event, uchar_t band, int error)
{
	strsig_t *ssp;
	k_siginfo_t info;
	struct pid *pidp;
	proc_t  *proc;

	info.si_signo = SIGPOLL;
	info.si_errno = 0;
	for (ssp = siglist; ssp; ssp = ssp->ss_next) {
		int sevent;

		sevent = ssp->ss_events & event;
		if (sevent == 0)
			continue;

		if ((pidp = ssp->ss_pidp) == NULL) {
			/* pid was released but still on event list */
			continue;
		}


		if (ssp->ss_pid > 0) {
			/*
			 * XXX This unfortunately still generates
			 * a signal when a fd is closed but
			 * the proc is active.
			 */
			ASSERT(ssp->ss_pid == pidp->pid_id);

			mutex_enter(&pidlock);
			proc = prfind_zone(pidp->pid_id, ALL_ZONES);
			if (proc == NULL) {
				mutex_exit(&pidlock);
				continue;
			}
			mutex_enter(&proc->p_lock);
			mutex_exit(&pidlock);
			dosendsig(proc, ssp->ss_events, sevent, &info,
			    band, error);
			mutex_exit(&proc->p_lock);
		} else {
			/*
			 * Send to process group. Hold pidlock across
			 * calls to dosendsig().
			 */
			pid_t pgrp = -ssp->ss_pid;

			mutex_enter(&pidlock);
			proc = pgfind_zone(pgrp, ALL_ZONES);
			while (proc != NULL) {
				mutex_enter(&proc->p_lock);
				dosendsig(proc, ssp->ss_events, sevent,
				    &info, band, error);
				mutex_exit(&proc->p_lock);
				proc = proc->p_pglink;
			}
			mutex_exit(&pidlock);
		}
	}
}

/*
 * Attach a stream device or module.
 * qp is a read queue; the new queue goes in so its next
 * read ptr is the argument, and the write queue corresponding
 * to the argument points to this queue. Return 0 on success,
 * or a non-zero errno on failure.
 */
int
qattach(queue_t *qp, dev_t *devp, int oflag, cred_t *crp, fmodsw_impl_t *fp,
    boolean_t is_insert)
{
	major_t			major;
	cdevsw_impl_t		*dp;
	struct streamtab	*str;
	queue_t			*rq;
	queue_t			*wrq;
	uint32_t		qflag;
	uint32_t		sqtype;
	perdm_t			*dmp;
	int			error;
	int			sflag;

	rq = allocq();
	wrq = _WR(rq);
	STREAM(rq) = STREAM(wrq) = STREAM(qp);

	if (fp != NULL) {
		str = fp->f_str;
		qflag = fp->f_qflag;
		sqtype = fp->f_sqtype;
		dmp = fp->f_dmp;
		IMPLY((qflag & (QPERMOD | QMTOUTPERIM)), dmp != NULL);
		sflag = MODOPEN;

		/*
		 * stash away a pointer to the module structure so we can
		 * unref it in qdetach.
		 */
		rq->q_fp = fp;
	} else {
		ASSERT(!is_insert);

		major = getmajor(*devp);
		dp = &devimpl[major];

		str = dp->d_str;
		ASSERT(str == STREAMSTAB(major));

		qflag = dp->d_qflag;
		ASSERT(qflag & QISDRV);
		sqtype = dp->d_sqtype;

		/* create perdm_t if needed */
		if (NEED_DM(dp->d_dmp, qflag))
			dp->d_dmp = hold_dm(str, qflag, sqtype);

		dmp = dp->d_dmp;
		sflag = 0;
	}

	TRACE_2(TR_FAC_STREAMS_FR, TR_QATTACH_FLAGS,
	    "qattach:qflag == %X(%X)", qflag, *devp);

	/* setq might sleep in allocator - avoid holding locks. */
	setq(rq, str->st_rdinit, str->st_wrinit, dmp, qflag, sqtype, B_FALSE);

	/*
	 * Before calling the module's open routine, set up the q_next
	 * pointer for inserting a module in the middle of a stream.
	 *
	 * Note that we can always set _QINSERTING and set up q_next
	 * pointer for both inserting and pushing a module.  Then there
	 * is no need for the is_insert parameter.  In insertq(), called
	 * by qprocson(), assume that q_next of the new module always points
	 * to the correct queue and use it for insertion.  Everything should
	 * work out fine.  But in the first release of _I_INSERT, we
	 * distinguish between inserting and pushing to make sure that
	 * pushing a module follows the same code path as before.
	 */
	if (is_insert) {
		rq->q_flag |= _QINSERTING;
		rq->q_next = qp;
	}

	/*
	 * If there is an outer perimeter get exclusive access during
	 * the open procedure.  Bump up the reference count on the queue.
	 */
	entersq(rq->q_syncq, SQ_OPENCLOSE);
	error = (*rq->q_qinfo->qi_qopen)(rq, devp, oflag, sflag, crp);
	if (error != 0)
		goto failed;
	leavesq(rq->q_syncq, SQ_OPENCLOSE);
	ASSERT(qprocsareon(rq));
	return (0);

failed:
	rq->q_flag &= ~_QINSERTING;
	if (backq(wrq) != NULL && backq(wrq)->q_next == wrq)
		qprocsoff(rq);
	leavesq(rq->q_syncq, SQ_OPENCLOSE);
	rq->q_next = wrq->q_next = NULL;
	qdetach(rq, 0, 0, crp, B_FALSE);
	return (error);
}

/*
 * Handle second open of stream. For modules, set the
 * last argument to MODOPEN and do not pass any open flags.
 * Ignore dummydev since this is not the first open.
 */
int
qreopen(queue_t *qp, dev_t *devp, int flag, cred_t *crp)
{
	int	error;
	dev_t dummydev;
	queue_t *wqp = _WR(qp);

	ASSERT(qp->q_flag & QREADR);
	entersq(qp->q_syncq, SQ_OPENCLOSE);

	dummydev = *devp;
	if (error = ((*qp->q_qinfo->qi_qopen)(qp, &dummydev,
	    (wqp->q_next ? 0 : flag), (wqp->q_next ? MODOPEN : 0), crp))) {
		leavesq(qp->q_syncq, SQ_OPENCLOSE);
		mutex_enter(&STREAM(qp)->sd_lock);
		qp->q_stream->sd_flag |= STREOPENFAIL;
		mutex_exit(&STREAM(qp)->sd_lock);
		return (error);
	}
	leavesq(qp->q_syncq, SQ_OPENCLOSE);

	/*
	 * successful open should have done qprocson()
	 */
	ASSERT(qprocsareon(_RD(qp)));
	return (0);
}

/*
 * Detach a stream module or device.
 * If clmode == 1 then the module or driver was opened and its
 * close routine must be called. If clmode == 0, the module
 * or driver was never opened or the open failed, and so its close
 * should not be called.
 */
void
qdetach(queue_t *qp, int clmode, int flag, cred_t *crp, boolean_t is_remove)
{
	queue_t *wqp = _WR(qp);
	ASSERT(STREAM(qp)->sd_flag & (STRCLOSE|STWOPEN|STRPLUMB));

	if (STREAM_NEEDSERVICE(STREAM(qp)))
		stream_runservice(STREAM(qp));

	if (clmode) {
		/*
		 * Make sure that all the messages on the write side syncq are
		 * processed and nothing is left. Since we are closing, no new
		 * messages may appear there.
		 */
		wait_q_syncq(wqp);

		entersq(qp->q_syncq, SQ_OPENCLOSE);
		if (is_remove) {
			mutex_enter(QLOCK(qp));
			qp->q_flag |= _QREMOVING;
			mutex_exit(QLOCK(qp));
		}
		(*qp->q_qinfo->qi_qclose)(qp, flag, crp);
		/*
		 * Check that qprocsoff() was actually called.
		 */
		ASSERT((qp->q_flag & QWCLOSE) && (wqp->q_flag & QWCLOSE));

		leavesq(qp->q_syncq, SQ_OPENCLOSE);
	} else {
		disable_svc(qp);
	}

	/*
	 * Allow any threads blocked in entersq to proceed and discover
	 * the QWCLOSE is set.
	 * Note: This assumes that all users of entersq check QWCLOSE.
	 * Currently runservice is the only entersq that can happen
	 * after removeq has finished.
	 * Removeq will have discarded all messages destined to the closing
	 * pair of queues from the syncq.
	 * NOTE: Calling a function inside an assert is unconventional.
	 * However, it does not cause any problem since flush_syncq() does
	 * not change any state except when it returns non-zero i.e.
	 * when the assert will trigger.
	 */
	ASSERT(flush_syncq(qp->q_syncq, qp) == 0);
	ASSERT(flush_syncq(wqp->q_syncq, wqp) == 0);
	ASSERT((qp->q_flag & QPERMOD) ||
	    ((qp->q_syncq->sq_head == NULL) &&
	    (wqp->q_syncq->sq_head == NULL)));

	/* release any fmodsw_impl_t structure held on behalf of the queue */
	ASSERT(qp->q_fp != NULL || qp->q_flag & QISDRV);
	if (qp->q_fp != NULL)
		fmodsw_rele(qp->q_fp);

	/* freeq removes us from the outer perimeter if any */
	freeq(qp);
}

/* Prevent service procedures from being called */
void
disable_svc(queue_t *qp)
{
	queue_t *wqp = _WR(qp);

	ASSERT(qp->q_flag & QREADR);
	mutex_enter(QLOCK(qp));
	qp->q_flag |= QWCLOSE;
	mutex_exit(QLOCK(qp));
	mutex_enter(QLOCK(wqp));
	wqp->q_flag |= QWCLOSE;
	mutex_exit(QLOCK(wqp));
}

/* Allow service procedures to be called again */
void
enable_svc(queue_t *qp)
{
	queue_t *wqp = _WR(qp);

	ASSERT(qp->q_flag & QREADR);
	mutex_enter(QLOCK(qp));
	qp->q_flag &= ~QWCLOSE;
	mutex_exit(QLOCK(qp));
	mutex_enter(QLOCK(wqp));
	wqp->q_flag &= ~QWCLOSE;
	mutex_exit(QLOCK(wqp));
}

/*
 * Remove queue from qhead/qtail if it is enabled.
 * Only reset QENAB if the queue was removed from the runlist.
 * A queue goes through 3 stages:
 *	It is on the service list and QENAB is set.
 *	It is removed from the service list but QENAB is still set.
 *	QENAB gets changed to QINSERVICE.
 *	QINSERVICE is reset (when the service procedure is done)
 * Thus we can not reset QENAB unless we actually removed it from the service
 * queue.
 */
void
remove_runlist(queue_t *qp)
{
	if (qp->q_flag & QENAB && qhead != NULL) {
		queue_t *q_chase;
		queue_t *q_curr;
		int removed;

		mutex_enter(&service_queue);
		RMQ(qp, qhead, qtail, q_link, q_chase, q_curr, removed);
		mutex_exit(&service_queue);
		if (removed) {
			STRSTAT(qremoved);
			qp->q_flag &= ~QENAB;
		}
	}
}


/*
 * Wait for any pending service processing to complete.
 * The removal of queues from the runlist is not atomic with the
 * clearing of the QENABLED flag and setting the INSERVICE flag.
 * consequently it is possible for remove_runlist in strclose
 * to not find the queue on the runlist but for it to be QENABLED
 * and not yet INSERVICE -> hence wait_svc needs to check QENABLED
 * as well as INSERVICE.
 */
void
wait_svc(queue_t *qp)
{
	queue_t *wqp = _WR(qp);

	ASSERT(qp->q_flag & QREADR);

	/*
	 * Try to remove queues from qhead/qtail list.
	 */
	if (qhead != NULL) {
		remove_runlist(qp);
		remove_runlist(wqp);
	}
	/*
	 * Wait till the syncqs associated with the queue disappear from the
	 * background processing list.
	 * This only needs to be done for non-PERMOD perimeters since
	 * for PERMOD perimeters the syncq may be shared and will only be freed
	 * when the last module/driver is unloaded.
	 * If for PERMOD perimeters queue was on the syncq list, removeq()
	 * should call propagate_syncq() or drain_syncq() for it. Both of these
	 * functions remove the queue from its syncq list, so sqthread will not
	 * try to access the queue.
	 */
	if (!(qp->q_flag & QPERMOD)) {
		syncq_t *rsq = qp->q_syncq;
		syncq_t *wsq = wqp->q_syncq;

		/*
		 * Disable rsq and wsq and wait for any background processing of
		 * syncq to complete.
		 */
		wait_sq_svc(rsq);
		if (wsq != rsq)
			wait_sq_svc(wsq);
	}

	mutex_enter(QLOCK(qp));
	while (qp->q_flag & (QINSERVICE|QENAB))
		cv_wait(&qp->q_wait, QLOCK(qp));
	mutex_exit(QLOCK(qp));
	mutex_enter(QLOCK(wqp));
	while (wqp->q_flag & (QINSERVICE|QENAB))
		cv_wait(&wqp->q_wait, QLOCK(wqp));
	mutex_exit(QLOCK(wqp));
}

/*
 * Put ioctl data from userland buffer `arg' into the mblk chain `bp'.
 * `flag' must always contain either K_TO_K or U_TO_K; STR_NOSIG may
 * also be set, and is passed through to allocb_cred_wait().
 *
 * Returns errno on failure, zero on success.
 */
int
putiocd(mblk_t *bp, char *arg, int flag, cred_t *cr)
{
	mblk_t *tmp;
	ssize_t  count;
	int error = 0;

	ASSERT((flag & (U_TO_K | K_TO_K)) == U_TO_K ||
	    (flag & (U_TO_K | K_TO_K)) == K_TO_K);

	if (bp->b_datap->db_type == M_IOCTL) {
		count = ((struct iocblk *)bp->b_rptr)->ioc_count;
	} else {
		ASSERT(bp->b_datap->db_type == M_COPYIN);
		count = ((struct copyreq *)bp->b_rptr)->cq_size;
	}
	/*
	 * strdoioctl validates ioc_count, so if this assert fails it
	 * cannot be due to user error.
	 */
	ASSERT(count >= 0);

	if ((tmp = allocb_cred_wait(count, (flag & STR_NOSIG), &error, cr,
	    curproc->p_pid)) == NULL) {
		return (error);
	}
	error = strcopyin(arg, tmp->b_wptr, count, flag & (U_TO_K|K_TO_K));
	if (error != 0) {
		freeb(tmp);
		return (error);
	}
	DB_CPID(tmp) = curproc->p_pid;
	tmp->b_wptr += count;
	bp->b_cont = tmp;

	return (0);
}

/*
 * Copy ioctl data to user-land. Return non-zero errno on failure,
 * 0 for success.
 */
int
getiocd(mblk_t *bp, char *arg, int copymode)
{
	ssize_t count;
	size_t  n;
	int	error;

	if (bp->b_datap->db_type == M_IOCACK)
		count = ((struct iocblk *)bp->b_rptr)->ioc_count;
	else {
		ASSERT(bp->b_datap->db_type == M_COPYOUT);
		count = ((struct copyreq *)bp->b_rptr)->cq_size;
	}
	ASSERT(count >= 0);

	for (bp = bp->b_cont; bp && count;
	    count -= n, bp = bp->b_cont, arg += n) {
		n = MIN(count, bp->b_wptr - bp->b_rptr);
		error = strcopyout(bp->b_rptr, arg, n, copymode);
		if (error)
			return (error);
	}
	ASSERT(count == 0);
	return (0);
}

/*
 * Allocate a linkinfo entry given the write queue of the
 * bottom module of the top stream and the write queue of the
 * stream head of the bottom stream.
 */
linkinfo_t *
alloclink(queue_t *qup, queue_t *qdown, file_t *fpdown)
{
	linkinfo_t *linkp;

	linkp = kmem_cache_alloc(linkinfo_cache, KM_SLEEP);

	linkp->li_lblk.l_qtop = qup;
	linkp->li_lblk.l_qbot = qdown;
	linkp->li_fpdown = fpdown;

	mutex_enter(&strresources);
	linkp->li_next = linkinfo_list;
	linkp->li_prev = NULL;
	if (linkp->li_next)
		linkp->li_next->li_prev = linkp;
	linkinfo_list = linkp;
	linkp->li_lblk.l_index = ++lnk_id;
	ASSERT(lnk_id != 0);	/* this should never wrap in practice */
	mutex_exit(&strresources);

	return (linkp);
}

/*
 * Free a linkinfo entry.
 */
void
lbfree(linkinfo_t *linkp)
{
	mutex_enter(&strresources);
	if (linkp->li_next)
		linkp->li_next->li_prev = linkp->li_prev;
	if (linkp->li_prev)
		linkp->li_prev->li_next = linkp->li_next;
	else
		linkinfo_list = linkp->li_next;
	mutex_exit(&strresources);

	kmem_cache_free(linkinfo_cache, linkp);
}

/*
 * Check for a potential linking cycle.
 * Return 1 if a link will result in a cycle,
 * and 0 otherwise.
 */
int
linkcycle(stdata_t *upstp, stdata_t *lostp, str_stack_t *ss)
{
	struct mux_node *np;
	struct mux_edge *ep;
	int i;
	major_t lomaj;
	major_t upmaj;
	/*
	 * if the lower stream is a pipe/FIFO, return, since link
	 * cycles can not happen on pipes/FIFOs
	 */
	if (lostp->sd_vnode->v_type == VFIFO)
		return (0);

	for (i = 0; i < ss->ss_devcnt; i++) {
		np = &ss->ss_mux_nodes[i];
		MUX_CLEAR(np);
	}
	lomaj = getmajor(lostp->sd_vnode->v_rdev);
	upmaj = getmajor(upstp->sd_vnode->v_rdev);
	np = &ss->ss_mux_nodes[lomaj];
	for (;;) {
		if (!MUX_DIDVISIT(np)) {
			if (np->mn_imaj == upmaj)
				return (1);
			if (np->mn_outp == NULL) {
				MUX_VISIT(np);
				if (np->mn_originp == NULL)
					return (0);
				np = np->mn_originp;
				continue;
			}
			MUX_VISIT(np);
			np->mn_startp = np->mn_outp;
		} else {
			if (np->mn_startp == NULL) {
				if (np->mn_originp == NULL)
					return (0);
				else {
					np = np->mn_originp;
					continue;
				}
			}
			/*
			 * If ep->me_nodep is a FIFO (me_nodep == NULL),
			 * ignore the edge and move on. ep->me_nodep gets
			 * set to NULL in mux_addedge() if it is a FIFO.
			 *
			 */
			ep = np->mn_startp;
			np->mn_startp = ep->me_nextp;
			if (ep->me_nodep == NULL)
				continue;
			ep->me_nodep->mn_originp = np;
			np = ep->me_nodep;
		}
	}
}

/*
 * Find linkinfo entry corresponding to the parameters.
 */
linkinfo_t *
findlinks(stdata_t *stp, int index, int type, str_stack_t *ss)
{
	linkinfo_t *linkp;
	struct mux_edge *mep;
	struct mux_node *mnp;
	queue_t *qup;

	mutex_enter(&strresources);
	if ((type & LINKTYPEMASK) == LINKNORMAL) {
		qup = getendq(stp->sd_wrq);
		for (linkp = linkinfo_list; linkp; linkp = linkp->li_next) {
			if ((qup == linkp->li_lblk.l_qtop) &&
			    (!index || (index == linkp->li_lblk.l_index))) {
				mutex_exit(&strresources);
				return (linkp);
			}
		}
	} else {
		ASSERT((type & LINKTYPEMASK) == LINKPERSIST);
		mnp = &ss->ss_mux_nodes[getmajor(stp->sd_vnode->v_rdev)];
		mep = mnp->mn_outp;
		while (mep) {
			if ((index == 0) || (index == mep->me_muxid))
				break;
			mep = mep->me_nextp;
		}
		if (!mep) {
			mutex_exit(&strresources);
			return (NULL);
		}
		for (linkp = linkinfo_list; linkp; linkp = linkp->li_next) {
			if ((!linkp->li_lblk.l_qtop) &&
			    (mep->me_muxid == linkp->li_lblk.l_index)) {
				mutex_exit(&strresources);
				return (linkp);
			}
		}
	}
	mutex_exit(&strresources);
	return (NULL);
}

/*
 * Given a queue ptr, follow the chain of q_next pointers until you reach the
 * last queue on the chain and return it.
 */
queue_t *
getendq(queue_t *q)
{
	ASSERT(q != NULL);
	while (_SAMESTR(q))
		q = q->q_next;
	return (q);
}

/*
 * Wait for the syncq count to drop to zero.
 * sq could be either outer or inner.
 */

static void
wait_syncq(syncq_t *sq)
{
	uint16_t count;

	mutex_enter(SQLOCK(sq));
	count = sq->sq_count;
	SQ_PUTLOCKS_ENTER(sq);
	SUM_SQ_PUTCOUNTS(sq, count);
	while (count != 0) {
		sq->sq_flags |= SQ_WANTWAKEUP;
		SQ_PUTLOCKS_EXIT(sq);
		cv_wait(&sq->sq_wait, SQLOCK(sq));
		count = sq->sq_count;
		SQ_PUTLOCKS_ENTER(sq);
		SUM_SQ_PUTCOUNTS(sq, count);
	}
	SQ_PUTLOCKS_EXIT(sq);
	mutex_exit(SQLOCK(sq));
}

/*
 * Wait while there are any messages for the queue in its syncq.
 */
static void
wait_q_syncq(queue_t *q)
{
	if ((q->q_sqflags & Q_SQQUEUED) || (q->q_syncqmsgs > 0)) {
		syncq_t *sq = q->q_syncq;

		mutex_enter(SQLOCK(sq));
		while ((q->q_sqflags & Q_SQQUEUED) || (q->q_syncqmsgs > 0)) {
			sq->sq_flags |= SQ_WANTWAKEUP;
			cv_wait(&sq->sq_wait, SQLOCK(sq));
		}
		mutex_exit(SQLOCK(sq));
	}
}


int
mlink_file(vnode_t *vp, int cmd, struct file *fpdown, cred_t *crp, int *rvalp,
    int lhlink)
{
	struct stdata *stp;
	struct strioctl strioc;
	struct linkinfo *linkp;
	struct stdata *stpdown;
	struct streamtab *str;
	queue_t *passq;
	syncq_t *passyncq;
	queue_t *rq;
	cdevsw_impl_t *dp;
	uint32_t qflag;
	uint32_t sqtype;
	perdm_t *dmp;
	int error = 0;
	netstack_t *ns;
	str_stack_t *ss;

	stp = vp->v_stream;
	TRACE_1(TR_FAC_STREAMS_FR,
	    TR_I_LINK, "I_LINK/I_PLINK:stp %p", stp);
	/*
	 * Test for invalid upper stream
	 */
	if (stp->sd_flag & STRHUP) {
		return (ENXIO);
	}
	if (vp->v_type == VFIFO) {
		return (EINVAL);
	}
	if (stp->sd_strtab == NULL) {
		return (EINVAL);
	}
	if (!stp->sd_strtab->st_muxwinit) {
		return (EINVAL);
	}
	if (fpdown == NULL) {
		return (EBADF);
	}
	ns = netstack_find_by_cred(crp);
	ASSERT(ns != NULL);
	ss = ns->netstack_str;
	ASSERT(ss != NULL);

	if (getmajor(stp->sd_vnode->v_rdev) >= ss->ss_devcnt) {
		netstack_rele(ss->ss_netstack);
		return (EINVAL);
	}
	mutex_enter(&muxifier);
	if (stp->sd_flag & STPLEX) {
		mutex_exit(&muxifier);
		netstack_rele(ss->ss_netstack);
		return (ENXIO);
	}

	/*
	 * Test for invalid lower stream.
	 * The check for the v_type != VFIFO and having a major
	 * number not >= devcnt is done to avoid problems with
	 * adding mux_node entry past the end of mux_nodes[].
	 * For FIFO's we don't add an entry so this isn't a
	 * problem.
	 */
	if (((stpdown = fpdown->f_vnode->v_stream) == NULL) ||
	    (stpdown == stp) || (stpdown->sd_flag &
	    (STPLEX|STRHUP|STRDERR|STWRERR|IOCWAIT|STRPLUMB)) ||
	    ((stpdown->sd_vnode->v_type != VFIFO) &&
	    (getmajor(stpdown->sd_vnode->v_rdev) >= ss->ss_devcnt)) ||
	    linkcycle(stp, stpdown, ss)) {
		mutex_exit(&muxifier);
		netstack_rele(ss->ss_netstack);
		return (EINVAL);
	}
	TRACE_1(TR_FAC_STREAMS_FR,
	    TR_STPDOWN, "stpdown:%p", stpdown);
	rq = getendq(stp->sd_wrq);
	if (cmd == I_PLINK)
		rq = NULL;

	linkp = alloclink(rq, stpdown->sd_wrq, fpdown);

	strioc.ic_cmd = cmd;
	strioc.ic_timout = INFTIM;
	strioc.ic_len = sizeof (struct linkblk);
	strioc.ic_dp = (char *)&linkp->li_lblk;

	/*
	 * STRPLUMB protects plumbing changes and should be set before
	 * link_addpassthru()/link_rempassthru() are called, so it is set here
	 * and cleared in the end of mlink when passthru queue is removed.
	 * Setting of STRPLUMB prevents reopens of the stream while passthru
	 * queue is in-place (it is not a proper module and doesn't have open
	 * entry point).
	 *
	 * STPLEX prevents any threads from entering the stream from above. It
	 * can't be set before the call to link_addpassthru() because putnext
	 * from below may cause stream head I/O routines to be called and these
	 * routines assert that STPLEX is not set. After link_addpassthru()
	 * nothing may come from below since the pass queue syncq is blocked.
	 * Note also that STPLEX should be cleared before the call to
	 * link_rempassthru() since when messages start flowing to the stream
	 * head (e.g. because of message propagation from the pass queue) stream
	 * head I/O routines may be called with STPLEX flag set.
	 *
	 * When STPLEX is set, nothing may come into the stream from above and
	 * it is safe to do a setq which will change stream head. So, the
	 * correct sequence of actions is:
	 *
	 * 1) Set STRPLUMB
	 * 2) Call link_addpassthru()
	 * 3) Set STPLEX
	 * 4) Call setq and update the stream state
	 * 5) Clear STPLEX
	 * 6) Call link_rempassthru()
	 * 7) Clear STRPLUMB
	 *
	 * The same sequence applies to munlink() code.
	 */
	mutex_enter(&stpdown->sd_lock);
	stpdown->sd_flag |= STRPLUMB;
	mutex_exit(&stpdown->sd_lock);
	/*
	 * Add passthru queue below lower mux. This will block
	 * syncqs of lower muxs read queue during I_LINK/I_UNLINK.
	 */
	passq = link_addpassthru(stpdown);

	mutex_enter(&stpdown->sd_lock);
	stpdown->sd_flag |= STPLEX;
	mutex_exit(&stpdown->sd_lock);

	rq = _RD(stpdown->sd_wrq);
	/*
	 * There may be messages in the streamhead's syncq due to messages
	 * that arrived before link_addpassthru() was done. To avoid
	 * background processing of the syncq happening simultaneous with
	 * setq processing, we disable the streamhead syncq and wait until
	 * existing background thread finishes working on it.
	 */
	wait_sq_svc(rq->q_syncq);
	passyncq = passq->q_syncq;
	if (!(passyncq->sq_flags & SQ_BLOCKED))
		blocksq(passyncq, SQ_BLOCKED, 0);

	ASSERT((rq->q_flag & QMT_TYPEMASK) == QMTSAFE);
	ASSERT(rq->q_syncq == SQ(rq) && _WR(rq)->q_syncq == SQ(rq));
	rq->q_ptr = _WR(rq)->q_ptr = NULL;

	/* setq might sleep in allocator - avoid holding locks. */
	/* Note: we are holding muxifier here. */

	str = stp->sd_strtab;
	dp = &devimpl[getmajor(vp->v_rdev)];
	ASSERT(dp->d_str == str);

	qflag = dp->d_qflag;
	sqtype = dp->d_sqtype;

	/* create perdm_t if needed */
	if (NEED_DM(dp->d_dmp, qflag))
		dp->d_dmp = hold_dm(str, qflag, sqtype);

	dmp = dp->d_dmp;

	setq(rq, str->st_muxrinit, str->st_muxwinit, dmp, qflag, sqtype,
	    B_TRUE);

	/*
	 * XXX Remove any "odd" messages from the queue.
	 * Keep only M_DATA, M_PROTO, M_PCPROTO.
	 */
	error = strdoioctl(stp, &strioc, FNATIVE,
	    K_TO_K | STR_NOERROR | STR_NOSIG, crp, rvalp);
	if (error != 0) {
		lbfree(linkp);

		if (!(passyncq->sq_flags & SQ_BLOCKED))
			blocksq(passyncq, SQ_BLOCKED, 0);
		/*
		 * Restore the stream head queue and then remove
		 * the passq. Turn off STPLEX before we turn on
		 * the stream by removing the passq.
		 */
		rq->q_ptr = _WR(rq)->q_ptr = stpdown;
		setq(rq, &strdata, &stwdata, NULL, QMTSAFE, SQ_CI|SQ_CO,
		    B_TRUE);

		mutex_enter(&stpdown->sd_lock);
		stpdown->sd_flag &= ~STPLEX;
		mutex_exit(&stpdown->sd_lock);

		link_rempassthru(passq);

		mutex_enter(&stpdown->sd_lock);
		stpdown->sd_flag &= ~STRPLUMB;
		/* Wakeup anyone waiting for STRPLUMB to clear. */
		cv_broadcast(&stpdown->sd_monitor);
		mutex_exit(&stpdown->sd_lock);

		mutex_exit(&muxifier);
		netstack_rele(ss->ss_netstack);
		return (error);
	}
	mutex_enter(&fpdown->f_tlock);
	fpdown->f_count++;
	mutex_exit(&fpdown->f_tlock);

	/*
	 * if we've made it here the linkage is all set up so we should also
	 * set up the layered driver linkages
	 */

	ASSERT((cmd == I_LINK) || (cmd == I_PLINK));
	if (cmd == I_LINK) {
		ldi_mlink_fp(stp, fpdown, lhlink, LINKNORMAL);
	} else {
		ldi_mlink_fp(stp, fpdown, lhlink, LINKPERSIST);
	}

	link_rempassthru(passq);

	mux_addedge(stp, stpdown, linkp->li_lblk.l_index, ss);

	/*
	 * Mark the upper stream as having dependent links
	 * so that strclose can clean it up.
	 */
	if (cmd == I_LINK) {
		mutex_enter(&stp->sd_lock);
		stp->sd_flag |= STRHASLINKS;
		mutex_exit(&stp->sd_lock);
	}
	/*
	 * Wake up any other processes that may have been
	 * waiting on the lower stream. These will all
	 * error out.
	 */
	mutex_enter(&stpdown->sd_lock);
	/* The passthru module is removed so we may release STRPLUMB */
	stpdown->sd_flag &= ~STRPLUMB;
	cv_broadcast(&rq->q_wait);
	cv_broadcast(&_WR(rq)->q_wait);
	cv_broadcast(&stpdown->sd_monitor);
	mutex_exit(&stpdown->sd_lock);
	mutex_exit(&muxifier);
	*rvalp = linkp->li_lblk.l_index;
	netstack_rele(ss->ss_netstack);
	return (0);
}

int
mlink(vnode_t *vp, int cmd, int arg, cred_t *crp, int *rvalp, int lhlink)
{
	int		ret;
	struct file	*fpdown;

	fpdown = getf(arg);
	ret = mlink_file(vp, cmd, fpdown, crp, rvalp, lhlink);
	if (fpdown != NULL)
		releasef(arg);
	return (ret);
}

/*
 * Unlink a multiplexor link. Stp is the controlling stream for the
 * link, and linkp points to the link's entry in the linkinfo list.
 * The muxifier lock must be held on entry and is dropped on exit.
 *
 * NOTE : Currently it is assumed that mux would process all the messages
 * sitting on it's queue before ACKing the UNLINK. It is the responsibility
 * of the mux to handle all the messages that arrive before UNLINK.
 * If the mux has to send down messages on its lower stream before
 * ACKing I_UNLINK, then it *should* know to handle messages even
 * after the UNLINK is acked (actually it should be able to handle till we
 * re-block the read side of the pass queue here). If the mux does not
 * open up the lower stream, any messages that arrive during UNLINK
 * will be put in the stream head. In the case of lower stream opening
 * up, some messages might land in the stream head depending on when
 * the message arrived and when the read side of the pass queue was
 * re-blocked.
 */
int
munlink(stdata_t *stp, linkinfo_t *linkp, int flag, cred_t *crp, int *rvalp,
    str_stack_t *ss)
{
	struct strioctl strioc;
	struct stdata *stpdown;
	queue_t *rq, *wrq;
	queue_t	*passq;
	syncq_t *passyncq;
	int error = 0;
	file_t *fpdown;

	ASSERT(MUTEX_HELD(&muxifier));

	stpdown = linkp->li_fpdown->f_vnode->v_stream;

	/*
	 * See the comment in mlink() concerning STRPLUMB/STPLEX flags.
	 */
	mutex_enter(&stpdown->sd_lock);
	stpdown->sd_flag |= STRPLUMB;
	mutex_exit(&stpdown->sd_lock);

	/*
	 * Add passthru queue below lower mux. This will block
	 * syncqs of lower muxs read queue during I_LINK/I_UNLINK.
	 */
	passq = link_addpassthru(stpdown);

	if ((flag & LINKTYPEMASK) == LINKNORMAL)
		strioc.ic_cmd = I_UNLINK;
	else
		strioc.ic_cmd = I_PUNLINK;
	strioc.ic_timout = INFTIM;
	strioc.ic_len = sizeof (struct linkblk);
	strioc.ic_dp = (char *)&linkp->li_lblk;

	error = strdoioctl(stp, &strioc, FNATIVE,
	    K_TO_K | STR_NOERROR | STR_NOSIG, crp, rvalp);

	/*
	 * If there was an error and this is not called via strclose,
	 * return to the user. Otherwise, pretend there was no error
	 * and close the link.
	 */
	if (error) {
		if (flag & LINKCLOSE) {
			cmn_err(CE_WARN, "KERNEL: munlink: could not perform "
			    "unlink ioctl, closing anyway (%d)\n", error);
		} else {
			link_rempassthru(passq);
			mutex_enter(&stpdown->sd_lock);
			stpdown->sd_flag &= ~STRPLUMB;
			cv_broadcast(&stpdown->sd_monitor);
			mutex_exit(&stpdown->sd_lock);
			mutex_exit(&muxifier);
			return (error);
		}
	}

	mux_rmvedge(stp, linkp->li_lblk.l_index, ss);
	fpdown = linkp->li_fpdown;
	lbfree(linkp);

	/*
	 * We go ahead and drop muxifier here--it's a nasty global lock that
	 * can slow others down. It's okay to since attempts to mlink() this
	 * stream will be stopped because STPLEX is still set in the stdata
	 * structure, and munlink() is stopped because mux_rmvedge() and
	 * lbfree() have removed it from mux_nodes[] and linkinfo_list,
	 * respectively.  Note that we defer the closef() of fpdown until
	 * after we drop muxifier since strclose() can call munlinkall().
	 */
	mutex_exit(&muxifier);

	wrq = stpdown->sd_wrq;
	rq = _RD(wrq);

	/*
	 * Get rid of outstanding service procedure runs, before we make
	 * it a stream head, since a stream head doesn't have any service
	 * procedure.
	 */
	disable_svc(rq);
	wait_svc(rq);

	/*
	 * Since we don't disable the syncq for QPERMOD, we wait for whatever
	 * is queued up to be finished. mux should take care that nothing is
	 * send down to this queue. We should do it now as we're going to block
	 * passyncq if it was unblocked.
	 */
	if (wrq->q_flag & QPERMOD) {
		syncq_t	*sq = wrq->q_syncq;

		mutex_enter(SQLOCK(sq));
		while (wrq->q_sqflags & Q_SQQUEUED) {
			sq->sq_flags |= SQ_WANTWAKEUP;
			cv_wait(&sq->sq_wait, SQLOCK(sq));
		}
		mutex_exit(SQLOCK(sq));
	}
	passyncq = passq->q_syncq;
	if (!(passyncq->sq_flags & SQ_BLOCKED)) {

		syncq_t *sq, *outer;

		/*
		 * Messages could be flowing from underneath. We will
		 * block the read side of the passq. This would be
		 * sufficient for QPAIR and QPERQ muxes to ensure
		 * that no data is flowing up into this queue
		 * and hence no thread active in this instance of
		 * lower mux. But for QPERMOD and QMTOUTPERIM there
		 * could be messages on the inner and outer/inner
		 * syncqs respectively. We will wait for them to drain.
		 * Because passq is blocked messages end up in the syncq
		 * And qfill_syncq could possibly end up setting QFULL
		 * which will access the rq->q_flag. Hence, we have to
		 * acquire the QLOCK in setq.
		 *
		 * XXX Messages can also flow from top into this
		 * queue though the unlink is over (Ex. some instance
		 * in putnext() called from top that has still not
		 * accessed this queue. And also putq(lowerq) ?).
		 * Solution : How about blocking the l_qtop queue ?
		 * Do we really care about such pure D_MP muxes ?
		 */

		blocksq(passyncq, SQ_BLOCKED, 0);

		sq = rq->q_syncq;
		if ((outer = sq->sq_outer) != NULL) {

			/*
			 * We have to just wait for the outer sq_count
			 * drop to zero. As this does not prevent new
			 * messages to enter the outer perimeter, this
			 * is subject to starvation.
			 *
			 * NOTE :Because of blocksq above, messages could
			 * be in the inner syncq only because of some
			 * thread holding the outer perimeter exclusively.
			 * Hence it would be sufficient to wait for the
			 * exclusive holder of the outer perimeter to drain
			 * the inner and outer syncqs. But we will not depend
			 * on this feature and hence check the inner syncqs
			 * separately.
			 */
			wait_syncq(outer);
		}


		/*
		 * There could be messages destined for
		 * this queue. Let the exclusive holder
		 * drain it.
		 */

		wait_syncq(sq);
		ASSERT((rq->q_flag & QPERMOD) ||
		    ((rq->q_syncq->sq_head == NULL) &&
		    (_WR(rq)->q_syncq->sq_head == NULL)));
	}

	/*
	 * We haven't taken care of QPERMOD case yet. QPERMOD is a special
	 * case as we don't disable its syncq or remove it off the syncq
	 * service list.
	 */
	if (rq->q_flag & QPERMOD) {
		syncq_t	*sq = rq->q_syncq;

		mutex_enter(SQLOCK(sq));
		while (rq->q_sqflags & Q_SQQUEUED) {
			sq->sq_flags |= SQ_WANTWAKEUP;
			cv_wait(&sq->sq_wait, SQLOCK(sq));
		}
		mutex_exit(SQLOCK(sq));
	}

	/*
	 * flush_syncq changes states only when there are some messages to
	 * free, i.e. when it returns non-zero value to return.
	 */
	ASSERT(flush_syncq(rq->q_syncq, rq) == 0);
	ASSERT(flush_syncq(wrq->q_syncq, wrq) == 0);

	/*
	 * Nobody else should know about this queue now.
	 * If the mux did not process the messages before
	 * acking the I_UNLINK, free them now.
	 */

	flushq(rq, FLUSHALL);
	flushq(_WR(rq), FLUSHALL);

	/*
	 * Convert the mux lower queue into a stream head queue.
	 * Turn off STPLEX before we turn on the stream by removing the passq.
	 */
	rq->q_ptr = wrq->q_ptr = stpdown;
	setq(rq, &strdata, &stwdata, NULL, QMTSAFE, SQ_CI|SQ_CO, B_TRUE);

	ASSERT((rq->q_flag & QMT_TYPEMASK) == QMTSAFE);
	ASSERT(rq->q_syncq == SQ(rq) && _WR(rq)->q_syncq == SQ(rq));

	enable_svc(rq);

	/*
	 * Now it is a proper stream, so STPLEX is cleared. But STRPLUMB still
	 * needs to be set to prevent reopen() of the stream - such reopen may
	 * try to call non-existent pass queue open routine and panic.
	 */
	mutex_enter(&stpdown->sd_lock);
	stpdown->sd_flag &= ~STPLEX;
	mutex_exit(&stpdown->sd_lock);

	ASSERT(((flag & LINKTYPEMASK) == LINKNORMAL) ||
	    ((flag & LINKTYPEMASK) == LINKPERSIST));

	/* clean up the layered driver linkages */
	if ((flag & LINKTYPEMASK) == LINKNORMAL) {
		ldi_munlink_fp(stp, fpdown, LINKNORMAL);
	} else {
		ldi_munlink_fp(stp, fpdown, LINKPERSIST);
	}

	link_rempassthru(passq);

	/*
	 * Now all plumbing changes are finished and STRPLUMB is no
	 * longer needed.
	 */
	mutex_enter(&stpdown->sd_lock);
	stpdown->sd_flag &= ~STRPLUMB;
	cv_broadcast(&stpdown->sd_monitor);
	mutex_exit(&stpdown->sd_lock);

	(void) closef(fpdown);
	return (0);
}

/*
 * Unlink all multiplexor links for which stp is the controlling stream.
 * Return 0, or a non-zero errno on failure.
 */
int
munlinkall(stdata_t *stp, int flag, cred_t *crp, int *rvalp, str_stack_t *ss)
{
	linkinfo_t *linkp;
	int error = 0;

	mutex_enter(&muxifier);
	while (linkp = findlinks(stp, 0, flag, ss)) {
		/*
		 * munlink() releases the muxifier lock.
		 */
		if (error = munlink(stp, linkp, flag, crp, rvalp, ss))
			return (error);
		mutex_enter(&muxifier);
	}
	mutex_exit(&muxifier);
	return (0);
}

/*
 * A multiplexor link has been made. Add an
 * edge to the directed graph.
 */
void
mux_addedge(stdata_t *upstp, stdata_t *lostp, int muxid, str_stack_t *ss)
{
	struct mux_node *np;
	struct mux_edge *ep;
	major_t upmaj;
	major_t lomaj;

	upmaj = getmajor(upstp->sd_vnode->v_rdev);
	lomaj = getmajor(lostp->sd_vnode->v_rdev);
	np = &ss->ss_mux_nodes[upmaj];
	if (np->mn_outp) {
		ep = np->mn_outp;
		while (ep->me_nextp)
			ep = ep->me_nextp;
		ep->me_nextp = kmem_alloc(sizeof (struct mux_edge), KM_SLEEP);
		ep = ep->me_nextp;
	} else {
		np->mn_outp = kmem_alloc(sizeof (struct mux_edge), KM_SLEEP);
		ep = np->mn_outp;
	}
	ep->me_nextp = NULL;
	ep->me_muxid = muxid;
	/*
	 * Save the dev_t for the purposes of str_stack_shutdown.
	 * str_stack_shutdown assumes that the device allows reopen, since
	 * this dev_t is the one after any cloning by xx_open().
	 * Would prefer finding the dev_t from before any cloning,
	 * but specfs doesn't retain that.
	 */
	ep->me_dev = upstp->sd_vnode->v_rdev;
	if (lostp->sd_vnode->v_type == VFIFO)
		ep->me_nodep = NULL;
	else
		ep->me_nodep = &ss->ss_mux_nodes[lomaj];
}

/*
 * A multiplexor link has been removed. Remove the
 * edge in the directed graph.
 */
void
mux_rmvedge(stdata_t *upstp, int muxid, str_stack_t *ss)
{
	struct mux_node *np;
	struct mux_edge *ep;
	struct mux_edge *pep = NULL;
	major_t upmaj;

	upmaj = getmajor(upstp->sd_vnode->v_rdev);
	np = &ss->ss_mux_nodes[upmaj];
	ASSERT(np->mn_outp != NULL);
	ep = np->mn_outp;
	while (ep) {
		if (ep->me_muxid == muxid) {
			if (pep)
				pep->me_nextp = ep->me_nextp;
			else
				np->mn_outp = ep->me_nextp;
			kmem_free(ep, sizeof (struct mux_edge));
			return;
		}
		pep = ep;
		ep = ep->me_nextp;
	}
	ASSERT(0);	/* should not reach here */
}

/*
 * Translate the device flags (from conf.h) to the corresponding
 * qflag and sq_flag (type) values.
 */
int
devflg_to_qflag(struct streamtab *stp, uint32_t devflag, uint32_t *qflagp,
	uint32_t *sqtypep)
{
	uint32_t qflag = 0;
	uint32_t sqtype = 0;

	if (devflag & _D_OLD)
		goto bad;

	/* Inner perimeter presence and scope */
	switch (devflag & D_MTINNER_MASK) {
	case D_MP:
		qflag |= QMTSAFE;
		sqtype |= SQ_CI;
		break;
	case D_MTPERQ|D_MP:
		qflag |= QPERQ;
		break;
	case D_MTQPAIR|D_MP:
		qflag |= QPAIR;
		break;
	case D_MTPERMOD|D_MP:
		qflag |= QPERMOD;
		break;
	default:
		goto bad;
	}

	/* Outer perimeter */
	if (devflag & D_MTOUTPERIM) {
		switch (devflag & D_MTINNER_MASK) {
		case D_MP:
		case D_MTPERQ|D_MP:
		case D_MTQPAIR|D_MP:
			break;
		default:
			goto bad;
		}
		qflag |= QMTOUTPERIM;
	}

	/* Inner perimeter modifiers */
	if (devflag & D_MTINNER_MOD) {
		switch (devflag & D_MTINNER_MASK) {
		case D_MP:
			goto bad;
		default:
			break;
		}
		if (devflag & D_MTPUTSHARED)
			sqtype |= SQ_CIPUT;
		if (devflag & _D_MTOCSHARED) {
			/*
			 * The code in putnext assumes that it has the
			 * highest concurrency by not checking sq_count.
			 * Thus _D_MTOCSHARED can only be supported when
			 * D_MTPUTSHARED is set.
			 */
			if (!(devflag & D_MTPUTSHARED))
				goto bad;
			sqtype |= SQ_CIOC;
		}
		if (devflag & _D_MTCBSHARED) {
			/*
			 * The code in putnext assumes that it has the
			 * highest concurrency by not checking sq_count.
			 * Thus _D_MTCBSHARED can only be supported when
			 * D_MTPUTSHARED is set.
			 */
			if (!(devflag & D_MTPUTSHARED))
				goto bad;
			sqtype |= SQ_CICB;
		}
		if (devflag & _D_MTSVCSHARED) {
			/*
			 * The code in putnext assumes that it has the
			 * highest concurrency by not checking sq_count.
			 * Thus _D_MTSVCSHARED can only be supported when
			 * D_MTPUTSHARED is set. Also _D_MTSVCSHARED is
			 * supported only for QPERMOD.
			 */
			if (!(devflag & D_MTPUTSHARED) || !(qflag & QPERMOD))
				goto bad;
			sqtype |= SQ_CISVC;
		}
	}

	/* Default outer perimeter concurrency */
	sqtype |= SQ_CO;

	/* Outer perimeter modifiers */
	if (devflag & D_MTOCEXCL) {
		if (!(devflag & D_MTOUTPERIM)) {
			/* No outer perimeter */
			goto bad;
		}
		sqtype &= ~SQ_COOC;
	}

	/* Synchronous Streams extended qinit structure */
	if (devflag & D_SYNCSTR)
		qflag |= QSYNCSTR;

	/*
	 * Private flag used by a transport module to indicate
	 * to sockfs that it supports direct-access mode without
	 * having to go through STREAMS.
	 */
	if (devflag & _D_DIRECT) {
		/* Reject unless the module is fully-MT (no perimeter) */
		if ((qflag & QMT_TYPEMASK) != QMTSAFE)
			goto bad;
		qflag |= _QDIRECT;
	}

	*qflagp = qflag;
	*sqtypep = sqtype;
	return (0);

bad:
	cmn_err(CE_WARN,
	    "stropen: bad MT flags (0x%x) in driver '%s'",
	    (int)(qflag & D_MTSAFETY_MASK),
	    stp->st_rdinit->qi_minfo->mi_idname);

	return (EINVAL);
}

/*
 * Set the interface values for a pair of queues (qinit structure,
 * packet sizes, water marks).
 * setq assumes that the caller does not have a claim (entersq or claimq)
 * on the queue.
 */
void
setq(queue_t *rq, struct qinit *rinit, struct qinit *winit,
    perdm_t *dmp, uint32_t qflag, uint32_t sqtype, boolean_t lock_needed)
{
	queue_t *wq;
	syncq_t	*sq, *outer;

	ASSERT(rq->q_flag & QREADR);
	ASSERT((qflag & QMT_TYPEMASK) != 0);
	IMPLY((qflag & (QPERMOD | QMTOUTPERIM)), dmp != NULL);

	wq = _WR(rq);
	rq->q_qinfo = rinit;
	rq->q_hiwat = rinit->qi_minfo->mi_hiwat;
	rq->q_lowat = rinit->qi_minfo->mi_lowat;
	rq->q_minpsz = rinit->qi_minfo->mi_minpsz;
	rq->q_maxpsz = rinit->qi_minfo->mi_maxpsz;
	wq->q_qinfo = winit;
	wq->q_hiwat = winit->qi_minfo->mi_hiwat;
	wq->q_lowat = winit->qi_minfo->mi_lowat;
	wq->q_minpsz = winit->qi_minfo->mi_minpsz;
	wq->q_maxpsz = winit->qi_minfo->mi_maxpsz;

	/* Remove old syncqs */
	sq = rq->q_syncq;
	outer = sq->sq_outer;
	if (outer != NULL) {
		ASSERT(wq->q_syncq->sq_outer == outer);
		outer_remove(outer, rq->q_syncq);
		if (wq->q_syncq != rq->q_syncq)
			outer_remove(outer, wq->q_syncq);
	}
	ASSERT(sq->sq_outer == NULL);
	ASSERT(sq->sq_onext == NULL && sq->sq_oprev == NULL);

	if (sq != SQ(rq)) {
		if (!(rq->q_flag & QPERMOD))
			free_syncq(sq);
		if (wq->q_syncq == rq->q_syncq)
			wq->q_syncq = NULL;
		rq->q_syncq = NULL;
	}
	if (wq->q_syncq != NULL && wq->q_syncq != sq &&
	    wq->q_syncq != SQ(rq)) {
		free_syncq(wq->q_syncq);
		wq->q_syncq = NULL;
	}
	ASSERT(rq->q_syncq == NULL || (rq->q_syncq->sq_head == NULL &&
	    rq->q_syncq->sq_tail == NULL));
	ASSERT(wq->q_syncq == NULL || (wq->q_syncq->sq_head == NULL &&
	    wq->q_syncq->sq_tail == NULL));

	if (!(rq->q_flag & QPERMOD) &&
	    rq->q_syncq != NULL && rq->q_syncq->sq_ciputctrl != NULL) {
		ASSERT(rq->q_syncq->sq_nciputctrl == n_ciputctrl - 1);
		SUMCHECK_CIPUTCTRL_COUNTS(rq->q_syncq->sq_ciputctrl,
		    rq->q_syncq->sq_nciputctrl, 0);
		ASSERT(ciputctrl_cache != NULL);
		kmem_cache_free(ciputctrl_cache, rq->q_syncq->sq_ciputctrl);
		rq->q_syncq->sq_ciputctrl = NULL;
		rq->q_syncq->sq_nciputctrl = 0;
	}

	if (!(wq->q_flag & QPERMOD) &&
	    wq->q_syncq != NULL && wq->q_syncq->sq_ciputctrl != NULL) {
		ASSERT(wq->q_syncq->sq_nciputctrl == n_ciputctrl - 1);
		SUMCHECK_CIPUTCTRL_COUNTS(wq->q_syncq->sq_ciputctrl,
		    wq->q_syncq->sq_nciputctrl, 0);
		ASSERT(ciputctrl_cache != NULL);
		kmem_cache_free(ciputctrl_cache, wq->q_syncq->sq_ciputctrl);
		wq->q_syncq->sq_ciputctrl = NULL;
		wq->q_syncq->sq_nciputctrl = 0;
	}

	sq = SQ(rq);
	ASSERT(sq->sq_head == NULL && sq->sq_tail == NULL);
	ASSERT(sq->sq_outer == NULL);
	ASSERT(sq->sq_onext == NULL && sq->sq_oprev == NULL);

	/*
	 * Create syncqs based on qflag and sqtype. Set the SQ_TYPES_IN_FLAGS
	 * bits in sq_flag based on the sqtype.
	 */
	ASSERT((sq->sq_flags & ~SQ_TYPES_IN_FLAGS) == 0);

	rq->q_syncq = wq->q_syncq = sq;
	sq->sq_type = sqtype;
	sq->sq_flags = (sqtype & SQ_TYPES_IN_FLAGS);

	/*
	 *  We are making sq_svcflags zero,
	 *  resetting SQ_DISABLED in case it was set by
	 *  wait_svc() in the munlink path.
	 *
	 */
	ASSERT((sq->sq_svcflags & SQ_SERVICE) == 0);
	sq->sq_svcflags = 0;

	/*
	 * We need to acquire the lock here for the mlink and munlink case,
	 * where canputnext, backenable, etc can access the q_flag.
	 */
	if (lock_needed) {
		mutex_enter(QLOCK(rq));
		rq->q_flag = (rq->q_flag & ~QMT_TYPEMASK) | QWANTR | qflag;
		mutex_exit(QLOCK(rq));
		mutex_enter(QLOCK(wq));
		wq->q_flag = (wq->q_flag & ~QMT_TYPEMASK) | QWANTR | qflag;
		mutex_exit(QLOCK(wq));
	} else {
		rq->q_flag = (rq->q_flag & ~QMT_TYPEMASK) | QWANTR | qflag;
		wq->q_flag = (wq->q_flag & ~QMT_TYPEMASK) | QWANTR | qflag;
	}

	if (qflag & QPERQ) {
		/* Allocate a separate syncq for the write side */
		sq = new_syncq();
		sq->sq_type = rq->q_syncq->sq_type;
		sq->sq_flags = rq->q_syncq->sq_flags;
		ASSERT(sq->sq_outer == NULL && sq->sq_onext == NULL &&
		    sq->sq_oprev == NULL);
		wq->q_syncq = sq;
	}
	if (qflag & QPERMOD) {
		sq = dmp->dm_sq;

		/*
		 * Assert that we do have an inner perimeter syncq and that it
		 * does not have an outer perimeter associated with it.
		 */
		ASSERT(sq->sq_outer == NULL && sq->sq_onext == NULL &&
		    sq->sq_oprev == NULL);
		rq->q_syncq = wq->q_syncq = sq;
	}
	if (qflag & QMTOUTPERIM) {
		outer = dmp->dm_sq;

		ASSERT(outer->sq_outer == NULL);
		outer_insert(outer, rq->q_syncq);
		if (wq->q_syncq != rq->q_syncq)
			outer_insert(outer, wq->q_syncq);
	}
	ASSERT((rq->q_syncq->sq_flags & SQ_TYPES_IN_FLAGS) ==
	    (rq->q_syncq->sq_type & SQ_TYPES_IN_FLAGS));
	ASSERT((wq->q_syncq->sq_flags & SQ_TYPES_IN_FLAGS) ==
	    (wq->q_syncq->sq_type & SQ_TYPES_IN_FLAGS));
	ASSERT((rq->q_flag & QMT_TYPEMASK) == (qflag & QMT_TYPEMASK));

	/*
	 * Initialize struio() types.
	 */
	rq->q_struiot =
	    (rq->q_flag & QSYNCSTR) ? rinit->qi_struiot : STRUIOT_NONE;
	wq->q_struiot =
	    (wq->q_flag & QSYNCSTR) ? winit->qi_struiot : STRUIOT_NONE;
}

perdm_t *
hold_dm(struct streamtab *str, uint32_t qflag, uint32_t sqtype)
{
	syncq_t	*sq;
	perdm_t	**pp;
	perdm_t	*p;
	perdm_t	*dmp;

	ASSERT(str != NULL);
	ASSERT(qflag & (QPERMOD | QMTOUTPERIM));

	rw_enter(&perdm_rwlock, RW_READER);
	for (p = perdm_list; p != NULL; p = p->dm_next) {
		if (p->dm_str == str) {	/* found one */
			atomic_inc_32(&(p->dm_ref));
			rw_exit(&perdm_rwlock);
			return (p);
		}
	}
	rw_exit(&perdm_rwlock);

	sq = new_syncq();
	if (qflag & QPERMOD) {
		sq->sq_type = sqtype | SQ_PERMOD;
		sq->sq_flags = sqtype & SQ_TYPES_IN_FLAGS;
	} else {
		ASSERT(qflag & QMTOUTPERIM);
		sq->sq_onext = sq->sq_oprev = sq;
	}

	dmp = kmem_alloc(sizeof (perdm_t), KM_SLEEP);
	dmp->dm_sq = sq;
	dmp->dm_str = str;
	dmp->dm_ref = 1;
	dmp->dm_next = NULL;

	rw_enter(&perdm_rwlock, RW_WRITER);
	for (pp = &perdm_list; (p = *pp) != NULL; pp = &(p->dm_next)) {
		if (p->dm_str == str) {	/* already present */
			p->dm_ref++;
			rw_exit(&perdm_rwlock);
			free_syncq(sq);
			kmem_free(dmp, sizeof (perdm_t));
			return (p);
		}
	}

	*pp = dmp;
	rw_exit(&perdm_rwlock);
	return (dmp);
}

void
rele_dm(perdm_t *dmp)
{
	perdm_t **pp;
	perdm_t *p;

	rw_enter(&perdm_rwlock, RW_WRITER);
	ASSERT(dmp->dm_ref > 0);

	if (--dmp->dm_ref > 0) {
		rw_exit(&perdm_rwlock);
		return;
	}

	for (pp = &perdm_list; (p = *pp) != NULL; pp = &(p->dm_next))
		if (p == dmp)
			break;
	ASSERT(p == dmp);
	*pp = p->dm_next;
	rw_exit(&perdm_rwlock);

	/*
	 * Wait for any background processing that relies on the
	 * syncq to complete before it is freed.
	 */
	wait_sq_svc(p->dm_sq);
	free_syncq(p->dm_sq);
	kmem_free(p, sizeof (perdm_t));
}

/*
 * Make a protocol message given control and data buffers.
 * n.b., this can block; be careful of what locks you hold when calling it.
 *
 * If sd_maxblk is less than *iosize this routine can fail part way through
 * (due to an allocation failure). In this case on return *iosize will contain
 * the amount that was consumed. Otherwise *iosize will not be modified
 * i.e. it will contain the amount that was consumed.
 */
int
strmakemsg(
	struct strbuf *mctl,
	ssize_t *iosize,
	struct uio *uiop,
	stdata_t *stp,
	int32_t flag,
	mblk_t **mpp)
{
	mblk_t *mpctl = NULL;
	mblk_t *mpdata = NULL;
	int error;

	ASSERT(uiop != NULL);

	*mpp = NULL;
	/* Create control part, if any */
	if ((mctl != NULL) && (mctl->len >= 0)) {
		error = strmakectl(mctl, flag, uiop->uio_fmode, &mpctl);
		if (error)
			return (error);
	}
	/* Create data part, if any */
	if (*iosize >= 0) {
		error = strmakedata(iosize, uiop, stp, flag, &mpdata);
		if (error) {
			freemsg(mpctl);
			return (error);
		}
	}
	if (mpctl != NULL) {
		if (mpdata != NULL)
			linkb(mpctl, mpdata);
		*mpp = mpctl;
	} else {
		*mpp = mpdata;
	}
	return (0);
}

/*
 * Make the control part of a protocol message given a control buffer.
 * n.b., this can block; be careful of what locks you hold when calling it.
 */
int
strmakectl(
	struct strbuf *mctl,
	int32_t flag,
	int32_t fflag,
	mblk_t **mpp)
{
	mblk_t *bp = NULL;
	unsigned char msgtype;
	int error = 0;
	cred_t *cr = CRED();

	/* We do not support interrupt threads using the stream head to send */
	ASSERT(cr != NULL);

	*mpp = NULL;
	/*
	 * Create control part of message, if any.
	 */
	if ((mctl != NULL) && (mctl->len >= 0)) {
		caddr_t base;
		int ctlcount;
		int allocsz;

		if (flag & RS_HIPRI)
			msgtype = M_PCPROTO;
		else
			msgtype = M_PROTO;

		ctlcount = mctl->len;
		base = mctl->buf;

		/*
		 * Give modules a better chance to reuse M_PROTO/M_PCPROTO
		 * blocks by increasing the size to something more usable.
		 */
		allocsz = MAX(ctlcount, 64);

		/*
		 * Range checking has already been done; simply try
		 * to allocate a message block for the ctl part.
		 */
		while ((bp = allocb_cred(allocsz, cr,
		    curproc->p_pid)) == NULL) {
			if (fflag & (FNDELAY|FNONBLOCK))
				return (EAGAIN);
			if (error = strwaitbuf(allocsz, BPRI_MED))
				return (error);
		}

		bp->b_datap->db_type = msgtype;
		if (copyin(base, bp->b_wptr, ctlcount)) {
			freeb(bp);
			return (EFAULT);
		}
		bp->b_wptr += ctlcount;
	}
	*mpp = bp;
	return (0);
}

/*
 * Make a protocol message given data buffers.
 * n.b., this can block; be careful of what locks you hold when calling it.
 *
 * If sd_maxblk is less than *iosize this routine can fail part way through
 * (due to an allocation failure). In this case on return *iosize will contain
 * the amount that was consumed. Otherwise *iosize will not be modified
 * i.e. it will contain the amount that was consumed.
 */
int
strmakedata(
	ssize_t   *iosize,
	struct uio *uiop,
	stdata_t *stp,
	int32_t flag,
	mblk_t **mpp)
{
	mblk_t *mp = NULL;
	mblk_t *bp;
	int wroff = (int)stp->sd_wroff;
	int tail_len = (int)stp->sd_tail;
	int extra = wroff + tail_len;
	int error = 0;
	ssize_t maxblk;
	ssize_t count = *iosize;
	cred_t *cr;

	*mpp = NULL;
	if (count < 0)
		return (0);

	/* We do not support interrupt threads using the stream head to send */
	cr = CRED();
	ASSERT(cr != NULL);

	maxblk = stp->sd_maxblk;
	if (maxblk == INFPSZ)
		maxblk = count;

	/*
	 * Create data part of message, if any.
	 */
	do {
		ssize_t size;
		dblk_t  *dp;

		ASSERT(uiop);

		size = MIN(count, maxblk);

		while ((bp = allocb_cred(size + extra, cr,
		    curproc->p_pid)) == NULL) {
			error = EAGAIN;
			if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
			    (error = strwaitbuf(size + extra, BPRI_MED)) != 0) {
				if (count == *iosize) {
					freemsg(mp);
					return (error);
				} else {
					*iosize -= count;
					*mpp = mp;
					return (0);
				}
			}
		}
		dp = bp->b_datap;
		dp->db_cpid = curproc->p_pid;
		ASSERT(wroff <= dp->db_lim - bp->b_wptr);
		bp->b_wptr = bp->b_rptr = bp->b_rptr + wroff;

		if (flag & STRUIO_POSTPONE) {
			/*
			 * Setup the stream uio portion of the
			 * dblk for subsequent use by struioget().
			 */
			dp->db_struioflag = STRUIO_SPEC;
			dp->db_cksumstart = 0;
			dp->db_cksumstuff = 0;
			dp->db_cksumend = size;
			*(long long *)dp->db_struioun.data = 0ll;
			bp->b_wptr += size;
		} else {
			if (stp->sd_copyflag & STRCOPYCACHED)
				uiop->uio_extflg |= UIO_COPY_CACHED;

			if (size != 0) {
				error = uiomove(bp->b_wptr, size, UIO_WRITE,
				    uiop);
				if (error != 0) {
					freeb(bp);
					freemsg(mp);
					return (error);
				}
			}
			bp->b_wptr += size;

			if (stp->sd_wputdatafunc != NULL) {
				mblk_t *newbp;

				newbp = (stp->sd_wputdatafunc)(stp->sd_vnode,
				    bp, NULL, NULL, NULL, NULL);
				if (newbp == NULL) {
					freeb(bp);
					freemsg(mp);
					return (ECOMM);
				}
				bp = newbp;
			}
		}

		count -= size;

		if (mp == NULL)
			mp = bp;
		else
			linkb(mp, bp);
	} while (count > 0);

	*mpp = mp;
	return (0);
}

/*
 * Wait for a buffer to become available. Return non-zero errno
 * if not able to wait, 0 if buffer is probably there.
 */
int
strwaitbuf(size_t size, int pri)
{
	bufcall_id_t id;

	mutex_enter(&bcall_monitor);
	if ((id = bufcall(size, pri, (void (*)(void *))cv_broadcast,
	    &ttoproc(curthread)->p_flag_cv)) == 0) {
		mutex_exit(&bcall_monitor);
		return (ENOSR);
	}
	if (!cv_wait_sig(&(ttoproc(curthread)->p_flag_cv), &bcall_monitor)) {
		unbufcall(id);
		mutex_exit(&bcall_monitor);
		return (EINTR);
	}
	unbufcall(id);
	mutex_exit(&bcall_monitor);
	return (0);
}

/*
 * This function waits for a read or write event to happen on a stream.
 * fmode can specify FNDELAY and/or FNONBLOCK.
 * The timeout is in ms with -1 meaning infinite.
 * The flag values work as follows:
 *	READWAIT	Check for read side errors, send M_READ
 *	GETWAIT		Check for read side errors, no M_READ
 *	WRITEWAIT	Check for write side errors.
 *	NOINTR		Do not return error if nonblocking or timeout.
 * 	STR_NOERROR	Ignore all errors except STPLEX.
 *	STR_NOSIG	Ignore/hold signals during the duration of the call.
 *	STR_PEEK	Pass through the strgeterr().
 */
int
strwaitq(stdata_t *stp, int flag, ssize_t count, int fmode, clock_t timout,
    int *done)
{
	int slpflg, errs;
	int error;
	kcondvar_t *sleepon;
	mblk_t *mp;
	ssize_t *rd_count;
	clock_t rval;

	ASSERT(MUTEX_HELD(&stp->sd_lock));
	if ((flag & READWAIT) || (flag & GETWAIT)) {
		slpflg = RSLEEP;
		sleepon = &_RD(stp->sd_wrq)->q_wait;
		errs = STRDERR|STPLEX;
	} else {
		slpflg = WSLEEP;
		sleepon = &stp->sd_wrq->q_wait;
		errs = STWRERR|STRHUP|STPLEX;
	}
	if (flag & STR_NOERROR)
		errs = STPLEX;

	if (stp->sd_wakeq & slpflg) {
		/*
		 * A strwakeq() is pending, no need to sleep.
		 */
		stp->sd_wakeq &= ~slpflg;
		*done = 0;
		return (0);
	}

	if (stp->sd_flag & errs) {
		/*
		 * Check for errors before going to sleep since the
		 * caller might not have checked this while holding
		 * sd_lock.
		 */
		error = strgeterr(stp, errs, (flag & STR_PEEK));
		if (error != 0) {
			*done = 1;
			return (error);
		}
	}

	/*
	 * If any module downstream has requested read notification
	 * by setting SNDMREAD flag using M_SETOPTS, send a message
	 * down stream.
	 */
	if ((flag & READWAIT) && (stp->sd_flag & SNDMREAD)) {
		mutex_exit(&stp->sd_lock);
		if (!(mp = allocb_wait(sizeof (ssize_t), BPRI_MED,
		    (flag & STR_NOSIG), &error))) {
			mutex_enter(&stp->sd_lock);
			*done = 1;
			return (error);
		}
		mp->b_datap->db_type = M_READ;
		rd_count = (ssize_t *)mp->b_wptr;
		*rd_count = count;
		mp->b_wptr += sizeof (ssize_t);
		/*
		 * Send the number of bytes requested by the
		 * read as the argument to M_READ.
		 */
		stream_willservice(stp);
		putnext(stp->sd_wrq, mp);
		stream_runservice(stp);
		mutex_enter(&stp->sd_lock);

		/*
		 * If any data arrived due to inline processing
		 * of putnext(), don't sleep.
		 */
		if (_RD(stp->sd_wrq)->q_first != NULL) {
			*done = 0;
			return (0);
		}
	}

	if (fmode & (FNDELAY|FNONBLOCK)) {
		if (!(flag & NOINTR))
			error = EAGAIN;
		else
			error = 0;
		*done = 1;
		return (error);
	}

	stp->sd_flag |= slpflg;
	TRACE_5(TR_FAC_STREAMS_FR, TR_STRWAITQ_WAIT2,
	    "strwaitq sleeps (2):%p, %X, %lX, %X, %p",
	    stp, flag, count, fmode, done);

	rval = str_cv_wait(sleepon, &stp->sd_lock, timout, flag & STR_NOSIG);
	if (rval > 0) {
		/* EMPTY */
		TRACE_5(TR_FAC_STREAMS_FR, TR_STRWAITQ_WAKE2,
		    "strwaitq awakes(2):%X, %X, %X, %X, %X",
		    stp, flag, count, fmode, done);
	} else if (rval == 0) {
		TRACE_5(TR_FAC_STREAMS_FR, TR_STRWAITQ_INTR2,
		    "strwaitq interrupt #2:%p, %X, %lX, %X, %p",
		    stp, flag, count, fmode, done);
		stp->sd_flag &= ~slpflg;
		cv_broadcast(sleepon);
		if (!(flag & NOINTR))
			error = EINTR;
		else
			error = 0;
		*done = 1;
		return (error);
	} else {
		/* timeout */
		TRACE_5(TR_FAC_STREAMS_FR, TR_STRWAITQ_TIME,
		    "strwaitq timeout:%p, %X, %lX, %X, %p",
		    stp, flag, count, fmode, done);
		*done = 1;
		if (!(flag & NOINTR))
			return (ETIME);
		else
			return (0);
	}
	/*
	 * If the caller implements delayed errors (i.e. queued after data)
	 * we can not check for errors here since data as well as an
	 * error might have arrived at the stream head. We return to
	 * have the caller check the read queue before checking for errors.
	 */
	if ((stp->sd_flag & errs) && !(flag & STR_DELAYERR)) {
		error = strgeterr(stp, errs, (flag & STR_PEEK));
		if (error != 0) {
			*done = 1;
			return (error);
		}
	}
	*done = 0;
	return (0);
}

/*
 * Perform job control discipline access checks.
 * Return 0 for success and the errno for failure.
 */

#define	cantsend(p, t, sig) \
	(sigismember(&(p)->p_ignore, sig) || signal_is_blocked((t), sig))

int
straccess(struct stdata *stp, enum jcaccess mode)
{
	extern kcondvar_t lbolt_cv;	/* XXX: should be in a header file */
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	sess_t *sp;

	ASSERT(mutex_owned(&stp->sd_lock));

	if (stp->sd_sidp == NULL || stp->sd_vnode->v_type == VFIFO)
		return (0);

	mutex_enter(&p->p_lock);		/* protects p_pgidp */

	for (;;) {
		mutex_enter(&p->p_splock);	/* protects p->p_sessp */
		sp = p->p_sessp;
		mutex_enter(&sp->s_lock);	/* protects sp->* */

		/*
		 * If this is not the calling process's controlling terminal
		 * or if the calling process is already in the foreground
		 * then allow access.
		 */
		if (sp->s_dev != stp->sd_vnode->v_rdev ||
		    p->p_pgidp == stp->sd_pgidp) {
			mutex_exit(&sp->s_lock);
			mutex_exit(&p->p_splock);
			mutex_exit(&p->p_lock);
			return (0);
		}

		/*
		 * Check to see if controlling terminal has been deallocated.
		 */
		if (sp->s_vp == NULL) {
			if (!cantsend(p, t, SIGHUP))
				sigtoproc(p, t, SIGHUP);
			mutex_exit(&sp->s_lock);
			mutex_exit(&p->p_splock);
			mutex_exit(&p->p_lock);
			return (EIO);
		}

		mutex_exit(&sp->s_lock);
		mutex_exit(&p->p_splock);

		if (mode == JCGETP) {
			mutex_exit(&p->p_lock);
			return (0);
		}

		if (mode == JCREAD) {
			if (p->p_detached || cantsend(p, t, SIGTTIN)) {
				mutex_exit(&p->p_lock);
				return (EIO);
			}
			mutex_exit(&p->p_lock);
			mutex_exit(&stp->sd_lock);
			pgsignal(p->p_pgidp, SIGTTIN);
			mutex_enter(&stp->sd_lock);
			mutex_enter(&p->p_lock);
		} else {  /* mode == JCWRITE or JCSETP */
			if ((mode == JCWRITE && !(stp->sd_flag & STRTOSTOP)) ||
			    cantsend(p, t, SIGTTOU)) {
				mutex_exit(&p->p_lock);
				return (0);
			}
			if (p->p_detached) {
				mutex_exit(&p->p_lock);
				return (EIO);
			}
			mutex_exit(&p->p_lock);
			mutex_exit(&stp->sd_lock);
			pgsignal(p->p_pgidp, SIGTTOU);
			mutex_enter(&stp->sd_lock);
			mutex_enter(&p->p_lock);
		}

		/*
		 * We call cv_wait_sig_swap() to cause the appropriate
		 * action for the jobcontrol signal to take place.
		 * If the signal is being caught, we will take the
		 * EINTR error return.  Otherwise, the default action
		 * of causing the process to stop will take place.
		 * In this case, we rely on the periodic cv_broadcast() on
		 * &lbolt_cv to wake us up to loop around and test again.
		 * We can't get here if the signal is ignored or
		 * if the current thread is blocking the signal.
		 */
		mutex_exit(&stp->sd_lock);
		if (!cv_wait_sig_swap(&lbolt_cv, &p->p_lock)) {
			mutex_exit(&p->p_lock);
			mutex_enter(&stp->sd_lock);
			return (EINTR);
		}
		mutex_exit(&p->p_lock);
		mutex_enter(&stp->sd_lock);
		mutex_enter(&p->p_lock);
	}
}

/*
 * Return size of message of block type (bp->b_datap->db_type)
 */
size_t
xmsgsize(mblk_t *bp)
{
	unsigned char type;
	size_t count = 0;

	type = bp->b_datap->db_type;

	for (; bp; bp = bp->b_cont) {
		if (type != bp->b_datap->db_type)
			break;
		ASSERT(bp->b_wptr >= bp->b_rptr);
		count += bp->b_wptr - bp->b_rptr;
	}
	return (count);
}

/*
 * Allocate a stream head.
 */
struct stdata *
shalloc(queue_t *qp)
{
	stdata_t *stp;

	stp = kmem_cache_alloc(stream_head_cache, KM_SLEEP);

	stp->sd_wrq = _WR(qp);
	stp->sd_strtab = NULL;
	stp->sd_iocid = 0;
	stp->sd_mate = NULL;
	stp->sd_freezer = NULL;
	stp->sd_refcnt = 0;
	stp->sd_wakeq = 0;
	stp->sd_anchor = 0;
	stp->sd_struiowrq = NULL;
	stp->sd_struiordq = NULL;
	stp->sd_struiodnak = 0;
	stp->sd_struionak = NULL;
	stp->sd_t_audit_data = NULL;
	stp->sd_rput_opt = 0;
	stp->sd_wput_opt = 0;
	stp->sd_read_opt = 0;
	stp->sd_rprotofunc = strrput_proto;
	stp->sd_rmiscfunc = strrput_misc;
	stp->sd_rderrfunc = stp->sd_wrerrfunc = NULL;
	stp->sd_rputdatafunc = stp->sd_wputdatafunc = NULL;
	stp->sd_ciputctrl = NULL;
	stp->sd_nciputctrl = 0;
	stp->sd_qhead = NULL;
	stp->sd_qtail = NULL;
	stp->sd_servid = NULL;
	stp->sd_nqueues = 0;
	stp->sd_svcflags = 0;
	stp->sd_copyflag = 0;

	return (stp);
}

/*
 * Free a stream head.
 */
void
shfree(stdata_t *stp)
{
	ASSERT(MUTEX_NOT_HELD(&stp->sd_lock));

	stp->sd_wrq = NULL;

	mutex_enter(&stp->sd_qlock);
	while (stp->sd_svcflags & STRS_SCHEDULED) {
		STRSTAT(strwaits);
		cv_wait(&stp->sd_qcv, &stp->sd_qlock);
	}
	mutex_exit(&stp->sd_qlock);

	if (stp->sd_ciputctrl != NULL) {
		ASSERT(stp->sd_nciputctrl == n_ciputctrl - 1);
		SUMCHECK_CIPUTCTRL_COUNTS(stp->sd_ciputctrl,
		    stp->sd_nciputctrl, 0);
		ASSERT(ciputctrl_cache != NULL);
		kmem_cache_free(ciputctrl_cache, stp->sd_ciputctrl);
		stp->sd_ciputctrl = NULL;
		stp->sd_nciputctrl = 0;
	}
	ASSERT(stp->sd_qhead == NULL);
	ASSERT(stp->sd_qtail == NULL);
	ASSERT(stp->sd_nqueues == 0);
	kmem_cache_free(stream_head_cache, stp);
}

/*
 * Allocate a pair of queues and a syncq for the pair
 */
queue_t *
allocq(void)
{
	queinfo_t *qip;
	queue_t *qp, *wqp;
	syncq_t	*sq;

	qip = kmem_cache_alloc(queue_cache, KM_SLEEP);

	qp = &qip->qu_rqueue;
	wqp = &qip->qu_wqueue;
	sq = &qip->qu_syncq;

	qp->q_last	= NULL;
	qp->q_next	= NULL;
	qp->q_ptr	= NULL;
	qp->q_flag	= QUSE | QREADR;
	qp->q_bandp	= NULL;
	qp->q_stream	= NULL;
	qp->q_syncq	= sq;
	qp->q_nband	= 0;
	qp->q_nfsrv	= NULL;
	qp->q_draining	= 0;
	qp->q_syncqmsgs	= 0;
	qp->q_spri	= 0;
	qp->q_qtstamp	= 0;
	qp->q_sqtstamp	= 0;
	qp->q_fp	= NULL;

	wqp->q_last	= NULL;
	wqp->q_next	= NULL;
	wqp->q_ptr	= NULL;
	wqp->q_flag	= QUSE;
	wqp->q_bandp	= NULL;
	wqp->q_stream	= NULL;
	wqp->q_syncq	= sq;
	wqp->q_nband	= 0;
	wqp->q_nfsrv	= NULL;
	wqp->q_draining	= 0;
	wqp->q_syncqmsgs = 0;
	wqp->q_qtstamp	= 0;
	wqp->q_sqtstamp	= 0;
	wqp->q_spri	= 0;

	sq->sq_count	= 0;
	sq->sq_rmqcount	= 0;
	sq->sq_flags	= 0;
	sq->sq_type	= 0;
	sq->sq_callbflags = 0;
	sq->sq_cancelid	= 0;
	sq->sq_ciputctrl = NULL;
	sq->sq_nciputctrl = 0;
	sq->sq_needexcl = 0;
	sq->sq_svcflags = 0;

	return (qp);
}

/*
 * Free a pair of queues and the "attached" syncq.
 * Discard any messages left on the syncq(s), remove the syncq(s) from the
 * outer perimeter, and free the syncq(s) if they are not the "attached" syncq.
 */
void
freeq(queue_t *qp)
{
	qband_t *qbp, *nqbp;
	syncq_t *sq, *outer;
	queue_t *wqp = _WR(qp);

	ASSERT(qp->q_flag & QREADR);

	/*
	 * If a previously dispatched taskq job is scheduled to run
	 * sync_service() or a service routine is scheduled for the
	 * queues about to be freed, wait here until all service is
	 * done on the queue and all associated queues and syncqs.
	 */
	wait_svc(qp);

	(void) flush_syncq(qp->q_syncq, qp);
	(void) flush_syncq(wqp->q_syncq, wqp);
	ASSERT(qp->q_syncqmsgs == 0 && wqp->q_syncqmsgs == 0);

	/*
	 * Flush the queues before q_next is set to NULL This is needed
	 * in order to backenable any downstream queue before we go away.
	 * Note: we are already removed from the stream so that the
	 * backenabling will not cause any messages to be delivered to our
	 * put procedures.
	 */
	flushq(qp, FLUSHALL);
	flushq(wqp, FLUSHALL);

	/* Tidy up - removeq only does a half-remove from stream */
	qp->q_next = wqp->q_next = NULL;
	ASSERT(!(qp->q_flag & QENAB));
	ASSERT(!(wqp->q_flag & QENAB));

	outer = qp->q_syncq->sq_outer;
	if (outer != NULL) {
		outer_remove(outer, qp->q_syncq);
		if (wqp->q_syncq != qp->q_syncq)
			outer_remove(outer, wqp->q_syncq);
	}
	/*
	 * Free any syncqs that are outside what allocq returned.
	 */
	if (qp->q_syncq != SQ(qp) && !(qp->q_flag & QPERMOD))
		free_syncq(qp->q_syncq);
	if (qp->q_syncq != wqp->q_syncq && wqp->q_syncq != SQ(qp))
		free_syncq(wqp->q_syncq);

	ASSERT((qp->q_sqflags & (Q_SQQUEUED | Q_SQDRAINING)) == 0);
	ASSERT((wqp->q_sqflags & (Q_SQQUEUED | Q_SQDRAINING)) == 0);
	ASSERT(MUTEX_NOT_HELD(QLOCK(qp)));
	ASSERT(MUTEX_NOT_HELD(QLOCK(wqp)));
	sq = SQ(qp);
	ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
	ASSERT(sq->sq_head == NULL && sq->sq_tail == NULL);
	ASSERT(sq->sq_outer == NULL);
	ASSERT(sq->sq_onext == NULL && sq->sq_oprev == NULL);
	ASSERT(sq->sq_callbpend == NULL);
	ASSERT(sq->sq_needexcl == 0);

	if (sq->sq_ciputctrl != NULL) {
		ASSERT(sq->sq_nciputctrl == n_ciputctrl - 1);
		SUMCHECK_CIPUTCTRL_COUNTS(sq->sq_ciputctrl,
		    sq->sq_nciputctrl, 0);
		ASSERT(ciputctrl_cache != NULL);
		kmem_cache_free(ciputctrl_cache, sq->sq_ciputctrl);
		sq->sq_ciputctrl = NULL;
		sq->sq_nciputctrl = 0;
	}

	ASSERT(qp->q_first == NULL && wqp->q_first == NULL);
	ASSERT(qp->q_count == 0 && wqp->q_count == 0);
	ASSERT(qp->q_mblkcnt == 0 && wqp->q_mblkcnt == 0);

	qp->q_flag &= ~QUSE;
	wqp->q_flag &= ~QUSE;

	/* NOTE: Uncomment the assert below once bugid 1159635 is fixed. */
	/* ASSERT((qp->q_flag & QWANTW) == 0 && (wqp->q_flag & QWANTW) == 0); */

	qbp = qp->q_bandp;
	while (qbp) {
		nqbp = qbp->qb_next;
		freeband(qbp);
		qbp = nqbp;
	}
	qbp = wqp->q_bandp;
	while (qbp) {
		nqbp = qbp->qb_next;
		freeband(qbp);
		qbp = nqbp;
	}
	kmem_cache_free(queue_cache, qp);
}

/*
 * Allocate a qband structure.
 */
qband_t *
allocband(void)
{
	qband_t *qbp;

	qbp = kmem_cache_alloc(qband_cache, KM_NOSLEEP);
	if (qbp == NULL)
		return (NULL);

	qbp->qb_next	= NULL;
	qbp->qb_count	= 0;
	qbp->qb_mblkcnt	= 0;
	qbp->qb_first	= NULL;
	qbp->qb_last	= NULL;
	qbp->qb_flag	= 0;

	return (qbp);
}

/*
 * Free a qband structure.
 */
void
freeband(qband_t *qbp)
{
	kmem_cache_free(qband_cache, qbp);
}

/*
 * Just like putnextctl(9F), except that allocb_wait() is used.
 *
 * Consolidation Private, and of course only callable from the stream head or
 * routines that may block.
 */
int
putnextctl_wait(queue_t *q, int type)
{
	mblk_t *bp;
	int error;

	if ((datamsg(type) && (type != M_DELAY)) ||
	    (bp = allocb_wait(0, BPRI_HI, 0, &error)) == NULL)
		return (0);

	bp->b_datap->db_type = (unsigned char)type;
	putnext(q, bp);
	return (1);
}

/*
 * Run any possible bufcalls.
 */
void
runbufcalls(void)
{
	strbufcall_t *bcp;

	mutex_enter(&bcall_monitor);
	mutex_enter(&strbcall_lock);

	if (strbcalls.bc_head) {
		size_t count;
		int nevent;

		/*
		 * count how many events are on the list
		 * now so we can check to avoid looping
		 * in low memory situations
		 */
		nevent = 0;
		for (bcp = strbcalls.bc_head; bcp; bcp = bcp->bc_next)
			nevent++;

		/*
		 * get estimate of available memory from kmem_avail().
		 * awake all bufcall functions waiting for
		 * memory whose request could be satisfied
		 * by 'count' memory and let 'em fight for it.
		 */
		count = kmem_avail();
		while ((bcp = strbcalls.bc_head) != NULL && nevent) {
			STRSTAT(bufcalls);
			--nevent;
			if (bcp->bc_size <= count) {
				bcp->bc_executor = curthread;
				mutex_exit(&strbcall_lock);
				(*bcp->bc_func)(bcp->bc_arg);
				mutex_enter(&strbcall_lock);
				bcp->bc_executor = NULL;
				cv_broadcast(&bcall_cv);
				strbcalls.bc_head = bcp->bc_next;
				kmem_free(bcp, sizeof (strbufcall_t));
			} else {
				/*
				 * too big, try again later - note
				 * that nevent was decremented above
				 * so we won't retry this one on this
				 * iteration of the loop
				 */
				if (bcp->bc_next != NULL) {
					strbcalls.bc_head = bcp->bc_next;
					bcp->bc_next = NULL;
					strbcalls.bc_tail->bc_next = bcp;
					strbcalls.bc_tail = bcp;
				}
			}
		}
		if (strbcalls.bc_head == NULL)
			strbcalls.bc_tail = NULL;
	}

	mutex_exit(&strbcall_lock);
	mutex_exit(&bcall_monitor);
}


/*
 * Actually run queue's service routine.
 */
static void
runservice(queue_t *q)
{
	qband_t *qbp;

	ASSERT(q->q_qinfo->qi_srvp);
again:
	entersq(q->q_syncq, SQ_SVC);
	TRACE_1(TR_FAC_STREAMS_FR, TR_QRUNSERVICE_START,
	    "runservice starts:%p", q);

	if (!(q->q_flag & QWCLOSE))
		(*q->q_qinfo->qi_srvp)(q);

	TRACE_1(TR_FAC_STREAMS_FR, TR_QRUNSERVICE_END,
	    "runservice ends:(%p)", q);

	leavesq(q->q_syncq, SQ_SVC);

	mutex_enter(QLOCK(q));
	if (q->q_flag & QENAB) {
		q->q_flag &= ~QENAB;
		mutex_exit(QLOCK(q));
		goto again;
	}
	q->q_flag &= ~QINSERVICE;
	q->q_flag &= ~QBACK;
	for (qbp = q->q_bandp; qbp; qbp = qbp->qb_next)
		qbp->qb_flag &= ~QB_BACK;
	/*
	 * Wakeup thread waiting for the service procedure
	 * to be run (strclose and qdetach).
	 */
	cv_broadcast(&q->q_wait);

	mutex_exit(QLOCK(q));
}

/*
 * Background processing of bufcalls.
 */
void
streams_bufcall_service(void)
{
	callb_cpr_t	cprinfo;

	CALLB_CPR_INIT(&cprinfo, &strbcall_lock, callb_generic_cpr,
	    "streams_bufcall_service");

	mutex_enter(&strbcall_lock);

	for (;;) {
		if (strbcalls.bc_head != NULL && kmem_avail() > 0) {
			mutex_exit(&strbcall_lock);
			runbufcalls();
			mutex_enter(&strbcall_lock);
		}
		if (strbcalls.bc_head != NULL) {
			STRSTAT(bcwaits);
			/* Wait for memory to become available */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			(void) cv_reltimedwait(&memavail_cv, &strbcall_lock,
			    SEC_TO_TICK(60), TR_CLOCK_TICK);
			CALLB_CPR_SAFE_END(&cprinfo, &strbcall_lock);
		}

		/* Wait for new work to arrive */
		if (strbcalls.bc_head == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&strbcall_cv, &strbcall_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &strbcall_lock);
		}
	}
}

/*
 * Background processing of streams background tasks which failed
 * taskq_dispatch.
 */
static void
streams_qbkgrnd_service(void)
{
	callb_cpr_t cprinfo;
	queue_t *q;

	CALLB_CPR_INIT(&cprinfo, &service_queue, callb_generic_cpr,
	    "streams_bkgrnd_service");

	mutex_enter(&service_queue);

	for (;;) {
		/*
		 * Wait for work to arrive.
		 */
		while ((freebs_list == NULL) && (qhead == NULL)) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&services_to_run, &service_queue);
			CALLB_CPR_SAFE_END(&cprinfo, &service_queue);
		}
		/*
		 * Handle all pending freebs requests to free memory.
		 */
		while (freebs_list != NULL) {
			mblk_t *mp = freebs_list;
			freebs_list = mp->b_next;
			mutex_exit(&service_queue);
			mblk_free(mp);
			mutex_enter(&service_queue);
		}
		/*
		 * Run pending queues.
		 */
		while (qhead != NULL) {
			DQ(q, qhead, qtail, q_link);
			ASSERT(q != NULL);
			mutex_exit(&service_queue);
			queue_service(q);
			mutex_enter(&service_queue);
		}
		ASSERT(qhead == NULL && qtail == NULL);
	}
}

/*
 * Background processing of streams background tasks which failed
 * taskq_dispatch.
 */
static void
streams_sqbkgrnd_service(void)
{
	callb_cpr_t cprinfo;
	syncq_t *sq;

	CALLB_CPR_INIT(&cprinfo, &service_queue, callb_generic_cpr,
	    "streams_sqbkgrnd_service");

	mutex_enter(&service_queue);

	for (;;) {
		/*
		 * Wait for work to arrive.
		 */
		while (sqhead == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&syncqs_to_run, &service_queue);
			CALLB_CPR_SAFE_END(&cprinfo, &service_queue);
		}

		/*
		 * Run pending syncqs.
		 */
		while (sqhead != NULL) {
			DQ(sq, sqhead, sqtail, sq_next);
			ASSERT(sq != NULL);
			ASSERT(sq->sq_svcflags & SQ_BGTHREAD);
			mutex_exit(&service_queue);
			syncq_service(sq);
			mutex_enter(&service_queue);
		}
	}
}

/*
 * Disable the syncq and wait for background syncq processing to complete.
 * If the syncq is placed on the sqhead/sqtail queue, try to remove it from the
 * list.
 */
void
wait_sq_svc(syncq_t *sq)
{
	mutex_enter(SQLOCK(sq));
	sq->sq_svcflags |= SQ_DISABLED;
	if (sq->sq_svcflags & SQ_BGTHREAD) {
		syncq_t *sq_chase;
		syncq_t *sq_curr;
		int removed;

		ASSERT(sq->sq_servcount == 1);
		mutex_enter(&service_queue);
		RMQ(sq, sqhead, sqtail, sq_next, sq_chase, sq_curr, removed);
		mutex_exit(&service_queue);
		if (removed) {
			sq->sq_svcflags &= ~SQ_BGTHREAD;
			sq->sq_servcount = 0;
			STRSTAT(sqremoved);
			goto done;
		}
	}
	while (sq->sq_servcount != 0) {
		sq->sq_flags |= SQ_WANTWAKEUP;
		cv_wait(&sq->sq_wait, SQLOCK(sq));
	}
done:
	mutex_exit(SQLOCK(sq));
}

/*
 * Put a syncq on the list of syncq's to be serviced by the sqthread.
 * Add the argument to the end of the sqhead list and set the flag
 * indicating this syncq has been enabled.  If it has already been
 * enabled, don't do anything.
 * This routine assumes that SQLOCK is held.
 * NOTE that the lock order is to have the SQLOCK first,
 * so if the service_syncq lock is held, we need to release it
 * before acquiring the SQLOCK (mostly relevant for the background
 * thread, and this seems to be common among the STREAMS global locks).
 * Note that the sq_svcflags are protected by the SQLOCK.
 */
void
sqenable(syncq_t *sq)
{
	/*
	 * This is probably not important except for where I believe it
	 * is being called.  At that point, it should be held (and it
	 * is a pain to release it just for this routine, so don't do
	 * it).
	 */
	ASSERT(MUTEX_HELD(SQLOCK(sq)));

	IMPLY(sq->sq_servcount == 0, sq->sq_next == NULL);
	IMPLY(sq->sq_next != NULL, sq->sq_svcflags & SQ_BGTHREAD);

	/*
	 * Do not put on list if background thread is scheduled or
	 * syncq is disabled.
	 */
	if (sq->sq_svcflags & (SQ_DISABLED | SQ_BGTHREAD))
		return;

	/*
	 * Check whether we should enable sq at all.
	 * Non PERMOD syncqs may be drained by at most one thread.
	 * PERMOD syncqs may be drained by several threads but we limit the
	 * total amount to the lesser of
	 *	Number of queues on the squeue and
	 *	Number of CPUs.
	 */
	if (sq->sq_servcount != 0) {
		if (((sq->sq_type & SQ_PERMOD) == 0) ||
		    (sq->sq_servcount >= MIN(sq->sq_nqueues, ncpus_online))) {
			STRSTAT(sqtoomany);
			return;
		}
	}

	sq->sq_tstamp = ddi_get_lbolt();
	STRSTAT(sqenables);

	/* Attempt a taskq dispatch */
	sq->sq_servid = (void *)taskq_dispatch(streams_taskq,
	    (task_func_t *)syncq_service, sq, TQ_NOSLEEP | TQ_NOQUEUE);
	if (sq->sq_servid != NULL) {
		sq->sq_servcount++;
		return;
	}

	/*
	 * This taskq dispatch failed, but a previous one may have succeeded.
	 * Don't try to schedule on the background thread whilst there is
	 * outstanding taskq processing.
	 */
	if (sq->sq_servcount != 0)
		return;

	/*
	 * System is low on resources and can't perform a non-sleeping
	 * dispatch. Schedule the syncq for a background thread and mark the
	 * syncq to avoid any further taskq dispatch attempts.
	 */
	mutex_enter(&service_queue);
	STRSTAT(taskqfails);
	ENQUEUE(sq, sqhead, sqtail, sq_next);
	sq->sq_svcflags |= SQ_BGTHREAD;
	sq->sq_servcount = 1;
	cv_signal(&syncqs_to_run);
	mutex_exit(&service_queue);
}

/*
 * Note: fifo_close() depends on the mblk_t on the queue being freed
 * asynchronously. The asynchronous freeing of messages breaks the
 * recursive call chain of fifo_close() while there are I_SENDFD type of
 * messages referring to other file pointers on the queue. Then when
 * closing pipes it can avoid stack overflow in case of daisy-chained
 * pipes, and also avoid deadlock in case of fifonode_t pairs (which
 * share the same fifolock_t).
 *
 * No need to kpreempt_disable to access cpu_seqid.  If we migrate and
 * the esb queue does not match the new CPU, that is OK.
 */
void
freebs_enqueue(mblk_t *mp, dblk_t *dbp)
{
	int qindex = CPU->cpu_seqid >> esbq_log2_cpus_per_q;
	esb_queue_t *eqp;

	ASSERT(dbp->db_mblk == mp);
	ASSERT(qindex < esbq_nelem);

	eqp = system_esbq_array;
	if (eqp != NULL) {
		eqp += qindex;
	} else {
		mutex_enter(&esbq_lock);
		if (kmem_ready && system_esbq_array == NULL)
			system_esbq_array = (esb_queue_t *)kmem_zalloc(
			    esbq_nelem * sizeof (esb_queue_t), KM_NOSLEEP);
		mutex_exit(&esbq_lock);
		eqp = system_esbq_array;
		if (eqp != NULL)
			eqp += qindex;
		else
			eqp = &system_esbq;
	}

	/*
	 * Check data sanity. The dblock should have non-empty free function.
	 * It is better to panic here then later when the dblock is freed
	 * asynchronously when the context is lost.
	 */
	if (dbp->db_frtnp->free_func == NULL) {
		panic("freebs_enqueue: dblock %p has a NULL free callback",
		    (void *)dbp);
	}

	mutex_enter(&eqp->eq_lock);
	/* queue the new mblk on the esballoc queue */
	if (eqp->eq_head == NULL) {
		eqp->eq_head = eqp->eq_tail = mp;
	} else {
		eqp->eq_tail->b_next = mp;
		eqp->eq_tail = mp;
	}
	eqp->eq_len++;

	/* If we're the first thread to reach the threshold, process */
	if (eqp->eq_len >= esbq_max_qlen &&
	    !(eqp->eq_flags & ESBQ_PROCESSING))
		esballoc_process_queue(eqp);

	esballoc_set_timer(eqp, esbq_timeout);
	mutex_exit(&eqp->eq_lock);
}

static void
esballoc_process_queue(esb_queue_t *eqp)
{
	mblk_t	*mp;

	ASSERT(MUTEX_HELD(&eqp->eq_lock));

	eqp->eq_flags |= ESBQ_PROCESSING;

	do {
		/*
		 * Detach the message chain for processing.
		 */
		mp = eqp->eq_head;
		eqp->eq_tail->b_next = NULL;
		eqp->eq_head = eqp->eq_tail = NULL;
		eqp->eq_len = 0;
		mutex_exit(&eqp->eq_lock);

		/*
		 * Process the message chain.
		 */
		esballoc_enqueue_mblk(mp);
		mutex_enter(&eqp->eq_lock);
	} while ((eqp->eq_len >= esbq_max_qlen) && (eqp->eq_len > 0));

	eqp->eq_flags &= ~ESBQ_PROCESSING;
}

/*
 * taskq callback routine to free esballoced mblk's
 */
static void
esballoc_mblk_free(mblk_t *mp)
{
	mblk_t	*nextmp;

	for (; mp != NULL; mp = nextmp) {
		nextmp = mp->b_next;
		mp->b_next = NULL;
		mblk_free(mp);
	}
}

static void
esballoc_enqueue_mblk(mblk_t *mp)
{

	if (taskq_dispatch(system_taskq, (task_func_t *)esballoc_mblk_free, mp,
	    TQ_NOSLEEP) == NULL) {
		mblk_t *first_mp = mp;
		/*
		 * System is low on resources and can't perform a non-sleeping
		 * dispatch. Schedule for a background thread.
		 */
		mutex_enter(&service_queue);
		STRSTAT(taskqfails);

		while (mp->b_next != NULL)
			mp = mp->b_next;

		mp->b_next = freebs_list;
		freebs_list = first_mp;
		cv_signal(&services_to_run);
		mutex_exit(&service_queue);
	}
}

static void
esballoc_timer(void *arg)
{
	esb_queue_t *eqp = arg;

	mutex_enter(&eqp->eq_lock);
	eqp->eq_flags &= ~ESBQ_TIMER;

	if (!(eqp->eq_flags & ESBQ_PROCESSING) &&
	    eqp->eq_len > 0)
		esballoc_process_queue(eqp);

	esballoc_set_timer(eqp, esbq_timeout);
	mutex_exit(&eqp->eq_lock);
}

static void
esballoc_set_timer(esb_queue_t *eqp, clock_t eq_timeout)
{
	ASSERT(MUTEX_HELD(&eqp->eq_lock));

	if (eqp->eq_len > 0 && !(eqp->eq_flags & ESBQ_TIMER)) {
		(void) timeout(esballoc_timer, eqp, eq_timeout);
		eqp->eq_flags |= ESBQ_TIMER;
	}
}

/*
 * Setup esbq array length based upon NCPU scaled by CPUs per
 * queue. Use static system_esbq until kmem_ready and we can
 * create an array in freebs_enqueue().
 */
void
esballoc_queue_init(void)
{
	esbq_log2_cpus_per_q = highbit(esbq_cpus_per_q - 1);
	esbq_cpus_per_q = 1 << esbq_log2_cpus_per_q;
	esbq_nelem = howmany(NCPU, esbq_cpus_per_q);
	system_esbq.eq_len = 0;
	system_esbq.eq_head = system_esbq.eq_tail = NULL;
	system_esbq.eq_flags = 0;
}

/*
 * Set the QBACK or QB_BACK flag in the given queue for
 * the given priority band.
 */
void
setqback(queue_t *q, unsigned char pri)
{
	int i;
	qband_t *qbp;
	qband_t **qbpp;

	ASSERT(MUTEX_HELD(QLOCK(q)));
	if (pri != 0) {
		if (pri > q->q_nband) {
			qbpp = &q->q_bandp;
			while (*qbpp)
				qbpp = &(*qbpp)->qb_next;
			while (pri > q->q_nband) {
				if ((*qbpp = allocband()) == NULL) {
					cmn_err(CE_WARN,
					    "setqback: can't allocate qband\n");
					return;
				}
				(*qbpp)->qb_hiwat = q->q_hiwat;
				(*qbpp)->qb_lowat = q->q_lowat;
				q->q_nband++;
				qbpp = &(*qbpp)->qb_next;
			}
		}
		qbp = q->q_bandp;
		i = pri;
		while (--i)
			qbp = qbp->qb_next;
		qbp->qb_flag |= QB_BACK;
	} else {
		q->q_flag |= QBACK;
	}
}

int
strcopyin(void *from, void *to, size_t len, int copyflag)
{
	if (copyflag & U_TO_K) {
		ASSERT((copyflag & K_TO_K) == 0);
		if (copyin(from, to, len))
			return (EFAULT);
	} else {
		ASSERT(copyflag & K_TO_K);
		bcopy(from, to, len);
	}
	return (0);
}

int
strcopyout(void *from, void *to, size_t len, int copyflag)
{
	if (copyflag & U_TO_K) {
		if (copyout(from, to, len))
			return (EFAULT);
	} else {
		ASSERT(copyflag & K_TO_K);
		bcopy(from, to, len);
	}
	return (0);
}

/*
 * strsignal_nolock() posts a signal to the process(es) at the stream head.
 * It assumes that the stream head lock is already held, whereas strsignal()
 * acquires the lock first.  This routine was created because a few callers
 * release the stream head lock before calling only to re-acquire it after
 * it returns.
 */
void
strsignal_nolock(stdata_t *stp, int sig, uchar_t band)
{
	ASSERT(MUTEX_HELD(&stp->sd_lock));
	switch (sig) {
	case SIGPOLL:
		if (stp->sd_sigflags & S_MSG)
			strsendsig(stp->sd_siglist, S_MSG, band, 0);
		break;
	default:
		if (stp->sd_pgidp)
			pgsignal(stp->sd_pgidp, sig);
		break;
	}
}

void
strsignal(stdata_t *stp, int sig, int32_t band)
{
	TRACE_3(TR_FAC_STREAMS_FR, TR_SENDSIG,
	    "strsignal:%p, %X, %X", stp, sig, band);

	mutex_enter(&stp->sd_lock);
	switch (sig) {
	case SIGPOLL:
		if (stp->sd_sigflags & S_MSG)
			strsendsig(stp->sd_siglist, S_MSG, (uchar_t)band, 0);
		break;

	default:
		if (stp->sd_pgidp) {
			pgsignal(stp->sd_pgidp, sig);
		}
		break;
	}
	mutex_exit(&stp->sd_lock);
}

void
strhup(stdata_t *stp)
{
	ASSERT(mutex_owned(&stp->sd_lock));
	pollwakeup(&stp->sd_pollist, POLLHUP);
	if (stp->sd_sigflags & S_HANGUP)
		strsendsig(stp->sd_siglist, S_HANGUP, 0, 0);
}

/*
 * Backenable the first queue upstream from `q' with a service procedure.
 */
void
backenable(queue_t *q, uchar_t pri)
{
	queue_t	*nq;

	/*
	 * Our presence might not prevent other modules in our own
	 * stream from popping/pushing since the caller of getq might not
	 * have a claim on the queue (some drivers do a getq on somebody
	 * else's queue - they know that the queue itself is not going away
	 * but the framework has to guarantee q_next in that stream).
	 */
	claimstr(q);

	/* Find nearest back queue with service proc */
	for (nq = backq(q); nq && !nq->q_qinfo->qi_srvp; nq = backq(nq)) {
		ASSERT(STRMATED(q->q_stream) || STREAM(q) == STREAM(nq));
	}

	if (nq) {
		kthread_t *freezer;
		/*
		 * backenable can be called either with no locks held
		 * or with the stream frozen (the latter occurs when a module
		 * calls rmvq with the stream frozen). If the stream is frozen
		 * by the caller the caller will hold all qlocks in the stream.
		 * Note that a frozen stream doesn't freeze a mated stream,
		 * so we explicitly check for that.
		 */
		freezer = STREAM(q)->sd_freezer;
		if (freezer != curthread || STREAM(q) != STREAM(nq)) {
			mutex_enter(QLOCK(nq));
		}
#ifdef DEBUG
		else {
			ASSERT(frozenstr(q));
			ASSERT(MUTEX_HELD(QLOCK(q)));
			ASSERT(MUTEX_HELD(QLOCK(nq)));
		}
#endif
		setqback(nq, pri);
		qenable_locked(nq);
		if (freezer != curthread || STREAM(q) != STREAM(nq))
			mutex_exit(QLOCK(nq));
	}
	releasestr(q);
}

/*
 * Return the appropriate errno when one of flags_to_check is set
 * in sd_flags. Uses the exported error routines if they are set.
 * Will return 0 if non error is set (or if the exported error routines
 * do not return an error).
 *
 * If there is both a read and write error to check, we prefer the read error.
 * Also, give preference to recorded errno's over the error functions.
 * The flags that are handled are:
 *	STPLEX		return EINVAL
 *	STRDERR		return sd_rerror (and clear if STRDERRNONPERSIST)
 *	STWRERR		return sd_werror (and clear if STWRERRNONPERSIST)
 *	STRHUP		return sd_werror
 *
 * If the caller indicates that the operation is a peek, a nonpersistent error
 * is not cleared.
 */
int
strgeterr(stdata_t *stp, int32_t flags_to_check, int ispeek)
{
	int32_t sd_flag = stp->sd_flag & flags_to_check;
	int error = 0;

	ASSERT(MUTEX_HELD(&stp->sd_lock));
	ASSERT((flags_to_check & ~(STRDERR|STWRERR|STRHUP|STPLEX)) == 0);
	if (sd_flag & STPLEX)
		error = EINVAL;
	else if (sd_flag & STRDERR) {
		error = stp->sd_rerror;
		if ((stp->sd_flag & STRDERRNONPERSIST) && !ispeek) {
			/*
			 * Read errors are non-persistent i.e. discarded once
			 * returned to a non-peeking caller,
			 */
			stp->sd_rerror = 0;
			stp->sd_flag &= ~STRDERR;
		}
		if (error == 0 && stp->sd_rderrfunc != NULL) {
			int clearerr = 0;

			error = (*stp->sd_rderrfunc)(stp->sd_vnode, ispeek,
			    &clearerr);
			if (clearerr) {
				stp->sd_flag &= ~STRDERR;
				stp->sd_rderrfunc = NULL;
			}
		}
	} else if (sd_flag & STWRERR) {
		error = stp->sd_werror;
		if ((stp->sd_flag & STWRERRNONPERSIST) && !ispeek) {
			/*
			 * Write errors are non-persistent i.e. discarded once
			 * returned to a non-peeking caller,
			 */
			stp->sd_werror = 0;
			stp->sd_flag &= ~STWRERR;
		}
		if (error == 0 && stp->sd_wrerrfunc != NULL) {
			int clearerr = 0;

			error = (*stp->sd_wrerrfunc)(stp->sd_vnode, ispeek,
			    &clearerr);
			if (clearerr) {
				stp->sd_flag &= ~STWRERR;
				stp->sd_wrerrfunc = NULL;
			}
		}
	} else if (sd_flag & STRHUP) {
		/* sd_werror set when STRHUP */
		error = stp->sd_werror;
	}
	return (error);
}


/*
 * Single-thread open/close/push/pop
 * for twisted streams also
 */
int
strstartplumb(stdata_t *stp, int flag, int cmd)
{
	int waited = 1;
	int error = 0;

	if (STRMATED(stp)) {
		struct stdata *stmatep = stp->sd_mate;

		STRLOCKMATES(stp);
		while (waited) {
			waited = 0;
			while (stmatep->sd_flag & (STWOPEN|STRCLOSE|STRPLUMB)) {
				if ((cmd == I_POP) &&
				    (flag & (FNDELAY|FNONBLOCK))) {
					STRUNLOCKMATES(stp);
					return (EAGAIN);
				}
				waited = 1;
				mutex_exit(&stp->sd_lock);
				if (!cv_wait_sig(&stmatep->sd_monitor,
				    &stmatep->sd_lock)) {
					mutex_exit(&stmatep->sd_lock);
					return (EINTR);
				}
				mutex_exit(&stmatep->sd_lock);
				STRLOCKMATES(stp);
			}
			while (stp->sd_flag & (STWOPEN|STRCLOSE|STRPLUMB)) {
				if ((cmd == I_POP) &&
				    (flag & (FNDELAY|FNONBLOCK))) {
					STRUNLOCKMATES(stp);
					return (EAGAIN);
				}
				waited = 1;
				mutex_exit(&stmatep->sd_lock);
				if (!cv_wait_sig(&stp->sd_monitor,
				    &stp->sd_lock)) {
					mutex_exit(&stp->sd_lock);
					return (EINTR);
				}
				mutex_exit(&stp->sd_lock);
				STRLOCKMATES(stp);
			}
			if (stp->sd_flag & (STRDERR|STWRERR|STRHUP|STPLEX)) {
				error = strgeterr(stp,
				    STRDERR|STWRERR|STRHUP|STPLEX, 0);
				if (error != 0) {
					STRUNLOCKMATES(stp);
					return (error);
				}
			}
		}
		stp->sd_flag |= STRPLUMB;
		STRUNLOCKMATES(stp);
	} else {
		mutex_enter(&stp->sd_lock);
		while (stp->sd_flag & (STWOPEN|STRCLOSE|STRPLUMB)) {
			if (((cmd == I_POP) || (cmd == _I_REMOVE)) &&
			    (flag & (FNDELAY|FNONBLOCK))) {
				mutex_exit(&stp->sd_lock);
				return (EAGAIN);
			}
			if (!cv_wait_sig(&stp->sd_monitor, &stp->sd_lock)) {
				mutex_exit(&stp->sd_lock);
				return (EINTR);
			}
			if (stp->sd_flag & (STRDERR|STWRERR|STRHUP|STPLEX)) {
				error = strgeterr(stp,
				    STRDERR|STWRERR|STRHUP|STPLEX, 0);
				if (error != 0) {
					mutex_exit(&stp->sd_lock);
					return (error);
				}
			}
		}
		stp->sd_flag |= STRPLUMB;
		mutex_exit(&stp->sd_lock);
	}
	return (0);
}

/*
 * Complete the plumbing operation associated with stream `stp'.
 */
void
strendplumb(stdata_t *stp)
{
	ASSERT(MUTEX_HELD(&stp->sd_lock));
	ASSERT(stp->sd_flag & STRPLUMB);
	stp->sd_flag &= ~STRPLUMB;
	cv_broadcast(&stp->sd_monitor);
}

/*
 * This describes how the STREAMS framework handles synchronization
 * during open/push and close/pop.
 * The key interfaces for open and close are qprocson and qprocsoff,
 * respectively. While the close case in general is harder both open
 * have close have significant similarities.
 *
 * During close the STREAMS framework has to both ensure that there
 * are no stale references to the queue pair (and syncq) that
 * are being closed and also provide the guarantees that are documented
 * in qprocsoff(9F).
 * If there are stale references to the queue that is closing it can
 * result in kernel memory corruption or kernel panics.
 *
 * Note that is it up to the module/driver to ensure that it itself
 * does not have any stale references to the closing queues once its close
 * routine returns. This includes:
 *  - Cancelling any timeout/bufcall/qtimeout/qbufcall callback routines
 *    associated with the queues. For timeout and bufcall callbacks the
 *    module/driver also has to ensure (or wait for) any callbacks that
 *    are in progress.
 *  - If the module/driver is using esballoc it has to ensure that any
 *    esballoc free functions do not refer to a queue that has closed.
 *    (Note that in general the close routine can not wait for the esballoc'ed
 *    messages to be freed since that can cause a deadlock.)
 *  - Cancelling any interrupts that refer to the closing queues and
 *    also ensuring that there are no interrupts in progress that will
 *    refer to the closing queues once the close routine returns.
 *  - For multiplexors removing any driver global state that refers to
 *    the closing queue and also ensuring that there are no threads in
 *    the multiplexor that has picked up a queue pointer but not yet
 *    finished using it.
 *
 * In addition, a driver/module can only reference the q_next pointer
 * in its open, close, put, or service procedures or in a
 * qtimeout/qbufcall callback procedure executing "on" the correct
 * stream. Thus it can not reference the q_next pointer in an interrupt
 * routine or a timeout, bufcall or esballoc callback routine. Likewise
 * it can not reference q_next of a different queue e.g. in a mux that
 * passes messages from one queues put/service procedure to another queue.
 * In all the cases when the driver/module can not access the q_next
 * field it must use the *next* versions e.g. canputnext instead of
 * canput(q->q_next) and putnextctl instead of putctl(q->q_next, ...).
 *
 *
 * Assuming that the driver/module conforms to the above constraints
 * the STREAMS framework has to avoid stale references to q_next for all
 * the framework internal cases which include (but are not limited to):
 *  - Threads in canput/canputnext/backenable and elsewhere that are
 *    walking q_next.
 *  - Messages on a syncq that have a reference to the queue through b_queue.
 *  - Messages on an outer perimeter (syncq) that have a reference to the
 *    queue through b_queue.
 *  - Threads that use q_nfsrv (e.g. canput) to find a queue.
 *    Note that only canput and bcanput use q_nfsrv without any locking.
 *
 * The STREAMS framework providing the qprocsoff(9F) guarantees means that
 * after qprocsoff returns, the framework has to ensure that no threads can
 * enter the put or service routines for the closing read or write-side queue.
 * In addition to preventing "direct" entry into the put procedures
 * the framework also has to prevent messages being drained from
 * the syncq or the outer perimeter.
 * XXX Note that currently qdetach does relies on D_MTOCEXCL as the only
 * mechanism to prevent qwriter(PERIM_OUTER) from running after
 * qprocsoff has returned.
 * Note that if a module/driver uses put(9F) on one of its own queues
 * it is up to the module/driver to ensure that the put() doesn't
 * get called when the queue is closing.
 *
 *
 * The framework aspects of the above "contract" is implemented by
 * qprocsoff, removeq, and strlock:
 *  - qprocsoff (disable_svc) sets QWCLOSE to prevent runservice from
 *    entering the service procedures.
 *  - strlock acquires the sd_lock and sd_reflock to prevent putnext,
 *    canputnext, backenable etc from dereferencing the q_next that will
 *    soon change.
 *  - strlock waits for sd_refcnt to be zero to wait for e.g. any canputnext
 *    or other q_next walker that uses claimstr/releasestr to finish.
 *  - optionally for every syncq in the stream strlock acquires all the
 *    sq_lock's and waits for all sq_counts to drop to a value that indicates
 *    that no thread executes in the put or service procedures and that no
 *    thread is draining into the module/driver. This ensures that no
 *    open, close, put, service, or qtimeout/qbufcall callback procedure is
 *    currently executing hence no such thread can end up with the old stale
 *    q_next value and no canput/backenable can have the old stale
 *    q_nfsrv/q_next.
 *  - qdetach (wait_svc) makes sure that any scheduled or running threads
 *    have either finished or observed the QWCLOSE flag and gone away.
 */


/*
 * Get all the locks necessary to change q_next.
 *
 * Wait for sd_refcnt to reach 0 and, if sqlist is present, wait for the
 * sq_count of each syncq in the list to drop to sq_rmqcount, indicating that
 * the only threads inside the syncq are threads currently calling removeq().
 * Since threads calling removeq() are in the process of removing their queues
 * from the stream, we do not need to worry about them accessing a stale q_next
 * pointer and thus we do not need to wait for them to exit (in fact, waiting
 * for them can cause deadlock).
 *
 * This routine is subject to starvation since it does not set any flag to
 * prevent threads from entering a module in the stream (i.e. sq_count can
 * increase on some syncq while it is waiting on some other syncq).
 *
 * Assumes that only one thread attempts to call strlock for a given
 * stream. If this is not the case the two threads would deadlock.
 * This assumption is guaranteed since strlock is only called by insertq
 * and removeq and streams plumbing changes are single-threaded for
 * a given stream using the STWOPEN, STRCLOSE, and STRPLUMB flags.
 *
 * For pipes, it is not difficult to atomically designate a pair of streams
 * to be mated. Once mated atomically by the framework the twisted pair remain
 * configured that way until dismantled atomically by the framework.
 * When plumbing takes place on a twisted stream it is necessary to ensure that
 * this operation is done exclusively on the twisted stream since two such
 * operations, each initiated on different ends of the pipe will deadlock
 * waiting for each other to complete.
 *
 * On entry, no locks should be held.
 * The locks acquired and held by strlock depends on a few factors.
 * - If sqlist is non-NULL all the syncq locks in the sqlist will be acquired
 *   and held on exit and all sq_count are at an acceptable level.
 * - In all cases, sd_lock and sd_reflock are acquired and held on exit with
 *   sd_refcnt being zero.
 */

static void
strlock(struct stdata *stp, sqlist_t *sqlist)
{
	syncql_t *sql, *sql2;
retry:
	/*
	 * Wait for any claimstr to go away.
	 */
	if (STRMATED(stp)) {
		struct stdata *stp1, *stp2;

		STRLOCKMATES(stp);
		/*
		 * Note that the selection of locking order is not
		 * important, just that they are always acquired in
		 * the same order.  To assure this, we choose this
		 * order based on the value of the pointer, and since
		 * the pointer will not change for the life of this
		 * pair, we will always grab the locks in the same
		 * order (and hence, prevent deadlocks).
		 */
		if (&(stp->sd_lock) > &((stp->sd_mate)->sd_lock)) {
			stp1 = stp;
			stp2 = stp->sd_mate;
		} else {
			stp2 = stp;
			stp1 = stp->sd_mate;
		}
		mutex_enter(&stp1->sd_reflock);
		if (stp1->sd_refcnt > 0) {
			STRUNLOCKMATES(stp);
			cv_wait(&stp1->sd_refmonitor, &stp1->sd_reflock);
			mutex_exit(&stp1->sd_reflock);
			goto retry;
		}
		mutex_enter(&stp2->sd_reflock);
		if (stp2->sd_refcnt > 0) {
			STRUNLOCKMATES(stp);
			mutex_exit(&stp1->sd_reflock);
			cv_wait(&stp2->sd_refmonitor, &stp2->sd_reflock);
			mutex_exit(&stp2->sd_reflock);
			goto retry;
		}
		STREAM_PUTLOCKS_ENTER(stp1);
		STREAM_PUTLOCKS_ENTER(stp2);
	} else {
		mutex_enter(&stp->sd_lock);
		mutex_enter(&stp->sd_reflock);
		while (stp->sd_refcnt > 0) {
			mutex_exit(&stp->sd_lock);
			cv_wait(&stp->sd_refmonitor, &stp->sd_reflock);
			if (mutex_tryenter(&stp->sd_lock) == 0) {
				mutex_exit(&stp->sd_reflock);
				mutex_enter(&stp->sd_lock);
				mutex_enter(&stp->sd_reflock);
			}
		}
		STREAM_PUTLOCKS_ENTER(stp);
	}

	if (sqlist == NULL)
		return;

	for (sql = sqlist->sqlist_head; sql; sql = sql->sql_next) {
		syncq_t *sq = sql->sql_sq;
		uint16_t count;

		mutex_enter(SQLOCK(sq));
		count = sq->sq_count;
		ASSERT(sq->sq_rmqcount <= count);
		SQ_PUTLOCKS_ENTER(sq);
		SUM_SQ_PUTCOUNTS(sq, count);
		if (count == sq->sq_rmqcount)
			continue;

		/* Failed - drop all locks that we have acquired so far */
		if (STRMATED(stp)) {
			STREAM_PUTLOCKS_EXIT(stp);
			STREAM_PUTLOCKS_EXIT(stp->sd_mate);
			STRUNLOCKMATES(stp);
			mutex_exit(&stp->sd_reflock);
			mutex_exit(&stp->sd_mate->sd_reflock);
		} else {
			STREAM_PUTLOCKS_EXIT(stp);
			mutex_exit(&stp->sd_lock);
			mutex_exit(&stp->sd_reflock);
		}
		for (sql2 = sqlist->sqlist_head; sql2 != sql;
		    sql2 = sql2->sql_next) {
			SQ_PUTLOCKS_EXIT(sql2->sql_sq);
			mutex_exit(SQLOCK(sql2->sql_sq));
		}

		/*
		 * The wait loop below may starve when there are many threads
		 * claiming the syncq. This is especially a problem with permod
		 * syncqs (IP). To lessen the impact of the problem we increment
		 * sq_needexcl and clear fastbits so that putnexts will slow
		 * down and call sqenable instead of draining right away.
		 */
		sq->sq_needexcl++;
		SQ_PUTCOUNT_CLRFAST_LOCKED(sq);
		while (count > sq->sq_rmqcount) {
			sq->sq_flags |= SQ_WANTWAKEUP;
			SQ_PUTLOCKS_EXIT(sq);
			cv_wait(&sq->sq_wait, SQLOCK(sq));
			count = sq->sq_count;
			SQ_PUTLOCKS_ENTER(sq);
			SUM_SQ_PUTCOUNTS(sq, count);
		}
		sq->sq_needexcl--;
		if (sq->sq_needexcl == 0)
			SQ_PUTCOUNT_SETFAST_LOCKED(sq);
		SQ_PUTLOCKS_EXIT(sq);
		ASSERT(count == sq->sq_rmqcount);
		mutex_exit(SQLOCK(sq));
		goto retry;
	}
}

/*
 * Drop all the locks that strlock acquired.
 */
static void
strunlock(struct stdata *stp, sqlist_t *sqlist)
{
	syncql_t *sql;

	if (STRMATED(stp)) {
		STREAM_PUTLOCKS_EXIT(stp);
		STREAM_PUTLOCKS_EXIT(stp->sd_mate);
		STRUNLOCKMATES(stp);
		mutex_exit(&stp->sd_reflock);
		mutex_exit(&stp->sd_mate->sd_reflock);
	} else {
		STREAM_PUTLOCKS_EXIT(stp);
		mutex_exit(&stp->sd_lock);
		mutex_exit(&stp->sd_reflock);
	}

	if (sqlist == NULL)
		return;

	for (sql = sqlist->sqlist_head; sql; sql = sql->sql_next) {
		SQ_PUTLOCKS_EXIT(sql->sql_sq);
		mutex_exit(SQLOCK(sql->sql_sq));
	}
}

/*
 * When the module has service procedure, we need check if the next
 * module which has service procedure is in flow control to trigger
 * the backenable.
 */
static void
backenable_insertedq(queue_t *q)
{
	qband_t	*qbp;

	claimstr(q);
	if (q->q_qinfo->qi_srvp != NULL && q->q_next != NULL) {
		if (q->q_next->q_nfsrv->q_flag & QWANTW)
			backenable(q, 0);

		qbp = q->q_next->q_nfsrv->q_bandp;
		for (; qbp != NULL; qbp = qbp->qb_next)
			if ((qbp->qb_flag & QB_WANTW) && qbp->qb_first != NULL)
				backenable(q, qbp->qb_first->b_band);
	}
	releasestr(q);
}

/*
 * Given two read queues, insert a new single one after another.
 *
 * This routine acquires all the necessary locks in order to change
 * q_next and related pointer using strlock().
 * It depends on the stream head ensuring that there are no concurrent
 * insertq or removeq on the same stream. The stream head ensures this
 * using the flags STWOPEN, STRCLOSE, and STRPLUMB.
 *
 * Note that no syncq locks are held during the q_next change. This is
 * applied to all streams since, unlike removeq, there is no problem of stale
 * pointers when adding a module to the stream. Thus drivers/modules that do a
 * canput(rq->q_next) would never get a closed/freed queue pointer even if we
 * applied this optimization to all streams.
 */
void
insertq(struct stdata *stp, queue_t *new)
{
	queue_t	*after;
	queue_t *wafter;
	queue_t *wnew = _WR(new);
	boolean_t have_fifo = B_FALSE;

	if (new->q_flag & _QINSERTING) {
		ASSERT(stp->sd_vnode->v_type != VFIFO);
		after = new->q_next;
		wafter = _WR(new->q_next);
	} else {
		after = _RD(stp->sd_wrq);
		wafter = stp->sd_wrq;
	}

	TRACE_2(TR_FAC_STREAMS_FR, TR_INSERTQ,
	    "insertq:%p, %p", after, new);
	ASSERT(after->q_flag & QREADR);
	ASSERT(new->q_flag & QREADR);

	strlock(stp, NULL);

	/* Do we have a FIFO? */
	if (wafter->q_next == after) {
		have_fifo = B_TRUE;
		wnew->q_next = new;
	} else {
		wnew->q_next = wafter->q_next;
	}
	new->q_next = after;

	set_nfsrv_ptr(new, wnew, after, wafter);
	/*
	 * set_nfsrv_ptr() needs to know if this is an insertion or not,
	 * so only reset this flag after calling it.
	 */
	new->q_flag &= ~_QINSERTING;

	if (have_fifo) {
		wafter->q_next = wnew;
	} else {
		if (wafter->q_next)
			_OTHERQ(wafter->q_next)->q_next = new;
		wafter->q_next = wnew;
	}

	set_qend(new);
	/* The QEND flag might have to be updated for the upstream guy */
	set_qend(after);

	ASSERT(_SAMESTR(new) == O_SAMESTR(new));
	ASSERT(_SAMESTR(wnew) == O_SAMESTR(wnew));
	ASSERT(_SAMESTR(after) == O_SAMESTR(after));
	ASSERT(_SAMESTR(wafter) == O_SAMESTR(wafter));
	strsetuio(stp);

	/*
	 * If this was a module insertion, bump the push count.
	 */
	if (!(new->q_flag & QISDRV))
		stp->sd_pushcnt++;

	strunlock(stp, NULL);

	/* check if the write Q needs backenable */
	backenable_insertedq(wnew);

	/* check if the read Q needs backenable */
	backenable_insertedq(new);
}

/*
 * Given a read queue, unlink it from any neighbors.
 *
 * This routine acquires all the necessary locks in order to
 * change q_next and related pointers and also guard against
 * stale references (e.g. through q_next) to the queue that
 * is being removed. It also plays part of the role in ensuring
 * that the module's/driver's put procedure doesn't get called
 * after qprocsoff returns.
 *
 * Removeq depends on the stream head ensuring that there are
 * no concurrent insertq or removeq on the same stream. The
 * stream head ensures this using the flags STWOPEN, STRCLOSE and
 * STRPLUMB.
 *
 * The set of locks needed to remove the queue is different in
 * different cases:
 *
 * Acquire sd_lock, sd_reflock, and all the syncq locks in the stream after
 * waiting for the syncq reference count to drop to 0 indicating that no
 * non-close threads are present anywhere in the stream. This ensures that any
 * module/driver can reference q_next in its open, close, put, or service
 * procedures.
 *
 * The sq_rmqcount counter tracks the number of threads inside removeq().
 * strlock() ensures that there is either no threads executing inside perimeter
 * or there is only a thread calling qprocsoff().
 *
 * strlock() compares the value of sq_count with the number of threads inside
 * removeq() and waits until sq_count is equal to sq_rmqcount. We need to wakeup
 * any threads waiting in strlock() when the sq_rmqcount increases.
 */

void
removeq(queue_t *qp)
{
	queue_t *wqp = _WR(qp);
	struct stdata *stp = STREAM(qp);
	sqlist_t *sqlist = NULL;
	boolean_t isdriver;
	int moved;
	syncq_t *sq = qp->q_syncq;
	syncq_t *wsq = wqp->q_syncq;

	ASSERT(stp);

	TRACE_2(TR_FAC_STREAMS_FR, TR_REMOVEQ,
	    "removeq:%p %p", qp, wqp);
	ASSERT(qp->q_flag&QREADR);

	/*
	 * For queues using Synchronous streams, we must wait for all threads in
	 * rwnext() to drain out before proceeding.
	 */
	if (qp->q_flag & QSYNCSTR) {
		/* First, we need wakeup any threads blocked in rwnext() */
		mutex_enter(SQLOCK(sq));
		if (sq->sq_flags & SQ_WANTWAKEUP) {
			sq->sq_flags &= ~SQ_WANTWAKEUP;
			cv_broadcast(&sq->sq_wait);
		}
		mutex_exit(SQLOCK(sq));

		if (wsq != sq) {
			mutex_enter(SQLOCK(wsq));
			if (wsq->sq_flags & SQ_WANTWAKEUP) {
				wsq->sq_flags &= ~SQ_WANTWAKEUP;
				cv_broadcast(&wsq->sq_wait);
			}
			mutex_exit(SQLOCK(wsq));
		}

		mutex_enter(QLOCK(qp));
		while (qp->q_rwcnt > 0) {
			qp->q_flag |= QWANTRMQSYNC;
			cv_wait(&qp->q_wait, QLOCK(qp));
		}
		mutex_exit(QLOCK(qp));

		mutex_enter(QLOCK(wqp));
		while (wqp->q_rwcnt > 0) {
			wqp->q_flag |= QWANTRMQSYNC;
			cv_wait(&wqp->q_wait, QLOCK(wqp));
		}
		mutex_exit(QLOCK(wqp));
	}

	mutex_enter(SQLOCK(sq));
	sq->sq_rmqcount++;
	if (sq->sq_flags & SQ_WANTWAKEUP) {
		sq->sq_flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&sq->sq_wait);
	}
	mutex_exit(SQLOCK(sq));

	isdriver = (qp->q_flag & QISDRV);

	sqlist = sqlist_build(qp, stp, STRMATED(stp));
	strlock(stp, sqlist);

	reset_nfsrv_ptr(qp, wqp);

	ASSERT(wqp->q_next == NULL || backq(qp)->q_next == qp);
	ASSERT(qp->q_next == NULL || backq(wqp)->q_next == wqp);
	/* Do we have a FIFO? */
	if (wqp->q_next == qp) {
		stp->sd_wrq->q_next = _RD(stp->sd_wrq);
	} else {
		if (wqp->q_next)
			backq(qp)->q_next = qp->q_next;
		if (qp->q_next)
			backq(wqp)->q_next = wqp->q_next;
	}

	/* The QEND flag might have to be updated for the upstream guy */
	if (qp->q_next)
		set_qend(qp->q_next);

	ASSERT(_SAMESTR(stp->sd_wrq) == O_SAMESTR(stp->sd_wrq));
	ASSERT(_SAMESTR(_RD(stp->sd_wrq)) == O_SAMESTR(_RD(stp->sd_wrq)));

	/*
	 * Move any messages destined for the put procedures to the next
	 * syncq in line. Otherwise free them.
	 */
	moved = 0;
	/*
	 * Quick check to see whether there are any messages or events.
	 */
	if (qp->q_syncqmsgs != 0 || (qp->q_syncq->sq_flags & SQ_EVENTS))
		moved += propagate_syncq(qp);
	if (wqp->q_syncqmsgs != 0 ||
	    (wqp->q_syncq->sq_flags & SQ_EVENTS))
		moved += propagate_syncq(wqp);

	strsetuio(stp);

	/*
	 * If this was a module removal, decrement the push count.
	 */
	if (!isdriver)
		stp->sd_pushcnt--;

	strunlock(stp, sqlist);
	sqlist_free(sqlist);

	/*
	 * Make sure any messages that were propagated are drained.
	 * Also clear any QFULL bit caused by messages that were propagated.
	 */

	if (qp->q_next != NULL) {
		clr_qfull(qp);
		/*
		 * For the driver calling qprocsoff, propagate_syncq
		 * frees all the messages instead of putting it in
		 * the stream head
		 */
		if (!isdriver && (moved > 0))
			emptysq(qp->q_next->q_syncq);
	}
	if (wqp->q_next != NULL) {
		clr_qfull(wqp);
		/*
		 * We come here for any pop of a module except for the
		 * case of driver being removed. We don't call emptysq
		 * if we did not move any messages. This will avoid holding
		 * PERMOD syncq locks in emptysq
		 */
		if (moved > 0)
			emptysq(wqp->q_next->q_syncq);
	}

	mutex_enter(SQLOCK(sq));
	sq->sq_rmqcount--;
	mutex_exit(SQLOCK(sq));
}

/*
 * Prevent further entry by setting a flag (like SQ_FROZEN, SQ_BLOCKED or
 * SQ_WRITER) on a syncq.
 * If maxcnt is not -1 it assumes that caller has "maxcnt" claim(s) on the
 * sync queue and waits until sq_count reaches maxcnt.
 *
 * If maxcnt is -1 there's no need to grab sq_putlocks since the caller
 * does not care about putnext threads that are in the middle of calling put
 * entry points.
 *
 * This routine is used for both inner and outer syncqs.
 */
static void
blocksq(syncq_t *sq, ushort_t flag, int maxcnt)
{
	uint16_t count = 0;

	mutex_enter(SQLOCK(sq));
	/*
	 * Wait for SQ_FROZEN/SQ_BLOCKED to be reset.
	 * SQ_FROZEN will be set if there is a frozen stream that has a
	 * queue which also refers to this "shared" syncq.
	 * SQ_BLOCKED will be set if there is "off" queue which also
	 * refers to this "shared" syncq.
	 */
	if (maxcnt != -1) {
		count = sq->sq_count;
		SQ_PUTLOCKS_ENTER(sq);
		SQ_PUTCOUNT_CLRFAST_LOCKED(sq);
		SUM_SQ_PUTCOUNTS(sq, count);
	}
	sq->sq_needexcl++;
	ASSERT(sq->sq_needexcl != 0);	/* wraparound */

	while ((sq->sq_flags & flag) ||
	    (maxcnt != -1 && count > (unsigned)maxcnt)) {
		sq->sq_flags |= SQ_WANTWAKEUP;
		if (maxcnt != -1) {
			SQ_PUTLOCKS_EXIT(sq);
		}
		cv_wait(&sq->sq_wait, SQLOCK(sq));
		if (maxcnt != -1) {
			count = sq->sq_count;
			SQ_PUTLOCKS_ENTER(sq);
			SUM_SQ_PUTCOUNTS(sq, count);
		}
	}
	sq->sq_needexcl--;
	sq->sq_flags |= flag;
	ASSERT(maxcnt == -1 || count == maxcnt);
	if (maxcnt != -1) {
		if (sq->sq_needexcl == 0) {
			SQ_PUTCOUNT_SETFAST_LOCKED(sq);
		}
		SQ_PUTLOCKS_EXIT(sq);
	} else if (sq->sq_needexcl == 0) {
		SQ_PUTCOUNT_SETFAST(sq);
	}

	mutex_exit(SQLOCK(sq));
}

/*
 * Reset a flag that was set with blocksq.
 *
 * Can not use this routine to reset SQ_WRITER.
 *
 * If "isouter" is set then the syncq is assumed to be an outer perimeter
 * and drain_syncq is not called. Instead we rely on the qwriter_outer thread
 * to handle the queued qwriter operations.
 *
 * No need to grab sq_putlocks here. See comment in strsubr.h that explains when
 * sq_putlocks are used.
 */
static void
unblocksq(syncq_t *sq, uint16_t resetflag, int isouter)
{
	uint16_t flags;

	mutex_enter(SQLOCK(sq));
	ASSERT(resetflag != SQ_WRITER);
	ASSERT(sq->sq_flags & resetflag);
	flags = sq->sq_flags & ~resetflag;
	sq->sq_flags = flags;
	if (flags & (SQ_QUEUED | SQ_WANTWAKEUP)) {
		if (flags & SQ_WANTWAKEUP) {
			flags &= ~SQ_WANTWAKEUP;
			cv_broadcast(&sq->sq_wait);
		}
		sq->sq_flags = flags;
		if ((flags & SQ_QUEUED) && !(flags & (SQ_STAYAWAY|SQ_EXCL))) {
			if (!isouter) {
				/* drain_syncq drops SQLOCK */
				drain_syncq(sq);
				return;
			}
		}
	}
	mutex_exit(SQLOCK(sq));
}

/*
 * Reset a flag that was set with blocksq.
 * Does not drain the syncq. Use emptysq() for that.
 * Returns 1 if SQ_QUEUED is set. Otherwise 0.
 *
 * No need to grab sq_putlocks here. See comment in strsubr.h that explains when
 * sq_putlocks are used.
 */
static int
dropsq(syncq_t *sq, uint16_t resetflag)
{
	uint16_t flags;

	mutex_enter(SQLOCK(sq));
	ASSERT(sq->sq_flags & resetflag);
	flags = sq->sq_flags & ~resetflag;
	if (flags & SQ_WANTWAKEUP) {
		flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&sq->sq_wait);
	}
	sq->sq_flags = flags;
	mutex_exit(SQLOCK(sq));
	if (flags & SQ_QUEUED)
		return (1);
	return (0);
}

/*
 * Empty all the messages on a syncq.
 *
 * No need to grab sq_putlocks here. See comment in strsubr.h that explains when
 * sq_putlocks are used.
 */
static void
emptysq(syncq_t *sq)
{
	uint16_t flags;

	mutex_enter(SQLOCK(sq));
	flags = sq->sq_flags;
	if ((flags & SQ_QUEUED) && !(flags & (SQ_STAYAWAY|SQ_EXCL))) {
		/*
		 * To prevent potential recursive invocation of drain_syncq we
		 * do not call drain_syncq if count is non-zero.
		 */
		if (sq->sq_count == 0) {
			/* drain_syncq() drops SQLOCK */
			drain_syncq(sq);
			return;
		} else
			sqenable(sq);
	}
	mutex_exit(SQLOCK(sq));
}

/*
 * Ordered insert while removing duplicates.
 */
static void
sqlist_insert(sqlist_t *sqlist, syncq_t *sqp)
{
	syncql_t *sqlp, **prev_sqlpp, *new_sqlp;

	prev_sqlpp = &sqlist->sqlist_head;
	while ((sqlp = *prev_sqlpp) != NULL) {
		if (sqlp->sql_sq >= sqp) {
			if (sqlp->sql_sq == sqp)	/* duplicate */
				return;
			break;
		}
		prev_sqlpp = &sqlp->sql_next;
	}
	new_sqlp = &sqlist->sqlist_array[sqlist->sqlist_index++];
	ASSERT((char *)new_sqlp < (char *)sqlist + sqlist->sqlist_size);
	new_sqlp->sql_next = sqlp;
	new_sqlp->sql_sq = sqp;
	*prev_sqlpp = new_sqlp;
}

/*
 * Walk the write side queues until we hit either the driver
 * or a twist in the stream (_SAMESTR will return false in both
 * these cases) then turn around and walk the read side queues
 * back up to the stream head.
 */
static void
sqlist_insertall(sqlist_t *sqlist, queue_t *q)
{
	while (q != NULL) {
		sqlist_insert(sqlist, q->q_syncq);

		if (_SAMESTR(q))
			q = q->q_next;
		else if (!(q->q_flag & QREADR))
			q = _RD(q);
		else
			q = NULL;
	}
}

/*
 * Allocate and build a list of all syncqs in a stream and the syncq(s)
 * associated with the "q" parameter. The resulting list is sorted in a
 * canonical order and is free of duplicates.
 * Assumes the passed queue is a _RD(q).
 */
static sqlist_t *
sqlist_build(queue_t *q, struct stdata *stp, boolean_t do_twist)
{
	sqlist_t *sqlist = sqlist_alloc(stp, KM_SLEEP);

	/*
	 * start with the current queue/qpair
	 */
	ASSERT(q->q_flag & QREADR);

	sqlist_insert(sqlist, q->q_syncq);
	sqlist_insert(sqlist, _WR(q)->q_syncq);

	sqlist_insertall(sqlist, stp->sd_wrq);
	if (do_twist)
		sqlist_insertall(sqlist, stp->sd_mate->sd_wrq);

	return (sqlist);
}

static sqlist_t *
sqlist_alloc(struct stdata *stp, int kmflag)
{
	size_t sqlist_size;
	sqlist_t *sqlist;

	/*
	 * Allocate 2 syncql_t's for each pushed module. Note that
	 * the sqlist_t structure already has 4 syncql_t's built in:
	 * 2 for the stream head, and 2 for the driver/other stream head.
	 */
	sqlist_size = 2 * sizeof (syncql_t) * stp->sd_pushcnt +
	    sizeof (sqlist_t);
	if (STRMATED(stp))
		sqlist_size += 2 * sizeof (syncql_t) * stp->sd_mate->sd_pushcnt;
	sqlist = kmem_alloc(sqlist_size, kmflag);

	sqlist->sqlist_head = NULL;
	sqlist->sqlist_size = sqlist_size;
	sqlist->sqlist_index = 0;

	return (sqlist);
}

/*
 * Free the list created by sqlist_alloc()
 */
static void
sqlist_free(sqlist_t *sqlist)
{
	kmem_free(sqlist, sqlist->sqlist_size);
}

/*
 * Prevent any new entries into any syncq in this stream.
 * Used by freezestr.
 */
void
strblock(queue_t *q)
{
	struct stdata	*stp;
	syncql_t	*sql;
	sqlist_t	*sqlist;

	q = _RD(q);

	stp = STREAM(q);
	ASSERT(stp != NULL);

	/*
	 * Get a sorted list with all the duplicates removed containing
	 * all the syncqs referenced by this stream.
	 */
	sqlist = sqlist_build(q, stp, B_FALSE);
	for (sql = sqlist->sqlist_head; sql != NULL; sql = sql->sql_next)
		blocksq(sql->sql_sq, SQ_FROZEN, -1);
	sqlist_free(sqlist);
}

/*
 * Release the block on new entries into this stream
 */
void
strunblock(queue_t *q)
{
	struct stdata	*stp;
	syncql_t	*sql;
	sqlist_t	*sqlist;
	int		drain_needed;

	q = _RD(q);

	/*
	 * Get a sorted list with all the duplicates removed containing
	 * all the syncqs referenced by this stream.
	 * Have to drop the SQ_FROZEN flag on all the syncqs before
	 * starting to drain them; otherwise the draining might
	 * cause a freezestr in some module on the stream (which
	 * would deadlock).
	 */
	stp = STREAM(q);
	ASSERT(stp != NULL);
	sqlist = sqlist_build(q, stp, B_FALSE);
	drain_needed = 0;
	for (sql = sqlist->sqlist_head; sql != NULL; sql = sql->sql_next)
		drain_needed += dropsq(sql->sql_sq, SQ_FROZEN);
	if (drain_needed) {
		for (sql = sqlist->sqlist_head; sql != NULL;
		    sql = sql->sql_next)
			emptysq(sql->sql_sq);
	}
	sqlist_free(sqlist);
}

#ifdef DEBUG
static int
qprocsareon(queue_t *rq)
{
	if (rq->q_next == NULL)
		return (0);
	return (_WR(rq->q_next)->q_next == _WR(rq));
}

int
qclaimed(queue_t *q)
{
	uint_t count;

	count = q->q_syncq->sq_count;
	SUM_SQ_PUTCOUNTS(q->q_syncq, count);
	return (count != 0);
}

/*
 * Check if anyone has frozen this stream with freezestr
 */
int
frozenstr(queue_t *q)
{
	return ((q->q_syncq->sq_flags & SQ_FROZEN) != 0);
}
#endif /* DEBUG */

/*
 * Enter a queue.
 * Obsoleted interface. Should not be used.
 */
void
enterq(queue_t *q)
{
	entersq(q->q_syncq, SQ_CALLBACK);
}

void
leaveq(queue_t *q)
{
	leavesq(q->q_syncq, SQ_CALLBACK);
}

/*
 * Enter a perimeter. c_inner and c_outer specifies which concurrency bits
 * to check.
 * Wait if SQ_QUEUED is set to preserve ordering between messages and qwriter
 * calls and the running of open, close and service procedures.
 *
 * If c_inner bit is set no need to grab sq_putlocks since we don't care
 * if other threads have entered or are entering put entry point.
 *
 * If c_inner bit is set it might have been possible to use
 * sq_putlocks/sq_putcounts instead of SQLOCK/sq_count (e.g. to optimize
 * open/close path for IP) but since the count may need to be decremented in
 * qwait() we wouldn't know which counter to decrement. Currently counter is
 * selected by current cpu_seqid and current CPU can change at any moment. XXX
 * in the future we might use curthread id bits to select the counter and this
 * would stay constant across routine calls.
 */
void
entersq(syncq_t *sq, int entrypoint)
{
	uint16_t	count = 0;
	uint16_t	flags;
	uint16_t	waitflags = SQ_STAYAWAY | SQ_EVENTS | SQ_EXCL;
	uint16_t	type;
	uint_t		c_inner = entrypoint & SQ_CI;
	uint_t		c_outer = entrypoint & SQ_CO;

	/*
	 * Increment ref count to keep closes out of this queue.
	 */
	ASSERT(sq);
	ASSERT(c_inner && c_outer);
	mutex_enter(SQLOCK(sq));
	flags = sq->sq_flags;
	type = sq->sq_type;
	if (!(type & c_inner)) {
		/* Make sure all putcounts now use slowlock. */
		count = sq->sq_count;
		SQ_PUTLOCKS_ENTER(sq);
		SQ_PUTCOUNT_CLRFAST_LOCKED(sq);
		SUM_SQ_PUTCOUNTS(sq, count);
		sq->sq_needexcl++;
		ASSERT(sq->sq_needexcl != 0);	/* wraparound */
		waitflags |= SQ_MESSAGES;
	}
	/*
	 * Wait until we can enter the inner perimeter.
	 * If we want exclusive access we wait until sq_count is 0.
	 * We have to do this before entering the outer perimeter in order
	 * to preserve put/close message ordering.
	 */
	while ((flags & waitflags) || (!(type & c_inner) && count != 0)) {
		sq->sq_flags = flags | SQ_WANTWAKEUP;
		if (!(type & c_inner)) {
			SQ_PUTLOCKS_EXIT(sq);
		}
		cv_wait(&sq->sq_wait, SQLOCK(sq));
		if (!(type & c_inner)) {
			count = sq->sq_count;
			SQ_PUTLOCKS_ENTER(sq);
			SUM_SQ_PUTCOUNTS(sq, count);
		}
		flags = sq->sq_flags;
	}

	if (!(type & c_inner)) {
		ASSERT(sq->sq_needexcl > 0);
		sq->sq_needexcl--;
		if (sq->sq_needexcl == 0) {
			SQ_PUTCOUNT_SETFAST_LOCKED(sq);
		}
	}

	/* Check if we need to enter the outer perimeter */
	if (!(type & c_outer)) {
		/*
		 * We have to enter the outer perimeter exclusively before
		 * we can increment sq_count to avoid deadlock. This implies
		 * that we have to re-check sq_flags and sq_count.
		 *
		 * is it possible to have c_inner set when c_outer is not set?
		 */
		if (!(type & c_inner)) {
			SQ_PUTLOCKS_EXIT(sq);
		}
		mutex_exit(SQLOCK(sq));
		outer_enter(sq->sq_outer, SQ_GOAWAY);
		mutex_enter(SQLOCK(sq));
		flags = sq->sq_flags;
		/*
		 * there should be no need to recheck sq_putcounts
		 * because outer_enter() has already waited for them to clear
		 * after setting SQ_WRITER.
		 */
		count = sq->sq_count;
#ifdef DEBUG
		/*
		 * SUMCHECK_SQ_PUTCOUNTS should return the sum instead
		 * of doing an ASSERT internally. Others should do
		 * something like
		 *	 ASSERT(SUMCHECK_SQ_PUTCOUNTS(sq) == 0);
		 * without the need to #ifdef DEBUG it.
		 */
		SUMCHECK_SQ_PUTCOUNTS(sq, 0);
#endif
		while ((flags & (SQ_EXCL|SQ_BLOCKED|SQ_FROZEN)) ||
		    (!(type & c_inner) && count != 0)) {
			sq->sq_flags = flags | SQ_WANTWAKEUP;
			cv_wait(&sq->sq_wait, SQLOCK(sq));
			count = sq->sq_count;
			flags = sq->sq_flags;
		}
	}

	sq->sq_count++;
	ASSERT(sq->sq_count != 0);	/* Wraparound */
	if (!(type & c_inner)) {
		/* Exclusive entry */
		ASSERT(sq->sq_count == 1);
		sq->sq_flags |= SQ_EXCL;
		if (type & c_outer) {
			SQ_PUTLOCKS_EXIT(sq);
		}
	}
	mutex_exit(SQLOCK(sq));
}

/*
 * Leave a syncq. Announce to framework that closes may proceed.
 * c_inner and c_outer specify which concurrency bits to check.
 *
 * Must never be called from driver or module put entry point.
 *
 * No need to grab sq_putlocks here. See comment in strsubr.h that explains when
 * sq_putlocks are used.
 */
void
leavesq(syncq_t *sq, int entrypoint)
{
	uint16_t	flags;
	uint16_t	type;
	uint_t		c_outer = entrypoint & SQ_CO;
#ifdef DEBUG
	uint_t		c_inner = entrypoint & SQ_CI;
#endif

	/*
	 * Decrement ref count, drain the syncq if possible, and wake up
	 * any waiting close.
	 */
	ASSERT(sq);
	ASSERT(c_inner && c_outer);
	mutex_enter(SQLOCK(sq));
	flags = sq->sq_flags;
	type = sq->sq_type;
	if (flags & (SQ_QUEUED|SQ_WANTWAKEUP|SQ_WANTEXWAKEUP)) {

		if (flags & SQ_WANTWAKEUP) {
			flags &= ~SQ_WANTWAKEUP;
			cv_broadcast(&sq->sq_wait);
		}
		if (flags & SQ_WANTEXWAKEUP) {
			flags &= ~SQ_WANTEXWAKEUP;
			cv_broadcast(&sq->sq_exitwait);
		}

		if ((flags & SQ_QUEUED) && !(flags & SQ_STAYAWAY)) {
			/*
			 * The syncq needs to be drained. "Exit" the syncq
			 * before calling drain_syncq.
			 */
			ASSERT(sq->sq_count != 0);
			sq->sq_count--;
			ASSERT((flags & SQ_EXCL) || (type & c_inner));
			sq->sq_flags = flags & ~SQ_EXCL;
			drain_syncq(sq);
			ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
			/* Check if we need to exit the outer perimeter */
			/* XXX will this ever be true? */
			if (!(type & c_outer))
				outer_exit(sq->sq_outer);
			return;
		}
	}
	ASSERT(sq->sq_count != 0);
	sq->sq_count--;
	ASSERT((flags & SQ_EXCL) || (type & c_inner));
	sq->sq_flags = flags & ~SQ_EXCL;
	mutex_exit(SQLOCK(sq));

	/* Check if we need to exit the outer perimeter */
	if (!(sq->sq_type & c_outer))
		outer_exit(sq->sq_outer);
}

/*
 * Prevent q_next from changing in this stream by incrementing sq_count.
 *
 * No need to grab sq_putlocks here. See comment in strsubr.h that explains when
 * sq_putlocks are used.
 */
void
claimq(queue_t *qp)
{
	syncq_t	*sq = qp->q_syncq;

	mutex_enter(SQLOCK(sq));
	sq->sq_count++;
	ASSERT(sq->sq_count != 0);	/* Wraparound */
	mutex_exit(SQLOCK(sq));
}

/*
 * Undo claimq.
 *
 * No need to grab sq_putlocks here. See comment in strsubr.h that explains when
 * sq_putlocks are used.
 */
void
releaseq(queue_t *qp)
{
	syncq_t	*sq = qp->q_syncq;
	uint16_t flags;

	mutex_enter(SQLOCK(sq));
	ASSERT(sq->sq_count > 0);
	sq->sq_count--;

	flags = sq->sq_flags;
	if (flags & (SQ_WANTWAKEUP|SQ_QUEUED)) {
		if (flags & SQ_WANTWAKEUP) {
			flags &= ~SQ_WANTWAKEUP;
			cv_broadcast(&sq->sq_wait);
		}
		sq->sq_flags = flags;
		if ((flags & SQ_QUEUED) && !(flags & (SQ_STAYAWAY|SQ_EXCL))) {
			/*
			 * To prevent potential recursive invocation of
			 * drain_syncq we do not call drain_syncq if count is
			 * non-zero.
			 */
			if (sq->sq_count == 0) {
				drain_syncq(sq);
				return;
			} else
				sqenable(sq);
		}
	}
	mutex_exit(SQLOCK(sq));
}

/*
 * Prevent q_next from changing in this stream by incrementing sd_refcnt.
 */
void
claimstr(queue_t *qp)
{
	struct stdata *stp = STREAM(qp);

	mutex_enter(&stp->sd_reflock);
	stp->sd_refcnt++;
	ASSERT(stp->sd_refcnt != 0);	/* Wraparound */
	mutex_exit(&stp->sd_reflock);
}

/*
 * Undo claimstr.
 */
void
releasestr(queue_t *qp)
{
	struct stdata *stp = STREAM(qp);

	mutex_enter(&stp->sd_reflock);
	ASSERT(stp->sd_refcnt != 0);
	if (--stp->sd_refcnt == 0)
		cv_broadcast(&stp->sd_refmonitor);
	mutex_exit(&stp->sd_reflock);
}

static syncq_t *
new_syncq(void)
{
	return (kmem_cache_alloc(syncq_cache, KM_SLEEP));
}

static void
free_syncq(syncq_t *sq)
{
	ASSERT(sq->sq_head == NULL);
	ASSERT(sq->sq_outer == NULL);
	ASSERT(sq->sq_callbpend == NULL);
	ASSERT((sq->sq_onext == NULL && sq->sq_oprev == NULL) ||
	    (sq->sq_onext == sq && sq->sq_oprev == sq));

	if (sq->sq_ciputctrl != NULL) {
		ASSERT(sq->sq_nciputctrl == n_ciputctrl - 1);
		SUMCHECK_CIPUTCTRL_COUNTS(sq->sq_ciputctrl,
		    sq->sq_nciputctrl, 0);
		ASSERT(ciputctrl_cache != NULL);
		kmem_cache_free(ciputctrl_cache, sq->sq_ciputctrl);
	}

	sq->sq_tail = NULL;
	sq->sq_evhead = NULL;
	sq->sq_evtail = NULL;
	sq->sq_ciputctrl = NULL;
	sq->sq_nciputctrl = 0;
	sq->sq_count = 0;
	sq->sq_rmqcount = 0;
	sq->sq_callbflags = 0;
	sq->sq_cancelid = 0;
	sq->sq_next = NULL;
	sq->sq_needexcl = 0;
	sq->sq_svcflags = 0;
	sq->sq_nqueues = 0;
	sq->sq_pri = 0;
	sq->sq_onext = NULL;
	sq->sq_oprev = NULL;
	sq->sq_flags = 0;
	sq->sq_type = 0;
	sq->sq_servcount = 0;

	kmem_cache_free(syncq_cache, sq);
}

/* Outer perimeter code */

/*
 * The outer syncq uses the fields and flags in the syncq slightly
 * differently from the inner syncqs.
 *	sq_count	Incremented when there are pending or running
 *			writers at the outer perimeter to prevent the set of
 *			inner syncqs that belong to the outer perimeter from
 *			changing.
 *	sq_head/tail	List of deferred qwriter(OUTER) operations.
 *
 *	SQ_BLOCKED	Set to prevent traversing of sq_next,sq_prev while
 *			inner syncqs are added to or removed from the
 *			outer perimeter.
 *	SQ_QUEUED	sq_head/tail has messages or events queued.
 *
 *	SQ_WRITER	A thread is currently traversing all the inner syncqs
 *			setting the SQ_WRITER flag.
 */

/*
 * Get write access at the outer perimeter.
 * Note that read access is done by entersq, putnext, and put by simply
 * incrementing sq_count in the inner syncq.
 *
 * Waits until "flags" is no longer set in the outer to prevent multiple
 * threads from having write access at the same time. SQ_WRITER has to be part
 * of "flags".
 *
 * Increases sq_count on the outer syncq to keep away outer_insert/remove
 * until the outer_exit is finished.
 *
 * outer_enter is vulnerable to starvation since it does not prevent new
 * threads from entering the inner syncqs while it is waiting for sq_count to
 * go to zero.
 */
void
outer_enter(syncq_t *outer, uint16_t flags)
{
	syncq_t	*sq;
	int	wait_needed;
	uint16_t	count;

	ASSERT(outer->sq_outer == NULL && outer->sq_onext != NULL &&
	    outer->sq_oprev != NULL);
	ASSERT(flags & SQ_WRITER);

retry:
	mutex_enter(SQLOCK(outer));
	while (outer->sq_flags & flags) {
		outer->sq_flags |= SQ_WANTWAKEUP;
		cv_wait(&outer->sq_wait, SQLOCK(outer));
	}

	ASSERT(!(outer->sq_flags & SQ_WRITER));
	outer->sq_flags |= SQ_WRITER;
	outer->sq_count++;
	ASSERT(outer->sq_count != 0);	/* wraparound */
	wait_needed = 0;
	/*
	 * Set SQ_WRITER on all the inner syncqs while holding
	 * the SQLOCK on the outer syncq. This ensures that the changing
	 * of SQ_WRITER is atomic under the outer SQLOCK.
	 */
	for (sq = outer->sq_onext; sq != outer; sq = sq->sq_onext) {
		mutex_enter(SQLOCK(sq));
		count = sq->sq_count;
		SQ_PUTLOCKS_ENTER(sq);
		sq->sq_flags |= SQ_WRITER;
		SUM_SQ_PUTCOUNTS(sq, count);
		if (count != 0)
			wait_needed = 1;
		SQ_PUTLOCKS_EXIT(sq);
		mutex_exit(SQLOCK(sq));
	}
	mutex_exit(SQLOCK(outer));

	/*
	 * Get everybody out of the syncqs sequentially.
	 * Note that we don't actually need to acquire the PUTLOCKS, since
	 * we have already cleared the fastbit, and set QWRITER.  By
	 * definition, the count can not increase since putnext will
	 * take the slowlock path (and the purpose of acquiring the
	 * putlocks was to make sure it didn't increase while we were
	 * waiting).
	 *
	 * Note that we still acquire the PUTLOCKS to be safe.
	 */
	if (wait_needed) {
		for (sq = outer->sq_onext; sq != outer; sq = sq->sq_onext) {
			mutex_enter(SQLOCK(sq));
			count = sq->sq_count;
			SQ_PUTLOCKS_ENTER(sq);
			SUM_SQ_PUTCOUNTS(sq, count);
			while (count != 0) {
				sq->sq_flags |= SQ_WANTWAKEUP;
				SQ_PUTLOCKS_EXIT(sq);
				cv_wait(&sq->sq_wait, SQLOCK(sq));
				count = sq->sq_count;
				SQ_PUTLOCKS_ENTER(sq);
				SUM_SQ_PUTCOUNTS(sq, count);
			}
			SQ_PUTLOCKS_EXIT(sq);
			mutex_exit(SQLOCK(sq));
		}
		/*
		 * Verify that none of the flags got set while we
		 * were waiting for the sq_counts to drop.
		 * If this happens we exit and retry entering the
		 * outer perimeter.
		 */
		mutex_enter(SQLOCK(outer));
		if (outer->sq_flags & (flags & ~SQ_WRITER)) {
			mutex_exit(SQLOCK(outer));
			outer_exit(outer);
			goto retry;
		}
		mutex_exit(SQLOCK(outer));
	}
}

/*
 * Drop the write access at the outer perimeter.
 * Read access is dropped implicitly (by putnext, put, and leavesq) by
 * decrementing sq_count.
 */
void
outer_exit(syncq_t *outer)
{
	syncq_t	*sq;
	int	 drain_needed;
	uint16_t flags;

	ASSERT(outer->sq_outer == NULL && outer->sq_onext != NULL &&
	    outer->sq_oprev != NULL);
	ASSERT(MUTEX_NOT_HELD(SQLOCK(outer)));

	/*
	 * Atomically (from the perspective of threads calling become_writer)
	 * drop the write access at the outer perimeter by holding
	 * SQLOCK(outer) across all the dropsq calls and the resetting of
	 * SQ_WRITER.
	 * This defines a locking order between the outer perimeter
	 * SQLOCK and the inner perimeter SQLOCKs.
	 */
	mutex_enter(SQLOCK(outer));
	flags = outer->sq_flags;
	ASSERT(outer->sq_flags & SQ_WRITER);
	if (flags & SQ_QUEUED) {
		write_now(outer);
		flags = outer->sq_flags;
	}

	/*
	 * sq_onext is stable since sq_count has not yet been decreased.
	 * Reset the SQ_WRITER flags in all syncqs.
	 * After dropping SQ_WRITER on the outer syncq we empty all the
	 * inner syncqs.
	 */
	drain_needed = 0;
	for (sq = outer->sq_onext; sq != outer; sq = sq->sq_onext)
		drain_needed += dropsq(sq, SQ_WRITER);
	ASSERT(!(outer->sq_flags & SQ_QUEUED));
	flags &= ~SQ_WRITER;
	if (drain_needed) {
		outer->sq_flags = flags;
		mutex_exit(SQLOCK(outer));
		for (sq = outer->sq_onext; sq != outer; sq = sq->sq_onext)
			emptysq(sq);
		mutex_enter(SQLOCK(outer));
		flags = outer->sq_flags;
	}
	if (flags & SQ_WANTWAKEUP) {
		flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&outer->sq_wait);
	}
	outer->sq_flags = flags;
	ASSERT(outer->sq_count > 0);
	outer->sq_count--;
	mutex_exit(SQLOCK(outer));
}

/*
 * Add another syncq to an outer perimeter.
 * Block out all other access to the outer perimeter while it is being
 * changed using blocksq.
 * Assumes that the caller has *not* done an outer_enter.
 *
 * Vulnerable to starvation in blocksq.
 */
static void
outer_insert(syncq_t *outer, syncq_t *sq)
{
	ASSERT(outer->sq_outer == NULL && outer->sq_onext != NULL &&
	    outer->sq_oprev != NULL);
	ASSERT(sq->sq_outer == NULL && sq->sq_onext == NULL &&
	    sq->sq_oprev == NULL);	/* Can't be in an outer perimeter */

	/* Get exclusive access to the outer perimeter list */
	blocksq(outer, SQ_BLOCKED, 0);
	ASSERT(outer->sq_flags & SQ_BLOCKED);
	ASSERT(!(outer->sq_flags & SQ_WRITER));

	mutex_enter(SQLOCK(sq));
	sq->sq_outer = outer;
	outer->sq_onext->sq_oprev = sq;
	sq->sq_onext = outer->sq_onext;
	outer->sq_onext = sq;
	sq->sq_oprev = outer;
	mutex_exit(SQLOCK(sq));
	unblocksq(outer, SQ_BLOCKED, 1);
}

/*
 * Remove a syncq from an outer perimeter.
 * Block out all other access to the outer perimeter while it is being
 * changed using blocksq.
 * Assumes that the caller has *not* done an outer_enter.
 *
 * Vulnerable to starvation in blocksq.
 */
static void
outer_remove(syncq_t *outer, syncq_t *sq)
{
	ASSERT(outer->sq_outer == NULL && outer->sq_onext != NULL &&
	    outer->sq_oprev != NULL);
	ASSERT(sq->sq_outer == outer);

	/* Get exclusive access to the outer perimeter list */
	blocksq(outer, SQ_BLOCKED, 0);
	ASSERT(outer->sq_flags & SQ_BLOCKED);
	ASSERT(!(outer->sq_flags & SQ_WRITER));

	mutex_enter(SQLOCK(sq));
	sq->sq_outer = NULL;
	sq->sq_onext->sq_oprev = sq->sq_oprev;
	sq->sq_oprev->sq_onext = sq->sq_onext;
	sq->sq_oprev = sq->sq_onext = NULL;
	mutex_exit(SQLOCK(sq));
	unblocksq(outer, SQ_BLOCKED, 1);
}

/*
 * Queue a deferred qwriter(OUTER) callback for this outer perimeter.
 * If this is the first callback for this outer perimeter then add
 * this outer perimeter to the list of outer perimeters that
 * the qwriter_outer_thread will process.
 *
 * Increments sq_count in the outer syncq to prevent the membership
 * of the outer perimeter (in terms of inner syncqs) to change while
 * the callback is pending.
 */
static void
queue_writer(syncq_t *outer, void (*func)(), queue_t *q, mblk_t *mp)
{
	ASSERT(MUTEX_HELD(SQLOCK(outer)));

	mp->b_prev = (mblk_t *)func;
	mp->b_queue = q;
	mp->b_next = NULL;
	outer->sq_count++;	/* Decremented when dequeued */
	ASSERT(outer->sq_count != 0);	/* Wraparound */
	if (outer->sq_evhead == NULL) {
		/* First message. */
		outer->sq_evhead = outer->sq_evtail = mp;
		outer->sq_flags |= SQ_EVENTS;
		mutex_exit(SQLOCK(outer));
		STRSTAT(qwr_outer);
		(void) taskq_dispatch(streams_taskq,
		    (task_func_t *)qwriter_outer_service, outer, TQ_SLEEP);
	} else {
		ASSERT(outer->sq_flags & SQ_EVENTS);
		outer->sq_evtail->b_next = mp;
		outer->sq_evtail = mp;
		mutex_exit(SQLOCK(outer));
	}
}

/*
 * Try and upgrade to write access at the outer perimeter. If this can
 * not be done without blocking then queue the callback to be done
 * by the qwriter_outer_thread.
 *
 * This routine can only be called from put or service procedures plus
 * asynchronous callback routines that have properly entered the queue (with
 * entersq). Thus qwriter(OUTER) assumes the caller has one claim on the syncq
 * associated with q.
 */
void
qwriter_outer(queue_t *q, mblk_t *mp, void (*func)())
{
	syncq_t	*osq, *sq, *outer;
	int	failed;
	uint16_t flags;

	osq = q->q_syncq;
	outer = osq->sq_outer;
	if (outer == NULL)
		panic("qwriter(PERIM_OUTER): no outer perimeter");
	ASSERT(outer->sq_outer == NULL && outer->sq_onext != NULL &&
	    outer->sq_oprev != NULL);

	mutex_enter(SQLOCK(outer));
	flags = outer->sq_flags;
	/*
	 * If some thread is traversing sq_next, or if we are blocked by
	 * outer_insert or outer_remove, or if the we already have queued
	 * callbacks, then queue this callback for later processing.
	 *
	 * Also queue the qwriter for an interrupt thread in order
	 * to reduce the time spent running at high IPL.
	 * to identify there are events.
	 */
	if ((flags & SQ_GOAWAY) || (curthread->t_pri >= kpreemptpri)) {
		/*
		 * Queue the become_writer request.
		 * The queueing is atomic under SQLOCK(outer) in order
		 * to synchronize with outer_exit.
		 * queue_writer will drop the outer SQLOCK
		 */
		if (flags & SQ_BLOCKED) {
			/* Must set SQ_WRITER on inner perimeter */
			mutex_enter(SQLOCK(osq));
			osq->sq_flags |= SQ_WRITER;
			mutex_exit(SQLOCK(osq));
		} else {
			if (!(flags & SQ_WRITER)) {
				/*
				 * The outer could have been SQ_BLOCKED thus
				 * SQ_WRITER might not be set on the inner.
				 */
				mutex_enter(SQLOCK(osq));
				osq->sq_flags |= SQ_WRITER;
				mutex_exit(SQLOCK(osq));
			}
			ASSERT(osq->sq_flags & SQ_WRITER);
		}
		queue_writer(outer, func, q, mp);
		return;
	}
	/*
	 * We are half-way to exclusive access to the outer perimeter.
	 * Prevent any outer_enter, qwriter(OUTER), or outer_insert/remove
	 * while the inner syncqs are traversed.
	 */
	outer->sq_count++;
	ASSERT(outer->sq_count != 0);	/* wraparound */
	flags |= SQ_WRITER;
	/*
	 * Check if we can run the function immediately. Mark all
	 * syncqs with the writer flag to prevent new entries into
	 * put and service procedures.
	 *
	 * Set SQ_WRITER on all the inner syncqs while holding
	 * the SQLOCK on the outer syncq. This ensures that the changing
	 * of SQ_WRITER is atomic under the outer SQLOCK.
	 */
	failed = 0;
	for (sq = outer->sq_onext; sq != outer; sq = sq->sq_onext) {
		uint16_t count;
		uint_t	maxcnt = (sq == osq) ? 1 : 0;

		mutex_enter(SQLOCK(sq));
		count = sq->sq_count;
		SQ_PUTLOCKS_ENTER(sq);
		SUM_SQ_PUTCOUNTS(sq, count);
		if (sq->sq_count > maxcnt)
			failed = 1;
		sq->sq_flags |= SQ_WRITER;
		SQ_PUTLOCKS_EXIT(sq);
		mutex_exit(SQLOCK(sq));
	}
	if (failed) {
		/*
		 * Some other thread has a read claim on the outer perimeter.
		 * Queue the callback for deferred processing.
		 *
		 * queue_writer will set SQ_QUEUED before we drop SQ_WRITER
		 * so that other qwriter(OUTER) calls will queue their
		 * callbacks as well. queue_writer increments sq_count so we
		 * decrement to compensate for the our increment.
		 *
		 * Dropping SQ_WRITER enables the writer thread to work
		 * on this outer perimeter.
		 */
		outer->sq_flags = flags;
		queue_writer(outer, func, q, mp);
		/* queue_writer dropper the lock */
		mutex_enter(SQLOCK(outer));
		ASSERT(outer->sq_count > 0);
		outer->sq_count--;
		ASSERT(outer->sq_flags & SQ_WRITER);
		flags = outer->sq_flags;
		flags &= ~SQ_WRITER;
		if (flags & SQ_WANTWAKEUP) {
			flags &= ~SQ_WANTWAKEUP;
			cv_broadcast(&outer->sq_wait);
		}
		outer->sq_flags = flags;
		mutex_exit(SQLOCK(outer));
		return;
	} else {
		outer->sq_flags = flags;
		mutex_exit(SQLOCK(outer));
	}

	/* Can run it immediately */
	(*func)(q, mp);

	outer_exit(outer);
}

/*
 * Dequeue all writer callbacks from the outer perimeter and run them.
 */
static void
write_now(syncq_t *outer)
{
	mblk_t		*mp;
	queue_t		*q;
	void	(*func)();

	ASSERT(MUTEX_HELD(SQLOCK(outer)));
	ASSERT(outer->sq_outer == NULL && outer->sq_onext != NULL &&
	    outer->sq_oprev != NULL);
	while ((mp = outer->sq_evhead) != NULL) {
		/*
		 * queues cannot be placed on the queuelist on the outer
		 * perimeter.
		 */
		ASSERT(!(outer->sq_flags & SQ_MESSAGES));
		ASSERT((outer->sq_flags & SQ_EVENTS));

		outer->sq_evhead = mp->b_next;
		if (outer->sq_evhead == NULL) {
			outer->sq_evtail = NULL;
			outer->sq_flags &= ~SQ_EVENTS;
		}
		ASSERT(outer->sq_count != 0);
		outer->sq_count--;	/* Incremented when enqueued. */
		mutex_exit(SQLOCK(outer));
		/*
		 * Drop the message if the queue is closing.
		 * Make sure that the queue is "claimed" when the callback
		 * is run in order to satisfy various ASSERTs.
		 */
		q = mp->b_queue;
		func = (void (*)())mp->b_prev;
		ASSERT(func != NULL);
		mp->b_next = mp->b_prev = NULL;
		if (q->q_flag & QWCLOSE) {
			freemsg(mp);
		} else {
			claimq(q);
			(*func)(q, mp);
			releaseq(q);
		}
		mutex_enter(SQLOCK(outer));
	}
	ASSERT(MUTEX_HELD(SQLOCK(outer)));
}

/*
 * The list of messages on the inner syncq is effectively hashed
 * by destination queue.  These destination queues are doubly
 * linked lists (hopefully) in priority order.  Messages are then
 * put on the queue referenced by the q_sqhead/q_sqtail elements.
 * Additional messages are linked together by the b_next/b_prev
 * elements in the mblk, with (similar to putq()) the first message
 * having a NULL b_prev and the last message having a NULL b_next.
 *
 * Events, such as qwriter callbacks, are put onto a list in FIFO
 * order referenced by sq_evhead, and sq_evtail.  This is a singly
 * linked list, and messages here MUST be processed in the order queued.
 */

/*
 * Run the events on the syncq event list (sq_evhead).
 * Assumes there is only one claim on the syncq, it is
 * already exclusive (SQ_EXCL set), and the SQLOCK held.
 * Messages here are processed in order, with the SQ_EXCL bit
 * held all the way through till the last message is processed.
 */
void
sq_run_events(syncq_t *sq)
{
	mblk_t		*bp;
	queue_t		*qp;
	uint16_t	flags = sq->sq_flags;
	void		(*func)();

	ASSERT(MUTEX_HELD(SQLOCK(sq)));
	ASSERT((sq->sq_outer == NULL && sq->sq_onext == NULL &&
	    sq->sq_oprev == NULL) ||
	    (sq->sq_outer != NULL && sq->sq_onext != NULL &&
	    sq->sq_oprev != NULL));

	ASSERT(flags & SQ_EXCL);
	ASSERT(sq->sq_count == 1);

	/*
	 * We need to process all of the events on this list.  It
	 * is possible that new events will be added while we are
	 * away processing a callback, so on every loop, we start
	 * back at the beginning of the list.
	 */
	/*
	 * We have to reaccess sq_evhead since there is a
	 * possibility of a new entry while we were running
	 * the callback.
	 */
	for (bp = sq->sq_evhead; bp != NULL; bp = sq->sq_evhead) {
		ASSERT(bp->b_queue->q_syncq == sq);
		ASSERT(sq->sq_flags & SQ_EVENTS);

		qp = bp->b_queue;
		func = (void (*)())bp->b_prev;
		ASSERT(func != NULL);

		/*
		 * Messages from the event queue must be taken off in
		 * FIFO order.
		 */
		ASSERT(sq->sq_evhead == bp);
		sq->sq_evhead = bp->b_next;

		if (bp->b_next == NULL) {
			/* Deleting last */
			ASSERT(sq->sq_evtail == bp);
			sq->sq_evtail = NULL;
			sq->sq_flags &= ~SQ_EVENTS;
		}
		bp->b_prev = bp->b_next = NULL;
		ASSERT(bp->b_datap->db_ref != 0);

		mutex_exit(SQLOCK(sq));

		(*func)(qp, bp);

		mutex_enter(SQLOCK(sq));
		/*
		 * re-read the flags, since they could have changed.
		 */
		flags = sq->sq_flags;
		ASSERT(flags & SQ_EXCL);
	}
	ASSERT(sq->sq_evhead == NULL && sq->sq_evtail == NULL);
	ASSERT(!(sq->sq_flags & SQ_EVENTS));

	if (flags & SQ_WANTWAKEUP) {
		flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&sq->sq_wait);
	}
	if (flags & SQ_WANTEXWAKEUP) {
		flags &= ~SQ_WANTEXWAKEUP;
		cv_broadcast(&sq->sq_exitwait);
	}
	sq->sq_flags = flags;
}

/*
 * Put messages on the event list.
 * If we can go exclusive now, do so and process the event list, otherwise
 * let the last claim service this list (or wake the sqthread).
 * This procedure assumes SQLOCK is held.  To run the event list, it
 * must be called with no claims.
 */
static void
sqfill_events(syncq_t *sq, queue_t *q, mblk_t *mp, void (*func)())
{
	uint16_t count;

	ASSERT(MUTEX_HELD(SQLOCK(sq)));
	ASSERT(func != NULL);

	/*
	 * This is a callback.  Add it to the list of callbacks
	 * and see about upgrading.
	 */
	mp->b_prev = (mblk_t *)func;
	mp->b_queue = q;
	mp->b_next = NULL;
	if (sq->sq_evhead == NULL) {
		sq->sq_evhead = sq->sq_evtail = mp;
		sq->sq_flags |= SQ_EVENTS;
	} else {
		ASSERT(sq->sq_evtail != NULL);
		ASSERT(sq->sq_evtail->b_next == NULL);
		ASSERT(sq->sq_flags & SQ_EVENTS);
		sq->sq_evtail->b_next = mp;
		sq->sq_evtail = mp;
	}
	/*
	 * We have set SQ_EVENTS, so threads will have to
	 * unwind out of the perimeter, and new entries will
	 * not grab a putlock.  But we still need to know
	 * how many threads have already made a claim to the
	 * syncq, so grab the putlocks, and sum the counts.
	 * If there are no claims on the syncq, we can upgrade
	 * to exclusive, and run the event list.
	 * NOTE: We hold the SQLOCK, so we can just grab the
	 * putlocks.
	 */
	count = sq->sq_count;
	SQ_PUTLOCKS_ENTER(sq);
	SUM_SQ_PUTCOUNTS(sq, count);
	/*
	 * We have no claim, so we need to check if there
	 * are no others, then we can upgrade.
	 */
	/*
	 * There are currently no claims on
	 * the syncq by this thread (at least on this entry). The thread who has
	 * the claim should drain syncq.
	 */
	if (count > 0) {
		/*
		 * Can't upgrade - other threads inside.
		 */
		SQ_PUTLOCKS_EXIT(sq);
		mutex_exit(SQLOCK(sq));
		return;
	}
	/*
	 * Need to set SQ_EXCL and make a claim on the syncq.
	 */
	ASSERT((sq->sq_flags & SQ_EXCL) == 0);
	sq->sq_flags |= SQ_EXCL;
	ASSERT(sq->sq_count == 0);
	sq->sq_count++;
	SQ_PUTLOCKS_EXIT(sq);

	/* Process the events list */
	sq_run_events(sq);

	/*
	 * Release our claim...
	 */
	sq->sq_count--;

	/*
	 * And release SQ_EXCL.
	 * We don't need to acquire the putlocks to release
	 * SQ_EXCL, since we are exclusive, and hold the SQLOCK.
	 */
	sq->sq_flags &= ~SQ_EXCL;

	/*
	 * sq_run_events should have released SQ_EXCL
	 */
	ASSERT(!(sq->sq_flags & SQ_EXCL));

	/*
	 * If anything happened while we were running the
	 * events (or was there before), we need to process
	 * them now.  We shouldn't be exclusive sine we
	 * released the perimeter above (plus, we asserted
	 * for it).
	 */
	if (!(sq->sq_flags & SQ_STAYAWAY) && (sq->sq_flags & SQ_QUEUED))
		drain_syncq(sq);
	else
		mutex_exit(SQLOCK(sq));
}

/*
 * Perform delayed processing. The caller has to make sure that it is safe
 * to enter the syncq (e.g. by checking that none of the SQ_STAYAWAY bits are
 * set).
 *
 * Assume that the caller has NO claims on the syncq.  However, a claim
 * on the syncq does not indicate that a thread is draining the syncq.
 * There may be more claims on the syncq than there are threads draining
 * (i.e.  #_threads_draining <= sq_count)
 *
 * drain_syncq has to terminate when one of the SQ_STAYAWAY bits gets set
 * in order to preserve qwriter(OUTER) ordering constraints.
 *
 * sq_putcount only needs to be checked when dispatching the queued
 * writer call for CIPUT sync queue, but this is handled in sq_run_events.
 */
void
drain_syncq(syncq_t *sq)
{
	queue_t		*qp;
	uint16_t	count;
	uint16_t	type = sq->sq_type;
	uint16_t	flags = sq->sq_flags;
	boolean_t	bg_service = sq->sq_svcflags & SQ_SERVICE;

	TRACE_1(TR_FAC_STREAMS_FR, TR_DRAIN_SYNCQ_START,
	    "drain_syncq start:%p", sq);
	ASSERT(MUTEX_HELD(SQLOCK(sq)));
	ASSERT((sq->sq_outer == NULL && sq->sq_onext == NULL &&
	    sq->sq_oprev == NULL) ||
	    (sq->sq_outer != NULL && sq->sq_onext != NULL &&
	    sq->sq_oprev != NULL));

	/*
	 * Drop SQ_SERVICE flag.
	 */
	if (bg_service)
		sq->sq_svcflags &= ~SQ_SERVICE;

	/*
	 * If SQ_EXCL is set, someone else is processing this syncq - let him
	 * finish the job.
	 */
	if (flags & SQ_EXCL) {
		if (bg_service) {
			ASSERT(sq->sq_servcount != 0);
			sq->sq_servcount--;
		}
		mutex_exit(SQLOCK(sq));
		return;
	}

	/*
	 * This routine can be called by a background thread if
	 * it was scheduled by a hi-priority thread.  SO, if there are
	 * NOT messages queued, return (remember, we have the SQLOCK,
	 * and it cannot change until we release it). Wakeup any waiters also.
	 */
	if (!(flags & SQ_QUEUED)) {
		if (flags & SQ_WANTWAKEUP) {
			flags &= ~SQ_WANTWAKEUP;
			cv_broadcast(&sq->sq_wait);
		}
		if (flags & SQ_WANTEXWAKEUP) {
			flags &= ~SQ_WANTEXWAKEUP;
			cv_broadcast(&sq->sq_exitwait);
		}
		sq->sq_flags = flags;
		if (bg_service) {
			ASSERT(sq->sq_servcount != 0);
			sq->sq_servcount--;
		}
		mutex_exit(SQLOCK(sq));
		return;
	}

	/*
	 * If this is not a concurrent put perimeter, we need to
	 * become exclusive to drain.  Also, if not CIPUT, we would
	 * not have acquired a putlock, so we don't need to check
	 * the putcounts.  If not entering with a claim, we test
	 * for sq_count == 0.
	 */
	type = sq->sq_type;
	if (!(type & SQ_CIPUT)) {
		if (sq->sq_count > 1) {
			if (bg_service) {
				ASSERT(sq->sq_servcount != 0);
				sq->sq_servcount--;
			}
			mutex_exit(SQLOCK(sq));
			return;
		}
		sq->sq_flags |= SQ_EXCL;
	}

	/*
	 * This is where we make a claim to the syncq.
	 * This can either be done by incrementing a putlock, or
	 * the sq_count.  But since we already have the SQLOCK
	 * here, we just bump the sq_count.
	 *
	 * Note that after we make a claim, we need to let the code
	 * fall through to the end of this routine to clean itself
	 * up.  A return in the while loop will put the syncq in a
	 * very bad state.
	 */
	sq->sq_count++;
	ASSERT(sq->sq_count != 0);	/* wraparound */

	while ((flags = sq->sq_flags) & SQ_QUEUED) {
		/*
		 * If we are told to stayaway or went exclusive,
		 * we are done.
		 */
		if (flags & (SQ_STAYAWAY)) {
			break;
		}

		/*
		 * If there are events to run, do so.
		 * We have one claim to the syncq, so if there are
		 * more than one, other threads are running.
		 */
		if (sq->sq_evhead != NULL) {
			ASSERT(sq->sq_flags & SQ_EVENTS);

			count = sq->sq_count;
			SQ_PUTLOCKS_ENTER(sq);
			SUM_SQ_PUTCOUNTS(sq, count);
			if (count > 1) {
				SQ_PUTLOCKS_EXIT(sq);
				/* Can't upgrade - other threads inside */
				break;
			}
			ASSERT((flags & SQ_EXCL) == 0);
			sq->sq_flags = flags | SQ_EXCL;
			SQ_PUTLOCKS_EXIT(sq);
			/*
			 * we have the only claim, run the events,
			 * sq_run_events will clear the SQ_EXCL flag.
			 */
			sq_run_events(sq);

			/*
			 * If this is a CIPUT perimeter, we need
			 * to drop the SQ_EXCL flag so we can properly
			 * continue draining the syncq.
			 */
			if (type & SQ_CIPUT) {
				ASSERT(sq->sq_flags & SQ_EXCL);
				sq->sq_flags &= ~SQ_EXCL;
			}

			/*
			 * And go back to the beginning just in case
			 * anything changed while we were away.
			 */
			ASSERT((sq->sq_flags & SQ_EXCL) || (type & SQ_CIPUT));
			continue;
		}

		ASSERT(sq->sq_evhead == NULL);
		ASSERT(!(sq->sq_flags & SQ_EVENTS));

		/*
		 * Find the queue that is not draining.
		 *
		 * q_draining is protected by QLOCK which we do not hold.
		 * But if it was set, then a thread was draining, and if it gets
		 * cleared, then it was because the thread has successfully
		 * drained the syncq, or a GOAWAY state occurred. For the GOAWAY
		 * state to happen, a thread needs the SQLOCK which we hold, and
		 * if there was such a flag, we would have already seen it.
		 */

		for (qp = sq->sq_head;
		    qp != NULL && (qp->q_draining ||
		    (qp->q_sqflags & Q_SQDRAINING));
		    qp = qp->q_sqnext)
			;

		if (qp == NULL)
			break;

		/*
		 * We have a queue to work on, and we hold the
		 * SQLOCK and one claim, call qdrain_syncq.
		 * This means we need to release the SQLOCK and
		 * acquire the QLOCK (OK since we have a claim).
		 * Note that qdrain_syncq will actually dequeue
		 * this queue from the sq_head list when it is
		 * convinced all the work is done and release
		 * the QLOCK before returning.
		 */
		qp->q_sqflags |= Q_SQDRAINING;
		mutex_exit(SQLOCK(sq));
		mutex_enter(QLOCK(qp));
		qdrain_syncq(sq, qp);
		mutex_enter(SQLOCK(sq));

		/* The queue is drained */
		ASSERT(qp->q_sqflags & Q_SQDRAINING);
		qp->q_sqflags &= ~Q_SQDRAINING;
		/*
		 * NOTE: After this point qp should not be used since it may be
		 * closed.
		 */
	}

	ASSERT(MUTEX_HELD(SQLOCK(sq)));
	flags = sq->sq_flags;

	/*
	 * sq->sq_head cannot change because we hold the
	 * sqlock. However, a thread CAN decide that it is no longer
	 * going to drain that queue.  However, this should be due to
	 * a GOAWAY state, and we should see that here.
	 *
	 * This loop is not very efficient. One solution may be adding a second
	 * pointer to the "draining" queue, but it is difficult to do when
	 * queues are inserted in the middle due to priority ordering. Another
	 * possibility is to yank the queue out of the sq list and put it onto
	 * the "draining list" and then put it back if it can't be drained.
	 */

	ASSERT((sq->sq_head == NULL) || (flags & SQ_GOAWAY) ||
	    (type & SQ_CI) || sq->sq_head->q_draining);

	/* Drop SQ_EXCL for non-CIPUT perimeters */
	if (!(type & SQ_CIPUT))
		flags &= ~SQ_EXCL;
	ASSERT((flags & SQ_EXCL) == 0);

	/* Wake up any waiters. */
	if (flags & SQ_WANTWAKEUP) {
		flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&sq->sq_wait);
	}
	if (flags & SQ_WANTEXWAKEUP) {
		flags &= ~SQ_WANTEXWAKEUP;
		cv_broadcast(&sq->sq_exitwait);
	}
	sq->sq_flags = flags;

	ASSERT(sq->sq_count != 0);
	/* Release our claim. */
	sq->sq_count--;

	if (bg_service) {
		ASSERT(sq->sq_servcount != 0);
		sq->sq_servcount--;
	}

	mutex_exit(SQLOCK(sq));

	TRACE_1(TR_FAC_STREAMS_FR, TR_DRAIN_SYNCQ_END,
	    "drain_syncq end:%p", sq);
}


/*
 *
 * qdrain_syncq can be called (currently) from only one of two places:
 *	drain_syncq
 * 	putnext  (or some variation of it).
 * and eventually
 * 	qwait(_sig)
 *
 * If called from drain_syncq, we found it in the list of queues needing
 * service, so there is work to be done (or it wouldn't be in the list).
 *
 * If called from some putnext variation, it was because the
 * perimeter is open, but messages are blocking a putnext and
 * there is not a thread working on it.  Now a thread could start
 * working on it while we are getting ready to do so ourself, but
 * the thread would set the q_draining flag, and we can spin out.
 *
 * As for qwait(_sig), I think I shall let it continue to call
 * drain_syncq directly (after all, it will get here eventually).
 *
 * qdrain_syncq has to terminate when:
 * - one of the SQ_STAYAWAY bits gets set to preserve qwriter(OUTER) ordering
 * - SQ_EVENTS gets set to preserve qwriter(INNER) ordering
 *
 * ASSUMES:
 *	One claim
 * 	QLOCK held
 * 	SQLOCK not held
 *	Will release QLOCK before returning
 */
void
qdrain_syncq(syncq_t *sq, queue_t *q)
{
	mblk_t		*bp;
#ifdef DEBUG
	uint16_t	count;
#endif

	TRACE_1(TR_FAC_STREAMS_FR, TR_DRAIN_SYNCQ_START,
	    "drain_syncq start:%p", sq);
	ASSERT(q->q_syncq == sq);
	ASSERT(MUTEX_HELD(QLOCK(q)));
	ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
	/*
	 * For non-CIPUT perimeters, we should be called with the exclusive bit
	 * set already. For CIPUT perimeters, we will be doing a concurrent
	 * drain, so it better not be set.
	 */
	ASSERT((sq->sq_flags & (SQ_EXCL|SQ_CIPUT)));
	ASSERT(!((sq->sq_type & SQ_CIPUT) && (sq->sq_flags & SQ_EXCL)));
	ASSERT((sq->sq_type & SQ_CIPUT) || (sq->sq_flags & SQ_EXCL));
	/*
	 * All outer pointers are set, or none of them are
	 */
	ASSERT((sq->sq_outer == NULL && sq->sq_onext == NULL &&
	    sq->sq_oprev == NULL) ||
	    (sq->sq_outer != NULL && sq->sq_onext != NULL &&
	    sq->sq_oprev != NULL));
#ifdef DEBUG
	count = sq->sq_count;
	/*
	 * This is OK without the putlocks, because we have one
	 * claim either from the sq_count, or a putcount.  We could
	 * get an erroneous value from other counts, but ours won't
	 * change, so one way or another, we will have at least a
	 * value of one.
	 */
	SUM_SQ_PUTCOUNTS(sq, count);
	ASSERT(count >= 1);
#endif /* DEBUG */

	/*
	 * The first thing to do is find out if a thread is already draining
	 * this queue. If so, we are done, just return.
	 */
	if (q->q_draining) {
		mutex_exit(QLOCK(q));
		return;
	}

	/*
	 * If the perimeter is exclusive, there is nothing we can do right now,
	 * go away. Note that there is nothing to prevent this case from
	 * changing right after this check, but the spin-out will catch it.
	 */

	/* Tell other threads that we are draining this queue */
	q->q_draining = 1;	/* Protected by QLOCK */

	/*
	 * If there is nothing to do, clear QFULL as necessary. This caters for
	 * the case where an empty queue was enqueued onto the syncq.
	 */
	if (q->q_sqhead == NULL) {
		ASSERT(q->q_syncqmsgs == 0);
		mutex_exit(QLOCK(q));
		clr_qfull(q);
		mutex_enter(QLOCK(q));
	}

	/*
	 * Note that q_sqhead must be re-checked here in case another message
	 * was enqueued whilst QLOCK was dropped during the call to clr_qfull.
	 */
	for (bp = q->q_sqhead; bp != NULL; bp = q->q_sqhead) {
		/*
		 * Because we can enter this routine just because a putnext is
		 * blocked, we need to spin out if the perimeter wants to go
		 * exclusive as well as just blocked. We need to spin out also
		 * if events are queued on the syncq.
		 * Don't check for SQ_EXCL, because non-CIPUT perimeters would
		 * set it, and it can't become exclusive while we hold a claim.
		 */
		if (sq->sq_flags & (SQ_STAYAWAY | SQ_EVENTS)) {
			break;
		}

#ifdef DEBUG
		/*
		 * Since we are in qdrain_syncq, we already know the queue,
		 * but for sanity, we want to check this against the qp that
		 * was passed in by bp->b_queue.
		 */

		ASSERT(bp->b_queue == q);
		ASSERT(bp->b_queue->q_syncq == sq);
		bp->b_queue = NULL;

		/*
		 * We would have the following check in the DEBUG code:
		 *
		 * if (bp->b_prev != NULL)  {
		 *	ASSERT(bp->b_prev == (void (*)())q->q_qinfo->qi_putp);
		 * }
		 *
		 * This can't be done, however, since IP modifies qinfo
		 * structure at run-time (switching between IPv4 qinfo and IPv6
		 * qinfo), invalidating the check.
		 * So the assignment to func is left here, but the ASSERT itself
		 * is removed until the whole issue is resolved.
		 */
#endif
		ASSERT(q->q_sqhead == bp);
		q->q_sqhead = bp->b_next;
		bp->b_prev = bp->b_next = NULL;
		ASSERT(q->q_syncqmsgs > 0);
		mutex_exit(QLOCK(q));

		ASSERT(bp->b_datap->db_ref != 0);

		(void) (*q->q_qinfo->qi_putp)(q, bp);

		mutex_enter(QLOCK(q));

		/*
		 * q_syncqmsgs should only be decremented after executing the
		 * put procedure to avoid message re-ordering. This is due to an
		 * optimisation in putnext() which can call the put procedure
		 * directly if it sees q_syncqmsgs == 0 (despite Q_SQQUEUED
		 * being set).
		 *
		 * We also need to clear QFULL in the next service procedure
		 * queue if this is the last message destined for that queue.
		 *
		 * It would make better sense to have some sort of tunable for
		 * the low water mark, but these semantics are not yet defined.
		 * So, alas, we use a constant.
		 */
		if (--q->q_syncqmsgs == 0) {
			mutex_exit(QLOCK(q));
			clr_qfull(q);
			mutex_enter(QLOCK(q));
		}

		/*
		 * Always clear SQ_EXCL when CIPUT in order to handle
		 * qwriter(INNER). The putp() can call qwriter and get exclusive
		 * access IFF this is the only claim. So, we need to test for
		 * this possibility, acquire the mutex and clear the bit.
		 */
		if ((sq->sq_type & SQ_CIPUT) && (sq->sq_flags & SQ_EXCL)) {
			mutex_enter(SQLOCK(sq));
			sq->sq_flags &= ~SQ_EXCL;
			mutex_exit(SQLOCK(sq));
		}
	}

	/*
	 * We should either have no messages on this queue, or we were told to
	 * goaway by a waiter (which we will wake up at the end of this
	 * function).
	 */
	ASSERT((q->q_sqhead == NULL) ||
	    (sq->sq_flags & (SQ_STAYAWAY | SQ_EVENTS)));

	ASSERT(MUTEX_HELD(QLOCK(q)));
	ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));

	/* Remove the q from the syncq list if all the messages are drained. */
	if (q->q_sqhead == NULL) {
		ASSERT(q->q_syncqmsgs == 0);
		mutex_enter(SQLOCK(sq));
		if (q->q_sqflags & Q_SQQUEUED)
			SQRM_Q(sq, q);
		mutex_exit(SQLOCK(sq));
		/*
		 * Since the queue is removed from the list, reset its priority.
		 */
		q->q_spri = 0;
	}

	/*
	 * Remember, the q_draining flag is used to let another thread know
	 * that there is a thread currently draining the messages for a queue.
	 * Since we are now done with this queue (even if there may be messages
	 * still there), we need to clear this flag so some thread will work on
	 * it if needed.
	 */
	ASSERT(q->q_draining);
	q->q_draining = 0;

	/* Called with a claim, so OK to drop all locks. */
	mutex_exit(QLOCK(q));

	TRACE_1(TR_FAC_STREAMS_FR, TR_DRAIN_SYNCQ_END,
	    "drain_syncq end:%p", sq);
}
/* END OF QDRAIN_SYNCQ  */


/*
 * This is the mate to qdrain_syncq, except that it is putting the message onto
 * the queue instead of draining. Since the message is destined for the queue
 * that is selected, there is no need to identify the function because the
 * message is intended for the put routine for the queue. For debug kernels,
 * this routine will do it anyway just in case.
 *
 * After the message is enqueued on the syncq, it calls putnext_tail()
 * which will schedule a background thread to actually process the message.
 *
 * Assumes that there is a claim on the syncq (sq->sq_count > 0) and
 * SQLOCK(sq) and QLOCK(q) are not held.
 */
void
qfill_syncq(syncq_t *sq, queue_t *q, mblk_t *mp)
{
	ASSERT(MUTEX_NOT_HELD(SQLOCK(sq)));
	ASSERT(MUTEX_NOT_HELD(QLOCK(q)));
	ASSERT(sq->sq_count > 0);
	ASSERT(q->q_syncq == sq);
	ASSERT((sq->sq_outer == NULL && sq->sq_onext == NULL &&
	    sq->sq_oprev == NULL) ||
	    (sq->sq_outer != NULL && sq->sq_onext != NULL &&
	    sq->sq_oprev != NULL));

	mutex_enter(QLOCK(q));

#ifdef DEBUG
	/*
	 * This is used for debug in the qfill_syncq/qdrain_syncq case
	 * to trace the queue that the message is intended for.  Note
	 * that the original use was to identify the queue and function
	 * to call on the drain.  In the new syncq, we have the context
	 * of the queue that we are draining, so call it's putproc and
	 * don't rely on the saved values.  But for debug this is still
	 * useful information.
	 */
	mp->b_prev = (mblk_t *)q->q_qinfo->qi_putp;
	mp->b_queue = q;
	mp->b_next = NULL;
#endif
	ASSERT(q->q_syncq == sq);
	/*
	 * Enqueue the message on the list.
	 * SQPUT_MP() accesses q_syncqmsgs.  We are already holding QLOCK to
	 * protect it.  So it's ok to acquire SQLOCK after SQPUT_MP().
	 */
	SQPUT_MP(q, mp);
	mutex_enter(SQLOCK(sq));

	/*
	 * And queue on syncq for scheduling, if not already queued.
	 * Note that we need the SQLOCK for this, and for testing flags
	 * at the end to see if we will drain.  So grab it now, and
	 * release it before we call qdrain_syncq or return.
	 */
	if (!(q->q_sqflags & Q_SQQUEUED)) {
		q->q_spri = curthread->t_pri;
		SQPUT_Q(sq, q);
	}
#ifdef DEBUG
	else {
		/*
		 * All of these conditions MUST be true!
		 */
		ASSERT(sq->sq_tail != NULL);
		if (sq->sq_tail == sq->sq_head) {
			ASSERT((q->q_sqprev == NULL) &&
			    (q->q_sqnext == NULL));
		} else {
			ASSERT((q->q_sqprev != NULL) ||
			    (q->q_sqnext != NULL));
		}
		ASSERT(sq->sq_flags & SQ_QUEUED);
		ASSERT(q->q_syncqmsgs != 0);
		ASSERT(q->q_sqflags & Q_SQQUEUED);
	}
#endif
	mutex_exit(QLOCK(q));
	/*
	 * SQLOCK is still held, so sq_count can be safely decremented.
	 */
	sq->sq_count--;

	putnext_tail(sq, q, 0);
	/* Should not reference sq or q after this point. */
}

/*  End of qfill_syncq  */

/*
 * Remove all messages from a syncq (if qp is NULL) or remove all messages
 * that would be put into qp by drain_syncq.
 * Used when deleting the syncq (qp == NULL) or when detaching
 * a queue (qp != NULL).
 * Return non-zero if one or more messages were freed.
 *
 * No need to grab sq_putlocks here. See comment in strsubr.h that explains when
 * sq_putlocks are used.
 *
 * NOTE: This function assumes that it is called from the close() context and
 * that all the queues in the syncq are going away. For this reason it doesn't
 * acquire QLOCK for modifying q_sqhead/q_sqtail fields. This assumption is
 * currently valid, but it is useful to rethink this function to behave properly
 * in other cases.
 */
int
flush_syncq(syncq_t *sq, queue_t *qp)
{
	mblk_t		*bp, *mp_head, *mp_next, *mp_prev;
	queue_t		*q;
	int		ret = 0;

	mutex_enter(SQLOCK(sq));

	/*
	 * Before we leave, we need to make sure there are no
	 * events listed for this queue.  All events for this queue
	 * will just be freed.
	 */
	if (qp != NULL && sq->sq_evhead != NULL) {
		ASSERT(sq->sq_flags & SQ_EVENTS);

		mp_prev = NULL;
		for (bp = sq->sq_evhead; bp != NULL; bp = mp_next) {
			mp_next = bp->b_next;
			if (bp->b_queue == qp) {
				/* Delete this message */
				if (mp_prev != NULL) {
					mp_prev->b_next = mp_next;
					/*
					 * Update sq_evtail if the last element
					 * is removed.
					 */
					if (bp == sq->sq_evtail) {
						ASSERT(mp_next == NULL);
						sq->sq_evtail = mp_prev;
					}
				} else
					sq->sq_evhead = mp_next;
				if (sq->sq_evhead == NULL)
					sq->sq_flags &= ~SQ_EVENTS;
				bp->b_prev = bp->b_next = NULL;
				freemsg(bp);
				ret++;
			} else {
				mp_prev = bp;
			}
		}
	}

	/*
	 * Walk sq_head and:
	 *	- match qp if qp is set, remove it's messages
	 *	- all if qp is not set
	 */
	q = sq->sq_head;
	while (q != NULL) {
		ASSERT(q->q_syncq == sq);
		if ((qp == NULL) || (qp == q)) {
			/*
			 * Yank the messages as a list off the queue
			 */
			mp_head = q->q_sqhead;
			/*
			 * We do not have QLOCK(q) here (which is safe due to
			 * assumptions mentioned above). To obtain the lock we
			 * need to release SQLOCK which may allow lots of things
			 * to change upon us. This place requires more analysis.
			 */
			q->q_sqhead = q->q_sqtail = NULL;
			ASSERT(mp_head->b_queue &&
			    mp_head->b_queue->q_syncq == sq);

			/*
			 * Free each of the messages.
			 */
			for (bp = mp_head; bp != NULL; bp = mp_next) {
				mp_next = bp->b_next;
				bp->b_prev = bp->b_next = NULL;
				freemsg(bp);
				ret++;
			}
			/*
			 * Now remove the queue from the syncq.
			 */
			ASSERT(q->q_sqflags & Q_SQQUEUED);
			SQRM_Q(sq, q);
			q->q_spri = 0;
			q->q_syncqmsgs = 0;

			/*
			 * If qp was specified, we are done with it and are
			 * going to drop SQLOCK(sq) and return. We wakeup syncq
			 * waiters while we still have the SQLOCK.
			 */
			if ((qp != NULL) && (sq->sq_flags & SQ_WANTWAKEUP)) {
				sq->sq_flags &= ~SQ_WANTWAKEUP;
				cv_broadcast(&sq->sq_wait);
			}
			/* Drop SQLOCK across clr_qfull */
			mutex_exit(SQLOCK(sq));

			/*
			 * We avoid doing the test that drain_syncq does and
			 * unconditionally clear qfull for every flushed
			 * message. Since flush_syncq is only called during
			 * close this should not be a problem.
			 */
			clr_qfull(q);
			if (qp != NULL) {
				return (ret);
			} else {
				mutex_enter(SQLOCK(sq));
				/*
				 * The head was removed by SQRM_Q above.
				 * reread the new head and flush it.
				 */
				q = sq->sq_head;
			}
		} else {
			q = q->q_sqnext;
		}
		ASSERT(MUTEX_HELD(SQLOCK(sq)));
	}

	if (sq->sq_flags & SQ_WANTWAKEUP) {
		sq->sq_flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&sq->sq_wait);
	}

	mutex_exit(SQLOCK(sq));
	return (ret);
}

/*
 * Propagate all messages from a syncq to the next syncq that are associated
 * with the specified queue. If the queue is attached to a driver or if the
 * messages have been added due to a qwriter(PERIM_INNER), free the messages.
 *
 * Assumes that the stream is strlock()'ed. We don't come here if there
 * are no messages to propagate.
 *
 * NOTE : If the queue is attached to a driver, all the messages are freed
 * as there is no point in propagating the messages from the driver syncq
 * to the closing stream head which will in turn get freed later.
 */
static int
propagate_syncq(queue_t *qp)
{
	mblk_t		*bp, *head, *tail, *prev, *next;
	syncq_t 	*sq;
	queue_t		*nqp;
	syncq_t		*nsq;
	boolean_t	isdriver;
	int 		moved = 0;
	uint16_t	flags;
	pri_t		priority = curthread->t_pri;
#ifdef DEBUG
	void		(*func)();
#endif

	sq = qp->q_syncq;
	ASSERT(MUTEX_HELD(SQLOCK(sq)));
	/* debug macro */
	SQ_PUTLOCKS_HELD(sq);
	/*
	 * As entersq() does not increment the sq_count for
	 * the write side, check sq_count for non-QPERQ
	 * perimeters alone.
	 */
	ASSERT((qp->q_flag & QPERQ) || (sq->sq_count >= 1));

	/*
	 * propagate_syncq() can be called because of either messages on the
	 * queue syncq or because on events on the queue syncq. Do actual
	 * message propagations if there are any messages.
	 */
	if (qp->q_syncqmsgs) {
		isdriver = (qp->q_flag & QISDRV);

		if (!isdriver) {
			nqp = qp->q_next;
			nsq = nqp->q_syncq;
			ASSERT(MUTEX_HELD(SQLOCK(nsq)));
			/* debug macro */
			SQ_PUTLOCKS_HELD(nsq);
#ifdef DEBUG
			func = (void (*)())nqp->q_qinfo->qi_putp;
#endif
		}

		SQRM_Q(sq, qp);
		priority = MAX(qp->q_spri, priority);
		qp->q_spri = 0;
		head = qp->q_sqhead;
		tail = qp->q_sqtail;
		qp->q_sqhead = qp->q_sqtail = NULL;
		qp->q_syncqmsgs = 0;

		/*
		 * Walk the list of messages, and free them if this is a driver,
		 * otherwise reset the b_prev and b_queue value to the new putp.
		 * Afterward, we will just add the head to the end of the next
		 * syncq, and point the tail to the end of this one.
		 */

		for (bp = head; bp != NULL; bp = next) {
			next = bp->b_next;
			if (isdriver) {
				bp->b_prev = bp->b_next = NULL;
				freemsg(bp);
				continue;
			}
			/* Change the q values for this message */
			bp->b_queue = nqp;
#ifdef DEBUG
			bp->b_prev = (mblk_t *)func;
#endif
			moved++;
		}
		/*
		 * Attach list of messages to the end of the new queue (if there
		 * is a list of messages).
		 */

		if (!isdriver && head != NULL) {
			ASSERT(tail != NULL);
			if (nqp->q_sqhead == NULL) {
				nqp->q_sqhead = head;
			} else {
				ASSERT(nqp->q_sqtail != NULL);
				nqp->q_sqtail->b_next = head;
			}
			nqp->q_sqtail = tail;
			/*
			 * When messages are moved from high priority queue to
			 * another queue, the destination queue priority is
			 * upgraded.
			 */

			if (priority > nqp->q_spri)
				nqp->q_spri = priority;

			SQPUT_Q(nsq, nqp);

			nqp->q_syncqmsgs += moved;
			ASSERT(nqp->q_syncqmsgs != 0);
		}
	}

	/*
	 * Before we leave, we need to make sure there are no
	 * events listed for this queue.  All events for this queue
	 * will just be freed.
	 */
	if (sq->sq_evhead != NULL) {
		ASSERT(sq->sq_flags & SQ_EVENTS);
		prev = NULL;
		for (bp = sq->sq_evhead; bp != NULL; bp = next) {
			next = bp->b_next;
			if (bp->b_queue == qp) {
				/* Delete this message */
				if (prev != NULL) {
					prev->b_next = next;
					/*
					 * Update sq_evtail if the last element
					 * is removed.
					 */
					if (bp == sq->sq_evtail) {
						ASSERT(next == NULL);
						sq->sq_evtail = prev;
					}
				} else
					sq->sq_evhead = next;
				if (sq->sq_evhead == NULL)
					sq->sq_flags &= ~SQ_EVENTS;
				bp->b_prev = bp->b_next = NULL;
				freemsg(bp);
			} else {
				prev = bp;
			}
		}
	}

	flags = sq->sq_flags;

	/* Wake up any waiter before leaving. */
	if (flags & SQ_WANTWAKEUP) {
		flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&sq->sq_wait);
	}
	sq->sq_flags = flags;

	return (moved);
}

/*
 * Try and upgrade to exclusive access at the inner perimeter. If this can
 * not be done without blocking then request will be queued on the syncq
 * and drain_syncq will run it later.
 *
 * This routine can only be called from put or service procedures plus
 * asynchronous callback routines that have properly entered the queue (with
 * entersq). Thus qwriter_inner assumes the caller has one claim on the syncq
 * associated with q.
 */
void
qwriter_inner(queue_t *q, mblk_t *mp, void (*func)())
{
	syncq_t	*sq = q->q_syncq;
	uint16_t count;

	mutex_enter(SQLOCK(sq));
	count = sq->sq_count;
	SQ_PUTLOCKS_ENTER(sq);
	SUM_SQ_PUTCOUNTS(sq, count);
	ASSERT(count >= 1);
	ASSERT(sq->sq_type & (SQ_CIPUT|SQ_CISVC));

	if (count == 1) {
		/*
		 * Can upgrade. This case also handles nested qwriter calls
		 * (when the qwriter callback function calls qwriter). In that
		 * case SQ_EXCL is already set.
		 */
		sq->sq_flags |= SQ_EXCL;
		SQ_PUTLOCKS_EXIT(sq);
		mutex_exit(SQLOCK(sq));
		(*func)(q, mp);
		/*
		 * Assumes that leavesq, putnext, and drain_syncq will reset
		 * SQ_EXCL for SQ_CIPUT/SQ_CISVC queues. We leave SQ_EXCL on
		 * until putnext, leavesq, or drain_syncq drops it.
		 * That way we handle nested qwriter(INNER) without dropping
		 * SQ_EXCL until the outermost qwriter callback routine is
		 * done.
		 */
		return;
	}
	SQ_PUTLOCKS_EXIT(sq);
	sqfill_events(sq, q, mp, func);
}

/*
 * Synchronous callback support functions
 */

/*
 * Allocate a callback parameter structure.
 * Assumes that caller initializes the flags and the id.
 * Acquires SQLOCK(sq) if non-NULL is returned.
 */
callbparams_t *
callbparams_alloc(syncq_t *sq, void (*func)(void *), void *arg, int kmflags)
{
	callbparams_t *cbp;
	size_t size = sizeof (callbparams_t);

	cbp = kmem_alloc(size, kmflags & ~KM_PANIC);

	/*
	 * Only try tryhard allocation if the caller is ready to panic.
	 * Otherwise just fail.
	 */
	if (cbp == NULL) {
		if (kmflags & KM_PANIC)
			cbp = kmem_alloc_tryhard(sizeof (callbparams_t),
			    &size, kmflags);
		else
			return (NULL);
	}

	ASSERT(size >= sizeof (callbparams_t));
	cbp->cbp_size = size;
	cbp->cbp_sq = sq;
	cbp->cbp_func = func;
	cbp->cbp_arg = arg;
	mutex_enter(SQLOCK(sq));
	cbp->cbp_next = sq->sq_callbpend;
	sq->sq_callbpend = cbp;
	return (cbp);
}

void
callbparams_free(syncq_t *sq, callbparams_t *cbp)
{
	callbparams_t **pp, *p;

	ASSERT(MUTEX_HELD(SQLOCK(sq)));

	for (pp = &sq->sq_callbpend; (p = *pp) != NULL; pp = &p->cbp_next) {
		if (p == cbp) {
			*pp = p->cbp_next;
			kmem_free(p, p->cbp_size);
			return;
		}
	}
	(void) (STRLOG(0, 0, 0, SL_CONSOLE,
	    "callbparams_free: not found\n"));
}

void
callbparams_free_id(syncq_t *sq, callbparams_id_t id, int32_t flag)
{
	callbparams_t **pp, *p;

	ASSERT(MUTEX_HELD(SQLOCK(sq)));

	for (pp = &sq->sq_callbpend; (p = *pp) != NULL; pp = &p->cbp_next) {
		if (p->cbp_id == id && p->cbp_flags == flag) {
			*pp = p->cbp_next;
			kmem_free(p, p->cbp_size);
			return;
		}
	}
	(void) (STRLOG(0, 0, 0, SL_CONSOLE,
	    "callbparams_free_id: not found\n"));
}

/*
 * Callback wrapper function used by once-only callbacks that can be
 * cancelled (qtimeout and qbufcall)
 * Contains inline version of entersq(sq, SQ_CALLBACK) that can be
 * cancelled by the qun* functions.
 */
void
qcallbwrapper(void *arg)
{
	callbparams_t *cbp = arg;
	syncq_t	*sq;
	uint16_t count = 0;
	uint16_t waitflags = SQ_STAYAWAY | SQ_EVENTS | SQ_EXCL;
	uint16_t type;

	sq = cbp->cbp_sq;
	mutex_enter(SQLOCK(sq));
	type = sq->sq_type;
	if (!(type & SQ_CICB)) {
		count = sq->sq_count;
		SQ_PUTLOCKS_ENTER(sq);
		SQ_PUTCOUNT_CLRFAST_LOCKED(sq);
		SUM_SQ_PUTCOUNTS(sq, count);
		sq->sq_needexcl++;
		ASSERT(sq->sq_needexcl != 0);	/* wraparound */
		waitflags |= SQ_MESSAGES;
	}
	/* Can not handle exclusive entry at outer perimeter */
	ASSERT(type & SQ_COCB);

	while ((sq->sq_flags & waitflags) || (!(type & SQ_CICB) &&count != 0)) {
		if ((sq->sq_callbflags & cbp->cbp_flags) &&
		    (sq->sq_cancelid == cbp->cbp_id)) {
			/* timeout has been cancelled */
			sq->sq_callbflags |= SQ_CALLB_BYPASSED;
			callbparams_free(sq, cbp);
			if (!(type & SQ_CICB)) {
				ASSERT(sq->sq_needexcl > 0);
				sq->sq_needexcl--;
				if (sq->sq_needexcl == 0) {
					SQ_PUTCOUNT_SETFAST_LOCKED(sq);
				}
				SQ_PUTLOCKS_EXIT(sq);
			}
			mutex_exit(SQLOCK(sq));
			return;
		}
		sq->sq_flags |= SQ_WANTWAKEUP;
		if (!(type & SQ_CICB)) {
			SQ_PUTLOCKS_EXIT(sq);
		}
		cv_wait(&sq->sq_wait, SQLOCK(sq));
		if (!(type & SQ_CICB)) {
			count = sq->sq_count;
			SQ_PUTLOCKS_ENTER(sq);
			SUM_SQ_PUTCOUNTS(sq, count);
		}
	}

	sq->sq_count++;
	ASSERT(sq->sq_count != 0);	/* Wraparound */
	if (!(type & SQ_CICB)) {
		ASSERT(count == 0);
		sq->sq_flags |= SQ_EXCL;
		ASSERT(sq->sq_needexcl > 0);
		sq->sq_needexcl--;
		if (sq->sq_needexcl == 0) {
			SQ_PUTCOUNT_SETFAST_LOCKED(sq);
		}
		SQ_PUTLOCKS_EXIT(sq);
	}

	mutex_exit(SQLOCK(sq));

	cbp->cbp_func(cbp->cbp_arg);

	/*
	 * We drop the lock only for leavesq to re-acquire it.
	 * Possible optimization is inline of leavesq.
	 */
	mutex_enter(SQLOCK(sq));
	callbparams_free(sq, cbp);
	mutex_exit(SQLOCK(sq));
	leavesq(sq, SQ_CALLBACK);
}

/*
 * No need to grab sq_putlocks here. See comment in strsubr.h that
 * explains when sq_putlocks are used.
 *
 * sq_count (or one of the sq_putcounts) has already been
 * decremented by the caller, and if SQ_QUEUED, we need to call
 * drain_syncq (the global syncq drain).
 * If putnext_tail is called with the SQ_EXCL bit set, we are in
 * one of two states, non-CIPUT perimeter, and we need to clear
 * it, or we went exclusive in the put procedure.  In any case,
 * we want to clear the bit now, and it is probably easier to do
 * this at the beginning of this function (remember, we hold
 * the SQLOCK).  Lastly, if there are other messages queued
 * on the syncq (and not for our destination), enable the syncq
 * for background work.
 */

/* ARGSUSED */
void
putnext_tail(syncq_t *sq, queue_t *qp, uint32_t passflags)
{
	uint16_t	flags = sq->sq_flags;

	ASSERT(MUTEX_HELD(SQLOCK(sq)));
	ASSERT(MUTEX_NOT_HELD(QLOCK(qp)));

	/* Clear SQ_EXCL if set in passflags */
	if (passflags & SQ_EXCL) {
		flags &= ~SQ_EXCL;
	}
	if (flags & SQ_WANTWAKEUP) {
		flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&sq->sq_wait);
	}
	if (flags & SQ_WANTEXWAKEUP) {
		flags &= ~SQ_WANTEXWAKEUP;
		cv_broadcast(&sq->sq_exitwait);
	}
	sq->sq_flags = flags;

	/*
	 * We have cleared SQ_EXCL if we were asked to, and started
	 * the wakeup process for waiters.  If there are no writers
	 * then we need to drain the syncq if we were told to, or
	 * enable the background thread to do it.
	 */
	if (!(flags & (SQ_STAYAWAY|SQ_EXCL))) {
		if ((passflags & SQ_QUEUED) ||
		    (sq->sq_svcflags & SQ_DISABLED)) {
			/* drain_syncq will take care of events in the list */
			drain_syncq(sq);
			return;
		} else if (flags & SQ_QUEUED) {
			sqenable(sq);
		}
	}
	/* Drop the SQLOCK on exit */
	mutex_exit(SQLOCK(sq));
	TRACE_3(TR_FAC_STREAMS_FR, TR_PUTNEXT_END,
	    "putnext_end:(%p, %p, %p) done", NULL, qp, sq);
}

void
set_qend(queue_t *q)
{
	mutex_enter(QLOCK(q));
	if (!O_SAMESTR(q))
		q->q_flag |= QEND;
	else
		q->q_flag &= ~QEND;
	mutex_exit(QLOCK(q));
	q = _OTHERQ(q);
	mutex_enter(QLOCK(q));
	if (!O_SAMESTR(q))
		q->q_flag |= QEND;
	else
		q->q_flag &= ~QEND;
	mutex_exit(QLOCK(q));
}

/*
 * Set QFULL in next service procedure queue (that cares) if not already
 * set and if there are already more messages on the syncq than
 * sq_max_size.  If sq_max_size is 0, no flow control will be asserted on
 * any syncq.
 *
 * The fq here is the next queue with a service procedure.  This is where
 * we would fail canputnext, so this is where we need to set QFULL.
 * In the case when fq != q we need to take QLOCK(fq) to set QFULL flag.
 *
 * We already have QLOCK at this point. To avoid cross-locks with
 * freezestr() which grabs all QLOCKs and with strlock() which grabs both
 * SQLOCK and sd_reflock, we need to drop respective locks first.
 */
void
set_qfull(queue_t *q)
{
	queue_t		*fq = NULL;

	ASSERT(MUTEX_HELD(QLOCK(q)));
	if ((sq_max_size != 0) && (!(q->q_nfsrv->q_flag & QFULL)) &&
	    (q->q_syncqmsgs > sq_max_size)) {
		if ((fq = q->q_nfsrv) == q) {
			fq->q_flag |= QFULL;
		} else {
			mutex_exit(QLOCK(q));
			mutex_enter(QLOCK(fq));
			fq->q_flag |= QFULL;
			mutex_exit(QLOCK(fq));
			mutex_enter(QLOCK(q));
		}
	}
}

void
clr_qfull(queue_t *q)
{
	queue_t	*oq = q;

	q = q->q_nfsrv;
	/* Fast check if there is any work to do before getting the lock. */
	if ((q->q_flag & (QFULL|QWANTW)) == 0) {
		return;
	}

	/*
	 * Do not reset QFULL (and backenable) if the q_count is the reason
	 * for QFULL being set.
	 */
	mutex_enter(QLOCK(q));
	/*
	 * If queue is empty i.e q_mblkcnt is zero, queue can not be full.
	 * Hence clear the QFULL.
	 * If both q_count and q_mblkcnt are less than the hiwat mark,
	 * clear the QFULL.
	 */
	if (q->q_mblkcnt == 0 || ((q->q_count < q->q_hiwat) &&
	    (q->q_mblkcnt < q->q_hiwat))) {
		q->q_flag &= ~QFULL;
		/*
		 * A little more confusing, how about this way:
		 * if someone wants to write,
		 * AND
		 *    both counts are less than the lowat mark
		 *    OR
		 *    the lowat mark is zero
		 * THEN
		 * backenable
		 */
		if ((q->q_flag & QWANTW) &&
		    (((q->q_count < q->q_lowat) &&
		    (q->q_mblkcnt < q->q_lowat)) || q->q_lowat == 0)) {
			q->q_flag &= ~QWANTW;
			mutex_exit(QLOCK(q));
			backenable(oq, 0);
		} else
			mutex_exit(QLOCK(q));
	} else
		mutex_exit(QLOCK(q));
}

/*
 * Set the forward service procedure pointer.
 *
 * Called at insert-time to cache a queue's next forward service procedure in
 * q_nfsrv; used by canput() and canputnext().  If the queue to be inserted
 * has a service procedure then q_nfsrv points to itself.  If the queue to be
 * inserted does not have a service procedure, then q_nfsrv points to the next
 * queue forward that has a service procedure.  If the queue is at the logical
 * end of the stream (driver for write side, stream head for the read side)
 * and does not have a service procedure, then q_nfsrv also points to itself.
 */
void
set_nfsrv_ptr(
	queue_t  *rnew,		/* read queue pointer to new module */
	queue_t  *wnew,		/* write queue pointer to new module */
	queue_t  *prev_rq,	/* read queue pointer to the module above */
	queue_t  *prev_wq)	/* write queue pointer to the module above */
{
	queue_t *qp;

	if (prev_wq->q_next == NULL) {
		/*
		 * Insert the driver, initialize the driver and stream head.
		 * In this case, prev_rq/prev_wq should be the stream head.
		 * _I_INSERT does not allow inserting a driver.  Make sure
		 * that it is not an insertion.
		 */
		ASSERT(!(rnew->q_flag & _QINSERTING));
		wnew->q_nfsrv = wnew;
		if (rnew->q_qinfo->qi_srvp)
			rnew->q_nfsrv = rnew;
		else
			rnew->q_nfsrv = prev_rq;
		prev_rq->q_nfsrv = prev_rq;
		prev_wq->q_nfsrv = prev_wq;
	} else {
		/*
		 * set up read side q_nfsrv pointer.  This MUST be done
		 * before setting the write side, because the setting of
		 * the write side for a fifo may depend on it.
		 *
		 * Suppose we have a fifo that only has pipemod pushed.
		 * pipemod has no read or write service procedures, so
		 * nfsrv for both pipemod queues points to prev_rq (the
		 * stream read head).  Now push bufmod (which has only a
		 * read service procedure).  Doing the write side first,
		 * wnew->q_nfsrv is set to pipemod's writeq nfsrv, which
		 * is WRONG; the next queue forward from wnew with a
		 * service procedure will be rnew, not the stream read head.
		 * Since the downstream queue (which in the case of a fifo
		 * is the read queue rnew) can affect upstream queues, it
		 * needs to be done first.  Setting up the read side first
		 * sets nfsrv for both pipemod queues to rnew and then
		 * when the write side is set up, wnew-q_nfsrv will also
		 * point to rnew.
		 */
		if (rnew->q_qinfo->qi_srvp) {
			/*
			 * use _OTHERQ() because, if this is a pipe, next
			 * module may have been pushed from other end and
			 * q_next could be a read queue.
			 */
			qp = _OTHERQ(prev_wq->q_next);
			while (qp && qp->q_nfsrv != qp) {
				qp->q_nfsrv = rnew;
				qp = backq(qp);
			}
			rnew->q_nfsrv = rnew;
		} else
			rnew->q_nfsrv = prev_rq->q_nfsrv;

		/* set up write side q_nfsrv pointer */
		if (wnew->q_qinfo->qi_srvp) {
			wnew->q_nfsrv = wnew;

			/*
			 * For insertion, need to update nfsrv of the modules
			 * above which do not have a service routine.
			 */
			if (rnew->q_flag & _QINSERTING) {
				for (qp = prev_wq;
				    qp != NULL && qp->q_nfsrv != qp;
				    qp = backq(qp)) {
					qp->q_nfsrv = wnew->q_nfsrv;
				}
			}
		} else {
			if (prev_wq->q_next == prev_rq)
				/*
				 * Since prev_wq/prev_rq are the middle of a
				 * fifo, wnew/rnew will also be the middle of
				 * a fifo and wnew's nfsrv is same as rnew's.
				 */
				wnew->q_nfsrv = rnew->q_nfsrv;
			else
				wnew->q_nfsrv = prev_wq->q_next->q_nfsrv;
		}
	}
}

/*
 * Reset the forward service procedure pointer; called at remove-time.
 */
void
reset_nfsrv_ptr(queue_t *rqp, queue_t *wqp)
{
	queue_t *tmp_qp;

	/* Reset the write side q_nfsrv pointer for _I_REMOVE */
	if ((rqp->q_flag & _QREMOVING) && (wqp->q_qinfo->qi_srvp != NULL)) {
		for (tmp_qp = backq(wqp);
		    tmp_qp != NULL && tmp_qp->q_nfsrv == wqp;
		    tmp_qp = backq(tmp_qp)) {
			tmp_qp->q_nfsrv = wqp->q_nfsrv;
		}
	}

	/* reset the read side q_nfsrv pointer */
	if (rqp->q_qinfo->qi_srvp) {
		if (wqp->q_next) {	/* non-driver case */
			tmp_qp = _OTHERQ(wqp->q_next);
			while (tmp_qp && tmp_qp->q_nfsrv == rqp) {
				/* Note that rqp->q_next cannot be NULL */
				ASSERT(rqp->q_next != NULL);
				tmp_qp->q_nfsrv = rqp->q_next->q_nfsrv;
				tmp_qp = backq(tmp_qp);
			}
		}
	}
}

/*
 * This routine should be called after all stream geometry changes to update
 * the stream head cached struio() rd/wr queue pointers. Note must be called
 * with the streamlock()ed.
 *
 * Note: only enables Synchronous STREAMS for a side of a Stream which has
 *	 an explicit synchronous barrier module queue. That is, a queue that
 *	 has specified a struio() type.
 */
static void
strsetuio(stdata_t *stp)
{
	queue_t *wrq;

	if (stp->sd_flag & STPLEX) {
		/*
		 * Not streamhead, but a mux, so no Synchronous STREAMS.
		 */
		stp->sd_struiowrq = NULL;
		stp->sd_struiordq = NULL;
		return;
	}
	/*
	 * Scan the write queue(s) while synchronous
	 * until we find a qinfo uio type specified.
	 */
	wrq = stp->sd_wrq->q_next;
	while (wrq) {
		if (wrq->q_struiot == STRUIOT_NONE) {
			wrq = 0;
			break;
		}
		if (wrq->q_struiot != STRUIOT_DONTCARE)
			break;
		if (! _SAMESTR(wrq)) {
			wrq = 0;
			break;
		}
		wrq = wrq->q_next;
	}
	stp->sd_struiowrq = wrq;
	/*
	 * Scan the read queue(s) while synchronous
	 * until we find a qinfo uio type specified.
	 */
	wrq = stp->sd_wrq->q_next;
	while (wrq) {
		if (_RD(wrq)->q_struiot == STRUIOT_NONE) {
			wrq = 0;
			break;
		}
		if (_RD(wrq)->q_struiot != STRUIOT_DONTCARE)
			break;
		if (! _SAMESTR(wrq)) {
			wrq = 0;
			break;
		}
		wrq = wrq->q_next;
	}
	stp->sd_struiordq = wrq ? _RD(wrq) : 0;
}

/*
 * pass_wput, unblocks the passthru queues, so that
 * messages can arrive at muxs lower read queue, before
 * I_LINK/I_UNLINK is acked/nacked.
 */
static void
pass_wput(queue_t *q, mblk_t *mp)
{
	syncq_t *sq;

	sq = _RD(q)->q_syncq;
	if (sq->sq_flags & SQ_BLOCKED)
		unblocksq(sq, SQ_BLOCKED, 0);
	putnext(q, mp);
}

/*
 * Set up queues for the link/unlink.
 * Create a new queue and block it and then insert it
 * below the stream head on the lower stream.
 * This prevents any messages from arriving during the setq
 * as well as while the mux is processing the LINK/I_UNLINK.
 * The blocked passq is unblocked once the LINK/I_UNLINK has
 * been acked or nacked or if a message is generated and sent
 * down muxs write put procedure.
 * See pass_wput().
 *
 * After the new queue is inserted, all messages coming from below are
 * blocked. The call to strlock will ensure that all activity in the stream head
 * read queue syncq is stopped (sq_count drops to zero).
 */
static queue_t *
link_addpassthru(stdata_t *stpdown)
{
	queue_t *passq;
	sqlist_t sqlist;

	passq = allocq();
	STREAM(passq) = STREAM(_WR(passq)) = stpdown;
	/* setq might sleep in allocator - avoid holding locks. */
	setq(passq, &passthru_rinit, &passthru_winit, NULL, QPERQ,
	    SQ_CI|SQ_CO, B_FALSE);
	claimq(passq);
	blocksq(passq->q_syncq, SQ_BLOCKED, 1);
	insertq(STREAM(passq), passq);

	/*
	 * Use strlock() to wait for the stream head sq_count to drop to zero
	 * since we are going to change q_ptr in the stream head.  Note that
	 * insertq() doesn't wait for any syncq counts to drop to zero.
	 */
	sqlist.sqlist_head = NULL;
	sqlist.sqlist_index = 0;
	sqlist.sqlist_size = sizeof (sqlist_t);
	sqlist_insert(&sqlist, _RD(stpdown->sd_wrq)->q_syncq);
	strlock(stpdown, &sqlist);
	strunlock(stpdown, &sqlist);

	releaseq(passq);
	return (passq);
}

/*
 * Let messages flow up into the mux by removing
 * the passq.
 */
static void
link_rempassthru(queue_t *passq)
{
	claimq(passq);
	removeq(passq);
	releaseq(passq);
	freeq(passq);
}

/*
 * Wait for the condition variable pointed to by `cvp' to be signaled,
 * or for `tim' milliseconds to elapse, whichever comes first.  If `tim'
 * is negative, then there is no time limit.  If `nosigs' is non-zero,
 * then the wait will be non-interruptible.
 *
 * Returns >0 if signaled, 0 if interrupted, or -1 upon timeout.
 */
clock_t
str_cv_wait(kcondvar_t *cvp, kmutex_t *mp, clock_t tim, int nosigs)
{
	clock_t ret;

	if (tim < 0) {
		if (nosigs) {
			cv_wait(cvp, mp);
			ret = 1;
		} else {
			ret = cv_wait_sig(cvp, mp);
		}
	} else if (tim > 0) {
		/*
		 * convert milliseconds to clock ticks
		 */
		if (nosigs) {
			ret = cv_reltimedwait(cvp, mp,
			    MSEC_TO_TICK_ROUNDUP(tim), TR_CLOCK_TICK);
		} else {
			ret = cv_reltimedwait_sig(cvp, mp,
			    MSEC_TO_TICK_ROUNDUP(tim), TR_CLOCK_TICK);
		}
	} else {
		ret = -1;
	}
	return (ret);
}

/*
 * Wait until the stream head can determine if it is at the mark but
 * don't wait forever to prevent a race condition between the "mark" state
 * in the stream head and any mark state in the caller/user of this routine.
 *
 * This is used by sockets and for a socket it would be incorrect
 * to return a failure for SIOCATMARK when there is no data in the receive
 * queue and the marked urgent data is traveling up the stream.
 *
 * This routine waits until the mark is known by waiting for one of these
 * three events:
 *	The stream head read queue becoming non-empty (including an EOF).
 *	The STRATMARK flag being set (due to a MSGMARKNEXT message).
 *	The STRNOTATMARK flag being set (which indicates that the transport
 *	has sent a MSGNOTMARKNEXT message to indicate that it is not at
 *	the mark).
 *
 * The routine returns 1 if the stream is at the mark; 0 if it can
 * be determined that the stream is not at the mark.
 * If the wait times out and it can't determine
 * whether or not the stream might be at the mark the routine will return -1.
 *
 * Note: This routine should only be used when a mark is pending i.e.,
 * in the socket case the SIGURG has been posted.
 * Note2: This can not wakeup just because synchronous streams indicate
 * that data is available since it is not possible to use the synchronous
 * streams interfaces to determine the b_flag value for the data queued below
 * the stream head.
 */
int
strwaitmark(vnode_t *vp)
{
	struct stdata *stp = vp->v_stream;
	queue_t *rq = _RD(stp->sd_wrq);
	int mark;

	mutex_enter(&stp->sd_lock);
	while (rq->q_first == NULL &&
	    !(stp->sd_flag & (STRATMARK|STRNOTATMARK|STREOF))) {
		stp->sd_flag |= RSLEEP;

		/* Wait for 100 milliseconds for any state change. */
		if (str_cv_wait(&rq->q_wait, &stp->sd_lock, 100, 1) == -1) {
			mutex_exit(&stp->sd_lock);
			return (-1);
		}
	}
	if (stp->sd_flag & STRATMARK)
		mark = 1;
	else if (rq->q_first != NULL && (rq->q_first->b_flag & MSGMARK))
		mark = 1;
	else
		mark = 0;

	mutex_exit(&stp->sd_lock);
	return (mark);
}

/*
 * Set a read side error. If persist is set change the socket error
 * to persistent. If errfunc is set install the function as the exported
 * error handler.
 */
void
strsetrerror(vnode_t *vp, int error, int persist, errfunc_t errfunc)
{
	struct stdata *stp = vp->v_stream;

	mutex_enter(&stp->sd_lock);
	stp->sd_rerror = error;
	if (error == 0 && errfunc == NULL)
		stp->sd_flag &= ~STRDERR;
	else
		stp->sd_flag |= STRDERR;
	if (persist) {
		stp->sd_flag &= ~STRDERRNONPERSIST;
	} else {
		stp->sd_flag |= STRDERRNONPERSIST;
	}
	stp->sd_rderrfunc = errfunc;
	if (error != 0 || errfunc != NULL) {
		cv_broadcast(&_RD(stp->sd_wrq)->q_wait);	/* readers */
		cv_broadcast(&stp->sd_wrq->q_wait);		/* writers */
		cv_broadcast(&stp->sd_monitor);			/* ioctllers */

		mutex_exit(&stp->sd_lock);
		pollwakeup(&stp->sd_pollist, POLLERR);
		mutex_enter(&stp->sd_lock);

		if (stp->sd_sigflags & S_ERROR)
			strsendsig(stp->sd_siglist, S_ERROR, 0, error);
	}
	mutex_exit(&stp->sd_lock);
}

/*
 * Set a write side error. If persist is set change the socket error
 * to persistent.
 */
void
strsetwerror(vnode_t *vp, int error, int persist, errfunc_t errfunc)
{
	struct stdata *stp = vp->v_stream;

	mutex_enter(&stp->sd_lock);
	stp->sd_werror = error;
	if (error == 0 && errfunc == NULL)
		stp->sd_flag &= ~STWRERR;
	else
		stp->sd_flag |= STWRERR;
	if (persist) {
		stp->sd_flag &= ~STWRERRNONPERSIST;
	} else {
		stp->sd_flag |= STWRERRNONPERSIST;
	}
	stp->sd_wrerrfunc = errfunc;
	if (error != 0 || errfunc != NULL) {
		cv_broadcast(&_RD(stp->sd_wrq)->q_wait);	/* readers */
		cv_broadcast(&stp->sd_wrq->q_wait);		/* writers */
		cv_broadcast(&stp->sd_monitor);			/* ioctllers */

		mutex_exit(&stp->sd_lock);
		pollwakeup(&stp->sd_pollist, POLLERR);
		mutex_enter(&stp->sd_lock);

		if (stp->sd_sigflags & S_ERROR)
			strsendsig(stp->sd_siglist, S_ERROR, 0, error);
	}
	mutex_exit(&stp->sd_lock);
}

/*
 * Make the stream return 0 (EOF) when all data has been read.
 * No effect on write side.
 */
void
strseteof(vnode_t *vp, int eof)
{
	struct stdata *stp = vp->v_stream;

	mutex_enter(&stp->sd_lock);
	if (!eof) {
		stp->sd_flag &= ~STREOF;
		mutex_exit(&stp->sd_lock);
		return;
	}
	stp->sd_flag |= STREOF;
	if (stp->sd_flag & RSLEEP) {
		stp->sd_flag &= ~RSLEEP;
		cv_broadcast(&_RD(stp->sd_wrq)->q_wait);
	}

	mutex_exit(&stp->sd_lock);
	pollwakeup(&stp->sd_pollist, POLLIN|POLLRDNORM);
	mutex_enter(&stp->sd_lock);

	if (stp->sd_sigflags & (S_INPUT|S_RDNORM))
		strsendsig(stp->sd_siglist, S_INPUT|S_RDNORM, 0, 0);
	mutex_exit(&stp->sd_lock);
}

void
strflushrq(vnode_t *vp, int flag)
{
	struct stdata *stp = vp->v_stream;

	mutex_enter(&stp->sd_lock);
	flushq(_RD(stp->sd_wrq), flag);
	mutex_exit(&stp->sd_lock);
}

void
strsetrputhooks(vnode_t *vp, uint_t flags,
		msgfunc_t protofunc, msgfunc_t miscfunc)
{
	struct stdata *stp = vp->v_stream;

	mutex_enter(&stp->sd_lock);

	if (protofunc == NULL)
		stp->sd_rprotofunc = strrput_proto;
	else
		stp->sd_rprotofunc = protofunc;

	if (miscfunc == NULL)
		stp->sd_rmiscfunc = strrput_misc;
	else
		stp->sd_rmiscfunc = miscfunc;

	if (flags & SH_CONSOL_DATA)
		stp->sd_rput_opt |= SR_CONSOL_DATA;
	else
		stp->sd_rput_opt &= ~SR_CONSOL_DATA;

	if (flags & SH_SIGALLDATA)
		stp->sd_rput_opt |= SR_SIGALLDATA;
	else
		stp->sd_rput_opt &= ~SR_SIGALLDATA;

	if (flags & SH_IGN_ZEROLEN)
		stp->sd_rput_opt |= SR_IGN_ZEROLEN;
	else
		stp->sd_rput_opt &= ~SR_IGN_ZEROLEN;

	mutex_exit(&stp->sd_lock);
}

void
strsetwputhooks(vnode_t *vp, uint_t flags, clock_t closetime)
{
	struct stdata *stp = vp->v_stream;

	mutex_enter(&stp->sd_lock);
	stp->sd_closetime = closetime;

	if (flags & SH_SIGPIPE)
		stp->sd_wput_opt |= SW_SIGPIPE;
	else
		stp->sd_wput_opt &= ~SW_SIGPIPE;
	if (flags & SH_RECHECK_ERR)
		stp->sd_wput_opt |= SW_RECHECK_ERR;
	else
		stp->sd_wput_opt &= ~SW_RECHECK_ERR;

	mutex_exit(&stp->sd_lock);
}

void
strsetrwputdatahooks(vnode_t *vp, msgfunc_t rdatafunc, msgfunc_t wdatafunc)
{
	struct stdata *stp = vp->v_stream;

	mutex_enter(&stp->sd_lock);

	stp->sd_rputdatafunc = rdatafunc;
	stp->sd_wputdatafunc = wdatafunc;

	mutex_exit(&stp->sd_lock);
}

/* Used within framework when the queue is already locked */
void
qenable_locked(queue_t *q)
{
	stdata_t *stp = STREAM(q);

	ASSERT(MUTEX_HELD(QLOCK(q)));

	if (!q->q_qinfo->qi_srvp)
		return;

	/*
	 * Do not place on run queue if already enabled or closing.
	 */
	if (q->q_flag & (QWCLOSE|QENAB))
		return;

	/*
	 * mark queue enabled and place on run list if it is not already being
	 * serviced. If it is serviced, the runservice() function will detect
	 * that QENAB is set and call service procedure before clearing
	 * QINSERVICE flag.
	 */
	q->q_flag |= QENAB;
	if (q->q_flag & QINSERVICE)
		return;

	/* Record the time of qenable */
	q->q_qtstamp = ddi_get_lbolt();

	/*
	 * Put the queue in the stp list and schedule it for background
	 * processing if it is not already scheduled or if stream head does not
	 * intent to process it in the foreground later by setting
	 * STRS_WILLSERVICE flag.
	 */
	mutex_enter(&stp->sd_qlock);
	/*
	 * If there are already something on the list, stp flags should show
	 * intention to drain it.
	 */
	IMPLY(STREAM_NEEDSERVICE(stp),
	    (stp->sd_svcflags & (STRS_WILLSERVICE | STRS_SCHEDULED)));

	ENQUEUE(q, stp->sd_qhead, stp->sd_qtail, q_link);
	stp->sd_nqueues++;

	/*
	 * If no one will drain this stream we are the first producer and
	 * need to schedule it for background thread.
	 */
	if (!(stp->sd_svcflags & (STRS_WILLSERVICE | STRS_SCHEDULED))) {
		/*
		 * No one will service this stream later, so we have to
		 * schedule it now.
		 */
		STRSTAT(stenables);
		stp->sd_svcflags |= STRS_SCHEDULED;
		stp->sd_servid = (void *)taskq_dispatch(streams_taskq,
		    (task_func_t *)stream_service, stp, TQ_NOSLEEP|TQ_NOQUEUE);

		if (stp->sd_servid == NULL) {
			/*
			 * Task queue failed so fail over to the backup
			 * servicing thread.
			 */
			STRSTAT(taskqfails);
			/*
			 * It is safe to clear STRS_SCHEDULED flag because it
			 * was set by this thread above.
			 */
			stp->sd_svcflags &= ~STRS_SCHEDULED;

			/*
			 * Failover scheduling is protected by service_queue
			 * lock.
			 */
			mutex_enter(&service_queue);
			ASSERT((stp->sd_qhead == q) && (stp->sd_qtail == q));
			ASSERT(q->q_link == NULL);
			/*
			 * Append the queue to qhead/qtail list.
			 */
			if (qhead == NULL)
				qhead = q;
			else
				qtail->q_link = q;
			qtail = q;
			/*
			 * Clear stp queue list.
			 */
			stp->sd_qhead = stp->sd_qtail = NULL;
			stp->sd_nqueues = 0;
			/*
			 * Wakeup background queue processing thread.
			 */
			cv_signal(&services_to_run);
			mutex_exit(&service_queue);
		}
	}
	mutex_exit(&stp->sd_qlock);
}

static void
queue_service(queue_t *q)
{
	/*
	 * The queue in the list should have
	 * QENAB flag set and should not have
	 * QINSERVICE flag set. QINSERVICE is
	 * set when the queue is dequeued and
	 * qenable_locked doesn't enqueue a
	 * queue with QINSERVICE set.
	 */

	ASSERT(!(q->q_flag & QINSERVICE));
	ASSERT((q->q_flag & QENAB));
	mutex_enter(QLOCK(q));
	q->q_flag &= ~QENAB;
	q->q_flag |= QINSERVICE;
	mutex_exit(QLOCK(q));
	runservice(q);
}

static void
syncq_service(syncq_t *sq)
{
	STRSTAT(syncqservice);
	mutex_enter(SQLOCK(sq));
	ASSERT(!(sq->sq_svcflags & SQ_SERVICE));
	ASSERT(sq->sq_servcount != 0);
	ASSERT(sq->sq_next == NULL);

	/* if we came here from the background thread, clear the flag */
	if (sq->sq_svcflags & SQ_BGTHREAD)
		sq->sq_svcflags &= ~SQ_BGTHREAD;

	/* let drain_syncq know that it's being called in the background */
	sq->sq_svcflags |= SQ_SERVICE;
	drain_syncq(sq);
}

static void
qwriter_outer_service(syncq_t *outer)
{
	/*
	 * Note that SQ_WRITER is used on the outer perimeter
	 * to signal that a qwriter(OUTER) is either investigating
	 * running or that it is actually running a function.
	 */
	outer_enter(outer, SQ_BLOCKED|SQ_WRITER);

	/*
	 * All inner syncq are empty and have SQ_WRITER set
	 * to block entering the outer perimeter.
	 *
	 * We do not need to explicitly call write_now since
	 * outer_exit does it for us.
	 */
	outer_exit(outer);
}

static void
mblk_free(mblk_t *mp)
{
	dblk_t *dbp = mp->b_datap;
	frtn_t *frp = dbp->db_frtnp;

	mp->b_next = NULL;
	if (dbp->db_fthdr != NULL)
		str_ftfree(dbp);

	ASSERT(dbp->db_fthdr == NULL);
	frp->free_func(frp->free_arg);
	ASSERT(dbp->db_mblk == mp);

	if (dbp->db_credp != NULL) {
		crfree(dbp->db_credp);
		dbp->db_credp = NULL;
	}
	dbp->db_cpid = -1;
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;

	kmem_cache_free(dbp->db_cache, dbp);
}

/*
 * Background processing of the stream queue list.
 */
static void
stream_service(stdata_t *stp)
{
	queue_t *q;

	mutex_enter(&stp->sd_qlock);

	STR_SERVICE(stp, q);

	stp->sd_svcflags &= ~STRS_SCHEDULED;
	stp->sd_servid = NULL;
	cv_signal(&stp->sd_qcv);
	mutex_exit(&stp->sd_qlock);
}

/*
 * Foreground processing of the stream queue list.
 */
void
stream_runservice(stdata_t *stp)
{
	queue_t *q;

	mutex_enter(&stp->sd_qlock);
	STRSTAT(rservice);
	/*
	 * We are going to drain this stream queue list, so qenable_locked will
	 * not schedule it until we finish.
	 */
	stp->sd_svcflags |= STRS_WILLSERVICE;

	STR_SERVICE(stp, q);

	stp->sd_svcflags &= ~STRS_WILLSERVICE;
	mutex_exit(&stp->sd_qlock);
	/*
	 * Help backup background thread to drain the qhead/qtail list.
	 */
	while (qhead != NULL) {
		STRSTAT(qhelps);
		mutex_enter(&service_queue);
		DQ(q, qhead, qtail, q_link);
		mutex_exit(&service_queue);
		if (q != NULL)
			queue_service(q);
	}
}

void
stream_willservice(stdata_t *stp)
{
	mutex_enter(&stp->sd_qlock);
	stp->sd_svcflags |= STRS_WILLSERVICE;
	mutex_exit(&stp->sd_qlock);
}

/*
 * Replace the cred currently in the mblk with a different one.
 * Also update db_cpid.
 */
void
mblk_setcred(mblk_t *mp, cred_t *cr, pid_t cpid)
{
	dblk_t *dbp = mp->b_datap;
	cred_t *ocr = dbp->db_credp;

	ASSERT(cr != NULL);

	if (cr != ocr) {
		crhold(dbp->db_credp = cr);
		if (ocr != NULL)
			crfree(ocr);
	}
	/* Don't overwrite with NOPID */
	if (cpid != NOPID)
		dbp->db_cpid = cpid;
}

/*
 * If the src message has a cred, then replace the cred currently in the mblk
 * with it.
 * Also update db_cpid.
 */
void
mblk_copycred(mblk_t *mp, const mblk_t *src)
{
	dblk_t *dbp = mp->b_datap;
	cred_t *cr, *ocr;
	pid_t cpid;

	cr = msg_getcred(src, &cpid);
	if (cr == NULL)
		return;

	ocr = dbp->db_credp;
	if (cr != ocr) {
		crhold(dbp->db_credp = cr);
		if (ocr != NULL)
			crfree(ocr);
	}
	/* Don't overwrite with NOPID */
	if (cpid != NOPID)
		dbp->db_cpid = cpid;
}

int
hcksum_assoc(mblk_t *mp,  multidata_t *mmd, pdesc_t *pd,
    uint32_t start, uint32_t stuff, uint32_t end, uint32_t value,
    uint32_t flags, int km_flags)
{
	int rc = 0;

	ASSERT(DB_TYPE(mp) == M_DATA || DB_TYPE(mp) == M_MULTIDATA);
	if (mp->b_datap->db_type == M_DATA) {
		/* Associate values for M_DATA type */
		DB_CKSUMSTART(mp) = (intptr_t)start;
		DB_CKSUMSTUFF(mp) = (intptr_t)stuff;
		DB_CKSUMEND(mp) = (intptr_t)end;
		DB_CKSUMFLAGS(mp) = flags;
		DB_CKSUM16(mp) = (uint16_t)value;

	} else {
		pattrinfo_t pa_info;

		ASSERT(mmd != NULL);

		pa_info.type = PATTR_HCKSUM;
		pa_info.len = sizeof (pattr_hcksum_t);

		if (mmd_addpattr(mmd, pd, &pa_info, B_TRUE, km_flags) != NULL) {
			pattr_hcksum_t *hck = (pattr_hcksum_t *)pa_info.buf;

			hck->hcksum_start_offset = start;
			hck->hcksum_stuff_offset = stuff;
			hck->hcksum_end_offset = end;
			hck->hcksum_cksum_val.inet_cksum = (uint16_t)value;
			hck->hcksum_flags = flags;
		} else {
			rc = -1;
		}
	}
	return (rc);
}

void
hcksum_retrieve(mblk_t *mp, multidata_t *mmd, pdesc_t *pd,
    uint32_t *start, uint32_t *stuff, uint32_t *end,
    uint32_t *value, uint32_t *flags)
{
	ASSERT(DB_TYPE(mp) == M_DATA || DB_TYPE(mp) == M_MULTIDATA);
	if (mp->b_datap->db_type == M_DATA) {
		if (flags != NULL) {
			*flags = DB_CKSUMFLAGS(mp) & HCK_FLAGS;
			if ((*flags & (HCK_PARTIALCKSUM |
			    HCK_FULLCKSUM)) != 0) {
				if (value != NULL)
					*value = (uint32_t)DB_CKSUM16(mp);
				if ((*flags & HCK_PARTIALCKSUM) != 0) {
					if (start != NULL)
						*start =
						    (uint32_t)DB_CKSUMSTART(mp);
					if (stuff != NULL)
						*stuff =
						    (uint32_t)DB_CKSUMSTUFF(mp);
					if (end != NULL)
						*end =
						    (uint32_t)DB_CKSUMEND(mp);
				}
			}
		}
	} else {
		pattrinfo_t hck_attr = {PATTR_HCKSUM};

		ASSERT(mmd != NULL);

		/* get hardware checksum attribute */
		if (mmd_getpattr(mmd, pd, &hck_attr) != NULL) {
			pattr_hcksum_t *hck = (pattr_hcksum_t *)hck_attr.buf;

			ASSERT(hck_attr.len >= sizeof (pattr_hcksum_t));
			if (flags != NULL)
				*flags = hck->hcksum_flags;
			if (start != NULL)
				*start = hck->hcksum_start_offset;
			if (stuff != NULL)
				*stuff = hck->hcksum_stuff_offset;
			if (end != NULL)
				*end = hck->hcksum_end_offset;
			if (value != NULL)
				*value = (uint32_t)
				    hck->hcksum_cksum_val.inet_cksum;
		}
	}
}

void
lso_info_set(mblk_t *mp, uint32_t mss, uint32_t flags)
{
	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT((flags & ~HW_LSO_FLAGS) == 0);

	/* Set the flags */
	DB_LSOFLAGS(mp) |= flags;
	DB_LSOMSS(mp) = mss;
}

void
lso_info_cleanup(mblk_t *mp)
{
	ASSERT(DB_TYPE(mp) == M_DATA);

	/* Clear the flags */
	DB_LSOFLAGS(mp) &= ~HW_LSO_FLAGS;
	DB_LSOMSS(mp) = 0;
}

/*
 * Checksum buffer *bp for len bytes with psum partial checksum,
 * or 0 if none, and return the 16 bit partial checksum.
 */
unsigned
bcksum(uchar_t *bp, int len, unsigned int psum)
{
	int odd = len & 1;
	extern unsigned int ip_ocsum();

	if (((intptr_t)bp & 1) == 0 && !odd) {
		/*
		 * Bp is 16 bit aligned and len is multiple of 16 bit word.
		 */
		return (ip_ocsum((ushort_t *)bp, len >> 1, psum));
	}
	if (((intptr_t)bp & 1) != 0) {
		/*
		 * Bp isn't 16 bit aligned.
		 */
		unsigned int tsum;

#ifdef _LITTLE_ENDIAN
		psum += *bp;
#else
		psum += *bp << 8;
#endif
		len--;
		bp++;
		tsum = ip_ocsum((ushort_t *)bp, len >> 1, 0);
		psum += (tsum << 8) & 0xffff | (tsum >> 8);
		if (len & 1) {
			bp += len - 1;
#ifdef _LITTLE_ENDIAN
			psum += *bp << 8;
#else
			psum += *bp;
#endif
		}
	} else {
		/*
		 * Bp is 16 bit aligned.
		 */
		psum = ip_ocsum((ushort_t *)bp, len >> 1, psum);
		if (odd) {
			bp += len - 1;
#ifdef _LITTLE_ENDIAN
			psum += *bp;
#else
			psum += *bp << 8;
#endif
		}
	}
	/*
	 * Normalize psum to 16 bits before returning the new partial
	 * checksum. The max psum value before normalization is 0x3FDFE.
	 */
	return ((psum >> 16) + (psum & 0xFFFF));
}

boolean_t
is_vmloaned_mblk(mblk_t *mp, multidata_t *mmd, pdesc_t *pd)
{
	boolean_t rc;

	ASSERT(DB_TYPE(mp) == M_DATA || DB_TYPE(mp) == M_MULTIDATA);
	if (DB_TYPE(mp) == M_DATA) {
		rc = (((mp)->b_datap->db_struioflag & STRUIO_ZC) != 0);
	} else {
		pattrinfo_t zcopy_attr = {PATTR_ZCOPY};

		ASSERT(mmd != NULL);
		rc = (mmd_getpattr(mmd, pd, &zcopy_attr) != NULL);
	}
	return (rc);
}

void
freemsgchain(mblk_t *mp)
{
	mblk_t	*next;

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		freemsg(mp);
		mp = next;
	}
}

mblk_t *
copymsgchain(mblk_t *mp)
{
	mblk_t	*nmp = NULL;
	mblk_t	**nmpp = &nmp;

	for (; mp != NULL; mp = mp->b_next) {
		if ((*nmpp = copymsg(mp)) == NULL) {
			freemsgchain(nmp);
			return (NULL);
		}

		nmpp = &((*nmpp)->b_next);
	}

	return (nmp);
}

/* NOTE: Do not add code after this point. */
#undef QLOCK

/*
 * Replacement for QLOCK macro for those that can't use it.
 */
kmutex_t *
QLOCK(queue_t *q)
{
	return (&(q)->q_lock);
}

/*
 * Dummy runqueues/queuerun functions functions for backwards compatibility.
 */
#undef runqueues
void
runqueues(void)
{
}

#undef queuerun
void
queuerun(void)
{
}

/*
 * Initialize the STR stack instance, which tracks autopush and persistent
 * links.
 */
/* ARGSUSED */
static void *
str_stack_init(netstackid_t stackid, netstack_t *ns)
{
	str_stack_t	*ss;
	int i;

	ss = (str_stack_t *)kmem_zalloc(sizeof (*ss), KM_SLEEP);
	ss->ss_netstack = ns;

	/*
	 * set up autopush
	 */
	sad_initspace(ss);

	/*
	 * set up mux_node structures.
	 */
	ss->ss_devcnt = devcnt;	/* In case it should change before free */
	ss->ss_mux_nodes = kmem_zalloc((sizeof (struct mux_node) *
	    ss->ss_devcnt), KM_SLEEP);
	for (i = 0; i < ss->ss_devcnt; i++)
		ss->ss_mux_nodes[i].mn_imaj = i;
	return (ss);
}

/*
 * Note: run at zone shutdown and not destroy so that the PLINKs are
 * gone by the time other cleanup happens from the destroy callbacks.
 */
static void
str_stack_shutdown(netstackid_t stackid, void *arg)
{
	str_stack_t *ss = (str_stack_t *)arg;
	int i;
	cred_t *cr;

	cr = zone_get_kcred(netstackid_to_zoneid(stackid));
	ASSERT(cr != NULL);

	/* Undo all the I_PLINKs for this zone */
	for (i = 0; i < ss->ss_devcnt; i++) {
		struct mux_edge		*ep;
		ldi_handle_t		lh;
		ldi_ident_t		li;
		int			ret;
		int			rval;
		dev_t			rdev;

		ep = ss->ss_mux_nodes[i].mn_outp;
		if (ep == NULL)
			continue;
		ret = ldi_ident_from_major((major_t)i, &li);
		if (ret != 0) {
			continue;
		}
		rdev = ep->me_dev;
		ret = ldi_open_by_dev(&rdev, OTYP_CHR, FREAD|FWRITE,
		    cr, &lh, li);
		if (ret != 0) {
			ldi_ident_release(li);
			continue;
		}

		ret = ldi_ioctl(lh, I_PUNLINK, (intptr_t)MUXID_ALL, FKIOCTL,
		    cr, &rval);
		if (ret) {
			(void) ldi_close(lh, FREAD|FWRITE, cr);
			ldi_ident_release(li);
			continue;
		}
		(void) ldi_close(lh, FREAD|FWRITE, cr);

		/* Close layered handles */
		ldi_ident_release(li);
	}
	crfree(cr);

	sad_freespace(ss);

	kmem_free(ss->ss_mux_nodes, sizeof (struct mux_node) * ss->ss_devcnt);
	ss->ss_mux_nodes = NULL;
}

/*
 * Free the structure; str_stack_shutdown did the other cleanup work.
 */
/* ARGSUSED */
static void
str_stack_fini(netstackid_t stackid, void *arg)
{
	str_stack_t	*ss = (str_stack_t *)arg;

	kmem_free(ss, sizeof (*ss));
}
