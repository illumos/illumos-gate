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

#ifndef	_SYS_SQUEUE_IMPL_H
#define	_SYS_SQUEUE_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/disp.h>
#include <sys/types.h>
#include <sys/squeue.h>
#include <inet/ip.h>

#define	SQ_NAMELEN 31

/*
 * SQUEUE_DEBUG: If defined as 1, special code is compiled in which records
 *      additional information aiding debugging is recorded in squeue.
 *
 * SQUEUE_PROFILE: If defined as 1, special code is compiled in which collects
 *      various squeue statistics and exports them as kstats.
 *
 * Ideally we would like both SQUEUE_DEBUG and SQUEUE_PROFILE to be always set,
 * but it affects performance, so they are enabled on DEBUG kernels and disabled
 * on non-DEBUG by default.
 */
#ifdef DEBUG
#define	SQUEUE_DEBUG 1
#define	SQUEUE_PROFILE 1
#else
#define	SQUEUE_DEBUG 0
#define	SQUEUE_PROFILE 0
#endif

#define	SQUEUE_DEFAULT_PRIORITY	MAXCLSYSPRI

typedef struct sqstat_s {
	uint_t		sq_max_qlen;
	uint_t		sq_npackets_worker;
	uint_t		sq_npackets_intr;
	uint_t		sq_npackets_other;
	uint_t		sq_nqueued_intr;
	uint_t		sq_nqueued_other;
	uint_t		sq_ndrains_worker;
	uint_t		sq_ndrains_intr;
	uint_t		sq_ndrains_other;
	hrtime_t	sq_time_worker;
	hrtime_t	sq_time_intr;
	hrtime_t	sq_time_other;
} sqstat_t;

typedef struct squeue_set_s {
	squeue_t	*sqs_head;
	squeue_t	*sqs_default;
	processorid_t	sqs_cpuid;
} squeue_set_t;

typedef void (*sqproc_t)(void *, mblk_t *, void *, struct ip_recv_attr_s *);
typedef void (*sq_enter_proc_t)(squeue_t *, mblk_t *, mblk_t *, uint32_t,
	    struct ip_recv_attr_s *, int, uint8_t);
typedef void (*sq_drain_proc_t)(squeue_t *, uint_t, hrtime_t);

extern void squeue_worker_wakeup(squeue_t *);
extern int ip_squeue_flag;

struct squeue_s {
	sq_enter_proc_t	sq_enter;	/* sq_process function */
	sq_drain_proc_t	sq_drain;	/* sq_drain function */
	kmutex_t	sq_lock;	/* lock before using any member */
	uint32_t	sq_state;	/* state flags and message count */
	int		sq_count;	/* # of mblocks in squeue */
	mblk_t		*sq_first;	/* first mblk chain or NULL */
	mblk_t		*sq_last;	/* last mblk chain or NULL */
	kthread_t	*sq_run;	/* Current thread processing sq */
	ill_rx_ring_t	*sq_rx_ring;	/* The Rx ring tied to this sq */
	ill_t		*sq_ill;	/* The ill this squeue is tied to */

	clock_t		sq_curr_time;	/* Current tick (lbolt) */
	kcondvar_t	sq_worker_cv;	/* cond var. worker thread blocks on */
	kcondvar_t	sq_poll_cv;	/* cond variable poll_thr waits on */
	kcondvar_t	sq_synch_cv;	/* cond var. synch thread waits on */
	kcondvar_t	sq_ctrlop_done_cv; /* cond variable for ctrl ops */
	clock_t		sq_wait;	/* lbolts to wait after a fill() */
	timeout_id_t	sq_tid;		/* timer id of pending timeout() */
	clock_t		sq_awaken;	/* time async thread was awakened */

	processorid_t	sq_bind;	/* processor to bind to */
	kthread_t	*sq_worker;	/* kernel thread id */
	kthread_t	*sq_poll_thr;	/* polling thread */
	uintptr_t	sq_private[SQPRIVATE_MAX];

	squeue_t	*sq_next;	/* managed by squeue creator */
	squeue_set_t	*sq_set;	/* managed by squeue creator */

	pri_t		sq_priority;	/* squeue thread priority */

	/* Keep the debug-only fields at the end of the structure */
#ifdef DEBUG
	int		sq_isintr;	/* serviced by interrupt */
	mblk_t		*sq_curmp;
	void		(*sq_curproc)();
	conn_t		*sq_connp;
	uchar_t		sq_tag;
#endif
};

/*
 * State flags.
 * Note: The MDB IP module depends on the values of these flags.
 */
#define	SQS_PROC	0x00000001	/* being processed */
#define	SQS_WORKER	0x00000002	/* worker thread */
#define	SQS_ENTER	0x00000004	/* enter thread */
#define	SQS_FAST	0x00000008	/* enter-fast thread */

#define	SQS_USER	0x00000010	/* A non interrupt user */
#define	SQS_BOUND	0x00000020	/* Worker thread is bound */
#define	SQS_REENTER	0x00000040	/* Re entered thread */
#define	SQS_TMO_PROG	0x00000080	/* Timeout is being set */

#define	SQS_POLL_CAPAB	0x00000100	/* Squeue can control interrupts */
#define	SQS_ILL_BOUND	0x00000200	/* Squeue bound to an ill */
#define	SQS_GET_PKTS	0x00000400	/* Moving pkts from NIC in progress */
#define	SQS_DEFAULT	0x00000800	/* The default squeue for the CPU */

#define	SQS_POLLING	0x00001000	/* Squeue in polling mode */
#define	SQS_INTR_BLANK	0x00002000	/* Interrupt blanking capability */
#define	SQS_PROC_HELD	0x00004000	/* SQS_PROC is held by the caller */
#define	SQS_FORCE_TIMER	0x00008000	/* Schedule worker due to B/W control */

#define	SQS_POLL_CLEANUP	0x00010000
#define	SQS_POLL_CLEANUP_DONE	0x00020000
#define	SQS_POLL_QUIESCE	0x00040000
#define	SQS_POLL_QUIESCE_DONE	0x00080000

#define	SQS_POLL_RESTART	0x00100000
#define	SQS_POLL_THR_QUIESCED	0x00200000
#define	SQS_POLL_THR_RESTART	0x00400000
#define	SQS_POLL_PROC		0x00800000 /* Poll thread processing the sq */

#define	SQS_POLL_RESTART_DONE	0x01000000
#define	SQS_POLL_THR_QUIESCE	0x02000000
#define	SQS_PAUSE		0x04000000 /* The squeue has been paused */

#define	SQS_WORKER_THR_CONTROL          \
	(SQS_POLL_QUIESCE | SQS_POLL_RESTART | SQS_POLL_CLEANUP)

#define	SQS_POLL_THR_CONTROL            \
	(SQS_POLL_THR_QUIESCE | SQS_POLL_THR_RESTART)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SQUEUE_IMPL_H */
