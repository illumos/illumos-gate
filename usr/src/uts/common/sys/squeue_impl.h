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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SQUEUE_IMPL_H
#define	_SYS_SQUEUE_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/squeue.h>

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

struct squeue_s {
	/* Keep the most used members 64bytes cache aligned */
	kmutex_t	sq_lock;	/* lock before using any member */
	uint32_t	sq_state;	/* state flags and message count */
	int		sq_count;	/* # of mblocks in squeue */
	mblk_t		*sq_first;	/* first mblk chain or NULL */
	mblk_t		*sq_last;	/* last mblk chain or NULL */
	clock_t		sq_awaken;	/* time async thread was awakened */
	kthread_t	*sq_run;	/* Current thread processing sq */
	void		*sq_rx_ring;
	clock_t		sq_avg_drain_time; /* Avg time to drain a pkt */

	processorid_t	sq_bind;	/* processor to bind to */
	kcondvar_t	sq_async;	/* async thread blocks on */
	clock_t		sq_wait;	/* lbolts to wait after a fill() */
	uintptr_t	sq_private[SQPRIVATE_MAX];
	timeout_id_t	sq_tid;		/* timer id of pending timeout() */
	kthread_t	*sq_worker;	/* kernel thread id */
	char		sq_name[SQ_NAMELEN + 1];

#if SQUEUE_DEBUG
	/* Debug-only fields */
	int		sq_isintr;	/* serviced by interrupt */
	mblk_t		*sq_curmp;
	void		(*sq_curproc)();
	conn_t		*sq_connp;
	uchar_t		sq_tag;
#endif

#if SQUEUE_PROFILE
	/* Profiling fields */
	kstat_t		*sq_kstat;	/* exported statistics */
	sqstat_t	sq_stats;
#endif
};

/*
 * State flags.
 * Note: The MDB IP module depends on the values of these flags.
 */
#define	SQS_PROC	0x0001	/* being processed */
#define	SQS_WORKER	0x0002	/* worker thread */
#define	SQS_ENTER	0x0004	/* enter thread */
#define	SQS_FAST	0x0008	/* enter-fast thread */
#define	SQS_USER	0x0010	/* A non interrupt user */
#define	SQS_BOUND	0x0020	/* Worker thread is bound */
#define	SQS_PROFILE	0x0040	/* Enable profiling */
#define	SQS_REENTER	0x0080	/* Re entered thread */
#define	SQS_TMO_PROG	0x0100	/* Timeout is being set */
#define	SQS_POLL_CAPAB	0x0200	/* Squeue can control interrupts */
#define	SQS_NO_INTR	0x0400	/* Interrupts currently disabled */
#define	SQS_ILL_BOUND	0x0800	/* Squeue bound to an ill */
#define	SQS_GET_PKTS	0x1000	/* Moving pkts from NIC in progress */
#define	SQS_DEFAULT	0x2000	/* The default squeue for the CPU */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SQUEUE_IMPL_H */
