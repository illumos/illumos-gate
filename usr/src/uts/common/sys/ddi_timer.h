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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DDI_TIMER_H
#define	_SYS_DDI_TIMER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Used by the new timeout functions
 */
typedef struct __timeout *timeout_t;

/*
 * Forward declarations.
 */
struct cyc_timer;
struct tm_req;

/*
 * Timing wheel cog.
 * Each cog has a timeout request queue which is guarded by the lock
 * here.
 */
typedef struct timer_tw {
	list_t req;			/* timeout request queue */
	kmutex_t lock;			/* lock for this queue */
} timer_tw_t;

/*
 * Timer based on the cyclic subsystem.
 * For each resolution, this timer structure should be allocated.
 * Note. currently only one timer is used for periodic timeout requests,
 * which is based on the system clock resolution.
 */
typedef struct cyc_timer {
	hrtime_t res;			/* this cyclic resolution */
	hrtime_t tick;			/* tick of this cyclic */
	hrtime_t tick_time;		/* current time on this timer */
/*
 * The hash size might need to be tuned if the lock contention is
 * observed. So far the current size (1024) is sufficient though.
 */
#define	TM_HASH_SZ	(1024)		/* must be power of 2 */
#define	TM_HASH(x)	((x) & (TM_HASH_SZ -1))
	timer_tw_t idhash[TM_HASH_SZ];	/* ID hash */
	timer_tw_t exhash[TM_HASH_SZ];  /* expiration time hash */
} cyc_timer_t;

/*
 * This value determines how many requests within 10ms can be allocated to
 * different slots. This is an exponential number powered by 2.
 * This value should be tuned with the hash size.
 * Note. This value is fixed now, but can be adjusted by checking the number
 * of CPUs when the timer structure is allocated.
 */
#define	TICK_FACTOR	(3)

/*
 * Timer request.
 */
typedef struct tm_req {
	struct list_node id_req;	/* request on ID hash */
	struct list_node ex_req;	/* request on expire hash */
	struct list_node disp_req;	/* request on dispatch queue */
	hrtime_t interval;	/* interval this request needs */
	hrtime_t exp_time;	/* time when the request executes */
	void (*handler)(void *);	/* timeout handler */
	void *arg;		/* timeout argument */
	kthread_t *h_thread;	/* handler thread */
	kmutex_t lock;		/* lock for setting counter and flag */
	kcondvar_t cv;		/* condition variable against the lock */
	timeout_t id;		/* this request id */
	int level;		/* interrupt level */
	volatile uint_t flags;	/* flags passed to ddi_timeout() */
	/*
	 * State flags
	 * These are used internally.
	 */
#define	TM_INVOKING	0x00000001	/* cyclic is invoked now */
#define	TM_EXECUTING	0x00000002	/* timeout is executed now */
#define	TM_CANCEL	0x00000004	/* request is canceled */
#define	TM_TRANSFER	0x00000008	/* request is transfered */
#define	TM_COMPLETE	0x00000010	/* request is complete */
#define	TM_COMPWAIT	0x00000020	/* wait request completion */
#define	TM_UTMCOMP	0x00000040	/* untimeout is complete */
	uint_t cnt;		/* invoke counter */
} tm_req_t;

/*
 * Software interrupt intr_state:
 *
 *  31              16 15               0
 * +------------------+------------------+
 * |  interrupt start |  interrupt set   |
 * +------------------+------------------+
 *
 * Note. This structure can accomodate interrupts up to the level 15,
 * but supported interrupts are up to the level 10 in practice because
 * of the ddi timer restriction.
 */
#define	TM_INTR_SET(l)		(1 << (l))
#define	TM_INTR_START(l)	(1 << ((l) + 16))

/*
 * internal functions for the ddi timeout
 */
void timer_init(void);
void cyclic_timer(void);
void timer_softintr(int);
timeout_t i_timeout(void (*)(void *), void *, hrtime_t, int);
void i_untimeout(timeout_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDI_TIMER_H */
