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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_TURNSTILE_H
#define	_SYS_TURNSTILE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/sleepq.h>
#include <sys/mutex.h>
#include <sys/lwp_timer_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	TS_WRITER_Q	0	/* writer sleepq (exclusive access to sobj) */
#define	TS_READER_Q	1	/* reader sleepq (shared access to sobj) */
#define	TS_NUM_Q	2	/* number of sleep queues per turnstile */

typedef struct turnstile turnstile_t;
struct _sobj_ops;

struct turnstile {
	turnstile_t	*ts_next;	/* next on hash chain */
	turnstile_t	*ts_free;	/* next on freelist */
	void		*ts_sobj;	/* s-object threads are blocking on */
	int		ts_waiters;	/* number of blocked threads */
	pri_t		ts_epri;	/* max priority of blocked threads */
	struct _kthread	*ts_inheritor;	/* thread inheriting priority */
	turnstile_t	*ts_prioinv;	/* next in inheritor's t_prioinv list */
	sleepq_t	ts_sleepq[TS_NUM_Q]; /* read/write sleep queues */
};

#ifdef	_KERNEL

extern turnstile_t *turnstile_lookup(void *);
extern void turnstile_exit(void *);
extern int turnstile_block(turnstile_t *, int, void *, struct _sobj_ops *,
    kmutex_t *, lwp_timer_t *);
extern void turnstile_wakeup(turnstile_t *, int, int, struct _kthread *);
extern void turnstile_change_pri(struct _kthread *, pri_t, pri_t *);
extern void turnstile_unsleep(struct _kthread *);
extern void turnstile_stay_asleep(struct _kthread *);
extern void turnstile_pi_recalc(void);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TURNSTILE_H */
