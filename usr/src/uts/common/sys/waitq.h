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

#ifndef _SYS_WAITQ_H
#define	_SYS_WAITQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#include <sys/types.h>
#include <sys/machlock.h>
#include <sys/thread.h>

typedef struct waitq {
	disp_lock_t	wq_lock;	/* protects all fields */
	kthread_t	*wq_first;	/* first thread on the queue */
	int		wq_count;	/* number of threads on the queue */
	boolean_t	wq_blocked;	/* True if threads can't be enqueued */
} waitq_t;

extern void		waitq_init(waitq_t *);
extern void		waitq_fini(waitq_t *);

/*
 * Place the thread on the wait queue. An attempt to enqueue a thread onto a
 * blocked queue fails and returns zero. Successful enqueue returns non-zero
 * value.
 */
extern int		waitq_enqueue(waitq_t *, kthread_t *);

/*
 * Take thread off its wait queue and make it runnable.
 */
extern void		waitq_setrun(kthread_t *t);

/*
 * Change priority for the thread on wait queue.
 */
extern void		waitq_change_pri(kthread_t *, pri_t);

/*
 * Take the first thread off the wait queue and make it runnable.
 */
extern void		waitq_runone(waitq_t *);

/*
 * Return True if there are no threads on the queue.
 */
extern boolean_t	waitq_isempty(waitq_t *);

/*
 * Prevent and allow placing new threads on wait queue.
 */
extern void		waitq_block(waitq_t *);
extern void		waitq_unblock(waitq_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_WAITQ_H */
