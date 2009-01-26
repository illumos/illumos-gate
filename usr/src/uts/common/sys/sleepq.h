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

#ifndef _SYS_SLEEPQ_H
#define	_SYS_SLEEPQ_H

#include <sys/machlock.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Common definition for a sleep queue,
 * be it an old-style sleep queue, or
 * a constituent of a turnstile.
 */

typedef struct sleepq {
	struct _kthread *sq_first;
} sleepq_t;

/*
 * Definition of the head of a sleep queue hash bucket.
 */
typedef struct _sleepq_head {
	sleepq_t	sq_queue;
	disp_lock_t	sq_lock;
} sleepq_head_t;

#ifdef	_KERNEL

#define	NSLEEPQ		2048
#define	SQHASHINDEX(X)	\
	((((uintptr_t)(X) >> 2) ^ ((uintptr_t)(X) >> 13) ^	\
	((uintptr_t)(X) >> 24)) & (NSLEEPQ - 1))
#define	SQHASH(X)	(&sleepq_head[SQHASHINDEX(X)])

extern sleepq_head_t	sleepq_head[NSLEEPQ];

extern void		sleepq_insert(sleepq_t *, struct _kthread *);
extern struct _kthread	*sleepq_wakeone_chan(sleepq_t *, void *);
extern void		sleepq_wakeall_chan(sleepq_t *, void *);
extern void		sleepq_unsleep(struct _kthread *);
extern void		sleepq_dequeue(struct _kthread *);
extern void		sleepq_unlink(struct _kthread **, struct _kthread *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SLEEPQ_H */
