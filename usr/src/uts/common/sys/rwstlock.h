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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_RWSTLOCK_H
#define	_SYS_RWSTLOCK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Alternate rwlock that is interruptible and can be released by a thread
 * other than the one that acquired the lock.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/rwlock.h>

typedef struct rwstlock {
	intptr_t	rwst_count;
	kcondvar_t	rwst_rcv;
	kcondvar_t	rwst_wcv;
	kmutex_t	rwst_lock;
} rwstlock_t;

/*
 * The interfaces below are private to Sun Microsystems,
 * and these might change without notice.
 */

#define	RWST_TRYENTER	0x01
#define	RWST_SIG	0x02

#define	RWST_HELD(l)		((l)->rwst_count != 0)
#define	RWST_READ_HELD(l)	((l)->rwst_count > 0)
#define	RWST_WRITE_HELD(l)	((l)->rwst_count < 0)
#define	RWST_WRITE_OWNER(l)	\
	((l)->rwst_count == (LONG_MIN | (intptr_t)curthread))
#define	RWST_OWNER(l)		(RWST_WRITE_HELD(l) ? \
	((struct _kthread *)((l)->rwst_count & ~LONG_MIN)) : NULL)
#define	RWST_READ_WANTED(l)	CV_HAS_WAITERS(&(l)->rwst_rcv)
#define	RWST_WRITE_WANTED(l)	CV_HAS_WAITERS(&(l)->rwst_wcv)
#define	RWST_WAIT(cv, lock, f)	\
	((f) & RWST_SIG ? cv_wait_sig(cv, lock) : (cv_wait(cv, lock), 1))
#define	RWST_READ_WAIT(l, f)	RWST_WAIT(&(l)->rwst_rcv, &(l)->rwst_lock, f)
#define	RWST_WRITE_WAIT(l, f)	RWST_WAIT(&(l)->rwst_wcv, &(l)->rwst_lock, f)
#define	RWST_READ_WAKE_ALL(l)	cv_broadcast(&(l)->rwst_rcv)
#define	RWST_WRITE_WAKE_ONE(l)	cv_signal(&(l)->rwst_wcv)
#define	RWST_READ_ENTER(l)	(l)->rwst_count++
#define	RWST_WRITE_ENTER(l)	(l)->rwst_count = LONG_MIN | (intptr_t)curthread
#define	RWST_READ_EXIT(l)	(l)->rwst_count--
#define	RWST_WRITE_EXIT(l)	(l)->rwst_count = 0

extern void rwst_enter(rwstlock_t *, krw_t);
extern int rwst_enter_sig(rwstlock_t *, krw_t);
extern void rwst_exit(rwstlock_t *);
extern void rwst_init(rwstlock_t *, char *, krw_type_t, void *);
extern void rwst_destroy(rwstlock_t *);
extern int rwst_lock_held(rwstlock_t *, krw_t);
extern int rwst_tryenter(rwstlock_t *, krw_t);
extern struct _kthread *rwst_owner(rwstlock_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_RWSTLOCK_H */
