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

#ifndef	_LIBNSL_INCLUDE_MT_H
#define	_LIBNSL_INCLUDE_MT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Threading and mutual exclusion declarations of primitives used for
 *	MT operation of libnsl code.
 *
 * Note: These primitives are designed to achieve the effect of avoiding a
 *	 deadlock possibility by an interface operation being called from
 *	 a signal handler while holding a lock.
 * Note: the sig_*() functions use the _sigoff() and _sigon() consolidation
 *       private interfaces provided by libc to defer all asynchronously
 *       generated signals for the duration of holding the lock.  Unlike
 *	 blocking all signals with sigprocmask() or thr_sigsetmask(),
 *	 _sigoff() allows signals with default dispositions to exercise
 *	 their default actions (killing the process, stopping the process).
 */

#include <thread.h>
#include <pthread.h>
#include <signal.h>
#include <synch.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern sigset_t fillset;	/* for actually blocking all signals */

extern void sig_mutex_lock(mutex_t *);
extern void sig_mutex_unlock(mutex_t *);
extern void sig_rw_rdlock(rwlock_t *);
extern void sig_rw_wrlock(rwlock_t *);
extern void sig_rw_unlock(rwlock_t *);

extern void _sigoff(void);
extern void _sigon(void);

extern void *thr_get_storage(pthread_key_t *, size_t, void(*)(void *));

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBNSL_INCLUDE_MT_H */
