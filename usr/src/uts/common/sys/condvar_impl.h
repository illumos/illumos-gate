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

#ifndef _SYS_CONDVAR_IMPL_H
#define	_SYS_CONDVAR_IMPL_H

/*
 * Implementation-private definitions for condition variables
 */

#ifndef	_ASM
#include <sys/types.h>
#include <sys/thread.h>
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

/*
 * Condtion variables.
 */

typedef struct _condvar_impl {
	ushort_t	cv_waiters;
} condvar_impl_t;

#define	CV_HAS_WAITERS(cvp)	(((condvar_impl_t *)(cvp))->cv_waiters != 0)

#endif	/* _ASM */


/*
 * The cvwaitlock_t structure and associated macros provide an implementation
 * of a locking mechanism that allows recursion on the reader lock without
 * danger of a pending write lock elsewhere being able to cause a deadlock.
 * The provision for supporting recursion is necessary for use with the
 * netinfo (neti) kernel module when processing network data.
 *
 * Support for recursion (giving precedence to readers and allowing them
 * to enter even when a write is blocked) can result in write starvation.
 * There is no priority inheritence for this locking interface.
 */
typedef	struct	cvwaitlock_s	{
	kmutex_t	cvw_lock;
	kcondvar_t	cvw_waiter;
	int		cvw_refcnt;
} cvwaitlock_t;


#define	CVW_INIT(_c)		{				\
	mutex_init(&(_c)->cvw_lock, NULL, MUTEX_DRIVER, NULL);	\
	cv_init(&(_c)->cvw_waiter, NULL, CV_DRIVER, NULL);	\
	(_c)->cvw_refcnt = 0;					\
}

#define	CVW_ENTER_READ(_c)	{				\
	mutex_enter(&(_c)->cvw_lock);				\
	while ((_c)->cvw_refcnt < 0)				\
		cv_wait(&((_c)->cvw_waiter), &(_c)->cvw_lock);	\
	(_c)->cvw_refcnt++;					\
	mutex_exit(&(_c)->cvw_lock);				\
}

#define	CVW_ENTER_WRITE(_c)	{				\
	mutex_enter(&(_c)->cvw_lock);				\
	while ((_c)->cvw_refcnt != 0)				\
		cv_wait(&((_c)->cvw_waiter), &(_c)->cvw_lock);	\
	(_c)->cvw_refcnt = -1;					\
	mutex_exit(&(_c)->cvw_lock);				\
}

#define	CVW_EXIT_READ(_c)	{			\
	mutex_enter(&(_c)->cvw_lock);			\
	ASSERT((_c)->cvw_refcnt > 0);			\
	if ((--((_c)->cvw_refcnt)) == 0)		\
		cv_broadcast(&(_c)->cvw_waiter);	\
	mutex_exit(&(_c)->cvw_lock);			\
}

#define	CVW_EXIT_WRITE(_c)	{			\
	mutex_enter(&(_c)->cvw_lock);			\
	ASSERT((_c)->cvw_refcnt == -1);			\
	(_c)->cvw_refcnt = 0;				\
	cv_broadcast(&(_c)->cvw_waiter);		\
	mutex_exit(&(_c)->cvw_lock);			\
}

#define	CVW_WRITE_TO_READ(_c)	{			\
	mutex_enter(&(_c)->cvw_lock);			\
	ASSERT((_c)->cvw_refcnt == -1);			\
	(_c)->cvw_refcnt = 1;				\
	cv_broadcast(&(_c)->cvw_waiter);		\
	mutex_exit(&(_c)->cvw_lock);			\
}

#define	CVW_DESTROY(_c)	{				\
	mutex_destroy(&(_c)->cvw_lock);			\
	cv_destroy(&(_c)->cvw_waiter);			\
}

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONDVAR_IMPL_H */
