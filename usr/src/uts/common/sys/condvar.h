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

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * condvar.h:
 *
 * definitions for thread synchronization primitives: condition variables
 * This is the public part of the interface to condition variables. The
 * private (implementation-specific) part is in <arch>/sys/condvar_impl.h.
 */

#ifndef _SYS_CONDVAR_H
#define	_SYS_CONDVAR_H

#ifndef	_ASM
#include <sys/types.h>
#include <sys/time.h>
#ifdef _KERNEL
#include <sys/mutex.h>
#endif	/* _KERNEL */
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

/*
 * Condtion variables.
 */

typedef struct _kcondvar {
	ushort_t	_opaque;
} kcondvar_t;

typedef	enum {
	CV_DEFAULT,
	CV_DRIVER
} kcv_type_t;

#if defined(_KERNEL)

/*
 * Time resolution values used in cv_reltimedwait() and cv_reltimedwait_sig()
 * to specify how accurately a relative timeout must expire - if it can be
 * anticipated or deferred.
 */
typedef enum {
	TR_NANOSEC,
	TR_MICROSEC,
	TR_MILLISEC,
	TR_SEC,
	TR_CLOCK_TICK,
	TR_COUNT
} time_res_t;

extern time_res_t time_res[];

#define	TIME_RES_VALID(tr)	(tr >= TR_NANOSEC && tr < TR_COUNT)

/*
 * condition variable function prototypes
 */

extern	void	cv_init(kcondvar_t *, char *, kcv_type_t, void *);
extern  void	cv_destroy(kcondvar_t *);
extern	void	cv_wait(kcondvar_t *, kmutex_t *);
extern	void	cv_wait_stop(kcondvar_t *, kmutex_t *, int);
extern	clock_t	cv_timedwait(kcondvar_t *, kmutex_t *, clock_t);
extern	clock_t	cv_timedwait_hires(kcondvar_t *, kmutex_t *, hrtime_t, hrtime_t,
    int);
extern	clock_t	cv_reltimedwait(kcondvar_t *, kmutex_t *, clock_t, time_res_t);
extern	int	cv_wait_sig(kcondvar_t *, kmutex_t *);
extern	clock_t	cv_timedwait_sig(kcondvar_t *, kmutex_t *, clock_t);
extern	int	cv_timedwait_sig_hrtime(kcondvar_t *, kmutex_t *, hrtime_t);
extern	clock_t	cv_reltimedwait_sig(kcondvar_t *, kmutex_t *, clock_t,
    time_res_t);
extern	int	cv_wait_sig_swap(kcondvar_t *, kmutex_t *);
extern	int	cv_wait_sig_swap_core(kcondvar_t *, kmutex_t *, int *);
extern	void	cv_signal(kcondvar_t *);
extern	void	cv_broadcast(kcondvar_t *);
extern	int	cv_waituntil_sig(kcondvar_t *, kmutex_t *, timestruc_t *, int);

#endif	/* defined(_KERNEL) */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONDVAR_H */
