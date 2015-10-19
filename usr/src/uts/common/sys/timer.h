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
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

#ifndef	_SYS_TIMER_H
#define	_SYS_TIMER_H

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	_TIMER_MAX	32
extern	int	timer_max;		/* patchable via /etc/system */

/*
 * Bit values for the it_lock field.
 */
#define	ITLK_LOCKED		0x01
#define	ITLK_WANTED		0x02
#define	ITLK_REMOVE		0x04

/*
 * Bit values for the it_flags field.
 */
#define	IT_SIGNAL		0x01
#define	IT_PORT			0x02	/* use event port notification */

struct clock_backend;

struct itimer;
typedef struct itimer itimer_t;

struct itimer {
	itimerspec_t	it_itime;
	hrtime_t	it_hrtime;
	ushort_t	it_flags;
	ushort_t	it_lock;
	void		*it_arg;	/* clock backend-specific data */
	struct proc	*it_proc;
	union {
		struct {
			sigqueue_t	*__it_sigq;
			klwp_t		*__it_lwp;
		} __proc;
		void *__it_frontend;
	} __data;			/* timer frontend-specific data */
	kcondvar_t	it_cv;
	int		it_blockers;
	int		it_pending;
	int		it_overrun;
	struct clock_backend *it_backend;
	void		(*it_fire)(itimer_t *);
	kmutex_t	it_mutex;
	void		*it_portev;	/* port_kevent_t pointer */
	void		*it_portsrc;	/* port_source_t pointer */
	int		it_portfd;	/* port file descriptor */
};

#define	it_sigq		__data.__proc.__it_sigq
#define	it_lwp		__data.__proc.__it_lwp
#define	it_frontend	__data.__it_frontend

typedef struct clock_backend {
	struct sigevent clk_default;
	int (*clk_clock_settime)(timespec_t *);
	int (*clk_clock_gettime)(timespec_t *);
	int (*clk_clock_getres)(timespec_t *);
	int (*clk_timer_create)(itimer_t *, void (*)(itimer_t *));
	int (*clk_timer_settime)(itimer_t *, int, const struct itimerspec *);
	int (*clk_timer_gettime)(itimer_t *, struct itimerspec *);
	int (*clk_timer_delete)(itimer_t *);
	void (*clk_timer_lwpbind)(itimer_t *);
} clock_backend_t;

extern void clock_add_backend(clockid_t clock, clock_backend_t *backend);
extern clock_backend_t *clock_get_backend(clockid_t clock);

extern void timer_lwpbind();

extern	void	timer_func(sigqueue_t *);
extern	void	timer_exit(void);
extern	void	timer_lwpexit(void);
extern	clock_t	hzto(struct timeval *);
extern	clock_t	timespectohz(timespec_t *, timespec_t);
extern	int64_t	timespectohz64(timespec_t *);
extern	int	itimerspecfix(timespec_t *);
extern	void	timespecadd(timespec_t *, timespec_t *);
extern	void	timespecsub(timespec_t *, timespec_t *);
extern	void	timespecfix(timespec_t *);
extern	int	xgetitimer(uint_t, struct itimerval *, int);
extern	int	xsetitimer(uint_t, struct itimerval *, int);
extern	void	delete_itimer_realprof(void);

#define	timerspecisset(tvp)		((tvp)->tv_sec || (tvp)->tv_nsec)
#define	timerspeccmp(tvp, uvp)		(((tvp)->tv_sec - (uvp)->tv_sec) ? \
	((tvp)->tv_sec - (uvp)->tv_sec):((tvp)->tv_nsec - (uvp)->tv_nsec))
#define	timerspecclear(tvp)		((tvp)->tv_sec = (tvp)->tv_nsec = 0)

struct oldsigevent {
	/* structure definition prior to notification attributes member */
	int		_notify;
	union {
		int		_signo;
		void		(*_notify_function)(union sigval);
	} _un;
	union sigval	_value;
};

#if defined(_SYSCALL32)

struct oldsigevent32 {
	int32_t		_notify;
	union {
		int32_t		_signo;
		caddr32_t	_notify_function;
	} _un;
	union sigval32	_value;
};

#endif	/* _SYSCALL32 */
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TIMER_H */
