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

#ifndef _SYS_FX_H
#define	_SYS_FX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpucaps.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fixed-priority dispatcher parameter table entry
 */
typedef struct fxdpent {
	pri_t	fx_globpri;	/* global (class independent) priority */
	int	fx_quantum;	/* time quantum given to procs at this level */
} fxdpent_t;

#ifdef _KERNEL

typedef uintptr_t fx_cookie_t;	/* handle for callback supplied storage */

/*
 * callbacks supplied by custom scheduler. In general, a change to quantum
 * and/or priority when returning from a callback has immediate effect.
 *
 * fx_exit - called when a thread exits. This also needs to free any storage
 *	for the fx_cookie_t.
 *
 * fx_callb_tick - called at every clock tick attributed to this thread
 *
 * fx_callb_preempt - called when a thread is being preempted or yielding
 *
 * fx_callb_stop/fx_callb_sleep - called when a thread stops running
 *
 * fx_callb_wakeup - called when a thread is again runnable
 */
typedef struct fx_callbacks {
	int fx_callb_version;
	void (*fx_callb_exit)(fx_cookie_t);
	void (*fx_callb_tick)(fx_cookie_t, clock_t *, pri_t *);
	void (*fx_callb_preempt)(fx_cookie_t, clock_t *, pri_t *);
	void (*fx_callb_stop)(fx_cookie_t);
	void (*fx_callb_sleep)(fx_cookie_t);
	void (*fx_callb_wakeup)(fx_cookie_t, clock_t *, pri_t *);

} fx_callbacks_t;


#define	FX_CALLB_VERSION_1	1

#define	FX_CALLB_REV	FX_CALLB_VERSION_1

#define	FX_CB_VERSION(cb)		cb->fx_callb_version

#define	FX_CB_EXIT(cb, c)		cb->fx_callb_exit(c)

#define	FX_CB_TICK(cb, c, q, p)		cb->fx_callb_tick(c, q, p)

#define	FX_CB_PREEMPT(cb, c, q, p)	cb->fx_callb_preempt(c, q, p)

#define	FX_CB_STOP(cb, c)		cb->fx_callb_stop(c)

#define	FX_CB_SLEEP(cb, c)		cb->fx_callb_sleep(c)

#define	FX_CB_WAKEUP(cb, c, q, p)	cb->fx_callb_wakeup(c, q, p)

/* priority setting */
#define	FX_CB_NOCHANGE	-32768


/*
 * Fixed-priority class specific thread structure
 */
typedef struct fxproc {
	int		fx_pquantum;	/* time quantum given to this proc */
	int		fx_timeleft;	/* time remaining in procs quantum */

	pri_t		fx_pri;		/* relative priority within fx class */
					/* same as user priority */

	pri_t		fx_uprilim;	/* user priority limit */

	char		fx_nice;	/* nice value for compatibility */
	uchar_t 	fx_flags;	/* flags defined below */
	kthread_t 	*fx_tp;		/* pointer to thread */

	/* the following are used only when we have callbacks registered */
	kt_did_t	fx_ktid;
	struct fxproc 	*fx_cb_next;	/* pointer to next fxproc that */
					/* has a callback */

	struct fxproc 	*fx_cb_prev;	/* pointer to previous fxproc that */
					/* has a callback */
	fx_cookie_t	fx_cookie;	/* cookie with which callback */
					/* was registered */
	fx_callbacks_t 	*fx_callback;	/* pointer to callback structure */
	caps_sc_t	fx_caps;	/* CPU caps specific data */
} fxproc_t;


#define	FX_CALLB(fxpp)	fxpp->fx_callback


/* flags */
#define	FXBACKQ	0x02	/* thread goes to back of disp q when preempted */

/*
 * Kernel version of fixed-priority class specific parameter structure
 */
typedef struct	fxkparms {
	pri_t	fx_upri;
	pri_t	fx_uprilim;
	int	fx_tqntm;
	uint_t	fx_cflags;
} fxkparms_t;



/*
 * Interface for partner private code. This is not a public interface.
 */
extern int fx_register_callbacks(fx_callbacks_t *, fx_cookie_t, pri_t, clock_t);
extern int fx_unregister_callbacks();
extern int fx_modify_priority(kt_did_t, clock_t, pri_t);
extern void *fx_get_mutex_cookie();
extern pri_t fx_get_maxpri();

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FX_H */
