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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#ifndef _SYS_DISP_H
#define	_SYS_DISP_H

#include <sys/priocntl.h>
#include <sys/thread.h>
#include <sys/class.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following is the format of a dispatcher queue entry.
 */
typedef struct dispq {
	kthread_t	*dq_first;	/* first thread on queue or NULL */
	kthread_t	*dq_last;	/* last thread on queue or NULL */
	int		dq_sruncnt;	/* number of loaded, runnable */
					/*    threads on queue */
} dispq_t;

/*
 * Dispatch queue structure.
 */
typedef struct _disp {
	disp_lock_t	disp_lock;	/* protects dispatching fields */
	pri_t		disp_npri;	/* # of priority levels in queue */
	dispq_t		*disp_q;		/* the dispatch queue */
	dispq_t		*disp_q_limit;	/* ptr past end of dispatch queue */
	ulong_t		*disp_qactmap;	/* bitmap of active dispatch queues */

	/*
	 * Priorities:
	 *	disp_maxrunpri is the maximum run priority of runnable threads
	 * 	on this queue.  It is -1 if nothing is runnable.
	 *
	 *	disp_max_unbound_pri is the maximum run priority of threads on
	 *	this dispatch queue but runnable by any CPU.  This may be left
	 * 	artificially high, then corrected when some CPU tries to take
	 *	an unbound thread.  It is -1 if nothing is runnable.
	 */
	pri_t		disp_maxrunpri;	/* maximum run priority */
	pri_t		disp_max_unbound_pri;	/* max pri of unbound threads */

	volatile int	disp_nrunnable;	/* runnable threads in cpu dispq */

	struct cpu	*disp_cpu;	/* cpu owning this queue or NULL */
	hrtime_t	disp_steal;	/* time when threads become stealable */
} disp_t;

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

#define	MAXCLSYSPRI	99
#define	MINCLSYSPRI	60


/*
 * Global scheduling variables.
 *	- See sys/cpuvar.h for CPU-local variables.
 */
extern int	nswapped;	/* number of swapped threads */
				/* nswapped protected by swap_lock */

extern	pri_t	minclsyspri;	/* minimum level of any system class */
extern	pri_t	maxclsyspri;	/* maximum level of any system class */
extern	pri_t	intr_pri;	/* interrupt thread priority base level */

#endif	/* _KERNEL || _FAKE_KERNEL */
#if defined(_KERNEL)

/*
 * Minimum amount of time that a thread can remain runnable before it can
 * be stolen by another CPU (in nanoseconds).
 */
extern hrtime_t nosteal_nsec;

/*
 * Kernel preemption occurs if a higher-priority thread is runnable with
 * a priority at or above kpreemptpri.
 *
 * So that other processors can watch for such threads, a separate
 * dispatch queue with unbound work above kpreemptpri is maintained.
 * This is part of the CPU partition structure (cpupart_t).
 */
extern	pri_t	kpreemptpri;	/* level above which preemption takes place */

extern void		disp_kp_alloc(disp_t *, pri_t);	/* allocate kp queue */
extern void		disp_kp_free(disp_t *);		/* free kp queue */

/*
 * Macro for use by scheduling classes to decide whether the thread is about
 * to be scheduled or not.  This returns the maximum run priority.
 */
#define	DISP_MAXRUNPRI(t)	((t)->t_disp_queue->disp_maxrunpri)

/*
 * Platform callbacks for various dispatcher operations
 *
 * idle_cpu() is invoked when a cpu goes idle, and has nothing to do.
 * disp_enq_thread() is invoked when a thread is placed on a run queue.
 */
extern void	(*idle_cpu)();
extern void	(*disp_enq_thread)(struct cpu *, int);


extern int		dispdeq(kthread_t *);
extern void		dispinit(void);
extern void		disp_add(sclass_t *);
extern int		intr_active(struct cpu *, int);
extern int		servicing_interrupt(void);
extern void		preempt(void);
extern void		setbackdq(kthread_t *);
extern void		setfrontdq(kthread_t *);
extern void		swtch(void);
extern void		swtch_to(kthread_t *);
extern void		swtch_from_zombie(void)
				__NORETURN;
extern void		dq_sruninc(kthread_t *);
extern void		dq_srundec(kthread_t *);
extern void		cpu_rechoose(kthread_t *);
extern void		cpu_surrender(kthread_t *);
extern void		kpreempt(int);
extern struct cpu	*disp_lowpri_cpu(struct cpu *, struct lgrp_ld *, pri_t,
			    struct cpu *);
extern int		disp_bound_threads(struct cpu *, int);
extern int		disp_bound_anythreads(struct cpu *, int);
extern int		disp_bound_partition(struct cpu *, int);
extern void		disp_cpu_init(struct cpu *);
extern void		disp_cpu_fini(struct cpu *);
extern void		disp_cpu_inactive(struct cpu *);
extern void		disp_adjust_unbound_pri(kthread_t *);
extern void		resume(kthread_t *);
extern void		resume_from_intr(kthread_t *);
extern void		resume_from_zombie(kthread_t *)
				__NORETURN;
extern void		disp_swapped_enq(kthread_t *);
extern int		disp_anywork(void);

#define	KPREEMPT_SYNC		(-1)
#define	kpreempt_disable()				\
	{						\
		curthread->t_preempt++;			\
		ASSERT(curthread->t_preempt >= 1);	\
	}
#define	kpreempt_enable()				\
	{						\
		ASSERT(curthread->t_preempt >= 1);	\
		if (--curthread->t_preempt == 0 &&	\
		    CPU->cpu_kprunrun)			\
			kpreempt(KPREEMPT_SYNC);	\
	}

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DISP_H */
