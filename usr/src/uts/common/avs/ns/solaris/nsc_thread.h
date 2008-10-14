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

#ifndef	_NSC_THREAD_H
#define	_NSC_THREAD_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#include <sys/ksynch.h>		/* for kmutex_t and kcondvar_t */

/*
 * A simple way to marshal kthreads into sets for use by nsctl / nskern
 * clients.  The ns threads are created in user land by nskernd, and
 * then call into the nskern kernel module for allocation into sets.
 */

struct nsthread;
struct nstset;

#ifndef _BLIND_T
#define	_BLIND_T
typedef void * blind_t;
#endif /* _BLIND_T */


/*
 * Queue stuff that should really be in the DDI.
 */

typedef struct nst_q {
	struct nst_q *q_forw;
	struct nst_q *q_back;
} nst_q_t;


/*
 * Per thread data structure.
 */

typedef struct nsthread {
	nst_q_t		tp_link;	/* Doubly linked free list */

	struct nstset	*tp_set;	/* Set to which thread belongs */
	struct nsthread *tp_chain;	/* Link in chain of threads in set */

	kcondvar_t	tp_cv;		/* Suspend/resume synchronisation */

	/*
	 * Everything past this point is cleared when the thread is
	 * initialised for (re)use.
	 */

	int		tp_flag;	/* State (below) */

	void		(*tp_func)();	/* First function */
	blind_t		tp_arg;		/* Argument to tp_func */
} nsthread_t;

/*
 * Flags for nst_init
 */
#define	NST_CREATE	0x1	/* Create resources to run thread */
#define	NST_SLEEP	0x2	/* Wait for resources to be available */

/*
 * Thread state flags
 */
#define	NST_TF_INUSE		0x1	/* Thread currently in use */
#define	NST_TF_ACTIVE		0x2	/* Thread is being manipulated */
#define	NST_TF_PENDING		0x4	/* Thread is pending a create */
#define	NST_TF_DESTROY		0x8	/* Destroy thread when finished */
#define	NST_TF_KILL		0x10	/* Thread is being killed */

/*
 * Thread set.
 */
typedef struct nstset {
	struct nstset	*set_next;	/* Next set in list of sets */

	nsthread_t	*set_chain;	/* Chain of all threads in set */
	nst_q_t		set_reuse;	/* Chain of reusable threads */
	nst_q_t		set_free;	/* Chain of free threads */

	char		set_name[32];	/* Name associated with set */

	ushort_t	set_nlive;	/* No. of active threads */
	ushort_t	set_nthread;	/* No. of threads in set */
	int		set_flag;	/* State (below) */
	int		set_pending;	/* Operation is pending */

	kmutex_t	set_lock;	/* Mutex for chains and counts */
	kcondvar_t	set_kill_cv;	/* Kill synchronisation */
	kcondvar_t	set_destroy_cv;	/* Shutdown synchronisation */
	volatile int	set_destroy_cnt; /* No. of waiters */

	kcondvar_t	set_res_cv;	/* Resource alloc synchronisation */
	int 		set_res_cnt;	/* No. of waiters */
} nstset_t;

/*
 * Set state flags
 */
#define	NST_SF_KILL	1	/* Set is being killed */

/*
 * General defines
 */
#define	NST_KILL_TIMEOUT	100000	/* usec to wait for threads to die */
#define	NST_MEMORY_TIMEOUT	500000	/* usec to wait for memory */

/*
 * Function prototypes
 */

int		nst_add_thread(nstset_t *, int);
nsthread_t	*nst_create(nstset_t *, void (*)(), blind_t, int);
int		nst_del_thread(nstset_t *, int);
void		nst_destroy(nstset_t *);
nstset_t	*nst_init(char *, int);
int		nst_nlive(nstset_t *);
int		nst_nthread(nstset_t *);
int		nst_startup(void);
void		nst_shutdown(void);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _NSC_THREAD_H */
