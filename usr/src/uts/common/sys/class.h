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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_CLASS_H
#define	_SYS_CLASS_H

#include <sys/t_lock.h>
#include <sys/cred.h>
#include <sys/thread.h>
#include <sys/priocntl.h>
#include <sys/mutex.h>
#include <sys/uio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * NOTE: Developers making use of the scheduler class switch mechanism
 * to develop scheduling class modules should be aware that the
 * architecture is not frozen and the kernel interface for scheduling
 * class modules may change in future releases of System V.  Support
 * for the current interface is not guaranteed and class modules
 * developed to this interface may require changes in order to work
 * with future releases of the system.
 */

/*
 * three different ops vectors are bundled together, here.
 * one is for each of the fundamental objects acted upon
 * by these operators: procs, threads, and the class manager itself.
 */

typedef struct class_ops {
	int	(*cl_admin)(caddr_t, cred_t *);
	int	(*cl_getclinfo)(void *);
	int	(*cl_parmsin)(void *);
	int	(*cl_parmsout)(void *, pc_vaparms_t *);
	int	(*cl_vaparmsin)(void *, pc_vaparms_t *);
	int	(*cl_vaparmsout)(void *, pc_vaparms_t *);
	int	(*cl_getclpri)(pcpri_t *);
	int	(*cl_alloc)(void **, int);
	void	(*cl_free)(void *);
} class_ops_t;

typedef struct thread_ops {
	int	(*cl_enterclass)(kthread_t *, id_t, void *, cred_t *, void *);
	void	(*cl_exitclass)(void *);
	int	(*cl_canexit)(kthread_t *, cred_t *);
	int	(*cl_fork)(kthread_t *, kthread_t *, void *);
	void	(*cl_forkret)(kthread_t *, kthread_t *);
	void	(*cl_parmsget)(kthread_t *, void *);
	int	(*cl_parmsset)(kthread_t *, void *, id_t, cred_t *);
	void	(*cl_stop)(kthread_t *, int, int);
	void	(*cl_exit)(kthread_t *);
	void	(*cl_active)(kthread_t *);
	void	(*cl_inactive)(kthread_t *);
	pri_t	(*cl_swapin)(kthread_t *, int);
	pri_t 	(*cl_swapout)(kthread_t *, int);
	void 	(*cl_trapret)(kthread_t *);
	void	(*cl_preempt)(kthread_t *);
	void	(*cl_setrun)(kthread_t *);
	void	(*cl_sleep)(kthread_t *);
	void	(*cl_tick)(kthread_t *);
	void	(*cl_wakeup)(kthread_t *);
	int	(*cl_donice)(kthread_t *, cred_t *, int, int *);
	pri_t	(*cl_globpri)(kthread_t *);
	void	(*cl_set_process_group)(pid_t, pid_t, pid_t);
	void	(*cl_yield)(kthread_t *);
	int	(*cl_doprio)(kthread_t *, cred_t *, int, int *);
} thread_ops_t;

typedef struct classfuncs {
	class_ops_t	sclass;
	thread_ops_t	thread;
} classfuncs_t;

typedef struct sclass {
	char		*cl_name;	/* class name */
	/* class specific initialization function */
	pri_t		(*cl_init)(id_t, int, classfuncs_t **);
	classfuncs_t	*cl_funcs;	/* pointer to classfuncs structure */
	krwlock_t	*cl_lock;	/* class structure read/write lock */
	int		cl_count;	/* # of threads trying to load class */
} sclass_t;

#define	STATIC_SCHED		(krwlock_t *)0xffffffff
#define	LOADABLE_SCHED(s)	((s)->cl_lock != STATIC_SCHED)
#define	SCHED_INSTALLED(s)	((s)->cl_funcs != NULL)
#define	ALLOCATED_SCHED(s)	((s)->cl_lock != NULL)

#if defined(_KERNEL) || defined(_FAKE_KERNEL)

#define	CLASS_KERNEL(cid)	((cid) == syscid || (cid) == sysdccid)

extern int	nclass;		/* number of configured scheduling classes */
extern char	*defaultclass;	/* default class for newproc'd processes */
extern struct sclass sclass[];	/* the class table */
extern kmutex_t	class_lock;	/* lock protecting class table */
extern int	loaded_classes;	/* number of classes loaded */

extern pri_t	minclsyspri;
extern id_t	syscid;		/* system scheduling class ID */
extern id_t	sysdccid;	/* system duty-cycle scheduling class ID */
extern id_t	defaultcid;	/* "default" class id; see dispadmin(1M) */

extern int	alloc_cid(char *, id_t *);
extern int	scheduler_load(char *, sclass_t *);
extern int	getcid(char *, id_t *);
extern int	getcidbyname(char *, id_t *);
extern int	parmsin(pcparms_t *, pc_vaparms_t *);
extern int	parmsout(pcparms_t *, pc_vaparms_t *);
extern int	parmsset(pcparms_t *, kthread_t *);
extern void	parmsget(kthread_t *, pcparms_t *);
extern int	vaparmsout(char *, pcparms_t *, pc_vaparms_t *, uio_seg_t);

#endif

#define	CL_ADMIN(clp, uaddr, reqpcredp) \
	(*(clp)->cl_funcs->sclass.cl_admin)(uaddr, reqpcredp)

#define	CL_ENTERCLASS(t, cid, clparmsp, credp, bufp) \
	(sclass[cid].cl_funcs->thread.cl_enterclass) (t, cid, \
	    (void *)clparmsp, credp, bufp)

#define	CL_EXITCLASS(cid, clprocp)\
	(sclass[cid].cl_funcs->thread.cl_exitclass) ((void *)clprocp)

#define	CL_CANEXIT(t, cr)	(*(t)->t_clfuncs->cl_canexit)(t, cr)

#define	CL_FORK(tp, ct, bufp)	(*(tp)->t_clfuncs->cl_fork)(tp, ct, bufp)

#define	CL_FORKRET(t, ct)	(*(t)->t_clfuncs->cl_forkret)(t, ct)

#define	CL_GETCLINFO(clp, clinfop) \
	(*(clp)->cl_funcs->sclass.cl_getclinfo)((void *)clinfop)

#define	CL_GETCLPRI(clp, clprip) \
	(*(clp)->cl_funcs->sclass.cl_getclpri)(clprip)

#define	CL_PARMSGET(t, clparmsp) \
	(*(t)->t_clfuncs->cl_parmsget)(t, (void *)clparmsp)

#define	CL_PARMSIN(clp, clparmsp) \
	(clp)->cl_funcs->sclass.cl_parmsin((void *)clparmsp)

#define	CL_PARMSOUT(clp, clparmsp, vaparmsp) \
	(clp)->cl_funcs->sclass.cl_parmsout((void *)clparmsp, vaparmsp)

#define	CL_VAPARMSIN(clp, clparmsp, vaparmsp) \
	(clp)->cl_funcs->sclass.cl_vaparmsin((void *)clparmsp, vaparmsp)

#define	CL_VAPARMSOUT(clp, clparmsp, vaparmsp) \
	(clp)->cl_funcs->sclass.cl_vaparmsout((void *)clparmsp, vaparmsp)

#define	CL_PARMSSET(t, clparmsp, cid, curpcredp) \
	(*(t)->t_clfuncs->cl_parmsset)(t, (void *)clparmsp, cid, curpcredp)

#define	CL_PREEMPT(tp)		(*(tp)->t_clfuncs->cl_preempt)(tp)

#define	CL_SETRUN(tp)		(*(tp)->t_clfuncs->cl_setrun)(tp)

#define	CL_SLEEP(tp)		(*(tp)->t_clfuncs->cl_sleep)(tp)

#define	CL_STOP(t, why, what)	(*(t)->t_clfuncs->cl_stop)(t, why, what)

#define	CL_EXIT(t)		(*(t)->t_clfuncs->cl_exit)(t)

#define	CL_ACTIVE(t)		(*(t)->t_clfuncs->cl_active)(t)

#define	CL_INACTIVE(t)		(*(t)->t_clfuncs->cl_inactive)(t)

#define	CL_SWAPIN(t, flags)	(*(t)->t_clfuncs->cl_swapin)(t, flags)

#define	CL_SWAPOUT(t, flags)	(*(t)->t_clfuncs->cl_swapout)(t, flags)

#define	CL_TICK(t)		(*(t)->t_clfuncs->cl_tick)(t)

#define	CL_TRAPRET(t)		(*(t)->t_clfuncs->cl_trapret)(t)

#define	CL_WAKEUP(t)		(*(t)->t_clfuncs->cl_wakeup)(t)

#define	CL_DONICE(t, cr, inc, ret) \
	(*(t)->t_clfuncs->cl_donice)(t, cr, inc, ret)

#define	CL_DOPRIO(t, cr, inc, ret) \
	(*(t)->t_clfuncs->cl_doprio)(t, cr, inc, ret)

#define	CL_GLOBPRI(t)		(*(t)->t_clfuncs->cl_globpri)(t)

#define	CL_SET_PROCESS_GROUP(t, s, b, f) \
	(*(t)->t_clfuncs->cl_set_process_group)(s, b, f)

#define	CL_YIELD(tp)		(*(tp)->t_clfuncs->cl_yield)(tp)

#define	CL_ALLOC(pp, cid, flag)	\
	(sclass[cid].cl_funcs->sclass.cl_alloc) (pp, flag)

#define	CL_FREE(cid, bufp)	(sclass[cid].cl_funcs->sclass.cl_free) (bufp)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CLASS_H */
