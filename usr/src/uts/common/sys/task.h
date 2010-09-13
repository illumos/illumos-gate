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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_TASK_H
#define	_SYS_TASK_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/rctl.h>

#define	TASK_NORMAL	0x0	/* task may create tasks via settaskid() */
#define	TASK_FINAL	0x1	/* task finalized, settaskid() will fail */
#define	TASK_MASK	0x1	/* task flags mask */

#define	TASK_PROJ_PURGE	0x100000	/* purge project.* rctl entities */
#define	TASK_PROJ_MASK	0x100000

#ifdef _KERNEL

#include <sys/id_space.h>
#include <sys/exacct_impl.h>
#include <sys/kmem.h>

struct proc;
struct zone;

typedef struct task {
	taskid_t	tk_tkid;	/* task id			*/
	uint_t		tk_flags;	/* task properties		*/
	struct kproject	*tk_proj;	/* project membership		*/
	uint_t		tk_hold_count;	/* number of members/observers	*/
	struct proc	*tk_memb_list;	/* pointer to the first process */
					/* in a doubly linked list of	*/
					/* task members			*/
	kmutex_t	tk_usage_lock;	/* lock to protect tk_*usage	*/
	task_usage_t	*tk_usage;	/* total task resource usage	*/
	task_usage_t	*tk_prevusage;	/* previous interval usage	*/
	task_usage_t	*tk_zoneusage;	/* previous interval usage in zone */
	rctl_set_t	*tk_rctls;	/* task's resource controls	*/
	rctl_qty_t	tk_nlwps;	/* protected by			*/
					/* tk_zone->zone_nlwps_lock	*/
	rctl_qty_t	tk_nlwps_ctl;	/* protected by tk_rctls->rcs_lock */
	rctl_qty_t	tk_cpu_time;	/* accumulated CPU seconds	*/
	struct zone	*tk_zone;	/* zone task belongs to		*/
	task_usage_t	*tk_inherited;	/* task resource usage		*/
					/* inherited with the first	*/
					/* member process		*/
	rctl_qty_t	tk_cpu_ticks;	/* accumulated CPU ticks	*/
	kmutex_t	tk_cpu_time_lock; /* accumulated CPU seconds lock */
	rctl_qty_t	tk_nprocs;	/* protected by			*/
					/* tk_zone->zone_nlwps_lock	*/
	rctl_qty_t	tk_nprocs_ctl;	/* protected by tk_rctls->rcs_lock */
	kstat_t		*tk_nprocs_kstat; /* max-processes rctl kstat   */
	struct task	*tk_commit_next;  /* next task on task commit list */
} task_t;

typedef struct task_kstat {
	kstat_named_t	ktk_zonename;
	kstat_named_t	ktk_usage;
	kstat_named_t	ktk_value;
} task_kstat_t;

extern task_t *task0p;
extern rctl_hndl_t rc_task_lwps;
extern rctl_hndl_t rc_task_nprocs;
extern rctl_hndl_t rc_task_cpu_time;

extern void task_init(void);
extern task_t *task_create(projid_t, struct zone *);
extern void task_begin(task_t *, struct proc *);
extern void task_attach(task_t *, struct proc *);
extern void task_change(task_t *, struct proc *);
extern void task_detach(struct proc *);
extern task_t *task_join(task_t *, uint_t);
extern task_t *task_hold_by_id(taskid_t);
extern task_t *task_hold_by_id_zone(taskid_t, zoneid_t);
extern void task_rele(task_t *);
extern void task_hold(task_t *);
extern void task_end(task_t *);
extern rctl_qty_t task_cpu_time_incr(task_t *, rctl_qty_t);
extern void task_commit_thread_init(void);

#else /* _KERNEL */

struct task;

extern taskid_t settaskid(projid_t, uint_t);
extern taskid_t gettaskid(void);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TASK_H */
