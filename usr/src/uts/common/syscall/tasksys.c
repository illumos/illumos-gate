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

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * System calls for creating and inquiring about tasks and projects
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/task.h>
#include <sys/systm.h>
#include <sys/project.h>
#include <sys/cpuvar.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/rctl.h>

/*
 * Limit projlist to 256k projects.
 */
#define	MAX_PROJLIST_BUFSIZE		1048576

typedef struct projlist_walk {
	projid_t	*pw_buf;
	size_t		pw_bufsz;
} projlist_walk_t;

/*
 * taskid_t tasksys_settaskid(projid_t projid, uint_t flags);
 *
 * Overview
 *   Place the calling process in a new task if sufficiently privileged.  If the
 *   present task is finalized, the process may not create a new task.
 *
 * Return values
 *   0 on success, errno on failure.
 */
static long
tasksys_settaskid(projid_t projid, uint_t flags)
{
	proc_t *p = ttoproc(curthread);
	kproject_t *oldpj;
	kproject_t *kpj;
	task_t *tk, *oldtk;
	rctl_entity_p_t e;
	zone_t *zone;
	int rctlfail = 0;

	if (secpolicy_tasksys(CRED()) != 0)
		return (set_errno(EPERM));

	if (projid < 0 || projid > MAXPROJID)
		return (set_errno(EINVAL));

	if (flags & ~TASK_FINAL)
		return (set_errno(EINVAL));

	mutex_enter(&pidlock);
	if (p->p_task->tk_flags & TASK_FINAL) {
		mutex_exit(&pidlock);
		return (set_errno(EACCES));
	}
	mutex_exit(&pidlock);

	/*
	 * Try to stop all other lwps in the process while we're changing
	 * our project.  This way, curthread doesn't need to grab its own
	 * thread_lock to find its project ID (see curprojid()).  If this
	 * is the /proc agent lwp, we know that the other lwps are already
	 * held.  If we failed to hold all lwps, bail out and return EINTR.
	 */
	if (curthread != p->p_agenttp && !holdlwps(SHOLDFORK1))
		return (set_errno(EINTR));
	/*
	 * Put a hold on our new project and make sure that nobody is
	 * trying to bind it to a pool while we're joining.
	 */
	kpj = project_hold_by_id(projid, p->p_zone, PROJECT_HOLD_INSERT);
	e.rcep_p.proj = kpj;
	e.rcep_t = RCENTITY_PROJECT;

	mutex_enter(&p->p_lock);
	oldpj = p->p_task->tk_proj;
	zone = p->p_zone;

	mutex_enter(&zone->zone_nlwps_lock);
	mutex_enter(&zone->zone_mem_lock);

	if (kpj->kpj_nlwps + p->p_lwpcnt > kpj->kpj_nlwps_ctl)
		if (rctl_test_entity(rc_project_nlwps, kpj->kpj_rctls, p, &e,
		    p->p_lwpcnt, 0) & RCT_DENY)
			rctlfail = 1;

	if (kpj->kpj_ntasks + 1 > kpj->kpj_ntasks_ctl)
		if (rctl_test_entity(rc_project_ntasks, kpj->kpj_rctls, p, &e,
		    1, 0) & RCT_DENY)
			rctlfail = 1;

	if (kpj != proj0p && kpj->kpj_nprocs + 1 > kpj->kpj_nprocs_ctl)
		if (rctl_test_entity(rc_project_nprocs, kpj->kpj_rctls, p, &e,
		    1, 0) & RCT_DENY)
			rctlfail = 1;

	if (kpj->kpj_data.kpd_locked_mem + p->p_locked_mem >
	    kpj->kpj_data.kpd_locked_mem_ctl)
		if (rctl_test_entity(rc_project_locked_mem, kpj->kpj_rctls, p,
		    &e, p->p_locked_mem, 0) & RCT_DENY)
			rctlfail = 1;

	mutex_enter(&(kpj->kpj_data.kpd_crypto_lock));
	if (kpj->kpj_data.kpd_crypto_mem + p->p_crypto_mem >
	    kpj->kpj_data.kpd_crypto_mem_ctl)
		if (rctl_test_entity(rc_project_crypto_mem, kpj->kpj_rctls, p,
		    &e, p->p_crypto_mem, 0) & RCT_DENY)
			rctlfail = 1;

	if (rctlfail) {
		mutex_exit(&(kpj->kpj_data.kpd_crypto_lock));
		mutex_exit(&zone->zone_mem_lock);
		mutex_exit(&zone->zone_nlwps_lock);
		if (curthread != p->p_agenttp)
			continuelwps(p);
		mutex_exit(&p->p_lock);
		project_rele(kpj);
		return (set_errno(EAGAIN));
	}
	kpj->kpj_data.kpd_crypto_mem += p->p_crypto_mem;
	mutex_exit(&(kpj->kpj_data.kpd_crypto_lock));
	kpj->kpj_data.kpd_locked_mem += p->p_locked_mem;
	kpj->kpj_nlwps += p->p_lwpcnt;
	kpj->kpj_ntasks++;
	kpj->kpj_nprocs++;

	oldpj->kpj_data.kpd_locked_mem -= p->p_locked_mem;
	mutex_enter(&(oldpj->kpj_data.kpd_crypto_lock));
	oldpj->kpj_data.kpd_crypto_mem -= p->p_crypto_mem;
	mutex_exit(&(oldpj->kpj_data.kpd_crypto_lock));
	oldpj->kpj_nlwps -= p->p_lwpcnt;
	oldpj->kpj_nprocs--;

	mutex_exit(&zone->zone_mem_lock);
	mutex_exit(&zone->zone_nlwps_lock);
	mutex_exit(&p->p_lock);

	mutex_enter(&kpj->kpj_poolbind);
	tk = task_create(projid, curproc->p_zone);
	mutex_enter(&cpu_lock);
	/*
	 * Returns with p_lock held.
	 */
	oldtk = task_join(tk, flags);
	if (curthread != p->p_agenttp)
		continuelwps(p);
	mutex_exit(&p->p_lock);
	mutex_exit(&cpu_lock);
	mutex_exit(&kpj->kpj_poolbind);
	task_rele(oldtk);
	project_rele(kpj);
	return (tk->tk_tkid);
}

/*
 * taskid_t tasksys_gettaskid(void);
 *
 * Overview
 *   Return the current task ID for this process.
 *
 * Return value
 *   The ID for the task to which the current process belongs.
 */
static long
tasksys_gettaskid()
{
	long ret;
	proc_t *p = ttoproc(curthread);

	mutex_enter(&pidlock);
	ret = p->p_task->tk_tkid;
	mutex_exit(&pidlock);
	return (ret);
}

/*
 * projid_t tasksys_getprojid(void);
 *
 * Overview
 *   Return the current project ID for this process.
 *
 * Return value
 *   The ID for the project to which the current process belongs.
 */
static long
tasksys_getprojid()
{
	long ret;
	proc_t *p = ttoproc(curthread);

	mutex_enter(&pidlock);
	ret = p->p_task->tk_proj->kpj_id;
	mutex_exit(&pidlock);
	return (ret);
}

static int
tasksys_projlist_cb(kproject_t *kp, void *buf)
{
	projlist_walk_t *pw = (projlist_walk_t *)buf;

	if (pw && pw->pw_bufsz >= sizeof (projid_t)) {
		*pw->pw_buf = kp->kpj_id;
		pw->pw_buf++;
		pw->pw_bufsz -= sizeof (projid_t);
	}

	return (0);
}

/*
 * long tasksys_projlist(void *buf, size_t bufsz)
 *
 * Overview
 *   Return a buffer containing the project IDs of all currently active projects
 *   in the current zone.
 *
 * Return values
 *   The minimum size of a buffer sufficiently large to contain all of the
 *   active project IDs, or -1 if an error occurs during copyout.
 */
static long
tasksys_projlist(void *buf, size_t bufsz)
{
	long ret = 0;
	projlist_walk_t pw;
	void *kbuf;

	if (buf == NULL || bufsz == 0)
		return (project_walk_all(getzoneid(), tasksys_projlist_cb,
		    NULL));

	if (bufsz > MAX_PROJLIST_BUFSIZE)
		return (set_errno(ENOMEM));

	kbuf = pw.pw_buf = kmem_zalloc(bufsz, KM_SLEEP);
	pw.pw_bufsz = bufsz;

	ret = project_walk_all(getzoneid(), tasksys_projlist_cb, &pw);

	if (copyout(kbuf, buf, bufsz) == -1)
		ret = set_errno(EFAULT);

	kmem_free(kbuf, bufsz);
	return (ret);
}

long
tasksys(int code, projid_t projid, uint_t flags, void *projidbuf, size_t pbufsz)
{
	switch (code) {
	case 0:
		return (tasksys_settaskid(projid, flags));
	case 1:
		return (tasksys_gettaskid());
	case 2:
		return (tasksys_getprojid());
	case 3:
		return (tasksys_projlist(projidbuf, pbufsz));
	default:
		return (set_errno(EINVAL));
	}
}
