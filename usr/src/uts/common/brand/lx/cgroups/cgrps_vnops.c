/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/dirent.h>
#include <sys/pathname.h>
#include <vm/seg_vn.h>
#include <sys/cmn_err.h>
#include <sys/buf.h>
#include <sys/vm.h>
#include <sys/prsystm.h>
#include <sys/policy.h>
#include <fs/fs_subr.h>
#include <sys/sdt.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>

#include "cgrps.h"

typedef enum cgrp_wr_type {
	CG_WR_PROCS = 1,
	CG_WR_TASKS
} cgrp_wr_type_t;

/* ARGSUSED1 */
static int
cgrp_open(struct vnode **vpp, int flag, struct cred *cred, caller_context_t *ct)
{
	/*
	 * swapon to a cgrp file is not supported so access is denied on open
	 * if VISSWAP is set.
	 */
	if ((*vpp)->v_flag & VISSWAP)
		return (EINVAL);

	return (0);
}

/* ARGSUSED1 */
static int
cgrp_close(struct vnode *vp, int flag, int count, offset_t offset,
    struct cred *cred, caller_context_t *ct)
{
	cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	return (0);
}

/*
 * Lookup proc or task based on pid and typ.
 */
static proc_t *
cgrp_p_for_wr(pid_t pid, cgrp_wr_type_t typ)
{
	int i;
	zoneid_t zoneid = curproc->p_zone->zone_id;
	pid_t schedpid = curproc->p_zone->zone_zsched->p_pid;

	ASSERT(MUTEX_HELD(&pidlock));

	/* getting a proc from a pid is easy */
	if (typ == CG_WR_PROCS)
		return (prfind(pid));

	ASSERT(typ == CG_WR_TASKS);

	/*
	 * We have to scan all of the process entries to find the proc
	 * containing this task.
	 */
	mutex_exit(&pidlock);
	for (i = 1; i < v.v_proc; i++) {
		proc_t *p;
		kthread_t *t;

		mutex_enter(&pidlock);
		/*
		 * Skip indices for which there is no pid_entry, PIDs for
		 * which there is no corresponding process, system processes,
		 * a PID of 0, the pid for our zsched process, anything the
		 * security policy doesn't allow us to look at, its not an
		 * lx-branded process and processes that are not in the zone.
		 */
		if ((p = pid_entry(i)) == NULL ||
		    p->p_stat == SIDL ||
		    (p->p_flag & SSYS) != 0 ||
		    p->p_pid == 0 ||
		    p->p_pid == schedpid ||
		    secpolicy_basic_procinfo(CRED(), p, curproc) != 0 ||
		    p->p_brand != &lx_brand ||
		    p->p_zone->zone_id != zoneid) {
			mutex_exit(&pidlock);
			continue;
		}

		mutex_enter(&p->p_lock);
		if ((t = p->p_tlist) == NULL) {
			/* no threads, skip it */
			mutex_exit(&p->p_lock);
			mutex_exit(&pidlock);
			continue;
		}

		/*
		 * Check all threads in this proc.
		 */
		do {
			lx_lwp_data_t *plwpd = ttolxlwp(t);
			if (plwpd != NULL && plwpd->br_pid == pid) {
				mutex_exit(&p->p_lock);
				return (p);
			}

			t = t->t_forw;
		} while (t != p->p_tlist);

		mutex_exit(&p->p_lock);
		mutex_exit(&pidlock);
	}

	mutex_enter(&pidlock);
	return (NULL);
}

/*
 * Move a thread from one cgroup to another. If the old cgroup is empty
 * we queue up an agent event. We return true in that case since we've
 * dropped the locks and the caller needs to reacquire them.
 */
static boolean_t
cgrp_thr_move(cgrp_mnt_t *cgm, lx_lwp_data_t *plwpd, cgrp_node_t *ncn,
    uint_t cg_id, proc_t *p)
{
	cgrp_node_t *ocn;

	ASSERT(MUTEX_HELD(&cgm->cg_contents));
	ASSERT(MUTEX_HELD(&p->p_lock));

	ocn = cgrp_cg_hash_lookup(cgm, plwpd->br_cgroupid);
	VERIFY(ocn != NULL);

	ASSERT(ocn->cgn_task_cnt > 0);
	atomic_dec_32(&ocn->cgn_task_cnt);
	atomic_inc_32(&ncn->cgn_task_cnt);
	plwpd->br_cgroupid = cg_id;

	if (ocn->cgn_task_cnt == 0 && ocn->cgn_dirents == N_DIRENTS(cgm) &&
	    ocn->cgn_notify == 1) {
		/*
		 * We want to drop p_lock before queuing the event since
		 * that might sleep. Dropping p_lock might cause the caller to
		 * have to restart the move process from the beginning.
		 */
		mutex_exit(&p->p_lock);
		cgrp_rel_agent_event(cgm, ocn);
		ASSERT(MUTEX_NOT_HELD(&cgm->cg_contents));
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Assign either all of the threads, or a single thread, for the specified pid
 * to the new cgroup. Controlled by the typ argument.
 */
static int
cgrp_proc_set_id(cgrp_mnt_t *cgm, uint_t cg_id, pid_t pid, cgrp_wr_type_t typ)
{
	proc_t *p;
	kthread_t *t;
	int error;
	cgrp_node_t *ncn;

	if (pid == 1)
		pid = curproc->p_zone->zone_proc_initpid;

	/*
	 * Move one or all threads to this cgroup.
	 */
	if (typ == CG_WR_TASKS) {
		error = ESRCH;
	} else {
		error = 0;
	}

restart:
	mutex_enter(&pidlock);

	p = cgrp_p_for_wr(pid, typ);
	if (p == NULL) {
		mutex_exit(&pidlock);
		return (ESRCH);
	}

	/*
	 * Fail writes for pids for which there is no corresponding process,
	 * system processes, a pid of 0, the pid for our zsched process,
	 * anything the security policy doesn't allow us to look at, and
	 * processes that are not in the zone.
	 */
	if (p->p_stat == SIDL ||
	    (p->p_flag & SSYS) != 0 ||
	    p->p_pid == 0 ||
	    p->p_pid == curproc->p_zone->zone_zsched->p_pid ||
	    secpolicy_basic_procinfo(CRED(), p, curproc) != 0 ||
	    p->p_zone->zone_id != curproc->p_zone->zone_id) {
		mutex_exit(&pidlock);
		return (ESRCH);
	}

	/*
	 * Ignore writes for PID which is not an lx-branded process or with
	 * no threads.
	 */

	mutex_enter(&p->p_lock);
	mutex_exit(&pidlock);
	if (p->p_brand != &lx_brand || (t = p->p_tlist) == NULL ||
	    p->p_flag & SEXITING) {
		mutex_exit(&p->p_lock);
		return (0);
	}

	mutex_enter(&cgm->cg_contents);

	ncn = cgrp_cg_hash_lookup(cgm, cg_id);
	VERIFY(ncn != NULL);

	do {
		lx_lwp_data_t *plwpd = ttolxlwp(t);
		if (plwpd != NULL && plwpd->br_cgroupid != cg_id) {
			if (typ == CG_WR_PROCS) {
				if (cgrp_thr_move(cgm, plwpd, ncn, cg_id, p)) {
					/*
					 * We dropped all of the locks so we
					 * need to start over.
					 */
					goto restart;
				}

			} else if (plwpd->br_pid == pid) {
				/* type is CG_WR_TASKS and we found the task */
				error = 0;
				if (cgrp_thr_move(cgm, plwpd, ncn, cg_id, p)) {
					goto done;
				} else {
					break;
				}
			}
		}
		t = t->t_forw;
	} while (t != p->p_tlist);

	mutex_exit(&cgm->cg_contents);
	mutex_exit(&p->p_lock);
done:

	return (error);
}

/*
 * User-level is writing a pid string. We need to get that string and convert
 * it to a pid. The user-level code has to completely write an entire pid
 * string at once. The user-level code could write multiple strings (delimited
 * by newline) although that is frowned upon. However, we must handle this
 * case too. Thus we consume the input one byte at a time until we get a whole
 * pid string. We can't consume more than a byte at a time since otherwise we
 * might be left with a partial pid string.
 */
static int
cgrp_get_pid_str(struct uio *uio, pid_t *pid)
{
	char buf[16];	/* big enough for a pid string */
	int i;
	int error;
	char *p = &buf[0];
	char *ep;
	long pidnum;

	bzero(buf, sizeof (buf));
	for (i = 0; uio->uio_resid > 0 && i < sizeof (buf); i++, p++) {
		error = uiomove(p, 1, UIO_WRITE, uio);
		if (error != 0)
			return (error);
		if (buf[i] == '\n') {
			buf[i] = '\0';
			break;
		}
	}

	if (buf[0] == '\0' || i >= sizeof (buf)) /* no input or too long */
		return (EINVAL);

	error = ddi_strtol(buf, &ep, 10, &pidnum);
	if (error != 0 || *ep != '\0' || pidnum > maxpid || pidnum < 0)
		return (EINVAL);

	*pid = (pid_t)pidnum;
	return (0);
}

static int
cgrp_wr_notify(cgrp_node_t *cn, struct uio *uio)
{
	int error;
	uint_t value;

	/*
	 * This is cheesy but since we only take a 0 or 1 value we can
	 * let the pid_str function do the uio string conversion.
	 */
	error = cgrp_get_pid_str(uio, (pid_t *)&value);
	if (error != 0)
		return (error);

	if (value != 0 && value != 1)
		return (EINVAL);

	/*
	 * The flag is on the containing dir. We don't bother taking the
	 * cg_contents lock since this is a simple assignment.
	 */
	cn->cgn_parent->cgn_notify = value;
	return (0);
}

static int
cgrp_wr_rel_agent(cgrp_mnt_t *cgm, struct uio *uio)
{
	int error;
	int len;
	char *wrp;

	len = uio->uio_offset + uio->uio_resid;
	if (len > MAXPATHLEN)
		return (EFBIG);

	mutex_enter(&cgm->cg_contents);

	wrp = &cgm->cg_agent[uio->uio_offset];
	error = uiomove(wrp, uio->uio_resid, UIO_WRITE, uio);
	cgm->cg_agent[len] = '\0';
	if (len > 1 && cgm->cg_agent[len - 1] == '\n')
		cgm->cg_agent[len - 1] = '\0';

	mutex_exit(&cgm->cg_contents);
	return (error);
}

static int
cgrp_wr_proc_or_task(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio,
    cgrp_wr_type_t typ)
{
	/* the cgroup ID is on the containing dir */
	uint_t cg_id = cn->cgn_parent->cgn_id;
	int error;
	pid_t pidnum;

	while (uio->uio_resid > 0) {
		error = cgrp_get_pid_str(uio, &pidnum);
		if (error != 0)
			return (error);

		error = cgrp_proc_set_id(cgm, cg_id, pidnum, typ);
		if (error != 0)
			return (error);
	}

	return (0);
}

static int
cgrp_wr(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio, struct cred *cr,
    caller_context_t *ct)
{
	struct vnode *vp;
	int error = 0;
	rlim64_t limit = uio->uio_llimit;

	vp = CGNTOV(cn);
	ASSERT(vp->v_type == VREG);

	if (uio->uio_loffset < 0)
		return (EINVAL);

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	if (uio->uio_loffset >= MAXOFF_T)
		return (EFBIG);

	if (uio->uio_resid == 0)
		return (0);

	if (limit > MAXOFF_T)
		limit = MAXOFF_T;

	switch (cn->cgn_type) {
	case CG_NOTIFY:
		error = cgrp_wr_notify(cn, uio);
		break;
	case CG_PROCS:
		error = cgrp_wr_proc_or_task(cgm, cn, uio, CG_WR_PROCS);
		break;
	case CG_REL_AGENT:
		error = cgrp_wr_rel_agent(cgm, uio);
		break;
	case CG_TASKS:
		error = cgrp_wr_proc_or_task(cgm, cn, uio, CG_WR_TASKS);
		break;
	default:
		VERIFY(0);
	}

	return (error);
}

/*
 * pidlock is held on entry but dropped on exit. Because we might have to drop
 * locks and loop if the process is already P_PR_LOCKed, it is possible that
 * the process might be gone when we return from this function.
 */
static proc_t *
cgrp_p_lock(proc_t *p)
{
	kmutex_t *mp;
	pid_t pid;

	ASSERT(MUTEX_HELD(&pidlock));

	/* first try the fast path */
	mutex_enter(&p->p_lock);
	if (p->p_flag & SEXITING) {
		mutex_exit(&p->p_lock);
		mutex_exit(&pidlock);
		return (NULL);
	}

	if (!(p->p_proc_flag & P_PR_LOCK)) {
		p->p_proc_flag |= P_PR_LOCK;
		mutex_exit(&p->p_lock);
		mutex_exit(&pidlock);
		THREAD_KPRI_REQUEST();
		return (p);
	}
	mutex_exit(&p->p_lock);

	pid = p->p_pid;
	for (;;) {
		/*
		 * p_lock is persistent, but p itself is not -- it could
		 * vanish during cv_wait().  Load p->p_lock now so we can
		 * drop it after cv_wait() without referencing p.
		 */
		mp = &p->p_lock;
		mutex_enter(mp);
		mutex_exit(&pidlock);

		if (p->p_flag & SEXITING) {
			mutex_exit(mp);
			return (NULL);
		}

		if (!(p->p_proc_flag & P_PR_LOCK))
			break;

		cv_wait(&pr_pid_cv[p->p_slot], mp);
		mutex_exit(mp);

		mutex_enter(&pidlock);
		p = prfind(pid);
		if (p == NULL || p->p_stat == SIDL) {
			mutex_exit(&pidlock);
			return (NULL);
		}
	}

	p->p_proc_flag |= P_PR_LOCK;
	mutex_exit(mp);
	ASSERT(!MUTEX_HELD(&pidlock));
	THREAD_KPRI_REQUEST();
	return (p);
}

static void
cgrp_p_unlock(proc_t *p)
{
	ASSERT(p->p_proc_flag & P_PR_LOCK);
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(!MUTEX_HELD(&pidlock));

	p->p_proc_flag &= ~P_PR_LOCK;
	cv_signal(&pr_pid_cv[p->p_slot]);
	mutex_exit(&p->p_lock);
	THREAD_KPRI_RELEASE();
}

/*
 * Read value from the notify_on_release pseudo file on the parent node
 * (which is the actual cgroup node). We don't bother taking the cg_contents
 * lock since it's a single instruction so an empty group action/read will
 * only see one value or the other.
 */
/* ARGSUSED */
static int
cgrp_rd_notify(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio)
{
	int len;
	int error = 0;
	char buf[16];
	char *rdp;
	/* the flag is on the containing dir */
	uint_t value = cn->cgn_parent->cgn_notify;

	len = snprintf(buf, sizeof (buf), "%u\n", value);
	if (uio->uio_offset > len)
		return (0);

	len -= uio->uio_offset;
	rdp = &buf[uio->uio_offset];
	len = (uio->uio_resid < len) ? uio->uio_resid : len;

	error = uiomove(rdp, len, UIO_READ, uio);
	return (error);
}

/*
 * Read value from the release_agent pseudo file.
 */
static int
cgrp_rd_rel_agent(cgrp_mnt_t *cgm, struct uio *uio)
{
	int len;
	int error = 0;
	char *rdp;

	mutex_enter(&cgm->cg_contents);

	if (cgm->cg_agent[0] == '\0') {
		mutex_exit(&cgm->cg_contents);
		return (0);
	}

	len = strlen(cgm->cg_agent);
	if (uio->uio_offset > len) {
		mutex_exit(&cgm->cg_contents);
		return (0);
	}

	len -= uio->uio_offset;
	rdp = &cgm->cg_agent[uio->uio_offset];
	len = (uio->uio_resid < len) ? uio->uio_resid : len;

	error = uiomove(rdp, len, UIO_READ, uio);

	mutex_exit(&cgm->cg_contents);

	return (error);
}

/*
 * Read pids from the cgroup.procs pseudo file. We have to look at all of the
 * processes to find applicable ones, then report pids for any process which
 * has all of its threads in the same cgroup.
 */
static int
cgrp_rd_procs(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio)
{
	int i;
	ssize_t offset = 0;
	ssize_t uresid;
	zoneid_t zoneid = curproc->p_zone->zone_id;
	int error = 0;
	pid_t initpid = curproc->p_zone->zone_proc_initpid;
	pid_t schedpid = curproc->p_zone->zone_zsched->p_pid;
	/* the cgroup ID is on the containing dir */
	uint_t cg_id = cn->cgn_parent->cgn_id;

	/* Scan all of the process entries */
	for (i = 1; i < v.v_proc && (uresid = uio->uio_resid) > 0; i++) {
		proc_t *p;
		int len;
		pid_t pid;
		char buf[16];
		char *rdp;
		kthread_t *t;
		boolean_t in_cg;

		mutex_enter(&pidlock);
		/*
		 * Skip indices for which there is no pid_entry, PIDs for
		 * which there is no corresponding process, system processes,
		 * a PID of 0, the pid for our zsched process,  anything the
		 * security policy doesn't allow us to look at, its not an
		 * lx-branded process and processes that are not in the zone.
		 */
		if ((p = pid_entry(i)) == NULL ||
		    p->p_stat == SIDL ||
		    (p->p_flag & SSYS) != 0 ||
		    p->p_pid == 0 ||
		    p->p_pid == schedpid ||
		    secpolicy_basic_procinfo(CRED(), p, curproc) != 0 ||
		    p->p_brand != &lx_brand ||
		    p->p_zone->zone_id != zoneid) {
			mutex_exit(&pidlock);
			continue;
		}

		mutex_enter(&p->p_lock);
		if ((t = p->p_tlist) == NULL) {
			/* no threads, skip it */
			mutex_exit(&p->p_lock);
			mutex_exit(&pidlock);
			continue;
		}

		/*
		 * Check if all threads are in this cgroup.
		 */
		in_cg = B_TRUE;
		mutex_enter(&cgm->cg_contents);
		do {
			lx_lwp_data_t *plwpd = ttolxlwp(t);
			if (plwpd == NULL || plwpd->br_cgroupid != cg_id) {
				in_cg = B_FALSE;
				break;
			}

			t = t->t_forw;
		} while (t != p->p_tlist);
		mutex_exit(&cgm->cg_contents);

		mutex_exit(&p->p_lock);
		if (!in_cg) {
			/*
			 * This proc, or at least one of its threads, is not
			 * in this cgroup.
			 */
			mutex_exit(&pidlock);
			continue;
		}

		/*
		 * Convert pid to the Linux default of 1 if we're the zone's
		 * init process, otherwise use the value from the proc struct
		 */
		if (p->p_pid == initpid) {
			pid = 1;
		} else {
			pid = p->p_pid;
		}

		mutex_exit(&pidlock);

		/*
		 * Generate pid line and write all or part of it if we're
		 * in the right spot within the pseudo file.
		 */
		len = snprintf(buf, sizeof (buf), "%u\n", pid);
		if ((offset + len) > uio->uio_offset) {
			int diff = (int)(uio->uio_offset - offset);

			ASSERT(diff < len);
			offset += diff;
			rdp = &buf[diff];
			len -= diff;
			if (len > uresid)
				len = uresid;

			error = uiomove(rdp, len, UIO_READ, uio);
			if (error != 0)
				return (error);
		}
		offset += len;
	}

	return (0);
}

/*
 * We are given a locked process we know is valid, report on any of its thresds
 * that are in the cgroup.
 */
static int
cgrp_rd_proc_tasks(uint_t cg_id, proc_t *p, pid_t initpid, ssize_t *offset,
    struct uio *uio)
{
	int error = 0;
	uint_t tid;
	char buf[16];
	char *rdp;
	kthread_t *t;

	ASSERT(p->p_proc_flag & P_PR_LOCK);

	/*
	 * Report all threads in this cgroup.
	 */
	t = p->p_tlist;
	do {
		lx_lwp_data_t *plwpd = ttolxlwp(t);
		if (plwpd == NULL) {
			t = t->t_forw;
			continue;
		}

		if (plwpd->br_cgroupid == cg_id) {
			int len;

			/*
			 * Convert taskid to the Linux default of 1 if
			 * we're the zone's init process.
			 */
			tid = plwpd->br_pid;
			if (tid == initpid)
				tid = 1;

			len = snprintf(buf, sizeof (buf), "%u\n", tid);
			if ((*offset + len) > uio->uio_offset) {
				int diff;

				diff = (int)(uio->uio_offset - *offset);
				ASSERT(diff < len);
				*offset = *offset + diff;
				rdp = &buf[diff];
				len -= diff;
				if (len > uio->uio_resid)
					len = uio->uio_resid;

				error = uiomove(rdp, len, UIO_READ, uio);
				if (error != 0)
					return (error);
			}
			*offset = *offset + len;
		}

		t = t->t_forw;
	} while (t != p->p_tlist && uio->uio_resid > 0);

	return (0);
}

/*
 * Read pids from the tasks pseudo file. We have to look at all of the
 * processes to find applicable ones, then report pids for any thread in the
 * cgroup. We return the emulated lx thread pid here, not the internal thread
 * ID. Because we're possibly doing IO for each taskid we lock the process
 * so that the threads don't change while we're working on it (although threads
 * can change if we fill up the read buffer and come back later for a
 * subsequent read).
 */
int
cgrp_rd_tasks(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio)
{
	int i;
	ssize_t offset = 0;
	ssize_t uresid;
	zoneid_t zoneid = curproc->p_zone->zone_id;
	int error = 0;
	pid_t initpid = curproc->p_zone->zone_proc_initpid;
	pid_t schedpid = curproc->p_zone->zone_zsched->p_pid;
	/* the cgroup ID is on the containing dir */
	uint_t cg_id = cn->cgn_parent->cgn_id;

	/* Scan all of the process entries */
	for (i = 1; i < v.v_proc && (uresid = uio->uio_resid) > 0; i++) {
		proc_t *p;

		mutex_enter(&pidlock);
		/*
		 * Skip indices for which there is no pid_entry, PIDs for
		 * which there is no corresponding process, system processes,
		 * a PID of 0, the pid for our zsched process,  anything the
		 * security policy doesn't allow us to look at, its not an
		 * lx-branded process and processes that are not in the zone.
		 */
		if ((p = pid_entry(i)) == NULL ||
		    p->p_stat == SIDL ||
		    (p->p_flag & SSYS) != 0 ||
		    p->p_pid == 0 ||
		    p->p_pid == schedpid ||
		    secpolicy_basic_procinfo(CRED(), p, curproc) != 0 ||
		    p->p_brand != &lx_brand ||
		    p->p_zone->zone_id != zoneid) {
			mutex_exit(&pidlock);
			continue;
		}

		if (p->p_tlist == NULL) {
			/* no threads, skip it */
			mutex_exit(&pidlock);
			continue;
		}

		p = cgrp_p_lock(p);
		ASSERT(!MUTEX_HELD(&pidlock));
		if (p == NULL)
			continue;

		mutex_enter(&cgm->cg_contents);
		error = cgrp_rd_proc_tasks(cg_id, p, initpid, &offset, uio);
		mutex_exit(&cgm->cg_contents);

		mutex_enter(&p->p_lock);
		cgrp_p_unlock(p);

		if (error != 0)
			return (error);
	}

	return (0);
}

static int
cgrp_rd(cgrp_mnt_t *cgm, cgrp_node_t *cn, struct uio *uio, caller_context_t *ct)
{
	int error = 0;

	if (uio->uio_loffset >= MAXOFF_T)
		return (0);
	if (uio->uio_loffset < 0)
		return (EINVAL);
	if (uio->uio_resid == 0)
		return (0);

	switch (cn->cgn_type) {
	case CG_NOTIFY:
		error = cgrp_rd_notify(cgm, cn, uio);
		break;
	case CG_PROCS:
		error = cgrp_rd_procs(cgm, cn, uio);
		break;
	case CG_REL_AGENT:
		error = cgrp_rd_rel_agent(cgm, uio);
		break;
	case CG_TASKS:
		error = cgrp_rd_tasks(cgm, cn, uio);
		break;
	default:
		VERIFY(0);
	}

	return (error);
}

/* ARGSUSED2 */
static int
cgrp_read(struct vnode *vp, struct uio *uiop, int ioflag, cred_t *cred,
    struct caller_context *ct)
{
	cgrp_node_t *cn = VTOCGN(vp);
	cgrp_mnt_t *cgm = VTOCGM(vp);
	int error;

	/*
	 * We don't support reading non-regular files
	 */
	if (vp->v_type == VDIR)
		return (EISDIR);
	if (vp->v_type != VREG)
		return (EINVAL);
	error = cgrp_rd(cgm, cn, uiop, ct);

	return (error);
}

static int
cgrp_write(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *cred,
    struct caller_context *ct)
{
	cgrp_node_t *cn = VTOCGN(vp);
	cgrp_mnt_t *cgm = VTOCGM(vp);
	int error;

	/*
	 * We don't support writing to non-regular files
	 */
	if (vp->v_type != VREG)
		return (EINVAL);

	if (ioflag & FAPPEND) {
		/* In append mode start at end of file. */
		uiop->uio_loffset = cn->cgn_size;
	}

	error = cgrp_wr(cgm, cn, uiop, cred, ct);

	return (error);
}

/* ARGSUSED2 */
static int
cgrp_getattr(struct vnode *vp, struct vattr *vap, int flags, struct cred *cred,
    caller_context_t *ct)
{
	cgrp_node_t *cn = VTOCGN(vp);
	cgrp_mnt_t *cgm;
	struct vattr va;
	int attrs = 1;

	cgm = VTOCGM(cn->cgn_vnode);
	mutex_enter(&cgm->cg_contents);
	if (attrs == 0) {
		cn->cgn_uid = va.va_uid;
		cn->cgn_gid = va.va_gid;
	}
	vap->va_type = vp->v_type;
	vap->va_mode = cn->cgn_mode & MODEMASK;
	vap->va_uid = cn->cgn_uid;
	vap->va_gid = cn->cgn_gid;
	vap->va_fsid = cn->cgn_fsid;
	vap->va_nodeid = (ino64_t)cn->cgn_nodeid;
	vap->va_nlink = cn->cgn_nlink;
	vap->va_size = (u_offset_t)cn->cgn_size;
	vap->va_atime = cn->cgn_atime;
	vap->va_mtime = cn->cgn_mtime;
	vap->va_ctime = cn->cgn_ctime;
	vap->va_blksize = PAGESIZE;
	vap->va_rdev = cn->cgn_rdev;
	vap->va_seq = cn->cgn_seq;

	vap->va_nblocks = (fsblkcnt64_t)btodb(ptob(btopr(vap->va_size)));
	mutex_exit(&cgm->cg_contents);
	return (0);
}

/*ARGSUSED4*/
static int
cgrp_setattr(struct vnode *vp, struct vattr *vap, int flags, struct cred *cred,
    caller_context_t *ct)
{
	cgrp_node_t *cn = VTOCGN(vp);
	cgrp_mnt_t *cgm;
	int error = 0;
	struct vattr *get;
	long mask;

	/*
	 * Cannot set these attributes
	 */
	if ((vap->va_mask & AT_NOSET) || (vap->va_mask & AT_XVATTR) ||
	    (vap->va_mode & (S_ISUID | S_ISGID)) || (vap->va_mask & AT_SIZE))
		return (EINVAL);

	cgm = VTOCGM(cn->cgn_vnode);
	mutex_enter(&cgm->cg_contents);

	get = &cn->cgn_attr;
	/*
	 * Change file access modes. Must be owner or have sufficient
	 * privileges.
	 */
	error = secpolicy_vnode_setattr(cred, vp, vap, get, flags, cgrp_taccess,
	    cn);

	if (error)
		goto out;

	mask = vap->va_mask;

	if (mask & AT_MODE) {
		get->va_mode &= S_IFMT;
		get->va_mode |= vap->va_mode & ~S_IFMT;
	}

	if (mask & AT_UID)
		get->va_uid = vap->va_uid;
	if (mask & AT_GID)
		get->va_gid = vap->va_gid;
	if (mask & AT_ATIME)
		get->va_atime = vap->va_atime;
	if (mask & AT_MTIME)
		get->va_mtime = vap->va_mtime;

	if (mask & (AT_UID | AT_GID | AT_MODE | AT_MTIME))
		gethrestime(&cn->cgn_ctime);

out:
	mutex_exit(&cgm->cg_contents);
	return (error);
}

/* ARGSUSED2 */
static int
cgrp_access(struct vnode *vp, int mode, int flags, struct cred *cred,
    caller_context_t *ct)
{
	cgrp_node_t *cn = VTOCGN(vp);
	cgrp_mnt_t *cgm;
	int error;

	cgm = VTOCGM(cn->cgn_vnode);
	mutex_enter(&cgm->cg_contents);
	error = cgrp_taccess(cn, mode, cred);
	mutex_exit(&cgm->cg_contents);
	return (error);
}

/* ARGSUSED3 */
static int
cgrp_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	cgrp_node_t *cn = VTOCGN(dvp);
	cgrp_mnt_t *cgm;
	cgrp_node_t *ncn = NULL;
	int error;

	/* disallow extended attrs */
	if (flags & LOOKUP_XATTR)
		return (EINVAL);

	/*
	 * Null component name is a synonym for directory being searched.
	 */
	if (*nm == '\0') {
		VN_HOLD(dvp);
		*vpp = dvp;
		return (0);
	}
	ASSERT(cn);

	cgm = VTOCGM(cn->cgn_vnode);
	mutex_enter(&cgm->cg_contents);
	error = cgrp_dirlookup(cn, nm, &ncn, cred);
	mutex_exit(&cgm->cg_contents);

	if (error == 0) {
		ASSERT(ncn);
		*vpp = CGNTOV(ncn);
	}

	return (error);
}

/*ARGSUSED7*/
static int
cgrp_create(struct vnode *dvp, char *nm, struct vattr *vap,
    enum vcexcl exclusive, int mode, struct vnode **vpp, struct cred *cred,
    int flag, caller_context_t *ct, vsecattr_t *vsecp)
{
	cgrp_node_t *parent = VTOCGN(dvp);
	cgrp_node_t *cn = NULL;
	cgrp_mnt_t *cgm;
	int error;

	if (*nm == '\0')
		return (EPERM);

	cgm = VTOCGM(parent->cgn_vnode);
	mutex_enter(&cgm->cg_contents);
	error = cgrp_dirlookup(parent, nm, &cn, cred);
	if (error == 0) {		/* name found */
		ASSERT(cn);

		mutex_exit(&cgm->cg_contents);
		/*
		 * Creating an existing file, allow it except for the following
		 * errors.
		 */
		if (exclusive == EXCL) {
			error = EEXIST;
		} else if ((CGNTOV(cn)->v_type == VDIR) && (mode & VWRITE)) {
			error = EISDIR;
		} else {
			error = cgrp_taccess(cn, mode, cred);
		}
		if (error != 0) {
			cgnode_rele(cn);
			return (error);
		}
		*vpp = CGNTOV(cn);
		return (0);
	}
	mutex_exit(&cgm->cg_contents);

	/*
	 * cgroups doesn't allow creation of additional, non-subsystem specific
	 * files in a dir
	 */
	return (EPERM);
}

/* ARGSUSED3 */
static int
cgrp_remove(struct vnode *dvp, char *nm, struct cred *cred,
    caller_context_t *ct, int flags)
{
	cgrp_node_t *parent = VTOCGN(dvp);
	int error;
	cgrp_node_t *cn = NULL;
	cgrp_mnt_t *cgm;

	/*
	 * Removal of subsystem-specific files is not allowed but we need
	 * to return the correct error if they try to remove a non-existent
	 * file.
	 */

	cgm = VTOCGM(parent->cgn_vnode);
	mutex_enter(&cgm->cg_contents);
	error = cgrp_dirlookup(parent, nm, &cn, cred);
	mutex_exit(&cgm->cg_contents);
	if (error)
		return (error);

	ASSERT(cn);
	cgnode_rele(cn);
	return (EPERM);
}

/* ARGSUSED4 */
static int
cgrp_link(struct vnode *dvp, struct vnode *srcvp, char *cnm, struct cred *cred,
    caller_context_t *ct, int flags)
{
	/* cgroups doesn't support hard links */
	return (EPERM);
}

/*
 * Rename of subsystem-specific files is not allowed but we can rename
 * directories (i.e. sub-groups). We cannot mv subdirs from one group to
 * another so the src and dest vnode must be the same.
 */
/* ARGSUSED5 */
static int
cgrp_rename(
	struct vnode *odvp,	/* source parent vnode */
	char *onm,		/* source name */
	struct vnode *ndvp,	/* destination parent vnode */
	char *nnm,		/* destination name */
	struct cred *cred,
	caller_context_t *ct,
	int flags)
{
	cgrp_node_t *fromparent;
	cgrp_node_t *toparent;
	cgrp_node_t *fromcn = NULL;	/* source cgrp_node */
	cgrp_mnt_t *cgm = VTOCGM(odvp);
	int error, err;

	fromparent = VTOCGN(odvp);
	toparent = VTOCGN(ndvp);

	if (fromparent != toparent)
		return (EIO);

	/* discourage additional use of toparent */
	toparent = NULL;

	mutex_enter(&cgm->cg_contents);

	/*
	 * Look up cgrp_node of file we're supposed to rename.
	 */
	error = cgrp_dirlookup(fromparent, onm, &fromcn, cred);
	if (error) {
		mutex_exit(&cgm->cg_contents);
		return (error);
	}

	if (fromcn->cgn_type != CG_CGROUP_DIR) {
		error = EPERM;
		goto done;
	}

	/*
	 * Make sure we can delete the old (source) entry.  This
	 * requires write permission on the containing directory.
	 */
	if (((error = cgrp_taccess(fromparent, VWRITE, cred)) != 0))
		goto done;

	/*
	 * Check for renaming to or from '.' or '..' or that
	 * fromcn == fromparent
	 */
	if ((onm[0] == '.' &&
	    (onm[1] == '\0' || (onm[1] == '.' && onm[2] == '\0'))) ||
	    (nnm[0] == '.' &&
	    (nnm[1] == '\0' || (nnm[1] == '.' && nnm[2] == '\0'))) ||
	    (fromparent == fromcn)) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Link source to new target
	 */
	error = cgrp_direnter(cgm, fromparent, nnm, DE_RENAME,
	    fromcn, (struct vattr *)NULL,
	    (cgrp_node_t **)NULL, cred, ct);

	if (error)
		goto done;

	/*
	 * Unlink from source.
	 */
	error = err = cgrp_dirdelete(fromparent, fromcn, onm, DR_RENAME, cred);

	/*
	 * The following handles the case where our source cgrp_node was
	 * removed before we got to it.
	 */
	if (error == ENOENT)
		error = 0;

	if (err == 0) {
		vnevent_rename_src(CGNTOV(fromcn), odvp, onm, ct);
		vnevent_rename_dest_dir(ndvp, CGNTOV(fromcn), nnm, ct);
	}

done:
	mutex_exit(&cgm->cg_contents);
	cgnode_rele(fromcn);

	return (error);
}

/* ARGSUSED5 */
static int
cgrp_mkdir(struct vnode *dvp, char *nm, struct vattr *va, struct vnode **vpp,
    struct cred *cred, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	cgrp_node_t *parent = VTOCGN(dvp);
	cgrp_node_t *self = NULL;
	cgrp_mnt_t *cgm = VTOCGM(dvp);
	int error;

	/*
	 * Might be dangling directory.  Catch it here, because a ENOENT
	 * return from cgrp_dirlookup() is an "ok return".
	 */
	if (parent->cgn_nlink == 0)
		return (ENOENT);

	mutex_enter(&cgm->cg_contents);
	error = cgrp_dirlookup(parent, nm, &self, cred);
	if (error == 0) {
		ASSERT(self != NULL);
		mutex_exit(&cgm->cg_contents);
		cgnode_rele(self);
		return (EEXIST);
	}
	if (error != ENOENT) {
		mutex_exit(&cgm->cg_contents);
		return (error);
	}

	error = cgrp_direnter(cgm, parent, nm, DE_MKDIR, (cgrp_node_t *)NULL,
	    va, &self, cred, ct);
	if (error) {
		mutex_exit(&cgm->cg_contents);
		if (self != NULL)
			cgnode_rele(self);
		return (error);
	}
	mutex_exit(&cgm->cg_contents);
	*vpp = CGNTOV(self);
	return (0);
}

/* ARGSUSED4 */
static int
cgrp_rmdir(struct vnode *dvp, char *nm, struct vnode *cdir, struct cred *cred,
    caller_context_t *ct, int flags)
{
	cgrp_node_t *parent = VTOCGN(dvp);
	cgrp_mnt_t *cgm;
	cgrp_node_t *self = NULL;
	struct vnode *vp;
	int error = 0;

	/*
	 * Return error when removing . and ..
	 */
	if (strcmp(nm, ".") == 0)
		return (EINVAL);
	if (strcmp(nm, "..") == 0)
		return (EEXIST); /* Should be ENOTEMPTY */

	cgm = VTOCGM(parent->cgn_vnode);
	mutex_enter(&cgm->cg_contents);

	error = cgrp_dirlookup(parent, nm, &self, cred);
	if (error) {
		mutex_exit(&cgm->cg_contents);
		return (error);
	}

	vp = CGNTOV(self);
	if (vp == dvp || vp == cdir) {
		error = EINVAL;
		goto done;
	}
	if (self->cgn_type != CG_CGROUP_DIR) {
		error = ENOTDIR;
		goto done;
	}

	cgm = (cgrp_mnt_t *)VFSTOCGM(self->cgn_vnode->v_vfsp);

	/*
	 * Check for the existence of any sub-cgroup directories or tasks in
	 * the cgroup.
	 */
	if (self->cgn_task_cnt > 0 || self->cgn_dirents > N_DIRENTS(cgm)) {
		error = EEXIST;
		/*
		 * Update atime because checking cn_dirents is logically
		 * equivalent to reading the directory
		 */
		gethrestime(&self->cgn_atime);
		goto done;
	}

	if (vn_vfswlock(vp)) {
		error = EBUSY;
		goto done;
	}
	if (vn_mountedvfs(vp) != NULL) {
		error = EBUSY;
	} else {
		error = cgrp_dirdelete(parent, self, nm, DR_RMDIR, cred);
	}

	vn_vfsunlock(vp);

	if (parent->cgn_task_cnt == 0 &&
	    parent->cgn_dirents == N_DIRENTS(cgm) && parent->cgn_notify == 1) {
		cgrp_rel_agent_event(cgm, parent);
		ASSERT(MUTEX_NOT_HELD(&cgm->cg_contents));
		goto dropped;
	}

done:
	mutex_exit(&cgm->cg_contents);
dropped:
	vnevent_rmdir(CGNTOV(self), dvp, nm, ct);
	cgnode_rele(self);

	return (error);
}

/* ARGSUSED2 */
static int
cgrp_readdir(struct vnode *vp, struct uio *uiop, struct cred *cred, int *eofp,
    caller_context_t *ct, int flags)
{
	cgrp_node_t *cn = VTOCGN(vp);
	cgrp_mnt_t *cgm;
	cgrp_dirent_t *cdp;
	int error = 0;
	size_t namelen;
	struct dirent64 *dp;
	ulong_t offset;
	ulong_t total_bytes_wanted;
	long outcount = 0;
	long bufsize;
	int reclen;
	caddr_t outbuf;

	if (uiop->uio_loffset >= MAXOFF_T) {
		if (eofp)
			*eofp = 1;
		return (0);
	}

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (vp->v_type != VDIR)
		return (ENOTDIR);

	cgm = VTOCGM(cn->cgn_vnode);
	mutex_enter(&cgm->cg_contents);

	if (cn->cgn_dir == NULL) {
		VERIFY(cn->cgn_nlink == 0);
		mutex_exit(&cgm->cg_contents);
		return (0);
	}

	/*
	 * Get space for multiple directory entries
	 */
	total_bytes_wanted = uiop->uio_iov->iov_len;
	bufsize = total_bytes_wanted + sizeof (struct dirent64);
	outbuf = kmem_alloc(bufsize, KM_SLEEP);

	dp = (struct dirent64 *)outbuf;

	offset = 0;
	cdp = cn->cgn_dir;
	while (cdp) {
		namelen = strlen(cdp->cgd_name);	/* no +1 needed */
		offset = cdp->cgd_offset;
		if (offset >= uiop->uio_offset) {
			reclen = (int)DIRENT64_RECLEN(namelen);
			if (outcount + reclen > total_bytes_wanted) {
				if (!outcount) {
					/* Buffer too small for any entries. */
					error = EINVAL;
				}
				break;
			}
			ASSERT(cdp->cgd_cgrp_node != NULL);

			/* use strncpy(9f) to zero out uninitialized bytes */

			(void) strncpy(dp->d_name, cdp->cgd_name,
			    DIRENT64_NAMELEN(reclen));
			dp->d_reclen = (ushort_t)reclen;
			dp->d_ino = (ino64_t)cdp->cgd_cgrp_node->cgn_nodeid;
			dp->d_off = (offset_t)cdp->cgd_offset + 1;
			dp = (struct dirent64 *)((uintptr_t)dp + dp->d_reclen);
			outcount += reclen;
			ASSERT(outcount <= bufsize);
		}
		cdp = cdp->cgd_next;
	}

	if (!error)
		error = uiomove(outbuf, outcount, UIO_READ, uiop);

	if (!error) {
		/*
		 * If we reached the end of the list our offset should now be
		 * just past the end.
		 */
		if (!cdp) {
			offset += 1;
			if (eofp)
				*eofp = 1;
		} else if (eofp)
			*eofp = 0;
		uiop->uio_offset = offset;
	}
	gethrestime(&cn->cgn_atime);

	mutex_exit(&cgm->cg_contents);

	kmem_free(outbuf, bufsize);
	return (error);
}

/* ARGSUSED5 */
static int
cgrp_symlink(struct vnode *dvp, char *lnm, struct vattr *cva, char *cnm,
    struct cred *cred, caller_context_t *ct, int flags)
{
	/* cgroups doesn't support symlinks */
	return (EPERM);
}

/* ARGSUSED */
static void
cgrp_inactive(struct vnode *vp, struct cred *cred, caller_context_t *ct)
{
	cgrp_node_t *cn = VTOCGN(vp);
	cgrp_mnt_t *cgm = VFSTOCGM(vp->v_vfsp);

	mutex_enter(&cgm->cg_contents);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);

	/*
	 * If we don't have the last hold or the link count is non-zero,
	 * there's little to do -- just drop our hold.
	 */
	if (vp->v_count > 1 || cn->cgn_nlink != 0) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		mutex_exit(&cgm->cg_contents);
		return;
	}

	if (cn->cgn_forw == NULL)
		cgm->cg_rootnode->cgn_back = cn->cgn_back;
	else
		cn->cgn_forw->cgn_back = cn->cgn_back;
	cn->cgn_back->cgn_forw = cn->cgn_forw;

	mutex_exit(&vp->v_lock);
	mutex_exit(&cgm->cg_contents);

	/* Here's our chance to send invalid event */
	vn_invalid(CGNTOV(cn));

	vn_free(CGNTOV(cn));
	kmem_free(cn, sizeof (cgrp_node_t));
}

/* ARGSUSED */
static int
cgrp_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/* ARGSUSED */
static int
cgrp_rwlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
	return (write_lock);
}

/* ARGSUSED */
static void
cgrp_rwunlock(struct vnode *vp, int write_lock, caller_context_t *ctp)
{
}

static int
cgrp_pathconf(struct vnode *vp, int cmd, ulong_t *valp, cred_t *cr,
    caller_context_t *ct)
{
	int error;

	switch (cmd) {
	case _PC_XATTR_EXISTS:
		if (vp->v_vfsp->vfs_flag & VFS_XATTR) {
			*valp = 0;	/* assume no attributes */
			error = 0;	/* okay to ask */
		} else {
			error = EINVAL;
		}
		break;
	case _PC_SATTR_ENABLED:
	case _PC_SATTR_EXISTS:
		*valp = vfs_has_feature(vp->v_vfsp, VFSFT_SYSATTR_VIEWS) &&
		    (vp->v_type == VREG || vp->v_type == VDIR);
		error = 0;
		break;
	case _PC_TIMESTAMP_RESOLUTION:
		/* nanosecond timestamp resolution */
		*valp = 1L;
		error = 0;
		break;
	default:
		error = fs_pathconf(vp, cmd, valp, cr, ct);
	}
	return (error);
}


struct vnodeops *cgrp_vnodeops;

const fs_operation_def_t cgrp_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = cgrp_open },
	VOPNAME_CLOSE,		{ .vop_close = cgrp_close },
	VOPNAME_READ,		{ .vop_read = cgrp_read },
	VOPNAME_WRITE,		{ .vop_write = cgrp_write },
	VOPNAME_GETATTR,	{ .vop_getattr = cgrp_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = cgrp_setattr },
	VOPNAME_ACCESS,		{ .vop_access = cgrp_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = cgrp_lookup },
	VOPNAME_CREATE,		{ .vop_create = cgrp_create },
	VOPNAME_REMOVE,		{ .vop_remove = cgrp_remove },
	VOPNAME_LINK,		{ .vop_link = cgrp_link },
	VOPNAME_RENAME,		{ .vop_rename = cgrp_rename },
	VOPNAME_MKDIR,		{ .vop_mkdir = cgrp_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = cgrp_rmdir },
	VOPNAME_READDIR,	{ .vop_readdir = cgrp_readdir },
	VOPNAME_SYMLINK,	{ .vop_symlink = cgrp_symlink },
	VOPNAME_INACTIVE,	{ .vop_inactive = cgrp_inactive },
	VOPNAME_RWLOCK,		{ .vop_rwlock = cgrp_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = cgrp_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = cgrp_seek },
	VOPNAME_PATHCONF,	{ .vop_pathconf = cgrp_pathconf },
	VOPNAME_VNEVENT,	{ .vop_vnevent = fs_vnevent_support },
	NULL,			NULL
};
