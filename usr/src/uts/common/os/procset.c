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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/var.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/acct.h>
#include <sys/procset.h>
#include <sys/cmn_err.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <sys/procfs.h>
#include <sys/session.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/pool.h>
#include <sys/zone.h>
#include <sys/contract/process_impl.h>

id_t	getmyid(idtype_t);
int	checkprocset(procset_t *);
static	kthread_t *getlwpptr(id_t);
int	procinset(proc_t *, procset_t *);
static	int lwpinset(proc_t *, procset_t *, kthread_t *, int *);

/*
 * The dotoprocs function locates the process(es) specified
 * by the procset structure pointed to by psp.  funcp points to a
 * function which dotoprocs will call for each process in the
 * specified set.  The arguments to this function will be a pointer
 * to the current process from the set and arg.
 * If the called function returns -1, it means that processing of the
 * procset should stop and a normal (non-error) return should be made
 * to the caller of dotoprocs.
 * If the called function returns any other non-zero value the search
 * is terminated and the function's return value is returned to
 * the caller of dotoprocs.  This will normally be an error code.
 * Otherwise, dotoprocs will return zero after processing the entire
 * process set unless no processes were found in which case ESRCH will
 * be returned.
 */
int
dotoprocs(procset_t *psp, int (*funcp)(), char *arg)
{
	proc_t	*prp;	/* A process from the set */
	int	error;
	int	nfound;	/* Nbr of processes found.	*/
	proc_t	*lastprp;	/* Last proc found.	*/

	ASSERT(funcp != NULL);

	/*
	 * Check that the procset_t is valid.
	 */
	error = checkprocset(psp);
	if (error) {
		return (error);
	}
	/*
	 * Check for the special value P_MYID in either operand
	 * and replace it with the correct value.  We don't check
	 * for an error return from getmyid() because the idtypes
	 * have been validated by the checkprocset() call above.
	 */
	mutex_enter(&pidlock);
	if (psp->p_lid == P_MYID) {
		psp->p_lid = getmyid(psp->p_lidtype);
	}
	if (psp->p_rid == P_MYID) {
		psp->p_rid = getmyid(psp->p_ridtype);
	}

	/*
	 * If psp only acts on a single proc, we can reduce pidlock hold time
	 * by avoiding a needless scan of the entire proc list.  Although
	 * there are many procset_t combinations which might boil down to a
	 * single proc, the most common case is an AND operation where one
	 * side is a specific pid, and the other side is P_ALL, so that is
	 * the case for which we will provide a fast path.  Other cases could
	 * be added in a similar fashion if they were to become significant
	 * pidlock bottlenecks.
	 *
	 * Perform the check symmetrically:  either the left or right side may
	 * specify a pid, with the opposite side being 'all'.
	 */
	if (psp->p_op == POP_AND) {
		if (((psp->p_lidtype == P_PID) && (psp->p_ridtype == P_ALL)) ||
		    ((psp->p_ridtype == P_PID) && (psp->p_lidtype == P_ALL))) {
			id_t pid;

			pid = (psp->p_lidtype == P_PID) ?
			    psp->p_lid : psp->p_rid;
			if (((prp = prfind((pid_t)pid)) == NULL) ||
			    (prp->p_stat == SIDL || prp->p_stat == SZOMB ||
			    prp->p_tlist == NULL || prp->p_flag & SSYS)) {
				/*
				 * Specified proc doesn't exist or should
				 * not be operated on.
				 * Don't need to make HASZONEACCESS check
				 * here since prfind() takes care of that.
				 */
				mutex_exit(&pidlock);
				return (ESRCH);
			}
			/*
			 * Operate only on the specified proc.  It's okay
			 * if it's init.
			 */
			error = (*funcp)(prp, arg);
			mutex_exit(&pidlock);
			if (error == -1)
				error = 0;
			return (error);
		}
	}

	nfound = 0;
	error  = 0;

	for (prp = practive; prp != NULL; prp = prp->p_next) {
		/*
		 * If caller is in a non-global zone, skip processes
		 * in other zones.
		 */
		if (!HASZONEACCESS(curproc, prp->p_zone->zone_id))
			continue;

		/*
		 * Ignore this process if it's coming or going,
		 * if it's a system process or if it's not in
		 * the given procset_t.
		 */
		if (prp->p_stat == SIDL || prp->p_stat == SZOMB)
			continue;

		mutex_enter(&prp->p_lock);
		if (prp->p_flag & SSYS || prp->p_tlist == NULL ||
		    procinset(prp, psp) == 0) {
			mutex_exit(&prp->p_lock);
		} else {
			mutex_exit(&prp->p_lock);
			nfound++;
			lastprp = prp;
			if (prp != proc_init) {
				error = (*funcp)(prp, arg);
				if (error == -1) {
					mutex_exit(&pidlock);
					return (0);
				} else if (error) {
					mutex_exit(&pidlock);
					return (error);
				}
			}
		}
	}
	if (nfound == 0) {
		mutex_exit(&pidlock);
		return (ESRCH);
	}
	if (nfound == 1 && lastprp == proc_init)
		error = (*funcp)(lastprp, arg);
	if (error == -1)
		error = 0;
	mutex_exit(&pidlock);
	return (error);
}

/*
 * Check if a procset_t is valid.  Return zero or an errno.
 */
int
checkprocset(procset_t *psp)
{
	switch (psp->p_lidtype) {
	case P_LWPID:
	case P_PID:
	case P_PPID:
	case P_PGID:
	case P_SID:
	case P_TASKID:
	case P_CID:
	case P_UID:
	case P_GID:
	case P_PROJID:
	case P_POOLID:
	case P_ZONEID:
	case P_CTID:
	case P_ALL:
		break;
	default:
		return (EINVAL);
	}

	switch (psp->p_ridtype) {
	case P_LWPID:
	case P_PID:
	case P_PPID:
	case P_PGID:
	case P_SID:
	case P_TASKID:
	case P_CID:
	case P_UID:
	case P_GID:
	case P_PROJID:
	case P_POOLID:
	case P_ZONEID:
	case P_CTID:
	case P_ALL:
		break;
	default:
		return (EINVAL);
	}

	switch (psp->p_op) {
	case POP_DIFF:
	case POP_AND:
	case POP_OR:
	case POP_XOR:
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * procinset returns 1 if the process pointed to by pp is in the process
 * set specified by psp, otherwise 0 is returned. If either process set operand
 * has type P_CID and pp refers to a process that is exiting, by which we mean
 * that its p_tlist is NULL, then procinset will return 0. pp's p_lock must be
 * held across the call to this function. The caller should ensure that the
 * process does not belong to the SYS scheduling class.
 *
 * This function expects to be called with a valid procset_t.
 * The set should be checked using checkprocset() before calling
 * this function.
 */
int
procinset(proc_t *pp, procset_t *psp)
{
	int	loperand = 0;
	int	roperand = 0;
	int	lwplinproc = 0;
	int	lwprinproc = 0;
	kthread_t	*tp;

	ASSERT(MUTEX_HELD(&pp->p_lock));

	switch (psp->p_lidtype) {

	case P_LWPID:
		if (pp == ttoproc(curthread))
			if (getlwpptr(psp->p_lid) != NULL)
				lwplinproc++;
		break;

	case P_PID:
		if (pp->p_pid == psp->p_lid)
			loperand++;
		break;

	case P_PPID:
		if (pp->p_ppid == psp->p_lid)
			loperand++;
		break;

	case P_PGID:
		if (pp->p_pgrp == psp->p_lid)
			loperand++;
		break;

	case P_SID:
		mutex_enter(&pp->p_splock);
		if (pp->p_sessp->s_sid == psp->p_lid)
			loperand++;
		mutex_exit(&pp->p_splock);
		break;

	case P_CID:
		tp = proctot(pp);
		if (tp == NULL)
			return (0);
		if (tp->t_cid == psp->p_lid)
			loperand++;
		break;

	case P_TASKID:
		if (pp->p_task->tk_tkid == psp->p_lid)
			loperand++;
		break;

	case P_UID:
		mutex_enter(&pp->p_crlock);
		if (crgetuid(pp->p_cred) == psp->p_lid)
			loperand++;
		mutex_exit(&pp->p_crlock);
		break;

	case P_GID:
		mutex_enter(&pp->p_crlock);
		if (crgetgid(pp->p_cred) == psp->p_lid)
			loperand++;
		mutex_exit(&pp->p_crlock);
		break;

	case P_PROJID:
		if (pp->p_task->tk_proj->kpj_id == psp->p_lid)
			loperand++;
		break;

	case P_POOLID:
		if (pp->p_pool->pool_id == psp->p_lid)
			loperand++;
		break;

	case P_ZONEID:
		if (pp->p_zone->zone_id == psp->p_lid)
			loperand++;
		break;

	case P_CTID:
		if (PRCTID(pp) == psp->p_lid)
			loperand++;
		break;

	case P_ALL:
		loperand++;
		break;

	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "procinset called with bad set");
		return (0);
#else
		return (0);
#endif
	}

	switch (psp->p_ridtype) {

	case P_LWPID:
		if (pp == ttoproc(curthread))
			if (getlwpptr(psp->p_rid) != NULL)
				lwprinproc++;
		break;

	case P_PID:
		if (pp->p_pid == psp->p_rid)
			roperand++;
		break;

	case P_PPID:
		if (pp->p_ppid == psp->p_rid)
			roperand++;
		break;

	case P_PGID:
		if (pp->p_pgrp == psp->p_rid)
			roperand++;
		break;

	case P_SID:
		mutex_enter(&pp->p_splock);
		if (pp->p_sessp->s_sid == psp->p_rid)
			roperand++;
		mutex_exit(&pp->p_splock);
		break;

	case P_TASKID:
		if (pp->p_task->tk_tkid == psp->p_rid)
			roperand++;
		break;

	case P_CID:
		tp = proctot(pp);
		if (tp == NULL)
			return (0);
		if (tp->t_cid == psp->p_rid)
			roperand++;
		break;

	case P_UID:
		mutex_enter(&pp->p_crlock);
		if (crgetuid(pp->p_cred) == psp->p_rid)
			roperand++;
		mutex_exit(&pp->p_crlock);
		break;

	case P_GID:
		mutex_enter(&pp->p_crlock);
		if (crgetgid(pp->p_cred) == psp->p_rid)
			roperand++;
		mutex_exit(&pp->p_crlock);
		break;

	case P_PROJID:
		if (pp->p_task->tk_proj->kpj_id == psp->p_rid)
			roperand++;
		break;

	case P_POOLID:
		if (pp->p_pool->pool_id == psp->p_rid)
			roperand++;
		break;

	case P_ZONEID:
		if (pp->p_zone->zone_id == psp->p_rid)
			roperand++;
		break;

	case P_CTID:
		if (PRCTID(pp) == psp->p_rid)
			roperand++;
		break;

	case P_ALL:
		roperand++;
		break;

	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "procinset called with bad set");
		return (0);
#else
		return (0);
#endif
	}

	switch (psp->p_op) {

	case POP_DIFF:
		if (loperand && !lwprinproc && !roperand)
			return (1);
		else
			return (0);

	case POP_AND:
		if (loperand && roperand)
			return (1);
		else
			return (0);

	case POP_OR:
		if (loperand || roperand)
			return (1);
		else
			return (0);

	case POP_XOR:
		if ((loperand && !lwprinproc && !roperand) ||
		    (roperand && !lwplinproc && !loperand))
			return (1);
		else
			return (0);

	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "procinset called with bad set");
		return (0);
#else
		return (0);
#endif
	}
	/* NOTREACHED */
}

/*
 * lwpinset returns 1 if the thread pointed to
 * by tp is in the process set specified by psp and is not in
 * the sys scheduling class - otherwise 0 is returned.
 *
 * This function expects to be called with a valid procset_t.
 * The set should be checked using checkprocset() before calling
 * this function.
 */
int
lwpinset(proc_t *pp, procset_t *psp, kthread_t *tp, int *done)
{
	int	loperand = 0;
	int	roperand = 0;
	int	lwplinset  = 0;
	int	lwprinset  = 0;

	ASSERT(ttoproc(tp) == pp);

	/*
	 * If process is in the sys class return (0).
	 */
	if (proctot(pp)->t_cid == 0) {
		return (0);
	}

	switch (psp->p_lidtype) {

	case P_LWPID:
		if (tp->t_tid == psp->p_lid)
			lwplinset ++;
		break;

	case P_PID:
		if (pp->p_pid == psp->p_lid)
			loperand++;
		break;

	case P_PPID:
		if (pp->p_ppid == psp->p_lid)
			loperand++;
		break;

	case P_PGID:
		if (pp->p_pgrp == psp->p_lid)
			loperand++;
		break;

	case P_SID:
		mutex_enter(&pp->p_splock);
		if (pp->p_sessp->s_sid == psp->p_lid)
			loperand++;
		mutex_exit(&pp->p_splock);
		break;

	case P_TASKID:
		if (pp->p_task->tk_tkid == psp->p_lid)
			loperand++;
		break;

	case P_CID:
		if (tp->t_cid == psp->p_lid)
			loperand++;
		break;

	case P_UID:
		mutex_enter(&pp->p_crlock);
		if (crgetuid(pp->p_cred) == psp->p_lid)
			loperand++;
		mutex_exit(&pp->p_crlock);
		break;

	case P_GID:
		mutex_enter(&pp->p_crlock);
		if (crgetgid(pp->p_cred) == psp->p_lid)
			loperand++;
		mutex_exit(&pp->p_crlock);
		break;

	case P_PROJID:
		if (pp->p_task->tk_proj->kpj_id == psp->p_lid)
			loperand++;
		break;

	case P_POOLID:
		if (pp->p_pool->pool_id == psp->p_lid)
			loperand++;
		break;

	case P_ZONEID:
		if (pp->p_zone->zone_id == psp->p_lid)
			loperand++;
		break;

	case P_CTID:
		if (PRCTID(pp) == psp->p_lid)
			loperand++;
		break;

	case P_ALL:
		loperand++;
		break;

	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "lwpinset called with bad set");
		return (0);
#else
		return (0);
#endif
	}

	switch (psp->p_ridtype) {

	case P_LWPID:
		if (tp->t_tid == psp->p_rid)
			lwprinset ++;
		break;

	case P_PID:
		if (pp->p_pid == psp->p_rid)
			roperand++;
		break;

	case P_PPID:
		if (pp->p_ppid == psp->p_rid)
			roperand++;
		break;

	case P_PGID:
		if (pp->p_pgrp == psp->p_rid)
			roperand++;
		break;

	case P_SID:
		mutex_enter(&pp->p_splock);
		if (pp->p_sessp->s_sid == psp->p_rid)
			roperand++;
		mutex_exit(&pp->p_splock);
		break;

	case P_TASKID:
		if (pp->p_task->tk_tkid == psp->p_rid)
			roperand++;
		break;

	case P_CID:
		if (tp->t_cid == psp->p_rid)
			roperand++;
		break;

	case P_UID:
		mutex_enter(&pp->p_crlock);
		if (crgetuid(pp->p_cred) == psp->p_rid)
			roperand++;
		mutex_exit(&pp->p_crlock);
		break;

	case P_GID:
		mutex_enter(&pp->p_crlock);
		if (crgetgid(pp->p_cred) == psp->p_rid)
			roperand++;
		mutex_exit(&pp->p_crlock);
		break;

	case P_PROJID:
		if (pp->p_task->tk_proj->kpj_id == psp->p_rid)
			roperand++;
		break;

	case P_POOLID:
		if (pp->p_pool->pool_id == psp->p_rid)
			roperand++;
		break;

	case P_ZONEID:
		if (pp->p_zone->zone_id == psp->p_rid)
			roperand++;
		break;

	case P_CTID:
		if (PRCTID(pp) == psp->p_rid)
			roperand++;
		break;

	case P_ALL:
		roperand++;
		break;

	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "lwpinset called with bad set");
		return (0);
#else
		return (0);
#endif
	}

	if (lwplinset && lwprinset)
		*done = 1;

	switch (psp->p_op) {

	case POP_DIFF:
		if ((loperand || lwplinset) && !(lwprinset || roperand))
			return (1);
		else
			return (0);

	case POP_AND:
		if ((loperand || lwplinset) && (roperand || lwprinset))
			return (1);
		else
			return (0);

	case POP_OR:
		if (loperand || roperand || lwplinset || lwprinset)
			return (1);
		else
			return (0);

	case POP_XOR:
		if (((loperand || lwplinset) &&
		    !(lwprinset || roperand)) ||
		    ((roperand || lwprinset) &&
		    !(lwplinset || loperand)))
			return (1);
		else
			return (0);

	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "lwpinset called with bad set");
		return (0);
#else
		return (0);
#endif
	}
	/* NOTREACHED */
}
/*
 * Check for common cases of procsets which specify only the
 * current process.  cur_inset_only() returns B_TRUE when
 * the current process is the only one in the set.  B_FALSE
 * is returned to indicate that this may not be the case.
 */
boolean_t
cur_inset_only(procset_t *psp)
{
	if (((psp->p_lidtype == P_PID &&
	    (psp->p_lid == P_MYID ||
	    psp->p_lid == ttoproc(curthread)->p_pid)) ||
	    ((psp->p_lidtype == P_LWPID) &&
	    (psp->p_lid == P_MYID ||
	    psp->p_lid == curthread->t_tid))) &&
	    psp->p_op == POP_AND && psp->p_ridtype == P_ALL)
		return (B_TRUE);

	if (((psp->p_ridtype == P_PID &&
	    (psp->p_rid == P_MYID ||
	    psp->p_rid == ttoproc(curthread)->p_pid)) ||
	    ((psp->p_ridtype == P_LWPID) &&
	    (psp->p_rid == P_MYID ||
	    psp->p_rid == curthread->t_tid))) &&
	    psp->p_op == POP_AND && psp->p_lidtype == P_ALL)
		return (B_TRUE);

	return (B_FALSE);
}

id_t
getmyid(idtype_t idtype)
{
	proc_t	*pp;
	uid_t uid;
	gid_t gid;
	pid_t sid;

	pp = ttoproc(curthread);

	switch (idtype) {
	case P_LWPID:
		return (curthread->t_tid);

	case P_PID:
		return (pp->p_pid);

	case P_PPID:
		return (pp->p_ppid);

	case P_PGID:
		return (pp->p_pgrp);

	case P_SID:
		mutex_enter(&pp->p_splock);
		sid = pp->p_sessp->s_sid;
		mutex_exit(&pp->p_splock);
		return (sid);

	case P_TASKID:
		return (pp->p_task->tk_tkid);

	case P_CID:
		return (curthread->t_cid);

	case P_UID:
		mutex_enter(&pp->p_crlock);
		uid = crgetuid(pp->p_cred);
		mutex_exit(&pp->p_crlock);
		return (uid);

	case P_GID:
		mutex_enter(&pp->p_crlock);
		gid = crgetgid(pp->p_cred);
		mutex_exit(&pp->p_crlock);
		return (gid);

	case P_PROJID:
		return (pp->p_task->tk_proj->kpj_id);

	case P_POOLID:
		return (pp->p_pool->pool_id);

	case P_ZONEID:
		return (pp->p_zone->zone_id);

	case P_CTID:
		return (PRCTID(pp));

	case P_ALL:
		/*
		 * The value doesn't matter for P_ALL.
		 */
		return (0);

	default:
		return (-1);
	}
}

static kthread_t *
getlwpptr(id_t id)
{
	proc_t		*p;
	kthread_t	*t;

	ASSERT(MUTEX_HELD(&(ttoproc(curthread)->p_lock)));

	if (id == P_MYID)
		t = curthread;
	else {
		p = ttoproc(curthread);
		t = idtot(p, id);
	}

	return (t);
}

/*
 * The dotolwp function locates the LWP(s) specified by the procset structure
 * pointed to by psp.  If funcp is non-NULL then it points to a function
 * which dotolwp will call for each LWP in the specified set.
 * LWPIDs specified in the procset structure always refer to lwps in curproc.
 * The arguments for this function must be "char *arg", and "kthread_t *tp",
 * where tp is a pointer to the current thread from the set.
 * Note that these arguments are passed to the function in reversed order
 * than the order of arguments passed by dotoprocs() to its callback function.
 * Also note that there are two separate cases where this routine returns zero.
 * In the first case no mutex is grabbed, in the second the p_lock mutex
 * is NOT RELEASED. The priocntl code is expecting this behaviour.
 */
int
dotolwp(procset_t *psp, int (*funcp)(), char *arg)
{
	int		error = 0;
	int		nfound = 0;
	kthread_t	*tp;
	proc_t		*pp;
	int		done = 0;

	/*
	 * Check that the procset_t is valid.
	 */
	error = checkprocset(psp);
	if (error) {
		return (error);
	}

	mutex_enter(&pidlock);

	/*
	 * Check for the special value P_MYID in either operand
	 * and replace it with the correct value.  We don't check
	 * for an error return from getmyid() because the idtypes
	 * have been validated by the checkprocset() call above.
	 */
	if (psp->p_lid == P_MYID) {
		psp->p_lid = getmyid(psp->p_lidtype);
	}
	if (psp->p_rid == P_MYID) {
		psp->p_rid = getmyid(psp->p_ridtype);
	}

	pp = ttoproc(curthread);

	mutex_enter(&pp->p_lock);
	if (procinset(pp, psp) ||
	    (tp = pp->p_tlist) == NULL) {
		mutex_exit(&pp->p_lock);
		mutex_exit(&pidlock);
		return (0);
	}
	do {
		if (lwpinset(pp, psp, tp, &done)) {
			nfound ++;
			error = (*funcp)(arg, tp);
			if (error) {
				mutex_exit(&pp->p_lock);
				mutex_exit(&pidlock);
				return (error);
			}
		}
	} while (((tp = tp->t_forw) != pp->p_tlist) && !done);

	if (nfound == 0) {
		mutex_exit(&pp->p_lock);
		mutex_exit(&pidlock);
		return (ESRCH);
	}

	mutex_exit(&pidlock);
	return (error);
}
