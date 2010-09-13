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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/cpupart.h>
#include <sys/pset.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/task.h>
#include <sys/loadavg.h>
#include <sys/fss.h>
#include <sys/pool.h>
#include <sys/pool_pset.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/contract/process_impl.h>

static int	pset(int, long, long, long, long);

static struct sysent pset_sysent = {
	5,
	SE_ARGC | SE_NOUNLOAD,
	(int (*)())pset,
};

static struct modlsys modlsys = {
	&mod_syscallops, "processor sets", &pset_sysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32, "32-bit pset(2) syscall", &pset_sysent
};
#endif

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};

#define	PSET_BADATTR(attr)	((~PSET_NOESCAPE) & (attr))

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
pset_create(psetid_t *psetp)
{
	psetid_t newpset;
	int error;

	if (secpolicy_pset(CRED()) != 0)
		return (set_errno(EPERM));

	pool_lock();
	if (pool_state == POOL_ENABLED) {
		pool_unlock();
		return (set_errno(ENOTSUP));
	}
	error = cpupart_create(&newpset);
	if (error) {
		pool_unlock();
		return (set_errno(error));
	}
	if (copyout(&newpset, psetp, sizeof (psetid_t)) != 0) {
		(void) cpupart_destroy(newpset);
		pool_unlock();
		return (set_errno(EFAULT));
	}
	pool_unlock();
	return (error);
}

static int
pset_destroy(psetid_t pset)
{
	int error;

	if (secpolicy_pset(CRED()) != 0)
		return (set_errno(EPERM));

	pool_lock();
	if (pool_state == POOL_ENABLED) {
		pool_unlock();
		return (set_errno(ENOTSUP));
	}
	error = cpupart_destroy(pset);
	pool_unlock();
	if (error)
		return (set_errno(error));
	else
		return (0);
}

static int
pset_assign(psetid_t pset, processorid_t cpuid, psetid_t *opset, int forced)
{
	psetid_t oldpset;
	int	error = 0;
	cpu_t	*cp;

	if (pset != PS_QUERY && secpolicy_pset(CRED()) != 0)
		return (set_errno(EPERM));

	pool_lock();
	if (pset != PS_QUERY && pool_state == POOL_ENABLED) {
		pool_unlock();
		return (set_errno(ENOTSUP));
	}

	mutex_enter(&cpu_lock);
	if ((cp = cpu_get(cpuid)) == NULL) {
		mutex_exit(&cpu_lock);
		pool_unlock();
		return (set_errno(EINVAL));
	}

	oldpset = cpupart_query_cpu(cp);

	if (pset != PS_QUERY)
		error = cpupart_attach_cpu(pset, cp, forced);
	mutex_exit(&cpu_lock);
	pool_unlock();

	if (error)
		return (set_errno(error));

	if (opset != NULL)
		if (copyout(&oldpset, opset, sizeof (psetid_t)) != 0)
			return (set_errno(EFAULT));

	return (0);
}

static int
pset_info(psetid_t pset, int *typep, uint_t *numcpusp,
    processorid_t *cpulistp)
{
	int pset_type;
	uint_t user_ncpus = 0, real_ncpus, copy_ncpus;
	processorid_t *pset_cpus = NULL;
	int error = 0;

	if (numcpusp != NULL) {
		if (copyin(numcpusp, &user_ncpus, sizeof (uint_t)) != 0)
			return (set_errno(EFAULT));
	}

	if (user_ncpus > max_ncpus)	/* sanity check */
		user_ncpus = max_ncpus;
	if (user_ncpus != 0 && cpulistp != NULL)
		pset_cpus = kmem_alloc(sizeof (processorid_t) * user_ncpus,
		    KM_SLEEP);

	real_ncpus = user_ncpus;
	if ((error = cpupart_get_cpus(&pset, pset_cpus, &real_ncpus)) != 0)
		goto out;

	/*
	 * Now copyout the information about this processor set.
	 */

	/*
	 * Get number of cpus to copy back.  If the user didn't pass in
	 * a big enough buffer, only copy back as many cpus as fits in
	 * the buffer but copy back the real number of cpus.
	 */

	if (user_ncpus != 0 && cpulistp != NULL) {
		copy_ncpus = MIN(real_ncpus, user_ncpus);
		if (copyout(pset_cpus, cpulistp,
		    sizeof (processorid_t) * copy_ncpus) != 0) {
			error = EFAULT;
			goto out;
		}
	}
	if (pset_cpus != NULL)
		kmem_free(pset_cpus, sizeof (processorid_t) * user_ncpus);
	if (typep != NULL) {
		if (pset == PS_NONE)
			pset_type = PS_NONE;
		else
			pset_type = PS_PRIVATE;
		if (copyout(&pset_type, typep, sizeof (int)) != 0)
			return (set_errno(EFAULT));
	}
	if (numcpusp != NULL)
		if (copyout(&real_ncpus, numcpusp, sizeof (uint_t)) != 0)
			return (set_errno(EFAULT));
	return (0);

out:
	if (pset_cpus != NULL)
		kmem_free(pset_cpus, sizeof (processorid_t) * user_ncpus);
	return (set_errno(error));
}

static int
pset_bind_thread(kthread_t *tp, psetid_t pset, psetid_t *oldpset, void *projbuf,
    void *zonebuf)
{
	int error = 0;

	ASSERT(pool_lock_held());
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&ttoproc(tp)->p_lock));

	*oldpset = tp->t_bind_pset;

	switch (pset) {
	case PS_SOFT:
		TB_PSET_SOFT_SET(tp);
		break;

	case PS_HARD:
		TB_PSET_HARD_SET(tp);
		break;

	case PS_QUERY:
		break;

	case PS_QUERY_TYPE:
		*oldpset = TB_PSET_IS_SOFT(tp) ? PS_SOFT : PS_HARD;
		break;

	default:
		/*
		 * Must have the same UID as the target process or
		 * have PRIV_PROC_OWNER privilege.
		 */
		if (!hasprocperm(tp->t_cred, CRED()))
			return (EPERM);
		/*
		 * Unbinding of an unbound thread should always succeed.
		 */
		if (*oldpset == PS_NONE && pset == PS_NONE)
			return (0);
		/*
		 * Only privileged processes can move threads from psets with
		 * PSET_NOESCAPE attribute.
		 */
		if ((tp->t_cpupart->cp_attr & PSET_NOESCAPE) &&
		    secpolicy_pbind(CRED()) != 0)
			return (EPERM);
		if ((error = cpupart_bind_thread(tp, pset, 0,
		    projbuf, zonebuf)) == 0)
			tp->t_bind_pset = pset;

		break;
	}

	return (error);
}

static int
pset_bind_process(proc_t *pp, psetid_t pset, psetid_t *oldpset, void *projbuf,
    void *zonebuf)
{
	int error = 0;
	kthread_t *tp;

	/* skip kernel processes */
	if ((pset != PS_QUERY) && pp->p_flag & SSYS) {
		*oldpset = PS_NONE;
		return (ENOTSUP);
	}

	mutex_enter(&pp->p_lock);
	tp = pp->p_tlist;
	if (tp != NULL) {
		do {
			int rval;

			rval = pset_bind_thread(tp, pset, oldpset, projbuf,
			    zonebuf);
			if (error == 0)
				error = rval;
		} while ((tp = tp->t_forw) != pp->p_tlist);
	} else
		error = ESRCH;
	mutex_exit(&pp->p_lock);

	return (error);
}

static int
pset_bind_task(task_t *tk, psetid_t pset, psetid_t *oldpset, void *projbuf,
    void *zonebuf)
{
	int error = 0;
	proc_t *pp;

	ASSERT(MUTEX_HELD(&pidlock));

	if ((pp = tk->tk_memb_list) == NULL) {
		return (ESRCH);
	}

	do {
		int rval;

		if (!(pp->p_flag & SSYS)) {
			rval = pset_bind_process(pp, pset, oldpset, projbuf,
			    zonebuf);
			if (error == 0)
				error = rval;
		}
	} while ((pp = pp->p_tasknext) != tk->tk_memb_list);

	return (error);
}

static int
pset_bind_project(kproject_t *kpj, psetid_t pset, psetid_t *oldpset,
    void *projbuf, void *zonebuf)
{
	int error = 0;
	proc_t *pp;

	ASSERT(MUTEX_HELD(&pidlock));

	for (pp = practive; pp != NULL; pp = pp->p_next) {
		if (pp->p_tlist == NULL)
			continue;
		if (pp->p_task->tk_proj == kpj && !(pp->p_flag & SSYS)) {
			int rval;

			rval = pset_bind_process(pp, pset, oldpset, projbuf,
			    zonebuf);
			if (error == 0)
				error = rval;
		}
	}

	return (error);
}

static int
pset_bind_zone(zone_t *zptr, psetid_t pset, psetid_t *oldpset, void *projbuf,
    void *zonebuf)
{
	int error = 0;
	proc_t *pp;

	ASSERT(MUTEX_HELD(&pidlock));

	for (pp = practive; pp != NULL; pp = pp->p_next) {
		if (pp->p_zone == zptr && !(pp->p_flag & SSYS)) {
			int rval;

			rval = pset_bind_process(pp, pset, oldpset, projbuf,
			    zonebuf);
			if (error == 0)
				error = rval;
		}
	}

	return (error);
}

/*
 * Unbind all threads from the specified processor set, or from all
 * processor sets.
 */
static int
pset_unbind(psetid_t pset, void *projbuf, void *zonebuf, idtype_t idtype)
{
	psetid_t olbind;
	kthread_t *tp;
	int error = 0;
	int rval;
	proc_t *pp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (idtype == P_PSETID && cpupart_find(pset) == NULL)
		return (EINVAL);

	mutex_enter(&pidlock);
	for (pp = practive; pp != NULL; pp = pp->p_next) {
		mutex_enter(&pp->p_lock);
		tp = pp->p_tlist;
		/*
		 * Skip zombies and kernel processes, and processes in
		 * other zones, if called from a non-global zone.
		 */
		if (tp == NULL || (pp->p_flag & SSYS) ||
		    !HASZONEACCESS(curproc, pp->p_zone->zone_id)) {
			mutex_exit(&pp->p_lock);
			continue;
		}
		do {
			if ((idtype == P_PSETID && tp->t_bind_pset != pset) ||
			    (idtype == P_ALL && tp->t_bind_pset == PS_NONE))
				continue;
			rval = pset_bind_thread(tp, PS_NONE, &olbind,
			    projbuf, zonebuf);
			if (error == 0)
				error = rval;
		} while ((tp = tp->t_forw) != pp->p_tlist);
		mutex_exit(&pp->p_lock);
	}
	mutex_exit(&pidlock);
	return (error);
}

static int
pset_bind_contract(cont_process_t *ctp, psetid_t pset, psetid_t *oldpset,
    void *projbuf, void *zonebuf)
{
	int error = 0;
	proc_t *pp;

	ASSERT(MUTEX_HELD(&pidlock));

	for (pp = practive; pp != NULL; pp = pp->p_next) {
		if (pp->p_ct_process == ctp) {
			int rval;

			rval = pset_bind_process(pp, pset, oldpset, projbuf,
			    zonebuf);
			if (error == 0)
				error = rval;
		}
	}

	return (error);
}

/*
 * Bind the lwp:id of process:pid to processor set: pset
 */
static int
pset_bind_lwp(psetid_t pset, id_t id, pid_t pid, psetid_t *opset)
{
	kthread_t	*tp;
	proc_t		*pp;
	psetid_t	oldpset;
	void		*projbuf, *zonebuf;
	int		error = 0;

	pool_lock();
	mutex_enter(&cpu_lock);
	projbuf = fss_allocbuf(FSS_NPROJ_BUF, FSS_ALLOC_PROJ);
	zonebuf = fss_allocbuf(FSS_NPROJ_BUF, FSS_ALLOC_ZONE);

	mutex_enter(&pidlock);
	if ((pid == P_MYID && id == P_MYID) ||
	    (pid == curproc->p_pid && id == P_MYID)) {
		pp = curproc;
		tp = curthread;
		mutex_enter(&pp->p_lock);
	} else {
		if (pid == P_MYID) {
			pp = curproc;
		} else if ((pp = prfind(pid)) == NULL) {
			error = ESRCH;
			goto err;
		}
		if (pp != curproc && id == P_MYID) {
			error = EINVAL;
			goto err;
		}
		mutex_enter(&pp->p_lock);
		if ((tp = idtot(pp, id)) == NULL) {
			mutex_exit(&pp->p_lock);
			error = ESRCH;
			goto err;
		}
	}

	error = pset_bind_thread(tp, pset, &oldpset, projbuf, zonebuf);
	mutex_exit(&pp->p_lock);
err:
	mutex_exit(&pidlock);

	fss_freebuf(projbuf, FSS_ALLOC_PROJ);
	fss_freebuf(zonebuf, FSS_ALLOC_ZONE);
	mutex_exit(&cpu_lock);
	pool_unlock();
	if (opset != NULL) {
		if (copyout(&oldpset, opset, sizeof (psetid_t)) != 0)
			return (set_errno(EFAULT));
	}
	if (error != 0)
		return (set_errno(error));
	return (0);
}

static int
pset_bind(psetid_t pset, idtype_t idtype, id_t id, psetid_t *opset)
{
	kthread_t	*tp;
	proc_t		*pp;
	task_t		*tk;
	kproject_t	*kpj;
	contract_t	*ct;
	zone_t		*zptr;
	psetid_t	oldpset;
	int		error = 0;
	void		*projbuf, *zonebuf;

	pool_lock();
	if ((pset != PS_QUERY) && (pset != PS_SOFT) &&
	    (pset != PS_HARD) && (pset != PS_QUERY_TYPE)) {
		/*
		 * Check if the set actually exists before checking
		 * permissions.  This is the historical error
		 * precedence.  Note that if pset was PS_MYID, the
		 * cpupart_get_cpus call will change it to the
		 * processor set id of the caller (or PS_NONE if the
		 * caller is not bound to a processor set).
		 */
		if (pool_state == POOL_ENABLED) {
			pool_unlock();
			return (set_errno(ENOTSUP));
		}
		if (cpupart_get_cpus(&pset, NULL, NULL) != 0) {
			pool_unlock();
			return (set_errno(EINVAL));
		} else if (pset != PS_NONE && secpolicy_pbind(CRED()) != 0) {
			pool_unlock();
			return (set_errno(EPERM));
		}
	}

	/*
	 * Pre-allocate enough buffers for FSS for all active projects
	 * and for all active zones on the system.  Unused buffers will
	 * be freed later by fss_freebuf().
	 */
	mutex_enter(&cpu_lock);
	projbuf = fss_allocbuf(FSS_NPROJ_BUF, FSS_ALLOC_PROJ);
	zonebuf = fss_allocbuf(FSS_NPROJ_BUF, FSS_ALLOC_ZONE);

	switch (idtype) {
	case P_LWPID:
		pp = curproc;
		mutex_enter(&pidlock);
		mutex_enter(&pp->p_lock);
		if (id == P_MYID) {
			tp = curthread;
		} else {
			if ((tp = idtot(pp, id)) == NULL) {
				mutex_exit(&pp->p_lock);
				mutex_exit(&pidlock);
				error = ESRCH;
				break;
			}
		}
		error = pset_bind_thread(tp, pset, &oldpset, projbuf, zonebuf);
		mutex_exit(&pp->p_lock);
		mutex_exit(&pidlock);
		break;

	case P_PID:
		mutex_enter(&pidlock);
		if (id == P_MYID) {
			pp = curproc;
		} else if ((pp = prfind(id)) == NULL) {
			mutex_exit(&pidlock);
			error = ESRCH;
			break;
		}
		error = pset_bind_process(pp, pset, &oldpset, projbuf, zonebuf);
		mutex_exit(&pidlock);
		break;

	case P_TASKID:
		mutex_enter(&pidlock);
		if (id == P_MYID)
			id = curproc->p_task->tk_tkid;
		if ((tk = task_hold_by_id(id)) == NULL) {
			mutex_exit(&pidlock);
			error = ESRCH;
			break;
		}
		error = pset_bind_task(tk, pset, &oldpset, projbuf, zonebuf);
		mutex_exit(&pidlock);
		task_rele(tk);
		break;

	case P_PROJID:
		pp = curproc;
		if (id == P_MYID)
			id = curprojid();
		if ((kpj = project_hold_by_id(id, pp->p_zone,
		    PROJECT_HOLD_FIND)) == NULL) {
			error = ESRCH;
			break;
		}
		mutex_enter(&pidlock);
		error = pset_bind_project(kpj, pset, &oldpset, projbuf,
		    zonebuf);
		mutex_exit(&pidlock);
		project_rele(kpj);
		break;

	case P_ZONEID:
		if (id == P_MYID)
			id = getzoneid();
		if ((zptr = zone_find_by_id(id)) == NULL) {
			error = ESRCH;
			break;
		}
		mutex_enter(&pidlock);
		error = pset_bind_zone(zptr, pset, &oldpset, projbuf, zonebuf);
		mutex_exit(&pidlock);
		zone_rele(zptr);
		break;

	case P_CTID:
		if (id == P_MYID)
			id = PRCTID(curproc);
		if ((ct = contract_type_ptr(process_type, id,
		    curproc->p_zone->zone_uniqid)) == NULL) {
			error = ESRCH;
			break;
		}
		mutex_enter(&pidlock);
		error = pset_bind_contract(ct->ct_data, pset, &oldpset, projbuf,
		    zonebuf);
		mutex_exit(&pidlock);
		contract_rele(ct);
		break;

	case P_PSETID:
		if (id == P_MYID || pset != PS_NONE || !INGLOBALZONE(curproc)) {
			error = EINVAL;
			break;
		}
		error = pset_unbind(id, projbuf, zonebuf, idtype);
		break;

	case P_ALL:
		if (id == P_MYID || pset != PS_NONE || !INGLOBALZONE(curproc)) {
			error = EINVAL;
			break;
		}
		error = pset_unbind(PS_NONE, projbuf, zonebuf, idtype);
		break;

	default:
		error = EINVAL;
		break;
	}

	fss_freebuf(projbuf, FSS_ALLOC_PROJ);
	fss_freebuf(zonebuf, FSS_ALLOC_ZONE);
	mutex_exit(&cpu_lock);
	pool_unlock();

	if (error != 0)
		return (set_errno(error));
	if (opset != NULL) {
		if (copyout(&oldpset, opset, sizeof (psetid_t)) != 0)
			return (set_errno(EFAULT));
	}
	return (0);
}

/*
 * Report load average statistics for the specified processor set.
 */
static int
pset_getloadavg(psetid_t pset, int *buf, int nelem)
{
	int loadbuf[LOADAVG_NSTATS];
	int error = 0;

	if (nelem < 0)
		return (set_errno(EINVAL));

	/*
	 * We keep the same number of load average statistics for processor
	 * sets as we do for the system as a whole.
	 */
	if (nelem > LOADAVG_NSTATS)
		nelem = LOADAVG_NSTATS;

	mutex_enter(&cpu_lock);
	error = cpupart_get_loadavg(pset, loadbuf, nelem);
	mutex_exit(&cpu_lock);
	if (!error && nelem && copyout(loadbuf, buf, nelem * sizeof (int)) != 0)
		error = EFAULT;

	if (error)
		return (set_errno(error));
	else
		return (0);
}


/*
 * Return list of active processor sets, up to a maximum indicated by
 * numpsets.  The total number of processor sets is stored in the
 * location pointed to by numpsets.
 */
static int
pset_list(psetid_t *psetlist, uint_t *numpsets)
{
	uint_t user_npsets = 0;
	uint_t real_npsets;
	psetid_t *psets = NULL;
	int error = 0;

	if (numpsets != NULL) {
		if (copyin(numpsets, &user_npsets, sizeof (uint_t)) != 0)
			return (set_errno(EFAULT));
	}

	/*
	 * Get the list of all processor sets.  First we need to find
	 * out how many there are, so we can allocate a large enough
	 * buffer.
	 */
	mutex_enter(&cpu_lock);
	if (!INGLOBALZONE(curproc) && pool_pset_enabled()) {
		psetid_t psetid = zone_pset_get(curproc->p_zone);

		if (psetid == PS_NONE) {
			real_npsets = 0;
		} else {
			real_npsets = 1;
			psets = kmem_alloc(real_npsets * sizeof (psetid_t),
			    KM_SLEEP);
			psets[0] = psetid;
		}
	} else {
		real_npsets = cpupart_list(0, NULL, CP_ALL);
		if (real_npsets) {
			psets = kmem_alloc(real_npsets * sizeof (psetid_t),
			    KM_SLEEP);
			(void) cpupart_list(psets, real_npsets, CP_ALL);
		}
	}
	mutex_exit(&cpu_lock);

	if (user_npsets > real_npsets)
		user_npsets = real_npsets;

	if (numpsets != NULL) {
		if (copyout(&real_npsets, numpsets, sizeof (uint_t)) != 0)
			error = EFAULT;
		else if (psetlist != NULL && user_npsets != 0) {
			if (copyout(psets, psetlist,
			    user_npsets * sizeof (psetid_t)) != 0)
				error = EFAULT;
		}
	}

	if (real_npsets)
		kmem_free(psets, real_npsets * sizeof (psetid_t));

	if (error)
		return (set_errno(error));
	else
		return (0);
}

static int
pset_setattr(psetid_t pset, uint_t attr)
{
	int error;

	if (secpolicy_pset(CRED()) != 0)
		return (set_errno(EPERM));
	pool_lock();
	if (pool_state == POOL_ENABLED) {
		pool_unlock();
		return (set_errno(ENOTSUP));
	}
	if (pset == PS_QUERY || PSET_BADATTR(attr)) {
		pool_unlock();
		return (set_errno(EINVAL));
	}
	if ((error = cpupart_setattr(pset, attr)) != 0) {
		pool_unlock();
		return (set_errno(error));
	}
	pool_unlock();
	return (0);
}

static int
pset_getattr(psetid_t pset, uint_t *attrp)
{
	int error = 0;
	uint_t attr;

	if (pset == PS_QUERY)
		return (set_errno(EINVAL));
	if ((error = cpupart_getattr(pset, &attr)) != 0)
		return (set_errno(error));
	if (copyout(&attr, attrp, sizeof (uint_t)) != 0)
		return (set_errno(EFAULT));
	return (0);
}

static int
pset(int subcode, long arg1, long arg2, long arg3, long arg4)
{
	switch (subcode) {
	case PSET_CREATE:
		return (pset_create((psetid_t *)arg1));
	case PSET_DESTROY:
		return (pset_destroy((psetid_t)arg1));
	case PSET_ASSIGN:
		return (pset_assign((psetid_t)arg1,
		    (processorid_t)arg2, (psetid_t *)arg3, 0));
	case PSET_INFO:
		return (pset_info((psetid_t)arg1, (int *)arg2,
		    (uint_t *)arg3, (processorid_t *)arg4));
	case PSET_BIND:
		return (pset_bind((psetid_t)arg1, (idtype_t)arg2,
		    (id_t)arg3, (psetid_t *)arg4));
	case PSET_BIND_LWP:
		return (pset_bind_lwp((psetid_t)arg1, (id_t)arg2,
		    (pid_t)arg3, (psetid_t *)arg4));
	case PSET_GETLOADAVG:
		return (pset_getloadavg((psetid_t)arg1, (int *)arg2,
		    (int)arg3));
	case PSET_LIST:
		return (pset_list((psetid_t *)arg1, (uint_t *)arg2));
	case PSET_SETATTR:
		return (pset_setattr((psetid_t)arg1, (uint_t)arg2));
	case PSET_GETATTR:
		return (pset_getattr((psetid_t)arg1, (uint_t *)arg2));
	case PSET_ASSIGN_FORCED:
		return (pset_assign((psetid_t)arg1,
		    (processorid_t)arg2, (psetid_t *)arg3, 1));
	default:
		return (set_errno(EINVAL));
	}
}
