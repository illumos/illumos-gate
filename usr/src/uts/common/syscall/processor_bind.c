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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/kstat.h>
#include <sys/uadmin.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/procset.h>
#include <sys/processor.h>
#include <sys/debug.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/zone.h>
#include <sys/contract_impl.h>
#include <sys/contract/process_impl.h>

/*
 * Bind all the threads of a process to a CPU.
 */
static int
cpu_bind_process(proc_t *pp, processorid_t bind, processorid_t *obind,
    int *error)
{
	kthread_t	*tp;
	kthread_t	*fp;
	int		err = 0;
	int		i;

	ASSERT(MUTEX_HELD(&pidlock));

	/* skip kernel processes */
	if (pp->p_flag & SSYS) {
		*obind = PBIND_NONE;
		*error = ENOTSUP;
		return (0);
	}

	mutex_enter(&pp->p_lock);
	tp = pp->p_tlist;
	if (tp != NULL) {
		fp = tp;
		do {
			i = cpu_bind_thread(tp, bind, obind, error);
			if (err == 0)
				err = i;
		} while ((tp = tp->t_forw) != fp);
	}

	mutex_exit(&pp->p_lock);
	return (err);
}

/*
 * Bind all the processes of a task to a CPU.
 */
static int
cpu_bind_task(task_t *tk, processorid_t bind, processorid_t *obind,
    int *error)
{
	proc_t	*p;
	int	err = 0;
	int	i;

	ASSERT(MUTEX_HELD(&pidlock));

	if ((p = tk->tk_memb_list) == NULL)
		return (ESRCH);

	do {
		if (!(p->p_flag & SSYS)) {
			i = cpu_bind_process(p, bind, obind, error);
			if (err == 0)
				err = i;
		}
	} while ((p = p->p_tasknext) != tk->tk_memb_list);

	return (err);
}

/*
 * Bind all the processes in a project to a CPU.
 */
static int
cpu_bind_project(kproject_t *kpj, processorid_t bind, processorid_t *obind,
    int *error)
{
	proc_t *p;
	int err = 0;
	int i;

	ASSERT(MUTEX_HELD(&pidlock));

	for (p = practive; p != NULL; p = p->p_next) {
		if (p->p_tlist == NULL)
			continue;
		if (p->p_task->tk_proj == kpj && !(p->p_flag & SSYS)) {
			i = cpu_bind_process(p, bind, obind, error);
			if (err == 0)
				err = i;
		}
	}
	return (err);
}

/*
 * Bind all the processes in a zone to a CPU.
 */
int
cpu_bind_zone(zone_t *zptr, processorid_t bind, processorid_t *obind,
    int *error)
{
	proc_t *p;
	int err = 0;
	int i;

	ASSERT(MUTEX_HELD(&pidlock));

	for (p = practive; p != NULL; p = p->p_next) {
		if (p->p_tlist == NULL)
			continue;
		if (p->p_zone == zptr && !(p->p_flag & SSYS)) {
			i = cpu_bind_process(p, bind, obind, error);
			if (err == 0)
				err = i;
		}
	}
	return (err);
}

/*
 * Bind all the processes in a process contract to a CPU.
 */
int
cpu_bind_contract(cont_process_t *ctp, processorid_t bind, processorid_t *obind,
    int *error)
{
	proc_t *p;
	int err = 0;
	int i;

	ASSERT(MUTEX_HELD(&pidlock));

	for (p = practive; p != NULL; p = p->p_next) {
		if (p->p_tlist == NULL)
			continue;
		if (p->p_ct_process == ctp) {
			i = cpu_bind_process(p, bind, obind, error);
			if (err == 0)
				err = i;
		}
	}
	return (err);
}

/*
 * processor_bind(2) - Processor binding interfaces.
 */
int
processor_bind(idtype_t idtype, id_t id, processorid_t bind,
    processorid_t *obindp)
{
	processorid_t	obind = PBIND_NONE;
	int		ret = 0;
	int		err = 0;
	cpu_t		*cp;
	kthread_id_t	tp;
	proc_t		*pp;
	task_t		*tk;
	kproject_t	*kpj;
	zone_t		*zptr;
	contract_t	*ct;

	/*
	 * Since we might be making a binding to a processor, hold the
	 * cpu_lock so that the processor cannot be taken offline while
	 * we do this.
	 */
	mutex_enter(&cpu_lock);

	/*
	 * Check to be sure binding processor ID is valid.
	 */
	switch (bind) {
	default:
		if ((cp = cpu_get(bind)) == NULL ||
		    (cp->cpu_flags & (CPU_QUIESCED | CPU_OFFLINE)))
			ret = EINVAL;
		else if ((cp->cpu_flags & CPU_READY) == 0)
			ret = EIO;
		break;

	case PBIND_NONE:
	case PBIND_QUERY:
	case PBIND_HARD:
	case PBIND_SOFT:
	case PBIND_QUERY_TYPE:
		break;
	}

	if (ret) {
		mutex_exit(&cpu_lock);
		return (set_errno(ret));
	}

	switch (idtype) {
	case P_LWPID:
		pp = curproc;
		mutex_enter(&pp->p_lock);
		if (id == P_MYID) {
			ret = cpu_bind_thread(curthread, bind, &obind, &err);
		} else {
			int	found = 0;

			tp = pp->p_tlist;
			do {
				if (tp->t_tid == id) {
					ret = cpu_bind_thread(tp,
					    bind, &obind, &err);
					found = 1;
					break;
				}
			} while ((tp = tp->t_forw) != pp->p_tlist);
			if (!found)
				ret = ESRCH;
		}
		mutex_exit(&pp->p_lock);
		break;

	case P_PID:
		/*
		 * Note.  Cannot use dotoprocs here because it doesn't find
		 * system class processes, which are legal to query.
		 */
		mutex_enter(&pidlock);
		if (id == P_MYID) {
			ret = cpu_bind_process(curproc, bind, &obind, &err);
		} else if ((pp = prfind(id)) != NULL) {
			ret = cpu_bind_process(pp, bind, &obind, &err);
		} else {
			ret = ESRCH;
		}
		mutex_exit(&pidlock);
		break;

	case P_TASKID:
		mutex_enter(&pidlock);
		if (id == P_MYID) {
			proc_t *p = curproc;
			id = p->p_task->tk_tkid;
		}

		if ((tk = task_hold_by_id(id)) != NULL) {
			ret = cpu_bind_task(tk, bind, &obind, &err);
			mutex_exit(&pidlock);
			task_rele(tk);
		} else {
			mutex_exit(&pidlock);
			ret = ESRCH;
		}
		break;

	case P_PROJID:
		pp = curproc;
		if (id == P_MYID)
			id = curprojid();
		if ((kpj = project_hold_by_id(id, pp->p_zone,
		    PROJECT_HOLD_FIND)) == NULL) {
			ret = ESRCH;
		} else {
			mutex_enter(&pidlock);
			ret = cpu_bind_project(kpj, bind, &obind, &err);
			mutex_exit(&pidlock);
			project_rele(kpj);
		}
		break;

	case P_ZONEID:
		if (id == P_MYID)
			id = getzoneid();

		if ((zptr = zone_find_by_id(id)) == NULL) {
			ret = ESRCH;
		} else {
			mutex_enter(&pidlock);
			ret = cpu_bind_zone(zptr, bind, &obind, &err);
			mutex_exit(&pidlock);
			zone_rele(zptr);
		}
		break;

	case P_CTID:
		if (id == P_MYID)
			id = PRCTID(curproc);

		if ((ct = contract_type_ptr(process_type, id,
		    curproc->p_zone->zone_uniqid)) == NULL) {
			ret = ESRCH;
		} else {
			mutex_enter(&pidlock);
			ret = cpu_bind_contract(ct->ct_data,
			    bind, &obind, &err);
			mutex_exit(&pidlock);
			contract_rele(ct);
		}
		break;

	case P_CPUID:
		if (id == P_MYID || bind != PBIND_NONE || cpu_get(id) == NULL)
			ret = EINVAL;
		else
			ret = cpu_unbind(id, B_TRUE);
		break;

	case P_ALL:
		if (id == P_MYID || bind != PBIND_NONE) {
			ret = EINVAL;
		} else {
			int i;
			cpu_t *cp = cpu_list;
			do {
				if ((cp->cpu_flags & CPU_EXISTS) == 0)
					continue;
				i = cpu_unbind(cp->cpu_id, B_TRUE);
				if (ret == 0)
					ret = i;
			} while ((cp = cp->cpu_next) != cpu_list);
		}
		break;

	default:
		/*
		 * Spec says this is invalid, even though we could
		 * handle other idtypes.
		 */
		ret = EINVAL;
		break;
	}
	mutex_exit(&cpu_lock);

	/*
	 * If no search error occurred, see if any permissions errors did.
	 */
	if (ret == 0)
		ret = err;

	if (ret == 0 && obindp != NULL)
		if (copyout((caddr_t)&obind, (caddr_t)obindp,
		    sizeof (obind)) == -1)
			ret = EFAULT;
	return (ret ? set_errno(ret) : 0);	/* return success or failure */
}
