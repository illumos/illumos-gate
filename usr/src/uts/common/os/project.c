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
 * Copyright 2016, Joyent, Inc.
 */

#include <sys/project.h>
#include <sys/modhash.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/proc.h>
#include <sys/rctl.h>
#include <sys/sunddi.h>
#include <sys/fss.h>
#include <sys/systm.h>
#include <sys/ipc_impl.h>
#include <sys/port_kernel.h>
#include <sys/task.h>
#include <sys/zone.h>
#include <sys/cpucaps.h>
#include <sys/klpd.h>

int project_hash_size = 64;
static kmutex_t project_hash_lock;
static kmutex_t projects_list_lock;
static mod_hash_t *projects_hash;
static kproject_t *projects_list;

rctl_hndl_t rc_project_cpu_shares;
rctl_hndl_t rc_project_cpu_cap;
rctl_hndl_t rc_project_nlwps;
rctl_hndl_t rc_project_nprocs;
rctl_hndl_t rc_project_ntasks;
rctl_hndl_t rc_project_msgmni;
rctl_hndl_t rc_project_semmni;
rctl_hndl_t rc_project_shmmax;
rctl_hndl_t rc_project_shmmni;
rctl_hndl_t rc_project_portids;
rctl_hndl_t rc_project_locked_mem;
rctl_hndl_t rc_project_contract;
rctl_hndl_t rc_project_crypto_mem;

/*
 * Dummy structure used when comparing projects.  This structure must be kept
 * identical to the first two fields of kproject_t.
 */
struct project_zone {
	projid_t	kpj_id;
	zoneid_t	kpj_zoneid;
};

/*
 * Projects
 *
 *   A dictionary of all active projects is maintained by the kernel so that we
 *   may track project usage and limits.  (By an active project, we mean a
 *   project associated with one or more task, and therefore with one or more
 *   processes.) We build the dictionary on top of the mod_hash facility, since
 *   project additions and deletions are relatively rare events.  An
 *   integer-to-pointer mapping is maintained within the hash, representing the
 *   map from project id to project structure.  All projects, including the
 *   primordial "project 0", are allocated via the project_hold_by_id()
 *   interface.
 *
 *   Currently, the project contains a reference count; the project ID, which is
 *   examined by the extended accounting subsystem as well as /proc; a resource
 *   control set, which contains the allowable values (and actions on exceeding
 *   those values) for controlled project-level resources on the system; and a
 *   number of CPU shares, which is used by the fair share scheduling class
 *   (FSS) to support its proportion-based scheduling algorithm.
 *
 * Reference counting convention
 *   The dictionary entry does not itself count as a reference--only references
 *   outside of the subsystem are tallied.  At the drop of the final external
 *   reference, the project entry is removed.  The reference counter keeps
 *   track of the number of threads *and* tasks within a project.
 *
 * Locking
 *   Walking the doubly-linked project list must be done while holding
 *   projects_list_lock.  Thus, any dereference of kpj_next or kpj_prev must be
 *   under projects_list_lock.
 *
 *   If both the hash lock, project_hash_lock, and the list lock are to be
 *   acquired, the hash lock is to be acquired first.
 */

static void project_kstat_create(kproject_t *pj, zone_t *zone);
static void project_kstat_delete(kproject_t *pj);

static void
project_data_init(kproject_data_t *data)
{
	/*
	 * Initialize subsystem-specific data
	 */
	data->kpd_shmmax = 0;
	data->kpd_ipc.ipcq_shmmni = 0;
	data->kpd_ipc.ipcq_semmni = 0;
	data->kpd_ipc.ipcq_msgmni = 0;
	data->kpd_locked_mem = 0;
	data->kpd_locked_mem_ctl = UINT64_MAX;
	data->kpd_contract = 0;
	data->kpd_crypto_mem = 0;
	data->kpd_crypto_mem_ctl = UINT64_MAX;
	data->kpd_lockedmem_kstat = NULL;
	data->kpd_nprocs_kstat = NULL;
}

/*ARGSUSED*/
static uint_t
project_hash_by_id(void *hash_data, mod_hash_key_t key)
{
	struct project_zone *pz = key;
	uint_t mykey;

	/*
	 * Merge the zoneid and projectid together to a 32-bit quantity, and
	 * then pass that in to the existing idhash.
	 */
	mykey = (pz->kpj_zoneid << 16) | pz->kpj_id;
	return (mod_hash_byid(hash_data, (mod_hash_key_t)(uintptr_t)mykey));
}

static int
project_hash_key_cmp(mod_hash_key_t key1, mod_hash_key_t key2)
{
	struct project_zone *pz1 = key1, *pz2 = key2;
	int retval;

	return ((int)((retval = pz1->kpj_id - pz2->kpj_id) != 0 ? retval :
	    pz1->kpj_zoneid - pz2->kpj_zoneid));
}

static void
project_hash_val_dtor(mod_hash_val_t val)
{
	kproject_t *kp = (kproject_t *)val;

	ASSERT(kp->kpj_count == 0);
	ASSERT(kp->kpj_cpucap == NULL);
	kmem_free(kp, sizeof (kproject_t));
}

/*
 * kproject_t *project_hold(kproject_t *)
 *
 * Overview
 *   Record that an additional reference on the indicated project has been
 *   taken.
 *
 * Return values
 *   A pointer to the indicated project.
 *
 * Caller's context
 *   project_hash_lock must not be held across the project_hold() call.
 */
kproject_t *
project_hold(kproject_t *p)
{
	mutex_enter(&project_hash_lock);
	ASSERT(p != NULL);
	p->kpj_count++;
	ASSERT(p->kpj_count != 0);
	mutex_exit(&project_hash_lock);
	return (p);
}

/*
 * kproject_t *project_hold_by_id(projid_t, zone_t *, int)
 *
 * Overview
 *   project_hold_by_id() performs a look-up in the dictionary of projects
 *   active on the system by specified project ID + zone and puts a hold on
 *   it.  The third argument defines the desired behavior in the case when
 *   project with given project ID cannot be found:
 *
 *   PROJECT_HOLD_INSERT	New entry is made in dictionary and the project
 *   				is added to the global list.
 *
 *   PROJECT_HOLD_FIND		Return NULL.
 *
 *   The project is returned with its reference count incremented by one.
 *   A new project derives its resource controls from those of project 0.
 *
 * Return values
 *   A pointer to the held project.
 *
 * Caller's context
 *   Caller must be in a context suitable for KM_SLEEP allocations.
 */
kproject_t *
project_hold_by_id(projid_t id, zone_t *zone, int flag)
{
	kproject_t *spare_p;
	kproject_t *p;
	mod_hash_hndl_t hndl;
	rctl_set_t *set;
	rctl_alloc_gp_t *gp;
	rctl_entity_p_t e;
	struct project_zone pz;
	boolean_t create = B_FALSE;

	pz.kpj_id = id;
	pz.kpj_zoneid = zone->zone_id;

	if (flag == PROJECT_HOLD_FIND) {
		mutex_enter(&project_hash_lock);

		if (mod_hash_find(projects_hash, (mod_hash_key_t)&pz,
		    (mod_hash_val_t)&p) == MH_ERR_NOTFOUND)
			p = NULL;
		else
			p->kpj_count++;

		mutex_exit(&project_hash_lock);
		return (p);
	}

	ASSERT(flag == PROJECT_HOLD_INSERT);

	spare_p = kmem_zalloc(sizeof (kproject_t), KM_SLEEP);
	set = rctl_set_create();

	gp = rctl_set_init_prealloc(RCENTITY_PROJECT);

	(void) mod_hash_reserve(projects_hash, &hndl);

	mutex_enter(&curproc->p_lock);
	mutex_enter(&project_hash_lock);
	if (mod_hash_find(projects_hash, (mod_hash_key_t)&pz,
	    (mod_hash_val_t *)&p) == MH_ERR_NOTFOUND) {

		p = spare_p;
		p->kpj_id = id;
		p->kpj_zone = zone;
		p->kpj_zoneid = zone->zone_id;
		p->kpj_count = 0;
		p->kpj_shares = 1;
		p->kpj_nlwps = 0;
		p->kpj_nprocs = 0;
		p->kpj_ntasks = 0;
		p->kpj_nlwps_ctl = INT_MAX;
		p->kpj_nprocs_ctl = INT_MAX;
		p->kpj_ntasks_ctl = INT_MAX;
		project_data_init(&p->kpj_data);
		e.rcep_p.proj = p;
		e.rcep_t = RCENTITY_PROJECT;
		p->kpj_rctls = rctl_set_init(RCENTITY_PROJECT, curproc, &e,
		    set, gp);
		mutex_exit(&curproc->p_lock);

		if (mod_hash_insert_reserve(projects_hash, (mod_hash_key_t)p,
		    (mod_hash_val_t)p, hndl))
			panic("unable to insert project %d(%p)", id, (void *)p);

		/*
		 * Insert project into global project list.
		 */
		mutex_enter(&projects_list_lock);
		if (id != 0 || zone != &zone0) {
			p->kpj_next = projects_list;
			p->kpj_prev = projects_list->kpj_prev;
			p->kpj_prev->kpj_next = p;
			projects_list->kpj_prev = p;
		} else {
			/*
			 * Special case: primordial hold on project 0.
			 */
			p->kpj_next = p;
			p->kpj_prev = p;
			projects_list = p;
		}
		mutex_exit(&projects_list_lock);
		create = B_TRUE;
	} else {
		mutex_exit(&curproc->p_lock);
		mod_hash_cancel(projects_hash, &hndl);
		kmem_free(spare_p, sizeof (kproject_t));
		rctl_set_free(set);
	}

	rctl_prealloc_destroy(gp);
	p->kpj_count++;
	mutex_exit(&project_hash_lock);

	/*
	 * The kstat stores the project's zone name, as zoneid's may change
	 * across reboots.
	 */
	if (create == B_TRUE) {
		/*
		 * Inform CPU caps framework of the new project
		 */
		cpucaps_project_add(p);
		/*
		 * Set up project kstats
		 */
		project_kstat_create(p, zone);
	}
	return (p);
}

/*
 * void project_rele(kproject_t *)
 *
 * Overview
 *   Advertise that one external reference to this project is no longer needed.
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   No restriction on context.
 */
void
project_rele(kproject_t *p)
{
	mutex_enter(&project_hash_lock);
	ASSERT(p->kpj_count != 0);
	p->kpj_count--;
	if (p->kpj_count == 0) {

		/*
		 * Remove project from global list.
		 */
		ASSERT(p->kpj_nprocs == 0);

		mutex_enter(&projects_list_lock);
		p->kpj_next->kpj_prev = p->kpj_prev;
		p->kpj_prev->kpj_next = p->kpj_next;
		if (projects_list == p)
			projects_list = p->kpj_next;
		mutex_exit(&projects_list_lock);

		cpucaps_project_remove(p);

		rctl_set_free(p->kpj_rctls);
		project_kstat_delete(p);

		if (p->kpj_klpd != NULL)
			klpd_freelist(&p->kpj_klpd);

		if (mod_hash_destroy(projects_hash, (mod_hash_key_t)p))
			panic("unable to delete project %d zone %d", p->kpj_id,
			    p->kpj_zoneid);

	}
	mutex_exit(&project_hash_lock);
}

/*
 * int project_walk_all(zoneid_t, int (*)(kproject_t *, void *), void *)
 *
 * Overview
 *   Walk the project list for the given zoneid with a callback.
 *
 * Return values
 *   -1 for an invalid walk, number of projects visited otherwise.
 *
 * Caller's context
 *   projects_list_lock must not be held, as it is acquired by
 *   project_walk_all().  Accordingly, callbacks may not perform KM_SLEEP
 *   allocations.
 */
int
project_walk_all(zoneid_t zoneid, int (*cb)(kproject_t *, void *),
    void *walk_data)
{
	int cnt = 0;
	kproject_t *kp = proj0p;

	mutex_enter(&projects_list_lock);
	do {
		if (zoneid != ALL_ZONES && kp->kpj_zoneid != zoneid)
			continue;
		if (cb(kp, walk_data) == -1) {
			cnt = -1;
			break;
		} else {
			cnt++;
		}
	} while ((kp = kp->kpj_next) != proj0p);
	mutex_exit(&projects_list_lock);
	return (cnt);
}

/*
 * projid_t curprojid(void)
 *
 * Overview
 *   Return project ID of the current thread
 *
 * Caller's context
 *   No restrictions.
 */
projid_t
curprojid()
{
	return (ttoproj(curthread)->kpj_id);
}

/*
 * project.cpu-shares resource control support.
 */
/*ARGSUSED*/
static rctl_qty_t
project_cpu_shares_usage(rctl_t *rctl, struct proc *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	return (p->p_task->tk_proj->kpj_shares);
}

/*ARGSUSED*/
static int
project_cpu_shares_set(rctl_t *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_qty_t nv)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	if (e->rcep_p.proj == NULL)
		return (0);

	e->rcep_p.proj->kpj_shares = nv;

	return (0);
}

static rctl_ops_t project_cpu_shares_ops = {
	rcop_no_action,
	project_cpu_shares_usage,
	project_cpu_shares_set,
	rcop_no_test
};


/*
 * project.cpu-cap resource control support.
 */
/*ARGSUSED*/
static rctl_qty_t
project_cpu_cap_get(rctl_t *rctl, struct proc *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	return (cpucaps_project_get(p->p_task->tk_proj));
}

/*ARGSUSED*/
static int
project_cpu_cap_set(rctl_t *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_qty_t nv)
{
	kproject_t *kpj = e->rcep_p.proj;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	if (kpj == NULL)
		return (0);

	/*
	 * set cap to the new value.
	 */
	return (cpucaps_project_set(kpj,  nv));
}

static rctl_ops_t project_cpu_cap_ops = {
	rcop_no_action,
	project_cpu_cap_get,
	project_cpu_cap_set,
	rcop_no_test
};

/*ARGSUSED*/
static rctl_qty_t
project_lwps_usage(rctl_t *r, proc_t *p)
{
	kproject_t *pj;
	rctl_qty_t nlwps;

	ASSERT(MUTEX_HELD(&p->p_lock));
	pj = p->p_task->tk_proj;
	mutex_enter(&p->p_zone->zone_nlwps_lock);
	nlwps = pj->kpj_nlwps;
	mutex_exit(&p->p_zone->zone_nlwps_lock);

	return (nlwps);
}

/*ARGSUSED*/
static int
project_lwps_test(rctl_t *r, proc_t *p, rctl_entity_p_t *e, rctl_val_t *rcntl,
    rctl_qty_t incr, uint_t flags)
{
	rctl_qty_t nlwps;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(MUTEX_HELD(&p->p_zone->zone_nlwps_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	if (e->rcep_p.proj == NULL)
		return (0);

	nlwps = e->rcep_p.proj->kpj_nlwps;
	if (nlwps + incr > rcntl->rcv_value)
		return (1);

	return (0);
}

/*ARGSUSED*/
static int
project_lwps_set(rctl_t *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_qty_t nv) {

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	if (e->rcep_p.proj == NULL)
		return (0);

	e->rcep_p.proj->kpj_nlwps_ctl = nv;
	return (0);
}

static rctl_ops_t project_lwps_ops = {
	rcop_no_action,
	project_lwps_usage,
	project_lwps_set,
	project_lwps_test,
};

/*ARGSUSED*/
static rctl_qty_t
project_procs_usage(rctl_t *r, proc_t *p)
{
	kproject_t *pj;
	rctl_qty_t nprocs;

	ASSERT(MUTEX_HELD(&p->p_lock));
	pj = p->p_task->tk_proj;
	mutex_enter(&p->p_zone->zone_nlwps_lock);
	nprocs = pj->kpj_nprocs;
	mutex_exit(&p->p_zone->zone_nlwps_lock);

	return (nprocs);
}

/*ARGSUSED*/
static int
project_procs_test(rctl_t *r, proc_t *p, rctl_entity_p_t *e, rctl_val_t *rcntl,
    rctl_qty_t incr, uint_t flags)
{
	rctl_qty_t nprocs;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(MUTEX_HELD(&p->p_zone->zone_nlwps_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	if (e->rcep_p.proj == NULL)
		return (0);

	nprocs = e->rcep_p.proj->kpj_nprocs;
	if (nprocs + incr > rcntl->rcv_value)
		return (1);

	return (0);
}

/*ARGSUSED*/
static int
project_procs_set(rctl_t *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_qty_t nv) {

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	if (e->rcep_p.proj == NULL)
		return (0);

	e->rcep_p.proj->kpj_nprocs_ctl = nv;
	return (0);
}

static rctl_ops_t project_procs_ops = {
	rcop_no_action,
	project_procs_usage,
	project_procs_set,
	project_procs_test,
};

/*ARGSUSED*/
static rctl_qty_t
project_ntasks_usage(rctl_t *r, proc_t *p)
{
	kproject_t *pj;
	rctl_qty_t ntasks;

	ASSERT(MUTEX_HELD(&p->p_lock));
	pj = p->p_task->tk_proj;
	mutex_enter(&p->p_zone->zone_nlwps_lock);
	ntasks = pj->kpj_ntasks;
	mutex_exit(&p->p_zone->zone_nlwps_lock);

	return (ntasks);
}

/*ARGSUSED*/
static int
project_ntasks_test(rctl_t *r, proc_t *p, rctl_entity_p_t *e, rctl_val_t *rcntl,
    rctl_qty_t incr, uint_t flags)
{
	rctl_qty_t ntasks;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	ntasks = e->rcep_p.proj->kpj_ntasks;
	if (ntasks + incr > rcntl->rcv_value)
		return (1);

	return (0);
}

/*ARGSUSED*/
static int
project_ntasks_set(rctl_t *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_qty_t nv) {

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	e->rcep_p.proj->kpj_ntasks_ctl = nv;
	return (0);
}

static rctl_ops_t project_tasks_ops = {
	rcop_no_action,
	project_ntasks_usage,
	project_ntasks_set,
	project_ntasks_test,
};

/*
 * project.max-shm-memory resource control support.
 */

/*ARGSUSED*/
static rctl_qty_t
project_shmmax_usage(rctl_t *rctl, struct proc *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	return (p->p_task->tk_proj->kpj_data.kpd_shmmax);
}

/*ARGSUSED*/
static int
project_shmmax_test(struct rctl *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_val_t *rval, rctl_qty_t inc, uint_t flags)
{
	rctl_qty_t v;
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	v = e->rcep_p.proj->kpj_data.kpd_shmmax + inc;
	if (v > rval->rcv_value)
		return (1);

	return (0);
}

static rctl_ops_t project_shmmax_ops = {
	rcop_no_action,
	project_shmmax_usage,
	rcop_no_set,
	project_shmmax_test
};

/*
 * project.max-shm-ids resource control support.
 */

/*ARGSUSED*/
static rctl_qty_t
project_shmmni_usage(rctl_t *rctl, struct proc *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	return (p->p_task->tk_proj->kpj_data.kpd_ipc.ipcq_shmmni);
}

/*ARGSUSED*/
static int
project_shmmni_test(struct rctl *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_val_t *rval, rctl_qty_t inc, uint_t flags)
{
	rctl_qty_t v;
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	v = e->rcep_p.proj->kpj_data.kpd_ipc.ipcq_shmmni + inc;
	if (v > rval->rcv_value)
		return (1);

	return (0);
}

static rctl_ops_t project_shmmni_ops = {
	rcop_no_action,
	project_shmmni_usage,
	rcop_no_set,
	project_shmmni_test
};

/*
 * project.max-sem-ids resource control support.
 */

/*ARGSUSED*/
static rctl_qty_t
project_semmni_usage(rctl_t *rctl, struct proc *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	return (p->p_task->tk_proj->kpj_data.kpd_ipc.ipcq_semmni);
}

/*ARGSUSED*/
static int
project_semmni_test(struct rctl *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_val_t *rval, rctl_qty_t inc, uint_t flags)
{
	rctl_qty_t v;
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	v = e->rcep_p.proj->kpj_data.kpd_ipc.ipcq_semmni + inc;
	if (v > rval->rcv_value)
		return (1);

	return (0);
}

static rctl_ops_t project_semmni_ops = {
	rcop_no_action,
	project_semmni_usage,
	rcop_no_set,
	project_semmni_test
};

/*
 * project.max-msg-ids resource control support.
 */

/*ARGSUSED*/
static rctl_qty_t
project_msgmni_usage(rctl_t *rctl, struct proc *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	return (p->p_task->tk_proj->kpj_data.kpd_ipc.ipcq_msgmni);
}

/*ARGSUSED*/
static int
project_msgmni_test(struct rctl *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_val_t *rval, rctl_qty_t inc, uint_t flags)
{
	rctl_qty_t v;
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	v = e->rcep_p.proj->kpj_data.kpd_ipc.ipcq_msgmni + inc;
	if (v > rval->rcv_value)
		return (1);

	return (0);
}

static rctl_ops_t project_msgmni_ops = {
	rcop_no_action,
	project_msgmni_usage,
	rcop_no_set,
	project_msgmni_test
};

/*ARGSUSED*/
static rctl_qty_t
project_locked_mem_usage(rctl_t *rctl, struct proc *p)
{
	rctl_qty_t q;
	ASSERT(MUTEX_HELD(&p->p_lock));
	mutex_enter(&p->p_zone->zone_mem_lock);
	q = p->p_task->tk_proj->kpj_data.kpd_locked_mem;
	mutex_exit(&p->p_zone->zone_mem_lock);
	return (q);
}

/*ARGSUSED*/
static int
project_locked_mem_test(struct rctl *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_val_t *rval, rctl_qty_t inc, uint_t flags)
{
	rctl_qty_t q;
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(MUTEX_HELD(&p->p_zone->zone_mem_lock));
	q = p->p_task->tk_proj->kpj_data.kpd_locked_mem;
	if (q + inc > rval->rcv_value)
		return (1);
	return (0);
}

/*ARGSUSED*/
static int
project_locked_mem_set(rctl_t *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_qty_t nv) {

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	if (e->rcep_p.proj == NULL)
		return (0);

	e->rcep_p.proj->kpj_data.kpd_locked_mem_ctl = nv;
	return (0);
}

static rctl_ops_t project_locked_mem_ops = {
	rcop_no_action,
	project_locked_mem_usage,
	project_locked_mem_set,
	project_locked_mem_test
};

/*
 * project.max-contracts resource control support.
 */

/*ARGSUSED*/
static int
project_contract_test(struct rctl *rctl, struct proc *p, rctl_entity_p_t *e,
    rctl_val_t *rval, rctl_qty_t inc, uint_t flags)
{
	rctl_qty_t v;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);

	v = e->rcep_p.proj->kpj_data.kpd_contract + inc;

	if ((p->p_task != NULL) && (p->p_task->tk_proj) != NULL &&
	    (v > rval->rcv_value))
		return (1);

	return (0);
}

static rctl_ops_t project_contract_ops = {
	rcop_no_action,
	rcop_no_usage,
	rcop_no_set,
	project_contract_test
};

/*ARGSUSED*/
static rctl_qty_t
project_crypto_usage(rctl_t *r, proc_t *p)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	return (p->p_task->tk_proj->kpj_data.kpd_crypto_mem);
}

/*ARGSUSED*/
static int
project_crypto_set(rctl_t *r, proc_t *p, rctl_entity_p_t *e,
    rctl_qty_t nv)
{
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	if (e->rcep_p.proj == NULL)
		return (0);

	e->rcep_p.proj->kpj_data.kpd_crypto_mem_ctl = nv;
	return (0);
}

/*ARGSUSED*/
static int
project_crypto_test(rctl_t *r, proc_t *p, rctl_entity_p_t *e,
    rctl_val_t *rval, rctl_qty_t incr, uint_t flags)
{
	rctl_qty_t v;
	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(e->rcep_t == RCENTITY_PROJECT);
	v = e->rcep_p.proj->kpj_data.kpd_crypto_mem + incr;
	if (v > rval->rcv_value)
		return (1);
	return (0);
}

static rctl_ops_t project_crypto_mem_ops = {
	rcop_no_action,
	project_crypto_usage,
	project_crypto_set,
	project_crypto_test
};

/*
 * void project_init(void)
 *
 * Overview
 *   Initialize the project subsystem, including the primordial project 0 entry.
 *   Register generic project resource controls, if any.
 *
 * Return values
 *   None.
 *
 * Caller's context
 *   Safe for KM_SLEEP allocations.
 */
void
project_init(void)
{
	rctl_qty_t shmmni, shmmax, qty;
	boolean_t check;

	projects_hash = mod_hash_create_extended("projects_hash",
	    project_hash_size, mod_hash_null_keydtor, project_hash_val_dtor,
	    project_hash_by_id,
	    (void *)(uintptr_t)mod_hash_iddata_gen(project_hash_size),
	    project_hash_key_cmp, KM_SLEEP);

	rc_project_cpu_shares = rctl_register("project.cpu-shares",
	    RCENTITY_PROJECT, RCTL_GLOBAL_SIGNAL_NEVER |
	    RCTL_GLOBAL_DENY_NEVER | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_COUNT | RCTL_GLOBAL_SYSLOG_NEVER,
	    FSS_MAXSHARES, FSS_MAXSHARES,
	    &project_cpu_shares_ops);
	rctl_add_default_limit("project.cpu-shares", 1, RCPRIV_PRIVILEGED,
	    RCTL_LOCAL_NOACTION);

	rc_project_cpu_cap = rctl_register("project.cpu-cap",
	    RCENTITY_PROJECT, RCTL_GLOBAL_SIGNAL_NEVER |
	    RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_COUNT | RCTL_GLOBAL_SYSLOG_NEVER |
	    RCTL_GLOBAL_INFINITE,
	    MAXCAP, MAXCAP, &project_cpu_cap_ops);

	rc_project_nlwps = rctl_register("project.max-lwps", RCENTITY_PROJECT,
	    RCTL_GLOBAL_NOACTION | RCTL_GLOBAL_NOBASIC | RCTL_GLOBAL_COUNT,
	    INT_MAX, INT_MAX, &project_lwps_ops);

	rc_project_nprocs = rctl_register("project.max-processes",
	    RCENTITY_PROJECT, RCTL_GLOBAL_NOACTION | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_COUNT, INT_MAX, INT_MAX, &project_procs_ops);

	rc_project_ntasks = rctl_register("project.max-tasks", RCENTITY_PROJECT,
	    RCTL_GLOBAL_NOACTION | RCTL_GLOBAL_NOBASIC | RCTL_GLOBAL_COUNT,
	    INT_MAX, INT_MAX, &project_tasks_ops);

	/*
	 * This rctl handle is used by /dev/crypto. It is here rather than
	 * in misc/kcf or the drv/crypto module because resource controls
	 * currently don't allow modules to be unloaded, and the control
	 * must be registered before init starts.
	 */
	rc_project_crypto_mem = rctl_register("project.max-crypto-memory",
	    RCENTITY_PROJECT, RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_BYTES, UINT64_MAX, UINT64_MAX,
	    &project_crypto_mem_ops);

	/*
	 * Default to a quarter of the machine's memory
	 */
	qty = availrmem_initial << (PAGESHIFT - 2);
	rctl_add_default_limit("project.max-crypto-memory", qty,
	    RCPRIV_PRIVILEGED, RCTL_LOCAL_DENY);

	/*
	 * System V IPC resource controls
	 */
	rc_project_semmni = rctl_register("project.max-sem-ids",
	    RCENTITY_PROJECT, RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_COUNT, IPC_IDS_MAX, IPC_IDS_MAX, &project_semmni_ops);
	rctl_add_legacy_limit("project.max-sem-ids", "semsys",
	    "seminfo_semmni", 128, IPC_IDS_MAX);

	rc_project_msgmni = rctl_register("project.max-msg-ids",
	    RCENTITY_PROJECT, RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_COUNT, IPC_IDS_MAX, IPC_IDS_MAX, &project_msgmni_ops);
	rctl_add_legacy_limit("project.max-msg-ids", "msgsys",
	    "msginfo_msgmni", 128, IPC_IDS_MAX);

	rc_project_shmmni = rctl_register("project.max-shm-ids",
	    RCENTITY_PROJECT, RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_COUNT, IPC_IDS_MAX, IPC_IDS_MAX, &project_shmmni_ops);
	rctl_add_legacy_limit("project.max-shm-ids", "shmsys",
	    "shminfo_shmmni", 128, IPC_IDS_MAX);

	rc_project_shmmax = rctl_register("project.max-shm-memory",
	    RCENTITY_PROJECT, RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_BYTES, UINT64_MAX, UINT64_MAX, &project_shmmax_ops);

	check = B_FALSE;
	if (!mod_sysvar("shmsys", "shminfo_shmmni", &shmmni))
		shmmni = 100;
	else
		check = B_TRUE;
	if (!mod_sysvar("shmsys", "shminfo_shmmax", &shmmax))
		shmmax = 0x800000;
	else
		check = B_TRUE;

	/*
	 * Default to a quarter of the machine's memory
	 */
	qty = availrmem_initial << (PAGESHIFT - 2);
	if (check) {
		if ((shmmax > 0) && (UINT64_MAX / shmmax <= shmmni))
			qty = UINT64_MAX;
		else if (shmmni * shmmax > qty)
			qty = shmmni * shmmax;
	}
	rctl_add_default_limit("project.max-shm-memory", qty,
	    RCPRIV_PRIVILEGED, RCTL_LOCAL_DENY);

	/*
	 * Event Ports resource controls
	 */

	rc_project_portids = rctl_register("project.max-port-ids",
	    RCENTITY_PROJECT, RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_COUNT, PORT_MAX_PORTS, PORT_MAX_PORTS,
	    &rctl_absolute_ops);
	rctl_add_default_limit("project.max-port-ids", PORT_DEFAULT_PORTS,
	    RCPRIV_PRIVILEGED, RCTL_LOCAL_DENY);

	/*
	 * Resource control for locked memory
	 */
	rc_project_locked_mem = rctl_register(
	    "project.max-locked-memory", RCENTITY_PROJECT,
	    RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC | RCTL_GLOBAL_BYTES,
	    UINT64_MAX, UINT64_MAX, &project_locked_mem_ops);

	/*
	 * Per project limit on contracts.
	 */
	rc_project_contract = rctl_register("project.max-contracts",
	    RCENTITY_PROJECT, RCTL_GLOBAL_DENY_ALWAYS | RCTL_GLOBAL_NOBASIC |
	    RCTL_GLOBAL_COUNT, INT_MAX, INT_MAX, &project_contract_ops);
	rctl_add_default_limit("project.max-contracts", 10000,
	    RCPRIV_PRIVILEGED, RCTL_LOCAL_DENY);

	t0.t_proj = proj0p = project_hold_by_id(0, &zone0,
	    PROJECT_HOLD_INSERT);

	mutex_enter(&p0.p_lock);
	proj0p->kpj_nlwps = p0.p_lwpcnt;
	mutex_exit(&p0.p_lock);
	proj0p->kpj_nprocs = 1;
	proj0p->kpj_ntasks = 1;
}

static int
project_lockedmem_kstat_update(kstat_t *ksp, int rw)
{
	kproject_t *pj = ksp->ks_private;
	kproject_kstat_t *kpk = ksp->ks_data;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	kpk->kpk_usage.value.ui64 = pj->kpj_data.kpd_locked_mem;
	kpk->kpk_value.value.ui64 = pj->kpj_data.kpd_locked_mem_ctl;
	return (0);
}

static int
project_nprocs_kstat_update(kstat_t *ksp, int rw)
{
	kproject_t *pj = ksp->ks_private;
	kproject_kstat_t *kpk = ksp->ks_data;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	kpk->kpk_usage.value.ui64 = pj->kpj_nprocs;
	kpk->kpk_value.value.ui64 = pj->kpj_nprocs_ctl;
	return (0);
}

static kstat_t *
project_kstat_create_common(kproject_t *pj, char *name, char *zonename,
    int (*updatefunc) (kstat_t *, int))
{
	kstat_t *ksp;
	kproject_kstat_t *kpk;

	ksp = rctl_kstat_create_project(pj, name, KSTAT_TYPE_NAMED,
	    sizeof (kproject_kstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (ksp == NULL)
		return (NULL);

	kpk = ksp->ks_data = kmem_alloc(sizeof (kproject_kstat_t), KM_SLEEP);
	ksp->ks_data_size += strlen(zonename) + 1;
	kstat_named_init(&kpk->kpk_zonename, "zonename", KSTAT_DATA_STRING);
	kstat_named_setstr(&kpk->kpk_zonename, zonename);
	kstat_named_init(&kpk->kpk_usage, "usage", KSTAT_DATA_UINT64);
	kstat_named_init(&kpk->kpk_value, "value", KSTAT_DATA_UINT64);
	ksp->ks_update = updatefunc;
	ksp->ks_private = pj;
	kstat_install(ksp);
	return (ksp);
}

static void
project_kstat_create(kproject_t *pj, zone_t *zone)
{
	kstat_t *ksp_lockedmem;
	kstat_t *ksp_nprocs;

	ksp_lockedmem = project_kstat_create_common(pj, "lockedmem",
	    zone->zone_name, project_lockedmem_kstat_update);
	ksp_nprocs = project_kstat_create_common(pj, "nprocs",
	    zone->zone_name, project_nprocs_kstat_update);

	mutex_enter(&project_hash_lock);
	ASSERT(pj->kpj_data.kpd_lockedmem_kstat == NULL);
	pj->kpj_data.kpd_lockedmem_kstat = ksp_lockedmem;
	ASSERT(pj->kpj_data.kpd_nprocs_kstat == NULL);
	pj->kpj_data.kpd_nprocs_kstat = ksp_nprocs;
	mutex_exit(&project_hash_lock);
}

static void
project_kstat_delete_common(kstat_t **kstat)
{
	void *data;

	if (*kstat != NULL) {
		data = (*kstat)->ks_data;
		kstat_delete(*kstat);
		kmem_free(data, sizeof (kproject_kstat_t));
		*kstat = NULL;
	}
}

static void
project_kstat_delete(kproject_t *pj)
{
	project_kstat_delete_common(&pj->kpj_data.kpd_lockedmem_kstat);
	project_kstat_delete_common(&pj->kpj_data.kpd_nprocs_kstat);
}
