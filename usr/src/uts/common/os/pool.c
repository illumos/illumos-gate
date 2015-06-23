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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/pool.h>
#include <sys/pool_impl.h>
#include <sys/pool_pset.h>
#include <sys/id_space.h>
#include <sys/mutex.h>
#include <sys/nvpair.h>
#include <sys/cpuvar.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/fss.h>
#include <sys/class.h>
#include <sys/exacct.h>
#include <sys/utsname.h>
#include <sys/procset.h>
#include <sys/atomic.h>
#include <sys/zone.h>
#include <sys/policy.h>
#include <sys/schedctl.h>
#include <sys/taskq.h>

/*
 * RESOURCE POOLS
 *
 * The resource pools facility brings together process-bindable resource into
 * a common abstraction called a pool. Processor sets and other entities can
 * be configured, grouped, and labelled such that workload components can be
 * associated with a subset of a system's total resources.
 *
 * When disabled, the pools facility is "invisible".  All processes belong
 * to the same pool (pool_default), and processor sets can be managed through
 * the old pset() system call.  When enabled, processor sets can only be
 * managed via the pools facility.  New pools can be created and associated
 * with processor sets.  Processes can be bound to pools which have non-empty
 * resource sets.
 *
 * Locking: pool_lock() protects global pools state and must be called
 * before modifying the configuration, or when taking a snapshot of the
 * configuration.  If pool_lock_intr() is used, the operation may be
 * interrupted by a signal or a request.
 *
 * To prevent processes from being rebound between pools while they are
 * the middle of an operation which affects resource set bindings, such
 * operations must be surrounded by calls to pool_barrier_enter() and
 * pool_barrier_exit().  This mechanism guarantees that such processes will
 * be stopped either at the beginning or at the end of the barrier so that
 * the rebind operation can atomically bind the process and its threads
 * to new resource sets, and then let process run again.
 *
 * Lock ordering with respect to other locks is as follows:
 *
 * 	pool_lock() -> cpu_lock -> pidlock -> p_lock -> pool_barrier_lock
 *
 * Most static and global variables defined in this file are protected
 * by calling pool_lock().
 *
 * The operation that binds tasks and projects to pools is atomic.  That is,
 * either all processes in a given task or a project will be bound to a
 * new pool, or (in case of an error) they will be all left bound to the
 * old pool. Processes in a given task or a given project can only be bound to
 * different pools if they were rebound individually one by one as single
 * processes.  Threads or LWPs of the same process do not have pool bindings,
 * and are bound to the same resource sets associated with the resource pool
 * of that process.
 *
 * The following picture shows one possible pool configuration with three
 * pools and three processor sets.  Note that processor set "foo" is not
 * associated with any pools and therefore cannot have any processes
 * bound to it.  Two pools (default and foo) are associated with the
 * same processor set (default).  Also, note that processes in Task 2
 * are bound to different pools.
 *
 *
 *							       Processor Sets
 *								+---------+
 *		       +--------------+========================>| default |
 *		      a|	      |				+---------+
 *		      s|	      |				    ||
 *		      s|	      |				+---------+
 *		      o|	      |				|   foo   |
 *		      c|	      |				+---------+
 *		      i|	      |				    ||
 *		      a|	      |				+---------+
 *		      t|	      |			+------>|   bar   |
 *		      e|	      |			|	+---------+
 *                    d|              |                 |
 *                     |              |                 |
 *	       +---------+      +---------+      +---------+
 *     Pools   | default |======|   foo   |======|   bar   |
 *	       +---------+      +---------+      +---------+
 *	           @  @            @              @ @   @
 *                b|  |            |              | |   |
 *                o|  |            |              | |   |
 *                u|  +-----+      |      +-------+ |   +---+
 *                n|        |      |      |         |       |
 *            ....d|........|......|......|.........|.......|....
 *            :    |   ::   |      |      |    ::   |       |   :
 *            :  +---+ :: +---+  +---+  +---+  :: +---+   +---+ :
 *  Processes :  | p | :: | p |  | p |  | p |  :: | p |...| p | :
 *            :  +---+ :: +---+  +---+  +---+  :: +---+   +---+ :
 *            :........::......................::...............:
 *              Task 1            Task 2              Task N
 *                 |                 |                  |
 *                 |                 |                  |
 *                 |  +-----------+  |             +-----------+
 *                 +--| Project 1 |--+             | Project N |
 *                    +-----------+                +-----------+
 *
 * This is just an illustration of relationships between processes, tasks,
 * projects, pools, and processor sets. New types of resource sets will be
 * added in the future.
 */

pool_t		*pool_default;	/* default pool which always exists */
int		pool_count;	/* number of pools created on this system */
int		pool_state;	/* pools state -- enabled/disabled */
void		*pool_buf;	/* pre-commit snapshot of the pools state */
size_t		pool_bufsz;	/* size of pool_buf */
static hrtime_t	pool_pool_mod;	/* last modification time for pools */
static hrtime_t	pool_sys_mod;	/* last modification time for system */
static nvlist_t	*pool_sys_prop;	/* system properties */
static id_space_t *pool_ids;	/* pool ID space */
static list_t	pool_list;	/* doubly-linked list of pools */
static kmutex_t		pool_mutex;		/* protects pool_busy_* */
static kcondvar_t	pool_busy_cv;		/* waiting for "pool_lock" */
static kthread_t	*pool_busy_thread;	/* thread holding "pool_lock" */
static kmutex_t		pool_barrier_lock;	/* synch. with pool_barrier_* */
static kcondvar_t	pool_barrier_cv;	/* synch. with pool_barrier_* */
static int		pool_barrier_count;	/* synch. with pool_barrier_* */
static list_t		pool_event_cb_list;	/* pool event callbacks */
static boolean_t	pool_event_cb_init = B_FALSE;
static kmutex_t		pool_event_cb_lock;
static taskq_t		*pool_event_cb_taskq = NULL;

void pool_event_dispatch(pool_event_t, poolid_t);

/*
 * Boot-time pool initialization.
 */
void
pool_init(void)
{
	pool_ids = id_space_create("pool_ids", POOL_DEFAULT + 1, POOL_MAXID);

	/*
	 * Initialize default pool.
	 */
	pool_default = kmem_zalloc(sizeof (pool_t), KM_SLEEP);
	pool_default->pool_id = POOL_DEFAULT;
	list_create(&pool_list, sizeof (pool_t), offsetof(pool_t, pool_link));
	list_insert_head(&pool_list, pool_default);

	/*
	 * Initialize plugins for resource sets.
	 */
	pool_pset_init();
	pool_count = 1;
	p0.p_pool = pool_default;
	global_zone->zone_pool = pool_default;
	pool_default->pool_ref = 1;
}

/*
 * Synchronization routines.
 *
 * pool_lock is only called from syscall-level routines (processor_bind(),
 * pset_*(), and /dev/pool ioctls).  The pool "lock" may be held for long
 * periods of time, including across sleeping operations, so we allow its
 * acquisition to be interruptible.
 *
 * The current thread that owns the "lock" is stored in the variable
 * pool_busy_thread, both to let pool_lock_held() work and to aid debugging.
 */
void
pool_lock(void)
{
	mutex_enter(&pool_mutex);
	ASSERT(!pool_lock_held());
	while (pool_busy_thread != NULL)
		cv_wait(&pool_busy_cv, &pool_mutex);
	pool_busy_thread = curthread;
	mutex_exit(&pool_mutex);
}

int
pool_lock_intr(void)
{
	mutex_enter(&pool_mutex);
	ASSERT(!pool_lock_held());
	while (pool_busy_thread != NULL) {
		if (cv_wait_sig(&pool_busy_cv, &pool_mutex) == 0) {
			cv_signal(&pool_busy_cv);
			mutex_exit(&pool_mutex);
			return (1);
		}
	}
	pool_busy_thread = curthread;
	mutex_exit(&pool_mutex);
	return (0);
}

int
pool_lock_held(void)
{
	return (pool_busy_thread == curthread);
}

void
pool_unlock(void)
{
	mutex_enter(&pool_mutex);
	ASSERT(pool_lock_held());
	pool_busy_thread = NULL;
	cv_signal(&pool_busy_cv);
	mutex_exit(&pool_mutex);
}

/*
 * Routines allowing fork(), exec(), exit(), and lwp_create() to synchronize
 * with pool_do_bind().
 *
 * Calls to pool_barrier_enter() and pool_barrier_exit() must bracket all
 * operations which modify pool or pset associations.  They can be called
 * while the process is multi-threaded.  In the common case, when current
 * process is not being rebound (PBWAIT flag is not set), these functions
 * will be just incrementing and decrementing reference counts.
 */
void
pool_barrier_enter(void)
{
	proc_t *p = curproc;

	ASSERT(MUTEX_HELD(&p->p_lock));
	while (p->p_poolflag & PBWAIT)
		cv_wait(&p->p_poolcv, &p->p_lock);
	p->p_poolcnt++;
}

void
pool_barrier_exit(void)
{
	proc_t *p = curproc;

	ASSERT(MUTEX_HELD(&p->p_lock));
	ASSERT(p->p_poolcnt > 0);
	p->p_poolcnt--;
	if (p->p_poolflag & PBWAIT) {
		mutex_enter(&pool_barrier_lock);
		ASSERT(pool_barrier_count > 0);
		pool_barrier_count--;
		if (pool_barrier_count == 0)
			cv_signal(&pool_barrier_cv);
		mutex_exit(&pool_barrier_lock);
		while (p->p_poolflag & PBWAIT)
			cv_wait(&p->p_poolcv, &p->p_lock);
	}
}

/*
 * Enable pools facility.
 */
static int
pool_enable(void)
{
	int ret;

	ASSERT(pool_lock_held());
	ASSERT(pool_count == 1);

	ret = pool_pset_enable();
	if (ret != 0)
		return (ret);
	(void) nvlist_alloc(&pool_sys_prop, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_string(pool_sys_prop, "system.name",
	    "default");
	(void) nvlist_add_string(pool_sys_prop, "system.comment", "");
	(void) nvlist_add_int64(pool_sys_prop, "system.version", 1);
	(void) nvlist_add_byte(pool_sys_prop, "system.bind-default", 1);
	(void) nvlist_add_string(pool_sys_prop, "system.poold.objectives",
	    "wt-load");

	(void) nvlist_alloc(&pool_default->pool_props,
	    NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_string(pool_default->pool_props,
	    "pool.name", "pool_default");
	(void) nvlist_add_string(pool_default->pool_props, "pool.comment", "");
	(void) nvlist_add_byte(pool_default->pool_props, "pool.default", 1);
	(void) nvlist_add_byte(pool_default->pool_props, "pool.active", 1);
	(void) nvlist_add_int64(pool_default->pool_props,
	    "pool.importance", 1);
	(void) nvlist_add_int64(pool_default->pool_props, "pool.sys_id",
	    pool_default->pool_id);

	pool_sys_mod = pool_pool_mod = gethrtime();

	return (ret);
}

/*
 * Disable pools facility.
 */
static int
pool_disable(void)
{
	int ret;

	ASSERT(pool_lock_held());

	if (pool_count > 1)	/* must destroy all pools first */
		return (EBUSY);

	ret = pool_pset_disable();
	if (ret != 0)
		return (ret);
	if (pool_sys_prop != NULL) {
		nvlist_free(pool_sys_prop);
		pool_sys_prop = NULL;
	}
	if (pool_default->pool_props != NULL) {
		nvlist_free(pool_default->pool_props);
		pool_default->pool_props = NULL;
	}
	return (0);
}

pool_t *
pool_lookup_pool_by_name(char *name)
{
	pool_t *pool = pool_default;
	char *p;

	ASSERT(pool_lock_held());
	for (pool = list_head(&pool_list); pool;
	    pool = list_next(&pool_list, pool)) {
		if (nvlist_lookup_string(pool->pool_props,
		    "pool.name", &p) == 0 && strcmp(name, p) == 0)
			return (pool);
	}
	return (NULL);
}

pool_t *
pool_lookup_pool_by_id(poolid_t poolid)
{
	pool_t *pool = pool_default;

	ASSERT(pool_lock_held());
	for (pool = list_head(&pool_list); pool;
	    pool = list_next(&pool_list, pool)) {
		if (pool->pool_id == poolid)
			return (pool);
	}
	return (NULL);
}

pool_t *
pool_lookup_pool_by_pset(int id)
{
	pool_t *pool = pool_default;
	psetid_t psetid = (psetid_t)id;

	ASSERT(pool_lock_held());
	for (pool = list_head(&pool_list); pool != NULL;
	    pool = list_next(&pool_list, pool)) {
		if (pool->pool_pset->pset_id == psetid)
			return (pool);
	}
	return (NULL);
}

/*
 * Create new pool, associate it with default resource sets, and give
 * it a temporary name.
 */
static int
pool_pool_create(poolid_t *poolid)
{
	pool_t *pool;
	char pool_name[40];

	ASSERT(pool_lock_held());

	pool = kmem_zalloc(sizeof (pool_t), KM_SLEEP);
	pool->pool_id = *poolid = id_alloc(pool_ids);
	pool->pool_pset = pool_pset_default;
	pool_pset_default->pset_npools++;
	list_insert_tail(&pool_list, pool);
	(void) nvlist_alloc(&pool->pool_props, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_int64(pool->pool_props, "pool.sys_id", pool->pool_id);
	(void) nvlist_add_byte(pool->pool_props, "pool.default", 0);
	pool_pool_mod = gethrtime();
	(void) snprintf(pool_name, sizeof (pool_name), "pool_%lld",
	    pool_pool_mod);
	(void) nvlist_add_string(pool->pool_props, "pool.name", pool_name);
	pool_count++;
	return (0);
}

struct destroy_zone_arg {
	pool_t *old;
	pool_t *new;
};

/*
 * Update pool pointers for zones that are currently bound to pool "old"
 * to be bound to pool "new".
 */
static int
pool_destroy_zone_cb(zone_t *zone, void *arg)
{
	struct destroy_zone_arg *dza = arg;

	ASSERT(pool_lock_held());
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (zone_pool_get(zone) == dza->old)
		zone_pool_set(zone, dza->new);
	return (0);
}

/*
 * Destroy specified pool, and rebind all processes in it
 * to the default pool.
 */
static int
pool_pool_destroy(poolid_t poolid)
{
	pool_t *pool;
	int ret;

	ASSERT(pool_lock_held());

	if (poolid == POOL_DEFAULT)
		return (EINVAL);
	if ((pool = pool_lookup_pool_by_id(poolid)) == NULL)
		return (ESRCH);
	ret = pool_do_bind(pool_default, P_POOLID, poolid, POOL_BIND_ALL);
	if (ret == 0) {
		struct destroy_zone_arg dzarg;

		dzarg.old = pool;
		dzarg.new = pool_default;
		mutex_enter(&cpu_lock);
		ret = zone_walk(pool_destroy_zone_cb, &dzarg);
		mutex_exit(&cpu_lock);
		ASSERT(ret == 0);
		ASSERT(pool->pool_ref == 0);
		(void) nvlist_free(pool->pool_props);
		id_free(pool_ids, pool->pool_id);
		pool->pool_pset->pset_npools--;
		list_remove(&pool_list, pool);
		pool_count--;
		pool_pool_mod = gethrtime();
		kmem_free(pool, sizeof (pool_t));
	}
	return (ret);
}

/*
 * Create new pool or resource set.
 */
int
pool_create(int class, int subclass, id_t *id)
{
	int ret;

	ASSERT(pool_lock_held());
	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	switch (class) {
	case PEC_POOL:
		ret = pool_pool_create((poolid_t *)id);
		break;
	case PEC_RES_COMP:
		switch (subclass) {
		case PREC_PSET:
			ret = pool_pset_create((psetid_t *)id);
			break;
		default:
			ret = EINVAL;
		}
		break;
	case PEC_RES_AGG:
		ret = ENOTSUP;
		break;
	default:
		ret = EINVAL;
	}
	return (ret);
}

/*
 * Destroy an existing pool or resource set.
 */
int
pool_destroy(int class, int subclass, id_t id)
{
	int ret;

	ASSERT(pool_lock_held());
	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	switch (class) {
	case PEC_POOL:
		ret = pool_pool_destroy((poolid_t)id);
		break;
	case PEC_RES_COMP:
		switch (subclass) {
		case PREC_PSET:
			ret = pool_pset_destroy((psetid_t)id);
			break;
		default:
			ret = EINVAL;
		}
		break;
	case PEC_RES_AGG:
		ret = ENOTSUP;
		break;
	default:
		ret = EINVAL;
	}
	return (ret);
}

/*
 * Enable or disable pools.
 */
int
pool_status(int status)
{
	int ret = 0;

	ASSERT(pool_lock_held());

	if (pool_state == status)
		return (0);
	switch (status) {
	case POOL_ENABLED:
		ret = pool_enable();
		if (ret != 0)
			return (ret);
		pool_state = POOL_ENABLED;
		pool_event_dispatch(POOL_E_ENABLE, NULL);
		break;
	case POOL_DISABLED:
		ret = pool_disable();
		if (ret != 0)
			return (ret);
		pool_state = POOL_DISABLED;
		pool_event_dispatch(POOL_E_DISABLE, NULL);
		break;
	default:
		ret = EINVAL;
	}
	return (ret);
}

/*
 * Associate pool with resource set.
 */
int
pool_assoc(poolid_t poolid, int idtype, id_t id)
{
	int ret;

	ASSERT(pool_lock_held());
	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	switch (idtype) {
	case PREC_PSET:
		ret = pool_pset_assoc(poolid, (psetid_t)id);
		if (ret == 0)
			pool_event_dispatch(POOL_E_CHANGE, poolid);
		break;
	default:
		ret = EINVAL;
	}
	if (ret == 0)
		pool_pool_mod = gethrtime();
	return (ret);
}

/*
 * Disassociate resource set from pool.
 */
int
pool_dissoc(poolid_t poolid, int idtype)
{
	int ret;

	ASSERT(pool_lock_held());
	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	switch (idtype) {
	case PREC_PSET:
		ret = pool_pset_assoc(poolid, PS_NONE);
		if (ret == 0)
			pool_event_dispatch(POOL_E_CHANGE, poolid);
		break;
	default:
		ret = EINVAL;
	}
	if (ret == 0)
		pool_pool_mod = gethrtime();
	return (ret);
}

/*
 * Transfer specified quantity of resources between resource sets.
 */
/*ARGSUSED*/
int
pool_transfer(int type, id_t src, id_t dst, uint64_t qty)
{
	int ret = EINVAL;

	return (ret);
}

static poolid_t
pool_lookup_id_by_pset(int id)
{
	pool_t *pool = pool_default;
	psetid_t psetid = (psetid_t)id;

	ASSERT(pool_lock_held());
	for (pool = list_head(&pool_list); pool != NULL;
	    pool = list_next(&pool_list, pool)) {
		if (pool->pool_pset->pset_id == psetid)
			return (pool->pool_id);
	}
	return (POOL_INVALID);
}

/*
 * Transfer resources specified by their IDs between resource sets.
 */
int
pool_xtransfer(int type, id_t src_pset, id_t dst_pset, uint_t size, id_t *ids)
{
	int ret;
	poolid_t src_pool, dst_pool;

	ASSERT(pool_lock_held());
	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	switch (type) {
	case PREC_PSET:
		ret = pool_pset_xtransfer((psetid_t)src_pset,
		    (psetid_t)dst_pset, size, ids);
		if (ret == 0) {
			if ((src_pool =  pool_lookup_id_by_pset(src_pset)) !=
			    POOL_INVALID)
				pool_event_dispatch(POOL_E_CHANGE, src_pool);
			if ((dst_pool =  pool_lookup_id_by_pset(dst_pset)) !=
			    POOL_INVALID)
				pool_event_dispatch(POOL_E_CHANGE, dst_pool);
		}
		break;
	default:
		ret = EINVAL;
	}
	return (ret);
}

/*
 * Bind processes to pools.
 */
int
pool_bind(poolid_t poolid, idtype_t idtype, id_t id)
{
	pool_t	*pool;

	ASSERT(pool_lock_held());

	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	if ((pool = pool_lookup_pool_by_id(poolid)) == NULL)
		return (ESRCH);

	switch (idtype) {
	case P_PID:
	case P_TASKID:
	case P_PROJID:
	case P_ZONEID:
		break;
	default:
		return (EINVAL);
	}
	return (pool_do_bind(pool, idtype, id, POOL_BIND_ALL));
}

/*
 * Query pool binding of the specifed process.
 */
int
pool_query_binding(idtype_t idtype, id_t id, id_t *poolid)
{
	proc_t *p;

	if (idtype != P_PID)
		return (ENOTSUP);
	if (id == P_MYID)
		id = curproc->p_pid;

	ASSERT(pool_lock_held());

	mutex_enter(&pidlock);
	if ((p = prfind((pid_t)id)) == NULL) {
		mutex_exit(&pidlock);
		return (ESRCH);
	}
	mutex_enter(&p->p_lock);
	/*
	 * In local zones, lie about pool bindings of processes from
	 * the global zone.
	 */
	if (!INGLOBALZONE(curproc) && INGLOBALZONE(p)) {
		pool_t *pool;

		pool = zone_pool_get(curproc->p_zone);
		*poolid = pool->pool_id;
	} else {
		*poolid = p->p_pool->pool_id;
	}
	mutex_exit(&p->p_lock);
	mutex_exit(&pidlock);
	return (0);
}

static ea_object_t *
pool_system_pack(void)
{
	ea_object_t *eo_system;
	size_t bufsz = 0;
	char *buf = NULL;

	ASSERT(pool_lock_held());

	eo_system = ea_alloc_group(EXT_GROUP | EXC_LOCAL | EXD_GROUP_SYSTEM);
	(void) ea_attach_item(eo_system, &pool_sys_mod, sizeof (hrtime_t),
	    EXC_LOCAL | EXD_SYSTEM_TSTAMP | EXT_UINT64);
	if (INGLOBALZONE(curproc))
		(void) ea_attach_item(eo_system, &pool_pool_mod,
		    sizeof (hrtime_t),
		    EXC_LOCAL | EXD_POOL_TSTAMP | EXT_UINT64);
	else
		(void) ea_attach_item(eo_system,
		    &curproc->p_zone->zone_pool_mod,
		    sizeof (hrtime_t),
		    EXC_LOCAL | EXD_POOL_TSTAMP | EXT_UINT64);
	(void) ea_attach_item(eo_system, &pool_pset_mod, sizeof (hrtime_t),
	    EXC_LOCAL | EXD_PSET_TSTAMP | EXT_UINT64);
	(void) ea_attach_item(eo_system, &pool_cpu_mod, sizeof (hrtime_t),
	    EXC_LOCAL | EXD_CPU_TSTAMP | EXT_UINT64);
	(void) nvlist_pack(pool_sys_prop, &buf, &bufsz, NV_ENCODE_NATIVE, 0);
	(void) ea_attach_item(eo_system, buf, bufsz,
	    EXC_LOCAL | EXD_SYSTEM_PROP | EXT_RAW);
	kmem_free(buf, bufsz);
	return (eo_system);
}

/*
 * Pack information about pools and attach it to specified exacct group.
 */
static int
pool_pool_pack(ea_object_t *eo_system)
{
	ea_object_t *eo_pool;
	pool_t *pool;
	size_t bufsz;
	char *buf;
	pool_t *myzonepool;

	ASSERT(pool_lock_held());
	myzonepool = zone_pool_get(curproc->p_zone);
	for (pool = list_head(&pool_list); pool;
	    pool = list_next(&pool_list, pool)) {
		if (!INGLOBALZONE(curproc) && myzonepool != pool)
			continue;
		bufsz = 0;
		buf = NULL;
		eo_pool = ea_alloc_group(EXT_GROUP |
		    EXC_LOCAL | EXD_GROUP_POOL);
		(void) ea_attach_item(eo_pool, &pool->pool_id, sizeof (id_t),
		    EXC_LOCAL | EXD_POOL_POOLID | EXT_UINT32);
		(void) ea_attach_item(eo_pool, &pool->pool_pset->pset_id,
		    sizeof (id_t), EXC_LOCAL | EXD_POOL_PSETID | EXT_UINT32);
		(void) nvlist_pack(pool->pool_props, &buf, &bufsz,
		    NV_ENCODE_NATIVE, 0);
		(void) ea_attach_item(eo_pool, buf, bufsz,
		    EXC_LOCAL | EXD_POOL_PROP | EXT_RAW);
		kmem_free(buf, bufsz);
		(void) ea_attach_to_group(eo_system, eo_pool);
	}
	return (0);
}

/*
 * Pack the whole pool configuration in the specified buffer.
 */
int
pool_pack_conf(void *kbuf, size_t kbufsz, size_t *asize)
{
	ea_object_t *eo_system;
	size_t ksize;
	int ret = 0;

	ASSERT(pool_lock_held());

	eo_system = pool_system_pack();		/* 1. pack system */
	(void) pool_pool_pack(eo_system);	/* 2. pack all pools */
	(void) pool_pset_pack(eo_system);	/* 3. pack all psets */
	ksize = ea_pack_object(eo_system, NULL, 0);
	if (kbuf == NULL || kbufsz == 0)
		*asize = ksize;
	else if (ksize > kbufsz)
		ret = ENOMEM;
	else
		*asize = ea_pack_object(eo_system, kbuf, kbufsz);
	ea_free_object(eo_system, EUP_ALLOC);
	return (ret);
}

/*
 * Start/end the commit transaction.  If commit transaction is currently
 * in progress, then all POOL_QUERY ioctls will return pools configuration
 * at the beginning of transaction.
 */
int
pool_commit(int state)
{
	ea_object_t *eo_system;
	int ret = 0;

	ASSERT(pool_lock_held());

	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	switch (state) {
	case 1:
		/*
		 * Beginning commit transation.
		 */
		if (pool_buf != NULL)		/* transaction in progress */
			return (EBUSY);
		eo_system = pool_system_pack();		/* 1. pack system */
		(void) pool_pool_pack(eo_system);	/* 2. pack all pools */
		(void) pool_pset_pack(eo_system);	/* 3. pack all psets */
		pool_bufsz = ea_pack_object(eo_system, NULL, 0);
		pool_buf = kmem_alloc(pool_bufsz, KM_SLEEP);
		pool_bufsz = ea_pack_object(eo_system, pool_buf, pool_bufsz);
		ea_free_object(eo_system, EUP_ALLOC);
		break;
	case 0:
		/*
		 * Finishing commit transaction.
		 */
		if (pool_buf != NULL) {
			kmem_free(pool_buf, pool_bufsz);
			pool_buf = NULL;
			pool_bufsz = 0;
		}
		break;
	default:
		ret = EINVAL;
	}
	return (ret);
}

/*
 * Check is the specified property is special
 */
static pool_property_t *
pool_property_find(char *name, pool_property_t *list)
{
	pool_property_t *prop;

	for (prop = list; prop->pp_name != NULL; prop++)
		if (strcmp(prop->pp_name, name) == 0)
			return (prop);
	return (NULL);
}

static pool_property_t pool_prop_sys[] = {
	{ "system.name",		DATA_TYPE_STRING,	PP_RDWR },
	{ "system.comment",		DATA_TYPE_STRING,	PP_RDWR },
	{ "system.version",		DATA_TYPE_UINT64,	PP_READ },
	{ "system.bind-default",	DATA_TYPE_BYTE,		PP_RDWR },
	{ "system.allocate-method",	DATA_TYPE_STRING,
	    PP_RDWR | PP_OPTIONAL },
	{ "system.poold.log-level",	DATA_TYPE_STRING,
	    PP_RDWR | PP_OPTIONAL },
	{ "system.poold.log-location",	DATA_TYPE_STRING,
	    PP_RDWR | PP_OPTIONAL },
	{ "system.poold.monitor-interval",	DATA_TYPE_UINT64,
	    PP_RDWR | PP_OPTIONAL },
	{ "system.poold.history-file",	DATA_TYPE_STRING,
	    PP_RDWR | PP_OPTIONAL },
	{ "system.poold.objectives",	DATA_TYPE_STRING,
	    PP_RDWR | PP_OPTIONAL },
	{ NULL,				0,			0 }
};

static pool_property_t pool_prop_pool[] = {
	{ "pool.sys_id",		DATA_TYPE_UINT64,	PP_READ },
	{ "pool.name",			DATA_TYPE_STRING,	PP_RDWR },
	{ "pool.default",		DATA_TYPE_BYTE,		PP_READ },
	{ "pool.active",		DATA_TYPE_BYTE,		PP_RDWR },
	{ "pool.importance",		DATA_TYPE_INT64,	PP_RDWR },
	{ "pool.comment",		DATA_TYPE_STRING,	PP_RDWR },
	{ "pool.scheduler",		DATA_TYPE_STRING,
	    PP_RDWR | PP_OPTIONAL },
	{ NULL,				0,			0 }
};

/*
 * Common routine to put new property on the specified list
 */
int
pool_propput_common(nvlist_t *nvlist, nvpair_t *pair, pool_property_t *props)
{
	pool_property_t *prop;

	if ((prop = pool_property_find(nvpair_name(pair), props)) != NULL) {
		/*
		 * No read-only properties or properties with bad types
		 */
		if (!(prop->pp_perm & PP_WRITE) ||
		    prop->pp_type != nvpair_type(pair))
			return (EINVAL);
	}
	return (nvlist_add_nvpair(nvlist, pair));
}

/*
 * Common routine to remove property from the given list
 */
int
pool_proprm_common(nvlist_t *nvlist, char *name, pool_property_t *props)
{
	pool_property_t *prop;

	if ((prop = pool_property_find(name, props)) != NULL) {
		if (!(prop->pp_perm & PP_OPTIONAL))
			return (EINVAL);
	}
	return (nvlist_remove_all(nvlist, name));
}

static int
pool_system_propput(nvpair_t *pair)
{
	int ret;

	ASSERT(pool_lock_held());
	ret = pool_propput_common(pool_sys_prop, pair, pool_prop_sys);
	if (ret == 0)
		pool_sys_mod = gethrtime();
	return (ret);
}

static int
pool_system_proprm(char *name)
{
	int ret;

	ASSERT(pool_lock_held());
	ret = pool_proprm_common(pool_sys_prop, name, pool_prop_sys);
	if (ret == 0)
		pool_sys_mod = gethrtime();
	return (ret);
}

static int
pool_pool_propput(poolid_t poolid, nvpair_t *pair)
{
	pool_t *pool;
	int ret;

	ASSERT(pool_lock_held());
	if ((pool = pool_lookup_pool_by_id(poolid)) == NULL)
		return (ESRCH);
	ret = pool_propput_common(pool->pool_props, pair, pool_prop_pool);
	if (ret == 0)
		pool_pool_mod = gethrtime();
	return (ret);
}

static int
pool_pool_proprm(poolid_t poolid, char *name)
{
	int ret;
	pool_t *pool;

	ASSERT(pool_lock_held());
	if ((pool = pool_lookup_pool_by_id(poolid)) == NULL)
		return (ESRCH);
	ret = pool_proprm_common(pool->pool_props, name, pool_prop_pool);
	if (ret == 0)
		pool_pool_mod = gethrtime();
	return (ret);
}

int
pool_propput(int class, int subclass, id_t id, nvpair_t *pair)
{
	int ret;

	ASSERT(pool_lock_held());
	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	switch (class) {
	case PEC_SYSTEM:
		ret = pool_system_propput(pair);
		break;
	case PEC_POOL:
		ret = pool_pool_propput((poolid_t)id, pair);
		break;
	case PEC_RES_COMP:
		switch (subclass) {
		case PREC_PSET:
			ret = pool_pset_propput((psetid_t)id, pair);
			break;
		default:
			ret = EINVAL;
		}
		break;
	case PEC_RES_AGG:
		ret = ENOTSUP;
		break;
	case PEC_COMP:
		switch (subclass) {
		case PCEC_CPU:
			ret = pool_cpu_propput((processorid_t)id, pair);
			break;
		default:
			ret = EINVAL;
		}
		break;
	default:
		ret = EINVAL;
	}
	return (ret);
}

int
pool_proprm(int class, int subclass, id_t id, char *name)
{
	int ret;

	ASSERT(pool_lock_held());
	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);
	switch (class) {
	case PEC_SYSTEM:
		ret = pool_system_proprm(name);
		break;
	case PEC_POOL:
		ret = pool_pool_proprm((poolid_t)id, name);
		break;
	case PEC_RES_COMP:
		switch (subclass) {
		case PREC_PSET:
			ret = pool_pset_proprm((psetid_t)id, name);
			break;
		default:
			ret = EINVAL;
		}
		break;
	case PEC_RES_AGG:
		ret = ENOTSUP;
		break;
	case PEC_COMP:
		switch (subclass) {
		case PCEC_CPU:
			ret = pool_cpu_proprm((processorid_t)id, name);
			break;
		default:
			ret = EINVAL;
		}
		break;
	default:
		ret = EINVAL;
	}
	return (ret);
}

int
pool_propget(char *name, int class, int subclass, id_t id, nvlist_t **nvlp)
{
	int ret;
	nvlist_t *nvl;

	ASSERT(pool_lock_held());
	if (pool_state == POOL_DISABLED)
		return (ENOTACTIVE);

	(void) nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);

	switch (class) {
	case PEC_SYSTEM:
	case PEC_POOL:
		ret = EINVAL;
		break;
	case PEC_RES_COMP:
		switch (subclass) {
		case PREC_PSET:
			ret = pool_pset_propget((psetid_t)id, name, nvl);
			break;
		default:
			ret = EINVAL;
		}
		break;
	case PEC_RES_AGG:
		ret = ENOTSUP;
		break;
	case PEC_COMP:
		switch (subclass) {
		case PCEC_CPU:
			ret = pool_cpu_propget((processorid_t)id, name, nvl);
			break;
		default:
			ret = EINVAL;
		}
		break;
	default:
		ret = EINVAL;
	}
	if (ret == 0)
		*nvlp = nvl;
	else
		nvlist_free(nvl);
	return (ret);
}

/*
 * pool_bind_wake and pool_bind_wakeall are helper functions to undo PBWAITs
 * in case of failure in pool_do_bind().
 */
static void
pool_bind_wake(proc_t *p)
{
	ASSERT(pool_lock_held());

	mutex_enter(&p->p_lock);
	ASSERT(p->p_poolflag & PBWAIT);
	if (p->p_poolcnt > 0) {
		mutex_enter(&pool_barrier_lock);
		pool_barrier_count -= p->p_poolcnt;
		mutex_exit(&pool_barrier_lock);
	}
	p->p_poolflag &= ~PBWAIT;
	cv_signal(&p->p_poolcv);
	mutex_exit(&p->p_lock);
}

static void
pool_bind_wakeall(proc_t **procs)
{
	proc_t *p, **pp;

	ASSERT(pool_lock_held());
	for (pp = procs; (p = *pp) != NULL; pp++)
		pool_bind_wake(p);
}

/*
 * Return the scheduling class for this pool, or
 * 	POOL_CLASS_UNSET if not set
 * 	POOL_CLASS_INVAL if set to an invalid class ID.
 */
id_t
pool_get_class(pool_t *pool)
{
	char *name;
	id_t cid;

	ASSERT(pool_lock_held());

	if (nvlist_lookup_string(pool->pool_props, "pool.scheduler",
	    &name) == 0) {
		if (getcidbyname(name, &cid) == 0)
			return (cid);
		else
			return (POOL_CLASS_INVAL);
	}
	return (POOL_CLASS_UNSET);
}

/*
 * Move process to the new scheduling class.
 */
static void
pool_change_class(proc_t *p, id_t cid)
{
	kthread_t *t;
	void *cldata;
	id_t oldcid;
	void **bufs;
	void **buf;
	int nlwp;
	int ret;
	int i;

	/*
	 * Do not move kernel processes (such as zsched).
	 */
	if (p->p_flag & SSYS)
		return;
	/*
	 * This process is in the pool barrier, so it can't possibly be
	 * adding new threads and we can use p_lwpcnt + p_zombcnt + 1
	 * (for possible agent LWP which doesn't use pool barrier) as
	 * our upper bound.
	 */
	nlwp = p->p_lwpcnt + p->p_zombcnt + 1;

	/*
	 * Pre-allocate scheduling class specific buffers before
	 * grabbing p_lock.
	 */
	bufs = kmem_zalloc(nlwp * sizeof (void *), KM_SLEEP);
	for (i = 0, buf = bufs; i < nlwp; i++, buf++) {
		ret = CL_ALLOC(buf, cid, KM_SLEEP);
		ASSERT(ret == 0);
	}

	/*
	 * Move threads one by one to the new scheduling class.
	 * This never fails because we have all the right
	 * privileges here.
	 */
	mutex_enter(&p->p_lock);
	ASSERT(p->p_poolflag & PBWAIT);
	buf = bufs;
	t = p->p_tlist;
	ASSERT(t != NULL);
	do {
		if (t->t_cid != cid) {
			oldcid = t->t_cid;
			cldata = t->t_cldata;
			ret = CL_ENTERCLASS(t, cid, NULL, NULL, *buf);
			ASSERT(ret == 0);
			CL_EXITCLASS(oldcid, cldata);
			schedctl_set_cidpri(t);
			*buf++ = NULL;
		}
	} while ((t = t->t_forw) != p->p_tlist);
	mutex_exit(&p->p_lock);
	/*
	 * Free unused scheduling class specific buffers.
	 */
	for (i = 0, buf = bufs; i < nlwp; i++, buf++) {
		if (*buf != NULL) {
			CL_FREE(cid, *buf);
			*buf = NULL;
		}
	}
	kmem_free(bufs, nlwp * sizeof (void *));
}

void
pool_get_name(pool_t *pool, char **name)
{
	ASSERT(pool_lock_held());

	(void) nvlist_lookup_string(pool->pool_props, "pool.name", name);

	ASSERT(strlen(*name) != 0);
}


/*
 * The meat of the bind operation.  The steps in pool_do_bind are:
 *
 * 1) Set PBWAIT in the p_poolflag of any process of interest, and add all
 *    such processes to an array.  For any interesting process that has
 *    threads inside the pool barrier set, increment a counter by the
 *    count of such threads.  Once PBWAIT is set on a process, that process
 *    will not disappear.
 *
 * 2) Wait for the counter from step 2 to drop to zero.  Any process which
 *    calls pool_barrier_exit() and notices that PBWAIT has been set on it
 *    will decrement that counter before going to sleep, and the process
 *    calling pool_barrier_exit() which does the final decrement will wake us.
 *
 * 3) For each interesting process, perform a calculation on it to see if
 *    the bind will actually succeed.  This uses the following three
 *    resource-set-specific functions:
 *
 *    - int set_bind_start(procs, pool)
 *
 *      Determine whether the given array of processes can be bound to the
 *      resource set associated with the given pool.  If it can, take and hold
 *      any locks necessary to ensure that the operation will succeed, and
 *      make any necessary reservations in the target resource set.  If it
 *      can't, return failure with no reservations made and no new locks held.
 *
 *    - void set_bind_abort(procs, pool)
 *
 *      set_bind_start() has completed successfully, but another resource set's
 *      set_bind_start() has failed, and we haven't begun the bind yet.  Undo
 *      any reservations made and drop any locks acquired by our
 *      set_bind_start().
 *
 *    - void set_bind_finish(void)
 *
 *      The bind has completed successfully.  The processes have been released,
 *      and the reservation acquired in set_bind_start() has been depleted as
 *      the processes have finished their bindings.  Drop any locks acquired by
 *      set_bind_start().
 *
 * 4) If we've decided that we can proceed with the bind, iterate through
 *    the list of interesting processes, grab the necessary locks (which
 *    may differ per resource set), perform the bind, and ASSERT that it
 *    succeeds.  Once a process has been rebound, it can be awakened.
 *
 * The operations from step 4 must be kept in sync with anything which might
 * cause the bind operations (e.g., cpupart_bind_thread()) to fail, and
 * are thus located in the same source files as the associated bind operations.
 */
int
pool_do_bind(pool_t *pool, idtype_t idtype, id_t id, int flags)
{
	extern uint_t nproc;
	klwp_t *lwp = ttolwp(curthread);
	proc_t **pp, **procs;
	proc_t *prstart;
	int procs_count = 0;
	kproject_t *kpj;
	procset_t set;
	zone_t *zone;
	int procs_size;
	int rv = 0;
	proc_t *p;
	id_t cid = -1;

	ASSERT(pool_lock_held());

	if ((cid = pool_get_class(pool)) == POOL_CLASS_INVAL)
		return (EINVAL);

	if (idtype == P_ZONEID) {
		zone = zone_find_by_id(id);
		if (zone == NULL)
			return (ESRCH);
		if (zone_status_get(zone) > ZONE_IS_RUNNING) {
			zone_rele(zone);
			return (EBUSY);
		}
	}

	if (idtype == P_PROJID) {
		kpj = project_hold_by_id(id, global_zone, PROJECT_HOLD_FIND);
		if (kpj == NULL)
			return (ESRCH);
		mutex_enter(&kpj->kpj_poolbind);
	}

	if (idtype == P_PID) {
		/*
		 * Fast-path for a single process case.
		 */
		procs_size = 2;	/* procs is NULL-terminated */
		procs = kmem_zalloc(procs_size * sizeof (proc_t *), KM_SLEEP);
		mutex_enter(&pidlock);
	} else {
		/*
		 * We will need enough slots for proc_t pointers for as many as
		 * twice the number of currently running processes (assuming
		 * that each one could be in fork() creating a new child).
		 */
		for (;;) {
			procs_size = nproc * 2;
			procs = kmem_zalloc(procs_size * sizeof (proc_t *),
			    KM_SLEEP);
			mutex_enter(&pidlock);

			if (nproc * 2 <= procs_size)
				break;
			/*
			 * If nproc has changed, try again.
			 */
			mutex_exit(&pidlock);
			kmem_free(procs, procs_size * sizeof (proc_t *));
		}
	}

	if (id == P_MYID)
		id = getmyid(idtype);
	setprocset(&set, POP_AND, idtype, id, P_ALL, 0);

	/*
	 * Do a first scan, and select target processes.
	 */
	if (idtype == P_PID)
		prstart = prfind(id);
	else
		prstart = practive;
	for (p = prstart, pp = procs; p != NULL; p = p->p_next) {
		mutex_enter(&p->p_lock);
		/*
		 * Skip processes that don't match our (id, idtype) set or
		 * on the way of becoming zombies.  Skip kernel processes
		 * from the global zone.
		 */
		if (procinset(p, &set) == 0 ||
		    p->p_poolflag & PEXITED ||
		    ((p->p_flag & SSYS) && INGLOBALZONE(p))) {
			mutex_exit(&p->p_lock);
			continue;
		}
		if (!INGLOBALZONE(p)) {
			switch (idtype) {
			case P_PID:
			case P_TASKID:
				/*
				 * Can't bind processes or tasks
				 * in local zones to pools.
				 */
				mutex_exit(&p->p_lock);
				mutex_exit(&pidlock);
				pool_bind_wakeall(procs);
				rv = EINVAL;
				goto out;
			case P_PROJID:
				/*
				 * Only projects in the global
				 * zone can be rebound.
				 */
				mutex_exit(&p->p_lock);
				continue;
			case P_POOLID:
				/*
				 * When rebinding pools, processes can be
				 * in different zones.
				 */
				break;
			}
		}

		p->p_poolflag |= PBWAIT;
		/*
		 * If some threads in this process are inside the pool
		 * barrier, add them to pool_barrier_count, as we have
		 * to wait for all of them to exit the barrier.
		 */
		if (p->p_poolcnt > 0) {
			mutex_enter(&pool_barrier_lock);
			pool_barrier_count += p->p_poolcnt;
			mutex_exit(&pool_barrier_lock);
		}
		ASSERT(pp < &procs[procs_size]);
		*pp++ = p;
		procs_count++;
		mutex_exit(&p->p_lock);

		/*
		 * We just found our process, so if we're only rebinding a
		 * single process then get out of this loop.
		 */
		if (idtype == P_PID)
			break;
	}
	*pp = NULL;	/* cap off the end of the array */
	mutex_exit(&pidlock);

	/*
	 * Wait for relevant processes to stop before they try to enter the
	 * barrier or at the exit from the barrier.  Make sure that we do
	 * not get stopped here while we're holding pool_lock.  If we were
	 * requested to stop, or got a signal then return EAGAIN to let the
	 * library know that it needs to retry.
	 */
	mutex_enter(&pool_barrier_lock);
	lwp->lwp_nostop++;
	while (pool_barrier_count > 0) {
		(void) cv_wait_sig(&pool_barrier_cv, &pool_barrier_lock);
		if (pool_barrier_count > 0) {
			/*
			 * We either got a signal or were requested to
			 * stop by /proc.  Bail out with EAGAIN.  If we were
			 * requested to stop, we'll stop in post_syscall()
			 * on our way back to userland.
			 */
			mutex_exit(&pool_barrier_lock);
			pool_bind_wakeall(procs);
			lwp->lwp_nostop--;
			rv = EAGAIN;
			goto out;
		}
	}
	lwp->lwp_nostop--;
	mutex_exit(&pool_barrier_lock);

	if (idtype == P_PID) {
		if ((p = *procs) == NULL)
			goto skip;
		mutex_enter(&p->p_lock);
		/* Drop the process if it is exiting */
		if (p->p_poolflag & PEXITED) {
			mutex_exit(&p->p_lock);
			pool_bind_wake(p);
			procs_count--;
		} else
			mutex_exit(&p->p_lock);
		goto skip;
	}

	/*
	 * Do another run, and drop processes that were inside the barrier
	 * in exit(), but when they have dropped to pool_barrier_exit
	 * they have become of no interest to us.  Pick up child processes that
	 * were created by fork() but didn't exist during our first scan.
	 * Their parents are now stopped at pool_barrier_exit in cfork().
	 */
	mutex_enter(&pidlock);
	for (pp = procs; (p = *pp) != NULL; pp++) {
		mutex_enter(&p->p_lock);
		if (p->p_poolflag & PEXITED) {
			ASSERT(p->p_lwpcnt == 0);
			mutex_exit(&p->p_lock);
			pool_bind_wake(p);
			/* flip w/last non-NULL slot */
			*pp = procs[procs_count - 1];
			procs[procs_count - 1] = NULL;
			procs_count--;
			pp--;			/* try this slot again */
			continue;
		} else
			mutex_exit(&p->p_lock);
		/*
		 * Look at the child and check if it should be rebound also.
		 * We're holding pidlock, so it is safe to reference p_child.
		 */
		if ((p = p->p_child) == NULL)
			continue;

		mutex_enter(&p->p_lock);

		/*
		 * Skip system processes and make sure that the child is in
		 * the same task/project/pool/zone as the parent.
		 */
		if ((!INGLOBALZONE(p) && idtype != P_ZONEID &&
		    idtype != P_POOLID) || p->p_flag & SSYS) {
			mutex_exit(&p->p_lock);
			continue;
		}

		/*
		 * If the child process has been already created by fork(), has
		 * not exited, and has not been added to the list already,
		 * then add it now.  We will hit this process again (since we
		 * stick it at the end of the procs list) but it will ignored
		 * because it will have the PBWAIT flag set.
		 */
		if (procinset(p, &set) &&
		    !(p->p_poolflag & PEXITED) &&
		    !(p->p_poolflag & PBWAIT)) {
			ASSERT(p->p_child == NULL); /* no child of a child */
			procs[procs_count] = p;
			procs[procs_count + 1] = NULL;
			procs_count++;
			p->p_poolflag |= PBWAIT;
		}
		mutex_exit(&p->p_lock);
	}
	mutex_exit(&pidlock);
skip:
	/*
	 * If there's no processes to rebind then return ESRCH, unless
	 * we're associating a pool with new resource set, destroying it,
	 * or binding a zone to a pool.
	 */
	if (procs_count == 0) {
		if (idtype == P_POOLID || idtype == P_ZONEID)
			rv = 0;
		else
			rv = ESRCH;
		goto out;
	}

#ifdef DEBUG
	/*
	 * All processes in the array should have PBWAIT set, and none
	 * should be in the critical section. Thus, although p_poolflag
	 * and p_poolcnt are protected by p_lock, their ASSERTions below
	 * should be stable without it. procinset(), however, ASSERTs that
	 * the p_lock is held upon entry.
	 */
	for (pp = procs; (p = *pp) != NULL; pp++) {
		int in_set;

		mutex_enter(&p->p_lock);
		in_set = procinset(p, &set);
		mutex_exit(&p->p_lock);

		ASSERT(in_set);
		ASSERT(p->p_poolflag & PBWAIT);
		ASSERT(p->p_poolcnt == 0);
	}
#endif

	/*
	 * Do the check if processor set rebinding is going to succeed or not.
	 */
	if ((flags & POOL_BIND_PSET) &&
	    (rv = pset_bind_start(procs, pool)) != 0) {
		pool_bind_wakeall(procs);
		goto out;
	}

	/*
	 * At this point, all bind operations should succeed.
	 */
	for (pp = procs; (p = *pp) != NULL; pp++) {
		if (flags & POOL_BIND_PSET) {
			psetid_t psetid = pool->pool_pset->pset_id;
			void *zonebuf;
			void *projbuf;

			/*
			 * Pre-allocate one buffer for FSS (per-project
			 * buffer for a new pset) in case if this is the
			 * first thread from its current project getting
			 * bound to this processor set.
			 */
			projbuf = fss_allocbuf(FSS_ONE_BUF, FSS_ALLOC_PROJ);
			zonebuf = fss_allocbuf(FSS_ONE_BUF, FSS_ALLOC_ZONE);

			mutex_enter(&pidlock);
			mutex_enter(&p->p_lock);
			pool_pset_bind(p, psetid, projbuf, zonebuf);
			mutex_exit(&p->p_lock);
			mutex_exit(&pidlock);
			/*
			 * Free buffers pre-allocated above if it
			 * wasn't actually used.
			 */
			fss_freebuf(projbuf, FSS_ALLOC_PROJ);
			fss_freebuf(zonebuf, FSS_ALLOC_ZONE);
		}
		/*
		 * Now let's change the scheduling class of this
		 * process if our target pool has it defined.
		 */
		if (cid != POOL_CLASS_UNSET)
			pool_change_class(p, cid);

		/*
		 * It is safe to reference p_pool here without holding
		 * p_lock because it cannot change underneath of us.
		 * We're holding pool_lock here, so nobody else can be
		 * moving this process between pools.  If process "p"
		 * would be exiting, we're guaranteed that it would be blocked
		 * at pool_barrier_enter() in exit().  Otherwise, it would've
		 * been skipped by one of our scans of the practive list
		 * as a process with PEXITED flag set.
		 */
		if (p->p_pool != pool) {
			ASSERT(p->p_pool->pool_ref > 0);
			atomic_dec_32(&p->p_pool->pool_ref);
			p->p_pool = pool;
			atomic_inc_32(&p->p_pool->pool_ref);
		}
		/*
		 * Okay, we've tortured this guy enough.
		 * Let this poor process go now.
		 */
		pool_bind_wake(p);
	}
	if (flags & POOL_BIND_PSET)
		pset_bind_finish();

out:	switch (idtype) {
	case P_PROJID:
		ASSERT(kpj != NULL);
		mutex_exit(&kpj->kpj_poolbind);
		project_rele(kpj);
		break;
	case P_ZONEID:
		if (rv == 0) {
			mutex_enter(&cpu_lock);
			zone_pool_set(zone, pool);
			mutex_exit(&cpu_lock);
		}
		zone->zone_pool_mod = gethrtime();
		zone_rele(zone);
		break;
	}

	kmem_free(procs, procs_size * sizeof (proc_t *));
	ASSERT(pool_barrier_count == 0);
	return (rv);
}

void
pool_event_cb_register(pool_event_cb_t *cb)
{
	ASSERT(!pool_lock_held() || panicstr);
	ASSERT(cb->pec_func != NULL);

	mutex_enter(&pool_event_cb_lock);
	if (!pool_event_cb_init) {
		list_create(&pool_event_cb_list,  sizeof (pool_event_cb_t),
		    offsetof(pool_event_cb_t, pec_list));
		pool_event_cb_init = B_TRUE;
	}
	list_insert_tail(&pool_event_cb_list, cb);
	mutex_exit(&pool_event_cb_lock);
}

void
pool_event_cb_unregister(pool_event_cb_t *cb)
{
	ASSERT(!pool_lock_held() || panicstr);

	mutex_enter(&pool_event_cb_lock);
	list_remove(&pool_event_cb_list, cb);
	mutex_exit(&pool_event_cb_lock);
}

typedef struct {
	pool_event_t	tqd_what;
	poolid_t	tqd_id;
} pool_tqd_t;

void
pool_event_notify(void *arg)
{
	pool_tqd_t	*tqd = (pool_tqd_t *)arg;
	pool_event_cb_t	*cb;

	ASSERT(!pool_lock_held() || panicstr);

	mutex_enter(&pool_event_cb_lock);
	for (cb = list_head(&pool_event_cb_list); cb != NULL;
	    cb = list_next(&pool_event_cb_list, cb)) {
		cb->pec_func(tqd->tqd_what, tqd->tqd_id, cb->pec_arg);
	}
	mutex_exit(&pool_event_cb_lock);
	kmem_free(tqd, sizeof (*tqd));
}

void
pool_event_dispatch(pool_event_t what, poolid_t id)
{
	pool_tqd_t *tqd = NULL;

	ASSERT(pool_lock_held());

	if (pool_event_cb_taskq == NULL) {
		pool_event_cb_taskq = taskq_create("pool_event_cb_taskq", 1,
		    -1, 1, 1, TASKQ_PREPOPULATE);
	}

	tqd = kmem_alloc(sizeof (*tqd), KM_SLEEP);
	tqd->tqd_what = what;
	tqd->tqd_id = id;

	(void) taskq_dispatch(pool_event_cb_taskq, pool_event_notify, tqd,
	    KM_SLEEP);
}
