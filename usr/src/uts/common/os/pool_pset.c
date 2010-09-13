/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/pool.h>
#include <sys/pool_impl.h>
#include <sys/pool_pset.h>
#include <sys/cpuvar.h>
#include <sys/cpupart.h>
#include <sys/mutex.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/fss.h>
#include <sys/exacct.h>
#include <sys/time.h>
#include <sys/policy.h>
#include <sys/class.h>
#include <sys/list.h>
#include <sys/cred.h>
#include <sys/zone.h>

/*
 * Processor set plugin for pools.
 *
 * This file contains various routines used by the common pools layer to create,
 * modify, and destroy processor sets.  All processor sets created by this
 * plug-in are stored in the pool_pset_list doubly-linked list, which is
 * guaranteed to always have an entry for the default processor set,
 * pool_pset_default.
 *
 * Interaction with zones:
 *
 * If pools are enabled, non-global zones only have visibility into the
 * pset of the pool to which they are bound.  This is accomplished by
 * changing the set of processors and processor sets which are visible
 * through both systemcall interfaces and system kstats.
 *
 * To avoid grabbing pool_lock() during cpu change operations, we cache
 * the pset the zone is currently bound to, and can read this value
 * while under cpu_lock.  The special psetid_t token ZONE_PS_INVAL means
 * that pools are disabled, and provides a mechanism for determining if the
 * status of pools without grabbing pool_lock().
 *
 * To avoid grabbing any locks to determine the instantaneous value of
 * the number of configured and online cpus in the zone, we also cache
 * these values in a zone_t.  If these values are zero, the pools
 * facility must be disabled, in which case relevant systemcall
 * interfaces will return the values for the system as a whole.
 *
 * The various kstat interfaces are dealt with as follows: if pools are
 * disabled all cpu-related kstats should be exported to all zones.
 * When pools are enabled we begin maintaining a list of "permitted
 * zones" on a per-kstat basis.  There are various hooks throughout the
 * code to update this list when certain pools- or cpu-related events
 * occur.
 */

static list_t pool_pset_list;	/* doubly-linked list of psets */
pool_pset_t *pool_pset_default;	/* default pset */
hrtime_t pool_pset_mod;		/* last modification time for psets */
hrtime_t pool_cpu_mod;		/* last modification time for CPUs */

static pool_pset_t *
pool_lookup_pset_by_id(psetid_t psetid)
{
	pool_pset_t *pset = pool_pset_default;

	ASSERT(pool_lock_held());

	for (pset = list_head(&pool_pset_list); pset;
	    pset = list_next(&pool_pset_list, pset)) {
		if (pset->pset_id == psetid)
			return (pset);
	}
	return (NULL);
}

struct setup_arg {
	psetid_t psetid;
	cpu_t *cpu;
	cpu_setup_t what;
};

/*
 * Callback function used to apply a cpu configuration event to a zone.
 */
static int
pool_pset_setup_cb(zone_t *zone, void *arg)
{
	struct setup_arg *sa = arg;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(INGLOBALZONE(curproc));
	ASSERT(zone != NULL);

	if (zone == global_zone)
		return (0);
	if (zone_pset_get(zone) != sa->psetid)
		return (0);	/* ignore */
	switch (sa->what) {
	case CPU_CONFIG:
		cpu_visibility_configure(sa->cpu, zone);
		break;
	case CPU_UNCONFIG:
		cpu_visibility_unconfigure(sa->cpu, zone);
		break;
	case CPU_ON:
		cpu_visibility_online(sa->cpu, zone);
		break;
	case CPU_OFF:
		cpu_visibility_offline(sa->cpu, zone);
		break;
	case CPU_CPUPART_IN:
		cpu_visibility_add(sa->cpu, zone);
		break;
	case CPU_CPUPART_OUT:
		cpu_visibility_remove(sa->cpu, zone);
		break;
	default:
		cmn_err(CE_PANIC, "invalid cpu_setup_t value %d", sa->what);
	}
	return (0);
}

/*
 * Callback function to be executed when a noteworthy cpu event takes
 * place.  Will ensure that the event is reflected by the zones which
 * were affected by it.
 */
/* ARGSUSED */
static int
pool_pset_cpu_setup(cpu_setup_t what, int id, void *arg)
{
	processorid_t cpuid = id;
	struct setup_arg sarg;
	int error;
	cpu_t *c;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(INGLOBALZONE(curproc));

	if (!pool_pset_enabled())
		return (0);
	if (what != CPU_CONFIG && what != CPU_UNCONFIG &&
	    what != CPU_ON && what != CPU_OFF &&
	    what != CPU_CPUPART_IN && what != CPU_CPUPART_OUT)
		return (0);
	c = cpu_get(cpuid);
	ASSERT(c != NULL);
	sarg.psetid = cpupart_query_cpu(c);
	sarg.cpu = c;
	sarg.what = what;

	error = zone_walk(pool_pset_setup_cb, &sarg);
	ASSERT(error == 0);
	return (0);
}

/*
 * Initialize processor set plugin.  Called once at boot time.
 */
void
pool_pset_init(void)
{
	ASSERT(pool_pset_default == NULL);
	pool_pset_default = kmem_zalloc(sizeof (pool_pset_t), KM_SLEEP);
	pool_pset_default->pset_id = PS_NONE;
	pool_pset_default->pset_npools = 1;	/* for pool_default */
	pool_default->pool_pset = pool_pset_default;
	list_create(&pool_pset_list, sizeof (pool_pset_t),
	    offsetof(pool_pset_t, pset_link));
	list_insert_head(&pool_pset_list, pool_pset_default);
	mutex_enter(&cpu_lock);
	register_cpu_setup_func(pool_pset_cpu_setup, NULL);
	mutex_exit(&cpu_lock);
}

/*
 * Dummy wrapper function that returns 0 to satisfy zone_walk().
 */
static int
pool_pset_zone_pset_set(zone_t *zone, void *arg)
{
	psetid_t psetid = (psetid_t)(uintptr_t)arg;

	ASSERT(MUTEX_HELD(&cpu_lock));
	zone_pset_set(zone, psetid);
	return (0);
}

/*
 * Enable processor set plugin.
 */
int
pool_pset_enable(void)
{
	int error;
	nvlist_t *props;

	ASSERT(pool_lock_held());
	ASSERT(INGLOBALZONE(curproc));
	/*
	 * Can't enable pools if there are existing cpu partitions.
	 */
	mutex_enter(&cpu_lock);
	if (cp_numparts > 1) {
		mutex_exit(&cpu_lock);
		return (EEXIST);
	}

	/*
	 * We want to switch things such that everything that was tagged with
	 * the special ALL_ZONES token now is explicitly visible to all zones:
	 * first add individual zones to the visibility list then remove the
	 * special "ALL_ZONES" token.  There must only be the default pset
	 * (PS_NONE) active if pools are being enabled, so we only need to
	 * deal with it.
	 *
	 * We want to make pool_pset_enabled() start returning B_TRUE before
	 * we call any of the visibility update functions.
	 */
	global_zone->zone_psetid = PS_NONE;
	/*
	 * We need to explicitly handle the global zone since
	 * zone_pset_set() won't modify it.
	 */
	pool_pset_visibility_add(PS_NONE, global_zone);
	/*
	 * A NULL argument means the ALL_ZONES token.
	 */
	pool_pset_visibility_remove(PS_NONE, NULL);
	error = zone_walk(pool_pset_zone_pset_set, (void *)PS_NONE);
	ASSERT(error == 0);

	/*
	 * It is safe to drop cpu_lock here.  We're still
	 * holding pool_lock so no new cpu partitions can
	 * be created while we're here.
	 */
	mutex_exit(&cpu_lock);
	(void) nvlist_alloc(&pool_pset_default->pset_props,
	    NV_UNIQUE_NAME, KM_SLEEP);
	props = pool_pset_default->pset_props;
	(void) nvlist_add_string(props, "pset.name", "pset_default");
	(void) nvlist_add_string(props, "pset.comment", "");
	(void) nvlist_add_int64(props, "pset.sys_id", PS_NONE);
	(void) nvlist_add_string(props, "pset.units", "population");
	(void) nvlist_add_byte(props, "pset.default", 1);
	(void) nvlist_add_uint64(props, "pset.max", 65536);
	(void) nvlist_add_uint64(props, "pset.min", 1);
	pool_pset_mod = pool_cpu_mod = gethrtime();
	return (0);
}

/*
 * Disable processor set plugin.
 */
int
pool_pset_disable(void)
{
	processorid_t cpuid;
	cpu_t *cpu;
	int error;

	ASSERT(pool_lock_held());
	ASSERT(INGLOBALZONE(curproc));

	mutex_enter(&cpu_lock);
	if (cp_numparts > 1) {	/* make sure only default pset is left */
		mutex_exit(&cpu_lock);
		return (EBUSY);
	}
	/*
	 * Remove all non-system CPU and processor set properties
	 */
	for (cpuid = 0; cpuid < NCPU; cpuid++) {
		if ((cpu = cpu_get(cpuid)) == NULL)
			continue;
		if (cpu->cpu_props != NULL) {
			(void) nvlist_free(cpu->cpu_props);
			cpu->cpu_props = NULL;
		}
	}

	/*
	 * We want to switch things such that everything is now visible
	 * to ALL_ZONES: first add the special "ALL_ZONES" token to the
	 * visibility list then remove individual zones.  There must
	 * only be the default pset active if pools are being disabled,
	 * so we only need to deal with it.
	 */
	error = zone_walk(pool_pset_zone_pset_set, (void *)ZONE_PS_INVAL);
	ASSERT(error == 0);
	pool_pset_visibility_add(PS_NONE, NULL);
	pool_pset_visibility_remove(PS_NONE, global_zone);
	/*
	 * pool_pset_enabled() will henceforth return B_FALSE.
	 */
	global_zone->zone_psetid = ZONE_PS_INVAL;
	mutex_exit(&cpu_lock);
	if (pool_pset_default->pset_props != NULL) {
		nvlist_free(pool_pset_default->pset_props);
		pool_pset_default->pset_props = NULL;
	}
	return (0);
}

/*
 * Create new processor set and give it a temporary name.
 */
int
pool_pset_create(psetid_t *id)
{
	char pset_name[40];
	pool_pset_t *pset;
	psetid_t psetid;
	int err;

	ASSERT(pool_lock_held());
	if ((err = cpupart_create(&psetid)) != 0)
		return (err);
	pset = kmem_alloc(sizeof (pool_pset_t), KM_SLEEP);
	pset->pset_id = *id = psetid;
	pset->pset_npools = 0;
	(void) nvlist_alloc(&pset->pset_props, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_int64(pset->pset_props, "pset.sys_id", psetid);
	(void) nvlist_add_byte(pset->pset_props, "pset.default", 0);
	pool_pset_mod = gethrtime();
	(void) snprintf(pset_name, sizeof (pset_name), "pset_%lld",
	    pool_pset_mod);
	(void) nvlist_add_string(pset->pset_props, "pset.name", pset_name);
	list_insert_tail(&pool_pset_list, pset);
	return (0);
}

/*
 * Destroy existing processor set.
 */
int
pool_pset_destroy(psetid_t psetid)
{
	pool_pset_t *pset;
	int ret;

	ASSERT(pool_lock_held());

	if (psetid == PS_NONE)
		return (EINVAL);
	if ((pset = pool_lookup_pset_by_id(psetid)) == NULL)
		return (ESRCH);
	if (pset->pset_npools > 0) /* can't destroy associated psets */
		return (EBUSY);
	if ((ret = cpupart_destroy(pset->pset_id)) != 0)
		return (ret);
	(void) nvlist_free(pset->pset_props);
	list_remove(&pool_pset_list, pset);
	pool_pset_mod = gethrtime();
	kmem_free(pset, sizeof (pool_pset_t));
	return (0);
}

/*
 * Change the visibility of a pset (and all contained cpus) in a zone.
 * A NULL zone argument implies the special ALL_ZONES token.
 */
static void
pool_pset_visibility_change(psetid_t psetid, zone_t *zone, boolean_t add)
{
	zoneid_t zoneid = zone ? zone->zone_id : ALL_ZONES;
	cpupart_t *cp;
	cpu_t *c;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(psetid != ZONE_PS_INVAL);

	cp = cpupart_find(psetid);
	ASSERT(cp != NULL);
	if (cp->cp_kstat != NULL) {
		if (add)
			kstat_zone_add(cp->cp_kstat, zoneid);
		else
			kstat_zone_remove(cp->cp_kstat, zoneid);
	}

	c = cpu_list;
	do {
		ASSERT(c != NULL);
		if (c->cpu_part == cp && !cpu_is_poweredoff(c)) {
			if (add)
				cpu_visibility_add(c, zone);
			else
				cpu_visibility_remove(c, zone);
		}
	} while ((c = c->cpu_next) != cpu_list);
}

/*
 * Make the processor set visible to the zone.  A NULL value for
 * the zone means that the special ALL_ZONES token should be added to
 * the visibility list.
 */
void
pool_pset_visibility_add(psetid_t psetid, zone_t *zone)
{
	pool_pset_visibility_change(psetid, zone, B_TRUE);
}

/*
 * Remove zone's visibility into the processor set.  A NULL value for
 * the zone means that the special ALL_ZONES token should be removed
 * from the visibility list.
 */
void
pool_pset_visibility_remove(psetid_t psetid, zone_t *zone)
{
	pool_pset_visibility_change(psetid, zone, B_FALSE);
}

/*
 * Quick way of seeing if pools are enabled (as far as processor sets are
 * concerned) without holding pool_lock().
 */
boolean_t
pool_pset_enabled(void)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	return (zone_pset_get(global_zone) != ZONE_PS_INVAL);
}

struct assoc_zone_arg {
	poolid_t poolid;
	psetid_t newpsetid;
};

/*
 * Callback function to update a zone's processor set visibility when
 * a pool is associated with a processor set.
 */
static int
pool_pset_assoc_zone_cb(zone_t *zone, void *arg)
{
	struct assoc_zone_arg *aza = arg;
	pool_t *pool;
	zoneid_t zoneid = zone->zone_id;

	ASSERT(pool_lock_held());
	ASSERT(MUTEX_HELD(&cpu_lock));

	if (zoneid == GLOBAL_ZONEID)
		return (0);
	pool = zone_pool_get(zone);
	if (pool->pool_id == aza->poolid)
		zone_pset_set(zone, aza->newpsetid);
	return (0);
}

/*
 * Associate pool with new processor set.
 */
int
pool_pset_assoc(poolid_t poolid, psetid_t psetid)
{
	pool_t *pool;
	pool_pset_t *pset, *oldpset;
	int err = 0;

	ASSERT(pool_lock_held());

	if ((pool = pool_lookup_pool_by_id(poolid)) == NULL ||
	    (pset = pool_lookup_pset_by_id(psetid)) == NULL) {
		return (ESRCH);
	}
	if (pool->pool_pset->pset_id == psetid) {
		/*
		 * Already associated.
		 */
		return (0);
	}

	/*
	 * Hang the new pset off the pool, and rebind all of the pool's
	 * processes to it.  If pool_do_bind fails, all processes will remain
	 * bound to the old set.
	 */
	oldpset = pool->pool_pset;
	pool->pool_pset = pset;
	err = pool_do_bind(pool, P_POOLID, poolid, POOL_BIND_PSET);
	if (err) {
		pool->pool_pset = oldpset;
	} else {
		struct assoc_zone_arg azarg;

		/*
		 * Update zones' visibility to reflect changes.
		 */
		azarg.poolid = poolid;
		azarg.newpsetid = pset->pset_id;
		mutex_enter(&cpu_lock);
		err = zone_walk(pool_pset_assoc_zone_cb, &azarg);
		ASSERT(err == 0);
		mutex_exit(&cpu_lock);

		oldpset->pset_npools--;
		pset->pset_npools++;
	}
	return (err);
}

/*
 * Transfer specified CPUs between processor sets.
 */
int
pool_pset_xtransfer(psetid_t src, psetid_t dst, size_t size, id_t *ids)
{
	struct cpu *cpu;
	int ret = 0;
	int id;

	ASSERT(pool_lock_held());
	ASSERT(INGLOBALZONE(curproc));

	if (size == 0 || size > max_ncpus)	/* quick sanity check */
		return (EINVAL);

	mutex_enter(&cpu_lock);
	for (id = 0; id < size; id++) {
		if ((cpu = cpu_get((processorid_t)ids[id])) == NULL ||
		    cpupart_query_cpu(cpu) != src) {
			ret = EINVAL;
			break;
		}
		if ((ret = cpupart_attach_cpu(dst, cpu, 1)) != 0)
			break;
	}
	mutex_exit(&cpu_lock);
	if (ret == 0)
		pool_pset_mod = gethrtime();
	return (ret);
}

/*
 * Bind process to processor set.  This should never fail because
 * we should've done all preliminary checks before calling it.
 */
void
pool_pset_bind(proc_t *p, psetid_t psetid, void *projbuf, void *zonebuf)
{
	kthread_t *t;
	int ret;

	ASSERT(pool_lock_held());
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&pidlock));
	ASSERT(MUTEX_HELD(&p->p_lock));

	if ((t = p->p_tlist) == NULL)
		return;
	do {
		ret = cpupart_bind_thread(t, psetid, 0, projbuf, zonebuf);
		ASSERT(ret == 0);
		t->t_bind_pset = psetid;
	} while ((t = t->t_forw) != p->p_tlist);
}

/*
 * See the comment above pool_do_bind() for the semantics of the pset_bind_*()
 * functions.  These must be kept in sync with cpupart_move_thread, and
 * anything else that could fail a pool_pset_bind.
 *
 * Returns non-zero errno on failure and zero on success.
 * Iff successful, cpu_lock is held on return.
 */
int
pset_bind_start(proc_t **procs, pool_t *pool)
{
	cred_t *pcred;
	proc_t *p, **pp;
	kthread_t *t;
	cpupart_t *newpp;
	int ret;

	extern int cpupart_movable_thread(kthread_id_t, cpupart_t *, int);

	ASSERT(pool_lock_held());
	ASSERT(INGLOBALZONE(curproc));

	mutex_enter(&cpu_lock);
	weakbinding_stop();

	newpp = cpupart_find(pool->pool_pset->pset_id);
	ASSERT(newpp != NULL);
	if (newpp->cp_cpulist == NULL) {
		weakbinding_start();
		mutex_exit(&cpu_lock);
		return (ENOTSUP);
	}

	pcred = crgetcred();

	/*
	 * Check for the PRIV_PROC_PRIOCNTL privilege that is required
	 * to enter and exit scheduling classes.  If other privileges
	 * are required by CL_ENTERCLASS/CL_CANEXIT types of routines
	 * in the future, this code will have to be updated.
	 */
	if (secpolicy_setpriority(pcred) != 0) {
		weakbinding_start();
		mutex_exit(&cpu_lock);
		crfree(pcred);
		return (EPERM);
	}

	for (pp = procs; (p = *pp) != NULL; pp++) {
		mutex_enter(&p->p_lock);
		if ((t = p->p_tlist) == NULL) {
			mutex_exit(&p->p_lock);
			continue;
		}
		/*
		 * Check our basic permissions to control this process.
		 */
		if (!prochasprocperm(p, curproc, pcred)) {
			mutex_exit(&p->p_lock);
			weakbinding_start();
			mutex_exit(&cpu_lock);
			crfree(pcred);
			return (EPERM);
		}
		do {
			/*
			 * Check that all threads can be moved to
			 * a new processor set.
			 */
			thread_lock(t);
			ret = cpupart_movable_thread(t, newpp, 0);
			thread_unlock(t);
			if (ret != 0) {
				mutex_exit(&p->p_lock);
				weakbinding_start();
				mutex_exit(&cpu_lock);
				crfree(pcred);
				return (ret);
			}
		} while ((t = t->t_forw) != p->p_tlist);
		mutex_exit(&p->p_lock);
	}
	crfree(pcred);
	return (0);	/* with cpu_lock held and weakbinding stopped */
}

/*ARGSUSED*/
void
pset_bind_abort(proc_t **procs, pool_t *pool)
{
	mutex_exit(&cpu_lock);
}

void
pset_bind_finish(void)
{
	weakbinding_start();
	mutex_exit(&cpu_lock);
}

static pool_property_t pool_pset_props[] = {
	{ "pset.name",			DATA_TYPE_STRING,	PP_RDWR },
	{ "pset.comment",		DATA_TYPE_STRING,	PP_RDWR },
	{ "pset.sys_id",		DATA_TYPE_UINT64,	PP_READ },
	{ "pset.units",			DATA_TYPE_STRING,	PP_RDWR },
	{ "pset.default",		DATA_TYPE_BYTE,		PP_READ },
	{ "pset.min",			DATA_TYPE_UINT64,	PP_RDWR },
	{ "pset.max",			DATA_TYPE_UINT64,	PP_RDWR },
	{ "pset.size",			DATA_TYPE_UINT64,	PP_READ },
	{ "pset.load",			DATA_TYPE_UINT64,	PP_READ },
	{ "pset.poold.objectives",	DATA_TYPE_STRING,
	    PP_RDWR | PP_OPTIONAL },
	{ NULL,				0,			0 }
};

static pool_property_t pool_cpu_props[] = {
	{ "cpu.sys_id",			DATA_TYPE_UINT64,	PP_READ },
	{ "cpu.comment",		DATA_TYPE_STRING,	PP_RDWR },
	{ "cpu.status",			DATA_TYPE_STRING,	PP_RDWR },
	{ "cpu.pinned",			DATA_TYPE_BYTE,
	    PP_RDWR | PP_OPTIONAL },
	{ NULL,				0,			0 }
};

/*
 * Put property on the specified processor set.
 */
int
pool_pset_propput(psetid_t psetid, nvpair_t *pair)
{
	pool_pset_t *pset;
	int ret;

	ASSERT(pool_lock_held());

	if ((pset = pool_lookup_pset_by_id(psetid)) == NULL)
		return (ESRCH);
	ret = pool_propput_common(pset->pset_props, pair, pool_pset_props);
	if (ret == 0)
		pool_pset_mod = gethrtime();
	return (ret);
}

/*
 * Remove existing processor set property.
 */
int
pool_pset_proprm(psetid_t psetid, char *name)
{
	pool_pset_t *pset;
	int ret;

	ASSERT(pool_lock_held());

	if ((pset = pool_lookup_pset_by_id(psetid)) == NULL)
		return (EINVAL);
	ret = pool_proprm_common(pset->pset_props, name, pool_pset_props);
	if (ret == 0)
		pool_pset_mod = gethrtime();
	return (ret);
}

/*
 * Put new CPU property.
 * Handle special case of "cpu.status".
 */
int
pool_cpu_propput(processorid_t cpuid, nvpair_t *pair)
{
	int ret = 0;
	cpu_t *cpu;

	ASSERT(pool_lock_held());
	ASSERT(INGLOBALZONE(curproc));

	if (nvpair_type(pair) == DATA_TYPE_STRING &&
	    strcmp(nvpair_name(pair), "cpu.status") == 0) {
		char *val;
		int status;
		int old_status;
		(void) nvpair_value_string(pair, &val);
		if (strcmp(val, PS_OFFLINE) == 0)
			status = P_OFFLINE;
		else if (strcmp(val, PS_ONLINE) == 0)
			status = P_ONLINE;
		else if (strcmp(val, PS_NOINTR) == 0)
			status = P_NOINTR;
		else if (strcmp(val, PS_FAULTED) == 0)
			status = P_FAULTED;
		else if (strcmp(val, PS_SPARE) == 0)
			status = P_SPARE;
		else
			return (EINVAL);
		ret = p_online_internal(cpuid, status, &old_status);
	} else {
		mutex_enter(&cpu_lock);
		if ((cpu = cpu_get(cpuid)) == NULL)
			ret = EINVAL;
		if (cpu->cpu_props == NULL) {
			(void) nvlist_alloc(&cpu->cpu_props,
			    NV_UNIQUE_NAME, KM_SLEEP);
			(void) nvlist_add_string(cpu->cpu_props,
			    "cpu.comment", "");
		}
		ret = pool_propput_common(cpu->cpu_props, pair, pool_cpu_props);
		if (ret == 0)
			pool_cpu_mod = gethrtime();
		mutex_exit(&cpu_lock);
	}
	return (ret);
}

/*
 * Remove existing CPU property.
 */
int
pool_cpu_proprm(processorid_t cpuid, char *name)
{
	int ret;
	cpu_t *cpu;

	ASSERT(pool_lock_held());
	ASSERT(INGLOBALZONE(curproc));

	mutex_enter(&cpu_lock);
	if ((cpu = cpu_get(cpuid)) == NULL || cpu_is_poweredoff(cpu)) {
		ret = EINVAL;
	} else {
		if (cpu->cpu_props == NULL)
			ret = EINVAL;
		else
			ret = pool_proprm_common(cpu->cpu_props, name,
			    pool_cpu_props);
	}
	if (ret == 0)
		pool_cpu_mod = gethrtime();
	mutex_exit(&cpu_lock);
	return (ret);
}

/*
 * This macro returns load average multiplied by 1000 w/o losing precision
 */
#define	PSET_LOAD(f)	(((f >> 16) * 1000) + (((f & 0xffff) * 1000) / 0xffff))

/*
 * Take a snapshot of the current state of processor sets and CPUs,
 * pack it in the exacct format, and attach it to specified exacct record.
 */
int
pool_pset_pack(ea_object_t *eo_system)
{
	ea_object_t *eo_pset, *eo_cpu;
	cpupart_t *cpupart;
	psetid_t mypsetid;
	pool_pset_t *pset;
	nvlist_t *nvl;
	size_t bufsz;
	cpu_t *cpu;
	char *buf;
	int ncpu;

	ASSERT(pool_lock_held());

	mutex_enter(&cpu_lock);
	mypsetid = zone_pset_get(curproc->p_zone);
	for (pset = list_head(&pool_pset_list); pset;
	    pset = list_next(&pool_pset_list, pset)) {
		psetid_t psetid = pset->pset_id;

		if (!INGLOBALZONE(curproc) && mypsetid != psetid)
			continue;
		cpupart = cpupart_find(psetid);
		ASSERT(cpupart != NULL);
		eo_pset = ea_alloc_group(EXT_GROUP |
		    EXC_LOCAL | EXD_GROUP_PSET);
		(void) ea_attach_item(eo_pset, &psetid, sizeof (id_t),
		    EXC_LOCAL | EXD_PSET_PSETID | EXT_UINT32);
		/*
		 * Pack info for all CPUs in this processor set.
		 */
		ncpu = 0;
		cpu = cpu_list;
		do {
			if (cpu->cpu_part != cpupart)	/* not our pset */
				continue;
			ncpu++;
			eo_cpu = ea_alloc_group(EXT_GROUP
			    | EXC_LOCAL | EXD_GROUP_CPU);
			(void) ea_attach_item(eo_cpu, &cpu->cpu_id,
			    sizeof (processorid_t),
			    EXC_LOCAL | EXD_CPU_CPUID | EXT_UINT32);
			if (cpu->cpu_props == NULL) {
				(void) nvlist_alloc(&cpu->cpu_props,
				    NV_UNIQUE_NAME, KM_SLEEP);
				(void) nvlist_add_string(cpu->cpu_props,
				    "cpu.comment", "");
			}
			(void) nvlist_dup(cpu->cpu_props, &nvl, KM_SLEEP);
			(void) nvlist_add_int64(nvl, "cpu.sys_id", cpu->cpu_id);
			(void) nvlist_add_string(nvl, "cpu.status",
			    (char *)cpu_get_state_str(cpu));
			buf = NULL;
			bufsz = 0;
			(void) nvlist_pack(nvl, &buf, &bufsz,
			    NV_ENCODE_NATIVE, 0);
			(void) ea_attach_item(eo_cpu, buf, bufsz,
			    EXC_LOCAL | EXD_CPU_PROP | EXT_RAW);
			(void) nvlist_free(nvl);
			kmem_free(buf, bufsz);
			(void) ea_attach_to_group(eo_pset, eo_cpu);
		} while ((cpu = cpu->cpu_next) != cpu_list);

		(void) nvlist_dup(pset->pset_props, &nvl, KM_SLEEP);
		(void) nvlist_add_uint64(nvl, "pset.size", ncpu);
		(void) nvlist_add_uint64(nvl, "pset.load",
		    (uint64_t)PSET_LOAD(cpupart->cp_hp_avenrun[0]));
		buf = NULL;
		bufsz = 0;
		(void) nvlist_pack(nvl, &buf, &bufsz, NV_ENCODE_NATIVE, 0);
		(void) ea_attach_item(eo_pset, buf, bufsz,
		    EXC_LOCAL | EXD_PSET_PROP | EXT_RAW);
		(void) nvlist_free(nvl);
		kmem_free(buf, bufsz);

		(void) ea_attach_to_group(eo_system, eo_pset);
	}
	mutex_exit(&cpu_lock);
	return (0);
}

/*
 * Get dynamic property for processor sets.
 * The only dynamic property currently implemented is "pset.load".
 */
int
pool_pset_propget(psetid_t psetid, char *name, nvlist_t *nvl)
{
	cpupart_t *cpupart;
	pool_pset_t *pset;
	int ret = ESRCH;

	ASSERT(pool_lock_held());

	mutex_enter(&cpu_lock);
	pset = pool_lookup_pset_by_id(psetid);
	cpupart = cpupart_find(psetid);
	if (cpupart == NULL || pset == NULL) {
		mutex_exit(&cpu_lock);
		return (EINVAL);
	}
	if (strcmp(name, "pset.load") == 0)
		ret = nvlist_add_uint64(nvl, "pset.load",
		    (uint64_t)PSET_LOAD(cpupart->cp_hp_avenrun[0]));
	else
		ret = EINVAL;
	mutex_exit(&cpu_lock);
	return (ret);
}

/*
 * Get dynamic property for CPUs.
 * The only dynamic property currently implemented is "cpu.status".
 */
int
pool_cpu_propget(processorid_t cpuid, char *name, nvlist_t *nvl)
{
	int ret = ESRCH;
	cpu_t *cpu;

	ASSERT(pool_lock_held());

	mutex_enter(&cpu_lock);
	if ((cpu = cpu_get(cpuid)) == NULL) {
		mutex_exit(&cpu_lock);
		return (ESRCH);
	}
	if (strcmp(name, "cpu.status") == 0) {
		ret = nvlist_add_string(nvl, "cpu.status",
		    (char *)cpu_get_state_str(cpu));
	} else {
		ret = EINVAL;
	}
	mutex_exit(&cpu_lock);
	return (ret);
}
