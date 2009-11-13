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

#include <sys/disp.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/cpucaps_impl.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>
#include <sys/debug.h>
#include <sys/rctl.h>
#include <sys/errno.h>

/*
 * CPU Caps implementation
 * =======================
 *
 * A CPU cap can be set on any project or any zone. Zone CPU cap limits the CPU
 * usage for all projects running inside the zone. If the zone CPU cap is set
 * below the project CPU cap, the latter will have no effect.
 *
 * When CPU usage of projects and/or zones reaches specified caps, threads in
 * them do not get scheduled and instead are placed on wait queues associated
 * with a cap. Such threads will start running again only when CPU usage drops
 * below the cap level. Each zone and each project has its own wait queue.
 *
 * When CPU cap is set, the kernel continously keeps track of CPU time used by
 * capped zones and/or projects over a short time interval and calculates their
 * current CPU usage as a percentage. When the accumulated usage reaches the CPU
 * cap, LWPs running in the user-land (when they are not holding any critical
 * kernel locks) are placed on special wait queues until their project's or
 * zone's CPU usage drops below the cap.
 *
 * The system maintains a list of all capped projects and all capped zones. On
 * every clock tick every active thread belonging to a capped project adds its
 * CPU usage to its project. Usage from all projects belonging to a capped zone
 * is aggregated to get the zone usage.
 *
 * When the current CPU usage is above the cap, a project or zone is considered
 * over-capped. Every user thread caught running in an over-capped project or
 * zone is marked by setting TS_PROJWAITQ flag in thread's t_schedflag field and
 * is requested to surrender its CPU. This causes scheduling class specific
 * CL_PREEMPT() callback to be invoked. The callback function places threads
 * marked as TS_PROJWAIT on a wait queue and calls switch().
 *
 * Threads are only placed on wait queues after trapping from user-land
 * (they could be holding some user locks, but no kernel locks) and while
 * returning from the trap back to the user-land when no kernel locks are held.
 * Putting threads on wait queues in random places while running in the
 * kernel might lead to all kinds of locking problems.
 *
 * Accounting
 * ==========
 *
 * Accounting of CPU usage is based on per-thread micro-state accounting data.
 * On every clock tick clock() adds new on-CPU time for every thread found on
 * CPU. Scheduling classes also add new on-CPU time for any thread leaving CPU.
 * New times means time since it was last accounted for. On-CPU times greater
 * than 1 tick are truncated to 1 tick.
 *
 * Project CPU usage is aggregated from all threads within the project.
 * Zone CPU usage is the sum of usages for all projects within the zone. Zone
 * CPU usage is calculated on every clock tick by walking list of projects and
 * adding their usage together.
 *
 * Decay
 * =====
 *
 * CPU usage is decayed by the caps_update() routine which is called once per
 * every clock tick. It walks lists of project caps and decays their usages by
 * one per cent. If CPU usage drops below cap levels, threads on the wait queue
 * are made runnable again, one thread per clock tick.
 *
 * Interfaces
 * ==========
 *
 * The CPU Caps facility provides the following interfaces to the rest of the
 * system:
 *
 *   cpucaps_project_add(kproject_t *)
 *
 * Notifies the framework of a new project. It should be put on the
 * capped_projects list if its zone has a cap.
 *
 *   cpucaps_project_remove(kproject_t *)
 *
 * Remove the association between the specified project and its cap.
 * Called right before the project is destroyed.
 *
 * cpucaps_project_set(kproject_t *, rctl_qty_t)
 *
 * Set project cap of the specified project to the specified value. Setting the
 * value to NOCAP is equivalent to removing the cap.
 *
 *   cpucaps_zone_set(zone_t *, rctl_qty_t)
 *
 * Set zone cap of the specified zone to the specified value. Setting the value
 * to NOCAP is equivalent to removing the cap.
 *
 *   cpucaps_zone_remove(zone_t *)
 *
 * Remove the association between the zone and its cap.
 *
 *   cpucaps_charge(kthread_id_t, caps_sc_t *, cpucaps_charge_t)
 *
 * Charges specified thread's project the amount of on-CPU time that it used.
 * If the third argument is CPUCAPS_CHARGE_ONLY returns False.
 * Otherwise returns True if project or zone should be penalized because its
 * project or zone is exceeding its cap. Also sets TS_PROJWAITQ or TS_ZONEWAITQ
 * bits in t_schedflag in this case.
 *
 *   CPUCAPS_ENFORCE(kthread_id_t *)
 *
 * Enforces CPU caps for a specified thread. Places LWPs running in LWP_USER
 * state on project or zone wait queues, as requested by TS_PROJWAITQ or
 * TS_ZONEWAITQ bits in t_schedflag. Returns True if the thread was placed on a
 * wait queue or False otherwise.
 *
 *   cpucaps_sc_init(caps_sc_t *)
 *
 * Initializes the scheduling-class specific CPU Caps data for a thread.
 *
 * LOCKS
 * =====
 *
 * all the individual caps structures and their lists are protected by a global
 * caps_lock mutex. The lock is grabbed either by clock() or by events modifying
 * caps, so it is usually uncontended. We avoid all blocking memory allocations
 * while holding caps_lock to prevent clock() from blocking.
 *
 * Thread state is protected by the thread lock. It protects the association
 * between a thread and its project and, as a consequence, to its zone. The
 * association can not break while thread lock is held, so the project or zone
 * cap are not going to disappear while thread lock is held.
 *
 * Cap usage field is protected by high-pil spin-lock cap_usagelock. It is
 * grabbed by scheduling classes already holding thread lock at high PIL and by
 * clock thread performing usage decay. We should do as little work as possible
 * while holding the lock since it may be very hot. All threads in the project
 * contend for the same cache line doing cap usage updates.
 */

/*
 * caps_lock protects list of capped projects and zones, changes in the cap
 * state and changes of the global cpucaps_enabled flag.
 *
 * Changing zone caps also sets cpucaps_busy to avoid races when a zone cap is
 * modified in parallel. This can be per-zone cap flag, but we don't keep any
 * cap state for now.
 */
static kmutex_t caps_lock;		/* lock to protect: */
static list_t capped_zones;		/* - list of zones with caps */
static list_t capped_projects;		/* - list of projects with caps */
boolean_t cpucaps_enabled;		/* - are there any caps defined? */
boolean_t cpucaps_busy;			/* - is framework busy? */

/*
 * The accounting is based on the number of nanoseconds threads spend running
 * during a tick which is kept in the cap_tick_cost variable.
 */
static hrtime_t cap_tick_cost;

/*
 * How much of the usage value is decayed every clock tick
 * Decay one per cent of value per tick
 */
#define	CAP_DECAY_FACTOR 100

/*
 * Scale the value and round it to the closest integer value
 */
#define	ROUND_SCALE(x, y) (((x) + (y) / 2) / (y))

static void caps_update();

/*
 * CAP kstats.
 */
struct cap_kstat {
	kstat_named_t	cap_value;
	kstat_named_t	cap_usage;
	kstat_named_t	cap_nwait;
	kstat_named_t	cap_below;
	kstat_named_t	cap_above;
	kstat_named_t	cap_maxusage;
	kstat_named_t	cap_zonename;
} cap_kstat = {
	{ "value",	KSTAT_DATA_UINT64 },
	{ "usage",	KSTAT_DATA_UINT64 },
	{ "nwait",	KSTAT_DATA_UINT64 },
	{ "below_sec",	KSTAT_DATA_UINT64 },
	{ "above_sec",	KSTAT_DATA_UINT64 },
	{ "maxusage",	KSTAT_DATA_UINT64 },
	{ "zonename",	KSTAT_DATA_STRING },
};


static kmutex_t cap_kstat_lock;
static int cap_kstat_update(kstat_t *, int);

/*
 * Initialize CPU caps infrastructure.
 *   - Initialize lists of capped zones and capped projects
 *   - Set cpucaps_clock_callout to NULL
 */
void
cpucaps_init()
{
	/*
	 * Initialize global variables
	 */
	cap_tick_cost = TICK_TO_NSEC((hrtime_t)1);

	list_create(&capped_zones, sizeof (cpucap_t),
	    offsetof(cpucap_t, cap_link));
	list_create(&capped_projects, sizeof (cpucap_t),
	    offsetof(cpucap_t, cap_link));

	cpucaps_enabled = B_FALSE;
	cpucaps_busy = B_FALSE;
	cpucaps_clock_callout = NULL;
}

/*
 * Initialize scheduling-class specific CPU Caps data.
 */
void
cpucaps_sc_init(caps_sc_t *csc)
{
	csc->csc_cputime = 0;
}

/*
 * Allocate and initialize cpucap structure
 */
static cpucap_t *
cap_alloc(void)
{
	cpucap_t *cap = kmem_zalloc(sizeof (cpucap_t), KM_SLEEP);

	DISP_LOCK_INIT(&cap->cap_usagelock);
	waitq_init(&cap->cap_waitq);

	return (cap);
}

/*
 * Free cpucap structure
 */
static void
cap_free(cpucap_t *cap)
{
	if (cap == NULL)
		return;

	/*
	 * This cap should not be active
	 */
	ASSERT(!list_link_active(&cap->cap_link));
	ASSERT(cap->cap_value == 0);
	ASSERT(!DISP_LOCK_HELD(&cap->cap_usagelock));

	waitq_fini(&cap->cap_waitq);
	DISP_LOCK_DESTROY(&cap->cap_usagelock);

	kmem_free(cap, sizeof (cpucap_t));
}

/*
 * Activate cap - insert into active list and unblock its
 * wait queue. Should be called with caps_lock held.
 * The cap_value field is set to the value supplied.
 */
static void
cap_enable(list_t *l, cpucap_t *cap, hrtime_t value)
{
	ASSERT(MUTEX_HELD(&caps_lock));

	/*
	 * Cap can not be already enabled
	 */
	ASSERT(!CAP_ENABLED(cap));
	ASSERT(!list_link_active(&cap->cap_link));

	list_insert_tail(l, cap);
	cap->cap_below = cap->cap_above = 0;
	cap->cap_maxusage = 0;
	cap->cap_usage = 0;
	cap->cap_value = value;
	waitq_unblock(&cap->cap_waitq);
	if (CPUCAPS_OFF()) {
		cpucaps_enabled = B_TRUE;
		cpucaps_clock_callout = caps_update;
	}
}

/*
 * Deactivate cap
 *   - Block its wait queue. This prevents any new threads from being
 *	enqueued there and moves all enqueued threads to the run queue.
 *   - Remove cap from list l.
 *   - Disable CPU caps globally if there are no capped projects or zones
 *
 * Should be called with caps_lock held.
 */
static void
cap_disable(list_t *l, cpucap_t *cap)
{
	ASSERT(MUTEX_HELD(&caps_lock));
	/*
	 * Cap should be currently active
	 */
	ASSERT(CPUCAPS_ON());
	ASSERT(list_link_active(&cap->cap_link));
	ASSERT(CAP_ENABLED(cap));

	waitq_block(&cap->cap_waitq);
	list_remove(l, cap);
	if (list_is_empty(&capped_projects) && list_is_empty(&capped_zones)) {
		cpucaps_enabled = B_FALSE;
		cpucaps_clock_callout = NULL;
	}
	cap->cap_value = 0;
	cap->cap_project = NULL;
	cap->cap_zone = NULL;
	if (cap->cap_kstat != NULL) {
		kstat_delete(cap->cap_kstat);
		cap->cap_kstat = NULL;
	}

}

/*
 * Enable cap for a project kpj
 * It is safe to enable already enabled project cap.
 * Should be called with caps_lock held.
 */
static void
cap_project_enable(kproject_t *kpj, hrtime_t value)
{
	cpucap_t *cap = kpj->kpj_cpucap;

	ASSERT(MUTEX_HELD(&caps_lock));
	ASSERT(cap != NULL);

	if (CAP_DISABLED(cap)) {
		ASSERT(cap->cap_kstat == NULL);
		cap_enable(&capped_projects, cap, value);
		cap->cap_project = kpj;
		cap->cap_zone = kpj->kpj_zone;

		/*
		 * Create cap kstats
		 */
		if ((cap->cap_kstat = rctl_kstat_create_project(kpj, "cpucaps",
		    KSTAT_TYPE_NAMED,
		    sizeof (cap_kstat) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL)) != NULL) {
			cap->cap_kstat->ks_data_size +=
			    strlen(cap->cap_zone->zone_name) + 1;
			cap->cap_kstat->ks_lock = &cap_kstat_lock;
			cap->cap_kstat->ks_data = &cap_kstat;
			cap->cap_kstat->ks_update = cap_kstat_update;
			cap->cap_kstat->ks_private = cap;
			kstat_install(cap->cap_kstat);
		}
	}
}

/*
 * Disable project cap.
 * It is safe to disable already disabled project cap.
 * Should be called with caps_lock held.
 */
static void
cap_project_disable(kproject_t *kpj)
{
	cpucap_t *cap = kpj->kpj_cpucap;

	ASSERT(MUTEX_HELD(&caps_lock));
	ASSERT(cap != NULL);
	ASSERT(cap->cap_project == kpj);

	if (CAP_ENABLED(cap))
		cap_disable(&capped_projects, cap);
}

/*
 * Enable cap for a zone
 * It is safe to enable already enabled zone cap.
 * Should be called with caps_lock held.
 */
static void
cap_zone_enable(zone_t *zone, hrtime_t value)
{
	cpucap_t *cap = zone->zone_cpucap;

	ASSERT(MUTEX_HELD(&caps_lock));
	ASSERT(cap != NULL);

	if (CAP_DISABLED(cap)) {
		ASSERT(cap->cap_kstat == NULL);
		cap_enable(&capped_zones, cap, value);
		cap->cap_zone = zone;

		/*
		 * Create cap kstats
		 */
		if ((cap->cap_kstat = rctl_kstat_create_zone(zone, "cpucaps",
		    KSTAT_TYPE_NAMED,
		    sizeof (cap_kstat) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL)) != NULL) {
			cap->cap_kstat->ks_data_size +=
			    strlen(cap->cap_zone->zone_name) + 1;
			cap->cap_kstat->ks_lock = &cap_kstat_lock;
			cap->cap_kstat->ks_data = &cap_kstat;
			cap->cap_kstat->ks_update = cap_kstat_update;
			cap->cap_kstat->ks_private = cap;
			kstat_install(cap->cap_kstat);
		}
	}
}

/*
 * Disable zone cap.
 * It is safe to disable already disabled zone cap.
 * Should be called with caps_lock held.
 */
static void
cap_zone_disable(zone_t *zone)
{
	cpucap_t *cap = zone->zone_cpucap;

	ASSERT(MUTEX_HELD(&caps_lock));
	ASSERT(cap != NULL);
	ASSERT(cap->cap_zone == zone);

	if (CAP_ENABLED(cap))
		cap_disable(&capped_zones, cap);
}

/*
 * Apply specified callback to all caps contained in the list `l'.
 */
static void
cap_walk(list_t *l, void (*cb)(cpucap_t *, int64_t))
{
	static uint64_t cpucap_walk_gen;
	cpucap_t *cap;

	ASSERT(MUTEX_HELD(&caps_lock));

	for (cap = list_head(l); cap != NULL; cap = list_next(l, cap)) {
		(*cb)(cap, cpucap_walk_gen);
	}

	atomic_inc_64(&cpucap_walk_gen);
}

/*
 * If cap limit is not reached, make one thread from wait queue runnable.
 * The waitq_isempty check is performed without the waitq lock. If a new thread
 * is placed on the waitq right after the check, it will be picked up during the
 * next invocation of cap_poke_waitq().
 */
/* ARGSUSED */
static void
cap_poke_waitq(cpucap_t *cap, int64_t gen)
{
	ASSERT(MUTEX_HELD(&caps_lock));

	if (cap->cap_usage >= cap->cap_value) {
		cap->cap_above++;
	} else {
		waitq_t *wq = &cap->cap_waitq;

		cap->cap_below++;

		if (!waitq_isempty(wq))
			waitq_runone(wq);
	}
}

/*
 * The callback function called for every cap on capped_projects list.
 * Decay cap usage by CAP_DECAY_FACTOR
 * Add this cap project usage to its zone usage.
 * Kick off a thread from the cap waitq if cap is not reached.
 */
static void
cap_project_usage_walker(cpucap_t *cap, int64_t gen)
{
	zone_t		*zone = cap->cap_zone;
	hrtime_t	cap_usage = cap->cap_usage;

	ASSERT(MUTEX_HELD(&caps_lock));
	ASSERT(cap->cap_project->kpj_cpucap == cap);
	ASSERT(zone == cap->cap_project->kpj_zone);
	ASSERT(CAP_ENABLED(cap));

	/*
	 * Set or clear the CAP_REACHED flag based on the current usage.
	 * Only projects having their own caps are ever marked as CAP_REACHED.
	 */
	cap_poke_waitq(cap, 0);

	/*
	 * Add project's CPU usage to our zone's CPU usage.
	 */
	if (ZONE_IS_CAPPED(zone)) {
		cpucap_t *zcap = zone->zone_cpucap;

		ASSERT(zcap->cap_zone == zone);

		/*
		 * If we haven't reset this zone's usage during this clock tick
		 * yet, then do it now. The cap_gen field is used to check
		 * whether this is the first zone's project we see during this
		 * tick or a subsequent one.
		 */
		if (zcap->cap_gen != gen) {
			if (zcap->cap_usage > zcap->cap_maxusage)
				zcap->cap_maxusage = zcap->cap_usage;
			zcap->cap_usage = 0;
			zcap->cap_gen = gen;
		}
		DTRACE_PROBE2(cpucaps__zusage, cpucap_t *, zcap,
		    hrtime_t, cap_usage);
		zcap->cap_usage += cap_usage;
		/* Check for overflows */
		if (zcap->cap_usage < 0)
			zcap->cap_usage = MAX_USAGE - 1;
	}

	/*
	 * Decay project usage.
	 */
	disp_lock_enter(&cap->cap_usagelock);
	cap->cap_usage -= ROUND_SCALE(cap_usage, CAP_DECAY_FACTOR);
	disp_lock_exit(&cap->cap_usagelock);
}

/*
 * On every clock tick walk the list of project caps and update the CPU usage.
 * Also walk the list of zone caps checking whether any threads should
 * transition from wait queue to run queue.
 *
 * This function gets called by the clock thread directly when there are any
 * defined caps. The only lock that it grabs is caps_lock. Nothing else grabs
 * caps_lock for long periods of time, so there should be almost no contention
 * for it.
 */
static void
caps_update()
{
	mutex_enter(&caps_lock);
	cap_walk(&capped_projects, cap_project_usage_walker);
	cap_walk(&capped_zones, cap_poke_waitq);
	mutex_exit(&caps_lock);
}

/*
 * The function is called for each project in a zone when the zone cap is
 * modified. It enables project caps if zone cap is enabled and disables if the
 * zone cap is disabled and project doesn't have its own cap.
 *
 * For each project that does not have cpucap structure allocated it allocates a
 * new structure and assigns to kpj->cpu_cap. The allocation is performed
 * without holding caps_lock to avoid using KM_SLEEP allocation with caps_lock
 * held.
 */
static int
cap_project_zone_modify_walker(kproject_t *kpj, void *arg)
{
	cpucap_t *project_cap = NULL;
	cpucap_t *zone_cap = (cpucap_t *)arg;

	ASSERT(zone_cap != NULL);

	if (kpj->kpj_cpucap == NULL) {
		/*
		 * This is the first time any cap was established for this
		 * project. Allocate a new cpucap structure for it.
		 */
		project_cap = cap_alloc();
	}

	mutex_enter(&caps_lock);

	/*
	 * Double-check that kpj_cpucap is still NULL - now with caps_lock held
	 * and assign the newly allocated cpucap structure to it.
	 */
	if (kpj->kpj_cpucap == NULL) {
		kpj->kpj_cpucap = project_cap;
	} else if (project_cap != NULL) {
		cap_free(project_cap);
	}

	project_cap = kpj->kpj_cpucap;

	if (CAP_DISABLED(zone_cap)) {
		/*
		 * Remove all projects in this zone without caps
		 * from the capped_projects list.
		 */
		if (project_cap->cap_value == MAX_USAGE) {
			cap_project_disable(kpj);
		}
	} else if (CAP_DISABLED(project_cap)) {
		/*
		 * Add the project to capped_projects list.
		 */
		ASSERT(project_cap->cap_value == 0);
		cap_project_enable(kpj, MAX_USAGE);
	}
	mutex_exit(&caps_lock);

	return (0);
}

/*
 * Set zone cap to cap_val
 * If cap_val is equal to NOCAP, disable zone cap.
 *
 * If this is the first time a cap is set on a zone, allocate cpucap structure
 * without holding caps_lock to avoid KM_SLEEP allocation with caps_lock held.
 */
int
cpucaps_zone_set(zone_t *zone, rctl_qty_t cap_val)
{
	cpucap_t *cap = NULL;
	hrtime_t value;

	if (cap_val == 0)
		return (EINVAL);

	ASSERT(cap_val <= MAXCAP);
	if (cap_val > MAXCAP)
		cap_val = MAXCAP;

	/*
	 * Nothing to do if trying to disable a cap on a zone when caps are off
	 * or a zone which does not have a cap yet.
	 */
	if ((CPUCAPS_OFF() || !ZONE_IS_CAPPED(zone)) && (cap_val == NOCAP))
		return (0);

	if (zone->zone_cpucap == NULL)
		cap = cap_alloc();

	mutex_enter(&caps_lock);

	if (cpucaps_busy) {
		mutex_exit(&caps_lock);
		return (EBUSY);
	}

	/*
	 * Double-check whether zone->zone_cpucap is NULL, now with caps_lock
	 * held. If it is still NULL, assign a newly allocated cpucap to it.
	 */
	if (zone->zone_cpucap == NULL) {
		zone->zone_cpucap = cap;
	} else if (cap != NULL) {
		cap_free(cap);
	}

	cap = zone->zone_cpucap;
	value = cap_val * cap_tick_cost;
	if (value < 0)
		value = MAX_USAGE;

	/* Nothing to do if the value is staying the same */
	if (value == cap->cap_value) {
		mutex_exit(&caps_lock);
		return (0);
	}

	/*
	 * Clear cap statistics since the cap value itself changes.
	 */
	cap->cap_above = cap->cap_below = 0;


	if (cap_val == NOCAP) {
		if (CAP_ENABLED(cap)) {
			/*
			 * Remove cap for the zone
			 */
			cap_zone_disable(zone);
			cpucaps_busy = B_TRUE;
			mutex_exit(&caps_lock);
			/*
			 * Disable caps for all project belonging to this zone
			 * unless they have their own cap.
			 */
			(void) project_walk_all(zone->zone_id,
			    cap_project_zone_modify_walker, cap);

			mutex_enter(&caps_lock);
			cpucaps_busy = B_FALSE;
		}
	} else if (CAP_DISABLED(cap)) {
		/*
		 * Set a cap on a zone which previously was not capped.
		 */
		cap_zone_enable(zone, value);
		cpucaps_busy = B_TRUE;
		mutex_exit(&caps_lock);

		/*
		 * Enable cap for all projects belonging to this zone.
		 */
		(void) project_walk_all(zone->zone_id,
		    cap_project_zone_modify_walker, cap);

		mutex_enter(&caps_lock);
		cpucaps_busy = B_FALSE;
	} else {
		/*
		 * No state transitions, just change the value
		 */
		cap->cap_value = value;
	}

	ASSERT(MUTEX_HELD(&caps_lock));
	ASSERT(!cpucaps_busy);
	mutex_exit(&caps_lock);

	return (0);
}

/*
 * The project is going away so disable its cap.
 */
void
cpucaps_project_remove(kproject_t *kpj)
{
	mutex_enter(&caps_lock);
	if (PROJECT_IS_CAPPED(kpj))
		cap_project_disable(kpj);
	if (kpj->kpj_cpucap != NULL) {
		cap_free(kpj->kpj_cpucap);
		kpj->kpj_cpucap = NULL;
	}
	mutex_exit(&caps_lock);
}

/*
 * The zone is going away, so disable its cap.
 */
void
cpucaps_zone_remove(zone_t *zone)
{
	mutex_enter(&caps_lock);
	while (ZONE_IS_CAPPED(zone)) {
		mutex_exit(&caps_lock);
		(void) cpucaps_zone_set(zone, NOCAP);
		mutex_enter(&caps_lock);
	}
	if (zone->zone_cpucap != NULL) {
		cap_free(zone->zone_cpucap);
		zone->zone_cpucap = NULL;
	}
	mutex_exit(&caps_lock);
}

/*
 * New project was created. It should be put on the capped_projects list if
 * its zone has a cap.
 */
void
cpucaps_project_add(kproject_t *kpj)
{
	cpucap_t *cap = NULL;

	if (CPUCAPS_OFF() || !ZONE_IS_CAPPED(kpj->kpj_zone))
		return;

	/*
	 * This project was never capped before, so allocate its cap structure.
	 */
	if (kpj->kpj_cpucap == NULL)
		cap = cap_alloc();

	mutex_enter(&caps_lock);
	/*
	 * Double-check with caps_lock held
	 */
	if (kpj->kpj_cpucap == NULL) {
		kpj->kpj_cpucap = cap;
	} else if (cap != NULL) {
		cap_free(cap);
	}

	if (ZONE_IS_CAPPED(kpj->kpj_zone))
		cap_project_enable(kpj, MAX_USAGE);

	mutex_exit(&caps_lock);
}

/*
 * Set project cap to cap_val
 * If cap_val is equal to NOCAP, disable project cap.
 *
 * If this is the first time a cap is set on a project, allocate cpucap
 * structure without holding caps_lock to avoid KM_SLEEP allocation with
 * caps_lock held.
 */
int
cpucaps_project_set(kproject_t *kpj, rctl_qty_t cap_val)
{
	cpucap_t *cap = NULL;
	hrtime_t value;

	if (cap_val == 0)
		return (EINVAL);

	ASSERT(cap_val <= MAXCAP);
	if (cap_val > MAXCAP)
		cap_val = MAXCAP;

	/*
	 * Nothing to do if trying to disable project cap and caps are not
	 * enabled or if trying to disable cap on a project that does not have
	 * cap enabled.
	 */
	if ((cap_val == NOCAP) && (CPUCAPS_OFF() || !PROJECT_IS_CAPPED(kpj)))
		return (0);

	if (kpj->kpj_cpucap == NULL) {
		/*
		 * This project was never capped before, so allocate its cap
		 * structure.
		 */
		cap = cap_alloc();
	}

	mutex_enter(&caps_lock);

	/*
	 * Double-check with caps_lock held.
	 */
	if (kpj->kpj_cpucap == NULL) {
		kpj->kpj_cpucap = cap;
	} else if (cap != NULL) {
		cap_free(cap);
	}

	/*
	 * Get the actual pointer to the project cap.
	 */
	cap = kpj->kpj_cpucap;
	value = cap_val * cap_tick_cost;
	if (value < 0)
		value = MAX_USAGE;

	/*
	 * Nothing to do if the value is not changing
	 */
	if (value == cap->cap_value) {
		mutex_exit(&caps_lock);
		return (0);
	}

	/*
	 * Clear cap statistics since the cap value itself changes.
	 */
	cap->cap_above = cap->cap_below = 0;
	cap->cap_maxusage = 0;

	if (cap_val != NOCAP) {
		/*
		 * Enable this cap if it is not already enabled.
		 */
		if (CAP_DISABLED(cap))
			cap_project_enable(kpj, value);
		else
			cap->cap_value = value;
	} else if (CAP_ENABLED(cap)) {
		/*
		 * User requested to drop a cap on the project. If it is part of
		 * capped zone, keep the cap and set the value to MAX_USAGE,
		 * otherwise disable the cap.
		 */
		if (ZONE_IS_CAPPED(kpj->kpj_zone)) {
			cap->cap_value = MAX_USAGE;
		} else {
			cap_project_disable(kpj);
		}
	}
	mutex_exit(&caps_lock);

	return (0);
}

/*
 * Get cap usage.
 */
static rctl_qty_t
cap_get(cpucap_t *cap)
{
	return (cap != NULL ? (rctl_qty_t)(cap->cap_usage / cap_tick_cost) : 0);
}

/*
 * Get current project usage.
 */
rctl_qty_t
cpucaps_project_get(kproject_t *kpj)
{
	return (cap_get(kpj->kpj_cpucap));
}

/*
 * Get current zone usage.
 */
rctl_qty_t
cpucaps_zone_get(zone_t *zone)
{
	return (cap_get(zone->zone_cpucap));
}

/*
 * Charge project of thread t the time thread t spent on CPU since previously
 * adjusted.
 *
 * Record the current on-CPU time in the csc structure.
 *
 * Do not adjust for more than one tick worth of time.
 *
 * It is possible that the project cap is being disabled while this routine is
 * executed. This should not cause any issues since the association between the
 * thread and its project is protected by thread lock.
 */
static void
caps_charge_adjust(kthread_id_t t, caps_sc_t *csc)
{
	kproject_t	*kpj = ttoproj(t);
	hrtime_t	new_usage;
	hrtime_t	usage_delta;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(kpj->kpj_cpucap != NULL);

	/* Get on-CPU time since birth of a thread */
	new_usage = mstate_thread_onproc_time(t);

	/* Time spent on CPU since last checked */
	usage_delta = new_usage - csc->csc_cputime;

	/* Save the accumulated on-CPU time */
	csc->csc_cputime = new_usage;

	/* Charge at most one tick worth of on-CPU time */
	if (usage_delta > cap_tick_cost)
		usage_delta = cap_tick_cost;

	/* Add usage_delta to the project usage value. */
	if (usage_delta > 0) {
		cpucap_t *cap = kpj->kpj_cpucap;

		DTRACE_PROBE2(cpucaps__project__charge,
		    kthread_id_t, t, hrtime_t, usage_delta);

		disp_lock_enter_high(&cap->cap_usagelock);
		cap->cap_usage += usage_delta;

		/* Check for overflows */
		if (cap->cap_usage < 0)
			cap->cap_usage = MAX_USAGE - 1;

		disp_lock_exit_high(&cap->cap_usagelock);

		/*
		 * cap_maxusage is only kept for observability. Move it outside
		 * the lock to reduce the time spent while holding the lock.
		 */
		if (cap->cap_usage > cap->cap_maxusage)
			cap->cap_maxusage = cap->cap_usage;
	}
}

/*
 * Charge thread's project and return True if project or zone should be
 * penalized because its project or zone is exceeding its cap. Also sets
 * TS_PROJWAITQ or TS_ZONEWAITQ in this case.
 *
 * It is possible that the project cap is being disabled while this routine is
 * executed. This should not cause any issues since the association between the
 * thread and its project is protected by thread lock. It will still set
 * TS_PROJECTWAITQ/TS_ZONEWAITQ in this case but cpucaps_enforce will not place
 * anything on the blocked wait queue.
 *
 */
boolean_t
cpucaps_charge(kthread_id_t t, caps_sc_t *csc, cpucaps_charge_t charge_type)
{
	kproject_t	*kpj = ttoproj(t);
	klwp_t		*lwp = t->t_lwp;
	zone_t		*zone;
	cpucap_t	*project_cap;
	boolean_t	rc = B_FALSE;

	ASSERT(THREAD_LOCK_HELD(t));

	/* Nothing to do for projects that are not capped. */
	if (lwp == NULL || !PROJECT_IS_CAPPED(kpj))
		return (B_FALSE);

	caps_charge_adjust(t, csc);

	/*
	 * The caller only requested to charge the project usage, no enforcement
	 * part.
	 */
	if (charge_type == CPUCAPS_CHARGE_ONLY)
		return (B_FALSE);

	project_cap = kpj->kpj_cpucap;

	if (project_cap->cap_usage >= project_cap->cap_value) {
		t->t_schedflag |= TS_PROJWAITQ;
		rc = B_TRUE;
	} else if (t->t_schedflag & TS_PROJWAITQ) {
		t->t_schedflag &= ~TS_PROJWAITQ;
	}

	zone = ttozone(t);
	if (!ZONE_IS_CAPPED(zone)) {
		if (t->t_schedflag & TS_ZONEWAITQ)
			t->t_schedflag &= ~TS_ZONEWAITQ;
	} else {
		cpucap_t *zone_cap = zone->zone_cpucap;

		if (zone_cap->cap_usage >= zone_cap->cap_value) {
			t->t_schedflag |= TS_ZONEWAITQ;
			rc = B_TRUE;
		} else if (t->t_schedflag & TS_ZONEWAITQ) {
			t->t_schedflag &= ~TS_ZONEWAITQ;
		}
	}


	return (rc);
}

/*
 * Enforce CPU caps. If got preempted in the user-land, we know that thread does
 * not hold any kernel locks, so enqueue ourselves on the waitq, if needed.
 *
 * CPU Caps are only enforced for user threads.
 *
 * Threads flagged with TS_PROJWAITQ are placed on their project wait queues and
 * threads marked with TS_ZONEWAITQ are placed on their zone wait queue.
 *
 * It is possible that by the time we enter cpucaps_enforce() the cap is already
 * disabled. In this case waitq_enqueue() fails and doesn't enqueue anything. We
 * still clear TS_PROJWAITQ/TS_ZONEWAITQ flags in this case since they no longer
 * apply.
 */
boolean_t
cpucaps_enforce(kthread_t *t)
{
	klwp_t *lwp = t->t_lwp;

	ASSERT(THREAD_LOCK_HELD(t));

	if (lwp != NULL && lwp->lwp_state == LWP_USER) {
		if (t->t_schedflag & TS_PROJWAITQ) {
			ASSERT(ttoproj(t)->kpj_cpucap != NULL);
			t->t_schedflag &= ~TS_ANYWAITQ;
			if (waitq_enqueue(&(ttoproj(t)->kpj_cpucap->cap_waitq),
			    t)) {
				return (B_TRUE);
			}
		}
		if (t->t_schedflag & TS_ZONEWAITQ) {
			ASSERT(ttozone(t)->zone_cpucap != NULL);
			t->t_schedflag &= ~TS_ZONEWAITQ;
			if (waitq_enqueue(&(ttozone(t)->zone_cpucap->cap_waitq),
			    t)) {
				return (B_TRUE);
			}
		}
	}

	/*
	 * The thread is not enqueued on the wait queue.
	 */
	return (B_FALSE);
}

/*
 * Convert internal cap statistics into values exported by cap kstat.
 */
static int
cap_kstat_update(kstat_t *ksp, int rw)
{
	struct cap_kstat *capsp = &cap_kstat;
	cpucap_t *cap = ksp->ks_private;
	clock_t	tick_sec = SEC_TO_TICK(1);
	char *zonename = cap->cap_zone->zone_name;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	capsp->cap_value.value.ui64 =
	    ROUND_SCALE(cap->cap_value, cap_tick_cost);
	capsp->cap_usage.value.ui64 =
	    ROUND_SCALE(cap->cap_usage, cap_tick_cost);
	capsp->cap_maxusage.value.ui64 =
	    ROUND_SCALE(cap->cap_maxusage, cap_tick_cost);
	capsp->cap_nwait.value.ui64 = cap->cap_waitq.wq_count;
	capsp->cap_below.value.ui64 = ROUND_SCALE(cap->cap_below, tick_sec);
	capsp->cap_above.value.ui64 = ROUND_SCALE(cap->cap_above, tick_sec);
	kstat_named_setstr(&capsp->cap_zonename, zonename);

	return (0);
}
